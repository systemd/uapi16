// SPDX-License-Identifier: LGPL-2.1-or-later
//! The files of a tree that are added to a manifest: what statx() says of
//! one, whether that shows a change, and why one could not be read. The
//! system calls that read them are in the module sys.

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

use rustix::fs::FileType;

use crate::error::{Error, ErrorKind, TreeProblem};
use crate::{Features, Mode, Name, Sha256};

/// The mount a file was reached through, as statx() tells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MountId {
    /// STATX_MNT_ID_UNIQUE, from Linux 6.8 on: no other mount gets this
    /// ID while the system runs.
    Unique(u64),
    /// STATX_MNT_ID, from Linux 5.8 on: the ID of the mount in
    /// /proc/self/mountinfo, which a later mount can get once this one is
    /// gone.
    Reusable(u64),
}

/// A device number as statx() gives it, split into its major and its minor
/// number.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct DeviceNumber {
    pub(crate) major: u32,
    pub(crate) minor: u32,
}

/// Which file a status is of. Two statuses of the same identity are of the
/// same file, reached through the same mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Identity {
    /// The mount the file was reached through. A bind mount is a mount of
    /// its own, so a file reached through it is not the file reached
    /// through its source.
    pub(crate) mount: MountId,
    /// The device of the file system the file is on.
    pub(crate) device: DeviceNumber,
    /// The inode number of the file.
    pub(crate) inode: u64,
    /// The subvolume the file is in, STATX_SUBVOL from Linux 6.10 on,
    /// where the file system has subvolumes, such as btrfs.
    pub(crate) subvolume: Option<u64>,
}

impl Identity {
    /// The inode, whatever mount it was reached through.
    pub(crate) fn inode_id(&self) -> InodeId {
        InodeId {
            device: self.device,
            inode: self.inode,
            subvolume: self.subvolume,
        }
    }
}

/// Which inode a file is, whatever mount it was reached through: the
/// device, the inode number and the subvolume of an [`Identity`], without
/// its mount.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct InodeId {
    pub(crate) device: DeviceNumber,
    pub(crate) inode: u64,
    pub(crate) subvolume: Option<u64>,
}

/// A time as statx() gives it: seconds since the epoch, negative before
/// it, and nanoseconds on top.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timestamp {
    pub(crate) seconds: i64,
    pub(crate) nanoseconds: u32,
}

/// What statx() says of a file: what a manifest records of it, and what
/// tells whether it changed.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Status {
    pub(crate) identity: Identity,
    /// The type of the file, from the type bits of its mode.
    pub(crate) file_type: FileType,
    /// The permission bits with the set-user-ID, the set-group-ID and the
    /// sticky bit.
    pub(crate) mode: Mode,
    /// How many names the file has.
    pub(crate) nlink: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    /// The size of the data of a regular file, the length of the target
    /// of a symbolic link.
    pub(crate) size: u64,
    /// When the data changed last.
    pub(crate) mtime: Timestamp,
    /// When the data or the metadata changed last, the modification time
    /// included. Nothing can set it.
    pub(crate) ctime: Timestamp,
    /// When the file was made, where the file system keeps that.
    pub(crate) btime: Option<Timestamp>,
    /// The device a device node stands for.
    pub(crate) rdev: DeviceNumber,
}

impl Status {
    /// Whether this status, read after `before`, shows that the file
    /// changed: that it is another file now, or that its size, its
    /// modification time, its change time or how many names it has are
    /// different. The change time changes with everything else, also when
    /// the modification time is set back. Not on FAT, though: a rename over
    /// a file changes no time of the file there, only how many names it
    /// has, and an unlink sets its modification time and its change time in
    /// steps of two seconds, so one in the same two seconds changes none.
    /// How many names it has shows both.
    pub(crate) fn changed_since(&self, before: &Status) -> bool {
        (self.identity, self.size, self.mtime, self.ctime, self.nlink)
            != (before.identity, before.size, before.mtime, before.ctime, before.nlink)
    }

    /// Whether this status, of a file that has the inode of the file `own`
    /// is the status of, is of that file as well. A file system can give
    /// two files one inode, see [`OwnFiles`](crate::sys::OwnFiles). They
    /// are one file if the type, the mode, the owner, the group, the number
    /// of names, the size, the modification time and the change time are
    /// the same, and the birth time where both statuses have one.
    pub(crate) fn matches(&self, own: &Status) -> bool {
        let born = match (self.btime, own.btime) {
            (Some(found), Some(own)) => found == own,
            _ => true,
        };
        let held = |s: &Status| (s.file_type, s.mode, s.uid, s.gid, s.nlink, s.size, s.mtime, s.ctime);
        born && held(self) == held(own)
    }

    /// What `read`, the read of the data of the file of this status, comes
    /// to, with `after`, the status of the file after the read. If the
    /// status shows that the file changed, the file changed while it was
    /// read. Data that did not end at its size is
    /// [`Failure::WrongSize`] where the status shows no change.
    pub(crate) fn check_read(
        &self,
        read: Result<Sha256, DataFailure>,
        after: Result<Status, Failure>,
    ) -> Result<Sha256, Failure> {
        // Another file in the place of this one also makes reads fail.
        if after.as_ref().is_ok_and(|after| after.changed_since(self)) {
            return Err(Failure::Changed);
        }
        let hash = match read {
            Ok(hash) => hash,
            Err(DataFailure::EndedEarly | DataFailure::WentOn) => return Err(Failure::WrongSize),
            Err(DataFailure::Io(e)) => return Err(Failure::Io(e)),
        };
        after.map(|_| hash)
    }
}

/// The handle of an [`Entry`]: the descriptor everything is read of the
/// file through.
#[derive(Debug)]
pub(crate) enum Handle<'fd> {
    /// A handle the entry was opened as, which is closed with the entry.
    Owned(OwnedFd),
    /// A descriptor of a caller, which the entry borrows and never closes.
    Borrowed(BorrowedFd<'fd>),
}

impl AsFd for Handle<'_> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        match self {
            Handle::Owned(handle) => handle.as_fd(),
            Handle::Borrowed(handle) => *handle,
        }
    }
}

/// A file of a tree, open as a handle that nothing is read through, and
/// its status. A symbolic link is the link itself, and a FIFO or a device
/// node is not opened. The entry of a descriptor that a caller gave borrows
/// that descriptor for `'fd`. Any other entry owns its handle.
#[derive(Debug)]
pub(crate) struct Entry<'fd> {
    handle: Handle<'fd>,
    status: Status,
    /// Whether it is an automount point, see [`Entry::is_automount`].
    automount: bool,
}

impl<'fd> Entry<'fd> {
    /// The entry of the handle `handle`, whose status is `status`, and
    /// which is an automount point if `automount` says so.
    pub(crate) fn new(handle: Handle<'fd>, status: Status, automount: bool) -> Entry<'fd> {
        Entry {
            handle,
            status,
            automount,
        }
    }

    /// The handle, which entries below a directory are opened in.
    pub(crate) fn handle(&self) -> BorrowedFd<'_> {
        self.handle.as_fd()
    }

    /// The status of the file when it was opened.
    pub(crate) fn status(&self) -> &Status {
        &self.status
    }

    /// Whether the file is an automount point: a directory that nothing is
    /// mounted on yet, and that the kernel mounts something on once it is
    /// opened or a name is looked up in it. Taking its handle mounts
    /// nothing. It is never opened and nothing is looked up in it, so a
    /// tree has it as the empty directory it is until then.
    pub(crate) fn is_automount(&self) -> bool {
        self.automount
    }
}

/// Where an entry of a tree is: the directory it is in and its name there,
/// which a directory is opened by, see [`Entry::reopen`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct Place<'a> {
    /// The directory, a handle or the directory open for its listing.
    pub(crate) dir: BorrowedFd<'a>,
    /// The name of the entry in it, one component.
    pub(crate) name: &'a CStr,
}

/// Why the data of a regular file was not read as far as its size.
#[derive(Debug)]
pub(crate) enum DataFailure {
    /// A read failed.
    Io(io::Error),
    /// The data ended before the size.
    EndedEarly,
    /// The data went on after the size.
    WentOn,
}

/// Why a feature that was asked for cannot be read from a file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Unreadable {
    /// The file system of the file has no inode flags.
    NoInodeFlags,
    /// The file system of the file has no DOS attributes.
    NoDosAttributes,
    /// The file system of the file has no extended attributes.
    NoXattrs,
    /// Extended attributes are read through procfs, which is not mounted.
    NoProcfs,
    /// An extended attribute of the file has a name a manifest cannot
    /// hold: one that is not UTF-8, or that has a control character or a
    /// noncharacter.
    XattrName,
    /// The file system cannot say what its label is.
    NoLabel,
    /// The label of the file system is not one a manifest can hold.
    LabelUnwritable,
    /// The file is an automount point, which is not opened, see
    /// [`Entry::is_automount`], and the feature is read from the open file.
    Automount,
}

impl fmt::Display for Unreadable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Unreadable::NoInodeFlags => f.write_str("the file system has no inode flags"),
            Unreadable::NoDosAttributes => f.write_str("the file system has no DOS attributes"),
            Unreadable::NoXattrs => f.write_str("the file system has no extended attributes"),
            Unreadable::NoProcfs => f.write_str("extended attributes are read through /proc, which is not mounted"),
            Unreadable::XattrName => f.write_str("an extended attribute has a name a manifest cannot hold"),
            Unreadable::NoLabel => f.write_str("the file system cannot say what its label is"),
            Unreadable::LabelUnwritable => f.write_str("the label of the file system is not one a manifest can hold"),
            Unreadable::Automount => f.write_str("the file is an automount point, which is not opened"),
        }
    }
}

/// Why a file of a tree could not be read as it is.
#[derive(Debug)]
pub(crate) enum Failure {
    /// A system call failed.
    Io(io::Error),
    /// statx() gives no mount ID: the kernel is older than 5.8.
    NoMountId,
    /// The file changed while it was read.
    Changed,
    /// The data of a regular file did not end at its size, and nothing
    /// else showed a change: the size of a file of procfs or sysfs says
    /// nothing of its data.
    WrongSize,
    /// A single feature that was asked for cannot be read from the file.
    Unavailable(Features, Unreadable),
    /// What was read of the file is more than a record of a manifest has
    /// room for.
    TooLarge,
}

impl Failure {
    /// The error of the file `name`, which failed so. The error that the
    /// kernel is too old is about no file.
    pub(crate) fn into_error(self, name: &Name) -> Error {
        let message = match self {
            Failure::Io(e) => {
                let message = format!("{}: {}", Subject(name), e);
                return Error::new(ErrorKind::Io, message).named(name.as_str()).caused_by(e);
            }
            Failure::NoMountId => {
                let message = "the kernel is too old: statx() reports no mount ID, uapi16 needs Linux 5.10 or newer";
                return Error::new(ErrorKind::Tree(TreeProblem::FeatureUnavailable), message.into());
            }
            Failure::Changed => format!("{}: changed while it was read", Subject(name)),
            Failure::WrongSize => format!("{}: its data does not end at its size", Subject(name)),
            Failure::Unavailable(feature, why) => {
                let message = format!(
                    "{}: '{}' cannot be read: {}",
                    Subject(name),
                    feature.names().next().unwrap_or_default(),
                    why
                );
                return Error::new(ErrorKind::Tree(TreeProblem::FeatureUnavailable), message)
                    .named(name.as_str())
                    .about(feature);
            }
            Failure::TooLarge => return Error::record_too_large().named(name.as_str()),
        };
        Error::new(ErrorKind::Tree(TreeProblem::Changed), message).named(name.as_str())
    }
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Failure {
        Failure::Io(error)
    }
}

/// A file of a tree as a message names it: by its name in the manifest,
/// and the root of the tree, which has none, as what it is.
struct Subject<'a>(&'a Name);

impl fmt::Display for Subject<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_root() {
            return f.write_str("the root of the tree");
        }
        write!(f, "{}", self.0.as_str().escape_debug())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The status of a regular file that a test changes.
    fn status() -> Status {
        let time = Timestamp {
            seconds: 1_700_000_000,
            nanoseconds: 123_456_789,
        };
        Status {
            identity: Identity {
                mount: MountId::Unique(1),
                device: DeviceNumber { major: 8, minor: 1 },
                inode: 2,
                subvolume: None,
            },
            file_type: FileType::RegularFile,
            mode: Mode::from_st_mode(0o644),
            nlink: 1,
            uid: 3,
            gid: 4,
            size: 5,
            mtime: time,
            ctime: time,
            btime: Some(time),
            rdev: DeviceNumber { major: 0, minor: 0 },
        }
    }

    /// Only another file, another size, another modification time,
    /// another change time or another number of names show that a file
    /// changed. The rest changes with the change time.
    #[test]
    fn what_shows_a_change() {
        let before = status();
        assert!(!before.changed_since(&before));
        type Change = fn(&mut Status);
        let changes: [(&str, Change, bool); 14] = [
            ("mount", |s| s.identity.mount = MountId::Reusable(1), true),
            ("device", |s| s.identity.device.minor ^= 1, true),
            ("inode", |s| s.identity.inode ^= 1, true),
            ("subvolume", |s| s.identity.subvolume = Some(6), true),
            ("size", |s| s.size ^= 1, true),
            ("mtime", |s| s.mtime.nanoseconds ^= 1, true),
            ("ctime", |s| s.ctime.seconds ^= 1, true),
            ("nlink", |s| s.nlink ^= 1, true),
            ("type", |s| s.file_type = FileType::Fifo, false),
            ("mode", |s| s.mode = Mode::from_st_mode(0o1234), false),
            ("uid", |s| s.uid ^= 1, false),
            ("gid", |s| s.gid ^= 1, false),
            ("btime", |s| s.btime = None, false),
            ("rdev", |s| s.rdev.major ^= 1, false),
        ];
        for (what, change, shows) in changes {
            let mut later = before;
            change(&mut later);
            assert_eq!(later.changed_since(&before), shows, "{}", what);
        }
    }

    /// Two statuses with one inode are of one file where the type, the
    /// mode, the owner, the group, the number of names, the size, the
    /// modification time and the change time are the same, to the
    /// nanosecond, and the birth time where both have one. The mount a file
    /// was reached through and the device a device node stands for say
    /// nothing of that.
    #[test]
    fn what_tells_files_with_one_inode_apart() {
        let own = status();
        assert!(own.matches(&own));
        type Change = fn(&mut Status);
        let changes: [(&str, Change, bool); 14] = [
            ("type", |s| s.file_type = FileType::Fifo, false),
            ("mode", |s| s.mode = Mode::from_st_mode(0o645), false),
            ("uid", |s| s.uid ^= 1, false),
            ("gid", |s| s.gid ^= 1, false),
            ("nlink", |s| s.nlink ^= 1, false),
            ("size", |s| s.size ^= 1, false),
            ("mtime", |s| s.mtime.nanoseconds ^= 1, false),
            ("mtime, its seconds", |s| s.mtime.seconds ^= 1, false),
            ("ctime", |s| s.ctime.nanoseconds ^= 1, false),
            ("ctime, its seconds", |s| s.ctime.seconds ^= 1, false),
            (
                "btime",
                |s| {
                    s.btime = Some(Timestamp {
                        seconds: 1,
                        nanoseconds: 2,
                    })
                },
                false,
            ),
            ("no btime", |s| s.btime = None, true),
            ("mount", |s| s.identity.mount = MountId::Reusable(1), true),
            ("rdev", |s| s.rdev.major ^= 1, true),
        ];
        for (what, change, one_file) in changes {
            let mut found = own;
            change(&mut found);
            assert_eq!(found.matches(&own), one_file, "{}", what);
            assert_eq!(own.matches(&found), one_file, "{}", what);
        }
        let mut neither = own;
        neither.btime = None;
        assert!(neither.matches(&neither));
    }

    /// A read and the status after it come to the hash when both went
    /// through and the file did not change. A change wins over a read that
    /// failed, as another file in the place of the one opened makes reads
    /// fail, and a read that failed over a statx() that failed. Data that
    /// does not end at the size of a file that shows no change is a failure
    /// of its own.
    #[test]
    fn what_a_read_comes_to() {
        /// What a read comes to where it does not come to a hash.
        #[derive(Debug, PartialEq)]
        enum Came {
            Changed,
            WrongSize,
            Failed(Option<i32>),
        }
        let before = status();
        let mut changed = before;
        changed.size += 1;
        let hash = Sha256::digest(b"data");
        let failed = |errno: i32| io::Error::from_raw_os_error(errno);
        let comes_to = |read, after| match before.check_read(read, after) {
            Ok(found) => Ok(found),
            Err(Failure::Io(e)) => Err(Came::Failed(e.raw_os_error())),
            Err(Failure::Changed) => Err(Came::Changed),
            Err(Failure::WrongSize) => Err(Came::WrongSize),
            Err(failure) => panic!("{:?}", failure),
        };
        assert_eq!(comes_to(Ok(hash), Ok(before)), Ok(hash));
        assert_eq!(comes_to(Ok(hash), Ok(changed)), Err(Came::Changed));
        let read_failed = Err(DataFailure::Io(failed(libc::EISDIR)));
        assert_eq!(comes_to(read_failed, Ok(changed)), Err(Came::Changed));
        for end in [DataFailure::EndedEarly, DataFailure::WentOn] {
            assert_eq!(comes_to(Err(end), Ok(before)), Err(Came::WrongSize));
        }
        for end in [DataFailure::EndedEarly, DataFailure::WentOn] {
            assert_eq!(comes_to(Err(end), Ok(changed)), Err(Came::Changed));
        }
        let statx_failed = Err(Failure::Io(failed(libc::ENOMEM)));
        assert_eq!(comes_to(Err(DataFailure::WentOn), statx_failed), Err(Came::WrongSize));
        let read_failed = Err(DataFailure::Io(failed(libc::EIO)));
        assert_eq!(comes_to(read_failed, Ok(before)), Err(Came::Failed(Some(libc::EIO))));
        let read_failed = Err(DataFailure::Io(failed(libc::EIO)));
        let statx_failed = Err(Failure::Io(failed(libc::ENOMEM)));
        assert_eq!(comes_to(read_failed, statx_failed), Err(Came::Failed(Some(libc::EIO))));
        let statx_failed = Err(Failure::Io(failed(libc::ENOMEM)));
        assert_eq!(comes_to(Ok(hash), statx_failed), Err(Came::Failed(Some(libc::ENOMEM))));
    }

    /// A failure is an error about the file that failed, with its name, but
    /// for the kernel that is too old. The root of the tree, which has no
    /// name, is named for what it is. An I/O error says which file it is of
    /// as well, and keeps the error of the system call.
    #[test]
    fn errors() {
        let name = Name::new("a/\"b\"").unwrap();
        let e = Failure::Changed.into_error(name);
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::Changed));
        assert_eq!(e.name(), Some(name.as_str()));
        assert_eq!(e.to_string(), r#"a/\"b\": changed while it was read"#);
        let e = Failure::Changed.into_error(Name::ROOT);
        assert_eq!(e.to_string(), "the root of the tree: changed while it was read");
        let e = Failure::WrongSize.into_error(name);
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::Changed), Some(name.as_str()))
        );
        assert_eq!(e.to_string(), r#"a/\"b\": its data does not end at its size"#);
        let e = Failure::Io(io::Error::from_raw_os_error(libc::EACCES)).into_error(name);
        assert_eq!(e.kind(), ErrorKind::Io);
        assert_eq!(e.name(), Some(name.as_str()));
        assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EACCES));
        let denied = io::Error::from_raw_os_error(libc::EACCES);
        assert_eq!(e.to_string(), format!(r#"a/\"b\": {}"#, denied));
        let failed = io::Error::from_raw_os_error(libc::EIO);
        let e = Failure::Io(io::Error::from_raw_os_error(libc::EIO)).into_error(Name::ROOT);
        assert_eq!(e.to_string(), format!("the root of the tree: {}", failed));
        let e = Failure::NoMountId.into_error(name);
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::FeatureUnavailable));
        assert_eq!((e.name(), e.feature(), e.io_error().is_none()), (None, None, true));
        assert_eq!(
            e.to_string(),
            "the kernel is too old: statx() reports no mount ID, uapi16 needs Linux 5.10 or newer"
        );
    }
}
