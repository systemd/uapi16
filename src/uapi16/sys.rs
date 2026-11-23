// SPDX-License-Identifier: LGPL-2.1-or-later
//! The system calls that read the files of the host, for the manifest
//! builder and for PinnedDirectory. Each takes the descriptors and the
//! buffers it works on and returns what it found. None keeps any state of
//! its own, but for what the process found out about O_EMPTYPATH and about
//! open_tree().
//!
//! A system call that fails with EINTR is made again, which a FUSE server
//! can answer any of them with. close() never is: Linux closes the
//! descriptor also when close() fails with EINTR, and by then its number
//! can be another file's.
//!
//! A file of a tree is opened by its name in its directory as a handle,
//! with O_PATH, which opens nothing behind it, and everything else is read
//! through that handle. The data of a regular file is read through the
//! handle opened again, never through the name: by then the name can lead
//! to another file, such as a device node, which would do what its driver
//! does on open. A directory is opened by its name in its directory
//! instead, with O_DIRECTORY and O_NOFOLLOW, which open nothing but a
//! directory, and it has to be the file of its handle. Nothing else is ever
//! opened.
//!
//! Nothing here mounts anything. The kernel mounts a file system on an
//! automount point when the directory is opened by its name or a name is
//! looked up in it, but not when its handle is taken. So an entry says
//! whether it is an automount point, see [`Entry::is_automount`], and one
//! that is one is not opened and has nothing opened in it. That leaves a
//! directory that becomes an automount point after its entry was looked at
//! and before it is opened by its name, see [`Entry::reopen`].
//!
//! The ioctls rustix has no call for and the lookups in the user database
//! are in the modules ioctl and nss, which have the unsafe code for them.
//! They are called from here and handed on from here, so that this module
//! stays the one place that talks to the host.

use std::collections::hash_map::RandomState;
use std::collections::{BTreeMap, HashMap};
use std::ffi::{CStr, CString};
use std::fs::File;
use std::hash::BuildHasher;
use std::io;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::str;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use pathrs::error::{Error as PathrsError, ErrorKind as PathrsErrorKind};
use pathrs::flags::OpenFlags;
use pathrs::HandleRef;
use rustix::fs::{
    AtFlags, FallocateFlags, FileType, FsWord, IFlags, OFlags, Statx, StatxAttributes, StatxFlags, StatxTimestamp, CWD,
};
use rustix::io::{retry_on_intr, Errno};
use rustix::mount::OpenTreeFlags;

use crate::digest::Sha256Context;
use crate::ioctl;
pub(crate) use crate::ioctl::{DosAttributes, FsLabel, FsUuid};
pub(crate) use crate::nss::UserDatabase;
use crate::object::{FatSerial, FileObject, InodeFlags};
use crate::tree::{
    DataFailure, DeviceNumber, Entry, Failure, Handle, Identity, InodeId, MountId, Place, Status, Timestamp, Unreadable,
};
use crate::{Features, Mode, Sha256, MAX_RECORD_SIZE, STRING_RULES, USER_NAMESPACE};

/// How much of a file is read at a time for its hash: the size of the
/// buffer the data is read through.
pub(crate) const DATA_BUFFER_SIZE: usize = 1024 * 1024;

/// What this process found out about O_EMPTYPATH: whether the kernel
/// reopens a descriptor with `openat(fd, "", O_EMPTYPATH | ..)`, which
/// needs no procfs. Linux 7.2 has it.
pub(crate) struct EmptyPath;

impl EmptyPath {
    /// O_EMPTYPATH, include/uapi/asm-generic/fcntl.h. No architecture
    /// overrides it, and fs/fcntl.c checks at build time that it is a bit
    /// of its own on every architecture.
    pub(crate) const FLAG: u32 = 1 << 26;
    /// Not tried yet.
    pub(crate) const UNKNOWN: u8 = 0;
    /// It worked once, so ENOENT is the file's own error from now on.
    const WORKS: u8 = 1;
    /// The kernel ignored the flag and refused the empty path.
    pub(crate) const MISSING: u8 = 2;
}

/// The state of [`EmptyPath`] for this process.
pub(crate) static EMPTYPATH: AtomicU8 = AtomicU8::new(EmptyPath::UNKNOWN);

/// What this process found out about open_tree(): whether it can be
/// called. Linux has it since 5.2, and a seccomp filter can refuse it, as
/// the default one of a container runtime does for a process that may not
/// mount.
struct OpenTree;

impl OpenTree {
    /// Nothing refused it so far, and it is called.
    const CALLED: u8 = 0;
    /// The kernel does not have the call, or a filter refused it, and it
    /// is not called again.
    const REFUSED: u8 = 1;
}

/// The state of [`OpenTree`] for this process.
static OPEN_TREE: AtomicU8 = AtomicU8::new(OpenTree::CALLED);

/// A regular file or a directory pinned by a handle, a descriptor opened
/// with O_PATH, through which it is opened for reading: without its name,
/// so that no other file can take its place.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PinnedFile<'fd>(BorrowedFd<'fd>);

impl<'fd> PinnedFile<'fd> {
    /// How the file is opened: for reading, without waiting for anything,
    /// without becoming the controlling terminal, and not inherited across
    /// exec.
    const READ_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);
    /// The same for the checked reopen of pathrs, which adds O_CLOEXEC on
    /// its own.
    const PATHRS_READ_FLAGS: OpenFlags = OpenFlags::O_RDONLY
        .union(OpenFlags::O_NONBLOCK)
        .union(OpenFlags::O_NOCTTY);
    /// The regular file or the directory `handle` refers to. It has to be
    /// one of the two: the file is opened whatever it is, a device node
    /// with what its driver does on open.
    pub(crate) fn new(handle: BorrowedFd<'fd>) -> PinnedFile<'fd> {
        PinnedFile(handle)
    }

    /// Opens the file for reading: through O_EMPTYPATH where the kernel
    /// has it, probed the way systemd's fd_reopen() does, and through
    /// procfs where it does not, with the checked reopen of pathrs.
    pub(crate) fn reopen(self) -> io::Result<File> {
        let state = EMPTYPATH.load(Ordering::Relaxed);
        if state != EmptyPath::MISSING {
            match self.reopen_empty_path() {
                Ok(file) => {
                    EMPTYPATH.store(EmptyPath::WORKS, Ordering::Relaxed);
                    return Ok(file);
                }
                // An older kernel ignores the flag and refuses the empty
                // path. Once it worked, ENOENT comes from the file itself.
                Err(Errno::NOENT) if state != EmptyPath::WORKS => {
                    EMPTYPATH.store(EmptyPath::MISSING, Ordering::Relaxed);
                }
                Err(e) => return Err(e.into()),
            }
        }
        self.reopen_procfs()
    }

    /// The reopen through O_EMPTYPATH.
    fn reopen_empty_path(self) -> rustix::io::Result<File> {
        let flags = PinnedFile::READ_FLAGS | OFlags::from_bits_retain(EmptyPath::FLAG);
        let fd = retry_on_intr(|| rustix::fs::openat(self.0, "", flags, rustix::fs::Mode::empty()))?;
        Ok(File::from(fd))
    }

    /// The checked reopen of pathrs, through a procfs of its own.
    fn reopen_procfs(self) -> io::Result<File> {
        loop {
            let reopened = HandleRef::from_fd(self.0)
                .reopen(PinnedFile::PATHRS_READ_FLAGS)
                .map_err(pathrs_io_error);
            match reopened {
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                reopened => return reopened,
            }
        }
    }
}

/// The link procfs has for a descriptor of the calling thread,
/// /proc/thread-self/fd/N, which leads to the file of the descriptor. It is
/// the link of the thread and not that of /proc/self, the thread group
/// leader: a thread that took a descriptor table of its own has other
/// descriptors than the leader.
///
/// What goes through the link is checked to be the inode of the descriptor,
/// by its device, its inode number and its subvolume: a /proc that is not
/// what it should be could lead elsewhere. What takes the path of the link
/// checks it before and after, see [`FdLink::check`]. That narrows what
/// such a /proc can do, but it doesn't close it: it can lead to the file
/// for the two checks and elsewhere in between. So only the extended
/// attributes of a file that is not open for reading are read through the
/// path, see [`UserXattrs`].
#[derive(Debug)]
pub(crate) struct FdLink<'fd> {
    fd: BorrowedFd<'fd>,
    path: String,
}

impl<'fd> FdLink<'fd> {
    /// Where procfs has a link for every descriptor of the calling thread.
    const THREAD_SELF_FD: &'static str = "/proc/thread-self/fd";

    /// The link of the descriptor `fd`.
    pub(crate) fn new(fd: BorrowedFd<'fd>) -> FdLink<'fd> {
        FdLink {
            fd,
            path: format!("{}/{}", FdLink::THREAD_SELF_FD, fd.as_raw_fd()),
        }
    }

    /// The path of the link, for what goes through it once it was checked.
    pub(crate) fn path(&self) -> &str {
        &self.path
    }

    /// Checks that the link leads to the file of the descriptor, before the
    /// path of the link is used and once more after, see [`FdLink`].
    pub(crate) fn check(&self) -> io::Result<()> {
        let statx =
            retry_on_intr(|| rustix::fs::statx(CWD, self.path.as_str(), AtFlags::NO_AUTOMOUNT, InodeId::REQUEST))?;
        if InodeId::from_statx(&statx) != InodeId::of(self.fd)? {
            return Err(io::Error::other(
                "the link of /proc/thread-self/fd leads to another file",
            ));
        }
        Ok(())
    }
}

/// The error `error` of pathrs as an I/O error: that of the system call
/// that failed, or the error of pathrs itself where none did.
pub(crate) fn pathrs_io_error(error: PathrsError) -> io::Error {
    match error.kind() {
        PathrsErrorKind::OsError(Some(errno)) => io::Error::from_raw_os_error(errno),
        _ => io::Error::other(error),
    }
}

impl InodeId {
    /// What statx() is asked for to tell the inode of a file, which takes
    /// no mount ID.
    const REQUEST: StatxFlags = StatxFlags::INO.union(Status::SUBVOL);

    /// The inode of the file `fd` refers to.
    fn of(fd: BorrowedFd<'_>) -> rustix::io::Result<InodeId> {
        let statx = retry_on_intr(|| rustix::fs::statx(fd, c"", Status::OF_DESCRIPTOR, InodeId::REQUEST))?;
        Ok(InodeId::from_statx(&statx))
    }

    /// The inode `statx` is of, with its subvolume where the mask has it.
    fn from_statx(statx: &Statx) -> InodeId {
        let mask = StatxFlags::from_bits_retain(statx.stx_mask);
        InodeId {
            device: DeviceNumber {
                major: statx.stx_dev_major,
                minor: statx.stx_dev_minor,
            },
            inode: statx.stx_ino,
            subvolume: mask.contains(Status::SUBVOL).then_some(statx.stx_subvol),
        }
    }
}

impl Status {
    /// STATX_MNT_ID_UNIQUE, include/uapi/linux/stat.h, which rustix has no
    /// name for. A kernel before 6.8 does not know the bit and passes over
    /// it.
    const MNT_ID_UNIQUE: StatxFlags = StatxFlags::from_bits_retain(0x4000);
    /// STATX_SUBVOL, include/uapi/linux/stat.h, which rustix has no name
    /// for either. A kernel before 6.10 passes over it.
    const SUBVOL: StatxFlags = StatxFlags::from_bits_retain(0x8000);
    /// What statx() is asked for: the fields of `struct stat` but the
    /// access time and the blocks, the birth time, the mount ID, the unique
    /// one where the kernel has it, and the subvolume. A kernel since 5.8
    /// gives the mount ID unasked.
    const REQUEST: StatxFlags = StatxFlags::TYPE
        .union(StatxFlags::MODE)
        .union(StatxFlags::NLINK)
        .union(StatxFlags::UID)
        .union(StatxFlags::GID)
        .union(StatxFlags::MTIME)
        .union(StatxFlags::CTIME)
        .union(StatxFlags::INO)
        .union(StatxFlags::SIZE)
        .union(StatxFlags::BTIME)
        .union(StatxFlags::MNT_ID)
        .union(Status::MNT_ID_UNIQUE)
        .union(Status::SUBVOL);
    /// How statx() looks at the file a descriptor refers to: at the file
    /// itself, a symbolic link too.
    const OF_DESCRIPTOR: AtFlags = AtFlags::EMPTY_PATH.union(AtFlags::SYMLINK_NOFOLLOW);

    /// The status of the file `fd` refers to.
    pub(crate) fn of(fd: BorrowedFd<'_>) -> Result<Status, Failure> {
        Status::from_statx(&retry_on_intr(|| {
            rustix::fs::statx(fd, c"", Status::OF_DESCRIPTOR, Status::REQUEST)
        })?)
    }

    /// The status `statx` gives. Without a mount ID there is none: the
    /// kernel is older than 5.8.
    ///
    /// The fields of `struct stat` are taken whatever `stx_mask` says, as
    /// stat() takes them. Every file system fills them in, and only a FUSE
    /// server can leave some out of the mask. The other fields are taken
    /// where the mask has them.
    fn from_statx(statx: &Statx) -> Result<Status, Failure> {
        let mask = StatxFlags::from_bits_retain(statx.stx_mask);
        // Asked for the unique ID, a kernel that has it gives that one and
        // says so instead of STATX_MNT_ID.
        let mount = if mask.contains(Status::MNT_ID_UNIQUE) {
            MountId::Unique(statx.stx_mnt_id)
        } else if mask.contains(StatxFlags::MNT_ID) {
            MountId::Reusable(statx.stx_mnt_id)
        } else {
            return Err(Failure::NoMountId);
        };
        let mode = u32::from(statx.stx_mode);
        Ok(Status {
            identity: Identity {
                mount,
                device: DeviceNumber {
                    major: statx.stx_dev_major,
                    minor: statx.stx_dev_minor,
                },
                inode: statx.stx_ino,
                subvolume: mask.contains(Status::SUBVOL).then_some(statx.stx_subvol),
            },
            file_type: FileType::from_raw_mode(mode),
            mode: Mode::from_st_mode(mode),
            nlink: statx.stx_nlink,
            uid: statx.stx_uid,
            gid: statx.stx_gid,
            size: statx.stx_size,
            mtime: statx.stx_mtime.into(),
            ctime: statx.stx_ctime.into(),
            btime: mask.contains(StatxFlags::BTIME).then(|| statx.stx_btime.into()),
            rdev: DeviceNumber {
                major: statx.stx_rdev_major,
                minor: statx.stx_rdev_minor,
            },
        })
    }
}

impl<'fd> Entry<'fd> {
    /// How an entry is opened: as a handle, which needs no permission on
    /// the file and opens nothing behind it, the symbolic link itself where
    /// it is one, and not inherited across exec.
    const HANDLE_FLAGS: OFlags = OFlags::PATH.union(OFlags::NOFOLLOW).union(OFlags::CLOEXEC);
    /// The same for open_tree(), which opens such a handle and is told
    /// outright not to mount anything on an automount point.
    const TREE_FLAGS: OpenTreeFlags = OpenTreeFlags::AT_NO_AUTOMOUNT
        .union(OpenTreeFlags::AT_SYMLINK_NOFOLLOW)
        .union(OpenTreeFlags::OPEN_TREE_CLOEXEC);
    /// `AUTOFS_SUPER_MAGIC`, include/uapi/linux/magic.h: the type statfs()
    /// gives for autofs, the file system of the automount points an
    /// automount unit of systemd or automount(8) makes.
    const AUTOFS_SUPER_MAGIC: FsWord = 0x0187;
    /// How a directory is opened by its name for reading: as a directory
    /// and nothing else, not through a symbolic link, and not inherited
    /// across exec.
    const DIRECTORY_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::DIRECTORY)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);

    /// Opens the entry `name` of the directory `dir`, one component and
    /// neither `.` nor `..`, such as a name of the listing of `dir`. `dir`
    /// is no automount point: nothing is looked up in one.
    ///
    /// Taking the handle mounts nothing on an automount point: open_tree()
    /// is told not to, and where it can't be called, openat() with O_PATH
    /// doesn't either for the last component of a name, which is all there
    /// is of this one.
    pub(crate) fn open_at(dir: BorrowedFd<'_>, name: &CStr) -> Result<Entry<'static>, Failure> {
        debug_assert!(!matches!(name.to_bytes(), b"" | b"." | b"..") && !name.to_bytes().contains(&b'/'));
        let handle = Entry::handle_at(dir, name)?;
        Entry::of_handle(Handle::Owned(handle), true)
    }

    /// The entry of the file `handle` refers to, a descriptor that a caller
    /// gave: a handle, or the file open for reading. The entry borrows the
    /// descriptor, and neither duplicates nor closes it.
    pub(crate) fn of(handle: BorrowedFd<'fd>) -> Result<Entry<'fd>, Failure> {
        Entry::of_handle(Handle::Borrowed(handle), false)
    }

    /// Takes the handle of the entry `name` of the directory `dir` with
    /// open_tree(), and with openat() where open_tree() can't be called:
    /// the kernel fails it with ENOSYS where it does not have it, and a
    /// seccomp filter refuses it with that or with EPERM, also one that the
    /// process got after open_tree() worked. openat() takes the same
    /// handle, so an EPERM that was the file's own after all is what
    /// openat() fails with as well.
    fn handle_at(dir: BorrowedFd<'_>, name: &CStr) -> rustix::io::Result<OwnedFd> {
        if OPEN_TREE.load(Ordering::Relaxed) != OpenTree::REFUSED {
            match retry_on_intr(|| rustix::mount::open_tree(dir, name, Entry::TREE_FLAGS)) {
                Err(Errno::NOSYS | Errno::PERM) => OPEN_TREE.store(OpenTree::REFUSED, Ordering::Relaxed),
                taken => return taken,
            }
        }
        retry_on_intr(|| rustix::fs::openat(dir, name, Entry::HANDLE_FLAGS, rustix::fs::Mode::empty()))
    }

    /// The entry of the handle `handle`, with its status and whether it is
    /// an automount point, see [`Entry::is_automount`]. Both are told from
    /// the handle, before anything is opened.
    ///
    /// A file system that mounts something on a directory of its own, as
    /// NFS, SMB, AFS and debugfs do, says so in statx(), with
    /// STATX_ATTR_AUTOMOUNT. autofs does not, and every directory of it can
    /// be one. So a directory is one as well where statfs() says that its
    /// file system is autofs, as for systemd's CHASE_NO_AUTOFS.
    ///
    /// `opened_here` says that the handle was opened in a directory that is
    /// no automount point, as [`Entry::open_at`] opens one. Such a
    /// directory is not on autofs, and what is in it is on its file system,
    /// unless something is mounted there, which the handle is the root of
    /// then. So only the root of a mount can be on autofs, and only that is
    /// asked for its file system then, where statx() tells one, which it
    /// does since Linux 5.8.
    fn of_handle(handle: Handle<'fd>, opened_here: bool) -> Result<Entry<'fd>, Failure> {
        let statx = retry_on_intr(|| rustix::fs::statx(&handle, c"", Status::OF_DESCRIPTOR, Status::REQUEST))?;
        let status = Status::from_statx(&statx)?;
        let mut automount = false;
        if status.file_type == FileType::Directory {
            let tells_root = statx.stx_attributes_mask.contains(StatxAttributes::MOUNT_ROOT);
            let root = statx.stx_attributes.contains(StatxAttributes::MOUNT_ROOT);
            automount = statx.stx_attributes.contains(StatxAttributes::AUTOMOUNT);
            if !automount && (root || !tells_root || !opened_here) {
                let file_system = retry_on_intr(|| rustix::fs::fstatfs(&handle))?;
                automount = file_system.f_type == Entry::AUTOFS_SUPER_MAGIC;
            }
        }
        Ok(Entry::new(handle, status, automount))
    }

    /// Opens the regular file or the directory of the entry for reading, so
    /// that no other file takes its place. A regular file is opened through
    /// its handle and never through its name, as [`PinnedFile`] opens one.
    /// A directory is opened by its name in its directory, `place`, with
    /// O_DIRECTORY and O_NOFOLLOW, which refuse anything else with ENOTDIR
    /// before it is opened, and what is opened has to be the file of the
    /// entry. That takes no procfs, and nothing but the permission to read
    /// the directory, which its listing takes anyway. A directory without a
    /// place, that of a descriptor a caller gave, such as the top directory
    /// of a walk, has no name to be opened by, and is opened through its
    /// handle as a regular file is. Anything else fails with EINVAL and is
    /// not opened: a FIFO or a device node would do what its driver does on
    /// open, and an automount point opened by its name would have a file
    /// system mounted on it, see [`Entry::is_automount`].
    ///
    /// Whether the entry is an automount point was told when its handle was
    /// taken. A directory that becomes one after that and before it is
    /// opened by its name has its file system mounted by that open, which
    /// then is the root of that file system and not the file of the entry:
    /// the tree changed. This is a known limit, and nothing here closes it.
    /// It takes someone who can mount in the mount namespace of the
    /// process, or an automount unit that is started at that moment.
    pub(crate) fn reopen(&self, place: Option<Place<'_>>) -> Result<Readable, Failure> {
        match (self.status().file_type, place) {
            (FileType::Directory, _) if self.is_automount() => Err(Errno::INVAL.into()),
            (FileType::Directory, Some(place)) => self.reopen_directory(place),
            (FileType::RegularFile | FileType::Directory, _) => Ok(Readable(PinnedFile::new(self.handle()).reopen()?)),
            _ => Err(Errno::INVAL.into()),
        }
    }

    /// Opens the directory of the entry by its name in its directory,
    /// `place`. Where the name leads to nothing by then, to something that
    /// is not a directory or to another directory, the tree changed.
    fn reopen_directory(&self, place: Place<'_>) -> Result<Readable, Failure> {
        let opened = retry_on_intr(|| {
            rustix::fs::openat(place.dir, place.name, Entry::DIRECTORY_FLAGS, rustix::fs::Mode::empty())
        });
        let directory = match opened {
            Ok(directory) => directory,
            Err(Errno::NOENT | Errno::NOTDIR) => return Err(Failure::Changed),
            Err(e) => return Err(e.into()),
        };
        if Status::of(directory.as_fd())?.identity != self.status().identity {
            return Err(Failure::Changed);
        }
        Ok(Readable(File::from(directory)))
    }
}

/// A regular file or a directory of a tree, opened for reading, see
/// [`Entry::reopen`]. The data of a regular file is read through it, the
/// entries of a directory are listed through it, and the inode flags, the
/// DOS attributes, the extended attributes and the identity of the file
/// system are read through it, which a handle cannot be asked for.
#[derive(Debug)]
pub(crate) struct Readable(File);

impl Readable {
    /// What a file system fails an ioctl with that it does not have: ENOTTY
    /// as a rule, and what systemd takes for the same besides.
    const NOT_SUPPORTED: [Errno; 4] = [Errno::NOTTY, Errno::OPNOTSUPP, Errno::NOSYS, Errno::INVAL];
    /// The inode flags the specification has a field for, as the kernel
    /// has them, each with its flag in a manifest.
    const INODE_FLAGS: [(IFlags, InodeFlags); 5] = [
        (IFlags::APPEND, InodeFlags::APPEND_ONLY),
        (IFlags::IMMUTABLE, InodeFlags::IMMUTABLE),
        (IFlags::NOATIME, InodeFlags::NO_ATIME),
        (IFlags::NOCOW, InodeFlags::NO_COW),
        (IFlags::NODUMP, InodeFlags::NO_DUMP),
    ];

    /// The descriptor, which the entries of a directory are listed
    /// through.
    pub(crate) fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }

    /// What the file system answers the ioctl `ask` makes with, or nothing
    /// if it does not have the ioctl.
    fn answer<T>(ask: impl FnMut() -> rustix::io::Result<T>) -> io::Result<Option<T>> {
        match retry_on_intr(ask) {
            Ok(answer) => Ok(Some(answer)),
            Err(e) if Readable::NOT_SUPPORTED.contains(&e) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Those of the inode flags the specification has a field for that are
    /// set on the file, or nothing if its file system has no inode flags.
    pub(crate) fn inode_flags(&self) -> io::Result<Option<InodeFlags>> {
        let Some(set) = Readable::answer(|| rustix::fs::ioctl_getflags(&self.0))? else {
            return Ok(None);
        };
        let flags = Readable::INODE_FLAGS
            .into_iter()
            .filter(|(flag, _)| set.contains(*flag))
            .fold(InodeFlags::default(), |flags, (_, flag)| flags | flag);
        Ok(Some(flags))
    }

    /// The DOS attributes of the file, or nothing if its file system has
    /// none. Whatever answers the ioctl has them: FAT and exFAT, and a
    /// FUSE server that implements it.
    pub(crate) fn dos_attributes(&self) -> io::Result<Option<DosAttributes>> {
        Readable::answer(|| ioctl::dos_attributes(self.as_fd()))
    }

    /// The volume serial number of the FAT file system the file is in, or
    /// nothing if it is in another file system.
    pub(crate) fn fat_serial(&self) -> io::Result<Option<FatSerial>> {
        Readable::answer(|| ioctl::fat_serial(self.as_fd()))
    }

    /// The label of the file system the file is in, or nothing if the file
    /// system cannot say.
    pub(crate) fn fs_label(&self) -> io::Result<Option<FsLabel>> {
        Readable::answer(|| ioctl::fs_label(self.as_fd()))
    }

    /// What the file system the file is in identifies itself with, or
    /// nothing if it has no identifier or the kernel is older than Linux
    /// 6.9.
    pub(crate) fn fs_uuid(&self) -> io::Result<Option<FsUuid>> {
        Readable::answer(|| ioctl::fs_uuid(self.as_fd()))
    }
}

/// Reads the extended attributes of the user namespace of the files of a
/// tree. Those of a file that is open for reading anyway are read through
/// that descriptor, see [`Entry::reopen`]: a directory that is listed, a
/// regular file that is opened for the hash of its data, and either of
/// them where it is opened for its inode flags, its DOS attributes or the
/// identity of its file system. Nothing is opened for its attributes
/// alone, so a file that may not be opened still has them read, and
/// reading them is never an open that others see. The system calls that
/// take a descriptor refuse a handle, also those of Linux 6.13 that take a
/// descriptor and an empty path. So the attributes of any other file are
/// read through the link procfs has for its handle, see [`FdLink`], which
/// leads to the file itself, the way systemd reads them.
///
/// It keeps what it reads into from one file to the next.
#[derive(Debug, Default)]
pub(crate) struct UserXattrs {
    /// The names of the attributes of the file, each with a NUL behind it,
    /// as listxattr() gives them.
    names: Vec<u8>,
    /// The value of one attribute.
    value: Vec<u8>,
}

impl UserXattrs {
    /// `XATTR_LIST_MAX`, include/uapi/linux/limits.h: the most bytes the
    /// names of the attributes of a file take.
    const LIST_MAX: usize = 65536;
    /// `XATTR_SIZE_MAX`, include/uapi/linux/limits.h: the most bytes the
    /// value of an attribute has.
    const SIZE_MAX: usize = 65536;
    /// What ends a name in the list of names.
    const NAME_END: u8 = b'\0';
    /// What separates the namespace of an attribute from its name.
    const NAMESPACE_SEPARATOR: u8 = b'.';

    /// A reader that has read nothing yet.
    pub(crate) fn new() -> UserXattrs {
        UserXattrs::default()
    }

    /// The name `full`, as listxattr() lists it, without the namespace in
    /// front, if it is in the user namespace.
    fn in_user_namespace(full: &[u8]) -> Option<&[u8]> {
        full.strip_prefix(USER_NAMESPACE.as_bytes())?
            .strip_prefix(&[UserXattrs::NAMESPACE_SEPARATOR])
    }

    /// The attributes of the user namespace of the regular file or the
    /// directory `file`, which is open for reading, by their names without
    /// the namespace.
    ///
    /// A name a manifest cannot hold fails, since a manifest lists all
    /// attributes of a file or none. So do attributes that take more than
    /// a record of a manifest has room for, before they are all read. An
    /// attribute that is gone by the time its value is read is left out.
    pub(crate) fn read(&mut self, file: &Readable) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
        self.read_from(XattrSource::File(file.as_fd()))
    }

    /// The same for the file of `entry`, which is not open for reading,
    /// through the link procfs has for its handle, see [`FdLink`]. A
    /// symbolic link cannot have any, and is not asked. Without a procfs
    /// they can't be read. A file that is gone by now can look like that,
    /// and fails as one that changed.
    pub(crate) fn read_unopened(&mut self, entry: &Entry<'_>) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
        debug_assert_ne!(entry.status().file_type, FileType::Symlink);
        let link = FdLink::new(entry.handle());
        match link.check() {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // The link is not there without a procfs. A file system
                // can also say so of a file that was removed, as a FUSE
                // file system does that finds its files by their names.
                // The handle itself tells the two apart.
                return Err(match InodeId::of(entry.handle()) {
                    Err(Errno::NOENT | Errno::STALE) => Failure::Changed,
                    _ => Failure::Unavailable(Features::USER_XATTR, Unreadable::NoProcfs),
                });
            }
            Err(e) => return Err(e.into()),
        }
        let attributes = self.read_from(XattrSource::Link(link.path()))?;
        // Where the link led elsewhere for a while, what was read can be of
        // another file.
        link.check()?;
        Ok(attributes)
    }

    /// Reads the attributes of the file `source` leads to.
    fn read_from(&mut self, source: XattrSource<'_>) -> Result<BTreeMap<String, Vec<u8>>, Failure> {
        let unavailable = |why| Failure::Unavailable(Features::USER_XATTR, why);
        let mut attributes = BTreeMap::new();
        self.names.resize(UserXattrs::LIST_MAX, 0);
        let listed = match retry_on_intr(|| source.list(&mut self.names[..])) {
            Ok(listed) => listed,
            Err(Errno::OPNOTSUPP | Errno::NOSYS) => return Err(unavailable(Unreadable::NoXattrs)),
            Err(e) => return Err(e.into()),
        };
        let mut size = 0;
        for full in self.names[..listed].split(|&byte| byte == UserXattrs::NAME_END) {
            let Some(name) = UserXattrs::in_user_namespace(full) else {
                continue;
            };
            let name = str::from_utf8(name)
                .ok()
                .filter(|name| FileObject::is_xattr_name(name) && STRING_RULES.admits(name))
                .ok_or(unavailable(Unreadable::XattrName))?;
            self.value.resize(UserXattrs::SIZE_MAX, 0);
            let len = match retry_on_intr(|| source.get(full, &mut self.value[..])) {
                Ok(len) => len,
                // Removed since it was listed, or listed on a file that
                // cannot have one.
                Err(Errno::NODATA) => continue,
                Err(Errno::OPNOTSUPP | Errno::NOSYS) => return Err(unavailable(Unreadable::NoXattrs)),
                Err(e) => return Err(e.into()),
            };
            size += name.len() + len;
            if size > MAX_RECORD_SIZE {
                return Err(Failure::TooLarge);
            }
            attributes.insert(name.to_owned(), self.value[..len].to_vec());
        }
        Ok(attributes)
    }
}

/// What the extended attributes of a file are read through.
#[derive(Clone, Copy, Debug)]
enum XattrSource<'a> {
    /// The file open for reading, with flistxattr() and fgetxattr().
    File(BorrowedFd<'a>),
    /// The path of the link procfs has for the handle of a file that is not
    /// open for reading, with listxattr() and getxattr(), which follow the
    /// link. llistxattr() and lgetxattr() would read the link itself.
    Link(&'a str),
}

impl XattrSource<'_> {
    /// Lists the names of the attributes into `names`.
    fn list(self, names: &mut [u8]) -> rustix::io::Result<usize> {
        match self {
            XattrSource::File(fd) => rustix::fs::flistxattr(fd, names),
            XattrSource::Link(path) => rustix::fs::listxattr(path, names),
        }
    }

    /// Reads the value of the attribute `name` into `value`.
    fn get(self, name: &[u8], value: &mut [u8]) -> rustix::io::Result<usize> {
        match self {
            XattrSource::File(fd) => rustix::fs::fgetxattr(fd, name, value),
            XattrSource::Link(path) => rustix::fs::getxattr(path, name, value),
        }
    }
}

/// A name nobody can guess, which a file has in a directory for a while: a
/// scratch file on a file system without O_TMPFILE until it loses it right
/// away, and a new file until it gets its own. Nobody else has it, so only
/// the one who made the file removes it.
#[derive(Debug)]
pub(crate) struct TemporaryName(CString);

impl TemporaryName {
    /// How many names that something else has are tried before giving up.
    const ATTEMPTS: u32 = 16;

    /// Makes a file in the directory `dir` with a name that starts with
    /// `prefix` and that nothing has, opened with `flags`, which have
    /// O_CREAT and O_EXCL, and with the access mode `mode`.
    fn create(
        dir: BorrowedFd<'_>,
        prefix: &str,
        flags: OFlags,
        mode: rustix::fs::Mode,
    ) -> io::Result<(OwnedFd, TemporaryName)> {
        // The keys of a hasher of std are random, and so is what it makes
        // of a number.
        let random = RandomState::new();
        let mut taken = 0;
        for number in 0_u64.. {
            let name = format!("{}{:016x}", prefix, random.hash_one(number));
            let name = TemporaryName(CString::new(name).expect("a formatted name has no NUL"));
            match rustix::fs::openat(dir, name.as_c_str(), flags, mode) {
                Ok(file) => return Ok((file, name)),
                Err(Errno::EXIST) => {
                    taken += 1;
                    if taken == TemporaryName::ATTEMPTS {
                        break;
                    }
                }
                // An open that was interrupted can have made the file
                // before it failed, and the same open again fails with
                // EEXIST then. So it is not made again: the name is
                // removed, and the next one is tried. That is no name
                // something else has, and does not count as one.
                Err(Errno::INTR) => name.remove(dir)?,
                Err(e) => return Err(e.into()),
            }
        }
        Err(Errno::EXIST.into())
    }

    /// The name, which need not be UTF-8 for anybody else.
    fn as_c_str(&self) -> &CStr {
        &self.0
    }

    /// Removes the name from the directory `dir`. A removal that was
    /// interrupted can have removed it before it failed, so one that finds
    /// the name gone is done.
    fn remove(&self, dir: BorrowedFd<'_>) -> rustix::io::Result<()> {
        match retry_on_intr(|| rustix::fs::unlinkat(dir, self.as_c_str(), AtFlags::empty())) {
            Ok(()) | Err(Errno::NOENT) => Ok(()),
            Err(e) => Err(e),
        }
    }
}

/// The files a manifest that is being built made itself and has open, such
/// as its scratch files. A walk of a tree that they are in passes over
/// them. They are known by their inodes and not by their names: a file
/// system can keep a file that was unlinked while it is open in its
/// directory, under a name of its own. NFS does, and so does libfuse for a
/// FUSE file system on its high-level interface that does not set
/// hard_remove.
///
/// The inode alone does not make a file one of them. A file system can
/// give two files the same device and the same inode number: a FUSE file
/// system that shows the files of two file systems with the inode numbers
/// they have there does. So each of these files is kept open with its
/// inode, and a file a walk comes to with that inode is one of them only
/// if its status is the status of the open file as well, see
/// [`OwnFiles::contains`]. A file of the tree that only has the number of
/// one of them is listed like any other. Two of these files can have one
/// inode as well. Both are kept open with it then, and a file with that
/// inode is one of them if its status is the status of either.
///
/// A scratch file is one of them from when it is made, and it stays one and
/// stays open once whoever made it is done with it. It is closed when these
/// files are dropped, which is not before whoever walks trees for the
/// manifest is, see
/// [`Scratch::own_files`](crate::scratch::Scratch::own_files). A file that
/// was closed could not be one of them: nothing is left that a file with
/// its inode could be held against. And a file system that keeps an
/// unlinked file under a name removes that name some time after the file
/// was closed, without anybody waiting for it, as FUSE and NFS do. A walk
/// that comes to the name in between would list a file of the manifest's
/// own, or fail because the file is gone when it is opened. So a scratch
/// file that is given back is only emptied, which gives its room back. It
/// takes a descriptor and nothing else until it is handed out again, which
/// it is before a new file is made, see
/// [`Scratch::file`](crate::scratch::Scratch::file).
#[derive(Debug, Default)]
pub(crate) struct OwnFiles {
    /// The files by their inodes, each of them open. An inode has every
    /// file that was kept with it, in the order they were kept: one file,
    /// and more where the file system gave its inode to another one of the
    /// files as well. No file is ever taken out of them, so each of them is
    /// open for as long as this is there.
    open: HashMap<InodeId, Vec<Arc<File>>>,
    /// The scratch files among them that were given back and emptied, and
    /// that were not handed out since.
    given_back: Vec<Arc<File>>,
}

impl OwnFiles {
    /// Takes the scratch file `file`, which has the inode `inode`, as one
    /// of the files, and keeps it open for as long as they are there. A
    /// file that was kept with that inode before stays one of them, and
    /// open, next to it.
    fn keep(&mut self, inode: InodeId, file: Arc<File>) {
        self.open.entry(inode).or_default().push(file);
    }

    /// Whether the file with the status `found`, which a walk came to, is
    /// one of the files: it has the inode of one of them, and its status
    /// is the one that file has now, see [`Status::matches`]. Where several
    /// of the files have that inode, it is held against one after the
    /// other, until its status is that of one of them. That takes one
    /// statx() of each open file it is held against: at most as many as
    /// have that inode, and none where no file has it. Where the status of
    /// one of them can't be read, this fails.
    pub(crate) fn contains(&self, found: &Status) -> Result<bool, Failure> {
        let own = self.open.get(&found.identity.inode_id());
        for file in own.into_iter().flatten() {
            if found.matches(&Status::of(file.as_fd())?) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Takes back the scratch file `file`, one of the files, which whoever
    /// had it is done with. It is emptied, which gives its room back, and
    /// it is handed out again where another one is needed. A file that
    /// cannot be emptied is kept as it is, and its room with it, until it
    /// is closed. It is never handed out again.
    pub(crate) fn take_back(&mut self, file: ScratchFile) {
        if file.set_len(0).is_ok() {
            self.given_back.push(file.file);
        }
    }

    /// A scratch file that was given back and emptied, if there is one that
    /// was not handed out since. It is one of the files as it was, with the
    /// inode it had.
    pub(crate) fn hand_out(&mut self) -> Option<ScratchFile> {
        let file = self.given_back.pop()?;
        Some(ScratchFile { file })
    }
}

/// A file without a name, which the builder keeps in what it cannot keep
/// in memory. It is read and written at the offsets the caller gives, and
/// it is gone once it is closed, also when the process dies. It is one of
/// the files of its builder, which keep it open: one that is given back to
/// them is emptied and handed out again where another one is needed, see
/// [`OwnFiles::take_back`], and one that is dropped stays as it is. Both
/// are closed with them.
#[derive(Debug)]
pub(crate) struct ScratchFile {
    /// The file, which the files of its builder have as well.
    file: Arc<File>,
}

impl ScratchFile {
    /// How a directory is opened that scratch files are made in: as a
    /// handle, for a directory and nothing else.
    const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
    /// How a file without a name is made: with O_TMPFILE, for reading and
    /// writing, and with O_EXCL, which for such a file says that it never
    /// gets a name.
    const UNNAMED_FLAGS: OFlags = OFlags::TMPFILE
        .union(OFlags::RDWR)
        .union(OFlags::EXCL)
        .union(OFlags::CLOEXEC);
    /// How a file is made that loses its name right away: only if nothing
    /// has that name, a symbolic link included.
    const NAMED_FLAGS: OFlags = OFlags::CREATE
        .union(OFlags::EXCL)
        .union(OFlags::RDWR)
        .union(OFlags::NOFOLLOW)
        .union(OFlags::CLOEXEC);
    /// Only the owner reads and writes a scratch file.
    const MODE: rustix::fs::Mode = rustix::fs::Mode::RUSR.union(rustix::fs::Mode::WUSR);
    /// The name a directory has in itself, which a file without a name is
    /// made in.
    const ITSELF: &'static CStr = c".";
    /// What the name of a file that loses its name right away starts with.
    const NAME_PREFIX: &'static str = ".uapi16-";
    /// How the room of a part of a file is given back: as a hole, which
    /// leaves the file as long as it is. fallocate() takes
    /// FALLOC_FL_PUNCH_HOLE only together with FALLOC_FL_KEEP_SIZE.
    const PUNCH_FLAGS: FallocateFlags = FallocateFlags::PUNCH_HOLE.union(FallocateFlags::KEEP_SIZE);

    /// Opens the directory `path` as one that scratch files are made in.
    pub(crate) fn open_directory(path: &Path) -> io::Result<OwnedFd> {
        Ok(retry_on_intr(|| {
            rustix::fs::open(path, ScratchFile::DIRECTORY_FLAGS, rustix::fs::Mode::empty())
        })?)
    }

    /// Makes a file without a name in the file system of the directory
    /// `dir`, which is one of the files `own`. Where the file system cannot
    /// make one, the file is made with a name that nothing has and loses it
    /// at once, as for systemd's open_tmpfile_unlinkable(): the file system
    /// says EOPNOTSUPP then, and a kernel that does not know O_TMPFILE tries
    /// to open the directory for writing and says EISDIR.
    pub(crate) fn create_in(dir: BorrowedFd<'_>, own: &mut OwnFiles) -> io::Result<ScratchFile> {
        match ScratchFile::create_unnamed(dir, own) {
            Ok(file) => Ok(file),
            Err(Errno::OPNOTSUPP | Errno::ISDIR) => ScratchFile::create_and_unlink(dir, own),
            Err(e) => Err(e.into()),
        }
    }

    /// Makes a file without a name with O_TMPFILE.
    fn create_unnamed(dir: BorrowedFd<'_>, own: &mut OwnFiles) -> rustix::io::Result<ScratchFile> {
        let file = retry_on_intr(|| {
            rustix::fs::openat(dir, ScratchFile::ITSELF, ScratchFile::UNNAMED_FLAGS, ScratchFile::MODE)
        })?;
        ScratchFile::new(file, own)
    }

    /// Makes a file with a name nobody can guess and removes the name.
    fn create_and_unlink(dir: BorrowedFd<'_>, own: &mut OwnFiles) -> io::Result<ScratchFile> {
        let (file, name) = TemporaryName::create(
            dir,
            ScratchFile::NAME_PREFIX,
            ScratchFile::NAMED_FLAGS,
            ScratchFile::MODE,
        )?;
        name.remove(dir)?;
        Ok(ScratchFile::new(file, own)?)
    }

    /// The scratch file `file`, which was just made, as one of the files
    /// `own`.
    fn new(file: OwnedFd, own: &mut OwnFiles) -> rustix::io::Result<ScratchFile> {
        let inode = InodeId::of(file.as_fd())?;
        let file = Arc::new(File::from(file));
        own.keep(inode, Arc::clone(&file));
        Ok(ScratchFile { file })
    }

    /// Makes the file `len` bytes long. What it gains reads as zeroes and
    /// takes no room until it is written.
    pub(crate) fn set_len(&self, len: u64) -> io::Result<()> {
        Ok(retry_on_intr(|| rustix::fs::ftruncate(&self.file, len))?)
    }

    /// The size of a block of the file in bytes, as statx() reports it: the
    /// block size of the file system, or several blocks where the file
    /// system does its I/O in more than one.
    pub(crate) fn block_size(&self) -> io::Result<u64> {
        let statx = retry_on_intr(|| rustix::fs::statx(&self.file, c"", Status::OF_DESCRIPTOR, StatxFlags::empty()))?;
        Ok(u64::from(statx.stx_blksize))
    }

    /// Gives the room of the `len` bytes of the file at `offset` back to
    /// the file system, as a hole: the bytes read as zeroes from then on,
    /// and the file stays as long as it is. `len` is not 0.
    ///
    /// A file system gives back whole blocks. What the range has of a
    /// block that is not all in it is only written over with zeroes, so a
    /// caller that wants room back asks for whole blocks, see
    /// [`ScratchFile::block_size`].
    ///
    /// Not every file system can punch holes. One that cannot fails with
    /// EOPNOTSUPP and leaves the file as it was.
    pub(crate) fn punch_hole(&self, offset: u64, len: u64) -> io::Result<()> {
        Ok(retry_on_intr(|| {
            rustix::fs::fallocate(&self.file, ScratchFile::PUNCH_FLAGS, offset, len)
        })?)
    }

    /// Fills `buffer` with what the file has at `offset`. A file that ends
    /// before the buffer is full fails: nothing that was written is ever
    /// that short.
    pub(crate) fn read_exact_at(&self, mut buffer: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !buffer.is_empty() {
            match rustix::io::pread(&self.file, &mut *buffer, offset) {
                Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                Ok(read) => {
                    let rest = buffer;
                    buffer = &mut rest[read..];
                    offset += read as u64;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// Writes all of `data` into the file at `offset`.
    pub(crate) fn write_all_at(&self, mut data: &[u8], mut offset: u64) -> io::Result<()> {
        while !data.is_empty() {
            match rustix::io::pwrite(&self.file, data, offset) {
                Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
                Ok(written) => {
                    data = &data[written..];
                    offset += written as u64;
                }
                Err(Errno::INTR) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }
}

/// The hash of the data of a regular file, read a part at a time, so that
/// a large file takes several steps: the file, opened again through the
/// handle of its entry, its status when the entry was opened, the hash of
/// what was read so far, and how much that was.
#[derive(Debug)]
pub(crate) struct DataHash {
    file: File,
    before: Status,
    context: Sha256Context,
    offset: u64,
}

impl DataHash {
    /// The most bytes of data a file is hashed with: 1 TiB. Hashing takes
    /// as long as the data is large, a sparse file has data of any size at
    /// no cost to whoever made it, and nothing stops a hash once an add
    /// began it.
    pub(crate) const MAX_SIZE: u64 = 1 << 40;

    /// Fails unless the data of a file with the status `status` is hashed:
    /// anything but a regular file fails with EINVAL, and a file that is
    /// larger than [`DataHash::MAX_SIZE`] with EFBIG, as for systemd's
    /// sha256_fd(). Both come from the status alone, before the file is
    /// opened or anything is read of it.
    pub(crate) fn admits(status: &Status) -> Result<(), Failure> {
        if status.file_type != FileType::RegularFile {
            return Err(Errno::INVAL.into());
        }
        if status.size > DataHash::MAX_SIZE {
            return Err(Errno::FBIG.into());
        }
        Ok(())
    }

    /// Opens the regular file of `entry` again, through its handle, for the
    /// hash of its data. A file whose data is not hashed fails and is not
    /// opened, see [`DataHash::admits`].
    pub(crate) fn start(entry: &Entry<'_>) -> Result<DataHash, Failure> {
        DataHash::admits(entry.status())?;
        DataHash::of(entry, entry.reopen(None)?)
    }

    /// The hash of the data of the regular file of `entry`, read through
    /// `opened`, which is that file opened again, see [`Entry::reopen`]. So
    /// a file that is open already, for its inode flags for example, is
    /// not opened once more for its data. A file whose data is not hashed
    /// fails, see [`DataHash::admits`].
    pub(crate) fn of(entry: &Entry<'_>, opened: Readable) -> Result<DataHash, Failure> {
        DataHash::admits(entry.status())?;
        Ok(DataHash {
            file: opened.0,
            before: *entry.status(),
            context: Sha256Context::new(),
            offset: 0,
        })
    }

    /// Reads at most `budget` more bytes of the data through `buffer`,
    /// which is not empty, and continues with what is left to read. Once
    /// the data was read up to the size the file had when its entry was
    /// opened, one byte more is read, which is not there if the data ends
    /// at that size, and the status of the file is checked against the one
    /// it had. Then it breaks with the hash. A file whose status shows a
    /// change changed while it was read. One whose data ends early or goes
    /// on after its size fails with [`Failure::WrongSize`] where its status
    /// shows none.
    pub(crate) fn read(mut self, buffer: &mut [u8], budget: u64) -> Result<ControlFlow<Sha256, DataHash>, Failure> {
        debug_assert!(!buffer.is_empty());
        let mut left = budget;
        let end = loop {
            let rest = self.before.size - self.offset;
            let want = if rest == 0 {
                1
            } else if left == 0 {
                return Ok(ControlFlow::Continue(self));
            } else {
                usize::try_from(rest.min(left)).map_or(buffer.len(), |most| most.min(buffer.len()))
            };
            let read = match rustix::io::pread(&self.file, &mut buffer[..want], self.offset) {
                Ok(read) => read,
                Err(Errno::INTR) => continue,
                Err(e) => break Err(DataFailure::Io(e.into())),
            };
            match (read, rest) {
                (0, 0) => break Ok(()),
                (0, _) => break Err(DataFailure::EndedEarly),
                (_, 0) => break Err(DataFailure::WentOn),
                _ => {}
            }
            self.context.update(&buffer[..read]);
            self.offset += read as u64;
            left -= read as u64;
        };
        let DataHash {
            file, before, context, ..
        } = self;
        let read = end.map(|()| context.finalize());
        before
            .check_read(read, Status::of(file.as_fd()))
            .map(ControlFlow::Break)
    }
}

impl From<StatxTimestamp> for Timestamp {
    fn from(time: StatxTimestamp) -> Timestamp {
        Timestamp {
            seconds: time.tv_sec,
            nanoseconds: time.tv_nsec,
        }
    }
}

impl From<Errno> for Failure {
    fn from(errno: Errno) -> Failure {
        Failure::Io(errno.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{OpenFile, TempDir, ST_BLOCKS_UNIT};
    use rustix::fs::{inotify, MemfdFlags, SealFlags, CWD};
    use rustix::io::FdFlags;
    use std::fmt;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::mem::MaybeUninit;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    /// Opens the directory `path` as a handle, the way an entry is opened.
    fn open_dir(path: &Path) -> OwnedFd {
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).unwrap()
    }

    /// Makes a FIFO at `path`.
    fn make_fifo(path: &Path) {
        let mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
        rustix::fs::mknodat(CWD, path, FileType::Fifo, mode, 0).unwrap();
    }

    /// The errno of `result`, which failed in a system call.
    fn errno<T: fmt::Debug>(result: Result<T, Failure>) -> i32 {
        match result {
            Err(Failure::Io(e)) => e.raw_os_error().unwrap(),
            other => panic!("{:?}", other),
        }
    }

    /// The device number `dev` of std, split as statx() splits it.
    fn device_number(dev: u64) -> (u32, u32) {
        (rustix::fs::major(dev), rustix::fs::minor(dev))
    }

    /// The time `time`, which is after the epoch, as statx() gives it.
    fn timestamp(time: SystemTime) -> (i64, u32) {
        let since = time.duration_since(UNIX_EPOCH).unwrap();
        (i64::try_from(since.as_secs()).unwrap(), since.subsec_nanos())
    }

    /// The mount ID that /proc/self/fdinfo gives for the file `fd` refers
    /// to, the one of /proc/self/mountinfo.
    fn mountinfo_id(fd: BorrowedFd<'_>) -> u64 {
        let info = fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).unwrap();
        let id = info.lines().find_map(|line| line.strip_prefix("mnt_id:")).unwrap();
        id.trim().parse().unwrap()
    }

    /// The mount of the file `fd` refers to, by the mount ID of
    /// /proc/self/mountinfo: what a kernel without unique mount IDs gives.
    fn reusable_mount(fd: BorrowedFd<'_>) -> MountId {
        let request = Status::REQUEST.difference(Status::MNT_ID_UNIQUE);
        let statx = rustix::fs::statx(fd, c"", Status::OF_DESCRIPTOR, request).unwrap();
        Status::from_statx(&statx).unwrap().identity.mount
    }

    /// The hash of the data of `entry`, read `budget` bytes at a time, and
    /// how many steps that took.
    fn hash_in_steps(entry: &Entry<'_>, buffer: &mut [u8], budget: u64) -> Result<(Sha256, u64), Failure> {
        let mut hash = DataHash::start(entry)?;
        let mut steps = 1;
        loop {
            match hash.read(buffer, budget)? {
                ControlFlow::Break(found) => return Ok((found, steps)),
                ControlFlow::Continue(more) => hash = more,
            }
            steps += 1;
        }
    }

    /// The hash of the data of `entry`, all of it read in one step.
    fn hash(entry: &Entry<'_>, buffer: &mut [u8]) -> Result<Sha256, Failure> {
        hash_in_steps(entry, buffer, u64::MAX).map(|(hash, _)| hash)
    }

    /// How long a test waits for the clock of a file system to move: more
    /// than the two seconds a time of FAT stands still.
    const CLOCK_WAIT: Duration = Duration::from_secs(3);

    /// How far back the probe for the change time sets a modification
    /// time: farther than any clock stands still.
    const SET_BACK: Duration = Duration::from_secs(3600);

    /// Waits until a change of a file in `dir` gets a later change time
    /// than `time`, for [`CLOCK_WAIT`] at most. A coarse clock gives all
    /// changes in a tick the same time, and a tick of FAT is two seconds.
    /// Multigrain timestamps, since Linux 6.13, give the first change
    /// after a statx() a time of its own anyway.
    fn wait_for_clock(dir: &Path, time: Timestamp) {
        let probe = dir.join("clock");
        let then = (time.seconds, i64::from(time.nanoseconds));
        let started = Instant::now();
        loop {
            // The time is taken before the clock is asked, so that the last
            // look comes after the whole wait, however late it comes.
            let waited = started.elapsed();
            fs::write(&probe, b"").unwrap();
            let meta = fs::symlink_metadata(&probe).unwrap();
            fs::remove_file(&probe).unwrap();
            if (meta.ctime(), meta.ctime_nsec()) > then {
                return;
            }
            assert!(waited < CLOCK_WAIT, "the clock of {:?} does not move", dir);
            thread::sleep(Duration::from_millis(1));
        }
    }

    /// Whether the change time of a file in `dir` moves with its
    /// modification time, as on FAT, which keeps one time for the two: a
    /// modification time that is set back takes the change time back with
    /// it there, and nothing tells that it was set.
    fn change_time_follows(dir: &Path) -> bool {
        let probe = dir.join("times");
        fs::write(&probe, b"").unwrap();
        let before = fs::symlink_metadata(&probe).unwrap();
        let back = before.modified().unwrap() - SET_BACK;
        File::options()
            .write(true)
            .open(&probe)
            .unwrap()
            .set_modified(back)
            .unwrap();
        let after = fs::symlink_metadata(&probe).unwrap();
        fs::remove_file(&probe).unwrap();
        (after.ctime(), after.ctime_nsec()) < (before.ctime(), before.ctime_nsec())
    }

    /// The opens of a file that inotify sees. A handle opened with O_PATH is
    /// not an open for inotify.
    struct Opens(OwnedFd);

    impl Opens {
        /// Watches the file `path`.
        fn of(path: &Path) -> Opens {
            let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).unwrap();
            inotify::add_watch(&inotify, path, inotify::WatchFlags::OPEN).unwrap();
            Opens(inotify)
        }

        /// Whether the file was opened since the last look.
        fn seen(&self) -> bool {
            let mut buffer = [MaybeUninit::uninit(); 4096];
            let mut events = inotify::Reader::new(&self.0, &mut buffer);
            let mut opened = false;
            loop {
                match events.next() {
                    Ok(event) => opened |= event.events().contains(inotify::ReadFlags::OPEN),
                    Err(Errno::AGAIN) => return opened,
                    Err(e) => panic!("{}", e),
                }
            }
        }
    }

    /// Checks that `status` says what lstat() says of `path`, in `meta`.
    fn check_status(status: &Status, meta: &fs::Metadata, path: &Path) {
        let identity = &status.identity;
        let device = (identity.device.major, identity.device.minor);
        assert_eq!(
            (device, identity.inode),
            (device_number(meta.dev()), meta.ino()),
            "{:?}",
            path
        );
        assert_eq!(status.file_type, FileType::from_raw_mode(meta.mode()), "{:?}", path);
        assert_eq!(status.mode, Mode::from_st_mode(meta.mode()), "{:?}", path);
        assert_eq!(u64::from(status.nlink), meta.nlink(), "{:?}", path);
        assert_eq!(
            (status.uid, status.gid, status.size),
            (meta.uid(), meta.gid(), meta.size()),
            "{:?}",
            path
        );
        let nanoseconds = |nsec: i64| u32::try_from(nsec).unwrap();
        let mtime = (status.mtime.seconds, status.mtime.nanoseconds);
        assert_eq!(mtime, (meta.mtime(), nanoseconds(meta.mtime_nsec())), "{:?}", path);
        let ctime = (status.ctime.seconds, status.ctime.nanoseconds);
        assert_eq!(ctime, (meta.ctime(), nanoseconds(meta.ctime_nsec())), "{:?}", path);
        assert_eq!(
            (status.rdev.major, status.rdev.minor),
            device_number(meta.rdev()),
            "{:?}",
            path
        );
        // std reads the birth time with statx() where it uses statx(),
        // which it does not on musl.
        if let Ok(created) = meta.created() {
            let btime = status.btime.map(|btime| (btime.seconds, btime.nanoseconds));
            assert_eq!(btime, Some(timestamp(created)), "{:?}", path);
        }
    }

    /// The status of an entry of every type a test can make, and of a
    /// device node every system has, is what lstat() says of it. The
    /// entries of a directory are on its mount, and two names of a file
    /// are the same file.
    #[test]
    fn statuses_are_what_lstat_says() {
        let tmp = TempDir::new("sys-status");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"hello").unwrap();
        fs::hard_link(dir.join("file"), dir.join("link")).unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        symlink("target", dir.join("symlink")).unwrap();
        make_fifo(&dir.join("fifo"));
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        let tree = open_dir(dir);
        let mount = Status::of(tree.as_fd()).unwrap().identity.mount;
        let names = [c"file", c"link", c"dir", c"symlink", c"fifo", c"socket"];
        let entries: Vec<Entry<'_>> = names
            .iter()
            .map(|name| Entry::open_at(tree.as_fd(), name).unwrap())
            .collect();
        for (name, entry) in names.iter().zip(&entries) {
            let path = dir.join(name.to_str().unwrap());
            check_status(entry.status(), &fs::symlink_metadata(&path).unwrap(), &path);
            assert_eq!(entry.status().identity.mount, mount, "{:?}", path);
        }
        assert_eq!(entries[0].status().nlink, 2);
        assert_eq!(entries[0].status().identity, entries[1].status().identity);
        let dev = open_dir(Path::new("/dev"));
        let null = Entry::open_at(dev.as_fd(), c"null").unwrap();
        let path = PathBuf::from("/dev/null");
        check_status(null.status(), &fs::symlink_metadata(&path).unwrap(), &path);
        assert_eq!(null.status().file_type, FileType::CharacterDevice);
    }

    /// Runs `check` with handles that open_tree() takes, and once more with
    /// handles that openat() takes, as in a process that open_tree() was
    /// refused in.
    fn with_both_handles(check: impl Fn()) {
        check();
        OPEN_TREE.store(OpenTree::REFUSED, Ordering::Relaxed);
        check();
        OPEN_TREE.store(OpenTree::CALLED, Ordering::Relaxed);
    }

    /// A file system that does not have an ioctl has no answer to it. It
    /// says so with ENOTTY as a rule, and EOPNOTSUPP, ENOSYS and EINVAL are
    /// taken for the same. Any other error of an ioctl is an error.
    #[test]
    fn ioctls_a_file_system_does_not_have() {
        for errno in [Errno::NOTTY, Errno::OPNOTSUPP, Errno::NOSYS, Errno::INVAL] {
            assert_eq!(Readable::answer(|| Err::<u8, _>(errno)).unwrap(), None, "{}", errno);
        }
        for errno in [Errno::IO, Errno::ACCESS, Errno::PERM, Errno::NOENT, Errno::BADF] {
            let e = Readable::answer(|| Err::<u8, _>(errno)).unwrap_err();
            assert_eq!(e.raw_os_error(), Some(errno.raw_os_error()));
        }
        assert_eq!(Readable::answer(|| Ok(7)).unwrap(), Some(7));
    }

    /// An entry is a handle, which is not inherited across exec and opens
    /// nothing behind it: a symbolic link is the link, and a FIFO is not
    /// waited for. Entries below a directory are opened in its handle. A
    /// file open for reading has the status of its entry. A handle that
    /// openat() takes, where open_tree() was refused, is the same.
    #[test]
    fn entries_are_handles() {
        let tmp = TempDir::new("sys-handles");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("a/b")).unwrap();
        fs::write(dir.join("a/b/file"), b"deep").unwrap();
        symlink("a", dir.join("link")).unwrap();
        make_fifo(&dir.join("fifo"));
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        let tree = open_dir(dir);
        with_both_handles(|| {
            for name in [c"a", c"link", c"fifo", c"socket"] {
                let entry = Entry::open_at(tree.as_fd(), name).unwrap();
                assert!(rustix::fs::fcntl_getfl(entry.handle()).unwrap().contains(OFlags::PATH));
                assert!(rustix::io::fcntl_getfd(entry.handle())
                    .unwrap()
                    .contains(FdFlags::CLOEXEC));
            }
            let link = Entry::open_at(tree.as_fd(), c"link").unwrap();
            assert_eq!(link.status().file_type, FileType::Symlink);
            assert_eq!(errno(Entry::open_at(link.handle(), c"b")), libc::ENOTDIR);
            assert_eq!(errno(Entry::open_at(tree.as_fd(), c"missing")), libc::ENOENT);
            let a = Entry::open_at(tree.as_fd(), c"a").unwrap();
            let b = Entry::open_at(a.handle(), c"b").unwrap();
            let file = Entry::open_at(b.handle(), c"file").unwrap();
            assert_eq!(
                (file.status().file_type, file.status().size),
                (FileType::RegularFile, 4)
            );
            let opened = File::open(dir.join("a/b/file")).unwrap();
            assert_eq!(Status::of(opened.as_fd()).unwrap().identity, file.status().identity);
        });
    }

    /// A descriptor of a caller is the entry of its file, a handle or the
    /// file open for reading. The entry borrows the descriptor: it reads
    /// through that one and takes none of its own, and the descriptor is
    /// open after the entry is gone.
    #[test]
    fn entries_of_descriptors() {
        let tmp = TempDir::new("sys-descriptors");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"data").unwrap();
        let tree = open_dir(dir);
        let handle = Entry::open_at(tree.as_fd(), c"file").unwrap();
        for fd in [
            OwnedFd::from(File::open(dir.join("file")).unwrap()),
            handle.handle().try_clone_to_owned().unwrap(),
        ] {
            let entry = Entry::of(fd.as_fd()).unwrap();
            assert_eq!(entry.handle().as_raw_fd(), fd.as_raw_fd());
            assert_eq!(entry.status().identity, handle.status().identity);
            assert!(!entry.status().changed_since(handle.status()));
            drop(entry);
            assert_eq!(Status::of(fd.as_fd()).unwrap().identity, handle.status().identity);
        }
    }

    /// A status has the unique mount ID where the kernel gives one when
    /// asked, and the one of /proc/self/mountinfo where it does not. A
    /// kernel gives one of the two. Without either there is no status.
    #[test]
    fn mount_ids() {
        let tmp = TempDir::new("sys-mount-ids");
        let tree = open_dir(&tmp.0);
        let statx = rustix::fs::statx(tree.as_fd(), c"", Status::OF_DESCRIPTOR, Status::REQUEST).unwrap();
        let mask = StatxFlags::from_bits_retain(statx.stx_mask);
        let unique = mask.contains(Status::MNT_ID_UNIQUE);
        assert_ne!(unique, mask.contains(StatxFlags::MNT_ID));
        let expected = if unique {
            MountId::Unique(statx.stx_mnt_id)
        } else {
            MountId::Reusable(statx.stx_mnt_id)
        };
        assert_eq!(Status::from_statx(&statx).unwrap().identity.mount, expected);
        assert_eq!(
            reusable_mount(tree.as_fd()),
            MountId::Reusable(mountinfo_id(tree.as_fd()))
        );
        let mut statx = statx;
        statx.stx_mask &= !(StatxFlags::MNT_ID | Status::MNT_ID_UNIQUE).bits();
        let failure = Status::from_statx(&statx).unwrap_err();
        assert!(matches!(failure, Failure::NoMountId), "{:?}", failure);
    }

    /// The subvolume and the birth time are there where the mask of
    /// statx() has them, and only there.
    #[test]
    fn what_the_mask_has() {
        let tmp = TempDir::new("sys-mask");
        let tree = open_dir(&tmp.0);
        let statx = rustix::fs::statx(tree.as_fd(), c"", Status::OF_DESCRIPTOR, Status::REQUEST).unwrap();
        let optional = Status::SUBVOL | StatxFlags::BTIME;
        let mut with = statx;
        with.stx_mask |= optional.bits();
        with.stx_subvol = 7;
        let status = Status::from_statx(&with).unwrap();
        assert_eq!(status.identity.subvolume, Some(7));
        assert_eq!(status.btime, Some(Timestamp::from(with.stx_btime)));
        let mut without = statx;
        without.stx_mask &= !optional.bits();
        let status = Status::from_statx(&without).unwrap();
        assert_eq!((status.identity.subvolume, status.btime), (None, None));
    }

    /// The variable that tells the test binary, run again inside the
    /// namespaces of [`bind_mounts_are_mounts_of_their_own`], where the
    /// directory with the bind mount is.
    const BIND_MOUNT_DIR: &str = "UAPI16_TEST_BIND_MOUNT_DIR";

    /// A bind mount is a mount of its own, by the unique mount IDs and by
    /// those of /proc/self/mountinfo, and a file reached through it is not
    /// the file reached through its source. The bind mount needs a user and
    /// a mount namespace, which unshare(1) makes, and the test binary runs
    /// this test again inside them.
    #[test]
    fn bind_mounts_are_mounts_of_their_own() {
        if let Some(dir) = std::env::var_os(BIND_MOUNT_DIR) {
            return check_bind_mount(Path::new(&dir));
        }
        let tmp = TempDir::new("sys-bind-mount");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("source/below")).unwrap();
        fs::create_dir(dir.join("mount")).unwrap();
        fs::write(dir.join("source/below/file"), b"bound").unwrap();
        // Where unshare(1) cannot make the namespaces, there is nothing to
        // run the test in.
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        let script = concat!(
            r#"mount --bind "$1/source" "$1/mount" && "#,
            r#"exec "$2" --exact sys::tests::bind_mounts_are_mounts_of_their_own"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(BIND_MOUNT_DIR, dir)
            .output()
            .unwrap();
        assert!(output.status.success(), "{:?}", output);
    }

    /// The checks of [`bind_mounts_are_mounts_of_their_own`] in `dir`, in
    /// which `mount` is a bind mount of `source`.
    fn check_bind_mount(dir: &Path) {
        let top = open_dir(dir);
        let top_mount = Status::of(top.as_fd()).unwrap().identity.mount;
        let source = Entry::open_at(top.as_fd(), c"source").unwrap();
        let mount = Entry::open_at(top.as_fd(), c"mount").unwrap();
        assert_eq!(source.status().identity.mount, top_mount);
        assert_ne!(mount.status().identity.mount, top_mount);
        let (through_source, through_mount) = (source.status().identity, mount.status().identity);
        assert_eq!(
            (through_source.device, through_source.inode),
            (through_mount.device, through_mount.inode)
        );
        // What is below the bind mount is in it.
        let below = Entry::open_at(mount.handle(), c"below").unwrap();
        let file = Entry::open_at(below.handle(), c"file").unwrap();
        assert_eq!(file.status().identity.mount, mount.status().identity.mount);
        let source_below = Entry::open_at(source.handle(), c"below").unwrap();
        let source_file = Entry::open_at(source_below.handle(), c"file").unwrap();
        assert_eq!(source_file.status().identity.mount, top_mount);
        assert_ne!(file.status().identity, source_file.status().identity);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        assert_eq!(hash(&file, &mut buffer).unwrap(), Sha256::digest(b"bound"));
        // The mount IDs of /proc/self/mountinfo tell the mounts apart too.
        for fd in [top.as_fd(), mount.handle()] {
            assert_eq!(reusable_mount(fd), MountId::Reusable(mountinfo_id(fd)));
        }
        assert_ne!(reusable_mount(top.as_fd()), reusable_mount(mount.handle()));
    }

    /// The hash of a regular file is that of its data, read through a
    /// buffer of any size and in steps of any budget: no data, less than
    /// the buffer, and the data of several buffers and of a part of one at
    /// the end. A file takes a step for every budget of its data, and the
    /// last one also checks that the data ends there. A budget of nothing
    /// reads nothing.
    #[test]
    fn hashes_the_data() {
        let tmp = TempDir::new("sys-hash");
        let dir = &tmp.0;
        let long: Vec<u8> = (0..2 * DATA_BUFFER_SIZE + 3).map(|i| (i % 251) as u8).collect();
        let whole = u64::try_from(DATA_BUFFER_SIZE).unwrap();
        /// A file the test hashes: its name, its data, the sizes of the
        /// buffers it is read through and the budgets of its steps.
        struct Sample<'a> {
            name: &'a CStr,
            data: &'a [u8],
            buffers: [usize; 3],
            budgets: [u64; 4],
        }
        let files = [
            Sample {
                name: c"empty",
                data: b"",
                buffers: [1, 7, DATA_BUFFER_SIZE],
                budgets: [1, 7, 4096, u64::MAX],
            },
            Sample {
                name: c"short",
                data: b"hello",
                buffers: [1, 7, DATA_BUFFER_SIZE],
                budgets: [1, 2, 7, u64::MAX],
            },
            Sample {
                name: c"long",
                data: &long,
                buffers: [4096, DATA_BUFFER_SIZE - 1, DATA_BUFFER_SIZE],
                budgets: [4096, whole - 1, whole, u64::MAX],
            },
        ];
        for file in &files {
            fs::write(dir.join(file.name.to_str().unwrap()), file.data).unwrap();
        }
        let tree = open_dir(dir);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        for file in &files {
            let entry = Entry::open_at(tree.as_fd(), file.name).unwrap();
            let expected = Sha256::digest(file.data);
            for size in file.buffers {
                let mut buffer = vec![0; size];
                assert_eq!(hash(&entry, &mut buffer).unwrap(), expected, "{:?} {}", file.name, size);
            }
            let len = u64::try_from(file.data.len()).unwrap();
            for budget in file.budgets {
                let found = hash_in_steps(&entry, &mut buffer, budget).unwrap();
                let steps = len.div_ceil(budget).max(1);
                assert_eq!(found, (expected, steps), "{:?} {}", file.name, budget);
            }
            match DataHash::start(&entry).unwrap().read(&mut buffer, 0).unwrap() {
                ControlFlow::Continue(more) => {
                    assert!(len > 0, "{:?}", file.name);
                    let found = more.read(&mut buffer, u64::MAX).unwrap();
                    assert!(matches!(found, ControlFlow::Break(found) if found == expected));
                }
                ControlFlow::Break(found) => assert_eq!((len, found), (0, expected)),
            }
        }
    }

    /// A file that grows or shrinks after it was opened, or whose data is
    /// written over with the same size, changed while it was read. So did
    /// one whose modification time is set back after that: its change time
    /// tells. That one is skipped where the change time moves with the
    /// modification time, as on FAT.
    #[test]
    fn changes_while_read() {
        let tmp = TempDir::new("sys-changes");
        let dir = &tmp.0;
        let path = dir.join("file");
        let tree = open_dir(dir);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        let long: Vec<u8> = (0..2 * DATA_BUFFER_SIZE + 3).map(|i| (i % 251) as u8).collect();
        let follows = change_time_follows(dir);
        if follows {
            eprintln!(
                "skipping a modification time that is set back: the change time of a file in the temporary directory moves with it"
            );
        }
        for data in [b"hello world".to_vec(), long] {
            let other: Vec<u8> = data.iter().map(|b| b ^ 1).collect();
            for what in ["grow", "shrink", "write over", "set back"] {
                if what == "set back" && follows {
                    continue;
                }
                fs::write(&path, &data).unwrap();
                let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
                let before = *entry.status();
                wait_for_clock(dir, before.ctime);
                let open = || File::options().write(true).open(&path).unwrap();
                match what {
                    "grow" => OpenOptions::new()
                        .append(true)
                        .open(&path)
                        .unwrap()
                        .write_all(b"!")
                        .unwrap(),
                    "shrink" => open().set_len(before.size / 2).unwrap(),
                    "write over" => open().write_all(&other).unwrap(),
                    _ => {
                        open().write_all(&other).unwrap();
                        let seconds = u64::try_from(before.mtime.seconds).unwrap();
                        let mtime = UNIX_EPOCH + Duration::new(seconds, before.mtime.nanoseconds);
                        open().set_modified(mtime).unwrap();
                        // Only the change time is different.
                        let now = Status::of(entry.handle()).unwrap();
                        assert_eq!((now.size, now.mtime), (before.size, before.mtime));
                        assert_ne!(now.ctime, before.ctime);
                    }
                }
                let read = hash(&entry, &mut buffer);
                assert!(
                    matches!(read, Err(Failure::Changed)),
                    "{} {}: {:?}",
                    what,
                    data.len(),
                    read
                );
            }
            // Left alone, the same file reads as it is.
            fs::write(&path, &data).unwrap();
            let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
            assert_eq!(hash(&entry, &mut buffer).unwrap(), Sha256::digest(&data));
        }
    }

    /// A file that changes between two steps of its hash changed while it
    /// was read, also where the change is in data that was read already.
    #[test]
    fn changes_between_steps() {
        let tmp = TempDir::new("sys-steps");
        let dir = &tmp.0;
        let path = dir.join("file");
        let tree = open_dir(dir);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        let budget = 4096;
        let long: Vec<u8> = (0..2 * DATA_BUFFER_SIZE + 3).map(|i| (i % 251) as u8).collect();
        for what in ["grow", "write over the start"] {
            fs::write(&path, &long).unwrap();
            let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
            let Ok(ControlFlow::Continue(mut hash)) = DataHash::start(&entry).unwrap().read(&mut buffer, budget) else {
                panic!("{}: the first step read all of it", what);
            };
            wait_for_clock(dir, entry.status().ctime);
            let mut file = File::options().write(true).open(&path).unwrap();
            match what {
                "grow" => OpenOptions::new()
                    .append(true)
                    .open(&path)
                    .unwrap()
                    .write_all(b"!")
                    .unwrap(),
                _ => file.write_all(&[!long[0]]).unwrap(),
            }
            let read = loop {
                match hash.read(&mut buffer, budget) {
                    Ok(ControlFlow::Continue(more)) => hash = more,
                    other => break other,
                }
            };
            assert!(matches!(read, Err(Failure::Changed)), "{}: {:?}", what, read);
        }
    }

    /// A file changed while it was read if its name leads to another file:
    /// one with the same data, a symbolic link, a FIFO, a directory, or
    /// nothing. The data is read through the handle of the file, which lost
    /// its name, and that changed the file.
    #[test]
    fn replaced_while_read() {
        let tmp = TempDir::new("sys-replaced");
        let dir = &tmp.0;
        let path = dir.join("file");
        let tree = open_dir(dir);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        type Replace = fn(&Path);
        let replacements: [(&str, Replace); 5] = [
            ("twin", |path| {
                let twin = path.with_file_name("twin");
                fs::write(&twin, b"hello").unwrap();
                fs::rename(twin, path).unwrap();
            }),
            ("symlink", |path| {
                fs::remove_file(path).unwrap();
                symlink("elsewhere", path).unwrap();
            }),
            ("fifo", |path| {
                fs::remove_file(path).unwrap();
                make_fifo(path);
            }),
            ("directory", |path| {
                fs::remove_file(path).unwrap();
                fs::create_dir(path).unwrap();
            }),
            ("nothing", |path| fs::remove_file(path).unwrap()),
        ];
        for (what, replace) in replacements {
            if path.is_dir() {
                fs::remove_dir(&path).unwrap();
            } else if fs::symlink_metadata(&path).is_ok() {
                fs::remove_file(&path).unwrap();
            }
            fs::write(&path, b"hello").unwrap();
            let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
            wait_for_clock(dir, entry.status().ctime);
            replace(&path);
            let read = hash(&entry, &mut buffer);
            assert!(matches!(read, Err(Failure::Changed)), "{}: {:?}", what, read);
        }
    }

    /// Nothing but the pinned file is opened for its data: a FIFO that takes
    /// its name is never opened, whichever way the file is opened again.
    /// Nor is anything that is not a regular file opened for data when its
    /// entry is one, which fails with EINVAL: a FIFO, a directory, a
    /// symbolic link and a device node.
    #[test]
    fn opens_nothing_but_the_pinned_file() {
        let tmp = TempDir::new("sys-fifo");
        let dir = &tmp.0;
        let path = dir.join("file");
        let tree = open_dir(dir);
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        for state in [EmptyPath::UNKNOWN, EmptyPath::MISSING] {
            EMPTYPATH.store(state, Ordering::Relaxed);
            fs::write(&path, b"hello").unwrap();
            let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
            wait_for_clock(dir, entry.status().ctime);
            make_fifo(&dir.join("fifo"));
            fs::rename(dir.join("fifo"), &path).unwrap();
            let opens = Opens::of(&path);
            let read = hash(&entry, &mut buffer);
            assert!(matches!(read, Err(Failure::Changed)), "{:?}", read);
            let fifo = Entry::open_at(tree.as_fd(), c"file").unwrap();
            assert_eq!(errno(DataHash::start(&fifo)), libc::EINVAL);
            assert!(!opens.seen());
            // An open of the FIFO does show up.
            let flags = OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC;
            drop(rustix::fs::open(&path, flags, rustix::fs::Mode::empty()).unwrap());
            assert!(opens.seen());
            fs::remove_file(&path).unwrap();
        }
        EMPTYPATH.store(EmptyPath::UNKNOWN, Ordering::Relaxed);
        fs::create_dir(dir.join("dir")).unwrap();
        symlink("dir", dir.join("link")).unwrap();
        let dev = open_dir(Path::new("/dev"));
        let opens = Opens::of(&dir.join("dir"));
        for (parent, name) in [(tree.as_fd(), c"dir"), (tree.as_fd(), c"link"), (dev.as_fd(), c"null")] {
            let entry = Entry::open_at(parent, name).unwrap();
            assert_eq!(errno(DataHash::start(&entry)), libc::EINVAL, "{:?}", name);
        }
        // The directory, which could be opened, was not opened either.
        assert!(!opens.seen());
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        drop(rustix::fs::open(dir.join("dir"), flags, rustix::fs::Mode::empty()).unwrap());
        assert!(opens.seen());
    }

    /// A pinned file is opened again every way there is: through
    /// O_EMPTYPATH where the kernel has it, and through the procfs of
    /// pathrs. Each gives the pinned file, after another file took its name
    /// and after it lost its last name.
    #[test]
    fn reopens_the_pinned_file() {
        let tmp = TempDir::new("sys-reopen");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"pinned").unwrap();
        let tree = open_dir(dir);
        let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
        let pinned = PinnedFile::new(entry.handle());
        let read = |mut file: File| {
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            text
        };
        fs::rename(dir.join("file"), dir.join("moved")).unwrap();
        fs::write(dir.join("file"), b"impostor").unwrap();
        for unlinked in [false, true] {
            if unlinked {
                fs::remove_file(dir.join("moved")).unwrap();
            }
            match pinned.reopen_empty_path() {
                Ok(file) => assert_eq!(read(file), "pinned"),
                Err(Errno::NOENT) => eprintln!("skipping O_EMPTYPATH, which the kernel does not have"),
                Err(e) => panic!("{}", e),
            }
            assert_eq!(read(pinned.reopen_procfs().unwrap()), "pinned");
            assert_eq!(read(pinned.reopen().unwrap()), "pinned");
        }
    }

    /// The link of a descriptor in procfs leads to its file, also after the
    /// file lost its name, which is checked before its path is used: a link
    /// that leads to another file fails.
    #[test]
    fn links_of_descriptors() {
        let tmp = TempDir::new("sys-fd-link");
        let dir = &tmp.0;
        fs::write(dir.join("a"), b"a").unwrap();
        fs::write(dir.join("b"), b"b").unwrap();
        let a = File::open(dir.join("a")).unwrap();
        let b = File::open(dir.join("b")).unwrap();
        fs::remove_file(dir.join("a")).unwrap();
        let link = FdLink::new(a.as_fd());
        link.check().unwrap();
        assert_eq!(fs::read(link.path()).unwrap(), b"a");
        let elsewhere = FdLink {
            fd: a.as_fd(),
            path: FdLink::new(b.as_fd()).path,
        };
        let e = elsewhere.check().unwrap_err();
        assert_eq!(e.to_string(), "the link of /proc/thread-self/fd leads to another file");
    }

    /// A regular file and a directory are opened for reading as the files
    /// of their entries: a regular file through its handle, also once
    /// another file has its name, and a directory by its name, which is a
    /// change once the name leads to another file or to none. A directory
    /// that may be read but not searched is opened by its name as well, and
    /// one without a name, of a descriptor a caller gave, through its
    /// handle. What is opened is not a handle, and it is not inherited
    /// across exec. Nothing else is opened: a symbolic link, a FIFO, a
    /// socket and a device node fail with EINVAL, and nobody opened the
    /// FIFO.
    #[test]
    fn reopens_files_and_directories() {
        let tmp = TempDir::new("sys-reopen-entries");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"pinned").unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        fs::write(dir.join("dir/inside"), b"").unwrap();
        fs::create_dir(dir.join("unsearchable")).unwrap();
        fs::set_permissions(dir.join("unsearchable"), fs::Permissions::from_mode(0o400)).unwrap();
        symlink("file", dir.join("link")).unwrap();
        make_fifo(&dir.join("fifo"));
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        let tree = open_dir(dir);
        let at = |name| {
            Some(Place {
                dir: tree.as_fd(),
                name,
            })
        };
        let file = Entry::open_at(tree.as_fd(), c"file").unwrap();
        let directory = Entry::open_at(tree.as_fd(), c"dir").unwrap();
        let unsearchable = Entry::open_at(tree.as_fd(), c"unsearchable").unwrap();
        fs::rename(dir.join("file"), dir.join("moved")).unwrap();
        fs::write(dir.join("file"), b"impostor").unwrap();
        fs::rename(dir.join("dir"), dir.join("moved-dir")).unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        let check_flags = |opened: &Readable| {
            assert!(!rustix::fs::fcntl_getfl(opened.as_fd()).unwrap().contains(OFlags::PATH));
            assert!(rustix::io::fcntl_getfd(opened.as_fd())
                .unwrap()
                .contains(FdFlags::CLOEXEC));
        };
        // The entries of a directory that is open, listed through it.
        let listed = |opened: &Readable| {
            rustix::fs::Dir::read_from(opened.as_fd())
                .unwrap()
                .map(|entry| entry.unwrap().file_name().to_owned())
                .filter(|name| !matches!(name.to_bytes(), b"." | b".."))
                .collect::<Vec<_>>()
        };
        for state in [EmptyPath::UNKNOWN, EmptyPath::MISSING] {
            EMPTYPATH.store(state, Ordering::Relaxed);
            for place in [None, at(c"file")] {
                let opened = file.reopen(place).unwrap();
                check_flags(&opened);
                let mut data = [0; 16];
                let read = rustix::io::pread(opened.as_fd(), &mut data, 0).unwrap();
                assert_eq!(&data[..read], b"pinned");
            }
            let opened = directory.reopen(None).unwrap();
            check_flags(&opened);
            assert_eq!(listed(&opened), [c"inside".to_owned()]);
            check_flags(&unsearchable.reopen(None).unwrap());
        }
        EMPTYPATH.store(EmptyPath::UNKNOWN, Ordering::Relaxed);
        let opened = directory.reopen(at(c"moved-dir")).unwrap();
        check_flags(&opened);
        assert_eq!(listed(&opened), [c"inside".to_owned()]);
        check_flags(&unsearchable.reopen(at(c"unsearchable")).unwrap());
        // Another directory, a regular file, a symbolic link to the
        // directory, and nothing.
        symlink("moved-dir", dir.join("dir-link")).unwrap();
        for name in [c"dir", c"file", c"dir-link", c"gone"] {
            let reopened = directory.reopen(at(name));
            assert!(matches!(reopened, Err(Failure::Changed)), "{:?}: {:?}", name, reopened);
        }
        let opens = Opens::of(&dir.join("fifo"));
        for name in [c"link", c"fifo", c"socket"] {
            let entry = Entry::open_at(tree.as_fd(), name).unwrap();
            for place in [None, at(name)] {
                assert_eq!(errno(entry.reopen(place)), libc::EINVAL, "{:?}", name);
            }
        }
        assert!(!opens.seen());
        let dev = open_dir(Path::new("/dev"));
        let null = Entry::open_at(dev.as_fd(), c"null").unwrap();
        let place = Place {
            dir: dev.as_fd(),
            name: c"null",
        };
        assert_eq!(errno(null.reopen(Some(place))), libc::EINVAL);
    }

    /// The data of a file that is open already is hashed through that
    /// descriptor, with the same checks as otherwise. A directory that is
    /// open has no data to hash.
    #[test]
    fn hashes_through_an_open_file() {
        let tmp = TempDir::new("sys-hash-open");
        let dir = &tmp.0;
        let data: Vec<u8> = (0..DATA_BUFFER_SIZE + 5).map(|i| (i % 249) as u8).collect();
        fs::write(dir.join("file"), &data).unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        let tree = open_dir(dir);
        let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        let mut hash = DataHash::of(&entry, entry.reopen(None).unwrap()).unwrap();
        let found = loop {
            match hash.read(&mut buffer, 4096).unwrap() {
                ControlFlow::Break(found) => break found,
                ControlFlow::Continue(more) => hash = more,
            }
        };
        assert_eq!(found, Sha256::digest(&data));
        // A file that changes after it was opened again changed while it
        // was read.
        let hash = DataHash::of(&entry, entry.reopen(None).unwrap()).unwrap();
        wait_for_clock(dir, entry.status().ctime);
        OpenOptions::new()
            .append(true)
            .open(dir.join("file"))
            .unwrap()
            .write_all(b"!")
            .unwrap();
        let read = hash.read(&mut buffer, u64::MAX);
        assert!(matches!(read, Err(Failure::Changed)), "{:?}", read);
        let directory = Entry::open_at(tree.as_fd(), c"dir").unwrap();
        let opened = directory
            .reopen(Some(Place {
                dir: tree.as_fd(),
                name: c"dir",
            }))
            .unwrap();
        assert_eq!(errno(DataHash::of(&directory, opened)), libc::EINVAL);
    }

    /// The names of the entries of the directory `dir`.
    fn names_in(dir: &Path) -> Vec<std::ffi::OsString> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect()
    }

    /// A temporary name is one nothing has, and it is removed, also once it
    /// is gone already, as after a removal that was interrupted after it
    /// was done.
    #[test]
    fn temporary_names() {
        let tmp = TempDir::new("sys-temporary-names");
        let dir = &tmp.0;
        let directory = File::open(dir).unwrap();
        let names = || -> Vec<Vec<u8>> {
            fs::read_dir(dir)
                .unwrap()
                .map(|entry| entry.unwrap().file_name().into_encoded_bytes())
                .collect()
        };
        let made = TemporaryName::create(directory.as_fd(), ".test-", ScratchFile::NAMED_FLAGS, ScratchFile::MODE);
        let (_file, name) = made.unwrap();
        assert_eq!(names(), [name.as_c_str().to_bytes()]);
        assert!(name.as_c_str().to_bytes().starts_with(b".test-"));
        for _ in 0..2 {
            name.remove(directory.as_fd()).unwrap();
            assert!(names().is_empty());
        }
    }

    /// A scratch file has no name and can get none, only its owner reads
    /// and writes it, and it is not inherited across exec. That holds for
    /// one made with O_TMPFILE and for one that lost its name right away.
    #[test]
    fn scratch_files_have_no_name() {
        let tmp = TempDir::new("sys-scratch");
        let dir = &tmp.0;
        let directory = ScratchFile::open_directory(dir).unwrap();
        let mut own = OwnFiles::default();
        let mut made = vec![
            ScratchFile::create_in(directory.as_fd(), &mut own).unwrap(),
            ScratchFile::create_and_unlink(directory.as_fd(), &mut own).unwrap(),
        ];
        match ScratchFile::create_unnamed(directory.as_fd(), &mut own) {
            Ok(file) => made.push(file),
            Err(e) => {
                assert!(matches!(e, Errno::OPNOTSUPP | Errno::ISDIR), "{}", e);
                eprintln!("skipping O_TMPFILE, which the temporary directory does not have");
            }
        }
        for file in &made {
            assert!(names_in(dir).is_empty());
            let meta = file.file.metadata().unwrap();
            assert_eq!((meta.nlink(), meta.len()), (0, 0));
            assert_eq!(meta.permissions().mode() & 0o7777 & !0o600, 0);
            assert!(meta.is_file());
            assert!(rustix::io::fcntl_getfd(&file.file).unwrap().contains(FdFlags::CLOEXEC));
            // Not through procfs either.
            let link = format!("/proc/self/fd/{}", file.file.as_raw_fd());
            let linked = rustix::fs::linkat(CWD, link.as_str(), &directory, "linked", AtFlags::SYMLINK_FOLLOW);
            assert_eq!(linked, Err(Errno::NOENT));
        }
        // A path that is not a directory is not one scratch files go to.
        fs::write(dir.join("file"), b"").unwrap();
        let not_directory = ScratchFile::open_directory(&dir.join("file")).unwrap_err();
        assert_eq!(not_directory.raw_os_error(), Some(libc::ENOTDIR));
        let missing = ScratchFile::open_directory(&dir.join("missing")).unwrap_err();
        assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));
    }

    /// A scratch file is one of the files of its builder from when it is
    /// made: one made with O_TMPFILE where there is one, and one that lost
    /// its name right away. It is there by the inode and the status a walk
    /// finds for it, and no other file is. One that is given back is
    /// emptied, and one that is dropped keeps what it has. Both stay open
    /// and among the files until those are dropped, which closes them.
    #[test]
    fn scratch_files_are_own_files() {
        let tmp = TempDir::new("sys-scratch-own");
        let dir = &tmp.0;
        let directory = ScratchFile::open_directory(dir).unwrap();
        let mut own = OwnFiles::default();
        // What a walk finds of the file: its status, with its inode.
        let found = |file: &File| Status::of(file.as_fd()).unwrap();
        let first = ScratchFile::create_in(directory.as_fd(), &mut own).unwrap();
        let second = ScratchFile::create_and_unlink(directory.as_fd(), &mut own).unwrap();
        let one = found(&first.file).identity.inode_id();
        let other = found(&second.file).identity.inode_id();
        assert_ne!(one, other);
        assert!(own.contains(&found(&first.file)).unwrap() && own.contains(&found(&second.file)).unwrap());
        fs::write(dir.join("file"), b"").unwrap();
        assert!(!own.contains(&found(&File::open(dir.join("file")).unwrap())).unwrap());
        // The files of another builder are not these.
        let mut others = OwnFiles::default();
        let third = ScratchFile::create_in(directory.as_fd(), &mut others).unwrap();
        assert!(others.contains(&found(&third.file)).unwrap() && !own.contains(&found(&third.file)).unwrap());
        assert!(!others.contains(&found(&first.file)).unwrap());
        // The files with the inodes `inodes` that this process has open
        // among those made in the directory, the smallest first.
        let open = |inodes: &[InodeId]| -> Vec<OpenFile> {
            let mut files = OpenFile::made_in(dir);
            files.retain(|file| inodes.contains(&file.inode));
            files.sort_unstable_by_key(|file| file.size);
            files
        };
        let sizes = |files: &[OpenFile]| -> Vec<u64> { files.iter().map(|file| file.size).collect() };
        const DATA: &[u8] = b"data";
        const MORE: &[u8] = b"more data";
        first.write_all_at(DATA, 0).unwrap();
        second.write_all_at(MORE, 0).unwrap();
        assert_eq!(sizes(&open(&[one, other])), [DATA.len() as u64, MORE.len() as u64]);
        own.take_back(first);
        let files = open(&[one, other]);
        assert_eq!(sizes(&files), [0, MORE.len() as u64]);
        assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
        own.take_back(second);
        let files = open(&[one, other]);
        assert_eq!(sizes(&files), [0, 0]);
        assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
        // A file that is dropped and not given back keeps what it has.
        let kept = ScratchFile::create_in(directory.as_fd(), &mut own).unwrap();
        kept.write_all_at(MORE, 0).unwrap();
        let unused = found(&kept.file).identity.inode_id();
        drop(kept);
        let files = open(&[one, other, unused]);
        assert_eq!(sizes(&files), [0, 0, MORE.len() as u64]);
        assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
        // A file that is still used outlives the files of its builder.
        let last = ScratchFile::create_in(directory.as_fd(), &mut own).unwrap();
        last.write_all_at(DATA, 0).unwrap();
        let inode = found(&last.file).identity.inode_id();
        drop(own);
        assert_eq!(sizes(&open(&[one, other, unused, inode])), [DATA.len() as u64]);
        let mut read = [0; DATA.len()];
        last.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(read, DATA);
        drop(last);
        assert!(open(&[one, other, unused, inode]).is_empty());
    }

    /// A file is one of the files of a builder by its inode and by its
    /// status. A file system can give two files one inode, so a file that
    /// has the inode of one of the files and another status is none of
    /// them. Here the inode of one file is taken as that of another one,
    /// which is kept open for it, as such a file system would have it.
    #[test]
    fn own_files_are_known_by_their_status() {
        let tmp = TempDir::new("sys-own-status");
        let dir = &tmp.0;
        fs::write(dir.join("ours"), b"ours").unwrap();
        fs::write(dir.join("theirs"), b"of the tree").unwrap();
        let open = |name: &str| File::open(dir.join(name)).unwrap();
        let found = |name: &str| Status::of(open(name).as_fd()).unwrap();
        let mut own = OwnFiles::default();
        assert!(!own.contains(&found("ours")).unwrap());
        own.keep(found("theirs").identity.inode_id(), Arc::new(open("ours")));
        assert!(!own.contains(&found("theirs")).unwrap());
        assert!(!own.contains(&found("ours")).unwrap());
        // Under its own inode the file is one of them, and the other one,
        // which is kept under its own inode as well now, is too.
        own.keep(found("ours").identity.inode_id(), Arc::new(open("ours")));
        assert!(own.contains(&found("ours")).unwrap());
        own.keep(found("theirs").identity.inode_id(), Arc::new(open("theirs")));
        assert!(own.contains(&found("theirs")).unwrap());
        // The status is the one the file has now, and not one it had.
        let before = found("ours");
        fs::write(dir.join("ours"), b"changed").unwrap();
        assert!(!own.contains(&before).unwrap());
        assert!(own.contains(&found("ours")).unwrap());
    }

    /// A file system that gives two files one inode can give it to two of
    /// the files of a builder. Both are kept with that inode then, and both
    /// are files of the builder's own: the one that was kept first is not
    /// given up for the one that is kept after it. Both stay open until the
    /// files are dropped. A file of the tree that has their inode and the
    /// status of neither is none of them. Here two files are kept under
    /// the inode of the first one, as such a file system would have them.
    #[test]
    fn own_files_with_one_inode() {
        let tmp = TempDir::new("sys-own-one-inode");
        let dir = &tmp.0;
        fs::write(dir.join("older"), b"the older one").unwrap();
        fs::write(dir.join("newer"), b"newer").unwrap();
        fs::write(dir.join("theirs"), b"of the tree").unwrap();
        let open = |name: &str| File::open(dir.join(name)).unwrap();
        let found = |name: &str| Status::of(open(name).as_fd()).unwrap();
        // What a walk finds of the file `name` where the file system gives
        // it the inode of the older file.
        let numbered = |name: &str| Status {
            identity: found("older").identity,
            ..found(name)
        };
        let inode = found("older").identity.inode_id();
        let mut own = OwnFiles::default();
        own.keep(inode, Arc::new(open("older")));
        assert!(own.contains(&found("older")).unwrap());
        assert!(!own.contains(&numbered("newer")).unwrap());
        own.keep(inode, Arc::new(open("newer")));
        assert!(own.contains(&found("older")).unwrap());
        assert!(own.contains(&numbered("newer")).unwrap());
        assert!(!own.contains(&numbered("theirs")).unwrap());
        // The files of the builder alone have the two open, until they are
        // dropped.
        let mut kept: Vec<u64> = OpenFile::made_in(dir).iter().map(|file| file.size).collect();
        kept.sort_unstable();
        assert_eq!(kept, [found("newer").size, found("older").size]);
        drop(own);
        assert!(OpenFile::made_in(dir).is_empty());
    }

    /// A scratch file that was given back is handed out again, once: it is
    /// empty, and it is the file it was, one of the files of its builder
    /// with the inode it had. The files of another builder hand out none of
    /// them. A file that could not be emptied when it was given back keeps
    /// what it has, stays one of the files, and is not handed out again.
    #[test]
    fn scratch_files_given_back_are_handed_out_again() {
        let tmp = TempDir::new("sys-scratch-again");
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        let mut own = OwnFiles::default();
        let inode_of = |file: &ScratchFile| InodeId::of(file.file.as_fd()).unwrap();
        let len_of = |file: &ScratchFile| file.file.metadata().unwrap().len();
        /// More files than the test makes. A file that is handed out is
        /// not handed out again, and one that was would be without end.
        const MOST: usize = 8;
        // Every file there is to hand out, which stays handed out.
        let handed_out =
            |own: &mut OwnFiles| -> Vec<ScratchFile> { std::iter::from_fn(|| own.hand_out()).take(MOST).collect() };
        assert!(handed_out(&mut own).is_empty());
        let first = ScratchFile::create_in(directory.as_fd(), &mut own).unwrap();
        let second = ScratchFile::create_in(directory.as_fd(), &mut own).unwrap();
        let (one, other) = (inode_of(&first), inode_of(&second));
        const DATA: &[u8] = b"data";
        first.write_all_at(DATA, 0).unwrap();
        second.write_all_at(DATA, 0).unwrap();
        assert!(handed_out(&mut own).is_empty());
        own.take_back(first);
        let mut others = OwnFiles::default();
        assert!(handed_out(&mut others).is_empty());
        let again = handed_out(&mut own);
        assert_eq!(again.len(), 1);
        assert_eq!((inode_of(&again[0]), len_of(&again[0])), (one, 0));
        assert!(own.contains(&Status::of(again[0].file.as_fd()).unwrap()).unwrap());
        // It is used like a new one, and handed out again once it is
        // given back again.
        again[0].write_all_at(DATA, 0).unwrap();
        let mut read = [0; DATA.len()];
        again[0].read_exact_at(&mut read, 0).unwrap();
        assert_eq!(read, DATA);
        again.into_iter().chain([second]).for_each(|file| own.take_back(file));
        let both = handed_out(&mut own);
        assert_eq!(both.len(), 2);
        assert!(both.iter().all(|file| len_of(file) == 0));
        let handed: Vec<InodeId> = both.iter().map(inode_of).collect();
        assert!(handed.contains(&one) && handed.contains(&other));
        // A file in memory that is sealed can't be made shorter.
        let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
        let Ok(sealed) = rustix::fs::memfd_create("uapi16-sealed", flags) else {
            eprintln!("skipping the file that can't be emptied: there is no memfd_create()");
            return;
        };
        let kept = ScratchFile::new(sealed, &mut own).unwrap();
        kept.write_all_at(DATA, 0).unwrap();
        rustix::fs::fcntl_add_seals(&kept.file, SealFlags::SHRINK).unwrap();
        assert_eq!(kept.set_len(0).unwrap_err().raw_os_error(), Some(libc::EPERM));
        let file = Arc::clone(&kept.file);
        own.take_back(kept);
        assert!(handed_out(&mut own).is_empty());
        assert_eq!(file.metadata().unwrap().len(), DATA.len() as u64);
        assert!(own.contains(&Status::of(file.as_fd()).unwrap()).unwrap());
    }

    /// A file system that has no O_TMPFILE gets a file that loses its name
    /// right away. The message queue file system is one, and lets anybody
    /// make a file in it.
    #[test]
    fn scratch_files_without_o_tmpfile() {
        let queues = Path::new("/dev/mqueue");
        let Ok(directory) = ScratchFile::open_directory(queues) else {
            eprintln!("skipping: there is no /dev/mqueue");
            return;
        };
        let mut own = OwnFiles::default();
        match ScratchFile::create_unnamed(directory.as_fd(), &mut own) {
            Err(Errno::OPNOTSUPP) => {}
            other => {
                eprintln!("skipping: O_TMPFILE in /dev/mqueue gives {:?}", other.map(|_| ()));
                return;
            }
        }
        let before = names_in(queues).len();
        let file = match ScratchFile::create_in(directory.as_fd(), &mut own) {
            Ok(file) => file,
            Err(e) => {
                eprintln!("skipping: no file can be made in /dev/mqueue: {}", e);
                return;
            }
        };
        assert_eq!(file.file.metadata().unwrap().nlink(), 0);
        // Other processes make and remove queues, but ours is gone.
        let prefix = ScratchFile::NAME_PREFIX.as_bytes();
        let left = names_in(queues)
            .iter()
            .filter(|name| name.as_encoded_bytes().starts_with(prefix))
            .count();
        assert_eq!(left, 0, "{} entries before", before);
    }

    /// A scratch file is read and written at any offset. What was never
    /// written reads as zeroes up to the end of the file, and a read past
    /// the end fails instead of coming back short.
    #[test]
    fn scratch_files_are_read_and_written_anywhere() {
        let tmp = TempDir::new("sys-scratch-io");
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        let file = ScratchFile::create_in(directory.as_fd(), &mut OwnFiles::default()).unwrap();
        let data: Vec<u8> = (0..3 * DATA_BUFFER_SIZE + 7).map(|i| (i % 253) as u8).collect();
        let far = 5 * 1024 * 1024 * 1024;
        file.write_all_at(&data, far).unwrap();
        file.write_all_at(b"start", 0).unwrap();
        file.write_all_at(b"", 1).unwrap();
        let mut read = vec![0xff; data.len()];
        file.read_exact_at(&mut read, far).unwrap();
        assert_eq!(read, data);
        let mut start = [0xff; 8];
        file.read_exact_at(&mut start, 0).unwrap();
        assert_eq!(&start, b"start\0\0\0");
        file.read_exact_at(&mut [], far + data.len() as u64 + 1).unwrap();
        // The last byte, and one more.
        let end = far + data.len() as u64;
        file.read_exact_at(&mut start[..1], end - 1).unwrap();
        let past = file.read_exact_at(&mut start[..2], end - 1).unwrap_err();
        assert_eq!(past.kind(), io::ErrorKind::UnexpectedEof);
        // A longer file has zeroes where nothing was written, and a
        // shorter one ends there.
        file.set_len(end + 4096).unwrap();
        let mut tail = [0xff; 4096];
        file.read_exact_at(&mut tail, end).unwrap();
        assert_eq!(tail, [0; 4096]);
        file.set_len(4).unwrap();
        let short = file.read_exact_at(&mut start[..5], 0).unwrap_err();
        assert_eq!(short.kind(), io::ErrorKind::UnexpectedEof);
        // Only what is written takes room.
        assert!(room_of(&file) < far);
    }

    /// How many bytes of room the scratch file `file` takes.
    fn room_of(file: &ScratchFile) -> u64 {
        file.file.metadata().unwrap().blocks() * ST_BLOCKS_UNIT
    }

    /// `blocks` blocks of `block` bytes of data without a zero.
    fn blocks_of_data(blocks: u64, block: u64) -> Vec<u8> {
        (0..blocks * block).map(|at| (at % 251) as u8 + 1).collect()
    }

    /// A hole punched into a scratch file reads as zeroes. The file stays
    /// as long as it is and keeps what is around the hole, and the room of
    /// the blocks that are all in the hole is given back. Where the
    /// temporary directory cannot punch holes this is skipped.
    #[test]
    fn holes_in_scratch_files() {
        let tmp = TempDir::new("sys-scratch-holes");
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        let file = ScratchFile::create_in(directory.as_fd(), &mut OwnFiles::default()).unwrap();
        let block = file.block_size().unwrap();
        assert!(block > 0);
        let data = blocks_of_data(8, block);
        file.write_all_at(&data, 0).unwrap();
        // What was written has its room now, and not only the promise of
        // it.
        file.file.sync_all().unwrap();
        let before = room_of(&file);
        // Two blocks, and a part of the block on either side of them.
        let (start, end) = (2 * block - 100, 4 * block + 100);
        if let Err(e) = file.punch_hole(start, end - start) {
            assert_eq!(e.raw_os_error(), Some(libc::EOPNOTSUPP), "{}", e);
            eprintln!("skipping: the temporary directory cannot punch holes");
            return;
        }
        assert_eq!(file.file.metadata().unwrap().len(), data.len() as u64);
        let mut read = vec![0xff; data.len()];
        file.read_exact_at(&mut read, 0).unwrap();
        let (start, end) = (start as usize, end as usize);
        assert!(read[..start] == data[..start] && read[end..] == data[end..]);
        assert!(read[start..end].iter().all(|&byte| byte == 0));
        assert!(room_of(&file) + 2 * block <= before, "{} -> {}", before, room_of(&file));
        // A hole in a hole, and one that is no block long.
        file.punch_hole(2 * block, block).unwrap();
        file.punch_hole(7 * block + 1, 1).unwrap();
        file.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(
            read[7 * block as usize..][..3],
            [data[7 * block as usize], 0, data[7 * block as usize + 2]]
        );
        // No hole is nothing to ask for.
        let empty = file.punch_hole(block, 0).unwrap_err();
        assert_eq!(empty.raw_os_error(), Some(libc::EINVAL));
    }

    /// The variable that names a directory of a file system that cannot
    /// punch holes, in which the test binary runs
    /// [`scratch_files_without_holes`] again.
    const NO_HOLES_DIR: &str = "UAPI16_TEST_NO_HOLES_DIR";

    /// A file system that cannot punch holes fails with EOPNOTSUPP, and the
    /// file keeps its data and its room. The test binary runs this test
    /// again with its directory on a ramfs, which is one, and it is skipped
    /// where that cannot be mounted.
    #[test]
    fn scratch_files_without_holes() {
        let Some(dir) = std::env::var_os(NO_HOLES_DIR) else {
            let tmp = TempDir::new("sys-scratch-no-holes");
            tmp.rerun_on("ramfs", None, "sys::tests::scratch_files_without_holes", NO_HOLES_DIR);
            return;
        };
        let directory = ScratchFile::open_directory(Path::new(&dir)).unwrap();
        let file = ScratchFile::create_in(directory.as_fd(), &mut OwnFiles::default()).unwrap();
        let block = file.block_size().unwrap();
        assert!(block > 0);
        let data = blocks_of_data(4, block);
        file.write_all_at(&data, 0).unwrap();
        let before = room_of(&file);
        let refused = file.punch_hole(block, 2 * block).unwrap_err();
        assert_eq!(refused.raw_os_error(), Some(libc::EOPNOTSUPP));
        let mut read = vec![0; data.len()];
        file.read_exact_at(&mut read, 0).unwrap();
        assert!(read == data);
        assert_eq!(room_of(&file), before);
    }

    /// The data of a file of procfs goes on after its size, which is 0,
    /// and the status of the file shows no change.
    #[test]
    fn data_after_the_size() {
        if rustix::fs::statfs("/proc").unwrap().f_type != rustix::fs::PROC_SUPER_MAGIC {
            return;
        }
        let process = open_dir(Path::new("/proc/self"));
        let entry = Entry::open_at(process.as_fd(), c"status").unwrap();
        assert_eq!(
            (entry.status().file_type, entry.status().size),
            (FileType::RegularFile, 0)
        );
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        let read = hash(&entry, &mut buffer);
        assert!(matches!(read, Err(Failure::WrongSize)), "{:?}", read);
    }

    /// A file that cannot be opened for reading fails with the error of the
    /// open. That takes a process that the permissions of a file hold for.
    #[test]
    fn unreadable() {
        let tmp = TempDir::new("sys-unreadable");
        let dir = &tmp.0;
        let path = dir.join("file");
        fs::write(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(&path).is_ok() {
            return;
        }
        let tree = open_dir(dir);
        let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        assert_eq!(errno(hash(&entry, &mut buffer)), libc::EACCES);
    }

    /// A regular file with more data than is hashed fails its hash with
    /// EFBIG, by its size alone, before it is opened and before anything
    /// is read of it. One with exactly as much is opened, and its data is
    /// read from the beginning. Neither is read through here: that takes a
    /// quarter of an hour.
    #[test]
    fn data_too_large_to_hash() {
        let tmp = TempDir::new("sys-too-large");
        let dir = &tmp.0;
        let file = File::create(dir.join("file")).unwrap();
        if let Err(e) = file.set_len(DataHash::MAX_SIZE + 1) {
            eprintln!("skipping: the temporary directory takes no file of that size: {}", e);
            return;
        }
        let tree = open_dir(dir);
        let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
        assert_eq!(entry.status().size, DataHash::MAX_SIZE + 1);
        assert_eq!(errno(DataHash::admits(entry.status())), libc::EFBIG);
        assert_eq!(errno(DataHash::start(&entry)), libc::EFBIG);
        let opened = entry.reopen(None).unwrap();
        assert_eq!(errno(DataHash::of(&entry, opened)), libc::EFBIG);
        // A file that may not be opened fails for its size all the same:
        // nothing opens it.
        fs::set_permissions(dir.join("file"), fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(errno(DataHash::start(&entry)), libc::EFBIG);
        fs::set_permissions(dir.join("file"), fs::Permissions::from_mode(0o644)).unwrap();
        file.set_len(DataHash::MAX_SIZE).unwrap();
        let entry = Entry::open_at(tree.as_fd(), c"file").unwrap();
        DataHash::admits(entry.status()).unwrap();
        let mut buffer = vec![0; DATA_BUFFER_SIZE];
        let begun = DataHash::start(&entry).unwrap().read(&mut buffer, 1).unwrap();
        assert!(matches!(begun, ControlFlow::Continue(hash) if hash.offset == 1));
    }

    /// The variable that names an automount point for
    /// [`automount_points_are_told_from_their_handles`].
    const AUTOMOUNT: &str = "UAPI16_TEST_AUTOMOUNT";

    /// An entry says whether it is an automount point that nothing is
    /// mounted on, and taking its handle mounts nothing, with open_tree()
    /// and with openat(), and neither does what is read through the handle.
    /// It is not opened: by its name that would mount what it stands for.
    /// Only root can make one, so the test takes one that is there:
    /// `UAPI16_TEST_AUTOMOUNT` names a directory that is one, such as the
    /// mount point of an automount unit of systemd, or `tracing` in a
    /// debugfs that was just mounted. Without the variable the test is
    /// skipped.
    #[test]
    fn automount_points_are_told_from_their_handles() {
        let Some(point) = std::env::var_os(AUTOMOUNT) else {
            eprintln!("skipping: {} names no automount point", AUTOMOUNT);
            return;
        };
        let point = Path::new(&point);
        let parent = open_dir(point.parent().unwrap());
        let name = [point.file_name().unwrap().to_str().unwrap(), "\0"].concat();
        let name = CStr::from_bytes_with_nul(name.as_bytes()).unwrap();
        // Once something is mounted on it, a handle is of the root of that,
        // which is no automount point. So each handle after the first one
        // says that the ones before it mounted nothing.
        with_both_handles(|| {
            for _ in 0..2 {
                let entry = Entry::open_at(parent.as_fd(), name).unwrap();
                assert!(entry.is_automount(), "{}", point.display());
                assert_eq!(entry.status().file_type, FileType::Directory);
                Status::of(entry.handle()).unwrap();
                FdLink::new(entry.handle()).check().unwrap();
                // Whether it has extended attributes is its file system's
                // to say. Asking mounts nothing.
                let _ = UserXattrs::new().read_unopened(&entry);
                let place = Place {
                    dir: parent.as_fd(),
                    name,
                };
                for place in [Some(place), None] {
                    assert_eq!(errno(entry.reopen(place)), libc::EINVAL);
                }
            }
        });
        // A directory that is none says so.
        let tmp = TempDir::new("sys-no-automount");
        fs::create_dir(tmp.0.join("dir")).unwrap();
        let tree = open_dir(&tmp.0);
        assert!(!Entry::open_at(tree.as_fd(), c"dir").unwrap().is_automount());
    }

    /// What is kept of a file of a tree, and of the hash of its data, can
    /// go to another thread and be shared between threads.
    #[test]
    fn send_and_sync() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<Status>();
        send_sync::<Entry<'_>>();
        send_sync::<DataHash>();
        send_sync::<Readable>();
        send_sync::<UserXattrs>();
        send_sync::<UserDatabase>();
        send_sync::<ScratchFile>();
    }
}
