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
//! does on open.
//!
//! Nothing here mounts anything. The kernel mounts a file system on an
//! automount point when the directory is opened by its name or a name is
//! looked up in it, but not when its handle is taken. So an entry says
//! whether it is an automount point, see [`Entry::is_automount`], and one
//! that is one is not opened and has nothing opened in it.

use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::sync::atomic::{AtomicU8, Ordering};

use pathrs::error::{Error as PathrsError, ErrorKind as PathrsErrorKind};
use pathrs::flags::OpenFlags;
use pathrs::HandleRef;
use rustix::fs::{AtFlags, FileType, FsWord, OFlags, Statx, StatxAttributes, StatxFlags, StatxTimestamp};
use rustix::io::{retry_on_intr, Errno};
use rustix::mount::OpenTreeFlags;

use crate::digest::Sha256Context;
use crate::tree::{DataFailure, DeviceNumber, Entry, Failure, Handle, Identity, MountId, Status, Timestamp};
use crate::{Mode, Sha256};

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
    const FLAG: u32 = 1 << 26;
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

/// A regular file pinned by a handle, a descriptor opened with O_PATH,
/// through which it is opened for reading: without its name, so that no
/// other file can take its place.
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
    /// The regular file `handle` refers to. It has to be one: the file is
    /// opened whatever it is, a device node with what its driver does on
    /// open.
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

/// The error `error` of pathrs as an I/O error: that of the system call
/// that failed, or the error of pathrs itself where none did.
pub(crate) fn pathrs_io_error(error: PathrsError) -> io::Error {
    match error.kind() {
        PathrsErrorKind::OsError(Some(errno)) => io::Error::from_raw_os_error(errno),
        _ => io::Error::other(error),
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
        Ok(DataHash {
            file: PinnedFile::new(entry.handle()).reopen()?,
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
    use crate::testing::TempDir;
    use rustix::fs::{inotify, CWD};
    use rustix::io::FdFlags;
    use std::fmt;
    use std::fs::{self, OpenOptions};
    use std::io::{Read, Write};
    use std::mem::MaybeUninit;
    use std::os::fd::AsRawFd;
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
    }
}
