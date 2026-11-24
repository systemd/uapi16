// SPDX-License-Identifier: LGPL-2.1-or-later
//! The directory next to a manifest that the data of its files is taken
//! from, with every name resolved below it.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;
use std::sync::atomic::{AtomicU8, Ordering};

use pathrs::error::{Error as PathrsError, ErrorKind as PathrsErrorKind};
use pathrs::flags::{OpenFlags, ResolverFlags};
use pathrs::{Handle, Root};
use rustix::fs::{FileType, Mode, OFlags};
use rustix::io::Errno;

use crate::content::{Directory, OpenError};
use crate::Name;

/// What this process found out about O_EMPTYPATH: whether the kernel
/// reopens a descriptor with `openat(fd, "", O_EMPTYPATH | ..)`, which
/// needs no procfs. Linux 7.2 has it.
struct EmptyPath;

impl EmptyPath {
    /// O_EMPTYPATH, include/uapi/asm-generic/fcntl.h. No architecture
    /// overrides it, and fs/fcntl.c checks at build time that it is a bit
    /// of its own on every architecture.
    const FLAG: u32 = 1 << 26;
    /// Not tried yet.
    const UNKNOWN: u8 = 0;
    /// It worked once, so ENOENT is the file's own error from now on.
    const WORKS: u8 = 1;
    /// The kernel ignored the flag and refused the empty path.
    const MISSING: u8 = 2;
}

/// The state of [`EmptyPath`] for this process.
static EMPTYPATH: AtomicU8 = AtomicU8::new(EmptyPath::UNKNOWN);

/// The directory on the host the files of a manifest are taken from: the
/// one the manifest lives in, or the one the caller chose instead. It is
/// opened once and never looked up again, and each file below it is
/// pinned before it is opened.
///
/// A [`DirectoryProvider`](crate::DirectoryProvider) reads the data of the
/// files from it. The copy of an object fails with
/// [`SourceProblem::Missing`] where its file is not there, with
/// [`SourceProblem::NotRegular`] where it is not a regular file, such as a
/// directory or a FIFO, and with [`DataProblem::SizeMismatch`] where it is
/// too short for the data the manifest says it holds. Unless symbolic
/// links are followed, see [`PinnedDirectory::follow_symlinks`], a name
/// that leads through one fails with [`SourceProblem::Unreadable`], and
/// [`Error::io_error`] gives ELOOP.
///
/// [`SourceProblem::Missing`]: crate::SourceProblem::Missing
/// [`SourceProblem::NotRegular`]: crate::SourceProblem::NotRegular
/// [`SourceProblem::Unreadable`]: crate::SourceProblem::Unreadable
/// [`DataProblem::SizeMismatch`]: crate::DataProblem::SizeMismatch
/// [`Error::io_error`]: crate::Error::io_error
#[derive(Debug)]
pub struct PinnedDirectory {
    root: Root,
}

impl PinnedDirectory {
    /// How a file is opened once it is pinned and known to be a regular
    /// file: for reading, without waiting for anything, and without
    /// becoming the controlling terminal.
    const OPEN_FLAGS: OpenFlags = OpenFlags::O_RDONLY
        .union(OpenFlags::O_NONBLOCK)
        .union(OpenFlags::O_NOCTTY);
    /// The same for the reopen through rustix, with O_CLOEXEC, which
    /// pathrs adds on its own.
    const REOPEN_FLAGS: OFlags = OFlags::RDONLY
        .union(OFlags::NONBLOCK)
        .union(OFlags::NOCTTY)
        .union(OFlags::CLOEXEC);
    /// How [`PinnedDirectory::open`] opens the directory: as a handle that
    /// nothing is read through, for a directory and nothing else.
    const DIRECTORY_FLAGS: OFlags = OFlags::PATH.union(OFlags::DIRECTORY).union(OFlags::CLOEXEC);
    /// What the root file object is resolved as, which has the empty name:
    /// the directory itself.
    const ITSELF: &'static str = ".";

    /// The files below the open directory `dir`, which the caller resolved
    /// once and which is never looked up again. A name is resolved below it
    /// the way systemd's chase() resolves a path below a root: an absolute
    /// symbolic link target starts over at `dir`, `..` at `dir` stays
    /// there, nothing resolves to anything outside it, and symbolic links
    /// are followed only when [`PinnedDirectory::follow_symlinks`] allows
    /// them. Magic links, such as those below `/proc/self/fd`, are never
    /// followed.
    ///
    /// `dir` has to be a directory, as [`PinnedDirectory::open`] makes
    /// sure: below anything else every file fails to open.
    pub fn new(dir: OwnedFd) -> PinnedDirectory {
        PinnedDirectory {
            root: Root::from_fd(dir).with_resolver_flags(ResolverFlags::NO_SYMLINKS),
        }
    }

    /// Opens the directory `path` and pins the files below it, see
    /// [`PinnedDirectory::new`]. The directory is opened with O_PATH, so it
    /// needs no read permission, and with O_DIRECTORY, so a path that is
    /// not a directory fails here, with ENOTDIR.
    pub fn open(path: impl AsRef<Path>) -> io::Result<PinnedDirectory> {
        let dir = rustix::fs::open(path.as_ref(), PinnedDirectory::DIRECTORY_FLAGS, Mode::empty())?;
        Ok(PinnedDirectory::new(dir))
    }

    /// Follows symbolic links, resolved as if the directory were the root:
    /// a link that points out of the directory leads to what has that path
    /// inside it instead. Off by default: a link planted in a tree would
    /// otherwise make a privileged copy read any file below the directory,
    /// such as one the planter cannot read.
    #[must_use]
    pub fn follow_symlinks(mut self, follow: bool) -> PinnedDirectory {
        let flags = if follow {
            ResolverFlags::empty()
        } else {
            ResolverFlags::NO_SYMLINKS
        };
        self.root.set_resolver_flags(flags);
        self
    }

    /// Pins the file `file` names below the directory and checks that it
    /// is a regular file. Returns it with its size.
    fn pin(&self, file: &Name) -> Result<(Handle, u64), OpenError> {
        let path = if file.is_root() {
            PinnedDirectory::ITSELF
        } else {
            file.as_str()
        };
        let pinned = self.root.resolve(path).map_err(PinnedDirectory::io_error)?;
        let stat = rustix::fs::fstat(&pinned).map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(OpenError::NotRegular);
        }
        // The size of a regular file is never negative.
        let len = u64::try_from(stat.st_size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok((pinned, len))
    }

    /// Opens the regular file `pinned` refers to for reading: through
    /// O_EMPTYPATH where the kernel has it, probed the way systemd's
    /// fd_reopen() does, and with the checked reopen of pathrs through
    /// procfs where it does not.
    fn reopen(pinned: &Handle) -> io::Result<File> {
        let state = EMPTYPATH.load(Ordering::Relaxed);
        if state != EmptyPath::MISSING {
            let flags = PinnedDirectory::REOPEN_FLAGS | OFlags::from_bits_retain(EmptyPath::FLAG);
            match rustix::fs::openat(pinned, "", flags, Mode::empty()) {
                Ok(fd) => {
                    EMPTYPATH.store(EmptyPath::WORKS, Ordering::Relaxed);
                    return Ok(File::from(fd));
                }
                // An older kernel ignores the flag and refuses the empty
                // path. Once it worked, ENOENT comes from the file itself.
                Err(Errno::NOENT) if state != EmptyPath::WORKS => {
                    EMPTYPATH.store(EmptyPath::MISSING, Ordering::Relaxed);
                }
                Err(e) => return Err(e.into()),
            }
        }
        pinned
            .reopen(PinnedDirectory::OPEN_FLAGS)
            .map_err(PinnedDirectory::io_error)
    }

    /// The error `error` of pathrs as an I/O error: that of the system call
    /// that failed, or the error of pathrs itself where none did.
    fn io_error(error: PathrsError) -> io::Error {
        match error.kind() {
            PathrsErrorKind::OsError(Some(errno)) => io::Error::from_raw_os_error(errno),
            _ => io::Error::other(error),
        }
    }
}

impl Directory for PinnedDirectory {
    type File = File;

    /// Opens the file: pinned, checked to be a regular file, and only then
    /// opened for reading.
    fn open(&self, file: &Name) -> Result<(File, u64), OpenError> {
        let (pinned, len) = self.pin(file)?;
        Ok((PinnedDirectory::reopen(&pinned)?, len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;
    use rustix::fs::CWD;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::symlink;

    /// What `dir` has under `name`: the text of a regular file, or why it
    /// has none.
    fn text(dir: &PinnedDirectory, name: &str) -> Result<String, Opened> {
        let (mut file, len) = dir.open(Name::new(name).unwrap()).map_err(Opened::from)?;
        let mut text = String::new();
        file.read_to_string(&mut text).unwrap();
        assert_eq!(text.len() as u64, len, "{}", name);
        Ok(text)
    }

    /// Why a file was not opened, in a form a test compares.
    #[derive(Debug, PartialEq)]
    enum Opened {
        NotRegular,
        Errno(i32),
    }

    impl From<OpenError> for Opened {
        fn from(e: OpenError) -> Opened {
            match e {
                OpenError::NotRegular => Opened::NotRegular,
                OpenError::Io(e) => Opened::Errno(e.raw_os_error().unwrap_or_else(|| panic!("{:?}", e))),
            }
        }
    }

    /// The escapes a resolution below the directory has to refuse, and the
    /// errors it refuses them with.
    #[test]
    fn stays_below_the_directory() {
        let tmp = TempDir::new("pinned");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("root/sub/deep")).unwrap();
        fs::write(dir.join("root/sub/deep/file"), b"inside").unwrap();
        fs::write(dir.join("root/top"), b"top").unwrap();
        fs::write(dir.join("outside"), b"outside").unwrap();
        symlink("deep/file", dir.join("root/sub/rel")).unwrap();
        symlink("/top", dir.join("root/sub/abs")).unwrap();
        symlink("../../outside", dir.join("root/sub/up")).unwrap();
        symlink(dir.join("outside"), dir.join("root/sub/far")).unwrap();
        symlink("loop", dir.join("root/loop")).unwrap();
        symlink("/proc/self/fd/0", dir.join("root/magic")).unwrap();
        let plain = PinnedDirectory::open(dir.join("root")).unwrap();
        assert_eq!(text(&plain, "sub/deep/file").as_deref(), Ok("inside"));
        assert_eq!(text(&plain, "top").as_deref(), Ok("top"));
        // A directory is not a regular file, and neither is the directory
        // itself, which the root file object names.
        assert_eq!(text(&plain, "sub"), Err(Opened::NotRegular));
        assert_eq!(
            plain.open(Name::ROOT).map(|_| ()).map_err(Opened::from),
            Err(Opened::NotRegular)
        );
        assert_eq!(text(&plain, "missing"), Err(Opened::Errno(libc::ENOENT)));
        assert_eq!(text(&plain, "top/x"), Err(Opened::Errno(libc::ENOTDIR)));
        // Without following, every symbolic link is a dead end.
        for link in ["sub/rel", "sub/abs", "sub/up", "sub/far", "loop", "magic"] {
            assert_eq!(text(&plain, link), Err(Opened::Errno(libc::ELOOP)), "{}", link);
        }
        // Following stays inside the directory: an absolute target starts at
        // the directory, ".." above it stays there, and a target that leads
        // outside is looked for inside.
        let following = PinnedDirectory::open(dir.join("root")).unwrap().follow_symlinks(true);
        assert_eq!(text(&following, "sub/rel").as_deref(), Ok("inside"));
        assert_eq!(text(&following, "sub/abs").as_deref(), Ok("top"));
        assert_eq!(text(&following, "sub/up"), Err(Opened::Errno(libc::ENOENT)));
        assert_eq!(text(&following, "sub/far"), Err(Opened::Errno(libc::ENOENT)));
        assert_eq!(text(&following, "loop"), Err(Opened::Errno(libc::ELOOP)));
        assert_eq!(text(&following, "magic"), Err(Opened::Errno(libc::ENOENT)));
        // Following can be turned off again.
        let plain = following.follow_symlinks(false);
        assert_eq!(text(&plain, "sub/rel"), Err(Opened::Errno(libc::ELOOP)));
    }

    /// A magic link is refused even where the directory is /proc, and the
    /// directories of procfs are not regular files.
    #[test]
    fn follows_no_magic_links() {
        if rustix::fs::statfs("/proc").unwrap().f_type != rustix::fs::PROC_SUPER_MAGIC {
            return;
        }
        let following = PinnedDirectory::open("/proc").unwrap().follow_symlinks(true);
        assert_eq!(text(&following, "self/fd/0"), Err(Opened::Errno(libc::ELOOP)));
        assert_eq!(text(&following, "self/fd"), Err(Opened::NotRegular));
        let plain = following.follow_symlinks(false);
        assert_eq!(text(&plain, "self/fd/0"), Err(Opened::Errno(libc::ELOOP)));
    }

    /// A pinned file is reopened whichever way the kernel offers, also after
    /// it was unlinked or replaced under its name.
    #[test]
    fn reopens_what_was_pinned() {
        let tmp = TempDir::new("pinned-reopen");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"pinned").unwrap();
        let directory = PinnedDirectory::open(dir).unwrap();
        let read = |file: &mut File| {
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            text
        };
        for state in [EmptyPath::UNKNOWN, EmptyPath::MISSING] {
            EMPTYPATH.store(state, Ordering::Relaxed);
            let (handle, _) = directory.pin(Name::new("file").unwrap()).unwrap();
            fs::rename(dir.join("file"), dir.join("moved")).unwrap();
            fs::write(dir.join("file"), b"impostor").unwrap();
            assert_eq!(read(&mut PinnedDirectory::reopen(&handle).unwrap()), "pinned");
            fs::remove_file(dir.join("moved")).unwrap();
            assert_eq!(read(&mut PinnedDirectory::reopen(&handle).unwrap()), "pinned");
            fs::write(dir.join("file"), b"pinned").unwrap();
        }
        EMPTYPATH.store(EmptyPath::UNKNOWN, Ordering::Relaxed);
    }

    /// Only a directory is pinned: anything else fails right away, where
    /// every file below it would fail to open later.
    #[test]
    fn pins_only_directories() {
        let tmp = TempDir::new("pinned-open");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"data").unwrap();
        let e = PinnedDirectory::open(dir.join("file")).unwrap_err();
        assert_eq!(e.raw_os_error(), Some(libc::ENOTDIR));
        let directory = PinnedDirectory::open(dir).unwrap();
        assert_eq!(text(&directory, "file").as_deref(), Ok("data"));
    }

    /// Nothing but a regular file is opened: a FIFO, whose open would wait
    /// for a writer, is not a regular file and is never opened.
    #[test]
    fn opens_only_regular_files() {
        let tmp = TempDir::new("pinned-fifo");
        let dir = &tmp.0;
        let fifo = dir.join("fifo");
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        fs::write(dir.join("file"), b"data").unwrap();
        let directory = PinnedDirectory::open(dir).unwrap();
        assert_eq!(text(&directory, "fifo"), Err(Opened::NotRegular));
        assert_eq!(text(&directory, "file").as_deref(), Ok("data"));
        // The file is the one that was pinned, open for reading only.
        let (file, len) = directory.open(Name::new("file").unwrap()).unwrap();
        assert_eq!(len, 4);
        let flags = rustix::fs::fcntl_getfl(&file).unwrap();
        assert_eq!(flags & OFlags::RWMODE, OFlags::RDONLY);
        assert!(flags.contains(OFlags::NONBLOCK));
    }
}
