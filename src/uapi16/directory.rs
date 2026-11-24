// SPDX-License-Identifier: LGPL-2.1-or-later
//! The directory next to a manifest that the data of its files is taken
//! from, with every name resolved below it.

use std::fs::File;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::Path;

use pathrs::flags::ResolverFlags;
use pathrs::{Handle, Root};
use rustix::fs::{FileType, Mode, OFlags};

use crate::content::{Directory, ExternalFile, OpenError};
use crate::sys::{pathrs_io_error, PinnedFile};
use crate::{Error, FileObject, Name};

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
/// too short for the data the manifest says it holds, or of another length
/// than [`ExternalFile::original_size`] says. Unless symbolic links are
/// followed, see [`PinnedDirectory::follow_symlinks`], a name that leads
/// through one fails with [`SourceProblem::Unreadable`], and
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

    /// Opens `file` for reading: the file the data of `object` is in, as
    /// [`FileObject::data_location`] gives it. The data starts at
    /// [`ExternalFile::offset`] in it and is as long as the object says, or
    /// reaches to the end of the file where the object gives no size. The
    /// file is open for reading, and blocks as a regular file does.
    ///
    /// The file is a regular file below the directory. One that is not
    /// there fails with [`SourceProblem::Missing`], one that is no regular
    /// file with [`SourceProblem::NotRegular`], one that can't be opened
    /// with [`SourceProblem::Unreadable`], and one that is too short for the
    /// data, or of another length than [`ExternalFile::original_size`] says,
    /// with [`DataProblem::SizeMismatch`]. The error names the object.
    ///
    /// The caller checks what it reads with a [`DataCheck`]. A file can hold
    /// the data of several file objects. Where the manifest gives a hash
    /// for the whole file and none for the object, the data of the object
    /// is not checked against it. A caller that wants that check reads the
    /// whole file and holds it against [`ExternalFile::original_sha256`].
    ///
    /// [`SourceProblem::Missing`]: crate::SourceProblem::Missing
    /// [`SourceProblem::NotRegular`]: crate::SourceProblem::NotRegular
    /// [`SourceProblem::Unreadable`]: crate::SourceProblem::Unreadable
    /// [`DataProblem::SizeMismatch`]: crate::DataProblem::SizeMismatch
    /// [`DataCheck`]: crate::DataCheck
    pub fn open_data(&self, object: &FileObject, file: &ExternalFile<'_>) -> Result<File, Error> {
        let (opened, len) = Directory::open(self, file.name()).map_err(|e| file.unavailable(object, e))?;
        file.check_len(object, len)?;
        PinnedDirectory::hand_out(opened).map_err(|e| file.unavailable(object, OpenError::Io(e)))
    }

    /// The file `file`, which [`PinnedDirectory::reopen`] opened, as a
    /// caller gets it: without O_NONBLOCK. The file is opened with the
    /// flag so that the open waits for nothing. read() and pread() of a
    /// regular file don't look at it, but io_uring does: where the file
    /// system has no reads that don't wait, it fails the read of such a
    /// descriptor with EAGAIN and doesn't hand it to a worker.
    fn hand_out(file: File) -> io::Result<File> {
        let flags = rustix::fs::fcntl_getfl(&file)?;
        rustix::fs::fcntl_setfl(&file, flags.difference(OFlags::NONBLOCK))?;
        Ok(file)
    }

    /// The descriptor the directory was made of, which it is taken apart
    /// for. A caller of the C API lends its descriptor to a directory and
    /// gets it back this way, so that nothing closes it.
    #[cfg(feature = "capi")]
    pub(crate) fn into_fd(self) -> OwnedFd {
        self.root.into()
    }

    /// Pins the file `file` names below the directory and checks that it
    /// is a regular file. Returns it with its size.
    fn pin(&self, file: &Name) -> Result<(Handle, u64), OpenError> {
        let path = if file.is_root() {
            PinnedDirectory::ITSELF
        } else {
            file.as_str()
        };
        let pinned = self.root.resolve(path).map_err(pathrs_io_error)?;
        let stat = rustix::fs::fstat(&pinned).map_err(io::Error::from)?;
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(OpenError::NotRegular);
        }
        // The size of a regular file is never negative.
        let len = u64::try_from(stat.st_size).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        Ok((pinned, len))
    }

    /// Opens the regular file `pinned` refers to for reading, through the
    /// handle, as [`PinnedFile::reopen`] does.
    fn reopen(pinned: &Handle) -> io::Result<File> {
        PinnedFile::new(pinned.as_fd()).reopen()
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
    use crate::sys::{EmptyPath, EMPTYPATH};
    use crate::testing::TempDir;
    use crate::{
        ContentsObject, ContentsSource, DataCheck, DataLocation, DataProblem, DirectoryProvider, ErrorKind, NameBuf,
        Sha256, Sha256Context, SourceProblem,
    };
    use rustix::fs::{SeekFrom, CWD};
    use rustix::io::Errno;
    use std::fs;
    use std::io::Read;
    use std::os::unix::fs::{symlink, FileExt};
    use std::sync::atomic::Ordering;

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

    /// The contents object that has the data in the file `file`, from
    /// `offset` on.
    fn in_file(file: &str, offset: u64) -> ContentsObject {
        let mut contents = ContentsObject::new(ContentsSource::File(NameBuf::new(file).unwrap()));
        contents.set_offset(offset);
        contents
    }

    /// The object `name` of a regular file with the contents object
    /// `contents`, and with the size `size` if it gives one.
    fn part(name: &str, contents: ContentsObject, size: Option<u64>) -> FileObject {
        let mut object = FileObject::new(NameBuf::new(name).unwrap());
        object.set_contents(vec![contents]);
        object.set_size(size);
        object
    }

    /// The file `object` has its data in.
    fn external(object: &FileObject) -> ExternalFile<'_> {
        match object.data_location() {
            Ok(DataLocation::External(file)) => file,
            other => panic!("{:?}", other),
        }
    }

    /// Reads the data of `object` as a caller of open_data() does: from the
    /// offset on, as many bytes as the object says or all there are up to
    /// the end of the file, each piece through a check.
    fn data(dir: &PinnedDirectory, object: &FileObject) -> Result<Vec<u8>, Error> {
        let file = external(object);
        let opened = dir.open_data(object, &file)?;
        let mut check = DataCheck::new(object);
        let mut data = Vec::new();
        let mut buffer = [0u8; 4];
        let mut left = object.size().unwrap_or(u64::MAX);
        while left > 0 {
            let want = usize::try_from(left).map_or(buffer.len(), |left| left.min(buffer.len()));
            let at = file.offset() + data.len() as u64;
            let read = opened.read_at(&mut buffer[..want], at).unwrap();
            if read == 0 {
                break;
            }
            check.update(&buffer[..read])?;
            data.extend_from_slice(&buffer[..read]);
            left -= read as u64;
        }
        assert_eq!(check.finish()?, data.len() as u64);
        Ok(data)
    }

    /// open_data() opens the file the data of an object is in: the file of
    /// its own name, or the one its contents object names. The data is in
    /// it from the offset on, as long as the object says or up to the end
    /// of the file, and a caller reads it from there and checks it.
    #[test]
    fn opens_the_file_the_data_is_in() {
        let tmp = TempDir::new("pinned-data");
        let dir = &tmp.0;
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("blob"), b"hello world").unwrap();
        fs::write(dir.join("sub/blob"), b"below").unwrap();
        fs::write(dir.join("empty"), b"").unwrap();
        let directory = PinnedDirectory::open(dir).unwrap();
        // A regular file without contents objects has its data in the file
        // of its name.
        let mut whole = FileObject::new(NameBuf::new("blob").unwrap());
        assert_eq!(data(&directory, &whole).unwrap(), b"hello world");
        whole.set_size(Some(11));
        whole.set_sha256(Some(Sha256::digest(b"hello world")));
        assert_eq!(data(&directory, &whole).unwrap(), b"hello world");
        for (file, offset, size, expected) in [
            ("sub/blob", 0, None, "below"),
            ("sub/blob", 0, Some(5), "below"),
            ("empty", 0, None, ""),
            ("empty", 0, Some(0), ""),
            // The start of a file that holds more, parts of it, and what
            // it holds from an offset on.
            ("blob", 0, Some(5), "hello"),
            ("blob", 6, Some(5), "world"),
            ("blob", 2, Some(3), "llo"),
            ("blob", 6, None, "world"),
            ("blob", 11, None, ""),
            ("blob", 11, Some(0), ""),
        ] {
            let object = part("x", in_file(file, offset), size);
            assert_eq!(
                data(&directory, &object).unwrap(),
                expected.as_bytes(),
                "{} {} {:?}",
                file,
                offset,
                size
            );
        }
        // The file is open for reading only, and without O_NONBLOCK, which
        // it was opened with: a caller gets a descriptor like any other. It
        // is the whole file, at its start, wherever the data is in it.
        let object = part("x", in_file("blob", 6), Some(5));
        let mut opened = directory.open_data(&object, &external(&object)).unwrap();
        let flags = rustix::fs::fcntl_getfl(&opened).unwrap();
        assert_eq!(flags & OFlags::RWMODE, OFlags::RDONLY);
        assert!(!flags.contains(OFlags::NONBLOCK));
        let mut text = String::new();
        opened.read_to_string(&mut text).unwrap();
        assert_eq!(text, "hello world");
        // Data that is not what the object says is found by the check of
        // the caller, not by the open.
        let mut object = part("x", in_file("blob", 6), Some(5));
        object.set_sha256(Some(Sha256::digest(b"world")));
        assert_eq!(data(&directory, &object).unwrap(), b"world");
        object.set_sha256(Some(Sha256::digest(b"hello")));
        let e = data(&directory, &object).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Data(DataProblem::HashMismatch));
    }

    /// open_data() opens nothing but a regular file below the directory
    /// that is long enough for the data. Its error says what is wrong with
    /// the file and names the object.
    #[test]
    fn opens_only_a_file_that_holds_the_data() {
        let tmp = TempDir::new("pinned-data-errors");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("root/sub")).unwrap();
        fs::write(dir.join("root/blob"), b"hello world").unwrap();
        fs::write(dir.join("outside"), b"outside").unwrap();
        symlink("blob", dir.join("root/link")).unwrap();
        symlink("../outside", dir.join("root/out")).unwrap();
        let fifo = dir.join("root/fifo");
        rustix::fs::mknodat(CWD, &fifo, FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        let directory = PinnedDirectory::open(dir.join("root")).unwrap();
        for (file, problem, errno, text) in [
            (
                "missing",
                SourceProblem::Missing,
                Some(libc::ENOENT),
                "x/y: failed to open missing: ",
            ),
            (
                "blob/below",
                SourceProblem::Missing,
                Some(libc::ENOTDIR),
                "x/y: failed to open blob/below: ",
            ),
            ("sub", SourceProblem::NotRegular, None, "x/y: sub is not a regular file"),
            // Nobody writes to the FIFO: it is refused before anything is
            // opened, so nothing waits for a writer.
            (
                "fifo",
                SourceProblem::NotRegular,
                None,
                "x/y: fifo is not a regular file",
            ),
            // A symbolic link is not followed, wherever it leads.
            (
                "link",
                SourceProblem::Unreadable,
                Some(libc::ELOOP),
                "x/y: failed to open link: ",
            ),
            (
                "out",
                SourceProblem::Unreadable,
                Some(libc::ELOOP),
                "x/y: failed to open out: ",
            ),
        ] {
            let object = part("x/y", in_file(file, 0), None);
            let e = directory.open_data(&object, &external(&object)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Source(problem), "{}", file);
            assert_eq!(e.name(), Some("x/y"), "{}", file);
            assert_eq!(e.io_error().and_then(io::Error::raw_os_error), errno, "{}", file);
            let cause = errno.map(|errno| io::Error::from_raw_os_error(errno).to_string());
            assert_eq!(e.to_string(), format!("{}{}", text, cause.unwrap_or_default()));
        }
        // The file of the name of the object, which is not there.
        let object = FileObject::new(NameBuf::new("sub/none").unwrap());
        let e = directory.open_data(&object, &external(&object)).unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Source(SourceProblem::Missing), Some("sub/none"))
        );
        // Where symbolic links are followed, one leads to the file it names
        // in the directory, and one that leads out of it to nothing.
        let following = PinnedDirectory::open(dir.join("root")).unwrap().follow_symlinks(true);
        let object = part("x/y", in_file("link", 6), Some(5));
        assert_eq!(data(&following, &object).unwrap(), b"world");
        let object = part("x/y", in_file("out", 0), None);
        let e = following.open_data(&object, &external(&object)).unwrap_err();
        assert_eq!(
            (e.kind(), e.io_error().and_then(io::Error::raw_os_error)),
            (ErrorKind::Source(SourceProblem::Missing), Some(libc::ENOENT))
        );
        // A file that is too short for the data: by one byte, for a part of
        // it, and for an offset behind its end.
        let mismatch = ErrorKind::Data(DataProblem::SizeMismatch);
        for (offset, size, text) in [
            (0, Some(12), "x/y: blob is too short for offset 0 and size 12"),
            (6, Some(6), "x/y: blob is too short for offset 6 and size 6"),
            (12, Some(0), "x/y: blob is too short for offset 12 and size 0"),
            (12, None, "x/y: blob is too short for offset 12 and size 0"),
        ] {
            let object = part("x/y", in_file("blob", offset), size);
            let e = directory.open_data(&object, &external(&object)).unwrap_err();
            assert_eq!(
                (e.kind(), e.name(), e.found_size(), e.expected_size()),
                (mismatch, Some("x/y"), Some(11), Some(12)),
                "{}",
                text
            );
            assert_eq!(e.to_string(), text);
        }
        // An offset and a size whose sum no number holds.
        let object = part("x/y", in_file("blob", u64::MAX), Some(5));
        let e = directory.open_data(&object, &external(&object)).unwrap_err();
        assert_eq!(
            (e.kind(), e.found_size(), e.expected_size()),
            (mismatch, Some(11), None)
        );
        // A file that is not as long as the manifest says the whole file
        // is, shorter or longer, fails the same way, as it does for a copy.
        for original_size in [10, 12] {
            let mut contents = in_file("blob", 0);
            contents.set_original_size(Some(original_size));
            let object = part("x/y", contents, Some(5));
            let e = directory.open_data(&object, &external(&object)).unwrap_err();
            assert_eq!(
                (e.kind(), e.name(), e.found_size(), e.expected_size()),
                (mismatch, Some("x/y"), Some(11), Some(original_size))
            );
            assert_eq!(
                e.to_string(),
                format!("x/y: blob is 11 bytes, the manifest says {}", original_size)
            );
        }
    }

    /// A file can hold the data of several objects. open_data() does not
    /// hold the data of one of them against the hash the manifest gives for
    /// the whole file, which a copy does. A caller that reads the whole
    /// file can.
    #[test]
    fn leaves_the_hash_of_the_whole_file_to_the_caller() {
        let tmp = TempDir::new("pinned-data-whole");
        let dir = &tmp.0;
        fs::write(dir.join("blob"), b"hello world").unwrap();
        let directory = PinnedDirectory::open(dir).unwrap();
        // The hash the manifest gives for the whole file: the one the file
        // has, and another one.
        for (original_sha256, matches) in [
            (Sha256::digest(b"hello world"), true),
            (Sha256::digest(b"another file"), false),
        ] {
            let mut provider = DirectoryProvider::new(PinnedDirectory::open(dir).unwrap());
            // Two parts of the file, without hashes of their own.
            for (name, offset, text) in [("first", 0, "hello"), ("second", 6, "world")] {
                let mut contents = in_file("blob", offset);
                contents.set_original_size(Some(11));
                contents.set_original_sha256(Some(original_sha256));
                let object = part(name, contents, Some(5));
                // The data passes the check of its object either way.
                assert_eq!(data(&directory, &object).unwrap(), text.as_bytes(), "{}", name);
                // A caller that wants the whole file checked reads it.
                let file = external(&object);
                let mut whole = Vec::new();
                let mut opened = directory.open_data(&object, &file).unwrap();
                opened.read_to_end(&mut whole).unwrap();
                assert_eq!(file.original_sha256() == Some(Sha256::digest(&whole)), matches);
                // A copy checks the whole file itself.
                let copied = object.copy_data(&mut provider, &mut Vec::new());
                let expected = if matches {
                    Ok(5)
                } else {
                    Err(ErrorKind::Data(DataProblem::HashMismatch))
                };
                assert_eq!(copied.map_err(|e| e.kind()), expected, "{}", name);
            }
        }
    }

    /// Reads the data of `object` as a tool does that skips the holes of a
    /// sparse file: what the file system says is a hole is not read, and
    /// goes into the check and into a hash as a run of zero bytes. Returns
    /// that hash. On a file system that knows no holes all of the file is
    /// data and is read.
    fn data_without_holes(dir: &PinnedDirectory, object: &FileObject) -> Result<Sha256, Error> {
        let file = external(object);
        let opened = dir.open_data(object, &file)?;
        let mut check = DataCheck::new(object);
        let mut context = Sha256Context::new();
        let mut buffer = [0u8; 4096];
        let mut at = file.offset();
        let end = at + object.size().unwrap();
        while at < end {
            // Where the next data is. ENXIO says that a hole reaches to the
            // end of the file.
            let data = match rustix::fs::seek(&opened, SeekFrom::Data(at)) {
                Ok(data) => data.min(end),
                Err(Errno::NXIO) => end,
                Err(e) => panic!("{}", e),
            };
            if data > at {
                check.update_zeros(data - at)?;
                context.update_zeros(data - at);
                at = data;
                continue;
            }
            let hole = rustix::fs::seek(&opened, SeekFrom::Hole(at)).unwrap().min(end);
            while at < hole {
                let want = usize::try_from(hole - at).map_or(buffer.len(), |left| left.min(buffer.len()));
                let read = opened.read_at(&mut buffer[..want], at).unwrap();
                assert_ne!(read, 0);
                check.update(&buffer[..read])?;
                context.update(&buffer[..read]);
                at += read as u64;
            }
        }
        check.finish()?;
        Ok(context.finalize())
    }

    /// The data of a sparse file passes its check and gets its hash
    /// without its holes being read: each goes in as a run of zero bytes,
    /// whether the data is all of the file or a part of it that starts or
    /// ends in a hole.
    #[test]
    fn reads_a_sparse_file_without_its_holes() {
        /// As large as the largest block of the file systems the tests run
        /// on, so that the file has holes there.
        const BLOCK: u64 = 64 * 1024;
        let tmp = TempDir::new("pinned-data-sparse");
        let dir = &tmp.0;
        // A hole, a block with data, a hole, a block with data and a hole.
        let sparse = File::create(dir.join("sparse")).unwrap();
        sparse.set_len(5 * BLOCK).unwrap();
        sparse.write_all_at(b"hello", BLOCK).unwrap();
        sparse.write_all_at(b"world", 3 * BLOCK + 7).unwrap();
        drop(sparse);
        let whole = fs::read(dir.join("sparse")).unwrap();
        let directory = PinnedDirectory::open(dir).unwrap();
        for (offset, size) in [
            (0, 5 * BLOCK),
            // From a hole to a hole, the data alone, from data to data, a
            // hole alone, and nothing at the end of the file.
            (BLOCK / 2, 2 * BLOCK),
            (BLOCK, 5),
            (BLOCK + 2, 2 * BLOCK + 8),
            (4 * BLOCK, BLOCK),
            (5 * BLOCK, 0),
        ] {
            let data = &whole[offset as usize..(offset + size) as usize];
            let mut object = part("x", in_file("sparse", offset), Some(size));
            object.set_sha256(Some(Sha256::digest(data)));
            let hash = data_without_holes(&directory, &object).unwrap();
            assert_eq!(hash, Sha256::digest(data), "{} {}", offset, size);
        }
        // An object that takes the file for a single hole: the data in it
        // fails the check.
        let mut object = part("x", in_file("sparse", 0), Some(5 * BLOCK));
        object.set_sha256(Some(Sha256::digest(&vec![0; whole.len()])));
        let e = data_without_holes(&directory, &object).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Data(DataProblem::HashMismatch));
    }
}
