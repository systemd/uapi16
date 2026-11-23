// SPDX-License-Identifier: LGPL-2.1-or-later
//! Where a manifest that is being built keeps what it cannot keep in
//! memory: in files without names, which are made when they are first
//! needed. A manifest of a small tree never needs one, and nothing is
//! opened for it.
//!
//! A manifest that is created as a file keeps them in the directory it is
//! created in, which has the room for the manifest as well, through the
//! descriptor the file has of that directory. Any other keeps them in the
//! directory `TMPDIR` names, and in /var/tmp where that names none: /tmp is
//! often memory, and what goes here is what did not fit into memory. A
//! `TMPDIR` that is set is used as it is, also where it is in memory, which
//! is its user's choice.
//!
//! Either directory can be in a tree the manifest lists, and a file
//! system can show a file without a name in its directory all the same. So
//! every scratch file is one of the files of the manifest's own, which a
//! walk passes over, and it stays open with them once it is given back, see
//! [`OwnFiles`]. A file that was given back is handed out again before a
//! new one is made. So no more files are made than are used at one time.

use std::env;
use std::ffi::OsString;
use std::io;
use std::os::fd::{AsFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::error::Error;
use crate::sys::{OwnFiles, ScratchFile};

/// The scratch space of a manifest that is being built: the directory its
/// scratch files are made in, and the files of the manifest's own, which
/// they are among.
#[derive(Debug)]
pub(crate) struct Scratch {
    /// The directory, if it was given or if a file was made already. One
    /// that was given is shared with whoever gave it.
    directory: Option<Arc<OwnedFd>>,
    /// The files the manifest made itself and has open. Every file made
    /// here is one of them, and they keep it open and hand it out again
    /// once it was given back.
    own: OwnFiles,
}

impl Scratch {
    /// The variable that names the directory for temporary files.
    const TMPDIR: &'static str = "TMPDIR";
    /// Where temporary files go that can be large, without that variable.
    const VAR_TMP: &'static str = "/var/tmp";

    /// Scratch space in `directory`, the directory a manifest is created
    /// in, which the new file keeps open as well.
    pub(crate) fn beside(directory: Arc<OwnedFd>) -> Scratch {
        Scratch {
            directory: Some(directory),
            own: OwnFiles::default(),
        }
    }

    /// Scratch space in the directory for temporary files. The directory
    /// is looked for and opened when the first file is made, so one that
    /// is not there only fails a manifest that needs it.
    pub(crate) fn temporary() -> Scratch {
        Scratch {
            directory: None,
            own: OwnFiles::default(),
        }
    }

    /// The files the manifest made itself and has open, for whoever walks a
    /// tree for the manifest and passes over them. They are there, and the
    /// scratch files among them open, until this scratch space is dropped.
    pub(crate) fn own_files(&self) -> &OwnFiles {
        &self.own
    }

    /// The directory for temporary files, where `tmpdir` is the value of
    /// `TMPDIR`: the one it names, or /var/tmp if it is not set or empty.
    fn temporary_directory(tmpdir: Option<OsString>) -> PathBuf {
        match tmpdir {
            Some(directory) if !directory.is_empty() => PathBuf::from(directory),
            _ => PathBuf::from(Scratch::VAR_TMP),
        }
    }

    /// Hands out a scratch file, which is empty, and one of the files of
    /// the manifest's own: one that was made here and given back since, if
    /// there is one, and a new one otherwise. A file that could not be
    /// emptied when it was given back is not handed out again. The first
    /// file in the directory for temporary files opens the directory, and
    /// where it can't be opened or the file can't be made in it, the error
    /// says which directory it is.
    pub(crate) fn file(&mut self) -> io::Result<ScratchFile> {
        if let Some(file) = self.own.hand_out() {
            return Ok(file);
        }
        if let Some(directory) = &self.directory {
            return ScratchFile::create_in(directory.as_fd(), &mut self.own);
        }
        let tmpdir = env::var_os(Scratch::TMPDIR);
        let named = tmpdir.as_ref().is_some_and(|tmpdir| !tmpdir.is_empty());
        let path = Scratch::temporary_directory(tmpdir);
        let first = ScratchFile::open_directory(&path).and_then(|directory| {
            let file = ScratchFile::create_in(directory.as_fd(), &mut self.own)?;
            Ok((directory, file))
        });
        let (directory, file) = first.map_err(|e| Error::io_about(Scratch::unusable(named, &path), e))?;
        self.directory = Some(Arc::new(directory));
        Ok(file)
    }

    /// Takes back the scratch file `file`, which was made here and which
    /// whoever had it is done with. It is emptied, which gives its room
    /// back, and handed out again before a new file is made. A file that is
    /// dropped instead is left as it is, and is closed with the others.
    pub(crate) fn take_back(&mut self, file: ScratchFile) {
        self.own.take_back(file);
    }

    /// What an error says of `path`, the directory for temporary files,
    /// which can't be used, where `named` says whether `TMPDIR` names it.
    fn unusable(named: bool, path: &Path) -> String {
        if named {
            format!(
                "the directory {} names, '{}', cannot be used",
                Scratch::TMPDIR,
                path.display()
            )
        } else {
            format!(
                "{} names no directory, and '{}' cannot be used",
                Scratch::TMPDIR,
                path.display()
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{OpenFile, TempDir};
    use crate::tree::InodeId;
    use std::collections::HashSet;
    use std::fs;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Command;

    /// The variable that tells the test binary, run again by
    /// [`temporary_directory_of_the_environment`], which directory the
    /// scratch space has to be in, or that there has to be none.
    const EXPECTED: &str = "UAPI16_TEST_SCRATCH_DIR";
    /// What that variable says where no directory can be opened.
    const NONE: &str = "none";

    /// The device and the inode number of the directory `scratch` makes
    /// its files in.
    fn directory_of(scratch: &Scratch) -> (u64, u64) {
        let directory = scratch.directory.as_ref().unwrap();
        let meta = fs::metadata(format!("/proc/self/fd/{}", directory.as_raw_fd())).unwrap();
        (meta.dev(), meta.ino())
    }

    /// The device and the inode number of the directory `path`.
    fn identity(path: &Path) -> (u64, u64) {
        let meta = fs::metadata(path).unwrap();
        (meta.dev(), meta.ino())
    }

    /// The directory for temporary files is the one `TMPDIR` names, and
    /// /var/tmp without one.
    #[test]
    fn temporary_directories() {
        let directory = |tmpdir: Option<&str>| Scratch::temporary_directory(tmpdir.map(OsString::from));
        assert_eq!(directory(None), Path::new("/var/tmp"));
        assert_eq!(directory(Some("")), Path::new("/var/tmp"));
        assert_eq!(directory(Some("/tmp")), Path::new("/tmp"));
        assert_eq!(directory(Some("relative/dir")), Path::new("relative/dir"));
    }

    /// Scratch space next to a manifest makes its files in the directory
    /// it was given, without a name, and every file is a new one.
    #[test]
    fn beside_a_manifest() {
        let tmp = TempDir::new("scratch-beside");
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        let mut scratch = Scratch::beside(directory.into());
        assert_eq!(directory_of(&scratch), identity(&tmp.0));
        let first = scratch.file().unwrap();
        let second = scratch.file().unwrap();
        first.write_all_at(b"first", 0).unwrap();
        second.write_all_at(b"second", 0).unwrap();
        let mut read = [0; 5];
        first.read_exact_at(&mut read, 0).unwrap();
        assert_eq!(&read, b"first");
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
        assert_eq!(directory_of(&scratch), identity(&tmp.0));
    }

    /// Every file of the scratch space is one of the files of its manifest,
    /// by the inode and the status a walk finds for it. One that is given
    /// back is emptied, and it stays open and one of them until the scratch
    /// space is dropped. Then it is closed. Until then it is handed out
    /// again, empty, before a new file is made.
    #[test]
    fn files_are_own_files() {
        let tmp = TempDir::new("scratch-own");
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        let mut scratch = Scratch::beside(directory.into());
        assert!(OpenFile::made_in(&tmp.0).is_empty());
        const DATA: &[u8] = b"data";
        let first = scratch.file().unwrap();
        first.write_all_at(DATA, 0).unwrap();
        let one = OpenFile::made_in(&tmp.0);
        assert_eq!(one.len(), 1);
        let own = scratch.own_files();
        assert!(own.contains(&one[0].status).unwrap() && one[0].size == DATA.len() as u64);
        let second = scratch.file().unwrap();
        second.write_all_at(DATA, 0).unwrap();
        let both = OpenFile::made_in(&tmp.0);
        assert_eq!(both.len(), 2);
        let own = scratch.own_files();
        assert!(both.iter().all(|file| own.contains(&file.status).unwrap()));
        scratch.take_back(first);
        let mut left = OpenFile::made_in(&tmp.0);
        left.sort_by_key(|file| file.size);
        assert_eq!(left.len(), 2);
        assert_eq!((left[0].inode, left[0].size), (one[0].inode, 0));
        assert_eq!(left[1].size, DATA.len() as u64);
        let own = scratch.own_files();
        assert!(left.iter().all(|file| own.contains(&file.status).unwrap()));
        scratch.take_back(second);
        let left = OpenFile::made_in(&tmp.0);
        assert_eq!(left.len(), 2);
        let own = scratch.own_files();
        assert!(left
            .iter()
            .all(|file| file.size == 0 && own.contains(&file.status).unwrap()));
        // The two that were given back are handed out again before a new
        // file is made, which the next one is.
        let inodes = |files: &[OpenFile]| -> HashSet<InodeId> { files.iter().map(|file| file.inode).collect() };
        let (third, fourth) = (scratch.file().unwrap(), scratch.file().unwrap());
        third.write_all_at(DATA, 0).unwrap();
        let mut open = OpenFile::made_in(&tmp.0);
        open.sort_by_key(|file| file.size);
        assert_eq!(inodes(&open), inodes(&left));
        assert_eq!((open[0].size, open[1].size), (0, DATA.len() as u64));
        let fifth = scratch.file().unwrap();
        let made = OpenFile::made_in(&tmp.0);
        assert_eq!(made.len(), 3);
        let own = scratch.own_files();
        assert!(made.iter().all(|file| own.contains(&file.status).unwrap()));
        // The scratch space of another manifest has files of its own, and
        // hands out none of these.
        let mut other = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        assert!(made
            .iter()
            .all(|file| !other.own_files().contains(&file.status).unwrap()));
        scratch.take_back(third);
        let of_other = other.file().unwrap();
        assert_eq!(OpenFile::made_in(&tmp.0).len(), 4);
        drop((of_other, other));
        assert_eq!(inodes(&OpenFile::made_in(&tmp.0)), inodes(&made));
        // A file that is still used outlives its scratch space, which
        // closes the others.
        drop(fourth);
        drop(scratch);
        assert_eq!(OpenFile::made_in(&tmp.0).len(), 1);
        drop(fifth);
        assert!(OpenFile::made_in(&tmp.0).is_empty());
    }

    /// Scratch space for temporary files opens nothing until a file is
    /// made. Then it is in the directory the environment names, or in
    /// /var/tmp, and a directory that is not there fails with its own
    /// error, which names it, instead of falling back to another one. The
    /// environment is that of a process, so the test binary runs this test
    /// again in one of its own for each case.
    #[test]
    fn temporary_directory_of_the_environment() {
        if let Some(expected) = env::var_os(EXPECTED) {
            let expected = Path::new(&expected);
            // The files this process makes in the directory are those it
            // has open there that it did not have open before: a descriptor
            // it inherited can be of a file in the directory as well.
            let inherited = if expected.is_dir() {
                OpenFile::made_in(expected)
            } else {
                Vec::new()
            };
            let made = || {
                let mut open = OpenFile::made_in(expected);
                open.retain(|file| inherited.iter().all(|other| other.inode != file.inode));
                open
            };
            let mut scratch = Scratch::temporary();
            assert!(scratch.directory.is_none());
            match scratch.file() {
                Ok(file) => {
                    assert_eq!(directory_of(&scratch), identity(expected));
                    // The first file, which opened the directory, is one of
                    // the files of the manifest's own as well, and stays
                    // one, and open, once it is given back.
                    let first = made();
                    assert_eq!(first.len(), 1);
                    assert!(scratch.own_files().contains(&first[0].status).unwrap());
                    scratch.take_back(file);
                    let left = made();
                    assert_eq!(left.len(), 1);
                    assert_eq!((left[0].inode, left[0].size), (first[0].inode, first[0].size));
                    assert!(scratch.own_files().contains(&left[0].status).unwrap());
                }
                Err(e) => {
                    assert_eq!(expected, Path::new(NONE), "{}", e);
                    let e = Error::from(e);
                    assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::ENOENT));
                    let said = match env::var_os(Scratch::TMPDIR).filter(|tmpdir| !tmpdir.is_empty()) {
                        Some(tmpdir) => format!(
                            "the directory TMPDIR names, '{}', cannot be used",
                            Path::new(&tmpdir).display()
                        ),
                        None => "TMPDIR names no directory, and '/var/tmp' cannot be used".to_string(),
                    };
                    let enoent = io::Error::from_raw_os_error(libc::ENOENT);
                    assert_eq!(e.to_string(), format!("{}: {}", said, enoent));
                    assert!(scratch.directory.is_none());
                }
            }
            return;
        }
        let tmp = TempDir::new("scratch-environment");
        let run = |tmpdir: Option<&Path>, expected: &Path| {
            let mut test = Command::new(env::current_exe().unwrap());
            test.args(["--exact", "scratch::tests::temporary_directory_of_the_environment"]);
            test.env(EXPECTED, expected);
            match tmpdir {
                Some(tmpdir) => test.env(Scratch::TMPDIR, tmpdir),
                None => test.env_remove(Scratch::TMPDIR),
            };
            let output = test.output().unwrap();
            assert!(output.status.success(), "{:?} {:?}: {:?}", tmpdir, expected, output);
        };
        run(Some(&tmp.0), &tmp.0);
        run(Some(&tmp.0.join("missing")), Path::new(NONE));
        // Without the variable, and with an empty one, /var/tmp, where
        // there is one that takes files.
        let var_tmp = Path::new(Scratch::VAR_TMP);
        let expected = match ScratchFile::open_directory(var_tmp) {
            Ok(directory) if ScratchFile::create_in(directory.as_fd(), &mut OwnFiles::default()).is_ok() => var_tmp,
            Ok(_) => {
                eprintln!("skipping /var/tmp, which takes no files");
                return;
            }
            Err(_) => Path::new(NONE),
        };
        run(None, expected);
        run(Some(Path::new("")), expected);
    }

    /// The scratch space of a manifest can go to another thread.
    #[test]
    fn send() {
        fn send<T: Send>() {}
        send::<Scratch>();
    }
}
