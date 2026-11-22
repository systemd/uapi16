// SPDX-License-Identifier: LGPL-2.1-or-later
//! File objects from what the file system says of a file.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::object::{FileObject, InodeType, Mode, UnknownInodeType};
use crate::{Features, Name};

impl FileObject {
    /// A file object for the file `name`, whose metadata is `meta`, with
    /// the fields that `features` records, such as the features
    /// [`RootObject::recorded_features`] gives. So a writer refuses none of
    /// them for a manifest that records those features. The object has the
    /// type of the file, and where `features` records them the access mode,
    /// except on a symbolic link, the user and the group ID of the owner,
    /// the modification time where `mTimeNSec` can express it, the size of
    /// a regular file and the device numbers of a device node.
    ///
    /// It has no hash, no target of a symbolic link and no inode token, and
    /// the caller gives it those a manifest needs. One that records
    /// `symlink`, as [`Features::DEFAULT`] does, refuses a symbolic link
    /// without its target. One that records `hardlink`, as the default
    /// features do too, takes an object without a token for a file of no
    /// other name, so the files with more than one name need their tokens.
    ///
    /// It fails for a file whose type is not an inode type.
    ///
    /// [`RootObject::recorded_features`]: crate::RootObject::recorded_features
    pub fn from_metadata(name: Name, meta: &Metadata, features: Features) -> Result<FileObject, UnknownInodeType> {
        let mut object = FileObject::new(name);
        object.inode_type = InodeType::try_from(meta.file_type())?;
        let inode = &mut object.inode;
        if features.contains(Features::MODE) && object.inode_type != InodeType::Symlink {
            inode.mode = Some(Mode::from_st_mode(meta.mode()));
        }
        if features.contains(Features::UID) {
            inode.uid = Some(meta.uid());
        }
        if features.contains(Features::GID) {
            inode.gid = Some(meta.gid());
        }
        if features.contains(Features::MTIME) {
            if let Ok(time) = meta.modified() {
                inode.set_mtime(time);
            }
        }
        if features.contains(Features::SIZE) && object.inode_type == InodeType::Regular {
            object.size = Some(meta.len());
        }
        if features.contains(Features::DEVICE) && object.inode_type.is_device() {
            let device = meta.rdev();
            object.major = Some(u64::from(rustix::fs::major(device)));
            object.minor = Some(u64::from(rustix::fs::minor(device)));
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::object::{ContentsObject, ContentsSource, InodeAttributes};
    use crate::testing::TempDir;
    use crate::{RootObject, Writer};
    use rustix::fs::{FileType, CWD};
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    /// Every type of file a test can make, and a device node every system
    /// has, with the fields each set of features gives them. A writer takes
    /// the objects for a manifest that records the same features.
    #[test]
    fn objects_of_every_inode_type() {
        let tmp = TempDir::new("metadata");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"hello").unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        let fifo_mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
        rustix::fs::mknodat(CWD, dir.join("fifo"), FileType::Fifo, fifo_mode, 0).unwrap();
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        // In the order of their names, as the writer wants them.
        let files = [
            ("dir", dir.join("dir"), InodeType::Directory),
            ("fifo", dir.join("fifo"), InodeType::Fifo),
            ("file", dir.join("file"), InodeType::Regular),
            ("link", dir.join("link"), InodeType::Symlink),
            ("null", PathBuf::from("/dev/null"), InodeType::CharDevice),
            ("socket", dir.join("socket"), InodeType::Socket),
        ];
        for features in [Features::NONE, Features::DEFAULT, Features::ALL] {
            let mut root = RootObject::default();
            root.set_features(Some(features));
            let mut writer = Writer::begin(Vec::new(), &root).unwrap();
            for (name, path, inode_type) in &files {
                let meta = fs::symlink_metadata(path).unwrap();
                let mut object = FileObject::from_metadata(Name::new(*name).unwrap(), &meta, features).unwrap();
                assert_eq!(object.inode_type(), *inode_type, "{}", name);
                let has = |feature: Features| features.contains(feature);
                let mut inode = InodeAttributes {
                    mode: (has(Features::MODE) && *inode_type != InodeType::Symlink)
                        .then(|| Mode::from_st_mode(meta.mode())),
                    uid: has(Features::UID).then(|| meta.uid()),
                    gid: has(Features::GID).then(|| meta.gid()),
                    ..InodeAttributes::default()
                };
                if has(Features::MTIME) {
                    inode.set_mtime(meta.modified().unwrap());
                }
                assert_eq!(object.inode(), &inode, "{}", name);
                let size = (has(Features::SIZE) && *inode_type == InodeType::Regular).then_some(5);
                assert_eq!(object.size(), size, "{}", name);
                let device = (has(Features::DEVICE) && inode_type.is_device()).then(|| {
                    let device = meta.rdev();
                    (
                        u64::from(rustix::fs::major(device)),
                        u64::from(rustix::fs::minor(device)),
                    )
                });
                assert_eq!(object.major().zip(object.minor()), device, "{}", name);
                assert_eq!(
                    (object.sha256(), object.contents().len(), object.inode_token()),
                    (None, 0, None)
                );
                assert!(features.contains(object.stated_features()), "{}", name);
                // The target of a symbolic link comes from the caller, where
                // the manifest records it.
                if *inode_type == InodeType::Symlink && has(Features::SYMLINK) {
                    let target = fs::read_link(path).unwrap().into_os_string().into_vec();
                    object.set_contents(vec![ContentsObject::new(ContentsSource::Literal(target))]);
                }
                writer.file(&object).unwrap_or_else(|e| panic!("{}: {}", name, e));
            }
            writer.finish().unwrap();
        }
    }
}
