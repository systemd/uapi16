// SPDX-License-Identifier: LGPL-2.1-or-later
//! File objects from what the file system says of a file.

use std::fs::Metadata;
use std::os::unix::fs::MetadataExt;

use crate::object::{FileObject, InodeType, Mode, UnknownInodeType};
use crate::{Features, NameBuf};

impl FileObject {
    /// A file object for the file `name`, whose metadata is `meta`, with
    /// the fields that `features` records, such as the features
    /// [`RootObject::recorded_features`] gives. So a writer refuses none of
    /// them for a manifest that records those features. The object has the
    /// type of the file, and where `features` records them the access mode,
    /// except on a symbolic link, the user and the group ID of the owner
    /// where a manifest can record them, the modification time where
    /// `mTimeNSec` can express it, the size of a regular file and the
    /// device numbers of a device node.
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
    pub fn from_metadata(name: NameBuf, meta: &Metadata, features: Features) -> Result<FileObject, UnknownInodeType> {
        let mut object = FileObject::new(name);
        object.inode_type = InodeType::try_from(meta.file_type())?;
        let inode = &mut object.inode;
        if features.contains(Features::MODE) && object.inode_type != InodeType::Symlink {
            inode.mode = Some(Mode::from_st_mode(meta.mode()));
        }
        // A manifest can't record the two IDs that stand for no ID, and a
        // writer refuses them.
        if features.contains(Features::UID) {
            inode.uid = Some(meta.uid()).filter(|&uid| FileObject::is_valid_id(uid));
        }
        if features.contains(Features::GID) {
            inode.gid = Some(meta.gid()).filter(|&gid| FileObject::is_valid_id(gid));
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
    use crate::{ErrorKind, Field, Problem, RootObject, Writer};
    use rustix::fs::{FileType, CWD};
    use std::fs;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::{Path, PathBuf};
    use std::process::Command;

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
                let mut object = FileObject::from_metadata(NameBuf::new(*name).unwrap(), &meta, features).unwrap();
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

    /// The variable that names the file the test binary looks at where it
    /// runs [`owners_a_manifest_cannot_record`] again in a user namespace.
    const NO_OWNER_FILE: &str = "UAPI16_TEST_METADATA_NO_OWNER_FILE";

    /// The variable that says which IDs of the test that user namespace
    /// maps: its user, its group, or both.
    const NO_OWNER_MAPS: &str = "UAPI16_TEST_METADATA_NO_OWNER_MAPS";

    /// The ID a user namespace of the test maps the user or the group of
    /// the test to: the one of the two IDs that stand for no ID that a file
    /// can have.
    const NO_ID: u32 = u16::MAX as u32;

    /// A file whose owner has the user or the group ID 65535 gets an
    /// object without that ID, since a manifest can't record it, and with
    /// the other one. A writer takes the object, and refuses it with the ID
    /// that was left out. The file is one of the test's own, seen from a
    /// user namespace that maps the user of the test to that ID, its
    /// group, or both. The one that is not mapped shows as the overflow
    /// ID, which a manifest can record, so that the user ID is told by
    /// itself and not by the group ID, and the other way round.
    /// unshare(1) makes the namespaces, and the test binary runs this test
    /// again in each. It is skipped where unshare can't do that.
    ///
    /// No stat() gives the other ID a manifest can't record, 4294967295:
    /// the kernel shows an owner it can't map as the overflow ID. So what
    /// tells the two IDs from all others is asked for it directly.
    #[test]
    fn owners_a_manifest_cannot_record() {
        if let Some(file) = std::env::var_os(NO_OWNER_FILE) {
            let maps = std::env::var(NO_OWNER_MAPS).unwrap();
            return check_no_owner(Path::new(&file), maps.contains("user"), maps.contains("group"));
        }
        for id in [NO_ID, u32::MAX] {
            assert!(!FileObject::is_valid_id(id), "{}", id);
        }
        for id in [0, NO_ID - 1, NO_ID + 1, u32::MAX - 1] {
            assert!(FileObject::is_valid_id(id), "{}", id);
        }
        let tmp = TempDir::new("metadata-no-owner");
        // A setgid directory hands its group down to the file. The group
        // unshare maps is that of this process.
        fs::set_permissions(&tmp.0, fs::Permissions::from_mode(0o700)).unwrap();
        let file = tmp.0.join("file");
        fs::write(&file, b"hello").unwrap();
        for maps in [&["user", "group"][..], &["user"], &["group"]] {
            let mut map = vec!["--user".to_owned()];
            map.extend(maps.iter().map(|id| format!("--map-{}={}", id, NO_ID)));
            let works = Command::new("unshare").args(&map).arg("true").output();
            if !works.is_ok_and(|output| output.status.success()) {
                eprintln!("skipping: unshare {} does not work here", map.join(" "));
                return;
            }
            let output = Command::new("unshare")
                .args(&map)
                .arg(std::env::current_exe().unwrap())
                .args(["--exact", "metadata::tests::owners_a_manifest_cannot_record"])
                .env(NO_OWNER_FILE, &file)
                .env(NO_OWNER_MAPS, maps.join(" "))
                .output()
                .unwrap();
            // A test binary that runs no test succeeds as well.
            let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
            assert!(output.status.success() && ran, "{:?}: {:?}", maps, output);
        }
    }

    /// The checks of [`owners_a_manifest_cannot_record`] for `file`, in a
    /// user namespace that maps the user of the test to [`NO_ID`] if
    /// `user` says so, and its group if `group` does.
    fn check_no_owner(file: &Path, user: bool, group: bool) {
        let meta = fs::metadata(file).unwrap();
        assert!(!user || meta.uid() == NO_ID, "{}", meta.uid());
        assert!(!group || meta.gid() == NO_ID, "{}", meta.gid());
        // The ID a manifest can't record is left out, and no other.
        let kept = |id: u32| Some(id).filter(|&id| id != NO_ID);
        for features in [Features::UID | Features::GID, Features::ALL] {
            let name = NameBuf::new("file").unwrap();
            let object = FileObject::from_metadata(name, &meta, features).unwrap();
            assert_eq!(
                (object.inode().uid, object.inode().gid),
                (kept(meta.uid()), kept(meta.gid()))
            );
            // What a manifest can record of the file is there.
            let all = features == Features::ALL;
            assert_eq!(object.inode().mode.is_some(), all);
            assert_eq!(object.size(), all.then_some(5));
            let mut root = RootObject::default();
            root.set_features(Some(features));
            let mut writer = Writer::begin(Vec::new(), &root).unwrap();
            writer.file(&object).unwrap();
            // With the ID that was left out, the writer refuses the object.
            for (field, left_out) in [(Field::Uid, meta.uid()), (Field::Gid, meta.gid())] {
                if left_out != NO_ID {
                    continue;
                }
                let mut refused = object.clone();
                refused.name = NameBuf::new("refused").unwrap();
                match field {
                    Field::Uid => refused.inode.uid = Some(meta.uid()),
                    _ => refused.inode.gid = Some(meta.gid()),
                }
                let e = writer.file(&refused).unwrap_err();
                assert_eq!(
                    (e.kind(), e.field()),
                    (ErrorKind::Manifest(Problem::FieldOutOfRange), Some(field))
                );
            }
            writer.finish().unwrap();
        }
    }
}
