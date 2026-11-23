// SPDX-License-Identifier: LGPL-2.1-or-later
//! What the features of a manifest record of a file of a tree that statx()
//! does not say: its inode flags, its DOS attributes, whether it is
//! read-only, its extended attributes and the names of its owners, and for
//! the root of the tree the identity of its file system.
//!
//! A feature that was asked for and that cannot be read is an error that
//! names the feature. A field that is missing where its feature is recorded
//! says that a flag is cleared, that a file has no extended attributes or
//! that a file system has no label, so leaving one out would claim what
//! nobody read. Three things never fail. The name of an owner that the
//! user database does not have is left out and counted, as the
//! specification gives a missing name no meaning. The UUID and the volume
//! serial number of a file system that has none are left out: the
//! specification leaves a missing one to whoever makes the file system.
//! And whether a file is read-only can always be told from its mode.

use std::collections::HashMap;
use std::hash::Hash;

use rustix::fs::FileType;

use crate::object::{
    DosFlags, FileObject, FileSystemIdentity, FlagSet, FlagStates, InodeAttributes, InodeFlags, RootObject, Uuid,
};
use crate::sys::{DosAttributes, FsLabel, FsUuid, Readable, UserDatabase, UserXattrs};
use crate::tree::{DeviceNumber, Entry, Failure, MountId, Place, Unreadable};
use crate::Features;

/// Answers that are asked for again and again, kept by what was asked. It
/// keeps so many at most. Full, it forgets them all, so that no tree can
/// make it grow, and each is asked for once more.
#[derive(Debug)]
struct Cache<K, V> {
    answers: HashMap<K, V>,
    /// How many answers are kept at most.
    most: usize,
}

impl<K: Eq + Hash, V> Cache<K, V> {
    /// A cache of at most `most` answers.
    fn new(most: usize) -> Cache<K, V> {
        Cache {
            answers: HashMap::new(),
            most,
        }
    }

    /// The answer kept for `key`.
    fn get(&self, key: &K) -> Option<&V> {
        self.answers.get(key)
    }

    /// Keeps `answer` for `key`.
    fn insert(&mut self, key: K, answer: V) {
        if self.answers.len() >= self.most {
            self.answers.clear();
        }
        self.answers.insert(key, answer);
    }
}

/// The names of the owners of the files of a tree, as the user database of
/// the host has them. The names are the view of the host, which need not
/// be that of the tree, so a manifest only records them where it is asked
/// to. Each ID is looked up once: what was found is kept, also that there
/// is no name, the way systemd's manifest_resolve_name() keeps it.
#[derive(Debug)]
struct OwnerNames {
    database: UserDatabase,
    users: Cache<u32, Option<Box<str>>>,
    groups: Cache<u32, Option<Box<str>>>,
}

impl OwnerNames {
    /// How many users and how many groups are kept.
    const KEPT: usize = 16384;

    fn new() -> OwnerNames {
        OwnerNames {
            database: UserDatabase::new(),
            users: Cache::new(OwnerNames::KEPT),
            groups: Cache::new(OwnerNames::KEPT),
        }
    }

    /// The name of the user `uid`, if it has one a manifest can hold.
    fn user(&mut self, uid: u32) -> Option<Box<str>> {
        if let Some(name) = self.users.get(&uid) {
            return name.clone();
        }
        let name = self.database.user_name(uid).map(String::into_boxed_str);
        self.users.insert(uid, name.clone());
        name
    }

    /// The name of the group `gid`, if it has one a manifest can hold.
    fn group(&mut self, gid: u32) -> Option<Box<str>> {
        if let Some(name) = self.groups.get(&gid) {
            return name.clone();
        }
        let name = self.database.group_name(gid).map(String::into_boxed_str);
        self.groups.insert(gid, name.clone());
        name
    }
}

/// Reads what the features of a manifest record of the files of a tree
/// beyond what statx() says of each, see the documentation of this module.
///
/// It reads through the handle of an entry where that is enough. Where it
/// takes the file itself, for its inode flags, its DOS attributes or the
/// identity of its file system, it opens the regular file or the directory,
/// see [`Entry::reopen`], unless the caller did so already, and leaves it
/// open for the caller. Nothing else is opened, and nothing is opened for
/// its extended attributes: they are read through the file where it is
/// open, and through its handle where it is not, see [`UserXattrs`]. An
/// automount point is not opened at all, see [`Entry::is_automount`], so
/// what takes the open file can't be read of it.
#[derive(Debug)]
pub(crate) struct FeatureReader {
    features: Features,
    /// The inode flags the features record.
    inode_flags: InodeFlags,
    /// The DOS attributes the features record.
    dos_flags: DosFlags,
    names: OwnerNames,
    xattrs: UserXattrs,
    /// Whether the files of a file system have DOS attributes, for the
    /// file systems that were asked so far. A file system is a device as
    /// one mount shows it.
    dos_attributes: Cache<(MountId, DeviceNumber), bool>,
}

impl FeatureReader {
    /// The features that record the identity of a file system.
    const IDENTITY: Features = Features::FAT_SERIAL.union(Features::FS_LABEL).union(Features::FS_UUID);
    /// How many file systems it is kept for whether they have DOS
    /// attributes.
    const FILE_SYSTEMS: usize = 1024;

    /// A reader for a manifest that records `features`.
    pub(crate) fn new(features: Features) -> FeatureReader {
        FeatureReader {
            features,
            inode_flags: InodeFlags::recorded_by(features),
            dos_flags: DosFlags::recorded_by(features),
            names: OwnerNames::new(),
            xattrs: UserXattrs::new(),
            dos_attributes: Cache::new(FeatureReader::FILE_SYSTEMS),
        }
    }

    /// Reads what the features record of the file of `entry`, which is not
    /// the root of the tree, into `object`. `place` is where the entry is,
    /// which a directory is opened by, see [`Entry::reopen`]. `opened` is
    /// the file opened for reading, if it is, and is filled in where this
    /// opens it. Returns how many fields were left out: the names of owners
    /// that have none.
    pub(crate) fn read(
        &mut self,
        entry: &Entry<'_>,
        place: Option<Place<'_>>,
        opened: &mut Option<Readable>,
        object: &mut FileObject,
    ) -> Result<u64, Failure> {
        let mut read_only = None;
        // Only regular files and directories have inode flags and DOS
        // attributes.
        if matches!(entry.status().file_type, FileType::RegularFile | FileType::Directory) {
            self.read_inode_flags(entry, place, opened, &mut object.inode)?;
            read_only = self.read_dos_attributes(entry, place, opened, &mut object.dos_flags)?;
        }
        self.read_inode(entry, opened, read_only, &mut object.inode)
    }

    /// Reads what the features record of the root of the tree, the
    /// directory of `entry`, into `root`, as [`FeatureReader::read`] does
    /// for the other files. The root has no DOS attributes, as the root
    /// directory of a FAT file system has no directory entry to keep them
    /// in, and it has the identity of its file system. It is the directory
    /// of a descriptor of a caller, which has no name to be opened by.
    /// Returns how many fields were left out: the names of owners that have
    /// none, and the UUID and the volume serial number of a file system
    /// that has none.
    pub(crate) fn read_root(
        &mut self,
        entry: &Entry<'_>,
        opened: &mut Option<Readable>,
        root: &mut RootObject,
    ) -> Result<u64, Failure> {
        debug_assert_eq!(entry.status().file_type, FileType::Directory);
        self.read_inode_flags(entry, None, opened, &mut root.inode)?;
        let identity = self.read_identity(entry, opened, &mut root.file_system)?;
        let names = self.read_inode(entry, opened, None, &mut root.inode)?;
        Ok(identity + names)
    }

    /// The file of `entry`, which is at `place`, open for reading: `opened`
    /// if it is, or else opened now, see [`Entry::reopen`], and kept in
    /// `opened`. It is opened for `feature`, which can't be read of an
    /// automount point, since that is not opened.
    fn open<'a>(
        entry: &Entry<'_>,
        place: Option<Place<'_>>,
        opened: &'a mut Option<Readable>,
        feature: Features,
    ) -> Result<&'a Readable, Failure> {
        let readable = match opened.take() {
            Some(readable) => readable,
            None if entry.is_automount() => return Err(Failure::Unavailable(feature, Unreadable::Automount)),
            None => entry.reopen(place)?,
        };
        Ok(opened.insert(readable))
    }

    /// Fails unless the file system of the directory of `entry`, that of a
    /// descriptor a caller gave, has DOS attributes, where the features
    /// record one of hidden, system and archive. A walk asks that of the
    /// directory it starts at before it adds anything: every file below it
    /// is asked for them, and the root of a tree itself has none to be
    /// asked for. The file system is asked the way its first file would
    /// ask it, and is not asked again. `opened` is as for
    /// [`FeatureReader::read`].
    pub(crate) fn check_dos_attributes(
        &mut self,
        entry: &Entry<'_>,
        opened: &mut Option<Readable>,
    ) -> Result<(), Failure> {
        debug_assert_eq!(entry.status().file_type, FileType::Directory);
        let Some(feature) = FeatureReader::first_feature(self.dos_flags) else {
            return Ok(());
        };
        match self.dos_attributes(entry, None, opened, feature)? {
            Some(_) => Ok(()),
            None => Err(Failure::Unavailable(feature, Unreadable::NoDosAttributes)),
        }
    }

    /// States each of the flags `recorded` in `states`: set if it is among
    /// `set`, and cleared if it is not.
    fn state<F: FlagSet>(states: &mut FlagStates<F>, recorded: F, set: F) {
        for &(flag, _, _) in F::FIELDS {
            if (recorded & flag) == flag {
                states.put(flag, Some((set & flag) == flag));
            }
        }
    }

    /// The feature of the first of the flags `recorded`, in the order of
    /// the names of their fields, which names an error about them all.
    fn first_feature<F: FlagSet>(recorded: F) -> Option<Features> {
        F::FIELDS
            .iter()
            .find(|&&(flag, _, _)| (recorded & flag) == flag)
            .map(|&(_, _, feature)| feature)
    }

    /// Reads the inode flags the features record of the regular file or
    /// the directory of `entry` into `inode`. A file system without inode
    /// flags cannot say that they are cleared.
    fn read_inode_flags(
        &mut self,
        entry: &Entry<'_>,
        place: Option<Place<'_>>,
        opened: &mut Option<Readable>,
        inode: &mut InodeAttributes,
    ) -> Result<(), Failure> {
        let Some(feature) = FeatureReader::first_feature(self.inode_flags) else {
            return Ok(());
        };
        match FeatureReader::open(entry, place, opened, feature)?.inode_flags()? {
            Some(set) => FeatureReader::state(&mut inode.flags, self.inode_flags, set),
            None => return Err(Failure::Unavailable(feature, Unreadable::NoInodeFlags)),
        }
        Ok(())
    }

    /// The DOS attributes of the regular file or the directory of `entry`,
    /// or nothing if its file system has none. A file system is asked with
    /// its first file, and one that has none is not asked again. They are
    /// read for `feature`.
    fn dos_attributes(
        &mut self,
        entry: &Entry<'_>,
        place: Option<Place<'_>>,
        opened: &mut Option<Readable>,
        feature: Features,
    ) -> Result<Option<DosAttributes>, Failure> {
        let identity = &entry.status().identity;
        let file_system = (identity.mount, identity.device);
        let known = self.dos_attributes.get(&file_system).copied();
        if known == Some(false) {
            return Ok(None);
        }
        let attributes = FeatureReader::open(entry, place, opened, feature)?.dos_attributes()?;
        if known.is_none() {
            self.dos_attributes.insert(file_system, attributes.is_some());
        }
        Ok(attributes)
    }

    /// Reads the DOS attributes the features record of the regular file or
    /// the directory of `entry`, which is not the root, into `flags`.
    /// Returns whether a regular file has the read-only attribute, where
    /// its file system has DOS attributes. The file system is only asked
    /// where its answer is used: for one of the attributes hidden, system
    /// and archive, or for whether a regular file is read-only.
    fn read_dos_attributes(
        &mut self,
        entry: &Entry<'_>,
        place: Option<Place<'_>>,
        opened: &mut Option<Readable>,
        flags: &mut FlagStates<DosFlags>,
    ) -> Result<Option<bool>, Failure> {
        let regular = entry.status().file_type == FileType::RegularFile;
        let feature = FeatureReader::first_feature(self.dos_flags);
        if feature.is_none() && !(regular && self.features.contains(Features::READ_ONLY)) {
            return Ok(None);
        }
        let asked_for = feature.unwrap_or(Features::READ_ONLY);
        let attributes = match (self.dos_attributes(entry, place, opened, asked_for), feature) {
            (Ok(attributes), _) => attributes,
            // Whether a file is read-only never fails: a file that cannot
            // be asked for its attribute has its mode.
            (Err(_), None) => None,
            (Err(failure), Some(_)) => return Err(failure),
        };
        match (attributes, feature) {
            (Some(attributes), _) => {
                FeatureReader::state(flags, self.dos_flags, attributes.flags());
                Ok(regular.then_some(attributes.is_read_only()))
            }
            (None, Some(feature)) => Err(Failure::Unavailable(feature, Unreadable::NoDosAttributes)),
            (None, None) => Ok(None),
        }
    }

    /// The label a manifest records for the answer `label` of a file
    /// system: none for the empty one.
    fn label(label: Option<FsLabel>) -> Result<Option<String>, Failure> {
        let unavailable = |why| Failure::Unavailable(Features::FS_LABEL, why);
        match label {
            Some(FsLabel::Label(label)) => Ok(Some(label)),
            Some(FsLabel::Empty) => Ok(None),
            Some(FsLabel::Unwritable) => Err(unavailable(Unreadable::LabelUnwritable)),
            None => Err(unavailable(Unreadable::NoLabel)),
        }
    }

    /// The UUID a manifest records for what a file system says it
    /// identifies itself with, in `identifier`. There is none where the
    /// file system has no identifier or the kernel can't be asked for it,
    /// and none where the identifier is no UUID: the one of all zeroes, or
    /// one of another size, as the volume serial number of FAT is.
    fn uuid(identifier: Option<FsUuid>) -> Option<Uuid> {
        match identifier {
            Some(FsUuid::Uuid(uuid)) => Some(uuid),
            Some(FsUuid::Null | FsUuid::NotUuid(_)) | None => None,
        }
    }

    /// Reads the identity of the file system the root of the tree, the
    /// directory of `entry`, is in into `identity`, as far as the features
    /// record it. A label that can't be read fails, since a root without
    /// one says that its file system has none. The UUID and the volume
    /// serial number are left out where the file system has none. An
    /// automount point, which is not opened, is not asked for them.
    /// Returns how many of the two were left out.
    fn read_identity(
        &mut self,
        entry: &Entry<'_>,
        opened: &mut Option<Readable>,
        identity: &mut FileSystemIdentity,
    ) -> Result<u64, Failure> {
        if (self.features & FeatureReader::IDENTITY) == Features::NONE {
            return Ok(0);
        }
        // The root is opened for the first of them, and stays open.
        let asked = !entry.is_automount();
        let mut omitted = 0;
        if self.features.contains(Features::FAT_SERIAL) {
            if asked {
                let root = FeatureReader::open(entry, None, opened, Features::FAT_SERIAL)?;
                identity.fat_serial = root.fat_serial()?;
            }
            omitted += u64::from(identity.fat_serial.is_none());
        }
        if self.features.contains(Features::FS_LABEL) {
            let root = FeatureReader::open(entry, None, opened, Features::FS_LABEL)?;
            identity.label = FeatureReader::label(root.fs_label()?)?;
        }
        if self.features.contains(Features::FS_UUID) {
            if asked {
                let root = FeatureReader::open(entry, None, opened, Features::FS_UUID)?;
                identity.uuid = FeatureReader::uuid(root.fs_uuid()?);
            }
            omitted += u64::from(identity.uuid.is_none());
        }
        Ok(omitted)
    }

    /// Reads what the features record of the file of `entry` that every
    /// type of file can have into `inode`: whether it is read-only, its
    /// extended attributes and the names of its owners. `opened` is the
    /// file opened for reading, if it is, which the extended attributes
    /// are read through then. `dos_read_only` says whether a regular file
    /// has the read-only attribute of DOS, where its file system has one.
    /// Returns how many names were left out.
    ///
    /// A regular file is read-only if it has that attribute, and anything
    /// else, or a file in a file system without DOS attributes, if its
    /// mode gives nobody write permission, as for systemd. The attribute
    /// does not go against the mode: `readOnly` may not contradict `mode`,
    /// and FAT and exFAT take the write permission away with the
    /// attribute. A symbolic link has no mode and is never read-only.
    /// `readOnly` is only stated where it is true, as the specification
    /// asks.
    fn read_inode(
        &mut self,
        entry: &Entry<'_>,
        opened: &mut Option<Readable>,
        dos_read_only: Option<bool>,
        inode: &mut InodeAttributes,
    ) -> Result<u64, Failure> {
        let status = entry.status();
        let symlink = status.file_type == FileType::Symlink;
        if self.features.contains(Features::READ_ONLY) && !symlink {
            let read_only = dos_read_only.unwrap_or(true) && !status.mode.is_writable();
            inode.read_only = read_only.then_some(true);
        }
        if self.features.contains(Features::USER_XATTR) && !symlink {
            // Through the file where it is open for reading anyway. Nothing
            // is opened for its attributes.
            let xattrs = match opened {
                Some(file) => self.xattrs.read(file)?,
                None => self.xattrs.read_unopened(entry)?,
            };
            inode.user_xattrs = Some(Box::new(xattrs));
        }
        let mut omitted = 0;
        if self.features.contains(Features::USER_NAME) {
            inode.user_name = self.names.user(status.uid);
            omitted += u64::from(inode.user_name.is_none());
        }
        if self.features.contains(Features::GROUP_NAME) {
            inode.group_name = self.names.group(status.gid);
            omitted += u64::from(inode.group_name.is_none());
        }
        Ok(omitted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{self, written, TempDir};
    use crate::tree::{Handle, Status};
    use crate::{Mode, Name, NameBuf};
    use rustix::fs::{IFlags, OFlags, XattrFlags, CWD};
    use rustix::io::Errno;
    use std::collections::BTreeMap;
    use std::ffi::CStr;
    use std::fs;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::Command;
    use std::time::Duration;

    /// Opens the directory `path` as a handle, the way an entry is opened.
    fn open_dir(path: &Path) -> OwnedFd {
        let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).unwrap()
    }

    /// The entry of the directory `path` itself, as the root of a tree.
    fn root_entry(path: &Path) -> Entry<'static> {
        let handle = open_dir(path);
        let status = Status::of(handle.as_fd()).unwrap();
        Entry::new(Handle::Owned(handle), status, false)
    }

    /// A tree with a file of every type a test can make: `file`, `dir`,
    /// `link`, `fifo` and `socket`.
    fn tree(name: &str) -> (TempDir, OwnedFd, UnixListener) {
        let tmp = TempDir::new(name);
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"data").unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        let mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
        rustix::fs::mknodat(CWD, dir.join("fifo"), FileType::Fifo, mode, 0).unwrap();
        let socket = UnixListener::bind(dir.join("socket")).unwrap();
        let top = open_dir(dir);
        (tmp, top, socket)
    }

    /// The names of the files of [`tree`].
    const NAMES: [&CStr; 5] = [c"file", c"dir", c"link", c"fifo", c"socket"];

    /// What `features` record of the entry `name` of `top`: the object,
    /// whether the file was opened, and how many fields were left out.
    fn read(features: Features, top: &OwnedFd, name: &CStr) -> Result<(FileObject, bool, u64), Failure> {
        let entry = Entry::open_at(top.as_fd(), name).unwrap();
        read_entry(&mut FeatureReader::new(features), &entry, top, name)
    }

    /// The same with the reader `reader` for the entry `entry`, which is
    /// at `name` in `top`.
    fn read_entry(
        reader: &mut FeatureReader,
        entry: &Entry<'_>,
        top: &OwnedFd,
        name: &CStr,
    ) -> Result<(FileObject, bool, u64), Failure> {
        let mut object = FileObject::new(NameBuf::new(name.to_str().unwrap()).unwrap());
        let mut opened = None;
        let place = Place { dir: top.as_fd(), name };
        let omitted = reader.read(entry, Some(place), &mut opened, &mut object)?;
        Ok((object, opened.is_some(), omitted))
    }

    /// What `features` record of the entry `name` of `top`, a regular file
    /// or a directory that is open for reading before it is read, as a
    /// file that is hashed and a directory that is listed are.
    fn read_open(features: Features, top: &OwnedFd, name: &CStr) -> Result<FileObject, Failure> {
        let entry = Entry::open_at(top.as_fd(), name).unwrap();
        let mut object = FileObject::new(NameBuf::new(name.to_str().unwrap()).unwrap());
        let place = Place { dir: top.as_fd(), name };
        let mut opened = Some(entry.reopen(Some(place))?);
        FeatureReader::new(features).read(&entry, Some(place), &mut opened, &mut object)?;
        assert!(opened.is_some());
        Ok(object)
    }

    /// The feature and the reason of a read that failed for a feature that
    /// cannot be read.
    fn unavailable<T: std::fmt::Debug>(read: Result<T, Failure>) -> (Features, Unreadable) {
        match read {
            Err(Failure::Unavailable(feature, why)) => (feature, why),
            other => panic!("{:?}", other),
        }
    }

    /// Whether the file system of the directory `dir` has DOS attributes,
    /// as FAT has.
    fn has_dos_attributes(dir: &Path) -> bool {
        let entry = root_entry(dir);
        entry.reopen(None).unwrap().dos_attributes().unwrap().is_some()
    }

    /// A cache keeps so many answers at most, and starts over once it is
    /// full.
    #[test]
    fn caches_are_bounded() {
        let mut cache = Cache::new(3);
        for key in 0..3 {
            cache.insert(key, key * 10);
        }
        assert_eq!(
            (0..3).map(|key| cache.get(&key).copied()).collect::<Vec<_>>(),
            [Some(0), Some(10), Some(20)]
        );
        cache.insert(3, 30);
        assert_eq!(cache.answers.len(), 1);
        assert_eq!((cache.get(&0), cache.get(&3)), (None, Some(&30)));
        // A key that is there is kept again without that.
        cache.insert(3, 31);
        cache.insert(4, 40);
        assert_eq!(
            (cache.get(&3), cache.get(&4), cache.answers.len()),
            (Some(&31), Some(&40), 2)
        );
    }

    /// The default features record nothing of what is read here: nothing
    /// is opened, nothing is stated and nothing is left out.
    #[test]
    fn nothing_is_read_unless_asked() {
        let (tmp, top, _socket) = tree("optional-default");
        for features in [Features::NONE, Features::DEFAULT, Features::DEFAULT | Features::MTIME] {
            for name in NAMES {
                let (object, opened, omitted) = read(features, &top, name).unwrap();
                let plain = FileObject::new(object.name().to_owned());
                assert_eq!((object, opened, omitted), (plain, false, 0), "{:?}", name);
            }
            let mut root = RootObject::default();
            let mut opened = None;
            let read = FeatureReader::new(features).read_root(&root_entry(&tmp.0), &mut opened, &mut root);
            assert_eq!(
                (read.unwrap(), opened.is_some(), root),
                (0, false, RootObject::default())
            );
        }
    }

    /// Whether a file is read-only follows its mode where its file system
    /// has no DOS attributes: it is, if nobody may write it. A symbolic
    /// link never is, and `readOnly` is only stated where it is true.
    #[test]
    fn read_only_follows_the_mode() {
        let (tmp, top, _socket) = tree("optional-read-only");
        let dir = &tmp.0;
        if has_dos_attributes(dir) {
            eprintln!("skipping: the temporary directory has DOS attributes");
            return;
        }
        let features = Features::DEFAULT | Features::READ_ONLY;
        let mut reader = FeatureReader::new(features);
        for (mode, read_only) in [
            (0o644, None),
            (0o444, Some(true)),
            (0o200, None),
            (0o020, None),
            (0o002, None),
            (0o555, Some(true)),
            (0o000, Some(true)),
        ] {
            for name in [c"file", c"dir", c"fifo", c"socket"] {
                let path = dir.join(name.to_str().unwrap());
                fs::set_permissions(&path, fs::Permissions::from_mode(mode)).unwrap();
                let entry = Entry::open_at(top.as_fd(), name).unwrap();
                let (object, opened, _) = read_entry(&mut reader, &entry, &top, name).unwrap();
                assert_eq!(object.inode().read_only(), read_only, "{:?} {:o}", name, mode);
                // Only the first regular file is opened, to ask its file
                // system for DOS attributes.
                assert_eq!(opened, name == c"file" && mode == 0o644, "{:?} {:o}", name, mode);
            }
        }
        // Restore what the removal of the tree needs.
        fs::set_permissions(dir.join("dir"), fs::Permissions::from_mode(0o755)).unwrap();
        let (link, opened, _) = read(features, &top, c"link").unwrap();
        assert_eq!((link.inode().read_only(), opened), (None, false));
        // The root has no DOS attributes to ask for.
        for (mode, read_only) in [(0o555, Some(true)), (0o755, None)] {
            fs::set_permissions(dir, fs::Permissions::from_mode(mode)).unwrap();
            let mut root = RootObject::default();
            let mut opened = None;
            FeatureReader::new(features)
                .read_root(&root_entry(dir), &mut opened, &mut root)
                .unwrap();
            assert_eq!(
                (root.inode().read_only(), opened.is_some()),
                (read_only, false),
                "{:o}",
                mode
            );
        }
    }

    /// The read-only attribute of DOS makes a regular file read-only, and
    /// only where its mode gives nobody write permission, which the two
    /// may not contradict each other in. Without the attribute a regular
    /// file is not read-only whatever its mode says, as mount options can
    /// take the write permission from every file.
    #[test]
    fn read_only_of_dos() {
        let (_tmp, top, _socket) = tree("optional-dos-read-only");
        let mut reader = FeatureReader::new(Features::READ_ONLY);
        let entry = Entry::open_at(top.as_fd(), c"file").unwrap();
        let mut status = *entry.status();
        let cases = [
            (0o444, Some(true), Some(true)),
            (0o444, Some(false), None),
            (0o644, Some(true), None),
            (0o644, Some(false), None),
            (0o444, None, Some(true)),
            (0o644, None, None),
        ];
        for (mode, dos_read_only, read_only) in cases {
            status.mode = Mode::from_st_mode(mode);
            let entry = Entry::new(Handle::Borrowed(entry.handle()), status, false);
            let mut inode = InodeAttributes::default();
            let read = reader.read_inode(&entry, &mut None, dos_read_only, &mut inode);
            assert_eq!(read.unwrap(), 0);
            assert_eq!(inode.read_only(), read_only, "{:o} {:?}", mode, dos_read_only);
        }
    }

    /// Only regular files and directories have inode flags. The flags the
    /// features record are stated, set or cleared, and no others. A file
    /// system without inode flags cannot say that they are cleared.
    ///
    /// What is stated is held against the flags the file system says the
    /// file has. A new file need not be without flags: a directory hands
    /// some of its own on to what is made in it, NOATIME and NODUMP among
    /// them on ext4 and on XFS.
    #[test]
    fn inode_flags() {
        let (tmp, top, _socket) = tree("optional-inode-flags");
        let dir = &tmp.0;
        let all = Features::FLAG_APPEND_ONLY
            | Features::FLAG_IMMUTABLE
            | Features::FLAG_NO_ATIME
            | Features::FLAG_NO_COW
            | Features::FLAG_NO_DUMP;
        for name in [c"link", c"fifo", c"socket"] {
            let (object, opened, _) = read(all, &top, name).unwrap();
            let plain = FileObject::new(object.name().to_owned());
            assert_eq!((object, opened), (plain, false), "{:?}", name);
        }
        let file = Entry::open_at(top.as_fd(), c"file").unwrap().reopen(None).unwrap();
        if file.inode_flags().unwrap().is_none() {
            eprintln!("skipping: the temporary directory has no inode flags");
            assert_eq!(
                unavailable(read(all, &top, c"file")),
                (Features::FLAG_APPEND_ONLY, Unreadable::NoInodeFlags)
            );
            return;
        }
        // The flags the file system says the file `name` has.
        let flags_of = |name: &CStr| {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            let opened = entry.reopen(Some(Place { dir: top.as_fd(), name })).unwrap();
            rustix::fs::ioctl_getflags(opened.as_fd()).unwrap()
        };
        // The owner of a file may set these two, where the file system
        // has them. They are added to the flags the file has, as chattr
        // adds them. Set in their place, they take the flag of a file with
        // extents away on ext4, which sets the two, tries to convert the
        // file then and fails where it can't.
        let set = |name: &CStr| {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            let opened = entry.reopen(Some(Place { dir: top.as_fd(), name })).unwrap();
            let flags = flags_of(name) | IFlags::NODUMP | IFlags::NOATIME;
            let set = rustix::fs::ioctl_setflags(opened.as_fd(), flags).is_ok();
            if !set {
                eprintln!("skipping the flags that are set: the temporary directory does not take them");
            }
            set
        };
        for (name, set) in [(c"file", set(c"file")), (c"dir", set(c"dir"))] {
            let flags = flags_of(name);
            let has = |flag: IFlags| Some(flags.contains(flag));
            assert!(!set || flags.contains(IFlags::NODUMP | IFlags::NOATIME), "{:?}", name);
            let (object, opened, _) = read(all, &top, name).unwrap();
            assert!(opened);
            let inode = object.inode();
            assert_eq!(
                (inode.flag_append_only(), inode.flag_immutable(), inode.flag_no_cow()),
                (has(IFlags::APPEND), has(IFlags::IMMUTABLE), has(IFlags::NOCOW)),
                "{:?}",
                name
            );
            assert_eq!(
                (inode.flag_no_atime(), inode.flag_no_dump()),
                (has(IFlags::NOATIME), has(IFlags::NODUMP)),
                "{:?}",
                name
            );
            // Only what the features record is stated.
            let (object, _, _) = read(Features::FLAG_NO_DUMP | Features::FLAG_IMMUTABLE, &top, name).unwrap();
            let inode = object.inode();
            assert_eq!(
                (inode.flag_no_dump(), inode.flag_immutable()),
                (has(IFlags::NODUMP), has(IFlags::IMMUTABLE))
            );
            assert_eq!(
                (inode.flag_append_only(), inode.flag_no_atime(), inode.flag_no_cow()),
                (None, None, None)
            );
        }
        // The root has inode flags as well.
        let mut root = RootObject {
            features: Some(all),
            ..RootObject::default()
        };
        let mut opened = None;
        FeatureReader::new(all)
            .read_root(&root_entry(dir), &mut opened, &mut root)
            .unwrap();
        assert!(opened.is_some());
        let of_root = rustix::fs::ioctl_getflags(fs::File::open(dir).unwrap()).unwrap();
        assert_eq!(root.inode().flag_no_dump(), Some(of_root.contains(IFlags::NODUMP)));
        // A writer takes the objects for a manifest of these features, and
        // writes the flags that are set.
        let (file, _, _) = read(all, &top, c"file").unwrap();
        let records = written(&root, |writer| writer.file(&file).unwrap());
        let of_file = flags_of(c"file");
        let fields: Vec<String> = [
            (IFlags::APPEND, "flagAppendOnly"),
            (IFlags::IMMUTABLE, "flagImmutable"),
            (IFlags::NOATIME, "flagNoAtime"),
            (IFlags::NOCOW, "flagNoCow"),
            (IFlags::NODUMP, "flagNoDump"),
        ]
        .into_iter()
        .filter(|&(flag, _)| of_file.contains(flag))
        .map(|(_, field)| format!(r#""{}":true,"#, field))
        .collect();
        assert_eq!(records[1], format!(r#"{{{}"name":"file"}}"#, fields.concat()));
        // procfs has no inode flags.
        if rustix::fs::statfs("/proc").is_ok_and(|proc| proc.f_type == rustix::fs::PROC_SUPER_MAGIC) {
            let process = open_dir(Path::new("/proc/self"));
            for name in [c"task", c"status"] {
                let read = read(Features::FLAG_NO_DUMP | Features::FLAG_IMMUTABLE, &process, name);
                assert_eq!(
                    unavailable(read),
                    (Features::FLAG_IMMUTABLE, Unreadable::NoInodeFlags),
                    "{:?}",
                    name
                );
            }
        }
    }

    /// A file system without DOS attributes cannot say that they are
    /// cleared, for a regular file or a directory. It is asked once, with
    /// its first file, and nothing is opened for it after that. Other files
    /// have no DOS attributes anywhere, and the root has none.
    #[test]
    fn no_dos_attributes() {
        let (tmp, top, _socket) = tree("optional-no-dos");
        let dir = &tmp.0;
        if has_dos_attributes(dir) {
            eprintln!("skipping: the temporary directory has DOS attributes");
            return;
        }
        let all = Features::FLAG_HIDDEN | Features::FLAG_SYSTEM | Features::FLAG_ARCHIVE;
        for (features, first) in [
            (all, Features::FLAG_ARCHIVE),
            (Features::FLAG_HIDDEN | Features::FLAG_SYSTEM, Features::FLAG_HIDDEN),
            (Features::FLAG_SYSTEM | Features::READ_ONLY, Features::FLAG_SYSTEM),
        ] {
            let mut reader = FeatureReader::new(features);
            for (round, name) in [c"dir", c"file", c"dir", c"file"].into_iter().enumerate() {
                let entry = Entry::open_at(top.as_fd(), name).unwrap();
                let mut object = FileObject::new(NameBuf::new(name.to_str().unwrap()).unwrap());
                let mut opened = None;
                let read = reader.read(&entry, Some(Place { dir: top.as_fd(), name }), &mut opened, &mut object);
                assert_eq!(unavailable(read), (first, Unreadable::NoDosAttributes), "{:?}", name);
                assert_eq!(opened.is_some(), round == 0, "{:?} {}", name, round);
            }
            for name in [c"link", c"fifo", c"socket"] {
                let entry = Entry::open_at(top.as_fd(), name).unwrap();
                let (object, opened, _) = read_entry(&mut reader, &entry, &top, name).unwrap();
                assert_eq!(object.flag_hidden(), None, "{:?}", name);
                assert!(!opened, "{:?}", name);
            }
            let mut root = RootObject::default();
            let mut opened = None;
            reader.read_root(&root_entry(dir), &mut opened, &mut root).unwrap();
            assert!(opened.is_none());
        }
        // Whether a file is read-only only asks with a regular file.
        let mut reader = FeatureReader::new(Features::READ_ONLY);
        for (name, opens) in [(c"dir", false), (c"file", true), (c"file", false), (c"dir", false)] {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            let (_, opened, _) = read_entry(&mut reader, &entry, &top, name).unwrap();
            assert_eq!(opened, opens, "{:?}", name);
        }
        // A file that cannot be opened is read-only by its mode, and the
        // next file asks. The attributes hidden, system and archive of such
        // a file cannot be read. That takes a process that the permissions
        // of a file hold for.
        fs::set_permissions(dir.join("file"), fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(dir.join("file")).is_ok() {
            return;
        }
        fs::write(dir.join("other"), b"").unwrap();
        let mut reader = FeatureReader::new(Features::READ_ONLY);
        for (name, opens, read_only) in [(c"file", false, Some(true)), (c"other", true, None)] {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            let (object, opened, _) = read_entry(&mut reader, &entry, &top, name).unwrap();
            assert_eq!((opened, object.inode().read_only()), (opens, read_only), "{:?}", name);
        }
        let read = read(Features::FLAG_HIDDEN | Features::READ_ONLY, &top, c"file");
        assert!(
            matches!(&read, Err(Failure::Io(e)) if e.raw_os_error() == Some(libc::EACCES)),
            "{:?}",
            read
        );
    }

    /// Sets the extended attribute `name` of `path` itself to `value`.
    fn set_xattr(path: &Path, name: &[u8], value: &[u8]) -> rustix::io::Result<()> {
        rustix::fs::lsetxattr(path, name, value, XattrFlags::empty())
    }

    /// The extended attributes of the user namespace of a file are read,
    /// all of them, by their names without the namespace, and none of
    /// another namespace. Nothing is opened for them: they are read through
    /// the handle of the file, and through the file itself where it is open
    /// for reading anyway, for its inode flags or by the caller. A file
    /// without any has none, which is not the same as saying nothing, also
    /// where it may not be opened, and a symbolic link says nothing. A file
    /// that lost its name keeps its attributes.
    #[test]
    fn extended_attributes() {
        let (tmp, top, _socket) = tree("optional-xattrs");
        let dir = &tmp.0;
        let features = Features::DEFAULT | Features::USER_XATTR;
        if let Err(e) = set_xattr(&dir.join("file"), b"user.first", b"1") {
            assert!(matches!(e, Errno::OPNOTSUPP | Errno::NOSYS), "{}", e);
            eprintln!("skipping: the temporary directory has no extended attributes");
            return;
        }
        let binary: Vec<u8> = (0..=u8::MAX).collect();
        set_xattr(&dir.join("file"), b"user.empty", b"").unwrap();
        set_xattr(&dir.join("file"), b"user.binary", &binary).unwrap();
        set_xattr(
            &dir.join("file"),
            "user.\u{fc}ml\u{e4}ut.dotted name".as_bytes(),
            b"text",
        )
        .unwrap();
        set_xattr(&dir.join("dir"), b"user.of the directory", b"2").unwrap();
        // Linux 7.1 and later take one on a socket, never on a FIFO.
        let on_socket = set_xattr(&dir.join("socket"), b"user.of the socket", b"3").is_ok();
        assert_eq!(set_xattr(&dir.join("fifo"), b"user.no", b"4"), Err(Errno::PERM));
        let attributes = |pairs: &[(&str, &[u8])]| {
            let pairs = pairs.iter().map(|(name, value)| (name.to_string(), value.to_vec()));
            Some(pairs.collect::<BTreeMap<_, _>>())
        };
        let found = |object: &FileObject| {
            object.inode().user_xattrs().map(|xattrs| {
                xattrs
                    .map(|(name, value)| (name.to_owned(), value.to_vec()))
                    .collect::<BTreeMap<_, _>>()
            })
        };
        let read_attributes = |name: &CStr| {
            let (object, opened, omitted) = read(features, &top, name).unwrap();
            assert_eq!((opened, omitted), (false, 0), "{:?}", name);
            found(&object)
        };
        let of_file = attributes(&[
            ("binary", &binary[..]),
            ("empty", &b""[..]),
            ("first", &b"1"[..]),
            ("\u{fc}ml\u{e4}ut.dotted name", &b"text"[..]),
        ]);
        let of_dir = attributes(&[("of the directory", &b"2"[..])]);
        assert_eq!(read_attributes(c"file"), of_file);
        assert_eq!(read_attributes(c"dir"), of_dir);
        // A file that is open for reading is read through that.
        assert_eq!(found(&read_open(features, &top, c"file").unwrap()), of_file);
        assert_eq!(found(&read_open(features, &top, c"dir").unwrap()), of_dir);
        // So is one that is opened for its inode flags.
        match read(features | Features::FLAG_NO_DUMP, &top, c"file") {
            Ok((object, opened, _)) => assert_eq!((found(&object), opened), (of_file.clone(), true)),
            Err(Failure::Unavailable(Features::FLAG_NO_DUMP, Unreadable::NoInodeFlags)) => {
                eprintln!("skipping the inode flags: the temporary directory has none");
            }
            Err(e) => panic!("{:?}", e),
        }
        // A file that may not be opened is asked as well, and has none.
        // Nobody but root reads the value of one it has.
        fs::write(dir.join("closed"), b"").unwrap();
        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o000)).unwrap();
        assert_eq!(read_attributes(c"closed"), attributes(&[]));
        let of_socket: &[(&str, &[u8])] = if on_socket {
            &[("of the socket", &b"3"[..])]
        } else {
            &[]
        };
        assert_eq!(read_attributes(c"socket"), attributes(of_socket));
        assert_eq!(read_attributes(c"fifo"), attributes(&[]));
        assert_eq!(read_attributes(c"link"), None);
        // A regular file that lost its name keeps its attributes, and
        // another file of its name has its own.
        fs::write(dir.join("named"), b"").unwrap();
        set_xattr(&dir.join("named"), b"user.of the named file", b"5").unwrap();
        let entry = Entry::open_at(top.as_fd(), c"named").unwrap();
        fs::rename(dir.join("named"), dir.join("renamed")).unwrap();
        fs::write(dir.join("named"), b"").unwrap();
        let (object, _, _) = read_entry(&mut FeatureReader::new(features), &entry, &top, c"named").unwrap();
        assert_eq!(object.inode().user_xattr("of the named file"), Some(&b"5"[..]));
        assert_eq!(read_attributes(c"named"), attributes(&[]));
        // A writer takes the object, and writes its attributes.
        let root = RootObject {
            features: Some(features),
            ..RootObject::default()
        };
        let (file, _, _) = read(features, &top, c"file").unwrap();
        let records = written(&root, |writer| writer.file(&file).unwrap());
        assert!(records[1].contains(r#""first":{"text":"1"}"#), "{}", records[1]);
        // A manifest lists all attributes of a file or none, so a name it
        // cannot hold fails: one that is not UTF-8, and one with a control
        // character.
        for name in [&b"user.\xff"[..], b"user.a\nb", b"user.\x7f"] {
            fs::write(dir.join("unwritable"), b"").unwrap();
            if set_xattr(&dir.join("unwritable"), name, b"").is_err() {
                eprintln!(
                    "skipping the name {:?}, which the temporary directory does not take",
                    name
                );
                continue;
            }
            let read = read(features, &top, c"unwritable");
            assert_eq!(
                unavailable(read),
                (Features::USER_XATTR, Unreadable::XattrName),
                "{:?}",
                name
            );
            fs::remove_file(dir.join("unwritable")).unwrap();
        }
    }

    /// The attributes of a file that take more than a record of a manifest
    /// has room for fail, before they are all read.
    #[test]
    fn too_many_extended_attributes() {
        let tmp = TempDir::new("optional-xattr-size");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"").unwrap();
        let value = vec![0x5a; 60 * 1024];
        let count = crate::MAX_RECORD_SIZE / value.len() + 2;
        for i in 0..count {
            let name = format!("user.{:04}", i);
            if let Err(e) = set_xattr(&dir.join("file"), name.as_bytes(), &value) {
                eprintln!(
                    "skipping: the temporary directory takes no more than {} large attributes ({})",
                    i, e
                );
                return;
            }
        }
        let top = open_dir(dir);
        let read = read(Features::USER_XATTR, &top, c"file");
        assert!(matches!(read, Err(Failure::TooLarge)), "{:?}", read);
    }

    /// The variable that tells the test binary, run again by
    /// [`extended_attributes_without_procfs`] with nothing in /proc, where
    /// the tree is.
    const NO_PROCFS_DIR: &str = "UAPI16_TEST_NO_PROCFS_DIR";

    /// The variable that tells the test binary, run again by
    /// [`extended_attributes_without_procfs`], that the kernel reopens a
    /// regular file without a procfs, with O_EMPTYPATH.
    const NO_PROCFS_REOPENS: &str = "UAPI16_TEST_NO_PROCFS_REOPENS";

    /// The extended attributes of a file that is open for reading are read
    /// through that descriptor, which takes no procfs. Those of a file that
    /// is not open are read through the link procfs has for its handle, and
    /// can't be read without it. The test binary runs this test again with
    /// an empty tmpfs over /proc, in a user and a mount namespace from
    /// unshare(1), and it is skipped where unshare can't make them.
    ///
    /// A directory is opened by its name. A regular file is opened through
    /// its handle, with O_EMPTYPATH where the kernel has it and through
    /// procfs where it does not, by pathrs, which panics where there is
    /// none. So the regular file is left out there.
    #[test]
    fn extended_attributes_without_procfs() {
        if let Some(dir) = std::env::var_os(NO_PROCFS_DIR) {
            return check_without_procfs(Path::new(&dir));
        }
        let (tmp, _, _socket) = tree("optional-no-procfs");
        let dir = &tmp.0;
        if let Err(e) = set_xattr(&dir.join("file"), b"user.of the file", b"1") {
            assert!(matches!(e, Errno::OPNOTSUPP | Errno::NOSYS), "{}", e);
            eprintln!("skipping: the temporary directory has no extended attributes");
            return;
        }
        set_xattr(&dir.join("dir"), b"user.of the directory", b"2").unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        let reopens = testing::has_empty_path();
        if !reopens {
            eprintln!("skipping the regular file: the kernel has no O_EMPTYPATH");
        }
        let script = concat!(
            r#"mount -t tmpfs tmpfs /proc && "#,
            r#"exec "$1" --exact optional::tests::extended_attributes_without_procfs --nocapture"#
        );
        let mut command = Command::new("unshare");
        command
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(std::env::current_exe().unwrap())
            .env(NO_PROCFS_DIR, dir);
        if reopens {
            command.env(NO_PROCFS_REOPENS, "1");
        }
        let output = command.output().unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`extended_attributes_without_procfs`] in `dir`, with
    /// nothing in /proc.
    fn check_without_procfs(dir: &Path) {
        assert!(fs::read_dir("/proc").unwrap().next().is_none());
        let top = open_dir(dir);
        let features = Features::USER_XATTR;
        let object = read_open(features, &top, c"dir").unwrap();
        assert_eq!(object.inode().user_xattr("of the directory"), Some(&b"2"[..]));
        if std::env::var_os(NO_PROCFS_REOPENS).is_some() {
            let object = read_open(features, &top, c"file").unwrap();
            assert_eq!(object.inode().user_xattr("of the file"), Some(&b"1"[..]));
        }
        // Nothing is opened for its attributes.
        for name in [c"dir", c"file", c"fifo"] {
            let read = read(features, &top, name);
            assert_eq!(
                unavailable(read),
                (Features::USER_XATTR, Unreadable::NoProcfs),
                "{:?}",
                name
            );
        }
    }

    /// The variable that names the merged directory of fuse-overlayfs in
    /// which the test binary runs
    /// [`extended_attributes_of_a_file_that_is_gone`] again.
    const GONE_DIR: &str = "UAPI16_TEST_GONE_DIR";

    /// The variable that names the directory of the layer the files of
    /// that test are in.
    const GONE_LAYER: &str = "UAPI16_TEST_GONE_LAYER";

    /// A file that is removed behind its file system after its handle was
    /// taken changed: the link procfs has for the handle leads nowhere
    /// then, as it does where there is no procfs, and the handle tells the
    /// two apart. fuse-overlayfs finds its files by their names, so it
    /// says ENOENT of a file that was removed in its layer, and with
    /// timeout=0 the kernel asks it every time. The test binary runs this
    /// test again in a user and mount namespace from unshare(1), on such a
    /// mount. It is skipped where there is no fuse-overlayfs, and where the
    /// handle of a file that is gone still has a status.
    #[test]
    fn extended_attributes_of_a_file_that_is_gone() {
        if let (Some(dir), Some(layer)) = (std::env::var_os(GONE_DIR), std::env::var_os(GONE_LAYER)) {
            return check_gone(Path::new(&dir), Path::new(&layer));
        }
        let tmp = TempDir::new("optional-gone");
        let dir = &tmp.0;
        for part in ["lower", "upper", "work", "merged"] {
            fs::create_dir(dir.join(part)).unwrap();
        }
        for name in GONE {
            fs::write(dir.join("lower").join(name.to_str().unwrap()), b"hello").unwrap();
        }
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        // The script exits with 77 where it can't mount the file system,
        // and unmounts it once the test is done, which ends fuse-overlayfs.
        let script = concat!(
            r#"d=$1; "#,
            r#"fuse-overlayfs -o "lowerdir=$d/lower,upperdir=$d/upper,workdir=$d/work,timeout=0" "$d/merged" "#,
            r#"|| exit 77; "#,
            r#""$2" --exact optional::tests::extended_attributes_of_a_file_that_is_gone --nocapture; status=$?; "#,
            r#"umount "$d/merged"; exit $status"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(GONE_DIR, dir.join("merged"))
            .env(GONE_LAYER, dir.join("lower"))
            .output()
            .unwrap();
        if output.status.code() == Some(77) {
            eprintln!("skipping: fuse-overlayfs can't mount a file system here");
            return;
        }
        // What the test said where it ran again, such as that it skipped.
        let said = String::from_utf8_lossy(&output.stderr);
        if let Some(skipped) = said.lines().find(|line| line.starts_with("skipping")) {
            eprintln!("{}", skipped);
        }
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The files of [`extended_attributes_of_a_file_that_is_gone`].
    const GONE: [&CStr; 2] = [c"one", c"other"];

    /// The checks of [`extended_attributes_of_a_file_that_is_gone`] in
    /// `dir`, whose files are in the directory `layer` behind it.
    fn check_gone(dir: &Path, layer: &Path) {
        let top = open_dir(dir);
        for name in GONE {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            fs::remove_file(layer.join(name.to_str().unwrap())).unwrap();
            if let Ok(status) = Status::of(entry.handle()) {
                eprintln!(
                    "skipping: a file that is gone still has a status here: {:?}",
                    status.file_type
                );
                return;
            }
            // Its extended attributes are read through its handle, which
            // is not open for reading.
            let mut reader = FeatureReader::new(Features::USER_XATTR);
            let read = read_entry(&mut reader, &entry, &top, name);
            assert!(
                matches!(read, Err(Failure::Changed)),
                "{:?}: {:?}",
                name,
                read.map(|read| read.2)
            );
        }
    }

    /// The variable that names the merged directory of fuse-overlayfs in
    /// which the test binary runs [`extended_attributes_behind_a_dead_server`]
    /// again.
    const DEAD_DIR: &str = "UAPI16_TEST_DEAD_DIR";

    /// The variable that names the process of that fuse-overlayfs.
    const DEAD_SERVER: &str = "UAPI16_TEST_DEAD_SERVER";

    /// How often the test asks for the status of a file whose server it
    /// killed until that fails, and how long it waits in between.
    const DEAD_TRIES: u32 = 500;
    const DEAD_WAIT: Duration = Duration::from_millis(10);

    /// Only a file that is gone is a change. A handle that can't be asked
    /// for another reason says nothing of its file, and a link that procfs
    /// does not have is a missing procfs then, as it is where the handle
    /// can be asked. Here the handle is of a file on fuse-overlayfs whose
    /// server the test kills, so that its status fails with ECONNABORTED
    /// or ENOTCONN, and /proc is an empty tmpfs. The test binary runs this
    /// test again in a user and mount namespace from unshare(1), where the
    /// shell that starts it has the server in its background. It is
    /// skipped where there is no fuse-overlayfs, and where the handle still
    /// has a status after its server is gone.
    #[test]
    fn extended_attributes_behind_a_dead_server() {
        if let (Some(dir), Ok(server)) = (std::env::var_os(DEAD_DIR), std::env::var(DEAD_SERVER)) {
            return check_dead_server(Path::new(&dir), &server);
        }
        let tmp = TempDir::new("optional-dead-server");
        let dir = &tmp.0;
        for part in ["lower", "upper", "work", "merged"] {
            fs::create_dir(dir.join(part)).unwrap();
        }
        fs::write(dir.join("lower/file"), b"hello").unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        // The script exits with 77 where the file system does not get
        // mounted, and ends the server first. The server stays in the
        // foreground, so that the shell knows its process, and writes to
        // nothing, so that this test waits for the script alone. What is
        // left of the mount goes with the namespace.
        let script = format!(
            concat!(
                r#"d=$1; "#,
                r#"fuse-overlayfs -f -o "lowerdir=$d/lower,upperdir=$d/upper,workdir=$d/work,timeout=0" "$d/merged" "#,
                r#"> /dev/null 2>&1 & "#,
                r#"server=$!; tries=0; "#,
                r#"until mountpoint -q "$d/merged"; do "#,
                r#"tries=$((tries + 1)); "#,
                r#"if [ "$tries" -gt 100 ] || ! kill -0 "$server" 2> /dev/null; then "#,
                r#"kill "$server" 2> /dev/null; exit 77; fi; "#,
                r#"sleep 0.05; done; "#,
                r#"{}=$server "$2" --exact optional::tests::extended_attributes_behind_a_dead_server --nocapture; "#,
                r#"status=$?; kill "$server" 2> /dev/null; exit $status"#
            ),
            DEAD_SERVER
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", &script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(DEAD_DIR, dir.join("merged"))
            .output()
            .unwrap();
        if output.status.code() == Some(77) {
            eprintln!("skipping: fuse-overlayfs can't mount a file system here");
            return;
        }
        // What the test said where it ran again, such as that it skipped.
        let said = String::from_utf8_lossy(&output.stderr);
        if let Some(skipped) = said.lines().find(|line| line.starts_with("skipping")) {
            eprintln!("{}", skipped);
        }
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`extended_attributes_behind_a_dead_server`] in `dir`,
    /// which the process `server` serves.
    fn check_dead_server(dir: &Path, server: &str) {
        let top = open_dir(dir);
        let entry = Entry::open_at(top.as_fd(), c"file").unwrap();
        // The shell has a kill of its own, and kill(1) need not be there.
        let killed = Command::new("sh")
            .args(["-c", r#"kill -KILL "$1""#, "sh", server])
            .status()
            .unwrap();
        assert!(killed.success());
        // The kernel answers for the server once its descriptor is closed.
        let mut tries = 0;
        let failed = loop {
            match Status::of(entry.handle()) {
                Err(failed) => break failed,
                Ok(_) if tries == DEAD_TRIES => {
                    eprintln!("skipping: a file whose server is gone still has a status here");
                    return;
                }
                Ok(_) => {
                    tries += 1;
                    std::thread::sleep(DEAD_WAIT);
                }
            }
        };
        // The kernel says that the connection was aborted, or that there
        // is none.
        assert!(
            matches!(&failed, Failure::Io(e) if matches!(e.raw_os_error(), Some(libc::ECONNABORTED | libc::ENOTCONN))),
            "{:?}",
            failed
        );
        // Nothing is in /proc from here on.
        let mounted = Command::new("mount")
            .args(["-t", "tmpfs", "tmpfs", "/proc"])
            .status()
            .unwrap();
        assert!(mounted.success());
        assert!(fs::read_dir("/proc").unwrap().next().is_none());
        let mut reader = FeatureReader::new(Features::USER_XATTR);
        let read = read_entry(&mut reader, &entry, &top, c"file");
        assert_eq!(unavailable(read), (Features::USER_XATTR, Unreadable::NoProcfs));
    }

    /// A file system is asked for its DOS attributes once, through the
    /// directory a walk starts at, and one without them fails where one of
    /// hidden, system and archive is recorded. Where none of them is
    /// recorded, it is not asked.
    #[test]
    fn checks_dos_attributes_once() {
        let tmp = TempDir::new("optional-dos-check");
        let dir = &tmp.0;
        if has_dos_attributes(dir) {
            eprintln!("skipping: the temporary directory has DOS attributes");
            return;
        }
        let entry = root_entry(dir);
        let mut reader = FeatureReader::new(Features::FLAG_HIDDEN | Features::READ_ONLY);
        let no_attributes = (Features::FLAG_HIDDEN, Unreadable::NoDosAttributes);
        // The first time asks, through the directory opened for that. Then
        // the answer is known, and nothing is opened for it any more.
        for asks in [true, false] {
            let mut opened = None;
            let check = reader.check_dos_attributes(&entry, &mut opened);
            assert_eq!((unavailable(check), opened.is_some()), (no_attributes, asks));
        }
        let mut opened = None;
        FeatureReader::new(Features::READ_ONLY)
            .check_dos_attributes(&entry, &mut opened)
            .unwrap();
        assert!(opened.is_none());
    }

    /// The names of the owners of a file are those the user database has
    /// for its user and its group. A name it does not have is left out and
    /// counted, and found again in what was kept.
    #[test]
    fn owner_names() {
        let (_tmp, top, _socket) = tree("optional-owners");
        let both = Features::USER_NAME | Features::GROUP_NAME;
        let entry = Entry::open_at(top.as_fd(), c"file").unwrap();
        let (uid, gid) = (entry.status().uid, entry.status().gid);
        let mut database = UserDatabase::new();
        let (user, group) = (database.user_name(uid), database.group_name(gid));
        let missing = u64::from(user.is_none()) + u64::from(group.is_none());
        let mut reader = FeatureReader::new(both);
        for name in NAMES {
            let entry = Entry::open_at(top.as_fd(), name).unwrap();
            let (object, opened, omitted) = read_entry(&mut reader, &entry, &top, name).unwrap();
            let inode = object.inode();
            assert_eq!(
                (inode.user_name(), inode.group_name()),
                (user.as_deref(), group.as_deref())
            );
            assert_eq!((opened, omitted), (false, missing), "{:?}", name);
        }
        assert_eq!(reader.names.users.get(&uid).map(Option::is_some), Some(user.is_some()));
        // Only the names the features record.
        let (object, _, omitted) = read(Features::GROUP_NAME, &top, c"file").unwrap();
        assert_eq!(
            (object.inode().user_name(), object.inode().group_name()),
            (None, group.as_deref())
        );
        assert_eq!(omitted, u64::from(group.is_none()));
        // An owner nobody knows, and the two IDs that stand for none.
        let unknown = (4_000_000_000..4_000_000_100)
            .find(|&id| database.user_name(id).is_none() && database.group_name(id).is_none())
            .expect("an ID without a user and a group");
        for id in [unknown, u32::MAX, u32::from(u16::MAX)] {
            let mut status = *entry.status();
            (status.uid, status.gid) = (id, id);
            let entry = Entry::new(Handle::Borrowed(entry.handle()), status, false);
            for _ in 0..2 {
                let (object, _, omitted) = read_entry(&mut reader, &entry, &top, c"file").unwrap();
                assert_eq!(
                    (object.inode().user_name(), object.inode().group_name(), omitted),
                    (None, None, 2)
                );
            }
            assert_eq!(reader.names.users.get(&id), Some(&None));
            assert_eq!(reader.names.groups.get(&id), Some(&None));
        }
        let (object, _, _) = read(both, &top, c"file").unwrap();
        let root = RootObject {
            features: Some(both),
            ..RootObject::default()
        };
        written(&root, |writer| writer.file(&object).unwrap());
    }

    /// What a file system says of its label and of what it identifies
    /// itself with, as a manifest records it: an empty label is no label,
    /// and a label a manifest cannot hold cannot be recorded, and neither
    /// can one the file system cannot say. An identifier that is not a UUID
    /// is none, and so is one the file system cannot say.
    #[test]
    fn labels_and_uuids() {
        assert_eq!(
            FeatureReader::label(Some(FsLabel::Label("ESP".into()))).unwrap(),
            Some("ESP".into())
        );
        assert_eq!(FeatureReader::label(Some(FsLabel::Empty)).unwrap(), None);
        assert_eq!(
            unavailable(FeatureReader::label(Some(FsLabel::Unwritable))),
            (Features::FS_LABEL, Unreadable::LabelUnwritable)
        );
        assert_eq!(
            unavailable(FeatureReader::label(None)),
            (Features::FS_LABEL, Unreadable::NoLabel)
        );
        let uuid = Uuid::new([7; Uuid::SIZE]);
        assert_eq!(FeatureReader::uuid(Some(FsUuid::Uuid(uuid))), Some(uuid));
        for identifier in [
            Some(FsUuid::Null),
            Some(FsUuid::NotUuid(4)),
            Some(FsUuid::NotUuid(8)),
            None,
        ] {
            assert_eq!(FeatureReader::uuid(identifier), None, "{:?}", identifier);
        }
    }

    /// The root of a tree has the identity of its file system, as far as
    /// the features record it and as the file system gives it. A label it
    /// cannot give fails. A UUID or a volume serial number it does not have
    /// is left out and counted, and fails nothing.
    #[test]
    fn identity_of_the_file_system() {
        let tmp = TempDir::new("optional-identity");
        let dir = &tmp.0;
        let entry = root_entry(dir);
        let asked = entry.reopen(None).unwrap();
        let identity = |features| {
            let mut root = RootObject::default();
            let mut opened = None;
            let read = FeatureReader::new(features).read_root(&entry, &mut opened, &mut root);
            read.map(|omitted| {
                assert!(opened.is_some());
                (root.file_system().clone(), omitted)
            })
        };
        match FeatureReader::label(asked.fs_label().unwrap()) {
            // The label is never left out: a file system that has none
            // says so with an empty one.
            Ok(label) => {
                let (labelled, omitted) = identity(Features::FS_LABEL).unwrap();
                assert_eq!((labelled.label(), omitted), (label.as_deref(), 0));
            }
            Err(failure) => assert_eq!(
                unavailable(identity(Features::FS_LABEL)),
                unavailable::<()>(Err(failure))
            ),
        }
        let uuid = FeatureReader::uuid(asked.fs_uuid().unwrap());
        let serial = asked.fat_serial().unwrap();
        let (no_uuid, no_serial) = (u64::from(uuid.is_none()), u64::from(serial.is_none()));
        let (with_uuid, omitted) = identity(Features::FS_UUID).unwrap();
        assert_eq!((with_uuid.uuid(), omitted), (uuid, no_uuid));
        let (with_serial, omitted) = identity(Features::FAT_SERIAL).unwrap();
        assert_eq!((with_serial.fat_serial(), omitted), (serial, no_serial));
        // Asked for both, it gives the one it has: the other one is left
        // out, and counted.
        let (both, omitted) = identity(Features::FS_UUID | Features::FAT_SERIAL).unwrap();
        assert_eq!(
            (both.uuid(), both.fat_serial(), omitted),
            (uuid, serial, no_uuid + no_serial)
        );
        // Only the root has it: nothing of it is read for another file.
        let top = open_dir(dir);
        fs::create_dir(dir.join("dir")).unwrap();
        let (object, opened, _) = read(FeatureReader::IDENTITY, &top, c"dir").unwrap();
        assert_eq!((object, opened), (FileObject::new(NameBuf::new("dir").unwrap()), false));
        // procfs has no label, no UUID and no volume serial number: the
        // label fails, and the other two are left out, and each of them is
        // counted.
        if rustix::fs::statfs("/proc").is_ok_and(|proc| proc.f_type == rustix::fs::PROC_SUPER_MAGIC) {
            let process = root_entry(Path::new("/proc/self"));
            let read = |features| {
                let mut root = RootObject::default();
                let read = FeatureReader::new(features).read_root(&process, &mut None, &mut root);
                read.map(|omitted| (root, omitted))
            };
            assert_eq!(
                unavailable(read(Features::FS_LABEL)),
                (Features::FS_LABEL, Unreadable::NoLabel)
            );
            assert_eq!(unavailable(read(FeatureReader::IDENTITY)).0, Features::FS_LABEL);
            for (features, left_out) in [
                (Features::FS_UUID, 1),
                (Features::FAT_SERIAL, 1),
                (Features::FS_UUID | Features::FAT_SERIAL, 2),
            ] {
                let (root, omitted) = read(features).unwrap();
                assert_eq!(
                    (root.file_system(), omitted),
                    (&FileSystemIdentity::default(), left_out),
                    "{:?}",
                    features
                );
            }
        }
    }

    /// The variable that names a directory of a mounted FAT file system
    /// for [`fat`], one with a regular file and a directory in it. Mounting
    /// one takes privileges, so the test is skipped without it.
    const FAT_DIR: &str = "UAPI16_TEST_FAT_DIR";

    /// On a FAT file system a regular file and a directory have their DOS
    /// attributes, a regular file is read-only if it has that attribute,
    /// the root has no DOS attributes, and the file system has a volume
    /// serial number, no UUID, which is left out and counted, and no label
    /// that can be read. Its root directory says that it has DOS attributes
    /// where a walk asks it.
    #[test]
    fn fat() {
        let Some(dir) = std::env::var_os(FAT_DIR) else {
            eprintln!("skipping: {} names no directory of a FAT file system", FAT_DIR);
            return;
        };
        let dir = Path::new(&dir);
        let top = open_dir(dir);
        let features = Features::FLAG_HIDDEN | Features::FLAG_SYSTEM | Features::FLAG_ARCHIVE | Features::READ_ONLY;
        let mut reader = FeatureReader::new(features);
        let (mut files, mut directories) = (0, 0);
        for listed in fs::read_dir(dir).unwrap() {
            let listed = listed.unwrap();
            let name = std::ffi::CString::new(listed.file_name().as_bytes()).unwrap();
            let entry = Entry::open_at(top.as_fd(), &name).unwrap();
            let mut object = FileObject::new(Name::ROOT.join_os(&listed.file_name()).unwrap());
            let mut opened = None;
            let place = Place {
                dir: top.as_fd(),
                name: &name,
            };
            reader.read(&entry, Some(place), &mut opened, &mut object).unwrap();
            let attributes = opened.unwrap().dos_attributes().unwrap().unwrap();
            let flags = attributes.flags();
            assert_eq!(object.flag_hidden(), Some(flags.contains(DosFlags::HIDDEN)));
            assert_eq!(object.flag_system(), Some(flags.contains(DosFlags::SYSTEM)));
            assert_eq!(object.flag_archive(), Some(flags.contains(DosFlags::ARCHIVE)));
            let writable = entry.status().mode.is_writable();
            if entry.status().file_type == FileType::RegularFile {
                files += 1;
                let read_only = (attributes.is_read_only() && !writable).then_some(true);
                assert_eq!(object.inode().read_only(), read_only);
            } else {
                directories += 1;
                assert_eq!(object.inode().read_only(), (!writable).then_some(true));
            }
        }
        assert!(
            files > 0 && directories > 0,
            "{:?} needs a regular file and a directory",
            dir
        );
        let identity = |features| {
            let mut root = RootObject::default();
            let read = FeatureReader::new(features).read_root(&root_entry(dir), &mut None, &mut root);
            read.map(|omitted| (root, omitted))
        };
        let (root, omitted) = identity(features | Features::FAT_SERIAL).unwrap();
        assert!(root.file_system().fat_serial().is_some());
        assert_eq!(omitted, 0);
        assert_eq!(
            unavailable(identity(Features::FS_LABEL)),
            (Features::FS_LABEL, Unreadable::NoLabel)
        );
        // What FAT identifies itself with is its volume serial number,
        // which is no UUID: the UUID is left out, and counted.
        let (root, omitted) = identity(Features::FS_UUID).unwrap();
        assert_eq!((root.file_system().uuid(), omitted), (None, 1));
        let (root, omitted) = identity(Features::FS_UUID | Features::FAT_SERIAL).unwrap();
        assert!(root.file_system().fat_serial().is_some());
        assert_eq!((root.file_system().uuid(), omitted), (None, 1));
        // A walk asks the directory it starts at whether its file system
        // has DOS attributes. The root directory of the file system has an
        // answer as well, though none is recorded of the root of a tree.
        let mut opened = None;
        FeatureReader::new(features)
            .check_dos_attributes(&root_entry(dir), &mut opened)
            .unwrap();
        assert!(opened.is_some());
    }
}
