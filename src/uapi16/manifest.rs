// SPDX-License-Identifier: LGPL-2.1-or-later
//! Building the manifest of a tree of files on the host.

use std::fmt;
use std::fs::File;
use std::io::Write;
use std::ops::ControlFlow;
use std::os::fd::{AsFd, BorrowedFd};
use std::path::Path;

use crate::error::{Error, ErrorKind, TreeProblem};
use crate::listing::{Listing, Totals, Writing};
use crate::scratch::Scratch;
use crate::sys::NewFile;
use crate::tree::Failure;
use crate::walk::{Add, AddFlags, Omitted, Walker, STEP_BUDGET};
use crate::{Features, FileObject, FileSystemIdentity, InodeAttributes, Order};

/// How to write the manifest of a tree of files on the host: the features
/// it records and the order of its file objects.
/// [`ManifestOptions::new`] gives the default features of the
/// specification, [`Features::DEFAULT`], and the code point order.
///
/// [`ManifestOptions::create_at`] writes a manifest to a new file, and
/// [`ManifestOptions::open`] to any [`Write`]. Both give a
/// [`ManifestWriter`], which takes the files the manifest lists, and whose
/// [`ManifestWriter::finish`] writes it. [`ManifestOptions::generate_at`] and
/// [`ManifestOptions::generate`] do all of that for one directory.
///
/// Every feature that systemd-manifest make records can be asked for.
/// [`Features::USER_XATTR`] reads the extended attributes of every file but
/// symbolic links, which have none. A file whose attributes make its record
/// larger than [`MAX_RECORD_SIZE`](crate::MAX_RECORD_SIZE) is
/// [`Problem::RecordTooLarge`](crate::Problem::RecordTooLarge), naming the
/// file: the walk fails where the attributes alone take more than that, and
/// [`ManifestWriter::finish`] otherwise. [`Features::READ_ONLY`] takes the
/// read-only attribute of a regular file on FAT, and the access mode of
/// anything else. The root has no DOS attributes. The label, the UUID and
/// the volume serial number of the file system are read from the directory
/// that is the root, and an empty label gives none.
///
/// No file is opened for its extended attributes. Those of a file that is
/// open anyway are read from the open file: a directory that is walked
/// into, a regular file whose data is hashed, and a regular file or a
/// directory that is opened for its inode flags, its DOS attributes or the
/// identity of its file system. Those of any other file are read through
/// /proc. Without a /proc they can't be read, and it has to be the one of
/// the kernel: whoever can mount something else there can have such a file
/// recorded with the attributes of another one.
///
/// The data of a regular file of more than 1 TiB is not hashed. Where the
/// manifest records hashes, or hard links and the file has more than one
/// name, the walk fails at such a file with an [`ErrorKind::Io`] error of
/// EFBIG, before anything is read of it. A sparse file is read in full.
///
/// A feature that can't be read of a file fails the walk at that file,
/// naming the feature, such as [`Features::FLAG_HIDDEN`] of a file system
/// without DOS attributes. Three things are left out instead, and counted
/// in [`ManifestReport::fields_omitted`]: the name of an owner that the
/// user database of the host does not have, the user and group IDs 65535
/// and 4294967295, which the specification does not permit, and a
/// modification time before 1970 or after 2554, which `mTimeNSec` can't
/// express. The names of owners are those of the host.
/// [`Features::FS_UUID`] and [`Features::FAT_SERIAL`] are read from the
/// root. A root whose file system has no UUID is written without one, and
/// so is one whose volume serial number can't be read, which only FAT
/// gives. Before Linux 6.9 no UUID can be read. Each is counted in
/// [`ManifestReport::fields_omitted`] as well. A manifest without a root
/// has neither. The features of partitions, such as
/// [`Features::GPT_LABEL`], don't apply to a tree of files:
/// [`ManifestOptions::create_at`], [`ManifestOptions::open`] and the
/// generate functions fail with [`TreeProblem::FeatureNotForTrees`] for
/// them.
///
/// Building a manifest needs Linux 5.10 or newer.
///
/// ```no_run
/// use std::fs::File;
/// use std::os::fd::AsFd;
/// use std::path::Path;
/// use uapi16::{AddFlags, Features, ManifestOptions};
///
/// let esp = File::open("/efi")?;
/// let out_dir = File::open("/var/lib/manifests")?;
/// let report = ManifestOptions::new()
///     .features(Features::DEFAULT | Features::MTIME)
///     .generate_at(out_dir.as_fd(), Path::new("esp.manifest"), &esp, AddFlags::NONE)?;
/// println!("{} files", report.files());
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, Debug)]
pub struct ManifestOptions {
    features: Features,
    order: Order,
    sync: bool,
}

impl ManifestOptions {
    /// The features of partitions, in the order of their names, the first
    /// of which an error names.
    const FOR_PARTITIONS: [Features; 7] = [
        Features::GPT_DISK_UUID,
        Features::GPT_FLAG_GROW_FILE_SYSTEM,
        Features::GPT_FLAG_NO_AUTO,
        Features::GPT_FLAGS,
        Features::GPT_LABEL,
        Features::GPT_TYPE_UUID,
        Features::GPT_UUID,
    ];

    /// Options with the default features of the specification and the code
    /// point order.
    pub fn new() -> ManifestOptions {
        ManifestOptions {
            features: Features::DEFAULT,
            order: Order::CodePoint,
            sync: false,
        }
    }

    /// The features to record, [`Features::DEFAULT`] unless set.
    pub fn features(&mut self, features: Features) -> &mut Self {
        self.features = features;
        self
    }

    /// The order of the file objects, [`Order::CodePoint`], the only one,
    /// unless set.
    pub fn order(&mut self, order: Order) -> &mut Self {
        self.order = order;
        self
    }

    /// Whether the new file of [`ManifestOptions::create_at`] and
    /// [`ManifestOptions::generate_at`] is written to disk before
    /// [`ManifestWriter::finish`] returns, so that a crash after that does
    /// not lose it. False unless set. The file is synced before it gets its
    /// name, so that the name never leads to a manifest that is not all on
    /// disk, and once more after it got it, with the directory it is in, so
    /// that the name is on disk as well. Nothing else is synced, and
    /// [`ManifestOptions::open`] and [`ManifestOptions::generate`] write to
    /// a writer of the caller, which the caller syncs.
    pub fn sync(&mut self, sync: bool) -> &mut Self {
        self.sync = sync;
        self
    }

    /// A new manifest file `name` in the directory `dir`. It appears at
    /// [`ManifestWriter::finish`], with the whole manifest in it. Until then
    /// nothing has the name, and a writer that is dropped instead leaves
    /// nothing behind.
    ///
    /// A name with more than one component names a file in a directory
    /// below `dir`. The components on the way are opened one at a time,
    /// each without following a symbolic link, and the file goes into the
    /// directory its last component is in. A symbolic link on the way fails
    /// with an [`ErrorKind::Io`] error of ELOOP, and an absolute name and
    /// one with `.` or `..` on the way with one of EINVAL. For a file in a
    /// directory that is not below `dir`, open that directory and pass it
    /// as `dir`.
    ///
    /// This never replaces a file: where something has the name already,
    /// this fails with an [`ErrorKind::Io`] error of EEXIST. To write over
    /// a file, open it and use [`ManifestOptions::open`].
    ///
    /// On FAT the new file gets the mode the mount gives every file, and
    /// it can't be larger than 4 GiB, so a manifest there holds about 2e7
    /// file objects at most: [`ManifestWriter::finish`] fails with EFBIG
    /// for more. A tree with more than about 9e6 files that have several
    /// names fails with EFBIG already while it is added.
    ///
    /// A manifest of a large tree takes room on disk while it is built, in
    /// the directory the file is in. On a file system without O_TMPFILE,
    /// such as FAT, the new file is in that directory under a temporary
    /// name until [`ManifestWriter::finish`].
    pub fn create_at(&self, dir: impl AsFd, name: &Path) -> Result<ManifestWriter<File>, Error> {
        self.create_at_dir(dir.as_fd(), name)
    }

    /// A manifest that is written to `out`. Nothing is written to `out`
    /// before [`ManifestWriter::finish`], and the manifest is complete once
    /// that returns. A manifest that `finish()` fails to write is
    /// incomplete, and readers refuse it, unless all it lacks is the
    /// newline at its end.
    ///
    /// A manifest of a large tree takes room on disk while it is built, in
    /// the directory `TMPDIR` names, or in /var/tmp where it names none.
    /// Where it is on FAT, which can't hold a file of more than 4 GiB, a
    /// manifest of more than about 3e7 file objects fails with EFBIG, and
    /// a tree with more than about 9e6 files that have several names fails
    /// with EFBIG already while it is added. A `TMPDIR` that is set is used
    /// as it is. It has to be a directory the caller trusts, since whoever
    /// controls it can change the manifest.
    pub fn open<W: Write>(&self, out: W) -> Result<ManifestWriter<W>, Error> {
        let walker = self.walker(Scratch::temporary())?;
        Ok(ManifestWriter {
            walker,
            out,
            new_file: None,
        })
    }

    /// The manifest of the directory `top` and everything below it, with
    /// `top` as the root, in a new file `name` in the directory `dir`: what
    /// [`ManifestOptions::create_at`], a walk of `top` and
    /// [`ManifestWriter::finish`] do.
    ///
    /// The name is checked now, so that a name that is taken fails before
    /// the tree is read, and again when the file gets its name.
    ///
    /// Where the features record [`Features::FLAG_HIDDEN`],
    /// [`Features::FLAG_SYSTEM`] or [`Features::FLAG_ARCHIVE`], a tree on a
    /// file system without DOS attributes fails before anything is read.
    ///
    /// A file below `top` is listed as what it is: a regular file, a
    /// directory, a symbolic link, a device node, a FIFO or a socket.
    ///
    /// The walk does not leave the mount `top` is on unless `flags` has
    /// [`AddFlags::CROSS_MOUNTS`]. A mount point, a bind mount as well, is
    /// found by the mount ID statx() gives. A mount point that is a
    /// directory and is not crossed is an empty directory with the
    /// attributes of the mounted root. A file that is mounted over another
    /// one is the file the mount shows, as there is nothing to walk into: a
    /// regular file with its attributes and the hash of its data, and a
    /// device node with its attributes and its device numbers. A btrfs
    /// subvolume is a directory like any other. Where the walk crosses
    /// mount points, a mount can show a directory again inside itself: a
    /// directory that is one of the directories it is in is
    /// [`TreeProblem::Loop`], naming the one below.
    ///
    /// The walk mounts nothing. An automount point that nothing is mounted
    /// on yet, such as the mount point of a systemd automount unit that was
    /// not used so far, is an empty directory with its own attributes,
    /// whether mount points are crossed or not. It is not opened, so what
    /// is read from the open file, such as an inode flag, can't be read of
    /// it. There is one known limit. The walk looks at a directory before it
    /// opens it, and a directory that becomes an automount point in between
    /// has its file system mounted by that open. The walk fails with
    /// [`TreeProblem::Changed`] then. That takes someone who can mount in
    /// the mount namespace of the caller, or an automount unit that is
    /// started at that moment.
    ///
    /// Symbolic links are listed with their targets and never followed. A
    /// target that can't be read is an error.
    ///
    /// A file with more than one name that is not a directory is identified
    /// by its mount, its device and its inode, and its subvolume where
    /// statx() reports one. Its names get one `inodeToken`, numbered in the
    /// order of the manifest. Every name of it after the first is held
    /// against the first: its type, mode, owner, device numbers, size,
    /// modification time and birth time have to be the same, but not its
    /// change time, and so do the hash of its data and the fields the
    /// specification wants the names of one inode to share. A name that is
    /// not the same is [`TreeProblem::HardlinkMismatch`]. A file reached
    /// through a bind mount is another file than the one reached through
    /// its source. On a file system that gives two files the same device
    /// and inode, as NFS can for btrfs snapshots, two files that are the
    /// same in everything held against each other are taken for one, and
    /// two that are not are [`TreeProblem::HardlinkMismatch`]. An overlayfs
    /// over btrfs before Linux 6.10 does that as well: it reports its own
    /// device with the inode numbers of btrfs, which repeat from one
    /// subvolume to the next, and no subvolume. Where the walk crosses
    /// mount points there, a subvolume below another one is
    /// [`TreeProblem::Loop`], since the roots of all subvolumes have the
    /// same inode number.
    ///
    /// A name a manifest can't hold, one that is not UTF-8, that is too long,
    /// or that has a control character or a noncharacter, is
    /// [`TreeProblem::UnwritableName`], unless `flags` has
    /// [`AddFlags::GRACEFUL`]. The names the specification reserves for the
    /// manifest at the top of a tree, such as `Uapi16Manifest`, are passed
    /// over.
    ///
    /// A file that changes while it is read is [`TreeProblem::Changed`],
    /// where the change shows: its size, its modification time, its change
    /// time and how many names it has are compared before and after, and
    /// the data of a regular file has to end at its size. A directory is
    /// compared before each of its entries and once more at the end of its
    /// listing, so a rename in it that moves its times stops the walk
    /// before the next entry, and then nothing is read twice. A file that
    /// its directory lists and that is gone when it is opened is
    /// [`TreeProblem::Changed`] as well. [`Changed`](TreeProblem::Changed)
    /// is a best effort. A tree that other processes change while it is
    /// walked can also fail the walk with another error, such as an
    /// [`Io`](ErrorKind::Io) error of ENOENT or ESTALE.
    ///
    /// Not every change shows in these fields. FAT keeps its times in steps
    /// of two seconds and never updates the times of its root directory.
    /// FAT also has no change time of its own, so a change that keeps the
    /// size of a file and sets its modification time back doesn't show
    /// there. On a file system without fine-grained timestamps, such as
    /// ramfs, and on every file system before Linux 6.13, two changes
    /// within one tick of the clock can leave the same times. A write
    /// through a shared mapping to a page that is already dirty moves no
    /// time at all. Such a change goes unnoticed: a file can be recorded
    /// with the hash of data it never held as a whole, and a directory can
    /// list a renamed file twice or not at all.
    ///
    /// A walk of the directory the new file is in passes over what the
    /// manifest keeps there, and over the new file under its temporary
    /// name. A manifest that is created inside the tree it describes can
    /// make a large walk fail with [`TreeProblem::Changed`] there, since
    /// the room it takes changes its own directory while the walk reads it.
    pub fn generate_at(
        &self,
        dir: impl AsFd,
        name: &Path,
        top: impl AsFd,
        flags: AddFlags,
    ) -> Result<ManifestReport, Error> {
        self.generate_at_dir(dir.as_fd(), name, top.as_fd(), flags)
    }

    /// The manifest of the directory `top` and everything below it, with
    /// `top` as the root, written to `out`: what [`ManifestOptions::open`],
    /// the walk of [`ManifestOptions::generate_at`] and
    /// [`ManifestWriter::finish`] do.
    pub fn generate<W: Write>(&self, out: W, top: impl AsFd, flags: AddFlags) -> Result<(W, ManifestReport), Error> {
        self.open(out)?.generate(top.as_fd(), flags)
    }

    /// Fails for a feature of partitions, which a tree of files does not
    /// have. Every way to make a writer asks this before it takes a
    /// descriptor, so that it fails the same way where the process has none
    /// left.
    pub(crate) fn check(&self) -> Result<(), Error> {
        let Some(feature) = ManifestOptions::FOR_PARTITIONS
            .into_iter()
            .find(|&feature| self.features.contains(feature))
        else {
            return Ok(());
        };
        let message = format!(
            "'{}' is a feature of partitions and does not apply to a tree of files",
            feature.names().next().unwrap_or_default()
        );
        Err(Error::new(ErrorKind::Tree(TreeProblem::FeatureNotForTrees), message).about(feature))
    }

    /// The walker of a manifest that keeps in `scratch` what does not fit
    /// into memory.
    fn walker(&self, scratch: Scratch) -> Result<Walker, Error> {
        self.check()?;
        let listing = Listing::new(self.features, self.order, scratch);
        Ok(Walker::new(self.features, listing))
    }

    /// What [`ManifestOptions::create_at`] does.
    fn create_at_dir(&self, dir: BorrowedFd<'_>, name: &Path) -> Result<ManifestWriter<File>, Error> {
        self.check()?;
        let (out, new_file) = NewFile::create_at(dir, name, self.sync)?;
        let mut walker = self.walker(Scratch::beside(new_file.directory()))?;
        // A file with a name of its own until it is complete is in the
        // directory it is created in, which can be in the tree.
        let named = new_file.named_file().map_err(Failure::into_unnamed_error)?;
        if let Some((inode, file)) = named {
            walker.pass_over(inode, file);
        }
        Ok(ManifestWriter {
            walker,
            out,
            new_file: Some(new_file),
        })
    }

    /// What [`ManifestOptions::generate_at`] does.
    fn generate_at_dir(
        &self,
        dir: BorrowedFd<'_>,
        name: &Path,
        top: BorrowedFd<'_>,
        flags: AddFlags,
    ) -> Result<ManifestReport, Error> {
        let writer = self.create_at_dir(dir, name)?;
        writer.generate(top, flags).map(|(_, report)| report)
    }
}

impl Default for ManifestOptions {
    /// [`ManifestOptions::new`].
    fn default() -> ManifestOptions {
        ManifestOptions::new()
    }
}

/// Takes the files a manifest lists, and writes the manifest once it has
/// them all, see [`ManifestOptions`].
///
/// [`ManifestWriter::add_object`] takes a file object that the caller made,
/// and [`ManifestWriter::add_root`] the root directory, as the caller
/// describes it.
///
/// The manifest lists its file objects in the order the options ask for,
/// and declares it in `order`, whatever order the adds came in. No add is
/// refused because of its order. The same name can be added more than
/// once. A file object equal to one added before is listed once. A
/// directory added more than once is listed with what the first add said
/// of it, and a directory that was added beats one that is only there
/// because files were added below it. Two other files with one name are
/// [`TreeProblem::Duplicate`], from [`ManifestWriter::finish`].
///
/// The root file object comes from [`ManifestWriter::add_root`], with the
/// attributes of the root directory and the identity of its file system.
/// A manifest without one has a root that only says that it is a
/// directory, as has every directory files were added below that was not
/// added itself. Where the features give a missing field a meaning, such
/// as [`Features::READ_ONLY`], [`Features::USER_XATTR`], the flags and,
/// for the root, [`Features::FS_LABEL`], such a directory would claim what
/// nobody read, and [`ManifestWriter::finish`] fails with
/// [`TreeProblem::MissingParent`] instead.
///
/// An add that fails leaves the writer as it was, as if the add had not
/// been. A writer that is dropped before [`ManifestWriter::finish`] writes
/// nothing.
pub struct ManifestWriter<W> {
    walker: Walker,
    out: W,
    /// The file of [`ManifestOptions::create_at`], which gets its name once
    /// the manifest is complete.
    new_file: Option<NewFile>,
}

impl<W: fmt::Debug> fmt::Debug for ManifestWriter<W> {
    /// The writer the manifest goes to, but not what the writer keeps of
    /// the files until the manifest is written.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ManifestWriter")
            .field("out", &self.out)
            .finish_non_exhaustive()
    }
}

impl<W: Write> ManifestWriter<W> {
    /// The directory `top` as the root, and everything below it: the walk
    /// of [`ManifestOptions::generate_at`] and [`ManifestOptions::generate`].
    fn add_all(&mut self, top: BorrowedFd<'_>, flags: AddFlags) -> Result<(), Error> {
        self.run(Add::Tree { top, flags })
    }

    /// What the generate functions do with their writer: the walk of `top`,
    /// and [`ManifestWriter::finish`]. A walk that fails ends the writer.
    /// What would have written its manifest gives the scratch files back
    /// first, see [`Writing::give_back`].
    fn generate(mut self, top: BorrowedFd<'_>, flags: AddFlags) -> Result<(W, ManifestReport), Error> {
        if let Err(e) = self.add_all(top, flags) {
            let (writing, _) = self.walker.finish();
            writing.give_back();
            return Err(e);
        }
        self.finish()
    }

    /// The root directory, as a caller describes it: its inode attributes
    /// and the identity of its file system. The order and the features of
    /// the root file object are those of the options. A root is checked as
    /// [`ManifestWriter::add_object`] checks a file object: one with a field
    /// of a feature the manifest does not record is refused. A root that is
    /// refused is not added, and the writer is as it was. The first root
    /// that is added says what the root is like, as for every directory.
    pub fn add_root(&mut self, inode: &InodeAttributes, file_system: &FileSystemIdentity) -> Result<(), Error> {
        self.run(Add::Root { inode, file_system })
    }

    /// The file object `object`, which a caller made. It is held to what
    /// [`Writer::file`](crate::Writer::file) holds a file object to here,
    /// but for where it comes, which [`ManifestWriter::finish`] checks. An
    /// object that is refused is not added, and the writer is as it was.
    /// Its `inodeToken` says which of the other file objects of a caller it
    /// shares an inode with, and the manifest numbers them in its own
    /// order. Those file objects have to have the fields the specification
    /// wants the names of one inode to share. One that doesn't fails the add
    /// with [`TreeProblem::HardlinkMismatch`], and [`Error::hardlink_name`]
    /// names the first of them.
    pub fn add_object(&mut self, object: &FileObject) -> Result<(), Error> {
        self.run(Add::Object(object))
    }

    /// Does the add `add` from its beginning to its end, a step at a time.
    /// The add borrows what it was given for that long, and duplicates
    /// none of it: it takes no descriptor but for what it opens of the
    /// tree.
    fn run(&mut self, add: Add<'_>) -> Result<(), Error> {
        let mut task = Walker::begin(add);
        while self.walker.step(&mut task, STEP_BUDGET)?.is_continue() {}
        Ok(())
    }

    /// Writes the manifest and returns what it was written to and what it
    /// lists. With [`ManifestOptions::create_at`] the file gets its name
    /// now, unless something else took it since, which is an
    /// [`ErrorKind::Io`] error of EEXIST. Where something fails once the
    /// file has its name, such as the sync of its directory, the file keeps
    /// the name, and this fails all the same.
    ///
    /// What the adds left open fails here: two files with one name, a
    /// directory that is missing, see [`ManifestWriter`], a file that is
    /// not a directory below which files were added, which is
    /// [`TreeProblem::NotDirectory`], a record that is larger than
    /// [`MAX_RECORD_SIZE`](crate::MAX_RECORD_SIZE), which is
    /// [`Problem::RecordTooLarge`](crate::Problem::RecordTooLarge), and
    /// what [`Writer::file`](crate::Writer::file) refuses of a file object
    /// of a caller where it comes.
    pub fn finish(self) -> Result<(W, ManifestReport), Error> {
        let ManifestWriter {
            walker,
            mut out,
            mut new_file,
        } = self;
        // No add comes any more. The walker goes here, and nothing is
        // closed with it: the scratch files the adds were done with stay
        // open until the manifest is written.
        let (mut writing, omitted) = walker.finish();
        let written = Self::write(&mut writing, &mut out, &mut new_file);
        // The manifest is written, or it failed. Either way the scratch
        // files go back before they are closed, which empties them: a file
        // system can keep an unlinked file in its directory until it is
        // released, with what it holds.
        writing.give_back();
        // A new file that is still here was never to get its name: the
        // manifest failed first. What was written of it goes as well.
        if let Some(new_file) = &new_file {
            new_file.give_up();
        }
        Ok((out, ManifestReport::new(written?, omitted)))
    }

    /// What [`ManifestWriter::finish`] does with what writes the manifest,
    /// `writing`: writes the manifest to `out`, a step at a time, and gives
    /// the file of `new_file` its name, which takes it from there. Returns
    /// what the manifest lists.
    fn write(writing: &mut Writing, out: &mut W, new_file: &mut Option<NewFile>) -> Result<Totals, Error> {
        // A write that fails says which file it is of, where the writer
        // knows the file.
        let failed = |error| match &new_file {
            Some(new_file) => new_file.failed(error),
            None => error,
        };
        let mut text = String::new();
        let totals = loop {
            let step = writing.step(STEP_BUDGET, &mut text)?;
            out.write_all(text.as_bytes()).map_err(failed)?;
            text.clear();
            if let ControlFlow::Break(totals) = step {
                break totals;
            }
        };
        out.flush().map_err(failed)?;
        if let Some(new_file) = new_file.take() {
            new_file.link()?;
        }
        Ok(totals)
    }
}

/// What a manifest lists, counted per file object: a file with three names
/// counts three times.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ManifestReport {
    files: u64,
    directories: u64,
    others: u64,
    bytes: u64,
    entries_omitted: u64,
    fields_omitted: u64,
}

impl ManifestReport {
    /// The report of a manifest that lists `totals`, of adds that left out
    /// `omitted`.
    fn new(totals: Totals, omitted: Omitted) -> ManifestReport {
        ManifestReport {
            files: totals.files,
            directories: totals.directories,
            others: totals.others,
            bytes: totals.bytes,
            entries_omitted: omitted.entries,
            fields_omitted: omitted.fields,
        }
    }

    /// How many regular files the manifest lists.
    pub fn files(&self) -> u64 {
        self.files
    }

    /// How many directories the manifest lists, the root among them.
    pub fn directories(&self) -> u64 {
        self.directories
    }

    /// How many other files the manifest lists: symbolic links, FIFOs,
    /// device nodes and sockets.
    pub fn others(&self) -> u64 {
        self.others
    }

    /// The sizes of the regular files, added up: those statx() gives for
    /// the files of a tree, also where the manifest does not record sizes,
    /// and those of the file objects of a caller. The data of a file with
    /// more than one name counts for each.
    pub fn bytes(&self) -> u64 {
        self.bytes
    }

    /// How many files [`AddFlags::GRACEFUL`] left out, a directory with
    /// everything below it as one.
    pub fn entries_omitted(&self) -> u64 {
        self.entries_omitted
    }

    /// How many fields were left out of the file objects: the names of
    /// owners that the user database does not have, the user and group IDs
    /// 65535 and 4294967295, modification times before 1970 or after 2554,
    /// and the UUID or the volume serial number of a file system that gives
    /// none.
    pub fn fields_omitted(&self) -> u64 {
        self.fields_omitted
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys::FsUuid;
    use crate::testing::{self, read_whole, OpenFile, TempDir};
    use crate::tree::{Entry, InodeId, Status};
    use crate::RootObject;
    use rustix::fs::OFlags;
    use std::fs;
    use std::io;
    use std::os::fd::OwnedFd;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::process::Command;
    use std::sync::Arc;

    /// Opens `path` as a handle, the link itself where it is a symbolic
    /// link.
    fn open_path(path: &Path) -> OwnedFd {
        let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).unwrap()
    }

    /// The names of the files in the directory `dir`, sorted.
    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    /// The errno of the I/O error `e`.
    fn errno(e: &Error) -> Option<i32> {
        assert_eq!(e.kind(), ErrorKind::Io, "{}", e);
        e.io_error().and_then(io::Error::raw_os_error)
    }

    /// A tree with a directory, files, a hard link and a symbolic link.
    fn tree(name: &str) -> TempDir {
        let tmp = TempDir::new(name);
        let dir = &tmp.0;
        fs::create_dir(dir.join("a")).unwrap();
        fs::write(dir.join("a/file"), b"hello").unwrap();
        fs::write(dir.join("linked"), b"twice").unwrap();
        fs::hard_link(dir.join("linked"), dir.join("a/linked-too")).unwrap();
        symlink("a", dir.join("link")).unwrap();
        tmp
    }

    /// A new manifest file appears once it is complete, as what the same
    /// manifest written to a stream holds, and the file that comes back is
    /// it. Until then nothing has its name, and the descriptor of the
    /// directory need not stay open.
    #[test]
    fn creates_the_file_once_complete() {
        let tree = tree("manifest-create");
        let out = TempDir::new("manifest-create-out");
        let options = ManifestOptions::new();
        let dir = File::open(&out.0).unwrap();
        let mut writer = options.create_at(&dir, Path::new("m")).unwrap();
        drop(dir);
        writer.add_all(open_path(&tree.0).as_fd(), AddFlags::NONE).unwrap();
        assert!(!out.0.join("m").exists());
        let (file, report) = writer.finish().unwrap();
        let written = fs::read(out.0.join("m")).unwrap();
        let (streamed, streamed_report) = options
            .generate(Vec::new(), open_path(&tree.0), AddFlags::NONE)
            .unwrap();
        assert_eq!((&written, report), (&streamed, streamed_report));
        let meta = fs::metadata(out.0.join("m")).unwrap();
        assert_eq!(file.metadata().unwrap().ino(), meta.ino());
        assert_eq!(meta.len(), written.len() as u64);
        // Read and write for everybody, less what the umask takes away.
        let created = out.0.join("created");
        File::create(&created).unwrap();
        assert_eq!(meta.mode(), fs::metadata(&created).unwrap().mode());
        // generate_at() is the same.
        let report = options
            .generate_at(
                File::open(&out.0).unwrap(),
                Path::new("again"),
                open_path(&tree.0),
                AddFlags::NONE,
            )
            .unwrap();
        assert_eq!(
            (fs::read(out.0.join("again")).unwrap(), report),
            (written, streamed_report)
        );
    }

    /// A new manifest file never replaces anything: a name that is taken
    /// fails when the writer is made, and one that is taken while the
    /// manifest is written fails at the end, leaving the file that took it.
    /// A writer that is dropped leaves nothing.
    #[test]
    fn never_replaces() {
        let tree = tree("manifest-replace");
        let out = TempDir::new("manifest-replace-out");
        let dir = &out.0;
        fs::write(dir.join("file"), b"mine").unwrap();
        fs::create_dir(dir.join("directory")).unwrap();
        symlink("nowhere", dir.join("dangling")).unwrap();
        let options = ManifestOptions::new();
        let taken = ["file", "directory", "dangling"];
        for name in taken {
            let created = options.create_at(File::open(dir).unwrap(), Path::new(name));
            let e = created.map(drop).unwrap_err();
            assert_eq!(errno(&e), Some(libc::EEXIST), "{}", name);
            let message = format!(
                "the manifest file '{}': {}",
                name,
                io::Error::from_raw_os_error(libc::EEXIST)
            );
            assert_eq!(e.to_string(), message);
        }
        let generated = options.generate_at(
            File::open(dir).unwrap(),
            Path::new("file"),
            open_path(&tree.0),
            AddFlags::NONE,
        );
        let e = generated.unwrap_err();
        assert_eq!(errno(&e), Some(libc::EEXIST));
        let message = format!(
            "the manifest file 'file': {}",
            io::Error::from_raw_os_error(libc::EEXIST)
        );
        assert_eq!(e.to_string(), message);
        let mut writer = options.create_at(File::open(dir).unwrap(), Path::new("later")).unwrap();
        writer.add_all(open_path(&tree.0).as_fd(), AddFlags::NONE).unwrap();
        fs::write(dir.join("later"), b"mine as well").unwrap();
        let e = writer.finish().unwrap_err();
        assert_eq!(errno(&e), Some(libc::EEXIST));
        let message = format!(
            "the manifest file 'later': {}",
            io::Error::from_raw_os_error(libc::EEXIST)
        );
        assert_eq!(e.to_string(), message);
        assert_eq!(fs::read(dir.join("later")).unwrap(), b"mine as well");
        let mut writer = options
            .create_at(File::open(dir).unwrap(), Path::new("dropped"))
            .unwrap();
        writer.add_all(open_path(&tree.0).as_fd(), AddFlags::NONE).unwrap();
        drop(writer);
        assert_eq!(names_in(dir), ["dangling", "directory", "file", "later"]);
    }

    /// A name with more than one component names a file in a directory
    /// below the directory, which is opened one component at a time. A
    /// symbolic link on the way is not followed, wherever it leads, and an
    /// absolute name and one with `.` or `..` on the way are no names below
    /// a directory. So no name sends a manifest, or what is kept next to it
    /// while it is built, out of the directory, also not one the owner of
    /// the tree made. A name that is empty or that ends in a slash, `.` or
    /// `..` is no name of a file, and a directory that is not there, or
    /// that is none, fails. Each error says which file it is of.
    #[test]
    fn names_of_new_files() {
        let out = TempDir::new("manifest-names");
        let elsewhere = TempDir::new("manifest-names-elsewhere");
        let dir = &out.0;
        fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        fs::write(dir.join("file"), b"").unwrap();
        symlink(&elsewhere.0, dir.join("meta")).unwrap();
        symlink("sub", dir.join("inside")).unwrap();
        let options = ManifestOptions::new();
        for name in ["sub/m", "sub/deeper/m", "sub//deeper///again"] {
            let writer = options.create_at(File::open(dir).unwrap(), Path::new(name)).unwrap();
            writer.finish().unwrap();
        }
        assert_eq!(names_in(&dir.join("sub")), ["deeper", "m"]);
        assert_eq!(names_in(&dir.join("sub/deeper")), ["again", "m"]);
        let absolute = elsewhere.0.join("absolute");
        let failures = [
            ("", libc::EINVAL),
            ("x/", libc::EINVAL),
            (".", libc::EINVAL),
            ("..", libc::EINVAL),
            ("sub/.", libc::EINVAL),
            ("sub/..", libc::EINVAL),
            ("./m", libc::EINVAL),
            ("sub/./m", libc::EINVAL),
            ("../m", libc::EINVAL),
            ("sub/../m", libc::EINVAL),
            ("sub/deeper/../../../elsewhere/m", libc::EINVAL),
            (absolute.to_str().unwrap(), libc::EINVAL),
            ("meta/m", libc::ELOOP),
            ("inside/m", libc::ELOOP),
            ("sub/../meta/m", libc::EINVAL),
            ("file/m", libc::ENOTDIR),
            ("missing/m", libc::ENOENT),
            ("sub/missing/m", libc::ENOENT),
        ];
        for (name, expected) in failures {
            let created = options.create_at(File::open(dir).unwrap(), Path::new(name));
            let e = created.map(drop).unwrap_err();
            assert_eq!(errno(&e), Some(expected), "{:?}", name);
            let message = format!(
                "the manifest file '{}': {}",
                name,
                io::Error::from_raw_os_error(expected)
            );
            assert_eq!(e.to_string(), message);
        }
        assert!(names_in(&elsewhere.0).is_empty());
        assert_eq!(names_in(dir), ["file", "inside", "meta", "sub"]);
        // The owner of a tree can't send its manifest elsewhere with a
        // directory of the tree that became a symbolic link.
        let tree = tree("manifest-names-tree");
        symlink(&elsewhere.0, tree.0.join("meta")).unwrap();
        let top = || open_path(&tree.0);
        for (name, expected) in [
            ("meta/root.manifest", libc::ELOOP),
            ("a/../../elsewhere/root.manifest", libc::EINVAL),
            (absolute.to_str().unwrap(), libc::EINVAL),
        ] {
            let generated = options.generate_at(top(), Path::new(name), top(), AddFlags::NONE);
            assert_eq!(errno(&generated.unwrap_err()), Some(expected), "{:?}", name);
        }
        assert!(names_in(&elsewhere.0).is_empty());
        assert_eq!(names_in(&tree.0), ["a", "link", "linked", "meta"]);
    }

    /// The variable that tells the test binary, run again by
    /// [`refuses_the_current_directory`], where the directory of the test
    /// is, which is the current directory of that process.
    const CURRENT_DIR: &str = "UAPI16_TEST_MANIFEST_CURRENT_DIR";

    /// rustix's `CWD` is no descriptor: it is AT_FDCWD, which stands for
    /// the current directory only where a path is looked up. A new file
    /// below it is refused with EBADF, whether its name has one component
    /// or more, and so is a walk of it, and nothing is made in the current
    /// directory. That is the directory of the process, so the test binary
    /// runs this test again in a process of its own, whose current
    /// directory is the directory of the test.
    #[test]
    fn refuses_the_current_directory() {
        let Some(dir) = std::env::var_os(CURRENT_DIR) else {
            let tmp = TempDir::new("manifest-current-directory");
            let dir = fs::canonicalize(&tmp.0).unwrap();
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "manifest::tests::refuses_the_current_directory",
                    "--nocapture",
                ])
                .env(CURRENT_DIR, &dir)
                .current_dir(&dir)
                .output()
                .unwrap();
            // A test binary that runs no test succeeds as well.
            let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
            assert!(output.status.success() && ran, "{:?}", output);
            return;
        };
        let dir = Path::new(&dir);
        assert_eq!(std::env::current_dir().unwrap(), dir);
        fs::create_dir_all(dir.join("sub/deeper")).unwrap();
        fs::create_dir(dir.join("tree")).unwrap();
        fs::write(dir.join("tree/file"), b"hello").unwrap();
        let options = ManifestOptions::new();
        for name in ["m", "sub/m", "sub/deeper/m"] {
            let name = Path::new(name);
            let created = options.create_at(rustix::fs::CWD, name).map(drop);
            let top = open_path(&dir.join("tree"));
            let generated = options
                .generate_at(rustix::fs::CWD, name, top, AddFlags::NONE)
                .map(drop);
            for e in [created.unwrap_err(), generated.unwrap_err()] {
                assert_eq!(errno(&e), Some(libc::EBADF), "{:?}", name);
                let message = format!(
                    "the manifest file '{}': {}",
                    name.display(),
                    io::Error::from_raw_os_error(libc::EBADF)
                );
                assert_eq!(e.to_string(), message);
            }
        }
        // The top of a walk is a descriptor as well.
        let walked = options.generate(Vec::new(), rustix::fs::CWD, AddFlags::NONE).map(drop);
        let sub = File::open(dir.join("sub")).unwrap();
        let generated = options
            .generate_at(sub, Path::new("m"), rustix::fs::CWD, AddFlags::NONE)
            .map(drop);
        for e in [walked.unwrap_err(), generated.unwrap_err()] {
            assert_eq!(errno(&e), Some(libc::EBADF));
            let message = format!("the root of the tree: {}", io::Error::from_raw_os_error(libc::EBADF));
            assert_eq!(e.to_string(), message);
        }
        assert_eq!(names_in(dir), ["sub", "tree"]);
        assert_eq!(names_in(&dir.join("sub")), ["deeper"]);
        assert!(names_in(&dir.join("sub/deeper")).is_empty());
        assert_eq!(names_in(&dir.join("tree")), ["file"]);
    }

    /// The scratch files of a manifest that is created as a file are made
    /// through the descriptor the new file has of its directory: the two
    /// share it, and no second one is taken.
    #[test]
    fn shares_the_directory_of_the_new_file() {
        let out = TempDir::new("manifest-shared-directory");
        let options = ManifestOptions::new();
        let writer = options.create_at(File::open(&out.0).unwrap(), Path::new("m")).unwrap();
        let directory = writer.new_file.as_ref().unwrap().directory();
        // The new file, the scratch space and this one.
        assert_eq!(Arc::strong_count(&directory), 3);
    }

    /// The variable that tells the test binary, run again by
    /// [`write_errors_name_the_file`] with a limit on the size of files,
    /// where its directories are.
    const FILE_SIZE_LIMIT_DIR: &str = "UAPI16_TEST_MANIFEST_FILE_SIZE_LIMIT_DIR";

    /// A write of the manifest that fails says which file it is of, where
    /// the writer made the file, and nothing has the name then. A writer of
    /// the caller is not named. The test binary runs this test again with a
    /// limit on the size of files that a manifest of a few files is over,
    /// and with SIGXFSZ ignored, so that the write fails with EFBIG.
    #[test]
    fn write_errors_name_the_file() {
        if let Some(dir) = std::env::var_os(FILE_SIZE_LIMIT_DIR) {
            return check_write_errors_name_the_file(Path::new(&dir));
        }
        let tmp = TempDir::new("manifest-write-errors");
        let dir = &tmp.0;
        fs::create_dir(dir.join("out")).unwrap();
        fs::create_dir(dir.join("tree")).unwrap();
        for number in 0..64 {
            fs::write(dir.join(format!("tree/file-{}", number)), b"").unwrap();
        }
        let script = concat!(
            r#"trap '' XFSZ; ulimit -f 1 || exit 1; "#,
            r#"exec "$1" --exact manifest::tests::write_errors_name_the_file"#
        );
        let output = Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(std::env::current_exe().unwrap())
            .env(FILE_SIZE_LIMIT_DIR, dir)
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`write_errors_name_the_file`] below `dir`.
    fn check_write_errors_name_the_file(dir: &Path) {
        let (out, tree) = (dir.join("out"), dir.join("tree"));
        let too_large = io::Error::from_raw_os_error(libc::EFBIG).to_string();
        let options = ManifestOptions::new();
        let generated = options.generate_at(
            File::open(&out).unwrap(),
            Path::new("m"),
            open_path(&tree),
            AddFlags::NONE,
        );
        let e = generated.unwrap_err();
        assert_eq!(errno(&e), Some(libc::EFBIG));
        assert_eq!(e.to_string(), format!("the manifest file 'm': {}", too_large));
        assert!(names_in(&out).is_empty());
        let file = File::create(out.join("stream")).unwrap();
        let e = options.generate(file, open_path(&tree), AddFlags::NONE).unwrap_err();
        assert_eq!(errno(&e), Some(libc::EFBIG));
        assert_eq!(e.to_string(), too_large);
    }

    /// The variable that tells the test binary, run again inside the
    /// namespaces of [`new_files_below_mount_points`], where the directory
    /// with the mount is.
    const MOUNT_DIR: &str = "UAPI16_TEST_MANIFEST_MOUNT_DIR";

    /// A mount point on the way to a new file is gone through: the file
    /// can be in a directory of another file system below the directory.
    /// The mount needs a user and a mount namespace, which unshare(1)
    /// makes, and the test binary runs this test again inside them.
    #[test]
    fn new_files_below_mount_points() {
        if let Some(dir) = std::env::var_os(MOUNT_DIR) {
            let dir = Path::new(&dir);
            let options = ManifestOptions::new();
            let writer = options.create_at(File::open(dir).unwrap(), Path::new("mount/sub/m"));
            writer.unwrap().finish().unwrap();
            assert_eq!(names_in(&dir.join("mount/sub")), ["m"]);
            return;
        }
        let tmp = TempDir::new("manifest-mount");
        let dir = &tmp.0;
        fs::create_dir(dir.join("mount")).unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        let script = concat!(
            r#"set -e; mount -t tmpfs tmpfs "$1/mount"; mkdir "$1/mount/sub"; "#,
            r#"exec "$2" --exact manifest::tests::new_files_below_mount_points"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(MOUNT_DIR, dir)
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The variable that names an automount point for
    /// [`new_files_below_automount_points`], which the test has something
    /// mounted on.
    const AUTOMOUNT_OUT: &str = "UAPI16_TEST_AUTOMOUNT_OUT";

    /// An automount point on the way to a new file has its file system
    /// mounted, as for any path a file is created at, and the file is in
    /// what is mounted. Only root can make an automount point, so the test
    /// takes one that is there: `UAPI16_TEST_AUTOMOUNT_OUT` names a
    /// directory that is one, that nothing is mounted on yet, and that
    /// mounts a file system files can be created in, such as the mount
    /// point of an automount unit of systemd for a tmpfs. Without the
    /// variable the test is skipped.
    #[test]
    fn new_files_below_automount_points() {
        let Some(point) = std::env::var_os(AUTOMOUNT_OUT) else {
            eprintln!("skipping: {} names no automount point", AUTOMOUNT_OUT);
            return;
        };
        let point = Path::new(&point);
        let parent = File::open(point.parent().unwrap()).unwrap();
        let name = Path::new(point.file_name().unwrap());
        let mounted = || {
            let handle = rustix::fs::openat(
                &parent,
                name,
                OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                rustix::fs::Mode::empty(),
            );
            let attributes = rustix::fs::statx(
                handle.unwrap(),
                c"",
                rustix::fs::AtFlags::EMPTY_PATH,
                rustix::fs::StatxFlags::MNT_ID,
            );
            attributes.unwrap().stx_mnt_id
        };
        let before = mounted();
        let options = ManifestOptions::new();
        let writer = options.create_at(&parent, &name.join("m")).unwrap();
        assert_ne!(mounted(), before, "nothing was mounted on {}", point.display());
        writer.finish().unwrap();
        assert!(names_in(point).contains(&"m".to_owned()));
        fs::remove_file(point.join("m")).unwrap();
    }

    /// What a test writes to, which counts the writes.
    #[derive(Default)]
    struct Counted {
        data: Vec<u8>,
        writes: usize,
        /// The most bytes one write brought.
        largest: usize,
        flushes: usize,
    }

    impl Write for Counted {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            self.writes += 1;
            self.largest = self.largest.max(data.len());
            self.data.extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushes += 1;
            Ok(())
        }
    }

    /// A manifest written to a stream gets nothing before finish(), and the
    /// whole manifest then. It lists its file objects in the order of their
    /// names whatever the order of the adds, and declares the order.
    #[test]
    fn writes_nothing_before_the_end() {
        let mut writer = ManifestOptions::new().open(Counted::default()).unwrap();
        for name in ["linked", "a/file", "link", "a/linked-too"] {
            writer.add_object(&FileObject::new(testing::name(name))).unwrap();
        }
        assert_eq!(writer.out.writes, 0);
        let (out, report) = writer.finish().unwrap();
        let whole = read_whole(&out.data).unwrap();
        let names: Vec<&str> = whole.objects.iter().map(|object| object.name().as_str()).collect();
        assert_eq!(names, ["a", "a/file", "a/linked-too", "link", "linked"]);
        assert_eq!(whole.root.order(), Some(Order::CodePoint));
        assert_eq!((report.files(), report.directories(), report.others()), (4, 2, 0));
    }

    /// The end writes the manifest a slice at a time, none larger than a
    /// step puts together, so that it never has more of the manifest in
    /// memory than that, and flushes what it wrote to once.
    #[test]
    fn writes_a_slice_at_a_time() {
        /// How many directories the tree has, how many files each of them
        /// has, and how long the names of the files are: a manifest of
        /// several slices, and of more than a step's budget. The files are
        /// in several directories, since a directory of FAT has room for
        /// 65,536 entries and a name that long takes 17 of them.
        const DIRECTORIES: usize = 4;
        const FILES: usize = 2_000;
        const NAME: usize = 200;
        let tmp = TempDir::new("manifest-slices");
        for directory in 0..DIRECTORIES {
            let directory = tmp.0.join(directory.to_string());
            fs::create_dir(&directory).unwrap();
            for number in 0..FILES {
                fs::write(directory.join(format!("{:0width$}", number, width = NAME)), b"").unwrap();
            }
        }
        let (out, report) = ManifestOptions::new()
            .generate(Counted::default(), open_path(&tmp.0), AddFlags::NONE)
            .unwrap();
        assert_eq!(report.files(), (DIRECTORIES * FILES) as u64);
        assert!(out.data.len() > STEP_BUDGET as usize, "{}", out.data.len());
        assert!(
            out.writes > 2 && out.largest <= STEP_BUDGET as usize,
            "{} {}",
            out.writes,
            out.largest
        );
        assert_eq!(out.flushes, 1);
    }

    /// The features of partitions don't apply to a tree, and nothing is made
    /// for them. The error names the first of them.
    #[test]
    fn features_of_partitions() {
        let tree = tree("manifest-gpt");
        let out = TempDir::new("manifest-gpt-out");
        let top = || open_path(&tree.0);
        for feature in ManifestOptions::FOR_PARTITIONS {
            let mut options = ManifestOptions::new();
            options.features(Features::DEFAULT | feature);
            let dir = || File::open(&out.0).unwrap();
            let errors = [
                options.create_at(dir(), Path::new("m")).map(drop).unwrap_err(),
                options.open(Vec::new()).map(drop).unwrap_err(),
                options
                    .generate_at(dir(), Path::new("m"), top(), AddFlags::NONE)
                    .map(drop)
                    .unwrap_err(),
                options
                    .generate(Vec::new(), top(), AddFlags::NONE)
                    .map(drop)
                    .unwrap_err(),
            ];
            for e in errors {
                assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::FeatureNotForTrees));
                assert_eq!(e.feature(), Some(feature));
            }
        }
        let mut options = ManifestOptions::new();
        options.features(Features::DEFAULT | Features::GPT_UUID | Features::GPT_LABEL);
        let e = options.open(Vec::new()).map(drop).unwrap_err();
        assert_eq!(e.feature(), Some(Features::GPT_LABEL));
        assert!(names_in(&out.0).is_empty());
    }

    /// The options start with the default features and the code point
    /// order, and say what the root file object says of the manifest.
    #[test]
    fn options() {
        assert_eq!(
            format!("{:?}", ManifestOptions::default()),
            format!("{:?}", ManifestOptions::new())
        );
        let tree = tree("manifest-options");
        let (out, _) = ManifestOptions::new()
            .generate(Vec::new(), open_path(&tree.0), AddFlags::NONE)
            .unwrap();
        let root = read_whole(&out).unwrap().root;
        assert_eq!((root.features(), root.order()), (None, Some(Order::CodePoint)));
        let (out, _) = ManifestOptions::new()
            .features(Features::DEFAULT | Features::MTIME)
            .order(Order::CodePoint)
            .generate(Vec::new(), open_path(&tree.0), AddFlags::NONE)
            .unwrap();
        let root: RootObject = read_whole(&out).unwrap().root;
        assert_eq!(root.features(), Some(Features::DEFAULT | Features::MTIME));
        assert!(root.inode().mtime().is_some());
    }

    /// The report counts every name of a file, the root among the
    /// directories, and what was left out.
    #[test]
    fn reports() {
        let tree = tree("manifest-report");
        let dir = &tree.0;
        fs::write(dir.join("\u{1}control"), b"").unwrap();
        let old = std::time::UNIX_EPOCH - std::time::Duration::from_secs(1);
        File::options()
            .write(true)
            .open(dir.join("a/file"))
            .unwrap()
            .set_modified(old)
            .unwrap();
        let mut options = ManifestOptions::new();
        options.features(Features::DEFAULT | Features::MTIME);
        let graceful = AddFlags::GRACEFUL;
        let (_, report) = options.generate(Vec::new(), open_path(dir), graceful).unwrap();
        assert_eq!(
            (report.files(), report.directories(), report.others(), report.bytes()),
            (3, 2, 1, 5 + 5 + 5)
        );
        assert_eq!((report.entries_omitted(), report.fields_omitted()), (1, 1));
        let e = options
            .generate(Vec::new(), open_path(dir), AddFlags::NONE)
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::UnwritableName));
        // generate_at() walks with the flags it is given as well, and a
        // walk that fails leaves no file.
        let out = TempDir::new("manifest-report-out");
        let e = options
            .generate_at(
                File::open(&out.0).unwrap(),
                Path::new("m"),
                open_path(dir),
                AddFlags::NONE,
            )
            .unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::UnwritableName));
        assert!(names_in(&out.0).is_empty());
        let in_file = options
            .generate_at(File::open(&out.0).unwrap(), Path::new("m"), open_path(dir), graceful)
            .unwrap();
        assert_eq!(in_file, report);
        assert_eq!(names_in(&out.0), ["m"]);
    }

    /// Two different files with one name are an error, the same file twice
    /// is one, and a directory that was not added fails where the features
    /// need what it would say.
    #[test]
    fn what_finish_decides() {
        let file = FileObject::new(testing::name("x"));
        let mut writer = ManifestOptions::new().open(Vec::new()).unwrap();
        writer.add_object(&file).unwrap();
        writer.add_object(&file).unwrap();
        let (out, report) = writer.finish().unwrap();
        assert_eq!((read_whole(&out).unwrap().objects.len(), report.files()), (1, 1));
        let mut other = FileObject::new(testing::name("x"));
        other.size = Some(1);
        let mut writer = ManifestOptions::new().open(Vec::new()).unwrap();
        writer.add_object(&file).unwrap();
        writer.add_object(&other).unwrap();
        let e = writer.finish().unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::Duplicate), Some("x"))
        );
        let mut options = ManifestOptions::new();
        options.features(Features::DEFAULT | Features::READ_ONLY);
        let mut writer = options.open(Vec::new()).unwrap();
        writer.add_object(&FileObject::new(testing::name("parent/x"))).unwrap();
        let e = writer.finish().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::MissingParent));
    }

    /// The variable that names a directory without O_TMPFILE, the one
    /// fuse-overlayfs mounts, in which the test binary runs
    /// [`created_in_the_tree`] again.
    const NO_TMPFILE_DIR: &str = "UAPI16_TEST_NO_TMPFILE_DIR";

    /// A manifest that is created in the tree it lists, on a file system
    /// without O_TMPFILE, has a name of its own until it is complete, which
    /// the walk passes over. The test binary runs this test again in a user
    /// and mount namespace from unshare(1), on a mount of fuse-overlayfs,
    /// which has no O_TMPFILE. It is skipped where there is none.
    #[test]
    fn created_in_the_tree() {
        if let Some(dir) = std::env::var_os(NO_TMPFILE_DIR) {
            return check_created_in_the_tree(Path::new(&dir));
        }
        let tmp = TempDir::new("manifest-in-the-tree");
        let dir = &tmp.0;
        for part in ["lower/a", "upper", "work", "merged"] {
            fs::create_dir_all(dir.join(part)).unwrap();
        }
        fs::write(dir.join("lower/a/file"), b"hello").unwrap();
        fs::write(dir.join("lower/file"), b"world").unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        // The script exits with 77 where it can't mount the file system,
        // and unmounts it once the test is done, which ends fuse-overlayfs.
        let script = concat!(
            r#"d=$1; "#,
            r#"fuse-overlayfs -o "lowerdir=$d/lower,upperdir=$d/upper,workdir=$d/work" "$d/merged" || exit 77; "#,
            r#""$2" --exact manifest::tests::created_in_the_tree; status=$?; "#,
            r#"umount "$d/merged"; exit $status"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(NO_TMPFILE_DIR, dir.join("merged"))
            .output()
            .unwrap();
        if output.status.code() == Some(77) {
            eprintln!("skipping: fuse-overlayfs can't mount a file system here");
            return;
        }
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The variable that names the merged directory of fuse-overlayfs in
    /// which the test binary runs [`files_with_the_inode_of_the_manifest`]
    /// again.
    const SAME_INODE_DIR: &str = "UAPI16_TEST_SAME_INODE_DIR";

    /// How many files the lower layer of that test has: more than the
    /// upper layer has inodes by the time the manifest is made there, so
    /// that one of them has the inode number the manifest gets.
    const LOWER_FILES: usize = 40;

    /// A file of the tree that has the device and the inode number of the
    /// manifest is listed, where the manifest itself is passed over. On
    /// fuse-overlayfs the files of both layers show under one device with
    /// the inode numbers they have in their layers. So with each layer on
    /// a file system of its own, a manifest that is created in the tree,
    /// which is made in the upper layer and has a name of its own there
    /// until it is complete, gets the number of a file of the lower one.
    /// The test binary runs this test again in a user and mount namespace
    /// from unshare(1), where the two layers are a tmpfs each. It is
    /// skipped where there is no fuse-overlayfs, and where no file has the
    /// number of the manifest.
    #[test]
    fn files_with_the_inode_of_the_manifest() {
        if let Some(dir) = std::env::var_os(SAME_INODE_DIR) {
            return check_same_inode(Path::new(&dir));
        }
        let tmp = TempDir::new("manifest-same-inode");
        rerun_on_two_layers(
            &tmp.0,
            "manifest::tests::files_with_the_inode_of_the_manifest",
            SAME_INODE_DIR,
        );
    }

    /// Runs the test `test` of the test binary again in a user and mount
    /// namespace from unshare(1), on a mount of fuse-overlayfs below the
    /// directory `dir` whose two layers are a tmpfs each, with
    /// [`LOWER_FILES`] files in the lower one, and with the merged
    /// directory as the value of the variable `variable`. The test is
    /// skipped where that can't be mounted.
    fn rerun_on_two_layers(dir: &Path, test: &str, variable: &str) {
        for part in ["lower", "upper", "merged"] {
            fs::create_dir(dir.join(part)).unwrap();
        }
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        // The script exits with 77 where it can't mount the file systems.
        // The files of the lower layer are made on its tmpfs, where a new
        // file system numbers them from its first inodes on.
        let script = concat!(
            r#"d=$1; mount -t tmpfs tmpfs "$d/lower" && mount -t tmpfs tmpfs "$d/upper" || exit 77; "#,
            r#"mkdir "$d/lower/files" "$d/upper/files" "$d/upper/work" || exit 77; "#,
            r#"i=0; while [ "$i" -lt "$3" ]; do echo "$i" > "$d/lower/files/f$i"; i=$((i + 1)); done; "#,
            r#"fuse-overlayfs -o "lowerdir=$d/lower/files,upperdir=$d/upper/files,workdir=$d/upper/work" "$d/merged" "#,
            r#"|| exit 77; "#,
            r#""$2" --exact "$4" --nocapture; status=$?; "#,
            r#"umount "$d/merged"; exit $status"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .arg(LOWER_FILES.to_string())
            .arg(test)
            .env(variable, dir.join("merged"))
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

    /// The checks of [`files_with_the_inode_of_the_manifest`] in `dir`.
    fn check_same_inode(dir: &Path) {
        let report = ManifestOptions::new()
            .generate_at(File::open(dir).unwrap(), Path::new("m"), open_path(dir), AddFlags::NONE)
            .unwrap();
        // The manifest has the inode it was made with, under its name now.
        let numbers = |name: &str| {
            let meta = fs::symlink_metadata(dir.join(name)).unwrap();
            (meta.dev(), meta.ino())
        };
        let mut files: Vec<String> = (0..LOWER_FILES).map(|i| format!("f{}", i)).collect();
        files.sort();
        let same: Vec<&String> = files.iter().filter(|name| numbers(name) == numbers("m")).collect();
        if same.is_empty() {
            eprintln!("skipping: no file of the lower layer has the inode number of the manifest here");
            return;
        }
        let names: Vec<String> = read_whole(&fs::read(dir.join("m")).unwrap())
            .unwrap()
            .objects
            .iter()
            .map(|object| object.name().to_string())
            .collect();
        assert_eq!(names, files, "{:?}", same);
        assert_eq!((report.files(), report.directories()), (LOWER_FILES as u64, 1));
    }

    /// The variable that names the merged directory of fuse-overlayfs in
    /// which the test binary runs
    /// [`own_files_with_the_inode_of_the_manifest`] again.
    const OWN_SAME_INODE_DIR: &str = "UAPI16_TEST_OWN_SAME_INODE_DIR";

    /// Two files of the manifest's own that have one device and one inode
    /// number are both passed over, and both are kept open. On
    /// fuse-overlayfs with each layer on a file system of its own, a
    /// manifest that is created in the tree gets the number of a file of
    /// the lower layer, see [`files_with_the_inode_of_the_manifest`]. Here
    /// that file is made a file of the manifest's own as well, as a scratch
    /// file with the number of the manifest would be. The walk lists
    /// neither of the two, and every other file. The test binary runs this
    /// test again as it does that one, and it is skipped where that one
    /// is.
    #[test]
    fn own_files_with_the_inode_of_the_manifest() {
        if let Some(dir) = std::env::var_os(OWN_SAME_INODE_DIR) {
            return check_own_same_inode(Path::new(&dir));
        }
        let tmp = TempDir::new("manifest-own-same-inode");
        rerun_on_two_layers(
            &tmp.0,
            "manifest::tests::own_files_with_the_inode_of_the_manifest",
            OWN_SAME_INODE_DIR,
        );
    }

    /// The checks of [`own_files_with_the_inode_of_the_manifest`] in `dir`.
    fn check_own_same_inode(dir: &Path) {
        let mut writer = ManifestOptions::new()
            .create_at(File::open(dir).unwrap(), Path::new("m"))
            .unwrap();
        // The inode the manifest is kept with, under the name it has until
        // it is complete.
        let new_file = writer.new_file.as_ref().unwrap();
        let (inode, _) = new_file.named_file().unwrap().expect("fuse-overlayfs has no O_TMPFILE");
        let inode_of = |name: &str| {
            let status = Status::of(open_path(&dir.join(name)).as_fd()).unwrap();
            status.identity.inode_id()
        };
        let mut files: Vec<String> = (0..LOWER_FILES).map(|i| format!("f{}", i)).collect();
        files.sort();
        let Some(same) = files.iter().position(|name| inode_of(name) == inode) else {
            eprintln!("skipping: no file of the lower layer has the inode number of the manifest here");
            return;
        };
        let same = files.remove(same);
        let other = Arc::new(File::open(dir.join(&same)).unwrap());
        writer.walker.pass_over(inode, Arc::clone(&other));
        writer.add_all(open_path(dir).as_fd(), AddFlags::NONE).unwrap();
        // What the writer has of that file, next to the test.
        let held = Arc::strong_count(&other) - 1;
        let (_, report) = writer.finish().unwrap();
        let names: Vec<String> = read_whole(&fs::read(dir.join("m")).unwrap())
            .unwrap()
            .objects
            .iter()
            .map(|object| object.name().to_string())
            .collect();
        assert_eq!(names, files, "{:?}", same);
        assert_eq!((report.files(), report.directories()), (LOWER_FILES as u64 - 1, 1));
        assert_eq!(held, 1);
    }

    /// The checks of [`created_in_the_tree`] in `dir`.
    fn check_created_in_the_tree(dir: &Path) {
        let flags = OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC;
        let unnamed = rustix::fs::open(dir, flags, rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR);
        assert_eq!(unnamed.unwrap_err(), rustix::io::Errno::OPNOTSUPP);
        let report = ManifestOptions::new()
            .sync(true)
            .generate_at(File::open(dir).unwrap(), Path::new("m"), open_path(dir), AddFlags::NONE)
            .unwrap();
        let names: Vec<String> = read_whole(&fs::read(dir.join("m")).unwrap())
            .unwrap()
            .objects
            .iter()
            .map(|object| object.name().to_string())
            .collect();
        assert_eq!(names, ["a", "a/file", "file"]);
        assert_eq!((report.files(), report.directories()), (2, 2));
        assert_eq!(names_in(dir), ["a", "file", "m"]);
    }

    /// The variable that tells the test binary, run again by
    /// [`no_descriptor_left`] with few descriptors, where the tree is.
    const NO_DESCRIPTORS_DIR: &str = "UAPI16_TEST_MANIFEST_NO_DESCRIPTORS_DIR";

    /// Where the process has no descriptor left, an add that opens nothing
    /// is done all the same, as that of a file object of a caller, and a
    /// walk fails with EMFILE where it first opens something, which is the
    /// directory it starts at. What fails for a reason of its own fails for
    /// it there as well: options with a feature of partitions fail with
    /// TreeProblem::FeatureNotForTrees, whichever way the writer is made,
    /// before a descriptor is taken. The test binary runs this test again
    /// with 64 descriptors at most, and the test takes what is left of
    /// them.
    #[test]
    fn no_descriptor_left() {
        if let Some(dir) = std::env::var_os(NO_DESCRIPTORS_DIR) {
            return check_no_descriptor_left(Path::new(&dir));
        }
        let tree = tree("manifest-no-descriptors");
        let dir = &tree.0;
        let script = r#"ulimit -n 64 || exit 1; exec "$1" --exact manifest::tests::no_descriptor_left"#;
        let output = Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(std::env::current_exe().unwrap())
            .env(NO_DESCRIPTORS_DIR, dir)
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`no_descriptor_left`] in the tree `dir`.
    fn check_no_descriptor_left(dir: &Path) {
        let top = open_path(dir);
        let mut partitions = ManifestOptions::new();
        partitions.features(Features::DEFAULT | Features::GPT_LABEL);
        let mut usable = ManifestOptions::new().open(Vec::new()).unwrap();
        let mut taken = Vec::new();
        loop {
            match rustix::fs::open("/dev/null", OFlags::RDONLY | OFlags::CLOEXEC, rustix::fs::Mode::empty()) {
                Ok(fd) => taken.push(fd),
                Err(rustix::io::Errno::MFILE) => break,
                Err(e) => panic!("{}", e),
            }
        }
        usable.add_object(&FileObject::new(testing::name("given"))).unwrap();
        // The directory a walk starts at is opened for its listing.
        let no_listing = ManifestOptions::new().generate(Vec::new(), &top, AddFlags::NONE);
        let refused = [
            partitions.open(Vec::new()).map(drop),
            partitions.generate(Vec::new(), &top, AddFlags::NONE).map(drop),
            partitions.create_at(&top, Path::new("m")).map(drop),
            partitions
                .generate_at(&top, Path::new("m"), &top, AddFlags::NONE)
                .map(drop),
        ];
        drop(taken);
        let e = no_listing.unwrap_err();
        assert_eq!((errno(&e), e.name()), (Some(libc::EMFILE), Some("")), "{}", e);
        let (out, report) = usable.finish().unwrap();
        let names: Vec<String> = read_whole(&out)
            .unwrap()
            .objects
            .iter()
            .map(|object| object.name().to_string())
            .collect();
        assert_eq!(names, ["given"]);
        assert_eq!((report.directories(), report.files()), (1, 1));
        for e in refused {
            assert_eq!(e.unwrap_err().kind(), ErrorKind::Tree(TreeProblem::FeatureNotForTrees));
        }
    }

    /// A file object of a caller that a writer refuses is refused when it
    /// is added, and the writer is as it was: it takes the next file
    /// object, and what it writes then is what it writes without the one
    /// it refused. That holds for what its contents objects say of
    /// themselves as well: a literal that is not the data its hash is of,
    /// and a file that is the root.
    #[test]
    fn refused_file_objects() {
        let mut refused = FileObject::new(testing::name("x"));
        refused.inode.uid = Some(65535);
        let mut writer = ManifestOptions::new().open(Vec::new()).unwrap();
        let e = writer.add_object(&refused).unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Manifest(crate::Problem::FieldOutOfRange), Some("x"))
        );
        let literal = crate::ContentsObject {
            original_sha256: Some(crate::Sha256::digest(b"abc")),
            ..crate::ContentsObject::new(crate::ContentsSource::Literal(b"xyz".to_vec()))
        };
        let root = crate::ContentsObject::new(crate::ContentsSource::File(crate::NameBuf::default()));
        let contents = [
            (literal, crate::Problem::Contradiction, crate::Field::Literal),
            (root, crate::Problem::InvalidContents, crate::Field::File),
        ];
        for (contents, problem, field) in contents {
            let mut refused = FileObject::new(testing::name("x"));
            refused.size = Some(3);
            refused.contents = vec![contents];
            let e = writer.add_object(&refused).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.name()),
                (ErrorKind::Manifest(problem), Some(field), Some("x")),
                "{}",
                e
            );
        }
        // A name of an inode that does not have what the first name of
        // that inode has is refused as well, and the first name stays.
        let linked = |name: &str, size| {
            let mut object = FileObject::new(testing::name(name));
            object.inode_token = std::num::NonZeroU64::new(1);
            object.size = Some(size);
            object
        };
        writer.add_object(&linked("first", 1)).unwrap();
        let e = writer.add_object(&linked("other", 2)).unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.hardlink_name()),
            (
                ErrorKind::Tree(TreeProblem::HardlinkMismatch),
                Some("other"),
                Some("first")
            )
        );
        let added = FileObject::new(testing::name("added"));
        writer.add_object(&added).unwrap();
        let (out, _) = writer.finish().unwrap();
        let mut clean = ManifestOptions::new().open(Vec::new()).unwrap();
        clean.add_object(&linked("first", 1)).unwrap();
        clean.add_object(&added).unwrap();
        let (clean, _) = clean.finish().unwrap();
        assert_eq!(out, clean);
    }

    /// The root a caller describes is the root file object of the manifest,
    /// with the features and the order of the options, and the first root
    /// that is added says what the root is like. A root with a field of a
    /// feature the manifest does not record is refused when it is added,
    /// and so is one with a field or a string no manifest may have, and one
    /// whose record is too large. The writer is as it was then: what it
    /// writes is what it writes without the roots it refused.
    #[test]
    fn roots_of_a_caller() {
        let mode = |bits| InodeAttributes {
            mode: Some(crate::Mode::new(bits).unwrap()),
            ..InodeAttributes::default()
        };
        let labeled = |label: &str| FileSystemIdentity {
            label: Some(label.to_string()),
            ..FileSystemIdentity::default()
        };
        let unlabeled = FileSystemIdentity::default();
        let features = Features::MODE | Features::MTIME | Features::FS_LABEL;
        let mut options = ManifestOptions::new();
        options.features(features);
        let inode = InodeAttributes {
            mtime_nsec: Some(1_000_000_007),
            ..mode(0o750)
        };
        let file = FileObject::new(testing::name("x"));
        let mut writer = options.open(Vec::new()).unwrap();
        writer.add_object(&file).unwrap();
        writer.add_root(&inode, &labeled("ESP")).unwrap();
        writer.add_root(&mode(0o700), &labeled("other")).unwrap();
        let (out, report) = writer.finish().unwrap();
        let whole = read_whole(&out).unwrap();
        assert!(whole.root.inode().eq_ignore_filled_in(&inode));
        assert_eq!(whole.root.file_system(), &labeled("ESP"));
        assert_eq!(
            (whole.root.features(), whole.root.order()),
            (Some(features), Some(Order::CodePoint))
        );
        assert_eq!((whole.objects.len(), report.files(), report.directories()), (1, 1, 1));
        // Roots that are refused: the label is recorded and the
        // modification time is not.
        options.features(Features::MODE | Features::UID | Features::FS_LABEL | Features::USER_XATTR);
        let owned = InodeAttributes {
            uid: Some(65535),
            ..mode(0o755)
        };
        let large = InodeAttributes {
            user_xattrs: Some(Box::new(
                [("large".to_string(), vec![0; crate::MAX_RECORD_SIZE])].into(),
            )),
            ..mode(0o755)
        };
        let refused = [
            (
                &inode,
                &unlabeled,
                crate::Problem::UnlistedFeature,
                Some(crate::Field::MTimeNSec),
            ),
            (
                &owned,
                &unlabeled,
                crate::Problem::FieldOutOfRange,
                Some(crate::Field::Uid),
            ),
            (
                &mode(0o755),
                &labeled("a\0b"),
                crate::Problem::InvalidString,
                Some(crate::Field::FsLabel),
            ),
            (&large, &unlabeled, crate::Problem::RecordTooLarge, None),
        ];
        let mut writer = options.open(Vec::new()).unwrap();
        for (inode, file_system, problem, field) in refused {
            let e = writer.add_root(inode, file_system).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.name(), e.record_number()),
                (ErrorKind::Manifest(problem), field, None, None),
                "{}",
                e
            );
        }
        writer.add_root(&mode(0o711), &labeled("ESP")).unwrap();
        writer.add_object(&file).unwrap();
        let (out, _) = writer.finish().unwrap();
        let mut clean = options.open(Vec::new()).unwrap();
        clean.add_root(&mode(0o711), &labeled("ESP")).unwrap();
        clean.add_object(&file).unwrap();
        assert_eq!(out, clean.finish().unwrap().0);
        assert_eq!(read_whole(&out).unwrap().root.inode().mode(), mode(0o711).mode);
        // A root whose record is as large as a record may be is taken, and
        // one byte more is refused when it is added: the record that is
        // checked is the one the manifest gets, with the features and the
        // order of the options.
        let sized = |value: usize| InodeAttributes {
            user_xattrs: Some(Box::new([("large".to_string(), vec![b'a'; value])].into())),
            ..mode(0o755)
        };
        let root_record = |out: &[u8]| out.iter().position(|&byte| byte == crate::RECORD_END).unwrap() + 1;
        let mut writer = options.open(Vec::new()).unwrap();
        writer.add_root(&sized(1), &unlabeled).unwrap();
        let fits = crate::MAX_RECORD_SIZE - (root_record(&writer.finish().unwrap().0) - 1);
        let mut writer = options.open(Vec::new()).unwrap();
        let e = writer.add_root(&sized(fits + 1), &unlabeled).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(crate::Problem::RecordTooLarge));
        writer.add_root(&sized(fits), &unlabeled).unwrap();
        assert_eq!(root_record(&writer.finish().unwrap().0), crate::MAX_RECORD_SIZE);
    }

    /// A manifest that records the UUID or the volume serial number of its
    /// file system need not have one. Without a root it is written with a
    /// plain one, a root a caller describes without them is taken as it
    /// is, and the walk of a tree leaves out the one its file system does
    /// not have. Only the walk counts what it leaves out.
    #[test]
    fn roots_without_a_uuid_or_a_serial() {
        let features = Features::DEFAULT | Features::FS_UUID | Features::FAT_SERIAL;
        let mut options = ManifestOptions::new();
        options.features(features);
        let file = FileObject::new(testing::name("x"));
        let root_of = |out: &[u8]| read_whole(out).unwrap().root;
        let mut writer = options.open(Vec::new()).unwrap();
        writer.add_object(&file).unwrap();
        let (plain, report) = writer.finish().unwrap();
        assert_eq!(
            (root_of(&plain).features(), root_of(&plain).file_system()),
            (Some(features), &FileSystemIdentity::default())
        );
        assert_eq!(report.fields_omitted(), 0);
        let mut writer = options.open(Vec::new()).unwrap();
        writer
            .add_root(&InodeAttributes::default(), &FileSystemIdentity::default())
            .unwrap();
        writer.add_object(&file).unwrap();
        let (given, report) = writer.finish().unwrap();
        assert_eq!((&given, report.fields_omitted()), (&plain, 0));
        // A root with one of the two has it.
        let with_uuid = FileSystemIdentity {
            uuid: Some("1234abcd-5678-4ef0-9abc-def012345678".parse().unwrap()),
            ..FileSystemIdentity::default()
        };
        let mut writer = options.open(Vec::new()).unwrap();
        writer.add_root(&InodeAttributes::default(), &with_uuid).unwrap();
        assert_eq!(root_of(&writer.finish().unwrap().0).file_system(), &with_uuid);
        // The walk of a tree records what its file system has of the two,
        // and fails for neither: a file system with a UUID is no FAT, and
        // FAT has none. It counts each one that it leaves out, and none
        // that the manifest does not record.
        let tree = tree("manifest-identity");
        let walk = |recorded| {
            let mut options = ManifestOptions::new();
            options.features(recorded);
            let (out, report) = options
                .generate(Vec::new(), open_path(&tree.0), AddFlags::NONE)
                .unwrap();
            (root_of(&out), report.fields_omitted())
        };
        let (root, omitted) = walk(features);
        assert_eq!((root.features(), root.file_system().label()), (Some(features), None));
        let (uuid, serial) = (root.file_system().uuid(), root.file_system().fat_serial());
        let (no_uuid, no_serial) = (u64::from(uuid.is_none()), u64::from(serial.is_none()));
        assert_eq!(omitted, no_uuid + no_serial);
        let (root, omitted) = walk(Features::DEFAULT | Features::FS_UUID);
        assert_eq!((root.file_system().uuid(), omitted), (uuid, no_uuid));
        let (root, omitted) = walk(Features::DEFAULT | Features::FAT_SERIAL);
        assert_eq!((root.file_system().fat_serial(), omitted), (serial, no_serial));
        assert_eq!(walk(Features::DEFAULT).1, 0);
    }

    /// The variable that tells the test binary, run again inside the
    /// namespaces of [`trees_without_a_uuid_or_a_serial`], where the
    /// directory with the mount is.
    const RAMFS_DIR: &str = "UAPI16_TEST_MANIFEST_RAMFS_DIR";

    /// The walk of a tree whose file system has neither a UUID nor a volume
    /// serial number leaves out both, and the report counts each of them.
    /// A ramfs is such a file system. Mounting one takes a user and a
    /// mount namespace, which unshare(1) makes, and the test binary runs
    /// this test again inside them. It is skipped where the kernel gives a
    /// ramfs a UUID, which the mount is asked for first.
    #[test]
    fn trees_without_a_uuid_or_a_serial() {
        if let Some(dir) = std::env::var_os(RAMFS_DIR) {
            let tree = Path::new(&dir).join("mount");
            // The mount is asked as a walk asks the root of a tree.
            let asked = Entry::of(open_path(&tree).as_fd()).unwrap().reopen(None).unwrap();
            if matches!(asked.fs_uuid().unwrap(), Some(FsUuid::Uuid(_))) {
                eprintln!("skipping: a ramfs has a UUID here");
                return;
            }
            fs::write(tree.join("file"), b"hello").unwrap();
            for (features, left_out) in [
                (Features::FS_UUID, 1),
                (Features::FAT_SERIAL, 1),
                (Features::FS_UUID | Features::FAT_SERIAL, 2),
                (Features::NONE, 0),
            ] {
                let mut options = ManifestOptions::new();
                options.features(features);
                let (out, report) = options.generate(Vec::new(), open_path(&tree), AddFlags::NONE).unwrap();
                let root: RootObject = read_whole(&out).unwrap().root;
                assert_eq!(
                    (root.file_system(), report.fields_omitted(), report.files()),
                    (&FileSystemIdentity::default(), left_out, 1),
                    "{:?}",
                    features
                );
            }
            return;
        }
        let tmp = TempDir::new("manifest-ramfs");
        let dir = &tmp.0;
        fs::create_dir(dir.join("mount")).unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        let script = concat!(
            r#"set -e; mount -t ramfs ramfs "$1/mount"; "#,
            r#"exec "$2" --exact manifest::tests::trees_without_a_uuid_or_a_serial --nocapture"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(RAMFS_DIR, dir)
            .output()
            .unwrap();
        // What the test said where it ran again, such as that it skipped.
        let said = String::from_utf8_lossy(&output.stderr);
        if let Some(skipped) = said.lines().find(|line| line.starts_with("skipping")) {
            eprintln!("{}", skipped);
        }
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// A writer shows what it writes to.
    #[test]
    fn debug() {
        let tree = tree("manifest-debug");
        let writer = ManifestOptions::new().open(Vec::<u8>::new()).unwrap();
        assert_eq!(format!("{:?}", writer), "ManifestWriter { out: [], .. }");
        let out = TempDir::new("manifest-debug-out");
        let writer = ManifestOptions::new()
            .create_at(File::open(&out.0).unwrap(), Path::new("m"))
            .unwrap();
        let shown = format!("{:?}", writer);
        assert!(shown.starts_with("ManifestWriter { out: File {"), "{}", shown);
        assert!(shown.ends_with(" }, .. }"), "{}", shown);
        drop(tree);
    }

    /// A manifest file is not synced unless asked for, and one that is
    /// comes out the same, from create_at() and from generate_at().
    #[test]
    fn synced_files() {
        assert!(!ManifestOptions::new().sync);
        assert!(!ManifestOptions::default().sync);
        let tree = tree("manifest-sync");
        let out = TempDir::new("manifest-sync-out");
        let (expected, _) = ManifestOptions::new()
            .generate(Vec::new(), open_path(&tree.0), AddFlags::NONE)
            .unwrap();
        let mut options = ManifestOptions::new();
        options.sync(true);
        let mut writer = options.create_at(File::open(&out.0).unwrap(), Path::new("m")).unwrap();
        writer.add_all(open_path(&tree.0).as_fd(), AddFlags::NONE).unwrap();
        writer.finish().unwrap();
        assert_eq!(fs::read(out.0.join("m")).unwrap(), expected);
        options
            .generate_at(
                File::open(&out.0).unwrap(),
                Path::new("again"),
                open_path(&tree.0),
                AddFlags::NONE,
            )
            .unwrap();
        assert_eq!(fs::read(out.0.join("again")).unwrap(), expected);
    }

    /// A finish() that fails after the call that gave the file its name
    /// leaves the manifest in the file, which keeps the name. Here the
    /// directory takes the name and can't be opened for the sync of it,
    /// since it may not be read. It is skipped where the tests may read any
    /// directory.
    #[test]
    fn keeps_the_manifest_where_the_sync_fails() {
        let tmp = TempDir::new("manifest-sync-fails");
        let dir = &tmp.0;
        let mut options = ManifestOptions::new();
        options.sync(true);
        let mut writer = options.create_at(File::open(dir).unwrap(), Path::new("m")).unwrap();
        writer.add_object(&FileObject::new(testing::name("file"))).unwrap();
        // A directory that may be written and searched, and not read.
        let locked = fs::set_permissions(dir, fs::Permissions::from_mode(0o300)).is_ok() && fs::read_dir(dir).is_err();
        let finished = writer.finish();
        let manifest = fs::read(dir.join("m"));
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).unwrap();
        if !locked {
            eprintln!("skipping the directory that can't be synced: the tests may read any");
            return;
        }
        assert_eq!(errno(&finished.unwrap_err()), Some(libc::EACCES));
        let whole = read_whole(&manifest.unwrap()).unwrap();
        let listed: Vec<&str> = whole.objects.iter().map(|object| object.name().as_str()).collect();
        assert_eq!((listed, names_in(dir)), (vec!["file"], vec!["m".to_string()]));
    }

    /// The variable that names a directory of a FAT file system, as for
    /// the tests of the optional features.
    const FAT_DIR: &str = "UAPI16_TEST_FAT_DIR";

    /// File objects of a caller that take more room than the 32 MiB the
    /// sort keeps in memory, so that a manifest that lists them writes
    /// runs to a scratch file.
    fn large_objects() -> Vec<FileObject> {
        (0..40u8)
            .map(|i| {
                let mut object = FileObject::new(testing::name(&format!("large/{:02}", i)));
                let data = vec![i; 1 << 20];
                object.size = Some(data.len() as u64);
                object.contents = vec![crate::ContentsObject::new(crate::ContentsSource::Literal(data))];
                object
            })
            .collect()
    }

    /// On FAT, which has no O_TMPFILE, a new manifest file has a name of
    /// its own until it is complete and gets its own with RENAME_NOREPLACE,
    /// and the scratch files get names that they lose right away. File
    /// objects that take more room than the sort keeps in memory make it
    /// write runs to them. The manifest is the one written to a stream, and
    /// nothing else is left behind. FAT has a volume serial number and no
    /// UUID, which the walk of a tree there leaves out and counts.
    #[test]
    fn on_fat() {
        let Some(dir) = std::env::var_os(FAT_DIR) else {
            eprintln!("skipping: {} names no directory of a FAT file system", FAT_DIR);
            return;
        };
        fn fill<W: Write>(writer: &mut ManifestWriter<W>, tree: &Path, large: &[FileObject]) {
            writer.add_all(open_path(tree).as_fd(), AddFlags::NONE).unwrap();
            for object in large {
                writer.add_object(object).unwrap();
            }
        }
        let fat = Path::new(&dir).join("manifest-on-fat");
        let _ = fs::remove_dir_all(&fat);
        let tree = fat.join("tree");
        fs::create_dir_all(tree.join("a")).unwrap();
        fs::write(tree.join("a/file"), b"hello").unwrap();
        fs::write(tree.join("file"), b"world").unwrap();
        let large = large_objects();
        let mut options = ManifestOptions::new();
        options.sync(true);
        let mut writer = options.create_at(File::open(&fat).unwrap(), Path::new("m")).unwrap();
        fill(&mut writer, &tree, &large);
        writer.finish().unwrap();
        let mut writer = options.open(Vec::new()).unwrap();
        fill(&mut writer, &tree, &large);
        let (streamed, report) = writer.finish().unwrap();
        assert_eq!((report.files(), report.directories()), (42, 3));
        assert_eq!(fs::read(fat.join("m")).unwrap(), streamed);
        assert_eq!(names_in(&fat), ["m", "tree"]);
        let scratch = std::env::temp_dir();
        assert!(names_in(&scratch).iter().all(|name| !name.starts_with(".uapi16-")));
        for (features, left_out) in [
            (Features::FS_UUID, 1),
            (Features::FS_UUID | Features::FAT_SERIAL, 1),
            (Features::FAT_SERIAL, 0),
        ] {
            let mut options = ManifestOptions::new();
            options.features(Features::DEFAULT | features);
            let (out, report) = options.generate(Vec::new(), open_path(&tree), AddFlags::NONE).unwrap();
            let root: RootObject = read_whole(&out).unwrap().root;
            let identity = root.file_system();
            assert_eq!(
                (
                    identity.uuid(),
                    identity.fat_serial().is_some(),
                    report.fields_omitted()
                ),
                (None, features.contains(Features::FAT_SERIAL), left_out),
                "{:?}",
                features
            );
        }
        fs::remove_dir_all(&fat).unwrap();
    }

    /// The variable that names a directory of a file system that keeps a
    /// file that is unlinked while it is open in its directory, under a
    /// name of its own, until the file is closed: NFS does, and so does
    /// libfuse for a FUSE file system on its high-level interface that does
    /// not set hard_remove.
    const SILLY_RENAME_DIR: &str = "UAPI16_TEST_SILLY_RENAME_DIR";

    /// Whether the directory `dir` comes to hold the names `names` and no
    /// others. A file system that keeps a file that was unlinked takes a
    /// moment to remove it once it was closed.
    fn comes_to_hold(dir: &Path, names: &[&str]) -> bool {
        const TRIES: u32 = 500;
        const PAUSE: std::time::Duration = std::time::Duration::from_millis(10);
        (0..TRIES).any(|_| {
            let there = names_in(dir) == names;
            if !there {
                std::thread::sleep(PAUSE);
            }
            there
        })
    }

    /// A manifest lists none of the files it made itself. On a file system
    /// that keeps a file that was unlinked while it is open, the scratch
    /// files of a manifest that is created in the tree it lists are in a
    /// directory of that tree, under the names the file system gave them.
    /// The walk passes over them, and over the manifest, which has a name
    /// of its own there until it is complete. Nothing but the manifest is
    /// left behind. It is skipped unless the variable names a directory of
    /// such a file system.
    #[test]
    fn scratch_files_in_the_tree() {
        let Some(dir) = std::env::var_os(SILLY_RENAME_DIR) else {
            eprintln!(
                "skipping: {} names no directory of a file system that keeps unlinked files",
                SILLY_RENAME_DIR
            );
            return;
        };
        let top = Path::new(&dir).join("manifest-scratch-in-the-tree");
        let out = top.join("out");
        // What an earlier run left behind: its directories, where the file
        // system removes none, see below.
        let _ = fs::remove_file(out.join("m"));
        let _ = fs::remove_dir_all(&top);
        fs::create_dir_all(top.join("a")).unwrap();
        fs::create_dir_all(&out).unwrap();
        fs::write(top.join("a/file"), b"hello").unwrap();
        // The file system is one that keeps such a file, until it is closed.
        let unlinked = File::create(out.join("unlinked")).unwrap();
        fs::remove_file(out.join("unlinked")).unwrap();
        assert_eq!(names_in(&out).len(), 1, "{:?} keeps no file that was unlinked", out);
        drop(unlinked);
        assert!(comes_to_hold(&out, &[]));
        let mut writer = ManifestOptions::new()
            .create_at(File::open(&out).unwrap(), Path::new("m"))
            .unwrap();
        for object in &large_objects() {
            writer.add_object(object).unwrap();
        }
        // The scratch file of the sort is in the directory now, next to
        // the manifest where that has a name of its own.
        let kept = names_in(&out);
        assert!(kept.iter().any(|name| !name.starts_with(".#uapi16-")), "{:?}", kept);
        writer.add_all(open_path(&top).as_fd(), AddFlags::NONE).unwrap();
        let (_, report) = writer.finish().unwrap();
        let whole = read_whole(&fs::read(out.join("m")).unwrap()).unwrap();
        let listed: Vec<&str> = whole
            .objects
            .iter()
            .map(|object| object.name().as_str())
            .filter(|name| !name.starts_with("large"))
            .collect();
        assert_eq!(listed, ["a", "a/file", "out"]);
        assert_eq!((report.files(), report.directories()), (41, 4));
        assert!(comes_to_hold(&out, &["m"]));
        // A FUSE file system need not be able to remove a directory, which
        // is ENOSYS then. The files go, and the directories are left behind.
        fs::remove_file(out.join("m")).unwrap();
        fs::remove_file(top.join("a/file")).unwrap();
        if let Err(e) = fs::remove_dir_all(&top) {
            assert_eq!(e.raw_os_error(), Some(libc::ENOSYS), "{}", e);
        }
    }

    /// Two file objects of a caller that are hard links of each other, by
    /// the token `token`.
    fn linked(token: u64) -> [FileObject; 2] {
        ["a", "b"].map(|side| {
            let mut object = FileObject::new(testing::name(&format!("links/{}-{}", token, side)));
            object.inode_token = std::num::NonZeroU64::new(token);
            object
        })
    }

    /// The files this process has open that were made in the directory
    /// `dir`, but for the files `others`: the scratch files of a writer
    /// that makes them there, where `others` is its new file.
    fn open_but(dir: &Path, others: &[OpenFile]) -> Vec<OpenFile> {
        let mut files = OpenFile::made_in(dir);
        files.retain(|file| others.iter().all(|other| other.inode != file.inode));
        files
    }

    /// A writer has every scratch file it made open for as long as it is
    /// there, also the ones it is done with. The table of the hard links
    /// gives back the file of its old pages once it has doubled on disk.
    /// That file is empty and open from then on, and the next doubling goes
    /// into it. So the table has three scratch files however often it
    /// doubles. A writer that is dropped closes all of them, and so does
    /// finish().
    #[test]
    fn keeps_its_scratch_files_open() {
        /// Far more hard links than move the table of the hard links to
        /// disk and double it there.
        const MOST: u64 = 500_000;
        /// How many hard links are added before the scratch files are
        /// looked at again.
        const BATCH: u64 = 1000;
        /// The scratch files of a table on disk: its pages, its names, and
        /// the pages it had, which is the file it doubles into next.
        const FILES: usize = 3;
        let tmp = TempDir::new("manifest-kept");
        let dir = &tmp.0;
        for finish in [false, true] {
            let mut writer = ManifestOptions::new()
                .create_at(File::open(dir).unwrap(), Path::new("m"))
                .unwrap();
            // What the writer has open in the directory but for the new
            // file, which is all it has there before the first add.
            let new_file = OpenFile::made_in(dir);
            let scratch_files = || open_but(dir, &new_file);
            assert!(scratch_files().is_empty());
            // Until the table is on disk and has doubled there twice: the
            // file that is empty is another one after each doubling.
            let mut token = 0;
            let mut emptied: Vec<InodeId> = Vec::new();
            let files = loop {
                let files = scratch_files();
                assert!(files.len() <= FILES, "{:?}", files);
                let empty: Vec<_> = files.iter().filter(|file| file.size == 0).collect();
                assert!(empty.len() <= 1, "{:?}", files);
                if let Some(empty) = empty.first().filter(|empty| emptied.last() != Some(&empty.inode)) {
                    emptied.push(empty.inode);
                }
                if emptied.len() == 2 {
                    break files;
                }
                assert!(token < MOST, "{:?}", files);
                for _ in 0..BATCH {
                    token += 1;
                    for object in linked(token) {
                        writer.add_object(&object).unwrap();
                    }
                }
            };
            // The pages and the names of the table, and the file of the
            // pages it had before, which the second doubling made no new
            // file for.
            assert_eq!(files.len(), FILES, "{:?}", files);
            if finish {
                writer.finish().unwrap();
                assert!(OpenFile::made_in(dir).is_empty());
                assert!(comes_to_hold(dir, &["m"]));
                fs::remove_file(dir.join("m")).unwrap();
            } else {
                drop(writer);
                assert!(OpenFile::made_in(dir).is_empty());
                assert!(comes_to_hold(dir, &[]));
            }
        }
    }

    /// The variable that tells the test binary, run again by
    /// [`gives_its_scratch_files_back`], where the directory of the test
    /// is, which is the temporary directory of that process.
    const GIVEN_BACK_DIR: &str = "UAPI16_TEST_MANIFEST_GIVEN_BACK_DIR";

    /// How the writer of [`gives_its_scratch_files_back`] ends.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum End {
        Finished,
        StepFailed,
        NameTaken,
        WalkFailed,
        Dropped,
    }

    /// finish() gives the scratch files of its writer back before it closes
    /// them, which empties them, also where it fails, and so does a
    /// generate function whose walk fails. A finish() that fails before the
    /// new file has its name empties it as well. A writer that is dropped
    /// closes its files as they are. A writer of open(), which has no new
    /// file, gives its scratch files back as one of create_at() does. It
    /// keeps them in the temporary directory, where other tests have
    /// theirs. So the test binary runs this test again in a process of its
    /// own, whose temporary directory is the directory of the test. The
    /// test has a handle of its own of each of the files, which keeps the
    /// file, and so sees what they are left with. The writer of
    /// generate_at() is nobody's but its own, so another thread takes the
    /// handles of its files while it walks a tree, and fails the walk then.
    #[test]
    fn gives_its_scratch_files_back() {
        /// More hard links than take the table of the hard links to disk.
        const LINKS: u64 = 20_000;
        /// The scratch files of the table that hold something then: its
        /// pages and its names.
        const FILES: usize = 2;
        /// The variable that names the temporary directory.
        const TMPDIR: &str = "TMPDIR";
        /// The size of a sparse file that takes a walk seconds to hash, and
        /// a minute in a build that is not optimized.
        const BRAKE: u64 = 4 << 30;
        /// How long the thread that looks at the descriptors of the process
        /// waits between two looks.
        const PAUSE: std::time::Duration = std::time::Duration::from_millis(1);
        let Some(dir) = std::env::var_os(GIVEN_BACK_DIR) else {
            let tmp = TempDir::new("manifest-given-back");
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "manifest::tests::gives_its_scratch_files_back",
                    "--nocapture",
                ])
                .env(GIVEN_BACK_DIR, &tmp.0)
                .env(TMPDIR, &tmp.0)
                .output()
                .unwrap();
            // A test binary that runs no test succeeds as well.
            let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
            assert!(output.status.success() && ran, "{:?}", output);
            return;
        };
        let dir = Path::new(&dir);
        let handle = |file: &OpenFile| {
            let descriptor = format!("/proc/self/fd/{}", file.descriptor);
            rustix::fs::open(descriptor, OFlags::PATH | OFlags::CLOEXEC, rustix::fs::Mode::empty()).unwrap()
        };
        let size = |handle: &OwnedFd| Status::of(handle.as_fd()).unwrap().size;
        // Every end of a writer of create_at(), and two of a writer of
        // open(), which give back where there is no new file: a finish()
        // that returns, and a walk that fails.
        for case @ (created, end) in [
            (true, End::Finished),
            (true, End::StepFailed),
            (true, End::NameTaken),
            (true, End::WalkFailed),
            (true, End::Dropped),
            (false, End::Finished),
            (false, End::WalkFailed),
        ] {
            let options = ManifestOptions::new();
            let mut writer = if created {
                options.create_at(File::open(dir).unwrap(), Path::new("m")).unwrap()
            } else {
                // What it writes is not looked at.
                options.open(File::create("/dev/null").unwrap()).unwrap()
            };
            // The new file, which is all a writer has open in the directory
            // before the first add: a writer of open() has nothing there.
            let new_file = OpenFile::made_in(dir);
            assert_eq!(new_file.is_empty(), !created);
            for object in (1..=LINKS).flat_map(linked) {
                writer.add_object(&object).unwrap();
            }
            // One of them has the scratch file of the sort as well. That
            // takes file objects of more than 32 MiB, and a while.
            let runs = created && end == End::WalkFailed;
            if runs {
                for object in &large_objects() {
                    writer.add_object(object).unwrap();
                }
            }
            let held: Vec<OwnedFd> = open_but(dir, &new_file).iter().map(handle).collect();
            let manifest = new_file.first().map(handle);
            let sizes = || -> Vec<u64> { held.iter().map(size).collect() };
            let before = sizes();
            let with_data = before.iter().filter(|&&size| size > 0).count();
            assert_eq!(with_data, FILES + usize::from(runs), "{:?}", before);
            match end {
                End::Finished => drop(writer.finish().unwrap()),
                End::StepFailed => {
                    // Two files with one name, which the last step of the
                    // manifest comes to, once most of it is written.
                    for size in [1, 2] {
                        let mut object = FileObject::new(testing::name("twice"));
                        object.size = Some(size);
                        writer.add_object(&object).unwrap();
                    }
                    let e = writer.finish().unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::Duplicate));
                    assert_eq!(manifest.as_ref().map(size), Some(0));
                }
                End::NameTaken => {
                    // Something else has the name by now. So finish()
                    // writes the manifest and fails where the file is to
                    // get the name.
                    fs::write(dir.join("m"), b"").unwrap();
                    assert_eq!(errno(&writer.finish().unwrap_err()), Some(libc::EEXIST));
                    assert_eq!(manifest.as_ref().map(size), Some(0));
                }
                End::WalkFailed => {
                    // What is no directory is no tree to walk.
                    let top = File::open("/dev/null").unwrap();
                    let e = writer.generate(top.as_fd(), AddFlags::NONE).unwrap_err();
                    assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::NotDirectory));
                }
                End::Dropped => drop(writer),
            }
            if end == End::Dropped {
                assert_eq!(sizes(), before);
            } else {
                assert!(sizes().iter().all(|&size| size == 0), "{:?}: {:?}", case, sizes());
            }
            let _ = fs::remove_file(dir.join("m"));
        }
        // generate_at() has its writer to itself, so another thread takes
        // the handles while it walks a tree. The tree has two directories.
        // The one readdir() gives first has the files with two names, which
        // take the table to disk, and the other one a sparse file that
        // takes long to hash. So the scratch files hold something from
        // then on, and the walk can't be over before the thread looked at
        // the descriptors once. It takes its handles and only then fails
        // the walk: with a file it puts into the tree, for a walk that is
        // still at the files with two names and comes back to the top, and
        // by cutting the sparse file off, for one that hashes it.
        let top = dir.join("tree/top");
        for half in ["a", "b"] {
            fs::create_dir_all(top.join(half)).unwrap();
        }
        let halves: Vec<_> = fs::read_dir(&top).unwrap().map(|half| half.unwrap().path()).collect();
        let (links, brake) = (&halves[0], halves[1].join("brake"));
        // The sparse file is made before the links: FAT takes neither, and
        // this is skipped there.
        if let Err(e) = File::create(&brake).unwrap().set_len(BRAKE) {
            eprintln!(
                "skipping generate_at(): the temporary directory takes no file of that size: {}",
                e
            );
            return;
        }
        for number in 0..LINKS {
            let name = links.join(number.to_string());
            fs::write(&name, b"").unwrap();
            fs::hard_link(&name, name.with_extension("b")).unwrap();
        }
        let over = std::sync::atomic::AtomicBool::new(false);
        let (walked, held) = std::thread::scope(|scope| {
            let looking = scope.spawn(|| {
                while !over.load(std::sync::atomic::Ordering::Relaxed) {
                    let files = OpenFile::made_in(dir);
                    if files.iter().filter(|file| file.size > 0).count() >= FILES {
                        let held: Vec<OwnedFd> = files.iter().map(handle).collect();
                        File::create(top.join("late")).unwrap();
                        File::create(&brake).unwrap();
                        return Some(held);
                    }
                    std::thread::sleep(PAUSE);
                }
                None
            });
            let (into, tree) = (File::open(dir).unwrap(), File::open(&top).unwrap());
            let walked = ManifestOptions::new().generate_at(into, Path::new("m"), tree, AddFlags::NONE);
            over.store(true, std::sync::atomic::Ordering::Relaxed);
            (walked, looking.join().unwrap())
        });
        assert_eq!(walked.unwrap_err().kind(), ErrorKind::Tree(TreeProblem::Changed));
        // The new file and the scratch files, each as the walk left it.
        let held = held.expect("the scratch files of the walk never held anything");
        let left: Vec<u64> = held.iter().map(size).collect();
        assert!(left.len() > FILES && left.iter().all(|&size| size == 0), "{:?}", left);
    }

    /// A writer can go to another thread where what it writes to can, and
    /// so can the options, the report and the errors.
    #[test]
    fn send_and_sync() {
        fn send<T: Send>() {}
        fn send_sync<T: Send + Sync>() {}
        fn send_sync_static<T: Send + Sync + 'static>() {}
        send::<ManifestWriter<File>>();
        send::<ManifestWriter<Vec<u8>>>();
        send_sync::<ManifestOptions>();
        send_sync::<ManifestReport>();
        send_sync::<AddFlags>();
        send_sync_static::<Error>();
    }
}
