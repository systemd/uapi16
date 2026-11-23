// SPDX-License-Identifier: LGPL-2.1-or-later
//! The adds of a manifest that is being built. The add of a tree takes a
//! descriptor, reads the directory it refers to as the root and everything
//! below it, and hands the file objects to the [`Listing`], which sorts
//! them. The add of a file object a caller made hands that one over.
//!
//! [`Walker`] does an add in steps, as the listing and the [`Writing`] do
//! their work. [`Walker::begin`] only says what is to be added, and
//! [`Walker::step`] does a part of it at a time, as much as its budget
//! allows, and says whether the add is done. Between two entries a step
//! looks at its budget and returns once it is used up, so a walk can be
//! stopped there and picked up again later. That is the shape of walkdir's
//! IntoIter and of fts(3): the directories a walk is in are on an explicit
//! stack instead of a recursion, and the stack is where the walk is from
//! one step to the next.
//!
//! Where an add is from one step to the next is its [`Task`], which
//! whoever began the add keeps and hands to every step. The walker keeps
//! none. An add borrows the descriptor it was given for as long as it is
//! being done, and does not duplicate it.
//!
//! The walk is by descriptor throughout, the way pathrs and cap-std walk.
//! Every entry is opened as a handle in the directory it is in, see
//! [`Entry::open_at`], and everything else is read through that handle. A
//! directory the walk goes into is opened by its name for its listing, and
//! has to be the file of its handle, see [`Entry::reopen`], and its entries
//! are opened in that descriptor. So a walk keeps one descriptor for every
//! directory it is in, and a buffer of 8 KiB to 32 KiB for the names
//! getdents() gave of it that are still to come, as glibc's opendir() keeps
//! a buffer for every directory that is open. The memory of a walk grows
//! with the depth of a tree that way: to about 32 MiB at 1024 levels, and
//! to 64 MiB at the about 2048 levels a name can have. The directories are
//! read in the order readdir() gives, since the listing sorts everything
//! anyway.
//!
//! - A file on another mount than the directory the walk started at is a
//!   mount point, by the mount ID of statx(). It is not walked into unless
//!   the add crosses mount points. A directory that is not walked into is
//!   an empty directory with the attributes of the mounted root. A file
//!   that is mounted over another one is the file the mount shows, with
//!   nothing to walk into: a regular file with its attributes and the hash
//!   of its data, a device node with its attributes and its device numbers.
//! - Nothing is mounted for an add. An automount point that nothing is
//!   mounted on yet is told from its handle, see [`Entry::is_automount`],
//!   before any directory is opened. It is never opened and nothing is
//!   looked up in it, since either can mount what it stands for. So it is
//!   an empty directory with its own attributes, with and without crossing
//!   mount points, and what is read from the open file can't be read of
//!   it. A directory that becomes an automount point after its handle was
//!   looked at and before it is opened by its name is a known limit: that
//!   open mounts its file system, and the add fails with a tree that
//!   changed, see [`Entry::reopen`].
//! - With mount points crossed, a mount can show a directory again inside
//!   itself. A directory that is one of the directories the walk is in, by
//!   device, inode and subvolume, fails the add.
//! - A symbolic link is the link, with its target, and is never followed.
//! - The names the specification reserves at the top of a tree are passed
//!   over. A name a manifest cannot hold fails the add, or is left out and
//!   counted where the add asks for that, a directory with everything below
//!   it.
//! - The files the manifest made itself and has open are passed over
//!   wherever a walk comes to one, see [`OwnFiles`]: the scratch files of
//!   the listing, which a file system can show in their directory although
//!   they have no name, and the manifest where it has a name of its own
//!   until it is complete. A file is one of them by its inode and by its
//!   status. A file system can give two files one inode number, and a file
//!   of the tree that only has the number of one of them is listed like
//!   any other. No scratch file is closed while the walker is there, also
//!   not one the listing is done with, so a walk never comes to one that
//!   is none of them any more.
//! - A directory that is walked into is opened for its listing before its
//!   own file object goes to the listing, and its file system is asked for
//!   the DOS attributes before that where it is the root, which has none
//!   of its own.
//! - An add that fails is over, and the walker keeps no note of it. A file
//!   object of a caller goes to the listing with the last turn of its add,
//!   so its add added nothing where it failed. The add of a tree that
//!   failed added a part of the tree, which the listing can't take back:
//!   whoever walks a tree gives the manifest up then.
//! - An add that is given up between two of its steps is like one that
//!   failed there. Its [`Task`] is dropped or leaked for that, which tells
//!   the walker nothing.
//! - A file that changes while it is read fails the add, where statx()
//!   shows the change. What statx() says of a file before and after it is
//!   read has to be the same. A directory is read while it is listed:
//!   before each of its entries and once more at the end of its listing,
//!   what statx() says of it has to be what it said when the directory was
//!   opened. A rename in a directory can make readdir() return an entry
//!   again under its new name, a whole directory or a file whose data was
//!   read. So where statx() shows every rename, a walk reads only the
//!   entries a directory had when it was opened, each once. Where it
//!   doesn't, see ManifestOptions::generate_at, an entry can come twice or
//!   not at all. A file that is gone between the listing of its directory
//!   and its open changed as well.
//!
//! [`OwnFiles`]: crate::sys::OwnFiles

use std::collections::HashSet;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem;
use std::ops::{BitAnd, BitOr, BitOrAssign, ControlFlow};
use std::os::fd::BorrowedFd;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use rustix::fs::FileType;

use crate::error::{Error, ErrorKind, TreeProblem};
use crate::listing::{Listing, Writing};
use crate::object::{
    ContentsObject, ContentsSource, FileObject, FileSystemIdentity, InodeAttributes, InodeType, RootObject,
};
use crate::optional::FeatureReader;
use crate::sys::{DataHash, Entries, Listed, Readable, DATA_BUFFER_SIZE};
use crate::tree::{Entry, Failure, InodeId, MountId, Place, Status, Subject};
use crate::{Features, Name, NameBuf, NameProblem, Sha256};

/// How much a step of an add does: bytes of data hashed, and [`OPEN`] for
/// every file that is opened. It is about one read of the data of a file.
pub(crate) const STEP_BUDGET: u64 = 1024 * 1024;

/// What a turn of a step costs at least, so that a step of any budget gets
/// further and comes to an end.
const TURN: u64 = 1;

/// What the turn that opens an entry of a directory costs besides the
/// bytes of its name. Opening a file and reading what a manifest records
/// of it takes about as long as hashing this many bytes of data. So a
/// budget is worth about the same time over many small files as over the
/// data of a large one.
const OPEN: u64 = 4096;

/// How [`ManifestOptions::generate_at`] and [`ManifestOptions::generate`]
/// walk: whether they cross mount points, and what they do with a file
/// whose name a manifest can't hold.
/// The flags combine with `|`.
///
/// ```
/// use uapi16::AddFlags;
///
/// let flags = AddFlags::CROSS_MOUNTS | AddFlags::GRACEFUL;
/// assert!(flags.contains(AddFlags::CROSS_MOUNTS));
/// assert!(!AddFlags::NONE.contains(AddFlags::CROSS_MOUNTS));
/// ```
///
/// [`ManifestOptions::generate_at`]: crate::ManifestOptions::generate_at
/// [`ManifestOptions::generate`]: crate::ManifestOptions::generate
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct AddFlags(u8);

impl AddFlags {
    /// No flags: mount points are not crossed, and a name a manifest can't
    /// hold is an error.
    pub const NONE: AddFlags = AddFlags(0);
    /// Walk into mount points instead of writing them as empty directories.
    pub const CROSS_MOUNTS: AddFlags = AddFlags(1 << 0);
    /// Leave out files whose names a manifest can't hold, a directory with
    /// everything below it, and count them in
    /// [`ManifestReport::entries_omitted`](crate::ManifestReport::entries_omitted),
    /// instead of failing.
    pub const GRACEFUL: AddFlags = AddFlags(1 << 1);

    /// Whether every flag of `flags` is among these.
    pub const fn contains(self, flags: AddFlags) -> bool {
        self.0 & flags.0 == flags.0
    }
}

impl BitOr for AddFlags {
    type Output = AddFlags;

    fn bitor(self, other: AddFlags) -> AddFlags {
        AddFlags(self.0 | other.0)
    }
}

impl BitOrAssign for AddFlags {
    fn bitor_assign(&mut self, other: AddFlags) {
        self.0 |= other.0;
    }
}

impl BitAnd for AddFlags {
    type Output = AddFlags;

    fn bitand(self, other: AddFlags) -> AddFlags {
        AddFlags(self.0 & other.0)
    }
}

/// What is to be added. An add borrows what it is given for as long as it
/// is being done, and duplicates none of it.
#[derive(Debug)]
pub(crate) enum Add<'a> {
    /// The directory a descriptor of a caller refers to, as the root, and
    /// everything below it.
    Tree { top: BorrowedFd<'a>, flags: AddFlags },
    /// The root as a caller describes it: its inode attributes and the
    /// identity of its file system.
    Root {
        inode: &'a InodeAttributes,
        file_system: &'a FileSystemIdentity,
    },
    /// A file object a caller made.
    Object(&'a FileObject),
}

/// What the adds left out of the manifest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Omitted {
    /// The entries whose names a manifest cannot hold, which the walk
    /// passed over. A directory counts once.
    pub(crate) entries: u64,
    /// The fields that were left out of file objects: the names of owners
    /// the user database does not have, the user and group IDs 65535 and
    /// 4294967295, which the specification does not permit, and
    /// modification times `mTimeNSec` cannot express, before 1970 or after
    /// 2554. And of the root of a walk the UUID and the volume serial
    /// number of its file system, where that has none.
    pub(crate) fields: u64,
}

/// What follows once an entry is read and its file object went to the
/// listing.
#[derive(Debug)]
enum Then {
    /// The add is done.
    Done,
    /// The walk goes into the directory that was read.
    Descend,
    /// The walk goes on with the next entry of the directory it is in.
    List,
}

/// A file object as an entry has it: that of the root of a tree, of which
/// the listing takes the inode attributes and the identity of its file
/// system, or that of any other file.
#[derive(Debug)]
enum Object {
    Root(Box<RootObject>),
    File(Box<FileObject>),
}

/// An entry that is being read.
#[derive(Debug)]
struct Reading<'a> {
    entry: Entry<'a>,
    object: Object,
    /// The file opened for reading, where that was needed: for its flags,
    /// its DOS attributes or the identity of its file system, or to list a
    /// directory that is walked into.
    opened: Option<Readable>,
    /// The hash of the data of a regular file while it is read, and how
    /// much of the data was read so far.
    hash: Option<DataHash>,
    hashed: u64,
    /// The hash of the data, once it was read.
    data: Option<Sha256>,
    /// Whether the status of the file is taken again before its object goes
    /// to the listing, because more than its status was read of it.
    check: bool,
    /// How many fields were left out of the object.
    omitted: u64,
    then: Then,
}

impl Object {
    /// The name of the file in the manifest.
    fn name(&self) -> &Name {
        match self {
            Object::Root(_) => Name::ROOT,
            Object::File(object) => &object.name,
        }
    }
}

/// A directory a walk is in.
#[derive(Debug)]
struct Level {
    entries: Entries,
    /// What statx() said of the directory when it was opened, which its
    /// status before each of its entries and at the end of its listing is
    /// held against.
    status: Status,
}

impl Level {
    /// Fails unless the directory, whose name in the manifest is `name`, is
    /// what it was when it was opened, with the same entries.
    fn unchanged(&self, name: &Name) -> Result<(), Error> {
        let now = self.entries.status().map_err(|failure| failure.into_error(name))?;
        if now.changed_since(&self.status) {
            return Err(Failure::Changed.into_error(name));
        }
        Ok(())
    }
}

/// The walk of a tree below the directory it starts at.
#[derive(Debug)]
struct Walk {
    /// The directories the walk is in, the one it lists last.
    levels: Vec<Level>,
    /// The name of the directory it lists.
    directory: NameBuf,
    /// The mount of the directory the walk started at. A file on another
    /// one is a mount point.
    mount: MountId,
    /// The inodes of the directories in `levels`, where the walk crosses
    /// mount points: a directory that is one of them again is a loop.
    ancestors: Option<HashSet<InodeId>>,
}

impl Walk {
    /// A walk below a directory on the mount `mount`.
    fn new(mount: MountId, flags: AddFlags) -> Walk {
        Walk {
            levels: Vec::new(),
            directory: NameBuf::default(),
            mount,
            ancestors: flags.contains(AddFlags::CROSS_MOUNTS).then(HashSet::new),
        }
    }

    /// Goes into the directory `name`, whose entries are `entries`.
    fn push(&mut self, level: Level, name: NameBuf) {
        if let Some(ancestors) = &mut self.ancestors {
            ancestors.insert(level.status.identity.inode_id());
        }
        self.levels.push(level);
        self.directory = name;
    }

    /// Leaves the directory it lists, and returns whether it is in one
    /// still.
    fn pop(&mut self) -> bool {
        let Some(level) = self.levels.pop() else {
            return false;
        };
        if let Some(ancestors) = &mut self.ancestors {
            ancestors.remove(&level.status.identity.inode_id());
        }
        if self.levels.is_empty() {
            return false;
        }
        // A directory the walk went into from another one has a name below
        // that one.
        self.directory = self.directory.parent().unwrap_or_default().to_owned();
        true
    }
}

/// What an add does next.
#[derive(Debug)]
enum Next<'a> {
    /// Takes the status of the descriptor the add was given.
    Start(BorrowedFd<'a>),
    /// Reads an entry, and hands its file object to the listing.
    Read(Box<Reading<'a>>),
    /// Takes the next entry of the directory the walk lists.
    List,
    /// Hands the root as a caller describes it to the listing.
    GivenRoot(&'a InodeAttributes, &'a FileSystemIdentity),
    /// Hands a file object of a caller to the listing.
    Given(&'a FileObject),
    /// Nothing, the add is done.
    Done,
    /// Nothing, a step of the add failed.
    Failed,
}

impl Task<'_> {
    /// Whether nothing is left to do of the add: it is done, or it failed.
    fn is_over(&self) -> bool {
        matches!(self.next, Next::Done | Next::Failed)
    }

    /// What follows once the directory of `entry`, which the add walks,
    /// was read: the walk into it, on the mount it is on. An automount
    /// point is not walked into: it is the empty directory it is until
    /// something is mounted on it, see [`Entry::is_automount`], and the
    /// add is done with it.
    fn walk_into(&mut self, entry: &Entry<'_>) -> Then {
        if entry.is_automount() {
            return Then::Done;
        }
        self.walk = Some(Walk::new(entry.status().identity.mount, self.flags));
        Then::Descend
    }
}

/// An add that is being done: what it was given, and where it is. Whoever
/// began the add keeps this and hands it to every step of it, see
/// [`Walker::begin`] and [`Walker::step`]. It borrows what the add was
/// given, and owns what the add opened on its way: a descriptor for every
/// directory the walk is in, and the file whose data is being read. So an
/// add that is given up closes those with this.
#[derive(Debug)]
pub(crate) struct Task<'a> {
    flags: AddFlags,
    next: Next<'a>,
    /// The walk below the top directory, once the add of a tree is at it.
    walk: Option<Walk>,
}

/// Does the adds of a manifest that is being built, see the documentation
/// of this module.
#[derive(Debug)]
pub(crate) struct Walker {
    features: Features,
    listing: Listing,
    reader: FeatureReader,
    /// What the data of regular files is read through, once one is hashed.
    buffer: Vec<u8>,
    omitted: Omitted,
}

impl Walker {
    /// A walker that hands what it reads to `listing`, which is for a
    /// manifest that records `features`.
    pub(crate) fn new(features: Features, listing: Listing) -> Walker {
        Walker {
            features,
            listing,
            reader: FeatureReader::new(features),
            buffer: Vec::new(),
            omitted: Omitted::default(),
        }
    }

    /// Makes walks pass over the file `file` as well, which has the inode
    /// `inode` and which the manifest made itself. It is kept open with the
    /// other files of the manifest's own, see [`Listing::own_files`].
    pub(crate) fn pass_over(&mut self, inode: InodeId, file: Arc<File>) {
        self.listing.own_files_mut().keep(inode, file);
    }

    /// Begins the add `add`, and returns it as it is done from here on, a
    /// part with every [`Walker::step`]. Nothing is read yet, and nothing
    /// is duplicated: the add borrows what it was given.
    pub(crate) fn begin(add: Add<'_>) -> Task<'_> {
        match add {
            Add::Tree { top, flags } => Task {
                flags,
                next: Next::Start(top),
                walk: None,
            },
            Add::Root { inode, file_system } => Task {
                flags: AddFlags::NONE,
                next: Next::GivenRoot(inode, file_system),
                walk: None,
            },
            Add::Object(object) => Task {
                flags: AddFlags::NONE,
                next: Next::Given(object),
                walk: None,
            },
        }
    }

    /// Does a part of the add `task` and returns whether that was the end
    /// of it, then it breaks. `budget` is about how many bytes it hashes,
    /// lists or reads before it returns: it does one thing at a time, opens
    /// an entry, reads a part of its data or hands its object to the
    /// listing, and goes on while there is budget left. Without a budget it
    /// does nothing.
    ///
    /// An add that fails is over. The add of a file object hands its object
    /// to the listing with its last turn, so one that failed added nothing,
    /// and the walker goes on with the next add. The add of a tree that
    /// failed added a part of the tree, which the listing cannot take back:
    /// whoever walks a tree gives the manifest up then.
    ///
    /// Of an add that is over nothing is left to do, whether it is done or
    /// failed: every later step of it does nothing and breaks, whatever
    /// its budget. It has nothing open any more either: the step that
    /// fails closes what the add had opened on its way.
    pub(crate) fn step(&mut self, task: &mut Task<'_>, budget: u64) -> Result<ControlFlow<()>, Error> {
        let mut left = budget;
        while !task.is_over() {
            if left == 0 {
                return Ok(ControlFlow::Continue(()));
            }
            if let Err(e) = self.turn(task, &mut left) {
                // The directories the walk was in are closed now, and not
                // when whoever has the add lets go of it.
                task.walk = None;
                return Err(e);
            }
        }
        Ok(ControlFlow::Break(()))
    }

    /// Ends the adds: the manifest is written from what they added, and
    /// what they left out is counted. Nothing is done for that yet, see
    /// [`Listing::finish`], and nothing is closed: the files of the
    /// manifest's own stay open with what writes the manifest.
    pub(crate) fn finish(self) -> (Writing, Omitted) {
        (self.listing.finish(), self.omitted)
    }

    /// The buffer the data of regular files is read through.
    fn buffer(&mut self) -> &mut [u8] {
        if self.buffer.is_empty() {
            self.buffer = vec![0; DATA_BUFFER_SIZE];
        }
        &mut self.buffer
    }

    /// Does one thing of `task`, and takes what it cost from `left`. An add
    /// whose turn fails is over.
    fn turn(&mut self, task: &mut Task<'_>, left: &mut u64) -> Result<(), Error> {
        let next = mem::replace(&mut task.next, Next::Failed);
        task.next = match next {
            Next::Start(fd) => {
                *left -= TURN;
                self.start(task, fd)?
            }
            Next::Read(reading) => self.read(task, reading, left)?,
            Next::List => self.list(task, left)?,
            Next::GivenRoot(inode, file_system) if !self.listing.make_room(*left)? => {
                *left = 0;
                Next::GivenRoot(inode, file_system)
            }
            Next::GivenRoot(inode, file_system) => {
                *left -= TURN;
                self.listing.add_given_root(inode, file_system)?;
                Next::Done
            }
            Next::Given(object) if !self.listing.make_room(*left)? => {
                *left = 0;
                Next::Given(object)
            }
            Next::Given(object) => {
                *left -= TURN;
                self.listing.add_given(object)?;
                Next::Done
            }
            over @ (Next::Done | Next::Failed) => over,
        };
        Ok(())
    }

    /// Begins `task` with the directory of the descriptor it was given,
    /// `top`, which is the root.
    fn start<'a>(&mut self, task: &mut Task<'a>, top: BorrowedFd<'a>) -> Result<Next<'a>, Error> {
        let entry = Entry::of(top).map_err(|failure| failure.into_error(Name::ROOT))?;
        if entry.status().file_type != FileType::Directory {
            return Err(Walker::not_directory());
        }
        let then = task.walk_into(&entry);
        Ok(Next::Read(self.reading(entry, None, NameBuf::default(), then)?))
    }

    /// Takes the next entry of the directory the walk of `task` lists.
    fn list(&mut self, task: &mut Task<'_>, left: &mut u64) -> Result<Next<'static>, Error> {
        let walk = task
            .walk
            .as_mut()
            .expect("an add lists below a directory once it walks");
        let Some(level) = walk.levels.last_mut() else {
            return Ok(Next::Done);
        };
        let listed = match level.entries.next() {
            Some(Ok(listed)) => listed,
            Some(Err(failure)) => return Err(failure.into_error(&walk.directory)),
            None => {
                *left -= TURN;
                // It is compared once more after its last entry was read.
                level.unchanged(&walk.directory)?;
                return Ok(if walk.pop() { Next::List } else { Next::Done });
            }
        };
        *left = left.saturating_sub(listed.name().to_bytes().len() as u64 + OPEN);
        // Before an entry is read, the directory has to be what it was when
        // it was opened. A rename in it can give an entry that was read the
        // next name readdir() returned, or make readdir() return the entry
        // again under its new name, and none is read twice.
        level.unchanged(&walk.directory)?;
        Ok(self.entry(walk, &listed, task.flags)?.unwrap_or(Next::List))
    }

    /// What follows from the entry `listed` of the directory `walk` lists:
    /// reading it, or nothing if it is passed over.
    fn entry(&mut self, walk: &Walk, listed: &Listed, flags: AddFlags) -> Result<Option<Next<'static>>, Error> {
        let component = listed.name().to_bytes();
        if walk.directory.is_root() && Name::is_reserved_component(component) {
            return Ok(None);
        }
        let name = match walk.directory.join_os(OsStr::from_bytes(component)) {
            Ok(name) => name,
            Err(_) if flags.contains(AddFlags::GRACEFUL) => {
                self.omitted.entries += 1;
                return Ok(None);
            }
            Err(problem) => return Err(Walker::unwritable(&walk.directory, component, problem)),
        };
        let level = walk.levels.last().expect("an entry is of the directory the walk lists");
        let entry = match Entry::open_at(level.entries.as_fd(), listed.name()) {
            Ok(entry) => entry,
            Err(Failure::Io(e)) if e.kind() == io::ErrorKind::NotFound => return Err(Walker::vanished(&name)),
            Err(failure) => return Err(failure.into_error(&name)),
        };
        let status = *entry.status();
        // Where the status of a file of the manifest's own can't be read,
        // the entry that has its inode can't be told from it.
        let own = self.listing.own_files().contains(&status);
        if own.map_err(|failure| Walker::own_unread(&name, failure))? {
            return Ok(None);
        }
        let crosses = flags.contains(AddFlags::CROSS_MOUNTS);
        let mount_point = status.identity.mount != walk.mount;
        let then = match status.file_type {
            // An automount point is the empty directory it is until
            // something is mounted on it, whatever the walk crosses.
            FileType::Directory if entry.is_automount() => Then::List,
            FileType::Directory if crosses || !mount_point => {
                let ancestors = walk.ancestors.as_ref();
                if ancestors.is_some_and(|ancestors| ancestors.contains(&status.identity.inode_id())) {
                    return Err(Walker::loops(&name));
                }
                Then::Descend
            }
            // Anything else is not walked into: a file that is not a
            // directory, also one that a mount shows, and a directory that
            // is a mount point the walk does not cross, which is an empty
            // directory with the attributes of the mounted root.
            _ => Then::List,
        };
        let place = Place {
            dir: level.entries.as_fd(),
            name: listed.name(),
        };
        Ok(Some(Next::Read(self.reading(entry, Some(place), name, then)?)))
    }

    /// Whether the data of the file with the status `status` is hashed:
    /// that of a regular file, where the manifest records hashes, and also
    /// where it records hard links and the file has more than one name,
    /// since its names are held against each other with their data.
    fn hashes(&self, status: &Status) -> bool {
        let linked = status.nlink > 1 && self.features.contains(Features::HARDLINK);
        status.file_type == FileType::RegularFile && (self.features.contains(Features::SHA256) || linked)
    }

    /// Begins to read the entry `entry`, which is at `place`, see
    /// [`Entry::reopen`], and whose name in the manifest is `name`: what
    /// its status says, the optional features, and the target of a
    /// symbolic link. The data of a regular file is hashed in the steps
    /// that follow, see [`Walker::hashes`].
    fn reading<'a>(
        &mut self,
        entry: Entry<'a>,
        place: Option<Place<'_>>,
        name: NameBuf,
        then: Then,
    ) -> Result<Box<Reading<'a>>, Error> {
        let features = self.features;
        let status = *entry.status();
        let hashed = self.hashes(&status);
        if hashed {
            DataHash::admits(&status).map_err(|failure| failure.into_error(&name))?;
        }
        let xattrs = features.contains(Features::USER_XATTR) && status.file_type != FileType::Symlink;
        // A directory that is walked into is opened for its listing before
        // anything else is read of it, and so before its object goes to the
        // listing. A regular file that is hashed is opened for that before
        // its extended attributes are read, which are read through the open
        // file then.
        let mut opened = match then {
            Then::Descend => Some(entry.reopen(place).map_err(|failure| failure.into_error(&name))?),
            _ if hashed && xattrs => Some(entry.reopen(place).map_err(|failure| failure.into_error(&name))?),
            _ => None,
        };
        let (object, omitted) = if name.is_root() {
            // Every file below the root is asked for its DOS attributes,
            // and the root has none. So the file system is asked before the
            // root of a walk goes to the listing.
            if matches!(then, Then::Descend) {
                self.reader
                    .check_dos_attributes(&entry, &mut opened)
                    .map_err(|failure| failure.into_error(&name))?;
            }
            let (inode, omitted) = InodeAttributes::of_status(&status, features);
            let mut root = RootObject {
                inode,
                ..RootObject::default()
            };
            let left_out = self
                .reader
                .read_root(&entry, &mut opened, &mut root)
                .map_err(|failure| failure.into_error(&name))?;
            (Object::Root(Box::new(root)), omitted + left_out)
        } else {
            let (mut object, omitted) = FileObject::of_status(name, &status, features)?;
            let names = self
                .reader
                .read(&entry, place, &mut opened, &mut object)
                .map_err(|failure| failure.into_error(&object.name))?;
            // The size of a symbolic link is the length of its target, as
            // for systemd-manifest, which knows it once it read the
            // target.
            if status.file_type == FileType::Symlink && features.contains(Features::SYMLINK) {
                let target = entry.target().map_err(|failure| failure.into_error(&object.name))?;
                if features.contains(Features::SIZE) {
                    object.size = Some(target.len() as u64);
                }
                object.contents = vec![ContentsObject::new(ContentsSource::Literal(target))];
            }
            (Object::File(Box::new(object)), omitted + names)
        };
        let hash = if hashed {
            let hash = match opened.take() {
                Some(readable) => DataHash::of(&entry, readable),
                None => DataHash::start(&entry),
            };
            Some(hash.map_err(|failure| failure.into_error(object.name()))?)
        } else {
            None
        };
        // The hash checks the status after the data, and the walk checks a
        // directory it goes into while it lists it. Anything else is
        // checked once more than its status was read: the flags, the DOS
        // attributes and the identity of the file system through the file
        // opened for reading, or the extended attributes.
        let check = hash.is_none() && !matches!(then, Then::Descend) && (opened.is_some() || xattrs);
        Ok(Box::new(Reading {
            entry,
            object,
            opened,
            hash,
            hashed: 0,
            data: None,
            check,
            omitted,
            then,
        }))
    }

    /// Goes on reading the entry of `reading`: hashes a part of its data,
    /// checks that it did not change, and hands its object to the listing
    /// once there is room. Then the add goes on as `reading` says.
    fn read<'a>(
        &mut self,
        task: &mut Task<'a>,
        mut reading: Box<Reading<'a>>,
        left: &mut u64,
    ) -> Result<Next<'a>, Error> {
        if let Some(hash) = reading.hash.take() {
            let size = reading.entry.status().size;
            let budget = *left;
            let read = hash
                .read(self.buffer(), budget)
                .map_err(|failure| failure.into_error(reading.object.name()))?;
            match read {
                ControlFlow::Continue(hash) => {
                    reading.hashed += budget;
                    reading.hash = Some(hash);
                    *left = 0;
                    return Ok(Next::Read(reading));
                }
                ControlFlow::Break(data) => {
                    *left = left.saturating_sub(size.saturating_sub(reading.hashed).max(TURN));
                    reading.data = Some(data);
                    if let Object::File(object) = &mut reading.object {
                        if self.features.contains(Features::SHA256) {
                            object.sha256 = Some(data);
                        }
                    }
                }
            }
        }
        if reading.check {
            let name = reading.object.name();
            let after = Status::of(reading.entry.handle()).map_err(|failure| failure.into_error(name))?;
            if after.changed_since(reading.entry.status()) {
                return Err(Failure::Changed.into_error(name));
            }
            reading.check = false;
        }
        if !self.listing.make_room(*left)? {
            *left = 0;
            return Ok(Next::Read(reading));
        }
        *left = left.saturating_sub(TURN);
        let Reading {
            entry,
            object,
            opened,
            data,
            omitted,
            then,
            ..
        } = *reading;
        let name = match object {
            Object::Root(root) => {
                self.listing.add_root(&root.inode, &root.file_system)?;
                NameBuf::default()
            }
            Object::File(object) => {
                self.listing.add_walked(&object, entry.status(), data)?;
                object.name
            }
        };
        self.omitted.fields += omitted;
        let next = match then {
            Then::Done => Next::Done,
            Then::Descend => {
                let readable = opened.expect("a directory that is walked into was opened for its listing");
                let entries = readable.entries();
                let walk = task.walk.as_mut().expect("an add walks once it goes into a directory");
                let status = *entry.status();
                walk.push(Level { entries, status }, name);
                Next::List
            }
            Then::List => Next::List,
        };
        Ok(next)
    }

    /// The error for the entry `name`, which has the inode of a file of
    /// the manifest's own whose status can't be read, for `failure`: the
    /// entry can't be told from that file. The error is that of the
    /// status and names the entry, and its message says that it is a file
    /// of the manifest's own that can't be read.
    fn own_unread(name: &Name, failure: Failure) -> Error {
        match failure {
            Failure::Io(e) => {
                let message = format!(
                    "{}: a file of the manifest's own with its inode can't be read: {}",
                    Subject(name),
                    e
                );
                Error::new(ErrorKind::Io, message).named(name.as_str()).caused_by(e)
            }
            failure => failure.into_error(name),
        }
    }

    /// The error for the file a walk is to start at, which is not a
    /// directory.
    fn not_directory() -> Error {
        let name = Name::ROOT;
        let message = format!("{}: is not a directory", Subject(name));
        Error::new(ErrorKind::Tree(TreeProblem::NotDirectory), message).named(name.as_str())
    }

    /// The error for an entry of the directory `directory` with the name
    /// `component`, which a manifest cannot hold for `problem`.
    fn unwritable(directory: &Name, component: &[u8], problem: NameProblem) -> Error {
        let raw = OsStr::from_bytes(component);
        let message = format!(
            "{}: has an entry with a name a manifest cannot hold, {:?}: {}",
            Subject(directory),
            raw,
            problem
        );
        Error::new(ErrorKind::Tree(TreeProblem::UnwritableName), message)
            .named(directory.as_str())
            .raw(raw)
            .because(problem)
    }

    /// The error for the file `name`, which its directory listed and which
    /// was gone when it was opened. Files must not change while they are
    /// read, and a directory is read when it is listed.
    fn vanished(name: &Name) -> Error {
        let message = format!("{}: was removed or renamed while its directory was read", Subject(name));
        Error::new(ErrorKind::Tree(TreeProblem::Changed), message).named(name.as_str())
    }

    /// The error for the directory `name`, which is one of the directories
    /// it is in, shown again by a mount.
    fn loops(name: &Name) -> Error {
        let message = format!(
            "{}: is one of the directories it is in, which a mount shows again",
            Subject(name)
        );
        Error::new(ErrorKind::Tree(TreeProblem::Loop), message).named(name.as_str())
    }
}

impl InodeType {
    /// The inode type of a file of the type `file_type`, if it is one.
    fn of_file_type(file_type: FileType) -> Option<InodeType> {
        Some(match file_type {
            FileType::RegularFile => InodeType::Regular,
            FileType::Directory => InodeType::Directory,
            FileType::Symlink => InodeType::Symlink,
            FileType::Fifo => InodeType::Fifo,
            FileType::CharacterDevice => InodeType::CharDevice,
            FileType::BlockDevice => InodeType::BlockDevice,
            FileType::Socket => InodeType::Socket,
            FileType::Unknown => return None,
        })
    }
}

impl InodeAttributes {
    /// The inode attributes a manifest that records `features` takes from
    /// `status`: the access mode, but of a symbolic link, the user and the
    /// group ID of the owner, and the modification time. Returns them with
    /// how many of them were left out: the IDs 65535 and 4294967295, which
    /// the specification does not permit, and a time before 1970 or after
    /// 2554, which `mTimeNSec` cannot express.
    fn of_status(status: &Status, features: Features) -> (InodeAttributes, u64) {
        let mut inode = InodeAttributes::default();
        let mut omitted = 0;
        if features.contains(Features::MODE) && status.file_type != FileType::Symlink {
            inode.mode = Some(status.mode);
        }
        let valid = |id: u32| Some(id).filter(|&id| FileObject::is_valid_id(id));
        if features.contains(Features::UID) {
            inode.uid = valid(status.uid);
            omitted += u64::from(inode.uid.is_none());
        }
        if features.contains(Features::GID) {
            inode.gid = valid(status.gid);
            omitted += u64::from(inode.gid.is_none());
        }
        if features.contains(Features::MTIME) {
            inode.mtime_nsec = status.mtime.since_epoch_nsec();
            omitted += u64::from(inode.mtime_nsec.is_none());
        }
        (inode, omitted)
    }
}

impl FileObject {
    /// The file object a manifest that records `features` gets for the file
    /// `name` from its status `status`: its type, its inode attributes, see
    /// [`InodeAttributes::of_status`], the size of a regular file and the
    /// device numbers of a device node. Returns it with how many fields
    /// were left out. A file of a type no manifest has fails.
    fn of_status(name: NameBuf, status: &Status, features: Features) -> Result<(FileObject, u64), Error> {
        let Some(inode_type) = InodeType::of_file_type(status.file_type) else {
            let unknown = io::Error::new(io::ErrorKind::InvalidData, "the file is of no type a manifest has");
            return Err(Error::from(unknown).named(name.as_str()));
        };
        let (inode, omitted) = InodeAttributes::of_status(status, features);
        let mut object = FileObject::new(name);
        object.inode_type = inode_type;
        object.inode = inode;
        if features.contains(Features::SIZE) && inode_type == InodeType::Regular {
            object.size = Some(status.size);
        }
        if features.contains(Features::DEVICE) && inode_type.is_device() {
            object.major = Some(u64::from(status.rdev.major));
            object.minor = Some(u64::from(status.rdev.minor));
        }
        Ok((object, omitted))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::listing::Totals;
    use crate::scratch::Scratch;
    use crate::sys::ScratchFile;
    use crate::testing::{self, read_whole, write_whole, TempDir, Whole};
    use crate::tree::{DeviceNumber, Identity, Timestamp};
    use crate::{Mode, Order};
    use rustix::fs::{inotify, OFlags, XattrFlags, CWD};
    use std::collections::HashMap;
    use std::ffi::{CString, OsString};
    use std::fs::{self, File};
    use std::io::Write;
    use std::os::fd::{AsFd, OwnedFd};
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    /// Opens `path` as a handle, the link itself where it is a symbolic link.
    fn open_path(path: &Path) -> OwnedFd {
        let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        rustix::fs::open(path, flags, rustix::fs::Mode::empty()).unwrap()
    }

    /// Makes a FIFO at `path`.
    fn make_fifo(path: &Path) {
        let mode = rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR;
        rustix::fs::mknodat(CWD, path, FileType::Fifo, mode, 0).unwrap();
    }

    /// A manifest a test builds, with its scratch files in a directory of
    /// its own.
    struct Build {
        walker: Walker,
        _scratch: TempDir,
    }

    impl Build {
        /// A manifest that records `features`.
        fn new(features: Features) -> Build {
            // The tests run next to each other, each with directories of
            // its own.
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let scratch = TempDir::new(&format!("walk-scratch-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
            let directory = Scratch::beside(ScratchFile::open_directory(&scratch.0).unwrap().into());
            let listing = Listing::new(features, Order::CodePoint, directory);
            Build {
                walker: Walker::new(features, listing),
                _scratch: scratch,
            }
        }

        /// The directory `top` refers to as the root, and everything below
        /// it, with the flags `flags`.
        fn add_all(&mut self, top: BorrowedFd<'_>, flags: AddFlags) -> Result<(), Error> {
            self.run(Add::Tree { top, flags })
        }

        /// Does the add `add` from its beginning to its end, as an add that
        /// is done in one call is.
        fn run(&mut self, add: Add<'_>) -> Result<(), Error> {
            let mut task = Walker::begin(add);
            while self.walker.step(&mut task, STEP_BUDGET)?.is_continue() {}
            Ok(())
        }

        /// The manifest, read back, what it lists and what was left out.
        fn finish(self) -> Result<(Whole, Totals, Omitted), Error> {
            let (mut writing, omitted) = self.walker.finish();
            let mut text = String::new();
            loop {
                if let ControlFlow::Break(totals) = writing.step(u64::MAX, &mut text)? {
                    return Ok((read_whole(text.as_bytes()).unwrap(), totals, omitted));
                }
            }
        }
    }

    /// The manifest of the tree `dir` as a whole, as its root, for
    /// `features`.
    fn walked(dir: &Path, features: Features, flags: AddFlags) -> Result<(Whole, Totals, Omitted), Error> {
        let mut build = Build::new(features);
        build.add_all(open_path(dir).as_fd(), flags)?;
        build.finish()
    }

    /// The names of the file objects of `whole`.
    fn names(whole: &Whole) -> Vec<&str> {
        whole.objects.iter().map(|object| object.name().as_str()).collect()
    }

    /// The file object `name` of `whole`.
    fn object<'a>(whole: &'a Whole, name: &str) -> &'a FileObject {
        whole.objects.iter().find(|object| object.name() == name).unwrap()
    }

    /// What a manifest that records `features` says of the root `dir` and
    /// of its files `names`, as std::fs reads them: the file objects in the
    /// order of their names, the names of one inode with one token, and the
    /// root with the attributes of `root`, or a made-up one without.
    fn expected(dir: &Path, root: Option<&Path>, names: &[&str], features: Features) -> Whole {
        let mut whole = Whole {
            root: RootObject {
                features: Some(features),
                order: Some(Order::CodePoint),
                ..RootObject::default()
            },
            objects: Vec::new(),
            signatures: Vec::new(),
        };
        if let Some(root) = root {
            let meta = fs::symlink_metadata(root).unwrap();
            let object = FileObject::from_metadata(testing::name("root"), &meta, features).unwrap();
            whole.root.inode = object.inode().clone();
        }
        let mut sorted: Vec<NameBuf> = names.iter().map(|name| testing::name(name)).collect();
        sorted.sort();
        let mut tokens = HashMap::new();
        for name in sorted {
            let path = dir.join(name.as_str());
            let meta = fs::symlink_metadata(&path).unwrap();
            let mut object = FileObject::from_metadata(name, &meta, features).unwrap();
            if meta.is_file() && features.contains(Features::SHA256) {
                object.sha256 = Some(Sha256::digest(&fs::read(&path).unwrap()));
            }
            if meta.is_symlink() && features.contains(Features::SYMLINK) {
                let target = fs::read_link(&path).unwrap().into_os_string().into_vec();
                if features.contains(Features::SIZE) {
                    object.size = Some(target.len() as u64);
                }
                object.contents = vec![ContentsObject::new(ContentsSource::Literal(target))];
            }
            if !meta.is_dir() && meta.nlink() > 1 && features.contains(Features::HARDLINK) {
                let next = tokens.len() as u64 + 1;
                let token = *tokens.entry((meta.dev(), meta.ino())).or_insert(next);
                object.inode_token = std::num::NonZeroU64::new(token);
            }
            whole.objects.push(object);
        }
        // The way the manifest of a walk comes back, through a writer and a
        // reader.
        read_whole(&write_whole(&whole).unwrap()).unwrap()
    }

    /// A tree with a file of every type a test can make, and the names of
    /// its files: regular files, among them an empty one and one that takes
    /// several reads, directories, symbolic links, a hard link, a FIFO and a
    /// socket.
    fn every_type(name: &str) -> (TempDir, UnixListener, Vec<&'static str>) {
        let tmp = TempDir::new(name);
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"hello").unwrap();
        fs::write(dir.join("empty"), b"").unwrap();
        let large: Vec<u8> = (0..3 * DATA_BUFFER_SIZE + 5).map(|i| (i % 251) as u8).collect();
        fs::write(dir.join("large"), large).unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        fs::set_permissions(dir.join("dir"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(dir.join("dir/inner"), b"inner").unwrap();
        fs::create_dir(dir.join("dir/empty-dir")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        symlink("nowhere/at/all", dir.join("dir/dangling")).unwrap();
        fs::write(dir.join("linked"), b"twice").unwrap();
        fs::hard_link(dir.join("linked"), dir.join("dir/linked-too")).unwrap();
        make_fifo(&dir.join("fifo"));
        let socket = UnixListener::bind(dir.join("socket")).unwrap();
        let names = vec![
            "file",
            "empty",
            "large",
            "dir",
            "dir/inner",
            "dir/empty-dir",
            "link",
            "dir/dangling",
            "linked",
            "dir/linked-too",
            "fifo",
            "socket",
        ];
        (tmp, socket, names)
    }

    /// A walk lists every file below the directory it starts at, of every
    /// type, with what the features record of each as std::fs reads it, in
    /// the order of the manifest. The names of one inode share a token, and
    /// what the manifest lists is counted.
    #[test]
    fn walks_every_type() {
        let (tmp, _socket, names) = every_type("walk-types");
        let dir = &tmp.0;
        let large = 3 * DATA_BUFFER_SIZE as u64 + 5;
        for features in [Features::NONE, Features::DEFAULT, Features::DEFAULT | Features::MTIME] {
            let (whole, totals, omitted) = walked(dir, features, AddFlags::NONE).unwrap();
            assert_eq!(whole, expected(dir, Some(dir), &names, features), "{:?}", features);
            let expected_totals = Totals {
                files: 6,
                directories: 3,
                others: 4,
                bytes: 5 + large + 5 + 5 + 5,
            };
            assert_eq!(totals, expected_totals, "{:?}", features);
            assert_eq!(omitted, Omitted::default());
        }
    }

    /// A directory is listed through itself opened by its name, which takes
    /// the permission to read it and not the one to search it. So an empty
    /// one that may only be read is walked as well.
    #[test]
    fn walks_directories_that_may_not_be_searched() {
        let tmp = TempDir::new("walk-unsearchable");
        let dir = &tmp.0;
        fs::create_dir(dir.join("read-only")).unwrap();
        fs::set_permissions(dir.join("read-only"), fs::Permissions::from_mode(0o400)).unwrap();
        let (whole, totals, _) = walked(dir, Features::DEFAULT, AddFlags::NONE).unwrap();
        assert_eq!(names(&whole), ["read-only"]);
        assert_eq!(object(&whole, "read-only").inode().mode().unwrap().bits(), 0o400);
        assert_eq!(totals.directories, 2);
    }

    /// A tree of nested directories: `a` (0700) with `b` (0750) with `c`
    /// (0755) with `file`, a symbolic link `a/link` to `b`, and a regular
    /// file `f`.
    fn nested(name: &str) -> TempDir {
        let tmp = TempDir::new(name);
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("a/b/c")).unwrap();
        fs::write(dir.join("a/b/c/file"), b"deep").unwrap();
        for (directory, mode) in [("a/b/c", 0o755), ("a/b", 0o750), ("a", 0o700)] {
            fs::set_permissions(dir.join(directory), fs::Permissions::from_mode(mode)).unwrap();
        }
        symlink("b", dir.join("a/link")).unwrap();
        fs::write(dir.join("f"), b"f").unwrap();
        tmp
    }

    /// The names the specification reserves for the manifest are passed
    /// over at the top of a tree, whatever the file is, and uncounted.
    /// Further down they are names like any other.
    #[test]
    fn passes_over_reserved_names() {
        let tmp = TempDir::new("walk-reserved");
        let dir = &tmp.0;
        fs::write(dir.join("Uapi16Manifest"), b"").unwrap();
        fs::write(dir.join("Uapi16Manifest.sig"), b"").unwrap();
        fs::create_dir(dir.join("Uapi16Manifest.d")).unwrap();
        fs::write(dir.join("Uapi16Manifest.d/x"), b"").unwrap();
        fs::create_dir(dir.join("sub")).unwrap();
        fs::write(dir.join("sub/Uapi16Manifest"), b"").unwrap();
        let (whole, _, omitted) = walked(dir, Features::DEFAULT, AddFlags::NONE).unwrap();
        assert_eq!(names(&whole), ["sub", "sub/Uapi16Manifest"]);
        assert_eq!(omitted, Omitted::default());
    }

    /// A name a manifest cannot hold fails the walk, naming the directory,
    /// with the name as it is and the rule it breaks. Where the walk skips
    /// such names, the entry is left out, a directory with everything below
    /// it, and counted once for every walk that skipped it.
    #[test]
    fn unwritable_names() {
        let unwritable: [(&[u8], NameProblem); 4] = [
            (b"\xff", NameProblem::NotUtf8),
            (b"control\x01", NameProblem::ContainsControlCharacter),
            (b"delete\x7f", NameProblem::ContainsControlCharacter),
            ("non\u{fffe}character".as_bytes(), NameProblem::ContainsNoncharacter),
        ];
        for (i, (bad, problem)) in unwritable.iter().enumerate() {
            let tmp = TempDir::new(&format!("walk-unwritable-{}", i));
            let dir = &tmp.0;
            fs::create_dir(dir.join("sub")).unwrap();
            fs::write(dir.join("sub/ok"), b"").unwrap();
            let bad_path = dir.join("sub").join(OsString::from_vec(bad.to_vec()));
            fs::create_dir(&bad_path).unwrap();
            fs::create_dir(bad_path.join("below")).unwrap();
            fs::write(bad_path.join("below/file"), b"").unwrap();
            let e = walked(dir, Features::DEFAULT, AddFlags::NONE).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::UnwritableName), "{}", e);
            assert_eq!(e.name(), Some("sub"));
            assert_eq!(e.raw_name(), Some(OsStr::from_bytes(bad)));
            assert_eq!(e.name_problem(), Some(*problem));
            let graceful = AddFlags::GRACEFUL;
            let (whole, _, omitted) = walked(dir, Features::DEFAULT, graceful).unwrap();
            assert_eq!(names(&whole), ["sub", "sub/ok"]);
            assert_eq!(omitted.entries, 1);
        }
    }

    /// A name longer than a manifest holds is unwritable at the directory
    /// whose entry it is, and a walk that skips such names stops there.
    #[test]
    fn names_too_long() {
        let tmp = TempDir::new("walk-long");
        let component = "d".repeat(200);
        let level = CString::new(component.as_str()).unwrap();
        let mut dir = open_path(&tmp.0);
        let mut depth = 0;
        // One more component than a name has room for, which takes paths
        // longer than the kernel takes, so the directories are made below
        // each other by descriptor.
        while depth * (component.len() + 1) <= Name::MAX_LEN + component.len() {
            rustix::fs::mkdirat(&dir, level.as_c_str(), rustix::fs::Mode::RWXU).unwrap();
            let flags = OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC;
            dir = rustix::fs::openat(&dir, level.as_c_str(), flags, rustix::fs::Mode::empty()).unwrap();
            depth += 1;
        }
        // How many components a name has room for, with a separator after
        // every one but the last.
        let fits = (Name::MAX_LEN + 1) / (component.len() + 1);
        let e = walked(&tmp.0, Features::NONE, AddFlags::NONE).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::UnwritableName));
        assert_eq!(e.name_problem(), Some(NameProblem::TooLong));
        let parent = vec![component.as_str(); fits].join("/");
        assert_eq!(e.name(), Some(parent.as_str()));
        assert_eq!(e.raw_name(), Some(OsStr::new(&component)));
        let (whole, _, omitted) = walked(&tmp.0, Features::NONE, AddFlags::GRACEFUL).unwrap();
        assert_eq!((whole.objects.len(), omitted.entries), (fits, 1));
    }

    /// The status of a file that a test makes up, with the owner `uid` and
    /// `gid` and the modification time `mtime`.
    fn made_up(uid: u32, gid: u32, mtime: Timestamp) -> Status {
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
            uid,
            gid,
            size: 0,
            mtime,
            ctime: mtime,
            btime: None,
            rdev: DeviceNumber { major: 0, minor: 0 },
        }
    }

    /// The IDs 65535 and 4294967295 and a time before 1970 or after 2554
    /// are left out and counted. Everything else is taken as it is.
    #[test]
    fn fields_a_manifest_cannot_hold() {
        /// The nanoseconds of a second.
        const SECOND: u64 = 1_000_000_000;
        let features = Features::UID | Features::GID | Features::MTIME;
        let time = |seconds, nanoseconds| Timestamp { seconds, nanoseconds };
        let last = u64::MAX;
        let last_second = i64::try_from(last / SECOND).unwrap();
        let last_nanosecond = u32::try_from(last % SECOND).unwrap();
        let cases = [
            (made_up(0, 0, time(0, 0)), (Some(0), Some(0), Some(0)), 0),
            (
                made_up(65534, 1, time(1, 5)),
                (Some(65534), Some(1), Some(SECOND + 5)),
                0,
            ),
            (made_up(65535, 4294967295, time(1, 0)), (None, None, Some(SECOND)), 2),
            (made_up(4294967295, 65535, time(-1, 0)), (None, None, None), 3),
            (made_up(1, 1, time(-1, 999_999_999)), (Some(1), Some(1), None), 1),
            (
                made_up(1, 1, time(last_second, last_nanosecond)),
                (Some(1), Some(1), Some(last)),
                0,
            ),
            (
                made_up(1, 1, time(last_second, last_nanosecond + 1)),
                (Some(1), Some(1), None),
                1,
            ),
            (made_up(1, 1, time(i64::MAX, 999_999_999)), (Some(1), Some(1), None), 1),
        ];
        for (status, (uid, gid, mtime), left_out) in cases {
            let (inode, omitted) = InodeAttributes::of_status(&status, features);
            assert_eq!(
                (inode.uid, inode.gid, inode.mtime_nsec),
                (uid, gid, mtime),
                "{:?}",
                status
            );
            assert_eq!(omitted, left_out, "{:?}", status);
        }
        // Without the features nothing is taken, and nothing left out.
        let (inode, omitted) = InodeAttributes::of_status(&made_up(65535, 65535, time(-1, 0)), Features::NONE);
        assert_eq!((inode, omitted), (InodeAttributes::default(), 0));
    }

    /// A file modified before 1970 is listed without its time, which is
    /// counted.
    #[test]
    fn times_before_1970() {
        let tmp = TempDir::new("walk-old");
        let dir = &tmp.0;
        let path = dir.join("old");
        fs::write(&path, b"").unwrap();
        let old = UNIX_EPOCH - Duration::from_secs(86400);
        File::options()
            .write(true)
            .open(&path)
            .unwrap()
            .set_modified(old)
            .unwrap();
        let features = Features::DEFAULT | Features::MTIME;
        let (whole, _, omitted) = walked(dir, features, AddFlags::NONE).unwrap();
        assert_eq!(object(&whole, "old").inode().mtime(), None);
        assert!(whole.root.inode().mtime().is_some());
        assert_eq!(omitted.fields, 1);
    }

    /// Does steps of `budget` of the add `add` of `build` until it is done,
    /// calling `between` after every step with how many there were, and
    /// returns how many it took.
    fn in_steps(build: &mut Build, add: Add<'_>, budget: u64, mut between: impl FnMut(u64)) -> Result<u64, Error> {
        let mut task = Walker::begin(add);
        let mut steps = 0;
        loop {
            steps += 1;
            if build.walker.step(&mut task, budget)?.is_break() {
                return Ok(steps);
            }
            between(steps);
        }
    }

    /// The add of all of the directory `top` refers to as the root.
    fn all_of(top: &OwnedFd, flags: AddFlags) -> Add<'_> {
        Add::Tree {
            top: top.as_fd(),
            flags,
        }
    }

    /// A walk in steps of any budget comes to the manifest a walk in one go
    /// comes to, and a large file is hashed over several of them. A step
    /// without a budget does nothing.
    #[test]
    fn walks_in_steps() {
        let tmp = nested("walk-steps");
        let dir = &tmp.0;
        let large: Vec<u8> = (0..65536 + 3).map(|i| (i % 251) as u8).collect();
        fs::write(dir.join("a/large"), large).unwrap();
        fs::hard_link(dir.join("a/large"), dir.join("a/b/large-too")).unwrap();
        let features = Features::DEFAULT | Features::MTIME;
        let (whole, _, _) = walked(dir, features, AddFlags::NONE).unwrap();
        let top = open_path(dir);
        let mut counted = Vec::new();
        for budget in [1, 4096, STEP_BUDGET] {
            let mut build = Build::new(features);
            let steps = in_steps(&mut build, all_of(&top, AddFlags::NONE), budget, |_| {}).unwrap();
            counted.push(steps);
            let (stepped, _, _) = build.finish().unwrap();
            assert_eq!(stepped, whole, "{}", budget);
        }
        // The large file alone takes as many steps as budgets of its data.
        assert!(counted[1] > 2 * 65536 / 4096, "{:?}", counted);
        assert!(counted[0] > counted[1] && counted[1] > counted[2], "{:?}", counted);
        let mut build = Build::new(features);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        for _ in 0..3 {
            assert!(build.walker.step(&mut task, 0).unwrap().is_continue());
        }
        while build.walker.step(&mut task, STEP_BUDGET).unwrap().is_continue() {}
        // Nothing is left of an add that is done, whatever the budget.
        for budget in [0, 1, STEP_BUDGET] {
            assert!(build.walker.step(&mut task, budget).unwrap().is_break());
        }
        assert_eq!(build.finish().unwrap().0, whole);
    }

    /// The turn that opens a file counts as [`OPEN`] bytes of data on top
    /// of its name. So a step gets through as many files as its budget has
    /// room for, and a walk of small files takes steps as the data of a
    /// large file does.
    #[test]
    fn opening_a_file_counts() {
        /// How many files the tree has, and how many a step has budget for.
        const FILES: u64 = 200;
        const EACH: u64 = 10;
        let tmp = TempDir::new("walk-open-counts");
        let dir = &tmp.0;
        for number in 0..FILES {
            fs::write(dir.join(format!("f{:03}", number)), b"").unwrap();
        }
        let top = open_path(dir);
        let mut build = Build::new(Features::NONE);
        let steps = in_steps(&mut build, all_of(&top, AddFlags::NONE), EACH * OPEN, |_| {}).unwrap();
        // The name of a file and the turn that hands its object over count
        // as well, so a step has not quite the budget for the last of its
        // files, and the walk a few steps more.
        assert!((FILES / EACH..=FILES / (EACH - 1) + 2).contains(&steps), "{}", steps);
    }

    /// Waits until the change time of the directory `dir` moves past that of
    /// `before`, making files in it, which changes it.
    fn change(dir: &Path, before: &fs::Metadata) {
        for i in 0..1000 {
            fs::write(dir.join(format!("new-{}", i)), b"").unwrap();
            let now = fs::symlink_metadata(dir).unwrap();
            if (now.ctime(), now.ctime_nsec()) != (before.ctime(), before.ctime_nsec()) {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("the change time of {:?} does not move", dir);
    }

    /// Waits until the clock is far enough past the change time of `dir`
    /// that a change gives it another one. The time of a change can come
    /// from a clock that is a tick of up to 10 ms behind.
    fn past_change_time(dir: &Path) {
        let meta = fs::symlink_metadata(dir).unwrap();
        let ctime = UNIX_EPOCH + Duration::new(meta.ctime() as u64, meta.ctime_nsec() as u32);
        while SystemTime::now() < ctime + Duration::from_millis(20) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    /// A directory that gets a new entry while it is listed changed while
    /// it was read, and so did one whose entries are gone before it lists
    /// the next one, and one whose entry is gone between the listing and
    /// its open. A file that changes while its data is read changed as
    /// well.
    #[test]
    fn changes_while_walked() {
        let tmp = TempDir::new("walk-changes");
        let dir = &tmp.0;
        for i in 0..5 {
            fs::write(dir.join(format!("f{}", i)), b"").unwrap();
        }
        let before = fs::symlink_metadata(dir).unwrap();
        let top = open_path(dir);
        // Two steps of one turn each go into the directory.
        let mut build = Build::new(Features::NONE);
        let e = in_steps(&mut build, all_of(&top, AddFlags::NONE), 1, |steps| {
            if steps == 2 {
                change(dir, &before);
            }
        })
        .unwrap_err();
        assert_eq!((e.kind(), e.name()), (ErrorKind::Tree(TreeProblem::Changed), Some("")));
        // The third step takes the first entry of the listing, which has
        // the names of all of them. The fourth one finds the directory
        // changed.
        for entry in fs::read_dir(dir).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        let names: Vec<String> = (0..5).map(|i| format!("f{}", i)).collect();
        for name in &names {
            fs::write(dir.join(name), b"").unwrap();
        }
        let mut build = Build::new(Features::NONE);
        let e = in_steps(&mut build, all_of(&top, AddFlags::NONE), 1, |steps| {
            if steps == 3 {
                past_change_time(dir);
                for name in &names {
                    fs::remove_file(dir.join(name)).unwrap();
                }
            }
        })
        .unwrap_err();
        assert_eq!((e.kind(), e.name()), (ErrorKind::Tree(TreeProblem::Changed), Some("")));
        // An entry that is gone between the comparison of its directory and
        // its open.
        for name in &names {
            fs::write(dir.join(name), b"").unwrap();
        }
        let mut build = Build::new(Features::NONE);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        for _ in 0..2 {
            assert!(build.walker.step(&mut task, 1).unwrap().is_continue());
        }
        let walk = task.walk.as_mut().unwrap();
        let listed = walk.levels.last_mut().unwrap().entries.next().unwrap().unwrap();
        let name = listed.name().to_str().unwrap().to_owned();
        fs::remove_file(dir.join(&name)).unwrap();
        let e = build.walker.entry(walk, &listed, AddFlags::NONE).unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::Changed), Some(name.as_str()))
        );
        assert!(e.to_string().contains("removed or renamed"), "{}", e);
        // A file that grows while it is hashed.
        fs::write(dir.join("large"), vec![1; 3 * DATA_BUFFER_SIZE]).unwrap();
        let mut build = Build::new(Features::DEFAULT);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        let mut grown = false;
        let e = loop {
            match build.walker.step(&mut task, 4096) {
                Ok(flow) => assert!(flow.is_continue()),
                Err(e) => break e,
            }
            if !grown && matches!(&task.next, Next::Read(reading) if reading.hashed > 0) {
                let mut file = File::options().append(true).open(dir.join("large")).unwrap();
                file.write_all(b"!").unwrap();
                grown = true;
            }
        };
        assert!(grown);
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::Changed), Some("large")),
            "{}",
            e
        );
    }

    /// The entries a walk in steps began to read, by name, and those whose
    /// data it read.
    #[derive(Debug, Default)]
    struct Reads {
        entries: Vec<String>,
        data: Vec<String>,
    }

    impl Reads {
        /// Notes what the add `task` reads between two of its steps.
        fn note(&mut self, task: &Task<'_>) {
            let Next::Read(reading) = &task.next else {
                return;
            };
            let name = reading.object.name().as_str();
            if self.entries.last().map(String::as_str) != Some(name) {
                self.entries.push(name.to_owned());
            }
            let read = reading.hashed > 0 || reading.data.is_some();
            if read && self.data.last().map(String::as_str) != Some(name) {
                self.data.push(name.to_owned());
            }
        }
    }

    /// Walks all of `dir` in steps of one turn until the walk fails, and
    /// calls `rename` between two steps until it says that it renamed
    /// something. Returns the error, what the walk read, and how many
    /// entries and data it had read before the rename.
    fn renamed_while_walked(
        dir: &Path,
        mut rename: impl FnMut(&Reads, &Task<'_>) -> bool,
    ) -> (Error, Reads, (usize, usize)) {
        let mut build = Build::new(Features::DEFAULT);
        let top = open_path(dir);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        let mut reads = Reads::default();
        let mut before = None;
        loop {
            match build.walker.step(&mut task, 1) {
                Ok(flow) => assert!(flow.is_continue(), "the walk ended, having read {:?}", reads),
                Err(e) => return (e, reads, before.expect("a rename while the walk went on")),
            }
            reads.note(&task);
            if before.is_none() && rename(&reads, &task) {
                before = Some((reads.entries.len(), reads.data.len()));
            }
        }
    }

    /// The names of the entries of `dir` in the order of a walk, which is
    /// that of readdir() as long as the directory doesn't change.
    fn listing_order(dir: &Path) -> Vec<String> {
        fs::read_dir(dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect()
    }

    /// Whether `task` is between two entries of the root of its walk.
    fn between_entries_of_root(task: &Task<'_>) -> bool {
        matches!(task.next, Next::List) && task.walk.as_ref().is_some_and(|walk| walk.levels.len() == 1)
    }

    /// A rename in a directory stops a walk before the next entry, and
    /// nothing is read again under another name: a directory with what is
    /// below it, a file whose data was read, a symbolic link, and a file
    /// renamed over the name that is listed next. A rename while an entry
    /// is read lets that entry finish, and nothing more is read.
    #[test]
    fn renames_while_walked() {
        let tree = |case: &str| {
            let tmp = TempDir::new(&format!("walk-renames-{}", case));
            let dir = &tmp.0;
            for i in 0..3 {
                fs::create_dir(dir.join(format!("d{}", i))).unwrap();
                fs::write(dir.join(format!("d{}/a", i)), b"below").unwrap();
                fs::write(dir.join(format!("f{}", i)), format!("data of f{}", i)).unwrap();
                symlink("target", dir.join(format!("l{}", i))).unwrap();
            }
            let order = listing_order(dir);
            (tmp, order)
        };
        let check = |(e, reads, before): (Error, Reads, (usize, usize)), case: &str| {
            assert_eq!(
                (e.kind(), e.name()),
                (ErrorKind::Tree(TreeProblem::Changed), Some("")),
                "{}: {}",
                case,
                e
            );
            assert_eq!((reads.entries.len(), reads.data.len()), before, "{}: {:?}", case, reads);
        };
        for (case, kind) in [("directory", 'd'), ("file", 'f'), ("symlink", 'l')] {
            let (tmp, order) = tree(case);
            let dir = &tmp.0;
            let target = order[..order.len() - 1]
                .iter()
                .find(|name| name.starts_with(kind))
                .unwrap()
                .clone();
            let result = renamed_while_walked(dir, |reads, task| {
                if !reads.entries.contains(&target) || !between_entries_of_root(task) {
                    return false;
                }
                past_change_time(dir);
                fs::rename(dir.join(&target), dir.join(format!("{}-renamed", target))).unwrap();
                true
            });
            check(result, case);
        }
        // In a tree of regular files every name but the last is followed by
        // one a file can be renamed over.
        let tmp = TempDir::new("walk-renames-over");
        let dir = &tmp.0;
        for i in 0..5 {
            fs::write(dir.join(format!("f{}", i)), format!("data of f{}", i)).unwrap();
        }
        let order = listing_order(dir);
        let (target, next) = (&order[0], &order[1]);
        let result = renamed_while_walked(dir, |reads, task| {
            if !reads.entries.contains(target) || !between_entries_of_root(task) {
                return false;
            }
            past_change_time(dir);
            fs::rename(dir.join(target), dir.join(next)).unwrap();
            true
        });
        check(result, "over the next name");
        let (tmp, order) = tree("while-read");
        let dir = &tmp.0;
        let result = renamed_while_walked(dir, |_, task| {
            let Next::Read(reading) = &task.next else {
                return false;
            };
            let in_root = task.walk.as_ref().is_some_and(|walk| walk.levels.len() == 1);
            if !in_root || reading.hashed == 0 || reading.data.is_some() {
                return false;
            }
            let other = order
                .iter()
                .find(|name| *name != reading.object.name().as_str())
                .unwrap();
            past_change_time(dir);
            fs::rename(dir.join(other), dir.join(format!("{}-renamed", other))).unwrap();
            true
        });
        check(result, "while an entry is read");
    }

    /// Two names of one inode are held against each other with the hash of
    /// their data where the manifest records hard links, also where it
    /// records no hashes: data that is written over with the same size and
    /// the modification time set back is another file.
    #[test]
    fn hard_links_are_held_against_their_data() {
        let tmp = TempDir::new("walk-hard-links");
        let dir = &tmp.0;
        fs::write(dir.join("a"), b"first").unwrap();
        fs::hard_link(dir.join("a"), dir.join("b")).unwrap();
        let features = Features::DEFAULT.without(Features::SHA256);
        let top = open_path(dir);
        let mut build = Build::new(features);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        // Steps of one turn each, until the first of the two names went to
        // the listing.
        let mut reads = Reads::default();
        while reads.entries.len() < 2 || !between_entries_of_root(&task) {
            assert!(build.walker.step(&mut task, 1).unwrap().is_continue());
            reads.note(&task);
        }
        let (first, second) = match reads.entries[1].as_str() {
            "a" => ("a", "b"),
            _ => ("b", "a"),
        };
        let mtime = fs::symlink_metadata(dir.join("a")).unwrap().modified().unwrap();
        let mut file = File::options().write(true).open(dir.join("a")).unwrap();
        file.write_all(b"other").unwrap();
        file.set_modified(mtime).unwrap();
        let e = build.walker.step(&mut task, STEP_BUDGET).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::HardlinkMismatch));
        assert_eq!((e.name(), e.hardlink_name()), (Some(second), Some(first)));
        // Left alone they share a token, without a hash in the manifest.
        let (whole, _, _) = walked(dir, features, AddFlags::NONE).unwrap();
        let (a, b) = (object(&whole, "a"), object(&whole, "b"));
        assert_eq!(a.inode_token(), b.inode_token());
        assert!(a.inode_token().is_some() && a.sha256().is_none());
    }

    /// A device node has its device numbers where the manifest records
    /// them, and none where it does not. /dev/null is there without a
    /// namespace.
    #[test]
    fn device_numbers() {
        let null = fs::metadata("/dev/null").unwrap();
        let numbers = (
            Some(u64::from(rustix::fs::major(null.rdev()))),
            Some(u64::from(rustix::fs::minor(null.rdev()))),
        );
        let status = Status::of(open_path(Path::new("/dev/null")).as_fd()).unwrap();
        let object = |features| {
            let (object, omitted) = FileObject::of_status(testing::name("null"), &status, features).unwrap();
            assert_eq!(omitted, 0);
            object
        };
        let device = object(Features::DEFAULT);
        assert_eq!(device.inode_type(), InodeType::CharDevice);
        assert_eq!((device.major(), device.minor()), numbers);
        assert_eq!((device.size(), device.sha256()), (None, None));
        let unrecorded = object(Features::DEFAULT.without(Features::DEVICE));
        assert_eq!((unrecorded.major(), unrecorded.minor()), (None, None));
    }

    /// A walk goes as deep as a tree goes, with a descriptor for every
    /// directory it is in.
    #[test]
    fn deep_trees() {
        let tmp = TempDir::new("walk-deep");
        let mut path = tmp.0.clone();
        let mut deep = Vec::new();
        let mut name = String::new();
        for _ in 0..300 {
            name = if name.is_empty() {
                "d".into()
            } else {
                format!("{}/d", name)
            };
            path.push("d");
            deep.push(name.clone());
        }
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("file"), b"bottom").unwrap();
        deep.push(format!("{}/file", name));
        let (whole, _, _) = walked(&tmp.0, Features::DEFAULT, AddFlags::NONE).unwrap();
        let listed: Vec<&str> = deep.iter().map(String::as_str).collect();
        assert_eq!(names(&whole), listed);
    }

    /// A walk passes over the files of the manifest's own, wherever they
    /// are in a tree: the file it is told to, the manifest itself, and what
    /// the scratch space of its listing has among its files, as it has
    /// every scratch file it made. They are known by their inodes, so one
    /// that has another name by the time the walk comes to it is passed
    /// over as well. A file system can give two files one inode. So a file
    /// that has the inode of one of them and is another file, by its
    /// status, is a file of the tree and is listed. Here the manifest is
    /// kept under the inode of such a file as well, as that file system
    /// would have it.
    #[test]
    fn passes_over_its_own_files() {
        let tmp = TempDir::new("walk-own");
        let dir = &tmp.0;
        fs::create_dir(dir.join("below")).unwrap();
        for name in ["manifest", "below/scratch", "other", "below/other", "same-number"] {
            fs::write(dir.join(name), name).unwrap();
        }
        let open = |name: &str| Arc::new(File::open(dir.join(name)).unwrap());
        let inode_of = |name: &str| {
            let status = Status::of(open_path(&dir.join(name)).as_fd()).unwrap();
            status.identity.inode_id()
        };
        let scratch_dir = TempDir::new("walk-own-scratch");
        let mut scratch = Scratch::beside(ScratchFile::open_directory(&scratch_dir.0).unwrap().into());
        let own = scratch.own_files_mut();
        own.keep(inode_of("below/scratch"), open("below/scratch"));
        let listing = Listing::new(Features::DEFAULT, Order::CodePoint, scratch);
        let mut build = Build {
            walker: Walker::new(Features::DEFAULT, listing),
            _scratch: scratch_dir,
        };
        let manifest = open("manifest");
        build.walker.pass_over(inode_of("manifest"), Arc::clone(&manifest));
        build.walker.pass_over(inode_of("same-number"), manifest);
        // As a file system renames a file that is unlinked while it is open.
        fs::rename(dir.join("below/scratch"), dir.join("below/.kept")).unwrap();
        build.add_all(open_path(dir).as_fd(), AddFlags::NONE).unwrap();
        let (whole, _, _) = build.finish().unwrap();
        assert_eq!(names(&whole), ["below", "below/other", "other", "same-number"]);
    }

    /// A file system that gives two files one inode can give it to two of
    /// the files of the manifest's own. A walk passes over both then: a
    /// file that is kept with the inode of one that was kept before does
    /// not take its place, and both stay open while the walker is there. A
    /// file of the tree that has their inode and the status of neither is
    /// listed. Here each of the two is kept under its own inode, under that
    /// of the other one and under that of such a file of the tree, as that
    /// file system would have them.
    #[test]
    fn passes_over_own_files_with_one_inode() {
        let tmp = TempDir::new("walk-own-one-inode");
        let dir = &tmp.0;
        fs::create_dir(dir.join("below")).unwrap();
        let files = [
            ("older", "the older one"),
            ("below/newer", "newer"),
            ("same-number", "of the tree"),
            ("other", "other"),
            ("below/other", "other"),
        ];
        for (name, data) in files {
            fs::write(dir.join(name), data).unwrap();
        }
        let open = |name: &str| Arc::new(File::open(dir.join(name)).unwrap());
        let inode_of = |name: &str| {
            let status = Status::of(open_path(&dir.join(name)).as_fd()).unwrap();
            status.identity.inode_id()
        };
        let mut build = Build::new(Features::DEFAULT);
        let (older, newer) = (open("older"), open("below/newer"));
        for name in ["older", "below/newer", "same-number"] {
            build.walker.pass_over(inode_of(name), Arc::clone(&older));
            build.walker.pass_over(inode_of(name), Arc::clone(&newer));
        }
        build.add_all(open_path(dir).as_fd(), AddFlags::NONE).unwrap();
        // What the walker has of the two, next to the test.
        let held = (Arc::strong_count(&older) - 1, Arc::strong_count(&newer) - 1);
        let (whole, _, _) = build.finish().unwrap();
        assert_eq!(names(&whole), ["below", "below/other", "other", "same-number"]);
        assert_eq!(held, (3, 3));
    }

    /// Where the status of a file of the manifest's own can't be read, a
    /// walk can't tell a file that has its inode from it. The add fails
    /// with the error of that status at the first such file. The error
    /// names the file, and its message says that it is a file of the
    /// manifest's own that can't be read. Here that file is the directory
    /// procfs has for the descriptors of a process that is gone by the time
    /// the walk asks: the kernel refuses its status with ENOENT then, since
    /// Linux 6.2. The test is skipped where the kernel still reads it.
    #[test]
    fn own_files_that_cannot_be_read() {
        let tmp = TempDir::new("walk-own-unread");
        let dir = &tmp.0;
        fs::create_dir(dir.join("below")).unwrap();
        fs::write(dir.join("below/file"), b"file").unwrap();
        fs::write(dir.join("other"), b"other").unwrap();
        // A process that is there until its input ends.
        let mut child = Command::new("cat")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()
            .unwrap();
        let gone = File::open(format!("/proc/{}/fd", child.id())).unwrap();
        drop(child.stdin.take());
        child.wait().unwrap();
        match Status::of(gone.as_fd()) {
            Err(Failure::Io(e)) => assert_eq!(e.raw_os_error(), Some(libc::ENOENT)),
            read => {
                eprintln!(
                    "skipping: the descriptors of a process that is gone have a status: {:?}",
                    read
                );
                return;
            }
        }
        let file = Status::of(open_path(&dir.join("below/file")).as_fd()).unwrap();
        let mut build = Build::new(Features::DEFAULT);
        build.walker.pass_over(file.identity.inode_id(), Arc::new(gone));
        let e = build.add_all(open_path(dir).as_fd(), AddFlags::NONE).unwrap_err();
        assert_eq!(
            (e.kind(), e.io_error().and_then(io::Error::raw_os_error), e.name()),
            (ErrorKind::Io, Some(libc::ENOENT), Some("below/file"))
        );
        assert_eq!(
            e.to_string(),
            "below/file: a file of the manifest's own with its inode can't be read: \
             No such file or directory (os error 2)"
        );
    }

    /// A feature that can't be read fails the walk at the first file it
    /// can't be read of, naming the file and the feature. A walk asks the
    /// file system of the directory it starts at for the DOS attributes
    /// with that directory, the root, which has none itself. So the walk of
    /// a tree without DOS attributes fails at the root. Whether a file is
    /// read-only never fails.
    #[test]
    fn features_that_cannot_be_read() {
        let tmp = nested("walk-unreadable");
        let dir = &tmp.0;
        let Err(e) = walked(dir, Features::FLAG_HIDDEN, AddFlags::NONE) else {
            eprintln!("skipping: the temporary directory has DOS attributes");
            return;
        };
        assert_eq!(
            (e.kind(), e.name(), e.feature()),
            (
                ErrorKind::Tree(TreeProblem::FeatureUnavailable),
                Some(""),
                Some(Features::FLAG_HIDDEN)
            ),
            "{}",
            e
        );
        walked(dir, Features::DEFAULT | Features::READ_ONLY, AddFlags::NONE).unwrap();
    }

    /// A regular file with more data than is hashed fails the walk with
    /// EFBIG where its data is hashed, in the first steps of the walk,
    /// before anything is read of it. Its size is recorded where its data
    /// is not hashed, and a file of the most data that is hashed begins to
    /// be read.
    #[test]
    fn files_too_large_to_hash() {
        let tmp = TempDir::new("walk-too-large");
        let dir = &tmp.0;
        let file = File::create(dir.join("large")).unwrap();
        if let Err(e) = file.set_len(DataHash::MAX_SIZE + 1) {
            eprintln!("skipping: the temporary directory takes no file of that size: {}", e);
            return;
        }
        let top = open_path(dir);
        // Reading the file through would take a quarter of an hour. So the
        // walk is done in steps of one byte, and only its first ones.
        const FIRST_STEPS: usize = 8;
        let mut build = Build::new(Features::DEFAULT);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        let failed = (0..FIRST_STEPS).find_map(|_| build.walker.step(&mut task, 1).err());
        let e = failed.expect("the walk fails before it reads");
        assert_eq!(
            (e.io_error().and_then(io::Error::raw_os_error), e.name()),
            (Some(libc::EFBIG), Some("large"))
        );
        // The file is not opened for that, so one that may not be opened
        // fails for its size, also where its extended attributes are read
        // through the file that is opened for its data. That takes a root
        // whose extended attributes can be read.
        fs::set_permissions(dir.join("large"), fs::Permissions::from_mode(0o000)).unwrap();
        let mut closed = Build::new(Features::DEFAULT | Features::USER_XATTR);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        let failed = (0..FIRST_STEPS).find_map(|_| closed.walker.step(&mut task, 1).err());
        match failed.expect("the walk fails before it reads") {
            e if e.kind() == ErrorKind::Tree(TreeProblem::FeatureUnavailable) => {
                eprintln!("skipping extended attributes: {}", e);
            }
            e => assert_eq!(e.io_error().and_then(io::Error::raw_os_error), Some(libc::EFBIG)),
        }
        fs::set_permissions(dir.join("large"), fs::Permissions::from_mode(0o644)).unwrap();
        // Without its hash it is a file like any other.
        let (whole, _, _) = walked(dir, Features::MODE | Features::SIZE, AddFlags::NONE).unwrap();
        assert_eq!(object(&whole, "large").size(), Some(DataHash::MAX_SIZE + 1));
        // One byte less, and the hash of its data begins.
        file.set_len(DataHash::MAX_SIZE).unwrap();
        let mut build = Build::new(Features::DEFAULT);
        let mut task = Walker::begin(all_of(&top, AddFlags::NONE));
        for _ in 0..FIRST_STEPS {
            assert!(build.walker.step(&mut task, 1).unwrap().is_continue());
        }
        assert!(matches!(&task.next, Next::Read(reading) if reading.hash.is_some() && reading.hashed > 0));
    }

    /// Nothing is opened for its extended attributes: where the data of a
    /// file is not hashed, inotify sees no open of it, and a file that may
    /// not be opened is added, with no attributes if it has none.
    #[test]
    fn extended_attributes_open_nothing() {
        let tmp = TempDir::new("walk-xattrs-open");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"data").unwrap();
        fs::write(dir.join("closed"), b"data").unwrap();
        let set = rustix::fs::setxattr(dir.join("file"), "user.of the file", b"1", XattrFlags::empty());
        if let Err(e) = set {
            eprintln!("skipping: the temporary directory has no extended attributes: {}", e);
            return;
        }
        let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).unwrap();
        for name in ["file", "closed"] {
            inotify::add_watch(&inotify, dir.join(name), inotify::WatchFlags::OPEN).unwrap();
        }
        fs::set_permissions(dir.join("closed"), fs::Permissions::from_mode(0o000)).unwrap();
        let features = Features::MODE | Features::SIZE | Features::USER_XATTR;
        let (whole, _, _) = walked(dir, features, AddFlags::NONE).unwrap();
        let attributes = |name| {
            let xattrs = object(&whole, name).inode().user_xattrs();
            xattrs.map(|xattrs| {
                xattrs
                    .map(|(name, value)| (name.to_owned(), value.to_vec()))
                    .collect::<Vec<_>>()
            })
        };
        assert_eq!(
            attributes("file"),
            Some(vec![("of the file".to_owned(), b"1".to_vec())])
        );
        assert_eq!(attributes("closed"), Some(Vec::new()));
        let mut buffer = [mem::MaybeUninit::uninit(); 4096];
        let mut events = inotify::Reader::new(&inotify, &mut buffer);
        assert!(matches!(events.next(), Err(rustix::io::Errno::AGAIN)));
    }

    /// The variable that tells the test binary, run again by
    /// [`walks_without_procfs`] with nothing in /proc, where the tree is.
    const NO_PROCFS_DIR: &str = "UAPI16_TEST_WALK_NO_PROCFS_DIR";

    /// A walk takes no procfs where everything it reads extended attributes
    /// of is open for reading anyway: the directories it lists, and the
    /// regular files whose data it hashes, which are opened before their
    /// attributes are read. A file that is not opened, such as a FIFO,
    /// can't have its attributes read without one. The test binary runs
    /// this test again with an empty tmpfs over /proc, in a user and a
    /// mount namespace from unshare(1), and it is skipped where unshare
    /// can't make them.
    ///
    /// Without O_EMPTYPATH a regular file and the directory of a caller are
    /// opened through procfs, by pathrs, which panics where there is none.
    /// So the test is skipped where the kernel does not have it.
    #[test]
    fn walks_without_procfs() {
        if let Some(dir) = std::env::var_os(NO_PROCFS_DIR) {
            return check_without_procfs(Path::new(&dir));
        }
        let tmp = TempDir::new("walk-no-procfs");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("tree/dir")).unwrap();
        fs::write(dir.join("tree/dir/file"), b"data").unwrap();
        for (name, value) in [("tree/dir", b"2"), ("tree/dir/file", b"1")] {
            let set = rustix::fs::setxattr(dir.join(name), "user.of it", value, XattrFlags::empty());
            if let Err(e) = set {
                eprintln!("skipping: the temporary directory has no extended attributes: {}", e);
                return;
            }
        }
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        if !testing::has_empty_path() {
            eprintln!("skipping: the kernel has no O_EMPTYPATH");
            return;
        }
        let script = concat!(
            r#"mount -t tmpfs tmpfs /proc && "#,
            r#"exec "$1" --exact walk::tests::walks_without_procfs --nocapture"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(std::env::current_exe().unwrap())
            .env(NO_PROCFS_DIR, dir)
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`walks_without_procfs`] below `dir`, with nothing in
    /// /proc.
    fn check_without_procfs(dir: &Path) {
        assert!(fs::read_dir("/proc").unwrap().next().is_none());
        let tree = dir.join("tree");
        let features = Features::DEFAULT | Features::USER_XATTR;
        let (whole, _, _) = walked(&tree, features, AddFlags::NONE).unwrap();
        assert_eq!(names(&whole), ["dir", "dir/file"]);
        assert_eq!(object(&whole, "dir").inode().user_xattr("of it"), Some(&b"2"[..]));
        assert_eq!(object(&whole, "dir/file").inode().user_xattr("of it"), Some(&b"1"[..]));
        // A file whose data is not hashed is not opened, and neither is a
        // FIFO.
        let unhashed = walked(&tree, Features::MODE | Features::USER_XATTR, AddFlags::NONE);
        make_fifo(&tree.join("fifo"));
        for failed in [unhashed, walked(&tree, features, AddFlags::NONE)] {
            let e = failed.unwrap_err();
            assert_eq!(
                (e.kind(), e.feature()),
                (
                    ErrorKind::Tree(TreeProblem::FeatureUnavailable),
                    Some(Features::USER_XATTR)
                ),
                "{}",
                e
            );
        }
    }

    /// The variable that names an automount point for
    /// [`automount_points`].
    const AUTOMOUNT: &str = "UAPI16_TEST_AUTOMOUNT";

    /// An automount point is added as the empty directory it is, with what
    /// statx() says of it, and nothing is mounted on it: where a walk comes
    /// to it, and where it is the directory a walk starts at, whether mount
    /// points are crossed or not. What is read from the open file can't be
    /// read of it.
    ///
    /// Only root can make an automount point, so the test takes one that is
    /// there: `UAPI16_TEST_AUTOMOUNT` names a directory that is one and
    /// that nothing is mounted on yet, such as the mount point of an
    /// automount unit of systemd, or `tracing` in a debugfs that was just
    /// mounted. The directory it is in is walked, without reading the data
    /// of any file. Without the variable the test is skipped.
    #[test]
    fn automount_points() {
        let Some(point) = std::env::var_os(AUTOMOUNT) else {
            eprintln!("skipping: {} names no automount point", AUTOMOUNT);
            return;
        };
        let point = Path::new(&point);
        let name = point.file_name().unwrap().to_str().unwrap();
        let top = open_path(point.parent().unwrap());
        let in_dir = CString::new(name).unwrap();
        // A handle of it says whether something is mounted on it by now:
        // it is the root of what is mounted then, and no automount point.
        let entry = || Entry::open_at(top.as_fd(), &in_dir).unwrap();
        assert!(
            entry().is_automount(),
            "{} is no automount point, or something is mounted on it",
            point.display()
        );
        let mode = entry().status().mode;
        let below = format!("{}/", name);
        for flags in [AddFlags::NONE, AddFlags::CROSS_MOUNTS] {
            // Where a walk comes to it.
            let (whole, _, _) = walked(point.parent().unwrap(), Features::MODE, flags).unwrap();
            let listed = object(&whole, name);
            assert_eq!(
                (listed.inode_type(), listed.inode().mode()),
                (InodeType::Directory, Some(mode))
            );
            assert!(!names(&whole).iter().any(|other| other.starts_with(&below)));
            // As the directory a walk starts at.
            let (whole, _, _) = walked(point, Features::DEFAULT, flags).unwrap();
            assert!(whole.objects.is_empty());
            assert_eq!(whole.root.inode().mode(), Some(mode));
        }
        // The inode flags are read from the open file, which there is none
        // of.
        let e = walked(point, Features::DEFAULT | Features::FLAG_NO_DUMP, AddFlags::NONE).unwrap_err();
        assert_eq!(
            (e.kind(), e.name(), e.feature()),
            (
                ErrorKind::Tree(TreeProblem::FeatureUnavailable),
                Some(""),
                Some(Features::FLAG_NO_DUMP)
            ),
            "{}",
            e
        );
        // The UUID and the volume serial number of the file system are
        // read from the open file as well, and are left out and counted as
        // where a file system has none.
        let identified = Features::MODE | Features::FS_UUID | Features::FAT_SERIAL;
        let (whole, _, omitted) = walked(point, identified, AddFlags::NONE).unwrap();
        assert!(whole.root.file_system().is_empty());
        assert_eq!(omitted.fields, 2);
        assert!(entry().is_automount(), "something was mounted on {}", point.display());
    }

    /// File objects of a caller that take more room than the 32 MiB the
    /// sort keeps in memory: the listing has to make room before it takes
    /// the last of them.
    fn large_objects() -> Vec<FileObject> {
        (0..36u8)
            .map(|number| {
                let mut object = FileObject::new(testing::name(&format!("large/{:02}", number)));
                let data = vec![number; 1 << 20];
                object.size = Some(data.len() as u64);
                object.contents = vec![ContentsObject::new(ContentsSource::Literal(data))];
                object
            })
            .collect()
    }

    /// A file object of a caller goes into the manifest next to the files of
    /// a tree. Its add waits while the listing makes room for it, a step at
    /// a time, and hands it over once there is room. So does the add of
    /// the root as a caller describes it, and so does the walk of a tree
    /// with what it read.
    #[test]
    fn file_objects_of_a_caller() {
        let (tmp, _socket, mut names) = every_type("walk-given");
        let dir = &tmp.0;
        let mut build = Build::new(Features::DEFAULT);
        build.add_all(open_path(dir).as_fd(), AddFlags::NONE).unwrap();
        let mut given = FileObject::new(testing::name("given"));
        given.size = Some(3);
        build.run(Add::Object(&given)).unwrap();
        let (whole, _, _) = build.finish().unwrap();
        names.push("given");
        assert_eq!(object(&whole, "given").size(), Some(3));
        assert_eq!(whole.objects.len(), names.len());
        // Objects the listing has to make room for. The add of the first
        // one that waits is given up for the walk of a tree, which waits
        // with the root it read and is given up for the add of a root,
        // which finds the listing without room as well.
        let top = open_path(dir);
        let objects = large_objects();
        let inode = InodeAttributes {
            mode: Some(Mode::new(0o750).unwrap()),
            ..InodeAttributes::default()
        };
        let file_system = FileSystemIdentity::default();
        let mut build = Build::new(Features::DEFAULT);
        let (mut waited, mut root_waited) = (0, 0);
        for object in &objects {
            let mut task = Walker::begin(Add::Object(object));
            if build.walker.step(&mut task, 1).unwrap().is_continue() {
                assert!(matches!(task.next, Next::Given(_)));
                waited += 1;
                // The first step of a walk reads its root, and the second
                // one waits with it.
                let mut walk = Walker::begin(all_of(&top, AddFlags::NONE));
                for _ in 0..2 {
                    assert!(build.walker.step(&mut walk, 1).unwrap().is_continue());
                    assert!(matches!(walk.next, Next::Read(_)));
                }
                drop(walk);
                let mut root = Walker::begin(Add::Root {
                    inode: &inode,
                    file_system: &file_system,
                });
                while build.walker.step(&mut root, 1).unwrap().is_continue() {
                    assert!(matches!(root.next, Next::GivenRoot(..)));
                    root_waited += 1;
                }
                build.run(Add::Object(object)).unwrap();
            }
        }
        assert!(waited > 0 && root_waited > 0);
        let (whole, _, _) = build.finish().unwrap();
        assert_eq!(whole.root.inode().mode(), inode.mode);
        let listed: Vec<&str> = objects.iter().map(|object| object.name().as_str()).collect();
        assert_eq!(self::names(&whole)[1..], listed);
    }

    /// The add of a file object that is refused adds nothing, and the adds
    /// go on as if it had not been. A walk that fails has nothing open any
    /// more, and nothing is left to do of it: every later step of it does
    /// nothing and breaks, whatever its budget. That holds for the walk of
    /// a file that is not a directory, for the walk of a directory that
    /// can't be listed, and for a walk that fails in the middle of a tree,
    /// in a directory it lists: at a file that can't be opened for its
    /// hash, which the error names, and at a name a manifest can't hold.
    #[test]
    fn what_a_failed_add_leaves() {
        let tmp = nested("walk-failed");
        let dir = &tmp.0;
        let top = open_path(dir);
        let all = |build: &mut Build| build.add_all(top.as_fd(), AddFlags::NONE).unwrap();
        let mut clean = Build::new(Features::DEFAULT);
        all(&mut clean);
        let (whole, _, _) = clean.finish().unwrap();
        // A file object with an owner that no manifest may have.
        let mut build = Build::new(Features::DEFAULT);
        let mut refused = FileObject::new(testing::name("refused"));
        refused.inode.uid = Some(65535);
        let e = build.run(Add::Object(&refused)).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(crate::Problem::FieldOutOfRange));
        all(&mut build);
        assert_eq!(build.finish().unwrap().0, whole);
        // Nothing is left to do of the add of a file object or of a root
        // that was refused either: every later step of it does nothing and
        // breaks, whatever its budget.
        let mut build = Build::new(Features::DEFAULT);
        let file_system = FileSystemIdentity::default();
        let refused_adds = [
            Add::Object(&refused),
            Add::Root {
                inode: &refused.inode,
                file_system: &file_system,
            },
        ];
        for add in refused_adds {
            let mut task = Walker::begin(add);
            let e = build.walker.step(&mut task, STEP_BUDGET).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(crate::Problem::FieldOutOfRange));
            assert!(matches!(task.next, Next::Failed));
            for budget in [0, 1, STEP_BUDGET] {
                assert!(build.walker.step(&mut task, budget).unwrap().is_break());
            }
        }
        all(&mut build);
        assert_eq!(build.finish().unwrap().0, whole);
        // Walks what `at` refers to in steps of one turn until the walk
        // fails. Returns the error, and whether the walk was in a directory
        // before.
        let failed = |at: &OwnedFd| {
            let mut build = Build::new(Features::DEFAULT);
            let mut task = Walker::begin(all_of(at, AddFlags::NONE));
            let mut open = false;
            let e = loop {
                open |= task.walk.as_ref().is_some_and(|walk| !walk.levels.is_empty());
                match build.walker.step(&mut task, 1) {
                    Ok(flow) => assert!(flow.is_continue()),
                    Err(e) => break e,
                }
            };
            assert!(task.walk.is_none() && matches!(task.next, Next::Failed));
            // Nothing is left of an add that failed, whatever the budget.
            for budget in [0, 1, STEP_BUDGET] {
                assert!(build.walker.step(&mut task, budget).unwrap().is_break());
            }
            (e, open)
        };
        // A file that is not a directory.
        let (e, _) = failed(&open_path(&dir.join("f")));
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::NotDirectory), Some(""))
        );
        // A directory that can't be listed, as one that may be searched
        // only, unless the tests may read any directory.
        let locked = TempDir::new("walk-failed-locked");
        fs::create_dir(locked.0.join("dir")).unwrap();
        fs::set_permissions(locked.0.join("dir"), fs::Permissions::from_mode(0o311)).unwrap();
        if fs::read_dir(locked.0.join("dir")).is_ok() {
            eprintln!("skipping the directory that can't be listed: the tests may read any");
        } else {
            let (e, _) = failed(&open_path(&locked.0.join("dir")));
            assert_eq!(
                (e.io_error().map(io::Error::kind), e.name()),
                (Some(io::ErrorKind::PermissionDenied), Some("")),
                "{}",
                e
            );
        }
        fs::set_permissions(locked.0.join("dir"), fs::Permissions::from_mode(0o755)).unwrap();
        // A file that can't be opened for its hash, in a directory the walk
        // lists, unless the tests may read any file.
        fs::write(locked.0.join("dir/closed"), b"data").unwrap();
        fs::set_permissions(locked.0.join("dir/closed"), fs::Permissions::from_mode(0o000)).unwrap();
        if File::open(locked.0.join("dir/closed")).is_ok() {
            eprintln!("skipping the file that can't be opened: the tests may read any");
        } else {
            let (e, open) = failed(&open_path(&locked.0));
            assert_eq!(
                (e.io_error().map(io::Error::kind), e.name()),
                (Some(io::ErrorKind::PermissionDenied), Some("dir/closed")),
                "{}",
                e
            );
            assert!(open);
        }
        // In the middle of a tree, in a directory the walk lists, which the
        // step that fails closes.
        fs::write(dir.join(OsString::from_vec(b"\xff".to_vec())), b"").unwrap();
        let (e, open) = failed(&top);
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::UnwritableName));
        assert!(open);
    }

    /// A walk opens nothing but regular files and directories: a FIFO, a
    /// socket and a symbolic link are read through their handles, whatever
    /// the features read of them, and inotify sees no open of the FIFO.
    #[test]
    fn opens_nothing_else() {
        let (tmp, _socket, _) = every_type("walk-opens");
        let dir = &tmp.0;
        let inotify = inotify::init(inotify::CreateFlags::CLOEXEC | inotify::CreateFlags::NONBLOCK).unwrap();
        inotify::add_watch(&inotify, dir.join("fifo"), inotify::WatchFlags::OPEN).unwrap();
        let features = Features::DEFAULT | Features::MTIME | Features::READ_ONLY | Features::USER_XATTR;
        match walked(dir, features, AddFlags::NONE) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::Tree(TreeProblem::FeatureUnavailable) => {
                eprintln!("skipping extended attributes: {}", e);
                walked(dir, Features::DEFAULT | Features::READ_ONLY, AddFlags::NONE).unwrap();
            }
            Err(e) => panic!("{}", e),
        }
        let mut buffer = [mem::MaybeUninit::uninit(); 4096];
        let mut events = inotify::Reader::new(&inotify, &mut buffer);
        assert!(matches!(events.next(), Err(rustix::io::Errno::AGAIN)));
    }

    /// What a walk keeps can go to another thread.
    #[test]
    fn send() {
        fn send<T: Send>() {}
        send::<Walker>();
        send::<Add<'_>>();
        send::<Task<'_>>();
    }

    /// The variable that tells the test binary, run again inside the
    /// namespaces of [`mounts`], where the trees with the mounts are.
    const MOUNTS_DIR: &str = "UAPI16_TEST_MOUNTS_DIR";

    /// Mount points: what a walk makes of them without crossing them and
    /// with, a mount that shows a directory again inside itself, and a
    /// walk that starts at a mount point. The mounts need a user and a
    /// mount namespace, which unshare(1) makes, and the test binary runs
    /// this test again inside them.
    #[test]
    fn mounts() {
        if let Some(dir) = std::env::var_os(MOUNTS_DIR) {
            return check_mounts(Path::new(&dir));
        }
        let tmp = TempDir::new("walk-mounts");
        let dir = &tmp.0;
        fs::create_dir_all(dir.join("a/tmpfs")).unwrap();
        fs::create_dir_all(dir.join("a/bind")).unwrap();
        fs::create_dir_all(dir.join("a/bind2")).unwrap();
        fs::write(dir.join("a/file-mount"), b"covered").unwrap();
        fs::set_permissions(dir.join("a/file-mount"), fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(dir.join("a/device-mount"), b"covered").unwrap();
        fs::write(dir.join("a/plain"), b"plain").unwrap();
        fs::create_dir_all(dir.join("source/below")).unwrap();
        fs::set_permissions(dir.join("source"), fs::Permissions::from_mode(0o750)).unwrap();
        fs::write(dir.join("source/below/x"), b"x").unwrap();
        fs::hard_link(dir.join("source/below/x"), dir.join("source/below/y")).unwrap();
        fs::write(dir.join("shown"), b"the file the mount shows").unwrap();
        fs::set_permissions(dir.join("shown"), fs::Permissions::from_mode(0o640)).unwrap();
        fs::create_dir_all(dir.join("b/x/loop")).unwrap();
        fs::write(dir.join("b/x/file"), b"").unwrap();
        let works = Command::new("unshare").args(["-Urm", "true"]).output();
        if !works.is_ok_and(|output| output.status.success()) {
            eprintln!("skipping: unshare -Urm does not work here");
            return;
        }
        let script = concat!(
            r#"set -e; d=$1; "#,
            r#"mount -t tmpfs -o mode=0711 tmpfs "$d/a/tmpfs"; "#,
            r#"echo inside > "$d/a/tmpfs/inside"; mkdir "$d/a/tmpfs/nested"; "#,
            r#"mount -t tmpfs -o mode=0700 tmpfs "$d/a/tmpfs/nested"; "#,
            r#"echo deeper > "$d/a/tmpfs/nested/deeper"; "#,
            r#"mount --bind "$d/source" "$d/a/bind"; "#,
            r#"mount --bind "$d/source" "$d/a/bind2"; "#,
            r#"mount --bind "$d/shown" "$d/a/file-mount"; "#,
            r#"mount --bind /dev/null "$d/a/device-mount"; "#,
            r#"mount --bind "$d/b" "$d/b/x/loop"; "#,
            r#"exec "$2" --exact walk::tests::mounts"#
        );
        let output = Command::new("unshare")
            .args(["-Urm", "sh", "-c", script, "sh"])
            .arg(dir)
            .arg(std::env::current_exe().unwrap())
            .env(MOUNTS_DIR, dir)
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
    }

    /// The checks of [`mounts`] below `dir`.
    fn check_mounts(dir: &Path) {
        let a = dir.join("a");
        let features = Features::DEFAULT;
        let none = AddFlags::NONE;
        let crossing = AddFlags::CROSS_MOUNTS;
        let mode = |whole: &Whole, name: &str| object(whole, name).inode().mode().unwrap().bits();
        // Without crossing them, a mount point that is a directory is an
        // empty one with the attributes of the mounted root, and a file that
        // is mounted over another one is the file the mount shows: a regular
        // file with its attributes and the hash of its data, a device node
        // with its attributes and its device numbers.
        let (whole, _, _) = walked(&a, features, none).unwrap();
        assert_eq!(
            names(&whole),
            ["bind", "bind2", "device-mount", "file-mount", "plain", "tmpfs"]
        );
        assert_eq!((mode(&whole, "tmpfs"), mode(&whole, "bind")), (0o711, 0o750));
        let shown = object(&whole, "file-mount");
        let data = b"the file the mount shows";
        assert_eq!(
            (shown.inode_type(), mode(&whole, "file-mount"), shown.size()),
            (InodeType::Regular, 0o640, Some(data.len() as u64))
        );
        assert_eq!(shown.sha256(), Some(Sha256::digest(data)));
        let null = fs::metadata("/dev/null").unwrap();
        let device = object(&whole, "device-mount");
        assert_eq!(
            (device.inode_type(), device.major(), device.minor()),
            (InodeType::CharDevice, Some(1), Some(3))
        );
        assert_eq!(mode(&whole, "device-mount"), null.mode() & 0o7777);
        assert_eq!((device.size(), device.sha256()), (None, None));
        // Crossing them, the walk goes into them. The same directory
        // mounted twice next to each other is no loop and is listed twice.
        let (whole, _, _) = walked(&a, features, crossing).unwrap();
        assert_eq!(
            names(&whole),
            [
                "bind",
                "bind/below",
                "bind/below/x",
                "bind/below/y",
                "bind2",
                "bind2/below",
                "bind2/below/x",
                "bind2/below/y",
                "device-mount",
                "file-mount",
                "plain",
                "tmpfs",
                "tmpfs/inside",
                "tmpfs/nested",
                "tmpfs/nested/deeper"
            ]
        );
        // A mount that shows a directory again inside itself is a loop where
        // the walk crosses mounts, and an empty directory where it does not.
        let b = dir.join("b");
        let (whole, _, _) = walked(&b, features, none).unwrap();
        assert_eq!(names(&whole), ["x", "x/file", "x/loop"]);
        let e = walked(&b, features, crossing).unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::Loop), Some("x/loop"))
        );
        // A walk that starts at a mount point walks what is mounted there,
        // with the attributes of the mounted root, and the mounts below it
        // are mount points.
        let (whole, _, _) = walked(&a.join("tmpfs"), features, none).unwrap();
        assert_eq!(names(&whole), ["inside", "nested"]);
        assert_eq!(whole.root.inode().mode().unwrap().bits(), 0o711);
        assert_eq!(mode(&whole, "nested"), 0o700);
        // The names of an inode reached through a bind mount are hard links
        // of each other, and not of the names reached through another
        // mount of the same directory.
        let (whole, _, _) = walked(&a, features, crossing).unwrap();
        let token = |name| object(&whole, name).inode_token().unwrap();
        assert_eq!(token("bind/below/x"), token("bind/below/y"));
        assert_ne!(token("bind/below/x"), token("bind2/below/x"));
    }
}
