// SPDX-License-Identifier: LGPL-2.1-or-later
//! The file objects of a manifest that is being built. They are added in
//! any order, and they are written in the order of the manifest.
//!
//! A [`Listing`] takes what is added: the root of a tree, the files of a
//! tree, and file objects a caller made. It sorts them by their names, in
//! memory while they fit and through a scratch file once they do not, see
//! the module sort, and notes the hard links among them, see the module
//! hardlink. Once nothing more is added it becomes a [`Writing`], which
//! puts the manifest together a part at a time: it merges what was sorted
//! and decides what the adds left open, since only now every object is next
//! to the others of its name and behind those of its directory.
//!
//! - A name that was added more than once is one file object. Directories
//!   merge, and the first one added says what the directory is like. Two
//!   files of a tree collapse if their file objects are equal, and are a
//!   file that changed if they are not: a walk comes to a name twice only
//!   where its directory changed while it was listed. Two file objects of
//!   a caller collapse if they are equal. Anything else is two different
//!   files for one name, an error.
//! - A directory that files were added below but that was not added itself
//!   is made up as a plain one, which says nothing but that it is a
//!   directory. Where the features of the manifest give a missing field a
//!   meaning, that would claim what nobody read, and is an error instead.
//! - The names of one inode get their `inodeToken`, a counter in the order
//!   of the manifest, as the specification asks. The file objects of a
//!   caller that share a token are numbered with them.
//!
//! Neither of the two does an unbounded amount of work at once: making
//! room for an add and writing the manifest both take a budget and say
//! whether they are done. What a step does is bounded, though not always
//! by its budget: the records the sort holds in memory, 32 MiB and at most
//! one record more, are sorted in one go before they are written as a run
//! and once nothing more is added, a merge of many runs reads what the
//! buffers of the runs need on top of its budget, see the module sort, and
//! a table of the hard links on disk that begins to double writes out the
//! pages memory holds of it first, see the module hardlink. And neither
//! writes anywhere: the manifest is appended to a string, through the
//! [`Encoder`], and whoever drives this sends it on. That is the shape of
//! the reader's [`Decoder`], which is fed and stepped by its caller.
//!
//! [`Decoder`]: crate::reader::Decoder

use std::cmp::Ordering;
use std::io;
use std::iter;
use std::ops::ControlFlow;

use crate::error::{Error, ErrorKind, Field, Problem, TreeProblem};
use crate::hardlink::{GroupKey, HardlinkTable, Likeness, Noted, Seen};
use crate::object::{FileObject, FileSystemIdentity, InodeAttributes, InodeType, RootObject, ValidityWindow};
use crate::record::{RecordReader, RecordWriter};
use crate::scratch::Scratch;
use crate::sort::{Merge, Sorter, MAX_BODY};
use crate::sys::OwnFiles;
use crate::tree::{Failure, Status, Subject};
use crate::writer::Encoder;
use crate::{Features, Name, NameBuf, Order, Sha256, MAX_CONTENTS};

/// What separates the components of a name.
const SEPARATOR: u8 = b'/';
/// What stands for the separator in the key a file object is sorted by, see
/// [`Order::sort_key`].
const KEY_SEPARATOR: u8 = 0;

/// The record is of a file of a tree that is not a directory.
const WALKED: u8 = 1 << 0;
/// The file has more names than one and gets an `inodeToken`: the key of
/// its inode is in front of its object.
const LINKED: u8 = 1 << 1;
/// The size statx() gave of the file is in front of its object, which has
/// none, as the manifest does not record sizes.
const SIZED: u8 = 1 << 2;
/// The record is of the root of a tree: its inode attributes and the
/// identity of its file system instead of an object.
const ROOT: u8 = 1 << 3;
/// Every mark a record can have.
const MARKS: u8 = WALKED | LINKED | SIZED | ROOT;

/// The features that give a field a directory does not have a meaning: it
/// is not read-only, it has no extended attributes, or a flag of it is
/// cleared. A directory that is made up cannot say that.
const SAID_BY_ABSENCE: Features = Features::READ_ONLY
    .union(Features::USER_XATTR)
    .union(Features::FLAG_HIDDEN)
    .union(Features::FLAG_SYSTEM)
    .union(Features::FLAG_ARCHIVE)
    .union(Features::FLAG_APPEND_ONLY)
    .union(Features::FLAG_IMMUTABLE)
    .union(Features::FLAG_NO_ATIME)
    .union(Features::FLAG_NO_COW)
    .union(Features::FLAG_NO_DUMP);
/// How many bytes are kept for the body of the next record once one was
/// put together. An object that needed more does not hold on to them.
const BODY_KEPT: usize = 64 * 1024;

/// An error for a record of the sort that is not what was written.
fn damaged() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a scratch file of the sort was changed")
}

impl Order {
    /// Writes the key a file object with the name `name` is sorted by into
    /// `key`: the keys are in the order of their bytes where the names are
    /// in this order.
    fn sort_key(self, name: &Name, key: &mut Vec<u8>) {
        key.clear();
        let name = name.as_str().bytes();
        match self {
            // The order of the names takes the end of a name before the
            // separator and the separator before any other byte. A name
            // has no NUL, so the keys have a NUL for the separator.
            Order::CodePoint => key.extend(name.map(|byte| if byte == SEPARATOR { KEY_SEPARATOR } else { byte })),
        }
    }

    /// The name the key `key` was made of.
    fn name_of(self, key: &[u8]) -> io::Result<NameBuf> {
        let name: Vec<u8> = match self {
            Order::CodePoint => key
                .iter()
                .map(|&byte| if byte == KEY_SEPARATOR { SEPARATOR } else { byte })
                .collect(),
        };
        let name = String::from_utf8(name).map_err(|_| damaged())?;
        if name.is_empty() {
            return Ok(NameBuf::default());
        }
        NameBuf::new(name).map_err(|_| damaged())
    }
}

/// What is kept of a file of a tree that is not a directory besides its
/// object.
#[derive(Debug)]
struct Walked {
    /// The key of its inode in the table of the hard links, where the file
    /// has more names than one and gets an `inodeToken`.
    key: Option<GroupKey>,
    /// The size statx() gave of a regular file whose object has none. What
    /// a manifest lists is counted also where it records no sizes.
    size: Option<u64>,
}

/// What was added under one name.
#[derive(Debug)]
enum Added {
    /// The root of a tree.
    Root(Box<(InodeAttributes, FileSystemIdentity)>),
    /// A file object: of a file of a tree that is not a directory, with
    /// what else is known of it, or of a directory of a tree or of a
    /// caller, without.
    File(Box<FileObject>, Option<Walked>),
}

impl Added {
    /// What the record with the key `key` and the body `body` is of, in a
    /// sort for the order `order`.
    fn decode(order: Order, key: &[u8], body: &[u8]) -> io::Result<Added> {
        let name = order.name_of(key)?;
        let mut record = RecordReader(body);
        let marks = record.u8()?;
        let has = |mark: u8| marks & mark != 0;
        // The marks of a file of a tree go together, and the root has
        // none of them. Only the root has the name of the root.
        let consistent = if has(ROOT) {
            marks == ROOT && name.is_root()
        } else {
            !name.is_root() && (has(WALKED) || !(has(LINKED) || has(SIZED)))
        };
        if marks & !MARKS != 0 || !consistent {
            return Err(damaged());
        }
        if has(ROOT) {
            let inode = InodeAttributes::from_record(&mut record)?;
            let file_system = FileSystemIdentity::from_record(&mut record)?;
            if !record.is_empty() {
                return Err(damaged());
            }
            return Ok(Added::Root(Box::new((inode, file_system))));
        }
        let walked = if has(WALKED) {
            let key = if has(LINKED) {
                Some(GroupKey::decode(&record.array()?)?)
            } else {
                None
            };
            let size = if has(SIZED) { Some(record.u64()?) } else { None };
            Some(Walked { key, size })
        } else {
            None
        };
        let object = FileObject::from_record(name, &mut record)?;
        Ok(Added::File(Box::new(object), walked))
    }

    /// The name this was added under.
    fn name(&self) -> &Name {
        match self {
            Added::Root(_) => Name::ROOT,
            Added::File(object, _) => &object.name,
        }
    }

    /// Whether this is a directory.
    fn is_directory(&self) -> bool {
        match self {
            Added::Root(_) => true,
            Added::File(object, _) => object.inode_type == InodeType::Directory,
        }
    }

    /// What it comes to that `later` was added under the name this was
    /// added under before. Two directories are one, as the first one says.
    /// Two files of a tree are one if their file objects are equal, and a
    /// file that changed if they are not: a walk comes to a name twice only
    /// where its directory changed while it was listed. Two file objects of
    /// a caller are one if they are equal. Everything else is two different
    /// files.
    fn or(self, later: Added) -> Result<Added, Error> {
        let duplicate = |name: &Name| {
            let message = format!("{}: was added twice, for two different files", Subject(name));
            Error::new(ErrorKind::Tree(TreeProblem::Duplicate), message).named(name.as_str())
        };
        if self.is_directory() && later.is_directory() {
            return Ok(self);
        }
        let same = match (&self, &later) {
            (Added::File(first, Some(one)), Added::File(second, Some(other))) => {
                if first != second {
                    return Err(Failure::Changed.into_error(&first.name));
                }
                // A file that got or lost a name between the two has the
                // key of its inode in one of them only. That one stays, so
                // that the file gets its token.
                if one.key.is_none() && other.key.is_some() {
                    return Ok(later);
                }
                true
            }
            (Added::File(first, None), Added::File(second, None)) => first == second,
            _ => false,
        };
        if same {
            Ok(self)
        } else {
            Err(duplicate(self.name()))
        }
    }
}

/// What a manifest lists, counted per file object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Totals {
    /// The regular files.
    pub(crate) files: u64,
    /// The directories, the root and those that were made up included.
    pub(crate) directories: u64,
    /// Everything else: symbolic links, FIFOs, device nodes and sockets.
    pub(crate) others: u64,
    /// The sizes of the regular files, added up. A file with several names
    /// counts once for each. A sum that is too large for the number is the
    /// largest number.
    pub(crate) bytes: u64,
}

/// Takes the file objects of a manifest in any order, see the
/// documentation of this module.
#[derive(Debug)]
pub(crate) struct Listing {
    features: Features,
    order: Order,
    scratch: Scratch,
    sorter: Sorter,
    links: HardlinkTable,
    /// The key and the body of a record while it is put together.
    key: Vec<u8>,
    body: Vec<u8>,
}

impl Listing {
    /// A listing for a manifest that records `features` and lists its file
    /// objects in `order`, with `scratch` for what does not fit into
    /// memory.
    pub(crate) fn new(features: Features, order: Order, scratch: Scratch) -> Listing {
        Listing::with_parts(features, order, scratch, Sorter::new(), HardlinkTable::new())
    }

    fn with_parts(features: Features, order: Order, scratch: Scratch, sorter: Sorter, links: HardlinkTable) -> Listing {
        Listing {
            features,
            order,
            scratch,
            sorter,
            links,
            key: Vec::new(),
            body: Vec::new(),
        }
    }

    /// The files the manifest made itself and has open, which its scratch
    /// files are among, for whoever walks a tree for the manifest and
    /// passes over them.
    pub(crate) fn own_files(&self) -> &OwnFiles {
        self.scratch.own_files()
    }

    /// Does a part of what is to do before the next add, and returns
    /// whether it is done: the table of the hard links doubles or moves to
    /// disk, and the sort writes a run. `budget` is about how many bytes are
    /// read and written for each of the two now: a step is bounded, but not
    /// held to its budget, see the documentation of this module.
    ///
    /// A caller that works in steps calls this until it returns true
    /// before it adds. An add does all that is left of it at once.
    pub(crate) fn make_room(&mut self, budget: u64) -> Result<bool, Error> {
        let room =
            self.links.make_room(&mut self.scratch, budget)? && self.sorter.make_room(&mut self.scratch, budget)?;
        Ok(room)
    }

    /// Refuses the file object `object` if it is one that no manifest
    /// holds whatever else it says, and that is not kept for that reason:
    /// an object without a name, which would be taken for the root, and
    /// one with more contents objects than there may be, each of which
    /// takes far more memory than bytes in a scratch file.
    ///
    /// A writer refuses both as well. It names the fault of an object that
    /// a reader finds first, which can be another one for an object with
    /// several.
    fn check(object: &FileObject) -> Result<(), Error> {
        let name = &object.name;
        if name.is_root() {
            let message = "a file object has no name".to_owned();
            return Err(Error::manifest(Problem::NoName, message).at(Field::Name));
        }
        if object.contents.len() > MAX_CONTENTS {
            return Err(Error::too_many_contents(Subject(name)).named(name.as_str()));
        }
        Ok(())
    }

    /// Puts the body of a record together: the marks `marks` and what
    /// `write` writes. The record is of the name `name`.
    ///
    /// A body that would be longer than the sort takes is not put
    /// together. It is of a file object whose record is larger than a
    /// record of a manifest may be, see [`MAX_BODY`], and is refused as
    /// that.
    fn fill(&mut self, name: &Name, marks: u8, write: impl FnOnce(&mut RecordWriter<'_>)) -> Result<(), Error> {
        self.body.clear();
        let mut record = RecordWriter::new(&mut self.body, MAX_BODY);
        record.u8(marks);
        write(&mut record);
        if record.is_cut() {
            self.body.clear();
            self.body.shrink_to(BODY_KEPT);
            let too_large = Error::record_too_large();
            return Err(if name.is_root() {
                too_large
            } else {
                too_large.named(name.as_str())
            });
        }
        Ok(())
    }

    /// Hands the record that was put together, which is of the name `name`,
    /// to the sort.
    fn push(&mut self, name: &Name) -> Result<(), Error> {
        self.order.sort_key(name, &mut self.key);
        let pushed = self.sorter.push(&mut self.scratch, &self.key, &self.body);
        self.body.clear();
        self.body.shrink_to(BODY_KEPT);
        Ok(pushed?)
    }

    /// Adds the root of a tree: `inode` are its inode attributes and
    /// `file_system` is the identity of its file system. Everything else a
    /// root file object says is what the listing was made with.
    pub(crate) fn add_root(&mut self, inode: &InodeAttributes, file_system: &FileSystemIdentity) -> Result<(), Error> {
        self.fill(Name::ROOT, ROOT, |record| {
            inode.to_record(record);
            file_system.to_record(record);
        })?;
        self.push(Name::ROOT)
    }

    /// Adds a file of a tree that is not its root: `object` is its file
    /// object, without an `inodeToken`, `status` what statx() said of it,
    /// and `data` the hash of its data, if it was hashed.
    ///
    /// A file with more names than one that is not a directory is a hard
    /// link, where the manifest records hard links. It is held against the
    /// first name of its inode, and fails if it does not show the same
    /// file.
    pub(crate) fn add_walked(
        &mut self,
        object: &FileObject,
        status: &Status,
        data: Option<Sha256>,
    ) -> Result<(), Error> {
        let name = &object.name;
        debug_assert!(object.inode_token.is_none(), "the listing hands out the tokens");
        Listing::check(object)?;
        if object.inode_type == InodeType::Directory {
            self.fill(name, 0, |record| object.to_record(record))?;
            return self.push(name);
        }
        let linked = status.nlink > 1 && self.features.contains(Features::HARDLINK);
        let key = linked.then_some(GroupKey::Walked(status.identity));
        // The sizes of the regular files are counted, and an object has
        // none where the manifest records no sizes.
        let sizeless = object.inode_type == InodeType::Regular && object.size.is_none();
        let size = sizeless.then_some(status.size);
        let marks = [(key.is_some(), LINKED), (size.is_some(), SIZED)];
        let marks = marks
            .into_iter()
            .filter(|(there, _)| *there)
            .fold(WALKED, |marks, (_, mark)| marks | mark);
        self.fill(name, marks, |record| {
            if let Some(key) = &key {
                record.raw(&key.encode());
            }
            if let Some(size) = size {
                record.u64(size);
            }
            object.to_record(record);
        })?;
        if let Some(key) = &key {
            // The hash is in the object where the manifest records it.
            let likeness = Likeness::walked(Seen::of(status), data.or(object.sha256), object);
            let noted = self.links.note(&mut self.scratch, key, name, &likeness)?;
            noted.check(name)?;
        }
        self.push(name)
    }

    /// Adds the file object `object` a caller made. One with an
    /// `inodeToken` is a hard link of the other file objects of that
    /// token. It is held against the first of them, and fails if it does
    /// not have the fields the specification wants them to share.
    ///
    /// The object is checked as a writer checks it, but for where it
    /// comes, see [`FileObject::check_alone`], and one that is refused is
    /// not added. Where it comes shows when the manifest is written, which
    /// checks every object as a writer does. The body of its record is put
    /// together first, which refuses an object that is far too large
    /// without writing its record out in full.
    pub(crate) fn add_given(&mut self, object: &FileObject) -> Result<(), Error> {
        let name = &object.name;
        Listing::check(object)?;
        self.fill(name, 0, |record| object.to_record(record))?;
        object.check_alone(self.features, self.order)?;
        if let Some(token) = object.inode_token.filter(|_| object.inode_type != InodeType::Directory) {
            let key = GroupKey::Given(token);
            match self
                .links
                .note(&mut self.scratch, &key, name, &Likeness::given(object))?
            {
                // The same name again with another object: what that
                // comes to shows when the two are next to each other.
                Noted::Differs(first) if first == *name => {}
                noted => noted.check(name)?,
            }
        }
        self.push(name)
    }

    /// Ends the listing: nothing more is added, and the manifest is
    /// written from what was. Nothing is done for that yet: the first step
    /// of the [`Writing`] sorts what the sort still has in memory, which
    /// is never more than it holds there. Nothing is closed either: the
    /// scratch space goes on to the [`Writing`], with the files of the
    /// manifest's own.
    pub(crate) fn finish(self) -> Writing {
        Writing {
            features: self.features,
            order: self.order,
            links: self.links,
            merge: self.sorter.finish(),
            scratch: self.scratch,
            encoder: None,
            held: None,
            next: None,
            last: NameBuf::default(),
            last_is_directory: true,
            totals: Totals::default(),
            over: false,
        }
    }
}

/// Writes the manifest of a [`Listing`], see the documentation of this
/// module.
#[derive(Debug)]
pub(crate) struct Writing {
    features: Features,
    order: Order,
    links: HardlinkTable,
    merge: Merge,
    /// The scratch space of the listing, which nothing is made in any
    /// more. It takes back the file the table of the hard links is done
    /// with, and keeps the files of the manifest's own open, also those the
    /// listing was done with, until the manifest is written or given up:
    /// they are closed with this, and none before.
    scratch: Scratch,
    /// What puts the records together, once the root file object went
    /// out.
    encoder: Option<Encoder>,
    /// What was added under the name the merge is at, as far as it came.
    held: Option<Added>,
    /// What was added under the name before that one, all of it. It goes
    /// out next, behind the directories it is in that were not added.
    next: Option<Added>,
    /// The name of the last file object that went out, and whether it is a
    /// directory. Every directory that name is in went out as one.
    last: NameBuf,
    last_is_directory: bool,
    totals: Totals,
    /// Whether the manifest ended or failed. Nothing more of it is written
    /// then.
    over: bool,
}

impl Writing {
    /// Appends the next part of the manifest to `text` and returns whether
    /// that was the end of it. Then it breaks with what the manifest lists.
    ///
    /// `budget` is about how many bytes it takes from the sort and appends
    /// before it returns. It does one thing at a time, takes a record from
    /// the sort or appends one, and goes on while there is budget left. So
    /// with any budget it gets further, and without one it does nothing. A
    /// hard link is appended with its token, and what the table of the hard
    /// links reads from its scratch file and writes to it for that token
    /// comes out of the budget as well, see [`HardlinkTable::token_cost`].
    /// What the sort has to do before it hands out its first record is
    /// done the same way, a part in each step and for the same budget: it
    /// writes a run it was still writing to its end, sorts what it has in
    /// memory, and merges its runs in passes where they are too many for
    /// one merge, see the module sort. A step is bounded, but not held to
    /// its budget: what is in memory is sorted in one go, what the table
    /// of the hard links has left to do, the passes and the records each
    /// take all of the budget, so the step in which one of them ends does
    /// more, and the passes read more than their budget besides, see
    /// [`Merge::prepare`].
    ///
    /// The errors of what was added come from here if they did not come
    /// from the add: a name that was added for two different files, a
    /// directory that was not added and cannot be made up, a file where a
    /// directory is needed, and everything a writer refuses in a file
    /// object. After an error and after the end every call fails.
    pub(crate) fn step(&mut self, budget: u64, text: &mut String) -> Result<ControlFlow<Totals>, Error> {
        if self.over {
            let over = io::Error::other("the manifest ended or failed, and nothing more of it is written");
            return Err(over.into());
        }
        let step = self.turns(budget, text);
        self.over = !matches!(step, Ok(ControlFlow::Continue(())));
        step
    }

    /// What [`Writing::step`] does.
    fn turns(&mut self, budget: u64, text: &mut String) -> Result<ControlFlow<Totals>, Error> {
        // What the table of the hard links was at when the last name
        // came is finished before it hands out a token.
        if !self.links.settle(&mut self.scratch, budget)? {
            return Ok(ControlFlow::Continue(()));
        }
        // The sort hands out its first record once its runs are few enough
        // for one merge.
        if !self.merge.prepare(budget)? {
            return Ok(ControlFlow::Continue(()));
        }
        let mut left = budget;
        while left > 0 {
            let (before, tokens) = (text.len(), self.links.token_cost());
            let ControlFlow::Continue(taken) = self.turn(text)? else {
                return Ok(ControlFlow::Break(self.totals));
            };
            // Every turn counts, also one that only found the end of the
            // sort.
            let cost = (taken + (text.len() - before)).max(1) as u64;
            let tokens = self.links.token_cost() - tokens;
            left = left.saturating_sub(cost.saturating_add(tokens));
        }
        Ok(ControlFlow::Continue(()))
    }

    /// Does one thing: takes a record from the sort, appends a file object
    /// to `text`, or ends the manifest. Returns how many bytes it took from
    /// the sort, and breaks at the end of the manifest.
    fn turn(&mut self, text: &mut String) -> Result<ControlFlow<(), usize>, Error> {
        if let Some(next) = self.next.take() {
            self.write(next, text)?;
            return Ok(ControlFlow::Continue(0));
        }
        let Some((key, body)) = self.merge.next()? else {
            // What the last name was added as, and then the end.
            if self.held.is_some() {
                self.next = self.held.take();
                return Ok(ControlFlow::Continue(0));
            }
            self.encoder(text)?.finish(text)?;
            return Ok(ControlFlow::Break(()));
        };
        let taken = key.len() + body.len();
        let added = Added::decode(self.order, key, body)?;
        self.held = match self.held.take() {
            None => Some(added),
            Some(first) => match first.name().cmp(added.name()) {
                Ordering::Less => {
                    self.next = Some(first);
                    Some(added)
                }
                Ordering::Equal => Some(first.or(added)?),
                // The sort hands the names out in their order.
                Ordering::Greater => return Err(damaged().into()),
            },
        };
        Ok(ControlFlow::Continue(taken))
    }

    /// What puts the records together. Before the first record this starts
    /// the manifest with a plain root file object, as no root was added.
    fn encoder(&mut self, text: &mut String) -> Result<&mut Encoder, Error> {
        match self.encoder {
            Some(ref mut encoder) => Ok(encoder),
            None => {
                // A root that is made up says that it has no label, and
                // whatever a directory that is made up says. It has no
                // UUID and no volume serial number, which a root need not
                // have.
                self.make_up(Name::ROOT, SAID_BY_ABSENCE.union(Features::FS_LABEL))?;
                self.start(InodeAttributes::default(), FileSystemIdentity::default(), text)
            }
        }
    }

    /// Starts the manifest: appends the root file object, for a root with
    /// the inode attributes `inode` in the file system `file_system`.
    fn start(
        &mut self,
        inode: InodeAttributes,
        file_system: FileSystemIdentity,
        text: &mut String,
    ) -> Result<&mut Encoder, Error> {
        let root = RootObject {
            inode,
            file_system,
            gpt_disk_uuid: None,
            order: Some(self.order),
            features: Some(self.features),
            validity: ValidityWindow::default(),
        };
        let encoder = Encoder::begin(&root, text)?;
        self.totals.directories += 1;
        Ok(self.encoder.insert(encoder))
    }

    /// Checks that the directory `name`, which was not added, can be made
    /// up as one that says nothing: the manifest records none of
    /// `features`, which give what a directory does not say a meaning.
    fn make_up(&self, name: &Name, features: Features) -> Result<(), Error> {
        let Some(feature) = (self.features & features).names().next() else {
            return Ok(());
        };
        let message = format!(
            "{}: the directory was not added, and one that is made up for it cannot say what '{}' records",
            Subject(name),
            feature
        );
        Err(Error::new(ErrorKind::Tree(TreeProblem::MissingParent), message).named(name.as_str()))
    }

    /// The first of the directories `name` is in that did not go out, if
    /// there is one. The last file object went out with every directory it
    /// is in, and `name` comes behind it in the order of the manifest. So
    /// the directories of `name` that went out are those the two names
    /// share, and the last file object itself if `name` is in it. It has
    /// to be a directory then.
    fn missing_parent(&self, name: &Name) -> Result<Option<NameBuf>, Error> {
        let (bytes, last) = (name.as_str().as_bytes(), self.last.as_str().as_bytes());
        let common = iter::zip(bytes, last).take_while(|(one, other)| one == other).count();
        let in_last = common == last.len() && bytes.get(common) == Some(&SEPARATOR);
        if in_last && !self.last_is_directory {
            let message = format!(
                "{}: is not a directory, and files were added below it",
                Subject(&self.last)
            );
            return Err(Error::new(ErrorKind::Tree(TreeProblem::NotDirectory), message).named(self.last.as_str()));
        }
        // Where the name goes on behind what went out, and where the next
        // directory it is in ends from there.
        let from = if in_last { common + 1 } else { common };
        let Some(end) = bytes[from..].iter().position(|&byte| byte == SEPARATOR) else {
            return Ok(None);
        };
        // What a name starts with up to a separator is a name.
        let parent = NameBuf::new(&name.as_str()[..from + end]).map_err(|_| damaged())?;
        Ok(Some(parent))
    }

    /// Appends the record of `object`, whose directory went out.
    fn put(&mut self, object: FileObject, text: &mut String) -> Result<(), Error> {
        self.encoder(text)?.file(&object, text)?;
        match object.inode_type {
            InodeType::Regular => self.totals.files += 1,
            InodeType::Directory => self.totals.directories += 1,
            _ => self.totals.others += 1,
        }
        self.last_is_directory = object.inode_type == InodeType::Directory;
        self.last = object.name;
        Ok(())
    }

    /// Appends what was added under one name, with its `inodeToken` if it
    /// is a hard link. If a directory it is in was not added, the first
    /// such directory is appended instead, as a plain one, and the turn of
    /// what was added comes again.
    fn write(&mut self, added: Added, text: &mut String) -> Result<(), Error> {
        let (mut object, walked) = match added {
            Added::Root(root) => {
                // The root comes before every other name, once.
                if self.encoder.is_some() {
                    return Err(damaged().into());
                }
                let (inode, file_system) = *root;
                return self.start(inode, file_system, text).map(drop);
            }
            Added::File(object, walked) => (object, walked),
        };
        self.encoder(text)?;
        if let Some(parent) = self.missing_parent(&object.name)? {
            self.next = Some(Added::File(object, walked));
            self.make_up(&parent, SAID_BY_ABSENCE)?;
            let mut directory = FileObject::new(parent);
            directory.inode_type = InodeType::Directory;
            return self.put(directory, text);
        }
        let key = match &walked {
            Some(walked) => walked.key,
            None if object.inode_type == InodeType::Directory => None,
            None => object.inode_token.map(GroupKey::Given),
        };
        if let Some(key) = key {
            object.inode_token = Some(self.links.token(&mut self.scratch, &key)?);
        }
        if object.inode_type == InodeType::Regular {
            // What its object says, or else what statx() said of a file
            // of a tree.
            let size = object.size.or(walked.and_then(|walked| walked.size));
            self.totals.bytes = self.totals.bytes.saturating_add(size.unwrap_or_default());
        }
        self.put(*object, text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hardlink::Limits as TableLimits;
    use crate::object::{ContentsObject, ContentsSource, Mode};
    use crate::sort::Limits as SortLimits;
    use crate::sys::ScratchFile;
    use crate::testing::{name, read_whole, write_whole, OpenFile, TempDir, Whole};
    use crate::tree::{DeviceNumber, Identity, MountId, Timestamp};
    use crate::{MAX_RECORD_SIZE, RECORD_SEPARATOR};
    use rustix::fs::FileType;
    use std::env;
    use std::fs;
    use std::num::NonZeroU64;
    use std::process::Command;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    use std::time::Instant;

    /// What a test adds to a listing.
    #[derive(Clone, Debug)]
    enum Add {
        Root(Box<RootObject>),
        Walked(Box<FileObject>, Status, Option<Sha256>),
        Given(Box<FileObject>),
    }

    /// How a test has a listing keep what it is given: all of it in
    /// memory, or as little as there can be. With little, every record is
    /// a run of its own and a merge takes two runs, so that the sort merges
    /// in as many passes as there can be.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum Memory {
        All,
        Little,
    }

    /// A listing for `features` that keeps what it is given as `memory`
    /// says, with its scratch files in `tmp`.
    fn listing(features: Features, memory: Memory, tmp: &TempDir) -> Listing {
        let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let (sorter, links) = match memory {
            Memory::All => (Sorter::new(), HardlinkTable::new()),
            Memory::Little => (
                Sorter::with_limits(SortLimits {
                    memory: 1,
                    run_buffer: 1,
                    write_buffer: 1,
                    runs: 2,
                    hole: 1,
                }),
                HardlinkTable::with_limits(TableLimits {
                    memory: 1,
                    first_pages: 1,
                    cached_pages: 1,
                }),
            ),
        };
        Listing::with_parts(features, Order::CodePoint, scratch, sorter, links)
    }

    /// Adds `add` to `listing`.
    fn add(listing: &mut Listing, add: &Add) -> Result<(), Error> {
        match add {
            Add::Root(root) => listing.add_root(&root.inode, &root.file_system),
            Add::Walked(object, status, data) => listing.add_walked(object, status, *data),
            Add::Given(object) => listing.add_given(object),
        }
    }

    /// Writes all of the manifest of `listing`, with the budget `budget`
    /// for a step, and returns it with what it lists, with how many steps
    /// it took and with how many records the step appended that appended
    /// the most.
    fn write(listing: Listing, budget: u64) -> Result<(String, Totals, u64, usize), Error> {
        let mut writing = listing.finish();
        let (mut text, mut steps, mut most) = (String::new(), 0, 0);
        loop {
            steps += 1;
            let before = text.len();
            let step = writing.step(budget, &mut text)?;
            most = most.max(text[before..].matches(char::from(RECORD_SEPARATOR)).count());
            if let ControlFlow::Break(totals) = step {
                return Ok((text, totals, steps, most));
            }
        }
    }

    /// The manifest of `adds` for `features`, and what it lists.
    fn manifest(features: Features, adds: &[Add], memory: Memory) -> Result<(String, Totals), Error> {
        // The tests run next to each other, each with directories of its
        // own.
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let tmp = TempDir::new(&format!("listing-{}", NEXT.fetch_add(1, Relaxed)));
        let mut listing = listing(features, memory, &tmp);
        for one in adds {
            add(&mut listing, one)?;
        }
        write(listing, u64::MAX).map(|(text, totals, _, _)| (text, totals))
    }

    /// What statx() says of the inode `inode` of a file system a test
    /// makes up, a file of the type `file_type` with `nlink` names.
    fn status(file_type: FileType, inode: u64, nlink: u32) -> Status {
        let time = Timestamp {
            seconds: 1_700_000_000,
            nanoseconds: 0,
        };
        Status {
            identity: Identity {
                mount: MountId::Unique(1),
                device: DeviceNumber { major: 8, minor: 1 },
                inode,
                subvolume: None,
            },
            file_type,
            mode: Mode::from_st_mode(0o644),
            nlink,
            uid: 0,
            gid: 0,
            size: 0,
            mtime: time,
            ctime: time,
            btime: Some(time),
            rdev: DeviceNumber { major: 0, minor: 0 },
        }
    }

    /// The regular file `file_name` of a tree with the data `data`, which
    /// is the inode `inode` and has `nlink` names.
    fn file(file_name: &str, data: &[u8], inode: u64, nlink: u32) -> Add {
        let mut status = status(FileType::RegularFile, inode, nlink);
        status.size = data.len() as u64;
        let mut object = FileObject::new(name(file_name));
        object.size = Some(status.size);
        object.sha256 = Some(Sha256::digest(data));
        object.inode.mode = Some(status.mode);
        Add::Walked(Box::new(object), status, object_hash(data))
    }

    /// The hash of the data `data`, as an add gets it.
    fn object_hash(data: &[u8]) -> Option<Sha256> {
        Some(Sha256::digest(data))
    }

    /// The directory `directory_name` of a tree with the mode `mode`,
    /// which is the inode `inode`.
    fn directory(directory_name: &str, mode: u32, inode: u64) -> Add {
        let mut status = status(FileType::Directory, inode, 2);
        status.mode = Mode::from_st_mode(mode);
        let mut object = FileObject::new(name(directory_name));
        object.inode_type = InodeType::Directory;
        object.inode.mode = Some(status.mode);
        Add::Walked(Box::new(object), status, None)
    }

    /// The symbolic link `link_name` of a tree to `target`.
    fn symlink(link_name: &str, target: &str, inode: u64) -> Add {
        let mut status = status(FileType::Symlink, inode, 1);
        status.size = target.len() as u64;
        let mut object = FileObject::new(name(link_name));
        object.inode_type = InodeType::Symlink;
        object.size = Some(status.size);
        object.contents = vec![ContentsObject::new(ContentsSource::Literal(target.into()))];
        Add::Walked(Box::new(object), status, None)
    }

    /// A file object a caller made for `given_name`, with the token
    /// `token` if it has one.
    fn given(given_name: &str, token: u64) -> Add {
        let mut object = FileObject::new(name(given_name));
        object.size = Some(3);
        object.inode_token = NonZeroU64::new(token);
        Add::Given(Box::new(object))
    }

    /// The root of a tree with the mode `mode`.
    fn root(mode: u32) -> Add {
        let mut root = RootObject::default();
        root.inode.mode = Some(Mode::from_st_mode(mode));
        Add::Root(Box::new(root))
    }

    /// The file object of `add`, which is not the root, as the manifest
    /// has it, with the token `token` if it has one.
    fn listed(add: &Add, token: u64) -> FileObject {
        let (Add::Walked(object, _, _) | Add::Given(object)) = add else {
            panic!("{:?}", add);
        };
        let mut object = (**object).clone();
        object.inode_token = NonZeroU64::new(token);
        object
    }

    /// A plain directory, as the manifest has one that was made up.
    fn plain(directory_name: &str) -> FileObject {
        let mut object = FileObject::new(name(directory_name));
        object.inode_type = InodeType::Directory;
        object
    }

    /// The manifest a writer writes for `root` and `objects`, in the code
    /// point order.
    fn expected(root: &Add, objects: Vec<FileObject>) -> String {
        let Add::Root(root) = root else {
            panic!("{:?}", root);
        };
        let mut root = (**root).clone();
        root.order = Some(Order::CodePoint);
        root.features = Some(Features::DEFAULT);
        let whole = Whole {
            root,
            objects,
            signatures: Vec::new(),
        };
        String::from_utf8(write_whole(&whole).unwrap()).unwrap()
    }

    /// The numbers from 0 up to `count` in an order that the number
    /// `seed` picks.
    fn shuffled(count: usize, seed: u64) -> Vec<usize> {
        let mut order: Vec<usize> = (0..count).collect();
        let mut state = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        for at in (1..count).rev() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            order.swap(at, (state % (at as u64 + 1)) as usize);
        }
        order
    }

    /// Every order of the numbers from 0 up to `count`.
    fn permutations(count: usize) -> Vec<Vec<usize>> {
        let mut all = vec![Vec::new()];
        for number in 0..count {
            all = all
                .iter()
                .flat_map(|order: &Vec<usize>| {
                    (0..=order.len()).map(move |at| {
                        let mut order = order.clone();
                        order.insert(at, number);
                        order
                    })
                })
                .collect();
        }
        all
    }

    /// A tree with everything a listing decides: a root, directories that
    /// were added and directories that were not, hard links of files of
    /// the tree and of file objects of a caller, an inode with one of its
    /// names in the tree, and a symbolic link. Returns what is added for
    /// it and the manifest that comes of it.
    fn tree() -> (Vec<Add>, String) {
        let adds = vec![
            root(0o755),
            directory("a", 0o750, 10),
            file("a/x", b"hello", 11, 1),
            symlink("a/l", "x", 12),
            file("b/deep/file", b"", 13, 1),
            file("h1", b"linked", 14, 2),
            file("a/h2", b"linked", 14, 2),
            file("z", b"alone", 15, 3),
            given("g1", 7),
            given("a/g2", 7),
            given("c", 0),
        ];
        let objects = vec![
            listed(&adds[1], 0),
            listed(&adds[9], 1),
            listed(&adds[6], 2),
            listed(&adds[3], 0),
            listed(&adds[2], 0),
            plain("b"),
            plain("b/deep"),
            listed(&adds[4], 0),
            listed(&adds[10], 0),
            listed(&adds[8], 1),
            listed(&adds[5], 2),
            listed(&adds[7], 3),
        ];
        let expected = expected(&adds[0], objects);
        (adds, expected)
    }

    /// Whatever order the files of a tree are added in, the manifest is
    /// the same, byte for byte, with all of them in memory and with every
    /// one of them in a run of its own. It is the manifest a writer writes
    /// for the file objects in the order of their names, with the
    /// directories that were not added made up and the tokens counted in
    /// that order, and a reader takes it as one in the code point order.
    #[test]
    fn every_order_gives_the_same_manifest() {
        let (adds, expected) = tree();
        let features = Features::DEFAULT;
        let (text, totals) = manifest(features, &adds, Memory::All).unwrap();
        assert_eq!(text, expected);
        assert_eq!(
            totals,
            Totals {
                files: 8,
                directories: 4,
                others: 1,
                bytes: 5 + 6 + 6 + 5 + 3 + 3 + 3
            }
        );
        let whole = read_whole(text.as_bytes()).unwrap();
        whole.root.require_order(Order::CodePoint).unwrap();
        assert_eq!(whole.objects.len(), 12);
        for seed in 0..300 {
            let order = shuffled(adds.len(), seed);
            let shuffled: Vec<Add> = order.iter().map(|&index| adds[index].clone()).collect();
            let memory = if seed % 3 == 0 { Memory::Little } else { Memory::All };
            let (text, shuffled_totals) = manifest(features, &shuffled, memory).unwrap();
            assert!(text == expected, "{:?}", order);
            assert_eq!(shuffled_totals, totals, "{:?}", order);
        }
        // Every order there is of the files that decide the most: the
        // names of the two inodes with tokens and what is below the
        // directories that are made up.
        let few = [4, 5, 6, 8, 9, 3, 1];
        for order in permutations(few.len()) {
            let mut permuted: Vec<Add> = order.iter().map(|&index| adds[few[index]].clone()).collect();
            permuted.extend([0, 2, 7, 10].map(|index| adds[index].clone()));
            let (text, _) = manifest(features, &permuted, Memory::All).unwrap();
            assert!(text == expected, "{:?}", order);
        }
    }

    /// The same for a tree of thousands of files that are added in an
    /// order of no use, with hard links in every directory.
    #[test]
    fn a_large_tree_in_any_order() {
        let mut adds = vec![root(0o755)];
        let mut inode = 100;
        for directory_index in 0..40 {
            let directory_name = format!("d{:02}", directory_index);
            adds.push(directory(&directory_name, 0o755, inode));
            for file_index in 0..50u64 {
                inode += 1;
                let file_name = format!("{}/sub{}/f{:02}", directory_name, file_index % 3, file_index);
                let data = inode.to_le_bytes();
                // Every fifth file has a second name in the next
                // directory.
                if file_index % 5 == 0 {
                    adds.push(file(&file_name, &data, inode, 2));
                    let other = format!("d{:02}/link{:02}", (directory_index + 1) % 40, file_index);
                    adds.push(file(&other, &data, inode, 2));
                } else {
                    adds.push(file(&file_name, &data, inode, 1));
                }
            }
            inode += 1;
        }
        let features = Features::DEFAULT;
        let (sorted, totals) = manifest(features, &adds, Memory::All).unwrap();
        assert_eq!((totals.files, totals.directories), (40 * 60, 1 + 40 + 40 * 3));
        for (seed, memory) in [(1, Memory::All), (2, Memory::Little), (3, Memory::Little)] {
            let order = shuffled(adds.len(), seed);
            let shuffled: Vec<Add> = order.iter().map(|&index| adds[index].clone()).collect();
            let (text, shuffled_totals) = manifest(features, &shuffled, memory).unwrap();
            assert!(text == sorted, "{}", seed);
            assert_eq!(shuffled_totals, totals);
        }
        // A reader takes it, and the tokens count up in its order: 1 to
        // 400, each on two names.
        let whole = read_whole(sorted.as_bytes()).unwrap();
        whole.root.require_order(Order::CodePoint).unwrap();
        let tokens: Vec<u64> = whole
            .objects
            .iter()
            .filter_map(|object| object.inode_token().map(NonZeroU64::get))
            .collect();
        assert_eq!(tokens.len(), 800);
        let mut highest = 0;
        for token in &tokens {
            assert!(*token <= highest + 1, "{} after {}", token, highest);
            highest = highest.max(*token);
        }
        assert_eq!(highest, 400);
        assert!((1..=400).all(|token| tokens.iter().filter(|&&other| other == token).count() == 2));
    }

    /// A manifest is written a part at a time, and the parts are the
    /// manifest. A step does one thing at a time while it has budget left:
    /// it takes a record from the sort or appends one to the manifest. So
    /// the smallest budget does one thing in a step, and without a budget
    /// a step does nothing. The steps before those are the sort's: it
    /// merges its runs in passes, a part in each step, and nothing of the
    /// manifest is written until it is done.
    #[test]
    fn writes_in_steps() {
        let (adds, expected) = tree();
        let tmp = TempDir::new("listing-steps");
        // Eleven records to take and thirteen to append, two of them for
        // directories that are made up, and the two turns that find the
        // end of the sort.
        let turns = 11 + 13 + 2;
        let added = || {
            let mut listing = listing(Features::DEFAULT, Memory::Little, &tmp);
            for one in &adds {
                while !listing.make_room(64).unwrap() {
                    assert!(!listing.make_room(0).unwrap());
                }
                add(&mut listing, one).unwrap();
            }
            listing
        };
        for (budget, fewest, most) in [(1, turns, turns), (100, 6, turns - 1), (u64::MAX, 1, 1)] {
            // How many steps the sort takes before its first record: ten
            // runs, two of which it merges at a time, are three passes.
            // The smallest budget moves one record in a step, and each of
            // the last two passes moves all that are in a run.
            let mut writing = added().finish();
            let mut before = 0u64;
            while !writing.merge.prepare(budget).unwrap() {
                before += 1;
            }
            assert_eq!(before > 0, budget < u64::MAX, "{}", before);
            assert!(budget > 1 || before > 2 * (adds.len() as u64 - 1), "{}", before);
            let (text, _, steps, records) = write(added(), budget).unwrap();
            assert_eq!(text, expected);
            assert!(
                (before + fewest..=before + most).contains(&steps),
                "{} {}",
                budget,
                steps
            );
            assert!(budget > 1 || records == 1, "{}", records);
        }
        // A name as deep as a name goes takes a step for each directory
        // that is made up for it. The root is made up with the first.
        let deepest = "d/".repeat(2047) + "f";
        let mut deep = listing(Features::DEFAULT, Memory::All, &tmp);
        add(&mut deep, &file(&deepest, b"", 54, 1)).unwrap();
        let (text, totals, steps, records) = write(deep, 1).unwrap();
        assert_eq!((totals.directories, totals.files), (2048, 1));
        assert_eq!((steps, records), (1 + 2048 + 2, 2));
        assert_eq!(read_whole(text.as_bytes()).unwrap().objects.len(), 2048);
        // Without a budget nothing happens, and after the end nothing can.
        let mut listing = listing(Features::DEFAULT, Memory::All, &tmp);
        add(&mut listing, &adds[0]).unwrap();
        let mut writing = listing.finish();
        let mut text = String::new();
        assert_eq!(writing.step(0, &mut text).unwrap(), ControlFlow::Continue(()));
        assert!(text.is_empty());
        assert!(matches!(
            writing.step(u64::MAX, &mut text).unwrap(),
            ControlFlow::Break(_)
        ));
        let written = text.clone();
        for budget in [0, 1, u64::MAX] {
            let after = writing.step(budget, &mut text).unwrap_err();
            assert_eq!(after.kind(), ErrorKind::Io);
            assert_eq!(text, written);
        }
    }

    /// What the table of the hard links was at when the last name came is
    /// finished a part at a time as well, before the first record goes
    /// out.
    #[test]
    fn settles_the_table_in_steps() {
        let tmp = TempDir::new("listing-settles");
        let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let table = HardlinkTable::with_limits(TableLimits {
            memory: 1,
            first_pages: 1,
            cached_pages: 1,
        });
        let features = Features::DEFAULT;
        let mut listing = Listing::with_parts(features, Order::CodePoint, scratch, Sorter::new(), table);
        // Hard links are added until the table begins to double, which it
        // does a page at a time with this budget. The sort has room.
        let mut adds = Vec::new();
        while adds.len() < 500 || listing.make_room(1).unwrap() {
            let inode = adds.len() as u64;
            adds.push(file(&format!("f{:05}", inode), b"x", 5000 + inode, 2));
            add(&mut listing, &adds[adds.len() - 1]).unwrap();
        }
        let mut writing = listing.finish();
        let (mut text, mut steps) = (String::new(), 0);
        while text.is_empty() {
            assert_eq!(writing.step(1, &mut text).unwrap(), ControlFlow::Continue(()));
            steps += 1;
        }
        // Two records are taken before the first one goes out, and the
        // table has dozens of pages.
        assert!(steps > 3 + 16, "{}", steps);
        while writing.step(u64::MAX, &mut text).unwrap().is_continue() {}
        let (expected, _) = manifest(features, &adds, Memory::All).unwrap();
        assert!(text == expected);
    }

    /// A step pays for the pages the table of the hard links reads from its
    /// scratch file and writes to it for the tokens it hands out. So a step
    /// over a table on disk that holds one page in memory reads and writes
    /// about its budget for them, and appends few hard links. The tokens of
    /// a table in memory cost nothing, and a step over one appends what its
    /// budget says.
    #[test]
    fn steps_pay_for_the_pages_of_the_hard_links() {
        /// How many hard links the manifest lists.
        const LINKS: u64 = 2_000;
        /// The budget of a step, which a manifest of that many takes many
        /// of.
        const BUDGET: u64 = 64 * 1024;
        /// How much more than its budget a step pays for tokens at most:
        /// its last turn begins with budget left and pays for all the pages
        /// its token takes, more than two where pages overflowed.
        const OVER: u64 = BUDGET;
        /// What a page of the table costs: as many bytes as it has.
        const PAGE: u64 = 4096;
        let adds: Vec<Add> = (0..LINKS)
            .map(|inode| file(&format!("f{:05}", inode), b"x", 5000 + inode, 2))
            .collect();
        let features = Features::DEFAULT;
        let (expected, _) = manifest(features, &adds, Memory::All).unwrap();
        for on_disk in [false, true] {
            let tmp = TempDir::new(&format!("listing-token-cost-{}", on_disk));
            let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
            let table = if on_disk {
                HardlinkTable::with_limits(TableLimits {
                    memory: 1,
                    first_pages: 1,
                    cached_pages: 1,
                })
            } else {
                HardlinkTable::new()
            };
            let mut listing = Listing::with_parts(features, Order::CodePoint, scratch, Sorter::new(), table);
            for one in &adds {
                add(&mut listing, one).unwrap();
            }
            // What the table has left to do is none of this.
            while !listing.make_room(u64::MAX).unwrap() {}
            let mut writing = listing.finish();
            let mut text = String::new();
            let (mut steps, mut paid) = (0, 0);
            loop {
                let (before, tokens) = (text.len(), writing.links.token_cost());
                let step = writing.step(BUDGET, &mut text).unwrap();
                let (appended, tokens) = ((text.len() - before) as u64, writing.links.token_cost() - tokens);
                steps += 1;
                paid += tokens;
                assert!(tokens <= BUDGET + OVER, "{} at step {}", tokens, steps);
                if step.is_break() {
                    break;
                }
                // The first step sorts, and appends nothing yet.
                if !on_disk && steps > 1 {
                    assert!(
                        tokens == 0 && appended >= BUDGET / 4,
                        "{} {} at step {}",
                        tokens,
                        appended,
                        steps
                    );
                }
            }
            assert!(text == expected);
            if on_disk {
                // A page read for nearly every token, and one written.
                assert!(paid >= LINKS * PAGE, "{}", paid);
                assert!(steps >= paid / (BUDGET + OVER), "{} {}", steps, paid);
            }
        }
    }

    /// A manifest that failed fails from there on: no later step goes on
    /// with what is left and ends a manifest that lacks what failed.
    #[test]
    fn nothing_follows_an_error() {
        let tmp = TempDir::new("listing-errors");
        let mut listing = listing(Features::DEFAULT, Memory::All, &tmp);
        for one in [
            file("a", b"", 80, 1),
            file("b", b"", 81, 1),
            given("b", 0),
            file("c", b"", 83, 1),
        ] {
            add(&mut listing, &one).unwrap();
        }
        let mut writing = listing.finish();
        let mut text = String::new();
        let first = loop {
            match writing.step(1, &mut text) {
                Ok(step) => assert_eq!(step, ControlFlow::Continue(())),
                Err(e) => break e,
            }
        };
        assert_eq!(first.kind(), ErrorKind::Tree(TreeProblem::Duplicate));
        assert_eq!(first.name(), Some("b"));
        let written = text.clone();
        for _ in 0..3 {
            assert_eq!(writing.step(u64::MAX, &mut text).unwrap_err().kind(), ErrorKind::Io);
            assert_eq!(text, written);
        }
        // What was written before is no manifest: it has no trailer.
        assert!(read_whole(text.as_bytes()).is_err());
    }

    /// The order of the manifest is that of the names and not that of
    /// their bytes: a directory comes right before what is below it, also
    /// where other names have a byte that is smaller than the separator.
    #[test]
    fn the_order_of_the_names() {
        let names = [
            "a",
            "a/b",
            "a/b/c",
            "a/b c",
            "a/b-c",
            "a/b.c",
            "a/b0",
            "a b",
            "a-b",
            "a.b",
            "a0",
            "a\u{1F600}",
        ];
        let adds: Vec<Add> = (0u64..)
            .zip(names)
            .map(|(inode, name)| match name {
                "a" | "a/b" => directory(name, 0o755, 90 + inode),
                _ => file(name, b"", 90 + inode, 1),
            })
            .collect();
        for seed in 0..20 {
            let order = shuffled(adds.len(), seed);
            let shuffled: Vec<Add> = order.iter().map(|&index| adds[index].clone()).collect();
            let memory = if seed % 2 == 0 { Memory::Little } else { Memory::All };
            let (text, _) = manifest(Features::DEFAULT, &shuffled, memory).unwrap();
            let whole = read_whole(text.as_bytes()).unwrap();
            whole.root.require_order(Order::CodePoint).unwrap();
            let listed: Vec<&str> = whole.objects.iter().map(|object| object.name().as_str()).collect();
            assert_eq!(listed, names);
        }
    }

    /// A manifest nothing was added to is that of an empty tree, with a
    /// plain root.
    #[test]
    fn nothing_added() {
        let (text, totals) = manifest(Features::DEFAULT, &[], Memory::All).unwrap();
        assert_eq!(
            text,
            concat!(
                "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
                "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
            )
        );
        assert_eq!(
            totals,
            Totals {
                directories: 1,
                ..Totals::default()
            }
        );
        // The features the listing was made for are those of the manifest.
        let tmp = TempDir::new("listing-options");
        let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let features = Features::DEFAULT | Features::MTIME;
        let listing = Listing::new(features, Order::CodePoint, scratch);
        let (text, _, _, _) = write(listing, u64::MAX).unwrap();
        let whole = read_whole(text.as_bytes()).unwrap();
        assert_eq!(whole.root.features(), Some(features));
    }

    /// The `inodeToken`s count up in the order of the manifest, over the
    /// inodes of a tree and the tokens of a caller alike, whatever the
    /// tokens of the caller were. A file with other names outside the tree
    /// has a token of its own. Without the feature nothing has a token.
    #[test]
    fn tokens_in_the_order_of_the_manifest() {
        let adds = [
            file("c", b"A", 20, 2),
            file("a", b"A", 20, 2),
            file("b", b"B", 21, 5),
            given("d", 900),
            given("aa", 900),
            given("e", 3),
            file("f", b"F", 22, 1),
        ];
        let tokens = |features, adds: &[Add]| {
            let (text, _) = manifest(features, adds, Memory::All).unwrap();
            let whole = read_whole(text.as_bytes()).unwrap();
            let tokens = whole.objects.iter().map(|object| {
                let token = object.inode_token().map_or(0, NonZeroU64::get);
                (object.name().as_str().to_owned(), token)
            });
            tokens.collect::<Vec<_>>()
        };
        let named = |pairs: &[(&str, u64)]| -> Vec<(String, u64)> {
            pairs.iter().map(|(name, token)| (name.to_string(), *token)).collect()
        };
        assert_eq!(
            tokens(Features::DEFAULT, &adds),
            named(&[("a", 1), ("aa", 2), ("b", 3), ("c", 1), ("d", 2), ("e", 4), ("f", 0)])
        );
        // Without hard links recorded, the files of a tree have no token,
        // and a file object with one is refused when it is added.
        let without = Features::DEFAULT.without(Features::HARDLINK);
        assert_eq!(tokens(without, &adds[..3]), named(&[("a", 0), ("b", 0), ("c", 0)]));
        let refused = manifest(without, &adds, Memory::All).unwrap_err();
        assert_eq!(refused.kind(), ErrorKind::Manifest(Problem::UnlistedFeature));
        assert_eq!(refused.name(), Some("d"));
    }

    /// A name of an inode that does not show the file its first name
    /// showed fails when it is added, and names both. So does a file
    /// object that does not agree with the first one of its token.
    #[test]
    fn hard_links_that_differ() {
        let tmp = TempDir::new("listing-links");
        for memory in [Memory::All, Memory::Little] {
            let mut listing = listing(Features::DEFAULT, memory, &tmp);
            add(&mut listing, &file("first", b"data", 30, 2)).unwrap();
            add(&mut listing, &file("second", b"data", 30, 2)).unwrap();
            let e = add(&mut listing, &file("third", b"other", 30, 2)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::HardlinkMismatch));
            assert_eq!((e.name(), e.hardlink_name()), (Some("third"), Some("first")));
            // The first name again, as another file.
            let e = add(&mut listing, &file("first", b"other", 30, 2)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::Changed));
            // Another inode is another file.
            add(&mut listing, &file("fourth", b"other", 31, 2)).unwrap();
            add(&mut listing, &given("g1", 5)).unwrap();
            let Add::Given(mut other) = given("g2", 5) else {
                unreachable!()
            };
            other.size = Some(4);
            let e = listing.add_given(&other).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::HardlinkMismatch));
            assert_eq!((e.name(), e.hardlink_name()), (Some("g2"), Some("g1")));
            // The token of a caller and the inode of a tree are apart.
            add(&mut listing, &given("g3", 30)).unwrap();
        }
        // What is not a hard link is not held against anything: a
        // directory, a file with one name, and any file where the
        // manifest records no hard links.
        let mut listing = listing(Features::DEFAULT.without(Features::HARDLINK), Memory::All, &tmp);
        add(&mut listing, &file("first", b"data", 30, 2)).unwrap();
        add(&mut listing, &file("second", b"other", 30, 2)).unwrap();
    }

    /// The same name added twice is one file object if it is one file:
    /// two directories, two files of a tree whose file objects are equal,
    /// or two equal file objects of a caller. Two files of a tree that are
    /// not equal are a file that changed, since a walk comes to a name
    /// twice only where its directory changed while it was listed, and
    /// anything else is two files with one name.
    #[test]
    fn the_same_name_twice() {
        let features = Features::DEFAULT;
        let first = |adds: &[Add]| manifest(features, adds, Memory::All).map(|(text, _)| text);
        let kind = |adds: &[Add]| {
            let e = first(adds).unwrap_err();
            assert_eq!(e.name(), Some("n"), "{}", e);
            e.kind()
        };
        let once = first(&[file("n", b"data", 40, 1)]).unwrap();
        // Two files of a tree with equal file objects are one file,
        // whichever inodes they are, also with more names than one.
        assert_eq!(
            first(&[file("n", b"data", 40, 1), file("n", b"data", 40, 1)]).unwrap(),
            once
        );
        assert_eq!(first(&vec![file("n", b"data", 40, 1); 5]).unwrap(), once);
        assert_eq!(
            first(&[file("n", b"data", 40, 1), file("n", b"data", 41, 1)]).unwrap(),
            once
        );
        let linked = first(&[file("n", b"data", 40, 2)]).unwrap();
        assert_eq!(
            first(&[file("n", b"data", 40, 2), file("n", b"data", 40, 2)]).unwrap(),
            linked
        );
        // A file that got or lost a name between the two has more names
        // than one in one of them only. That one stays, whichever came
        // first, so the file has its token.
        for nlinks in [[1, 2], [2, 1]] {
            let twice = nlinks.map(|nlink| file("n", b"data", 40, nlink));
            assert_eq!(first(&twice).unwrap(), linked, "{:?}", nlinks);
        }
        // With file objects that are not equal they are a file that
        // changed: other data, another mode, another type.
        let changed = ErrorKind::Tree(TreeProblem::Changed);
        assert_eq!(kind(&[file("n", b"data", 40, 1), file("n", b"DATA", 40, 1)]), changed);
        assert_eq!(kind(&[file("n", b"data", 40, 1), file("n", b"DATA", 41, 1)]), changed);
        // Also where only one of the two has more names than one.
        assert_eq!(kind(&[file("n", b"data", 40, 1), file("n", b"DATA", 40, 2)]), changed);
        assert_eq!(kind(&[file("n", b"data", 40, 2), file("n", b"DATA", 40, 1)]), changed);
        let Add::Walked(mut object, status, data) = file("n", b"data", 40, 1) else {
            unreachable!()
        };
        object.inode.mode = Some(Mode::from_st_mode(0o600));
        assert_eq!(
            kind(&[file("n", b"data", 40, 1), Add::Walked(object, status, data)]),
            changed
        );
        assert_eq!(kind(&[file("n", b"data", 40, 1), symlink("n", "data", 40)]), changed);
        // Directories are one, as the first one that was added says.
        let merged = first(&[directory("n", 0o700, 42), directory("n", 0o755, 43)]).unwrap();
        assert_eq!(merged, first(&[directory("n", 0o700, 42)]).unwrap());
        assert_ne!(
            merged,
            first(&[directory("n", 0o755, 43), directory("n", 0o700, 42)]).unwrap()
        );
        let Add::Given(mut made) = given("n", 0) else {
            unreachable!()
        };
        made.inode_type = InodeType::Directory;
        made.size = None;
        assert_eq!(
            first(&[directory("n", 0o700, 42), Add::Given(made.clone())]).unwrap(),
            merged
        );
        // A directory and a file, and a file of a tree and a file object
        // of a caller.
        let duplicate = ErrorKind::Tree(TreeProblem::Duplicate);
        assert_eq!(kind(&[directory("n", 0o700, 42), file("n", b"data", 40, 1)]), duplicate);
        assert_eq!(kind(&[file("n", b"data", 40, 1), Add::Given(made)]), duplicate);
        assert_eq!(kind(&[file("n", b"data", 40, 1), given("n", 0)]), duplicate);
        // File objects of a caller are one if they are equal.
        let made = first(&[given("n", 0)]).unwrap();
        assert_eq!(first(&[given("n", 0), given("n", 0)]).unwrap(), made);
        let Add::Given(mut other) = given("n", 0) else {
            unreachable!()
        };
        other.inode.uid = Some(1);
        assert_eq!(kind(&[given("n", 0), Add::Given(other)]), duplicate);
        assert_eq!(kind(&[given("n", 5), given("n", 6)]), duplicate);
        // With a token they are held against each other when they are
        // added, and what that leaves open shows when they are written.
        let tokened = first(&[given("n", 5)]).unwrap();
        assert_eq!(first(&[given("n", 5), given("n", 5)]).unwrap(), tokened);
        let Add::Given(mut other) = given("n", 5) else {
            unreachable!()
        };
        other.size = Some(4);
        assert_eq!(kind(&[given("n", 5), Add::Given(other)]), duplicate);
    }

    /// The record of a file of a tree that is not a directory is its file
    /// object behind a mark. The key of its inode is in between where the
    /// file has more names than one and the manifest records hard links,
    /// and its size where it is a regular file whose object has none.
    /// Nothing else that statx() says of it is kept. A directory of a tree
    /// and a file object of a caller are their file objects alone.
    #[test]
    fn records_of_the_files_of_a_tree() {
        let tmp = TempDir::new("listing-records");
        let record = |features: Features, add: &Add| {
            let mut listing = listing(features, Memory::All, &tmp);
            self::add(&mut listing, add).unwrap();
            let mut writing = listing.finish();
            while !writing.merge.prepare(u64::MAX).unwrap() {}
            let (_, body) = writing.merge.next().unwrap().unwrap();
            body.to_vec()
        };
        let bytes = |object: &FileObject| {
            let mut bytes = Vec::new();
            object.to_record(&mut RecordWriter::new(&mut bytes, MAX_BODY));
            bytes
        };
        let features = Features::DEFAULT;
        let Add::Walked(object, status, data) = file("n", b"data", 40, 2) else {
            unreachable!()
        };
        let mut unsized_object = object.clone();
        unsized_object.size = None;
        let once = Status { nlink: 1, ..status };
        let key = GroupKey::Walked(status.identity).encode();
        let size = status.size.to_le_bytes();
        let unlinked = features.without(Features::HARDLINK);
        let cases: [(Features, &FileObject, Status, Vec<&[u8]>); 5] = [
            (features, &object, once, vec![&[WALKED]]),
            (features, &object, status, vec![&[WALKED | LINKED], &key]),
            (unlinked, &object, status, vec![&[WALKED]]),
            (features, &unsized_object, once, vec![&[WALKED | SIZED], &size]),
            (
                features,
                &unsized_object,
                status,
                vec![&[WALKED | LINKED | SIZED], &key, &size],
            ),
        ];
        for (features, object, status, front) in cases {
            let add = Add::Walked(Box::new(object.clone()), status, data);
            assert_eq!(record(features, &add), [front.concat(), bytes(object)].concat());
        }
        // A symbolic link whose object has no size keeps none either.
        let Add::Walked(mut link, link_status, _) = symlink("l", "target", 41) else {
            unreachable!()
        };
        link.size = None;
        let add = Add::Walked(link.clone(), link_status, None);
        assert_eq!(record(features, &add), [vec![WALKED], bytes(&link)].concat());
        for add in [directory("d", 0o755, 42), given("g", 0), given("h", 7)] {
            let (Add::Walked(object, ..) | Add::Given(object)) = &add else {
                unreachable!()
            };
            assert_eq!(record(features, &add), [vec![0], bytes(object)].concat());
        }
    }

    /// A file object of a caller is checked when it is added, as a writer
    /// checks it but for where it comes, and one that a writer refuses is
    /// not added: one for each fault a writer finds, those of its contents
    /// objects in the field they are in, and a second directory object for
    /// a name, which the first one would otherwise hide. What the listing
    /// writes after that is what it writes without them.
    #[test]
    fn file_objects_of_a_caller_that_are_refused() {
        type Give = fn(&mut FileObject);
        let cases: [(Give, Problem); 9] = [
            (
                |o| o.contents = vec![ContentsObject::new(ContentsSource::Literal(vec![0; MAX_RECORD_SIZE]))],
                Problem::RecordTooLarge,
            ),
            (|o| o.inode.user_name = Some("u\u{fdd0}".into()), Problem::InvalidString),
            (
                |o| {
                    o.contents = vec![ContentsObject {
                        http_headers: vec![("A".into(), "b".into()), ("A".into(), "c".into())],
                        ..ContentsObject::new(ContentsSource::Url("https://example.com/x".into()))
                    }];
                },
                Problem::DuplicateKey,
            ),
            (
                |o| {
                    o.contents = vec![ContentsObject {
                        http_headers: vec![("A".into(), "b".into())],
                        ..ContentsObject::new(ContentsSource::File(name("a")))
                    }];
                },
                Problem::InvalidContents,
            ),
            (|o| o.inode.uid = Some(65535), Problem::FieldOutOfRange),
            (|o| o.inode_type = InodeType::Fifo, Problem::FieldNotPermitted),
            (
                |o| (o.inode.mode, o.inode.read_only) = (Some(Mode::from_st_mode(0o644)), Some(true)),
                Problem::Contradiction,
            ),
            (|o| o.inode.read_only = Some(false), Problem::UnlistedFeature),
            (
                |o| (o.inode_type, o.size) = (InodeType::Symlink, None),
                Problem::NoTarget,
            ),
        ];
        let features = Features::DEFAULT | Features::MODE;
        let kept = [root(0o755), directory("n", 0o700, 42), given("x", 0)];
        let (expected, _) = manifest(features, &kept, Memory::All).unwrap();
        let tmp = TempDir::new("listing-refused");
        let mut listing = listing(features, Memory::All, &tmp);
        for one in &kept {
            add(&mut listing, one).unwrap();
        }
        for (give, problem) in cases {
            let Add::Given(mut object) = given("refused", 0) else {
                unreachable!()
            };
            give(&mut object);
            let e = listing.add_given(&object).unwrap_err();
            assert_eq!(
                (e.kind(), e.name()),
                (ErrorKind::Manifest(problem), Some("refused")),
                "{}",
                e
            );
            assert_eq!(e.record_number(), None, "{}", e);
        }
        // A literal that is not the data its hash is of, and a contents
        // object that refers to the root.
        let contents: [(Give, Problem, Field); 2] = [
            (
                |o| {
                    o.contents = vec![ContentsObject {
                        original_sha256: Some(Sha256::digest(b"abc")),
                        ..ContentsObject::new(ContentsSource::Literal(b"xyz".to_vec()))
                    }];
                },
                Problem::Contradiction,
                Field::Literal,
            ),
            (
                |o| o.contents = vec![ContentsObject::new(ContentsSource::File(NameBuf::default()))],
                Problem::InvalidContents,
                Field::File,
            ),
        ];
        for (give, problem, field) in contents {
            let Add::Given(mut object) = given("refused", 0) else {
                unreachable!()
            };
            give(&mut object);
            let e = listing.add_given(&object).unwrap_err();
            assert_eq!(
                (e.kind(), e.field(), e.name()),
                (ErrorKind::Manifest(problem), Some(field), Some("refused")),
                "{}",
                e
            );
        }
        // A second directory object of a caller for a name, with an ID the
        // specification does not permit.
        let Add::Given(mut second) = given("n", 0) else {
            unreachable!()
        };
        (second.inode_type, second.size, second.inode.uid) = (InodeType::Directory, None, Some(65535));
        let e = listing.add_given(&second).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::FieldOutOfRange), "{}", e);
        assert!(e.to_string().starts_with("file object (n): "), "{}", e);
        let (text, _, _, _) = write(listing, u64::MAX).unwrap();
        assert_eq!(text, expected);
    }

    /// A directory that files were added below and that was not added is
    /// made up, however deep, unless the manifest records a feature that
    /// gives what a plain directory does not say a meaning. The root is
    /// made up the same way. It cannot say that its file system has no
    /// label then, and it has no UUID and no volume serial number, which a
    /// root need not have.
    #[test]
    fn directories_that_were_not_added() {
        let deep = [
            file("a/b/c/d", b"", 50, 1),
            file("a/b/e", b"", 51, 1),
            file("a/f/g", b"", 52, 1),
        ];
        let (text, totals) = manifest(Features::DEFAULT, &deep, Memory::All).unwrap();
        let whole = read_whole(text.as_bytes()).unwrap();
        let names: Vec<&str> = whole.objects.iter().map(|object| object.name().as_str()).collect();
        assert_eq!(names, ["a", "a/b", "a/b/c", "a/b/c/d", "a/b/e", "a/f", "a/f/g"]);
        assert_eq!(whole.objects[1], plain("a/b"));
        assert_eq!(whole.root, {
            let mut root = RootObject::default();
            root.set_order(Some(Order::CodePoint));
            root
        });
        assert_eq!((totals.files, totals.directories), (3, 5));
        // A directory that was added is not made up, wherever it comes.
        let mut with = deep.to_vec();
        with.push(directory("a/b", 0o700, 53));
        let (text, _) = manifest(Features::DEFAULT, &with, Memory::All).unwrap();
        let whole = read_whole(text.as_bytes()).unwrap();
        assert_eq!(whole.objects[1].inode().mode(), Some(Mode::from_st_mode(0o700)));
        let said_by_absence = [
            Features::READ_ONLY,
            Features::USER_XATTR,
            Features::FLAG_HIDDEN,
            Features::FLAG_SYSTEM,
            Features::FLAG_ARCHIVE,
            Features::FLAG_APPEND_ONLY,
            Features::FLAG_IMMUTABLE,
            Features::FLAG_NO_ATIME,
            Features::FLAG_NO_COW,
            Features::FLAG_NO_DUMP,
        ];
        for feature in said_by_absence {
            let features = Features::DEFAULT | feature;
            // The root comes first, and then the first directory.
            let e = manifest(features, &deep, Memory::All).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::MissingParent), "{:?}", feature);
            assert_eq!(e.name(), Some(""));
            let mut rooted = deep.to_vec();
            rooted.push(root(0o755));
            let e = manifest(features, &rooted, Memory::All).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::MissingParent), "{:?}", feature);
            assert_eq!(e.name(), Some("a"));
            rooted.extend([directory("a", 0o755, 55), directory("a/b", 0o755, 56)]);
            let e = manifest(features, &rooted, Memory::All).unwrap_err();
            assert_eq!(e.name(), Some("a/b/c"), "{:?}", feature);
            rooted.extend([directory("a/b/c", 0o755, 57), directory("a/f", 0o755, 58)]);
            manifest(features, &rooted, Memory::All).unwrap();
        }
        // A root that is made up says that its file system has no label.
        // Other directories have none.
        let labelled = Features::DEFAULT | Features::FS_LABEL;
        let e = manifest(labelled, &deep, Memory::All).unwrap_err();
        assert_eq!(
            (e.kind(), e.name()),
            (ErrorKind::Tree(TreeProblem::MissingParent), Some(""))
        );
        let mut rooted = deep.to_vec();
        rooted.push(root(0o755));
        manifest(labelled, &rooted, Memory::All).unwrap();
        // A root need not have the UUID or the volume serial number of its
        // file system where the manifest records them: one that is made up
        // has neither, and one that was added without them is taken.
        for feature in [Features::FS_UUID, Features::FAT_SERIAL] {
            let features = Features::DEFAULT | feature;
            for adds in [&deep[..], &[], &rooted[..]] {
                let (text, _) = manifest(features, adds, Memory::All).unwrap();
                let root = read_whole(text.as_bytes()).unwrap().root;
                assert_eq!(
                    (root.features(), root.file_system()),
                    (Some(features), &FileSystemIdentity::default())
                );
            }
        }
    }

    /// A file that is not a directory cannot have files below it,
    /// whether it is a file of a tree or a file object of a caller.
    #[test]
    fn files_below_a_file() {
        for below in ["a/b", "a/b/c/d"] {
            for parent in [file("a", b"", 60, 1), symlink("a", "elsewhere", 61), given("a", 0)] {
                let adds = [file(below, b"", 62, 1), parent, file("a-sibling", b"", 63, 1)];
                let e = manifest(Features::DEFAULT, &adds, Memory::All).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::NotDirectory), "{}", below);
                assert_eq!(e.name(), Some("a"));
            }
        }
        // A directory of the same name next to it is another matter.
        let adds = [
            file("a/b", b"", 62, 1),
            file("a.txt", b"", 60, 1),
            file("a0", b"", 64, 1),
        ];
        manifest(Features::DEFAULT, &adds, Memory::All).unwrap();
    }

    /// What a writer refuses in a file object of a caller is refused when
    /// the manifest is written, with the name of the object. An object
    /// without a name is refused when it is added.
    #[test]
    fn file_objects_a_writer_refuses() {
        let Add::Given(mut dated) = given("dated", 0) else {
            unreachable!()
        };
        dated.inode.mtime_nsec = Some(1);
        let e = manifest(Features::DEFAULT, &[Add::Given(dated.clone())], Memory::All).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::UnlistedFeature));
        assert_eq!(e.name(), Some("dated"));
        manifest(Features::DEFAULT | Features::MTIME, &[Add::Given(dated)], Memory::All).unwrap();
        // An object without a name is not the root. It is refused when it
        // is added, whatever it is, and leaves the root alone that was
        // added.
        let tmp = TempDir::new("listing-nameless");
        let mut listing = listing(Features::DEFAULT | Features::READ_ONLY, Memory::All, &tmp);
        add(&mut listing, &root(0o755)).unwrap();
        let mut nameless = FileObject::new(NameBuf::default());
        for inode_type in [InodeType::Regular, InodeType::Directory] {
            nameless.inode_type = inode_type;
            for token in [0, 5] {
                nameless.inode_token = NonZeroU64::new(token);
                let e = listing.add_given(&nameless).unwrap_err();
                assert_eq!(e.kind(), ErrorKind::Manifest(Problem::NoName), "{:?}", inode_type);
                assert_eq!((e.name(), e.field()), (None, Some(Field::Name)));
            }
        }
        let (text, totals, _, _) = write(listing, u64::MAX).unwrap();
        let whole = read_whole(text.as_bytes()).unwrap();
        assert_eq!(whole.root.inode().mode(), Some(Mode::from_st_mode(0o755)));
        assert_eq!((whole.objects.len(), totals.directories), (0, 1));
    }

    /// A file object whose record is as large as a record of a manifest
    /// may be is taken, and one that is larger is refused: when it is
    /// written, or already when it is added if it is larger than anything
    /// a writer takes, for what a writer refuses it for.
    #[test]
    fn large_file_objects() {
        let literal = |size: usize| {
            let Add::Given(mut large) = given("large", 0) else {
                unreachable!()
            };
            large.size = Some(size as u64);
            large.contents = vec![ContentsObject::new(ContentsSource::Literal(vec![b'a'; size]))];
            Add::Given(large)
        };
        // Three bytes of a literal are four in a record, and the size of a
        // large one has seven digits where that of three bytes has one.
        let (small, _) = manifest(Features::DEFAULT, &[literal(3)], Memory::All).unwrap();
        let record = small.split_inclusive(char::from(crate::RECORD_END)).nth(1).unwrap();
        let fits = (MAX_RECORD_SIZE - (record.len() - 4 + 6)) / 4 * 3;
        for memory in [Memory::All, Memory::Little] {
            let (text, _) = manifest(Features::DEFAULT, &[literal(fits), file("z", b"", 72, 1)], memory).unwrap();
            let largest = text.split_inclusive(char::from(crate::RECORD_END)).nth(1).unwrap();
            assert!(MAX_RECORD_SIZE - largest.len() < 4, "{}", largest.len());
            let whole = read_whole(text.as_bytes()).unwrap();
            let read = &whole.objects[0];
            assert_eq!(
                (read.name().as_str(), read.size(), read.contents.len()),
                ("large", Some(fits as u64), 1)
            );
            assert!(read.contents[0].source == ContentsSource::Literal(vec![b'a'; fits]));
            // The next larger one is refused when it is added.
            let tmp = TempDir::new("listing-large");
            let mut listing = listing(Features::DEFAULT, memory, &tmp);
            let e = add(&mut listing, &literal(fits + 3)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::RecordTooLarge));
            assert_eq!(e.name(), Some("large"));
        }
        // What is larger than the sort takes is refused when it is added,
        // and so is an object with more contents objects than a manifest
        // may have, however small. Neither takes memory beyond that.
        let tmp = TempDir::new("listing-largest");
        let mut listing = listing(Features::DEFAULT, Memory::All, &tmp);
        for size in [MAX_BODY, 3 * MAX_BODY] {
            let e = add(&mut listing, &literal(size)).unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Manifest(Problem::RecordTooLarge));
            assert_eq!(e.name(), Some("large"));
            assert!(listing.body.capacity() <= BODY_KEPT, "{}", listing.body.capacity());
        }
        let Add::Given(mut many) = given("many", 0) else {
            unreachable!()
        };
        many.contents = vec![ContentsObject::default(); MAX_CONTENTS + 1];
        let e = listing.add_given(&many).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Manifest(Problem::InvalidContents));
        assert_eq!((e.name(), e.field()), (Some("many"), Some(Field::Contents)));
        // An object that is taken gives back what it needed, too.
        add(&mut listing, &literal(fits)).unwrap();
        assert!(listing.body.capacity() <= BODY_KEPT, "{}", listing.body.capacity());
        // None of those that were refused left anything behind.
        let (text, totals, _, _) = write(listing, u64::MAX).unwrap();
        assert_eq!(read_whole(text.as_bytes()).unwrap().objects.len(), 1);
        assert_eq!(totals.files, 1);
    }

    /// What a manifest lists is counted for each file object, and the
    /// sizes of the regular files are added up as far as a number goes.
    #[test]
    fn totals() {
        let sized = |name: &str, size: u64, inode: u64| {
            let Add::Walked(mut object, mut status, data) = file(name, b"", inode, 1) else {
                unreachable!()
            };
            (object.size, status.size) = (Some(size), size);
            // No test has that much data to hash.
            object.sha256 = Some(Sha256::digest(name.as_bytes()));
            let data = data.and(object.sha256);
            Add::Walked(object, status, data)
        };
        let adds = [
            sized("a", 5, 100),
            sized("d/b", 7, 101),
            symlink("l", "a", 102),
            given("g", 0),
            directory("e", 0o755, 103),
        ];
        let (_, totals) = manifest(Features::DEFAULT, &adds, Memory::All).unwrap();
        assert_eq!(
            totals,
            Totals {
                files: 3,
                directories: 3,
                others: 1,
                bytes: 5 + 7 + 3
            }
        );
        // Three files as large as a file gets.
        let largest = i64::MAX as u64;
        let adds = [
            sized("a", largest, 100),
            sized("b", largest, 101),
            sized("c", largest, 102),
        ];
        let (_, totals) = manifest(Features::DEFAULT, &adds[..2], Memory::All).unwrap();
        assert_eq!(totals.bytes, 2 * largest);
        let (_, totals) = manifest(Features::DEFAULT, &adds, Memory::All).unwrap();
        assert_eq!((totals.files, totals.bytes), (3, u64::MAX));
    }

    /// The root of a tree that was added is the root of the manifest, with
    /// its inode attributes and the identity of its file system. Added
    /// again it is one root, as the first one says.
    #[test]
    fn roots() {
        let features = Features::DEFAULT | Features::FS_LABEL | Features::FS_UUID | Features::MTIME;
        let mut first = RootObject::default();
        first.inode.mode = Some(Mode::from_st_mode(0o700));
        first.inode.mtime_nsec = Some(7);
        first.file_system.label = Some("ESP".into());
        first.file_system.uuid = Some(crate::Uuid::new([9; 16]));
        let adds = [Add::Root(Box::new(first.clone())), root(0o755), file("f", b"", 70, 1)];
        let (text, totals) = manifest(features, &adds, Memory::Little).unwrap();
        let whole = read_whole(text.as_bytes()).unwrap();
        first.order = Some(Order::CodePoint);
        first.features = Some(features);
        assert_eq!(whole.root, first);
        assert_eq!((totals.directories, totals.files), (1, 1));
    }

    /// The variable that tells the test binary, run again by [`measured`],
    /// how many files to list.
    const FILES: &str = "UAPI16_TEST_LISTING_FILES";
    /// What the line starts with that says what was measured, which the
    /// harness does not say of a test of this module.
    const MEASURED: &str = "listed:";
    /// How many files a directory of the tree that is measured has.
    const FILES_IN_DIRECTORY: u64 = 20;

    /// The resident memory of this process that is its own, in bytes, which
    /// the kernel reports in kilobytes: RssAnon, without the pages of the
    /// files it has mapped. Those of the test binary come and go with the
    /// file system it is on, and are none of the listing's. A kernel before
    /// Linux 4.5 does not tell the two apart, and all that is resident is
    /// taken there.
    fn resident() -> u64 {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
        let line = field("RssAnon:").or_else(|| field("VmRSS:")).unwrap();
        let kilobytes: u64 = line.trim().trim_end_matches("kB").trim().parse().unwrap();
        kilobytes * 1024
    }

    /// Lists a tree of `count` regular files, twenty to a directory and
    /// every fourth of them a hard link, which are added in an order that
    /// is as good as random, and writes its manifest. Checks that the
    /// manifest lists the tree and that the memory of the process stays
    /// within what the sort and the table of the hard links take.
    fn list_files(count: u64) {
        // A number that count has no factor in common with, so that the
        // multiples of it go through all the files.
        const STRIDE: u64 = 1_000_003;
        assert!(count % FILES_IN_DIRECTORY == 0 && count % STRIDE != 0);
        let tmp = TempDir::new("listing-measure");
        let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let before = resident();
        let mut listing = Listing::new(Features::DEFAULT, Order::CodePoint, scratch);
        let started = Instant::now();
        let hash = Sha256::digest(b"data");
        let mut most = 0;
        for index in 0..count {
            let number = index * STRIDE % count;
            let name = format!("usr/share/p{:06}/f{:08}", number / FILES_IN_DIRECTORY, number);
            // The files 8n and 8n + 1 are the two names of one inode.
            let (inode, nlink) = match number % 8 {
                0 => (number, 2),
                1 => (number - 1, 2),
                _ => (number, 1),
            };
            let mut status = status(FileType::RegularFile, inode, nlink);
            status.size = 4;
            let mut object = FileObject::new(NameBuf::new(name).unwrap());
            object.size = Some(status.size);
            object.sha256 = Some(hash);
            object.inode.mode = Some(status.mode);
            listing.add_walked(&object, &status, Some(hash)).unwrap();
            if index % 4096 == 0 {
                most = most.max(resident());
            }
        }
        let directories = count / FILES_IN_DIRECTORY;
        for number in (0..directories).rev() {
            let Add::Walked(object, status, _) = directory(&format!("usr/share/p{:06}", number), 0o755, count + number)
            else {
                unreachable!()
            };
            listing.add_walked(&object, &status, None).unwrap();
        }
        let added = started.elapsed();
        let mut writing = listing.finish();
        // A megabyte of the manifest at a time, which goes nowhere.
        let (mut text, mut size, mut records) = (String::new(), 0, 0u64);
        let totals = loop {
            text.clear();
            let step = writing.step(1024 * 1024, &mut text).unwrap();
            size += text.len();
            records += text.matches(char::from(RECORD_SEPARATOR)).count() as u64;
            most = most.max(resident());
            if let ControlFlow::Break(totals) = step {
                break totals;
            }
        };
        // The root, "usr" and "usr/share" are made up, and a trailer ends
        // the manifest.
        assert_eq!(records, count + directories + 4);
        assert_eq!(
            totals,
            Totals {
                files: count,
                directories: directories + 3,
                others: 0,
                bytes: count * 4
            }
        );
        println!(
            "{} {} files, {} of them hard links, in {} directories, {:.2} s to add them and {:.2} s to write {} MiB, \
             resident {} KiB before and {} KiB at most",
            MEASURED,
            count,
            count / 4,
            directories,
            added.as_secs_f64(),
            (started.elapsed() - added).as_secs_f64(),
            size >> 20,
            before / 1024,
            most / 1024,
        );
        // The records of the sort and the table of the hard links in
        // memory, a buffer for each run, the part of the manifest that is
        // written, and room for what an allocator keeps around.
        const ALLOWED: u64 = 72 * 1024 * 1024;
        assert!(most <= before + ALLOWED, "{} -> {}", before, most);
    }

    /// Runs the test binary again to list `count` files in a process that
    /// does nothing else, so that its memory is that of the listing.
    fn measured(count: u64) {
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "listing::tests::memory_is_bounded", "--nocapture"])
            .env(FILES, count.to_string())
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}\n{}",
            said,
            String::from_utf8_lossy(&output.stderr)
        );
        // The harness can have its own words in front on the same line.
        if let Some(measured) = said.lines().find_map(|line| line.find(MEASURED).map(|at| &line[at..])) {
            println!("{}", measured);
        }
    }

    /// The memory of a listing is that of its sort and of its table of
    /// hard links, however many files it lists.
    #[test]
    fn memory_is_bounded() {
        match env::var(FILES) {
            Ok(count) => list_files(count.parse().unwrap()),
            Err(_) => measured(20_000),
        }
    }

    /// The same for a million files.
    #[test]
    #[ignore = "lists a million files"]
    fn memory_is_bounded_for_a_million_files() {
        measured(1_000_000);
    }

    /// The same for ten million files, with scratch files of gigabytes.
    #[test]
    #[ignore = "lists ten million files"]
    fn memory_is_bounded_for_ten_million_files() {
        measured(10_000_000);
    }

    /// The listing hands on the files of the manifest's own that its
    /// scratch space makes its files for, and none of its own: a scratch
    /// file of that scratch space is one of them, and one of another
    /// scratch space is not.
    #[test]
    fn own_files() {
        let tmp = TempDir::new("listing-own");
        let scratch_in = || Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let (mut scratch, mut other) = (scratch_in(), scratch_in());
        let _file = scratch.file().unwrap();
        let made = OpenFile::made_in(&tmp.0);
        assert_eq!(made.len(), 1);
        let _other_file = other.file().unwrap();
        let both = OpenFile::made_in(&tmp.0);
        let others: Vec<_> = both.iter().filter(|file| file.inode != made[0].inode).collect();
        assert_eq!(others.len(), 1);
        let listing = Listing::new(Features::DEFAULT, Order::CodePoint, scratch);
        let own = listing.own_files();
        assert!(own.contains(&made[0].status).unwrap() && !own.contains(&others[0].status).unwrap());
        assert!(other.own_files().contains(&others[0].status).unwrap());
    }

    /// Ending a listing closes nothing. What writes its manifest keeps the
    /// scratch space, and the files of the manifest's own stay open with
    /// it, also one that was dropped before, until it is dropped itself.
    #[test]
    fn the_writing_keeps_the_own_files_open() {
        let tmp = TempDir::new("listing-kept");
        let mut scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        drop(scratch.file().unwrap());
        let listing = Listing::new(Features::DEFAULT, Order::CodePoint, scratch);
        let open = OpenFile::made_in(&tmp.0);
        assert_eq!(open.len(), 1);
        let writing = listing.finish();
        let kept = OpenFile::made_in(&tmp.0);
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].inode, open[0].inode);
        drop(writing);
        assert!(OpenFile::made_in(&tmp.0).is_empty());
    }

    /// A listing and what writes its manifest can go to another thread.
    #[test]
    fn send() {
        fn send<T: Send>() {}
        send::<Listing>();
        send::<Writing>();
        send::<Totals>();
    }

    /// The variable that tells the test binary, run again by
    /// [`adds_that_fail_for_the_table`], to do the checks.
    const FAILING_WRITES: &str = "UAPI16_TEST_LISTING_FAILING_WRITES";

    /// How far into a file this process may write at most, as prlimit(1)
    /// prints the hard limit of RLIMIT_FSIZE, if it can be asked.
    fn hard_write_limit() -> Option<String> {
        let pid = std::process::id().to_string();
        let output = Command::new("prlimit")
            .args(["--pid", &pid, "--fsize", "--noheadings", "--raw", "--output", "HARD"])
            .output()
            .ok()?;
        let limit = String::from_utf8_lossy(&output.stdout).trim().to_string();
        (output.status.success() && !limit.is_empty()).then_some(limit)
    }

    /// Sets how far into a file this process may write, with prlimit(1):
    /// with "0" every write to a file fails with EFBIG, where SIGXFSZ is
    /// ignored, and with the hard limit none does that did not before.
    /// Returns whether it is set.
    fn write_limit(soft: &str) -> bool {
        Command::new("prlimit")
            .args(["--pid", &std::process::id().to_string(), &format!("--fsize={}:", soft)])
            .status()
            .is_ok_and(|status| status.success())
    }

    /// An add of a file object of a caller that fails for the scratch files
    /// of the table of the hard links adds nothing and leaves the listing
    /// as it was: the adds go on, and the manifest is that of the adds that
    /// went through. Here every write to a file fails for every third add,
    /// once with one page of the table in memory and once with all of
    /// them, so that an add fails where the table writes a page out for
    /// the one it needs and where it writes the first names of its groups
    /// out. The sort keeps its records in memory, so that the table alone
    /// writes. The test binary runs this test again in a process of its
    /// own, which ignores SIGXFSZ and sets its own limit with prlimit(1).
    /// It is skipped where that can't be done, and where a write past the
    /// limit does not fail.
    #[test]
    fn adds_that_fail_for_the_table() {
        if env::var_os(FAILING_WRITES).is_some() {
            return check_adds_that_fail_for_the_table();
        }
        let script = r#"trap '' XFSZ; exec "$1" --exact listing::tests::adds_that_fail_for_the_table --nocapture"#;
        let output = Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(env::current_exe().unwrap())
            .env(FAILING_WRITES, "1")
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    /// The checks of [`adds_that_fail_for_the_table`].
    fn check_adds_that_fail_for_the_table() {
        let Some(hard) = hard_write_limit().filter(|hard| write_limit(hard)) else {
            eprintln!("skipping: prlimit(1) can't set the limit of this process");
            return;
        };
        // A file system that takes a write past the limit fails no add.
        let probe = TempDir::new("listing-failing-writes-probe");
        assert!(write_limit("0"));
        let written = fs::write(probe.0.join("probe"), b"x");
        assert!(write_limit(&hard));
        if written.map_err(|e| e.raw_os_error()) != Err(Some(libc::EFBIG)) {
            eprintln!("skipping: a write past the limit on the size of a file does not fail with EFBIG here");
            return;
        }
        // With one page of the table in memory an add fails where a page
        // is written out for the one it needs. With all of them in memory
        // it fails where the first names are written out, which only a
        // few adds do. So each of the two has to fail adds by itself.
        let failed = check_failing_writes(&hard, 1);
        assert!(failed > 20, "{}", failed);
        let failed = check_failing_writes(&hard, 64);
        assert!(failed > 0, "{}", failed);
    }

    /// The checks of [`adds_that_fail_for_the_table`] for a table that has
    /// `cached_pages` of its pages in memory, where `hard` is the limit
    /// the writes go through with. Returns how many adds failed.
    fn check_failing_writes(hard: &str, cached_pages: usize) -> u64 {
        let tmp = TempDir::new("listing-failing-writes");
        let clean_tmp = TempDir::new("listing-failing-writes-clean");
        let scratch = Scratch::beside(ScratchFile::open_directory(&tmp.0).unwrap().into());
        let table = HardlinkTable::with_limits(TableLimits {
            memory: 1,
            first_pages: 1,
            cached_pages,
        });
        let mut faulted = Listing::with_parts(Features::DEFAULT, Order::CodePoint, scratch, Sorter::new(), table);
        // The same adds without a fault, with everything in memory.
        let mut clean = listing(Features::DEFAULT, Memory::All, &clean_tmp);
        let (mut failed, mut refused) = (0, 0);
        // The names are nearly as long as a name can be, in directories
        // that are not added, so that the table writes the first names of
        // its groups out every few adds, and some of those writes fail.
        let deep = format!("{}/", "y".repeat(200)).repeat(19);
        // Another name of the token `token` that does not have the size
        // its names have, which is refused with the first name of the
        // token where a name of it was added.
        let other = |name: String, token: u64| {
            let Add::Given(mut object) = given(&name, token) else {
                unreachable!()
            };
            object.size = Some(4);
            Add::Given(object)
        };
        const ADDS: u64 = 600;
        // The adds, and then one more name for every token with the
        // writes going through: every first name is still there.
        for index in 0..ADDS + ADDS / 2 {
            // Two names for every token, and now and then another name of
            // a token of before.
            let add = if index >= ADDS {
                other(format!("{}check{}", deep, index), 1 + index - ADDS)
            } else if index % 7 == 6 {
                other(format!("{}late{}", deep, index), 1 + index / 4)
            } else {
                given(&format!("{}n{}", deep, index), 1 + index / 2)
            };
            let Add::Given(object) = &add else { unreachable!() };
            let off = (40..ADDS).contains(&index) && index % 3 == 0;
            if off {
                assert!(write_limit("0"));
            }
            // As an add does it: room first, then the object.
            let room = loop {
                match faulted.make_room(u64::MAX) {
                    Ok(true) => break Ok(()),
                    Ok(false) => {}
                    Err(e) => break Err(e),
                }
            };
            let result = room.and_then(|()| faulted.add_given(object));
            if off {
                assert!(write_limit(hard));
            }
            match result {
                Ok(()) => clean.add_given(object).unwrap(),
                Err(e) if e.io_error().and_then(io::Error::raw_os_error) == Some(libc::EFBIG) => failed += 1,
                Err(e) => {
                    // Refused for what it is: without the fault as well,
                    // and with the same words.
                    let other = clean.add_given(object).unwrap_err();
                    assert_eq!(e.to_string(), other.to_string(), "{}", index);
                    refused += 1;
                }
            }
        }
        assert!(refused > 20, "{}", refused);
        let (text, totals, _, _) = write(faulted, u64::MAX).unwrap();
        let (expected, expected_totals, _, _) = write(clean, u64::MAX).unwrap();
        assert!(
            text == expected,
            "{} bytes, {} bytes without a fault",
            text.len(),
            expected.len()
        );
        assert_eq!(totals, expected_totals);
        eprintln!(
            "adds_that_fail_for_the_table: {} pages in memory: {} adds failed with EFBIG, {} were refused",
            cached_pages, failed, refused
        );
        failed
    }
}
