// SPDX-License-Identifier: LGPL-2.1-or-later
//! The hard links of the files that are added to a manifest: which names
//! are names of one inode, whether they show the same file, and the
//! `inodeToken` each inode gets.
//!
//! The names of an inode can come far apart, and a tree can have as many
//! inodes with several names as it has files. So what is kept for each of
//! them, a group, is kept in a hash table that moves to a scratch file once
//! it has outgrown a few megabytes. From then on memory holds a fixed
//! number of its pages and no more, however large the tree is.
//!
//! The table is made of pages of 4 KiB, each with room for a fixed number
//! of groups. A group goes into the page its key hashes to, and into the
//! next page that has room if that one is full, which is then marked as
//! having overflowed. A lookup goes on to the next page only from a page
//! with that mark. Nothing is ever removed, so there is nothing to mark as
//! removed. Once three quarters of the room are taken the table doubles:
//! its pages are read one after the other and every group is placed again
//! in a table of twice the pages. The old pages are only read for that, so
//! a doubling that fails keeps them, and the table is as it was before it
//! began. On disk the pages go through a small cache, each page in the one
//! place of the cache its number gives it. The number of places is prime,
//! so the two pages a page splits into when the table doubles never push
//! each other out.
//!
//! A table on disk doubles into a second scratch file, and gives the file
//! of the old pages back once it has. A doubling that fails gives back the
//! second file instead, and a move to disk that fails both of its files. A
//! scratch file that is given back is not closed: it is emptied and stays
//! open for as long as trees are walked for the manifest, see
//! [`OwnFiles`](crate::sys::OwnFiles). Otherwise a walk of the directory
//! the scratch files are in could come to what a file system still shows of
//! a file that was just closed. The scratch space hands such a file out
//! again before it makes a new one, see
//! [`Scratch::file`](crate::scratch::Scratch::file). So a table on disk
//! takes turns between two files for its pages, however often it doubles,
//! and has one descriptor more than it uses, for the file that is empty.
//! Where something else was handed that file meanwhile, as the sort can
//! be, the next doubling makes one more.
//!
//! A group is kept until the manifest is complete, also once as many of
//! its names came as its inode has. That costs room: the scratch file
//! grows by a few hundred bytes for every inode with several names. Giving
//! the room back would split an inode into two groups with two tokens
//! whenever the number of its names is wrong or changes while a tree is
//! read, as with a rename into a directory that is still to come or with a
//! file system that makes the number up. The specification gives one inode
//! one token.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::io;
use std::mem;
use std::num::NonZeroU64;

use rustix::fs::FileType;

use crate::digest::Sha256Context;
use crate::error::{Error, ErrorKind, Field, TreeProblem};
use crate::object::{FileObject, FlagSet, InodeFlags};
use crate::scratch::Scratch;
use crate::sys::ScratchFile;
use crate::tree::{DeviceNumber, Failure, Identity, MountId, Status, Subject, Timestamp};
use crate::{Mode, Name, NameBuf, Sha256};

/// The size of a page of the table.
const PAGE_SIZE: usize = 4096;
/// The size of what a page starts with: how many groups it holds, in two
/// bytes, and its marks, in two more. The rest is zero.
const HEADER_SIZE: usize = 8;
/// The mark of a page that was full when a group came that belongs into
/// it, so that the group is in a page behind it.
const OVERFLOWED: u16 = 1;
/// The size of the key of a group.
const KEY_SIZE: usize = 40;
/// The size of what statx() says of a file, see [`Seen`].
const SEEN_SIZE: usize = 52;
/// The size of what is kept of the file a group is of, see [`Likeness`]:
/// what is there, what statx() says of the file, the hash of its data and
/// the hash of the fields of its file object.
const LIKENESS_SIZE: usize = 1 + SEEN_SIZE + 2 * Sha256::SIZE;
/// The size of a group in a page: its key, its token, where its first
/// name is and how long, and what is kept of its file, padded to a
/// multiple of eight.
const SLOT_SIZE: usize = 176;
/// How many groups a page has room for.
const SLOTS: usize = (PAGE_SIZE - HEADER_SIZE) / SLOT_SIZE;
/// Where a group has its token in its slot, right behind its key.
const TOKEN_AT: usize = KEY_SIZE;
/// What the token of a group is before it has one.
const NO_TOKEN: u64 = 0;

/// How large the table and the first names of its groups get, with the
/// pages a doubling needs for a while, before they move to scratch files.
const MEMORY_LIMIT: usize = 8 * 1024 * 1024;
/// How many pages the table starts with.
const FIRST_PAGES: u64 = 16;
/// How many pages of a table on disk are kept in memory: a prime.
const CACHED_PAGES: usize = 251;
/// How many pages are read at a time when a table on disk doubles.
const CHUNK_PAGES: usize = 256;
/// How many bytes of names are gathered before they are written out.
const NAMES_BUFFER: usize = 64 * 1024;
/// What a page costs that the table reads from its scratch file or writes
/// to it to hand out a token, in bytes of the budget of whoever asks for
/// the token: as many as the page has. So a step that asks a table on disk
/// for tokens reads and writes about what its budget says, as a step does
/// that asks for none.
const PAGE_COST: u64 = PAGE_SIZE as u64;

/// An error for a scratch file that does not hold what was written to it.
fn damaged() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "a scratch file of the hard links was changed",
    )
}

/// Writes the parts of a group one behind the other.
struct Encoder<'a> {
    bytes: &'a mut [u8],
    at: usize,
}

impl Encoder<'_> {
    fn bytes(&mut self, bytes: &[u8]) {
        self.bytes[self.at..self.at + bytes.len()].copy_from_slice(bytes);
        self.at += bytes.len();
    }

    fn u8(&mut self, value: u8) {
        self.bytes(&[value]);
    }

    fn u16(&mut self, value: u16) {
        self.bytes(&value.to_le_bytes());
    }

    fn u32(&mut self, value: u32) {
        self.bytes(&value.to_le_bytes());
    }

    fn u64(&mut self, value: u64) {
        self.bytes(&value.to_le_bytes());
    }

    fn i64(&mut self, value: i64) {
        self.bytes(&value.to_le_bytes());
    }
}

/// Reads the parts of a group one behind the other. What is read comes
/// from a scratch file, so nothing about it is taken for granted.
struct Decoder<'a> {
    bytes: &'a [u8],
}

impl Decoder<'_> {
    fn array<const SIZE: usize>(&mut self) -> io::Result<[u8; SIZE]> {
        let (array, rest) = self.bytes.split_first_chunk().ok_or_else(damaged)?;
        self.bytes = rest;
        Ok(*array)
    }

    fn u8(&mut self) -> io::Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn i64(&mut self) -> io::Result<i64> {
        Ok(i64::from_le_bytes(self.array()?))
    }
}

/// What tells the groups of hard links apart.
///
/// The names of the files of a tree are in one group if they are names of
/// one inode reached through one mount. The file objects a caller hands in
/// are in one group if they have the same `inodeToken`, and they never
/// share a group with the files of a tree: the tokens of a caller are
/// numbers of its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum GroupKey {
    /// A file of a tree.
    Walked(Identity),
    /// A file object of a caller, with its `inodeToken`.
    Given(NonZeroU64),
}

impl GroupKey {
    /// A file of a tree whose mount ID no other mount ever gets.
    const WALKED_UNIQUE: u8 = 1;
    /// A file of a tree whose mount ID is the one of /proc/self/mountinfo.
    const WALKED_REUSABLE: u8 = 2;
    /// A file object of a caller.
    const GIVEN: u8 = 3;

    /// The key as the table has it: what kind of key it is, whether a
    /// file is in a subvolume, and the numbers. No key starts with a zero,
    /// which is how an empty slot starts.
    pub(crate) fn encode(&self) -> [u8; KEY_SIZE] {
        let mut key = [0; KEY_SIZE];
        let mut encoder = Encoder { bytes: &mut key, at: 0 };
        match self {
            GroupKey::Walked(identity) => {
                let (kind, mount) = match identity.mount {
                    MountId::Unique(mount) => (GroupKey::WALKED_UNIQUE, mount),
                    MountId::Reusable(mount) => (GroupKey::WALKED_REUSABLE, mount),
                };
                encoder.u8(kind);
                encoder.u8(u8::from(identity.subvolume.is_some()));
                encoder.bytes(&[0; 6]);
                encoder.u64(mount);
                encoder.u32(identity.device.major);
                encoder.u32(identity.device.minor);
                encoder.u64(identity.inode);
                encoder.u64(identity.subvolume.unwrap_or_default());
            }
            GroupKey::Given(token) => {
                encoder.u8(GroupKey::GIVEN);
                encoder.bytes(&[0; 7]);
                encoder.u64(token.get());
            }
        }
        key
    }

    /// The key `key` is the form of in the table.
    pub(crate) fn decode(key: &[u8; KEY_SIZE]) -> io::Result<GroupKey> {
        let mut decoder = Decoder { bytes: key };
        let (kind, in_subvolume) = (decoder.u8()?, decoder.u8()?);
        let _: [u8; 6] = decoder.array()?;
        let number = decoder.u64()?;
        let mount = match kind {
            GroupKey::WALKED_UNIQUE => MountId::Unique(number),
            GroupKey::WALKED_REUSABLE => MountId::Reusable(number),
            GroupKey::GIVEN => return NonZeroU64::new(number).map(GroupKey::Given).ok_or_else(damaged),
            _ => return Err(damaged()),
        };
        let device = DeviceNumber {
            major: decoder.u32()?,
            minor: decoder.u32()?,
        };
        let (inode, subvolume) = (decoder.u64()?, decoder.u64()?);
        let subvolume = match in_subvolume {
            0 => None,
            1 => Some(subvolume),
            _ => return Err(damaged()),
        };
        Ok(GroupKey::Walked(Identity {
            mount,
            device,
            inode,
            subvolume,
        }))
    }
}

/// What statx() says of a file that all of its names have to agree in: its
/// type, its mode, its owner, the device it stands for, its size, its
/// modification time and its birth time. The change time is not among
/// them: making or removing another name of the file moves it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    file_type: FileType,
    mode: Mode,
    uid: u32,
    gid: u32,
    rdev: DeviceNumber,
    size: u64,
    mtime: Timestamp,
    btime: Option<Timestamp>,
}

impl Seen {
    /// The birth time of the file is there.
    const HAS_BTIME: u8 = 1 << 0;
    /// The types of files, each with the number it has in the bytes.
    const FILE_TYPES: [(FileType, u8); 8] = [
        (FileType::Unknown, 0),
        (FileType::RegularFile, 1),
        (FileType::Directory, 2),
        (FileType::Symlink, 3),
        (FileType::Fifo, 4),
        (FileType::CharacterDevice, 5),
        (FileType::BlockDevice, 6),
        (FileType::Socket, 7),
    ];
    /// A time that is not there, in the bytes.
    const NO_TIME: Timestamp = Timestamp {
        seconds: 0,
        nanoseconds: 0,
    };

    /// What the status `status` says of its file that all names of the
    /// file have to agree in.
    pub(crate) fn of(status: &Status) -> Seen {
        Seen {
            file_type: status.file_type,
            mode: status.mode,
            uid: status.uid,
            gid: status.gid,
            rdev: status.rdev,
            size: status.size,
            mtime: status.mtime,
            btime: status.btime,
        }
    }

    /// Whether this and `other` can be of one file. The birth time only
    /// counts where both have one.
    pub(crate) fn same_file(&self, other: &Seen) -> bool {
        let btime = match (self.btime, other.btime) {
            (Some(one), Some(another)) => one == another,
            _ => true,
        };
        btime
            && (self.file_type, self.mode, self.uid, self.gid) == (other.file_type, other.mode, other.uid, other.gid)
            && (self.rdev, self.size, self.mtime) == (other.rdev, other.size, other.mtime)
    }

    /// Writes this into `bytes`, as a slot of the table has it.
    fn encode(&self, bytes: &mut [u8; SEEN_SIZE]) {
        let file_type = Seen::FILE_TYPES
            .iter()
            .find(|(file_type, _)| *file_type == self.file_type)
            .map_or(0, |&(_, number)| number);
        let btime = self.btime.unwrap_or(Seen::NO_TIME);
        let mut encoder = Encoder { bytes, at: 0 };
        encoder.u8(if self.btime.is_some() { Seen::HAS_BTIME } else { 0 });
        encoder.u8(file_type);
        // A mode has twelve bits.
        encoder.u16(self.mode.bits() as u16);
        encoder.u32(self.uid);
        encoder.u32(self.gid);
        encoder.u32(self.rdev.major);
        encoder.u32(self.rdev.minor);
        encoder.u64(self.size);
        encoder.i64(self.mtime.seconds);
        encoder.u32(self.mtime.nanoseconds);
        encoder.i64(btime.seconds);
        encoder.u32(btime.nanoseconds);
        debug_assert_eq!(encoder.at, SEEN_SIZE);
    }

    /// What `bytes` holds, which [`Seen::encode`] wrote.
    fn decode(bytes: &[u8; SEEN_SIZE]) -> io::Result<Seen> {
        let mut decoder = Decoder { bytes };
        let (marks, file_type) = (decoder.u8()?, decoder.u8()?);
        if marks & !Seen::HAS_BTIME != 0 {
            return Err(damaged());
        }
        let file_type = Seen::FILE_TYPES
            .iter()
            .find(|(_, number)| *number == file_type)
            .map(|&(file_type, _)| file_type)
            .ok_or_else(damaged)?;
        let mode = Mode::new(u32::from(decoder.u16()?)).map_err(|_| damaged())?;
        let (uid, gid) = (decoder.u32()?, decoder.u32()?);
        let rdev = DeviceNumber {
            major: decoder.u32()?,
            minor: decoder.u32()?,
        };
        let size = decoder.u64()?;
        let mtime = Timestamp {
            seconds: decoder.i64()?,
            nanoseconds: decoder.u32()?,
        };
        let btime = Timestamp {
            seconds: decoder.i64()?,
            nanoseconds: decoder.u32()?,
        };
        let btime = match (marks & Seen::HAS_BTIME != 0, btime) {
            (true, btime) => Some(btime),
            (false, Seen::NO_TIME) => None,
            (false, _) => return Err(damaged()),
        };
        Ok(Seen {
            file_type,
            mode,
            uid,
            gid,
            rdev,
            size,
            mtime,
            btime,
        })
    }
}

/// What the names of one inode have to be alike in to be names of the
/// same file. The first name of a group gives it, and every other name is
/// held against it.
///
/// For a file of a tree that is what statx() says of it, the hash of its
/// data if it is a regular file, and a hash of the fields the manifest
/// records for it. For a file object of a caller it is only the last one.
/// The specification asks all file objects of one `inodeToken` to have the
/// same type, mode, owner, names of the owner, modification time, size,
/// hash, device numbers, extended attributes and inode flags, and these
/// are the fields that hash is over. So a group whose extended attributes
/// change between two of its names does not go out with two versions of
/// them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Likeness {
    seen: Option<Seen>,
    data: Option<Sha256>,
    fields: Sha256,
}

impl Likeness {
    /// What statx() said of the file is there.
    const HAS_SEEN: u8 = 1 << 0;
    /// The hash of the data of the file is there.
    const HAS_DATA: u8 = 1 << 1;

    /// What a file of a tree has to be alike in with its other names,
    /// where `seen` is what statx() says of it, `data` is the hash of its
    /// data, if it is a regular file, and `object` is the file object the
    /// manifest gets for this name.
    pub(crate) fn walked(seen: Seen, data: Option<Sha256>, object: &FileObject) -> Likeness {
        Likeness {
            seen: Some(seen),
            data,
            fields: Likeness::fields(object),
        }
    }

    /// What the file object `object` of a caller has to be alike in with
    /// the other file objects of its `inodeToken`.
    pub(crate) fn given(object: &FileObject) -> Likeness {
        Likeness {
            seen: None,
            data: None,
            fields: Likeness::fields(object),
        }
    }

    /// A hash over the fields of `object` that the specification asks to be
    /// the same on all file objects of one `inodeToken`: the type, `mode`,
    /// `uid`, `gid`, `userName`, `groupName`, `mTimeNSec`, `size`,
    /// `sha256`, `major`, `minor`, `extendedAttributes` and the inode
    /// flags. They go in as the record of the object has them: a field a
    /// reader filled in or a flag that is cleared is not in the record.
    /// Every field goes in with whether it is there and with its length, so
    /// that no two sets of fields give the same bytes.
    fn fields(object: &FileObject) -> Sha256 {
        let mut hash = Sha256Context::new();
        let mut field = |value: Option<&[u8]>| {
            hash.update(&[u8::from(value.is_some())]);
            let value = value.unwrap_or_default();
            hash.update(&(value.len() as u64).to_le_bytes());
            hash.update(value);
        };
        let filled_in = object.filled_in();
        let inode = object.inode();
        let number = |value: Option<u64>| value.map(u64::to_le_bytes);
        field(Some(object.inode_type().as_str().as_bytes()));
        field(
            number(inode.mode().map(|mode| u64::from(mode.bits())))
                .as_ref()
                .map(|n| &n[..]),
        );
        field(number(inode.uid().map(u64::from)).as_ref().map(|n| &n[..]));
        field(number(inode.gid().map(u64::from)).as_ref().map(|n| &n[..]));
        field(inode.user_name().map(str::as_bytes));
        field(inode.group_name().map(str::as_bytes));
        field(number(inode.mtime_nsec()).as_ref().map(|n| &n[..]));
        let size = object.size().filter(|_| !filled_in.contains(Field::Size));
        field(number(size).as_ref().map(|n| &n[..]));
        let sha256 = object.sha256().filter(|_| !filled_in.contains(Field::Sha256));
        field(sha256.as_ref().map(|sha256| &sha256.as_bytes()[..]));
        field(number(object.major()).as_ref().map(|n| &n[..]));
        field(number(object.minor()).as_ref().map(|n| &n[..]));
        // A record has no `extendedAttributes` where there are none, so no
        // attributes and none that are listed are the same here.
        for (name, value) in inode.user_xattrs().into_iter().flatten() {
            field(Some(name.as_bytes()));
            field(Some(value));
        }
        field(None);
        for &(flag, _, _) in InodeFlags::FIELDS {
            field(Some(&[u8::from(inode.flags.get(flag) == Some(true))]));
        }
        hash.finalize()
    }

    /// Whether this and `other` can be of one file. The hashes of the data
    /// only count where both have one: a file that is not a regular file
    /// has none, and neither has a file object of a caller.
    fn same_file(&self, other: &Likeness) -> bool {
        let seen = match (&self.seen, &other.seen) {
            (Some(one), Some(another)) => one.same_file(another),
            (None, None) => true,
            _ => false,
        };
        let data = match (self.data, other.data) {
            (Some(one), Some(another)) => one == another,
            _ => true,
        };
        seen && data && self.fields == other.fields
    }

    /// Writes this into `bytes`, as a slot of the table has it.
    fn encode(&self, bytes: &mut [u8; LIKENESS_SIZE]) {
        let mut seen = [0; SEEN_SIZE];
        if let Some(of_file) = &self.seen {
            of_file.encode(&mut seen);
        }
        let marks = [
            (self.seen.is_some(), Likeness::HAS_SEEN),
            (self.data.is_some(), Likeness::HAS_DATA),
        ];
        let marks = marks
            .into_iter()
            .filter(|(there, _)| *there)
            .fold(0, |marks, (_, mark)| marks | mark);
        let mut encoder = Encoder { bytes, at: 0 };
        encoder.u8(marks);
        encoder.bytes(&seen);
        encoder.bytes(self.data.unwrap_or(Sha256::EMPTY).as_bytes());
        encoder.bytes(self.fields.as_bytes());
        debug_assert_eq!(encoder.at, LIKENESS_SIZE);
    }

    /// What `bytes` holds, which [`Likeness::encode`] wrote.
    fn decode(bytes: &[u8; LIKENESS_SIZE]) -> io::Result<Likeness> {
        let mut decoder = Decoder { bytes };
        let marks = decoder.u8()?;
        if marks & !(Likeness::HAS_SEEN | Likeness::HAS_DATA) != 0 {
            return Err(damaged());
        }
        let seen = Seen::decode(&decoder.array()?)?;
        let data = Sha256::from(decoder.array()?);
        let fields = Sha256::from(decoder.array()?);
        Ok(Likeness {
            seen: (marks & Likeness::HAS_SEEN != 0).then_some(seen),
            data: (marks & Likeness::HAS_DATA != 0).then_some(data),
            fields,
        })
    }
}

/// Where the first name of a group is among the names, and how long it is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NameAt {
    offset: u64,
    len: u16,
}

/// A group as a slot of the table has it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Group {
    key: [u8; KEY_SIZE],
    /// The token of the group, [`NO_TOKEN`] until it gets one.
    token: u64,
    name: NameAt,
    likeness: Likeness,
}

impl Group {
    fn encode(&self) -> [u8; SLOT_SIZE] {
        let mut slot = [0; SLOT_SIZE];
        let mut likeness = [0; LIKENESS_SIZE];
        self.likeness.encode(&mut likeness);
        let mut encoder = Encoder {
            bytes: &mut slot,
            at: 0,
        };
        encoder.bytes(&self.key);
        encoder.u64(self.token);
        encoder.u64(self.name.offset);
        encoder.u16(self.name.len);
        encoder.bytes(&likeness);
        slot
    }

    fn decode(slot: &[u8]) -> io::Result<Group> {
        let mut decoder = Decoder { bytes: slot };
        let key = decoder.array()?;
        let token = decoder.u64()?;
        let name = NameAt {
            offset: decoder.u64()?,
            len: decoder.u16()?,
        };
        let likeness = Likeness::decode(&decoder.array()?)?;
        Ok(Group {
            key,
            token,
            name,
            likeness,
        })
    }
}

/// A page of the table: how many groups it holds, whether it overflowed,
/// and its slots, of which the first ones are taken.
struct Page;

impl Page {
    /// How many groups the page `page` holds.
    fn count(page: &[u8]) -> io::Result<usize> {
        let count = usize::from(u16::from_le_bytes([page[0], page[1]]));
        if count > SLOTS {
            return Err(damaged());
        }
        Ok(count)
    }

    /// How many groups the page `page` holds, and whether it was full when
    /// a group came for it. Only a full page is ever marked as that, so a
    /// lookup that finds the mark on another page is not sent on through
    /// the whole table by it.
    fn state(page: &[u8]) -> io::Result<(usize, bool)> {
        let count = Page::count(page)?;
        let overflowed = u16::from_le_bytes([page[2], page[3]]) & OVERFLOWED != 0;
        if overflowed && count < SLOTS {
            return Err(damaged());
        }
        Ok((count, overflowed))
    }

    /// Marks the page `page` as one that overflowed.
    fn set_overflowed(page: &mut [u8]) {
        page[2..4].copy_from_slice(&OVERFLOWED.to_le_bytes());
    }

    /// The slot `index` of the page `page`.
    fn slot(page: &[u8], index: usize) -> &[u8] {
        let at = HEADER_SIZE + index * SLOT_SIZE;
        &page[at..at + SLOT_SIZE]
    }

    /// Puts `slot` into the first free slot of the page `page`, which
    /// holds `count` groups and has room for one more.
    fn push(page: &mut [u8], count: usize, slot: &[u8]) {
        let at = HEADER_SIZE + count * SLOT_SIZE;
        page[at..at + SLOT_SIZE].copy_from_slice(slot);
        // A page has room for fewer groups than two bytes count.
        page[0..2].copy_from_slice(&(count as u16 + 1).to_le_bytes());
    }
}

/// The pages of a table in a scratch file, with those of them that memory
/// holds. A page that is asked for takes the place its number gives it, and
/// the page that was there is written out first if it changed.
#[derive(Debug)]
struct DiskPages {
    file: ScratchFile,
    /// How many pages the file has.
    pages: u64,
    /// The pages memory holds, one after the other.
    cache: Vec<u8>,
    /// The number of the page in each place, [`DiskPages::NONE`] for
    /// none.
    numbers: Vec<u64>,
    /// Whether the page in each place changed since it was read.
    changed: Vec<bool>,
    /// How many pages were read from the file and written to it.
    transfers: u64,
}

impl DiskPages {
    /// The number of no page.
    const NONE: u64 = u64::MAX;

    /// The table of `pages` pages in `file`, with `cached` of them in
    /// memory at a time.
    fn new(file: ScratchFile, pages: u64, cached: usize) -> DiskPages {
        DiskPages::with_cache(file, pages, vec![0; cached * PAGE_SIZE])
    }

    /// The table of `pages` pages in `file`, with as many of them in
    /// memory at a time as `cache` has room for, which holds none yet.
    fn with_cache(file: ScratchFile, pages: u64, cache: Vec<u8>) -> DiskPages {
        let cached = cache.len() / PAGE_SIZE;
        DiskPages {
            file,
            pages,
            cache,
            numbers: vec![DiskPages::NONE; cached],
            changed: vec![false; cached],
            transfers: 0,
        }
    }

    /// Where the page `number` is in the file.
    fn offset(number: u64) -> u64 {
        number * PAGE_SIZE as u64
    }

    /// Writes the page in the place `place` out, if it changed.
    fn write_out(&mut self, place: usize) -> io::Result<()> {
        if self.changed[place] {
            let page = &self.cache[place * PAGE_SIZE..(place + 1) * PAGE_SIZE];
            self.file.write_all_at(page, DiskPages::offset(self.numbers[place]))?;
            self.changed[place] = false;
            self.transfers += 1;
        }
        Ok(())
    }

    /// Writes every page that changed out.
    fn flush(&mut self) -> io::Result<()> {
        (0..self.numbers.len()).try_for_each(|place| self.write_out(place))
    }

    /// Hands the memory the pages are kept in over, to the table this one
    /// doubles into, once every page that changed was written out: memory
    /// holds none of these pages from then on, and the memory comes back
    /// where the doubling fails, see [`Store::take_back_cache`].
    fn lend_cache(&mut self) -> io::Result<Vec<u8>> {
        self.flush()?;
        self.numbers.fill(DiskPages::NONE);
        Ok(mem::take(&mut self.cache))
    }

    /// The place of the page `number` in memory, read from the file if it
    /// is not there.
    fn load(&mut self, number: u64) -> io::Result<usize> {
        // The remainder is less than the number of places.
        let place = (number % self.numbers.len() as u64) as usize;
        if self.numbers[place] != number {
            self.write_out(place)?;
            // The place holds no page until the read went through.
            self.numbers[place] = DiskPages::NONE;
            let page = &mut self.cache[place * PAGE_SIZE..(place + 1) * PAGE_SIZE];
            self.file.read_exact_at(page, DiskPages::offset(number))?;
            self.numbers[place] = number;
            self.transfers += 1;
        }
        Ok(place)
    }
}

/// The pages of the table, where they are.
#[derive(Debug)]
enum Store {
    /// In memory, one after the other.
    Memory(Vec<u8>),
    /// In a scratch file.
    Disk(DiskPages),
}

impl Store {
    /// Takes back the memory this table lent to the pages it doubled into,
    /// `doubled`, which are given up: the doubling did not finish. Their
    /// scratch file goes back to `scratch`. A table in memory lent nothing
    /// and doubled into no file.
    fn take_back_cache(&mut self, doubled: Store, scratch: &mut Scratch) {
        if let (Store::Disk(pages), Store::Disk(doubled)) = (self, doubled) {
            pages.cache = doubled.cache;
            scratch.take_back(doubled.file);
        }
    }

    /// Gives the pages up: their scratch file goes back to `scratch`, if
    /// they are in one.
    fn give_back(self, scratch: &mut Scratch) {
        if let Store::Disk(pages) = self {
            scratch.take_back(pages.file);
        }
    }

    /// How many pages were read from a scratch file and written to it for
    /// these pages: none for pages in memory.
    fn transfers(&self) -> u64 {
        match self {
            Store::Memory(_) => 0,
            Store::Disk(disk) => disk.transfers,
        }
    }

    /// How many pages there are: none, or a power of two.
    fn pages(&self) -> u64 {
        match self {
            Store::Memory(pages) => (pages.len() / PAGE_SIZE) as u64,
            Store::Disk(disk) => disk.pages,
        }
    }

    /// The page `number`, which there is, to look at.
    fn page(&mut self, number: u64) -> io::Result<&[u8]> {
        match self {
            Store::Memory(pages) => {
                let at = usize::try_from(number).map_err(|_| damaged())? * PAGE_SIZE;
                pages.get(at..at + PAGE_SIZE).ok_or_else(damaged)
            }
            Store::Disk(disk) => {
                let place = disk.load(number)?;
                Ok(&disk.cache[place * PAGE_SIZE..(place + 1) * PAGE_SIZE])
            }
        }
    }

    /// The page `number`, which there is, to change.
    fn page_mut(&mut self, number: u64) -> io::Result<&mut [u8]> {
        match self {
            Store::Memory(pages) => {
                let at = usize::try_from(number).map_err(|_| damaged())? * PAGE_SIZE;
                pages.get_mut(at..at + PAGE_SIZE).ok_or_else(damaged)
            }
            Store::Disk(disk) => {
                let place = disk.load(number)?;
                disk.changed[place] = true;
                Ok(&mut disk.cache[place * PAGE_SIZE..(place + 1) * PAGE_SIZE])
            }
        }
    }

    /// Puts the group `slot` into the page `home`, or into the next page
    /// behind it that has room.
    fn place(&mut self, home: u64, slot: &[u8]) -> io::Result<()> {
        let pages = self.pages();
        let mut number = home;
        for _ in 0..pages {
            let page = self.page(number)?;
            let (count, overflowed) = Page::state(page)?;
            if count < SLOTS {
                Page::push(self.page_mut(number)?, count, slot);
                return Ok(());
            }
            if !overflowed {
                Page::set_overflowed(self.page_mut(number)?);
            }
            number = (number + 1) % pages;
        }
        // A table doubles long before every page is full.
        Err(damaged())
    }
}

/// The first names of the groups, one behind the other, which an error
/// about another name of a group names.
#[derive(Debug)]
enum Names {
    /// In memory.
    Memory(Vec<u8>),
    /// In a scratch file, but for the last ones, which are gathered in
    /// memory and written out together.
    Disk {
        file: ScratchFile,
        /// How many bytes the file holds.
        written: u64,
        /// The names that are still to be written.
        pending: Vec<u8>,
    },
}

impl Names {
    /// How many bytes of names memory holds.
    fn in_memory(&self) -> usize {
        match self {
            Names::Memory(names) => names.len(),
            Names::Disk { pending, .. } => pending.len(),
        }
    }

    /// Adds `name` and returns where it is.
    fn push(&mut self, name: &Name) -> io::Result<NameAt> {
        let bytes = name.as_str().as_bytes();
        // A name is at most Name::MAX_LEN bytes long.
        let len = u16::try_from(bytes.len()).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        match self {
            Names::Memory(names) => {
                let offset = names.len() as u64;
                names.extend_from_slice(bytes);
                Ok(NameAt { offset, len })
            }
            Names::Disk { file, written, pending } => {
                if pending.len() + bytes.len() > NAMES_BUFFER {
                    file.write_all_at(pending, *written)?;
                    *written += pending.len() as u64;
                    pending.clear();
                }
                let offset = *written + pending.len() as u64;
                pending.extend_from_slice(bytes);
                Ok(NameAt { offset, len })
            }
        }
    }

    /// The name at `at`.
    fn get(&self, at: NameAt) -> io::Result<NameBuf> {
        let len = usize::from(at.len);
        let mut bytes = vec![0; len];
        match self {
            Names::Memory(names) => {
                let start = usize::try_from(at.offset).map_err(|_| damaged())?;
                bytes.copy_from_slice(
                    names
                        .get(start..)
                        .and_then(|rest| rest.get(..len))
                        .ok_or_else(damaged)?,
                );
            }
            Names::Disk { file, written, pending } => match at.offset.checked_sub(*written) {
                Some(start) => {
                    let start = usize::try_from(start).map_err(|_| damaged())?;
                    bytes.copy_from_slice(
                        pending
                            .get(start..)
                            .and_then(|rest| rest.get(..len))
                            .ok_or_else(damaged)?,
                    );
                }
                None => file.read_exact_at(&mut bytes, at.offset)?,
            },
        }
        let name = String::from_utf8(bytes).map_err(|_| damaged())?;
        // The name of the root is a name as well, the one without bytes.
        if name.is_empty() {
            return Ok(NameBuf::default());
        }
        NameBuf::new(name).map_err(|_| damaged())
    }
}

/// What the table is doing to make room.
#[derive(Debug)]
enum Growth {
    /// Nothing.
    None,
    /// Its pages and its names, which were in memory, are written to
    /// scratch files as they are: so many bytes of the pages, and then of
    /// the names, are there.
    Moving {
        pages: ScratchFile,
        names: ScratchFile,
        written: usize,
    },
    /// The groups of the pages it had are placed in twice the pages: those
    /// of so many of the old pages are.
    Doubling { old: Store, placed: u64 },
}

/// What it comes to that a name of a group was noted.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Noted {
    /// It is the first name of its group.
    First,
    /// It is another name of a group, of the same file as the first one.
    Again,
    /// It is another name of a group, and it does not show the file the
    /// first name of the group showed, which is this one.
    Differs(NameBuf),
}

impl Noted {
    /// Fails for the name `name`, which was noted, if it does not show the
    /// file the first name of its group showed. Two names of one inode
    /// that differ are a hard-link mismatch that names both, also where
    /// `name` was noted before: a group keeps its first name and no other.
    /// The first name itself, noted again, names a file that changed.
    pub(crate) fn check(self, name: &Name) -> Result<(), Error> {
        match self {
            Noted::First | Noted::Again => Ok(()),
            Noted::Differs(first) if first == *name => Err(Failure::Changed.into_error(name)),
            Noted::Differs(first) => {
                let message = format!(
                    "{}: is a name of the inode of '{}', but does not show the same file",
                    Subject(name),
                    first.as_str().escape_debug()
                );
                Err(Error::new(ErrorKind::Tree(TreeProblem::HardlinkMismatch), message)
                    .named(name.as_str())
                    .linked(first))
            }
        }
    }
}

/// How large a table gets in memory and how much of it memory holds once
/// it is on disk.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// How many bytes the pages and the names take in memory at most,
    /// while a table doubles as well.
    pub(crate) memory: usize,
    /// How many pages the table starts with, a power of two.
    pub(crate) first_pages: u64,
    /// How many pages of a table on disk memory holds.
    pub(crate) cached_pages: usize,
}

/// The table of the groups of hard links, see the documentation of this
/// module.
#[derive(Debug)]
pub(crate) struct HardlinkTable {
    store: Store,
    names: Names,
    /// How many groups the table holds.
    groups: u64,
    /// How many groups have a token.
    tokens: u64,
    /// How many pages were read from the scratch file of the pages and
    /// written to it to hand out tokens.
    token_transfers: u64,
    growth: Growth,
    /// What the pages of a table on disk are read into when it doubles.
    chunk: Vec<u8>,
    /// What hashes the keys. Its keys are random, so that a tree cannot
    /// pick inode numbers that all go to one page.
    hasher: RandomState,
    limits: Limits,
}

impl HardlinkTable {
    /// A table without groups, which takes no room yet.
    pub(crate) fn new() -> HardlinkTable {
        HardlinkTable::with_limits(Limits {
            memory: MEMORY_LIMIT,
            first_pages: FIRST_PAGES,
            cached_pages: CACHED_PAGES,
        })
    }

    /// A table that takes as much memory as `limits` says.
    pub(crate) fn with_limits(limits: Limits) -> HardlinkTable {
        HardlinkTable {
            store: Store::Memory(Vec::new()),
            names: Names::Memory(Vec::new()),
            groups: 0,
            tokens: 0,
            token_transfers: 0,
            growth: Growth::None,
            chunk: Vec::new(),
            hasher: RandomState::new(),
            limits,
        }
    }

    /// The page the key `key` belongs into, in a table of `pages` pages
    /// whose keys `hasher` hashes.
    fn home(hasher: &RandomState, key: &[u8], pages: u64) -> u64 {
        hasher.hash_one(key) % pages
    }

    /// Whether one more group takes the table over three quarters of its
    /// room.
    fn is_full(&self) -> bool {
        (self.groups + 1) * 4 > self.store.pages() * SLOTS as u64 * 3
    }

    /// Does a part of what is to do before the table takes another group,
    /// and returns whether it is done: the table has room, and what does
    /// not fit into memory is on disk. `budget` is about how many bytes are
    /// read and written for it now. A doubling of a table on disk that
    /// begins writes out the pages memory holds of it first, whatever the
    /// budget, which are a megabyte at most. The scratch files it takes
    /// come from `scratch`, and those it is done with go back to it.
    ///
    /// A caller that works in steps calls this until it returns true
    /// before it notes a name. [`HardlinkTable::note`] does all that is
    /// left of it at once.
    ///
    /// Where a scratch file cannot be made, read or written this fails, and
    /// the table is as it was. That holds for a doubling that fails half
    /// way, as on a disk that is full: it keeps the pages it had, and the
    /// next call begins it again.
    pub(crate) fn make_room(&mut self, scratch: &mut Scratch, budget: u64) -> io::Result<bool> {
        // A table without groups takes no room before the first one comes,
        // which a tree without hard links never has.
        if self.store.pages() == 0 {
            return Ok(true);
        }
        self.grow(scratch, budget)
    }

    /// Does a part of what [`HardlinkTable::make_room`] began and did not
    /// finish, and returns whether it is done. `budget` is about how many
    /// bytes are read and written for it now. A scratch file it is done
    /// with goes back to `scratch`.
    ///
    /// Unlike [`HardlinkTable::make_room`] this begins nothing. It is what
    /// is left to do once no more names come and the groups get their
    /// tokens. [`HardlinkTable::token`] does all that is left of it at
    /// once.
    pub(crate) fn settle(&mut self, scratch: &mut Scratch, budget: u64) -> io::Result<bool> {
        let mut left = budget;
        self.advance(scratch, &mut left)
    }

    /// What [`HardlinkTable::make_room`] does: one thing after the other
    /// begins and is finished, until the table has room or the budget is
    /// used up.
    fn grow(&mut self, scratch: &mut Scratch, budget: u64) -> io::Result<bool> {
        let mut left = budget;
        loop {
            if !self.advance(scratch, &mut left)? {
                return Ok(false);
            }
            if !self.begin(scratch)? {
                return Ok(true);
            }
        }
    }

    /// Begins what is to do before the table takes another group, and
    /// returns whether there was something: a table that does not fit into
    /// memory any more moves to disk, and one that is full doubles.
    fn begin(&mut self, scratch: &mut Scratch) -> io::Result<bool> {
        if self.store.pages() == 0 {
            // The first group: the first pages.
            let size = usize::try_from(self.limits.first_pages).map_err(|_| damaged())? * PAGE_SIZE;
            self.store = Store::Memory(vec![0; size]);
        }
        let full = self.is_full();
        // In memory there has to be room for one more name, and while the
        // table doubles for the pages it has and for twice as many new
        // ones.
        let in_pages = match &self.store {
            Store::Memory(pages) => pages.len(),
            Store::Disk(_) => 0,
        };
        let needed = self.names.in_memory() + Name::MAX_LEN + if full { in_pages * 3 } else { in_pages };
        if in_pages > 0 && needed > self.limits.memory {
            let pages = scratch.file()?;
            let names = match scratch.file() {
                Ok(names) => names,
                Err(e) => {
                    // The first file goes back: the table took neither.
                    scratch.take_back(pages);
                    return Err(e);
                }
            };
            self.growth = Growth::Moving {
                pages,
                names,
                written: 0,
            };
        } else if full {
            let doubled = match &mut self.store {
                Store::Memory(old) => Store::Memory(vec![0; old.len() * 2]),
                Store::Disk(old) => {
                    // The pages are read from the file from here on, and
                    // what held some of them holds those of the new table
                    // while it doubles.
                    let file = scratch.file()?;
                    let sized = file.set_len(DiskPages::offset(old.pages * 2));
                    match sized.and_then(|()| old.lend_cache()) {
                        Ok(cache) => Store::Disk(DiskPages::with_cache(file, old.pages * 2, cache)),
                        Err(e) => {
                            // The file goes back, and the table is as it
                            // was: it doubles into none.
                            scratch.take_back(file);
                            return Err(e);
                        }
                    }
                }
            };
            let old = mem::replace(&mut self.store, doubled);
            self.growth = Growth::Doubling { old, placed: 0 };
        } else {
            return Ok(false);
        }
        Ok(true)
    }

    /// Goes on with what began until it is finished or `left` is used up,
    /// and returns whether it is finished. `left` is how many bytes may
    /// still be read and written. The scratch file of the pages a doubling
    /// is done with goes back to `scratch`, and so do the files of a
    /// doubling or of a move to disk that fails.
    fn advance(&mut self, scratch: &mut Scratch, left: &mut u64) -> io::Result<bool> {
        loop {
            match mem::replace(&mut self.growth, Growth::None) {
                Growth::None => return Ok(true),
                Growth::Moving { pages, names, written } => {
                    let (Store::Memory(table), Names::Memory(first)) = (&self.store, &self.names) else {
                        return Err(damaged());
                    };
                    if *left == 0 {
                        self.growth = Growth::Moving { pages, names, written };
                        return Ok(false);
                    }
                    // A page at least, as for a table that doubles.
                    let most = usize::try_from(*left).unwrap_or(usize::MAX).max(PAGE_SIZE);
                    let (moved, done) = match written.checked_sub(table.len()) {
                        None => {
                            let end = table.len().min(written.saturating_add(most));
                            (pages.write_all_at(&table[written..end], written as u64), end)
                        }
                        Some(at) => {
                            let end = first.len().min(at.saturating_add(most));
                            (names.write_all_at(&first[at..end], at as u64), table.len() + end)
                        }
                    };
                    if let Err(e) = moved {
                        // The move is given up, and both of its files go
                        // back: the table is in memory as it was.
                        scratch.take_back(names);
                        scratch.take_back(pages);
                        return Err(e);
                    }
                    *left = left.saturating_sub((done - written) as u64);
                    if done < table.len() + first.len() {
                        self.growth = Growth::Moving {
                            pages,
                            names,
                            written: done,
                        };
                        continue;
                    }
                    let count = (table.len() / PAGE_SIZE) as u64;
                    let named = first.len() as u64;
                    self.store = Store::Disk(DiskPages::new(pages, count, self.limits.cached_pages));
                    self.names = Names::Disk {
                        file: names,
                        written: named,
                        pending: Vec::with_capacity(NAMES_BUFFER),
                    };
                }
                Growth::Doubling { old, placed } => {
                    if *left == 0 {
                        self.growth = Growth::Doubling { old, placed };
                        return Ok(false);
                    }
                    let now = (*left / PAGE_SIZE as u64)
                        .clamp(1, CHUNK_PAGES as u64)
                        .min(old.pages() - placed);
                    if let Err(e) = self.place_again(&old, placed, now) {
                        // Some of the groups are in the new pages, and the
                        // old ones have them all. So the table goes back to
                        // those, with the memory they lent the new ones,
                        // whose scratch file goes back.
                        let doubled = mem::replace(&mut self.store, old);
                        self.store.take_back_cache(doubled, scratch);
                        return Err(e);
                    }
                    *left = left.saturating_sub(now * PAGE_SIZE as u64);
                    // Once every page is placed the old ones are given up:
                    // their scratch file goes back, which empties it, and
                    // the next doubling is handed it again, see the
                    // documentation of this module.
                    if placed + now < old.pages() {
                        self.growth = Growth::Doubling {
                            old,
                            placed: placed + now,
                        };
                    } else {
                        old.give_back(scratch);
                    }
                }
            }
        }
    }

    /// Places the groups of the pages `first` to `first + count` of `old`
    /// in the table, which has twice the pages of `old`.
    fn place_again(&mut self, old: &Store, first: u64, count: u64) -> io::Result<()> {
        // At most CHUNK_PAGES pages are placed at a time.
        let size = usize::try_from(count).map_err(|_| damaged())? * PAGE_SIZE;
        let chunk = match old {
            Store::Memory(pages) => {
                let at = usize::try_from(first).map_err(|_| damaged())? * PAGE_SIZE;
                pages.get(at..at + size).ok_or_else(damaged)?
            }
            Store::Disk(disk) => {
                self.chunk.resize(CHUNK_PAGES * PAGE_SIZE, 0);
                disk.file
                    .read_exact_at(&mut self.chunk[..size], DiskPages::offset(first))?;
                &self.chunk[..size]
            }
        };
        let pages = self.store.pages();
        for page in chunk.chunks_exact(PAGE_SIZE) {
            for index in 0..Page::count(page)? {
                let slot = Page::slot(page, index);
                let home = HardlinkTable::home(&self.hasher, &slot[..KEY_SIZE], pages);
                self.store.place(home, slot)?;
            }
        }
        Ok(())
    }

    /// Where the group of the key `key` is: its page and its slot there.
    fn find(&mut self, key: &[u8; KEY_SIZE]) -> io::Result<Option<(u64, usize)>> {
        let pages = self.store.pages();
        if pages == 0 {
            return Ok(None);
        }
        let mut number = HardlinkTable::home(&self.hasher, key, pages);
        for _ in 0..pages {
            let page = self.store.page(number)?;
            let (count, overflowed) = Page::state(page)?;
            if let Some(index) = (0..count).find(|&index| Page::slot(page, index)[..KEY_SIZE] == key[..]) {
                return Ok(Some((number, index)));
            }
            if !overflowed {
                return Ok(None);
            }
            number = (number + 1) % pages;
        }
        Ok(None)
    }

    /// Notes that the file `name` is a name of the group `key`, a file
    /// that is `likeness`. The first name of a group makes the group. Every
    /// other one is held against the first: it is a name of the same
    /// file, or it is not, and then the first name comes back for the
    /// error.
    pub(crate) fn note(
        &mut self,
        scratch: &mut Scratch,
        key: &GroupKey,
        name: &Name,
        likeness: &Likeness,
    ) -> io::Result<Noted> {
        // Every group is where a lookup finds it once what began is
        // finished.
        while !self.settle(scratch, u64::MAX)? {}
        let key = key.encode();
        if let Some((number, index)) = self.find(&key)? {
            let group = Group::decode(Page::slot(self.store.page(number)?, index))?;
            if group.likeness.same_file(likeness) {
                return Ok(Noted::Again);
            }
            return Ok(Noted::Differs(self.names.get(group.name)?));
        }
        while !self.grow(scratch, u64::MAX)? {}
        let group = Group {
            key,
            token: NO_TOKEN,
            name: self.names.push(name)?,
            likeness: *likeness,
        };
        let home = HardlinkTable::home(&self.hasher, &key, self.store.pages());
        self.store.place(home, &group.encode())?;
        self.groups += 1;
        Ok(Noted::First)
    }

    /// The `inodeToken` of the group `key`, which has to be there. A group
    /// gets its token when it is first asked for, the next number from 1
    /// on. So asked in the order of the manifest, the groups are numbered
    /// in the order the specification wants.
    ///
    /// A table on disk reads the page of the group from its scratch file
    /// where memory does not hold it, and writes out the page that makes
    /// room for it if that one changed. [`HardlinkTable::token_cost`] says
    /// what that comes to. What is left to finish of what made room is
    /// finished first, with `scratch`, see [`HardlinkTable::settle`].
    pub(crate) fn token(&mut self, scratch: &mut Scratch, key: &GroupKey) -> io::Result<NonZeroU64> {
        while !self.settle(scratch, u64::MAX)? {}
        let before = self.store.transfers();
        let token = self.token_of(key);
        self.token_transfers += self.store.transfers() - before;
        token
    }

    /// What the tokens that were handed out so far cost, in bytes of a
    /// budget: [`PAGE_COST`] for every page that was read from the scratch
    /// file of the table or written to it for them. A token that the pages
    /// in memory answer costs nothing, and so no token of a table in memory
    /// does.
    pub(crate) fn token_cost(&self) -> u64 {
        self.token_transfers * PAGE_COST
    }

    /// What [`HardlinkTable::token`] does, once nothing is left to finish.
    fn token_of(&mut self, key: &GroupKey) -> io::Result<NonZeroU64> {
        let (number, index) = self.find(&key.encode())?.ok_or_else(damaged)?;
        let at = HEADER_SIZE + index * SLOT_SIZE + TOKEN_AT;
        let page = self.store.page(number)?;
        let token = u64::from_le_bytes(*page[at..].first_chunk().ok_or_else(damaged)?);
        if let Some(token) = NonZeroU64::new(token) {
            // No group has a token that was not handed out.
            return if token.get() <= self.tokens {
                Ok(token)
            } else {
                Err(damaged())
            };
        }
        let next = NonZeroU64::new(self.tokens + 1).ok_or_else(damaged)?;
        self.store.page_mut(number)?[at..at + size_of::<u64>()].copy_from_slice(&next.get().to_le_bytes());
        self.tokens = next.get();
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{name, OpenFile, TempDir};
    use crate::tree::InodeId;
    use crate::InodeType;
    use std::collections::{HashMap, HashSet};
    use std::env;
    use std::fs;
    use std::io::Write;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Instant;

    /// Scratch space in a directory of its own.
    fn scratch(name: &str) -> (TempDir, Scratch) {
        let tmp = TempDir::new(name);
        let directory = ScratchFile::open_directory(&tmp.0).unwrap();
        (tmp, Scratch::beside(directory.into()))
    }

    /// A table that leaves memory and doubles after a few groups, and that
    /// holds few of its pages in memory then.
    fn small() -> HardlinkTable {
        HardlinkTable::with_limits(Limits {
            memory: 8 * PAGE_SIZE,
            first_pages: 1,
            cached_pages: 3,
        })
    }

    /// The key of the inode `inode` of a file system a test makes up.
    fn walked(inode: u64) -> GroupKey {
        GroupKey::Walked(Identity {
            mount: MountId::Unique(7),
            device: DeviceNumber { major: 8, minor: 1 },
            inode,
            subvolume: None,
        })
    }

    /// The status of a regular file with two names.
    fn status() -> Status {
        let time = Timestamp {
            seconds: 1_700_000_000,
            nanoseconds: 123_456_789,
        };
        Status {
            identity: Identity {
                mount: MountId::Unique(7),
                device: DeviceNumber { major: 8, minor: 1 },
                inode: 2,
                subvolume: None,
            },
            file_type: FileType::RegularFile,
            mode: Mode::from_st_mode(0o644),
            nlink: 2,
            uid: 3,
            gid: 4,
            size: 5,
            mtime: time,
            ctime: time,
            btime: Some(time),
            rdev: DeviceNumber { major: 0, minor: 0 },
        }
    }

    /// What a regular file of the size `size` with the data `data` has to
    /// be alike in with its other names.
    fn likeness(size: u64, data: &[u8]) -> Likeness {
        let mut status = status();
        status.size = size;
        let mut object = FileObject::new(name("file"));
        object.size = Some(size);
        Likeness::walked(Seen::of(&status), Some(Sha256::digest(data)), &object)
    }

    /// A key is in the table as it comes back from it, and no two keys
    /// are there the same way. Bytes that are no key are refused.
    #[test]
    fn keys() {
        let identity = |mount, inode, subvolume| Identity {
            mount,
            device: DeviceNumber { major: 8, minor: 1 },
            inode,
            subvolume,
        };
        let keys = [
            GroupKey::Walked(identity(MountId::Unique(5), 5, None)),
            GroupKey::Walked(identity(MountId::Reusable(5), 5, None)),
            GroupKey::Walked(identity(MountId::Unique(5), 5, Some(0))),
            GroupKey::Walked(identity(MountId::Unique(5), 5, Some(5))),
            GroupKey::Walked(identity(MountId::Unique(5), 6, None)),
            GroupKey::Walked(identity(MountId::Unique(6), 5, None)),
            GroupKey::Walked(identity(MountId::Unique(u64::MAX), u64::MAX, Some(u64::MAX))),
            GroupKey::Given(NonZeroU64::new(5).unwrap()),
            GroupKey::Given(NonZeroU64::MAX),
        ];
        let mut device = identity(MountId::Unique(5), 5, None);
        device.device.minor = 2;
        let encoded: Vec<_> = keys
            .iter()
            .chain([&GroupKey::Walked(device)])
            .map(GroupKey::encode)
            .collect();
        for (key, encoded) in keys.iter().zip(&encoded) {
            assert_eq!(GroupKey::decode(encoded).unwrap(), *key);
            assert_ne!(encoded[0], 0);
        }
        for (index, one) in encoded.iter().enumerate() {
            assert!(!encoded[..index].contains(one), "{:?}", one);
        }
        let mut no_kind = encoded[0];
        no_kind[0] = 0;
        let mut unknown_kind = encoded[0];
        unknown_kind[0] = 9;
        let mut subvolume = encoded[0];
        subvolume[1] = 2;
        let mut no_token = encoded[7];
        no_token[8..16].fill(0);
        for bytes in [no_kind, unknown_kind, subvolume, no_token] {
            assert_eq!(GroupKey::decode(&bytes).unwrap_err().kind(), io::ErrorKind::InvalidData);
        }
    }

    /// What a file has to be alike in with its other names is in the table
    /// as it comes back from it. Bytes that are none are refused.
    #[test]
    fn likenesses() {
        let mut other = status();
        other.btime = None;
        other.file_type = FileType::Symlink;
        other.mtime.seconds = -5;
        other.rdev = DeviceNumber {
            major: u32::MAX,
            minor: 7,
        };
        other.mode = Mode::from_st_mode(0o7777);
        let object = FileObject::new(name("a"));
        let all = [
            likeness(5, b"hello"),
            Likeness::walked(Seen::of(&other), None, &object),
            Likeness::walked(Seen::of(&status()), None, &object),
            Likeness::given(&object),
        ];
        for likeness in &all {
            let mut bytes = [0xff; LIKENESS_SIZE];
            likeness.encode(&mut bytes);
            assert_eq!(Likeness::decode(&bytes).unwrap(), *likeness);
        }
        // Marks nobody has, a type of file there is none of, a mode with
        // more than its twelve bits, and a birth time that is not there
        // and is not zero.
        let mut bytes = [0; LIKENESS_SIZE];
        all[0].encode(&mut bytes);
        let mut without_btime = [0; LIKENESS_SIZE];
        all[1].encode(&mut without_btime);
        let changed = [
            (bytes, 0, 0x80),
            (bytes, 0, 0x04),
            (bytes, 1, 0x02),
            (bytes, 2, 8),
            (bytes, 4, 0x10),
        ];
        for (mut bytes, at, bits) in
            changed
                .into_iter()
                .chain([(without_btime, LIKENESS_SIZE - 2 * Sha256::SIZE - 1, 1)])
        {
            bytes[at] |= bits;
            assert_eq!(
                Likeness::decode(&bytes).unwrap_err().kind(),
                io::ErrorKind::InvalidData,
                "{}",
                at
            );
        }
        // What statx() says of a file alone comes back the same way.
        for status in [status(), other] {
            let seen = Seen::of(&status);
            let mut bytes = [0xff; SEEN_SIZE];
            seen.encode(&mut bytes);
            assert_eq!(Seen::decode(&bytes).unwrap(), seen);
        }
    }

    /// The names of one inode show the same file if statx() says the same
    /// of it, but for the change time and for a birth time only one of
    /// them has, if the fields its file objects have to agree in are the
    /// same, and if its data is, where both have a hash of it.
    #[test]
    fn what_shows_the_same_file() {
        let before = status();
        let object = FileObject::new(name("file"));
        let hash = Some(Sha256::digest(b"data"));
        let first = Likeness::walked(Seen::of(&before), hash, &object);
        assert!(first.same_file(&first));
        type Change = fn(&mut Status);
        let changes: [(&str, Change, bool); 13] = [
            ("type", |s| s.file_type = FileType::Fifo, false),
            ("mode", |s| s.mode = Mode::from_st_mode(0o600), false),
            ("uid", |s| s.uid ^= 1, false),
            ("gid", |s| s.gid ^= 1, false),
            ("rdev", |s| s.rdev.minor ^= 1, false),
            ("size", |s| s.size ^= 1, false),
            ("mtime", |s| s.mtime.nanoseconds ^= 1, false),
            ("mtime seconds", |s| s.mtime.seconds ^= 1, false),
            (
                "btime",
                |s| s.btime = Some(s.mtime).map(|mut t| (t.seconds ^= 1, t).1),
                false,
            ),
            ("no btime", |s| s.btime = None, true),
            ("ctime", |s| s.ctime.seconds ^= 1, true),
            ("nlink", |s| s.nlink += 1, true),
            ("identity", |s| s.identity.inode ^= 1, true),
        ];
        for (what, change, same) in changes {
            let mut later = before;
            change(&mut later);
            let later = Likeness::walked(Seen::of(&later), hash, &object);
            assert_eq!(first.same_file(&later), same, "{}", what);
            assert_eq!(later.same_file(&first), same, "{}", what);
        }
        let other_data = Likeness::walked(Seen::of(&before), Some(Sha256::digest(b"other")), &object);
        let no_data = Likeness::walked(Seen::of(&before), None, &object);
        let mut recorded = object.clone();
        recorded.inode.uid = Some(3);
        let other_fields = Likeness::walked(Seen::of(&before), hash, &recorded);
        let given = Likeness::given(&object);
        assert!(first.same_file(&no_data) && no_data.same_file(&first));
        for other in [other_data, other_fields, given] {
            assert!(!first.same_file(&other) && !other.same_file(&first), "{:?}", other);
        }
        assert!(given.same_file(&Likeness::given(&object)));
        assert!(!given.same_file(&Likeness::given(&recorded)));
    }

    /// The fields that have to be the same on all file objects of one
    /// `inodeToken` are those the specification names, as a record has
    /// them. Nothing else of an object counts.
    #[test]
    fn fields_that_have_to_agree() {
        let mut base = FileObject::new(name("first"));
        base.inode.mode = Some(Mode::from_st_mode(0o644));
        base.size = Some(5);
        let fields = Likeness::fields(&base);
        type Change = fn(&mut FileObject);
        let counted: [(&str, Change); 20] = [
            ("type", |o| o.inode_type = InodeType::Fifo),
            ("mode", |o| o.inode.mode = Some(Mode::from_st_mode(0o600))),
            ("no mode", |o| o.inode.mode = None),
            ("uid", |o| o.inode.uid = Some(0)),
            ("gid", |o| o.inode.gid = Some(0)),
            ("userName", |o| o.inode.user_name = Some("root".into())),
            ("groupName", |o| o.inode.group_name = Some("root".into())),
            ("mTimeNSec", |o| o.inode.mtime_nsec = Some(0)),
            ("size", |o| o.size = Some(6)),
            ("no size", |o| o.size = None),
            ("sha256", |o| o.sha256 = Some(Sha256::digest(b"hello"))),
            ("major", |o| o.major = Some(0)),
            ("minor", |o| o.minor = Some(0)),
            ("an attribute", |o| drop(o.inode.insert_user_xattr("a", "b"))),
            ("flagAppendOnly", |o| o.inode.set_flag_append_only(Some(true))),
            ("flagImmutable", |o| o.inode.set_flag_immutable(Some(true))),
            ("flagNoAtime", |o| o.inode.set_flag_no_atime(Some(true))),
            ("flagNoCow", |o| o.inode.set_flag_no_cow(Some(true))),
            ("flagNoDump", |o| o.inode.set_flag_no_dump(Some(true))),
            ("uid for gid", |o| (o.inode.uid, o.inode.gid) = (Some(4), None)),
        ];
        let mut seen = vec![fields];
        for (what, change) in counted {
            let mut changed = base.clone();
            change(&mut changed);
            let fields = Likeness::fields(&changed);
            assert!(!seen.contains(&fields), "{}", what);
            seen.push(fields);
        }
        // Where an attribute ends and its value starts counts, and so does
        // which attribute has which value.
        let attributes = |pairs: &[(&str, &str)]| {
            let mut object = base.clone();
            for (name, value) in pairs {
                object.inode.insert_user_xattr(*name, *value);
            }
            Likeness::fields(&object)
        };
        let different = [
            attributes(&[("ab", "c")]),
            attributes(&[("a", "bc")]),
            attributes(&[("a", "b"), ("c", "")]),
            attributes(&[("a", ""), ("c", "b")]),
            attributes(&[("a", ""), ("b", "c")]),
        ];
        for (index, one) in different.iter().enumerate() {
            assert!(!different[..index].contains(one) && !seen.contains(one), "{}", index);
        }
        let ignored: [(&str, Change); 10] = [
            ("name", |o| o.name = name("second")),
            ("inodeToken", |o| o.inode_token = NonZeroU64::new(7)),
            ("validity", |o| o.validity.since_usec = 1),
            ("readOnly", |o| o.inode.read_only = Some(false)),
            ("flagHidden", |o| o.set_flag_hidden(Some(true))),
            ("a cleared flag", |o| o.inode.set_flag_immutable(Some(false))),
            ("no attributes", |o| o.inode.set_user_xattrs(Some(Default::default()))),
            ("a filled-in hash", |o| {
                o.sha256 = Some(Sha256::EMPTY);
                o.filled_in.insert(Field::Sha256);
            }),
            ("contents", |o| o.contents = vec![crate::ContentsObject::default()]),
            ("gptLabel", |o| o.gpt = Some(Box::default())),
        ];
        for (what, change) in ignored {
            let mut changed = base.clone();
            change(&mut changed);
            assert_eq!(Likeness::fields(&changed), fields, "{}", what);
        }
        // A size a reader filled in is not in the record.
        let mut filled = base.clone();
        filled.filled_in.insert(Field::Size);
        let mut without = base.clone();
        without.size = None;
        assert_eq!(Likeness::fields(&filled), Likeness::fields(&without));
    }

    /// The first name of a group makes the group. Another name of the same
    /// file is one of the group, and one of another file gets the first
    /// name back. That holds for groups in memory and for groups on disk,
    /// while the table doubles many times over, with only a few of its
    /// pages in memory. Groups of files of a tree and groups of file
    /// objects of a caller are apart.
    #[test]
    fn groups() {
        let (tmp, mut scratch) = scratch("hardlink-groups");
        let mut table = small();
        assert_eq!(table.store.pages(), 0);
        let count = 6000;
        let key = |index: u64| match index % 3 {
            0 => GroupKey::Given(NonZeroU64::new(index + 1).unwrap()),
            _ => walked(index + 1),
        };
        let first = |index: u64| {
            name(&format!(
                "dir/{}/first-{}",
                "x".repeat((index % 200) as usize + 1),
                index
            ))
        };
        let mut model = HashMap::new();
        for index in 0..count {
            let likeness = likeness(index, &index.to_le_bytes());
            let noted = table.note(&mut scratch, &key(index), &first(index), &likeness).unwrap();
            assert_eq!(noted, Noted::First, "{}", index);
            model.insert(key(index), (first(index), likeness));
            // Every group so far is found as it went in, now and then.
            if index % 500 == 0 || index + 1 == count {
                for (key, (first, likeness)) in &model {
                    let again = table.note(&mut scratch, key, &name("another"), likeness).unwrap();
                    assert_eq!(again, Noted::Again);
                    let other = self::likeness(u64::MAX, b"other");
                    let differs = table.note(&mut scratch, key, &name("another"), &other).unwrap();
                    assert_eq!(differs, Noted::Differs(first.clone()));
                }
            }
        }
        assert_eq!(table.groups, count);
        let Store::Disk(disk) = &table.store else {
            panic!("{:?}", table.store);
        };
        assert!(disk.pages.is_power_of_two() && disk.pages * SLOTS as u64 * 3 >= count * 4);
        assert!(matches!(table.names, Names::Disk { .. }));
        // The same token for a number and for an inode number are two
        // groups.
        assert!(model.contains_key(&walked(2)) && model.contains_key(&GroupKey::Given(NonZeroU64::new(1).unwrap())));
        // Nothing has a name in the directory of the scratch files.
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
    }

    /// A table stays in memory until its pages and the first names of its
    /// groups, with the pages a doubling takes for a while, would take
    /// more than their limit. Then it moves to scratch files as it is, and
    /// only then is a scratch file made.
    #[test]
    fn moves_to_disk_once() {
        let (_tmp, mut scratch) = scratch("hardlink-move");
        let mut table = HardlinkTable::new();
        let likeness = likeness(1, b"1");
        // A table of half the limit cannot double in memory any more, and
        // it is full at three quarters of its slots.
        let in_memory = (MEMORY_LIMIT / 2 / PAGE_SIZE * SLOTS * 3 / 4) as u64;
        for index in 0..in_memory {
            let noted = table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
            assert_eq!(noted, Noted::First);
            assert!(matches!(table.store, Store::Memory(_)), "{}", index);
        }
        let Store::Memory(pages) = &table.store else {
            unreachable!();
        };
        assert_eq!(pages.len(), MEMORY_LIMIT / 2);
        table
            .note(&mut scratch, &walked(in_memory), &name("n"), &likeness)
            .unwrap();
        let Store::Disk(disk) = &table.store else {
            panic!("{:?}", table.growth);
        };
        assert_eq!(disk.pages as usize * PAGE_SIZE, MEMORY_LIMIT);
        assert_eq!(disk.cache.len(), CACHED_PAGES * PAGE_SIZE);
        // Long names move a table earlier.
        let mut table = HardlinkTable::new();
        let long = name(&"n".repeat(Name::MAX_LEN));
        let mut noted = 0;
        while matches!(table.store, Store::Memory(_)) {
            table.note(&mut scratch, &walked(noted), &long, &likeness).unwrap();
            noted += 1;
        }
        assert!(noted < in_memory / 4, "{}", noted);
        assert!((noted as usize) * Name::MAX_LEN <= MEMORY_LIMIT);
        let other = self::likeness(2, b"2");
        let differs = table.note(&mut scratch, &walked(0), &name("m"), &other).unwrap();
        assert_eq!(differs, Noted::Differs(long));
    }

    /// The first names come back from memory and from disk, short and as
    /// long as a name gets, also those that were not written out yet.
    #[test]
    fn first_names() {
        let (_tmp, mut scratch) = scratch("hardlink-names");
        let mut table = small();
        let likeness = likeness(1, b"1");
        let other = self::likeness(2, b"2");
        let first = |index: u64| match index % 7 {
            0 => name(&format!("{}{}", "long/".repeat(818), "names")),
            1 => name("a"),
            2 => NameBuf::default(),
            _ => name(&format!("{}/\u{fc}-{}", "d".repeat((index % 97) as usize + 1), index)),
        };
        let count = 3000;
        for index in 0..count {
            table
                .note(&mut scratch, &walked(index), &first(index), &likeness)
                .unwrap();
            for earlier in [0, index / 2, index] {
                let differs = table.note(&mut scratch, &walked(earlier), &name("x"), &other).unwrap();
                assert_eq!(differs, Noted::Differs(first(earlier)), "{} {}", index, earlier);
            }
        }
        let Names::Disk { written, pending, .. } = &table.names else {
            panic!("{:?}", table.names);
        };
        assert!(*written > NAMES_BUFFER as u64 && pending.len() <= NAMES_BUFFER);
    }

    /// The groups get their tokens in the order they are asked for them,
    /// from 1 on, and keep them, while the table doubles as well. A group
    /// that is not in the table has none.
    #[test]
    fn tokens() {
        let (_tmp, mut scratch) = scratch("hardlink-tokens");
        let mut table = small();
        let likeness = likeness(1, b"1");
        let count = 2000;
        for index in 0..count {
            table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
        }
        // Not in the order the groups were made in.
        let order: Vec<u64> = (0..count).map(|index| index * 7919 % count).collect();
        for (asked, index) in order.iter().enumerate() {
            let token = table.token(&mut scratch, &walked(*index)).unwrap();
            assert_eq!(token.get(), asked as u64 + 1);
            assert_eq!(table.token(&mut scratch, &walked(*index)).unwrap(), token);
        }
        for index in count..2 * count {
            table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
        }
        for (asked, index) in order.iter().enumerate() {
            let token = table.token(&mut scratch, &walked(*index)).unwrap();
            assert_eq!(token.get(), asked as u64 + 1);
        }
        assert_eq!(table.token(&mut scratch, &walked(count)).unwrap().get(), count + 1);
        let unknown = table.token(&mut scratch, &walked(u64::MAX)).unwrap_err();
        assert_eq!(unknown.kind(), io::ErrorKind::InvalidData);
        let unknown = HardlinkTable::new().token(&mut scratch, &walked(1)).unwrap_err();
        assert_eq!(unknown.kind(), io::ErrorKind::InvalidData);
    }

    /// Room is made a part at a time, with as much reading and writing as
    /// the budget of each step allows, and the groups are all there once
    /// it is made. Without a budget nothing is done, and where there is
    /// room nothing is to do.
    #[test]
    fn makes_room_in_steps() {
        for (budget, memory) in [
            (1, 8 * PAGE_SIZE),
            (PAGE_SIZE as u64, 8 * PAGE_SIZE),
            (3 * PAGE_SIZE as u64 + 1, usize::MAX),
        ] {
            let (_tmp, mut scratch) = scratch("hardlink-steps");
            let mut table = HardlinkTable::with_limits(Limits {
                memory,
                first_pages: 1,
                cached_pages: 3,
            });
            let likeness = likeness(1, b"1");
            let (mut steps, mut most) = (0, 0);
            for index in 0..3000 {
                let mut now = 0;
                while !table.make_room(&mut scratch, budget).unwrap() {
                    assert!(!table.make_room(&mut scratch, 0).unwrap());
                    now += 1;
                }
                assert!(table.make_room(&mut scratch, 0).unwrap());
                (steps, most) = (steps + now, most.max(now));
                let noted = table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
                assert_eq!(noted, Noted::First);
            }
            // The last doubling alone took a step for every page the
            // budget pays for, and a part of a page is paid in full.
            let pages_a_step = budget.div_ceil(PAGE_SIZE as u64);
            assert!(
                most + 1 >= table.store.pages() / 2 / pages_a_step,
                "{} {}",
                budget,
                most
            );
            assert!(steps > most);
            assert_eq!(matches!(table.store, Store::Memory(_)), memory == usize::MAX);
            for index in 0..3000 {
                let again = table.note(&mut scratch, &walked(index), &name("m"), &likeness).unwrap();
                assert_eq!(again, Noted::Again, "{}", index);
            }
        }
        // A name is noted whatever is left to do before.
        let (_tmp, mut scratch) = scratch("hardlink-steps");
        let mut table = small();
        let likeness = likeness(1, b"1");
        for index in 0..3000 {
            let _ = table.make_room(&mut scratch, 1).unwrap();
            table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
        }
        assert_eq!(table.groups, 3000);
    }

    /// Once no more names come, what was begun to make room is finished a
    /// part at a time as well, and nothing else begins: a table that is
    /// full stays as large as it is. A table without groups never took
    /// room.
    #[test]
    fn settles_in_steps() {
        let (_tmp, mut scratch) = scratch("hardlink-settles");
        let mut table = small();
        let likeness = likeness(1, b"1");
        let mut count = 0;
        // Up to the group before one that doubles a table of many pages
        // on disk.
        while !(table.store.pages() >= 64 && table.is_full()) {
            table.note(&mut scratch, &walked(count), &name("n"), &likeness).unwrap();
            count += 1;
        }
        assert!(matches!(table.store, Store::Disk(_)));
        let pages = table.store.pages();
        // Full as it is, there is nothing to finish.
        assert!(table.settle(&mut scratch, 0).unwrap() && table.settle(&mut scratch, u64::MAX).unwrap());
        assert_eq!(table.store.pages(), pages);
        // The table begins to double and gets as far as its first page.
        assert!(!table.make_room(&mut scratch, 1).unwrap());
        assert_eq!(table.store.pages(), 2 * pages);
        let mut steps = 0;
        while !table.settle(&mut scratch, 1).unwrap() {
            assert!(!table.settle(&mut scratch, 0).unwrap());
            steps += 1;
        }
        // A page a step, but for the first one and the last one.
        assert_eq!(steps, pages - 2);
        assert!(matches!(table.growth, Growth::None));
        assert_eq!(table.store.pages(), 2 * pages);
        // Every group is there, and gets its token whatever was left to
        // finish.
        for index in 0..count {
            assert_eq!(table.token(&mut scratch, &walked(index)).unwrap().get(), index + 1);
        }
        let with_tokens = count;
        while !table.is_full() {
            table.note(&mut scratch, &walked(count), &name("n"), &likeness).unwrap();
            count += 1;
        }
        let pages = table.store.pages();
        assert!(!table.make_room(&mut scratch, 1).unwrap());
        let token = table.token(&mut scratch, &walked(count - 1)).unwrap();
        assert_eq!(token.get(), with_tokens + 1);
        assert!(matches!(table.growth, Growth::None));
        assert_eq!(table.store.pages(), 2 * pages);
        let mut none = HardlinkTable::new();
        assert!(none.make_room(&mut scratch, u64::MAX).unwrap() && none.settle(&mut scratch, u64::MAX).unwrap());
        assert_eq!(none.store.pages(), 0);
        assert!(scratch.file().is_ok());
    }

    /// The tokens of a table in memory cost nothing. Those of a table on
    /// disk cost a page for every page that is read from its scratch file
    /// or written to it for them, and nothing where memory holds the page
    /// of the group. So with room in memory for every page a page is read
    /// once at most and none is written, and with room for one page nearly
    /// every token reads its page, and writes out the page of the token
    /// before it where that token was new. A page costs as many bytes as
    /// it has, no more and no less: with room for one page, a token costs
    /// the page that is read for it, and the page that is written out to
    /// make room for that one if it changed.
    #[test]
    fn what_tokens_cost() {
        /// How many groups each table has.
        const GROUPS: u64 = 2_000;
        /// Room for every page of a table of that many groups: a prime.
        const EVERY_PAGE: usize = 1021;
        let likeness = likeness(1, b"1");
        let (_tmp, mut scratch) = scratch("hardlink-cost");
        let mut in_memory = HardlinkTable::new();
        for index in 0..GROUPS {
            in_memory
                .note(&mut scratch, &walked(index), &name("n"), &likeness)
                .unwrap();
        }
        for index in 0..GROUPS {
            assert_eq!(in_memory.token(&mut scratch, &walked(index)).unwrap().get(), index + 1);
        }
        assert!(matches!(in_memory.store, Store::Memory(_)));
        assert_eq!(in_memory.token_cost(), 0);
        for cached_pages in [1, EVERY_PAGE] {
            let mut table = HardlinkTable::with_limits(Limits {
                memory: 8 * PAGE_SIZE,
                first_pages: 1,
                cached_pages,
            });
            for index in 0..GROUPS {
                table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
            }
            assert!(matches!(table.store, Store::Disk(_)));
            let pages = table.store.pages();
            assert!(pages < EVERY_PAGE as u64);
            // What the names cost is none of this.
            assert_eq!(table.token_cost(), 0);
            let mut costs = [0; 2];
            for cost in &mut costs {
                let before = table.token_cost();
                for index in 0..GROUPS {
                    assert_eq!(table.token(&mut scratch, &walked(index)).unwrap().get(), index + 1);
                }
                *cost = table.token_cost() - before;
            }
            let [new, again] = costs.map(|cost| cost / PAGE_COST);
            if cached_pages == EVERY_PAGE {
                assert!(new <= pages && again == 0, "{} {}", new, again);
            } else {
                // A read for nearly every token, and a write as well where
                // the tokens are new.
                assert!((GROUPS / 2..=2 * GROUPS).contains(&again), "{}", again);
                assert!((again + GROUPS / 2..=4 * GROUPS).contains(&new), "{} {}", new, again);
            }
        }
        /// The bytes of a page.
        const PAGE: u64 = PAGE_SIZE as u64;
        let mut table = HardlinkTable::with_limits(Limits {
            memory: 8 * PAGE_SIZE,
            first_pages: 1,
            cached_pages: 1,
        });
        for index in 0..GROUPS {
            table.note(&mut scratch, &walked(index), &name("n"), &likeness).unwrap();
        }
        // Two groups of two pages, each in the page its key belongs into,
        // so that one page is read to find it.
        let pages = table.store.pages();
        let mut at_home = Vec::new();
        for index in 0..GROUPS {
            let key = walked(index).encode();
            let home = HardlinkTable::home(&table.hasher, &key, pages);
            let found = table.find(&key).unwrap().unwrap().0;
            if found == home && at_home.iter().all(|&(_, other)| other != home) {
                at_home.push((index, home));
            }
            if at_home.len() == 2 {
                break;
            }
        }
        let [(one, _), (other, _)] = at_home[..] else {
            panic!("no two groups in pages of their own: {:?}", at_home);
        };
        let mut cost = |index: u64| {
            let before = table.token_cost();
            table.token(&mut scratch, &walked(index)).unwrap();
            table.token_cost() - before
        };
        // The first token is new, so its page changes and is written out
        // for the page of the second one, which is new as well.
        cost(one);
        assert_eq!(cost(other), 2 * PAGE);
        assert_eq!(cost(one), 2 * PAGE);
        // Neither page changes any more.
        assert_eq!(cost(other), PAGE);
        assert_eq!(cost(other), 0);
        assert_eq!(cost(one), PAGE);
    }

    /// A table that has doubled on disk gives back the scratch file of its
    /// old pages. That file is emptied, and it stays open and one of the
    /// files of the manifest's own, with the inode it had. The next
    /// doubling goes into it. So the table takes turns between two files
    /// for its pages and makes no file after its first doubling on disk,
    /// however often it doubles: it has three files open while it doubles
    /// and between doublings. A table that is dropped leaves them as they
    /// are, and all of them are closed once the scratch space is dropped.
    #[test]
    fn doubled_tables_take_turns_between_two_files() {
        /// How many times the table doubles on disk here.
        const DOUBLINGS: usize = 6;
        /// The files the table has: two for its pages, and the names.
        const FILES: usize = 3;
        let (tmp, mut scratch) = scratch("hardlink-kept");
        let mut table = small();
        let likeness = likeness(1, b"1");
        // The file among `files` that holds the pages of the table.
        let pages_of = |files: &[OpenFile], table: &HardlinkTable| {
            let size = DiskPages::offset(table.store.pages());
            let pages: Vec<_> = files.iter().filter(|file| file.size == size).collect();
            assert_eq!(pages.len(), 1, "{:?}", files);
            pages[0].inode
        };
        let inodes = |files: &[OpenFile]| -> HashSet<InodeId> { files.iter().map(|file| file.inode).collect() };
        let mut count = 0;
        let mut doublings = 0;
        // The file of the pages and the empty one after the last doubling.
        let mut last: Option<(InodeId, InodeId)> = None;
        while doublings < DOUBLINGS {
            let before = table.store.pages();
            if let Some((pages, empty)) = last.filter(|_| table.is_full()) {
                // The doubling begins, into the file that was empty.
                assert!(!table.make_room(&mut scratch, 0).unwrap());
                let files = OpenFile::made_in(&tmp.0);
                assert_eq!(files.len(), FILES, "{:?}", files);
                assert!(files.iter().all(|file| file.size > 0), "{:?}", files);
                assert_eq!(pages_of(&files, &table), empty);
                assert!(inodes(&files).contains(&pages));
            }
            table.note(&mut scratch, &walked(count), &name("n"), &likeness).unwrap();
            count += 1;
            if !matches!(table.store, Store::Disk(_)) {
                assert!(OpenFile::made_in(&tmp.0).is_empty());
                continue;
            }
            if table.store.pages() == before {
                continue;
            }
            // The table moved to disk and doubled there, or doubled there.
            doublings += 1;
            let files = OpenFile::made_in(&tmp.0);
            // The pages, the names, and the file of the pages the table
            // had, which is the one that is empty.
            assert_eq!(files.len(), FILES, "{:?}", files);
            let empty: Vec<_> = files
                .iter()
                .filter(|file| file.size == 0)
                .map(|file| file.inode)
                .collect();
            assert_eq!(empty.len(), 1, "{:?}", files);
            let pages = pages_of(&files, &table);
            // The two files of the pages changed places, and no file was
            // made.
            if let Some((had, was_empty)) = last {
                assert_eq!((pages, empty[0]), (was_empty, had), "{:?}", files);
            }
            last = Some((pages, empty[0]));
            let own = scratch.own_files();
            assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
        }
        // A table that is dropped leaves its files as they are. Nothing but
        // the scratch space empties one, and all are closed with it.
        drop(table);
        let files = OpenFile::made_in(&tmp.0);
        assert_eq!(files.len(), FILES);
        assert_eq!(files.iter().filter(|file| file.size == 0).count(), 1, "{:?}", files);
        let own = scratch.own_files();
        assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
        drop(scratch);
        assert!(OpenFile::made_in(&tmp.0).is_empty());
    }

    /// A scratch file that does not hold what was written to it is an
    /// error, whatever it holds instead.
    #[test]
    fn changed_scratch_files() {
        type Damage = fn(&mut HardlinkTable);
        let damages: [(&str, Damage); 5] = [
            ("marks", |table| {
                let Store::Disk(disk) = &mut table.store else {
                    unreachable!()
                };
                // Every page is marked as one that overflowed, full or
                // not.
                for page in 0..disk.pages {
                    let at = DiskPages::offset(page) + size_of::<u16>() as u64;
                    disk.file.write_all_at(&OVERFLOWED.to_le_bytes(), at).unwrap();
                }
            }),
            ("counts", |table| {
                let Store::Disk(disk) = &mut table.store else {
                    unreachable!()
                };
                for page in 0..disk.pages {
                    disk.file
                        .write_all_at(&[0xff; HEADER_SIZE], DiskPages::offset(page))
                        .unwrap();
                }
            }),
            ("slots", |table| {
                let Store::Disk(disk) = &mut table.store else {
                    unreachable!()
                };
                for page in 0..disk.pages {
                    let at = DiskPages::offset(page) + (HEADER_SIZE + KEY_SIZE) as u64;
                    disk.file.write_all_at(&[0xff; SLOT_SIZE - KEY_SIZE], at).unwrap();
                }
            }),
            ("a shorter file", |table| {
                let Store::Disk(disk) = &mut table.store else {
                    unreachable!()
                };
                disk.file.set_len(0).unwrap();
            }),
            ("names", |table| {
                let Names::Disk { file, .. } = &mut table.names else {
                    unreachable!()
                };
                file.write_all_at(&[0xff; 4 * NAMES_BUFFER], 0).unwrap();
            }),
        ];
        for (what, damage) in damages {
            let (_tmp, mut scratch) = scratch("hardlink-damage");
            let mut table = small();
            let likeness = likeness(1, b"1");
            let other = self::likeness(2, b"2");
            let count = 3000;
            for index in 0..count {
                let first = name(&format!("{}/{}", "d".repeat(100), index));
                table.note(&mut scratch, &walked(index), &first, &likeness).unwrap();
            }
            let Store::Disk(disk) = &mut table.store else {
                unreachable!()
            };
            disk.flush().unwrap();
            disk.numbers.fill(DiskPages::NONE);
            damage(&mut table);
            let failed = (0..count)
                .filter(|&index| {
                    let noted = table.note(&mut scratch, &walked(index), &name("m"), &other);
                    let token = table.token(&mut scratch, &walked(index));
                    noted.is_err() || token.is_err()
                })
                .count();
            assert!(failed > 0, "{}", what);
            // Whatever is there, a group that seems new still goes in or
            // fails. It fails where the marks say that every page was
            // full, and is not looked for in all of the table first.
            let new = table.note(&mut scratch, &walked(count), &name("new"), &likeness);
            assert!(what != "marks" || new.is_err(), "{:?}", new);
        }
    }

    /// The variable that tells the test binary, run again by
    /// [`memory_stays_flat`], how many names to note.
    const NAMES: &str = "UAPI16_TEST_HARDLINK_NAMES";

    /// What the line starts with that says what was measured.
    const MEASURED: &str = "hard links:";

    /// The resident memory of this process that is its own, in bytes, which
    /// the kernel reports in kilobytes: RssAnon, without the pages of the
    /// files it has mapped. Those of the test binary come and go with the
    /// file system it is on, and are none of the table's. A kernel before
    /// Linux 4.5 does not tell the two apart, and all that is resident is
    /// taken there.
    fn resident() -> u64 {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
        let line = field("RssAnon:").or_else(|| field("VmRSS:")).unwrap();
        let kilobytes: u64 = line.trim().trim_end_matches("kB").trim().parse().unwrap();
        kilobytes * 1024
    }

    /// Notes `names` names of half as many inodes, every inode first and
    /// then every inode again, which is as far apart as the names of an
    /// inode get, and checks that the memory of the process stops growing
    /// once the table is on disk.
    fn note_names(names: u64) {
        let (_tmp, mut scratch) = scratch("hardlink-flat");
        let mut table = HardlinkTable::new();
        let likeness = likeness(1, b"1");
        let inodes = names / 2;
        // By then the table is on disk, has doubled there and has every
        // buffer it ever takes.
        let settled = 20_000.min(inodes - 1);
        let started = Instant::now();
        let (mut before, mut most) = (0, 0);
        for round in 0..2 {
            for inode in 0..inodes {
                let first = name(&format!("usr/lib/{:03}/{:07}", inode % 1000, inode));
                let noted = table.note(&mut scratch, &walked(inode), &first, &likeness).unwrap();
                assert_eq!(noted == Noted::First, round == 0);
                if round == 0 && inode == settled {
                    before = resident();
                }
                if inode % 4096 == 0 && (round == 1 || inode > settled) {
                    most = most.max(resident());
                }
            }
        }
        most = most.max(resident());
        let Store::Disk(disk) = &table.store else {
            panic!("{} names stayed in memory", names);
        };
        let Names::Disk { written, .. } = &table.names else {
            unreachable!();
        };
        println!(
            "{} {} names, {} inodes, {:.2} s, resident {} KiB once on disk and {} KiB at most after, \
             table {} MiB, first names {} MiB",
            MEASURED,
            names,
            inodes,
            started.elapsed().as_secs_f64(),
            before / 1024,
            most / 1024,
            DiskPages::offset(disk.pages) >> 20,
            written >> 20,
        );
        // A table in memory would have grown by megabytes for every
        // doubling since.
        const SLACK: u64 = 2 * 1024 * 1024;
        assert!(most <= before + SLACK, "{} -> {}", before, most);
    }

    /// Runs the test binary again to note `names` names in a process that
    /// does nothing else, so that its memory is that of the table.
    fn stays_flat(names: u64) {
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "hardlink::tests::memory_stays_flat", "--nocapture"])
            .env(NAMES, names.to_string())
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

    /// The memory of the table does not grow with the number of names
    /// once it is on disk.
    #[test]
    fn memory_stays_flat() {
        match env::var(NAMES) {
            Ok(names) => note_names(names.parse().unwrap()),
            Err(_) => stays_flat(100_000),
        }
    }

    /// The same for a million names.
    #[test]
    #[ignore = "notes a million names"]
    fn memory_stays_flat_for_a_million_names() {
        stays_flat(1_000_000);
    }

    /// The same for ten million names, with a scratch file of gigabytes.
    #[test]
    #[ignore = "notes ten million names"]
    fn memory_stays_flat_for_ten_million_names() {
        stays_flat(10_000_000);
    }

    /// Every name of an inode is held against the first name that was
    /// noted of it. A name that does not show the file the first name
    /// showed is a hard-link mismatch that names both, also a name that was
    /// noted before and shows another file now. The first name itself,
    /// noted again, is a file that changed.
    #[test]
    fn errors() {
        let (_tmp, mut scratch) = scratch("hardlink-errors");
        let mut table = HardlinkTable::new();
        let (first, second) = (name("a/first \"name\""), name("b/second"));
        let noted = table
            .note(&mut scratch, &walked(1), &first, &likeness(1, b"1"))
            .unwrap();
        noted.check(&first).unwrap();
        let again = table
            .note(&mut scratch, &walked(1), &second, &likeness(1, b"1"))
            .unwrap();
        again.check(&second).unwrap();
        let differs = table
            .note(&mut scratch, &walked(1), &second, &likeness(1, b"2"))
            .unwrap();
        let e = differs.check(&second).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::HardlinkMismatch));
        assert_eq!(
            (e.name(), e.hardlink_name()),
            (Some("b/second"), Some("a/first \"name\""))
        );
        assert_eq!(
            e.to_string(),
            r#"b/second: is a name of the inode of 'a/first \"name\"', but does not show the same file"#
        );
        let differs = table
            .note(&mut scratch, &walked(1), &first, &likeness(1, b"2"))
            .unwrap();
        let e = differs.check(&first).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Tree(TreeProblem::Changed));
        assert_eq!((e.name(), e.hardlink_name()), (Some(first.as_str()), None));
    }

    /// A scratch file that cannot be read fails what needs it and leaves
    /// the table as it was.
    #[test]
    fn failures() {
        let (_tmp, mut scratch) = scratch("hardlink-failed");
        let mut table = small();
        let likeness = likeness(1, b"1");
        let mut count = 0;
        // Up to the group before one that doubles a table on disk.
        while !(matches!(table.store, Store::Disk(_)) && table.is_full()) {
            table.note(&mut scratch, &walked(count), &name("n"), &likeness).unwrap();
            count += 1;
        }
        let shorten = |table: &mut HardlinkTable, len: Option<u64>| {
            let Store::Disk(disk) = &mut table.store else {
                unreachable!()
            };
            disk.flush().unwrap();
            disk.numbers.fill(DiskPages::NONE);
            disk.file.set_len(len.unwrap_or(DiskPages::offset(disk.pages))).unwrap();
        };
        shorten(&mut table, Some(0));
        let failed = table.note(&mut scratch, &walked(0), &name("n"), &likeness).unwrap_err();
        assert_eq!(failed.kind(), io::ErrorKind::UnexpectedEof);
        assert!(table.token(&mut scratch, &walked(0)).is_err());
        // With the file as long as it was the table is used again. Its
        // pages read as zeroes now: no group is there.
        shorten(&mut table, None);
        let noted = table.note(&mut scratch, &walked(0), &name("n"), &likeness).unwrap();
        assert_eq!(noted, Noted::First);
    }

    /// A table that cannot finish doubling, because the second half of the
    /// pages it doubles into or of the pages it had cannot be read, fails
    /// with that error and keeps the pages it had: every group is there
    /// with its first name, and the next group doubles the table. The file
    /// it could not double into is given back, which empties it and leaves
    /// it open, and the next doubling goes into it again: no file is made
    /// for it.
    #[test]
    fn failed_doublings() {
        let (likeness, other) = (likeness(1, b"1"), likeness(1, b"2"));
        let first = |index: u64| name(&format!("n{}", index));
        let all_there = |table: &mut HardlinkTable, scratch: &mut Scratch, count: u64| {
            for index in 0..count {
                let again = table.note(scratch, &walked(index), &name("again"), &likeness).unwrap();
                let differs = table.note(scratch, &walked(index), &name("again"), &other).unwrap();
                assert_eq!((again, differs), (Noted::Again, Noted::Differs(first(index))));
            }
        };
        for old_pages in [false, true] {
            let (tmp, mut scratch) = scratch("hardlink-doubling");
            let mut table = small();
            let mut count = 0;
            // Up to the group before one that doubles a table on disk.
            while !(matches!(table.store, Store::Disk(_)) && table.is_full()) {
                table
                    .note(&mut scratch, &walked(count), &first(count), &likeness)
                    .unwrap();
                count += 1;
            }
            let pages = table.store.pages();
            let (half, end) = (DiskPages::offset(pages / 2), DiskPages::offset(pages));
            // The doubling begins. The pages it had come back once it
            // failed.
            assert!(!table.make_room(&mut scratch, 0).unwrap());
            let mut kept = vec![0; usize::try_from(end - half).unwrap()];
            if old_pages {
                let Growth::Doubling {
                    old: Store::Disk(had), ..
                } = &mut table.growth
                else {
                    unreachable!()
                };
                had.file.read_exact_at(&mut kept, half).unwrap();
                had.file.set_len(half).unwrap();
            } else {
                let Store::Disk(doubled) = &mut table.store else {
                    unreachable!()
                };
                doubled.file.set_len(end).unwrap();
            }
            let e = loop {
                match table.make_room(&mut scratch, PAGE_SIZE as u64) {
                    Ok(done) => assert!(!done),
                    Err(e) => break e,
                }
            };
            assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
            assert!(matches!(table.growth, Growth::None));
            assert_eq!(table.store.pages(), pages);
            // The pages, the names, and the file the table could not
            // double into, which is the one it moved to and is empty again.
            let files = OpenFile::made_in(&tmp.0);
            assert_eq!(files.len(), 3, "{:?}", files);
            assert_eq!(files.iter().filter(|file| file.size == 0).count(), 1, "{:?}", files);
            let own = scratch.own_files();
            assert!(files.iter().all(|file| own.contains(&file.status).unwrap()));
            let made: HashSet<InodeId> = files.iter().map(|file| file.inode).collect();
            if old_pages {
                let Store::Disk(had) = &mut table.store else {
                    unreachable!()
                };
                had.file.set_len(end).unwrap();
                had.file.write_all_at(&kept, half).unwrap();
            }
            all_there(&mut table, &mut scratch, count);
            table
                .note(&mut scratch, &walked(count), &first(count), &likeness)
                .unwrap();
            count += 1;
            assert_eq!(table.store.pages(), 2 * pages);
            let files = OpenFile::made_in(&tmp.0);
            assert_eq!(files.iter().map(|file| file.inode).collect::<HashSet<_>>(), made);
            all_there(&mut table, &mut scratch, count);
            for index in 0..count {
                assert_eq!(table.token(&mut scratch, &walked(index)).unwrap().get(), index + 1);
            }
        }
    }

    /// The variable that tells the test binary, run again by
    /// [`gives_back_the_files_it_cannot_use`], to do the checks.
    const UNUSABLE_FILES: &str = "UAPI16_TEST_HARDLINK_UNUSABLE_FILES";

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

    /// A table gives back the scratch files it took and can't use, and
    /// takes them again once it can: the first file of a move to disk
    /// whose second file can't be made, both files of a move that can't be
    /// written, and the file of a doubling that can't be made as long as
    /// it has to be. Each of them fails the name that is noted and leaves
    /// the table as it was. So a table whose move and whose every doubling
    /// failed once has three files in the end, its pages, its names and
    /// the file its next doubling goes into, and it made no other. The
    /// test binary runs this test again in a process of its own, which
    /// ignores SIGXFSZ, has few descriptors and sets its own limit with
    /// prlimit(1). It is skipped where that can't be done, and where a
    /// write past the limit does not fail.
    #[test]
    fn gives_back_the_files_it_cannot_use() {
        if env::var_os(UNUSABLE_FILES).is_some() {
            return check_unusable_files();
        }
        let script = concat!(
            r#"trap '' XFSZ; ulimit -n 256 || exit 1; "#,
            r#"exec "$1" --exact hardlink::tests::gives_back_the_files_it_cannot_use --nocapture"#
        );
        let output = Command::new("sh")
            .args(["-c", script, "sh"])
            .arg(env::current_exe().unwrap())
            .env(UNUSABLE_FILES, "1")
            .output()
            .unwrap();
        // A test binary that runs no test succeeds as well.
        let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
        assert!(output.status.success() && ran, "{:?}", output);
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    /// The checks of [`gives_back_the_files_it_cannot_use`].
    fn check_unusable_files() {
        /// How many groups the table gets: it doubles on disk four times.
        const GROUPS: u64 = 200;
        /// How many names fail once: the one that moves the table to disk,
        /// and the one that begins each of its doublings.
        const FAILURES: u64 = 5;
        /// The files of a table on disk: its pages, its names, and the
        /// file its next doubling goes into.
        const FILES: usize = 3;
        let Some(hard) = hard_write_limit().filter(|hard| write_limit(hard)) else {
            eprintln!("skipping: prlimit(1) can't set the limit of this process");
            return;
        };
        // A file system that takes a write past the limit fails nothing.
        let probe = TempDir::new("hardlink-unusable-probe");
        assert!(write_limit("0"));
        let written = fs::write(probe.0.join("probe"), b"x");
        assert!(write_limit(&hard));
        if written.map_err(|e| e.raw_os_error()) != Err(Some(libc::EFBIG)) {
            eprintln!("skipping: a write past the limit on the size of a file does not fail with EFBIG here");
            return;
        }
        let (tmp, mut scratch) = scratch("hardlink-unusable");
        // Every page of the table is in memory, and its names are short
        // and stay there. So it writes to a file only where it moves to
        // disk and where it doubles.
        let mut table = HardlinkTable::with_limits(Limits {
            memory: 1,
            first_pages: 1,
            cached_pages: 64,
        });
        let likeness = likeness(1, b"1");
        // One descriptor is left, which the first file of the move takes.
        let mut taken = Vec::new();
        loop {
            let flags = rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::CLOEXEC;
            match rustix::fs::open("/dev/null", flags, rustix::fs::Mode::empty()) {
                Ok(descriptor) => taken.push(descriptor),
                Err(rustix::io::Errno::MFILE) => break,
                Err(e) => panic!("{}", e),
            }
        }
        taken.pop();
        let failed = table.note(&mut scratch, &walked(0), &name("n"), &likeness);
        drop(taken);
        assert_eq!(failed.unwrap_err().raw_os_error(), Some(libc::EMFILE));
        assert!(matches!(table.growth, Growth::None) && matches!(table.store, Store::Memory(_)));
        assert_eq!(OpenFile::made_in(&tmp.0).len(), 1);
        // No write goes through, and a name that fails for it is noted
        // again with the writes going through.
        let mut failed = 0;
        assert!(write_limit("0"));
        for index in 0..GROUPS {
            let pages = table.store.pages();
            if let Err(e) = table.note(&mut scratch, &walked(index), &name("n"), &likeness) {
                assert_eq!(e.raw_os_error(), Some(libc::EFBIG), "{}", index);
                assert!(matches!(table.growth, Growth::None) && table.store.pages() == pages);
                assert!(write_limit(&hard));
                let noted = table.note(&mut scratch, &walked(index), &name("n"), &likeness);
                assert_eq!(noted.unwrap(), Noted::First);
                assert!(write_limit("0"));
                failed += 1;
            }
        }
        assert!(write_limit(&hard));
        assert_eq!(failed, FAILURES);
        let files = OpenFile::made_in(&tmp.0);
        assert_eq!(files.len(), FILES, "{:?}", files);
    }

    /// The variable that tells the test binary, run again inside the
    /// namespaces of [`doublings_on_a_full_file_system`], where the tmpfs
    /// is mounted.
    const FULL_DIR: &str = "UAPI16_TEST_HARDLINK_FULL_DIR";

    /// How much room the tmpfs of [`doublings_on_a_full_file_system`] has,
    /// in bytes: more than the files of the table take, and little to fill.
    const FULL_ROOM: u64 = 1024 * 1024;

    /// A file that takes the room its file system has left, and gives it
    /// back. It is open only while it grows, so it is none of the open
    /// files a test finds in its directory. It is removed when it is
    /// dropped.
    #[derive(Debug)]
    struct Filler(PathBuf);

    impl Filler {
        /// Fills the file system: the file grows until a write finds no
        /// room. The tmpfs of the test has room for [`FULL_ROOM`] bytes. A
        /// file that grows past that is on another file system, which the
        /// variable names by mistake. This fails then, and fills no more
        /// of it.
        fn fill(&self) {
            let mut file = fs::OpenOptions::new().create(true).append(true).open(&self.0).unwrap();
            let mut size = file.metadata().unwrap().len();
            let full = loop {
                if let Err(e) = file.write_all(&[0; PAGE_SIZE]) {
                    break e;
                }
                size += PAGE_SIZE as u64;
                assert!(size <= FULL_ROOM, "{:?} is not on the tmpfs of the test", self.0);
            };
            assert_eq!(full.raw_os_error(), Some(libc::ENOSPC));
        }

        /// Gives the room back.
        fn empty(&self) {
            fs::remove_file(&self.0).unwrap();
        }
    }

    impl Drop for Filler {
        /// Removes the file, also where the test fails.
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.0);
        }
    }

    /// A table that doubles on disk writes out the pages memory holds once
    /// the file it doubles into is as long as it has to be. On a file
    /// system that is full the length takes no room, and the pages find
    /// none unless their file has them already. The name that is noted
    /// fails with ENOSPC then and leaves the table as it was, and the file
    /// the doubling took is given back: it is empty, and the doubling goes
    /// into it once there is room, so that no file is made for it. The
    /// table here holds every page in memory. So its first doubling on disk
    /// fails nothing, as the file of its pages has them since the table
    /// moved to disk, and each later one fails once, as the file it doubled
    /// into before has none of them. The test binary runs this test again
    /// in a user and a mount namespace from unshare(1), with its directory
    /// on a tmpfs of a fixed size, which is full for every name once the
    /// table is on disk. It is skipped where unshare can't make the
    /// namespaces or no tmpfs can be mounted in them.
    #[test]
    fn doublings_on_a_full_file_system() {
        if let Some(dir) = env::var_os(FULL_DIR) {
            return check_full_file_system(Path::new(&dir));
        }
        let tmp = TempDir::new("hardlink-full");
        let room = format!("size={}", FULL_ROOM);
        let test = "hardlink::tests::doublings_on_a_full_file_system";
        tmp.rerun_on("tmpfs", Some(&room), test, FULL_DIR);
    }

    /// The checks of [`doublings_on_a_full_file_system`], with the scratch
    /// files in `dir`, where the tmpfs is mounted.
    fn check_full_file_system(dir: &Path) {
        /// How many groups the table gets: it doubles on disk four times.
        const GROUPS: u64 = 200;
        /// How many names fail once: the one that begins each doubling on
        /// disk but the first.
        const FAILURES: u64 = 3;
        /// The files of a table on disk: its pages, its names, and the
        /// file its next doubling goes into.
        const FILES: usize = 3;
        let directory = ScratchFile::open_directory(dir).unwrap();
        let mut scratch = Scratch::beside(directory.into());
        // Every page of the table is in memory, and its names are short
        // and stay there. So it writes to a file only where it moves to
        // disk and where it doubles.
        let mut table = HardlinkTable::with_limits(Limits {
            memory: 1,
            first_pages: 1,
            cached_pages: 64,
        });
        let likeness = likeness(1, b"1");
        // The first name moves the table to disk, which takes room.
        let noted = table.note(&mut scratch, &walked(0), &name("n"), &likeness);
        assert_eq!(noted.unwrap(), Noted::First);
        assert!(matches!(table.store, Store::Disk(_)));
        // From here on the file system is full for every name, and a name
        // that fails for it is noted again once there is room.
        let filler = Filler(dir.join("filler"));
        let mut failed = 0;
        for index in 1..GROUPS {
            filler.fill();
            let pages = table.store.pages();
            if let Err(e) = table.note(&mut scratch, &walked(index), &name("n"), &likeness) {
                assert_eq!(e.raw_os_error(), Some(libc::ENOSPC), "{}", index);
                assert!(matches!(table.growth, Growth::None) && table.store.pages() == pages);
                // The pages, and two files that are empty: the names, which
                // memory holds, and the file the doubling took.
                let mut sizes: Vec<u64> = OpenFile::made_in(dir).iter().map(|file| file.size).collect();
                sizes.sort_unstable();
                assert_eq!(sizes, [0, 0, DiskPages::offset(pages)], "{}", index);
                filler.empty();
                let noted = table.note(&mut scratch, &walked(index), &name("n"), &likeness);
                assert_eq!(noted.unwrap(), Noted::First);
                // The doubling went into that file: none was made for it.
                assert_eq!(OpenFile::made_in(dir).len(), FILES, "{}", index);
                failed += 1;
            }
        }
        assert_eq!(failed, FAILURES);
        // Every group is there.
        for index in 0..GROUPS {
            let again = table.note(&mut scratch, &walked(index), &name("again"), &likeness);
            assert_eq!(again.unwrap(), Noted::Again, "{}", index);
        }
    }

    /// A table can go to another thread.
    #[test]
    fn send() {
        fn send<T: Send>() {}
        send::<HardlinkTable>();
        send::<Likeness>();
        send::<GroupKey>();
    }
}
