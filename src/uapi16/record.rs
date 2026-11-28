// SPDX-License-Identifier: LGPL-2.1-or-later
//! File objects as the manifest builder keeps them while it sorts: in
//! bytes that are quick to write and to read back, and that say all an
//! object says. Two objects are equal if their bytes are.
//!
//! The bytes are never part of a manifest. They sit in memory or in a
//! scratch file until the objects are written in the order of the
//! manifest, and what comes back from a scratch file is checked like any
//! other input.
//!
//! An object is written into as many bytes as the one who writes it
//! allows, and no further. So an object that is larger than anything a
//! manifest holds takes no more memory here than one that fits.

use std::collections::BTreeMap;
use std::io;
use std::num::NonZeroU64;

use crate::object::{
    ContentsObject, ContentsSource, DosFlags, FatSerial, FileObject, FileSystemIdentity, FilledIn, FlagStates,
    GptPartition, InodeAttributes, InodeFlags, InodeType, Mode, Uuid, Validity, ValidityWindow,
};
use crate::{NameBuf, Sha256, MAX_CONTENTS};

/// An error for bytes that are not what was written.
fn damaged() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a scratch file of the sort was changed")
}

/// Writes the fields of an object one behind the other. Numbers are
/// little-endian, and what has no fixed length has its length in front.
pub(crate) struct RecordWriter<'a> {
    /// What the bytes are appended to.
    out: &'a mut Vec<u8>,
    /// How long that may get.
    limit: usize,
    /// Whether something did not fit and was left out.
    cut: bool,
}

impl<'a> RecordWriter<'a> {
    /// A writer that appends to `bytes` until they are `limit` bytes long.
    /// What does not fit then is left out, all of it, and so is everything
    /// that comes after it.
    pub(crate) fn new(out: &'a mut Vec<u8>, limit: usize) -> RecordWriter<'a> {
        RecordWriter { out, limit, cut: false }
    }

    /// Whether something was left out because it did not fit. The bytes
    /// are no record then.
    pub(crate) fn is_cut(&self) -> bool {
        self.cut
    }

    pub(crate) fn raw(&mut self, bytes: &[u8]) {
        if self.cut || bytes.len() > self.limit.saturating_sub(self.out.len()) {
            self.cut = true;
            return;
        }
        self.out.extend_from_slice(bytes);
    }

    pub(crate) fn u8(&mut self, value: u8) {
        self.raw(&[value]);
    }

    pub(crate) fn u16(&mut self, value: u16) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn u32(&mut self, value: u32) {
        self.raw(&value.to_le_bytes());
    }

    pub(crate) fn u64(&mut self, value: u64) {
        self.raw(&value.to_le_bytes());
    }

    /// Bytes with their length in front.
    pub(crate) fn bytes(&mut self, bytes: &[u8]) {
        // Nothing an object holds is as long as four gigabytes: a record
        // of it is refused long before.
        self.u32(u32::try_from(bytes.len()).unwrap_or(u32::MAX));
        self.raw(bytes);
    }

    /// The bits of `marks` whose value is there.
    fn mask<const BITS: usize>(marks: [(bool, u16); BITS]) -> u16 {
        marks
            .into_iter()
            .filter(|(there, _)| *there)
            .fold(0, |mask, (_, bit)| mask | bit)
    }

    fn flags<F: Copy>(&mut self, states: &FlagStates<F>, bits: impl Fn(F) -> u8) {
        self.raw(&[bits(states.stated), bits(states.set), bits(states.filled)]);
    }
}

/// Reads the fields of an object back, and takes nothing about them for
/// granted.
pub(crate) struct RecordReader<'a>(pub(crate) &'a [u8]);

impl<'a> RecordReader<'a> {
    pub(crate) fn array<const SIZE: usize>(&mut self) -> io::Result<[u8; SIZE]> {
        let (array, rest) = self.0.split_first_chunk().ok_or_else(damaged)?;
        self.0 = rest;
        Ok(*array)
    }

    pub(crate) fn u8(&mut self) -> io::Result<u8> {
        Ok(u8::from_le_bytes(self.array()?))
    }

    pub(crate) fn u16(&mut self) -> io::Result<u16> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> io::Result<u32> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> io::Result<u64> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    /// Bytes that have their length in front.
    pub(crate) fn bytes(&mut self) -> io::Result<&'a [u8]> {
        let len = usize::try_from(self.u32()?).map_err(|_| damaged())?;
        let (bytes, rest) = self.0.split_at_checked(len).ok_or_else(damaged)?;
        self.0 = rest;
        Ok(bytes)
    }

    fn string(&mut self) -> io::Result<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(|_| damaged())
    }

    /// A name, which is the name of the root if it has no bytes.
    fn name(&mut self) -> io::Result<NameBuf> {
        let name = self.string()?;
        if name.is_empty() {
            return Ok(NameBuf::default());
        }
        NameBuf::new(name).map_err(|_| damaged())
    }

    /// A mask that has no bits but those of `known`.
    fn mask(&mut self, known: u16) -> io::Result<u16> {
        let mask = self.u16()?;
        if mask & !known != 0 {
            return Err(damaged());
        }
        Ok(mask)
    }

    /// The value `read` reads, if `mask` has the bit `bit`.
    fn optional<T>(
        &mut self,
        mask: u16,
        bit: u16,
        read: impl FnOnce(&mut RecordReader<'a>) -> io::Result<T>,
    ) -> io::Result<Option<T>> {
        if mask & bit == 0 {
            return Ok(None);
        }
        read(self).map(Some)
    }

    fn flags<F: Copy + PartialEq + std::ops::BitAnd<Output = F>>(
        &mut self,
        from_bits: impl Fn(u8) -> Option<F>,
    ) -> io::Result<FlagStates<F>> {
        let [stated, set, filled] = self.array()?;
        let flags = |bits| from_bits(bits).ok_or_else(damaged);
        let (stated, set, filled) = (flags(stated)?, flags(set)?, flags(filled)?);
        // Only a flag that is stated is set or filled in.
        if (set & stated) != set || (filled & stated) != filled {
            return Err(damaged());
        }
        Ok(FlagStates { stated, set, filled })
    }

    /// Whether everything was read.
    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl InodeType {
    /// The inode types, each at the place of its number in the bytes.
    const NUMBERED: [InodeType; 7] = [
        InodeType::Regular,
        InodeType::Directory,
        InodeType::Symlink,
        InodeType::Fifo,
        InodeType::CharDevice,
        InodeType::BlockDevice,
        InodeType::Socket,
    ];

    fn to_record(self, record: &mut RecordWriter<'_>) {
        let number = InodeType::NUMBERED.iter().position(|&numbered| numbered == self);
        // Every inode type has a number that fits into a byte.
        record.u8(number.unwrap_or_default() as u8);
    }

    fn from_record(record: &mut RecordReader<'_>) -> io::Result<InodeType> {
        let number = usize::from(record.u8()?);
        InodeType::NUMBERED.get(number).copied().ok_or_else(damaged)
    }
}

impl ValidityWindow {
    fn to_record(self, record: &mut RecordWriter<'_>) {
        record.u64(self.since_usec);
        record.u8(u8::from(self.until_usec.is_some()));
        record.u64(self.until_usec.unwrap_or_default());
        record.u8(u8::from(self.state == Validity::Revoked));
    }

    fn from_record(record: &mut RecordReader<'_>) -> io::Result<ValidityWindow> {
        let since_usec = record.u64()?;
        let until_usec = match (record.u8()?, record.u64()?) {
            (0, 0) => None,
            (1, until_usec) => Some(until_usec),
            _ => return Err(damaged()),
        };
        let state = match record.u8()? {
            0 => Validity::Good,
            1 => Validity::Revoked,
            _ => return Err(damaged()),
        };
        Ok(ValidityWindow {
            since_usec,
            until_usec,
            state,
        })
    }
}

impl GptPartition {
    const LABEL: u16 = 1 << 0;
    const UUID: u16 = 1 << 1;
    const TYPE_UUID: u16 = 1 << 2;
    const FLAGS: u16 = 1 << 3;
    const NO_AUTO: u16 = 1 << 4;
    const NO_AUTO_SET: u16 = 1 << 5;
    const GROW_FILE_SYSTEM: u16 = 1 << 6;
    const GROW_FILE_SYSTEM_SET: u16 = 1 << 7;
    const KNOWN: u16 = (1 << 8) - 1;

    fn to_record(&self, record: &mut RecordWriter<'_>) {
        record.u16(RecordWriter::mask([
            (self.label.is_some(), GptPartition::LABEL),
            (self.uuid.is_some(), GptPartition::UUID),
            (self.type_uuid.is_some(), GptPartition::TYPE_UUID),
            (self.flags.is_some(), GptPartition::FLAGS),
            (self.no_auto.is_some(), GptPartition::NO_AUTO),
            (self.no_auto == Some(true), GptPartition::NO_AUTO_SET),
            (self.grow_file_system.is_some(), GptPartition::GROW_FILE_SYSTEM),
            (self.grow_file_system == Some(true), GptPartition::GROW_FILE_SYSTEM_SET),
        ]));
        if let Some(label) = &self.label {
            record.bytes(label.as_bytes());
        }
        for uuid in [self.uuid, self.type_uuid].into_iter().flatten() {
            record.raw(uuid.as_bytes());
        }
        if let Some(flags) = self.flags {
            record.u64(flags);
        }
    }

    fn from_record(record: &mut RecordReader<'_>) -> io::Result<GptPartition> {
        let mask = record.mask(GptPartition::KNOWN)?;
        let flag = |there: u16, set: u16| match (mask & there != 0, mask & set != 0) {
            (true, set) => Ok(Some(set)),
            (false, false) => Ok(None),
            (false, true) => Err(damaged()),
        };
        Ok(GptPartition {
            label: record.optional(mask, GptPartition::LABEL, RecordReader::string)?,
            uuid: record.optional(mask, GptPartition::UUID, |record| record.array().map(Uuid::new))?,
            type_uuid: record.optional(mask, GptPartition::TYPE_UUID, |record| record.array().map(Uuid::new))?,
            flags: record.optional(mask, GptPartition::FLAGS, RecordReader::u64)?,
            no_auto: flag(GptPartition::NO_AUTO, GptPartition::NO_AUTO_SET)?,
            grow_file_system: flag(GptPartition::GROW_FILE_SYSTEM, GptPartition::GROW_FILE_SYSTEM_SET)?,
        })
    }
}

impl ContentsObject {
    /// The numbers of the sources of a contents object in the bytes.
    const IMPLIED: u8 = 0;
    const FILE: u8 = 1;
    const URL: u8 = 2;
    const LITERAL: u8 = 3;

    const ENCODING: u16 = 1 << 0;
    const ENCODED_SIZE: u16 = 1 << 1;
    const ENCODED_SHA256: u16 = 1 << 2;
    const ORIGINAL_SIZE: u16 = 1 << 3;
    const ORIGINAL_SHA256: u16 = 1 << 4;
    const KNOWN: u16 = (1 << 5) - 1;

    fn to_record(&self, record: &mut RecordWriter<'_>) {
        match &self.source {
            ContentsSource::Implied => record.u8(ContentsObject::IMPLIED),
            ContentsSource::File(name) => {
                record.u8(ContentsObject::FILE);
                record.bytes(name.as_str().as_bytes());
            }
            ContentsSource::Url(url) => {
                record.u8(ContentsObject::URL);
                record.bytes(url.as_bytes());
            }
            ContentsSource::Literal(literal) => {
                record.u8(ContentsObject::LITERAL);
                record.bytes(literal);
            }
        }
        record.u32(u32::try_from(self.http_headers.len()).unwrap_or(u32::MAX));
        for (name, value) in &self.http_headers {
            record.bytes(name.as_bytes());
            record.bytes(value.as_bytes());
        }
        record.u16(RecordWriter::mask([
            (self.encoding.is_some(), ContentsObject::ENCODING),
            (self.encoded_size.is_some(), ContentsObject::ENCODED_SIZE),
            (self.encoded_sha256.is_some(), ContentsObject::ENCODED_SHA256),
            (self.original_size.is_some(), ContentsObject::ORIGINAL_SIZE),
            (self.original_sha256.is_some(), ContentsObject::ORIGINAL_SHA256),
        ]));
        if let Some(encoding) = &self.encoding {
            record.bytes(encoding.as_bytes());
        }
        if let Some(size) = self.encoded_size {
            record.u64(size);
        }
        if let Some(sha256) = &self.encoded_sha256 {
            record.raw(sha256.as_bytes());
        }
        if let Some(size) = self.original_size {
            record.u64(size);
        }
        if let Some(sha256) = &self.original_sha256 {
            record.raw(sha256.as_bytes());
        }
        record.u64(self.offset);
        record.u16(self.filled_in.bits());
    }

    fn from_record(record: &mut RecordReader<'_>) -> io::Result<ContentsObject> {
        let source = match record.u8()? {
            ContentsObject::IMPLIED => ContentsSource::Implied,
            ContentsObject::FILE => ContentsSource::File(record.name()?),
            ContentsObject::URL => ContentsSource::Url(record.string()?),
            ContentsObject::LITERAL => ContentsSource::Literal(record.bytes()?.to_vec()),
            _ => return Err(damaged()),
        };
        let headers = record.u32()?;
        let mut http_headers = Vec::new();
        for _ in 0..headers {
            http_headers.push((record.string()?, record.string()?));
        }
        let mask = record.mask(ContentsObject::KNOWN)?;
        let sha256 = |record: &mut RecordReader<'_>| record.array().map(Sha256::from);
        Ok(ContentsObject {
            source,
            http_headers,
            encoding: record.optional(mask, ContentsObject::ENCODING, RecordReader::string)?,
            encoded_size: record.optional(mask, ContentsObject::ENCODED_SIZE, RecordReader::u64)?,
            encoded_sha256: record.optional(mask, ContentsObject::ENCODED_SHA256, sha256)?,
            original_size: record.optional(mask, ContentsObject::ORIGINAL_SIZE, RecordReader::u64)?,
            original_sha256: record.optional(mask, ContentsObject::ORIGINAL_SHA256, sha256)?,
            offset: record.u64()?,
            filled_in: FilledIn::from_bits(record.u16()?),
        })
    }
}

impl InodeAttributes {
    const MODE: u16 = 1 << 0;
    const UID: u16 = 1 << 1;
    const GID: u16 = 1 << 2;
    const USER_NAME: u16 = 1 << 3;
    const GROUP_NAME: u16 = 1 << 4;
    const MTIME: u16 = 1 << 5;
    const XATTRS: u16 = 1 << 6;
    const READ_ONLY: u16 = 1 << 7;
    const READ_ONLY_SET: u16 = 1 << 8;
    const FLAGS: u16 = 1 << 9;
    const FILLED_IN: u16 = 1 << 10;
    const KNOWN: u16 = (1 << 11) - 1;

    /// Writes the inode attributes, which a file object and the root file
    /// object both have.
    pub(crate) fn to_record(&self, record: &mut RecordWriter<'_>) {
        record.u16(RecordWriter::mask([
            (self.mode.is_some(), InodeAttributes::MODE),
            (self.uid.is_some(), InodeAttributes::UID),
            (self.gid.is_some(), InodeAttributes::GID),
            (self.user_name.is_some(), InodeAttributes::USER_NAME),
            (self.group_name.is_some(), InodeAttributes::GROUP_NAME),
            (self.mtime_nsec.is_some(), InodeAttributes::MTIME),
            (self.user_xattrs.is_some(), InodeAttributes::XATTRS),
            (self.read_only.is_some(), InodeAttributes::READ_ONLY),
            (self.read_only == Some(true), InodeAttributes::READ_ONLY_SET),
            (self.flags != FlagStates::default(), InodeAttributes::FLAGS),
            (!self.filled_in.is_empty(), InodeAttributes::FILLED_IN),
        ]));
        if let Some(mode) = self.mode {
            // A mode has twelve bits.
            record.u16(mode.bits() as u16);
        }
        for id in [self.uid, self.gid].into_iter().flatten() {
            record.u32(id);
        }
        for name in [&self.user_name, &self.group_name].into_iter().flatten() {
            record.bytes(name.as_bytes());
        }
        if let Some(mtime) = self.mtime_nsec {
            record.u64(mtime);
        }
        if let Some(xattrs) = &self.user_xattrs {
            record.u32(u32::try_from(xattrs.len()).unwrap_or(u32::MAX));
            for (name, value) in xattrs.iter() {
                record.bytes(name.as_bytes());
                record.bytes(value);
            }
        }
        if self.flags != FlagStates::default() {
            record.flags(&self.flags, InodeFlags::bits);
        }
        if !self.filled_in.is_empty() {
            record.u16(self.filled_in.bits());
        }
    }

    /// Reads the inode attributes back.
    pub(crate) fn from_record(record: &mut RecordReader<'_>) -> io::Result<InodeAttributes> {
        let mask = record.mask(InodeAttributes::KNOWN)?;
        let mode = record.optional(mask, InodeAttributes::MODE, RecordReader::u16)?;
        let mode = mode
            .map(|mode| Mode::new(u32::from(mode)))
            .transpose()
            .map_err(|_| damaged())?;
        let uid = record.optional(mask, InodeAttributes::UID, RecordReader::u32)?;
        let gid = record.optional(mask, InodeAttributes::GID, RecordReader::u32)?;
        let name = |record: &mut RecordReader<'_>| record.string().map(String::into_boxed_str);
        let user_name = record.optional(mask, InodeAttributes::USER_NAME, name)?;
        let group_name = record.optional(mask, InodeAttributes::GROUP_NAME, name)?;
        let mtime_nsec = record.optional(mask, InodeAttributes::MTIME, RecordReader::u64)?;
        let user_xattrs = record.optional(mask, InodeAttributes::XATTRS, |record| {
            let mut xattrs = BTreeMap::new();
            for _ in 0..record.u32()? {
                // The attributes are written in the order of their names,
                // each name once.
                let (name, value) = (record.string()?, record.bytes()?.to_vec());
                if xattrs.last_key_value().is_some_and(|(last, _)| *last >= name) {
                    return Err(damaged());
                }
                xattrs.insert(name, value);
            }
            Ok(Box::new(xattrs))
        })?;
        let read_only = match (
            mask & InodeAttributes::READ_ONLY != 0,
            mask & InodeAttributes::READ_ONLY_SET != 0,
        ) {
            (true, set) => Some(set),
            (false, false) => None,
            (false, true) => return Err(damaged()),
        };
        let flags = record.optional(mask, InodeAttributes::FLAGS, |record| {
            record.flags(InodeFlags::from_bits)
        })?;
        let filled_in = record.optional(mask, InodeAttributes::FILLED_IN, RecordReader::u16)?;
        if flags == Some(FlagStates::default()) || filled_in == Some(0) {
            return Err(damaged());
        }
        Ok(InodeAttributes {
            mode,
            uid,
            gid,
            user_name,
            group_name,
            mtime_nsec,
            user_xattrs,
            read_only,
            flags: flags.unwrap_or_default(),
            filled_in: FilledIn::from_bits(filled_in.unwrap_or_default()),
        })
    }
}

impl FileSystemIdentity {
    const UUID: u16 = 1 << 0;
    const LABEL: u16 = 1 << 1;
    const FAT_SERIAL: u16 = 1 << 2;
    const KNOWN: u16 = (1 << 3) - 1;

    /// Writes the identity of a file system, which the root of a tree
    /// has.
    pub(crate) fn to_record(&self, record: &mut RecordWriter<'_>) {
        record.u16(RecordWriter::mask([
            (self.uuid.is_some(), FileSystemIdentity::UUID),
            (self.label.is_some(), FileSystemIdentity::LABEL),
            (self.fat_serial.is_some(), FileSystemIdentity::FAT_SERIAL),
        ]));
        if let Some(uuid) = &self.uuid {
            record.raw(uuid.as_bytes());
        }
        if let Some(label) = &self.label {
            record.bytes(label.as_bytes());
        }
        if let Some(serial) = self.fat_serial {
            record.u32(serial.get());
        }
    }

    /// Reads the identity of a file system back.
    pub(crate) fn from_record(record: &mut RecordReader<'_>) -> io::Result<FileSystemIdentity> {
        let mask = record.mask(FileSystemIdentity::KNOWN)?;
        Ok(FileSystemIdentity {
            uuid: record.optional(mask, FileSystemIdentity::UUID, |record| record.array().map(Uuid::new))?,
            label: record.optional(mask, FileSystemIdentity::LABEL, RecordReader::string)?,
            fat_serial: record.optional(mask, FileSystemIdentity::FAT_SERIAL, |record| {
                record.u32().map(FatSerial::new)
            })?,
        })
    }
}

impl FileObject {
    const SIZE: u16 = 1 << 0;
    const SHA256: u16 = 1 << 1;
    const INODE_TOKEN: u16 = 1 << 2;
    const MAJOR: u16 = 1 << 3;
    const MINOR: u16 = 1 << 4;
    const GPT: u16 = 1 << 5;
    const CONTENTS: u16 = 1 << 6;
    const DOS_FLAGS: u16 = 1 << 7;
    const VALIDITY: u16 = 1 << 8;
    const FILLED_IN: u16 = 1 << 9;
    const KNOWN: u16 = (1 << 10) - 1;

    /// Writes everything the object says but its name, which is what it
    /// is sorted by and is kept in front of this. What most objects do not
    /// have takes no room.
    ///
    /// An object with more contents objects than a manifest may have does
    /// not come back from what this writes. No writer takes it, and
    /// whoever keeps objects refuses it before.
    pub(crate) fn to_record(&self, record: &mut RecordWriter<'_>) {
        self.inode_type.to_record(record);
        record.u16(RecordWriter::mask([
            (self.size.is_some(), FileObject::SIZE),
            (self.sha256.is_some(), FileObject::SHA256),
            (self.inode_token.is_some(), FileObject::INODE_TOKEN),
            (self.major.is_some(), FileObject::MAJOR),
            (self.minor.is_some(), FileObject::MINOR),
            (self.gpt.is_some(), FileObject::GPT),
            (!self.contents.is_empty(), FileObject::CONTENTS),
            (self.dos_flags != FlagStates::default(), FileObject::DOS_FLAGS),
            (self.validity != ValidityWindow::default(), FileObject::VALIDITY),
            (!self.filled_in.is_empty(), FileObject::FILLED_IN),
        ]));
        if let Some(size) = self.size {
            record.u64(size);
        }
        if let Some(sha256) = &self.sha256 {
            record.raw(sha256.as_bytes());
        }
        if let Some(token) = self.inode_token {
            record.u64(token.get());
        }
        for number in [self.major, self.minor].into_iter().flatten() {
            record.u64(number);
        }
        if let Some(gpt) = &self.gpt {
            gpt.to_record(record);
        }
        if !self.contents.is_empty() {
            record.u32(u32::try_from(self.contents.len()).unwrap_or(u32::MAX));
            for contents in &self.contents {
                contents.to_record(record);
            }
        }
        if self.dos_flags != FlagStates::default() {
            record.flags(&self.dos_flags, DosFlags::bits);
        }
        if self.validity != ValidityWindow::default() {
            self.validity.to_record(record);
        }
        if !self.filled_in.is_empty() {
            record.u16(self.filled_in.bits());
        }
        self.inode.to_record(record);
    }

    /// Reads the object with the name `name` back, from all of `record`.
    pub(crate) fn from_record(name: NameBuf, record: &mut RecordReader<'_>) -> io::Result<FileObject> {
        let inode_type = InodeType::from_record(record)?;
        let mask = record.mask(FileObject::KNOWN)?;
        let size = record.optional(mask, FileObject::SIZE, RecordReader::u64)?;
        let sha256 = record.optional(mask, FileObject::SHA256, |record| record.array().map(Sha256::from))?;
        let inode_token = record.optional(mask, FileObject::INODE_TOKEN, |record| {
            NonZeroU64::new(record.u64()?).ok_or_else(damaged)
        })?;
        let major = record.optional(mask, FileObject::MAJOR, RecordReader::u64)?;
        let minor = record.optional(mask, FileObject::MINOR, RecordReader::u64)?;
        let gpt = record.optional(mask, FileObject::GPT, |record| {
            GptPartition::from_record(record).map(Box::new)
        })?;
        let contents = record.optional(mask, FileObject::CONTENTS, |record| {
            // A contents object is much larger in memory than its bytes
            // are, and no object that was kept has more of them than
            // this.
            let count = usize::try_from(record.u32()?).map_err(|_| damaged())?;
            if count > MAX_CONTENTS {
                return Err(damaged());
            }
            let mut contents = Vec::with_capacity(count);
            for _ in 0..count {
                contents.push(ContentsObject::from_record(record)?);
            }
            Ok(contents)
        })?;
        let dos_flags = record.optional(mask, FileObject::DOS_FLAGS, |record| record.flags(DosFlags::from_bits))?;
        let validity = record.optional(mask, FileObject::VALIDITY, ValidityWindow::from_record)?;
        let filled_in = record.optional(mask, FileObject::FILLED_IN, RecordReader::u16)?;
        // What is there says something: nothing is written that an
        // object without it would not say as well.
        if contents.as_ref().is_some_and(Vec::is_empty)
            || dos_flags == Some(FlagStates::default())
            || validity == Some(ValidityWindow::default())
            || filled_in == Some(0)
        {
            return Err(damaged());
        }
        let object = FileObject {
            name,
            inode_type,
            size,
            sha256,
            contents: contents.unwrap_or_default(),
            inode_token,
            major,
            minor,
            gpt,
            dos_flags: dos_flags.unwrap_or_default(),
            inode: InodeAttributes::from_record(record)?,
            validity: validity.unwrap_or_default(),
            filled_in: FilledIn::from_bits(filled_in.unwrap_or_default()),
        };
        if !record.is_empty() {
            return Err(damaged());
        }
        Ok(object)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{everything, name};

    /// The bytes of `object`.
    fn bytes(object: &FileObject) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut record = RecordWriter::new(&mut bytes, usize::MAX);
        object.to_record(&mut record);
        assert!(!record.is_cut());
        bytes
    }

    /// The object of the bytes `bytes`, named as `object` is.
    fn read(object: &FileObject, bytes: &[u8]) -> io::Result<FileObject> {
        FileObject::from_record(object.name().to_owned(), &mut RecordReader(bytes))
    }

    /// Objects that differ from one another in one thing each, from one
    /// that says nothing to one that says everything.
    fn objects() -> Vec<FileObject> {
        let mut objects = vec![FileObject::new(name("plain")), everything()];
        type Change = fn(&mut FileObject);
        let changes: [Change; 31] = [
            |o| o.inode_type = InodeType::Socket,
            |o| o.size = Some(0),
            |o| o.size = Some(u64::MAX),
            |o| o.sha256 = Some(Sha256::EMPTY),
            |o| o.inode_token = NonZeroU64::new(1),
            |o| o.inode_token = Some(NonZeroU64::MAX),
            |o| o.major = Some(0),
            |o| o.minor = Some(0),
            |o| o.gpt = Some(Box::default()),
            |o| o.gpt.get_or_insert_default().no_auto = Some(false),
            |o| o.gpt.get_or_insert_default().grow_file_system = Some(true),
            |o| o.gpt.get_or_insert_default().label = Some(String::new()),
            |o| o.contents = vec![ContentsObject::default()],
            |o| o.contents = vec![ContentsObject::new(ContentsSource::Literal(Vec::new()))],
            |o| o.contents = vec![ContentsObject::new(ContentsSource::Url(String::new()))],
            |o| o.contents = vec![ContentsObject::new(ContentsSource::File(name("f")))],
            |o| o.contents = vec![ContentsObject::new(ContentsSource::File(NameBuf::default()))],
            |o| o.dos_flags.put(DosFlags::HIDDEN, Some(false)),
            |o| o.dos_flags.put(DosFlags::HIDDEN, Some(true)),
            |o| o.inode.flags.put(InodeFlags::NO_DUMP, Some(false)),
            |o| o.inode.flags.fill_in(crate::Features::FLAG_NO_COW, InodeType::Regular),
            |o| o.inode.mode = Some(Mode::from_st_mode(0)),
            |o| o.inode.uid = Some(0),
            |o| o.inode.gid = Some(0),
            |o| o.inode.user_name = Some("".into()),
            |o| o.inode.group_name = Some("".into()),
            |o| o.inode.mtime_nsec = Some(0),
            |o| o.inode.user_xattrs = Some(Box::default()),
            |o| o.inode.read_only = Some(false),
            |o| o.validity.until_usec = Some(0),
            |o| o.filled_in.insert(crate::Field::Size),
        ];
        for change in changes {
            let mut object = FileObject::new(name("plain"));
            change(&mut object);
            objects.push(object);
        }
        let mut revoked = FileObject::new(name("plain"));
        revoked.validity.state = Validity::Revoked;
        revoked.validity.since_usec = 1;
        objects.push(revoked);
        objects
    }

    /// An object comes back from its bytes as it went in, with what a
    /// reader filled in, and no two objects that differ have the same
    /// bytes.
    #[test]
    fn objects_come_back() {
        let objects = objects();
        let all: Vec<Vec<u8>> = objects.iter().map(bytes).collect();
        for (index, (object, bytes)) in objects.iter().zip(&all).enumerate() {
            assert_eq!(read(object, bytes).unwrap(), *object, "{}", index);
            assert!(!all[..index].contains(bytes), "{}", index);
        }
        // The name is not in the bytes: it is what an object is sorted by.
        let mut renamed = everything();
        renamed.name = name("other");
        assert_eq!(bytes(&renamed), bytes(&everything()));
        // An object that says nothing takes a few bytes.
        assert_eq!(bytes(&FileObject::new(name("plain"))).len(), 5);
        // As many contents objects as a manifest may have come back, and
        // more do not.
        let mut many = FileObject::new(name("plain"));
        many.contents = vec![ContentsObject::default(); MAX_CONTENTS];
        assert!(read(&many, &bytes(&many)).unwrap() == many);
        many.contents.push(ContentsObject::default());
        let more = read(&many, &bytes(&many)).unwrap_err();
        assert_eq!(more.kind(), io::ErrorKind::InvalidData);
    }

    /// A writer stops at its limit: what does not fit is left out with
    /// everything behind it, and the writer says so.
    #[test]
    fn writes_up_to_a_limit() {
        let object = everything();
        let whole = bytes(&object);
        for limit in [0, 1, 4, whole.len() / 2, whole.len() - 1] {
            let mut bytes = Vec::new();
            let mut record = RecordWriter::new(&mut bytes, limit);
            object.to_record(&mut record);
            assert!(record.is_cut(), "{}", limit);
            assert!(bytes.len() <= limit && whole.starts_with(&bytes), "{}", limit);
        }
        for limit in [whole.len(), whole.len() + 1] {
            let mut bytes = Vec::new();
            let mut record = RecordWriter::new(&mut bytes, limit);
            object.to_record(&mut record);
            assert!(!record.is_cut() && bytes == whole, "{}", limit);
        }
        // Something small still fits behind something that did not, and
        // is left out all the same.
        let mut bytes = Vec::new();
        let mut record = RecordWriter::new(&mut bytes, 4);
        record.u16(1);
        record.u32(2);
        record.u8(3);
        assert!(record.is_cut());
        assert_eq!(bytes, [1, 0]);
        // Bytes that are longer than the limit to begin with take nothing.
        let mut bytes = vec![0; 8];
        let mut record = RecordWriter::new(&mut bytes, 4);
        record.u8(1);
        assert!(record.is_cut());
        assert_eq!(bytes.len(), 8);
    }

    /// Bytes that are cut short, that go on after the object or that were
    /// changed never come back as the object, and never as a panic: they
    /// are another object or an error.
    #[test]
    fn changed_bytes_are_refused() {
        for object in objects() {
            let bytes = bytes(&object);
            for len in 0..bytes.len() {
                assert!(read(&object, &bytes[..len]).is_err(), "{:?} cut to {}", object, len);
            }
            let mut longer = bytes.clone();
            longer.push(0);
            assert_eq!(read(&object, &longer).unwrap_err().kind(), io::ErrorKind::InvalidData);
            for at in 0..bytes.len() {
                for bit in 0..8 {
                    let mut changed = bytes.clone();
                    changed[at] ^= 1 << bit;
                    if let Ok(read) = read(&object, &changed) {
                        assert_ne!(read, object, "{} bit {}", at, bit);
                    }
                }
            }
        }
    }

    /// The identity of a file system comes back as it went in.
    #[test]
    fn identities_come_back() {
        let identities = [
            FileSystemIdentity::default(),
            FileSystemIdentity {
                uuid: Some(Uuid::new([7; Uuid::SIZE])),
                label: Some("ESP".into()),
                fat_serial: Some(FatSerial::new(0x1234_abcd)),
            },
            FileSystemIdentity {
                uuid: None,
                label: Some(String::new()),
                fat_serial: Some(FatSerial::new(0)),
            },
        ];
        for identity in &identities {
            let mut bytes = Vec::new();
            identity.to_record(&mut RecordWriter::new(&mut bytes, usize::MAX));
            let mut reader = RecordReader(&bytes);
            assert_eq!(FileSystemIdentity::from_record(&mut reader).unwrap(), *identity);
            assert!(reader.is_empty());
            for len in 0..bytes.len() {
                assert!(FileSystemIdentity::from_record(&mut RecordReader(&bytes[..len])).is_err());
            }
        }
    }
}
