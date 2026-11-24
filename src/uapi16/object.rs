// SPDX-License-Identifier: LGPL-2.1-or-later
//! The objects of a manifest.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::num::NonZeroU64;
use std::ops::{BitAnd, BitOr, Not};
use std::os::unix::fs::FileTypeExt;
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::decode::ROOT_RECORD;
use crate::error::{Error, ErrorKind, Field, Problem, ValidityProblem};
use crate::hex::Hex;
use crate::{Features, Name, NameBuf, Order, Sha256, STRING_RULES};

/// The inode type of a file object, its `type` field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum InodeType {
    /// `reg`: a regular file.
    Regular,
    /// `dir`: a directory.
    Directory,
    /// `lnk`: a symbolic link.
    Symlink,
    /// `fifo`: a FIFO.
    Fifo,
    /// `chr`: a character device node.
    CharDevice,
    /// `blk`: a block device node.
    BlockDevice,
    /// `sock`: a socket.
    Socket,
}

/// A string or a file type that is not an inode type, see [`InodeType`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UnknownInodeType(());

impl fmt::Display for UnknownInodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not an inode type")
    }
}

impl std::error::Error for UnknownInodeType {}

impl InodeType {
    /// The name the type has in a manifest.
    pub const fn as_str(self) -> &'static str {
        match self {
            InodeType::Regular => "reg",
            InodeType::Directory => "dir",
            InodeType::Symlink => "lnk",
            InodeType::Fifo => "fifo",
            InodeType::CharDevice => "chr",
            InodeType::BlockDevice => "blk",
            InodeType::Socket => "sock",
        }
    }

    /// Whether an object of this type has data: a regular file the bytes
    /// it holds, a symbolic link its target and a directory a manifest of
    /// its own. Only such an object has a size, contents objects and a
    /// hash.
    pub const fn has_data(self) -> bool {
        matches!(self, InodeType::Regular | InodeType::Symlink | InodeType::Directory)
    }

    /// Whether this is a device node, which has a major and a minor
    /// number.
    pub const fn is_device(self) -> bool {
        matches!(self, InodeType::CharDevice | InodeType::BlockDevice)
    }
}

impl fmt::Display for InodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for InodeType {
    type Err = UnknownInodeType;

    fn from_str(name: &str) -> Result<InodeType, UnknownInodeType> {
        Ok(match name {
            "reg" => InodeType::Regular,
            "dir" => InodeType::Directory,
            "lnk" => InodeType::Symlink,
            "fifo" => InodeType::Fifo,
            "chr" => InodeType::CharDevice,
            "blk" => InodeType::BlockDevice,
            "sock" => InodeType::Socket,
            _ => return Err(UnknownInodeType(())),
        })
    }
}

/// The inode type of a file, from the file type its metadata gives.
///
/// ```
/// use uapi16::InodeType;
///
/// let metadata = std::fs::symlink_metadata("/")?;
/// assert_eq!(InodeType::try_from(metadata.file_type()), Ok(InodeType::Directory));
/// # Ok::<(), std::io::Error>(())
/// ```
impl TryFrom<fs::FileType> for InodeType {
    type Error = UnknownInodeType;

    fn try_from(file_type: fs::FileType) -> Result<InodeType, UnknownInodeType> {
        Ok(if file_type.is_file() {
            InodeType::Regular
        } else if file_type.is_dir() {
            InodeType::Directory
        } else if file_type.is_symlink() {
            InodeType::Symlink
        } else if file_type.is_fifo() {
            InodeType::Fifo
        } else if file_type.is_char_device() {
            InodeType::CharDevice
        } else if file_type.is_block_device() {
            InodeType::BlockDevice
        } else if file_type.is_socket() {
            InodeType::Socket
        } else {
            return Err(UnknownInodeType(()));
        })
    }
}

/// The access mode of a file object, its `mode` field: the permission
/// bits with the set-user-ID, the set-group-ID and the sticky bit.
///
/// ```
/// use uapi16::Mode;
///
/// let mode = Mode::new(0o644)?;
/// assert!(mode.is_writable());
/// assert!(!Mode::new(0o444)?.is_writable());
/// assert!(Mode::new(0o100644).is_err());
/// # Ok::<(), uapi16::InvalidMode>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Mode(u32);

/// Bits that are not a mode, see [`Mode::new`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidMode(());

impl fmt::Display for InvalidMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not the bits of a mode")
    }
}

impl std::error::Error for InvalidMode {}

impl Mode {
    /// Every bit a mode can have. The specification gives `mode` the range
    /// `0o0000` to `0o7777`: the permission bits, the set-user-ID, the
    /// set-group-ID and the sticky bit.
    const ALL: u32 = 0o7777;
    /// The three 'w' bits of the specification: the write permission of
    /// the owner, of the group and of everybody else.
    const WRITE: u32 = 0o222;

    /// The mode of the file mode `st_mode`: its permission bits with the
    /// set-user-ID, the set-group-ID and the sticky bit, without the bits
    /// of the file type.
    pub(crate) const fn from_st_mode(st_mode: u32) -> Mode {
        Mode(st_mode & Mode::ALL)
    }

    /// The mode with the bits `bits`. Bits that a mode does not have, such
    /// as those of the file type in an `st_mode`, fail.
    pub const fn new(bits: u32) -> Result<Mode, InvalidMode> {
        if bits & !Mode::ALL == 0 {
            Ok(Mode(bits))
        } else {
            Err(InvalidMode(()))
        }
    }

    /// The bits of the mode.
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Whether anybody has write permission.
    pub const fn is_writable(self) -> bool {
        self.0 & Mode::WRITE != 0
    }
}

impl From<Mode> for u32 {
    fn from(mode: Mode) -> u32 {
        mode.0
    }
}

impl fmt::Debug for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mode({:#o})", self.0)
    }
}

/// The `validity` field of a file object.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Validity {
    /// `good`, and any value the specification adds later.
    #[default]
    Good,
    /// `revoked`: the file is not to be used anymore.
    Revoked,
}

impl Validity {
    /// The value of `validity` that says this.
    pub const fn as_str(self) -> &'static str {
        match self {
            Validity::Good => "good",
            Validity::Revoked => "revoked",
        }
    }
}

impl fmt::Display for Validity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// When a file may be used: from `validSinceUSec` on and before
/// `validUntilUSec`, unless `validity` says it is revoked.
///
/// A file object and the root file object both have these fields. What is
/// true of a directory is true of everything in it, so the window of the
/// root file object is that of the whole manifest.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ValidityWindow {
    pub(crate) since_usec: u64,
    pub(crate) until_usec: Option<u64>,
    pub(crate) state: Validity,
}

impl ValidityWindow {
    /// `validSinceUSec`: the file is not to be used before this time, in
    /// microseconds since the epoch.
    pub fn since_usec(&self) -> u64 {
        self.since_usec
    }

    /// Sets `validSinceUSec`.
    pub fn set_since_usec(&mut self, since_usec: u64) {
        self.since_usec = since_usec;
    }

    /// `validUntilUSec`: the file is not to be used from this time on, in
    /// microseconds since the epoch.
    pub fn until_usec(&self) -> Option<u64> {
        self.until_usec
    }

    /// Sets `validUntilUSec`.
    pub fn set_until_usec(&mut self, until_usec: Option<u64>) {
        self.until_usec = until_usec;
    }

    /// `validity`: whether the file is revoked.
    pub fn state(&self) -> Validity {
        self.state
    }

    /// Sets `validity`.
    pub fn set_state(&mut self, state: Validity) {
        self.state = state;
    }

    /// Checks that what the window is of, which a message calls `subject`,
    /// may be used at the time `now_usec`, in microseconds since the epoch:
    /// that it is not revoked and that the time is inside the window.
    fn check(&self, now_usec: u64, subject: impl fmt::Display) -> Result<(), Error> {
        let (reason, state) = if self.state == Validity::Revoked {
            (ValidityProblem::Revoked, "is revoked")
        } else if now_usec < self.since_usec {
            (ValidityProblem::NotYetValid, "is not valid yet")
        } else if self.until_usec.is_some_and(|until| now_usec >= until) {
            (ValidityProblem::Expired, "has expired")
        } else {
            return Ok(());
        };
        Err(Error::new(
            ErrorKind::NotValid(reason),
            format!("{} {}", subject, state),
        ))
    }
}

/// A UUID, as the `fsUUID`, `gptUuid`, `gptTypeUuid` and `gptDiskUuid`
/// fields carry one.
///
/// It prints the way RFC 9562 writes it, in lower case. It parses from
/// that form in either case, from 32 hex digits without the hyphens, and
/// from both with `urn:uuid:` in front.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Uuid([u8; Uuid::SIZE]);

/// A string that is not a UUID.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidUuid(());

impl fmt::Display for InvalidUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a UUID")
    }
}

impl std::error::Error for InvalidUuid {}

impl Uuid {
    /// The size of a UUID in bytes.
    pub const SIZE: usize = 16;
    /// The bytes of the fields the text form writes as groups, which the
    /// hyphens separate. They are named after the fields of the time-based
    /// UUID, version 1 in RFC 9562, whose layout the text form follows.
    const TIME_LOW: usize = 4;
    const TIME_MID: usize = 2;
    const TIME_HIGH_AND_VERSION: usize = 2;
    const CLOCK_SEQ_AND_VARIANT: usize = 2;
    const NODE: usize = 6;
    const GROUPS: [usize; 5] = [
        Uuid::TIME_LOW,
        Uuid::TIME_MID,
        Uuid::TIME_HIGH_AND_VERSION,
        Uuid::CLOCK_SEQ_AND_VARIANT,
        Uuid::NODE,
    ];
    /// What separates the groups.
    const HYPHEN: u8 = b'-';
    /// What a UUID can have in front, in either case.
    const URN: &'static str = "urn:uuid:";
    /// The hex digits of one byte.
    const DIGITS_PER_BYTE: usize = 2;

    /// The UUID with the bytes `bytes`.
    pub const fn new(bytes: [u8; Uuid::SIZE]) -> Uuid {
        Uuid(bytes)
    }

    /// The bytes of the UUID.
    pub fn as_bytes(&self) -> &[u8; Uuid::SIZE] {
        &self.0
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut rest = &self.0[..];
        for (i, &group) in Uuid::GROUPS.iter().enumerate() {
            if i > 0 {
                fmt::Write::write_char(f, char::from(Uuid::HYPHEN))?;
            }
            let (bytes, tail) = rest.split_at(group);
            Hex(bytes).fmt(f)?;
            rest = tail;
        }
        Ok(())
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Uuid({})", self)
    }
}

impl FromStr for Uuid {
    type Err = InvalidUuid;

    fn from_str(text: &str) -> Result<Uuid, InvalidUuid> {
        // Compare bytes: the string comes from a manifest, and cutting it
        // at a byte offset could cut a character.
        let text = match text.as_bytes().split_at_checked(Uuid::URN.len()) {
            Some((urn, rest)) if urn.eq_ignore_ascii_case(Uuid::URN.as_bytes()) => rest,
            _ => text.as_bytes(),
        };
        let mut digits = [0u8; Uuid::SIZE * Uuid::DIGITS_PER_BYTE];
        let hyphens = Uuid::GROUPS.len() - 1;
        let hyphenated = text.len() == digits.len() + hyphens;
        if !hyphenated && text.len() != digits.len() {
            return Err(InvalidUuid(()));
        }
        // The digits without the hyphens between the groups. Anything else
        // that is not a hex digit fails to decode.
        let mut out = &mut digits[..];
        let mut rest = text;
        for (i, &group) in Uuid::GROUPS.iter().enumerate() {
            if hyphenated && i > 0 {
                rest = rest.strip_prefix(&[Uuid::HYPHEN]).ok_or(InvalidUuid(()))?;
            }
            let (hex, tail) = rest
                .split_at_checked(group * Uuid::DIGITS_PER_BYTE)
                .ok_or(InvalidUuid(()))?;
            let (group_digits, left) = out.split_at_mut(hex.len());
            group_digits.copy_from_slice(hex);
            out = left;
            rest = tail;
        }
        std::str::from_utf8(&digits)
            .ok()
            .and_then(Hex::decode_array)
            .map(Uuid)
            .ok_or(InvalidUuid(()))
    }
}

/// The `gpt` fields of a file object that describe a regular file as a
/// partition of a GPT partition table: those of its entry in the table.
///
/// `gptFlags` holds all attribute flags of the entry. `gptFlagNoAuto`,
/// `gptFlagGrowFileSystem` and `readOnly` give one of them each, and where
/// a flag is given both ways the two agree. Where the manifest lists the
/// feature of one of these fields, a regular file without the field has the
/// flags it gives cleared. A reader checks the fields against each other
/// that way and leaves them as the manifest has them: a regular file
/// without any `gpt` field has no `GptPartition`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct GptPartition {
    pub(crate) label: Option<String>,
    pub(crate) uuid: Option<Uuid>,
    pub(crate) type_uuid: Option<Uuid>,
    pub(crate) flags: Option<u64>,
    pub(crate) no_auto: Option<bool>,
    pub(crate) grow_file_system: Option<bool>,
}

impl GptPartition {
    /// The bits the flags of the Discoverable Partitions Specification
    /// have in the attribute flags.
    const NO_AUTO_BIT: u32 = 63;
    const READ_ONLY_BIT: u32 = 60;
    const GROW_FILE_SYSTEM_BIT: u32 = 59;
    /// The flag `gptFlagNoAuto` mirrors in `gptFlags`.
    pub const FLAG_NO_AUTO: u64 = 1 << GptPartition::NO_AUTO_BIT;
    /// The flag `readOnly` mirrors in `gptFlags`. It has no `gptFlag`
    /// field of its own.
    pub const FLAG_READ_ONLY: u64 = 1 << GptPartition::READ_ONLY_BIT;
    /// The flag `gptFlagGrowFileSystem` mirrors in `gptFlags`.
    pub const FLAG_GROW_FILE_SYSTEM: u64 = 1 << GptPartition::GROW_FILE_SYSTEM_BIT;
    /// The longest partition label, in UTF-16 units.
    pub const LABEL_MAX: usize = 36;

    /// `gptLabel`: the partition label, at most 36 UTF-16 units.
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Sets `gptLabel`.
    pub fn set_label(&mut self, label: Option<String>) {
        self.label = label;
    }

    /// `gptUuid`: the partition UUID.
    pub fn uuid(&self) -> Option<Uuid> {
        self.uuid
    }

    /// Sets `gptUuid`.
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) {
        self.uuid = uuid;
    }

    /// `gptTypeUuid`: the partition type UUID.
    pub fn type_uuid(&self) -> Option<Uuid> {
        self.type_uuid
    }

    /// Sets `gptTypeUuid`.
    pub fn set_type_uuid(&mut self, type_uuid: Option<Uuid>) {
        self.type_uuid = type_uuid;
    }

    /// `gptFlags`: the attribute flags of the partition entry.
    pub fn flags(&self) -> Option<u64> {
        self.flags
    }

    /// Sets `gptFlags`.
    pub fn set_flags(&mut self, flags: Option<u64>) {
        self.flags = flags;
    }

    /// `gptFlagNoAuto`: the flag of that name in the Discoverable
    /// Partitions Specification, [`GptPartition::FLAG_NO_AUTO`].
    pub fn no_auto(&self) -> Option<bool> {
        self.no_auto
    }

    /// Sets `gptFlagNoAuto`.
    pub fn set_no_auto(&mut self, no_auto: Option<bool>) {
        self.no_auto = no_auto;
    }

    /// `gptFlagGrowFileSystem`: the flag of that name in the Discoverable
    /// Partitions Specification, [`GptPartition::FLAG_GROW_FILE_SYSTEM`].
    pub fn grow_file_system(&self) -> Option<bool> {
        self.grow_file_system
    }

    /// Sets `gptFlagGrowFileSystem`.
    pub fn set_grow_file_system(&mut self, grow_file_system: Option<bool>) {
        self.grow_file_system = grow_file_system;
    }

    /// Whether any of the fields is set. Only a regular file describes a
    /// partition.
    pub fn describes_partition(&self) -> bool {
        self.label.is_some()
            || self.uuid.is_some()
            || self.type_uuid.is_some()
            || self.flags.is_some()
            || self.no_auto.is_some()
            || self.grow_file_system.is_some()
    }
}

/// A set of flags of one kind that the specification has a field for each:
/// [`DosFlags`] and [`InodeFlags`]. [`FlagStates`] says the states of the
/// flags of one kind.
pub(crate) trait FlagSet:
    Copy + Default + PartialEq + BitAnd<Output = Self> + BitOr<Output = Self> + Not<Output = Self> + 'static
{
    /// Every single flag with its field and the feature that records it, in
    /// the order of the names of the fields.
    const FIELDS: &'static [(Self, Field, Features)];

    /// The flag `field` is the field of.
    fn from_field(field: Field) -> Option<Self> {
        Self::FIELDS
            .iter()
            .find(|&&(_, of, _)| of == field)
            .map(|&(flag, _, _)| flag)
    }

    /// The flags an object of the type `inode_type` may have: every one on
    /// a regular file or a directory, none on any other file.
    fn permitted(inode_type: InodeType) -> Self {
        // The default is no flag, so its complement is every flag.
        let none = Self::default();
        match inode_type {
            InodeType::Regular | InodeType::Directory => !none,
            _ => none,
        }
    }

    /// The flags `features` records.
    fn recorded_by(features: Features) -> Self {
        Self::FIELDS
            .iter()
            .filter(|&&(_, _, feature)| features.contains(feature))
            .fold(Self::default(), |flags, &(flag, _, _)| flags | flag)
    }
}

/// What [`DosFlags`] and [`InodeFlags`] both have besides their flags:
/// `contains()`, `without()`, the operators of sets and a `Debug` that
/// lists the fields of the flags.
macro_rules! flag_set {
    ($flags:ident) => {
        impl $flags {
            /// Whether every flag of `flags` is among these.
            pub(crate) const fn contains(self, flags: $flags) -> bool {
                self.0 & flags.0 == flags.0
            }

            /// These flags without those of `flags`.
            #[must_use]
            pub(crate) const fn without(self, flags: $flags) -> $flags {
                $flags(self.0 & !flags.0)
            }
        }

        impl BitOr for $flags {
            type Output = $flags;

            fn bitor(self, other: $flags) -> $flags {
                $flags(self.0 | other.0)
            }
        }

        impl BitAnd for $flags {
            type Output = $flags;

            fn bitand(self, other: $flags) -> $flags {
                $flags(self.0 & other.0)
            }
        }

        impl Not for $flags {
            type Output = $flags;

            /// The flags of this kind that are not among these.
            fn not(self) -> $flags {
                $flags::ALL.without(self)
            }
        }

        impl fmt::Debug for $flags {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($flags), "("))?;
                let fields = $flags::FIELDS.iter().filter(|(flag, _, _)| self.contains(*flag));
                for (i, (_, field, _)) in fields.enumerate() {
                    if i > 0 {
                        f.write_str(" | ")?;
                    }
                    f.write_str(field.as_str())?;
                }
                f.write_str(")")
            }
        }
    };
}

/// The DOS attributes the specification has a field for, one each: hidden,
/// system and archive.
///
/// They are the attributes of FAT, of exFAT and of file systems like them.
/// The read-only attribute has no field of its own. `readOnly` stands for
/// it, see [`InodeAttributes::read_only()`]. Only regular files and
/// directories have DOS attributes, and the root directory has none: the
/// root directory of FAT has no directory entry to keep them in.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct DosFlags(u8);

impl DosFlags {
    /// `flagHidden`: the DOS attribute `ATTR_HIDDEN`.
    pub(crate) const HIDDEN: DosFlags = DosFlags(1 << 0);
    /// `flagSystem`: the DOS attribute `ATTR_SYSTEM`.
    pub(crate) const SYSTEM: DosFlags = DosFlags(1 << 1);
    /// `flagArchive`: the DOS attribute `ATTR_ARCHIVE`.
    pub(crate) const ARCHIVE: DosFlags = DosFlags(1 << 2);

    /// Every DOS attribute.
    pub(crate) const ALL: DosFlags = DosFlags(DosFlags::HIDDEN.0 | DosFlags::SYSTEM.0 | DosFlags::ARCHIVE.0);
}

impl FlagSet for DosFlags {
    const FIELDS: &'static [(DosFlags, Field, Features)] = &[
        (DosFlags::ARCHIVE, Field::FlagArchive, Features::FLAG_ARCHIVE),
        (DosFlags::HIDDEN, Field::FlagHidden, Features::FLAG_HIDDEN),
        (DosFlags::SYSTEM, Field::FlagSystem, Features::FLAG_SYSTEM),
    ];
}

flag_set!(DosFlags);

/// The Linux inode flags the specification has a field for, one each:
/// some of those `chattr(1)` changes.
///
/// Only regular files and directories have them, the root directory among
/// them.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub(crate) struct InodeFlags(u8);

impl InodeFlags {
    /// `flagAppendOnly`: the inode flag `FS_APPEND_FL`.
    pub(crate) const APPEND_ONLY: InodeFlags = InodeFlags(1 << 0);
    /// `flagImmutable`: the inode flag `FS_IMMUTABLE_FL`.
    pub(crate) const IMMUTABLE: InodeFlags = InodeFlags(1 << 1);
    /// `flagNoAtime`: the inode flag `FS_NOATIME_FL`.
    pub(crate) const NO_ATIME: InodeFlags = InodeFlags(1 << 2);
    /// `flagNoCow`: the inode flag `FS_NOCOW_FL`.
    pub(crate) const NO_COW: InodeFlags = InodeFlags(1 << 3);
    /// `flagNoDump`: the inode flag `FS_NODUMP_FL`.
    pub(crate) const NO_DUMP: InodeFlags = InodeFlags(1 << 4);

    /// Every inode flag.
    pub(crate) const ALL: InodeFlags = InodeFlags(
        InodeFlags::APPEND_ONLY.0
            | InodeFlags::IMMUTABLE.0
            | InodeFlags::NO_ATIME.0
            | InodeFlags::NO_COW.0
            | InodeFlags::NO_DUMP.0,
    );
}

impl FlagSet for InodeFlags {
    const FIELDS: &'static [(InodeFlags, Field, Features)] = &[
        (
            InodeFlags::APPEND_ONLY,
            Field::FlagAppendOnly,
            Features::FLAG_APPEND_ONLY,
        ),
        (InodeFlags::IMMUTABLE, Field::FlagImmutable, Features::FLAG_IMMUTABLE),
        (InodeFlags::NO_ATIME, Field::FlagNoAtime, Features::FLAG_NO_ATIME),
        (InodeFlags::NO_COW, Field::FlagNoCow, Features::FLAG_NO_COW),
        (InodeFlags::NO_DUMP, Field::FlagNoDump, Features::FLAG_NO_DUMP),
    ];
}

flag_set!(InodeFlags);

/// What an object says about the flags of one kind, [`DosFlags`] or
/// [`InodeFlags`]: which of them it states, which of those are set, and
/// which a reader filled in. Nothing is known about the others. The
/// objects give one getter and one setter for each flag, which go through
/// [`FlagStates::get`] and [`FlagStates::put`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct FlagStates<F> {
    /// The flags the object states.
    pub(crate) stated: F,
    /// Of those, the flags that are set. [`FlagStates::put`] keeps them
    /// among those it states.
    pub(crate) set: F,
    /// Of those stated, the flags a reader filled in, see [`FilledIn`].
    /// They are cleared, and the record of the object does not have them.
    pub(crate) filled: F,
}

impl<F: FlagSet> FlagStates<F> {
    /// Whether `flag` is set, cleared, or not known.
    pub(crate) fn get(self, flag: F) -> Option<bool> {
        ((self.stated & flag) == flag).then_some((self.set & flag) == flag)
    }

    /// States `flag` as set or cleared, or as not known. A flag a reader
    /// filled in is one the object states from then on.
    pub(crate) fn put(&mut self, flag: F, state: Option<bool>) {
        self.stated = self.stated & !flag;
        self.set = self.set & !flag;
        self.filled = self.filled & !flag;
        if let Some(set) = state {
            self.stated = self.stated | flag;
            if set {
                self.set = self.set | flag;
            }
        }
    }

    /// The flags the record of the object gives: those it states but a
    /// reader did not fill in.
    fn given(&self) -> F {
        self.stated & !self.filled
    }

    /// The fields of the flags the record of the object gives, each with
    /// the feature that records it.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        let given = self.given();
        F::FIELDS
            .iter()
            .filter(move |(flag, _, _)| (given & *flag) == *flag)
            .map(|&(_, field, feature)| (field, feature))
    }

    /// The field of the first flag the record gives that an object of the
    /// type `inode_type` cannot have. The flags given are held against those
    /// the type permits all at once, and the fields are only looked through
    /// to name the first flag that is not permitted.
    pub(crate) fn unpermitted_field(&self, inode_type: InodeType) -> Option<Field> {
        let unpermitted = self.given() & !F::permitted(inode_type);
        if unpermitted == F::default() {
            return None;
        }
        F::FIELDS
            .iter()
            .find(|&&(flag, _, _)| (unpermitted & flag) == flag)
            .map(|&(_, field, _)| field)
    }

    /// Fills in what `features`, which a manifest records, say about the
    /// flags an object of the type `inode_type` does not state: a flag the
    /// manifest records is cleared, and noted as filled in.
    pub(crate) fn fill_in(&mut self, features: Features, inode_type: InodeType) {
        let filled = F::recorded_by(features) & F::permitted(inode_type) & !self.stated;
        self.stated = self.stated | filled;
        self.filled = self.filled | filled;
    }

    /// The fields of the flags a reader filled in.
    pub(crate) fn filled_in(&self) -> FilledIn {
        F::FIELDS
            .iter()
            .filter(|&&(flag, _, _)| (self.filled & flag) == flag)
            .fold(FilledIn::default(), |mut filled_in, &(_, field, _)| {
                filled_in.insert(field);
                filled_in
            })
    }

    /// Whether `other` says the same of every flag: set, cleared or not
    /// known. Which flags a reader filled in does not count.
    pub(crate) fn eq_ignore_filled_in(&self, other: &FlagStates<F>) -> bool {
        // Every field is named, so that a new field breaks the build here
        // until it is compared.
        let FlagStates { stated, set, filled: _ } = self;
        *stated == other.stated && *set == other.set
    }
}

/// The fields of an object of a manifest that a reader filled in, which
/// the record of the object does not have: the sizes and hashes that
/// follow from other fields, `readOnly` and the flags, which are false
/// where the manifest records their features, and `extendedAttributes`,
/// which lists none where the manifest records `user-xattr`. A writer
/// leaves them out, and the checks of an object take a filled-in
/// `readOnly`, flag or `extendedAttributes` for one that is not there.
///
/// The `size`, the `sha256` and the DOS attributes of a [`FileObject`],
/// the sizes and hashes of a [`ContentsObject`] and the `readOnly`, the
/// inode flags and the `extendedAttributes` of [`InodeAttributes`] can be
/// filled in. [`FileObject::filled_in()`], [`ContentsObject::filled_in()`]
/// and [`InodeAttributes::filled_in()`] say which were.
///
/// A value that is set is not one a reader filled in. A value that the
/// sizes and hashes of the same object follow from also drops those that
/// a reader filled in when it is set: they are None then. These are the
/// size and the hash of a file object, and the sizes, the hashes, the
/// encoding and the source of a contents object. The next reader of the
/// manifest fills them in again. The contents objects of a file object
/// fill in again what follows from them when they are set, see
/// [`FileObject::set_contents`].
///
/// `==` of the objects compares these marks too. Equal objects are the
/// same record, and a writer writes or refuses them alike. An object with a
/// value a reader filled in is not equal to one with the same value set.
/// [`FileObject::eq_ignore_filled_in`], [`RootObject::eq_ignore_filled_in`],
/// [`InodeAttributes::eq_ignore_filled_in`] and
/// [`ContentsObject::eq_ignore_filled_in`] compare the values alone.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct FilledIn(u16);

impl FilledIn {
    /// The fields that can be filled in, in the order of their bits.
    const FIELDS: [Field; 16] = [
        Field::Size,
        Field::Sha256,
        Field::EncodedSize,
        Field::EncodedSha256,
        Field::OriginalSize,
        Field::OriginalSha256,
        Field::ReadOnly,
        Field::ExtendedAttributes,
        Field::FlagAppendOnly,
        Field::FlagArchive,
        Field::FlagHidden,
        Field::FlagImmutable,
        Field::FlagNoAtime,
        Field::FlagNoCow,
        Field::FlagNoDump,
        Field::FlagSystem,
    ];

    /// The bit of `field`, none for one that cannot be filled in.
    fn bit(field: Field) -> u16 {
        FilledIn::FIELDS
            .iter()
            .position(|&fillable| fillable == field)
            .map_or(0, |at| 1 << at)
    }

    /// Whether `field` was filled in.
    pub fn contains(self, field: Field) -> bool {
        self.0 & FilledIn::bit(field) != 0
    }

    /// Whether no field was filled in.
    pub fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The fields that were filled in.
    pub fn iter(self) -> impl Iterator<Item = Field> {
        FilledIn::FIELDS.into_iter().filter(move |&field| self.contains(field))
    }

    /// Notes that `field` was filled in, if it is one that can be.
    pub(crate) fn insert(&mut self, field: Field) {
        self.0 |= FilledIn::bit(field);
    }

    /// Notes that `field` was not filled in, for a value that was set
    /// since.
    pub(crate) fn remove(&mut self, field: Field) {
        self.0 &= !FilledIn::bit(field);
    }

    /// The fields that either this or `other` notes, such as those of an
    /// object and those of its inode attributes.
    pub(crate) const fn union(self, other: FilledIn) -> FilledIn {
        FilledIn(self.0 | other.0)
    }
}

impl fmt::Debug for FilledIn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FilledIn(")?;
        for (i, field) in self.iter().enumerate() {
            if i > 0 {
                f.write_str(" | ")?;
            }
            f.write_str(field.as_str())?;
        }
        f.write_str(")")
    }
}

/// The 32-bit volume serial number of a FAT or exFAT file system, the
/// field `fatSerial`. It is written as FAT tools show it: two groups of
/// four hexadecimal digits, the upper 16 bits first, `1234-ABCD`.
///
/// ```
/// use uapi16::FatSerial;
///
/// let serial: FatSerial = "1234-abcd".parse()?;
/// assert_eq!(serial, FatSerial::new(0x1234_abcd));
/// assert_eq!(serial.get(), 0x1234_abcd);
/// assert_eq!(serial.to_string(), "1234-ABCD");
/// # Ok::<(), uapi16::InvalidFatSerial>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct FatSerial(pub(crate) u32);

/// A string that is not a FAT volume serial number, see [`FatSerial`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidFatSerial(());

impl fmt::Display for InvalidFatSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a FAT volume serial number")
    }
}

impl std::error::Error for InvalidFatSerial {}

impl FatSerial {
    /// The hexadecimal digits of each group.
    const GROUP_DIGITS: usize = 4;
    /// The bits of each group.
    const GROUP_BITS: u32 = 16;
    /// What separates the groups.
    const SEPARATOR: char = '-';
    /// The radix of the digits.
    const HEX: u32 = 16;

    /// The serial number with the 32 bits `serial`.
    pub const fn new(serial: u32) -> FatSerial {
        FatSerial(serial)
    }

    /// The 32 bits of the serial number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The serial number the specification derives from a file system
    /// UUID: its first four bytes.
    pub fn from_uuid(uuid: &Uuid) -> FatSerial {
        let [a, b, c, d, ..] = *uuid.as_bytes();
        FatSerial(u32::from_be_bytes([a, b, c, d]))
    }
}

impl fmt::Debug for FatSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FatSerial({:#x})", self.0)
    }
}

impl fmt::Display for FatSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04X}{}{:04X}",
            self.0 >> FatSerial::GROUP_BITS,
            FatSerial::SEPARATOR,
            self.0 & u32::from(u16::MAX)
        )
    }
}

impl FromStr for FatSerial {
    type Err = InvalidFatSerial;

    fn from_str(text: &str) -> Result<FatSerial, InvalidFatSerial> {
        let group = |digits: &str| {
            // from_str_radix would also take a sign.
            if digits.len() != FatSerial::GROUP_DIGITS || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(InvalidFatSerial(()));
            }
            u32::from_str_radix(digits, FatSerial::HEX).map_err(|_| InvalidFatSerial(()))
        };
        let (upper, lower) = text.split_once(FatSerial::SEPARATOR).ok_or(InvalidFatSerial(()))?;
        Ok(FatSerial((group(upper)? << FatSerial::GROUP_BITS) | group(lower)?))
    }
}

/// The identity of the file system the file objects of a manifest are
/// placed in: the fields `fsUUID`, `fsLabel` and `fatSerial`, which only
/// the root file object has.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileSystemIdentity {
    pub(crate) uuid: Option<Uuid>,
    pub(crate) label: Option<String>,
    pub(crate) fat_serial: Option<FatSerial>,
}

impl FileSystemIdentity {
    /// `fsUUID`: the UUID of the file system.
    pub fn uuid(&self) -> Option<Uuid> {
        self.uuid
    }

    /// Sets `fsUUID`.
    pub fn set_uuid(&mut self, uuid: Option<Uuid>) {
        self.uuid = uuid;
    }

    /// `fsLabel`: the label of the file system, see
    /// [`FileSystemIdentity::is_valid_label`].
    pub fn label(&self) -> Option<&str> {
        self.label.as_deref()
    }

    /// Sets `fsLabel`.
    pub fn set_label(&mut self, label: Option<String>) {
        self.label = label;
    }

    /// `fatSerial`: the volume serial number of a FAT or exFAT file system.
    pub fn fat_serial(&self) -> Option<FatSerial> {
        self.fat_serial
    }

    /// Sets `fatSerial`.
    pub fn set_fat_serial(&mut self, fat_serial: Option<FatSerial>) {
        self.fat_serial = fat_serial;
    }

    /// Whether `label` can be the label of a file system in a manifest,
    /// in `fsLabel`: a string a manifest can have, without control
    /// characters. A file system can take less than that.
    ///
    /// ```
    /// use uapi16::FileSystemIdentity;
    ///
    /// assert!(FileSystemIdentity::is_valid_label("ESP"));
    /// assert!(FileSystemIdentity::is_valid_label("A.B \u{e9}"));
    /// assert!(!FileSystemIdentity::is_valid_label("a\tb"));
    /// assert!(!FileSystemIdentity::is_valid_label("a\u{fffe}"));
    /// ```
    pub fn is_valid_label(label: &str) -> bool {
        STRING_RULES.admits(label) && !label.chars().any(char::is_control)
    }

    /// Whether it says nothing.
    pub fn is_empty(&self) -> bool {
        self.uuid.is_none() && self.label.is_none() && self.fat_serial.is_none()
    }

    /// The volume serial number a FAT or exFAT file system takes from the
    /// identity, as the specification has it: `fatSerial`, or else the one
    /// derived from `fsUUID`, see [`FatSerial::from_uuid`].
    ///
    /// ```
    /// use uapi16::{FatSerial, FileSystemIdentity};
    ///
    /// let mut identity = FileSystemIdentity::default();
    /// identity.set_uuid("1234abcd-5678-4ef0-9abc-def012345678".parse().ok());
    /// assert_eq!(identity.volume_serial(), Some(FatSerial::new(0x1234_abcd)));
    /// identity.set_fat_serial(Some(FatSerial::new(0x5678_9abc)));
    /// assert_eq!(identity.volume_serial(), Some(FatSerial::new(0x5678_9abc)));
    /// ```
    pub fn volume_serial(&self) -> Option<FatSerial> {
        self.fat_serial.or_else(|| self.uuid.as_ref().map(FatSerial::from_uuid))
    }
}

/// The source of a contents object: where it says the data is. It names
/// at most one.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentsSource {
    /// Neither `file`, `url` nor `literal` is given: the data is in the
    /// file of the object's own name, next to the manifest.
    #[default]
    Implied,
    /// `file`: the data is in this file next to the manifest.
    File(NameBuf),
    /// `url`: the data is at this http or https URL.
    Url(String),
    /// `literal`: the data is in the manifest, and here.
    Literal(Vec<u8>),
}

/// A contents object: one place the data of a file object can be taken
/// from, and how it is stored there.
///
/// The data can be stored in an encoding, such as gzip. The encoded sizes
/// and hashes are those of the data as it is stored, the original ones
/// those of the decoded data. The file object's data is the part of the
/// decoded data that starts at `offset`.
///
/// `==` compares which values a reader filled in as well, see
/// [`FilledIn`]. [`ContentsObject::eq_ignore_filled_in`] compares the
/// values alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ContentsObject {
    pub(crate) source: ContentsSource,
    pub(crate) http_headers: Vec<(String, String)>,
    pub(crate) encoding: Option<String>,
    pub(crate) encoded_size: Option<u64>,
    pub(crate) encoded_sha256: Option<Sha256>,
    pub(crate) original_size: Option<u64>,
    pub(crate) original_sha256: Option<Sha256>,
    pub(crate) offset: u64,
    /// The sizes and hashes a reader filled in.
    pub(crate) filled_in: FilledIn,
}

impl ContentsObject {
    /// A contents object for data from the source `source`, stored as it
    /// is.
    pub fn new(source: ContentsSource) -> ContentsObject {
        ContentsObject {
            source,
            ..ContentsObject::default()
        }
    }

    /// The data the manifest carries itself, if this is where the data
    /// is.
    pub fn literal(&self) -> Option<&[u8]> {
        match &self.source {
            ContentsSource::Literal(data) => Some(data),
            _ => None,
        }
    }

    /// The file next to the manifest the data is in, if `file` names one.
    pub fn file(&self) -> Option<&Name> {
        match &self.source {
            ContentsSource::File(name) => Some(name),
            _ => None,
        }
    }

    /// The URL the data is at, if this is where the data is.
    pub fn url(&self) -> Option<&str> {
        match &self.source {
            ContentsSource::Url(url) => Some(url),
            _ => None,
        }
    }

    /// `file`, `url` or `literal`: where the data is.
    pub fn source(&self) -> &ContentsSource {
        &self.source
    }

    /// Sets `file`, `url` or `literal`, and drops what a reader filled in.
    pub fn set_source(&mut self, source: ContentsSource) {
        self.drop_filled_in();
        self.source = source;
    }

    /// `file`, `url` or `literal`, moved out of the contents object, such
    /// as the data of a literal.
    pub fn into_source(self) -> ContentsSource {
        self.source
    }

    /// `httpHeaders`: the header fields of the HTTP requests for the data
    /// at `url`, by name, in the order the manifest lists them.
    pub fn http_headers(&self) -> impl ExactSizeIterator<Item = (&str, &str)> {
        self.http_headers
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Sets `httpHeaders`.
    pub fn set_http_headers(&mut self, headers: Vec<(String, String)>) {
        self.http_headers = headers;
    }

    /// `encoding`: the HTTP content coding the data is stored in, in
    /// lower case. None is no encoding.
    pub fn encoding(&self) -> Option<&str> {
        self.encoding.as_deref()
    }

    /// Sets `encoding`, and drops what a reader filled in.
    pub fn set_encoding(&mut self, encoding: Option<String>) {
        self.drop_filled_in();
        self.encoding = encoding;
    }

    /// `encodedSize`: the size of the data as it is stored.
    pub fn encoded_size(&self) -> Option<u64> {
        self.encoded_size
    }

    /// Sets `encodedSize`, and drops what a reader filled in.
    pub fn set_encoded_size(&mut self, size: Option<u64>) {
        self.drop_filled_in();
        self.encoded_size = size;
    }

    /// `encodedSha256`: the hash of the data as it is stored.
    pub fn encoded_sha256(&self) -> Option<Sha256> {
        self.encoded_sha256
    }

    /// Sets `encodedSha256`, and drops what a reader filled in.
    pub fn set_encoded_sha256(&mut self, sha256: Option<Sha256>) {
        self.drop_filled_in();
        self.encoded_sha256 = sha256;
    }

    /// `originalSize`: the size of the decoded data.
    pub fn original_size(&self) -> Option<u64> {
        self.original_size
    }

    /// Sets `originalSize`, and drops what a reader filled in.
    pub fn set_original_size(&mut self, size: Option<u64>) {
        self.drop_filled_in();
        self.original_size = size;
    }

    /// `originalSha256`: the hash of the decoded data.
    pub fn original_sha256(&self) -> Option<Sha256> {
        self.original_sha256
    }

    /// Sets `originalSha256`, and drops what a reader filled in.
    pub fn set_original_sha256(&mut self, sha256: Option<Sha256>) {
        self.drop_filled_in();
        self.original_sha256 = sha256;
    }

    /// `offset`: where the file object's data starts in the decoded data.
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Sets `offset`.
    pub fn set_offset(&mut self, offset: u64) {
        self.offset = offset;
    }

    /// The sizes and hashes a reader filled in, see [`FilledIn`].
    pub fn filled_in(&self) -> FilledIn {
        self.filled_in
    }

    /// Whether `other` has the same values: what the getters return. Unlike
    /// `==` it leaves out which values a reader filled in, see
    /// [`FilledIn`].
    pub fn eq_ignore_filled_in(&self, other: &ContentsObject) -> bool {
        // Every field is named, so that a new field breaks the build here
        // until it is compared.
        let ContentsObject {
            source,
            http_headers,
            encoding,
            encoded_size,
            encoded_sha256,
            original_size,
            original_sha256,
            offset,
            filled_in: _,
        } = self;
        *source == other.source
            && *http_headers == other.http_headers
            && *encoding == other.encoding
            && *encoded_size == other.encoded_size
            && *encoded_sha256 == other.encoded_sha256
            && *original_size == other.original_size
            && *original_sha256 == other.original_sha256
            && *offset == other.offset
    }

    /// Drops the sizes and hashes a reader filled in, which follow from the
    /// other fields: they are None, and none is noted as filled in.
    fn drop_filled_in(&mut self) {
        let filled_in = std::mem::take(&mut self.filled_in);
        if filled_in.contains(Field::EncodedSize) {
            self.encoded_size = None;
        }
        if filled_in.contains(Field::EncodedSha256) {
            self.encoded_sha256 = None;
        }
        if filled_in.contains(Field::OriginalSize) {
            self.original_size = None;
        }
        if filled_in.contains(Field::OriginalSha256) {
            self.original_sha256 = None;
        }
    }
}

/// The inode attributes of a file: its access mode, its owner, its
/// modification time and extended attributes, whether it is read-only and
/// its Linux inode flags.
///
/// They are what a file is as an inode rather than as an entry of a
/// directory. A [`FileObject`] has them for its file and the
/// [`RootObject`] for the root directory. The specification calls them so
/// where a directory is described twice: by the file object of the
/// manifest it is in and by the root file object of a sub-manifest of its
/// own.
///
/// The Linux inode flags the specification has, some of those
/// `chattr(1)` changes, have a field each, such as `flagImmutable`. Only
/// regular files and directories have them, the root directory among
/// them.
///
/// `==` compares which values a reader filled in as well, see
/// [`FilledIn`]. [`InodeAttributes::eq_ignore_filled_in`] compares the
/// values alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct InodeAttributes {
    pub(crate) mode: Option<Mode>,
    pub(crate) uid: Option<u32>,
    pub(crate) gid: Option<u32>,
    pub(crate) user_name: Option<Box<str>>,
    pub(crate) group_name: Option<Box<str>>,
    pub(crate) mtime_nsec: Option<u64>,
    /// The extended attributes by their names. A map lists them all, so an
    /// empty one says the file has none. Few files have any, and the box
    /// keeps the attributes of the others small.
    #[allow(clippy::box_collection)]
    pub(crate) user_xattrs: Option<Box<BTreeMap<String, Vec<u8>>>>,
    pub(crate) read_only: Option<bool>,
    /// `flagAppendOnly` and the other fields of the inode flags: the
    /// flags the object states.
    pub(crate) flags: FlagStates<InodeFlags>,
    /// `readOnly` and `extendedAttributes`, where a reader filled them in.
    /// `flags` notes the inode flags a reader filled in.
    pub(crate) filled_in: FilledIn,
}

impl InodeAttributes {
    /// The fields of the inode attributes that belong to a feature, each
    /// with its feature, in the order of their names. The fields of the
    /// inode flags are in [`InodeFlags::FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 8] = [
        (Field::ExtendedAttributes, Features::USER_XATTR),
        (Field::Gid, Features::GID),
        (Field::GroupName, Features::GROUP_NAME),
        (Field::MTimeNSec, Features::MTIME),
        (Field::Mode, Features::MODE),
        (Field::ReadOnly, Features::READ_ONLY),
        (Field::Uid, Features::UID),
        (Field::UserName, Features::USER_NAME),
    ];

    /// Whether the attributes have `field`, one of
    /// [`InodeAttributes::FEATURE_FIELDS`].
    fn has_feature_field(&self, field: Field) -> bool {
        match field {
            Field::ExtendedAttributes => self.user_xattrs.is_some() && !self.filled_in.contains(field),
            Field::Gid => self.gid.is_some(),
            Field::GroupName => self.group_name.is_some(),
            Field::MTimeNSec => self.mtime_nsec.is_some(),
            Field::Mode => self.mode.is_some(),
            Field::ReadOnly => self.stated_read_only().is_some(),
            Field::Uid => self.uid.is_some(),
            Field::UserName => self.user_name.is_some(),
            _ => false,
        }
    }

    /// The fields the attributes have that belong to a feature, each with
    /// its feature.
    fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        InodeAttributes::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.flags.feature_fields())
    }

    /// `readOnly` as the record of the object has it: None where a reader
    /// filled it in.
    pub(crate) fn stated_read_only(&self) -> Option<bool> {
        self.read_only.filter(|_| !self.filled_in.contains(Field::ReadOnly))
    }

    /// Fills in what `features`, which the manifest records, say about the
    /// attributes a file of the type `inode_type` does not have: an inode
    /// flag the manifest records is cleared, the file is not read-only if
    /// the manifest records `readOnly`, and it has no extended attributes
    /// if the manifest records them. Each is noted as filled in.
    fn fill_in(&mut self, features: Features, inode_type: InodeType) {
        self.flags.fill_in(features, inode_type);
        if features.contains(Features::READ_ONLY) && self.read_only.is_none() {
            self.read_only = Some(false);
            self.filled_in.insert(Field::ReadOnly);
        }
        if features.contains(Features::USER_XATTR) && self.user_xattrs.is_none() {
            self.user_xattrs = Some(Box::default());
            self.filled_in.insert(Field::ExtendedAttributes);
        }
    }

    /// `mode`: the access mode.
    pub fn mode(&self) -> Option<Mode> {
        self.mode
    }

    /// Sets `mode`.
    pub fn set_mode(&mut self, mode: Option<Mode>) {
        self.mode = mode;
    }

    /// `uid`: the owning user.
    pub fn uid(&self) -> Option<u32> {
        self.uid
    }

    /// Sets `uid`.
    pub fn set_uid(&mut self, uid: Option<u32>) {
        self.uid = uid;
    }

    /// `gid`: the owning group.
    pub fn gid(&self) -> Option<u32> {
        self.gid
    }

    /// Sets `gid`.
    pub fn set_gid(&mut self, gid: Option<u32>) {
        self.gid = gid;
    }

    /// `userName`: the name of the owning user.
    pub fn user_name(&self) -> Option<&str> {
        self.user_name.as_deref()
    }

    /// Sets `userName`.
    pub fn set_user_name(&mut self, name: Option<String>) {
        self.user_name = name.map(String::into_boxed_str);
    }

    /// `groupName`: the name of the owning group.
    pub fn group_name(&self) -> Option<&str> {
        self.group_name.as_deref()
    }

    /// Sets `groupName`.
    pub fn set_group_name(&mut self, name: Option<String>) {
        self.group_name = name.map(String::into_boxed_str);
    }

    /// `mTimeNSec`: the modification time in nanoseconds since the epoch,
    /// see [`InodeAttributes::mtime`].
    pub fn mtime_nsec(&self) -> Option<u64> {
        self.mtime_nsec
    }

    /// Sets `mTimeNSec`. Unlike [`InodeAttributes::set_mtime`] it can take
    /// the time away.
    pub fn set_mtime_nsec(&mut self, nsec: Option<u64>) {
        self.mtime_nsec = nsec;
    }

    /// `extendedAttributes`: the extended attributes of the `user`
    /// namespace, by their names without the `user.` in front, in the order
    /// of their names. None says nothing about them. Some lists them all,
    /// so where it lists none the file has none.
    pub fn user_xattrs(&self) -> Option<impl ExactSizeIterator<Item = (&str, &[u8])>> {
        let xattrs = self.user_xattrs.as_deref()?;
        Some(xattrs.iter().map(|(name, value)| (name.as_str(), value.as_slice())))
    }

    /// The value of the extended attribute of the `user` namespace whose
    /// name without the `user.` in front is `name`, if the attributes list
    /// it.
    pub fn user_xattr(&self, name: &str) -> Option<&[u8]> {
        self.user_xattrs.as_deref()?.get(name).map(Vec::as_slice)
    }

    /// Sets `extendedAttributes`, see [`InodeAttributes::user_xattrs`].
    pub fn set_user_xattrs(&mut self, xattrs: Option<BTreeMap<String, Vec<u8>>>) {
        self.filled_in.remove(Field::ExtendedAttributes);
        self.user_xattrs = xattrs.map(Box::new);
    }

    /// Sets the extended attribute of the `user` namespace whose name
    /// without the `user.` in front is `name` to `value`, and returns the
    /// value it had, like [`BTreeMap::insert`]. Attributes that said
    /// nothing about the extended attributes list this one alone then.
    pub fn insert_user_xattr(&mut self, name: impl Into<String>, value: impl Into<Vec<u8>>) -> Option<Vec<u8>> {
        self.filled_in.remove(Field::ExtendedAttributes);
        self.user_xattrs
            .get_or_insert_with(Box::default)
            .insert(name.into(), value.into())
    }

    /// Removes the extended attribute of the `user` namespace whose name
    /// without the `user.` in front is `name`, and returns its value, like
    /// [`BTreeMap::remove`].
    pub fn remove_user_xattr(&mut self, name: &str) -> Option<Vec<u8>> {
        self.filled_in.remove(Field::ExtendedAttributes);
        self.user_xattrs.as_deref_mut()?.remove(name)
    }

    /// `readOnly`: whether the file is read-only, see
    /// [`InodeAttributes::is_read_only`]. It stands for the read-only
    /// attribute of DOS and for [`GptPartition::FLAG_READ_ONLY`] too.
    pub fn read_only(&self) -> Option<bool> {
        self.read_only
    }

    /// Sets `readOnly`.
    pub fn set_read_only(&mut self, read_only: Option<bool>) {
        self.filled_in.remove(Field::ReadOnly);
        self.read_only = read_only;
    }

    /// `readOnly`, the inode flags and `extendedAttributes`, where a reader
    /// filled them in, see [`FilledIn`].
    pub fn filled_in(&self) -> FilledIn {
        self.filled_in.union(self.flags.filled_in())
    }

    /// Whether `other` has the same values: what the getters return. Unlike
    /// `==` it leaves out which values a reader filled in, see
    /// [`FilledIn`].
    pub fn eq_ignore_filled_in(&self, other: &InodeAttributes) -> bool {
        // Every field is named, so that a new field breaks the build here
        // until it is compared.
        let InodeAttributes {
            mode,
            uid,
            gid,
            user_name,
            group_name,
            mtime_nsec,
            user_xattrs,
            read_only,
            flags,
            filled_in: _,
        } = self;
        *mode == other.mode
            && *uid == other.uid
            && *gid == other.gid
            && *user_name == other.user_name
            && *group_name == other.group_name
            && *mtime_nsec == other.mtime_nsec
            && *user_xattrs == other.user_xattrs
            && *read_only == other.read_only
            && flags.eq_ignore_filled_in(&other.flags)
    }

    /// The modification time, if the attributes have one.
    pub fn mtime(&self) -> Option<SystemTime> {
        self.mtime_nsec.map(|nsec| UNIX_EPOCH + Duration::from_nanos(nsec))
    }

    /// Sets the modification time to `time`. `mTimeNSec` counts
    /// nanoseconds since the epoch in 64 bits, which ends in the year
    /// 2554. A time it cannot express leaves the attributes without one.
    pub fn set_mtime(&mut self, time: SystemTime) {
        self.mtime_nsec = time
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|since| u64::try_from(since.as_nanos()).ok());
    }

    /// Whether the file gets the read-only attribute in a file system with
    /// DOS attributes, such as FAT: what `readOnly` says, or else whether
    /// `mode` gives nobody write permission. Attributes with neither are
    /// not read-only.
    ///
    /// The specification lets `mode` stand in for `readOnly` for the DOS
    /// attribute only, and only where the manifest does not list the
    /// `read-only` feature. Where it lists it, an object without `readOnly`
    /// is not read-only, and a reader fills that in. The read-only flag of
    /// a GPT partition, [`GptPartition::FLAG_READ_ONLY`], is `readOnly`
    /// alone.
    pub fn is_read_only(&self) -> bool {
        match (self.read_only, self.mode) {
            (Some(read_only), _) => read_only,
            (None, Some(mode)) => !mode.is_writable(),
            (None, None) => false,
        }
    }

    /// `flagAppendOnly`: whether the inode flag `FS_APPEND_FL` is set. None
    /// says nothing about it.
    pub fn flag_append_only(&self) -> Option<bool> {
        self.flags.get(InodeFlags::APPEND_ONLY)
    }

    /// Sets `flagAppendOnly`: the inode flag `FS_APPEND_FL` is set, cleared, or
    /// not known.
    /// `Some(false)` needs a manifest that records `flag-append-only` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_append_only(&mut self, append_only: Option<bool>) {
        self.flags.put(InodeFlags::APPEND_ONLY, append_only);
    }

    /// `flagImmutable`: whether the inode flag `FS_IMMUTABLE_FL` is set. None
    /// says nothing about it.
    pub fn flag_immutable(&self) -> Option<bool> {
        self.flags.get(InodeFlags::IMMUTABLE)
    }

    /// Sets `flagImmutable`: the inode flag `FS_IMMUTABLE_FL` is set, cleared,
    /// or not known.
    /// `Some(false)` needs a manifest that records `flag-immutable` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_immutable(&mut self, immutable: Option<bool>) {
        self.flags.put(InodeFlags::IMMUTABLE, immutable);
    }

    /// `flagNoAtime`: whether the inode flag `FS_NOATIME_FL` is set. None says
    /// nothing about it.
    pub fn flag_no_atime(&self) -> Option<bool> {
        self.flags.get(InodeFlags::NO_ATIME)
    }

    /// Sets `flagNoAtime`: the inode flag `FS_NOATIME_FL` is set, cleared, or
    /// not known.
    /// `Some(false)` needs a manifest that records `flag-no-atime` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_no_atime(&mut self, no_atime: Option<bool>) {
        self.flags.put(InodeFlags::NO_ATIME, no_atime);
    }

    /// `flagNoCow`: whether the inode flag `FS_NOCOW_FL` is set. None says
    /// nothing about it.
    pub fn flag_no_cow(&self) -> Option<bool> {
        self.flags.get(InodeFlags::NO_COW)
    }

    /// Sets `flagNoCow`: the inode flag `FS_NOCOW_FL` is set, cleared, or not
    /// known.
    /// `Some(false)` needs a manifest that records `flag-no-cow` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_no_cow(&mut self, no_cow: Option<bool>) {
        self.flags.put(InodeFlags::NO_COW, no_cow);
    }

    /// `flagNoDump`: whether the inode flag `FS_NODUMP_FL` is set. None says
    /// nothing about it.
    pub fn flag_no_dump(&self) -> Option<bool> {
        self.flags.get(InodeFlags::NO_DUMP)
    }

    /// Sets `flagNoDump`: the inode flag `FS_NODUMP_FL` is set, cleared, or not
    /// known.
    /// `Some(false)` needs a manifest that records `flag-no-dump` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_no_dump(&mut self, no_dump: Option<bool>) {
        self.flags.put(InodeFlags::NO_DUMP, no_dump);
    }
}

/// A file object: what a manifest says about one file below its root.
///
/// Every field but the name and the type is optional. What the file is as
/// an inode, its access mode, owner, time and the like, is in
/// [`FileObject::inode()`], as it is for the root directory in the
/// [`RootObject`]. A reader fills in what follows from the other fields:
/// the size 0 for the hash of no data and that hash for the size 0, and
/// the size and the hash of a file whose contents object gives them. It
/// notes them, see [`FileObject::filled_in()`], and a writer leaves them
/// out.
///
/// The DOS attributes hidden, system and archive have a field each:
/// `flagHidden`, `flagSystem` and `flagArchive`. They are the attributes
/// of FAT, of exFAT and of file systems like them. The read-only attribute
/// has no field of its own. `readOnly` stands for it, see
/// [`InodeAttributes::read_only()`]. Only regular files and directories
/// have DOS attributes, and the root directory has none: the root
/// directory of FAT has no directory entry to keep them in.
///
/// `==` compares which values a reader filled in as well, see
/// [`FilledIn`]. [`FileObject::eq_ignore_filled_in`] compares the values
/// alone.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FileObject {
    pub(crate) name: NameBuf,
    pub(crate) inode_type: InodeType,
    pub(crate) size: Option<u64>,
    pub(crate) sha256: Option<Sha256>,
    pub(crate) contents: Vec<ContentsObject>,
    pub(crate) inode_token: Option<NonZeroU64>,
    pub(crate) major: Option<u64>,
    pub(crate) minor: Option<u64>,
    pub(crate) gpt: Option<Box<GptPartition>>,
    /// `flagHidden`, `flagSystem` and `flagArchive`: the DOS attributes the
    /// object states.
    pub(crate) dos_flags: FlagStates<DosFlags>,
    pub(crate) inode: InodeAttributes,
    pub(crate) validity: ValidityWindow,
    /// The size and the hash, where a reader filled them in. `dos_flags`
    /// notes the DOS attributes a reader filled in.
    pub(crate) filled_in: FilledIn,
}

impl FileObject {
    /// The fields of a file object that belong to a feature, each with its
    /// feature, in the order of their names. Those of the DOS attributes
    /// are in [`DosFlags::FIELDS`], those of the inode attributes in
    /// [`InodeAttributes::FEATURE_FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 12] = [
        (Field::Contents, Features::SYMLINK),
        (Field::GptFlagGrowFileSystem, Features::GPT_FLAG_GROW_FILE_SYSTEM),
        (Field::GptFlagNoAuto, Features::GPT_FLAG_NO_AUTO),
        (Field::GptFlags, Features::GPT_FLAGS),
        (Field::GptLabel, Features::GPT_LABEL),
        (Field::GptTypeUuid, Features::GPT_TYPE_UUID),
        (Field::GptUuid, Features::GPT_UUID),
        (Field::InodeToken, Features::HARDLINK),
        (Field::Major, Features::DEVICE),
        (Field::Minor, Features::DEVICE),
        (Field::Sha256, Features::SHA256),
        (Field::Size, Features::SIZE),
    ];

    /// A file object for the regular file `name` that says nothing else
    /// about it.
    pub fn new(name: NameBuf) -> FileObject {
        FileObject {
            name,
            inode_type: InodeType::Regular,
            size: None,
            sha256: None,
            contents: Vec::new(),
            inode_token: None,
            major: None,
            minor: None,
            gpt: None,
            dos_flags: FlagStates::default(),
            inode: InodeAttributes::default(),
            validity: ValidityWindow::default(),
            filled_in: FilledIn::default(),
        }
    }

    /// `name`: the path of the file below the root.
    pub fn name(&self) -> &Name {
        &self.name
    }

    /// Sets `name`.
    pub fn set_name(&mut self, name: NameBuf) {
        self.name = name;
    }

    /// The name, the object taken apart for it.
    pub fn into_name(self) -> NameBuf {
        self.name
    }

    /// `type`: the inode type. An object that does not say is a regular
    /// file.
    pub fn inode_type(&self) -> InodeType {
        self.inode_type
    }

    /// Sets `type`.
    pub fn set_inode_type(&mut self, inode_type: InodeType) {
        self.inode_type = inode_type;
    }

    /// `size`: the size of the data in bytes. For a symbolic link that is
    /// the length of its target, for a directory the size of the manifest
    /// of its own that `contents` refers to.
    pub fn size(&self) -> Option<u64> {
        self.size
    }

    /// Sets `size`, and drops what a reader filled in, see [`FilledIn`].
    pub fn set_size(&mut self, size: Option<u64>) {
        self.drop_filled_in();
        self.size = size;
    }

    /// `sha256`: the hash of the data.
    pub fn sha256(&self) -> Option<Sha256> {
        self.sha256
    }

    /// Sets `sha256`, and drops what a reader filled in, see [`FilledIn`].
    pub fn set_sha256(&mut self, sha256: Option<Sha256>) {
        self.drop_filled_in();
        self.sha256 = sha256;
    }

    /// `contents`: where the data can be taken from. A regular file without
    /// contents objects has its data in the file of its own name next to
    /// the manifest, see [`FileObject::data_location`].
    pub fn contents(&self) -> &[ContentsObject] {
        &self.contents
    }

    /// Sets `contents`, and fills in what follows from them as a reader
    /// does, see [`FilledIn`]: what each contents object says of its own
    /// data, and the size and the hash of the data of the file. Only a
    /// contents object a reader takes gives anything. Where one has a value
    /// a reader refuses, such as a URL that is neither http nor https, or
    /// fields that contradict each other, nothing is filled in for it, and
    /// the size and the hash of the file are not filled in either. What a
    /// reader filled in that no longer follows is dropped, and what the
    /// object states stays. A writer refuses an object whose fields
    /// contradict each other or that has such a value, and more than
    /// [`MAX_CONTENTS`] contents objects, for which nothing is filled in at
    /// all.
    ///
    /// [`MAX_CONTENTS`]: crate::MAX_CONTENTS
    pub fn set_contents(&mut self, contents: Vec<ContentsObject>) {
        self.drop_filled_in();
        self.contents = contents;
        self.fill_in_from_contents();
    }

    /// Takes `contents` out of the object, with the size and the hash a
    /// reader filled in, which follow from them. Set back with
    /// [`FileObject::set_contents`], they fill them in again.
    pub fn take_contents(&mut self) -> Vec<ContentsObject> {
        self.drop_filled_in();
        std::mem::take(&mut self.contents)
    }

    /// `inodeToken`: the objects that carry the same token are hard links
    /// to one file. None is a file of its own.
    pub fn inode_token(&self) -> Option<NonZeroU64> {
        self.inode_token
    }

    /// Sets `inodeToken`.
    pub fn set_inode_token(&mut self, token: Option<NonZeroU64>) {
        self.inode_token = token;
    }

    /// `major`: the major number of a device node.
    pub fn major(&self) -> Option<u64> {
        self.major
    }

    /// Sets `major`.
    pub fn set_major(&mut self, major: Option<u64>) {
        self.major = major;
    }

    /// `minor`: the minor number of a device node.
    pub fn minor(&self) -> Option<u64> {
        self.minor
    }

    /// Sets `minor`.
    pub fn set_minor(&mut self, minor: Option<u64>) {
        self.minor = minor;
    }

    /// The `gpt` fields, if the object describes a partition.
    pub fn gpt(&self) -> Option<&GptPartition> {
        self.gpt.as_deref()
    }

    /// The `gpt` fields to change in place. Nothing follows from them.
    pub fn gpt_mut(&mut self) -> Option<&mut GptPartition> {
        self.gpt.as_deref_mut()
    }

    /// Sets the `gpt` fields.
    pub fn set_gpt(&mut self, gpt: Option<GptPartition>) {
        self.gpt = gpt.map(Box::new);
    }

    /// Takes the `gpt` fields out of the object.
    pub fn take_gpt(&mut self) -> Option<GptPartition> {
        self.gpt.take().map(|gpt| *gpt)
    }

    /// The inode attributes of the file.
    pub fn inode(&self) -> &InodeAttributes {
        &self.inode
    }

    /// The inode attributes of the file, to change them.
    pub fn inode_mut(&mut self) -> &mut InodeAttributes {
        &mut self.inode
    }

    /// `validSinceUSec`, `validUntilUSec` and `validity`: when the file may
    /// be used.
    pub fn validity(&self) -> ValidityWindow {
        self.validity
    }

    /// Sets `validSinceUSec`, `validUntilUSec` and `validity`.
    pub fn set_validity(&mut self, validity: ValidityWindow) {
        self.validity = validity;
    }

    /// What a reader filled in of the object: its size, its hash and its
    /// DOS attributes, and what [`InodeAttributes::filled_in()`] says of its
    /// inode attributes, see [`FilledIn`]. A writer leaves these out.
    pub fn filled_in(&self) -> FilledIn {
        self.filled_in
            .union(self.dos_flags.filled_in())
            .union(self.inode.filled_in())
    }

    /// Whether `other` has the same values: what the getters return, those
    /// of the contents objects and of the inode attributes among them.
    /// Unlike `==` it leaves out which values a reader filled in, see
    /// [`FilledIn`].
    ///
    /// ```
    /// use uapi16::{FileObject, NameBuf, Object, Reader, Sha256};
    ///
    /// let manifest = concat!(
    ///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n",
    ///     "\x1e{\"name\":\"e\",\"size\":0}\n",
    ///     "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
    /// );
    /// let mut reader = Reader::open(manifest.as_bytes())?;
    /// let Some(Object::File(read)) = reader.next().transpose()? else {
    ///     panic!("no file object");
    /// };
    /// // The reader filled in the hash of no data for the size 0.
    /// let mut set = FileObject::new(NameBuf::new("e")?);
    /// set.set_size(Some(0));
    /// set.set_sha256(Some(Sha256::EMPTY));
    /// assert!(read.eq_ignore_filled_in(&set));
    /// assert_ne!(*read, set);
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn eq_ignore_filled_in(&self, other: &FileObject) -> bool {
        // Every field is named, so that a new field breaks the build here
        // until it is compared.
        let FileObject {
            name,
            inode_type,
            size,
            sha256,
            contents,
            inode_token,
            major,
            minor,
            gpt,
            dos_flags,
            inode,
            validity,
            filled_in: _,
        } = self;
        *name == other.name
            && *inode_type == other.inode_type
            && *size == other.size
            && *sha256 == other.sha256
            && contents.len() == other.contents.len()
            && contents
                .iter()
                .zip(&other.contents)
                .all(|(contents, other)| contents.eq_ignore_filled_in(other))
            && *inode_token == other.inode_token
            && *major == other.major
            && *minor == other.minor
            && *gpt == other.gpt
            && dos_flags.eq_ignore_filled_in(&other.dos_flags)
            && inode.eq_ignore_filled_in(&other.inode)
            && *validity == other.validity
    }

    /// Drops the size and the hash a reader filled in, which follow from
    /// each other and from the contents objects: they are None, and
    /// neither is noted as filled in.
    fn drop_filled_in(&mut self) {
        let filled_in = std::mem::take(&mut self.filled_in);
        if filled_in.contains(Field::Size) {
            self.size = None;
        }
        if filled_in.contains(Field::Sha256) {
            self.sha256 = None;
        }
    }

    /// Whether the object has `field`, one of [`FileObject::FEATURE_FIELDS`],
    /// other than one a reader filled in. `contents` belongs to a feature on
    /// a symbolic link only.
    fn has_feature_field(&self, field: Field) -> bool {
        let gpt = self.gpt.as_deref();
        match field {
            Field::Contents => self.inode_type == InodeType::Symlink && !self.contents.is_empty(),
            Field::GptFlagGrowFileSystem => gpt.is_some_and(|gpt| gpt.grow_file_system.is_some()),
            Field::GptFlagNoAuto => gpt.is_some_and(|gpt| gpt.no_auto.is_some()),
            Field::GptFlags => gpt.is_some_and(|gpt| gpt.flags.is_some()),
            Field::GptLabel => gpt.is_some_and(|gpt| gpt.label.is_some()),
            Field::GptTypeUuid => gpt.is_some_and(|gpt| gpt.type_uuid.is_some()),
            Field::GptUuid => gpt.is_some_and(|gpt| gpt.uuid.is_some()),
            Field::InodeToken => self.inode_token.is_some(),
            Field::Major => self.major.is_some(),
            Field::Minor => self.minor.is_some(),
            Field::Sha256 => self.sha256.is_some() && !self.filled_in.contains(field),
            Field::Size => self.size.is_some() && !self.filled_in.contains(field),
            _ => false,
        }
    }

    /// The fields the object has that belong to a feature, each with its
    /// feature: the fields a manifest that does not record the feature
    /// cannot have. Its own come first, then those of its inode
    /// attributes.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        FileObject::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.dos_flags.feature_fields())
            .chain(self.inode.feature_fields())
    }

    /// The features whose fields the object has, see [`Features`]. A
    /// manifest records them all or the object is not one of its file
    /// objects. What a reader filled in, see [`FilledIn`], does not count.
    pub fn stated_features(&self) -> Features {
        self.feature_fields()
            .fold(Features::NONE, |features, (_, feature)| features | feature)
    }

    /// Fills in what `features`, which its manifest records, say about the
    /// fields the object does not have: a flag the manifest records is
    /// cleared, the file is not read-only if the manifest records
    /// `readOnly`, and it has no extended attributes if the manifest
    /// records them. The `gpt` fields are not filled in, see
    /// [`GptPartition`].
    pub(crate) fn fill_in(&mut self, features: Features) {
        self.dos_flags.fill_in(features, self.inode_type);
        self.inode.fill_in(features, self.inode_type);
    }

    /// The field of the first flag the object states that it cannot have:
    /// only regular files and directories have flags.
    pub(crate) fn unpermitted_flag(&self) -> Option<Field> {
        self.dos_flags
            .unpermitted_field(self.inode_type)
            .or_else(|| self.inode.flags.unpermitted_field(self.inode_type))
    }

    /// Checks that the object may be used at the time `now_usec`, in
    /// microseconds since the epoch: that it is not revoked and that the
    /// time is inside its validity window. What is true of a directory is
    /// true of everything in it, but the check looks at the object alone. A
    /// caller that uses an entry checks the objects of the directories it
    /// is in as well, which come before it in the manifest.
    pub fn check_validity(&self, now_usec: u64) -> Result<(), Error> {
        self.validity
            .check(now_usec, self.name.as_str().escape_debug())
            .map_err(|e| e.named(self.name.as_str()))
    }

    /// `flagArchive`: whether the DOS attribute `ATTR_ARCHIVE` is set. None
    /// says nothing about it.
    pub fn flag_archive(&self) -> Option<bool> {
        self.dos_flags.get(DosFlags::ARCHIVE)
    }

    /// Sets `flagArchive`: the DOS attribute `ATTR_ARCHIVE` is set, cleared, or
    /// not known.
    /// `Some(false)` needs a manifest that records `flag-archive` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_archive(&mut self, archive: Option<bool>) {
        self.dos_flags.put(DosFlags::ARCHIVE, archive);
    }

    /// `flagHidden`: whether the DOS attribute `ATTR_HIDDEN` is set. None says
    /// nothing about it.
    pub fn flag_hidden(&self) -> Option<bool> {
        self.dos_flags.get(DosFlags::HIDDEN)
    }

    /// Sets `flagHidden`: the DOS attribute `ATTR_HIDDEN` is set, cleared, or
    /// not known.
    /// `Some(false)` needs a manifest that records `flag-hidden` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_hidden(&mut self, hidden: Option<bool>) {
        self.dos_flags.put(DosFlags::HIDDEN, hidden);
    }

    /// `flagSystem`: whether the DOS attribute `ATTR_SYSTEM` is set. None says
    /// nothing about it.
    pub fn flag_system(&self) -> Option<bool> {
        self.dos_flags.get(DosFlags::SYSTEM)
    }

    /// Sets `flagSystem`: the DOS attribute `ATTR_SYSTEM` is set, cleared, or
    /// not known.
    /// `Some(false)` needs a manifest that records `flag-system` just as
    /// `Some(true)` does: a writer leaves a cleared flag out, and only the
    /// feature makes a missing field mean cleared.
    pub fn set_flag_system(&mut self, system: Option<bool>) {
        self.dos_flags.put(DosFlags::SYSTEM, system);
    }
}

/// The root file object: what a manifest says about the root directory of
/// the tree it describes, and about the manifest itself.
///
/// It is the first object of a manifest. It has no name and is a
/// directory, so neither is a field here. Like a [`FileObject`] it has the
/// inode attributes of its directory and a validity window, which is that
/// of the whole manifest. The other fields only the root file object has:
/// what the manifest records and the order it lists its file objects in,
/// and the identity of the file system or of the partition table the file
/// objects are placed in.
///
/// `==` compares which values a reader filled in as well, see
/// [`FilledIn`]. [`RootObject::eq_ignore_filled_in`] compares the values
/// alone.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RootObject {
    pub(crate) inode: InodeAttributes,
    pub(crate) file_system: FileSystemIdentity,
    pub(crate) gpt_disk_uuid: Option<Uuid>,
    pub(crate) order: Option<Order>,
    pub(crate) features: Option<Features>,
    pub(crate) validity: ValidityWindow,
}

impl RootObject {
    /// The fields of the root file object that belong to a feature, each
    /// with its feature, in the order of their names. Those of the inode
    /// attributes are in [`InodeAttributes::FEATURE_FIELDS`].
    const FEATURE_FIELDS: [(Field, Features); 4] = [
        (Field::FatSerial, Features::FAT_SERIAL),
        (Field::FsLabel, Features::FS_LABEL),
        (Field::FsUuid, Features::FS_UUID),
        (Field::GptDiskUuid, Features::GPT_DISK_UUID),
    ];

    /// The inode attributes of the root directory.
    pub fn inode(&self) -> &InodeAttributes {
        &self.inode
    }

    /// The inode attributes of the root directory, to change them.
    pub fn inode_mut(&mut self) -> &mut InodeAttributes {
        &mut self.inode
    }

    /// `fsUUID`, `fsLabel` and `fatSerial`: the identity of the file
    /// system the file objects are placed in.
    pub fn file_system(&self) -> &FileSystemIdentity {
        &self.file_system
    }

    /// The identity of the file system, to change it.
    pub fn file_system_mut(&mut self) -> &mut FileSystemIdentity {
        &mut self.file_system
    }

    /// `gptDiskUuid`: the disk UUID of the GPT partition table the file
    /// objects are placed in as partitions.
    pub fn gpt_disk_uuid(&self) -> Option<Uuid> {
        self.gpt_disk_uuid
    }

    /// Sets `gptDiskUuid`.
    pub fn set_gpt_disk_uuid(&mut self, uuid: Option<Uuid>) {
        self.gpt_disk_uuid = uuid;
    }

    /// `order`: the order the manifest lists its file objects in.
    pub fn order(&self) -> Option<Order> {
        self.order
    }

    /// Sets `order`.
    pub fn set_order(&mut self, order: Option<Order>) {
        self.order = order;
    }

    /// `features`: what the manifest records. None is
    /// [`Features::DEFAULT`].
    pub fn features(&self) -> Option<Features> {
        self.features
    }

    /// Sets `features`.
    pub fn set_features(&mut self, features: Option<Features>) {
        self.features = features;
    }

    /// `validSinceUSec`, `validUntilUSec` and `validity`: when the
    /// manifest may be used.
    pub fn validity(&self) -> ValidityWindow {
        self.validity
    }

    /// Sets `validSinceUSec`, `validUntilUSec` and `validity`.
    pub fn set_validity(&mut self, validity: ValidityWindow) {
        self.validity = validity;
    }

    /// Whether `other` has the same values: what the getters return, those
    /// of the inode attributes among them. Unlike `==` it leaves out which
    /// values a reader filled in, see [`FilledIn`].
    pub fn eq_ignore_filled_in(&self, other: &RootObject) -> bool {
        // Every field is named, so that a new field breaks the build here
        // until it is compared.
        let RootObject {
            inode,
            file_system,
            gpt_disk_uuid,
            order,
            features,
            validity,
        } = self;
        inode.eq_ignore_filled_in(&other.inode)
            && *file_system == other.file_system
            && *gpt_disk_uuid == other.gpt_disk_uuid
            && *order == other.order
            && *features == other.features
            && *validity == other.validity
    }

    /// Whether the object has `field`, one of
    /// [`RootObject::FEATURE_FIELDS`].
    fn has_feature_field(&self, field: Field) -> bool {
        match field {
            Field::FatSerial => self.file_system.fat_serial.is_some(),
            Field::FsLabel => self.file_system.label.is_some(),
            Field::FsUuid => self.file_system.uuid.is_some(),
            Field::GptDiskUuid => self.gpt_disk_uuid.is_some(),
            _ => false,
        }
    }

    /// The fields the object has that belong to a feature, each with its
    /// feature: the fields a manifest that does not record the feature
    /// cannot have. Its own come first, then those of its inode
    /// attributes.
    pub(crate) fn feature_fields(&self) -> impl Iterator<Item = (Field, Features)> + '_ {
        RootObject::FEATURE_FIELDS
            .into_iter()
            .filter(|(field, _)| self.has_feature_field(*field))
            .chain(self.inode.feature_fields())
    }

    /// The features whose fields the object has, see [`Features`]. A
    /// manifest records them all or this is not its root file object. What
    /// a reader filled in, see [`FilledIn`], does not count.
    pub fn stated_features(&self) -> Features {
        self.feature_fields()
            .fold(Features::NONE, |features, (_, feature)| features | feature)
    }

    /// What the manifest records: the features the root file object lists
    /// in `features`, or [`Features::DEFAULT`] if it lists none.
    pub fn recorded_features(&self) -> Features {
        self.features.unwrap_or(Features::DEFAULT)
    }

    /// Requires the manifest to declare `order` in its root file object, as
    /// a consumer does that relies on the order: a manifest that does not is
    /// [`Problem::NoOrder`], even if its file objects are in that order. A
    /// reader checks the file objects against the order the manifest
    /// declares while it reads them.
    pub fn require_order(&self, order: Order) -> Result<(), Error> {
        if self.order == Some(order) {
            return Ok(());
        }
        Err(Error::manifest(
            Problem::NoOrder,
            format!(
                "the manifest does not declare \"{}\": \"{}\" in its root file object",
                Field::Order,
                order
            ),
        )
        .at(Field::Order)
        .in_record(ROOT_RECORD))
    }

    /// Fills in what `features`, which the manifest records, say about the
    /// fields of the root directory the object does not have, as
    /// [`FileObject::fill_in`] does for a file object.
    pub(crate) fn fill_in(&mut self, features: Features) {
        self.inode.fill_in(features, InodeType::Directory);
    }

    /// Checks that the manifest may be used at the time `now_usec`, in
    /// microseconds since the epoch: that its root file object is not
    /// revoked and that the time is inside its validity window.
    pub fn check_validity(&self, now_usec: u64) -> Result<(), Error> {
        self.validity.check(now_usec, "the manifest")
    }
}

/// A signature object: a signature over the manifest up to the first
/// signature object.
///
/// A manifest can carry several. This crate reads them and does not
/// verify them.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SignatureObject {
    pub(crate) mechanism: String,
    pub(crate) key: Option<Vec<u8>>,
    pub(crate) data: Option<Vec<u8>>,
}

impl SignatureObject {
    /// A signature object of the mechanism `mechanism`, without a key
    /// and without data.
    pub fn new(mechanism: impl Into<String>) -> SignatureObject {
        SignatureObject {
            mechanism: mechanism.into(),
            key: None,
            data: None,
        }
    }

    /// `mechanism`: how the signature was made. The specification has
    /// `openpgp` and `pkcs7`.
    pub fn mechanism(&self) -> &str {
        &self.mechanism
    }

    /// Sets `mechanism`.
    pub fn set_mechanism(&mut self, mechanism: impl Into<String>) {
        self.mechanism = mechanism.into();
    }

    /// `key`: what identifies the key, such as its fingerprint.
    pub fn key(&self) -> Option<&[u8]> {
        self.key.as_deref()
    }

    /// Sets `key`.
    pub fn set_key(&mut self, key: Option<Vec<u8>>) {
        self.key = key;
    }

    /// `data`: the signature.
    pub fn data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Sets `data`.
    pub fn set_data(&mut self, data: Option<Vec<u8>>) {
        self.data = data;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Gives an object a field.
    type Give<T> = fn(&mut T);

    #[test]
    fn inode_types() {
        for (name, inode_type) in [
            ("reg", InodeType::Regular),
            ("dir", InodeType::Directory),
            ("lnk", InodeType::Symlink),
            ("fifo", InodeType::Fifo),
            ("chr", InodeType::CharDevice),
            ("blk", InodeType::BlockDevice),
            ("sock", InodeType::Socket),
        ] {
            assert_eq!(name.parse(), Ok(inode_type));
            assert_eq!(inode_type.as_str(), name);
            assert_eq!(inode_type.to_string(), name);
            assert_eq!(inode_type.has_data(), ["reg", "dir", "lnk"].contains(&name), "{}", name);
            assert_eq!(inode_type.is_device(), ["chr", "blk"].contains(&name), "{}", name);
        }
        for name in ["", "REG", "file", "symlink", "reg "] {
            assert!(name.parse::<InodeType>().is_err(), "{:?}", name);
        }
    }

    /// The types of file a test makes without help, and a device node every
    /// system has. FileObject::from_metadata() is tested with a FIFO as well.
    #[test]
    fn inode_types_of_files() {
        use crate::testing::TempDir;
        use std::os::unix::fs::symlink;
        use std::os::unix::net::UnixListener;

        let tmp = TempDir::new("inode-types");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"").unwrap();
        fs::create_dir(dir.join("dir")).unwrap();
        symlink("file", dir.join("link")).unwrap();
        let _socket = UnixListener::bind(dir.join("socket")).unwrap();
        for (path, inode_type) in [
            (dir.join("file"), InodeType::Regular),
            (dir.join("dir"), InodeType::Directory),
            (dir.join("link"), InodeType::Symlink),
            (dir.join("socket"), InodeType::Socket),
            ("/dev/null".into(), InodeType::CharDevice),
        ] {
            let file_type = fs::symlink_metadata(&path).unwrap().file_type();
            assert_eq!(InodeType::try_from(file_type), Ok(inode_type), "{}", path.display());
        }
    }

    #[test]
    fn modes() {
        for bits in [0, 0o644, 0o755, 0o4755, 0o7777] {
            let mode = Mode::new(bits).unwrap();
            assert_eq!(mode.bits(), bits);
            assert_eq!(u32::from(mode), bits);
        }
        assert_eq!(Mode::new(0o10000), Err(InvalidMode(())));
        assert_eq!(Mode::new(0o100644), Err(InvalidMode(())));
        assert_eq!(Mode::new(u32::MAX), Err(InvalidMode(())));
        for (bits, writable) in [
            (0o644, true),
            (0o444, false),
            (0o020, true),
            (0o002, true),
            (0o555, false),
            (0o7555, false),
            (0, false),
        ] {
            assert_eq!(Mode::new(bits).unwrap().is_writable(), writable, "{:o}", bits);
        }
        assert_eq!(format!("{:?}", Mode::new(0o644).unwrap()), "Mode(0o644)");
    }

    #[test]
    fn uuids() {
        let bytes = [
            0x4f, 0x68, 0xbc, 0xe3, 0xe8, 0xcd, 0x4d, 0xb1, 0x96, 0xe7, 0xfb, 0xca, 0xf9, 0x84, 0xb7, 0x09,
        ];
        // The groups of the text form are the whole UUID.
        assert_eq!(Uuid::GROUPS.iter().sum::<usize>(), Uuid::SIZE);
        let uuid = Uuid::new(bytes);
        let text = "4f68bce3-e8cd-4db1-96e7-fbcaf984b709";
        assert_eq!(uuid.to_string(), text);
        assert_eq!(format!("{:?}", uuid), format!("Uuid({})", text));
        assert_eq!(uuid.as_bytes(), &bytes);
        for spelling in [
            text.to_string(),
            text.to_uppercase(),
            text.replace('-', ""),
            format!("urn:uuid:{}", text),
            format!("URN:UUID:{}", text.to_uppercase()),
            format!("urn:uuid:{}", text.replace('-', "")),
        ] {
            assert_eq!(spelling.parse(), Ok(uuid), "{}", spelling);
        }
        for bad in [
            "",
            "not-a-uuid",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b7090",
            "4f68bce3e8cd-4db1-96e7-fbcaf984b709",
            "4f68bce3-e8cd-4db1-96e7fbcaf984b709-",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70g",
            "4f68bce3 e8cd 4db1 96e7 fbcaf984b709",
            "4f68bce3e8cd4db196e7fbcaf984b70 9",
            "{4f68bce3-e8cd-4db1-96e7-fbcaf984b709}",
            "urn:uuid:",
            "uuid:4f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            // Whitespace, a sign or a prefix where a digit belongs, at the
            // length of a UUID.
            "4f68bce3e8cd4db196e7fbcaf984b7 9",
            " f68bce3e8cd4db196e7fbcaf984b709",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b70\n",
            "4f68bce3-e8cd-4db1-96e7-\tbcaf984b709",
            "+f68bce3-e8cd-4db1-96e7-fbcaf984b709",
            "0x68bce3e8cd4db196e7fbcaf984b709",
            // Characters of more than one byte, where a cut by bytes
            // would fall inside one.
            "12345678\u{e9}",
            "\u{e9}\u{e9}\u{e9}\u{e9}\u{e9}",
            "4f68bce3-e8cd-4db1-96e7-fbcaf984b7\u{e9}",
        ] {
            assert!(bad.parse::<Uuid>().is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn fat_serials() {
        assert_eq!(format!("{:?}", FatSerial::new(0x1234_abcd)), "FatSerial(0x1234abcd)");
    }

    #[test]
    fn times() {
        let mut inode = InodeAttributes::default();
        assert_eq!(inode.mtime(), None);
        inode.set_mtime(UNIX_EPOCH);
        assert_eq!((inode.mtime_nsec, inode.mtime()), (Some(0), Some(UNIX_EPOCH)));
        let time = UNIX_EPOCH + Duration::new(1_700_000_000, 5);
        inode.set_mtime(time);
        assert_eq!(inode.mtime_nsec, Some(1_700_000_000_000_000_005));
        assert_eq!(inode.mtime(), Some(time));
        // mTimeNSec holds nanoseconds since the epoch in 64 bits: up to the
        // year 2554, and nothing before 1970.
        let last = UNIX_EPOCH + Duration::from_nanos(u64::MAX);
        inode.set_mtime(last);
        assert_eq!((inode.mtime_nsec, inode.mtime()), (Some(u64::MAX), Some(last)));
        inode.set_mtime(last + Duration::from_nanos(1));
        assert_eq!(inode.mtime_nsec, None);
        inode.set_mtime(UNIX_EPOCH - Duration::from_secs(1));
        assert_eq!(inode.mtime_nsec, None);
    }

    #[test]
    fn read_only() {
        let mut inode = InodeAttributes::default();
        assert!(!inode.is_read_only());
        inode.mode = Some(Mode::new(0o444).unwrap());
        assert!(inode.is_read_only());
        inode.mode = Some(Mode::new(0o464).unwrap());
        assert!(!inode.is_read_only());
        inode.read_only = Some(true);
        assert!(inode.is_read_only());
        inode.mode = None;
        assert!(inode.is_read_only());
        inode.read_only = Some(false);
        assert!(!inode.is_read_only());
        // What readOnly says counts, the false a reader fills in too.
        inode.mode = Some(Mode::new(0o444).unwrap());
        assert!(!inode.is_read_only());
    }

    #[test]
    fn validity() {
        assert_eq!(
            (Validity::Good.as_str(), Validity::Revoked.as_str()),
            ("good", "revoked")
        );
        assert_eq!(Validity::Revoked.to_string(), "revoked");
        assert_eq!(ValidityWindow::default().state, Validity::Good);
        let kind = |object: &FileObject, now| object.check_validity(now).map_err(|e| e.kind());
        let mut object = FileObject::new(NameBuf::new("d/x").unwrap());
        assert_eq!(kind(&object, 0), Ok(()));
        assert_eq!(kind(&object, u64::MAX), Ok(()));
        object.validity.since_usec = 10;
        object.validity.until_usec = Some(20);
        assert_eq!(kind(&object, 9), Err(ErrorKind::NotValid(ValidityProblem::NotYetValid)));
        assert_eq!(kind(&object, 10), Ok(()));
        assert_eq!(kind(&object, 19), Ok(()));
        assert_eq!(kind(&object, 20), Err(ErrorKind::NotValid(ValidityProblem::Expired)));
        let e = object.check_validity(20).unwrap_err();
        assert_eq!((e.name(), e.to_string().as_str()), (Some("d/x"), "d/x has expired"));
        assert_eq!(
            object.check_validity(9).unwrap_err().to_string(),
            "d/x is not valid yet"
        );
        // Revoked whatever the time is.
        object.validity.state = Validity::Revoked;
        for now in [9, 15, 20] {
            assert_eq!(kind(&object, now), Err(ErrorKind::NotValid(ValidityProblem::Revoked)));
        }
        assert_eq!(object.check_validity(15).unwrap_err().to_string(), "d/x is revoked");
        // The root file object speaks for the manifest, which has no name.
        let mut root = RootObject::default();
        assert_eq!(root.check_validity(u64::MAX).map_err(|e| e.kind()), Ok(()));
        root.validity.until_usec = Some(1);
        let e = root.check_validity(1).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotValid(ValidityProblem::Expired));
        assert_eq!((e.name(), e.to_string().as_str()), (None, "the manifest has expired"));
        root.validity.state = Validity::Revoked;
        assert_eq!(
            root.check_validity(0).unwrap_err().to_string(),
            "the manifest is revoked"
        );
    }

    #[test]
    fn flags() {
        // The tables are in the order of the names of the fields, and each
        // has every flag of its kind.
        let dos: Vec<&str> = DosFlags::FIELDS.iter().map(|(_, field, _)| field.as_str()).collect();
        let inode: Vec<&str> = InodeFlags::FIELDS.iter().map(|(_, field, _)| field.as_str()).collect();
        assert!(dos.windows(2).all(|pair| pair[0] < pair[1]), "{:?}", dos);
        assert!(inode.windows(2).all(|pair| pair[0] < pair[1]), "{:?}", inode);
        let every_dos = DosFlags::FIELDS
            .iter()
            .fold(DosFlags::default(), |every, (flag, _, _)| every | *flag);
        let every_inode = InodeFlags::FIELDS
            .iter()
            .fold(InodeFlags::default(), |every, (flag, _, _)| every | *flag);
        assert_eq!((every_dos, every_inode), (DosFlags::ALL, InodeFlags::ALL));
        // A field is the field of one kind of flags.
        assert!(dos.iter().all(|field| !inode.contains(field)));
        for &(flag, _, _) in DosFlags::FIELDS {
            assert_eq!((!flag & flag, !flag | flag), (DosFlags::default(), DosFlags::ALL));
        }
        for &(flag, _, _) in InodeFlags::FIELDS {
            assert_eq!((!flag & flag, !flag | flag), (InodeFlags::default(), InodeFlags::ALL));
        }
        assert_eq!(
            (!DosFlags::default(), !InodeFlags::ALL),
            (DosFlags::ALL, InodeFlags::default())
        );
        let flags = DosFlags::HIDDEN | DosFlags::ARCHIVE;
        assert!(flags.contains(DosFlags::ARCHIVE) && !flags.contains(DosFlags::ALL));
        assert_eq!(flags.without(DosFlags::ARCHIVE), DosFlags::HIDDEN);
        assert_eq!(format!("{:?}", flags), "DosFlags(flagArchive | flagHidden)");
        assert_eq!(
            format!("{:?}", InodeFlags::NO_COW | InodeFlags::APPEND_ONLY),
            "InodeFlags(flagAppendOnly | flagNoCow)"
        );
        assert_eq!(format!("{:?}", InodeFlags::default()), "InodeFlags()");
        // What an object says about the flags of one kind.
        let mut states = FlagStates::default();
        assert_eq!(states.get(InodeFlags::IMMUTABLE), None);
        states.put(InodeFlags::IMMUTABLE, Some(true));
        states.put(InodeFlags::NO_DUMP, Some(false));
        assert_eq!(states.get(InodeFlags::IMMUTABLE), Some(true));
        assert_eq!(states.get(InodeFlags::NO_DUMP), Some(false));
        assert_eq!(states.get(InodeFlags::NO_COW), None);
        assert_eq!(states.stated, InodeFlags::IMMUTABLE | InodeFlags::NO_DUMP);
        assert_eq!(states.set, InodeFlags::IMMUTABLE);
        states.put(InodeFlags::IMMUTABLE, Some(false));
        assert_eq!(states.get(InodeFlags::IMMUTABLE), Some(false));
        states.put(InodeFlags::IMMUTABLE, None);
        states.put(InodeFlags::NO_DUMP, None);
        assert_eq!(states, FlagStates::default());
    }

    /// Every flag has a getter and a setter of its own, for its field and
    /// no other.
    #[test]
    fn flag_accessors() {
        type Get<T> = fn(&T) -> Option<bool>;
        type Set<T> = fn(&mut T, Option<bool>);
        let inode: [(InodeFlags, Get<InodeAttributes>, Set<InodeAttributes>); 5] = [
            (
                InodeFlags::APPEND_ONLY,
                InodeAttributes::flag_append_only,
                InodeAttributes::set_flag_append_only,
            ),
            (
                InodeFlags::IMMUTABLE,
                InodeAttributes::flag_immutable,
                InodeAttributes::set_flag_immutable,
            ),
            (
                InodeFlags::NO_ATIME,
                InodeAttributes::flag_no_atime,
                InodeAttributes::set_flag_no_atime,
            ),
            (
                InodeFlags::NO_COW,
                InodeAttributes::flag_no_cow,
                InodeAttributes::set_flag_no_cow,
            ),
            (
                InodeFlags::NO_DUMP,
                InodeAttributes::flag_no_dump,
                InodeAttributes::set_flag_no_dump,
            ),
        ];
        let dos: [(DosFlags, Get<FileObject>, Set<FileObject>); 3] = [
            (
                DosFlags::ARCHIVE,
                FileObject::flag_archive,
                FileObject::set_flag_archive,
            ),
            (DosFlags::HIDDEN, FileObject::flag_hidden, FileObject::set_flag_hidden),
            (DosFlags::SYSTEM, FileObject::flag_system, FileObject::set_flag_system),
        ];
        // One pair for every field, in the order of the fields.
        let fields: Vec<InodeFlags> = InodeFlags::FIELDS.iter().map(|&(flag, _, _)| flag).collect();
        assert_eq!(inode.map(|(flag, _, _)| flag).to_vec(), fields);
        let fields: Vec<DosFlags> = DosFlags::FIELDS.iter().map(|&(flag, _, _)| flag).collect();
        assert_eq!(dos.map(|(flag, _, _)| flag).to_vec(), fields);
        for state in [Some(true), Some(false), None] {
            for (flag, get, set) in inode {
                let mut attributes = InodeAttributes::default();
                set(&mut attributes, state);
                assert_eq!(get(&attributes), state, "{:?}", flag);
                let stated = if state.is_some() { flag } else { InodeFlags::default() };
                assert_eq!(attributes.flags.stated, stated, "{:?}", flag);
                assert_eq!(attributes.flags.get(flag), state, "{:?}", flag);
            }
            for (flag, get, set) in dos {
                let mut object = FileObject::new(NameBuf::new("f").unwrap());
                set(&mut object, state);
                assert_eq!(get(&object), state, "{:?}", flag);
                let stated = if state.is_some() { flag } else { DosFlags::default() };
                assert_eq!(object.dos_flags.stated, stated, "{:?}", flag);
                assert_eq!(object.dos_flags.get(flag), state, "{:?}", flag);
            }
        }
    }

    #[test]
    fn features_of_the_fields() {
        const UUID: Uuid = Uuid::new([1; Uuid::SIZE]);
        // Every feature has a field, of a file object or of the root file
        // object, and every table is in the order of the names.
        let tables: [&[(Field, Features)]; 3] = [
            &InodeAttributes::FEATURE_FIELDS,
            &FileObject::FEATURE_FIELDS,
            &RootObject::FEATURE_FIELDS,
        ];
        for table in tables {
            assert!(
                table.windows(2).all(|pair| pair[0].0.as_str() < pair[1].0.as_str()),
                "{:?}",
                table
            );
        }
        let dos = DosFlags::FIELDS.iter().map(|&(_, field, feature)| (field, feature));
        let inode = InodeFlags::FIELDS.iter().map(|&(_, field, feature)| (field, feature));
        let every = tables
            .iter()
            .flat_map(|table| table.iter().copied())
            .chain(dos)
            .chain(inode)
            .fold(Features::NONE, |every, (_, feature)| every | feature);
        assert_eq!(every, Features::ALL);
        // A field makes a file object state its feature.
        assert_eq!(
            FileObject::new(NameBuf::new("f").unwrap()).stated_features(),
            Features::NONE
        );
        let partition = |set: Give<GptPartition>| {
            let mut gpt = GptPartition::default();
            set(&mut gpt);
            Some(Box::new(gpt))
        };
        let cases: [(Give<FileObject>, Features); 14] = [
            (|o| o.size = Some(1), Features::SIZE),
            (|o| o.sha256 = Some(Sha256::EMPTY), Features::SHA256),
            (|o| o.inode_token = NonZeroU64::new(1), Features::HARDLINK),
            (|o| o.major = Some(1), Features::DEVICE),
            (|o| o.minor = Some(1), Features::DEVICE),
            (
                |o| o.dos_flags.put(DosFlags::HIDDEN, Some(false)),
                Features::FLAG_HIDDEN,
            ),
            (|o| o.dos_flags.put(DosFlags::SYSTEM, Some(true)), Features::FLAG_SYSTEM),
            (
                |o| o.dos_flags.put(DosFlags::ARCHIVE, Some(true)),
                Features::FLAG_ARCHIVE,
            ),
            (|o| o.inode.mode = Some(Mode::new(0o644).unwrap()), Features::MODE),
            (|o| o.inode.uid = Some(0), Features::UID),
            (|o| o.inode.user_name = Some("u".into()), Features::USER_NAME),
            (|o| o.inode.mtime_nsec = Some(0), Features::MTIME),
            (|o| o.inode.user_xattrs = Some(Box::default()), Features::USER_XATTR),
            (|o| o.inode.read_only = Some(false), Features::READ_ONLY),
        ];
        for (set, feature) in cases {
            let mut object = FileObject::new(NameBuf::new("f").unwrap());
            set(&mut object);
            assert_eq!(object.stated_features(), feature, "{:?}", object);
        }
        let partitions: [(Give<GptPartition>, Features); 6] = [
            (|gpt| gpt.label = Some("l".into()), Features::GPT_LABEL),
            (|gpt| gpt.uuid = Some(UUID), Features::GPT_UUID),
            (|gpt| gpt.type_uuid = Some(UUID), Features::GPT_TYPE_UUID),
            (|gpt| gpt.flags = Some(0), Features::GPT_FLAGS),
            (|gpt| gpt.no_auto = Some(false), Features::GPT_FLAG_NO_AUTO),
            (
                |gpt| gpt.grow_file_system = Some(true),
                Features::GPT_FLAG_GROW_FILE_SYSTEM,
            ),
        ];
        for (set, feature) in partitions {
            let mut object = FileObject::new(NameBuf::new("f").unwrap());
            object.gpt = partition(set);
            assert_eq!(object.stated_features(), feature, "{:?}", object);
        }
        let mut object = FileObject::new(NameBuf::new("f").unwrap());
        (object.inode.gid, object.inode.group_name) = (Some(0), Some("g".into()));
        assert_eq!(object.stated_features(), Features::GID | Features::GROUP_NAME);
        for &(flag, _, feature) in InodeFlags::FIELDS {
            let mut object = FileObject::new(NameBuf::new("f").unwrap());
            object.inode.flags.put(flag, Some(true));
            assert_eq!(object.stated_features(), feature, "{:?}", flag);
        }
        // The contents of a symbolic link are its target, which a feature
        // records. Those of other files are not.
        let mut object = FileObject::new(NameBuf::new("f").unwrap());
        object.contents = vec![ContentsObject::new(ContentsSource::Literal(b"t".to_vec()))];
        assert_eq!(object.stated_features(), Features::NONE);
        object.inode_type = InodeType::Symlink;
        assert_eq!(object.stated_features(), Features::SYMLINK);
        // What a reader filled in does not count.
        let mut object = FileObject::new(NameBuf::new("f").unwrap());
        (object.size, object.sha256) = (Some(0), Some(Sha256::EMPTY));
        object.filled_in.insert(Field::Size);
        assert_eq!(object.stated_features(), Features::SHA256);
        object.filled_in.insert(Field::Sha256);
        assert_eq!(object.stated_features(), Features::NONE);
        // The fields of the root file object, its inode attributes among
        // them.
        assert_eq!(RootObject::default().stated_features(), Features::NONE);
        let cases: [(Give<RootObject>, Features); 6] = [
            (|r| r.file_system.uuid = Some(UUID), Features::FS_UUID),
            (|r| r.file_system.label = Some("ESP".into()), Features::FS_LABEL),
            (|r| r.file_system.fat_serial = Some(FatSerial(1)), Features::FAT_SERIAL),
            (|r| r.gpt_disk_uuid = Some(UUID), Features::GPT_DISK_UUID),
            (|r| r.inode.mtime_nsec = Some(0), Features::MTIME),
            (
                |r| r.inode.flags.put(InodeFlags::NO_COW, Some(false)),
                Features::FLAG_NO_COW,
            ),
        ];
        for (set, feature) in cases {
            let mut root = RootObject::default();
            set(&mut root);
            assert_eq!(root.stated_features(), feature, "{:?}", root);
        }
        // order and features describe the manifest, no feature records
        // them.
        let mut root = RootObject::default();
        (root.order, root.features) = (Some(Order::CodePoint), Some(Features::ALL));
        assert_eq!(root.stated_features(), Features::NONE);
    }

    #[test]
    fn contents_objects() {
        let contents = ContentsObject::default();
        assert_eq!(contents.source, ContentsSource::Implied);
        assert_eq!(
            (contents.literal(), contents.file(), contents.url()),
            (None, None, None)
        );
        let literal = ContentsObject::new(ContentsSource::Literal(b"data".to_vec()));
        assert_eq!(literal.literal(), Some(&b"data"[..]));
        assert_eq!((literal.file(), literal.url(), literal.offset), (None, None, 0));
        let file = ContentsObject::new(ContentsSource::File(NameBuf::new("blob").unwrap()));
        assert_eq!(file.file().map(Name::as_str), Some("blob"));
        let url = ContentsObject::new(ContentsSource::Url("https://example.com/x".to_string()));
        assert_eq!(url.url(), Some("https://example.com/x"));
    }

    /// The extended attributes and the HTTP header fields come out as they
    /// went in, the attributes in the order of their names.
    #[test]
    fn lists() {
        let mut inode = InodeAttributes::default();
        assert!(inode.user_xattrs().is_none());
        assert_eq!(inode.user_xattr("a"), None);
        inode.set_user_xattrs(Some(BTreeMap::from([
            ("b".to_string(), b"2".to_vec()),
            ("a".to_string(), Vec::new()),
        ])));
        let listed: Vec<(&str, &[u8])> = inode.user_xattrs().unwrap().collect();
        assert_eq!(listed, [("a", &b""[..]), ("b", &b"2"[..])]);
        assert_eq!(inode.user_xattrs().map(|xattrs| xattrs.len()), Some(2));
        assert_eq!((inode.user_xattr("b"), inode.user_xattr("c")), (Some(&b"2"[..]), None));
        // None of them, which says that the file has none.
        inode.set_user_xattrs(Some(BTreeMap::new()));
        assert_eq!(inode.user_xattrs().map(|xattrs| xattrs.len()), Some(0));
        let mut contents = ContentsObject::new(ContentsSource::Url("https://example.com/x".to_string()));
        contents.set_http_headers(vec![("X-B".into(), "2".into()), ("X-A".into(), "1".into())]);
        let headers: Vec<(&str, &str)> = contents.http_headers().collect();
        assert_eq!(headers, [("X-B", "2"), ("X-A", "1")]);
    }

    /// The fields of a partition change in place, and come out whole.
    #[test]
    fn gpt_in_place() {
        let mut object = FileObject::new(NameBuf::new("a").unwrap());
        assert!(object.gpt_mut().is_none());
        object.set_gpt(Some(GptPartition::default()));
        object.gpt_mut().unwrap().set_label(Some("esp".to_string()));
        assert_eq!(object.gpt().and_then(GptPartition::label), Some("esp"));
        let gpt = object.take_gpt().unwrap();
        assert_eq!((gpt.label(), object.gpt()), (Some("esp"), None));
    }

    /// A value that is set drops the sizes and hashes a reader filled in on
    /// the same object, and leaves the ones the record gives.
    #[test]
    fn setters_drop_what_a_reader_filled_in() {
        use crate::testing::{manifest, read_whole, record, sequence, EMPTY, HELLO, TRAILER};

        let read = |record: &str| read_whole(&manifest(&[record])).unwrap().objects.pop().unwrap();
        let hello: Option<Sha256> = HELLO.parse().ok();
        let none = FilledIn::default();
        // The size 0 a reader fills in for the hash of no data, and the
        // hash of no data for the size 0.
        let mut object = read(&format!(r#"{{"name":"a","sha256":"{}"}}"#, EMPTY));
        assert_eq!(
            (object.size(), object.filled_in().contains(Field::Size)),
            (Some(0), true)
        );
        object.set_sha256(hello);
        assert_eq!(
            (object.size(), object.sha256(), object.filled_in()),
            (None, hello, none)
        );
        assert_eq!(record(&object), format!(r#"{{"name":"a","sha256":"{}"}}"#, HELLO));
        let mut object = read(r#"{"name":"a","size":0}"#);
        assert!(object.filled_in().contains(Field::Sha256));
        object.set_size(Some(5));
        assert_eq!(
            (object.size(), object.sha256(), object.filled_in()),
            (Some(5), None, none)
        );
        // The size a contents object gives, which contents that are set
        // fill in again.
        let mut object = read(r#"{"name":"a","contents":[{"file":"blob","originalSize":3}]}"#);
        assert_eq!(object.size(), Some(3));
        let mut contents = object.take_contents();
        assert_eq!((object.size(), object.filled_in()), (None, none));
        contents[0].set_original_size(Some(7));
        object.set_contents(contents);
        assert_eq!(
            (
                object.size(),
                object.contents()[0].encoded_size(),
                object.filled_in().contains(Field::Size)
            ),
            (Some(7), Some(7), true)
        );
        // Contents that contradict the size the object states fill in
        // nothing, and the size stays.
        let mut object = read(r#"{"name":"a","size":3,"contents":[{"file":"blob","originalSize":3}]}"#);
        let mut contents = object.take_contents();
        contents[0].set_original_size(Some(7));
        object.set_contents(contents);
        assert_eq!((object.size(), object.filled_in()), (Some(3), none));
        // What the record gives stays.
        let mut object = read(&format!(r#"{{"name":"a","size":5,"sha256":"{}"}}"#, HELLO));
        object.set_size(Some(5));
        assert_eq!((object.size(), object.sha256()), (Some(5), hello));
        // Without an encoding the encoded size is the original size, and a
        // literal gives both.
        let object = read(r#"{"name":"a","contents":[{"file":"blob","originalSize":3}]}"#);
        let mut contents = object.contents()[0].clone();
        assert_eq!(contents.encoded_size(), Some(3));
        assert!(contents.filled_in().contains(Field::EncodedSize));
        contents.set_original_size(Some(7));
        assert_eq!(
            (contents.encoded_size(), contents.original_size(), contents.filled_in()),
            (None, Some(7), none)
        );
        let mut contents = object.contents()[0].clone();
        contents.set_encoding(Some("gzip".to_string()));
        assert_eq!((contents.encoded_size(), contents.original_size()), (None, Some(3)));
        let object = read(r#"{"name":"a","contents":[{"literal":"aGVsbG8="}]}"#);
        let mut contents = object.contents()[0].clone();
        assert_eq!((contents.encoded_size(), contents.original_size()), (Some(5), Some(5)));
        contents.set_source(ContentsSource::File(NameBuf::new("blob").unwrap()));
        assert_eq!(
            (contents.encoded_size(), contents.original_size(), contents.filled_in()),
            (None, None, none)
        );
        // readOnly, which the object notes with its own marks.
        let root = r#"{"features":["read-only"],"mediaType":"application/vnd.uapi.16.manifest"}"#;
        let whole = read_whole(&sequence(&[root, r#"{"name":"a"}"#, TRAILER])).unwrap();
        let mut object = whole.objects.into_iter().next().unwrap();
        assert_eq!(object.inode().read_only(), Some(false));
        assert!(object.filled_in().contains(Field::ReadOnly));
        object.inode_mut().set_read_only(Some(false));
        assert_eq!(object.inode().read_only(), Some(false));
        assert!(!object.filled_in().contains(Field::ReadOnly));
        // The flags and the extended attributes as well.
        let root = concat!(
            r#"{"features":["flag-hidden","flag-no-dump","user-xattr"],"#,
            r#""mediaType":"application/vnd.uapi.16.manifest"}"#
        );
        let whole = read_whole(&sequence(&[root, r#"{"name":"a"}"#, TRAILER])).unwrap();
        let mut object = whole.objects.into_iter().next().unwrap();
        let filled_in: Vec<Field> = object.filled_in().iter().collect();
        assert_eq!(
            filled_in,
            [Field::ExtendedAttributes, Field::FlagHidden, Field::FlagNoDump]
        );
        object.set_flag_hidden(Some(false));
        object.inode_mut().set_flag_no_dump(Some(false));
        object.inode_mut().set_user_xattrs(Some(BTreeMap::new()));
        assert!(object.filled_in().is_empty());
        assert_eq!(
            object.stated_features(),
            Features::FLAG_HIDDEN | Features::FLAG_NO_DUMP | Features::USER_XATTR
        );
        // One extended attribute at a time as well.
        let whole = read_whole(&sequence(&[root, r#"{"name":"a"}"#, TRAILER])).unwrap();
        let mut object = whole.objects.into_iter().next().unwrap();
        let inode = object.inode_mut();
        assert_eq!(inode.remove_user_xattr("comment"), None);
        assert!(!inode.filled_in().contains(Field::ExtendedAttributes));
        assert_eq!(inode.insert_user_xattr("comment", b"one"), None);
        assert_eq!(inode.insert_user_xattr("comment", b"two"), Some(b"one".to_vec()));
        assert_eq!(inode.remove_user_xattr("comment"), Some(b"two".to_vec()));
        assert_eq!(inode.user_xattrs().map(|xattrs| xattrs.len()), Some(0));
    }

    /// eq_ignore_filled_in() compares every value and none of the marks of
    /// what a reader filled in, which == compares too. The objects are built
    /// with every field named, so that a new field breaks the build here
    /// until it has a case below.
    #[test]
    fn compares_the_values_without_the_marks() {
        /// Checks that each of `changes`, which changes one value, makes an
        /// object differ from `object` for `eq`, both ways around.
        fn each_differs<T: Clone + fmt::Debug>(object: &T, changes: &[Give<T>], eq: fn(&T, &T) -> bool) {
            assert!(eq(object, object));
            for change in changes {
                let mut changed = object.clone();
                change(&mut changed);
                assert!(!eq(object, &changed) && !eq(&changed, object), "{:?}", changed);
            }
        }
        let contents = ContentsObject {
            source: ContentsSource::Literal(b"hello".to_vec()),
            http_headers: Vec::new(),
            encoding: None,
            encoded_size: Some(5),
            encoded_sha256: None,
            original_size: Some(5),
            original_sha256: None,
            offset: 0,
            filled_in: FilledIn::default(),
        };
        let inode = InodeAttributes {
            mode: Some(Mode::new(0o644).unwrap()),
            uid: Some(1),
            gid: Some(2),
            user_name: Some("u".into()),
            group_name: Some("g".into()),
            mtime_nsec: Some(3),
            user_xattrs: Some(Box::default()),
            read_only: Some(false),
            flags: FlagStates {
                stated: InodeFlags::IMMUTABLE | InodeFlags::NO_DUMP,
                set: InodeFlags::IMMUTABLE,
                filled: InodeFlags::default(),
            },
            filled_in: FilledIn::default(),
        };
        let object = FileObject {
            name: NameBuf::new("f").unwrap(),
            inode_type: InodeType::Regular,
            size: Some(5),
            sha256: Some(Sha256::digest(b"hello")),
            contents: vec![contents.clone()],
            inode_token: NonZeroU64::new(1),
            major: None,
            minor: None,
            gpt: None,
            dos_flags: FlagStates {
                stated: DosFlags::HIDDEN,
                set: DosFlags::default(),
                filled: DosFlags::default(),
            },
            inode: inode.clone(),
            validity: ValidityWindow::default(),
            filled_in: FilledIn::default(),
        };
        let root = RootObject {
            inode: inode.clone(),
            file_system: FileSystemIdentity::default(),
            gpt_disk_uuid: None,
            order: None,
            features: None,
            validity: ValidityWindow::default(),
        };
        each_differs(
            &contents,
            &[
                |c| c.source = ContentsSource::Url("https://example.com/x".into()),
                |c| c.http_headers = vec![("A".into(), "b".into())],
                |c| c.encoding = Some("gzip".into()),
                |c| c.encoded_size = None,
                |c| c.encoded_sha256 = Some(Sha256::EMPTY),
                |c| c.original_size = None,
                |c| c.original_sha256 = Some(Sha256::EMPTY),
                |c| c.offset = 1,
            ],
            ContentsObject::eq_ignore_filled_in,
        );
        each_differs(
            &inode,
            &[
                |i| i.mode = None,
                |i| i.uid = None,
                |i| i.gid = None,
                |i| i.user_name = None,
                |i| i.group_name = None,
                |i| i.mtime_nsec = None,
                |i| i.user_xattrs = None,
                |i| i.read_only = None,
                // A flag not known any more, and one set instead of cleared.
                |i| i.flags.put(InodeFlags::NO_DUMP, None),
                |i| i.flags.put(InodeFlags::NO_DUMP, Some(true)),
            ],
            InodeAttributes::eq_ignore_filled_in,
        );
        each_differs(
            &object,
            &[
                |o| o.name = NameBuf::new("g").unwrap(),
                |o| o.inode_type = InodeType::Symlink,
                |o| o.size = None,
                |o| o.sha256 = None,
                |o| o.contents.clear(),
                |o| o.contents[0].offset = 1,
                |o| o.inode_token = None,
                |o| o.major = Some(1),
                |o| o.minor = Some(1),
                |o| o.gpt = Some(Box::default()),
                |o| o.dos_flags.put(DosFlags::HIDDEN, None),
                |o| o.dos_flags.put(DosFlags::HIDDEN, Some(true)),
                |o| o.inode.uid = None,
                |o| o.validity.state = Validity::Revoked,
            ],
            FileObject::eq_ignore_filled_in,
        );
        each_differs(
            &root,
            &[
                |r| r.inode.uid = None,
                |r| r.file_system.label = Some("ESP".into()),
                |r| r.gpt_disk_uuid = Some(Uuid::new([1; Uuid::SIZE])),
                |r| r.order = Some(Order::CodePoint),
                |r| r.features = Some(Features::ALL),
                |r| r.validity.until_usec = Some(1),
            ],
            RootObject::eq_ignore_filled_in,
        );
        // The same values, filled in by a reader on one side and set on the
        // other.
        let mut filled = contents.clone();
        filled.filled_in.insert(Field::EncodedSize);
        assert!(filled.eq_ignore_filled_in(&contents) && filled != contents);
        let (mut filled, mut set) = (inode.clone(), inode.clone());
        filled.filled_in.insert(Field::ReadOnly);
        filled.filled_in.insert(Field::ExtendedAttributes);
        filled.flags.fill_in(Features::FLAG_NO_COW, InodeType::Regular);
        set.set_flag_no_cow(Some(false));
        assert!(filled.eq_ignore_filled_in(&set) && filled != set);
        let (mut filled, mut set) = (object.clone(), object.clone());
        filled.filled_in.insert(Field::Size);
        filled.contents[0].filled_in.insert(Field::OriginalSize);
        filled.inode.filled_in.insert(Field::ReadOnly);
        filled.dos_flags.fill_in(Features::FLAG_ARCHIVE, InodeType::Regular);
        set.set_flag_archive(Some(false));
        assert!(filled.eq_ignore_filled_in(&set) && filled != set);
        let mut filled = root.clone();
        filled.inode.filled_in.insert(Field::ExtendedAttributes);
        assert!(filled.eq_ignore_filled_in(&root) && filled != root);
    }
}
