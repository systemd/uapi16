// SPDX-License-Identifier: LGPL-2.1-or-later
//! The four ioctls of the manifest builder that rustix has no call for: the
//! DOS attributes of a file, the volume serial number of a FAT file system,
//! and the label and the UUID of any file system. Only the module sys calls
//! them.
//!
//! This module and the module nss have the unsafe code of the crate, but
//! for the one cast of the module name. An ioctl is whatever the driver
//! behind a descriptor makes of its number, and the kernel writes its
//! answer through a pointer of the caller. So three things are made sure of
//! here:
//!
//! - The ioctls only go to a regular file or a directory, which the
//!   descriptor is checked to be. Theirs go to the file system, where these
//!   four numbers mean what the headers of the kernel say or nothing at
//!   all, and not to the driver of a device.
//! - The value the kernel writes into is zeroed first, and is of a type
//!   that has no padding and takes any bytes. So it is a value whatever the
//!   kernel writes, and however much of it: xfs writes 13 of the 256 bytes
//!   of a label, ext4 17.
//! - What the kernel answered is checked before it is handed on: a label
//!   ends inside its buffer and is a string a manifest can hold, a UUID is
//!   16 bytes and not all zeroes, and of the DOS attributes only the bits
//!   that are read count.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::{c_void, CStr};
use std::os::fd::BorrowedFd;
use std::ptr;

use rustix::fs::FileType;
use rustix::io::Errno;
use rustix::ioctl::{self, opcode, Ioctl, IoctlOutput, Opcode};

use crate::object::{DosFlags, FatSerial, FileSystemIdentity, Uuid};

/// The group of the ioctls of FAT, include/uapi/linux/msdos_fs.h.
const FAT_GROUP: u8 = b'r';
/// The number of `FAT_IOCTL_GET_ATTRIBUTES` in its group.
const FAT_GET_ATTRIBUTES: u8 = 0x10;
/// The number of `FAT_IOCTL_GET_VOLUME_ID` in its group.
const FAT_GET_VOLUME_ID: u8 = 0x13;
/// The group of `FS_IOC_GETFSLABEL`, include/uapi/linux/fs.h, which took
/// the ioctl over from btrfs with its number.
const FSLABEL_GROUP: u8 = 0x94;
/// The number of `FS_IOC_GETFSLABEL` in its group.
const GET_FSLABEL: u8 = 49;
/// `FSLABEL_MAX`, include/uapi/linux/fs.h: the size of the buffer a label
/// is read into.
const FSLABEL_MAX: usize = 256;
/// The group of `FS_IOC_GETFSUUID`, include/uapi/linux/fs.h.
const FSUUID_GROUP: u8 = 0x15;
/// The number of `FS_IOC_GETFSUUID` in its group.
const GET_FSUUID: u8 = 0;
/// The size of `struct fsuuid2`, include/uapi/linux/fs.h: a byte that says
/// how many bytes the identifier of the file system has, and 16 bytes for
/// them.
const FSUUID2_SIZE: usize = 1 + Uuid::SIZE;

/// What the kernel fills in for an ioctl that reads.
///
/// # Safety
///
/// The type has no padding, and every pattern of bits is one of its values.
/// So a value of it that the kernel wrote any bytes into, all of them or
/// only some, is a value still.
unsafe trait Plain: Copy {
    /// The value of all zeroes, which the kernel writes into.
    const ZERO: Self;
}

// SAFETY: An integer has no padding, and every pattern of bits is one.
unsafe impl Plain for u32 {
    const ZERO: u32 = 0;
}

// SAFETY: A byte has no padding and an array of bytes none between them,
// and every pattern of bits is a byte.
unsafe impl<const SIZE: usize> Plain for [u8; SIZE] {
    const ZERO: [u8; SIZE] = [0; SIZE];
}

/// The ioctl `_IOR(GROUP, NUMBER, T)`: one that takes nothing, and that
/// writes a `T` at most through the pointer it is given. This is the `T` it
/// writes into.
struct Read<const GROUP: u8, const NUMBER: u8, T>(T);

/// `FAT_IOCTL_GET_ATTRIBUTES`, `_IOR('r', 0x10, __u32)`.
type FatGetAttributes = Read<FAT_GROUP, FAT_GET_ATTRIBUTES, u32>;
/// `FAT_IOCTL_GET_VOLUME_ID`, `_IOR('r', 0x13, __u32)`.
type FatGetVolumeId = Read<FAT_GROUP, FAT_GET_VOLUME_ID, u32>;
/// `FS_IOC_GETFSLABEL`, `_IOR(0x94, 49, char[FSLABEL_MAX])`.
type GetFsLabel = Read<FSLABEL_GROUP, GET_FSLABEL, [u8; FSLABEL_MAX]>;
/// `FS_IOC_GETFSUUID`, `_IOR(0x15, 0, struct fsuuid2)`. The struct is
/// bytes only, so an array of as many stands in for it.
type GetFsUuid = Read<FSUUID_GROUP, GET_FSUUID, [u8; FSUUID2_SIZE]>;

// SAFETY: What the trait asks for holds as follows.
// - as_ptr() gives a pointer to the `T` this value owns. It is valid for
//   writes of size_of::<T>() bytes and aligned for a `T` for as long as the
//   value is neither moved nor dropped, and rustix::ioctl::ioctl() does
//   neither between as_ptr() and output_from_ptr().
// - output_from_ptr() reads that `T` back through the pointer of as_ptr(),
//   and does so only after the call.
// - opcode() is `_IOR(GROUP, NUMBER, T)`, so the size the opcode carries
//   is that of the `T` the pointer leads to. The two cannot disagree.
// - IS_MUTATING is true: the kernel writes through the pointer.
// That the ioctl of this opcode writes no more than a `T` is up to whoever
// makes the call, see Read::call().
unsafe impl<const GROUP: u8, const NUMBER: u8, T: Plain> Ioctl for Read<GROUP, NUMBER, T> {
    type Output = T;

    const IS_MUTATING: bool = true;

    fn opcode(&self) -> Opcode {
        opcode::read::<T>(GROUP, NUMBER)
    }

    fn as_ptr(&mut self) -> *mut c_void {
        ptr::from_mut(&mut self.0).cast()
    }

    unsafe fn output_from_ptr(_: IoctlOutput, value: *mut c_void) -> rustix::io::Result<T> {
        // SAFETY: The caller passes the pointer as_ptr() returned for a
        // `Read` that is still alive, so it points to a `T`, is aligned for
        // one and nothing else reads or writes it now. That `T` was a value
        // before the call, the kernel wrote at most its size_of::<T>()
        // bytes, and a `Plain` type takes any bytes. So it is a value.
        Ok(unsafe { value.cast::<T>().read() })
    }
}

impl<const GROUP: u8, const NUMBER: u8, T: Plain> Read<GROUP, NUMBER, T> {
    /// Issues the ioctl on `fd` and returns what the kernel wrote, with
    /// zeroes wherever it wrote nothing.
    ///
    /// # Safety
    ///
    /// For the file `fd` refers to, the ioctl `_IOR(GROUP, NUMBER, T)` does
    /// nothing but write at most `size_of::<T>()` bytes through the pointer
    /// it is given, or fails.
    unsafe fn call(fd: BorrowedFd<'_>) -> rustix::io::Result<T> {
        // SAFETY: `Read` implements `Ioctl` as that trait asks, see there.
        // What the ioctl does to the memory of the process is what the
        // caller guarantees: it writes into the `T` of the `Read` and
        // nowhere else.
        unsafe { ioctl::ioctl(fd, Read::<GROUP, NUMBER, T>(T::ZERO)) }
    }
}

/// Checks that `fd` refers to a regular file or a directory. The ioctls
/// of one go to its file system. Those of anything else go to a driver,
/// which can make something else of the same number, so on anything else
/// they fail here with ENOTTY, as an ioctl a file does not have, and are
/// not issued.
fn check_file_or_directory(fd: BorrowedFd<'_>) -> rustix::io::Result<()> {
    let stat = rustix::fs::fstat(fd)?;
    match FileType::from_raw_mode(stat.st_mode) {
        FileType::RegularFile | FileType::Directory => Ok(()),
        _ => Err(Errno::NOTTY),
    }
}

/// The DOS attributes of a file, as `FAT_IOCTL_GET_ATTRIBUTES` gives them:
/// the attribute byte of its directory entry. Only the four bits that are
/// read here count, whatever else the answer has.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct DosAttributes(u32);

impl DosAttributes {
    /// `ATTR_RO`, include/uapi/linux/msdos_fs.h: the file is read-only.
    const READ_ONLY: u32 = 0x01;
    /// `ATTR_HIDDEN`: the file is hidden.
    const HIDDEN: u32 = 0x02;
    /// `ATTR_SYS`: the file is a system file.
    const SYSTEM: u32 = 0x04;
    /// `ATTR_ARCH`: the file changed since it was archived.
    const ARCHIVE: u32 = 0x20;
    /// Each of the attributes that have a flag of their own in a manifest,
    /// with that flag.
    const FLAGS: [(u32, DosFlags); 3] = [
        (DosAttributes::HIDDEN, DosFlags::HIDDEN),
        (DosAttributes::SYSTEM, DosFlags::SYSTEM),
        (DosAttributes::ARCHIVE, DosFlags::ARCHIVE),
    ];

    /// The attributes of the answer `raw` of the kernel.
    pub(crate) fn from_raw(raw: u32) -> DosAttributes {
        DosAttributes(raw)
    }

    /// Whether the read-only attribute is set.
    pub(crate) fn is_read_only(self) -> bool {
        self.0 & DosAttributes::READ_ONLY != 0
    }

    /// The attributes hidden, system and archive that are set.
    pub(crate) fn flags(self) -> DosFlags {
        DosAttributes::FLAGS
            .into_iter()
            .filter(|(attribute, _)| self.0 & attribute != 0)
            .fold(DosFlags::default(), |flags, (_, flag)| flags | flag)
    }
}

/// The label of a file system, as `FS_IOC_GETFSLABEL` gives it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FsLabel {
    /// The file system has no label: its label is empty.
    Empty,
    /// The label, a string a manifest can hold.
    Label(String),
    /// A label a manifest cannot hold: it does not end inside the buffer
    /// of the ioctl, it is not UTF-8, or it has a control character or a
    /// noncharacter.
    Unwritable,
}

impl FsLabel {
    /// The label in the buffer `raw` the kernel wrote it into, which was
    /// zeroed before. The label ends at the first NUL.
    fn from_raw(raw: &[u8; FSLABEL_MAX]) -> FsLabel {
        let Ok(label) = CStr::from_bytes_until_nul(raw) else {
            return FsLabel::Unwritable;
        };
        match label.to_str() {
            Ok("") => FsLabel::Empty,
            Ok(label) if FileSystemIdentity::is_valid_label(label) => FsLabel::Label(label.to_owned()),
            _ => FsLabel::Unwritable,
        }
    }
}

/// What a file system identifies itself with, as `FS_IOC_GETFSUUID` gives
/// it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FsUuid {
    /// A UUID.
    Uuid(Uuid),
    /// The UUID of all zeroes, which is none.
    Null,
    /// Something of another size than a UUID, of this many bytes: the 4 of
    /// the volume serial number of FAT, the 8 of that of NTFS, or a size
    /// that `struct fsuuid2` has no room for.
    NotUuid(u8),
}

impl FsUuid {
    /// The identifier in the `struct fsuuid2` `raw` the kernel wrote, which
    /// was zeroed before: a size, and as many bytes.
    fn from_raw(raw: &[u8; FSUUID2_SIZE]) -> FsUuid {
        let [len, uuid @ ..] = *raw;
        if usize::from(len) != Uuid::SIZE {
            return FsUuid::NotUuid(len);
        }
        if uuid == [0; Uuid::SIZE] {
            return FsUuid::Null;
        }
        FsUuid::Uuid(Uuid::new(uuid))
    }
}

/// The DOS attributes of the regular file or the directory `fd` is open
/// on for reading. A file system that has none fails with ENOTTY.
pub(crate) fn dos_attributes(fd: BorrowedFd<'_>) -> rustix::io::Result<DosAttributes> {
    check_file_or_directory(fd)?;
    // SAFETY: `fd` is a regular file or a directory, so the ioctl goes to
    // its file system. include/uapi/linux/msdos_fs.h defines the opcode as
    // one that reads a `__u32`, which is the `u32` it is issued with. fat
    // and exfat answer it with put_user() of a `u32`, FUSE cuts what its
    // server answers to the size in the opcode, and a file system that
    // does not know the opcode fails without writing.
    unsafe { FatGetAttributes::call(fd) }.map(DosAttributes::from_raw)
}

/// The volume serial number of the FAT file system the regular file or the
/// directory `fd` is open on for reading is in. Any other file system fails
/// with ENOTTY.
pub(crate) fn fat_serial(fd: BorrowedFd<'_>) -> rustix::io::Result<FatSerial> {
    check_file_or_directory(fd)?;
    // SAFETY: As for the DOS attributes: the opcode reads a `__u32`, fat
    // answers it with put_user() of a `u32`, and every bit pattern is a
    // serial number.
    unsafe { FatGetVolumeId::call(fd) }.map(FatSerial::new)
}

/// The label of the file system the regular file or the directory `fd` is
/// open on for reading is in. A file system that cannot say fails with
/// ENOTTY.
pub(crate) fn fs_label(fd: BorrowedFd<'_>) -> rustix::io::Result<FsLabel> {
    check_file_or_directory(fd)?;
    // SAFETY: `fd` is a regular file or a directory. include/uapi/linux/fs.h
    // defines the opcode as one that reads a `char[FSLABEL_MAX]`, and the
    // array it is issued with has FSLABEL_MAX bytes. A file system writes
    // its label and at most that many bytes, often fewer.
    let raw = unsafe { GetFsLabel::call(fd) }?;
    Ok(FsLabel::from_raw(&raw))
}

/// What the file system the regular file or the directory `fd` is open on
/// for reading is in identifies itself with. A file system without an
/// identifier fails with ENOTTY, and so does a kernel before Linux 6.9,
/// which does not have the ioctl.
pub(crate) fn fs_uuid(fd: BorrowedFd<'_>) -> rustix::io::Result<FsUuid> {
    check_file_or_directory(fd)?;
    // SAFETY: `fd` is a regular file or a directory. include/uapi/linux/fs.h
    // defines the opcode as one that reads a `struct fsuuid2`, 17 bytes
    // without padding, and the array it is issued with has as many. The
    // kernel answers it for every file system with copy_to_user() of one
    // such struct.
    let raw = unsafe { GetFsUuid::call(fd) }?;
    Ok(FsUuid::from_raw(&raw))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;
    use rustix::fs::{Mode, OFlags, CWD};
    use std::fs::{self, File};
    use std::os::fd::AsFd;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    /// The four opcodes are the numbers the headers of the kernel give
    /// them. Most architectures put the direction into the upper two bits.
    /// powerpc, sparc and mips put it into the upper three, with other
    /// values. The type of an opcode differs between the targets, and so
    /// does whether it has a sign, so its 32 bits are compared.
    #[test]
    fn opcodes() {
        let bits = |opcode: Opcode| i128::from(opcode) & i128::from(u32::MAX);
        let opcodes = [
            bits(FatGetAttributes::opcode(&Read(0))),
            bits(FatGetVolumeId::opcode(&Read(0))),
            bits(GetFsLabel::opcode(&Read([0; FSLABEL_MAX]))),
            bits(GetFsUuid::opcode(&Read([0; FSUUID2_SIZE]))),
        ];
        let expected: [i128; 4] = if cfg!(any(
            target_arch = "powerpc",
            target_arch = "powerpc64",
            target_arch = "sparc",
            target_arch = "sparc64",
            target_arch = "mips",
            target_arch = "mips64"
        )) {
            [0x4004_7210, 0x4004_7213, 0x4100_9431, 0x4011_1500]
        } else {
            [0x8004_7210, 0x8004_7213, 0x8100_9431, 0x8011_1500]
        };
        assert_eq!(opcodes, expected);
        assert_eq!(FSUUID2_SIZE, 17);
    }

    /// Of the DOS attributes only the four bits that are read count: the
    /// attributes for a directory and for a volume label that FAT has next
    /// to them do not, nor does anything above the attribute byte.
    #[test]
    fn dos_attributes_are_the_bits_that_are_read() {
        let none = DosAttributes::from_raw(0);
        assert!(!none.is_read_only());
        assert_eq!(none.flags(), DosFlags::default());
        let cases = [
            (0x01, true, DosFlags::default()),
            (0x02, false, DosFlags::HIDDEN),
            (0x04, false, DosFlags::SYSTEM),
            (0x20, false, DosFlags::ARCHIVE),
            (0x27, true, DosFlags::ALL),
            (0x08 | 0x10 | 0x40 | 0x80, false, DosFlags::default()),
            (0xffff_ff00, false, DosFlags::default()),
            (u32::MAX, true, DosFlags::ALL),
            (0x10 | 0x20, false, DosFlags::ARCHIVE),
        ];
        for (raw, read_only, flags) in cases {
            let attributes = DosAttributes::from_raw(raw);
            assert_eq!(attributes.is_read_only(), read_only, "{:#x}", raw);
            assert_eq!(attributes.flags(), flags, "{:#x}", raw);
        }
    }

    /// A label is what comes before the first NUL of the buffer. Without a
    /// NUL in the buffer it has no end, and a manifest holds it only if it
    /// is a string without control characters and noncharacters.
    #[test]
    fn labels() {
        let label = |text: &[u8]| {
            let mut raw = [0; FSLABEL_MAX];
            raw[..text.len()].copy_from_slice(text);
            FsLabel::from_raw(&raw)
        };
        assert_eq!(label(b""), FsLabel::Empty);
        assert_eq!(label(b"ESP"), FsLabel::Label("ESP".into()));
        assert_eq!(
            label("r\u{f6}\u{f6}t \u{221e}".as_bytes()),
            FsLabel::Label("r\u{f6}\u{f6}t \u{221e}".into())
        );
        // What follows the first NUL is not the label.
        assert_eq!(label(b"boot\0junk\xff"), FsLabel::Label("boot".into()));
        assert_eq!(label(b"\0junk"), FsLabel::Empty);
        // The longest label that ends inside the buffer, and one that fills
        // it.
        assert_eq!(
            label(&[b'a'; FSLABEL_MAX - 1]),
            FsLabel::Label("a".repeat(FSLABEL_MAX - 1))
        );
        assert_eq!(label(&[b'a'; FSLABEL_MAX]), FsLabel::Unwritable);
        for text in [&b"a\xffb"[..], b"\xc3", b"a\tb", b"a\nb", b"\x7f", b"\x1b[0m"] {
            assert_eq!(label(text), FsLabel::Unwritable, "{:?}", text);
        }
        assert_eq!(label("a\u{fffe}".as_bytes()), FsLabel::Unwritable);
        assert_eq!(label("\u{fdd0}".as_bytes()), FsLabel::Unwritable);
    }

    /// Only 16 bytes that are not all zeroes are a UUID.
    #[test]
    fn uuids() {
        let identifier = |len: u8, bytes: [u8; Uuid::SIZE]| {
            let mut raw = [0; FSUUID2_SIZE];
            raw[0] = len;
            raw[1..].copy_from_slice(&bytes);
            FsUuid::from_raw(&raw)
        };
        let bytes: [u8; Uuid::SIZE] = std::array::from_fn(|i| i as u8 + 1);
        assert_eq!(identifier(16, bytes), FsUuid::Uuid(Uuid::new(bytes)));
        assert_eq!(identifier(16, [0; Uuid::SIZE]), FsUuid::Null);
        let mut last = [0; Uuid::SIZE];
        last[Uuid::SIZE - 1] = 1;
        assert_eq!(identifier(16, last), FsUuid::Uuid(Uuid::new(last)));
        for len in [0, 4, 8, 15, 17, 32, u8::MAX] {
            assert_eq!(identifier(len, bytes), FsUuid::NotUuid(len), "{}", len);
        }
    }

    /// Opens `path` for reading without following a symbolic link.
    fn open(path: &Path, flags: OFlags) -> File {
        let flags = flags | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
        File::from(rustix::fs::open(path, flags, Mode::empty()).unwrap())
    }

    /// The ioctls are only issued on a regular file or a directory.
    /// Anything else fails with ENOTTY before that, also a handle, on which
    /// the kernel refuses every ioctl with EBADF.
    #[test]
    fn only_files_and_directories_are_asked() {
        let tmp = TempDir::new("ioctl-types");
        let dir = &tmp.0;
        symlink("target", dir.join("link")).unwrap();
        rustix::fs::mknodat(CWD, dir.join("fifo"), FileType::Fifo, Mode::RUSR | Mode::WUSR, 0).unwrap();
        let others = [
            open(&dir.join("link"), OFlags::PATH),
            open(&dir.join("fifo"), OFlags::PATH),
            open(&dir.join("fifo"), OFlags::RDONLY),
            open(Path::new("/dev/null"), OFlags::RDONLY),
        ];
        for file in &others {
            let fd = file.as_fd();
            assert_eq!(dos_attributes(fd), Err(Errno::NOTTY));
            assert_eq!(fat_serial(fd), Err(Errno::NOTTY));
            assert_eq!(fs_label(fd), Err(Errno::NOTTY));
            assert_eq!(fs_uuid(fd), Err(Errno::NOTTY));
        }
        // A handle of a directory is a directory, and the kernel refuses
        // the ioctl on it.
        let handle = open(dir, OFlags::PATH);
        assert_eq!(dos_attributes(handle.as_fd()), Err(Errno::BADF));
        assert_eq!(fs_uuid(handle.as_fd()), Err(Errno::BADF));
    }

    /// What a file system the tests can write to answers: no DOS attributes
    /// and no volume serial number unless it is FAT, and a label and a UUID
    /// or none, as it has them. A file and its directory are in the same
    /// file system and get the same answers.
    #[test]
    fn what_a_file_system_answers() {
        let tmp = TempDir::new("ioctl-answers");
        let dir = &tmp.0;
        fs::write(dir.join("file"), b"data").unwrap();
        let directory = open(dir, OFlags::RDONLY | OFlags::DIRECTORY);
        let file = open(&dir.join("file"), OFlags::RDONLY);
        let unsupported = |errno| matches!(errno, Errno::NOTTY | Errno::OPNOTSUPP | Errno::NOSYS | Errno::INVAL);
        for fd in [directory.as_fd(), file.as_fd()] {
            match dos_attributes(fd) {
                // FAT: every file has the attributes of its type.
                Ok(_) => assert!(fat_serial(fd).is_ok() || fat_serial(fd).is_err_and(unsupported)),
                Err(e) => {
                    assert!(unsupported(e), "{}", e);
                    assert!(fat_serial(fd).is_err_and(unsupported));
                }
            }
        }
        let label = fs_label(directory.as_fd());
        assert_eq!(label, fs_label(file.as_fd()));
        match label {
            Ok(FsLabel::Label(label)) => assert!(FileSystemIdentity::is_valid_label(&label)),
            Ok(FsLabel::Empty | FsLabel::Unwritable) => {}
            Err(e) => assert!(unsupported(e), "{}", e),
        }
        let uuid = fs_uuid(directory.as_fd());
        assert_eq!(uuid, fs_uuid(file.as_fd()));
        match uuid {
            Ok(FsUuid::Uuid(uuid)) => assert_ne!(uuid.as_bytes(), &[0; Uuid::SIZE]),
            Ok(FsUuid::Null | FsUuid::NotUuid(_)) => {}
            Err(e) => assert!(unsupported(e), "{}", e),
        }
        // procfs has no label, no UUID and nothing of FAT.
        if rustix::fs::statfs("/proc").is_ok_and(|proc| proc.f_type == rustix::fs::PROC_SUPER_MAGIC) {
            let process = open(Path::new("/proc/self/task"), OFlags::RDONLY | OFlags::DIRECTORY);
            let status = open(Path::new("/proc/self/status"), OFlags::RDONLY);
            for fd in [process.as_fd(), status.as_fd()] {
                assert_eq!(dos_attributes(fd), Err(Errno::NOTTY));
                assert_eq!(fat_serial(fd), Err(Errno::NOTTY));
                assert_eq!(fs_label(fd), Err(Errno::NOTTY));
                assert_eq!(fs_uuid(fd), Err(Errno::NOTTY));
            }
        }
    }

    /// The variable that names a directory of a mounted FAT file system
    /// for [`fat`]. Mounting one takes privileges, so the test is skipped
    /// without it.
    const FAT_DIR: &str = "UAPI16_TEST_FAT_DIR";

    /// On a FAT file system a directory has no attribute but the ones that
    /// are not read, unless it was given some, a file system has a volume
    /// serial number, and it identifies itself with the 4 bytes of that
    /// number where the kernel has `FS_IOC_GETFSUUID`.
    #[test]
    fn fat() {
        let Some(dir) = std::env::var_os(FAT_DIR) else {
            eprintln!("skipping: {} names no directory of a FAT file system", FAT_DIR);
            return;
        };
        let directory = open(Path::new(&dir), OFlags::RDONLY | OFlags::DIRECTORY);
        let fd = directory.as_fd();
        dos_attributes(fd).unwrap();
        let serial = fat_serial(fd).unwrap();
        match fs_uuid(fd) {
            Ok(identifier) => assert_eq!(identifier, FsUuid::NotUuid(4)),
            Err(e) => assert_eq!(e, Errno::NOTTY),
        }
        // The same serial number through any file of the file system.
        for entry in fs::read_dir(Path::new(&dir)).unwrap() {
            let path = entry.unwrap().path();
            let meta = fs::symlink_metadata(&path).unwrap();
            if !meta.is_file() && !meta.is_dir() {
                continue;
            }
            let file = open(&path, OFlags::RDONLY);
            let attributes = dos_attributes(file.as_fd()).unwrap();
            assert_eq!(fat_serial(file.as_fd()).unwrap(), serial);
            // The mode of a file with the read-only attribute gives nobody
            // write permission.
            if meta.is_file() && attributes.is_read_only() {
                assert!(meta.permissions().readonly(), "{:?}", path);
            }
        }
    }
}
