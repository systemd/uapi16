// SPDX-License-Identifier: LGPL-2.1-or-later
//! The C API of the crate, which the feature `capi` adds: what uapi16.h
//! declares. cbindgen writes that header from this file, see cbindgen.toml:
//! the types, the enums with their numbers, the functions, and the comments
//! on them, which are written for callers in C. The rules that hold for
//! every function are in the comment at the top of the header, which
//! cbindgen.toml has.
//!
//! With the feature, this module has unsafe code as well, next to the
//! modules ioctl and nss and the one cast of the module name. A caller in C
//! hands over pointers and numbers, and nothing can check what a pointer
//! leads to. So every function takes this on trust, which the SAFETY
//! comments call the rules of the caller:
//!
//! - An object is NULL, or a pointer that a function of this module
//!   returned and that was not freed since. No two calls use an object at
//!   the same time, except for calls that only read it: those of reports
//!   and errors, of a file object that nothing changes, and the opens of a
//!   directory.
//! - A string is NULL, or points to bytes that end in a NUL and that do
//!   not change during the call.
//! - Bytes are a pointer and a size. Unless the size is 0, the pointer is
//!   NULL or valid for the read of that many bytes, which do not change
//!   during the call.
//! - `ret` and every `ret_` argument are NULL, or valid for the write of
//!   what they are for. The `ret` of the two functions that read from a
//!   reader is valid for the read of a pointer as well, and that pointer
//!   is NULL or an object, as above.
//! - `reterr` is NULL, or valid for the read and the write of a pointer
//!   that nothing else uses during the call. A caller is told that it
//!   points to NULL then.
//! - A descriptor that is not negative is open and stays open during the
//!   call. One that an object keeps stays open until the object is freed.
//!
//! Everything else is checked before it is used: an object, a string, bytes
//! or a `ret` that is NULL, a `reterr` that points to anything but NULL, a
//! descriptor that is negative, a flag, a bit or a number that nothing here
//! knows, a name of a file object that is not UTF-8 or that is none for
//! another reason, and a name of a new file that names none. The pointers
//! are turned into references, borrowed descriptors, strings and slices
//! where a function begins, in [`Descriptor`], [`Text`], [`Bytes`],
//! [`Place`], [`Refill`], [`ErrorPlace`] and [`Object`], and everything
//! after that is safe code. The exceptions are [`Lent`], which holds a
//! descriptor that a caller lends to an object, and two types that have
//! nothing of a caller: [`ForkCheck`], which maps the page that tells a
//! child of a fork(), and [`OnceBox`], which keeps what is made once.
//!
//! A panic does not unwind into C: a function with the C ABI aborts the
//! process instead. So does an allocation that fails.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]
// The types, the enumerators and the functions have the names C has for
// them.
#![allow(non_camel_case_types)]

use std::borrow::Cow;
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::ffi::{c_char, c_int, c_void, CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::mem::{self, ManuallyDrop};
use std::num::{NonZeroU64, NonZeroUsize};
use std::ops::{Deref, DerefMut};
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{self, AtomicBool, AtomicPtr, AtomicUsize};
use std::sync::Arc;

use rustix::fs::IFlags;

use crate::decode::ROOT_RECORD;
use crate::error::{
    DataProblem, Error, ErrorKind, Field, Problem, SourceProblem, TreeProblem, UnsupportedData, ValidityProblem,
};
use crate::ioctl::DosAttributes;
use crate::name::NamePair;
use crate::reader::Object as Record;
use crate::sys::NewFile;
use crate::{
    AddFlags, ContentsObject, ContentsSource, DataCheck, DataLocation, ExternalFile, FatSerial, Features, FileObject,
    FileSystemIdentity, InodeAttributes, InodeType, ManifestOptions, ManifestReport, ManifestWriter, Mode, Name,
    NameProblem, Order, PinnedDirectory, Reader, RootObject, Sha256, Sha256Context, SignatureObject, Uuid,
    ValidityWindow, Writer,
};

/// A feature of a manifest: what its file objects record. The features
/// are those of the specification, which spells them in lower case with
/// dashes: UAPI16_FEATURE_USER_XATTR is user-xattr. A feature is a number,
/// and a list of features is an array of them. Later versions add features
/// after the last one.
///
/// The features of partitions, UAPI16_FEATURE_GPT_LABEL to
/// UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM, don't apply to a tree of
/// files. No manifest writer is made for options that have one of them, and
/// the generate functions refuse them. The writer of records takes them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_feature_t {
    /// No feature. uapi16_feature_from_name() returns it for a name that no
    /// feature has.
    UAPI16_FEATURE_NONE = 0,
    /// The access mode.
    UAPI16_FEATURE_MODE = 1,
    /// The user ID of the owner.
    UAPI16_FEATURE_UID = 2,
    /// The group ID of the owner.
    UAPI16_FEATURE_GID = 3,
    /// The name of the owning user, as the user database of the host has
    /// it.
    UAPI16_FEATURE_USER_NAME = 4,
    /// The name of the owning group, as the user database of the host has
    /// it.
    UAPI16_FEATURE_GROUP_NAME = 5,
    /// The size of the data of a regular file.
    UAPI16_FEATURE_SIZE = 6,
    /// The SHA-256 hash of the data of a regular file.
    UAPI16_FEATURE_SHA256 = 7,
    /// The targets of symbolic links.
    UAPI16_FEATURE_SYMLINK = 8,
    /// The major and minor numbers of device nodes.
    UAPI16_FEATURE_DEVICE = 9,
    /// Which file objects are names of one file.
    UAPI16_FEATURE_HARDLINK = 10,
    /// The modification time.
    UAPI16_FEATURE_MTIME = 11,
    /// The extended attributes of the user namespace.
    ///
    /// The generate functions open no file for its extended attributes.
    /// Those of a file that is open anyway are read from the open file: a
    /// directory that is walked into, a regular file whose data is hashed,
    /// and a regular file or a directory that is opened for its inode
    /// flags, its DOS attributes or the identity of its file system. Those
    /// of any other file are read through /proc. Without a /proc they can't
    /// be read, and it has to be the one of the kernel: whoever can mount
    /// something else there can have such a file recorded with the
    /// attributes of another one.
    UAPI16_FEATURE_USER_XATTR = 12,
    /// The DOS attribute hidden.
    UAPI16_FEATURE_FLAG_HIDDEN = 13,
    /// The DOS attribute system.
    UAPI16_FEATURE_FLAG_SYSTEM = 14,
    /// The DOS attribute archive.
    UAPI16_FEATURE_FLAG_ARCHIVE = 15,
    /// The inode flag append only.
    UAPI16_FEATURE_FLAG_APPEND_ONLY = 16,
    /// The inode flag immutable.
    UAPI16_FEATURE_FLAG_IMMUTABLE = 17,
    /// The inode flag no atime updates.
    UAPI16_FEATURE_FLAG_NO_ATIME = 18,
    /// The inode flag no copy on write.
    UAPI16_FEATURE_FLAG_NO_COW = 19,
    /// The inode flag no dump.
    UAPI16_FEATURE_FLAG_NO_DUMP = 20,
    /// Whether a file is read-only.
    UAPI16_FEATURE_READ_ONLY = 21,
    /// The UUID of the file system of the root.
    ///
    /// UAPI16_FEATURE_FS_UUID and UAPI16_FEATURE_FAT_SERIAL are read from the
    /// root. A root whose file system has no UUID is written without one,
    /// and so is one whose volume serial number can't be read, which only
    /// FAT gives. Before Linux 6.9 no UUID can be read. Each is counted in
    /// uapi16_manifest_report_fields_omitted() as well. A manifest without a
    /// root has neither.
    UAPI16_FEATURE_FS_UUID = 22,
    /// The label of the file system of the root.
    UAPI16_FEATURE_FS_LABEL = 23,
    /// The volume serial number of the FAT file system of the root.
    UAPI16_FEATURE_FAT_SERIAL = 24,
    /// The label of a partition.
    UAPI16_FEATURE_GPT_LABEL = 25,
    /// The UUID of a partition.
    UAPI16_FEATURE_GPT_UUID = 26,
    /// The type UUID of a partition.
    UAPI16_FEATURE_GPT_TYPE_UUID = 27,
    /// The disk UUID of a partition table.
    UAPI16_FEATURE_GPT_DISK_UUID = 28,
    /// The attribute flags of a partition.
    UAPI16_FEATURE_GPT_FLAGS = 29,
    /// The partition attribute flag no auto.
    UAPI16_FEATURE_GPT_FLAG_NO_AUTO = 30,
    /// The partition attribute flag grow file system.
    UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM = 31,
}

/// The order a manifest lists its file objects in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_order_t {
    /// No order. With options that have it, uapi16_writer_begin() writes a
    /// manifest that declares none, and uapi16_reader_order() returns it
    /// for such a manifest. The functions that sort refuse options that
    /// have it.
    UAPI16_ORDER_NONE = 0,
    /// The order of the code points of the names, component by component:
    /// codepoint in the specification.
    UAPI16_ORDER_CODEPOINT = 1,
}

/// A flag of the generate functions. A set of them is a
/// uapi16_add_flags_t.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_add_flag_t {
    /// No flag.
    // Only C names it: a set without a flag is 0 here.
    #[allow(dead_code)]
    UAPI16_ADD_NONE = 0,
    /// Walk into mount points instead of writing them as empty
    /// directories.
    UAPI16_ADD_CROSS_MOUNTS = 1 << 0,
    /// Leave out files whose names a manifest can't hold, a directory with
    /// everything below it, and count them in
    /// uapi16_manifest_report_entries_omitted(), instead of failing.
    UAPI16_ADD_GRACEFUL = 1 << 1,
}

/// What kind of error a uapi16_error is, with the errno of each kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_error_kind_t {
    /// Reading or writing failed. The errno is that of the system call
    /// that failed, or EIO where none did.
    UAPI16_ERROR_IO = 1,
    /// The name of the file to create is taken. EEXIST.
    UAPI16_ERROR_EXISTS = 2,
    /// The same name was added for two different files that are not both
    /// directories. EEXIST.
    UAPI16_ERROR_DUPLICATE = 3,
    /// A file changed while it was read. ESTALE.
    UAPI16_ERROR_CHANGED = 4,
    /// Two names of one inode don't show the same file. ESTALE.
    UAPI16_ERROR_HARDLINK_MISMATCH = 5,
    /// A file has a name that a manifest can't hold. EILSEQ for a name that
    /// is not UTF-8, ENAMETOOLONG for one that is too long, and EINVAL for
    /// any other.
    UAPI16_ERROR_UNWRITABLE_NAME = 6,
    /// A file that is not a directory is where a directory is needed.
    /// ENOTDIR.
    UAPI16_ERROR_NOT_DIRECTORY = 7,
    /// A feature that was asked for can't be read here, or the data of a
    /// file object is not data the library takes. EOPNOTSUPP.
    UAPI16_ERROR_UNSUPPORTED = 8,
    /// The call is not a valid one. EINVAL for a NULL object or string, no
    /// `ret` for an object other than a report, an unknown flag, feature or
    /// order and a name that is none. EBADF for a negative descriptor.
    /// ECHILD in a child of fork(). EINVAL for options with a feature of
    /// partitions, which a call that makes a manifest writer checks after
    /// the process, and for options whose order is UAPI16_ORDER_NONE in a
    /// function that sorts, which checks them there too.
    UAPI16_ERROR_INVALID_ARGUMENT = 9,
    /// A directory is one of the directories it is in, because a mount
    /// shows it again. ELOOP.
    UAPI16_ERROR_LOOP = 10,
    /// A directory that files were added below was not added itself, and
    /// the features need what it would record. ENOENT.
    UAPI16_ERROR_MISSING_PARENT = 11,
    /// What a manifest records of a file is more than one of its records
    /// has room for, such as more than 4 MiB of extended attributes. E2BIG.
    UAPI16_ERROR_TOO_LARGE = 12,
    /// The object takes nothing more: a writer, a computation or a check
    /// that is finished, a writer that failed to write a record, or a
    /// reader that failed to read an object. ESTALE. A call is checked for
    /// what it is given first and for its process next, so one that is
    /// UAPI16_ERROR_INVALID_ARGUMENT is that on such an object as well.
    UAPI16_ERROR_ENDED = 13,
    /// A manifest is malformed, or a file object is not one a manifest can
    /// hold. uapi16_error_problem() names the rule that is broken,
    /// uapi16_error_field() the field and uapi16_error_record() the record.
    /// EBADMSG.
    UAPI16_ERROR_MANIFEST = 14,
    /// The file a manifest has the data of a file object in is not there.
    /// ENOENT.
    UAPI16_ERROR_SOURCE_MISSING = 15,
    /// The file a manifest has the data of a file object in is not a regular
    /// file. EINVAL.
    UAPI16_ERROR_SOURCE_NOT_REGULAR = 16,
    /// The data of a file is not as many bytes as the manifest says, or its
    /// file is too short for it. EBADMSG.
    UAPI16_ERROR_SIZE_MISMATCH = 17,
    /// The data of a file does not have the hash the manifest says. EBADMSG.
    UAPI16_ERROR_HASH_MISMATCH = 18,
    /// A file object or a manifest is revoked. EKEYREVOKED.
    UAPI16_ERROR_REVOKED = 19,
    /// The time is before the one a file object or a manifest may be used
    /// from. EKEYEXPIRED.
    UAPI16_ERROR_NOT_YET_VALID = 20,
    /// The time is not before the one a file object or a manifest may be
    /// used until. EKEYEXPIRED.
    UAPI16_ERROR_EXPIRED = 21,
}

/// Which rule of the names of a manifest a name breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_name_problem_t {
    /// It is not UTF-8.
    UAPI16_NAME_PROBLEM_NOT_UTF8 = 1,
    /// It is empty.
    UAPI16_NAME_PROBLEM_EMPTY = 2,
    /// It is longer than 4095 bytes.
    UAPI16_NAME_PROBLEM_TOO_LONG = 3,
    /// Its first component is Uapi16Manifest or begins with
    /// Uapi16Manifest., which the specification reserves.
    UAPI16_NAME_PROBLEM_RESERVED = 4,
    /// It has a control character: ASCII 0 to 31 or 127.
    UAPI16_NAME_PROBLEM_CONTROL_CHARACTER = 5,
    /// It has a Unicode noncharacter.
    UAPI16_NAME_PROBLEM_NONCHARACTER = 6,
    /// One of its components is empty: it begins or ends with a slash, or
    /// has two slashes in a row.
    UAPI16_NAME_PROBLEM_EMPTY_COMPONENT = 7,
    /// One of its components is "." or "..".
    UAPI16_NAME_PROBLEM_DOT_COMPONENT = 8,
}

/// Where the data of a file object is, as uapi16_file_object_data_location()
/// finds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_data_location_t {
    /// Nowhere: the object has no data.
    UAPI16_DATA_LOCATION_NONE = 0,
    /// In the manifest itself. uapi16_file_object_literal() gives it.
    UAPI16_DATA_LOCATION_LITERAL = 1,
    /// In a file next to the manifest. uapi16_directory_open_data() opens
    /// it.
    UAPI16_DATA_LOCATION_EXTERNAL = 2,
    /// At a URL or in an encoding. The library neither fetches nor decodes
    /// data.
    UAPI16_DATA_LOCATION_UNSUPPORTED = 3,
}

/// A flag of uapi16_directory_new(). A set of them is a
/// uapi16_directory_flags_t.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_directory_flag_t {
    /// No flag.
    // Only C names it: a set without a flag is 0 here.
    #[allow(dead_code)]
    UAPI16_DIRECTORY_NONE = 0,
    /// Follow symbolic links below the directory, resolved as if the
    /// directory were the root: a link that points out of the directory
    /// leads to what has that path inside it instead. Without this flag a
    /// name that leads through a symbolic link fails with ELOOP.
    UAPI16_DIRECTORY_FOLLOW_SYMLINKS = 1 << 0,
}

/// Whether a file object says that its file is read-only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_read_only_t {
    /// The object does not say.
    UAPI16_READ_ONLY_UNSTATED = 0,
    /// The file is not read-only.
    UAPI16_READ_ONLY_NO = 1,
    /// The file is read-only.
    UAPI16_READ_ONLY_YES = 2,
}

/// Where one name comes to another in the code point order, as
/// uapi16_name_compare() returns it. This is the one signed enum: its
/// numbers are those a comparison function of qsort() returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i64)]
enum uapi16_name_order_t {
    /// The first name comes before the second.
    UAPI16_NAME_BEFORE = -1,
    /// The two names are the same.
    UAPI16_NAME_SAME = 0,
    /// The first name comes after the second.
    UAPI16_NAME_AFTER = 1,
}

/// What uapi16_reader_next() and uapi16_reader_next_signature() read. Each
/// returns one of these as an int, or a negative errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
enum uapi16_read_t {
    /// The trailer was read and checked. The manifest is complete.
    UAPI16_READ_END = 0,
    /// One file object was read, and is in `ret`.
    UAPI16_READ_FILE = 1,
    /// The file objects have ended, and signature objects follow. From now
    /// on uapi16_reader_signed_len() has what they sign.
    UAPI16_READ_SIGNATURES = 2,
    /// One signature object was read, and is in `ret`. Only
    /// uapi16_reader_next_signature() returns this.
    UAPI16_READ_SIGNATURE = 3,
}

/// A set of uapi16_add_flag_t: their bitwise OR.
type uapi16_add_flags_t = u64;

/// A set of uapi16_directory_flag_t: their bitwise OR.
type uapi16_directory_flags_t = u64;

/// The token of a file, see uapi16_file_object_set_inode_token().
type uapi16_inode_token_t = u64;

/// The number that is no token, see uapi16_file_object_set_inode_token().
// cbindgen writes only the constants that are pub.
#[allow(unreachable_pub)]
pub const UAPI16_INODE_TOKEN_NONE: uapi16_inode_token_t = 0;

// How many bytes a UUID has, and how many uint64_t that is. cbindgen writes
// only the constants that are pub, and it takes a number or one name as
// the length of an array, so the second one is a constant of its own.
#[allow(unreachable_pub)]
pub const UAPI16_UUID_SIZE: usize = 16;
#[allow(unreachable_pub)]
pub const UAPI16_UUID_QWORDS: usize = 2;

const _: () = assert!(UAPI16_UUID_QWORDS * size_of::<u64>() == UAPI16_UUID_SIZE);

/// A UUID, as the fs-uuid field carries one.
#[repr(C)]
union uapi16_uuid_t {
    bytes: [u8; UAPI16_UUID_SIZE],
    qwords: [u64; UAPI16_UUID_QWORDS],
}

// The same for a SHA-256 hash.
#[allow(unreachable_pub)]
pub const UAPI16_SHA256_SIZE: usize = 32;
#[allow(unreachable_pub)]
pub const UAPI16_SHA256_QWORDS: usize = 4;

const _: () = assert!(UAPI16_SHA256_QWORDS * size_of::<u64>() == UAPI16_SHA256_SIZE);

/// A SHA-256 hash.
#[repr(C)]
union uapi16_sha256_digest_t {
    bytes: [u8; UAPI16_SHA256_SIZE],
    qwords: [u64; UAPI16_SHA256_QWORDS],
}

/// A number of uapi16_order_t as a caller passes it: any number, since
/// nothing holds C to those of the enum. uapi16.h has it as
/// uapi16_order_t, see cbindgen.toml.
/// cbindgen:no-export
type OrderNumber = u64;
/// A number of uapi16_error_kind_t as a caller gets it, or 0 for none.
/// uapi16.h has it as uapi16_error_kind_t.
/// cbindgen:no-export
type ErrorKindNumber = u64;
/// A number of uapi16_feature_t as a caller gets it, or 0 for none.
/// uapi16.h has it as uapi16_feature_t.
/// cbindgen:no-export
type FeatureNumber = u64;
/// A number of uapi16_name_problem_t as a caller gets it, or 0 for none.
/// uapi16.h has it as uapi16_name_problem_t.
/// cbindgen:no-export
type NameProblemNumber = u64;
/// A number of uapi16_data_location_t as a caller gets it, or 0 for none.
/// uapi16.h has it as uapi16_data_location_t.
/// cbindgen:no-export
type DataLocationNumber = u64;
/// A number of uapi16_read_only_t as a caller passes it and gets it.
/// uapi16.h has it as uapi16_read_only_t.
/// cbindgen:no-export
type ReadOnlyNumber = u64;

impl uapi16_read_only_t {
    /// Every answer, as C has it and as Rust has it.
    const ALL: [(uapi16_read_only_t, Option<bool>); 3] = [
        (uapi16_read_only_t::UAPI16_READ_ONLY_UNSTATED, None),
        (uapi16_read_only_t::UAPI16_READ_ONLY_NO, Some(false)),
        (uapi16_read_only_t::UAPI16_READ_ONLY_YES, Some(true)),
    ];

    /// What C has for what a file object says of `readOnly`.
    fn of(read_only: Option<bool>) -> uapi16_read_only_t {
        let mut all = uapi16_read_only_t::ALL.into_iter();
        let found = all.find(|(_, rust)| *rust == read_only);
        found.map_or(uapi16_read_only_t::UAPI16_READ_ONLY_UNSTATED, |(c, _)| c)
    }

    /// What a file object says of `readOnly` for the number `read_only` of
    /// a caller. A number that is none of the enum fails.
    fn of_number(read_only: ReadOnlyNumber) -> Result<Option<bool>, uapi16_error> {
        let mut all = uapi16_read_only_t::ALL.into_iter();
        let found = all.find(|(c, _)| *c as ReadOnlyNumber == read_only);
        found.map(|(_, rust)| rust).ok_or_else(uapi16_error::misuse)
    }
}

impl uapi16_name_order_t {
    /// What C has for the ordering `ordering` of two names.
    fn of(ordering: Ordering) -> uapi16_name_order_t {
        match ordering {
            Ordering::Less => uapi16_name_order_t::UAPI16_NAME_BEFORE,
            Ordering::Equal => uapi16_name_order_t::UAPI16_NAME_SAME,
            Ordering::Greater => uapi16_name_order_t::UAPI16_NAME_AFTER,
        }
    }
}

/// A value that is made when it is first asked for, and kept: what a
/// OnceLock is, without its lock.
///
/// A lock would be held while the value is made. Another thread can fork at
/// any time, and its child has that one thread: there the lock is never
/// released, and whoever asks for the same value waits for it forever. So
/// no thread waits for another here. Threads that ask at the same time make
/// a value each. The one that is stored first is the value, and the others
/// drop theirs.
#[derive(Debug)]
struct OnceBox<T> {
    /// The value, which was a Box, or null as long as there is none.
    value: AtomicPtr<T>,
    /// The cell owns the value, though it holds it as a pointer.
    owned: PhantomData<Box<T>>,
}

impl<T> OnceBox<T> {
    /// A cell without a value.
    const fn new() -> OnceBox<T> {
        OnceBox {
            value: AtomicPtr::new(ptr::null_mut()),
            owned: PhantomData,
        }
    }

    /// Forgets the value, so that the next one who asks has it made anew.
    fn reset(&mut self) {
        let value = mem::replace(self.value.get_mut(), ptr::null_mut());
        if !value.is_null() {
            // SAFETY: `value` came from Box::into_raw() in get_or_init() and
            // was stored, so the cell owns it. Nothing borrows it any more:
            // every borrow of it is one of the cell, which is borrowed
            // mutably here.
            drop(unsafe { Box::from_raw(value) });
        }
    }
}

// A value can be made by one thread and dropped by another, and several
// threads can read it at once.
impl<T: Send + Sync> OnceBox<T> {
    /// The value, which `make` makes where there is none yet.
    fn get_or_init(&self, make: impl FnOnce() -> T) -> &T {
        let mut value = self.value.load(atomic::Ordering::Acquire);
        if value.is_null() {
            let made = Box::into_raw(Box::new(make()));
            let stored = self.value.compare_exchange(
                ptr::null_mut(),
                made,
                atomic::Ordering::AcqRel,
                atomic::Ordering::Acquire,
            );
            value = match stored {
                Ok(_) => made,
                Err(theirs) => {
                    // SAFETY: `made` came from Box::into_raw() just now and
                    // was not stored, so nothing else has it.
                    drop(unsafe { Box::from_raw(made) });
                    theirs
                }
            };
        }
        // SAFETY: `value` came from Box::into_raw() and was stored, so the
        // cell owns it, and it is dropped by reset() and by drop() alone.
        // Both borrow the cell mutably, which they can't while this borrow
        // of it lasts.
        unsafe { &*value }
    }
}

impl<T> Default for OnceBox<T> {
    fn default() -> OnceBox<T> {
        OnceBox::new()
    }
}

impl<T> Drop for OnceBox<T> {
    fn drop(&mut self) {
        self.reset();
    }
}

/// The names the library hands out as constants: those the specification
/// has for a field, for a rule and for a feature. Rust has each as a
/// `&'static str`, and C takes a string that ends in a NUL. So a copy of a
/// name is made when it is first asked for, and stays for as long as the
/// process runs.
#[derive(Debug)]
struct Constants<const N: usize>([OnceBox<Option<CString>>; N]);

impl<const N: usize> Constants<N> {
    /// Room for `N` names, none of which was asked for yet.
    const fn new() -> Constants<N> {
        Constants([const { OnceBox::new() }; N])
    }

    /// The name `name`, which is number `index` of these, as C takes it.
    /// None for a number these have no room for, and for a name with a NUL,
    /// which the specification has none of.
    fn get(&'static self, index: usize, name: &'static str) -> Option<&'static CStr> {
        let slot = self.0.get(index)?;
        slot.get_or_init(|| CString::new(name).ok()).as_deref()
    }
}

/// The names of the fields, each at the number of its field. They have
/// room for more fields than there are.
static FIELD_NAMES: Constants<{ u8::MAX as usize + 1 }> = Constants::new();
/// The names of the rules of the specification, each at the number of its
/// rule.
static PROBLEM_NAMES: Constants<{ Problem::ALL.len() }> = Constants::new();
/// The names of the features, each at the place of its feature in
/// [`uapi16_feature_t::ALL`].
static FEATURE_NAMES: Constants<{ uapi16_feature_t::ALL.len() }> = Constants::new();

impl Field {
    /// The field as the specification spells it, as C takes it.
    fn c_name(self) -> Option<&'static CStr> {
        FIELD_NAMES.get(self as usize, self.as_str())
    }
}

impl Problem {
    /// The name of the rule, which never changes, as C takes it.
    fn c_name(self) -> Option<&'static CStr> {
        PROBLEM_NAMES.get(self as usize, self.as_str())
    }
}

impl uapi16_feature_t {
    /// Every single feature, as C has it and as Rust has it.
    const ALL: [(uapi16_feature_t, Features); 31] = [
        (uapi16_feature_t::UAPI16_FEATURE_MODE, Features::MODE),
        (uapi16_feature_t::UAPI16_FEATURE_UID, Features::UID),
        (uapi16_feature_t::UAPI16_FEATURE_GID, Features::GID),
        (uapi16_feature_t::UAPI16_FEATURE_USER_NAME, Features::USER_NAME),
        (uapi16_feature_t::UAPI16_FEATURE_GROUP_NAME, Features::GROUP_NAME),
        (uapi16_feature_t::UAPI16_FEATURE_SIZE, Features::SIZE),
        (uapi16_feature_t::UAPI16_FEATURE_SHA256, Features::SHA256),
        (uapi16_feature_t::UAPI16_FEATURE_SYMLINK, Features::SYMLINK),
        (uapi16_feature_t::UAPI16_FEATURE_DEVICE, Features::DEVICE),
        (uapi16_feature_t::UAPI16_FEATURE_HARDLINK, Features::HARDLINK),
        (uapi16_feature_t::UAPI16_FEATURE_MTIME, Features::MTIME),
        (uapi16_feature_t::UAPI16_FEATURE_USER_XATTR, Features::USER_XATTR),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_HIDDEN, Features::FLAG_HIDDEN),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_SYSTEM, Features::FLAG_SYSTEM),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_ARCHIVE, Features::FLAG_ARCHIVE),
        (
            uapi16_feature_t::UAPI16_FEATURE_FLAG_APPEND_ONLY,
            Features::FLAG_APPEND_ONLY,
        ),
        (
            uapi16_feature_t::UAPI16_FEATURE_FLAG_IMMUTABLE,
            Features::FLAG_IMMUTABLE,
        ),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_NO_ATIME, Features::FLAG_NO_ATIME),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_NO_COW, Features::FLAG_NO_COW),
        (uapi16_feature_t::UAPI16_FEATURE_FLAG_NO_DUMP, Features::FLAG_NO_DUMP),
        (uapi16_feature_t::UAPI16_FEATURE_READ_ONLY, Features::READ_ONLY),
        (uapi16_feature_t::UAPI16_FEATURE_FS_UUID, Features::FS_UUID),
        (uapi16_feature_t::UAPI16_FEATURE_FS_LABEL, Features::FS_LABEL),
        (uapi16_feature_t::UAPI16_FEATURE_FAT_SERIAL, Features::FAT_SERIAL),
        (uapi16_feature_t::UAPI16_FEATURE_GPT_LABEL, Features::GPT_LABEL),
        (uapi16_feature_t::UAPI16_FEATURE_GPT_UUID, Features::GPT_UUID),
        (uapi16_feature_t::UAPI16_FEATURE_GPT_TYPE_UUID, Features::GPT_TYPE_UUID),
        (uapi16_feature_t::UAPI16_FEATURE_GPT_DISK_UUID, Features::GPT_DISK_UUID),
        (uapi16_feature_t::UAPI16_FEATURE_GPT_FLAGS, Features::GPT_FLAGS),
        (
            uapi16_feature_t::UAPI16_FEATURE_GPT_FLAG_NO_AUTO,
            Features::GPT_FLAG_NO_AUTO,
        ),
        (
            uapi16_feature_t::UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM,
            Features::GPT_FLAG_GROW_FILE_SYSTEM,
        ),
    ];

    /// The number C has for the single feature `feature`, as an error
    /// names one.
    fn of(feature: Features) -> Option<uapi16_feature_t> {
        let mut all = uapi16_feature_t::ALL.into_iter();
        all.find(|(_, rust)| *rust == feature).map(|(c, _)| c)
    }

    /// The place in [`uapi16_feature_t::ALL`] of the feature with the number
    /// `feature`, which is that place and one more. None for
    /// UAPI16_FEATURE_NONE and for a number that is no feature.
    fn place_of(feature: FeatureNumber) -> Option<usize> {
        let place = usize::try_from(feature.checked_sub(1)?).ok()?;
        (place < uapi16_feature_t::ALL.len()).then_some(place)
    }

    /// The feature Rust has for the number `feature`. None for
    /// UAPI16_FEATURE_NONE and for a number that is no feature.
    fn rust_of(feature: FeatureNumber) -> Option<Features> {
        uapi16_feature_t::place_of(feature).map(|place| uapi16_feature_t::ALL[place].1)
    }

    /// The name the specification has for the feature with the number
    /// `feature`, as C takes it. None for a number that is not one feature.
    fn name_of(feature: FeatureNumber) -> Option<&'static CStr> {
        let place = uapi16_feature_t::place_of(feature)?;
        let name = uapi16_feature_t::ALL[place].1.names().next()?;
        FEATURE_NAMES.get(place, name)
    }
}

// A feature goes between C and Rust as its number, which is its place in
// the table and one more. So the numbers of C have no gap, and C has every
// feature Rust has and no other. None of that builds otherwise.
const _: () = {
    let mut all = Features::NONE;
    let mut next = 0;
    while next < uapi16_feature_t::ALL.len() {
        let (c, rust) = uapi16_feature_t::ALL[next];
        assert!(c as u64 == next as u64 + 1);
        all = all.union(rust);
        next += 1;
    }
    assert!(all.contains(Features::ALL) && Features::ALL.contains(all));
};

impl Features {
    /// Whether the set has the feature with the number `feature` of C. It
    /// has none for a number that is no feature.
    fn has_number(self, feature: FeatureNumber) -> bool {
        uapi16_feature_t::rust_of(feature).is_some_and(|rust| self.contains(rust))
    }

    /// Feature `i` of the set as C numbers it, counted from 0 in the order
    /// of the numbers. UAPI16_FEATURE_NONE past the last one.
    fn number_at(self, i: usize) -> FeatureNumber {
        let mut held = uapi16_feature_t::ALL
            .into_iter()
            .filter(|(_, rust)| self.contains(*rust));
        held.nth(i).map_or(uapi16_feature_t::UAPI16_FEATURE_NONE, |(c, _)| c) as FeatureNumber
    }
}

impl uapi16_name_problem_t {
    /// The number C has for `problem`. A name with more than one component
    /// where one is taken has none: no name gets here that way. A caller
    /// in C passes whole names, and the kernel lists no name with a slash
    /// in a directory.
    fn of(problem: NameProblem) -> Option<uapi16_name_problem_t> {
        Some(match problem {
            NameProblem::NotUtf8 => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_NOT_UTF8,
            NameProblem::Empty => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_EMPTY,
            NameProblem::TooLong => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_TOO_LONG,
            NameProblem::Reserved => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_RESERVED,
            NameProblem::ContainsControlCharacter => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_CONTROL_CHARACTER,
            NameProblem::ContainsNoncharacter => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_NONCHARACTER,
            NameProblem::EmptyComponent => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_EMPTY_COMPONENT,
            NameProblem::ContainsDotComponent => uapi16_name_problem_t::UAPI16_NAME_PROBLEM_DOT_COMPONENT,
            NameProblem::ContainsSeparator => return None,
        })
    }
}

/// The process an object of the C API was made in. After fork() the child
/// has the objects of its parent, and must not use them: they share
/// descriptors, scratch files and a file that is not complete with the
/// parent. A call on such an object fails with ECHILD.
///
/// A process is known by its generation, see [`ForkCheck`]: a number that
/// the child of a fork() does not have in common with its parent. An object
/// has the generation of the process that made it.
///
/// A call is checked in the order sd-bus checks one: what it is given
/// first, an object, a string, a flag, a name or a descriptor, which fails
/// with EINVAL or EBADF, then the process, and then what the options and
/// the writer say of themselves: the features of the options where a
/// writer is made, and whether the writer takes anything more. Nothing is
/// done before the process is checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Process {
    /// A process with its generation.
    Known(NonZeroUsize),
    /// A process without a generation, since its line of processes used up
    /// every one of them. No object is an object of such a process, also
    /// none it makes itself.
    Spent,
    /// A process that nothing tells from its children: the kernel gave it
    /// no page that is wiped in a child, see [`ForkCheck::of_process`].
    /// Nothing is checked there. A child uses the objects of its parent
    /// like its own, and frees them like its parent would.
    Untold,
}

impl Process {
    /// The process that is running.
    fn current() -> Process {
        match ForkCheck::of_process() {
            Some(check) => check.generation().map_or(Process::Spent, Process::Known),
            None => Process::Untold,
        }
    }

    /// Fails in any process but this one.
    fn check(self) -> Result<(), uapi16_error> {
        if self.is(Process::current()) {
            Ok(())
        } else {
            Err(uapi16_error::refused(libc::ECHILD))
        }
    }

    /// Whether this is the process `running`, as far as that can be told.
    /// A process without a generation is no process that is known, not even
    /// itself. Where nothing tells a child, every process passes for the
    /// one that is running. So does the process of an object that was made
    /// without a page, also in a process that has one by now.
    fn is(self, running: Process) -> bool {
        match (self, running) {
            (Process::Known(made), Process::Known(now)) => made == now,
            (Process::Spent, _) | (_, Process::Spent) => false,
            (Process::Untold, _) | (_, Process::Untold) => true,
        }
    }
}

/// How a process finds out that it is the child of a fork(), which has the
/// objects of its parent in its memory: by a page of memory that a child
/// gets filled with zeroes, one with MADV_WIPEONFORK, see madvise(2). The
/// page holds the generation of the process, which is never 0. A child
/// finds 0 there and takes the next generation. So a child is known also
/// where it has the PID of its parent, as the first process of a new PID
/// namespace can have, and no call asks the kernel for a PID.
#[derive(Clone, Copy, Debug)]
struct ForkCheck(&'static AtomicUsize);

impl ForkCheck {
    /// How many bytes are mapped for the generation. The kernel maps whole
    /// pages, so this is one page.
    const LEN: usize = size_of::<AtomicUsize>();

    /// The first generation. 0 is what a page holds that has none.
    const FIRST: usize = 1;

    /// The page of this process, by which it and its children are told
    /// apart. None where the kernel makes no such page: an old one, or one
    /// that a seccomp filter keeps a process from. Nothing tells a child
    /// there, and there is nothing to fall back to: the calls go on, in a
    /// child as in its parent. The first call of a process finds that out,
    /// and a child has what its parent found.
    ///
    /// No lock is held for that. Another thread can fork at any time, and
    /// its child has that one thread: a lock that another thread of the
    /// parent held is never released there, and the first call of the child
    /// would wait for it forever. So threads that make the first call at
    /// the same time map a page each. The page that is stored first is the
    /// page of the process, and the other threads unmap theirs. A child that
    /// is forked before a page is stored maps its own.
    fn of_process() -> Option<ForkCheck> {
        /// The page of this process, or null as long as it has none.
        static FOUND: AtomicPtr<AtomicUsize> = AtomicPtr::new(ptr::null_mut());
        /// Whether the kernel refused the page, so that it is asked once
        /// and not at every call.
        ///
        /// A refusal need not last. A mmap() can fail once, in a thread
        /// whose first call comes while another thread stores a page. The
        /// process has its page then, and that one call goes on without
        /// it: an object it makes is of no process that is told, and passes
        /// in every child, see [`Process::is`]. Nothing is done about
        /// that. It is what every object is like where the kernel has no
        /// such page, and there the calls are to go on.
        static REFUSED: AtomicBool = AtomicBool::new(false);
        let mut found = FOUND.load(atomic::Ordering::Acquire);
        if found.is_null() {
            if REFUSED.load(atomic::Ordering::Relaxed) {
                return None;
            }
            let Some(mine) = ForkCheck::wiped_page() else {
                REFUSED.store(true, atomic::Ordering::Relaxed);
                return None;
            };
            let stored = FOUND.compare_exchange(
                ptr::null_mut(),
                mine.as_ptr(),
                atomic::Ordering::AcqRel,
                atomic::Ordering::Acquire,
            );
            found = match stored {
                Ok(_) => mine.as_ptr(),
                Err(theirs) => {
                    // SAFETY: `mine` is a mapping of wiped_page() that was
                    // not stored, so nothing refers to the mapping that
                    // goes.
                    unsafe { libc::munmap(mine.as_ptr().cast(), ForkCheck::LEN) };
                    theirs
                }
            };
        }
        // SAFETY: `found` is a mapping of wiped_page() that was stored as
        // the page of the process, and such a mapping is never unmapped. It
        // is as large as an AtomicUsize at least and starts at a page, so
        // it is aligned for one. It is readable and writable, and it was
        // made of zeroes, which are a value of it. Nothing reads or writes
        // it but through references like this one, and the kernel, which
        // fills it with zeroes for a child: the child starts with that, and
        // an atomic is read anew each time.
        Some(ForkCheck(unsafe { &*found }))
    }

    /// Maps a page that a child of a fork() gets filled with zeroes. None
    /// where the kernel refuses the mapping or does not wipe it.
    fn wiped_page() -> Option<NonNull<AtomicUsize>> {
        // Miri has no such madvise(), and stops at it. So there is no
        // page under Miri, as on a kernel that refuses one.
        if cfg!(miri) {
            return None;
        }
        let protection = libc::PROT_READ | libc::PROT_WRITE;
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS;
        // SAFETY: a new mapping of memory that belongs to no file, at an
        // address the kernel picks, changes nothing that is mapped.
        let page = unsafe { libc::mmap(ptr::null_mut(), ForkCheck::LEN, protection, flags, -1, 0) };
        if page == libc::MAP_FAILED {
            return None;
        }
        // SAFETY: `page` is the mapping that was just made, and nothing
        // else has it.
        if unsafe { libc::madvise(page, ForkCheck::LEN, libc::MADV_WIPEONFORK) } != 0 {
            // SAFETY: as above, so nothing refers to the mapping that goes.
            unsafe { libc::munmap(page, ForkCheck::LEN) };
            return None;
        }
        NonNull::new(page.cast())
    }

    /// The generation of the process that is running. None for a process
    /// whose line of processes used up every generation.
    fn generation(self) -> Option<NonZeroUsize> {
        /// The generation that is handed out next. A child has the count of
        /// its parent.
        static NEXT: AtomicUsize = AtomicUsize::new(ForkCheck::FIRST);
        ForkCheck::generation_of(self.0, &NEXT)
    }

    /// The generation `page` holds. A page that holds 0 is one that no
    /// generation was stored in yet: that of a process that was just
    /// forked, or one that was just mapped. It gets the generation `next`
    /// counts, which is above every one that was handed out before. Threads
    /// that find 0 at the same time agree on the generation of the one that
    /// stores it first.
    ///
    /// The count stops at its end and does not start over, since a
    /// generation that comes again would be that of an object of a process
    /// long before. A page gets none then, and neither does a page of any
    /// child after it.
    fn generation_of(page: &AtomicUsize, next: &AtomicUsize) -> Option<NonZeroUsize> {
        let held = match page.load(atomic::Ordering::Acquire) {
            0 => {
                let taken = ForkCheck::counted(next)?;
                let stored = page.compare_exchange(0, taken, atomic::Ordering::AcqRel, atomic::Ordering::Acquire);
                stored.map_or_else(|theirs| theirs, |_| taken)
            }
            held => held,
        };
        NonZeroUsize::new(held)
    }

    /// Takes the generation `next` is at, and counts one up. None once the
    /// count is at its end, where it stays.
    fn counted(next: &AtomicUsize) -> Option<usize> {
        let mut taken = next.load(atomic::Ordering::Relaxed);
        loop {
            let after = taken.checked_add(1)?;
            match next.compare_exchange_weak(taken, after, atomic::Ordering::Relaxed, atomic::Ordering::Relaxed) {
                Ok(_) => return Some(taken),
                Err(now) => taken = now,
            }
        }
    }
}

/// A descriptor as a caller passes it: a number, which is one of its open
/// descriptors unless it is negative.
#[derive(Clone, Copy, Debug)]
struct Descriptor<'fd>(c_int, PhantomData<BorrowedFd<'fd>>);

impl<'fd> Descriptor<'fd> {
    /// The descriptor `fd` of a caller.
    ///
    /// # Safety
    ///
    /// Unless `fd` is negative, it is an open descriptor, and stays open
    /// for `'fd`.
    unsafe fn new(fd: c_int) -> Descriptor<'fd> {
        Descriptor(fd, PhantomData)
    }

    /// Borrows the descriptor. A negative number is none, also AT_FDCWD,
    /// which stands for a directory only where a path is looked up.
    fn borrow(self) -> Result<BorrowedFd<'fd>, uapi16_error> {
        if self.0 < 0 {
            return Err(uapi16_error::refused(uapi16_error::NO_DESCRIPTOR));
        }
        // SAFETY: the number is not negative, so it is not -1, and whoever
        // made this said that it is an open descriptor then, which stays
        // open for `'fd`.
        Ok(unsafe { BorrowedFd::borrow_raw(self.0) })
    }

    /// Lends the descriptor to what `make` makes of it, which holds it as
    /// if it owned it. Nothing closes the descriptor all the same, and no
    /// duplicate is made of it: the [`Lent`] this returns gives it back
    /// when it is dropped.
    ///
    /// # Safety
    ///
    /// The descriptor stays open until what this returns is dropped.
    /// `make` returns the descriptor inside what it makes of it.
    unsafe fn lend<T: Borrower>(self, make: impl FnOnce(OwnedFd) -> T) -> Result<Lent<T>, uapi16_error> {
        let fd = self.borrow()?;
        // SAFETY: the descriptor is open, and stays open for as long as
        // what is made of it lives, as the caller says. It is owned in name
        // only: `make` keeps it inside what it makes, and `Lent` takes it
        // out of that again instead of closing it.
        let owned = unsafe { OwnedFd::from_raw_fd(fd.as_raw_fd()) };
        Ok(Lent(ManuallyDrop::new(make(owned))))
    }
}

/// What the library makes of a descriptor that a caller lends it, and that
/// can be taken apart for the descriptor again.
trait Borrower {
    /// The descriptor this was made of. None where something shares it
    /// still: nothing closes it then either.
    fn into_descriptor(self) -> Option<OwnedFd>;
}

/// The file a manifest is read from or written to.
impl Borrower for File {
    fn into_descriptor(self) -> Option<OwnedFd> {
        Some(self.into())
    }
}

/// The directory the files of a manifest are taken from.
impl Borrower for PinnedDirectory {
    fn into_descriptor(self) -> Option<OwnedFd> {
        Some(self.into_fd())
    }
}

/// The directory of a new manifest file, which the file shares with what
/// else the writer keeps there while the manifest is built.
impl Borrower for Arc<OwnedFd> {
    /// A directory that something shares still is forgotten and not
    /// dropped, so that whatever drops it last does not close it.
    fn into_descriptor(self) -> Option<OwnedFd> {
        Arc::try_unwrap(self).map_err(mem::forget).ok()
    }
}

/// What the library holds of a descriptor that a caller lends it: `T` is
/// made of the descriptor as if it owned it. The descriptor stays the
/// caller's, which keeps it open for as long as this lives. When this is
/// dropped, `T` is taken apart and the descriptor is left open: nothing
/// here closes it, and no duplicate is made of it.
#[derive(Debug)]
struct Lent<T: Borrower>(ManuallyDrop<T>);

impl<T: Borrower> Deref for Lent<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Borrower> DerefMut for Lent<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Borrower> Drop for Lent<T> {
    fn drop(&mut self) {
        // SAFETY: the value is taken out once, here, and nothing uses this
        // after it was dropped.
        let made = unsafe { ManuallyDrop::take(&mut self.0) };
        if let Some(descriptor) = made.into_descriptor() {
            // The descriptor is the caller's, which closes it.
            let _ = descriptor.into_raw_fd();
        }
    }
}

impl Read for Lent<File> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.0.read(buf)
    }
}

impl Write for Lent<File> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

/// A string as a caller passes it: NULL, or NUL-terminated.
#[derive(Clone, Copy, Debug)]
struct Text<'a>(Option<&'a CStr>);

impl<'a> Text<'a> {
    /// The string `text` of a caller.
    ///
    /// # Safety
    ///
    /// `text` is NULL, or points to bytes that end in a NUL and that are
    /// valid and do not change for `'a`.
    unsafe fn new(text: *const c_char) -> Text<'a> {
        if text.is_null() {
            return Text(None);
        }
        // SAFETY: `text` is not NULL, so it points to bytes that end in a
        // NUL and stay as they are for `'a`, as the caller says.
        Text(Some(unsafe { CStr::from_ptr(text) }))
    }

    /// The string, which has to be one.
    fn get(self) -> Result<&'a CStr, uapi16_error> {
        self.0.ok_or_else(uapi16_error::misuse)
    }

    /// The string as text, whatever it is: NULL is the empty string, and
    /// bytes that are not UTF-8 become the replacement character.
    fn lossy(self) -> Cow<'a, str> {
        self.0.map_or(Cow::Borrowed(""), CStr::to_string_lossy)
    }
}

impl Order {
    /// Every order, as C has it and as Rust has it. UAPI16_ORDER_NONE is no
    /// order.
    const ALL: [(uapi16_order_t, Option<Order>); 2] = [
        (uapi16_order_t::UAPI16_ORDER_NONE, None),
        (uapi16_order_t::UAPI16_ORDER_CODEPOINT, Some(Order::CodePoint)),
    ];

    /// The order a caller in C passes as `order`: a number of
    /// uapi16_order_t, of which UAPI16_ORDER_NONE is no order. Any other
    /// number fails.
    fn of_number(order: OrderNumber) -> Result<Option<Order>, uapi16_error> {
        let mut all = Order::ALL.into_iter();
        all.find(|(c, _)| *c as OrderNumber == order)
            .map(|(_, rust)| rust)
            .ok_or_else(uapi16_error::misuse)
    }

    /// The number C has for the order `order`, or for none.
    fn number(order: Option<Order>) -> uapi16_order_t {
        let mut all = Order::ALL.into_iter();
        all.find(|(_, rust)| *rust == order)
            .map_or(uapi16_order_t::UAPI16_ORDER_NONE, |(c, _)| c)
    }
}

impl Name {
    /// The name a caller in C passes as `text`: the empty string for the
    /// root of the tree, which has no name, and the name of a file object
    /// for any other file.
    fn of_text(text: Text<'_>) -> Result<&Name, uapi16_error> {
        let text = text.get()?.to_str();
        let text = text.map_err(|_| uapi16_error::bad_name(NameProblem::NotUtf8))?;
        if text.is_empty() {
            return Ok(Name::ROOT);
        }
        Name::new(text).map_err(uapi16_error::bad_name)
    }
}

impl uapi16_add_flag_t {
    /// Every flag, as C has it and as Rust has it.
    const ALL: [(uapi16_add_flag_t, AddFlags); 2] = [
        (uapi16_add_flag_t::UAPI16_ADD_CROSS_MOUNTS, AddFlags::CROSS_MOUNTS),
        (uapi16_add_flag_t::UAPI16_ADD_GRACEFUL, AddFlags::GRACEFUL),
    ];
}

impl AddFlags {
    /// The flags a caller in C passes as `bits`: a set of
    /// uapi16_add_flag_t. A bit that is no flag fails.
    fn of_bits(bits: uapi16_add_flags_t) -> Result<AddFlags, uapi16_error> {
        let mut flags = AddFlags::NONE;
        let mut known = 0;
        for (c, rust) in uapi16_add_flag_t::ALL {
            let bit = c as u64;
            known |= bit;
            if bits & bit != 0 {
                flags |= rust;
            }
        }
        if bits & !known != 0 {
            return Err(uapi16_error::misuse());
        }
        Ok(flags)
    }
}

/// Where a call stores its error, as a caller passes it in `reterr`: NULL
/// for a caller that wants no error, or a place for one, which a caller is
/// told to set to NULL.
#[derive(Debug)]
struct ErrorPlace<'a>(Option<&'a mut *mut uapi16_error>);

impl<'a> ErrorPlace<'a> {
    /// No place: what a function has that takes no `reterr`.
    const NONE: ErrorPlace<'static> = ErrorPlace(None);

    /// The place `reterr` of a caller.
    ///
    /// # Safety
    ///
    /// `reterr` is NULL, or valid for the read and the write of a pointer
    /// for `'a`, and nothing else uses what it points to for `'a`.
    unsafe fn new(reterr: *mut *mut uapi16_error) -> ErrorPlace<'a> {
        // SAFETY: `reterr` is NULL or points to a pointer that can be read
        // and written for `'a` and that nothing else uses then, as the
        // caller says.
        ErrorPlace(unsafe { reterr.as_mut() })
    }

    /// Whether a call can store an error here: there is no place, or it
    /// holds NULL. A place that holds anything else is not clear, and a
    /// call that is given one is no valid call. What it holds may be an
    /// error that was not freed, which a new one would leak, or no error at
    /// all, so nothing ever reads through it, frees it or replaces it.
    fn is_clear(&self) -> bool {
        self.0.as_deref().is_none_or(|held| held.is_null())
    }

    /// What a call returns that ended as `result`: 0, or the errno of the
    /// error, negated. The error goes to the place if there is one, and
    /// nothing is written there for a call that did not fail. A place that
    /// is not clear keeps what it holds: the call was refused for it.
    fn returned(self, result: Result<(), uapi16_error>) -> c_int {
        let Err(error) = result else {
            return 0;
        };
        let errno = error.errno;
        if let Some(place) = self.0.filter(|place| place.is_null()) {
            *place = error.into_raw();
        }
        -errno
    }

    /// What a call returns that was to read an object and ended as `read`:
    /// the number of what it read, or what [`ErrorPlace::returned`] returns
    /// for the error.
    fn read(self, read: Result<uapi16_read_t, uapi16_error>) -> c_int {
        match read {
            // The numbers of uapi16_read_t are small.
            Ok(read) => read as c_int,
            Err(e) => self.returned(Err(e)),
        }
    }
}

/// An object of the C API. A caller holds it by a pointer, and frees it
/// with the function of its type.
trait Object: Sized {
    /// Hands the object to a caller.
    fn into_raw(self) -> *mut Self {
        Box::into_raw(Box::new(self))
    }

    /// Frees the object `object` points to, unless that is NULL, and
    /// returns NULL.
    ///
    /// # Safety
    ///
    /// `object` is NULL, or came from [`Object::into_raw`], was not freed
    /// since, and is used by nothing else now or later.
    unsafe fn free(object: *mut Self) -> *mut Self {
        if !object.is_null() {
            // SAFETY: `object` is not NULL, so it came from Box::into_raw()
            // and nothing else has it, as the caller says.
            drop(unsafe { Box::from_raw(object) });
        }
        ptr::null_mut()
    }

    /// What a call returns that was to make an object of this type and
    /// ended as `made`: 0 with the object in `ret`, or what
    /// [`ErrorPlace::returned`] returns for the error, which goes to
    /// `reterr`. A caller that passes NULL for `ret` does not want the
    /// object, which is dropped.
    ///
    /// # Safety
    ///
    /// `ret` is NULL or valid for the write of a pointer.
    unsafe fn returned(made: Result<Self, uapi16_error>, ret: *mut *mut Self, reterr: ErrorPlace<'_>) -> c_int {
        let stored = made.map(|object| {
            if !ret.is_null() {
                // SAFETY: `ret` is not NULL, so it is valid for the write of
                // a pointer, as the caller says.
                unsafe { ret.write(object.into_raw()) };
            }
        });
        reterr.returned(stored)
    }
}

/// Where a read stores the object it read, as getline() takes its buffer.
/// What a caller passes in `ret` points to NULL, and the read makes a new
/// object there, or to an object of the caller, which the read fills again
/// in place of all it held. A read that has no object to store leaves both
/// alone, so the object stays the caller's whatever the read returns.
#[derive(Debug)]
struct Refill<'a, T: Object>(&'a mut *mut T);

impl<'a, T: Object> Refill<'a, T> {
    /// The place `ret` of a caller, or None where that is NULL.
    ///
    /// # Safety
    ///
    /// `ret` is NULL, or valid for the read and the write of a pointer for
    /// `'a`. That pointer is NULL, or came from [`Object::into_raw`] and
    /// was not freed since. Nothing else uses the pointer or the object
    /// for `'a`.
    unsafe fn new(ret: *mut *mut T) -> Option<Refill<'a, T>> {
        // SAFETY: `ret` is NULL or points to a pointer that can be read and
        // written for `'a` and that nothing else uses then, as the caller
        // says.
        unsafe { ret.as_mut() }.map(Refill)
    }

    /// The object of the caller, if it has one.
    fn object(&self) -> Option<&T> {
        // SAFETY: the pointer is NULL or an object that was not freed and
        // that nothing else uses for `'a`, as whoever made this said.
        unsafe { (*self.0).as_ref() }
    }

    /// Stores `object`: in the object of the caller, in place of all it
    /// held, or as a new object where the caller has none.
    fn store(self, object: T) {
        // SAFETY: the pointer is NULL or an object that was not freed and
        // that nothing else uses for `'a`, as whoever made this said.
        match unsafe { (*self.0).as_mut() } {
            Some(kept) => *kept = object,
            None => *self.0 = object.into_raw(),
        }
    }
}

/// Bytes as a caller passes them: a pointer and how many there are.
#[derive(Clone, Copy, Debug)]
struct Bytes<'a>(Option<&'a [u8]>);

impl<'a> Bytes<'a> {
    /// The `size` bytes at `data` of a caller. Where `size` is 0 there are
    /// none, and `data` is not looked at. A size over `isize::MAX` is one
    /// that nothing in memory has, so there are no bytes for it, as for
    /// NULL.
    ///
    /// # Safety
    ///
    /// Unless `size` is 0 or over `isize::MAX`, `data` is NULL or valid for
    /// the read of `size` bytes, which do not change for `'a`.
    unsafe fn new(data: *const c_void, size: usize) -> Bytes<'a> {
        if size == 0 {
            return Bytes(Some(&[]));
        }
        if data.is_null() || isize::try_from(size).is_err() {
            return Bytes(None);
        }
        // SAFETY: `size` is not 0 and not over isize::MAX, and `data` is
        // not NULL, so it is valid for the read of `size` bytes that stay
        // as they are for `'a`, as the caller says.
        Bytes(Some(unsafe { slice::from_raw_parts(data.cast::<u8>(), size) }))
    }

    /// The bytes, which have to be there.
    fn get(self) -> Result<&'a [u8], uapi16_error> {
        self.0.ok_or_else(uapi16_error::misuse)
    }
}

/// A list of features as a caller passes it: a pointer to their numbers and
/// how many there are.
#[derive(Clone, Copy, Debug)]
struct FeatureList<'a>(Option<&'a [FeatureNumber]>);

impl<'a> FeatureList<'a> {
    /// The `n` numbers at `features` of a caller. Where `n` is 0 there are
    /// none, and `features` is not looked at. More numbers than memory can
    /// hold are none that are there, as for NULL.
    ///
    /// # Safety
    ///
    /// Unless `n` is 0 or more than memory can hold, `features` is NULL or
    /// valid for the read of `n` numbers, which do not change for `'a`.
    unsafe fn new(features: *const FeatureNumber, n: usize) -> FeatureList<'a> {
        if n == 0 {
            return FeatureList(Some(&[]));
        }
        if features.is_null() || n > isize::MAX as usize / size_of::<FeatureNumber>() {
            return FeatureList(None);
        }
        // SAFETY: `n` is not 0, `n` numbers are not more than isize::MAX
        // bytes, and `features` is not NULL, so it is valid for the read of
        // `n` numbers that stay as they are for `'a`, as the caller says.
        FeatureList(Some(unsafe { slice::from_raw_parts(features, n) }))
    }

    /// The features of the list as a set, which have to be there. A feature
    /// can be in the list more than once, and UAPI16_FEATURE_NONE is passed
    /// over. A number that is no feature fails.
    fn get(self) -> Result<Features, uapi16_error> {
        let mut features = Features::NONE;
        for &number in self.0.ok_or_else(uapi16_error::misuse)? {
            if number == uapi16_feature_t::UAPI16_FEATURE_NONE as FeatureNumber {
                continue;
            }
            features |= uapi16_feature_t::rust_of(number).ok_or_else(uapi16_error::misuse)?;
        }
        Ok(features)
    }
}

/// Where a call stores a value, as a caller passes it in `ret` or in one of
/// its `ret_` arguments: NULL, or a place for the value.
#[derive(Debug)]
struct Place<'a, T>(*mut T, PhantomData<&'a mut T>);

impl<'a, T> Place<'a, T> {
    /// The place `to` of a caller.
    ///
    /// # Safety
    ///
    /// `to` is NULL, or valid for the write of a `T` for `'a`.
    unsafe fn new(to: *mut T) -> Place<'a, T> {
        Place(to, PhantomData)
    }

    /// The place, which has to be one.
    fn needed(self) -> Result<Place<'a, T>, uapi16_error> {
        if self.0.is_null() {
            return Err(uapi16_error::misuse());
        }
        Ok(self)
    }

    /// Stores `value`, unless there is no place for it.
    fn store(self, value: T) {
        if !self.0.is_null() {
            // SAFETY: the place is not NULL, so it is valid for the write of
            // a `T`, as whoever made it said.
            unsafe { self.0.write(value) };
        }
    }
}

impl InodeType {
    /// Every type, with the bits `st_mode` has for it.
    const ST_MODES: [(InodeType, u32); 7] = [
        (InodeType::Regular, libc::S_IFREG),
        (InodeType::Directory, libc::S_IFDIR),
        (InodeType::Symlink, libc::S_IFLNK),
        (InodeType::Fifo, libc::S_IFIFO),
        (InodeType::CharDevice, libc::S_IFCHR),
        (InodeType::BlockDevice, libc::S_IFBLK),
        (InodeType::Socket, libc::S_IFSOCK),
    ];

    /// The type the bits of the file type in `st_mode` are, if they are
    /// one.
    fn of_st_mode(st_mode: u32) -> Option<InodeType> {
        let bits = st_mode & libc::S_IFMT;
        let mut all = InodeType::ST_MODES.into_iter();
        all.find(|(_, known)| *known == bits).map(|(inode_type, _)| inode_type)
    }

    /// The bits `st_mode` has for the type.
    fn st_mode(self) -> u32 {
        let mut all = InodeType::ST_MODES.into_iter();
        all.find(|(inode_type, _)| *inode_type == self)
            .map_or(0, |(_, bits)| bits)
    }
}

/// How to write a manifest: the features it records, the order of its
/// file objects and whether a new file is synced. Made by
/// uapi16_manifest_options_new(), which gives the default features and
/// the code point order and does not sync, and freed by
/// uapi16_manifest_options_free().
#[derive(Debug)]
struct uapi16_manifest_options {
    options: ManifestOptions,
    /// The features and the order of the options, which a writer of records
    /// gives its root file object. Options of C can have no order, which
    /// `options` can't: only a writer of records takes those.
    features: Features,
    order: Option<Order>,
    process: Process,
}

impl Object for uapi16_manifest_options {}

impl uapi16_manifest_options {
    /// New options, of this process.
    fn new() -> uapi16_manifest_options {
        uapi16_manifest_options {
            options: ManifestOptions::new(),
            features: Features::DEFAULT,
            order: Some(Order::CodePoint),
            process: Process::current(),
        }
    }

    /// What uapi16_manifest_options_set_features() does.
    fn set_features(&mut self, features: FeatureList<'_>) -> Result<(), uapi16_error> {
        let features = features.get()?;
        self.record(features)
    }

    /// What uapi16_manifest_options_add_features() does.
    fn add_features(&mut self, features: FeatureList<'_>) -> Result<(), uapi16_error> {
        let features = self.features | features.get()?;
        self.record(features)
    }

    /// What uapi16_manifest_options_remove_features() does.
    fn remove_features(&mut self, features: FeatureList<'_>) -> Result<(), uapi16_error> {
        let features = self.features.without(features.get()?);
        self.record(features)
    }

    /// Makes `features` the features to record.
    fn record(&mut self, features: Features) -> Result<(), uapi16_error> {
        self.process.check()?;
        self.options.features(features);
        self.features = features;
        Ok(())
    }

    /// What uapi16_manifest_options_set_order() does.
    fn set_order(&mut self, order: OrderNumber) -> Result<(), uapi16_error> {
        let order = Order::of_number(order)?;
        self.process.check()?;
        if let Some(order) = order {
            self.options.order(order);
        }
        self.order = order;
        Ok(())
    }

    /// The options for a writer that sorts: the manifest writer and the
    /// generate functions list the file objects in the order of the
    /// options, and declare it. Options without an order are no options
    /// for them.
    fn sorted(&self) -> Result<&ManifestOptions, uapi16_error> {
        self.order.map(|_| &self.options).ok_or_else(uapi16_error::misuse)
    }

    /// What uapi16_manifest_options_set_sync() does.
    fn set_sync(&mut self, sync: bool) -> Result<(), uapi16_error> {
        self.process.check()?;
        self.options.sync(sync);
        Ok(())
    }

    /// The name of a new file as a caller passes it in `name`: a path,
    /// which is taken as the bytes it is, as Rust takes a `Path`, and not
    /// as UTF-8, as the other strings that go in are. A name that names no
    /// file below a directory is refused here, as an argument that is not
    /// valid, before anything is looked up.
    fn file_name(name: Text<'_>) -> Result<&Path, uapi16_error> {
        let name = Path::new(OsStr::from_bytes(name.get()?.to_bytes()));
        if NewFile::split(name).is_none() {
            return Err(uapi16_error::misuse());
        }
        Ok(name)
    }

    /// What uapi16_manifest_writer_create_at() does. The writer has `dir`
    /// on loan: a file whose name has one component and what else the
    /// writer keeps in the directory of the file use `dir` itself.
    ///
    /// # Safety
    ///
    /// `dir` stays open until the writer this returns is dropped.
    unsafe fn create_at(&self, dir: Descriptor<'_>, name: Text<'_>) -> Result<uapi16_manifest_writer, uapi16_error> {
        let name = uapi16_manifest_options::file_name(name)?;
        // SAFETY: the writer keeps the directory until it is dropped, and
        // the descriptor stays open for that long, as the caller says.
        let dir = unsafe { dir.lend(Arc::new) }?;
        self.process.check()?;
        let created = self.sorted()?.create_at_lent(&dir, name);
        let writer = created.map_err(|e| uapi16_error::from(e).of_new_file())?;
        Ok(uapi16_manifest_writer::new(WriterTo::NewFile(writer, dir)))
    }

    /// What uapi16_manifest_writer_open() does. The writer has `fd` on
    /// loan, and writes the manifest to it.
    ///
    /// # Safety
    ///
    /// `fd` stays open until the writer this returns is dropped.
    unsafe fn open(&self, fd: Descriptor<'_>) -> Result<uapi16_manifest_writer, uapi16_error> {
        // SAFETY: the writer keeps the file until it is dropped, and the
        // descriptor stays open for that long, as the caller says.
        let out = unsafe { fd.lend(File::from) }?;
        self.process.check()?;
        let writer = self.sorted()?.open(out)?;
        Ok(uapi16_manifest_writer::new(WriterTo::Descriptor(writer)))
    }

    /// What uapi16_manifest_generate_at() does.
    fn generate_at(
        &self,
        dir: Descriptor<'_>,
        name: Text<'_>,
        top: Descriptor<'_>,
        flags: uapi16_add_flags_t,
    ) -> Result<uapi16_manifest_report, uapi16_error> {
        let flags = AddFlags::of_bits(flags)?;
        let name = uapi16_manifest_options::file_name(name)?;
        // SAFETY: the directory is dropped before this returns, and the
        // descriptor is open for that long, as whoever made `dir` said.
        let dir = unsafe { dir.lend(Arc::new) }?;
        let top = top.borrow()?;
        self.process.check()?;
        let generated = self.sorted()?.generate_at_lent(&dir, name, top, flags);
        let report = generated.map_err(|e| uapi16_error::from(e).of_new_file())?;
        Ok(uapi16_manifest_report { report })
    }

    /// What uapi16_manifest_generate() does.
    fn generate(
        &self,
        fd: Descriptor<'_>,
        top: Descriptor<'_>,
        flags: uapi16_add_flags_t,
    ) -> Result<uapi16_manifest_report, uapi16_error> {
        let flags = AddFlags::of_bits(flags)?;
        // SAFETY: the file is dropped before this returns, and the
        // descriptor is open for that long, as whoever made `fd` said.
        let out = unsafe { fd.lend(File::from) }?;
        let top = top.borrow()?;
        self.process.check()?;
        let (_, report) = self.sorted()?.generate(out, top, flags)?;
        Ok(uapi16_manifest_report { report })
    }
}

/// Takes the files a manifest lists, and writes the manifest once it has
/// them all. Made by uapi16_manifest_writer_create_at() and
/// uapi16_manifest_writer_open(), and freed by
/// uapi16_manifest_writer_free().
///
/// The manifest lists its file objects in the order of the options,
/// whatever order the adds came in. Two equal file objects under one name
/// are listed once. A directory added twice is listed with what the first
/// add said of it. Two other files under one name, also a directory and a
/// file that is none, are UAPI16_ERROR_DUPLICATE, from
/// uapi16_manifest_writer_finish().
///
/// An add that fails leaves the writer as it was, as if the add had not
/// been.
struct uapi16_manifest_writer {
    /// The writer, until uapi16_manifest_writer_finish() took it.
    writer: Option<WriterTo>,
    process: Process,
}

/// The writer of a manifest of the C API, by where its manifest goes.
enum WriterTo {
    /// To a new file, of uapi16_manifest_writer_create_at(), which gets
    /// its name when the writer finishes. With it comes the directory the
    /// caller lent. The writer is dropped before it, with everything that
    /// shares the directory.
    NewFile(ManifestWriter<File>, Lent<Arc<OwnedFd>>),
    /// To the descriptor the caller lent to uapi16_manifest_writer_open().
    Descriptor(ManifestWriter<Lent<File>>),
}

impl WriterTo {
    /// [`ManifestWriter::add_object`].
    fn add_object(&mut self, object: &FileObject) -> Result<(), Error> {
        match self {
            WriterTo::NewFile(writer, _) => writer.add_object(object),
            WriterTo::Descriptor(writer) => writer.add_object(object),
        }
    }

    /// [`ManifestWriter::add_root`].
    fn add_root(&mut self, root: &RootObject) -> Result<(), Error> {
        match self {
            WriterTo::NewFile(writer, _) => writer.add_root(root.inode(), root.file_system()),
            WriterTo::Descriptor(writer) => writer.add_root(root.inode(), root.file_system()),
        }
    }

    /// [`ManifestWriter::finish`]. What the manifest was written to is
    /// done with here: the new file is closed, and the descriptor of the
    /// caller is left open.
    fn finish(self) -> Result<ManifestReport, uapi16_error> {
        match self {
            WriterTo::NewFile(writer, _directory) => {
                let finished = writer.finish().map_err(|e| uapi16_error::from(e).of_new_file())?;
                Ok(finished.1)
            }
            WriterTo::Descriptor(writer) => Ok(writer.finish()?.1),
        }
    }

    /// [`ManifestWriter::abandon`].
    fn abandon(self) {
        match self {
            WriterTo::NewFile(writer, _directory) => writer.abandon(),
            WriterTo::Descriptor(writer) => writer.abandon(),
        }
    }
}

impl Object for uapi16_manifest_writer {}

impl uapi16_manifest_writer {
    /// The writer of this process for `writer`.
    fn new(writer: WriterTo) -> uapi16_manifest_writer {
        uapi16_manifest_writer {
            writer: Some(writer),
            process: Process::current(),
        }
    }

    /// The writer, unless it is finished: one that is takes nothing more.
    fn writer(&mut self) -> Result<&mut WriterTo, uapi16_error> {
        self.writer.as_mut().ok_or_else(uapi16_error::ended)
    }

    /// What uapi16_manifest_writer_add_object() does. A call that is not
    /// valid fails for that in another process and on a writer that is
    /// finished as well.
    fn add_object(&mut self, object: &uapi16_file_object) -> Result<(), uapi16_error> {
        self.process.check()?;
        object.process.check()?;
        let writer = self.writer()?;
        if object.is_root() {
            let added = writer.add_root(&object.as_tree_root()?);
            added.map_err(|e| uapi16_error::from(e).of_root())?;
        } else {
            writer.add_object(object.as_file()?)?;
        }
        Ok(())
    }

    /// What uapi16_manifest_writer_finish() does. The writer is finished
    /// after that, also where it failed.
    fn finish(&mut self) -> Result<uapi16_manifest_report, uapi16_error> {
        self.process.check()?;
        let writer = self.writer.take().ok_or_else(uapi16_error::ended)?;
        let report = writer.finish()?;
        Ok(uapi16_manifest_report { report })
    }
}

impl Drop for uapi16_manifest_writer {
    /// A writer that is freed in the process that made it is dropped as
    /// any writer. In another one, the child of a fork(), nothing of it is
    /// removed: a file that has a name until it is complete is the
    /// parent's, which has the writer still.
    fn drop(&mut self) {
        let Some(writer) = self.writer.take() else {
            return;
        };
        if !self.process.is(Process::current()) {
            writer.abandon();
        }
    }
}

/// What a manifest lists, counted per file object: a file with three names
/// counts three times. Made by uapi16_manifest_writer_finish() and the
/// generate functions, and freed by uapi16_manifest_report_free().
#[derive(Debug)]
struct uapi16_manifest_report {
    report: ManifestReport,
}

impl Object for uapi16_manifest_report {}

/// Why a call failed. A call that fails stores one where its `reterr`
/// points to, unless `reterr` is NULL, and uapi16_error_free() frees it.
/// `reterr` has to point to NULL: a call that finds anything else there,
/// such as an error that was not freed, fails with -EINVAL before it does
/// anything, and leaves what is there as it is.
#[derive(Debug)]
struct uapi16_error {
    kind: uapi16_error_kind_t,
    /// The errno, a positive number.
    errno: c_int,
    path: Option<CString>,
    hardlink_path: Option<CString>,
    /// The one feature it is about.
    feature: Option<uapi16_feature_t>,
    raw_name: Option<Box<[u8]>>,
    name_problem: Option<uapi16_name_problem_t>,
    /// The field it is about.
    field: Option<Field>,
    /// The record it is about, counting from 0.
    record: Option<u64>,
    /// The rule of the specification that is broken.
    problem: Option<Problem>,
}

impl Object for uapi16_error {}

// What the description of the C API leaves open about errors. These are
// the answers until it says.
impl uapi16_error {
    /// The errno of an I/O error that no system call gave one: a link of
    /// procfs that leads to another file than the one it is for, a scratch
    /// file that was changed, and a file of no type a manifest has.
    const WITHOUT_ERRNO: c_int = libc::EIO;
    /// The errno of a descriptor that is negative.
    const NO_DESCRIPTOR: c_int = libc::EBADF;
    /// The errno of a getter of what its object does not have: a field of
    /// a file object, and the record of an error that is about none.
    const NO_DATA: c_int = libc::ENODATA;
}

impl uapi16_error {
    /// The kind and the errno of a call on an object that takes nothing
    /// more: a writer, a computation or a check that is finished, and a
    /// reader that failed.
    const ENDED: (uapi16_error_kind_t, c_int) = (uapi16_error_kind_t::UAPI16_ERROR_ENDED, libc::ESTALE);

    /// An error of the kind `kind` with the errno `errno`, about nothing in
    /// particular.
    fn new(kind: uapi16_error_kind_t, errno: c_int) -> uapi16_error {
        uapi16_error {
            kind,
            errno,
            path: None,
            hardlink_path: None,
            feature: None,
            raw_name: None,
            name_problem: None,
            field: None,
            record: None,
            problem: None,
        }
    }

    /// The error of a call that is refused for how it was made, before it
    /// did anything, with the errno `errno`.
    fn refused(errno: c_int) -> uapi16_error {
        uapi16_error::new(uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, errno)
    }

    /// The error of a call with an object, a string or a `ret` that is
    /// NULL, or with a flag, a bit or a number nothing knows.
    fn misuse() -> uapi16_error {
        uapi16_error::refused(libc::EINVAL)
    }

    /// The error of a getter of what its object does not have. Such a
    /// getter takes no `reterr`, so only its errno gets to a caller.
    fn absent() -> uapi16_error {
        uapi16_error::refused(uapi16_error::NO_DATA)
    }

    /// The error of a call on an object that takes nothing more: a writer,
    /// a computation or a check that is finished, and a reader that failed.
    fn ended() -> uapi16_error {
        let (kind, errno) = uapi16_error::ENDED;
        uapi16_error::new(kind, errno)
    }

    /// The error of a call with a name that is not the name of a file
    /// object, for `problem`.
    fn bad_name(problem: NameProblem) -> uapi16_error {
        uapi16_error {
            name_problem: uapi16_name_problem_t::of(problem),
            ..uapi16_error::misuse()
        }
    }

    /// The same error as that of a call that makes a new file or gives it
    /// its name. There, EEXIST of a system call says that the name is
    /// taken.
    fn of_new_file(mut self) -> uapi16_error {
        if self.kind == uapi16_error_kind_t::UAPI16_ERROR_IO && self.errno == libc::EEXIST {
            self.kind = uapi16_error_kind_t::UAPI16_ERROR_EXISTS;
        }
        self
    }

    /// The same error, about the file `name` where it names none. The root
    /// is the empty string in C, where Rust names no file.
    fn about(mut self, name: &Name) -> uapi16_error {
        if self.path.is_none() {
            self.path = CString::new(name.as_str()).ok();
        }
        self
    }

    /// The same error as that of a writer of records that refused the
    /// record `record`: the number the record would have had. An error that
    /// names a record keeps it.
    fn in_record(mut self, record: u64) -> uapi16_error {
        self.record.get_or_insert(record);
        self
    }

    /// The same error as that of a call that was given the root. Where a
    /// rule of the specification refuses the root, the error is about the
    /// root.
    fn of_root(self) -> uapi16_error {
        if self.problem.is_some() {
            self.about(Name::ROOT)
        } else {
            self
        }
    }

    /// The same error as that of a reader that read the record of the
    /// root. An error about a field of that record is about the root. One
    /// about the record as a whole, such as text that is no JSON, is about
    /// no file.
    fn of_root_record(self) -> uapi16_error {
        if self.field.is_some() {
            self.about(Name::ROOT)
        } else {
            self
        }
    }

    /// The kind and the errno C has for the error `error` of the builder.
    fn kind_of(error: &Error) -> (uapi16_error_kind_t, c_int) {
        match error.kind() {
            ErrorKind::Io => uapi16_error::io_kind_of(error),
            ErrorKind::Tree(problem) => match problem {
                TreeProblem::Duplicate => (uapi16_error_kind_t::UAPI16_ERROR_DUPLICATE, libc::EEXIST),
                TreeProblem::Changed => (uapi16_error_kind_t::UAPI16_ERROR_CHANGED, libc::ESTALE),
                TreeProblem::HardlinkMismatch => (uapi16_error_kind_t::UAPI16_ERROR_HARDLINK_MISMATCH, libc::ESTALE),
                TreeProblem::UnwritableName => {
                    let errno = match error.name_problem() {
                        Some(NameProblem::NotUtf8) => libc::EILSEQ,
                        Some(NameProblem::TooLong) => libc::ENAMETOOLONG,
                        _ => libc::EINVAL,
                    };
                    (uapi16_error_kind_t::UAPI16_ERROR_UNWRITABLE_NAME, errno)
                }
                TreeProblem::NotDirectory => (uapi16_error_kind_t::UAPI16_ERROR_NOT_DIRECTORY, libc::ENOTDIR),
                TreeProblem::FeatureUnavailable => (uapi16_error_kind_t::UAPI16_ERROR_UNSUPPORTED, libc::EOPNOTSUPP),
                TreeProblem::FeatureNotForTrees => (uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, libc::EINVAL),
                TreeProblem::Loop => (uapi16_error_kind_t::UAPI16_ERROR_LOOP, libc::ELOOP),
                TreeProblem::MissingParent => (uapi16_error_kind_t::UAPI16_ERROR_MISSING_PARENT, libc::ENOENT),
            },
            ErrorKind::Manifest(Problem::RecordTooLarge) => (uapi16_error_kind_t::UAPI16_ERROR_TOO_LARGE, libc::E2BIG),
            ErrorKind::Manifest(_) => (uapi16_error_kind_t::UAPI16_ERROR_MANIFEST, libc::EBADMSG),
            ErrorKind::Source(problem) => match problem {
                SourceProblem::Missing => (uapi16_error_kind_t::UAPI16_ERROR_SOURCE_MISSING, libc::ENOENT),
                SourceProblem::NotRegular => (uapi16_error_kind_t::UAPI16_ERROR_SOURCE_NOT_REGULAR, libc::EINVAL),
                SourceProblem::Unreadable => uapi16_error::io_kind_of(error),
            },
            ErrorKind::Data(problem) => match problem {
                DataProblem::SizeMismatch => (uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH, libc::EBADMSG),
                DataProblem::HashMismatch => (uapi16_error_kind_t::UAPI16_ERROR_HASH_MISMATCH, libc::EBADMSG),
                // Only a provider that copies data finds these two, and no
                // call of the C API copies data.
                DataProblem::StreamEnded | DataProblem::SourceChanged => {
                    (uapi16_error_kind_t::UAPI16_ERROR_IO, uapi16_error::WITHOUT_ERRNO)
                }
            },
            ErrorKind::Unsupported(data) => match data {
                UnsupportedData::OffsetInStream
                | UnsupportedData::NoSize
                | UnsupportedData::UrlOrEncoding
                | UnsupportedData::Absent => (uapi16_error_kind_t::UAPI16_ERROR_UNSUPPORTED, libc::EOPNOTSUPP),
            },
            ErrorKind::NotValid(problem) => match problem {
                ValidityProblem::Revoked => (uapi16_error_kind_t::UAPI16_ERROR_REVOKED, libc::EKEYREVOKED),
                ValidityProblem::NotYetValid => (uapi16_error_kind_t::UAPI16_ERROR_NOT_YET_VALID, libc::EKEYEXPIRED),
                ValidityProblem::Expired => (uapi16_error_kind_t::UAPI16_ERROR_EXPIRED, libc::EKEYEXPIRED),
            },
        }
    }

    /// The kind and the errno of the error `error` of a system call: the
    /// errno it failed with, or [`uapi16_error::WITHOUT_ERRNO`] where it
    /// has none.
    fn io_kind_of(error: &Error) -> (uapi16_error_kind_t, c_int) {
        let errno = error.io_error().and_then(io::Error::raw_os_error);
        let errno = errno.filter(|errno| *errno > 0);
        (
            uapi16_error_kind_t::UAPI16_ERROR_IO,
            errno.unwrap_or(uapi16_error::WITHOUT_ERRNO),
        )
    }
}

impl From<Error> for uapi16_error {
    /// The error C has for the error `error` of the builder: its kind and
    /// its errno, and what it is about as strings C can take.
    fn from(error: Error) -> uapi16_error {
        let (kind, errno) = uapi16_error::kind_of(&error);
        // No name of a file object has a NUL, which is a control character.
        let text = |text: Option<&str>| text.and_then(|text| CString::new(text).ok());
        uapi16_error {
            kind,
            errno,
            path: text(error.name()),
            hardlink_path: text(error.hardlink_name()),
            feature: error.feature().and_then(uapi16_feature_t::of),
            raw_name: error.raw_name().map(|name| name.as_bytes().into()),
            name_problem: error.name_problem().and_then(uapi16_name_problem_t::of),
            field: error.field(),
            record: error.record_number(),
            problem: match error.kind() {
                ErrorKind::Manifest(problem) => Some(problem),
                _ => None,
            },
        }
    }
}

/// How a flag of a `T` is read: whether it is set, cleared or not stated.
/// cbindgen:no-export
type FlagGetter<T> = fn(&T) -> Option<bool>;
/// How a flag of a `T` is stated as set or cleared, or taken away.
/// cbindgen:no-export
type FlagSetter<T> = fn(&mut T, Option<bool>);

/// The strings of a file object as C takes them: each ends in a NUL. Rust
/// keeps none of them that way, so a copy of a string is made when a caller
/// first asks for it, and stays until the object is given another one
/// there.
#[derive(Debug, Default)]
struct Texts {
    name: OnceBox<CString>,
    user_name: OnceBox<Option<CString>>,
    group_name: OnceBox<Option<CString>>,
    fs_label: OnceBox<Option<CString>>,
    /// The name of the file the data is in, where that is another one than
    /// the object's own. It is handed out only while the object names that
    /// file, and made again once it names another one.
    contents_file: OnceBox<Option<CString>>,
    /// The names of the extended attributes, in their order.
    xattr_names: OnceBox<Box<[CString]>>,
}

impl Texts {
    /// The string `text` as C takes it, which `slot` keeps: NULL where
    /// there is none, and for one with a NUL, which C can't take.
    fn optional(slot: &OnceBox<Option<CString>>, text: Option<&str>) -> *const c_char {
        let kept = slot.get_or_init(|| text.and_then(|text| CString::new(text).ok()));
        kept.as_deref().map_or(ptr::null(), CStr::as_ptr)
    }
}

/// A file object: what a manifest says about one file, or about the root
/// directory of the tree it describes. Made by uapi16_file_object_new() and
/// by uapi16_reader_next(), handed out by uapi16_reader_root(), and freed by
/// uapi16_file_object_free().
///
/// The root is the object with the empty name. It is a directory. Besides
/// its attributes it has the label, the UUID and the FAT serial number of
/// the file system. It has no size, no hash, no target, no device numbers,
/// no token and no DOS attributes.
///
/// A setter stores what it is given and checks the call alone. A writer
/// checks the object when it gets it. A getter of a number that the object
/// does not have fails with -ENODATA and stores nothing, and a getter of a
/// string returns NULL for it. What a reader filled in reads like any other
/// value: a size and a hash that follow from other fields, and a flag that
/// is cleared, a file that is not read-only and extended attributes there
/// are none of, where the features of the manifest say so. A writer leaves
/// these out again.
///
/// The object keeps a copy of every string and of all bytes it is given.
#[derive(Debug)]
struct uapi16_file_object {
    /// What the object says of the file. The root is here as well, under
    /// the empty name and as a directory: a setter stores what it is given,
    /// and a writer refuses a root that has what only another file object
    /// has.
    object: FileObject,
    /// What only the root says: the identity of its file system. A writer
    /// refuses any other object that has one.
    file_system: FileSystemIdentity,
    /// `gptDiskUuid` of a root that a reader handed out, which no setter
    /// sets. A writer of records writes it back.
    gpt_disk_uuid: Option<Uuid>,
    texts: Texts,
    process: Process,
}

impl Object for uapi16_file_object {}

impl uapi16_file_object {
    /// The Linux inode flags a manifest has: the bit FS_IOC_GETFLAGS has
    /// for each, how it is read and how it is set.
    const INODE_FLAGS: [(IFlags, FlagGetter<InodeAttributes>, FlagSetter<InodeAttributes>); 5] = [
        (
            IFlags::APPEND,
            InodeAttributes::flag_append_only,
            InodeAttributes::set_flag_append_only,
        ),
        (
            IFlags::IMMUTABLE,
            InodeAttributes::flag_immutable,
            InodeAttributes::set_flag_immutable,
        ),
        (
            IFlags::NOATIME,
            InodeAttributes::flag_no_atime,
            InodeAttributes::set_flag_no_atime,
        ),
        (
            IFlags::NOCOW,
            InodeAttributes::flag_no_cow,
            InodeAttributes::set_flag_no_cow,
        ),
        (
            IFlags::NODUMP,
            InodeAttributes::flag_no_dump,
            InodeAttributes::set_flag_no_dump,
        ),
    ];
    /// The DOS attributes a manifest has a field for: the bit a directory
    /// entry of FAT has for each, how it is read and how it is set.
    const DOS_ATTRIBUTES: [(u32, FlagGetter<FileObject>, FlagSetter<FileObject>); 3] = [
        (
            DosAttributes::HIDDEN,
            FileObject::flag_hidden,
            FileObject::set_flag_hidden,
        ),
        (
            DosAttributes::SYSTEM,
            FileObject::flag_system,
            FileObject::set_flag_system,
        ),
        (
            DosAttributes::ARCHIVE,
            FileObject::flag_archive,
            FileObject::set_flag_archive,
        ),
    ];

    /// The object of this process for the file object `object` and the
    /// identity `file_system` of a file system.
    fn of(object: FileObject, file_system: FileSystemIdentity, gpt_disk_uuid: Option<Uuid>) -> uapi16_file_object {
        uapi16_file_object {
            object,
            file_system,
            gpt_disk_uuid,
            texts: Texts::default(),
            process: Process::current(),
        }
    }

    /// What uapi16_file_object_new() does.
    fn new(name: Text<'_>) -> Result<uapi16_file_object, uapi16_error> {
        let name = Name::of_text(name)?;
        let mut object = FileObject::new(name.to_owned());
        if name.is_root() {
            object.set_inode_type(InodeType::Directory);
        }
        Ok(uapi16_file_object::of(object, FileSystemIdentity::default(), None))
    }

    /// The object for a file object that a reader read.
    fn of_file(object: FileObject) -> uapi16_file_object {
        uapi16_file_object::of(object, FileSystemIdentity::default(), None)
    }

    /// The object for the root file object `root` that a reader read. What
    /// the root says of the manifest as a whole stays with the reader: the
    /// features and the order.
    fn of_root(root: &RootObject) -> uapi16_file_object {
        let mut object = FileObject::new(Name::ROOT.to_owned());
        object.set_inode_type(InodeType::Directory);
        *object.inode_mut() = root.inode().clone();
        object.set_validity(root.validity());
        uapi16_file_object::of(object, root.file_system().clone(), root.gpt_disk_uuid())
    }

    /// Whether the object is the root: the one with the empty name.
    fn is_root(&self) -> bool {
        self.object.name().is_root()
    }

    /// The root file object of what the object says, whatever its name is,
    /// without what a manifest says as a whole: its features and its order.
    fn root(&self) -> RootObject {
        let mut root = RootObject::default();
        *root.inode_mut() = self.object.inode().clone();
        *root.file_system_mut() = self.file_system.clone();
        root.set_gpt_disk_uuid(self.gpt_disk_uuid);
        root.set_validity(self.object.validity());
        root
    }

    /// The root as a manifest writer lists it: the inode attributes of the
    /// root directory and the identity of its file system, which is all
    /// the manifest of a tree says of its root. A root that says more is
    /// refused, as an object with a field it can't have. Only a root that
    /// a reader read can: the UUID of a disk, and when the manifest may be
    /// used.
    fn as_tree_root(&self) -> Result<RootObject, uapi16_error> {
        let root = self.as_root()?;
        let validity = root.validity();
        let more = [
            (Field::GptDiskUuid, root.gpt_disk_uuid().is_some()),
            (
                Field::ValidSinceUSec,
                validity.since_usec() != ValidityWindow::default().since_usec(),
            ),
            (Field::ValidUntilUSec, validity.until_usec().is_some()),
            (Field::Validity, validity.state() != ValidityWindow::default().state()),
        ];
        match more.into_iter().find(|(_, has)| *has) {
            Some((field, _)) => Err(self.not_permitted(field)),
            None => Ok(root),
        }
    }

    /// The error of a writer that is given an object with the field
    /// `field`, which a manifest can't hold on it.
    fn not_permitted(&self, field: Field) -> uapi16_error {
        let message = format!("'{}' is not permitted on this file object", field);
        Error::manifest(Problem::FieldNotPermitted, message)
            .at(field)
            .named(self.object.name().as_str())
            .into()
    }

    /// The object as the root file object a writer takes. The root has no
    /// size, no hash, no contents, no token, no device numbers and no DOS
    /// attributes, so an object that states one of them is refused, as a
    /// reader refuses a root with such a field. An object with another name
    /// is no root.
    fn as_root(&self) -> Result<RootObject, uapi16_error> {
        if !self.is_root() {
            return Err(uapi16_error::misuse());
        }
        let object = &self.object;
        let stated = |field, has: bool| has && !object.filled_in().contains(field);
        let only_files_have = [
            (Field::Size, stated(Field::Size, object.size().is_some())),
            (Field::Sha256, stated(Field::Sha256, object.sha256().is_some())),
            (Field::Contents, !object.contents().is_empty()),
            (Field::InodeToken, object.inode_token().is_some()),
            (Field::Major, object.major().is_some()),
            (Field::Minor, object.minor().is_some()),
            (Field::FlagArchive, object.flag_archive().is_some()),
            (Field::FlagHidden, object.flag_hidden().is_some()),
            (Field::FlagSystem, object.flag_system().is_some()),
        ];
        match only_files_have.into_iter().find(|(_, has)| *has) {
            Some((field, _)) => Err(self.not_permitted(field)),
            None => Ok(self.root()),
        }
    }

    /// The object as a file object a writer takes. Only the root has the
    /// identity of a file system, so any other object that has a part of
    /// one is refused, as a reader refuses it. The root is passed on as it
    /// is: the writer says what it makes of a file object without a name.
    fn as_file(&self) -> Result<&FileObject, uapi16_error> {
        let only_the_root_has = [
            (Field::FatSerial, self.file_system.fat_serial().is_some()),
            (Field::FsLabel, self.file_system.label().is_some()),
            (Field::FsUuid, self.file_system.uuid().is_some()),
            (Field::GptDiskUuid, self.gpt_disk_uuid.is_some()),
        ];
        match only_the_root_has.into_iter().find(|(_, has)| *has) {
            Some((field, _)) if !self.is_root() => Err(self.not_permitted(field)),
            _ => Ok(&self.object),
        }
    }

    /// What uapi16_file_object_set_name() does.
    fn set_name(&mut self, name: Text<'_>) -> Result<(), uapi16_error> {
        let name = Name::of_text(name)?;
        if self.is_root() || name.is_root() {
            return Err(uapi16_error::misuse());
        }
        self.process.check()?;
        self.object.set_name(name.to_owned());
        self.texts.name.reset();
        Ok(())
    }

    /// What uapi16_file_object_name() does.
    fn name(&self) -> *const c_char {
        let name = || CString::new(self.object.name().as_str()).unwrap_or_default();
        self.texts.name.get_or_init(name).as_ptr()
    }

    /// What uapi16_file_object_set_type() does.
    fn set_type(&mut self, st_mode: u32) -> Result<(), uapi16_error> {
        let inode_type = InodeType::of_st_mode(st_mode).ok_or_else(uapi16_error::misuse)?;
        if self.is_root() && inode_type != InodeType::Directory {
            return Err(uapi16_error::misuse());
        }
        self.process.check()?;
        self.object.set_inode_type(inode_type);
        Ok(())
    }

    /// What uapi16_file_object_set_mode() does.
    fn set_mode(&mut self, st_mode: u32) -> Result<(), uapi16_error> {
        let mode = Mode::new(st_mode & !libc::S_IFMT).map_err(|_| uapi16_error::misuse())?;
        self.process.check()?;
        self.object.inode_mut().set_mode(Some(mode));
        Ok(())
    }

    /// The inode attributes, to change them, in the process that made the
    /// object.
    fn inode_mut(&mut self) -> Result<&mut InodeAttributes, uapi16_error> {
        self.process.check()?;
        Ok(self.object.inode_mut())
    }

    /// The inode attributes, in the process that made the object.
    fn inode(&self) -> Result<&InodeAttributes, uapi16_error> {
        self.process.check()?;
        Ok(self.object.inode())
    }

    /// The file object, to change it, in the process that made the object.
    fn file_mut(&mut self) -> Result<&mut FileObject, uapi16_error> {
        self.process.check()?;
        Ok(&mut self.object)
    }

    /// The file object, in the process that made the object.
    fn file(&self) -> Result<&FileObject, uapi16_error> {
        self.process.check()?;
        Ok(&self.object)
    }

    /// The identity of the file system, to change it, in the process that
    /// made the object.
    fn file_system_mut(&mut self) -> Result<&mut FileSystemIdentity, uapi16_error> {
        self.process.check()?;
        Ok(&mut self.file_system)
    }

    /// The identity of the file system, in the process that made the
    /// object.
    fn file_system(&self) -> Result<&FileSystemIdentity, uapi16_error> {
        self.process.check()?;
        Ok(&self.file_system)
    }

    /// A string as a setter takes it: UTF-8, which a caller is told to
    /// pass.
    fn text(text: Text<'_>) -> Result<String, uapi16_error> {
        let text = text.get()?.to_str().map_err(|_| uapi16_error::misuse())?;
        Ok(text.to_owned())
    }

    /// What uapi16_file_object_set_user_name() does.
    fn set_user_name(&mut self, name: Text<'_>) -> Result<(), uapi16_error> {
        let name = uapi16_file_object::text(name)?;
        self.inode_mut()?.set_user_name(Some(name));
        self.texts.user_name.reset();
        Ok(())
    }

    /// What uapi16_file_object_user_name() does.
    fn user_name(&self) -> *const c_char {
        Texts::optional(&self.texts.user_name, self.object.inode().user_name())
    }

    /// What uapi16_file_object_set_group_name() does.
    fn set_group_name(&mut self, name: Text<'_>) -> Result<(), uapi16_error> {
        let name = uapi16_file_object::text(name)?;
        self.inode_mut()?.set_group_name(Some(name));
        self.texts.group_name.reset();
        Ok(())
    }

    /// What uapi16_file_object_group_name() does.
    fn group_name(&self) -> *const c_char {
        Texts::optional(&self.texts.group_name, self.object.inode().group_name())
    }

    /// What uapi16_file_object_set_inode_token() does:
    /// UAPI16_INODE_TOKEN_NONE is no token.
    fn set_inode_token(&mut self, token: uapi16_inode_token_t) -> Result<(), uapi16_error> {
        let token = match token {
            UAPI16_INODE_TOKEN_NONE => None,
            token => NonZeroU64::new(token),
        };
        self.file_mut()?.set_inode_token(token);
        Ok(())
    }

    /// What uapi16_file_object_set_user_xattrs() does.
    fn set_user_xattrs(&mut self) -> Result<(), uapi16_error> {
        self.inode_mut()?.set_user_xattrs(Some(BTreeMap::new()));
        // No attribute is left, so no name is handed out before one is
        // added, which has the names made anew. This frees the old ones
        // early.
        self.texts.xattr_names.reset();
        Ok(())
    }

    /// What uapi16_file_object_add_user_xattr() does.
    fn add_user_xattr(&mut self, name: Text<'_>, value: Bytes<'_>) -> Result<(), uapi16_error> {
        let (name, value) = (uapi16_file_object::text(name)?, value.get()?);
        self.inode_mut()?.insert_user_xattr(name, value);
        self.texts.xattr_names.reset();
        Ok(())
    }

    /// What uapi16_file_object_user_xattrs() does.
    fn user_xattrs(&self) -> Result<usize, uapi16_error> {
        let xattrs = self.inode()?.user_xattrs().ok_or_else(uapi16_error::absent)?;
        Ok(xattrs.len())
    }

    /// What uapi16_file_object_user_xattr() does: the name, the value and
    /// the size of the value of the extended attribute number `i`. The
    /// names are copied once for all of them, and a value is looked up by
    /// its name, so that going through all of them does not look at each
    /// one for every other.
    fn user_xattr(&self, i: usize) -> Result<(*const c_char, *const c_void, usize), uapi16_error> {
        let inode = self.object.inode();
        // What a call is given comes first, then the process, and the
        // names are made after both.
        if i >= inode.user_xattrs().map_or(0, |xattrs| xattrs.len()) {
            return Err(uapi16_error::misuse());
        }
        self.process.check()?;
        let listed = || match inode.user_xattrs() {
            Some(xattrs) => xattrs.map(|(name, _)| CString::new(name).unwrap_or_default()).collect(),
            None => Box::default(),
        };
        let name = self.texts.xattr_names.get_or_init(listed).get(i);
        let name = name.ok_or_else(uapi16_error::misuse)?;
        let value = name.to_str().ok().and_then(|name| inode.user_xattr(name));
        let value = value.unwrap_or_default();
        Ok((name.as_ptr(), value.as_ptr().cast(), value.len()))
    }

    /// What uapi16_file_object_set_read_only() does.
    fn set_read_only(&mut self, read_only: ReadOnlyNumber) -> Result<(), uapi16_error> {
        let read_only = uapi16_read_only_t::of_number(read_only)?;
        self.inode_mut()?.set_read_only(read_only);
        Ok(())
    }

    /// What uapi16_file_object_set_inode_flags() does.
    fn set_inode_flags(&mut self, stated: u32, set: u32) -> Result<(), uapi16_error> {
        let inode = self.inode_mut()?;
        for (flag, _, put) in uapi16_file_object::INODE_FLAGS {
            let flag = flag.bits();
            put(inode, (stated & flag != 0).then_some(set & flag != 0));
        }
        Ok(())
    }

    /// What uapi16_file_object_inode_flags() does: the flags the object
    /// states, and those of them that are set.
    fn inode_flags(&self) -> Result<(u32, u32), uapi16_error> {
        let inode = self.inode()?;
        let mut flags = (0, 0);
        for (flag, get, _) in uapi16_file_object::INODE_FLAGS {
            if let Some(set) = get(inode) {
                flags.0 |= flag.bits();
                flags.1 |= if set { flag.bits() } else { 0 };
            }
        }
        Ok(flags)
    }

    /// What uapi16_file_object_set_dos_attributes() does.
    fn set_dos_attributes(&mut self, stated: u32, set: u32) -> Result<(), uapi16_error> {
        let object = self.file_mut()?;
        for (attribute, _, put) in uapi16_file_object::DOS_ATTRIBUTES {
            put(object, (stated & attribute != 0).then_some(set & attribute != 0));
        }
        Ok(())
    }

    /// What uapi16_file_object_dos_attributes() does: the attributes the
    /// object states, and those of them that are set.
    fn dos_attributes(&self) -> Result<(u32, u32), uapi16_error> {
        let object = self.file()?;
        let mut attributes = (0, 0);
        for (attribute, get, _) in uapi16_file_object::DOS_ATTRIBUTES {
            if let Some(set) = get(object) {
                attributes.0 |= attribute;
                attributes.1 |= if set { attribute } else { 0 };
            }
        }
        Ok(attributes)
    }

    /// What uapi16_file_object_set_target() does.
    fn set_target(&mut self, target: Bytes<'_>) -> Result<(), uapi16_error> {
        let target = ContentsSource::Literal(target.get()?.to_vec());
        self.file_mut()?.set_contents(vec![ContentsObject::new(target)]);
        Ok(())
    }

    /// What uapi16_file_object_set_contents_file() does. The empty name is
    /// that of the root, which is no file next to a manifest.
    fn set_contents_file(&mut self, file: Text<'_>) -> Result<(), uapi16_error> {
        let file = Name::of_text(file)?;
        if file.is_root() {
            return Err(uapi16_error::bad_name(NameProblem::Empty));
        }
        let file = ContentsSource::File(file.to_owned());
        self.file_mut()?.set_contents(vec![ContentsObject::new(file)]);
        self.texts.contents_file.reset();
        Ok(())
    }

    /// The file the data of the object is in and where the data starts in
    /// it, where that is another file than the one of its own name.
    fn other_file(&self) -> Option<ExternalFile<'_>> {
        match self.object.data_location() {
            Ok(DataLocation::External(file)) if file.name() != self.object.name() => Some(file),
            _ => None,
        }
    }

    /// What uapi16_file_object_contents_file() does: the name of that file,
    /// as a string of the object, and where the data starts in it.
    fn contents_file(&self) -> Result<(*const c_char, u64), uapi16_error> {
        self.process.check()?;
        let file = self.other_file().ok_or_else(uapi16_error::absent)?;
        let name = Texts::optional(&self.texts.contents_file, Some(file.name().as_str()));
        Ok((name, file.offset()))
    }

    /// What uapi16_file_object_data_location() does: where the data is.
    fn data_location(&self) -> uapi16_data_location_t {
        match self.object.data_location() {
            Ok(DataLocation::Literal(_)) => uapi16_data_location_t::UAPI16_DATA_LOCATION_LITERAL,
            Ok(DataLocation::External(_)) => uapi16_data_location_t::UAPI16_DATA_LOCATION_EXTERNAL,
            Err(e) if e.kind() == ErrorKind::Unsupported(UnsupportedData::UrlOrEncoding) => {
                uapi16_data_location_t::UAPI16_DATA_LOCATION_UNSUPPORTED
            }
            Err(_) => uapi16_data_location_t::UAPI16_DATA_LOCATION_NONE,
        }
    }

    /// What uapi16_file_object_literal() does: the data, where the manifest
    /// carries it.
    fn literal(&self) -> Option<&[u8]> {
        match self.object.data_location() {
            Ok(DataLocation::Literal(data)) => Some(data),
            _ => None,
        }
    }

    /// What uapi16_file_object_set_fs_label() does.
    fn set_fs_label(&mut self, label: Text<'_>) -> Result<(), uapi16_error> {
        let label = uapi16_file_object::text(label)?;
        self.file_system_mut()?.set_label(Some(label));
        self.texts.fs_label.reset();
        Ok(())
    }

    /// What uapi16_file_object_fs_label() does.
    fn fs_label(&self) -> *const c_char {
        Texts::optional(&self.texts.fs_label, self.file_system.label())
    }

    /// What uapi16_file_object_has_stated_feature() and
    /// uapi16_file_object_stated_feature() answer from: the features of the
    /// fields of a file object, and of those only the root has. A root file
    /// object knows the features of the second. It gets them without what
    /// is in them, and gets no inode attributes, which the file object
    /// counts itself: a field that is there states its feature, whatever
    /// it holds. So the two getters copy neither the extended attributes
    /// nor the label of an object, however large they are.
    fn stated_features(&self) -> Features {
        let mut root = RootObject::default();
        let identity = root.file_system_mut();
        identity.set_uuid(self.file_system.uuid());
        identity.set_label(self.file_system.label().map(|_| String::new()));
        identity.set_fat_serial(self.file_system.fat_serial());
        root.set_gpt_disk_uuid(self.gpt_disk_uuid);
        self.object.stated_features() | root.stated_features()
    }

    /// What uapi16_file_object_retain_features() does. What only the root
    /// has is kept next to the file object, so it goes through a root file
    /// object for that, which knows the features of its fields. A string
    /// the object handed out stays where it is as long as its field does.
    fn retain_features(&mut self, features: FeatureList<'_>) -> Result<(), uapi16_error> {
        let features = features.get()?;
        self.process.check()?;
        self.object.retain_features(features);
        let mut root = RootObject::default();
        *root.file_system_mut() = mem::take(&mut self.file_system);
        root.set_gpt_disk_uuid(self.gpt_disk_uuid);
        root.retain_features(features);
        self.file_system = mem::take(root.file_system_mut());
        self.gpt_disk_uuid = root.gpt_disk_uuid();
        let inode = self.object.inode();
        if inode.user_name().is_none() {
            self.texts.user_name.reset();
        }
        if inode.group_name().is_none() {
            self.texts.group_name.reset();
        }
        if inode.user_xattrs().is_none() {
            // As in set_user_xattrs(): this frees the old names early.
            self.texts.xattr_names.reset();
        }
        if self.file_system.label().is_none() {
            self.texts.fs_label.reset();
        }
        Ok(())
    }

    /// What uapi16_file_object_check_validity() does. The validity of the
    /// root is that of its manifest, which a root file object checks. It
    /// gets the validity and nothing else, so the check copies none of the
    /// object's fields.
    fn check_validity(&self, now_usec: u64) -> Result<(), uapi16_error> {
        self.process.check()?;
        if self.is_root() {
            let mut root = RootObject::default();
            root.set_validity(self.object.validity());
            let checked = root.check_validity(now_usec);
            checked.map_err(|e| uapi16_error::from(e).about(Name::ROOT))?;
        } else {
            self.object.check_validity(now_usec)?;
        }
        Ok(())
    }
}

/// A signature object: a signature over the manifest up to the first
/// signature object. Made by uapi16_signature_new() and by
/// uapi16_reader_next_signature(), and freed by uapi16_signature_free().
///
/// A manifest can carry several. The library reads and writes them, and
/// neither makes nor verifies a signature: that takes an OpenPGP or an X.509
/// implementation.
#[derive(Debug)]
struct uapi16_signature {
    signature: SignatureObject,
    /// The mechanism as C takes it, from when a caller first asks for it.
    mechanism: OnceBox<Option<CString>>,
    process: Process,
}

impl Object for uapi16_signature {}

impl uapi16_signature {
    /// The object of this process for the signature object `signature`.
    fn of(signature: SignatureObject) -> uapi16_signature {
        uapi16_signature {
            signature,
            mechanism: OnceBox::new(),
            process: Process::current(),
        }
    }

    /// What uapi16_signature_new() does.
    fn new(mechanism: Text<'_>) -> Result<uapi16_signature, uapi16_error> {
        let mechanism = mechanism.get()?.to_str().map_err(|_| uapi16_error::misuse())?;
        Ok(uapi16_signature::of(SignatureObject::new(mechanism)))
    }

    /// What uapi16_signature_mechanism() does.
    fn mechanism(&self) -> *const c_char {
        Texts::optional(&self.mechanism, Some(self.signature.mechanism()))
    }

    /// The signature object, to change it, in the process that made the
    /// object.
    fn signature_mut(&mut self) -> Result<&mut SignatureObject, uapi16_error> {
        self.process.check()?;
        Ok(&mut self.signature)
    }

    /// Bytes as the two setters take them: the `size` bytes at `data`, or
    /// none at all for a `data` of NULL, which takes them away.
    ///
    /// # Safety
    ///
    /// `data` is NULL, or valid for the read of `size` bytes that do not
    /// change for `'a`.
    unsafe fn bytes<'a>(data: *const c_void, size: usize) -> Option<Bytes<'a>> {
        if data.is_null() {
            return None;
        }
        // SAFETY: `data` is not NULL, so it is valid for the read of `size`
        // bytes that stay as they are for `'a`, as the caller says.
        Some(unsafe { Bytes::new(data, size) })
    }

    /// What a getter of bytes returns for `bytes`: where they are, with
    /// how many there are in `ret_size`, or NULL and 0 for none.
    fn bytes_out(bytes: Option<&[u8]>, ret_size: Place<'_, usize>) -> *const c_void {
        ret_size.store(bytes.map_or(0, <[u8]>::len));
        bytes.map_or(ptr::null(), |bytes| bytes.as_ptr().cast())
    }
}

/// Reads a manifest record by record, and checks it. Made by
/// uapi16_reader_open(), and freed by uapi16_reader_free().
///
/// The reader checks every object against the rules of the specification,
/// and where it comes: right after the object of its directory, and in the
/// order the manifest declares. It keeps one record in memory, whatever the
/// size of the manifest, and reads its descriptor once, so a manifest can
/// come through a pipe.
///
/// uapi16_reader_next() reads the file objects, and says what it read with
/// a uapi16_read_t. It returns UAPI16_READ_END once it has read and checked
/// the trailer: then the manifest is complete. Where signature objects
/// follow the file objects, it returns UAPI16_READ_SIGNATURES first. A
/// caller that wants them reads them with uapi16_reader_next_signature()
/// then. A caller that does not goes on with uapi16_reader_next(), which
/// passes over them. The signature objects are checked and not verified.
///
/// Once one of the two failed to read an object, every later call of them
/// fails with UAPI16_ERROR_ENDED. EAGAIN of a descriptor that does not
/// block is the exception: the reader lost nothing, and reads on with the
/// next call.
#[derive(Debug)]
struct uapi16_reader {
    /// The reader, of the descriptor the caller lent to
    /// uapi16_reader_open().
    reader: Reader<Lent<File>>,
    /// The root of the manifest as the file object that
    /// uapi16_reader_root() hands out.
    root: uapi16_file_object,
    stage: Stage,
    process: Process,
}

/// How far a reader of the C API has got in its manifest.
#[derive(Debug)]
enum Stage {
    /// File objects come.
    Files,
    /// The file objects are done and signature objects come. The first of
    /// them was read to find that out, and waits here until a caller takes
    /// it or passes over it.
    Signatures(Option<SignatureObject>),
    /// The trailer was read, so the manifest is complete.
    End,
    /// A call failed to read an object. The reader takes nothing more.
    Failed,
}

impl Object for uapi16_reader {}

impl uapi16_reader {
    /// What uapi16_reader_open() does. The reader has `fd` on loan, and
    /// reads the manifest from it.
    ///
    /// # Safety
    ///
    /// `fd` stays open until the reader this returns is dropped.
    unsafe fn open(fd: Descriptor<'_>) -> Result<uapi16_reader, uapi16_error> {
        // SAFETY: the reader keeps the file until it is dropped, and the
        // descriptor stays open for that long, as the caller says.
        let file = unsafe { fd.lend(File::from) }?;
        let reader = Reader::open(file).map_err(|e| uapi16_error::from(e).of_root_record())?;
        Ok(uapi16_reader {
            root: uapi16_file_object::of_root(reader.root()),
            reader,
            stage: Stage::Files,
            process: Process::current(),
        })
    }

    /// What uapi16_reader_order() does: the order the manifest declares.
    fn order(&self) -> uapi16_order_t {
        Order::number(self.reader.root().order())
    }

    /// What uapi16_reader_require_order() does. No order is none to
    /// require. The error is about the root, whose record has the field.
    fn require_order(&self, order: OrderNumber) -> Result<(), uapi16_error> {
        let order = Order::of_number(order)?.ok_or_else(uapi16_error::misuse)?;
        self.process.check()?;
        let required = self.reader.root().require_order(order);
        required.map_err(|e| uapi16_error::from(e).of_root_record())?;
        Ok(())
    }

    /// What uapi16_reader_check_validity() does.
    fn check_validity(&self, now_usec: u64) -> Result<(), uapi16_error> {
        self.process.check()?;
        let checked = self.reader.root().check_validity(now_usec);
        checked.map_err(|e| uapi16_error::from(e).about(Name::ROOT))?;
        Ok(())
    }

    /// What uapi16_reader_signed_len() does.
    fn signed_len(&self) -> Result<u64, uapi16_error> {
        self.process.check()?;
        self.reader.signed_len().ok_or_else(uapi16_error::absent)
    }

    /// Reads the next object of the manifest, or None once its trailer was
    /// read. An error ends the reader, unless it is that of a descriptor
    /// that does not block and has nothing right now: the reader lost
    /// nothing then, and reads on with the next call.
    fn pull(&mut self) -> Result<Option<Record>, uapi16_error> {
        match self.reader.next() {
            Some(Ok(object)) => Ok(Some(object)),
            None => {
                self.stage = Stage::End;
                Ok(None)
            }
            Some(Err(e)) => {
                if e.io_error().map(io::Error::kind) != Some(io::ErrorKind::WouldBlock) {
                    self.stage = Stage::Failed;
                }
                Err(e.into())
            }
        }
    }

    /// What uapi16_reader_next() does: what the call returns. A file
    /// object goes to `kept`, which stays as it is where the call returns
    /// anything but UAPI16_READ_FILE. An object of the caller that the
    /// call is to fill is one of this process, as every object a call is
    /// given.
    fn next(&mut self, kept: Refill<'_, uapi16_file_object>) -> Result<uapi16_read_t, uapi16_error> {
        self.process.check()?;
        kept.object().map_or(Ok(()), |object| object.process.check())?;
        loop {
            match self.stage {
                Stage::Failed => return Err(uapi16_error::ended()),
                Stage::End => return Ok(uapi16_read_t::UAPI16_READ_END),
                Stage::Files => match self.pull()? {
                    Some(Record::File(object)) => {
                        kept.store(uapi16_file_object::of_file(*object));
                        return Ok(uapi16_read_t::UAPI16_READ_FILE);
                    }
                    Some(Record::Signature(signature)) => {
                        self.stage = Stage::Signatures(Some(signature));
                        return Ok(uapi16_read_t::UAPI16_READ_SIGNATURES);
                    }
                    None => {}
                },
                // The signature objects are passed over. The reader checks
                // each of them all the same, and that no file object comes
                // after them.
                Stage::Signatures(_) => {
                    self.stage = Stage::Signatures(None);
                    self.pull()?;
                }
            }
        }
    }

    /// What uapi16_reader_next_signature() does: what the call returns. A
    /// signature object goes to `kept`, as a file object of
    /// uapi16_reader_next() does. It is not a valid call while file objects
    /// come. At the end of a manifest it says so, also for a manifest that
    /// has no signature objects.
    fn next_signature(&mut self, kept: Refill<'_, uapi16_signature>) -> Result<uapi16_read_t, uapi16_error> {
        self.process.check()?;
        kept.object().map_or(Ok(()), |signature| signature.process.check())?;
        loop {
            let signature = match &mut self.stage {
                Stage::Failed => return Err(uapi16_error::ended()),
                Stage::End => return Ok(uapi16_read_t::UAPI16_READ_END),
                Stage::Files => return Err(uapi16_error::misuse()),
                Stage::Signatures(waiting) => waiting.take(),
            };
            let signature = match signature {
                Some(signature) => Some(signature),
                None => match self.pull()? {
                    Some(Record::Signature(signature)) => Some(signature),
                    // The reader refuses a file object after a signature
                    // object, so none comes here.
                    Some(Record::File(_)) | None => None,
                },
            };
            if let Some(signature) = signature {
                kept.store(uapi16_signature::of(signature));
                return Ok(uapi16_read_t::UAPI16_READ_SIGNATURE);
            }
        }
    }
}

/// Writes a manifest record by record, for a caller that has its file
/// objects in the order of the manifest already: every directory before
/// what is in it, and the names of a directory in the order of their bytes.
/// Made by uapi16_writer_begin(), and freed by uapi16_writer_free().
///
/// With options whose order is UAPI16_ORDER_NONE the manifest declares no
/// order, and the file objects are written in the order of the caller. Each
/// still comes right after the object of its directory.
///
/// Every call writes its record before it returns, and nothing is kept on
/// disk. A manifest without its trailer is one a reader takes as
/// incomplete, so a writer that is freed before it finished leaves nothing
/// that passes for a manifest. A write that fails ends the writer.
#[derive(Debug)]
struct uapi16_writer {
    /// The writer, of the descriptor the caller lent to
    /// uapi16_writer_begin(), until uapi16_writer_finish() took it.
    writer: Option<Writer<Lent<File>>>,
    process: Process,
}

impl Object for uapi16_writer {}

impl uapi16_writer {
    /// What uapi16_writer_begin() does. The root says what the root
    /// directory and its file system are like, and the options what the
    /// manifest records and in which order. The writer has `fd` on loan,
    /// and writes the manifest to it.
    ///
    /// # Safety
    ///
    /// `fd` stays open until the writer this returns is dropped.
    unsafe fn begin(
        options: &uapi16_manifest_options,
        fd: Descriptor<'_>,
        root: Option<&uapi16_file_object>,
    ) -> Result<uapi16_writer, uapi16_error> {
        if root.is_some_and(|root| !root.is_root()) {
            return Err(uapi16_error::misuse());
        }
        // SAFETY: the writer keeps the file until it is dropped, and the
        // descriptor stays open for that long, as the caller says.
        let out = unsafe { fd.lend(File::from) }?;
        options.process.check()?;
        root.map_or(Ok(()), |root| root.process.check())?;
        // A root that is refused here would have been the first record, as
        // one that the writer refuses.
        let root = root.map_or_else(|| Ok(RootObject::default()), uapi16_file_object::as_root);
        let mut root = root.map_err(|e| e.in_record(ROOT_RECORD))?;
        root.set_features(Some(options.features));
        root.set_order(options.order);
        let writer = Writer::begin(out, &root).map_err(|e| uapi16_error::from(e).of_root())?;
        Ok(uapi16_writer {
            writer: Some(writer),
            process: Process::current(),
        })
    }

    /// The writer in the process that made it, unless it is finished: one
    /// that is takes nothing more.
    fn writer(&mut self) -> Result<&mut Writer<Lent<File>>, uapi16_error> {
        self.process.check()?;
        self.writer.as_mut().ok_or_else(uapi16_error::ended)
    }

    /// What uapi16_writer_file() does. The object is one of this process
    /// as well, as every object a call is given. An object that is refused
    /// here is refused as the record it would have been, as one that the
    /// writer refuses.
    fn file(&mut self, object: &uapi16_file_object) -> Result<(), uapi16_error> {
        self.process.check()?;
        object.process.check()?;
        let writer = self.writer()?;
        let file = object.as_file().map_err(|e| e.in_record(writer.next_record()))?;
        let written = writer.file(file);
        self.written(written)
    }

    /// What uapi16_writer_signature() does.
    fn signature(&mut self, signature: &uapi16_signature) -> Result<(), uapi16_error> {
        self.process.check()?;
        signature.process.check()?;
        let written = self.writer()?.signature(&signature.signature);
        self.written(written)
    }

    /// What a write of a record came to. A write that failed ends the
    /// writer: it takes nothing more, as after uapi16_writer_finish(). The
    /// writer has counted the record as written before its bytes went out,
    /// so what was written lacks the record, or has a part of it, and
    /// whatever came after that would pass for a manifest that has it. A
    /// record that the writer refuses is no write, and leaves the writer as
    /// it was.
    fn written(&mut self, written: Result<(), Error>) -> Result<(), uapi16_error> {
        if written.as_ref().is_err_and(|e| e.kind() == ErrorKind::Io) {
            self.writer = None;
        }
        Ok(written?)
    }

    /// What uapi16_writer_finish() does. The writer is finished after
    /// that, also where it failed. The descriptor of the caller is done
    /// with here, and is left open.
    fn finish(&mut self) -> Result<(), uapi16_error> {
        self.process.check()?;
        let writer = self.writer.take().ok_or_else(uapi16_error::ended)?;
        writer.finish()?;
        Ok(())
    }
}

/// Computes the SHA-256 hash of data that comes in pieces, such as the data
/// of a file while it is copied into an image. Made by uapi16_sha256_new(),
/// and freed by uapi16_sha256_free().
#[derive(Debug)]
struct uapi16_sha256 {
    /// The computation, until uapi16_sha256_finish() took it.
    context: Option<Sha256Context>,
    process: Process,
}

impl Object for uapi16_sha256 {}

impl uapi16_sha256 {
    /// A computation of this process that has taken no data yet.
    fn new() -> uapi16_sha256 {
        uapi16_sha256 {
            context: Some(Sha256Context::new()),
            process: Process::current(),
        }
    }

    /// The computation in the process that made it, unless it is finished:
    /// one that is takes nothing more.
    fn context(&mut self) -> Result<&mut Sha256Context, uapi16_error> {
        self.process.check()?;
        self.context.as_mut().ok_or_else(uapi16_error::ended)
    }

    /// What uapi16_sha256_update() does.
    fn update(&mut self, data: Bytes<'_>) -> Result<(), uapi16_error> {
        let data = data.get()?;
        self.context()?.update(data);
        Ok(())
    }

    /// What uapi16_sha256_update_zeros() does.
    fn update_zeros(&mut self, size: u64) -> Result<(), uapi16_error> {
        self.context()?.update_zeros(size);
        Ok(())
    }

    /// What uapi16_sha256_finish() does: the hash of all the data.
    fn finish(&mut self) -> Result<[u8; Sha256::SIZE], uapi16_error> {
        self.process.check()?;
        let context = self.context.take().ok_or_else(uapi16_error::ended)?;
        Ok(context.finalize().into())
    }
}

/// The directory the files of a manifest are taken from: the one the
/// manifest is in, or one the caller chose instead. Made by
/// uapi16_directory_new(), and freed by uapi16_directory_free().
///
/// The directory is never looked up again, and nothing resolves to
/// anything outside it. Several threads can open files from one directory
/// at the same time.
#[derive(Debug)]
struct uapi16_directory {
    /// The directory, of the descriptor the caller lent to
    /// uapi16_directory_new().
    directory: Lent<PinnedDirectory>,
    process: Process,
}

impl Object for uapi16_directory {}

impl uapi16_directory {
    /// What uapi16_directory_new() does. A bit of `flags` that is no flag
    /// fails. The directory has `dir` on loan.
    ///
    /// # Safety
    ///
    /// `dir` stays open until the directory this returns is dropped.
    unsafe fn new(dir: Descriptor<'_>, flags: uapi16_directory_flags_t) -> Result<uapi16_directory, uapi16_error> {
        let follow = uapi16_directory_flag_t::UAPI16_DIRECTORY_FOLLOW_SYMLINKS as u64;
        if flags & !follow != 0 {
            return Err(uapi16_error::misuse());
        }
        let pin = |dir| PinnedDirectory::new(dir).follow_symlinks(flags & follow != 0);
        // SAFETY: the directory is kept until this is dropped, and the
        // descriptor stays open for that long, as the caller says.
        let directory = unsafe { dir.lend(pin) }?;
        Ok(uapi16_directory {
            directory,
            process: Process::current(),
        })
    }

    /// What uapi16_directory_open_data() does: the file the data of
    /// `object` is in, open for reading, and where the data starts in it.
    /// Data that is not in a file is none this opens.
    fn open_data(&self, object: &uapi16_file_object) -> Result<(OwnedFd, u64), uapi16_error> {
        self.process.check()?;
        let object = object.file()?;
        match object.data_location()? {
            DataLocation::External(file) => {
                let opened = self.directory.open_data(object, &file)?;
                Ok((opened.into(), file.offset()))
            }
            DataLocation::Literal(_) => {
                let in_no_file = uapi16_error::new(uapi16_error_kind_t::UAPI16_ERROR_UNSUPPORTED, libc::EOPNOTSUPP);
                Err(in_no_file.about(object.name()))
            }
        }
    }
}

/// Holds the data of a file object against the size and the hash the
/// object gives, as the data passes. Made by uapi16_data_check_new(), and
/// freed by uapi16_data_check_free().
#[derive(Debug)]
struct uapi16_data_check {
    /// The check, until uapi16_data_check_finish() took it. It has the name
    /// of the file object of the caller as its own, and what else it needs
    /// of the object, so the caller can change or free the object.
    check: Option<DataCheck<'static>>,
    process: Process,
}

impl Object for uapi16_data_check {}

impl uapi16_data_check {
    /// What uapi16_data_check_new() does.
    fn new(object: &uapi16_file_object) -> Result<uapi16_data_check, uapi16_error> {
        object.process.check()?;
        Ok(uapi16_data_check {
            check: Some(DataCheck::new(&object.object).into_owned()),
            process: Process::current(),
        })
    }

    /// The check in the process that made it, unless it is finished: one
    /// that is takes nothing more.
    fn check(&mut self) -> Result<&mut DataCheck<'static>, uapi16_error> {
        self.process.check()?;
        self.check.as_mut().ok_or_else(uapi16_error::ended)
    }

    /// What uapi16_data_check_update() does.
    fn update(&mut self, data: Bytes<'_>) -> Result<(), uapi16_error> {
        let data = data.get()?;
        self.check()?.update(data)?;
        Ok(())
    }

    /// What uapi16_data_check_update_zeros() does.
    fn update_zeros(&mut self, size: u64) -> Result<(), uapi16_error> {
        self.check()?.update_zeros(size)?;
        Ok(())
    }

    /// What uapi16_data_check_finish() does: how many bytes the data is.
    /// The check is finished after that, also where it failed.
    fn finish(&mut self) -> Result<u64, uapi16_error> {
        self.process.check()?;
        let check = self.check.take().ok_or_else(uapi16_error::ended)?;
        Ok(check.finish()?)
    }
}

/// Makes options with the default features, the code point order and no
/// syncing. The default features are those of a manifest that lists none:
/// UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID,
/// UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256, UAPI16_FEATURE_SYMLINK,
/// UAPI16_FEATURE_DEVICE and UAPI16_FEATURE_HARDLINK. They are freed with
/// uapi16_manifest_options_free().
#[no_mangle]
extern "C" fn uapi16_manifest_options_new() -> *mut uapi16_manifest_options {
    uapi16_manifest_options::new().into_raw()
}

/// Sets the features to record to the `n` features at `features`, and no
/// others. A number that is no feature, other than UAPI16_FEATURE_NONE,
/// fails with -EINVAL, and the options are as they were. The features of
/// partitions are taken here, and refused when a manifest writer is made.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_set_features(
    o: *mut uapi16_manifest_options,
    features: *const FeatureNumber,
    n: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `features` is NULL or valid for
    // the read of `n` numbers that do not change during the call.
    let features = unsafe { FeatureList::new(features, n) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // else uses during the call.
    let options = unsafe { o.as_mut() };
    let set = match options {
        Some(options) => options.set_features(features),
        None => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(set)
}

/// Adds the `n` features at `features` to those to record. A number that is
/// no feature, other than UAPI16_FEATURE_NONE, fails with -EINVAL, and the
/// options are as they were.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_add_features(
    o: *mut uapi16_manifest_options,
    features: *const FeatureNumber,
    n: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `features` is NULL or valid for
    // the read of `n` numbers that do not change during the call.
    let features = unsafe { FeatureList::new(features, n) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // else uses during the call.
    let options = unsafe { o.as_mut() };
    let added = match options {
        Some(options) => options.add_features(features),
        None => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(added)
}

/// Takes the `n` features at `features` away from those to record. A number
/// that is no feature, other than UAPI16_FEATURE_NONE, fails with -EINVAL,
/// and the options are as they were.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_remove_features(
    o: *mut uapi16_manifest_options,
    features: *const FeatureNumber,
    n: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `features` is NULL or valid for
    // the read of `n` numbers that do not change during the call.
    let features = unsafe { FeatureList::new(features, n) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // else uses during the call.
    let options = unsafe { o.as_mut() };
    let removed = match options {
        Some(options) => options.remove_features(features),
        None => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(removed)
}

/// Sets the order of the file objects. UAPI16_ORDER_CODEPOINT is the only
/// one. UAPI16_ORDER_NONE is taken too, for a manifest that declares no
/// order, and any other number fails with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_set_order(o: *mut uapi16_manifest_options, order: OrderNumber) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // else uses during the call.
    let options = unsafe { o.as_mut() };
    let set = match options {
        Some(options) => options.set_order(order),
        None => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(set)
}

/// Sets whether the new file of uapi16_manifest_writer_create_at() and
/// uapi16_manifest_generate_at() is written to disk before
/// uapi16_manifest_writer_finish() or uapi16_manifest_generate_at()
/// returns, so that a crash after that does not lose it. It is off unless
/// set.
///
/// The file is synced before it gets its name, so that the name never
/// leads to a manifest that is not all on disk, and once more after it got
/// it, with the directory it is in, so that the name is on disk as well.
/// Nothing else is synced: uapi16_manifest_writer_open() and
/// uapi16_manifest_generate() write to a descriptor of the caller, which
/// the caller syncs.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_set_sync(o: *mut uapi16_manifest_options, sync: bool) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // else uses during the call.
    let options = unsafe { o.as_mut() };
    let set = match options {
        Some(options) => options.set_sync(sync),
        None => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(set)
}

/// Frees options. NULL is fine. Returns NULL, so that
/// `o = uapi16_manifest_options_free(o);` clears the pointer. A writer
/// that was made with them does not need them any more.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_options_free(o: *mut uapi16_manifest_options) -> *mut uapi16_manifest_options {
    // SAFETY: by the rules of the caller `o` is NULL or options that were
    // not freed, and nothing uses them after this call.
    unsafe { uapi16_manifest_options::free(o) }
}

/// Writes the manifest of the directory `top_fd` and everything below it
/// to a new file `name` in the directory `dir_fd`, and stores a report of
/// what it lists in `ret`, unless that is NULL. It is
/// uapi16_manifest_writer_create_at(), a walk of `top_fd` as the root, and
/// uapi16_manifest_writer_finish() in one call. `name` is what
/// uapi16_manifest_writer_create_at() takes, and `flags` is a set of
/// uapi16_add_flag_t. The manifest is sorted, so options whose order is
/// UAPI16_ORDER_NONE fail with -EINVAL.
///
/// Symbolic links are recorded and never followed. Mount points are not
/// crossed unless UAPI16_ADD_CROSS_MOUNTS is given: one that is a
/// directory is written as an empty directory. The walk mounts nothing: an
/// automount point that nothing is mounted on yet is written as an empty
/// directory with its own attributes, with any flags. There is one known
/// limit. The walk looks at a directory before it opens it, and a
/// directory that becomes an automount point in between has its file
/// system mounted by that open. The walk fails with UAPI16_ERROR_CHANGED
/// then. That takes someone who can mount in the mount namespace of the
/// caller, or an automount unit that is started at that moment.
///
/// A file that changes while it is read fails with UAPI16_ERROR_CHANGED,
/// where its size, its times or its number of links show the change.
///
/// Where the features record UAPI16_FEATURE_FLAG_HIDDEN,
/// UAPI16_FEATURE_FLAG_SYSTEM or UAPI16_FEATURE_FLAG_ARCHIVE, a tree on a
/// file system without DOS attributes fails before anything is read.
///
/// The data of a regular file of more than 1 TiB is not hashed. Where the
/// manifest records hashes, or hard links and the file has more than one
/// name, the walk fails at such a file with UAPI16_ERROR_IO and EFBIG,
/// before anything is read of it.
///
/// A walk of the directory the new file is in passes over what the
/// manifest keeps there, and over the new file under its temporary name.
/// On a file system without O_TMPFILE, such as FAT, a manifest that is
/// created inside the tree it describes can make the walk of a large tree
/// fail with UAPI16_ERROR_CHANGED, since the room it takes changes its own
/// directory while the walk reads it.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_generate_at(
    o: *const uapi16_manifest_options,
    dir_fd: c_int,
    name: *const c_char,
    top_fd: c_int,
    flags: uapi16_add_flags_t,
    ret: *mut *mut uapi16_manifest_report,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses during the
    // call.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // changes during the call.
    let options = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `dir_fd` and `top_fd` are open
    // during the call unless they are negative.
    let (dir, top) = unsafe { (Descriptor::new(dir_fd), Descriptor::new(top_fd)) };
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    let generated = match options {
        Some(options) if reterr.is_clear() => options.generate_at(dir, name, top, flags),
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_manifest_report::returned(generated, ret, reterr) }
}

/// Writes the manifest of the directory `top_fd` and everything below it
/// to the descriptor `fd`, and stores a report of what it lists in `ret`,
/// unless that is NULL. It is uapi16_manifest_writer_open(), a walk of
/// `top_fd` as the root, and uapi16_manifest_writer_finish() in one call.
/// `flags` is a set of uapi16_add_flag_t, and the walk is the one of
/// uapi16_manifest_generate_at(). The manifest is sorted, so options whose
/// order is UAPI16_ORDER_NONE fail with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_generate(
    o: *const uapi16_manifest_options,
    fd: c_int,
    top_fd: c_int,
    flags: uapi16_add_flags_t,
    ret: *mut *mut uapi16_manifest_report,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses during the
    // call.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // changes during the call.
    let options = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `fd` and `top_fd` are open during
    // the call unless they are negative.
    let (fd, top) = unsafe { (Descriptor::new(fd), Descriptor::new(top_fd)) };
    let generated = match options {
        Some(options) if reterr.is_clear() => options.generate(fd, top, flags),
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_manifest_report::returned(generated, ret, reterr) }
}

/// Makes a writer for a new manifest file `name` in the directory
/// `dir_fd`, and stores it in `ret`. The file appears when
/// uapi16_manifest_writer_finish() gives it its name, with the whole
/// manifest in it. Until then nothing has the name, and a writer that is
/// freed instead leaves nothing behind. The writer sorts, so options whose
/// order is UAPI16_ORDER_NONE fail with -EINVAL.
///
/// The writer borrows `dir_fd` until it is freed: the caller keeps it open
/// until then, and closes it itself.
///
/// `name` is a path, and is taken as the bytes it is, which need not be
/// UTF-8. One with more than one component names a file in a directory
/// below `dir_fd`. The components on the way are opened one at a time,
/// each without following a symbolic link, and the file goes into the
/// directory its last component is in. A symbolic link on the way fails
/// with -ELOOP, and anything else on the way that is no directory with
/// -ENOTDIR. A name that names no file below `dir_fd` fails with -EINVAL
/// before anything is looked up: one that is empty or that ends in a
/// slash, "." or "..", an absolute one, and one with "." or ".." on the
/// way. For a file in a directory that is not below `dir_fd`, open that
/// directory and pass it as `dir_fd`.
///
/// This never replaces a file: where something has the name already, it
/// fails with UAPI16_ERROR_EXISTS. The name is checked again when the file
/// gets it. To write over a file, open it and use
/// uapi16_manifest_writer_open().
///
/// On FAT the new file gets the mode the mount gives every file, and it
/// can't be larger than 4 GiB, so a manifest there holds about 2e7 file
/// objects at most: uapi16_manifest_writer_finish() fails with EFBIG for
/// more. A tree with more than about 9e6 files that have several names
/// fails with EFBIG already while it is added.
///
/// The manifest of a large tree takes room on disk while it is built, in
/// the directory the file goes to. On a file system without O_TMPFILE, such
/// as FAT, the new file is in that directory under a temporary name until
/// uapi16_manifest_writer_finish().
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_writer_create_at(
    o: *const uapi16_manifest_options,
    dir_fd: c_int,
    name: *const c_char,
    ret: *mut *mut uapi16_manifest_writer,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses during the
    // call.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // changes during the call.
    let options = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `dir_fd` is open during the call
    // unless it is negative.
    let dir = unsafe { Descriptor::new(dir_fd) };
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    // A writer that nobody takes would be dropped, so no place for it is
    // no call. Neither is a place for the error that holds something.
    let made = match options {
        // SAFETY: by the rules of the caller `dir_fd` stays open until the
        // writer is freed, which is when it is dropped.
        Some(options) if !ret.is_null() && reterr.is_clear() => unsafe { options.create_at(dir, name) },
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_manifest_writer::returned(made, ret, reterr) }
}

/// Makes a writer for a manifest that is written to the descriptor `fd`,
/// and stores it in `ret`. Nothing is written before
/// uapi16_manifest_writer_finish(), and the manifest is complete once that
/// returns 0. The writer borrows `fd` until it is freed: the caller keeps it
/// open until then, and closes it itself. The writer sorts, so options whose
/// order is UAPI16_ORDER_NONE fail with -EINVAL.
///
/// The manifest of a large tree takes room on disk while it is built, in
/// the directory TMPDIR names, or in /var/tmp where it names none. Where it
/// is on FAT, which can't hold a file of more than 4 GiB, a manifest of
/// more than about 3e7 file objects fails with EFBIG, and a tree with
/// more than about 9e6 files that have several names fails with EFBIG
/// already while it is added. A TMPDIR that is set is used as it is. It has
/// to be a directory the caller trusts, since whoever controls it can
/// change the manifest.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_writer_open(
    o: *const uapi16_manifest_options,
    fd: c_int,
    ret: *mut *mut uapi16_manifest_writer,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses during the
    // call.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or options that nothing
    // changes during the call.
    let options = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `fd` is open during the call
    // unless it is negative.
    let fd = unsafe { Descriptor::new(fd) };
    // A writer that nobody takes would be dropped, so no place for it is
    // no call. Neither is a place for the error that holds something.
    let made = match options {
        // SAFETY: by the rules of the caller `fd` stays open until the
        // writer is freed, which is when it is dropped.
        Some(options) if !ret.is_null() && reterr.is_clear() => unsafe { options.open(fd) },
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_manifest_writer::returned(made, ret, reterr) }
}

/// Adds the file object `o`. It is checked as a writer of records checks a
/// file object, but for where it comes, which
/// uapi16_manifest_writer_finish() checks. An object that is refused is not
/// added, and the writer is as it was. The writer keeps a copy: the caller
/// can change the object, add it again under another name, or free it.
///
/// The objects can come in any order. The object with the empty name is the
/// root, and says what the root directory and its file system are like. A
/// root with a validity, a validity window or a GPT disk UUID, which only a
/// root that a reader read can have, is refused, since this writer writes
/// none of them. uapi16_writer_begin() writes them. The first object of a
/// directory says what the directory is like. Two equal objects of one name
/// are listed once, and two that differ and are not both directories are
/// UAPI16_ERROR_DUPLICATE, from uapi16_manifest_writer_finish().
///
/// Objects with the same token are names of one file, and say the same
/// about it. One that does not fails the add with
/// UAPI16_ERROR_HARDLINK_MISMATCH, and uapi16_error_hardlink_path() names the
/// first of them.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_writer_add_object(
    w: *mut uapi16_manifest_writer,
    o: *const uapi16_file_object,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `w` is NULL or an object that
    // nothing else uses during the call, and `o` is NULL or an object that
    // nothing changes during it.
    let (writer, object) = unsafe { (w.as_mut(), o.as_ref()) };
    let added = match (writer, object) {
        (Some(writer), Some(object)) if reterr.is_clear() => writer.add_object(object),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(added)
}

/// Writes the manifest, and stores a report of what it lists in `ret`,
/// unless that is NULL. With uapi16_manifest_writer_create_at() the file
/// gets its name now, unless something took the name since, which is
/// UAPI16_ERROR_EXISTS. Where something fails once the file has its name,
/// such as the sync of its directory, the file keeps the name, and the
/// call fails all the same.
///
/// What the adds left open fails here: two different files under one
/// name, a directory that was not added where the features need it, a file
/// that is not a directory and that files were added below, and a record
/// that is too large.
///
/// The writer is finished after this, whether it succeeded or failed.
/// Every later add and finish on it fails with UAPI16_ERROR_ENDED, and
/// uapi16_manifest_writer_free() frees it.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_writer_finish(
    w: *mut uapi16_manifest_writer,
    ret: *mut *mut uapi16_manifest_report,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses during the
    // call.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `w` is NULL or a writer that
    // nothing else uses during the call.
    let writer = unsafe { w.as_mut() };
    let finished = match writer {
        Some(writer) if reterr.is_clear() => writer.finish(),
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_manifest_report::returned(finished, ret, reterr) }
}

/// Frees a writer. One that was not finished writes nothing and leaves no
/// file behind. NULL is fine. Returns NULL. The descriptor of the caller
/// stays open.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_writer_free(w: *mut uapi16_manifest_writer) -> *mut uapi16_manifest_writer {
    // SAFETY: by the rules of the caller `w` is NULL or a writer that was
    // not freed, and nothing uses it after this call.
    unsafe { uapi16_manifest_writer::free(w) }
}

/// How many regular files the manifest lists. 0 for NULL, as for every
/// function of a report.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_files(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.files())
}

/// How many directories the manifest lists, the root among them.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_directories(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.directories())
}

/// How many other files the manifest lists: symbolic links, FIFOs, device
/// nodes and sockets.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_others(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.others())
}

/// The sizes of the regular files, added up. The data of a file with more
/// than one name counts for each.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_bytes(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.bytes())
}

/// How many files UAPI16_ADD_GRACEFUL left out, a directory with everything
/// below it as one.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_entries_omitted(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.entries_omitted())
}

/// How many fields were left out of the file objects: the names of owners
/// that the user database does not have, the user and group IDs 65535 and
/// 4294967295, modification times before 1970 or after 2554, and the UUID
/// or the volume serial number of a file system that gives none.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_fields_omitted(r: *const uapi16_manifest_report) -> u64 {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed.
    let report = unsafe { r.as_ref() };
    report.map_or(0, |r| r.report.fields_omitted())
}

/// Frees a report. NULL is fine. Returns NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_manifest_report_free(r: *mut uapi16_manifest_report) -> *mut uapi16_manifest_report {
    // SAFETY: by the rules of the caller `r` is NULL or a report that was
    // not freed, and nothing uses it after this call.
    unsafe { uapi16_manifest_report::free(r) }
}

/// Starts to read a manifest from the descriptor `fd`, reads its root, and
/// stores the reader in `ret`. The reader borrows `fd` until it is freed:
/// the caller keeps it open until then, and closes it itself. On a
/// descriptor that does not block, EAGAIN fails the open and loses what it
/// read, so the descriptor has to block, or already hold the root and the
/// start of the next record.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_open(
    fd: c_int,
    ret: *mut *mut uapi16_reader,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `fd` is one of its descriptors
    // unless it is negative.
    let fd = unsafe { Descriptor::new(fd) };
    let made = if !ret.is_null() && reterr.is_clear() {
        // SAFETY: by the rules of the caller `fd` stays open until the
        // reader is freed, which is when it is dropped.
        unsafe { uapi16_reader::open(fd) }
    } else {
        Err(uapi16_error::misuse())
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_reader::returned(made, ret, reterr) }
}

/// The root of the manifest: an object with the empty name. It belongs to
/// the reader and lives until the reader is freed. NULL for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_root(r: *const uapi16_reader) -> *const uapi16_file_object {
    if r.is_null() {
        return ptr::null();
    }
    // SAFETY: by the rules of the caller `r` is an object, so its root is
    // in bounds of it. The pointer comes from `r` itself and not from a
    // reference to the reader: the caller keeps it, and the next call that
    // changes the reader takes the reader as a whole, which ends every
    // pointer that came from an earlier reference to it.
    unsafe { &raw const (*r).root }
}

/// Whether the manifest records the feature `feature`. A manifest that lists
/// no features records the default features. false for a number that is no
/// feature, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_has_feature(r: *const uapi16_reader, feature: FeatureNumber) -> bool {
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    reader.is_some_and(|reader| reader.reader.root().recorded_features().has_number(feature))
}

/// Feature `i` of those the manifest records, counted from 0 in the order
/// of their numbers. UAPI16_FEATURE_NONE past the last one, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_feature(r: *const uapi16_reader, i: usize) -> FeatureNumber {
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    reader.map_or(uapi16_feature_t::UAPI16_FEATURE_NONE as FeatureNumber, |reader| {
        reader.reader.root().recorded_features().number_at(i)
    })
}

/// The order the manifest declares, or UAPI16_ORDER_NONE where it declares
/// none.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_order(r: *const uapi16_reader) -> OrderNumber {
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    let order = reader.map_or(uapi16_order_t::UAPI16_ORDER_NONE, uapi16_reader::order);
    order as OrderNumber
}

/// Requires the manifest to declare the order `order`, as a caller does
/// that relies on it. A manifest that does not fails with
/// UAPI16_ERROR_MANIFEST, even if its file objects are in that order. The
/// reader checks the file objects against the order the manifest declares
/// while it reads them. UAPI16_ORDER_NONE is no order to require, and fails
/// with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_require_order(
    r: *const uapi16_reader,
    order: OrderNumber,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    let required = match reader {
        Some(reader) if reterr.is_clear() => reader.require_order(order),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(required)
}

/// Checks that the manifest may be used at the time `now_usec`, in
/// microseconds since 1970: that its root is not revoked and that the time
/// is inside its validity window.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_check_validity(
    r: *const uapi16_reader,
    now_usec: u64,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    let checked = match reader {
        Some(reader) if reterr.is_clear() => reader.check_validity(now_usec),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(checked)
}

/// Reads on, and returns what it read as a uapi16_read_t, or a negative
/// errno:
///
/// - UAPI16_READ_FILE: one file object, which is in `*ret`.
/// - UAPI16_READ_SIGNATURES: the file objects have ended, and signature
///   objects follow. The next call passes over them, and checks them.
/// - UAPI16_READ_END: the trailer was read and checked, and the manifest is
///   complete. Every later call returns this again.
///
/// `ret` points to NULL or to a file object of the caller. Where it points
/// to NULL, a file object that is read is stored there as a new object.
/// Where it points to an object, that object is cleared and filled again,
/// and nothing of what it held before is left: the strings and bytes its
/// getters returned before are gone with it. So one object serves a whole
/// loop, as the buffer of getline() does. A call that reads no file object
/// leaves `*ret` as it is. The object stays the caller's, to free with
/// uapi16_file_object_free(), also after a call that failed.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_next(
    r: *mut uapi16_reader,
    ret: *mut *mut uapi16_file_object,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing else uses during the call.
    let reader = unsafe { r.as_mut() };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the read
    // and the write of a pointer, which is NULL or a file object that
    // nothing else uses during the call.
    let kept = unsafe { Refill::new(ret) };
    let read = match (reader, kept) {
        (Some(reader), Some(kept)) if reterr.is_clear() => reader.next(kept),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.read(read)
}

/// Reads the next signature object, and returns what it read as a
/// uapi16_read_t, or a negative errno:
///
/// - UAPI16_READ_SIGNATURE: one signature object, which is in `*ret`.
/// - UAPI16_READ_END: the trailer was read and checked, and the manifest is
///   complete. Every later call returns this again.
///
/// The signature objects come after the file objects: a call before
/// uapi16_reader_next() returned UAPI16_READ_SIGNATURES or UAPI16_READ_END
/// fails with -EINVAL. `ret` points to NULL or to a signature object of the
/// caller, and is used as uapi16_reader_next() uses its `ret`. The object is
/// freed with uapi16_signature_free().
#[no_mangle]
unsafe extern "C" fn uapi16_reader_next_signature(
    r: *mut uapi16_reader,
    ret: *mut *mut uapi16_signature,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing else uses during the call.
    let reader = unsafe { r.as_mut() };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the read
    // and the write of a pointer, which is NULL or a signature object that
    // nothing else uses during the call.
    let kept = unsafe { Refill::new(ret) };
    let read = match (reader, kept) {
        (Some(reader), Some(kept)) if reterr.is_clear() => reader.next_signature(kept),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.read(read)
}

/// Stores in `ret` how many bytes at the start of the manifest its signature
/// objects sign: all that comes before the record of the first of them, up
/// to its record separator. -ENODATA before uapi16_reader_next() returned
/// UAPI16_READ_SIGNATURES, and so for a manifest without signature objects.
///
/// The library does not verify signatures. With this number and the
/// signature objects a caller can.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_signed_len(r: *const uapi16_reader, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing changes during the call.
    let reader = unsafe { r.as_ref() };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a number.
    let ret = unsafe { Place::new(ret) };
    let got = match (reader, ret.needed()) {
        (Some(reader), Ok(ret)) => reader.signed_len().map(|len| ret.store(len)),
        _ => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(got)
}

/// Frees a reader, and its root with it. NULL is fine. Returns NULL. The
/// descriptor of the caller stays open.
#[no_mangle]
unsafe extern "C" fn uapi16_reader_free(r: *mut uapi16_reader) -> *mut uapi16_reader {
    // SAFETY: by the rules of the caller `r` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_reader::free(r) }
}

/// Starts a manifest on the descriptor `fd` with the root `root`, and stores
/// the writer in `ret`. The features and the order are those of the options
/// `o`, and options with UAPI16_ORDER_NONE make a manifest that declares no
/// order. `root` is an object with the empty name, or NULL for a root that
/// says nothing. The writer borrows `fd` until it is freed: the caller keeps
/// it open until then, and closes it itself.
#[no_mangle]
unsafe extern "C" fn uapi16_writer_begin(
    o: *const uapi16_manifest_options,
    fd: c_int,
    root: *const uapi16_file_object,
    ret: *mut *mut uapi16_writer,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` and `root` are NULL or objects
    // that nothing changes during the call.
    let (options, root) = unsafe { (o.as_ref(), root.as_ref()) };
    // SAFETY: by the rules of the caller `fd` is one of its descriptors
    // unless it is negative.
    let fd = unsafe { Descriptor::new(fd) };
    let made = match options {
        // SAFETY: by the rules of the caller `fd` stays open until the
        // writer is freed, which is when it is dropped.
        Some(options) if !ret.is_null() && reterr.is_clear() => unsafe { uapi16_writer::begin(options, fd, root) },
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_writer::returned(made, ret, reterr) }
}

/// Writes the file object `o`. The writer checks it as a reader does: it has
/// no field of a feature the manifest does not record, it comes right after
/// the object of its directory, and it keeps to the order. An object that is
/// refused is not written, and the writer goes on as if it had not been
/// given it.
///
/// In a manifest that declares no order, the order of the names is not
/// checked. A name that comes again right after the entries of the directory
/// it names is still refused. One that comes again later is not found.
#[no_mangle]
unsafe extern "C" fn uapi16_writer_file(
    w: *mut uapi16_writer,
    o: *const uapi16_file_object,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `w` is NULL or an object that
    // nothing else uses during the call, and `o` is NULL or an object that
    // nothing changes during it.
    let (writer, object) = unsafe { (w.as_mut(), o.as_ref()) };
    let written = match (writer, object) {
        (Some(writer), Some(object)) if reterr.is_clear() => writer.file(object),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(written)
}

/// Writes the signature object `s`. No file object can follow it: it would
/// be one the signature does not cover. The signature objects of a manifest
/// sign the manifest up to the first of them, which is all that the writer
/// wrote to its descriptor before the first call of this.
#[no_mangle]
unsafe extern "C" fn uapi16_writer_signature(
    w: *mut uapi16_writer,
    s: *const uapi16_signature,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `w` is NULL or an object that
    // nothing else uses during the call, and `s` is NULL or an object that
    // nothing changes during it.
    let (writer, signature) = unsafe { (w.as_mut(), s.as_ref()) };
    let written = match (writer, signature) {
        (Some(writer), Some(signature)) if reterr.is_clear() => writer.signature(signature),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(written)
}

/// Ends the manifest with its trailer. The writer is finished after this,
/// whether it succeeded or failed: every later call on it fails with
/// UAPI16_ERROR_ENDED, and uapi16_writer_free() frees it.
#[no_mangle]
unsafe extern "C" fn uapi16_writer_finish(w: *mut uapi16_writer, reterr: *mut *mut uapi16_error) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `w` is NULL or an object that
    // nothing else uses during the call.
    let writer = unsafe { w.as_mut() };
    let finished = match writer {
        Some(writer) if reterr.is_clear() => writer.finish(),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(finished)
}

/// Frees a writer of records. NULL is fine. Returns NULL. The descriptor of
/// the caller stays open.
#[no_mangle]
unsafe extern "C" fn uapi16_writer_free(w: *mut uapi16_writer) -> *mut uapi16_writer {
    // SAFETY: by the rules of the caller `w` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_writer::free(w) }
}

/// Makes a signature object of the mechanism `mechanism`, without a key and
/// without data, and stores it in `ret`. The specification has "openpgp" and
/// "pkcs7".
#[no_mangle]
unsafe extern "C" fn uapi16_signature_new(mechanism: *const c_char, ret: *mut *mut uapi16_signature) -> c_int {
    // SAFETY: by the rules of the caller `mechanism` is NULL or a string
    // that does not change during the call.
    let mechanism = unsafe { Text::new(mechanism) };
    let made = if ret.is_null() {
        Err(uapi16_error::misuse())
    } else {
        uapi16_signature::new(mechanism)
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_signature::returned(made, ret, ErrorPlace::NONE) }
}

/// How the signature was made: its mechanism. NULL for NULL. The string
/// belongs to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_mechanism(s: *const uapi16_signature) -> *const c_char {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing changes during the call.
    let signature = unsafe { s.as_ref() };
    signature.map_or(ptr::null(), uapi16_signature::mechanism)
}

/// Sets what identifies the key, such as its fingerprint: the `size` bytes
/// at `key`. A `key` of NULL takes it away.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_set_key(s: *mut uapi16_signature, key: *const c_void, size: usize) -> c_int {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing else uses during the call.
    let signature = unsafe { s.as_mut() };
    // SAFETY: by the rules of the caller `key` is NULL or valid for the
    // read of `size` bytes.
    let key = unsafe { uapi16_signature::bytes(key, size) };
    let set = signature.ok_or_else(uapi16_error::misuse).and_then(|signature| {
        let key = key.map(Bytes::get).transpose()?.map(<[u8]>::to_vec);
        signature.signature_mut().map(|signature| signature.set_key(key))
    });
    ErrorPlace::NONE.returned(set)
}

/// What identifies the key, and its size in `ret_size`, unless that is NULL.
/// No NUL ends the bytes. NULL and 0 where the object has none. The bytes
/// belong to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_key(s: *const uapi16_signature, ret_size: *mut usize) -> *const c_void {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing changes during the call.
    let signature = unsafe { s.as_ref() };
    // SAFETY: by the rules of the caller `ret_size` is NULL or valid for
    // the write of a size.
    let ret_size = unsafe { Place::new(ret_size) };
    uapi16_signature::bytes_out(signature.and_then(|signature| signature.signature.key()), ret_size)
}

/// Sets the signature: the `size` bytes at `data`. A `data` of NULL takes it
/// away.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_set_data(s: *mut uapi16_signature, data: *const c_void, size: usize) -> c_int {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing else uses during the call.
    let signature = unsafe { s.as_mut() };
    // SAFETY: by the rules of the caller `data` is NULL or valid for the
    // read of `size` bytes.
    let data = unsafe { uapi16_signature::bytes(data, size) };
    let set = signature.ok_or_else(uapi16_error::misuse).and_then(|signature| {
        let data = data.map(Bytes::get).transpose()?.map(<[u8]>::to_vec);
        signature.signature_mut().map(|signature| signature.set_data(data))
    });
    ErrorPlace::NONE.returned(set)
}

/// The signature, and its size in `ret_size`, unless that is NULL. No NUL
/// ends the bytes. NULL and 0 where the object has none. The bytes belong to
/// the object.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_data(s: *const uapi16_signature, ret_size: *mut usize) -> *const c_void {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing changes during the call.
    let signature = unsafe { s.as_ref() };
    // SAFETY: by the rules of the caller `ret_size` is NULL or valid for
    // the write of a size.
    let ret_size = unsafe { Place::new(ret_size) };
    uapi16_signature::bytes_out(signature.and_then(|signature| signature.signature.data()), ret_size)
}

/// Frees a signature object. NULL is fine. Returns NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_signature_free(s: *mut uapi16_signature) -> *mut uapi16_signature {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_signature::free(s) }
}

impl uapi16_file_object {
    /// What a setter returns that changes the object `o` points to with
    /// `set`: 0, or a negative errno. NULL is no object.
    ///
    /// # Safety
    ///
    /// `o` is NULL, or an object of a caller that nothing else uses during
    /// the call.
    unsafe fn change(
        o: *mut uapi16_file_object,
        set: impl FnOnce(&mut uapi16_file_object) -> Result<(), uapi16_error>,
    ) -> c_int {
        // SAFETY: `o` is NULL or an object nothing else uses now, as the
        // caller says.
        let object = unsafe { o.as_mut() };
        ErrorPlace::NONE.returned(object.ok_or_else(uapi16_error::misuse).and_then(set))
    }

    /// What a getter returns that stores in `ret` what `get` reads of the
    /// object `o` points to: 0, or a negative errno, for which nothing is
    /// stored. NULL is no object, and no place to store anything.
    ///
    /// # Safety
    ///
    /// `o` is NULL, or an object of a caller that nothing changes during
    /// the call. `ret` is NULL, or valid for the write of a `T`.
    unsafe fn read<T>(
        o: *const uapi16_file_object,
        ret: *mut T,
        get: impl FnOnce(&uapi16_file_object) -> Result<T, uapi16_error>,
    ) -> c_int {
        // SAFETY: `o` is NULL or an object nothing changes now, as the
        // caller says.
        let object = unsafe { o.as_ref() };
        // SAFETY: `ret` is NULL or valid for the write of a `T`, as the
        // caller says.
        let ret = unsafe { Place::new(ret) };
        let got = match (object, ret.needed()) {
            (Some(object), Ok(ret)) => get(object).map(|value| ret.store(value)),
            _ => Err(uapi16_error::misuse()),
        };
        ErrorPlace::NONE.returned(got)
    }
}

/// Makes a file object for the regular file `name` that says nothing else
/// about it, and stores it in `ret`. `name` is the path of the file below
/// the root of the tree, as a manifest has it: components separated by
/// single slashes, none of them empty, "." or "..". The empty string makes
/// the root. A name that a manifest can't hold fails with
/// UAPI16_ERROR_INVALID_ARGUMENT, and uapi16_error_name_problem() says which
/// rule it breaks.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_new(
    name: *const c_char,
    ret: *mut *mut uapi16_file_object,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    let made = if !ret.is_null() && reterr.is_clear() {
        uapi16_file_object::new(name)
    } else {
        Err(uapi16_error::misuse())
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_file_object::returned(made, ret, reterr) }
}

/// Frees a file object. NULL is fine. Returns NULL. An object of
/// uapi16_reader_root() belongs to its reader and is not freed with this.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_free(o: *mut uapi16_file_object) -> *mut uapi16_file_object {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_file_object::free(o) }
}

/// Gives the object the name `name`, which uapi16_file_object_new() checks
/// the same way. The names of one file carry the same fields: a caller adds
/// the object under one name, sets the next name and adds it again. A name
/// that is refused leaves the object as it was. The root keeps its name, and
/// no other object takes the empty one: both fail with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_name(
    o: *mut uapi16_file_object,
    name: *const c_char,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing else uses during the call.
    let object = unsafe { o.as_mut() };
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    let set = match object {
        Some(object) if reterr.is_clear() => object.set_name(name),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(set)
}

/// The name of the file: its path below the root. The root is the empty
/// string. NULL for NULL. The string belongs to the object and lives until
/// the name is set again or the object is freed.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_name(o: *const uapi16_file_object) -> *const c_char {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(ptr::null(), uapi16_file_object::name)
}

/// Sets the type of the file from an `st_mode` as stat() gives it: S_IFREG,
/// S_IFDIR, S_IFLNK, S_IFIFO, S_IFCHR, S_IFBLK or S_IFSOCK. Only the bits of
/// the file type are read, and bits that are none of these fail with
/// -EINVAL. The root is a directory: S_IFDIR is fine for it, and any other
/// type fails with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_type(o: *mut uapi16_file_object, st_mode: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_type(st_mode)) }
}

/// The type of the file, as the bits of the file type in an `st_mode`. An
/// object that was given none is a regular file. 0 for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_type(o: *const uapi16_file_object) -> u32 {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(0, |object| object.object.inode_type().st_mode())
}

/// Sets the access mode from an `st_mode` as stat() gives it: the permission
/// bits with the set-user-ID, the set-group-ID and the sticky bit. The bits
/// of the file type are not read.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_mode(o: *mut uapi16_file_object, st_mode: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_mode(st_mode)) }
}

/// Stores the access mode in `ret`: the permission bits with the
/// set-user-ID, the set-group-ID and the sticky bit, and no bits of a file
/// type.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_mode(o: *const uapi16_file_object, ret: *mut u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret, |object| {
            object.inode()?.mode().map(Mode::bits).ok_or_else(uapi16_error::absent)
        })
    }
}

/// Sets the user ID of the owner.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_uid(o: *mut uapi16_file_object, uid: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.inode_mut().map(|inode| inode.set_uid(Some(uid)))) }
}

/// Stores the user ID of the owner in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_uid(o: *const uapi16_file_object, ret: *mut u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret, |object| object.inode()?.uid().ok_or_else(uapi16_error::absent)) }
}

/// Sets the group ID of the owner.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_gid(o: *mut uapi16_file_object, gid: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.inode_mut().map(|inode| inode.set_gid(Some(gid)))) }
}

/// Stores the group ID of the owner in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_gid(o: *const uapi16_file_object, ret: *mut u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret, |object| object.inode()?.gid().ok_or_else(uapi16_error::absent)) }
}

/// Sets the name of the owning user.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_user_name(o: *mut uapi16_file_object, name: *const c_char) -> c_int {
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_user_name(name)) }
}

/// The name of the owning user, or NULL where the object has none. The
/// string belongs to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_user_name(o: *const uapi16_file_object) -> *const c_char {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(ptr::null(), uapi16_file_object::user_name)
}

/// Sets the name of the owning group.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_group_name(o: *mut uapi16_file_object, name: *const c_char) -> c_int {
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_group_name(name)) }
}

/// The name of the owning group, or NULL where the object has none. The
/// string belongs to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_group_name(o: *const uapi16_file_object) -> *const c_char {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(ptr::null(), uapi16_file_object::group_name)
}

/// Sets the modification time, in nanoseconds since 1970.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_mtime_nsec(o: *mut uapi16_file_object, nsec: u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe {
        uapi16_file_object::change(o, |object| {
            object.inode_mut().map(|inode| inode.set_mtime_nsec(Some(nsec)))
        })
    }
}

/// Stores the modification time in `ret`, in nanoseconds since 1970.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_mtime_nsec(o: *const uapi16_file_object, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret, |object| {
            object.inode()?.mtime_nsec().ok_or_else(uapi16_error::absent)
        })
    }
}

/// Sets the size of the data in bytes. For a symbolic link that is the
/// length of its target.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_size(o: *mut uapi16_file_object, size: u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.file_mut().map(|file| file.set_size(Some(size)))) }
}

/// Stores the size of the data in `ret`, in bytes.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_size(o: *const uapi16_file_object, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret, |object| object.file()?.size().ok_or_else(uapi16_error::absent)) }
}

/// Sets the SHA-256 hash of the data to the one at `sha256`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_sha256(
    o: *mut uapi16_file_object,
    sha256: *const uapi16_sha256_digest_t,
) -> c_int {
    // SAFETY: by the rules of the caller `sha256` is NULL or valid for the
    // read of a hash, which is its bytes.
    let sha256 = unsafe { sha256.cast::<[u8; UAPI16_SHA256_SIZE]>().as_ref() };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe {
        uapi16_file_object::change(o, |object| {
            let sha256 = Sha256::from(*sha256.ok_or_else(uapi16_error::misuse)?);
            object.file_mut().map(|file| file.set_sha256(Some(sha256)))
        })
    }
}

/// Stores the SHA-256 hash of the data in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_sha256(
    o: *const uapi16_file_object,
    ret: *mut uapi16_sha256_digest_t,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret.cast(), |object| {
            object
                .file()?
                .sha256()
                .map(<[u8; Sha256::SIZE]>::from)
                .ok_or_else(uapi16_error::absent)
        })
    }
}

/// Sets the major number of a device node.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_major(o: *mut uapi16_file_object, major: u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.file_mut().map(|file| file.set_major(Some(major)))) }
}

/// Stores the major number of a device node in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_major(o: *const uapi16_file_object, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret, |object| object.file()?.major().ok_or_else(uapi16_error::absent)) }
}

/// Sets the minor number of a device node.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_minor(o: *mut uapi16_file_object, minor: u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.file_mut().map(|file| file.set_minor(Some(minor)))) }
}

/// Stores the minor number of a device node in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_minor(o: *const uapi16_file_object, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret, |object| object.file()?.minor().ok_or_else(uapi16_error::absent)) }
}

/// Sets the token of the file. The objects that carry the same token are
/// names of one file. Any number but 0 is a token, and
/// UAPI16_INODE_TOKEN_NONE takes the token away.
/// uapi16_manifest_writer_add_object() takes the numbers of the caller as
/// they are and gives the files the numbers the specification asks for.
/// uapi16_writer_file() writes the token as it is, so its caller numbers the
/// files itself: from 1, in the order they first come in the manifest.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_inode_token(
    o: *mut uapi16_file_object,
    token: uapi16_inode_token_t,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_inode_token(token)) }
}

/// Stores the token of the file in `ret`. -ENODATA where the object has
/// none: a file of no other name.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_inode_token(
    o: *const uapi16_file_object,
    ret: *mut uapi16_inode_token_t,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret, |object| {
            let token = object.file()?.inode_token().map(NonZeroU64::get);
            token.ok_or_else(uapi16_error::absent)
        })
    }
}

/// Makes the object list its extended attributes of the user namespace, and
/// lists none: the file has none, until uapi16_file_object_add_user_xattr()
/// adds one. An object that does not list them says nothing about them.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_user_xattrs(o: *mut uapi16_file_object) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, uapi16_file_object::set_user_xattrs) }
}

/// Adds the extended attribute `name` of the user namespace with the `size`
/// bytes at `value` as its value, or gives it that value where the object
/// lists it already. `name` is the name without "user." in front. The object
/// lists its extended attributes after this.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_add_user_xattr(
    o: *mut uapi16_file_object,
    name: *const c_char,
    value: *const c_void,
    size: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    // SAFETY: by the rules of the caller `value` is NULL or valid for the
    // read of `size` bytes, unless `size` is 0.
    let value = unsafe { Bytes::new(value, size) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.add_user_xattr(name, value)) }
}

/// Stores in `ret_count` how many extended attributes of the user namespace
/// the object lists. -ENODATA where it says nothing about them.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_user_xattrs(o: *const uapi16_file_object, ret_count: *mut usize) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret_count` is NULL or valid
    // for the write of what is stored there.
    unsafe { uapi16_file_object::read(o, ret_count, |object| object.user_xattrs()) }
}

/// Stores the name, the value and the size of the value of the extended
/// attribute number `i`, counting from 0 in the order of the names. The name
/// comes without "user." in front, and no NUL ends the value. Each of the
/// three can be NULL. An `i` that is not below the count of
/// uapi16_file_object_user_xattrs() fails with -EINVAL. The name and the
/// value belong to the object and live until it is changed or freed.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_user_xattr(
    o: *const uapi16_file_object,
    i: usize,
    ret_name: *mut *const c_char,
    ret_value: *mut *const c_void,
    ret_size: *mut usize,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller each of the three is NULL or valid
    // for the write of what is stored there.
    let (ret_name, ret_value, ret_size) =
        unsafe { (Place::new(ret_name), Place::new(ret_value), Place::new(ret_size)) };
    let got = object
        .ok_or_else(uapi16_error::misuse)
        .and_then(|object| object.user_xattr(i));
    ErrorPlace::NONE.returned(got.map(|(name, value, size)| {
        ret_name.store(name);
        ret_value.store(value);
        ret_size.store(size);
    }))
}

/// Sets whether the file is read-only: UAPI16_READ_ONLY_YES or
/// UAPI16_READ_ONLY_NO. UAPI16_READ_ONLY_UNSTATED takes the field away. Any
/// other number fails with -EINVAL. The field stands for the read-only
/// attribute of DOS too.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_read_only(o: *mut uapi16_file_object, read_only: ReadOnlyNumber) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_read_only(read_only)) }
}

/// Whether the file is read-only. UAPI16_READ_ONLY_UNSTATED where the object
/// does not say, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_read_only(o: *const uapi16_file_object) -> ReadOnlyNumber {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    let read_only = object.and_then(|object| object.object.inode().read_only());
    uapi16_read_only_t::of(read_only) as ReadOnlyNumber
}

/// Sets the Linux inode flags, as the bits FS_IOC_GETFLAGS gives. `stated`
/// has the flags the object says something about, and `set` those of them
/// that are set. A manifest has FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL,
/// FS_NOCOW_FL and FS_NODUMP_FL. Other bits are not read. A flag that is not
/// in `stated` is taken away from the object.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_inode_flags(o: *mut uapi16_file_object, stated: u32, set: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_inode_flags(stated, set)) }
}

/// Stores the Linux inode flags the object says something about in
/// `ret_stated`, and those of them that are set in `ret_set`, as the bits
/// FS_IOC_GETFLAGS gives. Either can be NULL. An object that says nothing
/// about any flag stores 0 in both.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_inode_flags(
    o: *const uapi16_file_object,
    ret_stated: *mut u32,
    ret_set: *mut u32,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller each of the two is NULL or valid
    // for the write of what is stored there.
    let (ret_stated, ret_set) = unsafe { (Place::new(ret_stated), Place::new(ret_set)) };
    let got = object
        .ok_or_else(uapi16_error::misuse)
        .and_then(uapi16_file_object::inode_flags);
    ErrorPlace::NONE.returned(got.map(|(stated, set)| {
        ret_stated.store(stated);
        ret_set.store(set);
    }))
}

/// Sets the DOS attributes hidden, system and archive, as the bits a
/// directory entry of FAT has: 0x02, 0x04 and 0x20. `stated` has the
/// attributes the object says something about, and `set` those of them that
/// are set. Other bits are not read. An attribute that is not in `stated` is
/// taken away from the object. The read-only attribute is
/// uapi16_file_object_set_read_only().
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_dos_attributes(o: *mut uapi16_file_object, stated: u32, set: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_dos_attributes(stated, set)) }
}

/// Stores the DOS attributes the object says something about in
/// `ret_stated`, and those of them that are set in `ret_set`, as the bits a
/// directory entry of FAT has. Either can be NULL. An object that says
/// nothing about any of them stores 0 in both.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_dos_attributes(
    o: *const uapi16_file_object,
    ret_stated: *mut u32,
    ret_set: *mut u32,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller each of the two is NULL or valid
    // for the write of what is stored there.
    let (ret_stated, ret_set) = unsafe { (Place::new(ret_stated), Place::new(ret_set)) };
    let got = object
        .ok_or_else(uapi16_error::misuse)
        .and_then(uapi16_file_object::dos_attributes);
    ErrorPlace::NONE.returned(got.map(|(stated, set)| {
        ret_stated.store(stated);
        ret_set.store(set);
    }))
}

/// Sets the target of a symbolic link: the `size` bytes at `target`, which
/// need not be UTF-8 and which no NUL ends. The manifest carries the target
/// itself. On a regular file they are the data of the file, which the
/// manifest carries the same way.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_target(
    o: *mut uapi16_file_object,
    target: *const c_void,
    size: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `target` is NULL or valid for the
    // read of `size` bytes, unless `size` is 0.
    let target = unsafe { Bytes::new(target, size) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_target(target)) }
}

/// Says that the data of the file is in the file `file` next to the
/// manifest, under another name than its own. `file` is a name as
/// uapi16_file_object_new() takes one, but for the empty one. A name that is
/// none fails as it does there. Without this, the data of a regular file is
/// in the file of its own name next to the manifest.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_contents_file(
    o: *mut uapi16_file_object,
    file: *const c_char,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing else uses during the call.
    let object = unsafe { o.as_mut() };
    // SAFETY: by the rules of the caller `file` is NULL or a string that
    // does not change during the call.
    let file = unsafe { Text::new(file) };
    let set = match object {
        Some(object) if reterr.is_clear() => object.set_contents_file(file),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(set)
}

/// The file the data of `o` is in, where that is another file than the one
/// of its own name, and where the data starts in it. -ENODATA where the
/// object names no such file. Both `ret_file` and `ret_offset` are needed: a
/// NULL one fails with -EINVAL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_contents_file(
    o: *const uapi16_file_object,
    ret_file: *mut *const c_char,
    ret_offset: *mut u64,
) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `ret_file` and `ret_offset` are
    // NULL or valid for the write of a pointer and of a number.
    let (ret_file, ret_offset) = unsafe { (Place::new(ret_file), Place::new(ret_offset)) };
    let read = match (object, ret_file.needed(), ret_offset.needed()) {
        (Some(object), Ok(ret_file), Ok(ret_offset)) => object.contents_file().map(|(file, offset)| {
            ret_file.store(file);
            ret_offset.store(offset);
        }),
        _ => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(read)
}

/// Where the data of the file is: the bytes of a regular file or the target
/// of a symbolic link. A literal is taken first. Otherwise the data is in
/// the file next to the manifest that the object refers to, or in the file
/// of its own name where it is a regular file and refers to none.
/// UAPI16_DATA_LOCATION_NONE for an object without data, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_data_location(o: *const uapi16_file_object) -> DataLocationNumber {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    let none = uapi16_data_location_t::UAPI16_DATA_LOCATION_NONE;
    object.map_or(none, uapi16_file_object::data_location) as DataLocationNumber
}

/// The data of the file where the manifest carries it itself, such as the
/// target of a symbolic link, and its size in `ret_size`, unless that is
/// NULL. Where the object gives a size, the data is that many bytes. No NUL
/// ends the bytes. NULL and 0 where the data is not in the manifest. The
/// bytes belong to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_literal(o: *const uapi16_file_object, ret_size: *mut usize) -> *const c_void {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    // SAFETY: by the rules of the caller `ret_size` is NULL or valid for
    // the write of a size.
    let ret_size = unsafe { Place::new(ret_size) };
    let literal = object.and_then(uapi16_file_object::literal);
    ret_size.store(literal.map_or(0, <[u8]>::len));
    literal.map_or(ptr::null(), |literal| literal.as_ptr().cast())
}

/// Sets the label of the file system. Only the root has one.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_fs_label(o: *mut uapi16_file_object, label: *const c_char) -> c_int {
    // SAFETY: by the rules of the caller `label` is NULL or a string that
    // does not change during the call.
    let label = unsafe { Text::new(label) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.set_fs_label(label)) }
}

/// The label of the file system, or NULL where the object has none. The
/// string belongs to the object.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_fs_label(o: *const uapi16_file_object) -> *const c_char {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(ptr::null(), uapi16_file_object::fs_label)
}

/// Sets the UUID of the file system to the one at `uuid`. Only the root has
/// one.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_fs_uuid(o: *mut uapi16_file_object, uuid: *const uapi16_uuid_t) -> c_int {
    // SAFETY: by the rules of the caller `uuid` is NULL or valid for the
    // read of a UUID, which is its bytes.
    let uuid = unsafe { uuid.cast::<[u8; UAPI16_UUID_SIZE]>().as_ref() };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe {
        uapi16_file_object::change(o, |object| {
            let uuid = Uuid::new(*uuid.ok_or_else(uapi16_error::misuse)?);
            object
                .file_system_mut()
                .map(|file_system| file_system.set_uuid(Some(uuid)))
        })
    }
}

/// Stores the UUID of the file system in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_fs_uuid(o: *const uapi16_file_object, ret: *mut uapi16_uuid_t) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret.cast(), |object| {
            object
                .file_system()?
                .uuid()
                .map(|uuid| *uuid.as_bytes())
                .ok_or_else(uapi16_error::absent)
        })
    }
}

/// Sets the volume serial number of a FAT or exFAT file system. Only the
/// root has one.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_set_fat_serial(o: *mut uapi16_file_object, serial: u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe {
        uapi16_file_object::change(o, |object| {
            object
                .file_system_mut()
                .map(|file_system| file_system.set_fat_serial(Some(FatSerial::new(serial))))
        })
    }
}

/// Stores the volume serial number of a FAT or exFAT file system in `ret`.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_fat_serial(o: *const uapi16_file_object, ret: *mut u32) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // changes during the call, and `ret` is NULL or valid
    // for the write of what is stored there.
    unsafe {
        uapi16_file_object::read(o, ret, |object| {
            object
                .file_system()?
                .fat_serial()
                .map(FatSerial::get)
                .ok_or_else(uapi16_error::absent)
        })
    }
}

/// Whether the object has the fields of the feature `feature`. A manifest
/// records every such feature, or the object is not one of its file objects.
/// What a reader filled in does not count. false for a number that is no
/// feature, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_has_stated_feature(
    o: *const uapi16_file_object,
    feature: FeatureNumber,
) -> bool {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.is_some_and(|object| object.stated_features().has_number(feature))
}

/// Feature `i` of those whose fields the object has, counted from 0 in the
/// order of their numbers. UAPI16_FEATURE_NONE past the last one, and for
/// NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_stated_feature(o: *const uapi16_file_object, i: usize) -> FeatureNumber {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    object.map_or(uapi16_feature_t::UAPI16_FEATURE_NONE as FeatureNumber, |object| {
        object.stated_features().number_at(i)
    })
}

/// Takes away the fields of every feature that is not one of the `n`
/// features at `features`. So a caller sets all it knows of a file and keeps
/// what its manifest records. The name, the type and what belongs to no
/// feature stay. The target of a symbolic link goes without
/// UAPI16_FEATURE_SYMLINK. The data a manifest carries of a regular file and
/// the file its data is in belong to no feature, and stay. An object whose
/// data starts at an offset in a file reaches to the end of it once its size
/// goes, and a hash that stays no longer fits. A number that is no feature,
/// other than UAPI16_FEATURE_NONE, fails with -EINVAL, and the object is as
/// it was.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_retain_features(
    o: *mut uapi16_file_object,
    features: *const FeatureNumber,
    n: usize,
) -> c_int {
    // SAFETY: by the rules of the caller `features` is NULL or valid for
    // the read of `n` numbers that do not change during the call.
    let features = unsafe { FeatureList::new(features, n) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that nothing
    // else uses during the call.
    unsafe { uapi16_file_object::change(o, |object| object.retain_features(features)) }
}

/// Checks that the object may be used at the time `now_usec`, in
/// microseconds since 1970: that it is not revoked and that the time is
/// inside its validity window. The check looks at the object alone. A caller
/// that uses a file checks the objects of the directories it is in as well,
/// which come before it in the manifest.
#[no_mangle]
unsafe extern "C" fn uapi16_file_object_check_validity(
    o: *const uapi16_file_object,
    now_usec: u64,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    let checked = match object {
        Some(object) if reterr.is_clear() => object.check_validity(now_usec),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(checked)
}

/// Makes a directory from the descriptor `dir_fd`, which may be opened with
/// O_PATH, and stores it in `ret`. `flags` is a set of
/// uapi16_directory_flag_t. The directory borrows `dir_fd` until it is
/// freed: the caller keeps it open until then, and closes it itself.
#[no_mangle]
unsafe extern "C" fn uapi16_directory_new(
    dir_fd: c_int,
    flags: uapi16_directory_flags_t,
    ret: *mut *mut uapi16_directory,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `dir_fd` is one of its descriptors
    // unless it is negative.
    let dir = unsafe { Descriptor::new(dir_fd) };
    let made = if !ret.is_null() && reterr.is_clear() {
        // SAFETY: by the rules of the caller `dir_fd` stays open until the
        // directory is freed, which is when it is dropped.
        unsafe { uapi16_directory::new(dir, flags) }
    } else {
        Err(uapi16_error::misuse())
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_directory::returned(made, ret, reterr) }
}

/// Opens the file the data of `o` is in, for reading, and stores a new
/// descriptor in `ret_fd`, which the caller closes. The descriptor is open
/// for reading, and blocks as a regular file does. Where the data starts in
/// the file is stored in `ret_offset`. Both `ret_fd` and `ret_offset` are
/// needed: a NULL one fails with -EINVAL. The data is as long as the object
/// says, or reaches to the end of the file where the object gives no size.
///
/// The file is a regular file. One that is not there fails with
/// UAPI16_ERROR_SOURCE_MISSING, one that is no regular file with
/// UAPI16_ERROR_SOURCE_NOT_REGULAR, one that can't be opened with
/// UAPI16_ERROR_IO and the errno of the system call, such as ELOOP for a
/// symbolic link on the way, and one that is too short for the data, or of
/// another size than the manifest gives for the file, with
/// UAPI16_ERROR_SIZE_MISMATCH. An object whose data is not in a file, see
/// uapi16_file_object_data_location(), fails with UAPI16_ERROR_UNSUPPORTED.
///
/// The caller checks what it reads with a uapi16_data_check. A file can hold
/// the data of several file objects. Where the manifest gives a hash for
/// the whole file and none for the object, the data of the object is not
/// checked against it.
#[no_mangle]
unsafe extern "C" fn uapi16_directory_open_data(
    d: *const uapi16_directory,
    o: *const uapi16_file_object,
    ret_fd: *mut c_int,
    ret_offset: *mut u64,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `d` and `o` are NULL or objects
    // that nothing changes during the call.
    let (directory, object) = unsafe { (d.as_ref(), o.as_ref()) };
    // SAFETY: by the rules of the caller `ret_fd` and `ret_offset` are NULL
    // or valid for the write of a number.
    let (ret_fd, ret_offset) = unsafe { (Place::new(ret_fd), Place::new(ret_offset)) };
    // A descriptor that nobody takes would stay open, and data read from
    // the wrong place is other data, so both places are needed.
    let opened = match (directory, object, ret_fd.needed(), ret_offset.needed()) {
        (Some(directory), Some(object), Ok(ret_fd), Ok(ret_offset)) if reterr.is_clear() => {
            directory.open_data(object).map(|(file, offset)| {
                // The descriptor is the caller's from here on.
                ret_fd.store(file.into_raw_fd());
                ret_offset.store(offset);
            })
        }
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(opened)
}

/// Frees a directory. NULL is fine. Returns NULL. The descriptor of the
/// caller stays open, and so do those that uapi16_directory_open_data()
/// stored.
#[no_mangle]
unsafe extern "C" fn uapi16_directory_free(d: *mut uapi16_directory) -> *mut uapi16_directory {
    // SAFETY: by the rules of the caller `d` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_directory::free(d) }
}

/// Makes a check of the data of `o`, of which nothing has passed yet, and
/// stores it in `ret`. The check keeps what it needs of the object, which
/// can be changed or freed after the call.
#[no_mangle]
unsafe extern "C" fn uapi16_data_check_new(o: *const uapi16_file_object, ret: *mut *mut uapi16_data_check) -> c_int {
    // SAFETY: by the rules of the caller `o` is NULL or an object that
    // nothing changes during the call.
    let object = unsafe { o.as_ref() };
    let made = match object {
        Some(object) if !ret.is_null() => uapi16_data_check::new(object),
        _ => Err(uapi16_error::misuse()),
    };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a pointer.
    unsafe { uapi16_data_check::returned(made, ret, ErrorPlace::NONE) }
}

/// Takes the `size` bytes at `data` as the next bytes of the data. Fails
/// with UAPI16_ERROR_SIZE_MISMATCH, and takes none of them, where they
/// would make the data larger than the size the object gives.
#[no_mangle]
unsafe extern "C" fn uapi16_data_check_update(
    c: *mut uapi16_data_check,
    data: *const c_void,
    size: usize,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `c` is NULL or an object that
    // nothing else uses during the call.
    let check = unsafe { c.as_mut() };
    // SAFETY: by the rules of the caller `data` is NULL or valid for the
    // read of `size` bytes, unless `size` is 0.
    let data = unsafe { Bytes::new(data, size) };
    let updated = match check {
        Some(check) if reterr.is_clear() => check.update(data),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(updated)
}

/// Takes `size` zero bytes as the next bytes of the data, such as a hole of
/// a sparse file that the caller did not read. Fails as
/// uapi16_data_check_update() does.
#[no_mangle]
unsafe extern "C" fn uapi16_data_check_update_zeros(
    c: *mut uapi16_data_check,
    size: u64,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `c` is NULL or an object that
    // nothing else uses during the call.
    let check = unsafe { c.as_mut() };
    let updated = match check {
        Some(check) if reterr.is_clear() => check.update_zeros(size),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(updated)
}

/// Checks the data that passed against the size and the hash the object
/// gives, and stores how many bytes it is in `ret_size`, unless that is
/// NULL. Data of another size fails with UAPI16_ERROR_SIZE_MISMATCH, and
/// data with another hash with UAPI16_ERROR_HASH_MISMATCH. Every later call
/// on the check but uapi16_data_check_free() fails with -ESTALE.
#[no_mangle]
unsafe extern "C" fn uapi16_data_check_finish(
    c: *mut uapi16_data_check,
    ret_size: *mut u64,
    reterr: *mut *mut uapi16_error,
) -> c_int {
    // SAFETY: by the rules of the caller `reterr` is NULL or valid for the
    // read and the write of a pointer that nothing else uses now.
    let reterr = unsafe { ErrorPlace::new(reterr) };
    // SAFETY: by the rules of the caller `c` is NULL or an object that
    // nothing else uses during the call.
    let check = unsafe { c.as_mut() };
    // SAFETY: by the rules of the caller `ret_size` is NULL or valid for
    // the write of a size.
    let ret_size = unsafe { Place::new(ret_size) };
    let finished = match check {
        Some(check) if reterr.is_clear() => check.finish().map(|size| ret_size.store(size)),
        _ => Err(uapi16_error::misuse()),
    };
    reterr.returned(finished)
}

/// Frees a check. NULL is fine. Returns NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_data_check_free(c: *mut uapi16_data_check) -> *mut uapi16_data_check {
    // SAFETY: by the rules of the caller `c` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_data_check::free(c) }
}

/// Makes a computation that has taken no data yet. It is freed with
/// uapi16_sha256_free().
#[no_mangle]
extern "C" fn uapi16_sha256_new() -> *mut uapi16_sha256 {
    uapi16_sha256::new().into_raw()
}

/// Takes the `size` bytes at `data` as more of the data.
#[no_mangle]
unsafe extern "C" fn uapi16_sha256_update(s: *mut uapi16_sha256, data: *const c_void, size: usize) -> c_int {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing else uses during the call.
    let sha256 = unsafe { s.as_mut() };
    // SAFETY: by the rules of the caller `data` is NULL or valid for the
    // read of `size` bytes, unless `size` is 0.
    let data = unsafe { Bytes::new(data, size) };
    let updated = sha256
        .ok_or_else(uapi16_error::misuse)
        .and_then(|sha256| sha256.update(data));
    ErrorPlace::NONE.returned(updated)
}

/// Takes `size` zero bytes as more of the data, such as a hole of a sparse
/// file that the caller did not read.
#[no_mangle]
unsafe extern "C" fn uapi16_sha256_update_zeros(s: *mut uapi16_sha256, size: u64) -> c_int {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing else uses during the call.
    let sha256 = unsafe { s.as_mut() };
    let updated = sha256
        .ok_or_else(uapi16_error::misuse)
        .and_then(|sha256| sha256.update_zeros(size));
    ErrorPlace::NONE.returned(updated)
}

/// Ends the computation and stores the hash of all the data in `ret`. Every
/// later call on it but uapi16_sha256_free() fails with -ESTALE.
#[no_mangle]
unsafe extern "C" fn uapi16_sha256_finish(s: *mut uapi16_sha256, ret: *mut uapi16_sha256_digest_t) -> c_int {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing else uses during the call.
    let sha256 = unsafe { s.as_mut() };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a hash, which is its bytes.
    let ret = unsafe { Place::new(ret.cast::<[u8; UAPI16_SHA256_SIZE]>()) };
    let finished = match (sha256, ret.needed()) {
        (Some(sha256), Ok(ret)) => sha256.finish().map(|hash| ret.store(hash)),
        _ => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(finished)
}

/// Frees a computation. NULL is fine. Returns NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_sha256_free(s: *mut uapi16_sha256) -> *mut uapi16_sha256 {
    // SAFETY: by the rules of the caller `s` is NULL or an object that
    // nothing uses any more.
    unsafe { uapi16_sha256::free(s) }
}

/// Compares two names the way a manifest in code point order lists its file
/// objects: component by component, each by its bytes, so that the name of
/// a directory comes right before the names below it. Returns one of
/// uapi16_name_order_t as an int: UAPI16_NAME_BEFORE where `a` comes before
/// `b`, UAPI16_NAME_SAME where they are the same, and UAPI16_NAME_AFTER
/// where `a` comes after `b`. A comparison function of qsort() returns that
/// as it is. This is not the order of strcmp(): "a/x" comes before "a-b".
/// NULL is the empty name, which comes first. Strings that are not UTF-8 are
/// no names, and they compare after the replacement.
#[no_mangle]
unsafe extern "C" fn uapi16_name_compare(a: *const c_char, b: *const c_char) -> c_int {
    // SAFETY: by the rules of the caller `a` and `b` are NULL or strings
    // that do not change during the call.
    let (a, b) = unsafe { (Text::new(a), Text::new(b)) };
    // A string that is not UTF-8 is no name. Its bytes that are none are
    // taken as the replacement character, so that every two strings have an
    // order.
    let (a, b) = (a.lossy(), b.lossy());
    // The three numbers of uapi16_name_order_t are small.
    uapi16_name_order_t::of(NamePair::new(&a, &b).ordering()) as c_int
}

/// The name the specification has for the feature `feature`, such as
/// "user-xattr" for UAPI16_FEATURE_USER_XATTR. NULL for a number that is
/// not one feature. The string is a constant of the library.
#[no_mangle]
extern "C" fn uapi16_feature_name(feature: FeatureNumber) -> *const c_char {
    uapi16_feature_t::name_of(feature).map_or(ptr::null(), CStr::as_ptr)
}

/// The feature with the name `name`, as the specification spells it.
/// UAPI16_FEATURE_NONE for a name that no feature has, and for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_feature_from_name(name: *const c_char) -> FeatureNumber {
    // SAFETY: by the rules of the caller `name` is NULL or a string that
    // does not change during the call.
    let name = unsafe { Text::new(name) };
    let name = name.get().ok().and_then(|name| name.to_str().ok());
    let feature = name.and_then(|name| name.parse::<Features>().ok());
    let feature = feature.and_then(uapi16_feature_t::of);
    feature.unwrap_or(uapi16_feature_t::UAPI16_FEATURE_NONE) as FeatureNumber
}

/// Turns every one of the `n` features at `features` that this library
/// doesn't have into UAPI16_FEATURE_NONE, and returns how many it turned
/// off. A program built with a newer header learns this way which of its
/// features the library it runs with has. 0 for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_feature_probe(features: *mut FeatureNumber, n: usize) -> usize {
    if features.is_null() || n > isize::MAX as usize / size_of::<FeatureNumber>() {
        return 0;
    }
    // SAFETY: `features` is not NULL and `n` numbers are not more than
    // isize::MAX bytes, so by the rules of the caller it is valid for the
    // read and the write of `n` numbers that nothing else uses during the
    // call.
    let features = unsafe { slice::from_raw_parts_mut(features, n) };
    let none = uapi16_feature_t::UAPI16_FEATURE_NONE as FeatureNumber;
    let mut turned_off = 0;
    for feature in features {
        if *feature != none && uapi16_feature_t::rust_of(*feature).is_none() {
            *feature = none;
            turned_off += 1;
        }
    }
    turned_off
}

/// What kind of error this is. 0 for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_error_kind(e: *const uapi16_error) -> ErrorKindNumber {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    error.map_or(0, |e| e.kind as u64)
}

/// The errno of the error, a positive number as errno has it. The call
/// that failed returned it negated. 0 for NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_error_errno(e: *const uapi16_error) -> c_int {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    error.map_or(0, |e| e.errno)
}

/// The name of the file the error is about, as the manifest has it, or
/// NULL if the error is about no file. The root of the tree is the empty
/// string. For a name a manifest can't hold, it is the name of the
/// directory the file is in. The string belongs to the error.
#[no_mangle]
unsafe extern "C" fn uapi16_error_path(e: *const uapi16_error) -> *const c_char {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let path = error.and_then(|e| e.path.as_deref());
    path.map_or(ptr::null(), CStr::as_ptr)
}

/// For UAPI16_ERROR_HARDLINK_MISMATCH, the other name of the inode, which
/// the file of uapi16_error_path() was compared with. NULL for any other
/// error. The string belongs to the error.
#[no_mangle]
unsafe extern "C" fn uapi16_error_hardlink_path(e: *const uapi16_error) -> *const c_char {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let path = error.and_then(|e| e.hardlink_path.as_deref());
    path.map_or(ptr::null(), CStr::as_ptr)
}

/// The feature the error is about: for UAPI16_ERROR_UNSUPPORTED the one
/// that can't be read, and for a feature of partitions that feature.
/// UAPI16_FEATURE_NONE if the error is about no feature.
#[no_mangle]
unsafe extern "C" fn uapi16_error_feature(e: *const uapi16_error) -> FeatureNumber {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let feature = error.and_then(|e| e.feature);
    feature.unwrap_or(uapi16_feature_t::UAPI16_FEATURE_NONE) as FeatureNumber
}

/// For UAPI16_ERROR_UNWRITABLE_NAME, the name of the file as its directory
/// has it: one component. Its bytes need not be UTF-8, and no NUL ends
/// them. How many there are is stored in `ret_size`, unless that is NULL.
/// For any other error this returns NULL and stores 0. The bytes belong to
/// the error.
#[no_mangle]
unsafe extern "C" fn uapi16_error_raw_name(e: *const uapi16_error, ret_size: *mut usize) -> *const c_void {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let name = error.and_then(|e| e.raw_name.as_deref());
    if !ret_size.is_null() {
        // SAFETY: `ret_size` is not NULL, so it is valid for the write of a
        // size by the rules of the caller.
        unsafe { ret_size.write(name.map_or(0, <[u8]>::len)) };
    }
    name.map_or(ptr::null(), |name| name.as_ptr().cast())
}

/// Which rule of a name the name breaks: for UAPI16_ERROR_UNWRITABLE_NAME
/// the name of uapi16_error_raw_name(), and for a name passed to a file
/// object that is no name, that one. 0 for any other error.
#[no_mangle]
unsafe extern "C" fn uapi16_error_name_problem(e: *const uapi16_error) -> NameProblemNumber {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let problem = error.and_then(|e| e.name_problem);
    problem.map_or(0, |problem| problem as u64)
}

/// The field the error is about, as the specification spells it, such as
/// "mode" or "inodeToken". NULL if the error is about no field. The string
/// is a constant of the library.
#[no_mangle]
unsafe extern "C" fn uapi16_error_field(e: *const uapi16_error) -> *const c_char {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let field = error.and_then(|e| e.field).and_then(Field::c_name);
    field.map_or(ptr::null(), CStr::as_ptr)
}

/// Stores in `ret` the number of the record the error is about, counting
/// from 0, which is the record of the root. For a reader that is the record
/// that failed, and for a writer of records the number the record it refused
/// would have had. -ENODATA if the error is about no record, as no error of
/// a manifest writer is.
#[no_mangle]
unsafe extern "C" fn uapi16_error_record(e: *const uapi16_error, ret: *mut u64) -> c_int {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    // SAFETY: by the rules of the caller `ret` is NULL or valid for the
    // write of a number.
    let ret = unsafe { Place::new(ret) };
    let got = match (error, ret.needed()) {
        (Some(error), Ok(ret)) => {
            let record = error.record.ok_or_else(uapi16_error::absent);
            record.map(|record| ret.store(record))
        }
        _ => Err(uapi16_error::misuse()),
    };
    ErrorPlace::NONE.returned(got)
}

/// For UAPI16_ERROR_MANIFEST and UAPI16_ERROR_TOO_LARGE, the rule of the
/// specification that a manifest or a file object breaks, by a name that
/// never changes. NULL for any other error. The string is a constant of the
/// library.
///
/// The names are "notJson", "duplicateKey", "invalidString", "notObject",
/// "notUtf8", "nulByte", "recordSeparator", "recordTooLarge", "empty",
/// "noTrailer", "dataAfterTrailer", "fileAfterSignature", "mediaType",
/// "firstHasName", "firstNotDirectory", "noOrder", "noName", "invalidName",
/// "duplicateName", "misplaced", "outOfOrder", "unlistedFeature",
/// "noTarget", "unknownType", "fieldType", "fieldRange",
/// "fieldNotPermitted", "contradiction", "contents", "signature" and
/// "extendedAttributes".
#[no_mangle]
unsafe extern "C" fn uapi16_error_problem(e: *const uapi16_error) -> *const c_char {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed.
    let error = unsafe { e.as_ref() };
    let problem = error.and_then(|e| e.problem).and_then(Problem::c_name);
    problem.map_or(ptr::null(), CStr::as_ptr)
}

/// Frees an error. NULL is fine. Returns NULL.
#[no_mangle]
unsafe extern "C" fn uapi16_error_free(e: *mut uapi16_error) -> *mut uapi16_error {
    // SAFETY: by the rules of the caller `e` is NULL or an error that was
    // not freed, and nothing uses it after this call.
    unsafe { uapi16_error::free(e) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::TempDir;
    use crate::NameBuf;
    use crate::Validity;
    use std::fs;
    use std::io::Seek;
    use std::os::fd::AsRawFd;

    /// The descriptor of `file` as a caller in C passes it.
    impl Process {
        /// A process that is not the one that is running. None where
        /// nothing tells the one that is running from another, as under
        /// Miri, which has no page for that.
        fn elsewhere() -> Option<Process> {
            match Process::current() {
                Process::Known(generation) => generation.checked_add(1).map(Process::Known),
                Process::Spent | Process::Untold => None,
            }
        }
    }

    fn descriptor(file: &File) -> Descriptor<'_> {
        Descriptor(file.as_raw_fd(), PhantomData)
    }

    /// The string `text` as a caller in C passes it.
    fn text(text: &CStr) -> Text<'_> {
        Text(Some(text))
    }

    /// The numbers C has for the features `features`, in their order.
    fn numbers_of(features: Features) -> Vec<FeatureNumber> {
        let held = uapi16_feature_t::ALL
            .into_iter()
            .filter(|(_, rust)| features.contains(*rust));
        held.map(|(c, _)| c as FeatureNumber).collect()
    }

    /// The numbers `numbers` as a caller in C passes a list of features.
    fn list(numbers: &[FeatureNumber]) -> FeatureList<'_> {
        FeatureList(Some(numbers))
    }

    /// The bytes `bytes` as a caller in C passes them.
    fn bytes(bytes: &[u8]) -> Bytes<'_> {
        Bytes(Some(bytes))
    }

    /// A tree with a directory and two files.
    fn tree(name: &str) -> (TempDir, File) {
        let tmp = TempDir::new(name);
        fs::create_dir(tmp.0.join("a")).unwrap();
        fs::write(tmp.0.join("a/file"), b"hello").unwrap();
        fs::write(tmp.0.join("top"), b"top").unwrap();
        let top = File::open(&tmp.0).unwrap();
        (tmp, top)
    }

    /// The kind and the errno of the error of the C API for `error`.
    fn kind_and_errno(error: Error) -> (uapi16_error_kind_t, c_int) {
        let error = uapi16_error::from(error);
        (error.kind, error.errno)
    }

    /// A file object of the C API with the name `name`.
    fn object(name: &CStr) -> uapi16_file_object {
        uapi16_file_object::new(text(name)).unwrap()
    }

    /// The numbers of the enums, which never change: C callers are built
    /// with them.
    #[test]
    fn numbers() {
        use uapi16_error_kind_t::*;
        use uapi16_name_problem_t::*;
        for (i, (c, rust)) in uapi16_feature_t::ALL.into_iter().enumerate() {
            assert_eq!(c as u64, i as u64 + 1);
            assert_eq!(rust.names().count(), 1);
        }
        assert_eq!(uapi16_feature_t::UAPI16_FEATURE_NONE as u64, 0);
        assert_eq!(uapi16_order_t::UAPI16_ORDER_NONE as u64, 0);
        assert_eq!(uapi16_order_t::UAPI16_ORDER_CODEPOINT as u64, 1);
        assert_eq!(uapi16_read_only_t::UAPI16_READ_ONLY_UNSTATED as u64, 0);
        assert_eq!(uapi16_read_only_t::UAPI16_READ_ONLY_NO as u64, 1);
        assert_eq!(uapi16_read_only_t::UAPI16_READ_ONLY_YES as u64, 2);
        // The numbers of an order of two names are those qsort() takes.
        assert_eq!(uapi16_name_order_t::UAPI16_NAME_BEFORE as i64, -1);
        assert_eq!(uapi16_name_order_t::UAPI16_NAME_SAME as i64, 0);
        assert_eq!(uapi16_name_order_t::UAPI16_NAME_AFTER as i64, 1);
        assert_eq!(uapi16_add_flag_t::UAPI16_ADD_NONE as u64, 0);
        assert_eq!(uapi16_add_flag_t::UAPI16_ADD_CROSS_MOUNTS as u64, 1);
        assert_eq!(uapi16_add_flag_t::UAPI16_ADD_GRACEFUL as u64, 2);
        assert_eq!(UAPI16_INODE_TOKEN_NONE, 0);
        let kinds = [
            (UAPI16_ERROR_IO, 1),
            (UAPI16_ERROR_EXISTS, 2),
            (UAPI16_ERROR_DUPLICATE, 3),
            (UAPI16_ERROR_CHANGED, 4),
            (UAPI16_ERROR_HARDLINK_MISMATCH, 5),
            (UAPI16_ERROR_UNWRITABLE_NAME, 6),
            (UAPI16_ERROR_NOT_DIRECTORY, 7),
            (UAPI16_ERROR_UNSUPPORTED, 8),
            (UAPI16_ERROR_INVALID_ARGUMENT, 9),
            (UAPI16_ERROR_LOOP, 10),
            (UAPI16_ERROR_MISSING_PARENT, 11),
            (UAPI16_ERROR_TOO_LARGE, 12),
            (UAPI16_ERROR_ENDED, 13),
            (UAPI16_ERROR_MANIFEST, 14),
            (UAPI16_ERROR_SOURCE_MISSING, 15),
            (UAPI16_ERROR_SOURCE_NOT_REGULAR, 16),
            (UAPI16_ERROR_SIZE_MISMATCH, 17),
            (UAPI16_ERROR_HASH_MISMATCH, 18),
            (UAPI16_ERROR_REVOKED, 19),
            (UAPI16_ERROR_NOT_YET_VALID, 20),
            (UAPI16_ERROR_EXPIRED, 21),
        ];
        for (kind, number) in kinds {
            assert_eq!(kind as u64, number, "{:?}", kind);
        }
        let problems = [
            (UAPI16_NAME_PROBLEM_NOT_UTF8, 1),
            (UAPI16_NAME_PROBLEM_EMPTY, 2),
            (UAPI16_NAME_PROBLEM_TOO_LONG, 3),
            (UAPI16_NAME_PROBLEM_RESERVED, 4),
            (UAPI16_NAME_PROBLEM_CONTROL_CHARACTER, 5),
            (UAPI16_NAME_PROBLEM_NONCHARACTER, 6),
            (UAPI16_NAME_PROBLEM_EMPTY_COMPONENT, 7),
            (UAPI16_NAME_PROBLEM_DOT_COMPONENT, 8),
        ];
        for (problem, number) in problems {
            assert_eq!(problem as u64, number, "{:?}", problem);
        }
        assert_eq!(uapi16_read_t::UAPI16_READ_END as u64, 0);
        assert_eq!(uapi16_read_t::UAPI16_READ_FILE as u64, 1);
        assert_eq!(uapi16_read_t::UAPI16_READ_SIGNATURES as u64, 2);
        assert_eq!(uapi16_read_t::UAPI16_READ_SIGNATURE as u64, 3);
        assert_eq!(uapi16_data_location_t::UAPI16_DATA_LOCATION_NONE as u64, 0);
        assert_eq!(uapi16_data_location_t::UAPI16_DATA_LOCATION_LITERAL as u64, 1);
        assert_eq!(uapi16_data_location_t::UAPI16_DATA_LOCATION_EXTERNAL as u64, 2);
        assert_eq!(uapi16_data_location_t::UAPI16_DATA_LOCATION_UNSUPPORTED as u64, 3);
        assert_eq!(uapi16_directory_flag_t::UAPI16_DIRECTORY_NONE as u64, 0);
        assert_eq!(uapi16_directory_flag_t::UAPI16_DIRECTORY_FOLLOW_SYMLINKS as u64, 1);
        // What a manifest has of the two kinds of flags is what the kernel
        // has for them.
        let inode_flags = uapi16_file_object::INODE_FLAGS.map(|(flag, _, _)| flag.bits());
        assert_eq!(inode_flags, [0x20, 0x10, 0x80, 0x0080_0000, 0x40]);
        let dos_attributes = uapi16_file_object::DOS_ATTRIBUTES.map(|(attribute, _, _)| attribute);
        assert_eq!(dos_attributes, [0x02, 0x04, 0x20]);
    }

    /// Every error of the crate has its kind and its errno in C.
    #[test]
    fn kinds_and_errnos() {
        use uapi16_error_kind_t::*;
        let of = |kind| Error::new(kind, String::new());
        for (kind, c, errno) in [
            (
                ErrorKind::Tree(TreeProblem::Duplicate),
                UAPI16_ERROR_DUPLICATE,
                libc::EEXIST,
            ),
            (
                ErrorKind::Tree(TreeProblem::Changed),
                UAPI16_ERROR_CHANGED,
                libc::ESTALE,
            ),
            (
                ErrorKind::Tree(TreeProblem::HardlinkMismatch),
                UAPI16_ERROR_HARDLINK_MISMATCH,
                libc::ESTALE,
            ),
            (
                ErrorKind::Tree(TreeProblem::UnwritableName),
                UAPI16_ERROR_UNWRITABLE_NAME,
                libc::EINVAL,
            ),
            (
                ErrorKind::Tree(TreeProblem::NotDirectory),
                UAPI16_ERROR_NOT_DIRECTORY,
                libc::ENOTDIR,
            ),
            (
                ErrorKind::Tree(TreeProblem::FeatureUnavailable),
                UAPI16_ERROR_UNSUPPORTED,
                libc::EOPNOTSUPP,
            ),
            (
                ErrorKind::Tree(TreeProblem::FeatureNotForTrees),
                UAPI16_ERROR_INVALID_ARGUMENT,
                libc::EINVAL,
            ),
            (ErrorKind::Tree(TreeProblem::Loop), UAPI16_ERROR_LOOP, libc::ELOOP),
            (
                ErrorKind::Tree(TreeProblem::MissingParent),
                UAPI16_ERROR_MISSING_PARENT,
                libc::ENOENT,
            ),
            (
                ErrorKind::Manifest(Problem::RecordTooLarge),
                UAPI16_ERROR_TOO_LARGE,
                libc::E2BIG,
            ),
            (
                ErrorKind::Source(SourceProblem::Missing),
                UAPI16_ERROR_SOURCE_MISSING,
                libc::ENOENT,
            ),
            (
                ErrorKind::Source(SourceProblem::NotRegular),
                UAPI16_ERROR_SOURCE_NOT_REGULAR,
                libc::EINVAL,
            ),
            (ErrorKind::Source(SourceProblem::Unreadable), UAPI16_ERROR_IO, libc::EIO),
            (
                ErrorKind::Data(DataProblem::SizeMismatch),
                UAPI16_ERROR_SIZE_MISMATCH,
                libc::EBADMSG,
            ),
            (
                ErrorKind::Data(DataProblem::HashMismatch),
                UAPI16_ERROR_HASH_MISMATCH,
                libc::EBADMSG,
            ),
            (
                ErrorKind::Unsupported(UnsupportedData::UrlOrEncoding),
                UAPI16_ERROR_UNSUPPORTED,
                libc::EOPNOTSUPP,
            ),
            (
                ErrorKind::Unsupported(UnsupportedData::Absent),
                UAPI16_ERROR_UNSUPPORTED,
                libc::EOPNOTSUPP,
            ),
            (
                ErrorKind::NotValid(ValidityProblem::Revoked),
                UAPI16_ERROR_REVOKED,
                libc::EKEYREVOKED,
            ),
            (
                ErrorKind::NotValid(ValidityProblem::NotYetValid),
                UAPI16_ERROR_NOT_YET_VALID,
                libc::EKEYEXPIRED,
            ),
            (
                ErrorKind::NotValid(ValidityProblem::Expired),
                UAPI16_ERROR_EXPIRED,
                libc::EKEYEXPIRED,
            ),
            (ErrorKind::Io, UAPI16_ERROR_IO, libc::EIO),
        ] {
            assert_eq!(kind_and_errno(of(kind)), (c, errno), "{:?}", kind);
        }
        // Every rule of the specification but the one of the size of a
        // record is the one kind, with the name of the rule.
        for &problem in Problem::ALL {
            let error = uapi16_error::from(of(ErrorKind::Manifest(problem)));
            let expected = match problem {
                Problem::RecordTooLarge => (UAPI16_ERROR_TOO_LARGE, libc::E2BIG),
                _ => (UAPI16_ERROR_MANIFEST, libc::EBADMSG),
            };
            assert_eq!((error.kind, error.errno), expected, "{:?}", problem);
            assert_eq!(error.problem, Some(problem));
            assert_eq!(problem.c_name().unwrap().to_str(), Ok(problem.as_str()));
        }
        // The errno of a name a manifest cannot hold says which rule it
        // breaks.
        for (problem, errno) in [
            (NameProblem::NotUtf8, libc::EILSEQ),
            (NameProblem::TooLong, libc::ENAMETOOLONG),
            (NameProblem::ContainsControlCharacter, libc::EINVAL),
        ] {
            let error = of(ErrorKind::Tree(TreeProblem::UnwritableName)).because(problem);
            assert_eq!(
                kind_and_errno(error),
                (UAPI16_ERROR_UNWRITABLE_NAME, errno),
                "{:?}",
                problem
            );
        }
        // An I/O error has the errno of its system call, where it has one,
        // and so has a file of a manifest that can't be read.
        let io = |errno| io::Error::from_raw_os_error(errno);
        assert_eq!(
            kind_and_errno(Error::from(io(libc::ENOSPC))),
            (UAPI16_ERROR_IO, libc::ENOSPC)
        );
        let unreadable = of(ErrorKind::Source(SourceProblem::Unreadable)).caused_by(io(libc::EACCES));
        assert_eq!(kind_and_errno(unreadable), (UAPI16_ERROR_IO, libc::EACCES));
        let other = Error::from(io::Error::other("no errno"));
        assert_eq!(kind_and_errno(other), (UAPI16_ERROR_IO, libc::EIO));
        // EEXIST where a new file gets its name is the name that is taken.
        let exists = uapi16_error::from(Error::from(io(libc::EEXIST))).of_new_file();
        assert_eq!((exists.kind, exists.errno), (UAPI16_ERROR_EXISTS, libc::EEXIST));
        assert_eq!(uapi16_error::ended().errno, libc::ESTALE);
        assert_eq!(uapi16_error::absent().errno, libc::ENODATA);
        assert_eq!(uapi16_error::misuse().errno, libc::EINVAL);
    }

    /// The header lists the names of the rules: every one of
    /// [`Problem::ALL`], in its order, and no other.
    #[test]
    fn the_header_names_every_rule() {
        let header = include_str!("uapi16.h");
        let (_, names) = header.split_once(" * The names are ").unwrap();
        let (names, _) = names.split_once(".\n */\nconst char *uapi16_error_problem(").unwrap();
        let listed: Vec<&str> = names.split('"').skip(1).step_by(2).collect();
        let rules: Vec<&str> = Problem::ALL.iter().map(|problem| problem.as_str()).collect();
        assert_eq!(listed, rules);
    }

    /// An error says in C what it says in Rust: the names, the feature, the
    /// name as its directory has it with the rule it breaks, the field, the
    /// record and the rule. The names of fields, rules and features are
    /// constants: the same string every time.
    #[test]
    fn what_an_error_is_about() {
        let error = Error::new(ErrorKind::Tree(TreeProblem::HardlinkMismatch), String::new())
            .named("a/second")
            .linked(NameBuf::new("a/first").unwrap());
        let error = uapi16_error::from(error);
        assert_eq!(error.path.as_deref(), Some(c"a/second"));
        assert_eq!(error.hardlink_path.as_deref(), Some(c"a/first"));
        assert_eq!((error.field, error.record, error.problem), (None, None, None));

        let error =
            Error::new(ErrorKind::Tree(TreeProblem::FeatureUnavailable), String::new()).about(Features::USER_XATTR);
        let error = uapi16_error::from(error);
        assert_eq!(error.feature, Some(uapi16_feature_t::UAPI16_FEATURE_USER_XATTR));

        let error = Error::new(ErrorKind::Tree(TreeProblem::UnwritableName), String::new())
            .named("a")
            .raw(OsStr::from_bytes(b"\xff"))
            .because(NameProblem::NotUtf8);
        let error = uapi16_error::from(error);
        assert_eq!(error.raw_name.as_deref(), Some(&b"\xff"[..]));
        assert_eq!(
            error.name_problem,
            Some(uapi16_name_problem_t::UAPI16_NAME_PROBLEM_NOT_UTF8)
        );

        let refused = || {
            let error = Error::manifest(Problem::FieldNotPermitted, String::new());
            uapi16_error::from(error.at(Field::InodeToken).in_record(7).named("x"))
        };
        let error = refused();
        assert_eq!(error.field, Some(Field::InodeToken));
        assert_eq!(error.record, Some(7));
        assert_eq!(error.problem, Some(Problem::FieldNotPermitted));
        // The record as C gets it: 0 is the record of the root, and an
        // error about no record stores none.
        for number in [0, 7] {
            let about = Error::manifest(Problem::FieldNotPermitted, String::new()).in_record(number);
            let e = uapi16_error::from(about).into_raw();
            let mut record = 77u64;
            // SAFETY: `e` is an error that is freed once, here, and `record`
            // is a local.
            unsafe {
                assert_eq!(uapi16_error_record(e, &mut record), 0);
                assert_eq!(record, number);
                assert_eq!(uapi16_error_record(e, ptr::null_mut()), -libc::EINVAL);
                assert_eq!(uapi16_error_record(ptr::null(), &mut record), -libc::EINVAL);
                assert!(uapi16_error_free(e).is_null());
            }
        }
        let e = uapi16_error::misuse().into_raw();
        let mut record = 77u64;
        // SAFETY: as above.
        unsafe {
            assert_eq!(uapi16_error_record(e, &mut record), -libc::ENODATA);
            assert_eq!(record, 77);
            assert!(uapi16_error_free(e).is_null());
        }
        assert_eq!(Field::InodeToken.c_name(), Some(c"inodeToken"));
        assert_eq!(Problem::FieldNotPermitted.c_name(), Some(c"fieldNotPermitted"));
        let again = |name: Option<&CStr>| name.map(CStr::as_ptr);
        assert_eq!(again(Field::InodeToken.c_name()), again(Field::InodeToken.c_name()));
        assert_eq!(
            again(Problem::FieldNotPermitted.c_name()),
            again(Problem::FieldNotPermitted.c_name())
        );

        for (c, rust) in uapi16_feature_t::ALL {
            let name = uapi16_feature_t::name_of(c as u64).unwrap();
            assert_eq!(name.to_str().unwrap().parse(), Ok(rust));
            assert_eq!(
                uapi16_feature_t::name_of(c as u64).map(CStr::as_ptr),
                Some(name.as_ptr())
            );
        }
        assert_eq!(
            uapi16_feature_t::name_of(uapi16_feature_t::UAPI16_FEATURE_USER_XATTR as u64),
            Some(c"user-xattr")
        );
        // (1 << 32) + 1 is the number of the access mode in its low 32
        // bits, which is all of a number where usize has 32.
        for none in [
            0,
            uapi16_feature_t::ALL.len() as u64 + 1,
            1 << 31,
            (1 << 32) + 1,
            u64::MAX,
        ] {
            assert_eq!(uapi16_feature_t::name_of(none), None, "{:#x}", none);
        }
    }

    /// A list of features as a caller passes it: nothing is read of a list
    /// without numbers, a feature can be in it more than once,
    /// UAPI16_FEATURE_NONE is passed over, and a list that is not there or
    /// has a number that is no feature fails. The probe turns the numbers
    /// that are no features off where they are, and counts them.
    #[test]
    fn lists_of_features() {
        let mode = uapi16_feature_t::UAPI16_FEATURE_MODE as FeatureNumber;
        let size = uapi16_feature_t::UAPI16_FEATURE_SIZE as FeatureNumber;
        let mtime = uapi16_feature_t::UAPI16_FEATURE_MTIME as FeatureNumber;
        let last = uapi16_feature_t::ALL.len() as FeatureNumber;
        // SAFETY: nothing is read where there are no numbers, and NULL has
        // none that are there.
        let (empty, null) = unsafe { (FeatureList::new(ptr::null(), 0), FeatureList::new(ptr::null(), 1)) };
        assert_eq!(empty.get().unwrap(), Features::NONE);
        assert_eq!(null.get().unwrap_err().errno, libc::EINVAL);
        assert_eq!(
            list(&[size, 0, mode, size]).get().unwrap(),
            Features::MODE | Features::SIZE
        );
        assert_eq!(list(&[0, 0]).get().unwrap(), Features::NONE);
        assert_eq!(list(&numbers_of(Features::ALL)).get().unwrap(), Features::ALL);
        // (1 << 32) + 1 is the number of the access mode in its low 32
        // bits, which is all of a number where usize has 32.
        for none in [last + 1, 1 << 31, (1 << 32) + 1, u64::MAX] {
            assert_eq!(list(&[mode, none]).get().unwrap_err().errno, libc::EINVAL);
            assert!(!Features::ALL.has_number(none));
        }

        let held = Features::SIZE | Features::MODE | Features::MTIME;
        assert!(held.has_number(mode) && held.has_number(size) && held.has_number(mtime));
        assert!(!held.has_number(0) && !held.has_number(last));
        assert_eq!([0, 1, 2, 3].map(|i| held.number_at(i)), [mode, size, mtime, 0]);
        assert_eq!(held.number_at(usize::MAX), 0);
        assert_eq!(Features::NONE.number_at(0), 0);

        let mut probed = [size, last + 1, 0, last, u64::MAX, mode];
        // SAFETY: the numbers are those of the array, and nothing is read
        // of no numbers or of NULL.
        unsafe {
            assert_eq!(uapi16_feature_probe(probed.as_mut_ptr(), probed.len()), 2);
            assert_eq!(probed, [size, 0, 0, last, 0, mode]);
            assert_eq!(uapi16_feature_probe(probed.as_mut_ptr(), probed.len()), 0);
            assert_eq!(uapi16_feature_probe(probed.as_mut_ptr(), 0), 0);
            assert_eq!(uapi16_feature_probe(ptr::null_mut(), probed.len()), 0);
        }
    }

    /// What a caller passes is checked before it is used: names, flags,
    /// bits, orders, descriptors, bytes and places.
    #[test]
    fn checks_what_a_caller_passes() {
        let misuse = |e: uapi16_error| {
            assert_eq!(
                (e.kind, e.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, libc::EINVAL)
            );
            e.name_problem
        };
        assert_eq!(Name::of_text(text(c"")).unwrap(), Name::ROOT);
        assert_eq!(Name::of_text(text(c"a/b")).unwrap().as_str(), "a/b");
        assert_eq!(misuse(Name::of_text(Text(None)).unwrap_err()), None);
        for (name, problem) in [
            (c"a//b", uapi16_name_problem_t::UAPI16_NAME_PROBLEM_EMPTY_COMPONENT),
            (c"a/../b", uapi16_name_problem_t::UAPI16_NAME_PROBLEM_DOT_COMPONENT),
            (c"\xff", uapi16_name_problem_t::UAPI16_NAME_PROBLEM_NOT_UTF8),
            (c"Uapi16Manifest", uapi16_name_problem_t::UAPI16_NAME_PROBLEM_RESERVED),
            (c"a\x01", uapi16_name_problem_t::UAPI16_NAME_PROBLEM_CONTROL_CHARACTER),
        ] {
            assert_eq!(
                misuse(Name::of_text(text(name)).unwrap_err()),
                Some(problem),
                "{:?}",
                name
            );
        }

        assert_eq!(AddFlags::of_bits(0).unwrap(), AddFlags::NONE);
        assert_eq!(
            AddFlags::of_bits(3).unwrap(),
            AddFlags::CROSS_MOUNTS | AddFlags::GRACEFUL
        );
        for bits in [1 << 2, 1 << 63, u64::MAX] {
            misuse(AddFlags::of_bits(bits).unwrap_err());
        }
        assert_eq!(Order::of_number(1).unwrap(), Some(Order::CodePoint));
        assert_eq!(Order::of_number(0).unwrap(), None);
        for number in [2, u64::MAX] {
            misuse(Order::of_number(number).unwrap_err());
        }
        for (c, rust) in Order::ALL {
            assert_eq!(Order::number(rust), c);
        }

        for none in [-1, libc::AT_FDCWD, c_int::MIN] {
            let e = Descriptor(none, PhantomData).borrow().unwrap_err();
            assert_eq!(
                (e.kind, e.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, libc::EBADF)
            );
        }

        // The name of a new file is bytes, and names a file below a
        // directory.
        let file_name = |name| uapi16_manifest_options::file_name(text(name));
        assert_eq!(
            file_name(c"sub/caf\xe9").unwrap().as_os_str().as_bytes(),
            b"sub/caf\xe9"
        );
        for name in [c"", c"/m", c"./m", c"../m", c"sub/../m", c"sub/"] {
            misuse(file_name(name).unwrap_err());
        }
        misuse(uapi16_manifest_options::file_name(Text(None)).unwrap_err());

        // No bytes are no pointer to look at. Some bytes need one.
        // SAFETY: nothing is read for a size of 0, and NULL is not read
        // through either.
        let (none, missing) = unsafe { (Bytes::new(ptr::null(), 0), Bytes::new(ptr::null(), 1)) };
        assert_eq!(none.get().unwrap(), b"");
        misuse(missing.get().unwrap_err());
        let three = *b"abc";
        // SAFETY: `three` is three bytes, which stay as they are.
        let some = unsafe { Bytes::new(three.as_ptr().cast(), three.len()) };
        assert_eq!(some.get().unwrap(), b"abc");
        // A size that nothing in memory has is refused like bytes that are
        // missing.
        for size in [isize::MAX.unsigned_abs() + 1, usize::MAX] {
            // SAFETY: nothing is read through the pointer for such a size.
            let huge = unsafe { Bytes::new(three.as_ptr().cast(), size) };
            misuse(huge.get().unwrap_err());
        }
        // SAFETY: as above. NULL takes the bytes of a signature away, and
        // an empty key is a key.
        let (gone, empty) = unsafe {
            (
                uapi16_signature::bytes(ptr::null(), 3),
                uapi16_signature::bytes(three.as_ptr().cast(), 0),
            )
        };
        assert!(gone.is_none());
        assert_eq!(empty.unwrap().get().unwrap(), b"");

        // A place is written to once, and one that is needed is not NULL.
        let mut number = 0u64;
        // SAFETY: `number` is a local that nothing else uses.
        unsafe { Place::new(&mut number) }.needed().unwrap().store(7);
        assert_eq!(number, 7);
        // SAFETY: NULL is no place, and nothing is written to it.
        let nowhere = unsafe { Place::<u64>::new(ptr::null_mut()) };
        misuse(nowhere.needed().unwrap_err());
        // SAFETY: as above.
        unsafe { Place::<u64>::new(ptr::null_mut()) }.store(1);

        // A string that is no UTF-8 has an order all the same.
        assert_eq!(Text(None).lossy(), "");
        assert_eq!(text(c"a\xffb").lossy(), "a\u{fffd}b");
    }

    /// A file object stores what it is given and gives it back, and what it
    /// was not given is not there. The strings it hands out end in a NUL
    /// and stay where they are until the object is given others.
    #[test]
    fn file_objects() {
        let absent = |e: uapi16_error| assert_eq!(e.errno, libc::ENODATA);
        let mut o = object(c"dir/file");
        // SAFETY: name() returns a string of the object, which is not
        // changed while it is read.
        let name = |o: &uapi16_file_object| unsafe { CStr::from_ptr(o.name()) }.to_owned();
        assert_eq!(name(&o).as_c_str(), c"dir/file");
        assert_eq!(o.name(), o.name());
        assert_eq!(o.object.inode_type().st_mode(), libc::S_IFREG);
        assert!(!o.is_root());

        o.set_name(text(c"dir/other")).unwrap();
        assert_eq!(name(&o).as_c_str(), c"dir/other");
        assert_eq!(o.set_name(text(c"")).unwrap_err().errno, libc::EINVAL);
        assert_eq!(o.set_name(text(c"a//b")).unwrap_err().errno, libc::EINVAL);
        assert_eq!(name(&o).as_c_str(), c"dir/other");

        for (inode_type, st_mode) in InodeType::ST_MODES {
            o.set_type(st_mode | 0o777).unwrap();
            assert_eq!(o.object.inode_type(), inode_type);
            assert_eq!(inode_type.st_mode(), st_mode);
        }
        assert_eq!(o.set_type(0).unwrap_err().errno, libc::EINVAL);
        assert_eq!(o.set_type(0o777).unwrap_err().errno, libc::EINVAL);
        o.set_type(libc::S_IFREG).unwrap();

        absent(o.inode().unwrap().mode().ok_or_else(uapi16_error::absent).unwrap_err());
        o.set_mode(libc::S_IFREG | 0o4755).unwrap();
        assert_eq!(o.object.inode().mode().map(Mode::bits), Some(0o4755));
        assert_eq!(o.object.inode_type(), InodeType::Regular);
        // A bit that is neither of the file type nor of the mode is refused.
        for no_mode in [(libc::S_IFMT | 0o7777) + 1, !libc::S_IFMT] {
            assert_eq!(o.set_mode(no_mode).unwrap_err().errno, libc::EINVAL);
        }
        assert_eq!(o.object.inode().mode().map(Mode::bits), Some(0o4755));

        assert!(o.user_name().is_null() && o.group_name().is_null() && o.fs_label().is_null());
        o.set_user_name(text(c"root")).unwrap();
        o.set_group_name(text(c"wheel")).unwrap();
        // SAFETY: the two return strings of the object, which is not changed
        // while they are read.
        let (user, group) = unsafe { (CStr::from_ptr(o.user_name()), CStr::from_ptr(o.group_name())) };
        assert_eq!((user, group), (c"root", c"wheel"));
        assert_eq!(o.user_name(), o.user_name());
        assert_eq!(o.set_user_name(text(c"\xff")).unwrap_err().errno, libc::EINVAL);
        assert_eq!(o.set_user_name(Text(None)).unwrap_err().errno, libc::EINVAL);
        assert_eq!(o.object.inode().user_name(), Some("root"));

        o.set_inode_token(7).unwrap();
        assert_eq!(o.object.inode_token().map(NonZeroU64::get), Some(7));
        o.set_inode_token(UAPI16_INODE_TOKEN_NONE).unwrap();
        assert_eq!(o.object.inode_token(), None);

        // Extended attributes: none said, none there, and some, in the
        // order of their names.
        absent(o.user_xattrs().unwrap_err());
        assert_eq!(o.user_xattr(0).unwrap_err().errno, libc::EINVAL);
        o.set_user_xattrs().unwrap();
        assert_eq!(o.user_xattrs().unwrap(), 0);
        o.add_user_xattr(text(c"b"), bytes(b"two")).unwrap();
        o.add_user_xattr(text(c"a"), bytes(b"")).unwrap();
        o.add_user_xattr(text(c"b"), bytes(b"2\x00")).unwrap();
        assert_eq!(o.user_xattrs().unwrap(), 2);
        let xattr = |o: &uapi16_file_object, i| {
            let (name, value, size) = o.user_xattr(i).unwrap();
            // SAFETY: the name is a string of the object and the value
            // `size` of its bytes, and the object is not changed meanwhile.
            unsafe {
                (
                    CStr::from_ptr(name).to_owned(),
                    slice::from_raw_parts(value.cast::<u8>(), size).to_vec(),
                )
            }
        };
        assert_eq!(xattr(&o, 0), (c"a".to_owned(), b"".to_vec()));
        assert_eq!(xattr(&o, 1), (c"b".to_owned(), b"2\x00".to_vec()));
        assert_eq!(o.user_xattr(2).unwrap_err().errno, libc::EINVAL);
        // The number of an attribute is checked before the process is, as
        // what a call is given comes first.
        if let Some(elsewhere) = Process::elsewhere() {
            let made = mem::replace(&mut o.process, elsewhere);
            assert_eq!(o.user_xattr(2).unwrap_err().errno, libc::EINVAL);
            assert_eq!(o.user_xattr(0).unwrap_err().errno, libc::ECHILD);
            o.process = made;
        }
        o.set_user_xattrs().unwrap();
        assert_eq!(o.user_xattrs().unwrap(), 0);
        // None of the names that were handed out is one of its attributes.
        assert_eq!(o.user_xattr(0).unwrap_err().errno, libc::EINVAL);
        // The names that were handed out are made anew after every change:
        // of all the attributes, and of one that is added.
        o.add_user_xattr(text(c"z"), bytes(b"1")).unwrap();
        assert_eq!(xattr(&o, 0), (c"z".to_owned(), b"1".to_vec()));
        o.add_user_xattr(text(c"y"), bytes(b"2")).unwrap();
        assert_eq!(xattr(&o, 0), (c"y".to_owned(), b"2".to_vec()));
        assert_eq!(xattr(&o, 1), (c"z".to_owned(), b"1".to_vec()));
        o.set_user_xattrs().unwrap();

        // Whether it is read-only has three answers, and a setter for
        // each.
        for (c, rust) in uapi16_read_only_t::ALL {
            o.set_read_only(c as u64).unwrap();
            assert_eq!(o.object.inode().read_only(), rust);
            assert_eq!(uapi16_read_only_t::of(rust), c);
        }
        assert_eq!(o.set_read_only(3).unwrap_err().errno, libc::EINVAL);
        assert_eq!(o.object.inode().read_only(), Some(true));

        // The flags of the two kinds: what is stated, and what of it is
        // set. A flag that is not stated is taken away.
        assert_eq!(o.inode_flags().unwrap(), (0, 0));
        o.set_inode_flags(0x20 | 0x10 | 0x1, 0x20 | 0x40).unwrap();
        assert_eq!(o.inode_flags().unwrap(), (0x20 | 0x10, 0x20));
        o.set_inode_flags(0x0080_0000, 0).unwrap();
        assert_eq!(o.inode_flags().unwrap(), (0x0080_0000, 0));
        assert_eq!(o.dos_attributes().unwrap(), (0, 0));
        o.set_dos_attributes(0x02 | 0x20 | 0x01, 0x20 | 0x04).unwrap();
        assert_eq!(o.dos_attributes().unwrap(), (0x02 | 0x20, 0x20));

        // Where the data is. An object that refers to another file names
        // it, with a string of its own that stays until it refers to
        // another one.
        assert_eq!(o.data_location(), uapi16_data_location_t::UAPI16_DATA_LOCATION_EXTERNAL);
        assert_eq!(o.literal(), None);
        absent(o.contents_file().unwrap_err());
        o.set_contents_file(text(c"blobs/1")).unwrap();
        assert_eq!(o.data_location(), uapi16_data_location_t::UAPI16_DATA_LOCATION_EXTERNAL);
        let named = |o: &uapi16_file_object| {
            let (file, offset) = o.contents_file().unwrap();
            // SAFETY: the name is a string of the object, which is not
            // changed while this reads it.
            (unsafe { CStr::from_ptr(file) }.to_owned(), offset)
        };
        assert_eq!(named(&o), (c"blobs/1".to_owned(), 0));
        assert_eq!(o.contents_file().unwrap().0, o.contents_file().unwrap().0);
        o.set_contents_file(text(c"blobs/2")).unwrap();
        assert_eq!(named(&o), (c"blobs/2".to_owned(), 0));
        // The file of its own name is no other file.
        let own = CString::new(o.object.name().as_str()).unwrap();
        o.set_contents_file(text(&own)).unwrap();
        absent(o.contents_file().unwrap_err());
        o.set_contents_file(text(c"blobs/1")).unwrap();
        let empty = o.set_contents_file(text(c"")).unwrap_err();
        assert_eq!(
            empty.name_problem,
            Some(uapi16_name_problem_t::UAPI16_NAME_PROBLEM_EMPTY)
        );
        o.set_type(libc::S_IFLNK).unwrap();
        o.set_target(bytes(b"to\xff")).unwrap();
        assert_eq!(o.data_location(), uapi16_data_location_t::UAPI16_DATA_LOCATION_LITERAL);
        assert_eq!(o.literal(), Some(&b"to\xff"[..]));
        let mut fifo = object(c"fifo");
        fifo.set_type(libc::S_IFIFO).unwrap();
        assert_eq!(fifo.data_location(), uapi16_data_location_t::UAPI16_DATA_LOCATION_NONE);

        // What the object states, as the features of its fields.
        let mut plain = object(c"plain");
        assert_eq!(plain.stated_features(), Features::NONE);
        plain.set_mode(0o644).unwrap();
        plain.file_mut().unwrap().set_size(Some(1));
        assert_eq!(plain.stated_features(), Features::MODE | Features::SIZE);
        plain.check_validity(0).unwrap();
        plain.as_file().unwrap();
        assert_eq!(plain.as_root().unwrap_err().errno, libc::EINVAL);
    }

    /// The root is the object with the empty name, a directory. A setter
    /// stores what it is given there as well, and a writer refuses a root
    /// with what only another file object has, and any other object with
    /// what only the root has.
    #[test]
    fn roots() {
        let refused = |e: uapi16_error, field: &CStr| {
            assert_eq!(
                (e.kind, e.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_MANIFEST, libc::EBADMSG)
            );
            assert_eq!(e.problem, Some(Problem::FieldNotPermitted));
            assert_eq!(e.field.and_then(Field::c_name), Some(field));
            e.path
        };
        let mut root = object(c"");
        assert!(root.is_root());
        assert_eq!(root.object.inode_type().st_mode(), libc::S_IFDIR);
        root.set_type(libc::S_IFDIR).unwrap();
        assert_eq!(root.set_type(libc::S_IFREG).unwrap_err().errno, libc::EINVAL);
        assert_eq!(root.set_name(text(c"a")).unwrap_err().errno, libc::EINVAL);
        root.set_mode(0o755).unwrap();
        root.set_fs_label(text(c"label")).unwrap();
        root.file_system_mut().unwrap().set_fat_serial(Some(FatSerial::new(7)));
        // SAFETY: fs_label() returns a string of the object, which is not
        // changed while it is read.
        assert_eq!(unsafe { CStr::from_ptr(root.fs_label()) }, c"label");
        assert_eq!(
            root.stated_features(),
            Features::MODE | Features::FS_LABEL | Features::FAT_SERIAL
        );
        let written = root.as_root().unwrap();
        assert_eq!(written.inode().mode().map(Mode::bits), Some(0o755));
        assert_eq!(written.file_system().label(), Some("label"));
        assert_eq!(written.file_system().fat_serial().map(FatSerial::get), Some(7));

        // What a root can't have is stored, and refused when it is written.
        type Setter = fn(&mut uapi16_file_object);
        let setters: [(&CStr, Setter); 6] = [
            (c"size", |o| o.file_mut().unwrap().set_size(Some(1))),
            (c"sha256", |o| o.file_mut().unwrap().set_sha256(Some(Sha256::EMPTY))),
            (c"contents", |o| o.set_target(Bytes(Some(b"t"))).unwrap()),
            (c"inodeToken", |o| o.set_inode_token(1).unwrap()),
            (c"major", |o| o.file_mut().unwrap().set_major(Some(1))),
            (c"flagHidden", |o| o.set_dos_attributes(0x02, 0).unwrap()),
        ];
        for (field, set) in setters {
            let mut root = object(c"");
            set(&mut root);
            assert_eq!(refused(root.as_root().unwrap_err(), field).as_deref(), Some(c""));
        }

        // The other way round.
        let mut file = object(c"a/file");
        file.as_file().unwrap();
        file.set_fs_label(text(c"label")).unwrap();
        assert_eq!(
            refused(file.as_file().unwrap_err(), c"fsLabel").as_deref(),
            Some(c"a/file")
        );
        let mut file = object(c"a/file");
        file.file_system_mut()
            .unwrap()
            .set_uuid(Some(Uuid::new([1; Uuid::SIZE])));
        refused(file.as_file().unwrap_err(), c"fsUUID");

        // A root that a reader read keeps what no setter sets.
        let mut read = RootObject::default();
        read.inode_mut().set_uid(Some(1));
        read.set_gpt_disk_uuid(Some(Uuid::new([2; Uuid::SIZE])));
        read.set_features(Some(Features::UID));
        let handed_out = uapi16_file_object::of_root(&read);
        assert!(handed_out.is_root());
        let mut back = handed_out.as_root().unwrap();
        back.set_features(read.features());
        assert_eq!(back, read);
        // A manifest writer lists the root directory and its file system,
        // and no more: it refuses a root with what only a manifest that
        // was read can say of it.
        refused(handed_out.as_tree_root().unwrap_err(), c"gptDiskUuid");
        type Window = fn(&mut ValidityWindow);
        let validity: [(&CStr, Window); 3] = [
            (c"validSinceUSec", |window| window.set_since_usec(1)),
            (c"validUntilUSec", |window| window.set_until_usec(Some(2))),
            (c"validity", |window| window.set_state(Validity::Revoked)),
        ];
        for (field, set) in validity {
            let mut read = RootObject::default();
            let mut window = read.validity();
            set(&mut window);
            read.set_validity(window);
            let handed_out = uapi16_file_object::of_root(&read);
            handed_out.as_root().unwrap();
            refused(handed_out.as_tree_root().unwrap_err(), field);
        }
        root.as_tree_root().unwrap();
    }

    /// An error about the root names it: the empty string. A reader says so
    /// for a field of the root record that it refuses, and not for a record
    /// that is no root at all. So does the check of when a root may be
    /// used.
    #[test]
    fn errors_about_the_root() {
        let out = TempDir::new("capi-root-errors");
        let open = |root: &str| {
            let mut file = tempfile(&out);
            file.write_all(format!("\x1e{}\n", root).as_bytes()).unwrap();
            file.rewind().unwrap();
            // SAFETY: no reader is made, and the file is open during the
            // call.
            unsafe { uapi16_reader::open(descriptor(&file)) }.unwrap_err()
        };
        let refused = open("{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"size\":1}");
        assert_eq!(refused.problem, Some(Problem::FieldNotPermitted));
        assert_eq!((refused.field, refused.record), (Some(Field::Size), Some(0)));
        assert_eq!(refused.path.as_deref(), Some(c""));
        let no_directory = open("{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"type\":\"reg\"}");
        assert_eq!(no_directory.problem, Some(Problem::RootNotDirectory));
        assert_eq!(no_directory.path.as_deref(), Some(c""));
        // A root with a name has that name.
        let named = open("{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"name\":\"x\"}");
        assert_eq!(named.path.as_deref(), Some(c"x"));
        // What is no root record is about no file.
        for no_root in ["{\"mediaType\":\"nope\"}", "nope"] {
            let e = open(no_root);
            assert_eq!(e.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
            assert_eq!((e.path, e.record), (None, Some(0)));
        }
        let mut revoked = RootObject::default();
        let mut window = revoked.validity();
        window.set_state(Validity::Revoked);
        revoked.set_validity(window);
        let e = uapi16_file_object::of_root(&revoked).check_validity(0).unwrap_err();
        assert_eq!(e.kind, uapi16_error_kind_t::UAPI16_ERROR_REVOKED);
        assert_eq!(e.path.as_deref(), Some(c""));
    }

    /// A manifest writer takes the root as the object with the empty name:
    /// the manifest says of its root directory and its file system what
    /// that object says. The first root that is added counts, and one with
    /// a field the manifest does not record is refused and adds nothing.
    #[test]
    fn root_adds() {
        let out = TempDir::new("capi-root-adds");
        let mut options = uapi16_manifest_options::new();
        let features = Features::MODE | Features::FS_LABEL | Features::FS_UUID;
        options.set_features(list(&numbers_of(features))).unwrap();
        let into = tempfile(&out);
        {
            // SAFETY: `into` is open until the writer was dropped.
            let mut writer = unsafe { options.open(descriptor(&into)) }.unwrap();
            let mut refused = object(c"");
            refused.set_mode(0o700).unwrap();
            refused
                .file_system_mut()
                .unwrap()
                .set_fat_serial(Some(FatSerial::new(7)));
            let unlisted = writer.add_object(&refused).unwrap_err();
            assert_eq!(unlisted.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
            assert_eq!(unlisted.problem, Some(Problem::UnlistedFeature));
            assert_eq!(unlisted.field, Some(Field::FatSerial));
            // An error about the root names it: the empty string. It is
            // about no record: a manifest writer has none until it finishes.
            assert_eq!(unlisted.path.as_deref(), Some(c""));
            assert_eq!(unlisted.record, None);
            // A writer of records refuses the root as the record it would
            // have been, the first one, whoever finds what is wrong with it.
            // SAFETY: no writer is made, so nothing keeps `into`.
            let begun = unsafe { uapi16_writer::begin(&options, descriptor(&into), Some(&refused)) };
            let begun = begun.unwrap_err();
            assert_eq!(begun.problem, Some(Problem::UnlistedFeature));
            assert_eq!(begun.path.as_deref(), Some(c""));
            assert_eq!(begun.record, Some(ROOT_RECORD));
            let mut with_size = object(c"");
            with_size.file_mut().unwrap().set_size(Some(1));
            // SAFETY: as above.
            let begun = unsafe { uapi16_writer::begin(&options, descriptor(&into), Some(&with_size)) };
            let begun = begun.unwrap_err();
            assert_eq!(begun.problem, Some(Problem::FieldNotPermitted));
            assert_eq!(begun.record, Some(ROOT_RECORD));
            let not_permitted = writer.add_object(&with_size).unwrap_err();
            assert_eq!(not_permitted.problem, Some(Problem::FieldNotPermitted));
            assert_eq!(not_permitted.path.as_deref(), Some(c""));
            assert_eq!(not_permitted.record, None);

            writer.add_object(&object(c"file")).unwrap();
            let mut root = object(c"");
            root.set_mode(0o750).unwrap();
            root.set_fs_label(text(c"label")).unwrap();
            let uuid = Uuid::new([3; Uuid::SIZE]);
            root.file_system_mut().unwrap().set_uuid(Some(uuid));
            writer.add_object(&root).unwrap();
            // Added twice, the first one says what the root is like.
            let mut again = object(c"");
            again.set_mode(0o755).unwrap();
            writer.add_object(&again).unwrap();
            let report = writer.finish().unwrap().report;
            assert_eq!((report.files(), report.directories()), (1, 1));
        }
        (&into).rewind().unwrap();
        // SAFETY: the reader is dropped before `into`.
        let reader = unsafe { reader_of(&into) };
        let read = reader.reader.root();
        assert_eq!(read.inode().mode().map(Mode::bits), Some(0o750));
        assert_eq!(read.file_system().label(), Some("label"));
        assert_eq!(read.file_system().uuid(), Some(Uuid::new([3; Uuid::SIZE])));
        assert_eq!(read.file_system().fat_serial(), None);
        assert_eq!(read.features(), Some(features));
    }

    /// The features an object states are those of its file object and of
    /// the root it would be. The two getters answer from the fields that
    /// are there, without a copy of what is in them, so the answer is held
    /// against that of a whole root here: for every set of the fields that
    /// only the root has, with and without inode attributes, under the
    /// name of the root and under another one.
    #[test]
    fn stated_features() {
        type Setter = fn(&mut uapi16_file_object);
        let only_the_root_has: [(Features, Setter); 4] = [
            (Features::FS_LABEL, |o| o.set_fs_label(text(c"label")).unwrap()),
            (Features::FS_UUID, |o| {
                o.file_system_mut().unwrap().set_uuid(Some(Uuid::new([1; Uuid::SIZE])))
            }),
            (Features::FAT_SERIAL, |o| {
                o.file_system_mut().unwrap().set_fat_serial(Some(FatSerial::new(7)))
            }),
            (Features::GPT_DISK_UUID, |o| {
                o.gpt_disk_uuid = Some(Uuid::new([2; Uuid::SIZE]))
            }),
        ];
        for name in [c"", c"dir/file"] {
            for chosen in 0..1usize << only_the_root_has.len() {
                for with_inode_attributes in [false, true] {
                    let mut o = object(name);
                    let mut expected = Features::NONE;
                    if with_inode_attributes {
                        o.set_mode(0o755).unwrap();
                        o.set_user_xattrs().unwrap();
                        o.add_user_xattr(text(c"key"), bytes(b"value")).unwrap();
                        expected |= Features::MODE | Features::USER_XATTR;
                    }
                    for (place, (feature, set)) in only_the_root_has.iter().enumerate() {
                        if chosen & (1 << place) != 0 {
                            set(&mut o);
                            expected |= *feature;
                        }
                    }
                    assert_eq!(o.stated_features(), expected);
                    assert_eq!(
                        o.stated_features(),
                        o.object.stated_features() | o.root().stated_features()
                    );
                }
            }
        }
    }

    /// The check of when an object may be used answers for the root what a
    /// whole root answers, with the same error, and without a copy of what
    /// the object holds: for every validity, at times before, in and after
    /// it, for a root with and without inode attributes and a label. A file
    /// is checked as itself.
    #[test]
    fn validity_checks() {
        const TIMES: [u64; 4] = [0, 15, 25, u64::MAX];
        type Window = fn(&mut ValidityWindow);
        // Each with the times of TIMES at which it holds.
        let windows: [(Window, [bool; TIMES.len()]); 4] = [
            (|_| {}, [true, true, true, true]),
            (|window| window.set_since_usec(10), [false, true, true, true]),
            (|window| window.set_until_usec(Some(20)), [true, true, false, false]),
            (
                |window| window.set_state(Validity::Revoked),
                [false, false, false, false],
            ),
        ];
        // Every field of an error, to hold one error against another.
        let said = |checked: Result<(), uapi16_error>| checked.map_err(|e| format!("{:?}", e));
        for (set, holds) in windows {
            let mut window = ValidityWindow::default();
            set(&mut window);
            for with_fields in [false, true] {
                let mut read = RootObject::default();
                read.set_validity(window);
                let mut root = uapi16_file_object::of_root(&read);
                let mut file = object(c"dir/file");
                file.object.set_validity(window);
                if with_fields {
                    for o in [&mut root, &mut file] {
                        o.set_mode(0o755).unwrap();
                        o.set_user_xattrs().unwrap();
                        o.add_user_xattr(text(c"key"), bytes(b"value")).unwrap();
                        o.set_fs_label(text(c"label")).unwrap();
                    }
                }
                for (now, valid) in TIMES.into_iter().zip(holds) {
                    let whole = root.root().check_validity(now);
                    let whole = whole.map_err(|e| uapi16_error::from(e).about(Name::ROOT));
                    assert_eq!(root.check_validity(now).is_ok(), valid);
                    assert_eq!(said(root.check_validity(now)), said(whole));
                    let itself = file.object.check_validity(now).map_err(uapi16_error::from);
                    assert_eq!(file.check_validity(now).is_ok(), valid);
                    assert_eq!(said(file.check_validity(now)), said(itself));
                }
            }
        }
    }

    /// An object keeps the fields of the features it is told to retain, and
    /// loses the others, also what only the root has. The name, the type
    /// and what belongs to no feature stay. A string the object handed out
    /// stays where it is as long as its field does.
    #[test]
    fn retained_features() {
        let mut o = object(c"dir/file");
        o.set_mode(libc::S_IFREG | 0o644).unwrap();
        o.inode_mut().unwrap().set_uid(Some(1));
        o.set_user_name(text(c"user")).unwrap();
        o.set_group_name(text(c"group")).unwrap();
        o.file_mut().unwrap().set_size(Some(3));
        o.set_user_xattrs().unwrap();
        o.add_user_xattr(text(c"key"), bytes(b"value")).unwrap();
        o.set_inode_token(4).unwrap();
        o.set_contents_file(text(c"blobs/1")).unwrap();
        let (name, user, group) = (o.name(), o.user_name(), o.group_name());
        assert!(!user.is_null() && !group.is_null());
        assert_eq!(o.user_xattr(0).map(|(name, _, _)| name.is_null()).ok(), Some(false));
        let all = o.stated_features();
        assert!(all.contains(Features::MODE | Features::UID | Features::USER_NAME | Features::GROUP_NAME));

        // Every feature it has: nothing changes.
        o.retain_features(list(&numbers_of(all))).unwrap();
        assert_eq!(o.stated_features(), all);
        assert_eq!((o.name(), o.user_name(), o.group_name()), (name, user, group));

        let kept = Features::MODE | Features::USER_NAME | Features::SIZE;
        o.retain_features(list(&numbers_of(kept))).unwrap();
        assert_eq!(o.stated_features(), kept);
        assert_eq!(o.object.inode().mode().map(Mode::bits), Some(0o644));
        assert_eq!((o.object.inode().uid(), o.object.size()), (None, Some(3)));
        assert_eq!(o.object.inode_token(), None);
        // The name of the user stays where it was, and the name of the
        // group is gone, with the extended attributes.
        assert_eq!((o.name(), o.user_name()), (name, user));
        assert!(o.group_name().is_null());
        assert_eq!(o.user_xattrs().unwrap_err().errno, libc::ENODATA);
        assert_eq!(o.user_xattr(0).unwrap_err().errno, libc::EINVAL);
        // The names of the attributes that went are not handed out for the
        // ones that come after them.
        o.add_user_xattr(text(c"later"), bytes(b"1")).unwrap();
        let (later, _, _) = o.user_xattr(0).unwrap();
        // SAFETY: the name is a string of the object, which is there.
        assert_eq!(unsafe { CStr::from_ptr(later) }, c"later");
        o.set_user_xattrs().unwrap();
        o.retain_features(list(&numbers_of(kept))).unwrap();
        // What belongs to no feature stays.
        assert_eq!(o.object.inode_type(), InodeType::Regular);
        assert_eq!(o.object.contents().len(), 1);

        // No feature at all.
        o.retain_features(list(&[])).unwrap();
        assert_eq!(o.stated_features(), Features::NONE);
        assert!(o.user_name().is_null());
        assert_eq!(o.name(), name);

        // The root loses what only it has the same way.
        let mut root = object(c"");
        root.set_mode(0o755).unwrap();
        root.set_fs_label(text(c"label")).unwrap();
        root.file_system_mut().unwrap().set_fat_serial(Some(FatSerial::new(7)));
        root.file_system_mut()
            .unwrap()
            .set_uuid(Some(Uuid::new([1; Uuid::SIZE])));
        let label = root.fs_label();
        root.retain_features(list(&numbers_of(Features::FS_LABEL | Features::FS_UUID)))
            .unwrap();
        assert_eq!(root.stated_features(), Features::FS_LABEL | Features::FS_UUID);
        assert_eq!(root.fs_label(), label);
        assert_eq!(root.file_system.fat_serial(), None);
        root.retain_features(list(&numbers_of(Features::FS_UUID))).unwrap();
        assert!(root.fs_label().is_null());
        assert_eq!(root.stated_features(), Features::FS_UUID);
        // The UUID goes like the label and the serial.
        let mut other = object(c"");
        other
            .file_system_mut()
            .unwrap()
            .set_uuid(Some(Uuid::new([1; Uuid::SIZE])));
        other.retain_features(list(&numbers_of(Features::FS_LABEL))).unwrap();
        assert_eq!(other.file_system.uuid(), None);
        assert_eq!(other.stated_features(), Features::NONE);
        // The UUID of a disk, which only a root that was read has, stays
        // with its feature and goes without it.
        let mut read = RootObject::default();
        read.set_gpt_disk_uuid(Some(Uuid::new([2; Uuid::SIZE])));
        let mut handed_out = uapi16_file_object::of_root(&read);
        assert!(handed_out.gpt_disk_uuid.is_some());
        handed_out
            .retain_features(list(&numbers_of(Features::GPT_DISK_UUID)))
            .unwrap();
        assert_eq!(handed_out.gpt_disk_uuid, read.gpt_disk_uuid());
        handed_out.retain_features(list(&numbers_of(Features::MODE))).unwrap();
        assert_eq!(handed_out.gpt_disk_uuid, None);

        // A number that is no feature, and another process.
        assert_eq!(root.retain_features(list(&[1 << 40])).unwrap_err().errno, libc::EINVAL);
        assert_eq!(root.stated_features(), Features::FS_UUID);
        if let Some(elsewhere) = Process::elsewhere() {
            root.process = elsewhere;
            assert_eq!(root.retain_features(list(&[])).unwrap_err().errno, libc::ECHILD);
            assert_eq!(root.stated_features(), Features::FS_UUID);
        }
    }

    /// Zero bytes that a caller did not read count as data: for a hash and
    /// for a check of data, which takes no more of them than its object
    /// has room for.
    #[test]
    fn zeros() {
        const HOLE: u64 = 70_000;
        let mut data = b"head".to_vec();
        data.resize(data.len() + HOLE as usize, 0);
        data.extend_from_slice(b"tail");
        let mut sha256 = uapi16_sha256::new();
        sha256.update(bytes(b"head")).unwrap();
        sha256.update_zeros(HOLE).unwrap();
        sha256.update_zeros(0).unwrap();
        sha256.update(bytes(b"tail")).unwrap();
        let hash = Sha256::from(sha256.finish().unwrap());
        assert_eq!(hash, Sha256::digest(&data));
        assert_eq!(sha256.update_zeros(1).unwrap_err().errno, libc::ESTALE);

        let mut o = object(c"sparse");
        let file = o.file_mut().unwrap();
        file.set_size(Some(data.len() as u64));
        file.set_sha256(Some(hash));
        let mut check = uapi16_data_check::new(&o).unwrap();
        check.update(bytes(b"head")).unwrap();
        check.update_zeros(HOLE).unwrap();
        check.update(bytes(b"tail")).unwrap();
        assert_eq!(check.finish().unwrap(), data.len() as u64);
        assert_eq!(check.update_zeros(1).unwrap_err().errno, libc::ESTALE);
        // More zero bytes than the object has room for are refused, as
        // other bytes are, and none of them is taken.
        let mut check = uapi16_data_check::new(&o).unwrap();
        check.update(bytes(b"head")).unwrap();
        let too_many = check.update_zeros(HOLE + 5).unwrap_err();
        assert_eq!(too_many.kind, uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH);
        check.update_zeros(HOLE).unwrap();
        check.update(bytes(b"tail")).unwrap();
        assert_eq!(check.finish().unwrap(), data.len() as u64);
        // Zero bytes where the data has others are another hash.
        let mut check = uapi16_data_check::new(&o).unwrap();
        check.update_zeros(data.len() as u64).unwrap();
        assert_eq!(
            check.finish().unwrap_err().kind,
            uapi16_error_kind_t::UAPI16_ERROR_HASH_MISMATCH
        );
        let mut check = uapi16_data_check::new(&o).unwrap();
        if let Some(elsewhere) = Process::elsewhere() {
            check.process = elsewhere;
            assert_eq!(check.update_zeros(1).unwrap_err().errno, libc::ECHILD);
        }
    }

    /// A directory opens the file the data of a file object is in, below
    /// the descriptor it has on loan, and says where the data starts. The
    /// descriptor it returns is new, and the caller's.
    #[test]
    fn opened_data() {
        let (tmp, top) = tree("capi-opened-data");
        fs::create_dir(tmp.0.join("blobs")).unwrap();
        fs::write(tmp.0.join("blobs/1"), b"0123456789").unwrap();
        std::os::unix::fs::symlink("a/file", tmp.0.join("link")).unwrap();
        let kind = |e: uapi16_error| (e.kind, e.errno);
        let read = |opened: (OwnedFd, u64)| {
            let mut data = Vec::new();
            File::from(opened.0).read_to_end(&mut data).unwrap();
            (data, opened.1)
        };
        // SAFETY: the directories are dropped before `top`.
        let directory = unsafe { uapi16_directory::new(descriptor(&top), 0) }.unwrap();
        let follow = uapi16_directory_flag_t::UAPI16_DIRECTORY_FOLLOW_SYMLINKS as u64;
        // SAFETY: as above.
        let following = unsafe { uapi16_directory::new(descriptor(&top), follow) }.unwrap();

        // The file of its own name.
        let mut file = object(c"a/file");
        let opened = directory.open_data(&file).unwrap();
        assert_ne!(opened.0.as_raw_fd(), top.as_raw_fd());
        assert_eq!(read(opened), (b"hello".to_vec(), 0));
        file.file_mut().unwrap().set_size(Some(5));
        assert_eq!(read(directory.open_data(&file).unwrap()).0, b"hello");
        // A file that is too short for the data.
        file.file_mut().unwrap().set_size(Some(6));
        assert_eq!(
            kind(directory.open_data(&file).unwrap_err()),
            (uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH, libc::EBADMSG)
        );
        // The file the object refers to.
        let mut blob = object(c"elsewhere");
        blob.set_contents_file(text(c"blobs/1")).unwrap();
        assert_eq!(read(directory.open_data(&blob).unwrap()), (b"0123456789".to_vec(), 0));
        // A manifest can say how long that file is. A file of another size,
        // shorter or longer, is not the one it means.
        let mut sized = object(c"sized");
        let mut contents = ContentsObject::new(ContentsSource::File(Name::new("blobs/1").unwrap().to_owned()));
        for (original_size, fits) in [(10, true), (11, false), (9, false)] {
            contents.set_original_size(Some(original_size));
            sized.file_mut().unwrap().set_contents(vec![contents.clone()]);
            let opened = directory.open_data(&sized);
            if fits {
                assert_eq!(read(opened.unwrap()).0, b"0123456789");
            } else {
                let mismatch = opened.unwrap_err();
                assert_eq!(mismatch.path.as_deref(), Some(c"sized"));
                assert_eq!(
                    kind(mismatch),
                    (uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH, libc::EBADMSG)
                );
            }
        }

        let missing = object(c"a/none");
        assert_eq!(
            kind(directory.open_data(&missing).unwrap_err()),
            (uapi16_error_kind_t::UAPI16_ERROR_SOURCE_MISSING, libc::ENOENT)
        );
        let no_file = object(c"a");
        assert_eq!(
            kind(directory.open_data(&no_file).unwrap_err()),
            (uapi16_error_kind_t::UAPI16_ERROR_SOURCE_NOT_REGULAR, libc::EINVAL)
        );
        // A symbolic link on the way is followed only where the directory
        // was made to follow them.
        let through = object(c"link");
        assert_eq!(
            kind(directory.open_data(&through).unwrap_err()),
            (uapi16_error_kind_t::UAPI16_ERROR_IO, libc::ELOOP)
        );
        assert_eq!(read(following.open_data(&through).unwrap()).0, b"hello");

        // Data that is in the manifest, and an object without data.
        let unsupported = (uapi16_error_kind_t::UAPI16_ERROR_UNSUPPORTED, libc::EOPNOTSUPP);
        let mut link = object(c"l");
        link.set_type(libc::S_IFLNK).unwrap();
        link.set_target(bytes(b"to")).unwrap();
        let carried = directory.open_data(&link).unwrap_err();
        assert_eq!(carried.path.as_deref(), Some(c"l"));
        assert_eq!(kind(carried), unsupported);
        let mut fifo = object(c"fifo");
        fifo.set_type(libc::S_IFIFO).unwrap();
        assert_eq!(kind(directory.open_data(&fifo).unwrap_err()), unsupported);
        assert_eq!(kind(directory.open_data(&object(c"")).unwrap_err()), unsupported);

        // Through the pointers C has: nothing is stored where it fails, and
        // both places are needed.
        let (mut fd, mut offset) = (-7, 7u64);
        let mut e: *mut uapi16_error = ptr::null_mut();
        // SAFETY: the objects are locals that live through the calls, and
        // the places are locals too.
        unsafe {
            let (d, o): (*const uapi16_directory, *const uapi16_file_object) = (&directory, &missing);
            assert_eq!(
                uapi16_directory_open_data(d, o, &mut fd, &mut offset, &mut e),
                -libc::ENOENT
            );
            assert_eq!((fd, offset), (-7, 7));
            assert_eq!(
                uapi16_error_kind(e),
                uapi16_error_kind_t::UAPI16_ERROR_SOURCE_MISSING as u64
            );
            e = uapi16_error_free(e);
            let o: *const uapi16_file_object = &blob;
            for (ret_fd, ret_offset) in [
                (ptr::null_mut(), &mut offset as *mut u64),
                (&mut fd as *mut c_int, ptr::null_mut()),
            ] {
                assert_eq!(
                    uapi16_directory_open_data(d, o, ret_fd, ret_offset, &mut e),
                    -libc::EINVAL
                );
                e = uapi16_error_free(e);
            }
            assert_eq!(
                uapi16_directory_open_data(ptr::null(), o, &mut fd, &mut offset, &mut e),
                -libc::EINVAL
            );
            e = uapi16_error_free(e);
            assert_eq!(
                uapi16_directory_open_data(d, ptr::null(), &mut fd, &mut offset, &mut e),
                -libc::EINVAL
            );
            e = uapi16_error_free(e);
            assert_eq!((fd, offset), (-7, 7));
            assert_eq!(uapi16_directory_open_data(d, o, &mut fd, &mut offset, &mut e), 0);
            assert!(fd >= 0 && offset == 0 && e.is_null());
            // The descriptor is the caller's: it is open, and closed here.
            assert_eq!(read((OwnedFd::from_raw_fd(fd), offset)).0, b"0123456789");
        }
        // In another process, and with an object of another process.
        let mut elsewhere = object(c"a/file");
        drop(following);
        let mut directory = directory;
        if let Some(other) = Process::elsewhere() {
            elsewhere.process = other;
            assert_eq!(directory.open_data(&elsewhere).unwrap_err().errno, libc::ECHILD);
            directory.process = other;
            assert_eq!(directory.open_data(&blob).unwrap_err().errno, libc::ECHILD);
        }
        drop(directory);
        assert!(rustix::io::fcntl_getfd(&top).is_ok());
        drop(tmp);
    }

    /// In another process than the one that made it, an object only fails
    /// where it can, and a writer that is dropped there leaves the file of
    /// its manifest to its parent. A call fails for what it is given first,
    /// then for the process, and only then for what the object says.
    #[test]
    fn another_process() {
        let child = |e: uapi16_error| {
            assert_eq!(
                (e.kind, e.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, libc::ECHILD)
            )
        };
        // Where nothing tells a process from another one, there is nothing
        // to refuse.
        let Some(elsewhere) = Process::elsewhere() else {
            return;
        };
        let out = TempDir::new("capi-process-out");
        let dir = File::open(&out.0).unwrap();

        let mut options = uapi16_manifest_options::new();
        // SAFETY: here and below, `dir` and `nowhere` stay open until the
        // test ends, and what borrows them is dropped before that.
        let mut created = unsafe { options.create_at(descriptor(&dir), text(c"m")) }.unwrap();
        // The name the new file has until it gets its own, where the file
        // system makes no file without a name.
        let names = || fs::read_dir(&out.0).unwrap().map(|entry| entry.unwrap().file_name());
        let temporary: Vec<_> = names().collect();
        let nowhere = File::options().write(true).open("/dev/null").unwrap();
        // SAFETY: as above.
        let mut finished = unsafe { options.open(descriptor(&nowhere)) }.unwrap();
        finished.finish().unwrap();
        let mut file = object(c"a");
        let mut sha256 = uapi16_sha256::new();
        let mut check = uapi16_data_check::new(&file).unwrap();
        // SAFETY: as above.
        let mut records = unsafe { uapi16_writer::begin(&options, descriptor(&nowhere), None) }.unwrap();

        options.process = elsewhere;
        created.process = elsewhere;
        finished.process = elsewhere;
        file.process = elsewhere;
        sha256.process = elsewhere;
        check.process = elsewhere;
        records.process = elsewhere;

        child(options.set_features(list(&[])).unwrap_err());
        child(options.set_order(1).unwrap_err());
        child(options.set_sync(true).unwrap_err());
        // SAFETY: as above.
        unsafe {
            child(options.create_at(descriptor(&dir), text(c"n")).err().unwrap());
            child(options.open(descriptor(&nowhere)).err().unwrap());
            child(uapi16_writer::begin(&options, descriptor(&nowhere), None).unwrap_err());
        }
        child(created.add_object(&object(c"x")).unwrap_err());
        child(created.finish().unwrap_err());
        // A writer that is finished says so only in its own process.
        child(finished.finish().unwrap_err());
        child(file.set_mode(0o644).unwrap_err());
        child(file.set_name(text(c"b")).unwrap_err());
        child(file.user_xattrs().unwrap_err());
        child(file.contents_file().unwrap_err());
        child(file.check_validity(0).unwrap_err());
        child(uapi16_data_check::new(&file).unwrap_err());
        child(sha256.update(bytes(b"x")).unwrap_err());
        child(sha256.finish().unwrap_err());
        child(check.update(bytes(b"x")).unwrap_err());
        child(check.finish().unwrap_err());
        child(records.file(&object(c"x")).unwrap_err());
        child(records.finish().unwrap_err());
        // An object of another process is none to give to an object of
        // this one either: a file object to the two writers, a root to a
        // writer of records that begins, and a signature object.
        {
            let here = uapi16_manifest_options::new();
            // SAFETY: as above.
            let mut to_descriptor = unsafe { here.open(descriptor(&nowhere)) }.unwrap();
            // SAFETY: as above.
            let mut of_records = unsafe { uapi16_writer::begin(&here, descriptor(&nowhere), None) }.unwrap();
            let mut foreign = object(c"");
            foreign.process = elsewhere;
            child(to_descriptor.add_object(&file).unwrap_err());
            child(to_descriptor.add_object(&foreign).unwrap_err());
            child(of_records.file(&file).unwrap_err());
            // SAFETY: as above.
            child(unsafe { uapi16_writer::begin(&here, descriptor(&nowhere), Some(&foreign)) }.unwrap_err());
            let mut signature = uapi16_signature::new(text(c"openpgp")).unwrap();
            signature.process = elsewhere;
            child(of_records.signature(&signature).unwrap_err());
            of_records.file(&object(c"x")).unwrap();
            to_descriptor.add_object(&object(c"x")).unwrap();
        }
        // What a call is given is looked at first.
        assert_eq!(options.set_features(list(&[1 << 40])).unwrap_err().errno, libc::EINVAL);
        assert_eq!(options.set_order(9).unwrap_err().errno, libc::EINVAL);
        assert_eq!(file.set_type(0).unwrap_err().errno, libc::EINVAL);
        assert_eq!(file.set_name(text(c"a//b")).unwrap_err().errno, libc::EINVAL);
        assert_eq!(sha256.update(Bytes(None)).unwrap_err().errno, libc::EINVAL);
        let nowhere_to = Descriptor(-1, PhantomData);
        // SAFETY: it is no descriptor, so nothing borrows it.
        let no_descriptor = unsafe { options.open(nowhere_to) }.err().unwrap();
        assert_eq!(no_descriptor.errno, libc::EBADF);
        // What can't fail gives what the object has.
        assert!(!file.name().is_null());
        assert_eq!(file.stated_features(), Features::NONE);

        // Dropped here they leave the directory as it is: nothing was
        // made, and the name the new file has is its parent's.
        drop((created, finished, records));
        assert_eq!(names().collect::<Vec<_>>(), temporary);
    }

    /// The functions of the builder as C calls them: the manifest of a tree
    /// goes to a new file and to a descriptor, and file objects of a caller
    /// make the manifest a record writer writes for them.
    #[test]
    fn the_functions() {
        let (tmp, top) = tree("capi-functions");
        let out = TempDir::new("capi-functions-out");
        let dir = File::open(&out.0).unwrap();
        let read = |mut file: File| {
            let mut data = Vec::new();
            file.rewind().unwrap();
            file.read_to_end(&mut data).unwrap();
            data
        };

        let options = uapi16_manifest_options::new();
        let report = options.generate_at(descriptor(&dir), text(c"m"), descriptor(&top), 0);
        let report = report.unwrap().report;
        assert_eq!((report.files(), report.directories()), (2, 2));
        let generated = fs::read(out.0.join("m")).unwrap();
        let into = tempfile(&out);
        options.generate(descriptor(&into), descriptor(&top), 0).unwrap();
        assert_eq!(read(into), generated);
        let exists = options.generate_at(descriptor(&dir), text(c"m"), descriptor(&top), 0);
        let exists = exists.unwrap_err();
        assert_eq!(exists.kind, uapi16_error_kind_t::UAPI16_ERROR_EXISTS);
        let unknown = options.generate(descriptor(&dir), descriptor(&top), 1 << 2);
        assert_eq!(unknown.unwrap_err().errno, libc::EINVAL);

        // The same manifest from file objects, which come in any order.
        let mut objects = Vec::new();
        for (name, st_mode, data) in [
            (c"top", libc::S_IFREG, Some(&b"top"[..])),
            (c"a/file", libc::S_IFREG, Some(&b"hello"[..])),
            (c"a", libc::S_IFDIR, None),
        ] {
            let mut object = object(name);
            object.set_type(st_mode).unwrap();
            if let Some(data) = data {
                let mut sha256 = uapi16_sha256::new();
                sha256.update(bytes(data)).unwrap();
                let hash = Sha256::from(sha256.finish().unwrap());
                assert_eq!(sha256.finish().unwrap_err().errno, libc::ESTALE);
                assert_eq!(sha256.update(bytes(data)).unwrap_err().errno, libc::ESTALE);
                let file = object.file_mut().unwrap();
                file.set_size(Some(data.len() as u64));
                file.set_sha256(Some(hash));
            }
            objects.push(object);
        }
        let mut options = uapi16_manifest_options::new();
        let features = Features::SIZE | Features::SHA256;
        options.set_features(list(&numbers_of(features))).unwrap();
        let into = tempfile(&out);
        // SAFETY: `into` is open until the writer was dropped.
        let mut writer = unsafe { options.open(descriptor(&into)) }.unwrap();
        for object in &objects {
            writer.add_object(object).unwrap();
        }
        // An object that is refused is not added, and the writer is as it
        // was.
        let mut with_mode = object(c"refused");
        with_mode.set_mode(0o644).unwrap();
        let refused = writer.add_object(&with_mode).unwrap_err();
        assert_eq!(refused.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
        assert_eq!(refused.field, Some(Field::Mode));
        let report = writer.finish().unwrap().report;
        assert_eq!((report.files(), report.directories(), report.bytes()), (2, 2, 8));
        assert_eq!(
            writer.finish().unwrap_err().kind,
            uapi16_error_kind_t::UAPI16_ERROR_ENDED
        );
        assert_eq!(writer.add_object(&objects[0]).unwrap_err().errno, libc::ESTALE);
        drop(writer);
        let built = read(into);

        // The record writer takes them in the order of the manifest.
        let records = tempfile(&out);
        // SAFETY: `records` is open until the writer was dropped.
        let mut record_writer = unsafe { uapi16_writer::begin(&options, descriptor(&records), None) }.unwrap();
        // An object that is refused is not written, and the writer goes
        // on as if it had not been given it.
        let misplaced = record_writer.file(&objects[1]).unwrap_err();
        assert_eq!(misplaced.problem, Some(Problem::Misplaced));
        record_writer.file(&objects[2]).unwrap();
        record_writer.file(&objects[1]).unwrap();
        record_writer.file(&objects[0]).unwrap();
        record_writer.finish().unwrap();
        assert_eq!(record_writer.finish().unwrap_err().errno, libc::ESTALE);
        assert_eq!(record_writer.file(&objects[0]).unwrap_err().errno, libc::ESTALE);
        drop(record_writer);
        let written = read(records);
        assert_eq!(String::from_utf8_lossy(&written), String::from_utf8_lossy(&built));
        drop(tmp);
    }

    /// A file in `dir` that is there to be written to and read back.
    fn tempfile(dir: &TempDir) -> File {
        use std::sync::atomic::{AtomicU32, Ordering};
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = dir.0.join(format!("scratch-{}", NEXT.fetch_add(1, Ordering::Relaxed)));
        File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap()
    }

    /// Where a caller keeps the object that a reader fills: a pointer, which
    /// is NULL until a read stored an object there. The object is freed
    /// with it.
    struct Kept<T: Object>(*mut T);

    impl<T: Object> Kept<T> {
        /// A place without an object.
        fn new() -> Kept<T> {
            Kept(ptr::null_mut())
        }

        /// The place as the two read functions of a reader take it.
        fn place(&mut self) -> Refill<'_, T> {
            // SAFETY: the pointer is a field of this, and is NULL or the
            // object a read stored there, which nothing else has.
            unsafe { Refill::new(&mut self.0) }.unwrap()
        }

        /// The object, if a read stored one.
        fn get(&self) -> Option<&T> {
            // SAFETY: as in place().
            unsafe { self.0.as_ref() }
        }
    }

    impl<T: Object> Drop for Kept<T> {
        fn drop(&mut self) {
            // SAFETY: as in place(), and nothing uses the object after this.
            unsafe { T::free(self.0) };
        }
    }

    /// A reader of the manifest in `file`.
    ///
    /// # Safety
    ///
    /// `file` stays open until the reader is dropped.
    unsafe fn reader_of(file: &File) -> uapi16_reader {
        // SAFETY: `file` stays open until the reader is dropped, as the
        // caller says.
        unsafe { uapi16_reader::open(descriptor(file)) }.unwrap()
    }

    /// A reader hands out the file objects, says when signature objects
    /// follow, and reads those for a caller that asks for them, or passes
    /// over them. The manifest is complete once it said so. A read fills
    /// the object of its caller, and one that reads no object leaves it as
    /// it is.
    #[test]
    fn reading() {
        use uapi16_read_t::*;
        let out = TempDir::new("capi-reading");
        let manifest = |signatures: &[&str], after: &str| {
            let mut text = String::from(concat!(
                "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
                "\x1e{\"name\":\"a\",\"type\":\"dir\"}\n",
                "\x1e{\"name\":\"a/b\",\"size\":0}\n",
            ));
            for signature in signatures {
                text.push_str(&format!(
                    "\x1e{{\"mediaType\":\"application/vnd.uapi.16.signature\",\"mechanism\":\"{}\"}}\n",
                    signature
                ));
            }
            text.push_str(after);
            let mut file = tempfile(&out);
            file.write_all(text.as_bytes()).unwrap();
            file.rewind().unwrap();
            file
        };
        let trailer = "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n";
        // The names of the file objects that come, read into one object,
        // and what came after them.
        let files = |reader: &mut uapi16_reader| {
            let mut kept = Kept::new();
            let mut names = Vec::new();
            loop {
                match reader.next(kept.place()).unwrap() {
                    UAPI16_READ_FILE => names.push(kept.get().unwrap().object.name().as_str().to_owned()),
                    other => return (names, other),
                }
            }
        };
        let next = |reader: &mut uapi16_reader| reader.next(Kept::new().place());
        let next_signature = |reader: &mut uapi16_reader| reader.next_signature(Kept::new().place());

        // No signature objects: the file objects, and the end.
        {
            let file = manifest(&[], trailer);
            // SAFETY: here and below, a reader is dropped before its file.
            let mut reader = unsafe { reader_of(&file) };
            assert!(reader.root.is_root());
            assert_eq!(reader.order(), uapi16_order_t::UAPI16_ORDER_CODEPOINT);
            reader.require_order(1).unwrap();
            assert_eq!(reader.require_order(2).unwrap_err().errno, libc::EINVAL);
            assert_eq!(reader.require_order(0).unwrap_err().errno, libc::EINVAL);
            reader.check_validity(0).unwrap();
            assert_eq!(reader.signed_len().unwrap_err().errno, libc::ENODATA);
            assert_eq!(next_signature(&mut reader).unwrap_err().errno, libc::EINVAL);
            assert_eq!(
                files(&mut reader),
                (vec!["a".to_owned(), "a/b".to_owned()], UAPI16_READ_END)
            );
            assert_eq!(reader.signed_len().unwrap_err().errno, libc::ENODATA);
            // It stays at its end, also for a caller that asks for signature
            // objects, of which it has none. That caller keeps the object
            // it has, as it is.
            assert_eq!(next(&mut reader).unwrap(), UAPI16_READ_END);
            let mut kept = Kept::new();
            assert_eq!(reader.next_signature(kept.place()).unwrap(), UAPI16_READ_END);
            assert!(kept.get().is_none());
            kept.place().store(uapi16_signature::new(text(c"mine")).unwrap());
            let mine = kept.0;
            for _ in 0..2 {
                assert_eq!(reader.next_signature(kept.place()).unwrap(), UAPI16_READ_END);
                assert_eq!(kept.0, mine);
                assert_eq!(kept.get().unwrap().signature.mechanism(), "mine");
            }
            assert_eq!(next(&mut reader).unwrap(), UAPI16_READ_END);
        }

        // Signature objects that are passed over.
        {
            let file = manifest(&["openpgp", "pkcs7"], trailer);
            // SAFETY: as above.
            let mut reader = unsafe { reader_of(&file) };
            assert_eq!(files(&mut reader).1, UAPI16_READ_SIGNATURES);
            let signed = reader.signed_len().unwrap();
            assert!(signed > 0);
            assert_eq!(next(&mut reader).unwrap(), UAPI16_READ_END);
            assert_eq!(reader.signed_len().unwrap(), signed);
        }

        // Signature objects that are read, each once, into one object. The
        // end leaves that object as it is.
        {
            let file = manifest(&["openpgp", "pkcs7"], trailer);
            // SAFETY: as above.
            let mut reader = unsafe { reader_of(&file) };
            assert_eq!(files(&mut reader).1, UAPI16_READ_SIGNATURES);
            let mut kept = Kept::new();
            for mechanism in ["openpgp", "pkcs7"] {
                assert_eq!(reader.next_signature(kept.place()).unwrap(), UAPI16_READ_SIGNATURE);
                assert_eq!(kept.get().unwrap().signature.mechanism(), mechanism);
            }
            let last = kept.0;
            assert_eq!(reader.next_signature(kept.place()).unwrap(), UAPI16_READ_END);
            assert_eq!(kept.0, last);
            assert_eq!(kept.get().unwrap().signature.mechanism(), "pkcs7");
            assert_eq!(next(&mut reader).unwrap(), UAPI16_READ_END);
        }

        // One that is read and the rest passed over.
        {
            let file = manifest(&["openpgp", "pkcs7"], trailer);
            // SAFETY: as above.
            let mut reader = unsafe { reader_of(&file) };
            assert_eq!(files(&mut reader).1, UAPI16_READ_SIGNATURES);
            assert_eq!(next_signature(&mut reader).unwrap(), UAPI16_READ_SIGNATURE);
            assert_eq!(next(&mut reader).unwrap(), UAPI16_READ_END);
        }

        // A file object after a signature object is refused, also where the
        // signature objects are passed over, and the reader takes nothing
        // more after that.
        let late = "\x1e{\"name\":\"c\"}\n";
        for take in [false, true] {
            let file = manifest(&["openpgp"], late);
            // SAFETY: as above.
            let mut reader = unsafe { reader_of(&file) };
            assert_eq!(files(&mut reader).1, UAPI16_READ_SIGNATURES);
            let failed = if take {
                assert_eq!(next_signature(&mut reader).unwrap(), UAPI16_READ_SIGNATURE);
                next_signature(&mut reader).unwrap_err()
            } else {
                next(&mut reader).unwrap_err()
            };
            assert_eq!(failed.problem, Some(Problem::FileAfterSignature));
            assert_eq!(failed.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
            let ended = uapi16_error_kind_t::UAPI16_ERROR_ENDED;
            assert_eq!(next(&mut reader).unwrap_err().kind, ended);
            assert_eq!(next_signature(&mut reader).unwrap_err().kind, ended);
        }

        // A manifest that ends without its trailer is not complete. The
        // read that finds that out leaves the object of the caller as the
        // read before left it, and so does every read after it.
        let file = manifest(&[], "");
        // SAFETY: as above.
        let mut reader = unsafe { reader_of(&file) };
        let mut kept = Kept::new();
        let mut names = Vec::new();
        let failed = loop {
            match reader.next(kept.place()) {
                Ok(UAPI16_READ_FILE) => names.push(kept.get().unwrap().object.name().as_str().to_owned()),
                Ok(other) => panic!("{:?}", other),
                Err(e) => break e,
            }
        };
        assert_eq!(names, ["a", "a/b"]);
        assert_eq!(failed.problem, Some(Problem::NoTrailer));
        let last = kept.0;
        assert_eq!(kept.get().unwrap().object.name().as_str(), "a/b");
        assert_eq!(reader.next(kept.place()).unwrap_err().errno, libc::ESTALE);
        assert_eq!(kept.0, last);
        assert_eq!(kept.get().unwrap().object.name().as_str(), "a/b");
    }

    /// A reader fills the object of a caller again as getline() fills its
    /// buffer: the object stays where it is, and nothing of the record
    /// before is left in it, also not the strings it handed out. An object
    /// of another process is not one a read fills.
    #[test]
    fn refilled_objects() {
        use uapi16_read_t::*;
        let out = TempDir::new("capi-refill");
        // A file object that says what an object can say, and one after it
        // that says nothing.
        let mut full = object(c"full");
        full.set_mode(libc::S_IFREG | 0o440).unwrap();
        let inode = full.inode_mut().unwrap();
        inode.set_uid(Some(1));
        inode.set_gid(Some(2));
        inode.set_mtime_nsec(Some(3));
        full.set_user_name(text(c"user")).unwrap();
        full.set_group_name(text(c"group")).unwrap();
        let file = full.file_mut().unwrap();
        file.set_size(Some(0));
        file.set_sha256(Some(Sha256::digest(b"")));
        full.set_inode_token(9).unwrap();
        full.set_user_xattrs().unwrap();
        full.add_user_xattr(text(c"key"), bytes(b"value")).unwrap();
        full.set_read_only(uapi16_read_only_t::UAPI16_READ_ONLY_YES as u64)
            .unwrap();
        full.set_inode_flags(0x20 | 0x10, 0x20).unwrap();
        full.set_dos_attributes(0x02 | 0x20, 0x20).unwrap();
        full.set_contents_file(text(c"blobs/1")).unwrap();
        let mut options = uapi16_manifest_options::new();
        options.set_features(list(&numbers_of(full.stated_features()))).unwrap();
        let manifest = tempfile(&out);
        {
            // SAFETY: `manifest` is open until the writer was dropped.
            let mut writer = unsafe { uapi16_writer::begin(&options, descriptor(&manifest), None) }.unwrap();
            writer.file(&full).unwrap();
            writer.file(&object(c"plain")).unwrap();
            writer.finish().unwrap();
        }

        // Each record read into an object of its own.
        (&manifest).rewind().unwrap();
        let fresh = {
            // SAFETY: here and below, a reader is dropped before `manifest`.
            let mut reader = unsafe { reader_of(&manifest) };
            let mut objects = Vec::new();
            loop {
                let mut kept = Kept::new();
                match reader.next(kept.place()).unwrap() {
                    UAPI16_READ_FILE => objects.push(kept),
                    UAPI16_READ_END => break objects,
                    other => panic!("{:?}", other),
                }
            }
        };
        assert_eq!(fresh.len(), 2);
        let same = |a: &uapi16_file_object, b: &uapi16_file_object| {
            assert_eq!(a.object, b.object);
            assert_eq!(a.file_system, b.file_system);
            assert_eq!(a.gpt_disk_uuid, b.gpt_disk_uuid);
        };
        // The strings an object hands out, which it keeps until it is
        // filled again.
        let strings = |o: &uapi16_file_object| {
            // SAFETY: a string that is not NULL is one of the object, which
            // is not changed while it is copied.
            let copy = |text: *const c_char| (!text.is_null()).then(|| unsafe { CStr::from_ptr(text) }.to_owned());
            let xattrs = o.user_xattrs().ok().map(|count| {
                let names = (0..count).map(|i| copy(o.user_xattr(i).unwrap().0));
                names.collect::<Vec<_>>()
            });
            let (name, label) = (copy(o.name()), copy(o.fs_label()));
            (name, copy(o.user_name()), copy(o.group_name()), label, xattrs)
        };

        // Both records read into one object.
        (&manifest).rewind().unwrap();
        // SAFETY: as above.
        let mut reader = unsafe { reader_of(&manifest) };
        let mut kept = Kept::new();
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_FILE);
        let first = kept.0;
        same(kept.get().unwrap(), fresh[0].get().unwrap());
        let handed_out = strings(kept.get().unwrap());
        assert_eq!(handed_out, strings(&full));
        assert_eq!(handed_out.1.as_deref(), Some(c"user"));
        assert_eq!(handed_out.4, Some(vec![Some(c"key".to_owned())]));
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_FILE);
        assert_eq!(kept.0, first);
        let plain = kept.get().unwrap();
        same(plain, fresh[1].get().unwrap());
        assert_eq!(strings(plain), strings(fresh[1].get().unwrap()));
        assert_eq!(strings(plain).0.as_deref(), Some(c"plain"));
        assert!(plain.user_name().is_null() && plain.group_name().is_null());
        let inode = plain.object.inode();
        assert_eq!(
            (inode.mode(), inode.uid(), inode.gid(), inode.mtime_nsec()),
            (None, None, None, None)
        );
        assert_eq!((plain.object.size(), plain.object.sha256()), (None, None));
        assert_eq!(plain.object.inode_token(), None);
        assert!(plain.object.contents().is_empty());
        // What the manifest records and the object does not say is filled
        // in, as for an object of its own.
        assert_eq!(plain.user_xattrs().unwrap(), 0);
        assert_eq!(inode.read_only(), Some(false));
        // The end leaves the object as it is.
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_END);
        assert_eq!(kept.0, first);
        same(kept.get().unwrap(), fresh[1].get().unwrap());
        drop(reader);

        // An object of another process is not filled, and nothing is read
        // for it.
        (&manifest).rewind().unwrap();
        // SAFETY: as above.
        let mut reader = unsafe { reader_of(&manifest) };
        // SAFETY: the object is the one the reads stored, which nothing
        // else uses.
        if let Some(elsewhere) = Process::elsewhere() {
            // SAFETY: as above.
            unsafe { (*kept.0).process = elsewhere };
            assert_eq!(reader.next(kept.place()).unwrap_err().errno, libc::ECHILD);
            same(kept.get().unwrap(), fresh[1].get().unwrap());
        }
        let mut other = Kept::new();
        assert_eq!(reader.next(other.place()).unwrap(), UAPI16_READ_FILE);
        same(other.get().unwrap(), fresh[0].get().unwrap());

        // One object for two records whose attributes have other names: the
        // names of the first record are not those of the second.
        let named = |name: &CStr, attribute: &CStr| {
            let mut o = object(name);
            o.set_user_xattrs().unwrap();
            o.add_user_xattr(text(attribute), bytes(b"1")).unwrap();
            o
        };
        let mut options = uapi16_manifest_options::new();
        options.set_features(list(&numbers_of(Features::USER_XATTR))).unwrap();
        let attributes = tempfile(&out);
        {
            // SAFETY: `attributes` is open until the writer was dropped.
            let mut writer = unsafe { uapi16_writer::begin(&options, descriptor(&attributes), None) }.unwrap();
            writer.file(&named(c"a", c"one")).unwrap();
            writer.file(&named(c"b", c"two")).unwrap();
            writer.finish().unwrap();
        }
        (&attributes).rewind().unwrap();
        // SAFETY: `attributes` is open until the reader was dropped.
        let mut reader = unsafe { uapi16_reader::open(descriptor(&attributes)) }.unwrap();
        let mut kept = Kept::new();
        for attribute in [c"one", c"two"] {
            assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_FILE);
            let (name, _, _) = kept.get().unwrap().user_xattr(0).unwrap();
            // SAFETY: the name is a string of the object, which is there.
            assert_eq!(unsafe { CStr::from_ptr(name) }, attribute);
        }
    }

    /// An object that keeps a descriptor has it on loan from its caller: it
    /// uses that descriptor and no duplicate of it, and leaves it open when
    /// it is dropped, also where it could not be made and in another
    /// process.
    #[test]
    fn lent_descriptors() {
        let out = TempDir::new("capi-lent");
        let dir = File::open(&out.0).unwrap();
        fs::create_dir(out.0.join("sub")).unwrap();
        let open = |file: &File| rustix::io::fcntl_getfd(file).is_ok();
        let options = uapi16_manifest_options::new();
        let mut manifest = tempfile(&out);
        let root = "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n";
        let trailer = "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n";
        manifest.write_all(root.as_bytes()).unwrap();
        manifest.write_all(trailer.as_bytes()).unwrap();
        manifest.rewind().unwrap();
        let empty = tempfile(&out);
        let records = tempfile(&out);
        let listing = tempfile(&out);

        // SAFETY: every object is dropped before the file it has on loan,
        // which is open until the test ends.
        unsafe {
            let reader = uapi16_reader::open(descriptor(&manifest)).unwrap();
            assert_eq!(reader.reader.get_ref().as_raw_fd(), manifest.as_raw_fd());
            drop(reader);
            assert!(open(&manifest));
            // A file that is no manifest makes no reader, and stays open.
            let no_manifest = uapi16_reader::open(descriptor(&empty)).unwrap_err();
            assert_eq!(no_manifest.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
            assert!(open(&empty));

            let mut writer = uapi16_writer::begin(&options, descriptor(&records), None).unwrap();
            let lent = writer.writer.as_ref().unwrap().get_ref().as_raw_fd();
            assert_eq!(lent, records.as_raw_fd());
            writer.finish().unwrap();
            assert!(open(&records));
            drop(writer);
            assert!(open(&records));
            // What it wrote went to the file of the caller.
            assert!(records.metadata().unwrap().len() > 0);

            let mut writer = options.open(descriptor(&listing)).unwrap();
            writer.add_object(&object(c"a")).unwrap();
            writer.finish().unwrap();
            assert!(open(&listing));
            drop(writer);
            assert!(open(&listing));
            // One that is dropped before it finished leaves it open too.
            drop(options.open(descriptor(&listing)).unwrap());
            assert!(open(&listing));

            // A new file whose name has one component is made in the
            // directory of the caller, which the writer shares with what it
            // keeps there. For a longer name the writer opens the
            // directory of the file itself.
            for (name, shared) in [(c"m", true), (c"sub/m", false)] {
                let writer = options.create_at(descriptor(&dir), text(name)).unwrap();
                let Some(WriterTo::NewFile(_, lent)) = writer.writer.as_ref() else {
                    panic!("no writer of a new file");
                };
                assert_eq!(lent.as_raw_fd(), dir.as_raw_fd());
                assert_eq!(Arc::strong_count(lent) > 1, shared, "{:?}", name);
                drop(writer);
                assert!(open(&dir));
            }
            let mut writer = options.create_at(descriptor(&dir), text(c"m")).unwrap();
            writer.finish().unwrap();
            assert!(open(&dir));
            drop(writer);
            assert!(open(&dir));
            // A name that is taken makes no writer.
            let exists = options.create_at(descriptor(&dir), text(c"m")).err().unwrap();
            assert_eq!(exists.kind, uapi16_error_kind_t::UAPI16_ERROR_EXISTS);
            assert!(open(&dir));
            // In another process the writer leaves the descriptor open as
            // well.
            let mut writer = options.create_at(descriptor(&dir), text(c"n")).unwrap();
            if let Some(elsewhere) = Process::elsewhere() {
                writer.process = elsewhere;
            }
            drop(writer);
            assert!(open(&dir));

            let directory = uapi16_directory::new(descriptor(&dir), 0).unwrap();
            drop(directory);
            assert!(open(&dir));
            assert_eq!(
                uapi16_directory::new(descriptor(&dir), 1 << 1).unwrap_err().errno,
                libc::EINVAL
            );
            assert!(open(&dir));
        }

        // The functions that make no object borrow for the call.
        let top = File::open(out.0.join("sub")).unwrap();
        options
            .generate_at(descriptor(&dir), text(c"g"), descriptor(&top), 0)
            .unwrap();
        options.generate(descriptor(&listing), descriptor(&top), 0).unwrap();
        assert!(open(&dir) && open(&listing) && open(&top));
        // What was lent is still what it was: the manifest reads again.
        manifest.rewind().unwrap();
        // SAFETY: the reader is dropped before `manifest`.
        let mut reader = unsafe { reader_of(&manifest) };
        let read = reader.next(Kept::new().place()).unwrap();
        assert_eq!(read, uapi16_read_t::UAPI16_READ_END);
    }

    /// A manifest goes through a pipe, from a writer of records to a reader
    /// and into one object of the caller. The writer and the reader have
    /// their ends of the pipe on loan, and leave them open. So does a
    /// directory, and a descriptor that was shared for a while. This test
    /// needs no file system, so it runs under Miri as well.
    #[test]
    fn through_a_pipe() {
        use uapi16_read_t::*;
        let mut ends = [0; 2];
        // SAFETY: pipe2() stores two descriptors in the array.
        assert_eq!(unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the two are new descriptors, which nothing else has.
        let (from, into) = unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
        let open = |file: &File| rustix::io::fcntl_getfd(file).is_ok();
        let options = uapi16_manifest_options::new();
        {
            // SAFETY: `into` is open until the writer was dropped.
            let mut writer = unsafe { uapi16_writer::begin(&options, descriptor(&into), None) }.unwrap();
            let lent = writer.writer.as_ref().unwrap().get_ref().as_raw_fd();
            assert_eq!(lent, into.as_raw_fd());
            for name in [c"a", c"b"] {
                writer.file(&object(name)).unwrap();
            }
            // An object that is refused would have been the next record,
            // whether the writer finds what is wrong with it or this does:
            // one that is out of order, and one with a field of the root.
            let out_of_order = writer.file(&object(c"a")).unwrap_err();
            assert_eq!(out_of_order.problem, Some(Problem::OutOfOrder));
            let mut labeled = object(c"c");
            labeled.set_fs_label(text(c"label")).unwrap();
            let not_permitted = writer.file(&labeled).unwrap_err();
            assert_eq!(not_permitted.problem, Some(Problem::FieldNotPermitted));
            assert_eq!((out_of_order.record, not_permitted.record), (Some(3), Some(3)));
            writer.file(&object(c"c")).unwrap();
            writer
                .signature(&uapi16_signature::new(text(c"openpgp")).unwrap())
                .unwrap();
            writer.finish().unwrap();
        }
        assert!(open(&into));
        drop(into);

        // SAFETY: the reader is dropped before `from`.
        let mut reader = unsafe { reader_of(&from) };
        assert_eq!(reader.reader.get_ref().as_raw_fd(), from.as_raw_fd());
        let mut kept = Kept::new();
        let mut names = Vec::new();
        let mut places = Vec::new();
        while reader.next(kept.place()).unwrap() == UAPI16_READ_FILE {
            names.push(kept.get().unwrap().object.name().as_str().to_owned());
            places.push(kept.0);
        }
        assert_eq!(names, ["a", "b", "c"]);
        // One object took all three, where the first read made it.
        assert!(!places[0].is_null() && places.iter().all(|place| *place == places[0]));
        let mut signature = Kept::new();
        assert_eq!(reader.next_signature(signature.place()).unwrap(), UAPI16_READ_SIGNATURE);
        assert_eq!(signature.get().unwrap().signature.mechanism(), "openpgp");
        assert_eq!(reader.next_signature(signature.place()).unwrap(), UAPI16_READ_END);
        assert_eq!(signature.get().unwrap().signature.mechanism(), "openpgp");
        drop(reader);
        assert!(open(&from));

        // SAFETY: what borrows `from` is dropped before it.
        unsafe {
            drop(uapi16_directory::new(descriptor(&from), 0).unwrap());
            assert!(open(&from));
            let lent = descriptor(&from).lend(Arc::new).unwrap();
            let shared = Arc::clone(&lent);
            assert_eq!(shared.as_raw_fd(), from.as_raw_fd());
            drop(shared);
            drop(lent);
            assert!(open(&from));
        }
    }

    /// A reader of a pipe that does not block fails with EAGAIN while
    /// nothing is there to read. That does not end it: it lost nothing, and
    /// it reads on with the next call, also where half a record came in
    /// between. The object of the caller stays as it is until then.
    #[test]
    fn no_blocking() {
        use uapi16_read_t::*;
        let mut ends = [0; 2];
        // SAFETY: pipe2() stores two descriptors in the array.
        let made = unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) };
        assert_eq!(made, 0);
        // SAFETY: the two are new descriptors, which nothing else has.
        let (from, mut into) = unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
        let begin = concat!(
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n",
            "\x1e{\"name\":\"a\"}\n",
            "\x1e",
        );
        let rest = concat!(
            "\"size\":7}\n",
            "\x1e{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n",
        );
        into.write_all(begin.as_bytes()).unwrap();
        // SAFETY: the reader is dropped before `from`.
        let mut reader = unsafe { reader_of(&from) };
        let mut kept = Kept::new();
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_FILE);
        for half in [None, Some("{\"name\":\"b\",")] {
            if let Some(half) = half {
                into.write_all(half.as_bytes()).unwrap();
            }
            let nothing = reader.next(kept.place()).unwrap_err();
            assert_eq!(
                (nothing.kind, nothing.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_IO, libc::EAGAIN)
            );
            assert_eq!(kept.get().unwrap().object.name().as_str(), "a");
        }
        into.write_all(rest.as_bytes()).unwrap();
        drop(into);
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_FILE);
        let read = &kept.get().unwrap().object;
        assert_eq!((read.name().as_str(), read.size()), ("b", Some(7)));
        assert_eq!(reader.next(kept.place()).unwrap(), UAPI16_READ_END);
    }

    /// The root of a reader as C uses it: the pointer is taken once, and the
    /// root is read through it while the reader reads on, until the reader
    /// is freed. This test needs no file system, so it runs under Miri as
    /// well, which finds a pointer that a later call on the reader ended.
    #[test]
    fn the_root_of_a_reader() {
        const LABEL: FeatureNumber = uapi16_feature_t::UAPI16_FEATURE_FS_LABEL as FeatureNumber;
        let mut ends = [0; 2];
        // SAFETY: pipe2() stores two descriptors in the array.
        assert_eq!(unsafe { libc::pipe2(ends.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        // SAFETY: the two are new descriptors, which nothing else has.
        let (from, into) = unsafe { (File::from_raw_fd(ends[0]), File::from_raw_fd(ends[1])) };
        // SAFETY: the pointers are locals, the strings are literals, and
        // every object is used as the functions say: made once, freed once,
        // and not used after that. The ends of the pipe are open for as
        // long as the writer and the reader are there.
        unsafe {
            let options = uapi16_manifest_options_new();
            assert_eq!(uapi16_manifest_options_add_features(options, &LABEL, 1), 0);
            let mut root: *mut uapi16_file_object = ptr::null_mut();
            assert_eq!(uapi16_file_object_new(c"".as_ptr(), &mut root, ptr::null_mut()), 0);
            assert_eq!(uapi16_file_object_set_fs_label(root, c"label".as_ptr()), 0);
            let mut writer: *mut uapi16_writer = ptr::null_mut();
            let begun = uapi16_writer_begin(options, into.as_raw_fd(), root, &mut writer, ptr::null_mut());
            assert_eq!(begun, 0);
            for name in [c"a", c"b"] {
                let mut file: *mut uapi16_file_object = ptr::null_mut();
                assert_eq!(uapi16_file_object_new(name.as_ptr(), &mut file, ptr::null_mut()), 0);
                assert_eq!(uapi16_writer_file(writer, file, ptr::null_mut()), 0);
                uapi16_file_object_free(file);
            }
            assert_eq!(uapi16_writer_finish(writer, ptr::null_mut()), 0);
            uapi16_writer_free(writer);
            uapi16_file_object_free(root);
            uapi16_manifest_options_free(options);
            drop(into);

            let mut reader: *mut uapi16_reader = ptr::null_mut();
            assert_eq!(uapi16_reader_open(from.as_raw_fd(), &mut reader, ptr::null_mut()), 0);
            let root = uapi16_reader_root(reader);
            let check_root = || {
                assert_eq!(CStr::from_ptr(uapi16_file_object_name(root)), c"");
                assert_eq!(uapi16_file_object_type(root), libc::S_IFDIR);
                assert_eq!(CStr::from_ptr(uapi16_file_object_fs_label(root)), c"label");
            };
            check_root();
            let mut kept: *mut uapi16_file_object = ptr::null_mut();
            for name in [c"a", c"b"] {
                let read = uapi16_reader_next(reader, &mut kept, ptr::null_mut());
                assert_eq!(read, uapi16_read_t::UAPI16_READ_FILE as c_int);
                assert_eq!(CStr::from_ptr(uapi16_file_object_name(kept)), name);
                check_root();
                assert_eq!(uapi16_reader_root(reader), root);
            }
            let read = uapi16_reader_next(reader, &mut kept, ptr::null_mut());
            assert_eq!(read, uapi16_read_t::UAPI16_READ_END as c_int);
            check_root();
            let recorded = numbers_of(Features::DEFAULT | Features::FS_LABEL);
            for (i, feature) in recorded.iter().enumerate() {
                assert!(uapi16_reader_has_feature(reader, *feature));
                assert_eq!(uapi16_reader_feature(reader, i), *feature);
            }
            assert_eq!(uapi16_reader_feature(reader, recorded.len()), 0);
            assert!(!uapi16_reader_has_feature(reader, 0));
            check_root();
            uapi16_reader_free(reader);
            uapi16_file_object_free(kept);
            assert!(uapi16_reader_root(ptr::null()).is_null());
        }
    }

    /// Options of C can have no order. A writer of records takes them: it
    /// writes the file objects in the order they come in and declares
    /// none. It still wants every object right after its directory, and
    /// finds a name that comes again right after the objects of the
    /// directory it names, but not every name that comes twice, as it does
    /// with an order. The writers that sort take no such options, and
    /// write nothing.
    #[test]
    fn no_order() {
        let (tmp, top) = tree("capi-no-order");
        let out = TempDir::new("capi-no-order-out");
        let dir = File::open(&out.0).unwrap();
        let mut options = uapi16_manifest_options::new();
        // File objects as a caller that does not sort has them, and what
        // the writer says to each.
        let write = |options: &uapi16_manifest_options, into: &File| {
            // SAFETY: `into` is open until the writer was dropped.
            let mut writer = unsafe { uapi16_writer::begin(options, descriptor(into), None) }.unwrap();
            let mut said = Vec::new();
            for (name, st_mode) in [
                (c"b", libc::S_IFDIR),
                (c"b/z", libc::S_IFREG),
                (c"b/y", libc::S_IFREG),
                (c"b/z", libc::S_IFREG),
                (c"b", libc::S_IFDIR),
                (c"a", libc::S_IFREG),
                (c"a", libc::S_IFREG),
                (c"b/x", libc::S_IFREG),
            ] {
                let mut object = object(name);
                object.set_type(st_mode).unwrap();
                said.push(writer.file(&object).err().and_then(|e| e.problem));
            }
            writer.finish().unwrap();
            said
        };

        options.set_order(uapi16_order_t::UAPI16_ORDER_NONE as u64).unwrap();
        let unsorted = tempfile(&out);
        assert_eq!(
            write(&options, &unsorted),
            [
                None,
                None,
                // After b/z, which it sorts before.
                None,
                // A name that comes twice, with another one in between.
                None,
                // The directory again, right after its objects.
                Some(Problem::DuplicateName),
                None,
                // The same name again, right away.
                Some(Problem::DuplicateName),
                // Not right after the object of its directory.
                Some(Problem::Misplaced),
            ]
        );
        // The manifest declares no order, and a reader takes it as it is.
        (&unsorted).rewind().unwrap();
        {
            // SAFETY: the reader is dropped before `unsorted`.
            let mut reader = unsafe { reader_of(&unsorted) };
            assert_eq!(reader.order(), uapi16_order_t::UAPI16_ORDER_NONE);
            let required = reader.require_order(uapi16_order_t::UAPI16_ORDER_CODEPOINT as u64);
            let required = required.unwrap_err();
            assert_eq!(required.kind, uapi16_error_kind_t::UAPI16_ERROR_MANIFEST);
            // The field is one of the record of the root, which the error
            // names.
            assert_eq!(required.path.as_deref(), Some(c""));
            let mut kept = Kept::new();
            let mut names = Vec::new();
            while reader.next(kept.place()).unwrap() == uapi16_read_t::UAPI16_READ_FILE {
                names.push(kept.get().unwrap().object.name().as_str().to_owned());
            }
            assert_eq!(names, ["b", "b/z", "b/y", "b/z", "a"]);
        }

        // The writers that sort take no options without an order.
        let refused = |e: uapi16_error| {
            assert_eq!(
                (e.kind, e.errno),
                (uapi16_error_kind_t::UAPI16_ERROR_INVALID_ARGUMENT, libc::EINVAL)
            )
        };
        let into = tempfile(&out);
        let names = || {
            let mut names: Vec<_> = fs::read_dir(&out.0)
                .unwrap()
                .map(|entry| entry.unwrap().file_name())
                .collect();
            names.sort();
            names
        };
        let before = names();
        // SAFETY: no writer is made, so nothing keeps `dir` or `into`.
        unsafe {
            refused(options.create_at(descriptor(&dir), text(c"m")).err().unwrap());
            refused(options.open(descriptor(&into)).err().unwrap());
        }
        refused(
            options
                .generate_at(descriptor(&dir), text(c"m"), descriptor(&top), 0)
                .unwrap_err(),
        );
        refused(options.generate(descriptor(&into), descriptor(&top), 0).unwrap_err());
        assert_eq!(into.metadata().unwrap().len(), 0);
        assert_eq!(names(), before);

        // With the code point order the names have to be in it, every name
        // that comes twice is found, and the writers that sort work again.
        options
            .set_order(uapi16_order_t::UAPI16_ORDER_CODEPOINT as u64)
            .unwrap();
        let sorted = tempfile(&out);
        assert_eq!(
            write(&options, &sorted),
            [
                None,
                None,
                Some(Problem::OutOfOrder),
                Some(Problem::DuplicateName),
                Some(Problem::DuplicateName),
                Some(Problem::OutOfOrder),
                Some(Problem::OutOfOrder),
                Some(Problem::OutOfOrder),
            ]
        );
        options.generate(descriptor(&into), descriptor(&top), 0).unwrap();
        assert!(into.metadata().unwrap().len() > 0);
        drop(tmp);
    }

    /// A check of data holds what passes against the size and the hash of
    /// its object. It has what it needs of the object as its own, the name
    /// included, so the object of the caller can go.
    #[test]
    fn data_checks() {
        let mut o = object(c"data");
        let file = o.file_mut().unwrap();
        file.set_size(Some(5));
        file.set_sha256(Some(Sha256::digest(b"hello")));
        let mut check = uapi16_data_check::new(&o).unwrap();
        let mut wrong = uapi16_data_check::new(&o).unwrap();
        let mut short = uapi16_data_check::new(&o).unwrap();
        drop(o);
        check.update(bytes(b"hel")).unwrap();
        check.update(bytes(b"")).unwrap();
        let more = check.update(bytes(b"lo!")).unwrap_err();
        assert_eq!(more.kind, uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH);
        assert_eq!(more.path.as_deref(), Some(c"data"));
        check.update(bytes(b"lo")).unwrap();
        assert_eq!(check.finish().unwrap(), 5);
        assert_eq!(check.finish().unwrap_err().errno, libc::ESTALE);
        assert_eq!(check.update(bytes(b"x")).unwrap_err().errno, libc::ESTALE);

        wrong.update(bytes(b"hallo")).unwrap();
        assert_eq!(
            wrong.finish().unwrap_err().kind,
            uapi16_error_kind_t::UAPI16_ERROR_HASH_MISMATCH
        );
        assert_eq!(wrong.finish().unwrap_err().errno, libc::ESTALE);
        short.update(bytes(b"hell")).unwrap();
        assert_eq!(
            short.finish().unwrap_err().kind,
            uapi16_error_kind_t::UAPI16_ERROR_SIZE_MISMATCH
        );
        // One that is dropped before it is finished frees what it has.
        let unfinished = uapi16_data_check::new(&object(c"other")).unwrap();
        drop(unfinished);
    }

    /// A value that is made once: the first one who asks has it made, and
    /// whoever asks after that gets the same one. A thread that asks while
    /// another one is still making its value does not wait for it: it makes
    /// one itself, and the thread whose value comes second drops it and
    /// takes the first. A cell that is reset has its value made anew, and
    /// one that is dropped drops its value.
    #[test]
    fn once_boxes() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        use std::sync::mpsc;
        /// How many values there are.
        static LIVE: AtomicUsize = AtomicUsize::new(0);
        /// How long an answer may take that has nothing to wait for.
        const PATIENCE: std::time::Duration = std::time::Duration::from_secs(30);
        struct Counted(usize);
        impl Counted {
            fn new(number: usize) -> Counted {
                LIVE.fetch_add(1, SeqCst);
                Counted(number)
            }
        }
        impl Drop for Counted {
            fn drop(&mut self) {
                LIVE.fetch_sub(1, SeqCst);
            }
        }

        let mut cell = OnceBox::new();
        assert_eq!(cell.get_or_init(|| Counted::new(1)).0, 1);
        assert_eq!(cell.get_or_init(|| Counted::new(2)).0, 1);
        assert_eq!(LIVE.load(SeqCst), 1);
        cell.reset();
        assert_eq!(LIVE.load(SeqCst), 0);
        cell.reset();
        assert_eq!(cell.get_or_init(|| Counted::new(3)).0, 3);
        assert_eq!(LIVE.load(SeqCst), 1);
        drop(cell);
        assert_eq!(LIVE.load(SeqCst), 0);

        // A thread is making its value, and another one asks meanwhile. It
        // gets its answer while the first one is still at it. A thread that
        // waited for the first one would wait forever here, so the wait for
        // its answer ends after a while.
        let cell = Arc::new(OnceBox::new());
        let (making, is_making) = mpsc::channel();
        let (go_on, may_go_on) = mpsc::channel();
        let (answer, answered) = mpsc::channel();
        let first = {
            let cell = Arc::clone(&cell);
            std::thread::spawn(move || {
                let slow = move || {
                    making.send(()).unwrap();
                    may_go_on.recv().unwrap();
                    Counted::new(4)
                };
                cell.get_or_init(slow).0
            })
        };
        is_making.recv().unwrap();
        let second = {
            let cell = Arc::clone(&cell);
            std::thread::spawn(move || answer.send(cell.get_or_init(|| Counted::new(5)).0).unwrap())
        };
        assert_eq!(answered.recv_timeout(PATIENCE), Ok(5));
        go_on.send(()).unwrap();
        assert_eq!(first.join().unwrap(), 5);
        second.join().unwrap();
        assert_eq!(cell.get_or_init(|| Counted::new(6)).0, 5);
        assert_eq!(LIVE.load(SeqCst), 1);
        drop(cell);
        assert_eq!(LIVE.load(SeqCst), 0);
    }

    /// A process is known by its generation, which is the same each time
    /// it is asked for. A page of zeroes, as a child of a fork() has it,
    /// gets the next generation: one above every generation before it, and
    /// the same for threads that ask at the same time. An object is one of
    /// the process with its generation, and of no other. Where a process
    /// has no page, nothing tells it from another, and nothing is refused.
    ///
    /// Under Miri the process has no page, so what a page does is shown on
    /// one of the test's own, which nothing wipes but the test.
    #[test]
    fn generations() {
        static PAGE: AtomicUsize = AtomicUsize::new(0);
        const CHILDREN: usize = 3;
        const THREADS: usize = 8;

        let check = ForkCheck(&PAGE);
        let parent = check.generation().unwrap();
        assert_eq!(check.generation(), Some(parent));
        let mut last = parent;
        for _ in 0..CHILDREN {
            PAGE.store(0, atomic::Ordering::Release);
            let child = check.generation().unwrap();
            assert!(child > last);
            assert_eq!(check.generation(), Some(child));
            last = child;
        }
        PAGE.store(0, atomic::Ordering::Release);
        let agreed: Vec<Option<NonZeroUsize>> = std::thread::scope(|scope| {
            let asking: Vec<_> = (0..THREADS).map(|_| scope.spawn(|| check.generation())).collect();
            asking.into_iter().map(|thread| thread.join().unwrap()).collect()
        });
        assert!(agreed.iter().all(|generation| *generation == agreed[0]));
        assert!(agreed[0].unwrap() > last);
        assert_eq!(check.generation(), agreed[0]);

        // The object of a parent, in the parent and in its child.
        let (parent, child) = (Process::Known(parent), Process::Known(last));
        assert!(parent.is(parent));
        assert!(child.is(child));
        assert!(!parent.is(child));
        assert!(!child.is(parent));
        // Without a page there is no telling, and nothing is refused: not
        // an object of such a process, and not in such a process.
        assert!(Process::Untold.is(Process::Untold));
        assert!(Process::Untold.is(child));
        assert!(parent.is(Process::Untold));

        // The process that is running is itself, and where it has a page it
        // is no other.
        let running = Process::current();
        assert_eq!(Process::current(), running);
        assert!(running.is(running));
        running.check().unwrap();
        match Process::elsewhere() {
            Some(elsewhere) => {
                assert!(!elsewhere.is(running));
                assert_eq!(elsewhere.check().unwrap_err().errno, libc::ECHILD);
            }
            None => assert_eq!(running, Process::Untold),
        }
        if cfg!(miri) {
            assert_eq!(running, Process::Untold);
        }
    }

    /// The count of the generations stops at its end: the last generation
    /// is handed out once, and a page that is wiped after that gets none,
    /// however often it asks. A process without a generation is no process
    /// of any object, also of none it made itself.
    #[test]
    fn spent_generations() {
        static PAGE: AtomicUsize = AtomicUsize::new(0);
        static NEXT: AtomicUsize = AtomicUsize::new(usize::MAX - 1);
        let last = ForkCheck::generation_of(&PAGE, &NEXT);
        assert_eq!(last, NonZeroUsize::new(usize::MAX - 1));
        assert_eq!(ForkCheck::generation_of(&PAGE, &NEXT), last);
        for _ in 0..2 {
            PAGE.store(0, atomic::Ordering::Release);
            assert_eq!(ForkCheck::generation_of(&PAGE, &NEXT), None);
            assert_eq!(PAGE.load(atomic::Ordering::Acquire), 0);
            assert_eq!(NEXT.load(atomic::Ordering::Acquire), usize::MAX);
        }

        let spent = Process::Spent;
        let known = Process::Known(last.unwrap());
        assert!(!spent.is(spent));
        assert!(!spent.is(known));
        assert!(!known.is(spent));
        assert!(!spent.is(Process::Untold));
        assert!(!Process::Untold.is(spent));
        assert_eq!(spent.check().unwrap_err().errno, libc::ECHILD);
    }

    /// A place for an error takes one error: it is written to once, by a
    /// call that fails, and one that holds something keeps it, whatever it
    /// is. An object that a caller passes no place for is dropped.
    #[test]
    fn error_places() {
        assert!(ErrorPlace::NONE.is_clear());
        assert_eq!(ErrorPlace::NONE.returned(Ok(())), 0);
        assert_eq!(ErrorPlace::NONE.returned(Err(uapi16_error::ended())), -libc::ESTALE);
        let mut e: *mut uapi16_error = ptr::null_mut();
        // SAFETY: `e` is a local that nothing else uses while a place has
        // it.
        let place = unsafe { ErrorPlace::new(&mut e) };
        assert!(place.is_clear());
        assert_eq!(place.returned(Ok(())), 0);
        assert!(e.is_null());
        // SAFETY: as above.
        let place = unsafe { ErrorPlace::new(&mut e) };
        assert_eq!(place.returned(Err(uapi16_error::ended())), -libc::ESTALE);
        let held = e;
        assert!(!held.is_null());
        // SAFETY: as above.
        let place = unsafe { ErrorPlace::new(&mut e) };
        assert!(!place.is_clear());
        assert_eq!(place.returned(Err(uapi16_error::misuse())), -libc::EINVAL);
        assert_eq!(e, held);
        // SAFETY: `e` is the error returned() stored, which is freed once.
        unsafe {
            assert_eq!(uapi16_error_kind(e), uapi16_error_kind_t::UAPI16_ERROR_ENDED as u64);
            assert!(uapi16_error_field(e).is_null() && uapi16_error_problem(e).is_null());
            // It is about no record, and says so without storing one.
            let mut record = 77u64;
            assert_eq!(uapi16_error_record(e, &mut record), -libc::ENODATA);
            assert_eq!(record, 77);
            assert!(uapi16_error_free(e).is_null());
        }
        // What is no error at all is kept as well, and not read through.
        let mut no_error = ptr::dangling_mut::<uapi16_error>();
        // SAFETY: `no_error` is a local that nothing else uses while a
        // place has it.
        let place = unsafe { ErrorPlace::new(&mut no_error) };
        assert!(!place.is_clear());
        assert_eq!(place.returned(Err(uapi16_error::misuse())), -libc::EINVAL);
        assert_eq!(no_error, ptr::dangling_mut());

        // A caller that passes no place for an object does not want it, and
        // the object is dropped. Miri finds one that is not.
        // SAFETY: NULL is a `ret` that nothing is written to.
        let unwanted =
            unsafe { uapi16_file_object::returned(Ok(object(c"unwanted")), ptr::null_mut(), ErrorPlace::NONE) };
        assert_eq!(unwanted, 0);
    }

    /// The functions as C calls them, with pointers: an object is made,
    /// changed, read and freed, NULL is no object, and a getter stores
    /// nothing where it fails.
    #[test]
    fn through_pointers() {
        let mut o: *mut uapi16_file_object = ptr::null_mut();
        let mut e: *mut uapi16_error = ptr::null_mut();
        // SAFETY: the pointers are locals, the strings are literals, and
        // every object is used as the functions say: made once, freed once,
        // and not used after that.
        unsafe {
            assert_eq!(uapi16_file_object_new(c"a//b".as_ptr(), &mut o, &mut e), -libc::EINVAL);
            assert!(o.is_null());
            assert_eq!(
                uapi16_error_name_problem(e),
                uapi16_name_problem_t::UAPI16_NAME_PROBLEM_EMPTY_COMPONENT as u64
            );
            // A place that holds an error takes no other.
            assert_eq!(uapi16_file_object_new(c"a".as_ptr(), &mut o, &mut e), -libc::EINVAL);
            assert!(o.is_null());
            e = uapi16_error_free(e);
            assert_eq!(
                uapi16_file_object_new(c"a".as_ptr(), ptr::null_mut(), &mut e),
                -libc::EINVAL
            );
            e = uapi16_error_free(e);
            assert_eq!(
                uapi16_file_object_new(ptr::null(), &mut o, ptr::null_mut()),
                -libc::EINVAL
            );
            assert_eq!(uapi16_file_object_new(c"a".as_ptr(), &mut o, &mut e), 0);
            assert!(!o.is_null() && e.is_null());

            let mut number = 77u32;
            assert_eq!(uapi16_file_object_uid(o, &mut number), -libc::ENODATA);
            assert_eq!(number, 77);
            assert_eq!(uapi16_file_object_set_uid(o, 1000), 0);
            assert_eq!(uapi16_file_object_uid(o, &mut number), 0);
            assert_eq!(number, 1000);
            assert_eq!(uapi16_file_object_uid(o, ptr::null_mut()), -libc::EINVAL);
            assert_eq!(uapi16_file_object_uid(ptr::null(), &mut number), -libc::EINVAL);
            assert_eq!(uapi16_file_object_set_uid(ptr::null_mut(), 1), -libc::EINVAL);

            let hash = uapi16_sha256_digest_t {
                bytes: [7; UAPI16_SHA256_SIZE],
            };
            let mut read = uapi16_sha256_digest_t {
                bytes: [0; UAPI16_SHA256_SIZE],
            };
            assert_eq!(uapi16_file_object_sha256(o, &mut read), -libc::ENODATA);
            assert_eq!(uapi16_file_object_set_sha256(o, ptr::null()), -libc::EINVAL);
            assert_eq!(uapi16_file_object_set_sha256(o, &hash), 0);
            assert_eq!(uapi16_file_object_sha256(o, &mut read), 0);
            assert_eq!(read.bytes, hash.bytes);

            assert_eq!(uapi16_file_object_read_only(o), 0);
            assert_eq!(uapi16_file_object_set_read_only(o, 5), -libc::EINVAL);
            assert_eq!(uapi16_file_object_set_read_only(o, 2), 0);
            assert_eq!(uapi16_file_object_read_only(o), 2);
            assert_eq!(uapi16_file_object_set_read_only(o, 0), 0);
            assert_eq!(uapi16_file_object_read_only(o), 0);
            assert_eq!(uapi16_file_object_read_only(ptr::null()), 0);
            let mut token = 77u64;
            assert_eq!(uapi16_file_object_inode_token(o, &mut token), -libc::ENODATA);
            assert_eq!(token, 77);
            assert_eq!(uapi16_file_object_set_inode_token(o, 9), 0);
            assert_eq!(uapi16_file_object_inode_token(o, &mut token), 0);
            assert_eq!(token, 9);
            assert_eq!(uapi16_file_object_set_inode_token(o, UAPI16_INODE_TOKEN_NONE), 0);
            assert_eq!(uapi16_file_object_inode_token(o, &mut token), -libc::ENODATA);

            assert_eq!(uapi16_file_object_add_user_xattr(o, c"k".as_ptr(), ptr::null(), 0), 0);
            assert_eq!(
                uapi16_file_object_add_user_xattr(o, c"k".as_ptr(), ptr::null(), 1),
                -libc::EINVAL
            );
            let (mut name, mut value, mut size) = (ptr::null(), ptr::null(), 9usize);
            assert_eq!(uapi16_file_object_user_xattr(o, 0, &mut name, &mut value, &mut size), 0);
            assert_eq!((CStr::from_ptr(name), size), (c"k", 0));
            assert_eq!(
                uapi16_file_object_user_xattr(o, 0, ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                0
            );
            assert_eq!(
                uapi16_file_object_user_xattr(o, 1, &mut name, &mut value, &mut size),
                -libc::EINVAL
            );

            let mut literal_size = 9usize;
            assert!(uapi16_file_object_literal(o, &mut literal_size).is_null());
            assert_eq!(literal_size, 0);
            assert_eq!(uapi16_file_object_set_target(o, c"to".as_ptr().cast(), 2), 0);
            let literal = uapi16_file_object_literal(o, &mut literal_size);
            assert_eq!(slice::from_raw_parts(literal.cast::<u8>(), literal_size), b"to");
            assert!(!uapi16_file_object_literal(o, ptr::null_mut()).is_null());
            assert_eq!(uapi16_file_object_type(o), libc::S_IFREG);
            assert_eq!(uapi16_file_object_type(ptr::null()), 0);
            assert_eq!(uapi16_file_object_inode_token(ptr::null(), &mut token), -libc::EINVAL);
            assert!(uapi16_file_object_name(ptr::null()).is_null());
            assert!(!uapi16_file_object_has_stated_feature(ptr::null(), 1));
            assert_eq!(uapi16_file_object_stated_feature(ptr::null(), 0), 0);
            assert_eq!(uapi16_file_object_data_location(ptr::null()), 0);

            assert!(uapi16_file_object_free(o).is_null());

            // A check outlives the object it was made of.
            let mut check: *mut uapi16_data_check = ptr::null_mut();
            assert_eq!(uapi16_file_object_new(c"data".as_ptr(), &mut o, &mut e), 0);
            assert_eq!(uapi16_file_object_set_size(o, 2), 0);
            assert_eq!(uapi16_data_check_new(o, &mut check), 0);
            assert_eq!(uapi16_data_check_new(o, ptr::null_mut()), -libc::EINVAL);
            assert_eq!(uapi16_data_check_new(ptr::null(), &mut check), -libc::EINVAL);
            assert!(uapi16_file_object_free(o).is_null());
            let mut total = 0u64;
            assert_eq!(uapi16_data_check_update(check, c"to".as_ptr().cast(), 2, &mut e), 0);
            assert_eq!(uapi16_data_check_finish(check, &mut total, &mut e), 0);
            assert_eq!(total, 2);
            assert_eq!(uapi16_data_check_finish(check, ptr::null_mut(), &mut e), -libc::ESTALE);
            assert_eq!(uapi16_error_kind(e), uapi16_error_kind_t::UAPI16_ERROR_ENDED as u64);
            e = uapi16_error_free(e);
            assert!(uapi16_data_check_free(check).is_null() && e.is_null());

            let sha256 = uapi16_sha256_new();
            assert_eq!(uapi16_sha256_update(sha256, c"hello".as_ptr().cast(), 5), 0);
            assert_eq!(uapi16_sha256_finish(sha256, ptr::null_mut()), -libc::EINVAL);
            assert_eq!(uapi16_sha256_finish(sha256, &mut read), 0);
            assert_eq!(read.bytes, *Sha256::digest(b"hello").as_bytes());
            assert_eq!(uapi16_sha256_finish(sha256, &mut read), -libc::ESTALE);
            assert!(uapi16_sha256_free(sha256).is_null());

            let mut signature: *mut uapi16_signature = ptr::null_mut();
            assert_eq!(uapi16_signature_new(ptr::null(), &mut signature), -libc::EINVAL);
            assert_eq!(
                uapi16_signature_new(c"openpgp".as_ptr(), ptr::null_mut()),
                -libc::EINVAL
            );
            assert_eq!(uapi16_signature_new(c"openpgp".as_ptr(), &mut signature), 0);
            assert_eq!(CStr::from_ptr(uapi16_signature_mechanism(signature)), c"openpgp");
            let mut key_size = 9usize;
            assert!(uapi16_signature_key(signature, &mut key_size).is_null());
            assert_eq!(key_size, 0);
            assert_eq!(uapi16_signature_set_key(signature, c"id".as_ptr().cast(), 2), 0);
            let key = uapi16_signature_key(signature, &mut key_size);
            assert_eq!(slice::from_raw_parts(key.cast::<u8>(), key_size), b"id");
            assert_eq!(uapi16_signature_set_key(signature, ptr::null(), 2), 0);
            assert!(uapi16_signature_key(signature, ptr::null_mut()).is_null());
            assert_eq!(uapi16_signature_set_data(signature, c"".as_ptr().cast(), 0), 0);
            assert!(!uapi16_signature_data(signature, &mut key_size).is_null());
            assert_eq!(key_size, 0);
            assert!(uapi16_signature_free(signature).is_null());

            assert_eq!(uapi16_name_compare(c"a/x".as_ptr(), c"a-b".as_ptr()), -1);
            assert_eq!(uapi16_name_compare(c"a-b".as_ptr(), c"a/x".as_ptr()), 1);
            assert_eq!(uapi16_name_compare(ptr::null(), c"".as_ptr()), 0);
            assert_eq!(uapi16_name_compare(ptr::null(), c"a".as_ptr()), -1);
            // What is not UTF-8 is replaced before two strings are compared,
            // so two different ones can be the same.
            assert_eq!(uapi16_name_compare(c"a\xffb".as_ptr(), c"a\xfeb".as_ptr()), 0);
            assert_eq!(uapi16_name_compare(c"\xff".as_ptr(), c"\u{fffd}".as_ptr()), 0);
            assert_eq!(uapi16_name_compare(c"\xff".as_ptr(), c"a".as_ptr()), 1);
            let user_xattr = uapi16_feature_t::UAPI16_FEATURE_USER_XATTR as FeatureNumber;
            let no_feature = uapi16_feature_t::ALL.len() as FeatureNumber + 1;
            assert_eq!(uapi16_feature_from_name(c"user-xattr".as_ptr()), user_xattr);
            assert_eq!(uapi16_feature_from_name(c"none".as_ptr()), 0);
            assert_eq!(uapi16_feature_from_name(ptr::null()), 0);
            assert_eq!(CStr::from_ptr(uapi16_feature_name(user_xattr)), c"user-xattr");
            assert!(uapi16_feature_name(0).is_null());
            assert!(uapi16_feature_name(no_feature).is_null());
        }
    }

    /// The objects go from thread to thread: a caller uses one from one
    /// thread at a time, and reads reports, errors and file objects that
    /// nothing changes from any.
    #[test]
    fn send_and_sync() {
        fn send<T: Send>() {}
        fn sync<T: Sync>() {}
        send::<uapi16_manifest_options>();
        send::<uapi16_manifest_writer>();
        send::<uapi16_manifest_report>();
        sync::<uapi16_manifest_report>();
        send::<uapi16_error>();
        sync::<uapi16_error>();
        send::<uapi16_file_object>();
        sync::<uapi16_file_object>();
        send::<uapi16_reader>();
        send::<uapi16_writer>();
        send::<uapi16_signature>();
        send::<uapi16_sha256>();
        send::<uapi16_directory>();
        sync::<uapi16_directory>();
        send::<uapi16_data_check>();
    }
}
