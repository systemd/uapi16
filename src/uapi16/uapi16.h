/* SPDX-License-Identifier: LGPL-2.1-or-later */

#ifndef UAPI16_H
#define UAPI16_H

/*
 * cbindgen wrote this file from capi.rs and cbindgen.toml. Change those and
 * write it again:
 *
 *     cbindgen --quiet --config cbindgen.toml --output uapi16.h capi.rs
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * The C API of uapi16: building UAPI.16 file manifests of trees of files,
 * and reading and writing them record by record.
 * https://uapi-group.org/specifications/specs/file_manifest/
 *
 * What holds for every function:
 *
 * - A function that can fail returns 0, or a negative errno if it fails.
 *   uapi16_reader_next() and uapi16_reader_next_signature() are the one
 *   exception: each returns a uapi16_read_t that says what it read, or a
 *   negative errno. uapi16_error_errno() can't fail and returns an errno
 *   as a positive number.
 *
 * - `reterr` is NULL or points to NULL. Unless it is NULL, a call that
 *   fails stores a new error there, which the caller frees with
 *   uapi16_error_free(). A call that succeeds does not write to it. A
 *   call whose `reterr` points to anything but NULL fails with -EINVAL
 *   before it does anything, and leaves what is there as it is.
 *
 * - Every call that makes an object stores it in `ret` if it succeeds,
 *   and does not write to `ret` if it fails. uapi16_reader_next() and
 *   uapi16_reader_next_signature() are the one exception: `*ret` is NULL
 *   or an object of the caller, which is cleared and filled again, and
 *   which stays the caller's whatever the call returns. A caller that
 *   does not want a report passes NULL for its `ret`. Every other object
 *   needs its `ret`.
 *
 * - Descriptors are borrowed. An object that keeps a descriptor borrows
 *   the caller's until its free function returns, and never closes it: a
 *   reader, a writer, a writer of records and a directory. The caller
 *   keeps the descriptor open until then. A function that makes no object
 *   borrows a descriptor for the call. A call that fails to make its
 *   object leaves the descriptor with the caller. Where the name of
 *   uapi16_manifest_writer_create_at() has several components, the
 *   library opens the directory of the file itself. A negative number is
 *   no descriptor, AT_FDCWD included, and fails with -EBADF.
 *
 * - Strings that go in are NUL-terminated UTF-8 and are read during the
 *   call. The name of a new manifest file is the exception: `name` of
 *   uapi16_manifest_writer_create_at() and uapi16_manifest_generate_at()
 *   is a path, which is taken as the bytes it is. Strings and bytes that
 *   come out belong to the object they come from. They live until it is
 *   freed, or until a call sets their field again, takes it away or fills
 *   the object again.
 *
 * - Every enum is 64 bits wide. Its numbers never change and new ones are
 *   only added, so a switch over one needs a default case. A set of flags
 *   has a type of its own: uapi16_add_flags_t and
 *   uapi16_directory_flags_t. uapi16_name_order_t is the one signed enum:
 *   it is 64 bits wide like the others, and its numbers are -1, 0 and 1.
 *
 * - An object is used by one thread at a time, and the library takes no
 *   locks. Reports and errors can be read from any thread. No thread of
 *   the library runs once a call returned, so a caller can fork() between
 *   calls.
 *
 * - After fork(), the child can't use the objects of its parent: a
 *   function that can fail fails with -ECHILD there.
 *
 * - The library installs no signal handlers and changes no signal masks.
 *   A system call that a signal interrupts is made again. SIGPIPE behaves
 *   as with write(2).
 *
 * - A call that is not valid fails with -EINVAL: one with an object or a
 *   string that is NULL, with no `ret` for an object other than a report,
 *   with a `reterr` that points to anything but NULL, or with a flag, a
 *   feature or an order that is unknown. If memory runs out or the library
 *   panics, the process aborts.
 *
 * - A call is checked in this order: what it is given first, which fails
 *   with -EINVAL or -EBADF, then the process it is made in, which fails
 *   with -ECHILD, and then its options or its writer. Options with a
 *   feature of partitions fail with -EINVAL in the calls that make a
 *   manifest writer, the generate functions among them, and a writer fails
 *   with -ESTALE once it takes nothing more. So a call that is not valid
 *   fails for that in a child and on such a writer as well, and a child
 *   gets -ECHILD for options with a feature of partitions.
 *
 * - Options whose order is UAPI16_ORDER_NONE are for a writer of records.
 *   The functions that sort refuse them with -EINVAL, where options with
 *   a feature of partitions fail too: uapi16_manifest_writer_create_at(),
 *   uapi16_manifest_writer_open(), uapi16_manifest_generate_at() and
 *   uapi16_manifest_generate().
 *
 * - Bytes go in as a pointer and a size, and are copied during the call.
 *   The pointer is not read where the size is 0. Bytes that are there and
 *   empty come out as a pointer that is not NULL, with the size 0.
 *
 * - A list of features goes in as a pointer to an array and its length,
 *   and is read during the call. The pointer is not read where the length
 *   is 0. A feature can be in a list more than once, and
 *   UAPI16_FEATURE_NONE in a list is passed over.
 *
 * - A getter of a field that an object does not have fails with -ENODATA
 *   and stores nothing, or returns NULL for a string.
 *
 * - A file object that no thread changes can be read from any thread, and
 *   several threads can open files from one uapi16_directory at the same
 *   time.
 *
 * - A reader that failed to read an object or a writer that failed to
 *   write a record, and a writer of records, a computation and a check
 *   that are finished, take nothing more: a later call fails with -ESTALE.
 */

#define UAPI16_UUID_SIZE 16

#define UAPI16_UUID_QWORDS 2

#define UAPI16_SHA256_SIZE 32

#define UAPI16_SHA256_QWORDS 4

/**
 * A feature of a manifest: what its file objects record. The features
 * are those of the specification, which spells them in lower case with
 * dashes: UAPI16_FEATURE_USER_XATTR is user-xattr. A feature is a number,
 * and a list of features is an array of them. Later versions add features
 * after the last one.
 *
 * The features of partitions, UAPI16_FEATURE_GPT_LABEL to
 * UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM, don't apply to a tree of
 * files. No manifest writer is made for options that have one of them, and
 * the generate functions refuse them. The writer of records takes them.
 */
enum uapi16_feature_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * No feature. uapi16_feature_from_name() returns it for a name that no
         * feature has.
         */
        UAPI16_FEATURE_NONE = 0,
        /**
         * The access mode.
         */
        UAPI16_FEATURE_MODE = 1,
        /**
         * The user ID of the owner.
         */
        UAPI16_FEATURE_UID = 2,
        /**
         * The group ID of the owner.
         */
        UAPI16_FEATURE_GID = 3,
        /**
         * The name of the owning user, as the user database of the host has
         * it.
         */
        UAPI16_FEATURE_USER_NAME = 4,
        /**
         * The name of the owning group, as the user database of the host has
         * it.
         */
        UAPI16_FEATURE_GROUP_NAME = 5,
        /**
         * The size of the data of a regular file.
         */
        UAPI16_FEATURE_SIZE = 6,
        /**
         * The SHA-256 hash of the data of a regular file.
         */
        UAPI16_FEATURE_SHA256 = 7,
        /**
         * The targets of symbolic links.
         */
        UAPI16_FEATURE_SYMLINK = 8,
        /**
         * The major and minor numbers of device nodes.
         */
        UAPI16_FEATURE_DEVICE = 9,
        /**
         * Which file objects are names of one file.
         */
        UAPI16_FEATURE_HARDLINK = 10,
        /**
         * The modification time.
         */
        UAPI16_FEATURE_MTIME = 11,
        /**
         * The extended attributes of the user namespace.
         *
         * The generate functions open no file for its extended attributes.
         * Those of a file that is open anyway are read from the open file: a
         * directory that is walked into, a regular file whose data is hashed,
         * and a regular file or a directory that is opened for its inode
         * flags, its DOS attributes or the identity of its file system. Those
         * of any other file are read through /proc. Without a /proc they can't
         * be read, and it has to be the one of the kernel: whoever can mount
         * something else there can have such a file recorded with the
         * attributes of another one.
         */
        UAPI16_FEATURE_USER_XATTR = 12,
        /**
         * The DOS attribute hidden.
         */
        UAPI16_FEATURE_FLAG_HIDDEN = 13,
        /**
         * The DOS attribute system.
         */
        UAPI16_FEATURE_FLAG_SYSTEM = 14,
        /**
         * The DOS attribute archive.
         */
        UAPI16_FEATURE_FLAG_ARCHIVE = 15,
        /**
         * The inode flag append only.
         */
        UAPI16_FEATURE_FLAG_APPEND_ONLY = 16,
        /**
         * The inode flag immutable.
         */
        UAPI16_FEATURE_FLAG_IMMUTABLE = 17,
        /**
         * The inode flag no atime updates.
         */
        UAPI16_FEATURE_FLAG_NO_ATIME = 18,
        /**
         * The inode flag no copy on write.
         */
        UAPI16_FEATURE_FLAG_NO_COW = 19,
        /**
         * The inode flag no dump.
         */
        UAPI16_FEATURE_FLAG_NO_DUMP = 20,
        /**
         * Whether a file is read-only.
         */
        UAPI16_FEATURE_READ_ONLY = 21,
        /**
         * The UUID of the file system of the root.
         *
         * UAPI16_FEATURE_FS_UUID and UAPI16_FEATURE_FAT_SERIAL are read from the
         * root. A root whose file system has no UUID is written without one,
         * and so is one whose volume serial number can't be read, which only
         * FAT gives. Before Linux 6.9 no UUID can be read. Each is counted in
         * uapi16_manifest_report_fields_omitted() as well. A manifest without a
         * root has neither.
         */
        UAPI16_FEATURE_FS_UUID = 22,
        /**
         * The label of the file system of the root.
         */
        UAPI16_FEATURE_FS_LABEL = 23,
        /**
         * The volume serial number of the FAT file system of the root.
         */
        UAPI16_FEATURE_FAT_SERIAL = 24,
        /**
         * The label of a partition.
         */
        UAPI16_FEATURE_GPT_LABEL = 25,
        /**
         * The UUID of a partition.
         */
        UAPI16_FEATURE_GPT_UUID = 26,
        /**
         * The type UUID of a partition.
         */
        UAPI16_FEATURE_GPT_TYPE_UUID = 27,
        /**
         * The disk UUID of a partition table.
         */
        UAPI16_FEATURE_GPT_DISK_UUID = 28,
        /**
         * The attribute flags of a partition.
         */
        UAPI16_FEATURE_GPT_FLAGS = 29,
        /**
         * The partition attribute flag no auto.
         */
        UAPI16_FEATURE_GPT_FLAG_NO_AUTO = 30,
        /**
         * The partition attribute flag grow file system.
         */
        UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM = 31,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_feature_t uapi16_feature_t;
#else
typedef uint64_t uapi16_feature_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * The order a manifest lists its file objects in.
 */
enum uapi16_order_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * No order. With options that have it, uapi16_writer_begin() writes a
         * manifest that declares none, and uapi16_reader_order() returns it
         * for such a manifest. The functions that sort refuse options that
         * have it.
         */
        UAPI16_ORDER_NONE = 0,
        /**
         * The order of the code points of the names, component by component:
         * codepoint in the specification.
         */
        UAPI16_ORDER_CODEPOINT = 1,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_order_t uapi16_order_t;
#else
typedef uint64_t uapi16_order_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * A flag of the generate functions. A set of them is a
 * uapi16_add_flags_t.
 */
enum uapi16_add_flag_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * No flag.
         */
        UAPI16_ADD_NONE = 0,
        /**
         * Walk into mount points instead of writing them as empty
         * directories.
         */
        UAPI16_ADD_CROSS_MOUNTS = (1 << 0),
        /**
         * Leave out files whose names a manifest can't hold, a directory with
         * everything below it, and count them in
         * uapi16_manifest_report_entries_omitted(), instead of failing.
         */
        UAPI16_ADD_GRACEFUL = (1 << 1),
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_add_flag_t uapi16_add_flag_t;
#else
typedef uint64_t uapi16_add_flag_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * What kind of error a uapi16_error is, with the errno of each kind.
 */
enum uapi16_error_kind_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * Reading or writing failed. The errno is that of the system call
         * that failed, or EIO where none did.
         */
        UAPI16_ERROR_IO = 1,
        /**
         * The name of the file to create is taken. EEXIST.
         */
        UAPI16_ERROR_EXISTS = 2,
        /**
         * The same name was added for two different files that are not both
         * directories. EEXIST.
         */
        UAPI16_ERROR_DUPLICATE = 3,
        /**
         * A file changed while it was read. ESTALE.
         */
        UAPI16_ERROR_CHANGED = 4,
        /**
         * Two names of one inode don't show the same file. ESTALE.
         */
        UAPI16_ERROR_HARDLINK_MISMATCH = 5,
        /**
         * A file has a name that a manifest can't hold. EILSEQ for a name that
         * is not UTF-8, ENAMETOOLONG for one that is too long, and EINVAL for
         * any other.
         */
        UAPI16_ERROR_UNWRITABLE_NAME = 6,
        /**
         * A file that is not a directory is where a directory is needed.
         * ENOTDIR.
         */
        UAPI16_ERROR_NOT_DIRECTORY = 7,
        /**
         * A feature that was asked for can't be read here, or the data of a
         * file object is not data the library takes. EOPNOTSUPP.
         */
        UAPI16_ERROR_UNSUPPORTED = 8,
        /**
         * The call is not a valid one. EINVAL for a NULL object or string, no
         * `ret` for an object other than a report, an unknown flag, feature or
         * order and a name that is none. EBADF for a negative descriptor.
         * ECHILD in a child of fork(). EINVAL for options with a feature of
         * partitions, which a call that makes a manifest writer checks after
         * the process, and for options whose order is UAPI16_ORDER_NONE in a
         * function that sorts, which checks them there too.
         */
        UAPI16_ERROR_INVALID_ARGUMENT = 9,
        /**
         * A directory is one of the directories it is in, because a mount
         * shows it again. ELOOP.
         */
        UAPI16_ERROR_LOOP = 10,
        /**
         * A directory that files were added below was not added itself, and
         * the features need what it would record. ENOENT.
         */
        UAPI16_ERROR_MISSING_PARENT = 11,
        /**
         * What a manifest records of a file is more than one of its records
         * has room for, such as more than 4 MiB of extended attributes. E2BIG.
         */
        UAPI16_ERROR_TOO_LARGE = 12,
        /**
         * The object takes nothing more: a writer, a computation or a check
         * that is finished, a writer that failed to write a record, or a
         * reader that failed to read an object. ESTALE. A call is checked for
         * what it is given first and for its process next, so one that is
         * UAPI16_ERROR_INVALID_ARGUMENT is that on such an object as well.
         */
        UAPI16_ERROR_ENDED = 13,
        /**
         * A manifest is malformed, or a file object is not one a manifest can
         * hold. uapi16_error_problem() names the rule that is broken,
         * uapi16_error_field() the field and uapi16_error_record() the record.
         * EBADMSG.
         */
        UAPI16_ERROR_MANIFEST = 14,
        /**
         * The file a manifest has the data of a file object in is not there.
         * ENOENT.
         */
        UAPI16_ERROR_SOURCE_MISSING = 15,
        /**
         * The file a manifest has the data of a file object in is not a regular
         * file. EINVAL.
         */
        UAPI16_ERROR_SOURCE_NOT_REGULAR = 16,
        /**
         * The data of a file is not as many bytes as the manifest says, or its
         * file is too short for it. EBADMSG.
         */
        UAPI16_ERROR_SIZE_MISMATCH = 17,
        /**
         * The data of a file does not have the hash the manifest says. EBADMSG.
         */
        UAPI16_ERROR_HASH_MISMATCH = 18,
        /**
         * A file object or a manifest is revoked. EKEYREVOKED.
         */
        UAPI16_ERROR_REVOKED = 19,
        /**
         * The time is before the one a file object or a manifest may be used
         * from. EKEYEXPIRED.
         */
        UAPI16_ERROR_NOT_YET_VALID = 20,
        /**
         * The time is not before the one a file object or a manifest may be
         * used until. EKEYEXPIRED.
         */
        UAPI16_ERROR_EXPIRED = 21,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_error_kind_t uapi16_error_kind_t;
#else
typedef uint64_t uapi16_error_kind_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Which rule of the names of a manifest a name breaks.
 */
enum uapi16_name_problem_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * It is not UTF-8.
         */
        UAPI16_NAME_PROBLEM_NOT_UTF8 = 1,
        /**
         * It is empty.
         */
        UAPI16_NAME_PROBLEM_EMPTY = 2,
        /**
         * It is longer than 4095 bytes.
         */
        UAPI16_NAME_PROBLEM_TOO_LONG = 3,
        /**
         * Its first component is Uapi16Manifest or begins with
         * Uapi16Manifest., which the specification reserves.
         */
        UAPI16_NAME_PROBLEM_RESERVED = 4,
        /**
         * It has a control character: ASCII 0 to 31 or 127.
         */
        UAPI16_NAME_PROBLEM_CONTROL_CHARACTER = 5,
        /**
         * It has a Unicode noncharacter.
         */
        UAPI16_NAME_PROBLEM_NONCHARACTER = 6,
        /**
         * One of its components is empty: it begins or ends with a slash, or
         * has two slashes in a row.
         */
        UAPI16_NAME_PROBLEM_EMPTY_COMPONENT = 7,
        /**
         * One of its components is "." or "..".
         */
        UAPI16_NAME_PROBLEM_DOT_COMPONENT = 8,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_name_problem_t uapi16_name_problem_t;
#else
typedef uint64_t uapi16_name_problem_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Whether a file object says that its file is read-only.
 */
enum uapi16_read_only_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * The object does not say.
         */
        UAPI16_READ_ONLY_UNSTATED = 0,
        /**
         * The file is not read-only.
         */
        UAPI16_READ_ONLY_NO = 1,
        /**
         * The file is read-only.
         */
        UAPI16_READ_ONLY_YES = 2,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_read_only_t uapi16_read_only_t;
#else
typedef uint64_t uapi16_read_only_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Where one name comes to another in the code point order, as
 * uapi16_name_compare() returns it. This is the one signed enum: its
 * numbers are those a comparison function of qsort() returns.
 */
enum uapi16_name_order_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : int64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * The first name comes before the second.
         */
        UAPI16_NAME_BEFORE = -1,
        /**
         * The two names are the same.
         */
        UAPI16_NAME_SAME = 0,
        /**
         * The first name comes after the second.
         */
        UAPI16_NAME_AFTER = 1,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_name_order_t uapi16_name_order_t;
#else
typedef int64_t uapi16_name_order_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * What uapi16_reader_next() and uapi16_reader_next_signature() read. Each
 * returns one of these as an int, or a negative errno.
 */
enum uapi16_read_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * The trailer was read and checked. The manifest is complete.
         */
        UAPI16_READ_END = 0,
        /**
         * One file object was read, and is in `ret`.
         */
        UAPI16_READ_FILE = 1,
        /**
         * The file objects have ended, and signature objects follow. From now
         * on uapi16_reader_signed_len() has what they sign.
         */
        UAPI16_READ_SIGNATURES = 2,
        /**
         * One signature object was read, and is in `ret`. Only
         * uapi16_reader_next_signature() returns this.
         */
        UAPI16_READ_SIGNATURE = 3,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_read_t uapi16_read_t;
#else
typedef uint64_t uapi16_read_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Where the data of a file object is, as uapi16_file_object_data_location()
 * finds it.
 */
enum uapi16_data_location_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * Nowhere: the object has no data.
         */
        UAPI16_DATA_LOCATION_NONE = 0,
        /**
         * In the manifest itself. uapi16_file_object_literal() gives it.
         */
        UAPI16_DATA_LOCATION_LITERAL = 1,
        /**
         * In a file next to the manifest. uapi16_directory_open_data() opens
         * it.
         */
        UAPI16_DATA_LOCATION_EXTERNAL = 2,
        /**
         * At a URL or in an encoding. The library neither fetches nor decodes
         * data.
         */
        UAPI16_DATA_LOCATION_UNSUPPORTED = 3,
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_data_location_t uapi16_data_location_t;
#else
typedef uint64_t uapi16_data_location_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * A flag of uapi16_directory_new(). A set of them is a
 * uapi16_directory_flags_t.
 */
enum uapi16_directory_flag_t
#if defined(__cplusplus) || __STDC_VERSION__ >= 202311L
  : uint64_t
#endif // defined(__cplusplus) || __STDC_VERSION__ >= 202311L
 {
        /**
         * No flag.
         */
        UAPI16_DIRECTORY_NONE = 0,
        /**
         * Follow symbolic links below the directory, resolved as if the
         * directory were the root: a link that points out of the directory
         * leads to what has that path inside it instead. Without this flag a
         * name that leads through a symbolic link fails with ELOOP.
         */
        UAPI16_DIRECTORY_FOLLOW_SYMLINKS = (1 << 0),
};
#ifndef __cplusplus
#if __STDC_VERSION__ >= 202311L
typedef enum uapi16_directory_flag_t uapi16_directory_flag_t;
#else
typedef uint64_t uapi16_directory_flag_t;
#endif // __STDC_VERSION__ >= 202311L
#endif // __cplusplus

/**
 * Holds the data of a file object against the size and the hash the
 * object gives, as the data passes. Made by uapi16_data_check_new(), and
 * freed by uapi16_data_check_free().
 */
typedef struct uapi16_data_check uapi16_data_check;

/**
 * The directory the files of a manifest are taken from: the one the
 * manifest is in, or one the caller chose instead. Made by
 * uapi16_directory_new(), and freed by uapi16_directory_free().
 *
 * The directory is never looked up again, and nothing resolves to
 * anything outside it. Several threads can open files from one directory
 * at the same time.
 */
typedef struct uapi16_directory uapi16_directory;

/**
 * Why a call failed. A call that fails stores one where its `reterr`
 * points to, unless `reterr` is NULL, and uapi16_error_free() frees it.
 * `reterr` has to point to NULL: a call that finds anything else there,
 * such as an error that was not freed, fails with -EINVAL before it does
 * anything, and leaves what is there as it is.
 */
typedef struct uapi16_error uapi16_error;

/**
 * A file object: what a manifest says about one file, or about the root
 * directory of the tree it describes. Made by uapi16_file_object_new() and
 * by uapi16_reader_next(), handed out by uapi16_reader_root(), and freed by
 * uapi16_file_object_free().
 *
 * The root is the object with the empty name. It is a directory. Besides
 * its attributes it has the label, the UUID and the FAT serial number of
 * the file system. It has no size, no hash, no target, no device numbers,
 * no token and no DOS attributes.
 *
 * A setter stores what it is given and checks the call alone. A writer
 * checks the object when it gets it. A getter of a number that the object
 * does not have fails with -ENODATA and stores nothing, and a getter of a
 * string returns NULL for it. What a reader filled in reads like any other
 * value: a size and a hash that follow from other fields, and a flag that
 * is cleared, a file that is not read-only and extended attributes there
 * are none of, where the features of the manifest say so. A writer leaves
 * these out again.
 *
 * The object keeps a copy of every string and of all bytes it is given.
 */
typedef struct uapi16_file_object uapi16_file_object;

/**
 * How to write a manifest: the features it records, the order of its
 * file objects and whether a new file is synced. Made by
 * uapi16_manifest_options_new(), which gives the default features and
 * the code point order and does not sync, and freed by
 * uapi16_manifest_options_free().
 */
typedef struct uapi16_manifest_options uapi16_manifest_options;

/**
 * What a manifest lists, counted per file object: a file with three names
 * counts three times. Made by uapi16_manifest_writer_finish() and the
 * generate functions, and freed by uapi16_manifest_report_free().
 */
typedef struct uapi16_manifest_report uapi16_manifest_report;

/**
 * Takes the files a manifest lists, and writes the manifest once it has
 * them all. Made by uapi16_manifest_writer_create_at() and
 * uapi16_manifest_writer_open(), and freed by
 * uapi16_manifest_writer_free().
 *
 * The manifest lists its file objects in the order of the options,
 * whatever order the adds came in. Two equal file objects under one name
 * are listed once. A directory added twice is listed with what the first
 * add said of it. Two other files under one name, also a directory and a
 * file that is none, are UAPI16_ERROR_DUPLICATE, from
 * uapi16_manifest_writer_finish().
 *
 * An add that fails leaves the writer as it was, as if the add had not
 * been.
 */
typedef struct uapi16_manifest_writer uapi16_manifest_writer;

/**
 * Reads a manifest record by record, and checks it. Made by
 * uapi16_reader_open(), and freed by uapi16_reader_free().
 *
 * The reader checks every object against the rules of the specification,
 * and where it comes: right after the object of its directory, and in the
 * order the manifest declares. It keeps one record in memory, whatever the
 * size of the manifest, and reads its descriptor once, so a manifest can
 * come through a pipe.
 *
 * uapi16_reader_next() reads the file objects, and says what it read with
 * a uapi16_read_t. It returns UAPI16_READ_END once it has read and checked
 * the trailer: then the manifest is complete. Where signature objects
 * follow the file objects, it returns UAPI16_READ_SIGNATURES first. A
 * caller that wants them reads them with uapi16_reader_next_signature()
 * then. A caller that does not goes on with uapi16_reader_next(), which
 * passes over them. The signature objects are checked and not verified.
 *
 * Once one of the two failed to read an object, every later call of them
 * fails with UAPI16_ERROR_ENDED. EAGAIN of a descriptor that does not
 * block is the exception: the reader lost nothing, and reads on with the
 * next call.
 */
typedef struct uapi16_reader uapi16_reader;

/**
 * Computes the SHA-256 hash of data that comes in pieces, such as the data
 * of a file while it is copied into an image. Made by uapi16_sha256_new(),
 * and freed by uapi16_sha256_free().
 */
typedef struct uapi16_sha256 uapi16_sha256;

/**
 * A signature object: a signature over the manifest up to the first
 * signature object. Made by uapi16_signature_new() and by
 * uapi16_reader_next_signature(), and freed by uapi16_signature_free().
 *
 * A manifest can carry several. The library reads and writes them, and
 * neither makes nor verifies a signature: that takes an OpenPGP or an X.509
 * implementation.
 */
typedef struct uapi16_signature uapi16_signature;

/**
 * Writes a manifest record by record, for a caller that has its file
 * objects in the order of the manifest already: every directory before
 * what is in it, and the names of a directory in the order of their bytes.
 * Made by uapi16_writer_begin(), and freed by uapi16_writer_free().
 *
 * With options whose order is UAPI16_ORDER_NONE the manifest declares no
 * order, and the file objects are written in the order of the caller. Each
 * still comes right after the object of its directory.
 *
 * Every call writes its record before it returns, and nothing is kept on
 * disk. A manifest without its trailer is one a reader takes as
 * incomplete, so a writer that is freed before it finished leaves nothing
 * that passes for a manifest. A write that fails ends the writer.
 */
typedef struct uapi16_writer uapi16_writer;

/**
 * A set of uapi16_add_flag_t: their bitwise OR.
 */
typedef uint64_t uapi16_add_flags_t;

/**
 * A SHA-256 hash.
 */
typedef union {
        uint8_t bytes[UAPI16_SHA256_SIZE];
        uint64_t qwords[UAPI16_SHA256_QWORDS];
} uapi16_sha256_digest_t;

/**
 * The token of a file, see uapi16_file_object_set_inode_token().
 */
typedef uint64_t uapi16_inode_token_t;

/**
 * A UUID, as the fs-uuid field carries one.
 */
typedef union {
        uint8_t bytes[UAPI16_UUID_SIZE];
        uint64_t qwords[UAPI16_UUID_QWORDS];
} uapi16_uuid_t;

/**
 * A set of uapi16_directory_flag_t: their bitwise OR.
 */
typedef uint64_t uapi16_directory_flags_t;

/**
 * The number that is no token, see uapi16_file_object_set_inode_token().
 */
#define UAPI16_INODE_TOKEN_NONE 0

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * Makes options with the default features, the code point order and no
 * syncing. The default features are those of a manifest that lists none:
 * UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID,
 * UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256, UAPI16_FEATURE_SYMLINK,
 * UAPI16_FEATURE_DEVICE and UAPI16_FEATURE_HARDLINK. They are freed with
 * uapi16_manifest_options_free().
 */
uapi16_manifest_options *uapi16_manifest_options_new(void);

/**
 * Sets the features to record to the `n` features at `features`, and no
 * others. A number that is no feature, other than UAPI16_FEATURE_NONE,
 * fails with -EINVAL, and the options are as they were. The features of
 * partitions are taken here, and refused when a manifest writer is made.
 */
int uapi16_manifest_options_set_features(uapi16_manifest_options *o,
                                         const uapi16_feature_t *features,
                                         size_t n);

/**
 * Adds the `n` features at `features` to those to record. A number that is
 * no feature, other than UAPI16_FEATURE_NONE, fails with -EINVAL, and the
 * options are as they were.
 */
int uapi16_manifest_options_add_features(uapi16_manifest_options *o,
                                         const uapi16_feature_t *features,
                                         size_t n);

/**
 * Takes the `n` features at `features` away from those to record. A number
 * that is no feature, other than UAPI16_FEATURE_NONE, fails with -EINVAL,
 * and the options are as they were.
 */
int uapi16_manifest_options_remove_features(uapi16_manifest_options *o,
                                            const uapi16_feature_t *features,
                                            size_t n);

/**
 * Sets the order of the file objects. UAPI16_ORDER_CODEPOINT is the only
 * one. UAPI16_ORDER_NONE is taken too, for a manifest that declares no
 * order, and any other number fails with -EINVAL.
 */
int uapi16_manifest_options_set_order(uapi16_manifest_options *o, uapi16_order_t order);

/**
 * Sets whether the new file of uapi16_manifest_writer_create_at() and
 * uapi16_manifest_generate_at() is written to disk before
 * uapi16_manifest_writer_finish() or uapi16_manifest_generate_at()
 * returns, so that a crash after that does not lose it. It is off unless
 * set.
 *
 * The file is synced before it gets its name, so that the name never
 * leads to a manifest that is not all on disk, and once more after it got
 * it, with the directory it is in, so that the name is on disk as well.
 * Nothing else is synced: uapi16_manifest_writer_open() and
 * uapi16_manifest_generate() write to a descriptor of the caller, which
 * the caller syncs.
 */
int uapi16_manifest_options_set_sync(uapi16_manifest_options *o, bool sync);

/**
 * Frees options. NULL is fine. Returns NULL, so that
 * `o = uapi16_manifest_options_free(o);` clears the pointer. A writer
 * that was made with them does not need them any more.
 */
uapi16_manifest_options *uapi16_manifest_options_free(uapi16_manifest_options *o);

/**
 * Writes the manifest of the directory `top_fd` and everything below it
 * to a new file `name` in the directory `dir_fd`, and stores a report of
 * what it lists in `ret`, unless that is NULL. It is
 * uapi16_manifest_writer_create_at(), a walk of `top_fd` as the root, and
 * uapi16_manifest_writer_finish() in one call. `name` is what
 * uapi16_manifest_writer_create_at() takes, and `flags` is a set of
 * uapi16_add_flag_t. The manifest is sorted, so options whose order is
 * UAPI16_ORDER_NONE fail with -EINVAL.
 *
 * Symbolic links are recorded and never followed. Mount points are not
 * crossed unless UAPI16_ADD_CROSS_MOUNTS is given: one that is a
 * directory is written as an empty directory. The walk mounts nothing: an
 * automount point that nothing is mounted on yet is written as an empty
 * directory with its own attributes, with any flags. There is one known
 * limit. The walk looks at a directory before it opens it, and a
 * directory that becomes an automount point in between has its file
 * system mounted by that open. The walk fails with UAPI16_ERROR_CHANGED
 * then. That takes someone who can mount in the mount namespace of the
 * caller, or an automount unit that is started at that moment.
 *
 * A file that changes while it is read fails with UAPI16_ERROR_CHANGED,
 * where its size, its times or its number of links show the change.
 *
 * Where the features record UAPI16_FEATURE_FLAG_HIDDEN,
 * UAPI16_FEATURE_FLAG_SYSTEM or UAPI16_FEATURE_FLAG_ARCHIVE, a tree on a
 * file system without DOS attributes fails before anything is read.
 *
 * The data of a regular file of more than 1 TiB is not hashed. Where the
 * manifest records hashes, or hard links and the file has more than one
 * name, the walk fails at such a file with UAPI16_ERROR_IO and EFBIG,
 * before anything is read of it.
 *
 * A walk of the directory the new file is in passes over what the
 * manifest keeps there, and over the new file under its temporary name.
 * On a file system without O_TMPFILE, such as FAT, a manifest that is
 * created inside the tree it describes can make the walk of a large tree
 * fail with UAPI16_ERROR_CHANGED, since the room it takes changes its own
 * directory while the walk reads it.
 */
int uapi16_manifest_generate_at(const uapi16_manifest_options *o,
                                int dir_fd,
                                const char *name,
                                int top_fd,
                                uapi16_add_flags_t flags,
                                uapi16_manifest_report **ret,
                                uapi16_error **reterr);

/**
 * Writes the manifest of the directory `top_fd` and everything below it
 * to the descriptor `fd`, and stores a report of what it lists in `ret`,
 * unless that is NULL. It is uapi16_manifest_writer_open(), a walk of
 * `top_fd` as the root, and uapi16_manifest_writer_finish() in one call.
 * `flags` is a set of uapi16_add_flag_t, and the walk is the one of
 * uapi16_manifest_generate_at(). The manifest is sorted, so options whose
 * order is UAPI16_ORDER_NONE fail with -EINVAL.
 */
int uapi16_manifest_generate(const uapi16_manifest_options *o,
                             int fd,
                             int top_fd,
                             uapi16_add_flags_t flags,
                             uapi16_manifest_report **ret,
                             uapi16_error **reterr);

/**
 * Makes a writer for a new manifest file `name` in the directory
 * `dir_fd`, and stores it in `ret`. The file appears when
 * uapi16_manifest_writer_finish() gives it its name, with the whole
 * manifest in it. Until then nothing has the name, and a writer that is
 * freed instead leaves nothing behind. The writer sorts, so options whose
 * order is UAPI16_ORDER_NONE fail with -EINVAL.
 *
 * The writer borrows `dir_fd` until it is freed: the caller keeps it open
 * until then, and closes it itself.
 *
 * `name` is a path, and is taken as the bytes it is, which need not be
 * UTF-8. One with more than one component names a file in a directory
 * below `dir_fd`. The components on the way are opened one at a time,
 * each without following a symbolic link, and the file goes into the
 * directory its last component is in. A symbolic link on the way fails
 * with -ELOOP, and anything else on the way that is no directory with
 * -ENOTDIR. A name that names no file below `dir_fd` fails with -EINVAL
 * before anything is looked up: one that is empty or that ends in a
 * slash, "." or "..", an absolute one, and one with "." or ".." on the
 * way. For a file in a directory that is not below `dir_fd`, open that
 * directory and pass it as `dir_fd`.
 *
 * This never replaces a file: where something has the name already, it
 * fails with UAPI16_ERROR_EXISTS. The name is checked again when the file
 * gets it. To write over a file, open it and use
 * uapi16_manifest_writer_open().
 *
 * On FAT the new file gets the mode the mount gives every file, and it
 * can't be larger than 4 GiB, so a manifest there holds about 2e7 file
 * objects at most: uapi16_manifest_writer_finish() fails with EFBIG for
 * more. A tree with more than about 9e6 files that have several names
 * fails with EFBIG already while it is added.
 *
 * The manifest of a large tree takes room on disk while it is built, in
 * the directory the file goes to. On a file system without O_TMPFILE, such
 * as FAT, the new file is in that directory under a temporary name until
 * uapi16_manifest_writer_finish().
 */
int uapi16_manifest_writer_create_at(const uapi16_manifest_options *o,
                                     int dir_fd,
                                     const char *name,
                                     uapi16_manifest_writer **ret,
                                     uapi16_error **reterr);

/**
 * Makes a writer for a manifest that is written to the descriptor `fd`,
 * and stores it in `ret`. Nothing is written before
 * uapi16_manifest_writer_finish(), and the manifest is complete once that
 * returns 0. The writer borrows `fd` until it is freed: the caller keeps it
 * open until then, and closes it itself. The writer sorts, so options whose
 * order is UAPI16_ORDER_NONE fail with -EINVAL.
 *
 * The manifest of a large tree takes room on disk while it is built, in
 * the directory TMPDIR names, or in /var/tmp where it names none. Where it
 * is on FAT, which can't hold a file of more than 4 GiB, a manifest of
 * more than about 3e7 file objects fails with EFBIG, and a tree with
 * more than about 9e6 files that have several names fails with EFBIG
 * already while it is added. A TMPDIR that is set is used as it is. It has
 * to be a directory the caller trusts, since whoever controls it can
 * change the manifest.
 */
int uapi16_manifest_writer_open(const uapi16_manifest_options *o,
                                int fd,
                                uapi16_manifest_writer **ret,
                                uapi16_error **reterr);

/**
 * Adds the file object `o`. It is checked as a writer of records checks a
 * file object, but for where it comes, which
 * uapi16_manifest_writer_finish() checks. An object that is refused is not
 * added, and the writer is as it was. The writer keeps a copy: the caller
 * can change the object, add it again under another name, or free it.
 *
 * The objects can come in any order. The object with the empty name is the
 * root, and says what the root directory and its file system are like. A
 * root with a validity, a validity window or a GPT disk UUID, which only a
 * root that a reader read can have, is refused, since this writer writes
 * none of them. uapi16_writer_begin() writes them. The first object of a
 * directory says what the directory is like. Two equal objects of one name
 * are listed once, and two that differ and are not both directories are
 * UAPI16_ERROR_DUPLICATE, from uapi16_manifest_writer_finish().
 *
 * Objects with the same token are names of one file, and say the same
 * about it. One that does not fails the add with
 * UAPI16_ERROR_HARDLINK_MISMATCH, and uapi16_error_hardlink_path() names the
 * first of them.
 */
int uapi16_manifest_writer_add_object(uapi16_manifest_writer *w,
                                      const uapi16_file_object *o,
                                      uapi16_error **reterr);

/**
 * Writes the manifest, and stores a report of what it lists in `ret`,
 * unless that is NULL. With uapi16_manifest_writer_create_at() the file
 * gets its name now, unless something took the name since, which is
 * UAPI16_ERROR_EXISTS. Where something fails once the file has its name,
 * such as the sync of its directory, the file keeps the name, and the
 * call fails all the same.
 *
 * What the adds left open fails here: two different files under one
 * name, a directory that was not added where the features need it, a file
 * that is not a directory and that files were added below, and a record
 * that is too large.
 *
 * The writer is finished after this, whether it succeeded or failed.
 * Every later add and finish on it fails with UAPI16_ERROR_ENDED, and
 * uapi16_manifest_writer_free() frees it.
 */
int uapi16_manifest_writer_finish(uapi16_manifest_writer *w,
                                  uapi16_manifest_report **ret,
                                  uapi16_error **reterr);

/**
 * Frees a writer. One that was not finished writes nothing and leaves no
 * file behind. NULL is fine. Returns NULL. The descriptor of the caller
 * stays open.
 */
uapi16_manifest_writer *uapi16_manifest_writer_free(uapi16_manifest_writer *w);

/**
 * How many regular files the manifest lists. 0 for NULL, as for every
 * function of a report.
 */
uint64_t uapi16_manifest_report_files(const uapi16_manifest_report *r);

/**
 * How many directories the manifest lists, the root among them.
 */
uint64_t uapi16_manifest_report_directories(const uapi16_manifest_report *r);

/**
 * How many other files the manifest lists: symbolic links, FIFOs, device
 * nodes and sockets.
 */
uint64_t uapi16_manifest_report_others(const uapi16_manifest_report *r);

/**
 * The sizes of the regular files, added up. The data of a file with more
 * than one name counts for each.
 */
uint64_t uapi16_manifest_report_bytes(const uapi16_manifest_report *r);

/**
 * How many files UAPI16_ADD_GRACEFUL left out, a directory with everything
 * below it as one.
 */
uint64_t uapi16_manifest_report_entries_omitted(const uapi16_manifest_report *r);

/**
 * How many fields were left out of the file objects: the names of owners
 * that the user database does not have, the user and group IDs 65535 and
 * 4294967295, modification times before 1970 or after 2554, and the UUID
 * or the volume serial number of a file system that gives none.
 */
uint64_t uapi16_manifest_report_fields_omitted(const uapi16_manifest_report *r);

/**
 * Frees a report. NULL is fine. Returns NULL.
 */
uapi16_manifest_report *uapi16_manifest_report_free(uapi16_manifest_report *r);

/**
 * Starts to read a manifest from the descriptor `fd`, reads its root, and
 * stores the reader in `ret`. The reader borrows `fd` until it is freed:
 * the caller keeps it open until then, and closes it itself. On a
 * descriptor that does not block, EAGAIN fails the open and loses what it
 * read, so the descriptor has to block, or already hold the root and the
 * start of the next record.
 */
int uapi16_reader_open(int fd, uapi16_reader **ret, uapi16_error **reterr);

/**
 * The root of the manifest: an object with the empty name. It belongs to
 * the reader and lives until the reader is freed. NULL for NULL.
 */
const uapi16_file_object *uapi16_reader_root(const uapi16_reader *r);

/**
 * Whether the manifest records the feature `feature`. A manifest that lists
 * no features records the default features. false for a number that is no
 * feature, and for NULL.
 */
bool uapi16_reader_has_feature(const uapi16_reader *r, uapi16_feature_t feature);

/**
 * Feature `i` of those the manifest records, counted from 0 in the order
 * of their numbers. UAPI16_FEATURE_NONE past the last one, and for NULL.
 */
uapi16_feature_t uapi16_reader_feature(const uapi16_reader *r, size_t i);

/**
 * The order the manifest declares, or UAPI16_ORDER_NONE where it declares
 * none.
 */
uapi16_order_t uapi16_reader_order(const uapi16_reader *r);

/**
 * Requires the manifest to declare the order `order`, as a caller does
 * that relies on it. A manifest that does not fails with
 * UAPI16_ERROR_MANIFEST, even if its file objects are in that order. The
 * reader checks the file objects against the order the manifest declares
 * while it reads them. UAPI16_ORDER_NONE is no order to require, and fails
 * with -EINVAL.
 */
int uapi16_reader_require_order(const uapi16_reader *r,
                                uapi16_order_t order,
                                uapi16_error **reterr);

/**
 * Checks that the manifest may be used at the time `now_usec`, in
 * microseconds since 1970: that its root is not revoked and that the time
 * is inside its validity window.
 */
int uapi16_reader_check_validity(const uapi16_reader *r, uint64_t now_usec, uapi16_error **reterr);

/**
 * Reads on, and returns what it read as a uapi16_read_t, or a negative
 * errno:
 *
 * - UAPI16_READ_FILE: one file object, which is in `*ret`.
 * - UAPI16_READ_SIGNATURES: the file objects have ended, and signature
 *   objects follow. The next call passes over them, and checks them.
 * - UAPI16_READ_END: the trailer was read and checked, and the manifest is
 *   complete. Every later call returns this again.
 *
 * `ret` points to NULL or to a file object of the caller. Where it points
 * to NULL, a file object that is read is stored there as a new object.
 * Where it points to an object, that object is cleared and filled again,
 * and nothing of what it held before is left: the strings and bytes its
 * getters returned before are gone with it. So one object serves a whole
 * loop, as the buffer of getline() does. A call that reads no file object
 * leaves `*ret` as it is. The object stays the caller's, to free with
 * uapi16_file_object_free(), also after a call that failed.
 */
int uapi16_reader_next(uapi16_reader *r, uapi16_file_object **ret, uapi16_error **reterr);

/**
 * Reads the next signature object, and returns what it read as a
 * uapi16_read_t, or a negative errno:
 *
 * - UAPI16_READ_SIGNATURE: one signature object, which is in `*ret`.
 * - UAPI16_READ_END: the trailer was read and checked, and the manifest is
 *   complete. Every later call returns this again.
 *
 * The signature objects come after the file objects: a call before
 * uapi16_reader_next() returned UAPI16_READ_SIGNATURES or UAPI16_READ_END
 * fails with -EINVAL. `ret` points to NULL or to a signature object of the
 * caller, and is used as uapi16_reader_next() uses its `ret`. The object is
 * freed with uapi16_signature_free().
 */
int uapi16_reader_next_signature(uapi16_reader *r, uapi16_signature **ret, uapi16_error **reterr);

/**
 * Stores in `ret` how many bytes at the start of the manifest its signature
 * objects sign: all that comes before the record of the first of them, up
 * to its record separator. -ENODATA before uapi16_reader_next() returned
 * UAPI16_READ_SIGNATURES, and so for a manifest without signature objects.
 *
 * The library does not verify signatures. With this number and the
 * signature objects a caller can.
 */
int uapi16_reader_signed_len(const uapi16_reader *r, uint64_t *ret);

/**
 * Frees a reader, and its root with it. NULL is fine. Returns NULL. The
 * descriptor of the caller stays open.
 */
uapi16_reader *uapi16_reader_free(uapi16_reader *r);

/**
 * Starts a manifest on the descriptor `fd` with the root `root`, and stores
 * the writer in `ret`. The features and the order are those of the options
 * `o`, and options with UAPI16_ORDER_NONE make a manifest that declares no
 * order. `root` is an object with the empty name, or NULL for a root that
 * says nothing. The writer borrows `fd` until it is freed: the caller keeps
 * it open until then, and closes it itself.
 */
int uapi16_writer_begin(const uapi16_manifest_options *o,
                        int fd,
                        const uapi16_file_object *root,
                        uapi16_writer **ret,
                        uapi16_error **reterr);

/**
 * Writes the file object `o`. The writer checks it as a reader does: it has
 * no field of a feature the manifest does not record, it comes right after
 * the object of its directory, and it keeps to the order. An object that is
 * refused is not written, and the writer goes on as if it had not been
 * given it.
 *
 * In a manifest that declares no order, the order of the names is not
 * checked. A name that comes again right after the entries of the directory
 * it names is still refused. One that comes again later is not found.
 */
int uapi16_writer_file(uapi16_writer *w, const uapi16_file_object *o, uapi16_error **reterr);

/**
 * Writes the signature object `s`. No file object can follow it: it would
 * be one the signature does not cover. The signature objects of a manifest
 * sign the manifest up to the first of them, which is all that the writer
 * wrote to its descriptor before the first call of this.
 */
int uapi16_writer_signature(uapi16_writer *w, const uapi16_signature *s, uapi16_error **reterr);

/**
 * Ends the manifest with its trailer. The writer is finished after this,
 * whether it succeeded or failed: every later call on it fails with
 * UAPI16_ERROR_ENDED, and uapi16_writer_free() frees it.
 */
int uapi16_writer_finish(uapi16_writer *w, uapi16_error **reterr);

/**
 * Frees a writer of records. NULL is fine. Returns NULL. The descriptor of
 * the caller stays open.
 */
uapi16_writer *uapi16_writer_free(uapi16_writer *w);

/**
 * Makes a signature object of the mechanism `mechanism`, without a key and
 * without data, and stores it in `ret`. The specification has "openpgp" and
 * "pkcs7".
 */
int uapi16_signature_new(const char *mechanism, uapi16_signature **ret);

/**
 * How the signature was made: its mechanism. NULL for NULL. The string
 * belongs to the object.
 */
const char *uapi16_signature_mechanism(const uapi16_signature *s);

/**
 * Sets what identifies the key, such as its fingerprint: the `size` bytes
 * at `key`. A `key` of NULL takes it away.
 */
int uapi16_signature_set_key(uapi16_signature *s, const void *key, size_t size);

/**
 * What identifies the key, and its size in `ret_size`, unless that is NULL.
 * No NUL ends the bytes. NULL and 0 where the object has none. The bytes
 * belong to the object.
 */
const void *uapi16_signature_key(const uapi16_signature *s, size_t *ret_size);

/**
 * Sets the signature: the `size` bytes at `data`. A `data` of NULL takes it
 * away.
 */
int uapi16_signature_set_data(uapi16_signature *s, const void *data, size_t size);

/**
 * The signature, and its size in `ret_size`, unless that is NULL. No NUL
 * ends the bytes. NULL and 0 where the object has none. The bytes belong to
 * the object.
 */
const void *uapi16_signature_data(const uapi16_signature *s, size_t *ret_size);

/**
 * Frees a signature object. NULL is fine. Returns NULL.
 */
uapi16_signature *uapi16_signature_free(uapi16_signature *s);

/**
 * Makes a file object for the regular file `name` that says nothing else
 * about it, and stores it in `ret`. `name` is the path of the file below
 * the root of the tree, as a manifest has it: components separated by
 * single slashes, none of them empty, "." or "..". The empty string makes
 * the root. A name that a manifest can't hold fails with
 * UAPI16_ERROR_INVALID_ARGUMENT, and uapi16_error_name_problem() says which
 * rule it breaks.
 */
int uapi16_file_object_new(const char *name, uapi16_file_object **ret, uapi16_error **reterr);

/**
 * Frees a file object. NULL is fine. Returns NULL. An object of
 * uapi16_reader_root() belongs to its reader and is not freed with this.
 */
uapi16_file_object *uapi16_file_object_free(uapi16_file_object *o);

/**
 * Gives the object the name `name`, which uapi16_file_object_new() checks
 * the same way. The names of one file carry the same fields: a caller adds
 * the object under one name, sets the next name and adds it again. A name
 * that is refused leaves the object as it was. The root keeps its name, and
 * no other object takes the empty one: both fail with -EINVAL.
 */
int uapi16_file_object_set_name(uapi16_file_object *o, const char *name, uapi16_error **reterr);

/**
 * The name of the file: its path below the root. The root is the empty
 * string. NULL for NULL. The string belongs to the object and lives until
 * the name is set again or the object is freed.
 */
const char *uapi16_file_object_name(const uapi16_file_object *o);

/**
 * Sets the type of the file from an `st_mode` as stat() gives it: S_IFREG,
 * S_IFDIR, S_IFLNK, S_IFIFO, S_IFCHR, S_IFBLK or S_IFSOCK. Only the bits of
 * the file type are read, and bits that are none of these fail with
 * -EINVAL. The root is a directory: S_IFDIR is fine for it, and any other
 * type fails with -EINVAL.
 */
int uapi16_file_object_set_type(uapi16_file_object *o, uint32_t st_mode);

/**
 * The type of the file, as the bits of the file type in an `st_mode`. An
 * object that was given none is a regular file. 0 for NULL.
 */
uint32_t uapi16_file_object_type(const uapi16_file_object *o);

/**
 * Sets the access mode from an `st_mode` as stat() gives it: the permission
 * bits with the set-user-ID, the set-group-ID and the sticky bit. The bits
 * of the file type are not read.
 */
int uapi16_file_object_set_mode(uapi16_file_object *o, uint32_t st_mode);

/**
 * Stores the access mode in `ret`: the permission bits with the
 * set-user-ID, the set-group-ID and the sticky bit, and no bits of a file
 * type.
 */
int uapi16_file_object_mode(const uapi16_file_object *o, uint32_t *ret);

/**
 * Sets the user ID of the owner.
 */
int uapi16_file_object_set_uid(uapi16_file_object *o, uint32_t uid);

/**
 * Stores the user ID of the owner in `ret`.
 */
int uapi16_file_object_uid(const uapi16_file_object *o, uint32_t *ret);

/**
 * Sets the group ID of the owner.
 */
int uapi16_file_object_set_gid(uapi16_file_object *o, uint32_t gid);

/**
 * Stores the group ID of the owner in `ret`.
 */
int uapi16_file_object_gid(const uapi16_file_object *o, uint32_t *ret);

/**
 * Sets the name of the owning user.
 */
int uapi16_file_object_set_user_name(uapi16_file_object *o, const char *name);

/**
 * The name of the owning user, or NULL where the object has none. The
 * string belongs to the object.
 */
const char *uapi16_file_object_user_name(const uapi16_file_object *o);

/**
 * Sets the name of the owning group.
 */
int uapi16_file_object_set_group_name(uapi16_file_object *o, const char *name);

/**
 * The name of the owning group, or NULL where the object has none. The
 * string belongs to the object.
 */
const char *uapi16_file_object_group_name(const uapi16_file_object *o);

/**
 * Sets the modification time, in nanoseconds since 1970.
 */
int uapi16_file_object_set_mtime_nsec(uapi16_file_object *o, uint64_t nsec);

/**
 * Stores the modification time in `ret`, in nanoseconds since 1970.
 */
int uapi16_file_object_mtime_nsec(const uapi16_file_object *o, uint64_t *ret);

/**
 * Sets the size of the data in bytes. For a symbolic link that is the
 * length of its target.
 */
int uapi16_file_object_set_size(uapi16_file_object *o, uint64_t size);

/**
 * Stores the size of the data in `ret`, in bytes.
 */
int uapi16_file_object_size(const uapi16_file_object *o, uint64_t *ret);

/**
 * Sets the SHA-256 hash of the data to the one at `sha256`.
 */
int uapi16_file_object_set_sha256(uapi16_file_object *o, const uapi16_sha256_digest_t *sha256);

/**
 * Stores the SHA-256 hash of the data in `ret`.
 */
int uapi16_file_object_sha256(const uapi16_file_object *o, uapi16_sha256_digest_t *ret);

/**
 * Sets the major number of a device node.
 */
int uapi16_file_object_set_major(uapi16_file_object *o, uint64_t major);

/**
 * Stores the major number of a device node in `ret`.
 */
int uapi16_file_object_major(const uapi16_file_object *o, uint64_t *ret);

/**
 * Sets the minor number of a device node.
 */
int uapi16_file_object_set_minor(uapi16_file_object *o, uint64_t minor);

/**
 * Stores the minor number of a device node in `ret`.
 */
int uapi16_file_object_minor(const uapi16_file_object *o, uint64_t *ret);

/**
 * Sets the token of the file. The objects that carry the same token are
 * names of one file. Any number but 0 is a token, and
 * UAPI16_INODE_TOKEN_NONE takes the token away.
 * uapi16_manifest_writer_add_object() takes the numbers of the caller as
 * they are and gives the files the numbers the specification asks for.
 * uapi16_writer_file() writes the token as it is, so its caller numbers the
 * files itself: from 1, in the order they first come in the manifest.
 */
int uapi16_file_object_set_inode_token(uapi16_file_object *o, uapi16_inode_token_t token);

/**
 * Stores the token of the file in `ret`. -ENODATA where the object has
 * none: a file of no other name.
 */
int uapi16_file_object_inode_token(const uapi16_file_object *o, uapi16_inode_token_t *ret);

/**
 * Makes the object list its extended attributes of the user namespace, and
 * lists none: the file has none, until uapi16_file_object_add_user_xattr()
 * adds one. An object that does not list them says nothing about them.
 */
int uapi16_file_object_set_user_xattrs(uapi16_file_object *o);

/**
 * Adds the extended attribute `name` of the user namespace with the `size`
 * bytes at `value` as its value, or gives it that value where the object
 * lists it already. `name` is the name without "user." in front. The object
 * lists its extended attributes after this.
 */
int uapi16_file_object_add_user_xattr(uapi16_file_object *o,
                                      const char *name,
                                      const void *value,
                                      size_t size);

/**
 * Stores in `ret_count` how many extended attributes of the user namespace
 * the object lists. -ENODATA where it says nothing about them.
 */
int uapi16_file_object_user_xattrs(const uapi16_file_object *o, size_t *ret_count);

/**
 * Stores the name, the value and the size of the value of the extended
 * attribute number `i`, counting from 0 in the order of the names. The name
 * comes without "user." in front, and no NUL ends the value. Each of the
 * three can be NULL. An `i` that is not below the count of
 * uapi16_file_object_user_xattrs() fails with -EINVAL. The name and the
 * value belong to the object and live until it is changed or freed.
 */
int uapi16_file_object_user_xattr(const uapi16_file_object *o,
                                  size_t i,
                                  const char **ret_name,
                                  const void **ret_value,
                                  size_t *ret_size);

/**
 * Sets whether the file is read-only: UAPI16_READ_ONLY_YES or
 * UAPI16_READ_ONLY_NO. UAPI16_READ_ONLY_UNSTATED takes the field away. Any
 * other number fails with -EINVAL. The field stands for the read-only
 * attribute of DOS too.
 */
int uapi16_file_object_set_read_only(uapi16_file_object *o, uapi16_read_only_t read_only);

/**
 * Whether the file is read-only. UAPI16_READ_ONLY_UNSTATED where the object
 * does not say, and for NULL.
 */
uapi16_read_only_t uapi16_file_object_read_only(const uapi16_file_object *o);

/**
 * Sets the Linux inode flags, as the bits FS_IOC_GETFLAGS gives. `stated`
 * has the flags the object says something about, and `set` those of them
 * that are set. A manifest has FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL,
 * FS_NOCOW_FL and FS_NODUMP_FL. Other bits are not read. A flag that is not
 * in `stated` is taken away from the object.
 */
int uapi16_file_object_set_inode_flags(uapi16_file_object *o, uint32_t stated, uint32_t set);

/**
 * Stores the Linux inode flags the object says something about in
 * `ret_stated`, and those of them that are set in `ret_set`, as the bits
 * FS_IOC_GETFLAGS gives. Either can be NULL. An object that says nothing
 * about any flag stores 0 in both.
 */
int uapi16_file_object_inode_flags(const uapi16_file_object *o,
                                   uint32_t *ret_stated,
                                   uint32_t *ret_set);

/**
 * Sets the DOS attributes hidden, system and archive, as the bits a
 * directory entry of FAT has: 0x02, 0x04 and 0x20. `stated` has the
 * attributes the object says something about, and `set` those of them that
 * are set. Other bits are not read. An attribute that is not in `stated` is
 * taken away from the object. The read-only attribute is
 * uapi16_file_object_set_read_only().
 */
int uapi16_file_object_set_dos_attributes(uapi16_file_object *o, uint32_t stated, uint32_t set);

/**
 * Stores the DOS attributes the object says something about in
 * `ret_stated`, and those of them that are set in `ret_set`, as the bits a
 * directory entry of FAT has. Either can be NULL. An object that says
 * nothing about any of them stores 0 in both.
 */
int uapi16_file_object_dos_attributes(const uapi16_file_object *o,
                                      uint32_t *ret_stated,
                                      uint32_t *ret_set);

/**
 * Sets the target of a symbolic link: the `size` bytes at `target`, which
 * need not be UTF-8 and which no NUL ends. The manifest carries the target
 * itself. On a regular file they are the data of the file, which the
 * manifest carries the same way.
 */
int uapi16_file_object_set_target(uapi16_file_object *o, const void *target, size_t size);

/**
 * Says that the data of the file is in the file `file` next to the
 * manifest, under another name than its own. `file` is a name as
 * uapi16_file_object_new() takes one, but for the empty one. A name that is
 * none fails as it does there. Without this, the data of a regular file is
 * in the file of its own name next to the manifest.
 */
int uapi16_file_object_set_contents_file(uapi16_file_object *o,
                                         const char *file,
                                         uapi16_error **reterr);

/**
 * The file the data of `o` is in, where that is another file than the one
 * of its own name, and where the data starts in it. -ENODATA where the
 * object names no such file. Both `ret_file` and `ret_offset` are needed: a
 * NULL one fails with -EINVAL.
 */
int uapi16_file_object_contents_file(const uapi16_file_object *o,
                                     const char **ret_file,
                                     uint64_t *ret_offset);

/**
 * Where the data of the file is: the bytes of a regular file or the target
 * of a symbolic link. A literal is taken first. Otherwise the data is in
 * the file next to the manifest that the object refers to, or in the file
 * of its own name where it is a regular file and refers to none.
 * UAPI16_DATA_LOCATION_NONE for an object without data, and for NULL.
 */
uapi16_data_location_t uapi16_file_object_data_location(const uapi16_file_object *o);

/**
 * The data of the file where the manifest carries it itself, such as the
 * target of a symbolic link, and its size in `ret_size`, unless that is
 * NULL. Where the object gives a size, the data is that many bytes. No NUL
 * ends the bytes. NULL and 0 where the data is not in the manifest. The
 * bytes belong to the object.
 */
const void *uapi16_file_object_literal(const uapi16_file_object *o, size_t *ret_size);

/**
 * Sets the label of the file system. Only the root has one.
 */
int uapi16_file_object_set_fs_label(uapi16_file_object *o, const char *label);

/**
 * The label of the file system, or NULL where the object has none. The
 * string belongs to the object.
 */
const char *uapi16_file_object_fs_label(const uapi16_file_object *o);

/**
 * Sets the UUID of the file system to the one at `uuid`. Only the root has
 * one.
 */
int uapi16_file_object_set_fs_uuid(uapi16_file_object *o, const uapi16_uuid_t *uuid);

/**
 * Stores the UUID of the file system in `ret`.
 */
int uapi16_file_object_fs_uuid(const uapi16_file_object *o, uapi16_uuid_t *ret);

/**
 * Sets the volume serial number of a FAT or exFAT file system. Only the
 * root has one.
 */
int uapi16_file_object_set_fat_serial(uapi16_file_object *o, uint32_t serial);

/**
 * Stores the volume serial number of a FAT or exFAT file system in `ret`.
 */
int uapi16_file_object_fat_serial(const uapi16_file_object *o, uint32_t *ret);

/**
 * Whether the object has the fields of the feature `feature`. A manifest
 * records every such feature, or the object is not one of its file objects.
 * What a reader filled in does not count. false for a number that is no
 * feature, and for NULL.
 */
bool uapi16_file_object_has_stated_feature(const uapi16_file_object *o, uapi16_feature_t feature);

/**
 * Feature `i` of those whose fields the object has, counted from 0 in the
 * order of their numbers. UAPI16_FEATURE_NONE past the last one, and for
 * NULL.
 */
uapi16_feature_t uapi16_file_object_stated_feature(const uapi16_file_object *o, size_t i);

/**
 * Takes away the fields of every feature that is not one of the `n`
 * features at `features`. So a caller sets all it knows of a file and keeps
 * what its manifest records. The name, the type and what belongs to no
 * feature stay. The target of a symbolic link goes without
 * UAPI16_FEATURE_SYMLINK. The data a manifest carries of a regular file and
 * the file its data is in belong to no feature, and stay. An object whose
 * data starts at an offset in a file reaches to the end of it once its size
 * goes, and a hash that stays no longer fits. A number that is no feature,
 * other than UAPI16_FEATURE_NONE, fails with -EINVAL, and the object is as
 * it was.
 */
int uapi16_file_object_retain_features(uapi16_file_object *o,
                                       const uapi16_feature_t *features,
                                       size_t n);

/**
 * Checks that the object may be used at the time `now_usec`, in
 * microseconds since 1970: that it is not revoked and that the time is
 * inside its validity window. The check looks at the object alone. A caller
 * that uses a file checks the objects of the directories it is in as well,
 * which come before it in the manifest.
 */
int uapi16_file_object_check_validity(const uapi16_file_object *o,
                                      uint64_t now_usec,
                                      uapi16_error **reterr);

/**
 * Makes a directory from the descriptor `dir_fd`, which may be opened with
 * O_PATH, and stores it in `ret`. `flags` is a set of
 * uapi16_directory_flag_t. The directory borrows `dir_fd` until it is
 * freed: the caller keeps it open until then, and closes it itself.
 */
int uapi16_directory_new(int dir_fd,
                         uapi16_directory_flags_t flags,
                         uapi16_directory **ret,
                         uapi16_error **reterr);

/**
 * Opens the file the data of `o` is in, for reading, and stores a new
 * descriptor in `ret_fd`, which the caller closes. The descriptor is open
 * for reading, and blocks as a regular file does. Where the data starts in
 * the file is stored in `ret_offset`. Both `ret_fd` and `ret_offset` are
 * needed: a NULL one fails with -EINVAL. The data is as long as the object
 * says, or reaches to the end of the file where the object gives no size.
 *
 * The file is a regular file. One that is not there fails with
 * UAPI16_ERROR_SOURCE_MISSING, one that is no regular file with
 * UAPI16_ERROR_SOURCE_NOT_REGULAR, one that can't be opened with
 * UAPI16_ERROR_IO and the errno of the system call, such as ELOOP for a
 * symbolic link on the way, and one that is too short for the data, or of
 * another size than the manifest gives for the file, with
 * UAPI16_ERROR_SIZE_MISMATCH. An object whose data is not in a file, see
 * uapi16_file_object_data_location(), fails with UAPI16_ERROR_UNSUPPORTED.
 *
 * The caller checks what it reads with a uapi16_data_check. A file can hold
 * the data of several file objects. Where the manifest gives a hash for
 * the whole file and none for the object, the data of the object is not
 * checked against it.
 */
int uapi16_directory_open_data(const uapi16_directory *d,
                               const uapi16_file_object *o,
                               int *ret_fd,
                               uint64_t *ret_offset,
                               uapi16_error **reterr);

/**
 * Frees a directory. NULL is fine. Returns NULL. The descriptor of the
 * caller stays open, and so do those that uapi16_directory_open_data()
 * stored.
 */
uapi16_directory *uapi16_directory_free(uapi16_directory *d);

/**
 * Makes a check of the data of `o`, of which nothing has passed yet, and
 * stores it in `ret`. The check keeps what it needs of the object, which
 * can be changed or freed after the call.
 */
int uapi16_data_check_new(const uapi16_file_object *o, uapi16_data_check **ret);

/**
 * Takes the `size` bytes at `data` as the next bytes of the data. Fails
 * with UAPI16_ERROR_SIZE_MISMATCH, and takes none of them, where they
 * would make the data larger than the size the object gives.
 */
int uapi16_data_check_update(uapi16_data_check *c,
                             const void *data,
                             size_t size,
                             uapi16_error **reterr);

/**
 * Takes `size` zero bytes as the next bytes of the data, such as a hole of
 * a sparse file that the caller did not read. Fails as
 * uapi16_data_check_update() does.
 */
int uapi16_data_check_update_zeros(uapi16_data_check *c, uint64_t size, uapi16_error **reterr);

/**
 * Checks the data that passed against the size and the hash the object
 * gives, and stores how many bytes it is in `ret_size`, unless that is
 * NULL. Data of another size fails with UAPI16_ERROR_SIZE_MISMATCH, and
 * data with another hash with UAPI16_ERROR_HASH_MISMATCH. Every later call
 * on the check but uapi16_data_check_free() fails with -ESTALE.
 */
int uapi16_data_check_finish(uapi16_data_check *c, uint64_t *ret_size, uapi16_error **reterr);

/**
 * Frees a check. NULL is fine. Returns NULL.
 */
uapi16_data_check *uapi16_data_check_free(uapi16_data_check *c);

/**
 * Makes a computation that has taken no data yet. It is freed with
 * uapi16_sha256_free().
 */
uapi16_sha256 *uapi16_sha256_new(void);

/**
 * Takes the `size` bytes at `data` as more of the data.
 */
int uapi16_sha256_update(uapi16_sha256 *s, const void *data, size_t size);

/**
 * Takes `size` zero bytes as more of the data, such as a hole of a sparse
 * file that the caller did not read.
 */
int uapi16_sha256_update_zeros(uapi16_sha256 *s, uint64_t size);

/**
 * Ends the computation and stores the hash of all the data in `ret`. Every
 * later call on it but uapi16_sha256_free() fails with -ESTALE.
 */
int uapi16_sha256_finish(uapi16_sha256 *s, uapi16_sha256_digest_t *ret);

/**
 * Frees a computation. NULL is fine. Returns NULL.
 */
uapi16_sha256 *uapi16_sha256_free(uapi16_sha256 *s);

/**
 * Compares two names the way a manifest in code point order lists its file
 * objects: component by component, each by its bytes, so that the name of
 * a directory comes right before the names below it. Returns one of
 * uapi16_name_order_t as an int: UAPI16_NAME_BEFORE where `a` comes before
 * `b`, UAPI16_NAME_SAME where they are the same, and UAPI16_NAME_AFTER
 * where `a` comes after `b`. A comparison function of qsort() returns that
 * as it is. This is not the order of strcmp(): "a/x" comes before "a-b".
 * NULL is the empty name, which comes first. Strings that are not UTF-8 are
 * no names, and they compare after the replacement.
 */
int uapi16_name_compare(const char *a, const char *b);

/**
 * The name the specification has for the feature `feature`, such as
 * "user-xattr" for UAPI16_FEATURE_USER_XATTR. NULL for a number that is
 * not one feature. The string is a constant of the library.
 */
const char *uapi16_feature_name(uapi16_feature_t feature);

/**
 * The feature with the name `name`, as the specification spells it.
 * UAPI16_FEATURE_NONE for a name that no feature has, and for NULL.
 */
uapi16_feature_t uapi16_feature_from_name(const char *name);

/**
 * Turns every one of the `n` features at `features` that this library
 * doesn't have into UAPI16_FEATURE_NONE, and returns how many it turned
 * off. A program built with a newer header learns this way which of its
 * features the library it runs with has. 0 for NULL.
 */
size_t uapi16_feature_probe(uapi16_feature_t *features, size_t n);

/**
 * What kind of error this is. 0 for NULL.
 */
uapi16_error_kind_t uapi16_error_kind(const uapi16_error *e);

/**
 * The errno of the error, a positive number as errno has it. The call
 * that failed returned it negated. 0 for NULL.
 */
int uapi16_error_errno(const uapi16_error *e);

/**
 * The name of the file the error is about, as the manifest has it, or
 * NULL if the error is about no file. The root of the tree is the empty
 * string. For a name a manifest can't hold, it is the name of the
 * directory the file is in. The string belongs to the error.
 */
const char *uapi16_error_path(const uapi16_error *e);

/**
 * For UAPI16_ERROR_HARDLINK_MISMATCH, the other name of the inode, which
 * the file of uapi16_error_path() was compared with. NULL for any other
 * error. The string belongs to the error.
 */
const char *uapi16_error_hardlink_path(const uapi16_error *e);

/**
 * The feature the error is about: for UAPI16_ERROR_UNSUPPORTED the one
 * that can't be read, and for a feature of partitions that feature.
 * UAPI16_FEATURE_NONE if the error is about no feature.
 */
uapi16_feature_t uapi16_error_feature(const uapi16_error *e);

/**
 * For UAPI16_ERROR_UNWRITABLE_NAME, the name of the file as its directory
 * has it: one component. Its bytes need not be UTF-8, and no NUL ends
 * them. How many there are is stored in `ret_size`, unless that is NULL.
 * For any other error this returns NULL and stores 0. The bytes belong to
 * the error.
 */
const void *uapi16_error_raw_name(const uapi16_error *e, size_t *ret_size);

/**
 * Which rule of a name the name breaks: for UAPI16_ERROR_UNWRITABLE_NAME
 * the name of uapi16_error_raw_name(), and for a name passed to a file
 * object that is no name, that one. 0 for any other error.
 */
uapi16_name_problem_t uapi16_error_name_problem(const uapi16_error *e);

/**
 * The field the error is about, as the specification spells it, such as
 * "mode" or "inodeToken". NULL if the error is about no field. The string
 * is a constant of the library.
 */
const char *uapi16_error_field(const uapi16_error *e);

/**
 * Stores in `ret` the number of the record the error is about, counting
 * from 0, which is the record of the root. For a reader that is the record
 * that failed, and for a writer of records the number the record it refused
 * would have had. -ENODATA if the error is about no record, as no error of
 * a manifest writer is.
 */
int uapi16_error_record(const uapi16_error *e, uint64_t *ret);

/**
 * For UAPI16_ERROR_MANIFEST and UAPI16_ERROR_TOO_LARGE, the rule of the
 * specification that a manifest or a file object breaks, by a name that
 * never changes. NULL for any other error. The string is a constant of the
 * library.
 *
 * The names are "notJson", "duplicateKey", "invalidString", "notObject",
 * "notUtf8", "nulByte", "recordSeparator", "recordTooLarge", "empty",
 * "noTrailer", "dataAfterTrailer", "fileAfterSignature", "mediaType",
 * "firstHasName", "firstNotDirectory", "noOrder", "noName", "invalidName",
 * "duplicateName", "misplaced", "outOfOrder", "unlistedFeature",
 * "noTarget", "unknownType", "fieldType", "fieldRange",
 * "fieldNotPermitted", "contradiction", "contents", "signature" and
 * "extendedAttributes".
 */
const char *uapi16_error_problem(const uapi16_error *e);

/**
 * Frees an error. NULL is fine. Returns NULL.
 */
uapi16_error *uapi16_error_free(uapi16_error *e);

#ifdef __cplusplus
}  // extern "C"
#endif  // __cplusplus

#ifndef __cplusplus
/**
 * A list of features, as an array and its length, for the calls that take
 * one:
 *
 *     uapi16_manifest_options_add_features(o,
 *             UAPI16_FEATURES(UAPI16_FEATURE_MTIME, UAPI16_FEATURE_USER_XATTR));
 */
#define UAPI16_FEATURES(...)                                    \
        ((uapi16_feature_t[]) { __VA_ARGS__ }),                 \
        (sizeof((uapi16_feature_t[]) { __VA_ARGS__ }) /         \
         sizeof(uapi16_feature_t))
#endif

/*
 * For __attribute__((cleanup(...))): each frees the object that its
 * argument points to, unless that is NULL.
 */
static inline void uapi16_manifest_options_freep(uapi16_manifest_options **o) {
        if (*o)
                *o = uapi16_manifest_options_free(*o);
}

static inline void uapi16_manifest_writer_freep(uapi16_manifest_writer **w) {
        if (*w)
                *w = uapi16_manifest_writer_free(*w);
}

static inline void uapi16_manifest_report_freep(uapi16_manifest_report **r) {
        if (*r)
                *r = uapi16_manifest_report_free(*r);
}

static inline void uapi16_error_freep(uapi16_error **e) {
        if (*e)
                *e = uapi16_error_free(*e);
}

static inline void uapi16_file_object_freep(uapi16_file_object **o) {
        if (*o)
                *o = uapi16_file_object_free(*o);
}

static inline void uapi16_writer_freep(uapi16_writer **w) {
        if (*w)
                *w = uapi16_writer_free(*w);
}

static inline void uapi16_signature_freep(uapi16_signature **s) {
        if (*s)
                *s = uapi16_signature_free(*s);
}

static inline void uapi16_sha256_freep(uapi16_sha256 **s) {
        if (*s)
                *s = uapi16_sha256_free(*s);
}

static inline void uapi16_reader_freep(uapi16_reader **r) {
        if (*r)
                *r = uapi16_reader_free(*r);
}

static inline void uapi16_directory_freep(uapi16_directory **d) {
        if (*d)
                *d = uapi16_directory_free(*d);
}

static inline void uapi16_data_check_freep(uapi16_data_check **c) {
        if (*c)
                *c = uapi16_data_check_free(*c);
}

#endif /* UAPI16_H */
