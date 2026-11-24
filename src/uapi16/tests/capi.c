/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Tests the C API of uapi16 through uapi16.h, against the shared or the
 * static library it is linked with. tests/capi.sh builds and runs it.
 *
 * It makes its trees in a directory of its own below TMPDIR, or below /tmp
 * where that is not set.
 *
 * A test declares its descriptors before the objects it makes from them,
 * so that a descriptor is closed after every object that was given it is
 * freed, and does not read from or write to one while such an object is
 * there.
 */

#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64

#include <dirent.h>
#include <endian.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <pthread.h>
#include <pwd.h>
#include <sched.h>
#include <semaphore.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))
#define ELEMENTSOF(x) (sizeof(x) / sizeof((x)[0]))

/* What a manifest starts every record with, and the records a test writes
 * itself: a root that declares the code point order and one that declares
 * none, a file object that has a name and nothing else, a signature object
 * that has a mechanism and nothing else, and the trailer. */
#define RECORD_SEPARATOR '\x1e'
#define RS "\x1e"
#define ROOT RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"order\":\"codepoint\"}\n"
#define ROOT_WITHOUT_ORDER RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n"
#define FILE_OBJECT(name) RS "{\"name\":\"" name "\"}\n"
#define SIGNATURE_OBJECT(mechanism)                                                                \
        RS "{\"mechanism\":\"" mechanism "\",\"mediaType\":\"application/vnd.uapi.16.signature\"}\n"
#define TRAILER RS "{\"mediaType\":\"application/vnd.uapi.16.trailer\"}\n"

/* The longest name of a file in a directory, and of a file object. */
#define COMPONENT_MAX 255
#define NAME_OF_OBJECT_MAX 4095

/* The largest record of a manifest, and the size of a value of an extended
 * attribute that is small enough for Btrfs and XFS. */
#define RECORD_MAX (4 * 1024 * 1024)
#define XATTR_VALUE_SIZE 8192

/* The most data a regular file is hashed with: 1 TiB. */
#define HASHED_MAX (UINT64_C(1) << 40)

/* A directory on a tmpfs, which takes that many extended attributes since
 * Linux 6.6, and a directory of a test in it. */
#define MEMORY_DIR "/dev/shm"
#define MEMORY_TEMPLATE MEMORY_DIR "/uapi16-capi-XXXXXX"

/* How many descriptors the process may have open in the test that leaves
 * it none: few enough to open them all. */
#define DESCRIPTORS_MAX 64

/* What a child exits with that could not do what it is for. */
#define EXIT_SKIPPED 77

/* How much a pipe has room for at least: a page. A test that fills a pipe
 * before anything reads from it puts in no more. */
#define PIPE_ROOM 4096

/* The default features, which a manifest that lists none records: to put
 * into a list. */
#define DEFAULT_FEATURES                                                                           \
        UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID, UAPI16_FEATURE_SIZE,          \
                UAPI16_FEATURE_SHA256, UAPI16_FEATURE_SYMLINK, UAPI16_FEATURE_DEVICE,              \
                UAPI16_FEATURE_HARDLINK

/* The first and the last feature of a tree of files, the first and the last
 * feature of partitions, and the first number that is no feature. */
#define FIRST_FEATURE_OF_TREES UAPI16_FEATURE_MODE
#define LAST_FEATURE_OF_TREES UAPI16_FEATURE_FAT_SERIAL
#define FIRST_FEATURE_OF_PARTITIONS UAPI16_FEATURE_GPT_LABEL
#define LAST_FEATURE_OF_PARTITIONS UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM
#define NO_FEATURE ((uapi16_feature_t) (LAST_FEATURE_OF_PARTITIONS + 1))

/* More numbers than a list of a test has, and than there are features. */
#define FEATURES_MAX 64

/* The Linux inode flags a manifest has, with the bits FS_IOC_GETFLAGS gives
 * them: FS_APPEND_FL, FS_IMMUTABLE_FL, FS_NOATIME_FL, FS_NOCOW_FL and
 * FS_NODUMP_FL of <linux/fs.h>. FS_SYNC_FL is one a manifest does not have. */
#define APPEND_FL UINT32_C(0x00000020)
#define IMMUTABLE_FL UINT32_C(0x00000010)
#define NOATIME_FL UINT32_C(0x00000080)
#define NOCOW_FL UINT32_C(0x00800000)
#define NODUMP_FL UINT32_C(0x00000040)
#define SYNC_FL UINT32_C(0x00000008)
#define INODE_FLAGS (APPEND_FL | IMMUTABLE_FL | NOATIME_FL | NOCOW_FL | NODUMP_FL)

/* The DOS attributes a manifest has a field for, with the bits a directory
 * entry of FAT has for them: hidden, system and archive. Read-only and
 * directory are two it has no such field for. */
#define DOS_HIDDEN UINT32_C(0x02)
#define DOS_SYSTEM UINT32_C(0x04)
#define DOS_ARCHIVE UINT32_C(0x20)
#define DOS_READ_ONLY UINT32_C(0x01)
#define DOS_DIRECTORY UINT32_C(0x10)
#define DOS_ATTRIBUTES (DOS_HIDDEN | DOS_SYSTEM | DOS_ARCHIVE)

/* The SHA-256 hashes of no data, of "abc", of the 56 bytes of FIPS 180-2
 * that take two blocks, of a million times "a", and of the data of the
 * files of the tests. */
#define SHA256_OF_NOTHING "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define SHA256_OF_ABC "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
#define TWO_BLOCKS "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define SHA256_OF_TWO_BLOCKS "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
#define SHA256_OF_A_MILLION_A "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
#define SHA256_OF_HELLO "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
#define SHA256_OF_TWICE "dc8ffdbf2736dbdf39508017ac594e0d069f3eee9b0f29ece256aa7d831f9ef6"

#define check(condition)                                                                           \
        do {                                                                                       \
                if (!(condition)) {                                                                \
                        fprintf(stderr, "%s:%d: %s is false\n", __FILE__, __LINE__, #condition);   \
                        abort();                                                                   \
                }                                                                                  \
        } while (0)

#define check_eq(got, want)                                                                        \
        do {                                                                                       \
                long long got_ = (long long) (got), want_ = (long long) (want);                    \
                if (got_ != want_) {                                                               \
                        fprintf(stderr, "%s:%d: %s is %lld, and %s is %lld\n", __FILE__, __LINE__, \
                                #got, got_, #want, want_);                                         \
                        abort();                                                                   \
                }                                                                                  \
        } while (0)

#define check_str(got, want)                                                                       \
        do {                                                                                       \
                const char *got_ = (got), *want_ = (want);                                         \
                if (!got_ || strcmp(got_, want_) != 0) {                                           \
                        fprintf(stderr, "%s:%d: %s is %s%s%s, and not \"%s\"\n", __FILE__,         \
                                __LINE__, #got, got_ ? "\"" : "", got_ ? got_ : "NULL",            \
                                got_ ? "\"" : "", want_);                                          \
                        abort();                                                                   \
                }                                                                                  \
        } while (0)

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static void freep(void *p) {
        free(*(void **) p);
}

/* The directory the trees of the tests are in, and its path. */
static int tmp_fd = -1;
static char tmp_path[PATH_MAX];

/* What takes a manifest that no test looks at: /dev/null. It is open for
 * as long as the tests run, and so for longer than any writer that is given
 * it. */
static int null_fd = -1;

static int make_dir(int dir_fd, const char *name) {
        int fd;

        check_eq(mkdirat(dir_fd, name, 0755), 0);
        fd = openat(dir_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(fd >= 0);
        return fd;
}

static void make_file(int dir_fd, const char *name, const char *data) {
        _cleanup_(closep) int fd = openat(dir_fd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);

        check(fd >= 0);
        check_eq(write(fd, data, strlen(data)), (ssize_t) strlen(data));
}

/* Removes the directory `name` in `dir_fd` with everything below it. */
static void remove_tree(int dir_fd, const char *name) {
        int fd = openat(dir_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        struct dirent *entry;
        DIR *dir;

        check(fd >= 0);
        dir = fdopendir(fd);
        check(dir);
        while ((entry = readdir(dir))) {
                if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                        continue;
                if (unlinkat(fd, entry->d_name, 0) < 0) {
                        check(errno == EISDIR || errno == EPERM);
                        remove_tree(fd, entry->d_name);
                }
        }
        closedir(dir);
        check_eq(unlinkat(dir_fd, name, AT_REMOVEDIR), 0);
}

/* How many descriptors the process has open. */
static size_t open_descriptors(void) {
        DIR *dir = opendir("/proc/self/fd");
        size_t count = 0;

        check(dir);
        while (readdir(dir))
                count++;
        closedir(dir);
        return count;
}

/* How many entries the directory `name` in `dir_fd` has. */
static size_t count_entries(int dir_fd, const char *name) {
        int fd = openat(dir_fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        struct dirent *entry;
        size_t count = 0;
        DIR *dir;

        check(fd >= 0);
        dir = fdopendir(fd);
        check(dir);
        while ((entry = readdir(dir)))
                if (strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0)
                        count++;
        closedir(dir);
        return count;
}

/* How many bytes the file `fd` holds. */
static size_t size_of(int fd) {
        struct stat st;

        check_eq(fstat(fd, &st), 0);
        return (size_t) st.st_size;
}

/* Everything the file `fd` holds, and how much that is. */
static char *read_all(int fd, size_t *ret_size) {
        size_t size = size_of(fd), done = 0;
        char *data = malloc(size + 1);

        check(data);
        while (done < size) {
                ssize_t n = pread(fd, data + done, size - done, (off_t) done);

                check(n > 0);
                done += (size_t) n;
        }
        data[done] = 0;
        *ret_size = done;
        return data;
}

static char *read_file(int dir_fd, const char *name, size_t *ret_size) {
        _cleanup_(closep) int fd = openat(dir_fd, name, O_RDONLY | O_CLOEXEC);

        check(fd >= 0);
        return read_all(fd, ret_size);
}

/* A file without a name, to write a manifest to. */
static int scratch_file(void) {
        int fd = memfd_create("uapi16-capi", MFD_CLOEXEC);

        check(fd >= 0);
        return fd;
}

/* Makes the file `fd` empty, for the next manifest. */
static void empty(int fd) {
        check_eq(ftruncate(fd, 0), 0);
        check_eq(lseek(fd, 0, SEEK_SET), 0);
}

/* A file without a name that holds `text`, to read a manifest from. */
static int manifest_file(const char *text) {
        int fd = scratch_file();

        check_eq(write(fd, text, strlen(text)), (ssize_t) strlen(text));
        check_eq(lseek(fd, 0, SEEK_SET), 0);
        return fd;
}

/* The end to read from of a pipe that holds `text` and nothing after it. */
static int manifest_pipe(const char *text) {
        int fds[2];

        check(strlen(text) <= PIPE_ROOM);
        check_eq(pipe2(fds, O_CLOEXEC), 0);
        check_eq(write(fds[1], text, strlen(text)), (ssize_t) strlen(text));
        check_eq(close(fds[1]), 0);
        return fds[0];
}

/* A page that can be neither read nor written. A call that is given it with
 * a size of 0 does not look at it. */
static const void *unreadable(void) {
        static void *page;

        if (!page) {
                page = mmap(NULL, (size_t) sysconf(_SC_PAGESIZE), PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
                            -1, 0);
                check(page != MAP_FAILED);
        }
        return page;
}

/* The manifest of the tree `top_fd` as uapi16_manifest_generate() writes it. */
static char *generate(const uapi16_manifest_options *o, int top_fd, uapi16_add_flags_t flags, size_t *ret_size) {
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(closep) int fd = scratch_file();

        check_eq(uapi16_manifest_generate(o, fd, top_fd, flags, &report, &e), 0);
        check(report && !e);
        return read_all(fd, ret_size);
}

/* Checks that the `size` bytes at `data` are the `expected_size` at
 * `expected`. */
static void check_same(const void *data, size_t size, const void *expected, size_t expected_size) {
        check_eq(size, expected_size);
        if (size > 0)
                check_eq(memcmp(data, expected, expected_size), 0);
}

/* Checks that `data` is a whole manifest. */
static void check_manifest(const char *data, size_t size) {
        check(size > strlen(TRAILER));
        check_eq(data[0], RECORD_SEPARATOR);
        check(strstr(data, "\"mediaType\":\"application/vnd.uapi.16.manifest\""));
        check_eq(memcmp(data + size - strlen(TRAILER), TRAILER, strlen(TRAILER)), 0);
}

/* The hash that the hex digits `hex` spell. */
static void unhex(const char *hex, uapi16_sha256_digest_t *ret) {
        check_eq(strlen(hex), 2 * UAPI16_SHA256_SIZE);
        for (size_t i = 0; i < UAPI16_SHA256_SIZE; i++) {
                unsigned byte;

                check_eq(sscanf(hex + 2 * i, "%2x", &byte), 1);
                ret->bytes[i] = (uint8_t) byte;
        }
}

/* Checks that `hash` is what the hex digits `hex` spell. */
static void check_hash(const uapi16_sha256_digest_t *hash, const char *hex) {
        uapi16_sha256_digest_t expected;

        unhex(hex, &expected);
        check_eq(memcmp(hash, &expected, sizeof(expected)), 0);
}

/* A list of features of a test. */
struct features {
        uapi16_feature_t list[FEATURES_MAX];
        size_t n;
};

/* The `n` features at `list` as a list of a test. */
static struct features features_of(const uapi16_feature_t *list, size_t n) {
        struct features features = { .n = n };

        check(n <= FEATURES_MAX);
        if (n > 0)
                memcpy(features.list, list, n * sizeof(*list));
        return features;
}

/* The features that follow as a list of a test. */
#define FEATURES(...) features_of(UAPI16_FEATURES(__VA_ARGS__))

/* The list `features` with the `n` features at `more` behind it. */
static struct features features_with(struct features features, const uapi16_feature_t *more, size_t n) {
        check(n <= FEATURES_MAX - features.n);
        if (n > 0)
                memcpy(features.list + features.n, more, n * sizeof(*more));
        features.n += n;
        return features;
}

/* The list `features` with the features that follow behind it. */
#define WITH(features, ...) features_with(features, UAPI16_FEATURES(__VA_ARGS__))

/* The list `features` without the feature `feature`. */
static struct features features_without(struct features features, uapi16_feature_t feature) {
        for (size_t i = 0; i < features.n; i++)
                if (features.list[i] == feature)
                        features.list[i] = UAPI16_FEATURE_NONE;
        return features;
}

/* The features from `first` to `last`. */
static struct features features_from(uapi16_feature_t first, uapi16_feature_t last) {
        struct features features = { .n = 0 };

        check(first <= last && last - first < FEATURES_MAX);
        for (uapi16_feature_t feature = first; feature <= last; feature++)
                features.list[features.n++] = feature;
        return features;
}

/* Every feature of a tree of files, every feature of partitions, and both. */
#define FEATURES_OF_TREES features_from(FIRST_FEATURE_OF_TREES, LAST_FEATURE_OF_TREES)
#define FEATURES_OF_PARTITIONS features_from(FIRST_FEATURE_OF_PARTITIONS, LAST_FEATURE_OF_PARTITIONS)
#define EVERY_FEATURE features_from(FIRST_FEATURE_OF_TREES, LAST_FEATURE_OF_PARTITIONS)

/* Says in `has` which numbers the list `features` has, and returns how many
 * they are. A feature can be in a list more than once, and
 * UAPI16_FEATURE_NONE is none. */
static size_t features_in(struct features features, bool has[FEATURES_MAX]) {
        size_t count = 0;

        memset(has, 0, FEATURES_MAX * sizeof(*has));
        for (size_t i = 0; i < features.n; i++) {
                uapi16_feature_t feature = features.list[i];

                check(feature < FEATURES_MAX);
                if (feature == UAPI16_FEATURE_NONE || has[feature])
                        continue;
                has[feature] = true;
                count++;
        }
        return count;
}

/* Checks that the lists `a` and `b` have the same features. */
static void check_same_features(struct features a, struct features b) {
        bool in_a[FEATURES_MAX], in_b[FEATURES_MAX];

        check_eq(features_in(a, in_a), features_in(b, in_b));
        check_eq(memcmp(in_a, in_b, sizeof(in_a)), 0);
}

/* Checks that the reader `r` records the features of `expected` and no
 * other: asked one by one, and listed in the order of their numbers, with
 * nothing past the last one. */
static void check_recorded(const uapi16_reader *r, struct features expected) {
        bool wanted[FEATURES_MAX];
        size_t count = features_in(expected, wanted);
        uapi16_feature_t last = UAPI16_FEATURE_NONE;

        for (uapi16_feature_t feature = UAPI16_FEATURE_NONE; feature < FEATURES_MAX; feature++)
                check_eq(uapi16_reader_has_feature(r, feature), wanted[feature]);
        for (size_t i = 0; i < count; i++) {
                uapi16_feature_t feature = uapi16_reader_feature(r, i);

                check(feature > last && feature < FEATURES_MAX && wanted[feature]);
                last = feature;
        }
        check_eq(uapi16_reader_feature(r, count), UAPI16_FEATURE_NONE);
        check_eq(uapi16_reader_feature(r, SIZE_MAX), UAPI16_FEATURE_NONE);
}

/* The same for the features whose fields the object `o` has. */
static void check_stated(const uapi16_file_object *o, struct features expected) {
        bool wanted[FEATURES_MAX];
        size_t count = features_in(expected, wanted);
        uapi16_feature_t last = UAPI16_FEATURE_NONE;

        for (uapi16_feature_t feature = UAPI16_FEATURE_NONE; feature < FEATURES_MAX; feature++)
                check_eq(uapi16_file_object_has_stated_feature(o, feature), wanted[feature]);
        for (size_t i = 0; i < count; i++) {
                uapi16_feature_t feature = uapi16_file_object_stated_feature(o, i);

                check(feature > last && feature < FEATURES_MAX && wanted[feature]);
                last = feature;
        }
        check_eq(uapi16_file_object_stated_feature(o, count), UAPI16_FEATURE_NONE);
        check_eq(uapi16_file_object_stated_feature(o, SIZE_MAX), UAPI16_FEATURE_NONE);
}

/* Checks that the objects `a` and `b` have the fields of the same
 * features. */
static void check_same_stated(const uapi16_file_object *a, const uapi16_file_object *b) {
        uapi16_feature_t feature;
        size_t i = 0;

        do {
                feature = uapi16_file_object_stated_feature(a, i);
                check_eq(uapi16_file_object_stated_feature(b, i), feature);
                i++;
        } while (feature != UAPI16_FEATURE_NONE);
}

/* uapi16_manifest_options_set_features() for a list of a test. */
static int set_features(uapi16_manifest_options *o, struct features features) {
        return uapi16_manifest_options_set_features(o, features.list, features.n);
}

/* uapi16_file_object_retain_features() for a list of a test. */
static int retain_features(uapi16_file_object *o, struct features features) {
        return uapi16_file_object_retain_features(o, features.list, features.n);
}

/*
 * Checks that the call that returned `r` failed with the error `e` of the
 * kind `kind` and the errno `error`, about `path`, and that the error says
 * nothing a caller did not ask to be checked.
 */
#define CHECK_HARDLINK_PATH (1 << 0)
#define CHECK_FEATURE (1 << 1)
#define CHECK_NAME (1 << 2)
#define CHECK_FIELD (1 << 3)
#define CHECK_RECORD (1 << 4)
#define CHECK_PROBLEM (1 << 5)
static void check_error(int r, const uapi16_error *e, uapi16_error_kind_t kind, int error, const char *path,
                        unsigned other) {
        size_t size = 1;

        check_eq(r, -error);
        check(e);
        check_eq(uapi16_error_kind(e), kind);
        check_eq(uapi16_error_errno(e), error);
        if (path)
                check_str(uapi16_error_path(e), path);
        else
                check(!uapi16_error_path(e));
        if (!(other & CHECK_HARDLINK_PATH))
                check(!uapi16_error_hardlink_path(e));
        if (!(other & CHECK_FEATURE))
                check_eq(uapi16_error_feature(e), UAPI16_FEATURE_NONE);
        if (!(other & CHECK_NAME)) {
                check_eq(uapi16_error_name_problem(e), 0);
                check(!uapi16_error_raw_name(e, &size));
                check_eq(size, 0);
        }
        if (!(other & CHECK_FIELD))
                check(!uapi16_error_field(e));
        if (!(other & CHECK_RECORD)) {
                uint64_t record = 77;

                check_eq(uapi16_error_record(e, &record), -ENODATA);
                check_eq(record, 77);
        }
        if (!(other & CHECK_PROBLEM))
                check(!uapi16_error_problem(e));
}

/* Checks that the error `e` is about the record `record` of a manifest,
 * of which the root is record 0. */
static void check_record(const uapi16_error *e, uint64_t record) {
        uint64_t got = UINT64_MAX;

        check_eq(uapi16_error_record(e, &got), 0);
        check_eq(got, record);
}

/* What a call with something missing or unknown fails with. */
static void check_misuse(int r, uapi16_error **e, int error) {
        check_error(r, *e, UAPI16_ERROR_INVALID_ARGUMENT, error, NULL, 0);
        *e = uapi16_error_free(*e);
        check(!*e);
}

/* What a call fails with on an object that takes nothing more. */
static void check_ended(int r, uapi16_error **e) {
        check_error(r, *e, UAPI16_ERROR_ENDED, ESTALE, NULL, 0);
        *e = uapi16_error_free(*e);
        check(!*e);
}

/*
 * What a call fails with that a manifest or a file object is refused by: an
 * error of the kind UAPI16_ERROR_MANIFEST that names the rule `problem`. It
 * is about the file `path`, or about no file, and about the field `field`,
 * or about no field.
 */
static void check_refused(int r, uapi16_error **e, const char *problem, const char *path,
                          const char *field) {
        check_error(r, *e, UAPI16_ERROR_MANIFEST, EBADMSG, path, CHECK_FIELD | CHECK_RECORD | CHECK_PROBLEM);
        check_str(uapi16_error_problem(*e), problem);
        if (field)
                check_str(uapi16_error_field(*e), field);
        else
                check(!uapi16_error_field(*e));
        *e = uapi16_error_free(*e);
        check(!*e);
}

/*
 * A tree with a directory, files, a hard link, a symbolic link and a FIFO:
 * three regular files of 5 bytes each, two directories with the root, and
 * two other files.
 */
static int make_tree(const char *name) {
        int fd = make_dir(tmp_fd, name);
        _cleanup_(closep) int a = make_dir(fd, "a");

        make_file(a, "file", "hello");
        make_file(fd, "linked", "twice");
        check_eq(linkat(fd, "linked", a, "linked-too", 0), 0);
        check_eq(symlinkat("a", fd, "link"), 0);
        check_eq(mkfifoat(fd, "fifo", 0600), 0);
        return fd;
}

/* A file object for `name` that says nothing else. */
static uapi16_file_object *make_object(const char *name) {
        uapi16_file_object *o = NULL;

        check_eq(uapi16_file_object_new(name, &o, NULL), 0);
        check(o);
        return o;
}

/* A file object for the regular file `name` with the data "hello": its size
 * and its hash. */
static uapi16_file_object *make_hello(const char *name) {
        uapi16_file_object *o = make_object(name);
        uapi16_sha256_digest_t hash;

        unhex(SHA256_OF_HELLO, &hash);
        check_eq(uapi16_file_object_set_size(o, strlen("hello")), 0);
        check_eq(uapi16_file_object_set_sha256(o, &hash), 0);
        return o;
}

/* A writer for the options `o`, which writes nowhere a test looks. */
static uapi16_manifest_writer *open_writer(const uapi16_manifest_options *o) {
        uapi16_manifest_writer *w = NULL;

        check_eq(uapi16_manifest_writer_open(o, null_fd, &w, NULL), 0);
        check(w);
        return w;
}

/* Finishes the writer `w` and checks how many regular files, directories
 * and other files it lists. */
static void check_listed(uapi16_manifest_writer *w, uint64_t files, uint64_t directories, uint64_t others) {
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;

        check_eq(uapi16_manifest_writer_finish(w, &report, NULL), 0);
        check_eq(uapi16_manifest_report_files(report), files);
        check_eq(uapi16_manifest_report_directories(report), directories);
        check_eq(uapi16_manifest_report_others(report), others);
}

/* A reader of the manifest the file `fd` holds, from its start. Whoever
 * calls this leaves `fd` alone until the reader is freed. */
static uapi16_reader *open_reader(int fd) {
        uapi16_reader *reader = NULL;

        check_eq(lseek(fd, 0, SEEK_SET), 0);
        check_eq(uapi16_reader_open(fd, &reader, NULL), 0);
        check(reader);
        return reader;
}

/* The next file object of `reader`, which has the name `name`. */
static uapi16_file_object *next_object(uapi16_reader *reader, const char *name) {
        uapi16_file_object *o = NULL;

        check_eq(uapi16_reader_next(reader, &o, NULL), UAPI16_READ_FILE);
        check(o);
        check_str(uapi16_file_object_name(o), name);
        return o;
}

/* Checks that the manifest of `reader` ends here, without signature
 * objects. */
static void check_ends(uapi16_reader *reader) {
        uapi16_file_object *o = NULL;

        check_eq(uapi16_reader_next(reader, &o, NULL), UAPI16_READ_END);
}

/* A writer of records for the options `o` that writes to `fd`, with a root
 * that says nothing. Whoever calls this leaves `fd` alone until the writer
 * is freed, but for looking at its size. */
static uapi16_writer *begin_records(const uapi16_manifest_options *o, int fd) {
        uapi16_writer *w = NULL;

        check_eq(uapi16_writer_begin(o, fd, NULL, &w, NULL), 0);
        check(w);
        return w;
}

/* The example of the description of the API: the manifest of a directory
 * in a new file. */
static int example(int out_dir_fd, int esp_fd, uint64_t *ret_files) {
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        int r;

        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME));
        if (r < 0)
                return r;

        r = uapi16_manifest_generate_at(o, out_dir_fd, "esp.manifest", esp_fd, UAPI16_ADD_NONE, &report, &e);
        if (r < 0) {
                fprintf(stderr, "Failed to write the manifest, at '%s' in the tree: %s\n",
                        uapi16_error_path(e) ? uapi16_error_path(e) : "n/a", strerror(-r));
                return r;
        }

        /* A call that succeeds leaves reterr alone. */
        check(!e);
        *ret_files = uapi16_manifest_report_files(report);
        return 0;
}

static void test_example(void) {
        _cleanup_(closep) int tree = make_tree("example"), out = make_dir(tmp_fd, "example-out");
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(freep) char *created = NULL, *streamed = NULL, *again = NULL;
        size_t created_size, streamed_size, again_size;
        uint64_t files = 0;

        check_eq(example(out, tree, &files), 0);
        check_eq(files, 3);
        created = read_file(out, "esp.manifest", &created_size);
        check_manifest(created, created_size);
        check(strstr(created, "\"name\":\"a/linked-too\""));
        check(strstr(created, "\"mTimeNSec\""));

        /* The same manifest goes to a descriptor, and to a new file again. */
        check(o);
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME)), 0);
        check_eq(uapi16_manifest_options_set_order(o, UAPI16_ORDER_CODEPOINT), 0);
        streamed = generate(o, tree, UAPI16_ADD_NONE, &streamed_size);
        check_same(streamed, streamed_size, created, created_size);
        check_eq(uapi16_manifest_generate_at(o, out, "again", tree, UAPI16_ADD_NONE, &report, NULL), 0);
        check_eq(uapi16_manifest_report_files(report), 3);
        again = read_file(out, "again", &again_size);
        check_same(again, again_size, created, created_size);

        /* A caller that does not want the report passes no place for it. */
        {
                _cleanup_(closep) int fd = scratch_file();
                _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
                _cleanup_(freep) char *generated = NULL, *generated_at = NULL;
                size_t size;

                check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, NULL, &e), 0);
                generated = read_all(fd, &size);
                check_same(generated, size, created, created_size);

                check_eq(uapi16_manifest_generate_at(o, out, "unreported", tree, UAPI16_ADD_NONE, NULL, NULL), 0);
                generated_at = read_file(out, "unreported", &size);
                check_same(generated_at, size, created, created_size);
                check(!e);
        }

        /* A new file that is synced holds the same manifest. Only the
         * calls that make a new file sync: with the options set, a
         * manifest goes to a descriptor as before. */
        {
                _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
                _cleanup_(freep) char *generated_at = NULL, *generated = NULL;
                size_t size;

                check_eq(uapi16_manifest_options_set_sync(o, true), 0);
                check_eq(uapi16_manifest_generate_at(o, out, "synced", tree, UAPI16_ADD_NONE, NULL, &e), 0);
                generated_at = read_file(out, "synced", &size);
                check_same(generated_at, size, created, created_size);

                generated = generate(o, tree, UAPI16_ADD_NONE, &size);
                check_same(generated, size, created, created_size);
                check_eq(uapi16_manifest_options_set_sync(o, false), 0);
                check(!e);
        }

        /* The file is made with the mode of any new file: read and write
         * for everybody, less what the umask takes away. */
        _cleanup_(closep) int plain_fd = openat(out, "plain", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
        struct stat made, plain;
        check(plain_fd >= 0);
        check_eq(fstatat(out, "again", &made, 0), 0);
        check_eq(fstat(plain_fd, &plain), 0);
        check_eq(made.st_mode, plain.st_mode);
}

static void test_report(void) {
        _cleanup_(closep) int tree = make_tree("report"), fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL, *skipped = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *listed = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("d/file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *alias = make_object("alias");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        struct timespec times[2] = { { .tv_sec = -1 }, { .tv_sec = -1 } };

        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 3);
        check_eq(uapi16_manifest_report_directories(report), 2);
        check_eq(uapi16_manifest_report_others(report), 2);
        check_eq(uapi16_manifest_report_bytes(report), 15);
        check_eq(uapi16_manifest_report_entries_omitted(report), 0);
        check_eq(uapi16_manifest_report_fields_omitted(report), 0);

        /* What is left out is counted: a name with a control character, and
         * a modification time before 1970. */
        make_file(tree, "\001control", "");
        check_eq(utimensat(tree, "a/file", times, 0), 0);
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME)), 0);
        empty(fd);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_GRACEFUL, &skipped, &e), 0);
        check_eq(uapi16_manifest_report_files(skipped), 3);
        check_eq(uapi16_manifest_report_entries_omitted(skipped), 1);
        check_eq(uapi16_manifest_report_fields_omitted(skipped), 1);

        /* The report of file objects counts each of them: two names of one
         * file are two files with the data of each, and the directory that
         * was not added and the root are directories. */
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES)), 0);
        w = open_writer(o);
        check_eq(uapi16_file_object_set_inode_token(file, 1), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);
        check_eq(uapi16_file_object_set_name(file, "other", &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);
        check_eq(uapi16_file_object_set_type(alias, S_IFLNK), 0);
        check_eq(uapi16_file_object_set_target(alias, "d", 1), 0);
        check_eq(uapi16_manifest_writer_add_object(w, alias, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, &listed, &e), 0);
        check_eq(uapi16_manifest_report_files(listed), 2);
        check_eq(uapi16_manifest_report_directories(listed), 2);
        check_eq(uapi16_manifest_report_others(listed), 1);
        check_eq(uapi16_manifest_report_bytes(listed), 10);
        check_eq(uapi16_manifest_report_entries_omitted(listed), 0);
        check_eq(uapi16_manifest_report_fields_omitted(listed), 0);
        check(!e);

        /* No report counts nothing. */
        check_eq(uapi16_manifest_report_files(NULL), 0);
        check_eq(uapi16_manifest_report_directories(NULL), 0);
        check_eq(uapi16_manifest_report_others(NULL), 0);
        check_eq(uapi16_manifest_report_bytes(NULL), 0);
        check_eq(uapi16_manifest_report_entries_omitted(NULL), 0);
        check_eq(uapi16_manifest_report_fields_omitted(NULL), 0);

        /* Freeing returns NULL, and takes NULL. */
        report = uapi16_manifest_report_free(report);
        check(!report);
        check(!uapi16_manifest_report_free(NULL));
}

static void test_options(void) {
        static const uapi16_feature_t for_partitions[] = {
                UAPI16_FEATURE_GPT_LABEL,     UAPI16_FEATURE_GPT_UUID,  UAPI16_FEATURE_GPT_TYPE_UUID,
                UAPI16_FEATURE_GPT_DISK_UUID, UAPI16_FEATURE_GPT_FLAGS, UAPI16_FEATURE_GPT_FLAG_NO_AUTO,
                UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM,
        };
        static const uint64_t no_orders[] = { 2, 3, UINT64_C(1) << 63, UINT64_MAX };
        _cleanup_(closep) int tree = make_tree("options"), out = make_dir(tmp_fd, "options-out");
        _cleanup_(closep) int fd = scratch_file(), written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *kept = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file");
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        struct features all = FEATURES(UAPI16_FEATURE_NONE);
        struct stat st;

        check(o);

        /* Every feature is taken, and a number that is none is not. */
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(set_features(o, EVERY_FEATURE), 0);
        check_eq(set_features(o, FEATURES(NO_FEATURE)), -EINVAL);
        check_eq(set_features(o, FEATURES(UINT64_C(1) << 63)), -EINVAL);
        check_eq(set_features(o, FEATURES(UINT64_MAX)), -EINVAL);
        check_eq(set_features(NULL, FEATURES(DEFAULT_FEATURES)), -EINVAL);

        /* The code point order is the only order. No order is taken too,
         * for a manifest that declares none, which test_no_order() writes.
         * Any other number is no order. */
        check_eq(uapi16_manifest_options_set_order(o, UAPI16_ORDER_NONE), 0);
        check_eq(uapi16_manifest_options_set_order(o, UAPI16_ORDER_CODEPOINT), 0);
        for (size_t i = 0; i < ELEMENTSOF(no_orders); i++)
                check_eq(uapi16_manifest_options_set_order(o, no_orders[i]), -EINVAL);
        check_eq(uapi16_manifest_options_set_order(NULL, UAPI16_ORDER_CODEPOINT), -EINVAL);
        check_eq(uapi16_manifest_options_set_order(NULL, UAPI16_ORDER_NONE), -EINVAL);

        /* Syncing is turned on and off. */
        check_eq(uapi16_manifest_options_set_sync(o, true), 0);
        check_eq(uapi16_manifest_options_set_sync(o, false), 0);
        check_eq(uapi16_manifest_options_set_sync(NULL, true), -EINVAL);

        /* The features of partitions are no features of a tree: nothing is
         * made for them, and the error says which one it is. */
        for (size_t i = 0; i < ELEMENTSOF(for_partitions); i++) {
                uapi16_manifest_writer *w = NULL;
                uapi16_manifest_report *report = NULL;
                uapi16_error *e = NULL;
                int r;

                all = WITH(all, for_partitions[i]);
                r = set_features(o, FEATURES(DEFAULT_FEATURES, for_partitions[i]));
                check_eq(r, 0);

                r = uapi16_manifest_writer_create_at(o, out, "m", &w, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
                check_eq(uapi16_error_feature(e), for_partitions[i]);
                e = uapi16_error_free(e);
                check(!e);

                r = uapi16_manifest_writer_open(o, fd, &w, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
                check_eq(uapi16_error_feature(e), for_partitions[i]);
                e = uapi16_error_free(e);

                r = uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, &report, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
                check_eq(uapi16_error_feature(e), for_partitions[i]);
                e = uapi16_error_free(e);

                r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
                check_eq(uapi16_error_feature(e), for_partitions[i]);
                e = uapi16_error_free(e);

                check(!w && !report);
        }
        check_same_features(all, FEATURES_OF_PARTITIONS);
        check_eq(fstatat(out, "m", &st, 0), -1);
        check_eq(size_of(fd), 0);

        /* A writer that was made with options does not need them any more,
         * and neither does a writer of records: both write what the options
         * said when they were made. */
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256)), 0);
        check_eq(uapi16_manifest_writer_open(o, fd, &kept, NULL), 0);
        records = begin_records(o, written);
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_MODE)), 0);
        o = uapi16_manifest_options_free(o);
        check(!o);
        check_eq(uapi16_manifest_writer_add_object(kept, file, NULL), 0);
        check_eq(uapi16_manifest_writer_finish(kept, NULL, NULL), 0);
        check_eq(uapi16_writer_file(records, file, NULL), 0);
        check_eq(uapi16_writer_finish(records, NULL), 0);
        kept = uapi16_manifest_writer_free(kept);
        records = uapi16_writer_free(records);
        reader = open_reader(fd);
        check_recorded(reader, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256));
        reader = uapi16_reader_free(reader);
        reader = open_reader(written);
        check_recorded(reader, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256));

        /* Freeing returns NULL, and takes NULL. */
        check(!uapi16_manifest_options_free(NULL));
}

static void test_misuse(void) {
        static const uint64_t no_flags[] = { UINT64_C(1) << 2, UINT64_C(1) << 3, UINT64_C(1) << 63,
                                             UINT64_MAX };
        static const uapi16_add_flags_t both = UAPI16_ADD_CROSS_MOUNTS | UAPI16_ADD_GRACEFUL;
        static const int no_descriptors[] = { -1, AT_FDCWD, INT_MIN };
        _cleanup_(closep) int tree = make_tree("misuse"), out = make_dir(tmp_fd, "misuse-out");
        _cleanup_(closep) int fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("a/file");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uint64_t record = 77;
        size_t size = 1;

        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);
        check(w && !e);

        /* An object that is NULL, with a place for the error and without. */
        check_misuse(uapi16_manifest_writer_create_at(NULL, out, "m", &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_open(NULL, fd, &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_add_object(NULL, file, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_add_object(w, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_finish(NULL, &report, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_generate_at(NULL, out, "m", tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_generate(NULL, fd, tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);
        check_eq(uapi16_manifest_writer_create_at(NULL, out, "m", &none, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_open(NULL, fd, &none, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_add_object(NULL, file, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_add_object(w, NULL, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_finish(NULL, &report, NULL), -EINVAL);
        check_eq(uapi16_manifest_generate_at(NULL, out, "m", tree, UAPI16_ADD_NONE, &report, NULL), -EINVAL);
        check_eq(uapi16_manifest_generate(NULL, fd, tree, UAPI16_ADD_NONE, &report, NULL), -EINVAL);

        /* No place for the writer a call makes, and no name. */
        check_misuse(uapi16_manifest_writer_create_at(o, out, "m", NULL, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_open(o, fd, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_create_at(o, out, NULL, &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_generate_at(o, out, NULL, tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);

        /* Flags that are none: every bit but the two of the flags, also
         * the one after them. The two can be given together. */
        for (size_t i = 0; i < ELEMENTSOF(no_flags); i++) {
                uint64_t no = no_flags[i];

                check_misuse(uapi16_manifest_generate_at(o, out, "m", tree, no, &report, &e), &e, EINVAL);
                check_misuse(uapi16_manifest_generate(o, fd, tree, no, &report, &e), &e, EINVAL);
        }

        /* A negative number is no descriptor, AT_FDCWD neither. */
        for (size_t i = 0; i < ELEMENTSOF(no_descriptors); i++) {
                int no = no_descriptors[i];

                check_misuse(uapi16_manifest_writer_create_at(o, no, "m", &none, &e), &e, EBADF);
                check_misuse(uapi16_manifest_writer_open(o, no, &none, &e), &e, EBADF);
                check_misuse(uapi16_manifest_generate_at(o, no, "m", tree, UAPI16_ADD_NONE, &report, &e), &e, EBADF);
                check_misuse(uapi16_manifest_generate_at(o, out, "m", no, UAPI16_ADD_NONE, &report, &e), &e, EBADF);
                check_misuse(uapi16_manifest_generate(o, no, tree, UAPI16_ADD_NONE, &report, &e), &e, EBADF);
                check_misuse(uapi16_manifest_generate(o, fd, no, UAPI16_ADD_NONE, &report, &e), &e, EBADF);
        }
        check(!none && !report);

        /* None of that made a file or wrote anything, and none of it ended
         * the writer. Once it is finished, it takes nothing more. */
        struct stat st;
        check_eq(fstatat(out, "m", &st, 0), -1);
        check_eq(size_of(fd), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(uapi16_manifest_report_directories(report), 2);
        check(size_of(fd) > 0);
        report = uapi16_manifest_report_free(report);
        check_ended(uapi16_manifest_writer_add_object(w, file, &e), &e);
        check_ended(uapi16_manifest_writer_finish(w, &report, &e), &e);
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), -ESTALE);
        check_eq(uapi16_manifest_writer_finish(w, NULL, NULL), -ESTALE);
        check(!report);
        /* A call that is not valid fails for that still. */
        check_misuse(uapi16_manifest_writer_add_object(w, NULL, &e), &e, EINVAL);
        w = uapi16_manifest_writer_free(w);

        /* The two flags together, on a manifest that goes to a descriptor
         * and on one that goes to a new file. */
        empty(fd);
        check_eq(uapi16_manifest_generate(o, fd, tree, both, &report, &e), 0);
        report = uapi16_manifest_report_free(report);
        check_eq(uapi16_manifest_generate_at(o, out, "both", tree, both, &report, &e), 0);
        check(!e);

        /* No error says nothing. */
        check_eq(uapi16_error_kind(NULL), 0);
        check_eq(uapi16_error_errno(NULL), 0);
        check(!uapi16_error_path(NULL));
        check(!uapi16_error_hardlink_path(NULL));
        check_eq(uapi16_error_feature(NULL), UAPI16_FEATURE_NONE);
        check(!uapi16_error_raw_name(NULL, &size));
        check_eq(size, 0);
        check(!uapi16_error_raw_name(NULL, NULL));
        check_eq(uapi16_error_name_problem(NULL), 0);
        check(!uapi16_error_field(NULL));
        check_eq(uapi16_error_record(NULL, &record), -EINVAL);
        check_eq(record, 77);
        check(!uapi16_error_problem(NULL));
        check(!uapi16_error_free(NULL));
        check(!uapi16_manifest_writer_free(NULL));
}

/*
 * What the walk of the generate functions records of a tree: every file
 * below its top in the order of the manifest, a symbolic link with its
 * target and without what it leads to, the names of one file as such, and
 * what the features ask for.
 */
static void test_walk(void) {
        static const char *const names[] = { "a", "a/file", "a/linked-too", "fifo", "link", "linked" };
        static const uapi16_add_flags_t both = UAPI16_ADD_CROSS_MOUNTS | UAPI16_ADD_GRACEFUL;
        static const struct timespec times[2] = {
                { .tv_sec = 1234567890, .tv_nsec = 123456789 },
                { .tv_sec = 1234567890, .tv_nsec = 123456789 },
        };
        _cleanup_(closep) int tree = make_tree("walk"), fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *plain = NULL, *flagged = NULL;
        const uapi16_file_object *root;
        struct features features;
        uapi16_inode_token_t linked = UAPI16_INODE_TOKEN_NONE;
        size_t plain_size, flagged_size;
        struct stat st;

        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        report = uapi16_manifest_report_free(report);
        reader = open_reader(fd);
        check_recorded(reader, FEATURES(DEFAULT_FEATURES));
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);

        /* The top of the tree is the root, with what stat() says of it. */
        root = uapi16_reader_root(reader);
        check_eq(fstat(tree, &st), 0);
        check_str(uapi16_file_object_name(root), "");
        check_eq(uapi16_file_object_type(root), S_IFDIR);
        {
                uint32_t mode = 0, uid = 0, gid = 0;

                check_eq(uapi16_file_object_mode(root, &mode), 0);
                check_eq(mode, st.st_mode & 07777);
                check_eq(uapi16_file_object_uid(root, &uid), 0);
                check_eq(uid, st.st_uid);
                check_eq(uapi16_file_object_gid(root, &gid), 0);
                check_eq(gid, st.st_gid);
        }

        /* Every file below it follows, in the order of the manifest: a
         * directory right before what is in it. */
        for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = next_object(reader, names[i]);
                uapi16_sha256_digest_t hash;
                uapi16_inode_token_t token = 77;
                uint64_t size = 77;
                uint32_t mode = 0;
                const void *target;
                size_t target_size = 1;

                if (i > 0)
                        check_eq(uapi16_name_compare(names[i - 1], names[i]), UAPI16_NAME_BEFORE);
                check_eq(fstatat(tree, names[i], &st, AT_SYMLINK_NOFOLLOW), 0);
                check_eq(uapi16_file_object_type(file), st.st_mode & S_IFMT);

                switch (st.st_mode & S_IFMT) {
                case S_IFREG:
                        /* A regular file has its size and the hash of its
                         * data, which is in the file of its name. */
                        check_eq(uapi16_file_object_size(file, &size), 0);
                        check_eq(size, 5);
                        check_eq(uapi16_file_object_sha256(file, &hash), 0);
                        check_hash(&hash, st.st_nlink > 1 ? SHA256_OF_TWICE : SHA256_OF_HELLO);
                        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_EXTERNAL);
                        check(!uapi16_file_object_literal(file, NULL));
                        break;
                case S_IFLNK:
                        /* A symbolic link is recorded with its target, and
                         * is not followed: nothing is listed below it. It
                         * has no access mode. */
                        target = uapi16_file_object_literal(file, &target_size);
                        check(target);
                        check_same(target, target_size, "a", 1);
                        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_LITERAL);
                        check_eq(uapi16_file_object_size(file, &size), 0);
                        check_eq(size, 1);
                        check_eq(uapi16_file_object_mode(file, &mode), -ENODATA);
                        break;
                default:
                        /* A directory and a FIFO have no data. */
                        check_eq(uapi16_file_object_size(file, &size), -ENODATA);
                        check_eq(uapi16_file_object_sha256(file, &hash), -ENODATA);
                        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_NONE);
                        break;
                }
                if (!S_ISLNK(st.st_mode)) {
                        check_eq(uapi16_file_object_mode(file, &mode), 0);
                        check_eq(mode, st.st_mode & 07777);
                }

                /* The two names of one file carry one token, and no other
                 * file has one. */
                if (!S_ISDIR(st.st_mode) && st.st_nlink > 1) {
                        check_eq(uapi16_file_object_inode_token(file, &token), 0);
                        check(token != UAPI16_INODE_TOKEN_NONE);
                        check(linked == UAPI16_INODE_TOKEN_NONE || linked == token);
                        linked = token;
                } else {
                        check_eq(uapi16_file_object_inode_token(file, &token), -ENODATA);
                        check_eq(token, 77);
                }
        }
        check_ends(reader);
        check(linked != UAPI16_INODE_TOKEN_NONE);
        reader = uapi16_reader_free(reader);

        /* The two flags change nothing for a tree without mount points and
         * without names a manifest can't hold. */
        plain = read_all(fd, &plain_size);
        flagged = generate(o, tree, both, &flagged_size);
        check_same(flagged, flagged_size, plain, plain_size);

        /* A manifest that records nothing has the names and the types of
         * the files, and nothing else: no target of a symbolic link, and no
         * token. */
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_NONE)), 0);
        empty(fd);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_bytes(report), 15);
        report = uapi16_manifest_report_free(report);
        reader = open_reader(fd);
        check_recorded(reader, FEATURES(UAPI16_FEATURE_NONE));
        check_stated(uapi16_reader_root(reader), FEATURES(UAPI16_FEATURE_NONE));
        for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = next_object(reader, names[i]);

                check_eq(fstatat(tree, names[i], &st, AT_SYMLINK_NOFOLLOW), 0);
                check_eq(uapi16_file_object_type(file), st.st_mode & S_IFMT);
                check_stated(file, FEATURES(UAPI16_FEATURE_NONE));
                check(!uapi16_file_object_literal(file, NULL));
        }
        check_ends(reader);
        reader = uapi16_reader_free(reader);

        /* The modification time, as stat() has it, and the name of the
         * owner as the user database has it, or none where it does not have
         * one, which the report counts. */
        features = FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME, UAPI16_FEATURE_USER_NAME);
        check_eq(utimensat(tree, "a/file", times, 0), 0);
        check_eq(fstatat(tree, "a/file", &st, 0), 0);
        check_eq(st.st_mtim.tv_sec, times[1].tv_sec);
        check_eq(set_features(o, features), 0);
        empty(fd);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        reader = open_reader(fd);
        check_recorded(reader, features);
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *a = next_object(reader, "a");
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = next_object(reader, "a/file");
                const struct passwd *owner = getpwuid(getuid());
                uint64_t mtime = 0;

                check_eq(uapi16_file_object_mtime_nsec(file, &mtime), 0);
                check_eq(mtime, (uint64_t) st.st_mtim.tv_sec * UINT64_C(1000000000) +
                                        (uint64_t) st.st_mtim.tv_nsec);
                if (owner) {
                        check_str(uapi16_file_object_user_name(file), owner->pw_name);
                        check_eq(uapi16_manifest_report_fields_omitted(report), 0);
                } else {
                        check(!uapi16_file_object_user_name(file));
                        check(uapi16_manifest_report_fields_omitted(report) > 0);
                }
                check(!uapi16_file_object_group_name(file));
        }
        check(!e);
}

/*
 * The extended attributes of the user namespace, which the walk records
 * where the manifest has the feature: the names without "user." in front,
 * in their order, and the values as the bytes they are. A file without any
 * lists none. Where the file system of the temporary directory has no such
 * attributes, there is nothing to test.
 */
static void test_walk_xattrs(void) {
        static const char binary[] = { 'b', 0, (char) 0xff };
        _cleanup_(closep) int tree = make_dir(tmp_fd, "xattrs"), fd = scratch_file(), file = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *with = NULL, *without = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const char *name = NULL;
        const void *value = NULL;
        size_t count = 77, size = 77;
        int r;

        make_file(tree, "with", "");
        make_file(tree, "without", "");
        file = openat(tree, "with", O_RDONLY | O_CLOEXEC);
        check(file >= 0);
        if (fsetxattr(file, "user.text", "a value", 7, 0) < 0) {
                fprintf(stderr, "skipping the extended attributes of a tree: %s\n", strerror(errno));
                return;
        }
        check_eq(fsetxattr(file, "user.binary", binary, sizeof(binary), 0), 0);
        check_eq(fsetxattr(file, "user.empty", "", 0, 0), 0);

        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_USER_XATTR));
        check_eq(r, 0);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, NULL, &e), 0);
        reader = open_reader(fd);
        check_eq(uapi16_file_object_user_xattrs(uapi16_reader_root(reader), &count), 0);
        check_eq(count, 0);

        with = next_object(reader, "with");
        check_eq(uapi16_file_object_user_xattrs(with, &count), 0);
        check_eq(count, 3);
        check_eq(uapi16_file_object_user_xattr(with, 0, &name, &value, &size), 0);
        check_str(name, "binary");
        check_same(value, size, binary, sizeof(binary));
        check_eq(uapi16_file_object_user_xattr(with, 1, &name, &value, &size), 0);
        check_str(name, "empty");
        check_eq(size, 0);
        check_eq(uapi16_file_object_user_xattr(with, 2, &name, &value, &size), 0);
        check_str(name, "text");
        check_same(value, size, "a value", 7);
        check(uapi16_file_object_has_stated_feature(with, UAPI16_FEATURE_USER_XATTR));

        /* The file without any lists none, which the manifest says by its
         * feature: the object has no field for it. */
        without = next_object(reader, "without");
        count = 77;
        check_eq(uapi16_file_object_user_xattrs(without, &count), 0);
        check_eq(count, 0);
        check(!uapi16_file_object_has_stated_feature(without, UAPI16_FEATURE_USER_XATTR));
        check_ends(reader);
        check(!e);
}

/*
 * A call whose `reterr` points to something is refused before it does
 * anything, by every function that takes a `reterr`, and what is there
 * stays there: an error that was not freed, and what is no error at all,
 * which nothing reads through.
 */
static void test_error_places(void) {
        static max_align_t no_error;
        _cleanup_(closep) int tree = make_tree("places"), out = make_dir(tmp_fd, "places-out");
        _cleanup_(closep) int fd = scratch_file(), written = scratch_file();
        _cleanup_(closep) int manifest =
                manifest_file(ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp") TRAILER);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *no_reader = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL, *no_records = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *labelled = make_object("labelled");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *linked = make_object("linked");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *first = NULL, *no_object = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL, *no_signature = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *directory = NULL, *no_directory = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *data = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *held = NULL;
        uapi16_error *holds[2], *e;
        uint64_t size = 77, offset = 7;
        size_t before, begun;
        int opened = -7;

        check_eq(uapi16_manifest_writer_open(o, fd, &w, NULL), 0);
        reader = open_reader(manifest);
        records = begin_records(o, written);
        begun = size_of(written);
        check_eq(uapi16_signature_new("openpgp", &signature), 0);
        check_eq(uapi16_data_check_new(file, &data), 0);
        check_eq(uapi16_directory_new(tree, UAPI16_DIRECTORY_NONE, &directory, NULL), 0);

        /* The error that is held: that of a file object that a writer
         * refuses for the label of a file system, which only the root has. */
        check_eq(uapi16_file_object_set_fs_label(labelled, "label"), 0);
        check_eq(uapi16_manifest_writer_add_object(w, labelled, &held), -EBADMSG);
        check(held);
        holds[0] = held;
        holds[1] = (uapi16_error *) &no_error;
        before = open_descriptors();

        for (size_t i = 0; i < ELEMENTSOF(holds); i++) {
                e = holds[i];
                check_eq(uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, &report, &e), -EINVAL);
                check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), -EINVAL);
                check_eq(uapi16_manifest_writer_create_at(o, out, "m", &none, &e), -EINVAL);
                check_eq(uapi16_manifest_writer_open(o, fd, &none, &e), -EINVAL);
                check_eq(uapi16_manifest_writer_add_object(w, file, &e), -EINVAL);
                check_eq(uapi16_manifest_writer_finish(w, &report, &e), -EINVAL);
                check_eq(uapi16_reader_open(manifest, &no_reader, &e), -EINVAL);
                check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e), -EINVAL);
                check_eq(uapi16_reader_check_validity(reader, 0, &e), -EINVAL);
                check_eq(uapi16_reader_next(reader, &no_object, &e), -EINVAL);
                check_eq(uapi16_reader_next_signature(reader, &no_signature, &e), -EINVAL);
                check_eq(uapi16_writer_begin(o, fd, NULL, &no_records, &e), -EINVAL);
                check_eq(uapi16_writer_file(records, file, &e), -EINVAL);
                check_eq(uapi16_writer_signature(records, signature, &e), -EINVAL);
                check_eq(uapi16_writer_finish(records, &e), -EINVAL);
                check_eq(uapi16_file_object_new("new", &no_object, &e), -EINVAL);
                check_eq(uapi16_file_object_set_name(file, "renamed", &e), -EINVAL);
                check_eq(uapi16_file_object_set_contents_file(file, "elsewhere", &e), -EINVAL);
                check_eq(uapi16_file_object_check_validity(file, 0, &e), -EINVAL);
                check_eq(uapi16_directory_new(tree, UAPI16_DIRECTORY_NONE, &no_directory, &e), -EINVAL);
                check_eq(uapi16_directory_open_data(directory, linked, &opened, &offset, &e), -EINVAL);
                check_eq(uapi16_data_check_update(data, "hello", 5, &e), -EINVAL);
                check_eq(uapi16_data_check_update_zeros(data, 5, &e), -EINVAL);
                check_eq(uapi16_data_check_finish(data, &size, &e), -EINVAL);
                /* It is refused for that before anything else is looked
                 * at: a negative descriptor fails with EBADF otherwise, and
                 * a name that is none with the rule it breaks. */
                check_eq(uapi16_manifest_writer_open(o, -1, &none, &e), -EINVAL);
                check_eq(uapi16_reader_open(-1, &no_reader, &e), -EINVAL);
                check_eq(uapi16_writer_begin(o, -1, NULL, &no_records, &e), -EINVAL);
                check_eq(uapi16_directory_new(-1, UAPI16_DIRECTORY_NONE, &no_directory, &e), -EINVAL);
                check_eq(uapi16_file_object_new("a//b", &no_object, &e), -EINVAL);
                check(e == holds[i]);
                check(!none && !report && !no_reader && !no_records && !no_object && !no_signature);
                check(!no_directory);
                check_eq(size, 77);
                check_eq(opened, -7);
                check_eq(offset, 7);
        }

        /* The error is the one it was. */
        check_eq(uapi16_error_kind(held), UAPI16_ERROR_MANIFEST);
        check_eq(uapi16_error_errno(held), EBADMSG);
        check_str(uapi16_error_path(held), "labelled");
        check_str(uapi16_error_field(held), "fsLabel");
        check_str(uapi16_error_problem(held), "fieldNotPermitted");

        /* No call made a file, wrote anything or kept a descriptor. */
        check_eq(count_entries(tmp_fd, "places-out"), 0);
        check_eq(size_of(fd), 0);
        check_eq(size_of(written), begun);
        check_eq(open_descriptors(), before);

        /* None changed its object: the file object has its name and its
         * data where they were, and the check has seen none of the data. */
        check_str(uapi16_file_object_name(file), "file");
        check_eq(uapi16_data_check_update(data, "hello", 5, NULL), 0);
        check_eq(uapi16_data_check_finish(data, &size, NULL), 0);
        check_eq(size, 5);

        /* None read anything: the reader hands out its first file object,
         * says that signature objects follow, and hands out the first of
         * them. */
        first = next_object(reader, "a");
        check_eq(uapi16_reader_next(reader, &no_object, NULL), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &no_signature, NULL), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(no_signature), "openpgp");

        /* None added anything to the writer or finished it, and none wrote
         * a record or finished the writer of records. */
        check_listed(w, 0, 1, 0);
        check_eq(uapi16_writer_file(records, file, NULL), 0);
        check_eq(uapi16_writer_finish(records, NULL), 0);

        /* The place is looked at before the object: one that is finished
         * fails for the place as well. */
        e = held;
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), -ESTALE);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), -EINVAL);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), -EINVAL);
        check_eq(uapi16_writer_file(records, file, NULL), -ESTALE);
        check_eq(uapi16_writer_file(records, file, &e), -EINVAL);
        check_eq(uapi16_writer_finish(records, &e), -EINVAL);
        check_eq(uapi16_data_check_update(data, "x", 1, NULL), -ESTALE);
        check_eq(uapi16_data_check_update(data, "x", 1, &e), -EINVAL);
        check_eq(uapi16_data_check_update_zeros(data, 1, NULL), -ESTALE);
        check_eq(uapi16_data_check_update_zeros(data, 1, &e), -EINVAL);
        check_eq(uapi16_data_check_finish(data, NULL, &e), -EINVAL);
        check(e == held && !report);
}

static void test_names(void) {
        char too_long[NAME_OF_OBJECT_MAX + 2];
        const struct {
                const char *name;
                uapi16_name_problem_t problem;
        } no_names[] = {
                { "\xff", UAPI16_NAME_PROBLEM_NOT_UTF8 },
                { "a/\xc3", UAPI16_NAME_PROBLEM_NOT_UTF8 },
                { too_long, UAPI16_NAME_PROBLEM_TOO_LONG },
                { "Uapi16Manifest", UAPI16_NAME_PROBLEM_RESERVED },
                { "Uapi16Manifest.sig/x", UAPI16_NAME_PROBLEM_RESERVED },
                { "a\001b", UAPI16_NAME_PROBLEM_CONTROL_CHARACTER },
                { "a/b\177", UAPI16_NAME_PROBLEM_CONTROL_CHARACTER },
                { "a/\xef\xbf\xbe", UAPI16_NAME_PROBLEM_NONCHARACTER },
                { "a//b", UAPI16_NAME_PROBLEM_EMPTY_COMPONENT },
                { "/a", UAPI16_NAME_PROBLEM_EMPTY_COMPONENT },
                { "a/", UAPI16_NAME_PROBLEM_EMPTY_COMPONENT },
                { ".", UAPI16_NAME_PROBLEM_DOT_COMPONENT },
                { "a/../b", UAPI16_NAME_PROBLEM_DOT_COMPONENT },
        };
        static const char *const no_file_names[] = {
                "",     "x/",      ".",        "..", "sub/.", "sub/..", "/",       "/m",       "./m",
                "../m", "sub/./m", "sub/../m", "//", "/./",   "/../",   "sub//..", "../sub/m", "sub/../../m",
        };
        static const struct {
                const char *name;
                int error;
        } not_below[] = {
                { "inside/m", ELOOP },
                { "outside/m", ELOOP },
                { "sub/outside/m", ELOOP },
                { "inside/missing/m", ELOOP },
                { "file/m", ENOTDIR },
                { "sub/file/m", ENOTDIR },
                { "missing/m", ENOENT },
                { "sub/missing/m", ENOENT },
        };
        _cleanup_(closep) int tree = make_tree("names"), out = make_dir(tmp_fd, "names-out");
        _cleanup_(closep) int fd = scratch_file(), sub = make_dir(out, "sub");
        _cleanup_(closep) int elsewhere = make_dir(tmp_fd, "names-elsewhere"), probe = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *named = make_object("named");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *longest = NULL, *accented = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *no_object = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *written = NULL;
        size_t written_size;
        struct stat st;
        int r;

        memset(too_long, 'a', sizeof(too_long) - 1);
        too_long[sizeof(too_long) - 1] = 0;

        /* A name that is none is refused for the rule it breaks: as the
         * name of a new file object, as another name for one, and as the
         * name of the file its data is in. The object stays as it was. */
        for (size_t i = 0; i < ELEMENTSOF(no_names); i++) {
                const char *no = no_names[i].name;

                check_eq(uapi16_file_object_new(no, &no_object, NULL), -EINVAL);
                check_eq(uapi16_file_object_set_name(named, no, NULL), -EINVAL);
                check_eq(uapi16_file_object_set_contents_file(named, no, NULL), -EINVAL);

                r = uapi16_file_object_new(no, &no_object, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_NAME);
                check_eq(uapi16_error_name_problem(e), no_names[i].problem);
                check(!uapi16_error_raw_name(e, NULL));
                e = uapi16_error_free(e);

                r = uapi16_file_object_set_name(named, no, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_NAME);
                check_eq(uapi16_error_name_problem(e), no_names[i].problem);
                e = uapi16_error_free(e);

                r = uapi16_file_object_set_contents_file(named, no, &e);
                check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_NAME);
                check_eq(uapi16_error_name_problem(e), no_names[i].problem);
                e = uapi16_error_free(e);

                check(!no_object);
                check_str(uapi16_file_object_name(named), "named");
        }

        /* The empty name is the name of the root. No file has its data in
         * a file of that name, which is refused as a name that is empty. */
        r = uapi16_file_object_set_contents_file(named, "", &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_NAME);
        check_eq(uapi16_error_name_problem(e), UAPI16_NAME_PROBLEM_EMPTY);
        e = uapi16_error_free(e);

        /* The longest name is one, and so is one that is not ASCII. A
         * manifest lists them as they are. */
        too_long[NAME_OF_OBJECT_MAX] = 0;
        check_eq(uapi16_file_object_new(too_long, &longest, &e), 0);
        check_str(uapi16_file_object_name(longest), too_long);
        check_eq(uapi16_file_object_new("b/\xc3\xa9", &accented, &e), 0);
        check_str(uapi16_file_object_name(accented), "b/\xc3\xa9");
        check_eq(uapi16_file_object_set_contents_file(accented, too_long, &e), 0);
        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, longest, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, accented, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 2);
        check_eq(uapi16_manifest_report_directories(report), 2);
        report = uapi16_manifest_report_free(report);
        w = uapi16_manifest_writer_free(w);
        written = read_all(fd, &written_size);
        check_manifest(written, written_size);
        check(strstr(written, "\"name\":\"b/\xc3\xa9\""));
        check(strstr(written, too_long));

        /* The name of a new file is a path below its directory. One that
         * names no file there is refused before anything is looked up:
         * one that is empty or that ends in a slash, "." or "..", an
         * absolute one, and one with "." or ".." on the way. */
        for (size_t i = 0; i < ELEMENTSOF(no_file_names); i++) {
                const char *no = no_file_names[i];

                check_misuse(uapi16_manifest_writer_create_at(o, out, no, &none, &e), &e, EINVAL);
                check_misuse(uapi16_manifest_generate_at(o, out, no, tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);
        }

        /* The directories on the way are opened one at a time, and none
         * through a symbolic link, whether it leads out of the directory
         * or not: a link fails with ELOOP, a file with ENOTDIR, and a name
         * that is not there with ENOENT. Nothing is made anywhere. */
        check_eq(symlinkat("sub", out, "inside"), 0);
        check_eq(symlinkat("../names-elsewhere", out, "outside"), 0);
        check_eq(symlinkat("../../names-elsewhere", sub, "outside"), 0);
        make_file(out, "file", "");
        make_file(sub, "file", "");
        for (size_t i = 0; i < ELEMENTSOF(not_below); i++) {
                r = uapi16_manifest_writer_create_at(o, out, not_below[i].name, &none, &e);
                check_error(r, e, UAPI16_ERROR_IO, not_below[i].error, NULL, 0);
                e = uapi16_error_free(e);
                r = uapi16_manifest_generate_at(o, out, not_below[i].name, tree, UAPI16_ADD_NONE, &report, &e);
                check_error(r, e, UAPI16_ERROR_IO, not_below[i].error, NULL, 0);
                e = uapi16_error_free(e);
        }
        check(!none && !report);
        check_eq(count_entries(tmp_fd, "names-elsewhere"), 0);
        check_eq(count_entries(out, "sub"), 2);
        check_eq(count_entries(tmp_fd, "names-out"), 4);

        /* A name with directories on the way names a file in the last of
         * them. */
        check_eq(uapi16_manifest_generate_at(o, out, "sub/m", tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(fstatat(sub, "m", &st, 0), 0);
        check(st.st_size > 0);
        report = uapi16_manifest_report_free(report);

        /* The name is taken as the bytes it is, which need not be UTF-8,
         * where the file system takes such a name. */
        probe = openat(out, "\xfe", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        if (probe < 0) {
                fprintf(stderr, "skipping the names of new files that are not UTF-8: %s\n", strerror(errno));
                return;
        }
        check_eq(uapi16_manifest_writer_create_at(o, out, "\xff", &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, named, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, NULL, &e), 0);
        check_eq(fstatat(out, "\xff", &st, AT_SYMLINK_NOFOLLOW), 0);
        check(S_ISREG(st.st_mode) && st.st_size > 0);
        check_eq(uapi16_manifest_generate_at(o, out, "sub/caf\xe9", tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(fstatat(sub, "caf\xe9", &st, AT_SYMLINK_NOFOLLOW), 0);
        check(S_ISREG(st.st_mode) && st.st_size > 0);
        check(!e);
}

/* A file with a name that a manifest can't hold, which fails the walk of
 * its tree with `error` for the rule `problem`, unless it is left out. The
 * error is about the directory `in` that the file is in. */
static void check_unwritable(int tree, const char *in, const char *raw, int error,
                             uapi16_name_problem_t problem) {
        _cleanup_(closep) int fd = scratch_file(), out = dup(tmp_fd);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const void *name;
        size_t size = 0;
        struct stat st;
        int r;

        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_UNWRITABLE_NAME, error, in, CHECK_NAME);
        check_eq(uapi16_error_name_problem(e), problem);
        name = uapi16_error_raw_name(e, &size);
        check(name);
        check_eq(size, strlen(raw));
        check_eq(memcmp(name, raw, size), 0);
        check(uapi16_error_raw_name(e, NULL) == name);
        e = uapi16_error_free(e);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, NULL), -error);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_CROSS_MOUNTS, &report, NULL), -error);

        /* A new file fails the same way, and is not made. */
        check(out >= 0);
        r = uapi16_manifest_generate_at(o, out, "unwritable.manifest", tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_UNWRITABLE_NAME, error, in, CHECK_NAME);
        check_eq(fstatat(out, "unwritable.manifest", &st, AT_SYMLINK_NOFOLLOW), -1);
        check_eq(errno, ENOENT);

        /* Nothing was written, and no report made. */
        check(!report);
        check_eq(size_of(fd), 0);

        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_GRACEFUL, &report, NULL);
        check_eq(r, 0);
        check_eq(uapi16_manifest_report_entries_omitted(report), 1);
        check(size_of(fd) > 0);
}

static void test_unwritable_names(void) {
        char component[COMPONENT_MAX + 1], deep[NAME_OF_OBJECT_MAX + 1];
        _cleanup_(closep) int control = make_dir(tmp_fd, "unwritable-control");
        _cleanup_(closep) int not_utf8 = make_dir(tmp_fd, "unwritable-utf8");
        _cleanup_(closep) int too_long = make_dir(tmp_fd, "unwritable-long");
        _cleanup_(closep) int whole = make_dir(tmp_fd, "unwritable-directory");
        _cleanup_(closep) int sub = make_dir(control, "sub"), other = make_dir(not_utf8, "sub");
        _cleanup_(closep) int below = make_dir(whole, "new\nline");
        int dir = dup(too_long);
        size_t length = 0;

        make_file(sub, "tab\there", "");
        check_unwritable(control, "sub", "tab\there", EINVAL, UAPI16_NAME_PROBLEM_CONTROL_CHARACTER);

        make_file(not_utf8, "caf\xe9", "");
        make_file(other, "fine", "");
        check_unwritable(not_utf8, "", "caf\xe9", EILSEQ, UAPI16_NAME_PROBLEM_NOT_UTF8);

        /* A directory with such a name is left out with everything below
         * it, as one. */
        make_file(below, "one", "");
        make_file(below, "two", "");
        check_unwritable(whole, "", "new\nline", EINVAL, UAPI16_NAME_PROBLEM_CONTROL_CHARACTER);

        /* Sixteen directories inside each other whose names are as long as
         * a name gets make the longest name of a file object. A file in
         * the last of them has a longer one. */
        memset(component, 'd', COMPONENT_MAX);
        component[COMPONENT_MAX] = 0;
        check(dir >= 0);
        while (length + COMPONENT_MAX <= NAME_OF_OBJECT_MAX) {
                int next = make_dir(dir, component);

                close(dir);
                dir = next;
                if (length > 0)
                        deep[length++] = '/';
                memcpy(deep + length, component, COMPONENT_MAX);
                length += COMPONENT_MAX;
        }
        deep[length] = 0;
        check_eq(length, NAME_OF_OBJECT_MAX);
        make_file(dir, "x", "");
        close(dir);
        check_unwritable(too_long, deep, "x", ENAMETOOLONG, UAPI16_NAME_PROBLEM_TOO_LONG);
}

/* What says when a file is read, and changes it then, once. */
static volatile sig_atomic_t grown;
static int grow_fd = -1;

static void grow(int signal) {
        (void) signal;
        if (!grown && write(grow_fd, "!", 1) == 1)
                grown = 1;
}

/*
 * UAPI16_ERROR_CHANGED: a file that changes while the walk reads it. The
 * kernel says when that is: a watch of the file sends a signal for a read
 * of it to the thread that reads, which gets it before its read returns.
 * The handler appends to the file. Where there is no such watch, there is
 * nothing to test.
 */
static void test_changes(void) {
        _cleanup_(closep) int tree = make_dir(tmp_fd, "changes"), fd = scratch_file();
        _cleanup_(closep) int watch = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        struct f_owner_ex owner = { .type = F_OWNER_TID, .pid = (pid_t) syscall(SYS_gettid) };
        struct sigaction append = { .sa_handler = grow }, old;
        char path[PATH_MAX];
        int r;

        make_file(tree, "before", "data");
        make_file(tree, "file", "hello");
        check((size_t) snprintf(path, sizeof(path), "%s/changes/file", tmp_path) < sizeof(path));
        watch = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (watch < 0 || inotify_add_watch(watch, path, IN_ACCESS) < 0) {
                fprintf(stderr, "skipping a file that changes while it is read: %s\n", strerror(errno));
                return;
        }
        grow_fd = openat(tree, "file", O_WRONLY | O_APPEND | O_CLOEXEC);
        check(grow_fd >= 0);
        check_eq(sigaction(SIGIO, &append, &old), 0);
        check_eq(fcntl(watch, F_SETOWN_EX, &owner), 0);
        check_eq(fcntl(watch, F_SETFL, O_ASYNC | O_NONBLOCK), 0);

        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);

        check_eq(close(watch), 0);
        watch = -1;
        check_eq(sigaction(SIGIO, &old, NULL), 0);
        check_eq(close(grow_fd), 0);
        grow_fd = -1;
        if (!grown) {
                fprintf(stderr, "skipping a file that changes while it is read: no signal for its read\n");
                return;
        }
        check_error(r, e, UAPI16_ERROR_CHANGED, ESTALE, "file", 0);
        check(!report);
        check_eq(size_of(fd), 0);
        e = uapi16_error_free(e);

        /* Once it changes no more, it is a file like any other. */
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_bytes(report), 10);
        check(!e);
}

static void test_errors(void) {
        _cleanup_(closep) int tree = make_tree("errors"), out = make_dir(tmp_fd, "errors-out");
        _cleanup_(closep) int file = openat(tree, "a/file", O_RDONLY | O_CLOEXEC), fd = scratch_file();
        _cleanup_(closep) int path = openat(tree, "a/file", O_PATH | O_CLOEXEC);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *no_reader = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *no_records = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *x = make_hello("x");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *other = make_object("x");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *below = make_object("x/y");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *directory = make_object("x");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *taken = NULL;
        size_t taken_size;
        int r;

        check(file >= 0 && path >= 0);
        check_eq(uapi16_file_object_set_type(directory, S_IFDIR), 0);

        /* UAPI16_ERROR_IO: a system call failed, with its errno. A manifest
         * can't be read from a directory, and none can be written to a
         * descriptor that is open for reading. */
        r = uapi16_reader_open(tree, &no_reader, &e);
        check_error(r, e, UAPI16_ERROR_IO, EISDIR, NULL, CHECK_RECORD);
        e = uapi16_error_free(e);
        r = uapi16_writer_begin(o, file, NULL, &no_records, &e);
        check_error(r, e, UAPI16_ERROR_IO, EBADF, NULL, CHECK_RECORD);
        e = uapi16_error_free(e);
        r = uapi16_manifest_generate(o, file, tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_IO, EBADF, NULL, 0);
        e = uapi16_error_free(e);
        check(!no_reader && !no_records && !report);

        /* UAPI16_ERROR_IO with EFBIG: a regular file of more than 1 TiB,
         * where its data is hashed, also for the names of one file alone.
         * Nothing of it is read for that. Where its data is not hashed it
         * is a file like any other. A limit on the size of a file, or a
         * file system that has no room for one this sparse, leaves nothing
         * to test. */
        {
                const struct features unhashed = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE,
                                                          UAPI16_FEATURE_HARDLINK);
                _cleanup_(closep) int top = make_dir(tmp_fd, "errors-large"), large = -1;
                const off_t more = (off_t) (HASHED_MAX + 1);
                struct rlimit limit;

                large = openat(top, "large", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
                check(large >= 0);
                check_eq(getrlimit(RLIMIT_FSIZE, &limit), 0);
                if (limit.rlim_cur != RLIM_INFINITY && limit.rlim_cur < (rlim_t) more)
                        fprintf(stderr, "skipping a file of more than 1 TiB: the limit on the size of a "
                                        "file is %" PRIu64 " bytes\n",
                                (uint64_t) limit.rlim_cur);
                else if (ftruncate(large, more) < 0)
                        fprintf(stderr, "skipping a file of more than 1 TiB: %s\n", strerror(errno));
                else {
                        r = uapi16_manifest_generate(o, fd, top, UAPI16_ADD_NONE, &report, &e);
                        check_error(r, e, UAPI16_ERROR_IO, EFBIG, "large", 0);
                        e = uapi16_error_free(e);
                        check_eq(size_of(fd), 0);

                        check_eq(set_features(o, unhashed), 0);
                        check_eq(uapi16_manifest_generate(o, fd, top, UAPI16_ADD_NONE, &report, &e), 0);
                        check_eq(uapi16_manifest_report_files(report), 1);
                        check_eq(uapi16_manifest_report_bytes(report), HASHED_MAX + 1);
                        report = uapi16_manifest_report_free(report);
                        empty(fd);

                        check_eq(linkat(top, "large", top, "large-too", 0), 0);
                        r = uapi16_manifest_generate(o, fd, top, UAPI16_ADD_NONE, &report, &e);
                        check_eq(r, -EFBIG);
                        check_eq(uapi16_error_kind(e), UAPI16_ERROR_IO);
                        check_eq(uapi16_error_errno(e), EFBIG);
                        check(strcmp(uapi16_error_path(e), "large") == 0 ||
                              strcmp(uapi16_error_path(e), "large-too") == 0);
                        e = uapi16_error_free(e);
                        check_eq(size_of(fd), 0);
                        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES)), 0);
                }
        }

        /* A directory that can't be listed fails the walk of its tree, and
         * no manifest is written of a part of it. Nothing stops root from
         * listing one. */
        if (geteuid() == 0)
                fprintf(stderr, "skipping a directory that can't be listed: nothing stops root\n");
        else {
                _cleanup_(closep) int locked = make_dir(tree, "locked");

                check_eq(fchmodat(tree, "locked", 0, 0), 0);
                r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);
                check_error(r, e, UAPI16_ERROR_IO, EACCES, "locked", 0);
                e = uapi16_error_free(e);
                r = uapi16_manifest_generate_at(o, out, "locked.manifest", tree, UAPI16_ADD_NONE, &report, &e);
                check_error(r, e, UAPI16_ERROR_IO, EACCES, "locked", 0);
                e = uapi16_error_free(e);
                check(!report);
                check_eq(size_of(fd), 0);
                check_eq(count_entries(tmp_fd, "errors-out"), 0);
                check_eq(unlinkat(tree, "locked", AT_REMOVEDIR), 0);
        }

        /* UAPI16_ERROR_EXISTS: the name of a new file is taken, when the
         * writer is made or by the time it finishes. What has the name
         * stays as it is. */
        make_file(out, "taken", "mine");
        check_eq(symlinkat("nowhere", out, "dangling"), 0);
        r = uapi16_manifest_writer_create_at(o, out, "taken", &none, &e);
        check_error(r, e, UAPI16_ERROR_EXISTS, EEXIST, NULL, 0);
        e = uapi16_error_free(e);
        r = uapi16_manifest_writer_create_at(o, out, "dangling", &none, &e);
        check_error(r, e, UAPI16_ERROR_EXISTS, EEXIST, NULL, 0);
        e = uapi16_error_free(e);
        r = uapi16_manifest_generate_at(o, out, "taken", tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_EXISTS, EEXIST, NULL, 0);
        e = uapi16_error_free(e);
        check(!none && !report);
        check_eq(uapi16_manifest_writer_create_at(o, out, "later", &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        make_file(out, "later", "mine as well");
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_EXISTS, EEXIST, NULL, 0);
        e = uapi16_error_free(e);
        check(!report);
        w = uapi16_manifest_writer_free(w);
        taken = read_file(out, "later", &taken_size);
        check_str(taken, "mine as well");

        /* UAPI16_ERROR_DUPLICATE: two different file objects of one name.
         * A directory and a file that is none are two as well. */
        w = open_writer(o);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, other, &e), 0);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_DUPLICATE, EEXIST, "x", 0);
        e = uapi16_error_free(e);
        w = uapi16_manifest_writer_free(w);
        w = open_writer(o);
        check_eq(uapi16_manifest_writer_add_object(w, directory, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_DUPLICATE, EEXIST, "x", 0);
        e = uapi16_error_free(e);
        check(!report);
        w = uapi16_manifest_writer_free(w);

        /* UAPI16_ERROR_NOT_DIRECTORY: a file that is not a directory is
         * where a directory is needed. The top of a tree is a directory,
         * whatever its descriptor was opened for. */
        r = uapi16_manifest_generate(o, fd, file, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_NOT_DIRECTORY, ENOTDIR, "", 0);
        e = uapi16_error_free(e);
        r = uapi16_manifest_generate_at(o, out, "of-a-file", path, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_NOT_DIRECTORY, ENOTDIR, "", 0);
        e = uapi16_error_free(e);
        check_eq(size_of(fd), 0);

        /* A file object that is not a directory and that one was added
         * below fails when the writer finishes, in whatever order they
         * came. */
        w = open_writer(o);
        check_eq(uapi16_manifest_writer_add_object(w, below, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_NOT_DIRECTORY, ENOTDIR, "x", 0);
        e = uapi16_error_free(e);
        check(!report);
        w = uapi16_manifest_writer_free(w);

        /* UAPI16_ERROR_UNSUPPORTED: a feature that can't be read here, such
         * as a DOS attribute of a file system that is not FAT. */
        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FLAG_HIDDEN));
        check_eq(r, 0);
        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);
        if (r == 0) {
                fprintf(stderr, "skipping UAPI16_ERROR_UNSUPPORTED: the temporary directory is on FAT\n");
                report = uapi16_manifest_report_free(report);
                empty(fd);
        } else {
                check_error(r, e, UAPI16_ERROR_UNSUPPORTED, EOPNOTSUPP, "", CHECK_FEATURE);
                check_eq(uapi16_error_feature(e), UAPI16_FEATURE_FLAG_HIDDEN);
                check_eq(size_of(fd), 0);
        }
        e = uapi16_error_free(e);

        /* The UUID and the volume serial number of the file system are no
         * such features: a file system need not have them. A manifest that
         * records them is written of a tree whose file system has none. Its
         * root says nothing of what is not there, and the report counts
         * each as a field that was left out. No file system has both. */
        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FS_UUID, UAPI16_FEATURE_FAT_SERIAL));
        check_eq(r, 0);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        {
                _cleanup_(uapi16_reader_freep) uapi16_reader *reader = open_reader(fd);
                const uapi16_file_object *root = uapi16_reader_root(reader);
                uapi16_uuid_t uuid;
                uint32_t serial = 77;
                int no_uuid, no_serial;

                check_recorded(reader, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FS_UUID,
                                                UAPI16_FEATURE_FAT_SERIAL));
                no_uuid = uapi16_file_object_fs_uuid(root, &uuid);
                no_serial = uapi16_file_object_fat_serial(root, &serial);
                check(no_uuid == 0 || no_uuid == -ENODATA);
                check(no_serial == 0 || no_serial == -ENODATA);
                check(no_uuid == -ENODATA || no_serial == -ENODATA);
                check_eq(uapi16_manifest_report_fields_omitted(report),
                         (uint64_t) (no_uuid == -ENODATA) + (uint64_t) (no_serial == -ENODATA));
        }
        report = uapi16_manifest_report_free(report);
        empty(fd);

        /* Without the root the manifest is written as well, with a root
         * that says nothing of them. Nothing was left out of a root that
         * was not read. */
        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(uapi16_manifest_report_fields_omitted(report), 0);
        report = uapi16_manifest_report_free(report);
        w = uapi16_manifest_writer_free(w);
        {
                _cleanup_(uapi16_reader_freep) uapi16_reader *reader = open_reader(fd);
                const uapi16_file_object *root = uapi16_reader_root(reader);
                uapi16_uuid_t uuid;
                uint32_t serial = 77;

                check_recorded(reader, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FS_UUID,
                                                UAPI16_FEATURE_FAT_SERIAL));
                check_stated(root, FEATURES(UAPI16_FEATURE_NONE));
                check_eq(uapi16_file_object_fs_uuid(root, &uuid), -ENODATA);
                check_eq(uapi16_file_object_fat_serial(root, &serial), -ENODATA);
                check_eq(serial, 77);
        }
        empty(fd);

        /* UAPI16_ERROR_MISSING_PARENT: a directory that was not added, where
         * the features need what it would record. The root is one. */
        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_READ_ONLY));
        check_eq(r, 0);
        w = open_writer(o);
        check_eq(uapi16_manifest_writer_add_object(w, x, &e), 0);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_MISSING_PARENT, ENOENT, "", 0);
        e = uapi16_error_free(e);
        check(!report);
        w = uapi16_manifest_writer_free(w);

        /* With the root added, it is the directory of a file object that
         * was not added itself. */
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");

                w = open_writer(o);
                check_eq(uapi16_manifest_writer_add_object(w, root, &e), 0);
                check_eq(uapi16_file_object_set_name(below, "parent/x", &e), 0);
                check_eq(uapi16_manifest_writer_add_object(w, below, &e), 0);
                r = uapi16_manifest_writer_finish(w, &report, &e);
                check_error(r, e, UAPI16_ERROR_MISSING_PARENT, ENOENT, "parent", 0);
                e = uapi16_error_free(e);
                check(!report);
                w = uapi16_manifest_writer_free(w);
        }
}

/*
 * Makes the directory `name` in `dir_fd` with a file in it that has more in
 * its extended attributes than a record of a manifest has room for, and
 * returns the directory. Where the file system does not take that much, it
 * leaves nothing behind and returns -1, with the error in errno.
 */
static int make_large(int dir_fd, const char *name) {
        _cleanup_(freep) char *value = malloc(XATTR_VALUE_SIZE);
        _cleanup_(closep) int file = -1;
        int tree = make_dir(dir_fd, name), refused;
        char attribute[32];

        make_file(tree, "file", "");
        file = openat(tree, "file", O_RDONLY | O_CLOEXEC);
        check(file >= 0 && value);
        memset(value, 'x', XATTR_VALUE_SIZE);
        for (size_t i = 0; i * XATTR_VALUE_SIZE <= RECORD_MAX; i++) {
                snprintf(attribute, sizeof(attribute), "user.large-%03zu", i);
                if (fsetxattr(file, attribute, value, XATTR_VALUE_SIZE, 0) < 0) {
                        refused = errno;
                        close(tree);
                        remove_tree(dir_fd, name);
                        errno = refused;
                        return -1;
                }
        }
        return tree;
}

/*
 * UAPI16_ERROR_TOO_LARGE: a file with more in its extended attributes than
 * a record of a manifest has room for. A file object of a caller has that
 * much wherever it is given it, and a writer refuses it and goes on. A
 * walk finds such a file where the file system of the temporary directory
 * takes that much. Where it does not, as ext4 does not, the file is made
 * on the tmpfs of /dev/shm. Where that does not take it either, the walk
 * has nothing to test.
 */
static void test_too_large(void) {
        _cleanup_(closep) int tree = -1, memory = -1, out = scratch_file(), written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *large = make_object("large");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *literal = make_object("literal");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *small = make_object("small");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *walked = NULL;
        _cleanup_(freep) char *value = malloc(RECORD_MAX);
        char memory_path[] = MEMORY_TEMPLATE;
        size_t before;
        int r, walk;

        check(value);
        memset(value, 'x', RECORD_MAX);
        check_eq(uapi16_file_object_add_user_xattr(large, "large", value, RECORD_MAX), 0);
        check_eq(uapi16_file_object_set_user_xattrs(small), 0);

        /* The features of a writer of records need no root. */
        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_USER_XATTR));
        check_eq(r, 0);
        records = begin_records(o, written);
        before = size_of(written);
        r = uapi16_writer_file(records, large, &e);
        check_error(r, e, UAPI16_ERROR_TOO_LARGE, E2BIG, "large", CHECK_RECORD | CHECK_PROBLEM);
        check_str(uapi16_error_problem(e), "recordTooLarge");
        e = uapi16_error_free(e);
        check_eq(size_of(written), before);
        check_eq(uapi16_writer_file(records, small, &e), 0);
        check_eq(uapi16_writer_finish(records, &e), 0);

        /* A file object with that much data in the manifest is too large
         * as well. It is not added, and the writer is as it was. */
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES)), 0);
        check_eq(uapi16_file_object_set_target(literal, value, RECORD_MAX), 0);
        w = open_writer(o);
        r = uapi16_manifest_writer_add_object(w, literal, &e);
        check_error(r, e, UAPI16_ERROR_TOO_LARGE, E2BIG, "literal", CHECK_PROBLEM);
        check_str(uapi16_error_problem(e), "recordTooLarge");
        e = uapi16_error_free(e);
        check_listed(w, 0, 1, 0);

        tree = make_large(tmp_fd, "large");
        if (tree < 0) {
                int refused = errno, again;
                bool made = mkdtemp(memory_path);

                if (made)
                        memory = open(memory_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
                if (memory >= 0)
                        tree = make_large(memory, "large");
                if (tree < 0) {
                        again = errno;
                        if (made)
                                check_eq(rmdir(memory_path), 0);
                        fprintf(stderr, "skipping UAPI16_ERROR_TOO_LARGE of a tree: the temporary "
                                        "directory: %s, ",
                                strerror(refused));
                        fprintf(stderr, "%s: %s\n", MEMORY_DIR, strerror(again));
                        return;
                }
        }

        r = set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_USER_XATTR));
        check_eq(r, 0);
        walk = uapi16_manifest_generate(o, out, tree, UAPI16_ADD_NONE, &report, &walked);

        /* What is in memory goes before anything is checked, so that a
         * check that fails leaves nothing there. */
        if (memory >= 0) {
                remove_tree(memory, "large");
                check_eq(rmdir(memory_path), 0);
        }
        check_error(walk, walked, UAPI16_ERROR_TOO_LARGE, E2BIG, "file", CHECK_PROBLEM);
        check_str(uapi16_error_problem(walked), "recordTooLarge");
        check(!report);
        check_eq(size_of(out), 0);
}

/* Writes "deny" or a map of one ID to a file of /proc/self. */
static bool write_proc(const char *path, const char *text) {
        int fd = open(path, O_WRONLY | O_CLOEXEC);
        bool written;

        if (fd < 0)
                return false;
        written = write(fd, text, strlen(text)) == (ssize_t) strlen(text);
        close(fd);
        return written;
}

/* Makes a user and a mount namespace for the process, in which it can
 * mount. `uid` and `gid` are the IDs it had. Says whether it could. */
static bool own_namespace(uid_t uid, gid_t gid) {
        char map[64];

        if (unshare(CLONE_NEWUSER | CLONE_NEWNS) < 0)
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) uid);
        if (!write_proc("/proc/self/uid_map", map) || !write_proc("/proc/self/setgroups", "deny"))
                return false;
        snprintf(map, sizeof(map), "0 %u 1", (unsigned) gid);
        if (!write_proc("/proc/self/gid_map", map))
                return false;
        return mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0;
}

/*
 * What the child of test_loop() does, which returns what it exits with:
 * it makes a user and a mount namespace for itself, mounts the tree
 * `source` once more at `target` inside it, and walks the tree.
 */
static int loop_in_namespace(const char *source, const char *target, uid_t uid, gid_t gid) {
        _cleanup_(closep) int tree = -1, fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        int r;

        if (!own_namespace(uid, gid))
                return EXIT_SKIPPED;
        /* The descriptors from before are of the mounts of the parent, so
         * the tree is opened in this namespace. */
        check_eq(mount(source, target, NULL, MS_BIND, NULL), 0);
        tree = open(source, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(tree >= 0);

        /* Without crossing it, the mount point is an empty directory. */
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_directories(report), 3);
        check_eq(uapi16_manifest_report_files(report), 1);
        report = uapi16_manifest_report_free(report);
        empty(fd);

        /* A walk that crosses it comes to a directory that is one of the
         * directories it is in, and no manifest is written. */
        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_CROSS_MOUNTS, &report, &e);
        check_error(r, e, UAPI16_ERROR_LOOP, ELOOP, "x/again", 0);
        check(!report);
        check_eq(size_of(fd), 0);
        return EXIT_SUCCESS;
}

/*
 * UAPI16_ERROR_LOOP: a mount that shows a directory again inside itself,
 * for a walk that crosses mount points. The mount needs a user and a mount
 * namespace, which a child makes for itself. Where it can't, there is
 * nothing to test.
 */
static void test_loop(void) {
        _cleanup_(closep) int tree = make_dir(tmp_fd, "loop"), x = make_dir(tree, "x");
        _cleanup_(closep) int again = make_dir(x, "again");
        char source[PATH_MAX], target[PATH_MAX];
        int status;
        pid_t pid;

        make_file(x, "file", "");
        check((size_t) snprintf(source, sizeof(source), "%s/loop", tmp_path) < sizeof(source));
        check((size_t) snprintf(target, sizeof(target), "%s/loop/x/again", tmp_path) < sizeof(target));
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                int code = loop_in_namespace(source, target, getuid(), getgid());

                fflush(NULL);
                _exit(code);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        if (WEXITSTATUS(status) == EXIT_SKIPPED)
                fprintf(stderr, "skipping UAPI16_ERROR_LOOP: no user namespace that can mount here\n");
        else
                check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
}

/* Checks that the descriptor `fd` is open. */
static void check_open(int fd) {
        check(fcntl(fd, F_GETFD) != -1);
}

/*
 * Descriptors are borrowed. What is made from one has it on loan until it
 * is freed, and never closes it: a writer, a writer of records, a reader
 * and a directory. The descriptor of the caller is open and works once the
 * object finished and once it is freed, with a finish or without one, and
 * the library makes no duplicate of it: the process has as many
 * descriptors with the object as without. The generate functions have
 * theirs for the call. A call that fails to make its object leaves the
 * descriptor with the caller.
 */
/*
 * What the child of test_no_uuid() does, which returns what it exits with:
 * it makes a user and a mount namespace for itself, mounts a ramfs, a file
 * system without a UUID, at `target` inside it, and writes the manifest of
 * a tree there.
 */
static int no_uuid_in_namespace(const char *target, uid_t uid, gid_t gid) {
        _cleanup_(closep) int tree = -1, fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uapi16_uuid_t uuid;

        if (!own_namespace(uid, gid) || mount("none", target, "ramfs", 0, NULL) < 0)
                return EXIT_SKIPPED;
        tree = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(tree >= 0);
        make_file(tree, "file", "hello");

        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FS_UUID)), 0);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(uapi16_manifest_report_fields_omitted(report), 1);
        reader = open_reader(fd);
        check_recorded(reader, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_FS_UUID));
        check_eq(uapi16_file_object_fs_uuid(uapi16_reader_root(reader), &uuid), -ENODATA);
        return EXIT_SUCCESS;
}

/* A manifest that records the UUID of the file system is written of a tree
 * on a file system that has none. Its root says nothing of it, and the
 * report counts it as a field that was left out. */
static void test_no_uuid(void) {
        _cleanup_(closep) int target = make_dir(tmp_fd, "no-uuid");
        char path[PATH_MAX];
        int status;
        pid_t pid;

        check((size_t) snprintf(path, sizeof(path), "%s/no-uuid", tmp_path) < sizeof(path));
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                int code = no_uuid_in_namespace(path, getuid(), getgid());

                fflush(NULL);
                _exit(code);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        if (WEXITSTATUS(status) == EXIT_SKIPPED)
                fprintf(stderr, "skipping a file system without a UUID: no user namespace that can mount here\n");
        else
                check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
}

/* The directory on FAT that the tests of the crate use, where there is
 * one. */
#define FAT_DIR "UAPI16_TEST_FAT_DIR"

/* A new file that is in its directory `dir` under a temporary name until
 * its manifest is complete, since nothing gave it a file without a name. A
 * child that frees the writer leaves that name alone: the parent finishes,
 * and the file has its name. `dir` is empty before and after. */
static void check_freed_in_a_child(int dir) {
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object("file");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        int status;
        pid_t pid;

        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_MODE)), 0);
        check_eq(uapi16_file_object_set_mode(file, S_IFREG | 0644), 0);
        check_eq(uapi16_manifest_writer_create_at(o, dir, "manifest", &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);
        check_eq(count_entries(dir, "."), 1);
        check_eq(faccessat(dir, "manifest", F_OK, 0), -1);
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                uapi16_manifest_writer_free(w);
                /* Its copies of the two others as well, so that it leaves
                 * nothing behind that a check for leaks would find. */
                uapi16_file_object_free(file);
                uapi16_manifest_options_free(o);
                _exit(EXIT_SUCCESS);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
        check_eq(count_entries(dir, "."), 1);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(count_entries(dir, "."), 1);
        check_eq(faccessat(dir, "manifest", F_OK, 0), 0);
        check_eq(unlinkat(dir, "manifest", 0), 0);
}

static bool wipes_on_fork(void);

/* A tree on FAT, which has a volume serial number and no UUID: a manifest
 * that records both has the serial, and the report counts the UUID as a
 * field that was left out. */
static void test_fat(void) {
        const char *fat = getenv(FAT_DIR);
        _cleanup_(closep) int tree = -1, fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const struct features features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_FS_UUID,
                                                  UAPI16_FEATURE_FAT_SERIAL);
        static const char freed[] = "uapi16-capi-freed";
        _cleanup_(closep) int out = -1;
        const uapi16_file_object *root;
        uapi16_uuid_t uuid;
        uint32_t serial;

        if (!fat || !*fat) {
                fprintf(stderr, "skipping a tree on FAT: " FAT_DIR " names none\n");
                return;
        }
        tree = open(fat, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(tree >= 0);
        check_eq(set_features(o, features), 0);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_fields_omitted(report), 1);
        reader = open_reader(fd);
        check_recorded(reader, features);
        root = uapi16_reader_root(reader);
        check_eq(uapi16_file_object_fat_serial(root, &serial), 0);
        check_eq(uapi16_file_object_fs_uuid(root, &uuid), -ENODATA);

        /* FAT has no O_TMPFILE, so a new file is in its directory under a
         * temporary name until its manifest is complete. A child that
         * frees the writer leaves that name alone: the parent finishes,
         * and the file has its name. That takes a child that is told. */
        if (!wipes_on_fork()) {
                fprintf(stderr, "skipping a new file on FAT: no memory that is wiped in a child here\n");
                return;
        }
        /* A run that was stopped can have left the directory behind. */
        if (faccessat(tree, freed, F_OK, AT_SYMLINK_NOFOLLOW) == 0)
                remove_tree(tree, freed);
        out = make_dir(tree, freed);
        check_freed_in_a_child(out);
        check_eq(unlinkat(tree, freed, AT_REMOVEDIR), 0);
}

static void test_descriptors(void) {
        _cleanup_(closep) int tree = make_tree("descriptors"), out = make_dir(tmp_fd, "descriptors-out");
        _cleanup_(closep) int sub = make_dir(out, "sub");
        _cleanup_(closep) int kept = openat(out, "kept", O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        _cleanup_(closep) int records = openat(out, "records", O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        _cleanup_(closep) int stream = openat(out, "streamed", O_RDWR | O_CREAT | O_CLOEXEC, 0644);
        _cleanup_(closep) int nothing = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *for_partitions =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *unordered =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *writer = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *directory = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *sized = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *only = NULL;
        _cleanup_(freep) char *expected = NULL, *generated = NULL, *streamed = NULL, *listed = NULL;
        _cleanup_(freep) char *written = NULL, *recorded = NULL;
        size_t before, expected_size, generated_size, streamed_size, listed_size, written_size;
        size_t recorded_size, entries, begun, unfinished, held, held_below;
        struct stat st;
        char first = 0;
        int r;

        check(kept >= 0 && records >= 0 && stream >= 0);
        r = set_features(for_partitions, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_GPT_LABEL));
        check_eq(r, 0);
        check_eq(uapi16_manifest_options_set_order(unordered, UAPI16_ORDER_NONE), 0);
        check_eq(uapi16_file_object_set_size(sized, 1), 0);
        expected = generate(o, tree, UAPI16_ADD_NONE, &expected_size);
        before = open_descriptors();

        /* The generate functions have their descriptors for the call: the
         * directory of the new file, the top of the tree and what the
         * manifest is written to are open when it returned, and the process
         * has as many descriptors as it had. The caller goes on with them:
         * the new file is found through its directory, and the manifest is
         * where the descriptor was. */
        check_eq(uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, &report, NULL), 0);
        report = uapi16_manifest_report_free(report);
        check_eq(uapi16_manifest_generate(o, stream, tree, UAPI16_ADD_NONE, &report, NULL), 0);
        report = uapi16_manifest_report_free(report);
        check_open(out);
        check_open(tree);
        check_open(stream);
        check_eq(open_descriptors(), before);
        generated = read_file(out, "m", &generated_size);
        check_same(generated, generated_size, expected, expected_size);
        check_eq(lseek(stream, 0, SEEK_CUR), (off_t) expected_size);
        streamed = read_all(stream, &streamed_size);
        check_same(streamed, streamed_size, expected, expected_size);
        check_eq(fstatat(tree, "a/file", &st, 0), 0);

        /* One that fails leaves them as well. */
        check_eq(uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, &report, NULL), -EEXIST);
        check_eq(uapi16_manifest_generate(for_partitions, stream, tree, UAPI16_ADD_NONE, &report, NULL), -EINVAL);
        check(!report);
        check_open(out);
        check_open(tree);
        check_open(stream);
        check_eq(open_descriptors(), before);
        check_eq(size_of(stream), expected_size);

        /* A writer of a new file has the directory of the file on loan.
         * Nothing has the name before the writer finishes. Once it
         * finished, and once it is freed, the directory is open, and the
         * file is found through it. */
        check_eq(uapi16_manifest_writer_create_at(o, out, "listed", &w, NULL), 0);
        held = open_descriptors() - before;
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        check_eq(fstatat(out, "listed", &st, 0), -1);
        check_eq(errno, ENOENT);
        check_eq(uapi16_manifest_writer_finish(w, NULL, NULL), 0);
        check_open(out);
        w = uapi16_manifest_writer_free(w);
        check_open(out);
        check_eq(open_descriptors(), before);
        listed = read_file(out, "listed", &listed_size);
        check_manifest(listed, listed_size);

        /* Where the name has several components, the library opens the
         * directory of the file itself: such a writer holds one descriptor
         * more than a writer of a file in the directory of the caller, and
         * that one is the library's to close. */
        check_eq(uapi16_manifest_writer_create_at(o, out, "sub/listed", &w, NULL), 0);
        held_below = open_descriptors() - before;
        check_eq(held_below, held + 1);
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        check_eq(uapi16_manifest_writer_finish(w, NULL, NULL), 0);
        w = uapi16_manifest_writer_free(w);
        check_open(out);
        check_open(sub);
        check_eq(open_descriptors(), before);
        check_eq(fstatat(sub, "listed", &st, 0), 0);
        check_eq((size_t) st.st_size, listed_size);

        /* A writer that is freed instead leaves its directory open as
         * well, and nothing in it. */
        entries = count_entries(tmp_fd, "descriptors-out");
        check_eq(uapi16_manifest_writer_create_at(o, out, "abandoned", &w, NULL), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        w = uapi16_manifest_writer_free(w);
        check_open(out);
        check_eq(open_descriptors(), before);
        check_eq(fstatat(out, "abandoned", &st, 0), -1);
        check_eq(errno, ENOENT);
        check_eq(count_entries(tmp_fd, "descriptors-out"), entries);

        /* What a writer writes its manifest to is the descriptor of the
         * caller, and no duplicate of it: the manifest goes where it
         * pointed to, and the caller writes on behind it. */
        check_eq(write(kept, "before\n", 7), 7);
        check_eq(uapi16_manifest_writer_open(o, kept, &w, NULL), 0);
        check_eq(open_descriptors(), before);
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        check_eq(uapi16_manifest_writer_finish(w, NULL, NULL), 0);
        check_open(kept);
        w = uapi16_manifest_writer_free(w);
        check_open(kept);
        check_eq(open_descriptors(), before);
        check_eq(lseek(kept, 0, SEEK_CUR), (off_t) (7 + listed_size));
        check_eq(write(kept, "after\n", 6), 6);
        written = read_all(kept, &written_size);
        check_eq(written_size, 7 + listed_size + 6);
        check_eq(memcmp(written, "before\n", 7), 0);
        check_eq(memcmp(written + 7, listed, listed_size), 0);
        check_eq(memcmp(written + 7 + listed_size, "after\n", 6), 0);

        /* A writer that is freed before it finished leaves its descriptor
         * open too, and has written nothing to it. */
        check_eq(uapi16_manifest_writer_open(o, kept, &w, NULL), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        w = uapi16_manifest_writer_free(w);
        check_open(kept);
        check_eq(open_descriptors(), before);
        check_eq(size_of(kept), written_size);
        check_eq(write(kept, "more\n", 5), 5);
        check_eq(size_of(kept), written_size + 5);

        /* The same for a writer of records, which writes every record
         * before its call returns. */
        check_eq(uapi16_writer_begin(o, records, NULL, &writer, NULL), 0);
        check_eq(open_descriptors(), before);
        begun = size_of(records);
        check(begun > 0);
        check_eq(uapi16_writer_file(writer, file, NULL), 0);
        check(size_of(records) > begun);
        check_eq(uapi16_writer_finish(writer, NULL), 0);
        check_eq(size_of(records), listed_size);
        check_open(records);
        writer = uapi16_writer_free(writer);
        check_open(records);
        check_eq(open_descriptors(), before);
        check_eq(lseek(records, 0, SEEK_CUR), (off_t) listed_size);
        recorded = read_all(records, &recorded_size);
        check_same(recorded, recorded_size, listed, listed_size);

        /* One that is freed before it finished leaves its descriptor open,
         * with the records it wrote, and the caller writes on behind
         * them. */
        check_eq(uapi16_writer_begin(o, nothing, NULL, &writer, NULL), 0);
        check_eq(uapi16_writer_file(writer, file, NULL), 0);
        unfinished = size_of(nothing);
        check(unfinished > 0 && unfinished < listed_size);
        writer = uapi16_writer_free(writer);
        check_open(nothing);
        check_eq(open_descriptors(), before);
        check_eq(size_of(nothing), unfinished);
        check_eq(write(nothing, "mine", 4), 4);
        check_eq(size_of(nothing), unfinished + 4);
        empty(nothing);

        /* What a reader reads its manifest from is the descriptor of the
         * caller as well. It is open once the reader read the trailer and
         * once the reader is freed, and the caller reads it again from its
         * start. */
        check_eq(lseek(records, 0, SEEK_SET), 0);
        check_eq(uapi16_reader_open(records, &reader, NULL), 0);
        check_eq(open_descriptors(), before);
        only = next_object(reader, "file");
        check_ends(reader);
        check_open(records);
        reader = uapi16_reader_free(reader);
        check_open(records);
        check_eq(open_descriptors(), before);
        check_eq(lseek(records, 0, SEEK_SET), 0);
        check_eq(read(records, &first, 1), 1);
        check_eq(first, RECORD_SEPARATOR);

        /* So it is once a reader is freed that did not read to the end. */
        check_eq(lseek(records, 0, SEEK_SET), 0);
        check_eq(uapi16_reader_open(records, &reader, NULL), 0);
        reader = uapi16_reader_free(reader);
        check_open(records);
        check_eq(open_descriptors(), before);
        first = 0;
        check_eq(pread(records, &first, 1, 0), 1);
        check_eq(first, RECORD_SEPARATOR);

        /* The descriptor of a directory is open once the directory is
         * freed, and files are found through it. */
        check_eq(uapi16_directory_new(out, UAPI16_DIRECTORY_NONE, &directory, NULL), 0);
        check(directory);
        check_eq(open_descriptors(), before);
        directory = uapi16_directory_free(directory);
        check(!directory);
        check_open(out);
        check_eq(open_descriptors(), before);
        check_eq(fstatat(out, "listed", &st, 0), 0);

        /* A call that fails to make its object leaves the descriptor with
         * the caller: a name that is taken, options no writer is made for,
         * a file that holds no manifest, a root no manifest can hold, and
         * a flag that is none. Nothing is written, and no file is made. */
        entries = count_entries(tmp_fd, "descriptors-out");
        check_eq(uapi16_manifest_writer_create_at(o, out, "listed", &w, NULL), -EEXIST);
        check_eq(uapi16_manifest_writer_create_at(for_partitions, out, "new", &w, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_create_at(unordered, out, "new", &w, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_open(for_partitions, kept, &w, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_open(unordered, kept, &w, NULL), -EINVAL);
        check_eq(uapi16_reader_open(nothing, &reader, NULL), -EBADMSG);
        check_eq(uapi16_writer_begin(o, nothing, sized, &writer, NULL), -EBADMSG);
        check_eq(uapi16_directory_new(out, UINT64_C(1) << 1, &directory, NULL), -EINVAL);
        check(!w && !reader && !writer && !directory);
        check_open(out);
        check_open(kept);
        check_open(nothing);
        check_eq(open_descriptors(), before);
        check_eq(size_of(nothing), 0);
        check_eq(size_of(kept), written_size + 5);
        check_eq(count_entries(tmp_fd, "descriptors-out"), entries);
        /* Each of them works as it did. */
        check_eq(write(nothing, "mine", 4), 4);
        check_eq(write(kept, "last\n", 5), 5);
        check_eq(fstatat(out, "kept", &st, 0), 0);
        check_eq((size_t) st.st_size, written_size + 10);

        /* The library kept none of its own. */
        check_open(tree);
        check_eq(open_descriptors(), before);
}

/*
 * A process that can open no descriptor. What is made from a descriptor of
 * the caller needs none of its own, so a reader, a writer of records and a
 * directory are made there and work. What a call fails for anyway, it
 * fails for there as well, and not for the want of a descriptor. A writer
 * that takes nothing more says so, and options with a feature of
 * partitions are refused, before either takes a descriptor. None of these
 * calls takes a descriptor away from the caller.
 */
static void test_no_descriptors(void) {
        _cleanup_(closep) int tree = make_tree("limit"), out = make_dir(tmp_fd, "limit-out");
        _cleanup_(closep) int fd = scratch_file(), manifest = manifest_file(ROOT FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *for_partitions =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *finished = open_writer(o);
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *no_reader = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL, *no_records = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *directory = NULL, *no_directory = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        struct rlimit limit, few;
        int taken[DESCRIPTORS_MAX], r;
        size_t n = 0;

        r = set_features(for_partitions, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_GPT_LABEL));
        check_eq(r, 0);
        check_eq(uapi16_manifest_writer_finish(finished, NULL, &e), 0);

        /* No descriptor is left from here on: the process may have few,
         * and has them all. */
        check_eq(getrlimit(RLIMIT_NOFILE, &limit), 0);
        few = limit;
        if (few.rlim_cur > DESCRIPTORS_MAX)
                few.rlim_cur = DESCRIPTORS_MAX;
        check_eq(setrlimit(RLIMIT_NOFILE, &few), 0);
        for (;;) {
                int next = open("/dev/null", O_RDONLY | O_CLOEXEC);

                if (next < 0)
                        break;
                check(n < ELEMENTSOF(taken));
                taken[n++] = next;
        }
        check_eq(errno, EMFILE);

        /* A reader reads its manifest from the descriptor of the caller,
         * a writer of records writes to it, and a directory is made from
         * it: no duplicate is made, which there is no room for. */
        check_eq(uapi16_reader_open(manifest, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "a");
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);
        check_eq(uapi16_writer_begin(o, written, NULL, &records, &e), 0);
        check_eq(uapi16_writer_file(records, file, &e), 0);
        check_eq(uapi16_writer_finish(records, &e), 0);
        records = uapi16_writer_free(records);
        check_eq(uapi16_directory_new(tree, UAPI16_DIRECTORY_NONE, &directory, &e), 0);
        directory = uapi16_directory_free(directory);
        check(!e);
        check(size_of(written) > 0);

        /* A call that is not valid fails for that. */
        check_misuse(uapi16_manifest_writer_open(o, -1, &none, &e), &e, EBADF);
        check_misuse(uapi16_manifest_writer_open(o, fd, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_reader_open(-1, &no_reader, &e), &e, EBADF);
        check_misuse(uapi16_reader_open(manifest, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_begin(o, -1, NULL, &no_records, &e), &e, EBADF);
        check_misuse(uapi16_writer_begin(o, fd, file, &no_records, &e), &e, EINVAL);
        check_misuse(uapi16_directory_new(-1, UAPI16_DIRECTORY_NONE, &no_directory, &e), &e, EBADF);
        check_misuse(uapi16_directory_new(tree, UINT64_C(1) << 1, &no_directory, &e), &e, EINVAL);
        check(!none && !no_reader && !no_records && !no_directory);

        /* Options with a feature of partitions make no writer, whatever
         * way it is made, and the error says which feature it is. */
        r = uapi16_manifest_writer_create_at(for_partitions, out, "m", &none, &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
        check_eq(uapi16_error_feature(e), UAPI16_FEATURE_GPT_LABEL);
        e = uapi16_error_free(e);
        r = uapi16_manifest_writer_open(for_partitions, fd, &none, &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
        check_eq(uapi16_error_feature(e), UAPI16_FEATURE_GPT_LABEL);
        e = uapi16_error_free(e);
        r = uapi16_manifest_generate_at(for_partitions, out, "m", tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
        check_eq(uapi16_error_feature(e), UAPI16_FEATURE_GPT_LABEL);
        e = uapi16_error_free(e);
        r = uapi16_manifest_generate(for_partitions, fd, tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
        check_eq(uapi16_error_feature(e), UAPI16_FEATURE_GPT_LABEL);
        e = uapi16_error_free(e);
        check(!none && !report);

        /* A writer that takes nothing more says that. */
        check_ended(uapi16_manifest_writer_add_object(finished, file, &e), &e);
        check_ended(uapi16_manifest_writer_finish(finished, &report, &e), &e);
        check(!report);

        /* None of that gave a descriptor back, and none closed one of the
         * caller. */
        check_eq(dup(fd), -1);
        check_eq(errno, EMFILE);
        check_open(tree);
        check_open(out);
        check_open(fd);
        check_open(manifest);
        check_open(written);

        while (n > 0)
                check_eq(close(taken[--n]), 0);
        check_eq(setrlimit(RLIMIT_NOFILE, &limit), 0);
}

/* Reads a pipe to its end, slowly, so that whoever writes to it waits. */
struct reader {
        int fd;
        char *data;
        size_t size;
};

static void *read_slowly(void *argument) {
        struct reader *reader = argument;
        struct timespec pause = { .tv_nsec = 20 * 1000 * 1000 };
        size_t room = 0;
        sigset_t all;

        /* The signals of the test are for the thread that writes. */
        sigfillset(&all);
        check_eq(pthread_sigmask(SIG_BLOCK, &all, NULL), 0);
        for (;;) {
                ssize_t n;

                if (reader->size == room) {
                        room = room ? room * 2 : 4096;
                        reader->data = realloc(reader->data, room);
                        check(reader->data);
                }
                nanosleep(&pause, NULL);
                n = read(reader->fd, reader->data + reader->size, room - reader->size);
                check(n >= 0);
                if (n == 0)
                        return NULL;
                reader->size += (size_t) n;
        }
}

/* Writes data to a pipe and closes it, slowly, so that whoever reads from
 * it waits. */
struct feeder {
        int fd;
        const char *data;
        size_t size;
};

static void *feed_slowly(void *argument) {
        struct feeder *feeder = argument;
        struct timespec pause = { .tv_nsec = 20 * 1000 * 1000 };
        size_t done = 0;
        sigset_t all;

        /* The signals of the test are for the thread that reads. */
        sigfillset(&all);
        check_eq(pthread_sigmask(SIG_BLOCK, &all, NULL), 0);
        while (done < feeder->size) {
                size_t piece = feeder->size - done < 16384 ? feeder->size - done : 16384;
                ssize_t n;

                nanosleep(&pause, NULL);
                n = write(feeder->fd, feeder->data + done, piece);
                check(n > 0);
                done += (size_t) n;
        }
        check_eq(close(feeder->fd), 0);
        return NULL;
}

static volatile sig_atomic_t alarms;

static void count_alarm(int signal) {
        (void) signal;
        alarms++;
}

/* The options of a child that a signal kills, where a tool that looks for
 * leaks finds them then. */
static uapi16_manifest_options *volatile killed;

/* What the process does with its signals: the handler of each, and which
 * of them it blocks. */
struct signals {
        struct sigaction actions[NSIG];
        sigset_t mask;
};

static void save_signals(struct signals *signals) {
        memset(signals, 0, sizeof(*signals));
        for (int i = 1; i < NSIG; i++)
                check(sigaction(i, NULL, &signals->actions[i]) == 0 || errno == EINVAL);
        check_eq(pthread_sigmask(SIG_SETMASK, NULL, &signals->mask), 0);
}

/* Checks that the process does with its signals what it did at `before`. */
static void check_signals(const struct signals *before) {
        struct sigaction after;
        sigset_t mask;

        for (int i = 1; i < NSIG; i++) {
                if (sigaction(i, NULL, &after) < 0)
                        continue;
                check(after.sa_handler == before->actions[i].sa_handler);
                check_eq(after.sa_flags, before->actions[i].sa_flags);
        }
        check_eq(pthread_sigmask(SIG_SETMASK, NULL, &mask), 0);
        for (int i = 1; i < NSIG; i++)
                check_eq(sigismember(&mask, i), sigismember(&before->mask, i));
}

/* Unblocks `signal` for this thread. A process can be started with a signal
 * blocked, and has it blocked in every thread and child then. Stores the
 * mask of before in `ret_old`, unless that is NULL. */
static void unblock_signal(int signal, sigset_t *ret_old) {
        sigset_t set;

        check_eq(sigemptyset(&set), 0);
        check_eq(sigaddset(&set, signal), 0);
        check_eq(pthread_sigmask(SIG_UNBLOCK, &set, ret_old), 0);
}

static void test_signals(void) {
        _cleanup_(closep) int tree = make_dir(tmp_fd, "signals"), manifest = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *source = NULL, *piped = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *copy = NULL, *broken = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *expected = NULL;
        struct sigaction old_alarm, old_pipe;
        struct sigaction count = { .sa_handler = count_alarm }, ignore = { .sa_handler = SIG_IGN };
        struct sigaction by_default = { .sa_handler = SIG_DFL };
        struct itimerval often = { { 0, 1000 }, { 0, 1000 } }, never = { { 0, 0 }, { 0, 0 } };
        struct reader reader = { .fd = -1 };
        struct feeder feeder = { .fd = -1 };
        struct signals before, during;
        sigset_t old_mask;
        size_t expected_size, files = 0;
        pthread_t thread;
        int pipe_fds[2], status, r;
        sig_atomic_t counted;
        char name[32];
        pid_t pid;

        /* A manifest that is larger than a pipe has room for. */
        for (int i = 0; i < 2000; i++) {
                snprintf(name, sizeof(name), "file-%04d", i);
                make_file(tree, name, "data");
        }

        /* The library leaves the handlers and the mask of the signals as
         * they are: here, and in everything below, where it is looked at
         * while the test has a handler of its own. */
        save_signals(&before);
        expected = generate(o, tree, UAPI16_ADD_NONE, &expected_size);
        check(expected_size > 128 * 1024);
        check_eq(uapi16_manifest_generate_at(o, tmp_fd, "signals.manifest", tree, UAPI16_ADD_NONE, &report, &e), 0);
        report = uapi16_manifest_report_free(report);
        check_signals(&before);
        check_eq(write(manifest, expected, expected_size), (ssize_t) expected_size);

        /* SIGPIPE is what it is for write(2): a pipe that nobody reads
         * kills a process that has the signal at its default. The default
         * is what the test can check, so each child sets it first and
         * unblocks the signal: the test can be started with the signal
         * ignored, as a runner of CI starts it, or blocked, and a child
         * has it so too then. This comes before the first thread of the
         * test, so that the child has nothing of a thread that a tool
         * could take for a leak. */
        check_eq(pipe2(pipe_fds, O_CLOEXEC), 0);
        check_eq(close(pipe_fds[0]), 0);
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                check_eq(sigaction(SIGPIPE, &by_default, NULL), 0);
                unblock_signal(SIGPIPE, NULL);
                killed = uapi16_manifest_options_new();
                uapi16_manifest_generate(killed, pipe_fds[1], tree, UAPI16_ADD_NONE, &report, NULL);
                _exit(EXIT_SUCCESS);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFSIGNALED(status));
        check_eq(WTERMSIG(status), SIGPIPE);
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                check_eq(sigaction(SIGPIPE, &by_default, NULL), 0);
                unblock_signal(SIGPIPE, NULL);
                killed = uapi16_manifest_options_new();
                uapi16_writer_begin(killed, pipe_fds[1], NULL, &broken, NULL);
                _exit(EXIT_SUCCESS);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFSIGNALED(status));
        check_eq(WTERMSIG(status), SIGPIPE);
        check_eq(close(pipe_fds[1]), 0);

        /* A signal that interrupts a system call does not fail the call:
         * the writes to a pipe that is full are made again. The alarms
         * have to arrive for that, so SIGALRM is unblocked for as long as
         * they are counted: the test can be started with it blocked. */
        unblock_signal(SIGALRM, &old_mask);
        check_eq(pipe2(pipe_fds, O_CLOEXEC), 0);
        reader.fd = pipe_fds[0];
        check_eq(pthread_create(&thread, NULL, read_slowly, &reader), 0);
        check_eq(sigaction(SIGALRM, &count, &old_alarm), 0);
        save_signals(&during);
        check_eq(setitimer(ITIMER_REAL, &often, NULL), 0);
        r = uapi16_manifest_generate(o, pipe_fds[1], tree, UAPI16_ADD_NONE, &report, &e);
        check_eq(setitimer(ITIMER_REAL, &never, NULL), 0);
        check_signals(&during);
        check_eq(sigaction(SIGALRM, &old_alarm, NULL), 0);
        check_eq(r, 0);
        check(alarms > 0);
        check_eq(close(pipe_fds[1]), 0);
        check_eq(pthread_join(thread, NULL), 0);
        check_eq(close(pipe_fds[0]), 0);
        check_same(reader.data, reader.size, expected, expected_size);
        free(reader.data);
        report = uapi16_manifest_report_free(report);

        /* So are those of a writer of records, which writes the manifest a
         * reader reads back to it, record by record. What comes out of the
         * pipe is the manifest. */
        check_eq(pipe2(pipe_fds, O_CLOEXEC), 0);
        reader = (struct reader) { .fd = pipe_fds[0] };
        source = open_reader(manifest);
        counted = alarms;
        check_eq(pthread_create(&thread, NULL, read_slowly, &reader), 0);
        check_eq(sigaction(SIGALRM, &count, &old_alarm), 0);
        save_signals(&during);
        check_eq(setitimer(ITIMER_REAL, &often, NULL), 0);
        r = uapi16_writer_begin(o, pipe_fds[1], uapi16_reader_root(source), &copy, &e);
        while (r == 0) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;

                if (uapi16_reader_next(source, &file, &e) != UAPI16_READ_FILE)
                        break;
                r = uapi16_writer_file(copy, file, &e);
                files++;
        }
        if (r == 0)
                r = uapi16_writer_finish(copy, &e);
        check_eq(setitimer(ITIMER_REAL, &never, NULL), 0);
        check_signals(&during);
        check_eq(sigaction(SIGALRM, &old_alarm, NULL), 0);
        check_eq(r, 0);
        check_eq(files, 2000);
        check(!e);
        check(alarms > counted);
        copy = uapi16_writer_free(copy);
        check_eq(close(pipe_fds[1]), 0);
        check_eq(pthread_join(thread, NULL), 0);
        check_eq(close(pipe_fds[0]), 0);
        check_same(reader.data, reader.size, expected, expected_size);
        free(reader.data);
        source = uapi16_reader_free(source);

        /* And the reads of a reader from a pipe that has nothing yet. */
        check_eq(pipe2(pipe_fds, O_CLOEXEC), 0);
        feeder = (struct feeder) { .fd = pipe_fds[1], .data = expected, .size = expected_size };
        counted = alarms;
        files = 0;
        check_eq(pthread_create(&thread, NULL, feed_slowly, &feeder), 0);
        check_eq(sigaction(SIGALRM, &count, &old_alarm), 0);
        save_signals(&during);
        check_eq(setitimer(ITIMER_REAL, &often, NULL), 0);
        r = uapi16_reader_open(pipe_fds[0], &piped, &e);
        while (r >= 0) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;

                r = uapi16_reader_next(piped, &file, &e);
                if (r != UAPI16_READ_FILE)
                        break;
                files++;
        }
        check_eq(setitimer(ITIMER_REAL, &never, NULL), 0);
        check_signals(&during);
        check_eq(sigaction(SIGALRM, &old_alarm, NULL), 0);
        check_eq(r, UAPI16_READ_END);
        check_eq(files, 2000);
        check(alarms > counted);
        check_eq(pthread_join(thread, NULL), 0);
        piped = uapi16_reader_free(piped);
        check_eq(close(pipe_fds[0]), 0);
        check(!e);
        check_eq(pthread_sigmask(SIG_SETMASK, &old_mask, NULL), 0);

        /* In a process that ignores the signal, a pipe that nobody reads
         * fails with EPIPE. */
        check_eq(pipe2(pipe_fds, O_CLOEXEC), 0);
        check_eq(close(pipe_fds[0]), 0);
        check_eq(sigaction(SIGPIPE, &ignore, &old_pipe), 0);
        save_signals(&during);
        r = uapi16_manifest_generate(o, pipe_fds[1], tree, UAPI16_ADD_NONE, &report, &e);
        check_error(r, e, UAPI16_ERROR_IO, EPIPE, NULL, 0);
        e = uapi16_error_free(e);
        r = uapi16_writer_begin(o, pipe_fds[1], NULL, &broken, &e);
        check_signals(&during);
        check_eq(sigaction(SIGPIPE, &old_pipe, NULL), 0);
        check_error(r, e, UAPI16_ERROR_IO, EPIPE, NULL, CHECK_RECORD);
        check(!report && !broken);
        check_eq(close(pipe_fds[1]), 0);
}

/* How many file objects the manifest has that the reader of test_fork()
 * reads: more than a reader has read of a manifest when it hands out its
 * first file object. */
#define MANY_OBJECTS 6000

/* What the parent of test_fork() has when it forks: an object of every
 * kind, and those that take nothing more. */
struct forked {
        /* Options, options with a feature of partitions, and options
         * without an order. */
        uapi16_manifest_options *o, *for_partitions, *unordered;
        uapi16_manifest_writer *created, *opened, *finished;
        const uapi16_manifest_report *report;
        const uapi16_error *error;
        /* A file object with every field, one with none but its data, and
         * a root. */
        uapi16_file_object *file, *hello, *root;
        /* A reader that hands out file objects, and one that hands out
         * signature objects. */
        uapi16_reader *reader, *signing;
        uapi16_writer *records, *finished_records;
        uapi16_signature *signature;
        uapi16_sha256 *sha, *finished_sha;
        uapi16_data_check *data, *finished_data;
        uapi16_directory *directory;
        /* The descriptors the objects have on loan: the tree and the
         * directory of the new file, and those of the writer that was
         * opened, of the writer of records and of the two readers. */
        int tree, out, opened_fd, records_fd, manifest_fd, signing_fd;
};

/* What a child can do with the objects of its parent: nothing but read
 * what can't fail, and free. */
static void check_child(const struct forked *p) {
        static const uapi16_uuid_t uuid = { .bytes = { 1 } };
        _cleanup_(closep) int fd = scratch_file(), written = scratch_file();
        _cleanup_(closep) int manifest =
                manifest_file(ROOT FILE_OBJECT("mine") SIGNATURE_OBJECT("pkcs7") TRAILER);
        _cleanup_(closep) int opened = -7;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *mine =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *none = NULL, *writer = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *no_report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *no_reader = NULL, *reader = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *no_records = NULL, *records = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *no_object = NULL, *object = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *own = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *no_signature = NULL, *signature = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *no_directory = NULL, *directory = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *no_data = NULL, *data = NULL;
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *sha = NULL;
        uapi16_sha256_digest_t hash = { .bytes = { 0 } };
        uapi16_uuid_t read_uuid = { .bytes = { 0 } };
        uint64_t number = 77, length = 77, offset = 7;
        uapi16_inode_token_t token = 77;
        uint32_t small = 77, stated = 77, set = 77;
        size_t count = 77, size = 77, begun;
        uapi16_file_object *theirs = p->hello;
        const char *contents_file = NULL;
        uapi16_signature *their_signature = p->signature;
        const char *name = NULL;
        const void *value = NULL;
        uapi16_error *e = NULL;
        int r;

        /* A call is checked for what it is given first. One that is not
         * valid fails for that here as it does in the parent. */
        check_misuse(uapi16_manifest_writer_add_object(NULL, p->hello, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_add_object(p->created, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_create_at(p->o, p->out, "", &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_create_at(p->o, p->out, "child", NULL, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_create_at(p->o, -1, "child", &none, &e), &e, EBADF);
        check_misuse(uapi16_manifest_writer_open(p->o, -1, &none, &e), &e, EBADF);
        r = uapi16_manifest_generate_at(p->o, p->out, "child", -1, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, EBADF);
        r = uapi16_manifest_generate(p->o, fd, p->tree, UINT64_C(1) << 40, &no_report, &e);
        check_misuse(r, &e, EINVAL);
        check_eq(set_features(p->o, FEATURES(UINT64_MAX)), -EINVAL);
        check_eq(uapi16_manifest_options_set_order(p->o, 2), -EINVAL);
        check_eq(uapi16_manifest_options_set_sync(NULL, true), -EINVAL);
        check_misuse(uapi16_reader_open(-1, &no_reader, &e), &e, EBADF);
        check_misuse(uapi16_reader_next(p->reader, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next_signature(p->signing, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_reader_require_order(p->reader, UAPI16_ORDER_NONE, &e), &e, EINVAL);
        check_eq(uapi16_reader_signed_len(p->signing, NULL), -EINVAL);
        check_misuse(uapi16_writer_begin(p->o, -1, NULL, &no_records, &e), &e, EBADF);
        check_misuse(uapi16_writer_begin(p->o, fd, p->hello, &no_records, &e), &e, EINVAL);
        check_misuse(uapi16_writer_file(p->records, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_signature(p->records, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_finish(NULL, &e), &e, EINVAL);
        check_eq(uapi16_signature_set_key(NULL, "k", 1), -EINVAL);
        check_eq(uapi16_file_object_set_type(p->file, 0), -EINVAL);
        check_eq(uapi16_file_object_set_read_only(p->file, 3), -EINVAL);
        check_eq(uapi16_file_object_set_sha256(p->file, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_user_name(p->file, NULL), -EINVAL);
        check_eq(uapi16_file_object_add_user_xattr(p->file, NULL, "v", 1), -EINVAL);
        check_eq(uapi16_file_object_add_user_xattr(p->file, "k", NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_mode(p->file, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_name(p->file, "a//b", NULL), -EINVAL);
        check_eq(uapi16_file_object_set_contents_file(p->file, NULL, NULL), -EINVAL);
        check_eq(uapi16_data_check_new(p->file, NULL), -EINVAL);
        check_misuse(uapi16_data_check_update(p->data, NULL, 1, &e), &e, EINVAL);
        check_eq(uapi16_sha256_update(p->sha, NULL, 1), -EINVAL);
        check_eq(uapi16_sha256_finish(p->sha, NULL), -EINVAL);
        check_misuse(uapi16_directory_new(-1, UAPI16_DIRECTORY_NONE, &no_directory, &e), &e, EBADF);
        check_misuse(uapi16_directory_new(p->tree, UINT64_C(1) << 1, &no_directory, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(p->directory, NULL, &opened, &offset, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(p->directory, p->hello, NULL, &offset, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(p->directory, p->hello, &opened, NULL, &e), &e, EINVAL);
        check_eq(retain_features(p->file, FEATURES(NO_FEATURE)), -EINVAL);
        check_misuse(uapi16_data_check_update_zeros(NULL, 1, &e), &e, EINVAL);
        check_eq(uapi16_sha256_update_zeros(NULL, 1), -EINVAL);
        check_eq(uapi16_error_record(p->error, NULL), -EINVAL);

        /* So does one whose `reterr` points to something, here to the
         * error of the parent, which stays where it is. */
        e = (uapi16_error *) p->error;
        check_eq(uapi16_manifest_writer_add_object(p->created, p->hello, &e), -EINVAL);
        check_eq(uapi16_manifest_writer_finish(p->finished, &no_report, &e), -EINVAL);
        check_eq(uapi16_manifest_writer_create_at(p->o, p->out, "child", &none, &e), -EINVAL);
        check_eq(uapi16_manifest_generate(p->for_partitions, fd, p->tree, UAPI16_ADD_NONE, &no_report, &e), -EINVAL);
        check_eq(uapi16_reader_next(p->reader, &no_object, &e), -EINVAL);
        check_eq(uapi16_writer_file(p->records, p->hello, &e), -EINVAL);
        check_eq(uapi16_file_object_set_name(p->file, "other", &e), -EINVAL);
        check_eq(uapi16_data_check_update(p->data, "lo", 2, &e), -EINVAL);
        check_eq(uapi16_data_check_update_zeros(p->data, 2, &e), -EINVAL);
        check_eq(uapi16_directory_open_data(p->directory, p->hello, &opened, &offset, &e), -EINVAL);
        check(e == p->error);
        e = NULL;

        /* Then for the process: options fail for it, however they are
         * used. */
        check_eq(set_features(p->o, FEATURES(DEFAULT_FEATURES)), -ECHILD);
        check_eq(uapi16_manifest_options_add_features(p->o, UAPI16_FEATURES(UAPI16_FEATURE_MTIME)), -ECHILD);
        check_eq(uapi16_manifest_options_remove_features(p->o, UAPI16_FEATURES(UAPI16_FEATURE_MODE)), -ECHILD);
        check_eq(uapi16_manifest_options_set_order(p->o, UAPI16_ORDER_CODEPOINT), -ECHILD);
        check_eq(uapi16_manifest_options_set_order(p->o, UAPI16_ORDER_NONE), -ECHILD);
        check_eq(uapi16_manifest_options_set_sync(p->o, true), -ECHILD);
        check_misuse(uapi16_manifest_writer_create_at(p->o, p->out, "child", &none, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_open(p->o, fd, &none, &e), &e, ECHILD);
        r = uapi16_manifest_generate_at(p->o, p->out, "child", p->tree, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, ECHILD);
        check_misuse(uapi16_manifest_generate(p->o, fd, p->tree, UAPI16_ADD_NONE, &no_report, &e), &e, ECHILD);
        check_misuse(uapi16_writer_begin(p->o, fd, NULL, &no_records, &e), &e, ECHILD);

        /* The features of the options are looked at after the process as
         * well: options with a feature of partitions fail for the process
         * here, and say nothing of the feature. */
        r = uapi16_manifest_writer_create_at(p->for_partitions, p->out, "child", &none, &e);
        check_misuse(r, &e, ECHILD);
        check_misuse(uapi16_manifest_writer_open(p->for_partitions, fd, &none, &e), &e, ECHILD);
        r = uapi16_manifest_generate_at(p->for_partitions, p->out, "child", p->tree, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, ECHILD);
        r = uapi16_manifest_generate(p->for_partitions, fd, p->tree, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, ECHILD);

        /* So is their order: options without one, which the functions that
         * sort refuse in the parent, fail for the process here. */
        r = uapi16_manifest_writer_create_at(p->unordered, p->out, "child", &none, &e);
        check_misuse(r, &e, ECHILD);
        check_misuse(uapi16_manifest_writer_open(p->unordered, fd, &none, &e), &e, ECHILD);
        r = uapi16_manifest_generate_at(p->unordered, p->out, "child", p->tree, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, ECHILD);
        r = uapi16_manifest_generate(p->unordered, fd, p->tree, UAPI16_ADD_NONE, &no_report, &e);
        check_misuse(r, &e, ECHILD);
        check_misuse(uapi16_writer_begin(p->unordered, fd, NULL, &no_records, &e), &e, ECHILD);
        check(!none && !no_report && !no_records);

        /* A writer fails for the process, and only then for what it is:
         * one that takes nothing more fails for the process here. */
        check_misuse(uapi16_manifest_writer_add_object(p->created, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_finish(p->created, &no_report, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_add_object(p->opened, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_finish(p->opened, &no_report, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_add_object(p->finished, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_finish(p->finished, &no_report, &e), &e, ECHILD);
        check_eq(uapi16_manifest_writer_add_object(p->created, p->hello, NULL), -ECHILD);
        check(!no_report);

        /* A reader reads nothing here, whatever comes next in its
         * manifest: a file object, a signature object, or a call that is
         * too early for one. */
        check_misuse(uapi16_reader_require_order(p->reader, UAPI16_ORDER_CODEPOINT, &e), &e, ECHILD);
        check_misuse(uapi16_reader_check_validity(p->reader, 0, &e), &e, ECHILD);
        check_misuse(uapi16_reader_next(p->reader, &no_object, &e), &e, ECHILD);
        check_misuse(uapi16_reader_next(p->signing, &no_object, &e), &e, ECHILD);
        check_misuse(uapi16_reader_next_signature(p->signing, &no_signature, &e), &e, ECHILD);
        check_misuse(uapi16_reader_next_signature(p->reader, &no_signature, &e), &e, ECHILD);
        check_eq(uapi16_reader_signed_len(p->signing, &length), -ECHILD);
        check_eq(uapi16_reader_signed_len(p->reader, &length), -ECHILD);
        check_eq(length, 77);
        check(!no_object && !no_signature);

        /* A writer of records writes nothing here. */
        check_misuse(uapi16_writer_file(p->records, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_writer_signature(p->records, p->signature, &e), &e, ECHILD);
        check_misuse(uapi16_writer_finish(p->records, &e), &e, ECHILD);
        check_misuse(uapi16_writer_file(p->finished_records, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_writer_signature(p->finished_records, p->signature, &e), &e, ECHILD);
        check_misuse(uapi16_writer_finish(p->finished_records, &e), &e, ECHILD);

        /* A signature object is not changed here. */
        check_eq(uapi16_signature_set_key(p->signature, "other", 5), -ECHILD);
        check_eq(uapi16_signature_set_key(p->signature, NULL, 0), -ECHILD);
        check_eq(uapi16_signature_set_data(p->signature, "data", 4), -ECHILD);
        check_eq(uapi16_signature_set_data(p->signature, NULL, 0), -ECHILD);

        /* A file object is neither changed nor read here by a function
         * that can fail, and such a getter stores nothing. */
        check_misuse(uapi16_file_object_set_name(p->file, "other", &e), &e, ECHILD);
        check_eq(uapi16_file_object_set_type(p->file, S_IFDIR), -ECHILD);
        check_eq(uapi16_file_object_set_mode(p->file, 0600), -ECHILD);
        check_eq(uapi16_file_object_mode(p->file, &small), -ECHILD);
        check_eq(uapi16_file_object_set_uid(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_uid(p->file, &small), -ECHILD);
        check_eq(uapi16_file_object_set_gid(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_gid(p->file, &small), -ECHILD);
        check_eq(uapi16_file_object_set_user_name(p->file, "other"), -ECHILD);
        check_eq(uapi16_file_object_set_group_name(p->file, "other"), -ECHILD);
        check_eq(uapi16_file_object_set_mtime_nsec(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_mtime_nsec(p->file, &number), -ECHILD);
        check_eq(uapi16_file_object_set_size(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_size(p->file, &number), -ECHILD);
        check_eq(uapi16_file_object_set_sha256(p->file, &hash), -ECHILD);
        check_eq(uapi16_file_object_sha256(p->file, &hash), -ECHILD);
        check_eq(uapi16_file_object_set_major(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_major(p->file, &number), -ECHILD);
        check_eq(uapi16_file_object_set_minor(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_minor(p->file, &number), -ECHILD);
        check_eq(uapi16_file_object_set_inode_token(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_inode_token(p->file, &token), -ECHILD);
        check_eq(uapi16_file_object_contents_file(p->file, &contents_file, &number), -ECHILD);
        check(!contents_file);
        check_eq(uapi16_file_object_set_user_xattrs(p->file), -ECHILD);
        check_eq(uapi16_file_object_add_user_xattr(p->file, "other", "v", 1), -ECHILD);
        check_eq(uapi16_file_object_user_xattrs(p->file, &count), -ECHILD);
        check_eq(uapi16_file_object_user_xattr(p->file, 0, &name, &value, &size), -ECHILD);
        check_eq(uapi16_file_object_set_read_only(p->file, UAPI16_READ_ONLY_YES), -ECHILD);
        check_eq(uapi16_file_object_set_inode_flags(p->file, 0, 0), -ECHILD);
        check_eq(uapi16_file_object_inode_flags(p->file, &stated, &set), -ECHILD);
        check_eq(uapi16_file_object_set_dos_attributes(p->file, 0, 0), -ECHILD);
        check_eq(uapi16_file_object_dos_attributes(p->file, &stated, &set), -ECHILD);
        check_eq(uapi16_file_object_set_target(p->file, "other", 5), -ECHILD);
        check_misuse(uapi16_file_object_set_contents_file(p->file, "other", &e), &e, ECHILD);
        check_eq(uapi16_file_object_set_fs_label(p->file, "other"), -ECHILD);
        check_eq(uapi16_file_object_set_fs_uuid(p->file, &uuid), -ECHILD);
        check_eq(uapi16_file_object_fs_uuid(p->file, &read_uuid), -ECHILD);
        check_eq(uapi16_file_object_set_fat_serial(p->file, 9), -ECHILD);
        check_eq(uapi16_file_object_fat_serial(p->file, &small), -ECHILD);
        check_misuse(uapi16_file_object_check_validity(p->file, 0, &e), &e, ECHILD);
        check_eq(retain_features(p->file, FEATURES(UAPI16_FEATURE_NONE)), -ECHILD);
        check_eq(retain_features(p->file, FEATURES(UAPI16_FEATURE_MODE)), -ECHILD);
        check_eq(small, 77);
        check_eq(number, 77);
        check_eq(token, 77);
        check_eq(count, 77);
        check_eq(size, 77);
        check(stated == 77 && set == 77 && !name && !value && hash.bytes[0] == 0 && read_uuid.bytes[0] == 0);

        /* One without a field fails for the process too, and not for the
         * field, and so does the root of a reader. */
        check_eq(uapi16_file_object_mode(p->hello, &small), -ECHILD);
        check_eq(uapi16_file_object_inode_token(p->hello, &token), -ECHILD);
        check_eq(uapi16_file_object_user_xattrs(p->hello, &count), -ECHILD);
        check_eq(uapi16_file_object_mode(uapi16_reader_root(p->reader), &small), -ECHILD);
        check_eq(uapi16_file_object_set_type(p->root, S_IFDIR), -ECHILD);

        /* No check is made of the data of such an object, a check takes no
         * data, and a hash is not computed on. */
        check_eq(uapi16_data_check_new(p->hello, &no_data), -ECHILD);
        check_misuse(uapi16_data_check_update(p->data, "lo", 2, &e), &e, ECHILD);
        check_misuse(uapi16_data_check_finish(p->data, &number, &e), &e, ECHILD);
        check_misuse(uapi16_data_check_update(p->finished_data, "lo", 2, &e), &e, ECHILD);
        check_misuse(uapi16_data_check_finish(p->finished_data, &number, &e), &e, ECHILD);
        check_eq(uapi16_sha256_update(p->sha, "lo", 2), -ECHILD);
        check_eq(uapi16_sha256_finish(p->sha, &hash), -ECHILD);
        check_eq(uapi16_sha256_update(p->finished_sha, "lo", 2), -ECHILD);
        check_eq(uapi16_sha256_finish(p->finished_sha, &hash), -ECHILD);
        check_misuse(uapi16_data_check_update_zeros(p->data, 2, &e), &e, ECHILD);
        check_misuse(uapi16_data_check_update_zeros(p->finished_data, 2, &e), &e, ECHILD);
        check_eq(uapi16_sha256_update_zeros(p->sha, 2), -ECHILD);
        check_eq(uapi16_sha256_update_zeros(p->finished_sha, 2), -ECHILD);
        check(!no_data && number == 77 && token == 77 && hash.bytes[0] == 0);

        /* What can't fail gives what the object has, as in the parent. */
        check_str(uapi16_file_object_name(p->file), "dir/file");
        check_eq(uapi16_file_object_type(p->file), S_IFREG);
        check_str(uapi16_file_object_user_name(p->file), "user");
        check_str(uapi16_file_object_group_name(p->file), "group");
        check_eq(uapi16_file_object_read_only(p->file), UAPI16_READ_ONLY_NO);
        check_eq(uapi16_file_object_data_location(p->file), UAPI16_DATA_LOCATION_LITERAL);
        value = uapi16_file_object_literal(p->file, &size);
        check_same(value, size, "target", 6);
        check_str(uapi16_file_object_fs_label(p->file), "label");
        check(uapi16_file_object_has_stated_feature(p->file, UAPI16_FEATURE_MODE));
        check_str(uapi16_signature_mechanism(p->signature), "openpgp");
        value = uapi16_signature_key(p->signature, &size);
        check_same(value, size, "key", 3);
        check(!uapi16_signature_data(p->signature, &size));
        check_eq(size, 0);
        check_str(uapi16_file_object_name(uapi16_reader_root(p->reader)), "");
        check_recorded(p->reader, FEATURES(DEFAULT_FEATURES));
        check_eq(uapi16_reader_order(p->reader), UAPI16_ORDER_CODEPOINT);
        check_eq(uapi16_name_compare("a/x", "a-b"), UAPI16_NAME_BEFORE);
        check_str(uapi16_feature_name(UAPI16_FEATURE_MODE), "mode");
        check_eq(uapi16_feature_from_name("mode"), UAPI16_FEATURE_MODE);

        /* Reports and errors are read as in the parent. */
        check_eq(uapi16_manifest_report_files(p->report), 3);
        check_eq(uapi16_error_kind(p->error), UAPI16_ERROR_INVALID_ARGUMENT);
        check_eq(uapi16_error_errno(p->error), EINVAL);
        check_eq(uapi16_error_name_problem(p->error), UAPI16_NAME_PROBLEM_EMPTY_COMPONENT);
        check_eq(uapi16_error_record(p->error, &number), -ENODATA);

        /* What the child makes itself is its own, and works. */
        check_eq(uapi16_manifest_generate_at(mine, p->out, "child", p->tree, UAPI16_ADD_NONE, &no_report, &e), 0);
        check_eq(uapi16_manifest_report_files(no_report), 3);
        check_eq(uapi16_file_object_new("mine", &object, &e), 0);
        check_eq(uapi16_file_object_set_size(object, 2), 0);
        check_eq(uapi16_signature_new("pkcs7", &signature), 0);
        check_eq(uapi16_signature_set_key(signature, "mine", 4), 0);
        check_eq(uapi16_data_check_new(object, &data), 0);
        check_eq(uapi16_data_check_update(data, "ok", 2, &e), 0);
        check_eq(uapi16_data_check_finish(data, &number, &e), 0);
        check_eq(number, 2);
        sha = uapi16_sha256_new();
        check_eq(uapi16_sha256_update(sha, "abc", 3), 0);
        check_eq(uapi16_sha256_finish(sha, &hash), 0);
        check_hash(&hash, SHA256_OF_ABC);
        check_eq(uapi16_manifest_writer_open(mine, fd, &writer, &e), 0);
        check_eq(uapi16_writer_begin(mine, written, NULL, &records, &e), 0);
        check_eq(uapi16_reader_open(manifest, &reader, &e), 0);
        check_eq(uapi16_directory_new(p->out, UAPI16_DIRECTORY_NONE, &directory, &e), 0);
        check_eq(uapi16_file_object_new("child", &own, &e), 0);
        check(!e);

        /* An object of the parent is none for a reader of the child to
         * fill: the read fails before it reads anything, and leaves the
         * object where it is and as it is. The reader hands out its first
         * file object after that, and its first signature object. */
        check_misuse(uapi16_reader_next(reader, &theirs, &e), &e, ECHILD);
        check(theirs == p->hello);
        check_str(uapi16_file_object_name(p->hello), "hello");
        check_eq(uapi16_reader_next(reader, &no_object, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(no_object), "mine");
        check_eq(uapi16_reader_next(reader, &no_object, &e), UAPI16_READ_SIGNATURES);
        check_misuse(uapi16_reader_next_signature(reader, &their_signature, &e), &e, ECHILD);
        check(their_signature == p->signature);
        check_str(uapi16_signature_mechanism(p->signature), "openpgp");
        check_eq(uapi16_reader_next_signature(reader, &no_signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(no_signature), "pkcs7");
        check_eq(uapi16_reader_next_signature(reader, &no_signature, &e), UAPI16_READ_END);

        /* A directory of the parent opens nothing here, and a directory of
         * the child opens nothing for an object of the parent. With an
         * object of the child it opens the manifest the child wrote. */
        check_misuse(uapi16_directory_open_data(p->directory, own, &opened, &offset, &e), &e, ECHILD);
        check_misuse(uapi16_directory_open_data(directory, p->hello, &opened, &offset, &e), &e, ECHILD);
        check_eq(opened, -7);
        check_eq(offset, 7);
        check_eq(uapi16_directory_open_data(directory, own, &opened, &offset, &e), 0);
        check(opened >= 0);
        check_eq(offset, 0);
        check(!e);

        /* An object of the parent is none for a writer of the child to
         * take either: a file object and a root for a writer, a file
         * object and a signature object for a writer of records, and a
         * root for a writer of records to begin with. Nothing is written
         * for them. */
        begun = size_of(written);
        check_misuse(uapi16_manifest_writer_add_object(writer, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_manifest_writer_add_object(writer, p->root, &e), &e, ECHILD);
        check_misuse(uapi16_writer_file(records, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_writer_signature(records, p->signature, &e), &e, ECHILD);
        check_misuse(uapi16_writer_begin(mine, fd, p->root, &no_records, &e), &e, ECHILD);
        check_eq(uapi16_manifest_writer_add_object(writer, p->hello, NULL), -ECHILD);
        check_eq(uapi16_writer_file(records, p->hello, NULL), -ECHILD);
        check(!no_records);
        check_eq(size_of(written), begun);
        check_eq(size_of(fd), 0);
        check_eq(uapi16_manifest_writer_add_object(writer, object, &e), 0);
        check_eq(uapi16_writer_file(records, object, &e), 0);
        check_eq(uapi16_writer_signature(records, signature, &e), 0);
        check(!e);

        /* The object a call is given is looked at for its process before
         * the writer is for what it is: one of the child that is finished
         * fails for an object of the parent as one that is not does. With
         * an object of the child it says that it takes nothing more. */
        check_eq(uapi16_manifest_writer_finish(writer, NULL, &e), 0);
        check_eq(uapi16_writer_finish(records, &e), 0);
        check_misuse(uapi16_manifest_writer_add_object(writer, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_writer_file(records, p->hello, &e), &e, ECHILD);
        check_misuse(uapi16_writer_signature(records, p->signature, &e), &e, ECHILD);
        check_ended(uapi16_manifest_writer_add_object(writer, object, &e), &e);
        check_ended(uapi16_writer_file(records, object, &e), &e);
        check_ended(uapi16_writer_signature(records, signature, &e), &e);

        /* Freeing works, and neither writes nor links anything. */
        check(!uapi16_manifest_writer_free(p->created));
        check(!uapi16_manifest_writer_free(p->opened));
        check(!uapi16_manifest_writer_free(p->finished));
        check(!uapi16_manifest_options_free(p->o));
        check(!uapi16_manifest_options_free(p->for_partitions));
        check(!uapi16_manifest_report_free((uapi16_manifest_report *) p->report));
        check(!uapi16_error_free((uapi16_error *) p->error));
        check(!uapi16_file_object_free(p->file));
        check(!uapi16_file_object_free(p->hello));
        check(!uapi16_file_object_free(p->root));
        check(!uapi16_reader_free(p->reader));
        check(!uapi16_reader_free(p->signing));
        check(!uapi16_writer_free(p->records));
        check(!uapi16_writer_free(p->finished_records));
        check(!uapi16_signature_free(p->signature));
        check(!uapi16_sha256_free(p->sha));
        check(!uapi16_sha256_free(p->finished_sha));
        check(!uapi16_data_check_free(p->data));
        check(!uapi16_data_check_free(p->finished_data));
        check(!uapi16_directory_free(p->directory));

        /* The descriptors those objects had on loan are open here once the
         * objects are freed: nothing closed the copy the child has of
         * them. */
        check_open(p->tree);
        check_open(p->out);
        check_open(p->opened_fd);
        check_open(p->records_fd);
        check_open(p->manifest_fd);
        check_open(p->signing_fd);
        check_open(null_fd);
}

static void test_fork(void) {
        static const uapi16_uuid_t uuid = { .bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } };
        _cleanup_(closep) int tree = make_tree("fork"), out = make_dir(tmp_fd, "fork-out");
        _cleanup_(closep) int fd = openat(out, "opened", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        _cleanup_(closep) int written = openat(out, "records", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        _cleanup_(closep) int manifest = scratch_file();
        _cleanup_(closep) int with_signature =
                manifest_file(ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp") TRAILER);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *for_partitions =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *unordered =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *created = NULL, *opened = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *finished = open_writer(o);
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *first = NULL, *second = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *error = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object("dir/file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *hello = make_hello("hello");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL, *no_object = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *signing = NULL, *written_back = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL, *finished_records = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL, *read_signature = NULL;
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *sha = uapi16_sha256_new();
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *finished_sha = uapi16_sha256_new();
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *data = NULL, *finished_data = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *directory = NULL;
        _cleanup_(freep) char *expected = NULL, *made = NULL, *streamed = NULL, *child = NULL;
        size_t expected_size, made_size, streamed_size, child_size, begun, key_size = 0;
        uapi16_sha256_digest_t hash;
        const void *key;
        struct forked parent;
        uint64_t total = 0;
        struct stat st;
        char name[32];
        int status, r;
        pid_t pid;

        check(fd >= 0 && written >= 0);
        expected = generate(o, tree, UAPI16_ADD_NONE, &expected_size);
        check_eq(uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e), 0);
        empty(fd);
        r = set_features(for_partitions, FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_GPT_LABEL));
        check_eq(r, 0);
        check_eq(uapi16_manifest_options_set_order(unordered, UAPI16_ORDER_NONE), 0);

        /* A file object with every field. */
        unhex(SHA256_OF_HELLO, &hash);
        check_eq(uapi16_file_object_set_mode(file, 0644), 0);
        check_eq(uapi16_file_object_set_uid(file, 1), 0);
        check_eq(uapi16_file_object_set_gid(file, 2), 0);
        check_eq(uapi16_file_object_set_user_name(file, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(file, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(file, 3), 0);
        check_eq(uapi16_file_object_set_size(file, 6), 0);
        check_eq(uapi16_file_object_set_sha256(file, &hash), 0);
        check_eq(uapi16_file_object_set_major(file, 4), 0);
        check_eq(uapi16_file_object_set_minor(file, 5), 0);
        check_eq(uapi16_file_object_set_inode_token(file, 6), 0);
        check_eq(uapi16_file_object_add_user_xattr(file, "k", "v", 1), 0);
        check_eq(uapi16_file_object_set_read_only(file, UAPI16_READ_ONLY_NO), 0);
        check_eq(uapi16_file_object_set_inode_flags(file, NODUMP_FL, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_dos_attributes(file, DOS_HIDDEN, 0), 0);
        check_eq(uapi16_file_object_set_target(file, "target", 6), 0);
        check_eq(uapi16_file_object_set_fs_label(file, "label"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(file, &uuid), 0);
        check_eq(uapi16_file_object_set_fat_serial(file, 7), 0);

        /* Two writers with a file object each, and one that is finished. */
        check_eq(uapi16_manifest_writer_create_at(o, out, "created", &created, &e), 0);
        check_eq(uapi16_manifest_writer_open(o, fd, &opened, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(created, hello, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(opened, hello, &e), 0);
        check_eq(uapi16_manifest_writer_finish(finished, NULL, &e), 0);
        check_eq(uapi16_file_object_new("a//b", &no_object, &error), -EINVAL);
        check(error);

        /* A reader that has handed out the first of many file objects, and
         * one that signature objects come from next. */
        check_eq(write(manifest, ROOT, strlen(ROOT)), (ssize_t) strlen(ROOT));
        for (int i = 0; i < MANY_OBJECTS; i++)
                check(dprintf(manifest, RS "{\"name\":\"file-%06d\"}\n", i) > 0);
        check_eq(write(manifest, TRAILER, strlen(TRAILER)), (ssize_t) strlen(TRAILER));
        reader = open_reader(manifest);
        got = next_object(reader, "file-000000");
        got = uapi16_file_object_free(got);
        signing = open_reader(with_signature);
        got = next_object(signing, "a");
        got = uapi16_file_object_free(got);
        check_eq(uapi16_reader_next(signing, &got, &e), UAPI16_READ_SIGNATURES);

        /* A writer of records that has written one, and one that is
         * finished. */
        check_eq(uapi16_signature_new("openpgp", &signature), 0);
        check_eq(uapi16_signature_set_key(signature, "key", 3), 0);
        records = begin_records(o, written);
        check_eq(uapi16_writer_file(records, hello, &e), 0);
        begun = size_of(written);
        finished_records = begin_records(o, null_fd);
        check_eq(uapi16_writer_finish(finished_records, &e), 0);

        /* A hash and a check that have seen a part of their data, and two
         * that are finished. */
        check_eq(uapi16_sha256_update(sha, "hel", 3), 0);
        check_eq(uapi16_sha256_finish(finished_sha, &hash), 0);
        check_eq(uapi16_data_check_new(hello, &data), 0);
        check_eq(uapi16_data_check_update(data, "hel", 3, &e), 0);
        check_eq(uapi16_data_check_new(hello, &finished_data), 0);
        check_eq(uapi16_data_check_update(finished_data, "hello", 5, &e), 0);
        check_eq(uapi16_data_check_finish(finished_data, NULL, &e), 0);
        check_eq(uapi16_directory_new(out, UAPI16_DIRECTORY_NONE, &directory, &e), 0);
        check(!e);

        parent = (struct forked) {
                .o = o,
                .for_partitions = for_partitions,
                .unordered = unordered,
                .created = created,
                .opened = opened,
                .finished = finished,
                .report = report,
                .error = error,
                .file = file,
                .hello = hello,
                .root = root,
                .reader = reader,
                .signing = signing,
                .records = records,
                .finished_records = finished_records,
                .signature = signature,
                .sha = sha,
                .finished_sha = finished_sha,
                .data = data,
                .finished_data = finished_data,
                .directory = directory,
                .tree = tree,
                .out = out,
                .opened_fd = fd,
                .records_fd = written,
                .manifest_fd = manifest,
                .signing_fd = with_signature,
        };
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                check_child(&parent);
                fflush(NULL);
                _exit(EXIT_SUCCESS);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        check_eq(WEXITSTATUS(status), EXIT_SUCCESS);

        /* The descriptors that are on loan are open in the parent, whose
         * objects the child freed in its own memory alone. */
        check_open(tree);
        check_open(out);
        check_open(fd);
        check_open(written);
        check_open(manifest);
        check_open(with_signature);
        check_open(null_fd);

        /* The child wrote nothing and linked nothing, and what it freed is
         * all there in the parent, which finishes. */
        check_eq(fstatat(out, "created", &st, 0), -1);
        check_eq(errno, ENOENT);
        check_eq(size_of(fd), 0);
        check_eq(size_of(written), begun);
        check_eq(uapi16_manifest_writer_finish(created, &first, &e), 0);
        check_eq(uapi16_manifest_writer_finish(opened, &second, &e), 0);
        check(!e);
        check_ended(uapi16_manifest_writer_add_object(finished, hello, &e), &e);
        check_eq(uapi16_manifest_report_files(first), 1);
        check_eq(uapi16_manifest_report_files(second), 1);
        opened = uapi16_manifest_writer_free(opened);
        r = uapi16_manifest_writer_open(for_partitions, fd, &none, &e);
        check_error(r, e, UAPI16_ERROR_INVALID_ARGUMENT, EINVAL, NULL, CHECK_FEATURE);
        check_eq(uapi16_error_feature(e), UAPI16_FEATURE_GPT_LABEL);
        e = uapi16_error_free(e);
        made = read_file(out, "created", &made_size);
        streamed = read_all(fd, &streamed_size);
        check_manifest(made, made_size);
        check_same(streamed, streamed_size, made, made_size);
        child = read_file(out, "child", &child_size);
        check_same(child, child_size, expected, expected_size);

        /* The reader reads on where it was: the child read nothing of its
         * manifest. */
        for (int i = 1; i < MANY_OBJECTS; i++) {
                snprintf(name, sizeof(name), "file-%06d", i);
                got = next_object(reader, name);
                got = uapi16_file_object_free(got);
        }
        check_ends(reader);
        check_eq(uapi16_reader_next_signature(signing, &read_signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(read_signature), "openpgp");
        read_signature = uapi16_signature_free(read_signature);
        check_eq(uapi16_reader_next_signature(signing, &read_signature, &e), UAPI16_READ_END);

        /* The writer of records writes on, and its manifest has what the
         * parent wrote. */
        check_eq(uapi16_writer_signature(records, signature, &e), 0);
        check_eq(uapi16_writer_finish(records, &e), 0);
        check_ended(uapi16_writer_finish(finished_records, &e), &e);
        records = uapi16_writer_free(records);
        written_back = open_reader(written);
        got = next_object(written_back, "hello");
        got = uapi16_file_object_free(got);
        check_eq(uapi16_reader_next(written_back, &got, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(written_back, &read_signature, &e), UAPI16_READ_SIGNATURE);
        key = uapi16_signature_key(read_signature, &key_size);
        check_same(key, key_size, "key", 3);
        read_signature = uapi16_signature_free(read_signature);
        check_eq(uapi16_reader_next_signature(written_back, &read_signature, &e), UAPI16_READ_END);

        /* The hash and the check go on with their data. */
        check_eq(uapi16_sha256_update(sha, "lo", 2), 0);
        check_eq(uapi16_sha256_finish(sha, &hash), 0);
        check_hash(&hash, SHA256_OF_HELLO);
        check_eq(uapi16_sha256_update(finished_sha, "x", 1), -ESTALE);
        check_eq(uapi16_data_check_update(data, "lo", 2, &e), 0);
        check_eq(uapi16_data_check_finish(data, &total, &e), 0);
        check_eq(total, 5);
        check_ended(uapi16_data_check_finish(finished_data, NULL, &e), &e);
        check(!e);
}

/* How many files test_scratch_files() gives a writer, each with two names
 * of the longest size: more file objects and more hard links than a writer
 * keeps in memory. */
#define SCRATCH_INODES 5000

/* How many files a writer has something in once it has that many file
 * objects: one with file objects, and two with hard links, their table and
 * their names. */
#define SCRATCH_FILES_MIN 3

/* How many descriptors test_scratch_files() and test_failed_walks() look
 * through for the files a writer keeps on disk: more than the process has
 * open. */
#define SCRATCH_DESCRIPTORS 256

/* Notes in `unnamed` which descriptors of the process are regular files
 * without a name that hold something, as the files do that a writer keeps
 * file objects and hard links in. */
static void unnamed_files(bool unnamed[static SCRATCH_DESCRIPTORS]) {
        for (int fd = 0; fd < SCRATCH_DESCRIPTORS; fd++) {
                struct stat st;

                unnamed[fd] = fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_nlink == 0 &&
                              st.st_size > 0;
        }
}

/* The name of a file of test_scratch_files(): `link` is 'a' or 'b' for the
 * first or the second name of the file `inode`. */
static void scratch_name(char name[static NAME_OF_OBJECT_MAX + 1], int inode, char link) {
        char start[16];
        int n = snprintf(start, sizeof(start), "%06d%c", inode, link);

        memset(name, 'n', NAME_OF_OBJECT_MAX);
        memcpy(name, start, (size_t) n);
        name[NAME_OF_OBJECT_MAX] = 0;
}

/* Whether the call that returned `r` found no room where it writes.
 * test_scratch_files() needs about 100 MiB there, and is skipped with a
 * line where a file system has less. */
static bool no_room(int r) {
        if (r != -ENOSPC)
                return false;
        fprintf(stderr, "skipping the scratch files of a writer: no room for them here, about 100 MiB\n");
        return true;
}

/* Adds the files of test_scratch_files() to `w`, the last one first. Then
 * the writer keeps file objects and hard links on disk, in files that were
 * not among `before`, which this checks. Notes those files in `scratch`. */
static bool add_scratch_files(uapi16_manifest_writer *w, const bool before[static SCRATCH_DESCRIPTORS],
                              bool scratch[static SCRATCH_DESCRIPTORS]) {
        char name[NAME_OF_OBJECT_MAX + 1];
        size_t count = 0;

        for (int inode = SCRATCH_INODES - 1; inode >= 0; inode--)
                for (char link = 'a'; link <= 'b'; link++) {
                        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
                        int r;

                        scratch_name(name, inode, link);
                        check_eq(uapi16_file_object_new(name, &o, NULL), 0);
                        check_eq(uapi16_file_object_set_size(o, 0), 0);
                        check_eq(uapi16_file_object_set_inode_token(o, (uapi16_inode_token_t) inode + 1), 0);
                        r = uapi16_manifest_writer_add_object(w, o, NULL);
                        if (no_room(r))
                                return false;
                        check_eq(r, 0);
                }
        unnamed_files(scratch);
        for (int fd = 0; fd < SCRATCH_DESCRIPTORS; fd++) {
                scratch[fd] = scratch[fd] && !before[fd];
                count += scratch[fd];
        }
        check(count >= SCRATCH_FILES_MIN);
        return true;
}

/* Checks that the manifest in the file `fd` has every file of
 * test_scratch_files(), with its two names as the names of one file. */
static void check_scratch_files(int fd) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        uapi16_reader *reader = open_reader(fd);
        char name[NAME_OF_OBJECT_MAX + 1];
        uapi16_inode_token_t last = UAPI16_INODE_TOKEN_NONE;

        for (int inode = 0; inode < SCRATCH_INODES; inode++) {
                uapi16_inode_token_t first = 0, second = 0;

                scratch_name(name, inode, 'a');
                check_eq(uapi16_reader_next(reader, &o, NULL), UAPI16_READ_FILE);
                check_str(uapi16_file_object_name(o), name);
                check_eq(uapi16_file_object_inode_token(o, &first), 0);
                scratch_name(name, inode, 'b');
                check_eq(uapi16_reader_next(reader, &o, NULL), UAPI16_READ_FILE);
                check_str(uapi16_file_object_name(o), name);
                check_eq(uapi16_file_object_inode_token(o, &second), 0);
                check_eq(second, first);
                check(first != last);
                last = first;
        }
        check_eq(uapi16_reader_next(reader, &o, NULL), UAPI16_READ_END);
        uapi16_reader_free(reader);
}

/* A writer of a large manifest keeps file objects and hard links in files
 * of its own, which the child of a fork() has open as well. A child that
 * frees the writer leaves them as they are: the parent finishes and has
 * the whole manifest, in a new file and in a file of its own. A writer
 * whose files were emptied fails, with EIO for an error that no system
 * call gave an errno. */
static void test_scratch_files(void) {
        _cleanup_(closep) int out = make_dir(tmp_fd, "scratch-out");
        _cleanup_(closep) int fd = openat(out, "opened", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *emptied = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        bool before[SCRATCH_DESCRIPTORS], scratch[SCRATCH_DESCRIPTORS];
        int r;

        check(o && fd >= 0);
        for (int created = 0; created < 2; created++) {
                _cleanup_(closep) int created_fd = -1;
                _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
                int status;
                pid_t pid;

                unnamed_files(before);
                if (created)
                        check_eq(uapi16_manifest_writer_create_at(o, out, "created", &w, &e), 0);
                else
                        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);
                if (!add_scratch_files(w, before, scratch))
                        return;

                fflush(NULL);
                pid = fork();
                check(pid >= 0);
                if (pid == 0) {
                        uapi16_manifest_writer_free(w);
                        /* Its copy of the options as well, so that it
                         * leaves nothing behind that a check for leaks
                         * would find. */
                        uapi16_manifest_options_free(o);
                        _exit(EXIT_SUCCESS);
                }
                check_eq(waitpid(pid, &status, 0), pid);
                check(WIFEXITED(status));
                check_eq(WEXITSTATUS(status), EXIT_SUCCESS);

                /* The parent has every file object and every hard link
                 * still, and a new file gets its name from it. */
                r = uapi16_manifest_writer_finish(w, &report, &e);
                if (no_room(r))
                        return;
                check_eq(r, 0);
                check(!e);
                check_eq(uapi16_manifest_report_files(report), 2 * SCRATCH_INODES);
                report = uapi16_manifest_report_free(report);
                if (created) {
                        created_fd = openat(out, "created", O_RDONLY | O_CLOEXEC);
                        check(created_fd >= 0);
                }
                check_scratch_files(created ? created_fd : fd);
                check_eq(count_entries(tmp_fd, "scratch-out"), (size_t) 1 + (size_t) created);
        }
        check_eq(unlinkat(out, "created", 0), 0);

        /* The files of a writer are emptied behind its back, as a child did
         * that did not leave them alone. The writer finds that when it
         * reads them, and fails. */
        empty(fd);
        unnamed_files(before);
        check_eq(uapi16_manifest_writer_open(o, fd, &emptied, &e), 0);
        if (!add_scratch_files(emptied, before, scratch))
                return;
        for (int scratch_fd = 0; scratch_fd < SCRATCH_DESCRIPTORS; scratch_fd++)
                if (scratch[scratch_fd])
                        check_eq(ftruncate(scratch_fd, 0), 0);
        r = uapi16_manifest_writer_finish(emptied, &report, &e);
        check_error(r, e, UAPI16_ERROR_IO, EIO, NULL, 0);
        check(!report);
        e = uapi16_error_free(e);
        check_ended(uapi16_manifest_writer_finish(emptied, &report, &e), &e);
}

/* How many directories inside each other the files of test_failed_walks()
 * are in, each with a name as long as a name gets: as many as leave room
 * for the name of a file in the last of them. */
#define WALK_DEPTH 15

/* How many files test_failed_walks() makes there, each with two names. A
 * walk keeps their hard links on disk before it has come to half of their
 * names. */
#define WALK_INODES 5000

/* How many descriptors of the files of a walk test_failed_walks() holds
 * at most: more than a walk has of them. */
#define WALK_FILES_MAX 16

/* What test_failed_walks() stops a walk with, and what it holds of the
 * files the walk keeps on disk. */
static struct {
        /* The watch of the directory the walk reads. */
        int watch;
        /* Which descriptors the process had before the walk. */
        bool before[SCRATCH_DESCRIPTORS];
        /* The limit that leaves the process no descriptor to open. */
        struct rlimit none;
        /* Whether a signal came for the walk, and whether it was stopped. */
        volatile sig_atomic_t signaled, stopped;
        /* A copy of each descriptor the walk had of a file without a name
         * when it was stopped. */
        int held[WALK_FILES_MAX];
        size_t count;
} walk;

/* Runs when the walk of test_failed_walks() has read on in its directory.
 * Once the walk keeps something on disk, in files without a name that the
 * process did not have before, this takes a copy of each descriptor of
 * such a file, and leaves the process no descriptor to open. The walk
 * fails at the next file it opens. */
static void stop_walk(int signal) {
        char events[sizeof(struct inotify_event) + NAME_MAX + 1];
        int found[WALK_FILES_MAX], saved = errno;
        bool with_data = false;
        size_t n = 0;

        (void) signal;
        /* A watch that is not read says nothing of the next read. */
        while (read(walk.watch, events, sizeof(events)) > 0)
                ;
        walk.signaled = 1;
        for (int fd = 0; !walk.stopped && fd < SCRATCH_DESCRIPTORS && n < WALK_FILES_MAX; fd++) {
                struct stat st;

                if (walk.before[fd] || fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_nlink > 0)
                        continue;
                found[n++] = fd;
                with_data = with_data || st.st_size > 0;
        }
        if (with_data) {
                for (size_t i = 0; i < n; i++)
                        walk.held[i] = fcntl(found[i], F_DUPFD_CLOEXEC, 0);
                walk.count = n;
                setrlimit(RLIMIT_NOFILE, &walk.none);
                walk.stopped = 1;
        }
        errno = saved;
}

/*
 * A walk that fails leaves nothing in the files it kept on disk: each of
 * them is empty when the generate function returns, as after a walk whose
 * manifest was written. The files of the tree have two names each, nearly
 * as long as a name gets, and there are more of them than a writer keeps
 * the hard links of in memory. The kernel says when the walk reads on in
 * the directory of the files: a watch of it sends a signal for each read
 * to the thread that reads. The handler stops the walk once it has files
 * that hold something, and keeps a descriptor of each, through which the
 * test sees what is left in them. Where there is no such watch, there is
 * nothing to test.
 */
static void test_failed_walks(void) {
        const struct features unhashed = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE,
                                                  UAPI16_FEATURE_HARDLINK);
        _cleanup_(closep) int tree = make_dir(tmp_fd, "failed-walks");
        _cleanup_(closep) int out = make_dir(tmp_fd, "failed-walks-out");
        _cleanup_(closep) int fd = scratch_file(), dir = dup(tree), watch = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        struct f_owner_ex owner = { .type = F_OWNER_TID, .pid = (pid_t) syscall(SYS_gettid) };
        struct sigaction stop = { .sa_handler = stop_walk }, old;
        char component[COMPONENT_MAX + 1], path[64];
        struct rlimit limit;

        check(o && dir >= 0);
        check_eq(set_features(o, unhashed), 0);
        memset(component, 'd', COMPONENT_MAX);
        component[COMPONENT_MAX] = 0;
        for (int depth = 0; depth < WALK_DEPTH; depth++) {
                int next = make_dir(dir, component);

                close(dir);
                dir = next;
        }
        /* The path of the directory is longer than a path can be. */
        snprintf(path, sizeof(path), "/proc/self/fd/%d", dir);
        watch = inotify_init1(IN_CLOEXEC | IN_NONBLOCK);
        if (watch < 0 || inotify_add_watch(watch, path, IN_ACCESS) < 0) {
                fprintf(stderr, "skipping the walks that fail: %s\n", strerror(errno));
                return;
        }
        for (int inode = 0; inode < WALK_INODES; inode++) {
                char name[16], link[16];

                snprintf(name, sizeof(name), "%06da", inode);
                snprintf(link, sizeof(link), "%06db", inode);
                make_file(dir, name, "");
                check_eq(linkat(dir, name, dir, link, 0), 0);
        }
        check_eq(getrlimit(RLIMIT_NOFILE, &limit), 0);
        walk.none = limit;
        walk.none.rlim_cur = 0;
        walk.watch = watch;
        check_eq(sigaction(SIGIO, &stop, &old), 0);
        check_eq(fcntl(watch, F_SETOWN_EX, &owner), 0);
        check_eq(fcntl(watch, F_SETFL, O_ASYNC | O_NONBLOCK), 0);

        /* To a descriptor of the caller first, and to a new file then. */
        for (int created = 0; created < 2; created++) {
                _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
                _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
                int r;

                for (int i = 0; i < SCRATCH_DESCRIPTORS; i++)
                        walk.before[i] = fcntl(i, F_GETFD) >= 0;
                walk.signaled = walk.stopped = 0;
                walk.count = 0;
                if (created)
                        r = uapi16_manifest_generate_at(o, out, "created", tree, UAPI16_ADD_NONE, &report, &e);
                else
                        r = uapi16_manifest_generate(o, fd, tree, UAPI16_ADD_NONE, &report, &e);
                check_eq(setrlimit(RLIMIT_NOFILE, &limit), 0);
                if (!walk.signaled || (!walk.stopped && r == -ENOSPC)) {
                        fprintf(stderr, "skipping the walks that fail: %s\n",
                                walk.signaled ? "no room for what a walk keeps on disk, about 10 MiB" :
                                                "no signal for the read of a directory");
                        break;
                }

                /* The walk kept something on disk, and failed after that. */
                check(walk.stopped);
                check_eq(r, -EMFILE);
                check_eq(uapi16_error_kind(e), UAPI16_ERROR_IO);
                check_eq(uapi16_error_errno(e), EMFILE);
                check(!report);
                for (size_t i = 0; i < walk.count; i++) {
                        check(walk.held[i] >= 0);
                        check_eq(size_of(walk.held[i]), 0);
                        check_eq(close(walk.held[i]), 0);
                }
                check_eq(size_of(fd), 0);
                check_eq(count_entries(tmp_fd, "failed-walks-out"), 0);
        }

        check_eq(close(watch), 0);
        watch = -1;
        check_eq(sigaction(SIGIO, &old, NULL), 0);
}

/*
 * A finish that fails once the new file has its name leaves the file under
 * the name, with the whole manifest in it. Here the file is synced, and
 * its directory can't be opened for the sync of it: it may be written and
 * searched, but not read. A writer of options whose syncing was turned on
 * and off again syncs nothing, and finishes in that directory. A process
 * that may read any directory, as root may, has nothing to test.
 */
static void test_failed_sync(void) {
        _cleanup_(closep) int out = make_dir(tmp_fd, "sync-out"), fd = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file"), *got = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        struct stat st;
        int r;

        check_eq(uapi16_manifest_options_set_sync(o, true), 0);
        check_eq(uapi16_manifest_writer_create_at(o, out, "m", &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);

        /* A directory that may be written and searched, and not read. */
        check_eq(fstat(out, &st), 0);
        check_eq(fchmod(out, 0300), 0);
        fd = openat(tmp_fd, "sync-out", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_eq(fchmod(out, st.st_mode & ALLPERMS), 0);
        if (fd >= 0) {
                fprintf(stderr, "skipping a finish whose sync fails: the process may read any directory\n");
                return;
        }
        check_error(r, e, UAPI16_ERROR_IO, EACCES, NULL, 0);
        check(!report);

        /* The file has its name, and the manifest in it is whole. */
        check_eq(count_entries(tmp_fd, "sync-out"), 1);
        fd = openat(out, "m", O_RDONLY | O_CLOEXEC);
        check(fd >= 0);
        reader = open_reader(fd);
        got = next_object(reader, "file");
        check_ends(reader);

        /* Syncing that was turned on and off again is off: the finish has
         * no directory to open, and succeeds where the one above failed. */
        {
                _cleanup_(closep) int unsynced_fd = -1;
                _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *off =
                        uapi16_manifest_options_new();
                _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *unsynced = NULL;
                _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *written = NULL;
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *listed = NULL;
                _cleanup_(uapi16_reader_freep) uapi16_reader *back = NULL;
                _cleanup_(uapi16_error_freep) uapi16_error *none = NULL;

                check_eq(uapi16_manifest_options_set_sync(off, true), 0);
                check_eq(uapi16_manifest_options_set_sync(off, false), 0);
                check_eq(uapi16_manifest_writer_create_at(off, out, "unsynced", &unsynced, &none), 0);
                check_eq(uapi16_manifest_writer_add_object(unsynced, file, &none), 0);
                check_eq(fchmod(out, 0300), 0);
                r = uapi16_manifest_writer_finish(unsynced, &written, &none);
                check_eq(fchmod(out, st.st_mode & ALLPERMS), 0);
                check_eq(r, 0);
                check(written && !none);
                check_eq(count_entries(tmp_fd, "sync-out"), 2);
                unsynced_fd = openat(out, "unsynced", O_RDONLY | O_CLOEXEC);
                check(unsynced_fd >= 0);
                back = open_reader(unsynced_fd);
                listed = next_object(back, "file");
                check_ends(back);
        }
}

/* Runs `body` in a child of this process, and returns what the child exits
 * with. */
static int in_child(int (*body)(void *), void *argument) {
        int status;
        pid_t pid;

        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                int code = body(argument);

                fflush(NULL);
                _exit(code);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        return WEXITSTATUS(status);
}

/* What madvise() notes of the pages that are wiped in a child of a fork(),
 * which is how the library tells a child, and what it is asked to do with
 * the next call for such a page. */
static struct {
        /* How many pages there are, and the first of them. */
        atomic_size_t count;
        void *pages[16];
        /* Whether the next call for such a page says that it has come,
         * and waits until it may go on. */
        atomic_bool hold;
        sem_t held, released;
} wiped;

/*
 * The madvise() of this program and of the library in it. It takes the
 * place of the one of the C library and does what that one does. For
 * test_forks() it also notes each page that it made one that is wiped in a
 * child, and it holds such a call where the test asks for that.
 */
int madvise(void *address, size_t size, int advice) {
        int r;

        if (advice == MADV_WIPEONFORK && atomic_exchange(&wiped.hold, false)) {
                check_eq(sem_post(&wiped.held), 0);
                while (sem_wait(&wiped.released) < 0)
                        check_eq(errno, EINTR);
        }
        r = (int) syscall(SYS_madvise, address, size, advice);
        if (advice == MADV_WIPEONFORK && r == 0) {
                size_t n = atomic_fetch_add(&wiped.count, 1);

                if (n < ELEMENTSOF(wiped.pages))
                        wiped.pages[n] = address;
        }
        return r;
}

/*
 * The malloc() of everything that is linked into this program, which the
 * linker makes it with --wrap=malloc: the test itself and, where it is
 * linked statically, the library. It is the malloc() of the C library, and
 * it holds a thread that asked for that in its next call, until the thread
 * is released. The shared library allocates past it, so nothing of that
 * one is held.
 */
void *__real_malloc(size_t size);
void *__wrap_malloc(size_t size);
static _Thread_local bool hold_malloc;
static sem_t malloc_held, malloc_released;

void *__wrap_malloc(size_t size) {
        if (hold_malloc) {
                hold_malloc = false;
                check_eq(sem_post(&malloc_held), 0);
                while (sem_wait(&malloc_released) < 0)
                        check_eq(errno, EINTR);
        }
        return __real_malloc(size);
}

/* Whether the kernel has memory that is wiped in a child of a fork(), by
 * which the library tells a child. Without it nothing tells a child, and
 * the library checks nothing. */
static bool wipes_on_fork(void) {
        long size = sysconf(_SC_PAGESIZE);
        void *page;
        bool wipes;

        check(size > 0);
        page = mmap(NULL, (size_t) size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(page != MAP_FAILED);
        /* Not by the madvise() of this program, which would note the page. */
        wipes = syscall(SYS_madvise, page, (size_t) size, MADV_WIPEONFORK) == 0;
        check_eq(munmap(page, (size_t) size), 0);
        return wipes;
}

/* Whether the page at `address` is wiped in a child of a fork(): its
 * mapping has "wf" among its VmFlags in /proc/self/smaps. A page that is
 * not mapped is none. -1 where that file can't be read. */
static int wiped_in_a_child(const void *address) {
        const uintptr_t page = (uintptr_t) address;
        FILE *f = fopen("/proc/self/smaps", "re");
        bool inside = false, wiped_there = false;
        char line[PATH_MAX + 128];

        if (!f)
                return -1;
        while (fgets(line, sizeof(line), f)) {
                unsigned long long start, end;

                if (sscanf(line, "%llx-%llx ", &start, &end) == 2)
                        inside = start <= page && page < end;
                else if (inside && strncmp(line, "VmFlags:", strlen("VmFlags:")) == 0)
                        wiped_there = strstr(line, " wf") != NULL;
        }
        check_eq(fclose(f), 0);
        return wiped_there;
}

/* What a process of test_forks() has of the processes it comes from: a
 * computation that each of them made. */
struct lineage {
        uapi16_sha256 *of_parent, *of_child;
};

/* A grandchild can use neither what its parent made nor what the parent of
 * that made, and can use what it makes itself. */
static int grandchild(void *argument) {
        const struct lineage *lineage = argument;
        uapi16_sha256 *own = uapi16_sha256_new();

        check_eq(uapi16_sha256_update(lineage->of_parent, "x", 1), -ECHILD);
        check_eq(uapi16_sha256_update(lineage->of_child, "x", 1), -ECHILD);
        check_eq(uapi16_sha256_update(own, "x", 1), 0);
        uapi16_sha256_free(own);
        return EXIT_SUCCESS;
}

/* A child that makes a child of its own, and is the process it was after
 * that. */
static int child_with_grandchild(void *argument) {
        struct lineage *lineage = argument;

        lineage->of_child = uapi16_sha256_new();
        check_eq(uapi16_sha256_update(lineage->of_parent, "x", 1), -ECHILD);
        check_eq(uapi16_sha256_update(lineage->of_child, "x", 1), 0);
        check_eq(in_child(grandchild, lineage), EXIT_SUCCESS);
        check_eq(uapi16_sha256_update(lineage->of_child, "y", 1), 0);
        check_eq(uapi16_sha256_update(lineage->of_parent, "x", 1), -ECHILD);
        uapi16_sha256_free(lineage->of_child);
        return EXIT_SUCCESS;
}

/* A child that makes a child before it has used the library itself. */
static int idle_child_with_grandchild(void *argument) {
        struct lineage *lineage = argument;
        struct lineage own = { .of_parent = lineage->of_parent, .of_child = lineage->of_parent };

        check_eq(in_child(grandchild, &own), EXIT_SUCCESS);
        check_eq(uapi16_sha256_update(lineage->of_parent, "x", 1), -ECHILD);
        return EXIT_SUCCESS;
}

/* How many threads of a child use the library for the first time at once. */
#define RACERS 8

struct race {
        pthread_barrier_t start;
        uapi16_sha256 *of_parent;
        uapi16_sha256 *made[RACERS];
};

struct racer {
        struct race *race;
        size_t number;
};

static void *race_in_child(void *argument) {
        struct racer *racer = argument;
        struct race *race = racer->race;
        int r = pthread_barrier_wait(&race->start);

        check(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        check_eq(uapi16_sha256_update(race->of_parent, "x", 1), -ECHILD);
        race->made[racer->number] = uapi16_sha256_new();
        check_eq(uapi16_sha256_update(race->made[racer->number], "x", 1), 0);
        return NULL;
}

/* The first calls of a child come from several threads at once. They agree
 * on which process this is: each is told that the object of the parent is
 * not one of its process, and what one of them makes, another one uses. */
static int child_with_threads(void *argument) {
        struct race race = { .of_parent = argument };
        struct racer racers[RACERS];
        pthread_t threads[RACERS];

        check_eq(pthread_barrier_init(&race.start, NULL, RACERS), 0);
        for (size_t i = 0; i < RACERS; i++) {
                racers[i] = (struct racer) { .race = &race, .number = i };
                check_eq(pthread_create(&threads[i], NULL, race_in_child, &racers[i]), 0);
        }
        for (size_t i = 0; i < RACERS; i++)
                check_eq(pthread_join(threads[i], NULL), 0);
        for (size_t i = 0; i < RACERS; i++) {
                check_eq(uapi16_sha256_update(race.made[i], "y", 1), 0);
                uapi16_sha256_free(race.made[i]);
        }
        check_eq(uapi16_sha256_update(race.of_parent, "x", 1), -ECHILD);
        check_eq(pthread_barrier_destroy(&race.start), 0);
        return EXIT_SUCCESS;
}

/* The child of the first process of a PID namespace, which is the first
 * process of a namespace of its own: it has the PID of its parent, and is
 * told that it is a child all the same. */
static int child_with_the_pid_of_its_parent(void *argument) {
        check_eq(getpid(), 1);
        check_eq(uapi16_sha256_update(argument, "x", 1), -ECHILD);
        return EXIT_SUCCESS;
}

static int first_of_a_namespace(void *argument) {
        uapi16_sha256 *sha = uapi16_sha256_new();
        int code;

        (void) argument;
        check_eq(getpid(), 1);
        check_eq(uapi16_sha256_update(sha, "x", 1), 0);
        if (unshare(CLONE_NEWPID) < 0)
                return EXIT_SKIPPED;
        code = in_child(child_with_the_pid_of_its_parent, sha);
        check_eq(uapi16_sha256_update(sha, "y", 1), 0);
        uapi16_sha256_free(sha);
        return code;
}

/* Makes a user and a PID namespace, of which its child is the first
 * process. */
static int namespace_of_its_own(void *argument) {
        if (unshare(CLONE_NEWUSER | CLONE_NEWPID) < 0)
                return EXIT_SKIPPED;
        return in_child(first_of_a_namespace, argument);
}

/* What the test is told to do when it runs itself once more, and the path
 * it runs itself by. The last three come with a directory to do it in. */
#define WITHOUT_WIPE_ON_FORK "--without-wipe-on-fork"
#define FORK_IN_THE_FIRST_CALL "--fork-in-the-first-call"
#define FIRST_CALLS_AT_ONCE "--first-calls-at-once"
#define FORK_IN_THE_FIRST_ASK "--fork-in-the-first-ask"
#define WITHOUT_TMPFILE "--without-tmpfile"
#define WITH_A_LINKED_NAME "--with-a-linked-name"
#define WITH_A_NAME_LEFT "--with-a-name-left"
#define WITH_A_NAME_THROUGH_PROCFS "--with-a-name-through-procfs"
static const char *self_path;

/* Runs the test once more, as a process that has used nothing of the
 * library yet and does what `what` says, with `argument` if that is not
 * NULL. Returns what it exits with. */
static int in_new_process(const char *what, const char *argument) {
        int status;
        pid_t pid;

        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                execl(self_path, self_path, what, argument, (char *) NULL);
                _exit(EXIT_FAILURE);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        return WEXITSTATUS(status);
}

/* How long the first call of a child may take. One that takes longer waits
 * for something that never comes, and the child is killed. */
#define FIRST_CALL_SECONDS 30

/* Forks while another thread is in the first call of the process: in the
 * madvise() of it. The child has this thread alone. Its own first call
 * comes back all the same: it waits for nothing that the other thread of
 * its parent was about to do. */
static void *fork_in_a_first_call(void *argument) {
        int status;
        pid_t pid;

        (void) argument;
        while (sem_wait(&wiped.held) < 0)
                check_eq(errno, EINTR);
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                uapi16_sha256 *own;

                alarm(FIRST_CALL_SECONDS);
                own = uapi16_sha256_new();
                check_eq(uapi16_sha256_update(own, "x", 1), 0);
                uapi16_sha256_free(own);
                fflush(NULL);
                _exit(EXIT_SUCCESS);
        }
        check_eq(sem_post(&wiped.released), 0);
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
        return NULL;
}

/* What the test does when test_forks() runs it with
 * FORK_IN_THE_FIRST_CALL: it makes its first call of the library while
 * another thread forks, see fork_in_a_first_call(). Returns what the
 * process exits with. */
static int fork_in_the_first_call(void) {
        uapi16_sha256 *sha;
        pthread_t thread;

        check_eq(sem_init(&wiped.held, 0, 0), 0);
        check_eq(sem_init(&wiped.released, 0, 0), 0);
        check_eq(pthread_create(&thread, NULL, fork_in_a_first_call, NULL), 0);
        atomic_store(&wiped.hold, true);
        sha = uapi16_sha256_new();
        /* A first call that asked for no such page was not held, and the
         * other thread forks after it. */
        if (atomic_exchange(&wiped.hold, false))
                check_eq(sem_post(&wiped.held), 0);
        check_eq(pthread_join(thread, NULL), 0);
        check_eq(uapi16_sha256_update(sha, "x", 1), 0);
        uapi16_sha256_free(sha);
        return EXIT_SUCCESS;
}

static void *race_to_the_first_call(void *argument) {
        struct racer *racer = argument;
        struct race *race = racer->race;
        int r = pthread_barrier_wait(&race->start);

        check(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        race->made[racer->number] = uapi16_sha256_new();
        check_eq(uapi16_sha256_update(race->made[racer->number], "x", 1), 0);
        return NULL;
}

/* What the test does when test_forks() runs it with FIRST_CALLS_AT_ONCE:
 * the first calls of the process come from several threads at once. They
 * agree on which process this is: what one of them makes, another one
 * uses. And they agree on one page that is wiped in a child: of the pages
 * they made for that, one is left, and there is one where the kernel has
 * such pages. Returns what the process exits with. */
static int first_calls_at_once(void) {
        struct race race = { .of_parent = NULL };
        struct racer racers[RACERS];
        pthread_t threads[RACERS];
        size_t made, left = 0;

        check_eq(pthread_barrier_init(&race.start, NULL, RACERS), 0);
        for (size_t i = 0; i < RACERS; i++) {
                racers[i] = (struct racer) { .race = &race, .number = i };
                check_eq(pthread_create(&threads[i], NULL, race_to_the_first_call, &racers[i]), 0);
        }
        for (size_t i = 0; i < RACERS; i++)
                check_eq(pthread_join(threads[i], NULL), 0);
        for (size_t i = 0; i < RACERS; i++) {
                check_eq(uapi16_sha256_update(race.made[i], "y", 1), 0);
                uapi16_sha256_free(race.made[i]);
        }
        check_eq(pthread_barrier_destroy(&race.start), 0);

        made = atomic_load(&wiped.count);
        check(made <= RACERS);
        for (size_t i = 0; i < made; i++) {
                int r = wiped_in_a_child(wiped.pages[i]);

                if (r < 0) {
                        fprintf(stderr, "skipping the pages that are left of the first calls: "
                                        "no /proc/self/smaps here\n");
                        return EXIT_SUCCESS;
                }
                left += (size_t) r;
        }
        check_eq(left, wipes_on_fork() ? 1 : 0);
        return EXIT_SUCCESS;
}

/* A string that the library makes when it is first asked for, and keeps:
 * the function that asks for it, the object it is a string of, and what the
 * thread that asked first got. */
struct ask {
        const char *(*string)(const void *object);
        const void *object;
        const char *got;
        /* Whether the thread went through its ask without being held, as
         * with the shared library, which shows nothing. */
        bool not_held;
};

static const char *ask_feature_name(const void *object) {
        (void) object;
        return uapi16_feature_name(UAPI16_FEATURE_MODE);
}

static const char *ask_object_name(const void *object) {
        return uapi16_file_object_name(object);
}

static const char *ask_mechanism(const void *object) {
        return uapi16_signature_mechanism(object);
}

/* Asks for a string for the first time, and is held in the malloc() that
 * makes the string, where the malloc() of this program is the one of the
 * library. */
static void *first_ask(void *argument) {
        struct ask *ask = argument;

        hold_malloc = true;
        ask->got = ask->string(ask->object);
        /* An ask that allocated past the malloc() of this program was not
         * held, and whoever waits for that goes on now. */
        if (hold_malloc) {
                hold_malloc = false;
                ask->not_held = true;
                check_eq(sem_post(&malloc_held), 0);
        }
        return NULL;
}

/* A thread is in its first ask for a string, and a child is forked then.
 * The child has no such thread. It asks for the same string and gets it:
 * it waits for nothing that the thread of its parent was about to do.
 * With `here`, this thread asks as well while the other one is held, and
 * both get the one string that is kept. */
static void fork_in_a_first_ask(struct ask *ask, bool here) {
        const char *got = NULL;
        pthread_t thread;
        int status;
        pid_t pid;

        check_eq(sem_init(&malloc_held, 0, 0), 0);
        check_eq(sem_init(&malloc_released, 0, 0), 0);
        check_eq(pthread_create(&thread, NULL, first_ask, ask), 0);
        while (sem_wait(&malloc_held) < 0)
                check_eq(errno, EINTR);
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                alarm(FIRST_CALL_SECONDS);
                _exit(ask->string(ask->object) ? EXIT_SUCCESS : EXIT_FAILURE);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
        if (here)
                got = ask->string(ask->object);
        check_eq(sem_post(&malloc_released), 0);
        check_eq(pthread_join(thread, NULL), 0);
        check(ask->got);
        if (here)
                check(got == ask->got);
        check_eq(sem_destroy(&malloc_held), 0);
        check_eq(sem_destroy(&malloc_released), 0);
}

/* What the test does when test_forks() runs it with FORK_IN_THE_FIRST_ASK:
 * a child is forked while another thread asks for a string that the
 * library makes then, see fork_in_a_first_ask(): for a name that is a
 * constant of the library, for a string of a file object and for the one
 * of a signature object. The name is one that nothing asked for yet in
 * this process, and two threads ask for it at once. An object is used by
 * one thread at a time. Returns what the process exits with. */
static int fork_in_the_first_ask(void) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = make_object("name");
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL;
        struct ask name = { .string = ask_feature_name };
        struct ask of_object = { .string = ask_object_name, .object = o };
        struct ask of_signature = { .string = ask_mechanism };

        check_eq(uapi16_signature_new("mechanism", &signature), 0);
        of_signature.object = signature;
        fork_in_a_first_ask(&name, true);
        check_str(name.got, "mode");
        fork_in_a_first_ask(&of_object, false);
        check_str(of_object.got, "name");
        fork_in_a_first_ask(&of_signature, false);
        check_str(of_signature.got, "mechanism");
        /* All three were held, or none was. */
        check(name.not_held == of_object.not_held && name.not_held == of_signature.not_held);
        return name.not_held ? EXIT_SKIPPED : EXIT_SUCCESS;
}

/* What a process that nothing tells from its children shares with one of
 * them: a computation and a writer. */
struct untold {
        uapi16_sha256 *sha;
        uapi16_manifest_writer *writer;
};

/* Gives this process the seccomp filter `filter` of `size` instructions,
 * next to those it has. Returns false where it can't have one. */
static bool filter_calls(struct sock_filter *filter, size_t size) {
        struct sock_fprog program = { .len = (unsigned short) size, .filter = filter };

        return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0 &&
               syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0;
}

/* Keeps this process from the system call `nr` where its argument
 * `argument`, counted from 0, has one of the bits `bits`, with a seccomp
 * filter that fails such a call with `error`. Returns false where the
 * process can't have a filter. */
static bool refuse_flag(long nr, size_t argument, uint32_t bits, int error) {
        /* Where the low half of that argument of a system call is. */
        const size_t flags = offsetof(struct seccomp_data, args) + argument * sizeof(uint64_t) +
                             (BYTE_ORDER == BIG_ENDIAN ? sizeof(uint32_t) : 0);
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t) nr, 0, 3),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (uint32_t) flags),
                BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, bits, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t) error),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };

        return filter_calls(filter, ELEMENTSOF(filter));
}

/* Keeps this process from files without a name: an openat() with O_TMPFILE
 * fails with EOPNOTSUPP, as on a file system that has no such files. A new
 * file is in its directory under a temporary name then, on any file
 * system. Returns false where the process can't have a filter. */
static bool refuse_tmpfile(void) {
        if (!refuse_flag(SYS_openat, 2, O_TMPFILE & ~O_DIRECTORY, EOPNOTSUPP))
                return false;
        check_eq(openat(AT_FDCWD, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600), -1);
        check_eq(errno, EOPNOTSUPP);
        return true;
}

/* Keeps this process from giving a file without a name its name by its
 * descriptor: a linkat() with AT_EMPTY_PATH fails with ENOENT, as Linux
 * before 6.10 fails it for a process that may not look up any name. Such a
 * file gets its name through the link procfs has for its descriptor then.
 * Returns false where the process can't have a filter. */
static bool refuse_link_by_descriptor(void) {
        if (!refuse_flag(SYS_linkat, 4, AT_EMPTY_PATH, ENOENT))
                return false;
        check_eq(syscall(SYS_linkat, -1, "", -1, "", AT_EMPTY_PATH), -1);
        check_eq(errno, ENOENT);
        return true;
}

/* Keeps this process from the system call `nr`, with a seccomp filter
 * that fails every call of it with `error`. Returns false where the
 * process can't have a filter. */
static bool refuse_call(long nr, int error) {
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, (uint32_t) nr, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (uint32_t) error),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };

        if (!filter_calls(filter, ELEMENTSOF(filter)))
                return false;
        check_eq(syscall(nr, -1, NULL, -1, NULL, 0), -1);
        check_eq(errno, error);
        return true;
}

/*
 * What the test does when test_forks() runs it with WITHOUT_TMPFILE: a
 * process keeps itself from files without a name, see refuse_tmpfile(). A
 * new file is in its directory under a temporary name then, and a child
 * that frees its writer leaves that name alone, see
 * check_freed_in_a_child(). Returns what the process exits with.
 */
static int without_tmpfile(void) {
        const char *tmpdir = getenv("TMPDIR");
        _cleanup_(closep) int dir = -1;
        char path[PATH_MAX];

        if (!refuse_tmpfile())
                return EXIT_SKIPPED;

        snprintf(path, sizeof(path), "%s/uapi16-capi-XXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
        check(mkdtemp(path));
        dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(dir >= 0);
        check_freed_in_a_child(dir);
        check_eq(rmdir(path), 0);
        return EXIT_SUCCESS;
}

/* How the new file of linked_name() comes to its name. */
enum linked {
        /* It has a temporary name, which is linked and then removed. */
        LINKED,
        /* The same, but the temporary name can't be removed. */
        LINKED_AND_LEFT,
        /* It has no name, and is linked through procfs to a temporary
         * name, which is linked and then removed. */
        LINKED_THROUGH_PROCFS,
};

/* Says why a part of test_linked_names() can't run here. Returns what its
 * process exits with. ci.yml matches the start of the line, so that the C
 * job of CI fails where a part did not run. */
static int skip_linked_name(const char *why) {
        fprintf(stderr, "skipping a new file that gets its name by a link: %s\n", why);
        return EXIT_SKIPPED;
}

/*
 * What the test does when test_linked_names() runs it for the directory
 * `path`: a process keeps itself from the rename that replaces nothing,
 * see refuse_call(), as a file system does that has none. A new file gets
 * its name by a link of a temporary name then, and the temporary name is
 * removed once the file has its own. `how` says where the temporary name
 * comes from. The process keeps itself from files without a name, see
 * refuse_tmpfile(), so the file has the temporary name from the start. Or
 * it keeps itself from linking a file by its descriptor, see
 * refuse_link_by_descriptor(), so a file without a name gets the temporary
 * name through procfs. With LINKED_AND_LEFT the process keeps itself from
 * removing a name as well. The finish fails then, and the file keeps both
 * names. The temporary one is left since nothing can remove it, as on a
 * file system that refuses to, and not since the writer forgot it. Returns
 * what the process exits with.
 */
static int linked_name(const char *path, enum linked how) {
        _cleanup_(closep) int dir = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC), fd = -1;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL, *got = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const bool left = how == LINKED_AND_LEFT, unnamed = how == LINKED_THROUGH_PROCFS;
        const size_t names = left ? 2 : 1;
        struct stat st;
        int r;

        check(dir >= 0);
        if (unnamed) {
                /* What that way takes besides the filters: procfs, and a
                 * directory that has files without a name. */
                if (faccessat(AT_FDCWD, "/proc/self/fd", F_OK, 0) < 0)
                        return skip_linked_name("no /proc here");
                fd = openat(dir, ".", O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
                if (fd < 0)
                        return skip_linked_name("no file without a name here");
                check_eq(close(fd), 0);
                fd = -1;
        }
        if (!(unnamed ? refuse_link_by_descriptor() : refuse_tmpfile()) ||
            !refuse_call(SYS_renameat2, EINVAL) || (left && !refuse_call(SYS_unlinkat, EPERM)))
                return skip_linked_name("no seccomp filter here");

        o = uapi16_manifest_options_new();
        file = make_hello("file");
        check_eq(uapi16_manifest_writer_create_at(o, dir, "m", &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, file, &e), 0);
        /* The name the file has until it gets its own, if it has one. */
        check_eq(count_entries(dir, "."), unnamed ? 0 : 1);
        check_eq(faccessat(dir, "m", F_OK, 0), -1);

        r = uapi16_manifest_writer_finish(w, &report, &e);
        if (left) {
                check_error(r, e, UAPI16_ERROR_IO, EPERM, NULL, 0);
                check(!report);
        } else {
                check_eq(r, 0);
                check(!e);
                check_eq(uapi16_manifest_report_files(report), 1);
        }

        /* The file has its name, and the manifest in it is whole. What is
         * in the directory besides is its temporary name, where that could
         * not be removed. A free of the writer changes nothing of that. */
        check_eq(count_entries(dir, "."), names);
        w = uapi16_manifest_writer_free(w);
        check_eq(count_entries(dir, "."), names);
        fd = openat(dir, "m", O_RDONLY | O_CLOEXEC);
        check(fd >= 0);
        check_eq(fstat(fd, &st), 0);
        check_eq(st.st_nlink, names);
        reader = open_reader(fd);
        got = next_object(reader, "file");
        check_ends(reader);
        return EXIT_SUCCESS;
}

/* The child of a process without memory that is wiped in a child. Nothing
 * tells it from its parent: its calls on the objects of its parent go on
 * as in the parent, and it frees the writer of its parent as the parent
 * would. */
static int child_without_wipe_on_fork(void *argument) {
        struct untold *untold = argument;
        uapi16_sha256 *own = uapi16_sha256_new();

        check_eq(uapi16_sha256_update(untold->sha, "x", 1), 0);
        check_eq(uapi16_sha256_update(own, "x", 1), 0);
        uapi16_sha256_free(own);
        uapi16_manifest_writer_free(untold->writer);
        return EXIT_SUCCESS;
}

/*
 * What the test does when test_forks() runs it with WITHOUT_WIPE_ON_FORK:
 * a process that has used nothing of the library yet keeps itself from
 * memory that is wiped in a child, with a seccomp filter that refuses the
 * advice MADV_WIPEONFORK of madvise() with EINVAL, as a kernel does that
 * has none. The library has nothing to tell a child by then, and nothing
 * to fall back to: the calls go on, in a child as in its parent, and
 * nothing waits or stops. A child that frees a writer frees it as its
 * parent would. That empties no file the writer keeps, so the writer of
 * the parent finishes all the same. What such a free takes with it is the
 * name a new file has until it is complete, on a file system that gives
 * it one, see test_fat(). Returns what the process exits with.
 */
static int without_wipe_on_fork(void) {
        /* Where the low half of the third argument of a system call is. */
        const uint32_t advice = offsetof(struct seccomp_data, args[2]) +
                                (BYTE_ORDER == BIG_ENDIAN ? sizeof(uint32_t) : 0);
        struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_madvise, 0, 3),
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, advice),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, MADV_WIPEONFORK, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EINVAL),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
        };
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(closep) int out = -1;
        bool before[SCRATCH_DESCRIPTORS], scratch[SCRATCH_DESCRIPTORS], spilled;
        long size = sysconf(_SC_PAGESIZE);
        struct untold untold = { .sha = NULL };
        uapi16_sha256_digest_t hash;
        void *page;
        int r;

        if (!filter_calls(filter, ELEMENTSOF(filter)))
                return EXIT_SKIPPED;
        check(size > 0);
        page = mmap(NULL, (size_t) size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        check(page != MAP_FAILED);
        check_eq(madvise(page, (size_t) size, MADV_WIPEONFORK), -1);
        check_eq(errno, EINVAL);
        check_eq(madvise(page, (size_t) size, MADV_DONTNEED), 0);
        check_eq(munmap(page, (size_t) size), 0);

        /* A computation, and a writer that keeps file objects in files of
         * its own. These are the first calls of the process. */
        untold.sha = uapi16_sha256_new();
        check_eq(uapi16_sha256_update(untold.sha, "a", 1), 0);
        o = uapi16_manifest_options_new();
        out = memfd_create("manifest", MFD_CLOEXEC);
        check(o && out >= 0);
        unnamed_files(before);
        check_eq(uapi16_manifest_writer_open(o, out, &untold.writer, &e), 0);
        spilled = add_scratch_files(untold.writer, before, scratch);
        if (!spilled)
                untold.writer = uapi16_manifest_writer_free(untold.writer);

        check_eq(in_child(child_without_wipe_on_fork, &untold), EXIT_SUCCESS);

        /* What the child did to its copy of the computation did nothing to
         * the one of the parent. */
        check_eq(uapi16_sha256_update(untold.sha, "bc", 2), 0);
        check_eq(uapi16_sha256_finish(untold.sha, &hash), 0);
        check_hash(&hash, SHA256_OF_ABC);
        uapi16_sha256_free(untold.sha);
        /* The files of the writer are those of the child as well, and the
         * child left them as they are when it freed its copy. */
        if (spilled) {
                r = uapi16_manifest_writer_finish(untold.writer, &report, &e);
                if (!no_room(r)) {
                        check_eq(r, 0);
                        check_eq(uapi16_manifest_report_files(report), 2 * SCRATCH_INODES);
                }
        }
        uapi16_manifest_writer_free(untold.writer);
        return EXIT_SUCCESS;
}

/* A fork is told in the child, however the child came to be: the child of
 * a child, one that makes a child before it uses the library, one whose
 * first calls come from several threads at once, one that has the PID of
 * its parent, one that is forked while another thread makes the first call
 * of its parent or asks for a string the first time. The parent is the
 * process it was after each of them. In a process that can't have memory
 * that is wiped in a child, nothing tells a child, and its calls go on. */
static void test_forks(void) {
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *sha = uapi16_sha256_new();
        struct lineage lineage = { .of_parent = sha };
        uapi16_sha256_digest_t hash;
        int code;

        check_eq(uapi16_sha256_update(sha, "a", 1), 0);
        check_eq(in_child(child_with_grandchild, &lineage), EXIT_SUCCESS);
        check_eq(in_child(idle_child_with_grandchild, &lineage), EXIT_SUCCESS);
        check_eq(in_child(child_with_threads, sha), EXIT_SUCCESS);
        check_eq(uapi16_sha256_update(sha, "b", 1), 0);

        code = in_child(namespace_of_its_own, sha);
        if (code == EXIT_SKIPPED)
                fprintf(stderr, "skipping a child with the PID of its parent: no user and PID namespace here\n");
        else
                check_eq(code, EXIT_SUCCESS);

        check_eq(in_new_process(FORK_IN_THE_FIRST_CALL, NULL), EXIT_SUCCESS);
        check_eq(in_new_process(FIRST_CALLS_AT_ONCE, NULL), EXIT_SUCCESS);
        code = in_new_process(FORK_IN_THE_FIRST_ASK, NULL);
        if (code == EXIT_SKIPPED)
                fprintf(stderr, "skipping a fork in a first ask for a string: the shared library allocates "
                                "past the malloc() of the test\n");
        else
                check_eq(code, EXIT_SUCCESS);
        /* ci.yml matches the starts of the next two skip lines, so that the
         * C job of CI fails where a part under a seccomp filter did not
         * run. */
        code = in_new_process(WITHOUT_TMPFILE, NULL);
        if (code == EXIT_SKIPPED)
                fprintf(stderr, "skipping a new file under a temporary name: no seccomp filter here\n");
        else
                check_eq(code, EXIT_SUCCESS);
        code = in_new_process(WITHOUT_WIPE_ON_FORK, NULL);
        if (code == EXIT_SKIPPED)
                fprintf(stderr, "skipping a fork that nothing tells: no seccomp filter here\n");
        else
                check_eq(code, EXIT_SUCCESS);

        /* What the children did to their copies did nothing to this one. */
        check_eq(uapi16_sha256_update(sha, "c", 1), 0);
        check_eq(uapi16_sha256_finish(sha, &hash), 0);
        check_hash(&hash, SHA256_OF_ABC);
}

/* A new file gets its name by a link where its file system has no rename
 * that replaces nothing. Three processes that keep themselves from that
 * rename make a manifest that way, each in a directory of its own, see
 * linked_name(). One that can't run here says why. */
static void test_linked_names(void) {
        static const struct {
                const char *what, *dir;
        } parts[] = {
                { WITH_A_LINKED_NAME, "linked-name" },
                { WITH_A_NAME_LEFT, "name-left" },
                { WITH_A_NAME_THROUGH_PROCFS, "name-through-procfs" },
        };
        char path[PATH_MAX];

        for (size_t i = 0; i < ELEMENTSOF(parts); i++) {
                int code;

                check_eq(mkdirat(tmp_fd, parts[i].dir, 0755), 0);
                check((size_t) snprintf(path, sizeof(path), "%s/%s", tmp_path, parts[i].dir) < sizeof(path));
                code = in_new_process(parts[i].what, path);
                check(code == EXIT_SUCCESS || code == EXIT_SKIPPED);
        }
}

/* The objects that go from thread to thread, one of every kind, and what
 * the threads do with them. */
struct step {
        uapi16_manifest_writer *writer;
        uapi16_manifest_report *report;
        uapi16_error *error;
        uapi16_file_object *file, *refused, *got;
        uapi16_reader *reader;
        uapi16_writer *records;
        uapi16_signature *signature;
        uapi16_sha256 *sha;
        uapi16_data_check *data;
        uapi16_directory *directory;
        uapi16_sha256_digest_t hash;
        uint64_t files, size;
        int r;
};

static void *add_in_thread(void *argument) {
        struct step *step = argument;

        check_eq(uapi16_manifest_writer_add_object(step->writer, step->file, NULL), 0);
        check_eq(uapi16_writer_file(step->records, step->file, NULL), 0);
        check_eq(uapi16_reader_next(step->reader, &step->got, NULL), UAPI16_READ_FILE);
        check_eq(uapi16_signature_set_key(step->signature, "key", 3), 0);
        check_eq(uapi16_sha256_update(step->sha, "hel", 3), 0);
        check_eq(uapi16_data_check_update(step->data, "hel", 3, NULL), 0);
        check_eq(uapi16_file_object_set_fs_label(step->refused, "label"), 0);
        step->r = uapi16_manifest_writer_add_object(step->writer, step->refused, &step->error);
        return NULL;
}

static void *finish_in_thread(void *argument) {
        struct step *step = argument;
        uapi16_file_object *none = NULL;

        check_eq(uapi16_writer_signature(step->records, step->signature, NULL), 0);
        check_eq(uapi16_writer_finish(step->records, NULL), 0);
        check_eq(uapi16_reader_next(step->reader, &none, NULL), UAPI16_READ_END);
        check_eq(uapi16_sha256_update(step->sha, "lo", 2), 0);
        check_eq(uapi16_sha256_finish(step->sha, &step->hash), 0);
        check_eq(uapi16_data_check_update(step->data, "lo", 2, NULL), 0);
        check_eq(uapi16_data_check_finish(step->data, &step->size, NULL), 0);
        step->r = uapi16_manifest_writer_finish(step->writer, &step->report, NULL);
        return NULL;
}

static void *read_in_thread(void *argument) {
        struct step *step = argument;

        step->files = uapi16_manifest_report_files(step->report);
        check_eq(uapi16_error_errno(step->error), EBADMSG);
        check_str(uapi16_error_path(step->error), "refused");
        check_str(uapi16_error_field(step->error), "fsLabel");
        check_str(uapi16_file_object_name(step->got), "a");
        check_str(uapi16_file_object_name(step->file), "hello");
        check_str(uapi16_signature_mechanism(step->signature), "openpgp");
        return NULL;
}

static void *free_in_thread(void *argument) {
        struct step *step = argument;

        step->writer = uapi16_manifest_writer_free(step->writer);
        step->report = uapi16_manifest_report_free(step->report);
        step->error = uapi16_error_free(step->error);
        step->file = uapi16_file_object_free(step->file);
        step->refused = uapi16_file_object_free(step->refused);
        step->got = uapi16_file_object_free(step->got);
        step->reader = uapi16_reader_free(step->reader);
        step->records = uapi16_writer_free(step->records);
        step->signature = uapi16_signature_free(step->signature);
        step->sha = uapi16_sha256_free(step->sha);
        step->data = uapi16_data_check_free(step->data);
        step->directory = uapi16_directory_free(step->directory);
        return NULL;
}

/* How many threads read what nothing changes at the same time, and how
 * often each does. */
#define READERS 4
#define ROUNDS 200

/* A file object, a report and an error that nothing changes, and what lets
 * the threads that read them start together. */
struct shared {
        pthread_barrier_t start;
        const uapi16_file_object *file;
        const uapi16_manifest_report *report;
        const uapi16_error *error;
};

static void *read_shared(void *argument) {
        struct shared *shared = argument;
        int r = pthread_barrier_wait(&shared->start);

        check(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        for (int i = 0; i < ROUNDS; i++) {
                uapi16_sha256_digest_t hash;
                uint32_t mode = 0, stated = 0, set = 0;
                uint64_t size = 0, record = 0;
                size_t count = 0, value_size = 0;
                const char *name = NULL;
                const void *value = NULL;

                check_str(uapi16_file_object_name(shared->file), "dir/file");
                check_str(uapi16_file_object_user_name(shared->file), "user");
                check_str(uapi16_file_object_group_name(shared->file), "group");
                check_eq(uapi16_file_object_type(shared->file), S_IFREG);
                check_eq(uapi16_file_object_mode(shared->file, &mode), 0);
                check_eq(mode, 0644);
                check_eq(uapi16_file_object_size(shared->file, &size), 0);
                check_eq(size, 5);
                check_eq(uapi16_file_object_sha256(shared->file, &hash), 0);
                check_hash(&hash, SHA256_OF_HELLO);
                check_eq(uapi16_file_object_user_xattrs(shared->file, &count), 0);
                check_eq(count, 2);
                check_eq(uapi16_file_object_user_xattr(shared->file, 1, &name, &value, &value_size), 0);
                check_str(name, "b");
                check_same(value, value_size, "two", 3);
                check_eq(uapi16_file_object_inode_flags(shared->file, &stated, &set), 0);
                check_eq(stated, NODUMP_FL);
                check_eq(set, 0);
                check_eq(uapi16_file_object_read_only(shared->file), UAPI16_READ_ONLY_NO);
                check_eq(uapi16_file_object_data_location(shared->file), UAPI16_DATA_LOCATION_EXTERNAL);
                check(uapi16_file_object_has_stated_feature(shared->file, UAPI16_FEATURE_USER_XATTR));
                check_eq(uapi16_file_object_check_validity(shared->file, 0, NULL), 0);

                check_eq(uapi16_manifest_report_files(shared->report), 1);
                check_eq(uapi16_manifest_report_bytes(shared->report), 5);
                check_eq(uapi16_error_kind(shared->error), UAPI16_ERROR_MANIFEST);
                check_eq(uapi16_error_errno(shared->error), EBADMSG);
                check_str(uapi16_error_path(shared->error), "refused");
                check_str(uapi16_error_field(shared->error), "fsLabel");
                check_str(uapi16_error_problem(shared->error), "fieldNotPermitted");
                check_eq(uapi16_error_record(shared->error, &record), -ENODATA);
        }
        return NULL;
}

static void test_threads(void) {
        void *(*const steps[])(void *) = { add_in_thread, finish_in_thread, read_in_thread, free_in_thread };
        _cleanup_(closep) int out = make_dir(tmp_fd, "threads-out"), written = scratch_file();
        _cleanup_(closep) int manifest = manifest_file(ROOT FILE_OBJECT("a") TRAILER);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("dir/file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("refused");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *counted = make_hello("counted");
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        _cleanup_(freep) char *made = NULL, *records = NULL;
        struct step step = { .file = make_hello("hello"), .refused = make_object("refused") };
        struct shared shared;
        pthread_t readers[READERS];
        size_t made_size, records_size;

        check_eq(uapi16_manifest_writer_create_at(o, out, "m", &step.writer, NULL), 0);
        step.records = begin_records(o, written);
        step.reader = open_reader(manifest);
        check_eq(uapi16_signature_new("openpgp", &step.signature), 0);
        step.sha = uapi16_sha256_new();
        check_eq(uapi16_data_check_new(step.file, &step.data), 0);
        check_eq(uapi16_directory_new(out, UAPI16_DIRECTORY_NONE, &step.directory, NULL), 0);

        /* An object is used by one thread at a time, which need not be the
         * one that made it. Each step here is a thread of its own. */
        for (size_t i = 0; i < ELEMENTSOF(steps); i++) {
                pthread_t thread;

                check_eq(pthread_create(&thread, NULL, steps[i], &step), 0);
                check_eq(pthread_join(thread, NULL), 0);
                if (steps[i] == add_in_thread)
                        check_eq(step.r, -EBADMSG);
                if (steps[i] == finish_in_thread)
                        check_eq(step.r, 0);
        }
        check_eq(step.files, 1);
        check_eq(step.size, 5);
        check_hash(&step.hash, SHA256_OF_HELLO);
        check(!step.writer && !step.report && !step.error && !step.file && !step.refused && !step.got);
        check(!step.reader && !step.records && !step.signature && !step.sha && !step.data);
        check(!step.directory);
        made = read_file(out, "m", &made_size);
        check_manifest(made, made_size);
        check(strstr(made, "\"name\":\"hello\""));
        records = read_all(written, &records_size);
        check_manifest(records, records_size);
        check(strstr(records, "\"mechanism\":\"openpgp\""));

        /* A file object that no thread changes is read from several threads
         * at the same time, and so are a report and an error. The strings
         * they hand out are asked for by all of the threads first. */
        check_eq(uapi16_file_object_set_mode(file, 0644), 0);
        check_eq(uapi16_file_object_set_user_name(file, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(file, "group"), 0);
        check_eq(uapi16_file_object_add_user_xattr(file, "b", "two", 3), 0);
        check_eq(uapi16_file_object_add_user_xattr(file, "a", "one", 3), 0);
        check_eq(uapi16_file_object_set_inode_flags(file, NODUMP_FL, 0), 0);
        check_eq(uapi16_file_object_set_read_only(file, UAPI16_READ_ONLY_NO), 0);
        check_eq(uapi16_file_object_set_fs_label(refused, "label"), 0);
        w = open_writer(o);
        check_eq(uapi16_manifest_writer_add_object(w, refused, &error), -EBADMSG);
        check_eq(uapi16_manifest_writer_add_object(w, counted, NULL), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, NULL), 0);
        shared.file = file;
        shared.report = report;
        shared.error = error;
        check_eq(pthread_barrier_init(&shared.start, NULL, READERS), 0);
        for (size_t i = 0; i < READERS; i++)
                check_eq(pthread_create(&readers[i], NULL, read_shared, &shared), 0);
        for (size_t i = 0; i < READERS; i++)
                check_eq(pthread_join(readers[i], NULL), 0);
        check_eq(pthread_barrier_destroy(&shared.start), 0);
}

/*
 * A file object stores what it is given and gives it back: every setter
 * with its getter. A getter of a number the object does not have fails
 * with -ENODATA and stores nothing, and one of a string returns NULL. The
 * object keeps a copy of what it is given, and says which features its
 * fields are of.
 */
static void test_file_objects(void) {
        static const uint32_t types[] = { S_IFREG, S_IFDIR, S_IFLNK, S_IFIFO, S_IFCHR, S_IFBLK, S_IFSOCK };
        static const uint32_t no_types[] = { 0, 0777, S_IFMT, S_IFMT | 0644 };
        static const struct {
                uint32_t flag;
                uapi16_feature_t feature;
        } inode_flags[] = {
                { APPEND_FL, UAPI16_FEATURE_FLAG_APPEND_ONLY },
                { IMMUTABLE_FL, UAPI16_FEATURE_FLAG_IMMUTABLE },
                { NOATIME_FL, UAPI16_FEATURE_FLAG_NO_ATIME },
                { NOCOW_FL, UAPI16_FEATURE_FLAG_NO_COW },
                { NODUMP_FL, UAPI16_FEATURE_FLAG_NO_DUMP },
        }, dos_attributes[] = {
                { DOS_HIDDEN, UAPI16_FEATURE_FLAG_HIDDEN },
                { DOS_SYSTEM, UAPI16_FEATURE_FLAG_SYSTEM },
                { DOS_ARCHIVE, UAPI16_FEATURE_FLAG_ARCHIVE },
        };
        static const char target[] = { 't', 'o', 0, '/', (char) 0xff };
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL, *none = NULL, *other = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uapi16_sha256_digest_t hash, read_hash = { .bytes = { 0 } };
        uapi16_uuid_t uuid = { .bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } };
        uapi16_uuid_t read_uuid = { .bytes = { 0 } };
        char text[] = "copied", bytes[] = { 'b', 0, 'c' };
        const char *name, *user, *group, *label, *xattr_name = NULL;
        const char *contents_file = NULL, *other_file = NULL;
        struct features features = FEATURES(UAPI16_FEATURE_NONE);
        uint64_t number = 77, offset = 77;
        uapi16_inode_token_t token = 77;
        uint32_t small = 77, stated = 77, set = 77;
        size_t count = 77, size = 77;
        const void *value = NULL;

        /* A new object is a regular file that says nothing else. */
        check_eq(uapi16_file_object_new("dir/file", &o, &e), 0);
        check(o && !e);
        name = uapi16_file_object_name(o);
        check_str(name, "dir/file");
        check_eq(uapi16_file_object_type(o), S_IFREG);
        check_stated(o, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_UNSTATED);
        check_eq(uapi16_file_object_check_validity(o, 0, &e), 0);
        check_eq(uapi16_file_object_check_validity(o, UINT64_MAX, NULL), 0);

        /* It needs a name, and a place to go to. */
        check_misuse(uapi16_file_object_new(NULL, &none, &e), &e, EINVAL);
        check_misuse(uapi16_file_object_new("x", NULL, &e), &e, EINVAL);
        check_eq(uapi16_file_object_new(NULL, &none, NULL), -EINVAL);
        check_eq(uapi16_file_object_new("x", NULL, NULL), -EINVAL);
        check(!none);

        /* The name: the object keeps its own copy, and hands out a string
         * that stays until the name is set again. */
        check_eq(uapi16_file_object_set_name(o, text, &e), 0);
        text[0] = 'C';
        name = uapi16_file_object_name(o);
        check_str(name, "copied");
        check_eq(uapi16_file_object_set_uid(o, 0), 0);
        check_str(name, "copied");
        check_eq(uapi16_file_object_set_name(o, "dir/file", NULL), 0);
        check_str(uapi16_file_object_name(o), "dir/file");
        check_misuse(uapi16_file_object_set_name(NULL, "x", &e), &e, EINVAL);
        check_misuse(uapi16_file_object_set_name(o, NULL, &e), &e, EINVAL);
        check_str(uapi16_file_object_name(o), "dir/file");
        check(!uapi16_file_object_name(NULL));
        features = WITH(features, UAPI16_FEATURE_UID);

        /* The type, as the bits of the file type in an st_mode. The other
         * bits are not read, and bits that are no type are refused. */
        for (size_t i = 0; i < ELEMENTSOF(types); i++) {
                check_eq(uapi16_file_object_set_type(o, types[i] | 0755), 0);
                check_eq(uapi16_file_object_type(o), types[i]);
        }
        for (size_t i = 0; i < ELEMENTSOF(no_types); i++) {
                check_eq(uapi16_file_object_set_type(o, no_types[i]), -EINVAL);
                check_eq(uapi16_file_object_type(o), S_IFSOCK);
        }
        check_eq(uapi16_file_object_set_type(o, S_IFREG), 0);
        check_eq(uapi16_file_object_set_type(NULL, S_IFREG), -EINVAL);
        check_eq(uapi16_file_object_type(NULL), 0);

        /* The access mode: the permission bits with the set-user-ID, the
         * set-group-ID and the sticky bit. The bits of the file type are
         * not read, and don't change the type. */
        check_eq(uapi16_file_object_mode(o, &small), -ENODATA);
        check_eq(small, 77);
        check_eq(uapi16_file_object_set_mode(o, S_IFDIR | 04755), 0);
        check_eq(uapi16_file_object_mode(o, &small), 0);
        check_eq(small, 04755);
        check_eq(uapi16_file_object_type(o), S_IFREG);
        check_eq(uapi16_file_object_set_mode(o, 07777), 0);
        check_eq(uapi16_file_object_mode(o, &small), 0);
        check_eq(small, 07777);
        check_eq(uapi16_file_object_set_mode(o, 0), 0);
        check_eq(uapi16_file_object_mode(o, &small), 0);
        check_eq(small, 0);
        /* A bit that is neither is refused, and the mode stays. */
        check_eq(uapi16_file_object_set_mode(o, (S_IFMT | 07777) + 1), -EINVAL);
        check_eq(uapi16_file_object_set_mode(o, ~(uint32_t) S_IFMT), -EINVAL);
        check_eq(uapi16_file_object_mode(o, &small), 0);
        check_eq(small, 0);
        check_eq(uapi16_file_object_set_mode(NULL, 0644), -EINVAL);
        check_eq(uapi16_file_object_mode(NULL, &small), -EINVAL);
        check_eq(uapi16_file_object_mode(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_MODE);
        check_stated(o, features);

        /* The owner, by its IDs. The object had its user ID from above. */
        small = 77;
        check_eq(uapi16_file_object_uid(o, &small), 0);
        check_eq(small, 0);
        check_eq(uapi16_file_object_set_uid(o, UINT32_MAX), 0);
        check_eq(uapi16_file_object_uid(o, &small), 0);
        check_eq(small, UINT32_MAX);
        check_eq(uapi16_file_object_set_uid(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_uid(NULL, &small), -EINVAL);
        check_eq(uapi16_file_object_uid(o, NULL), -EINVAL);
        small = 77;
        check_eq(uapi16_file_object_gid(o, &small), -ENODATA);
        check_eq(small, 77);
        check_eq(uapi16_file_object_set_gid(o, 1000), 0);
        check_eq(uapi16_file_object_gid(o, &small), 0);
        check_eq(small, 1000);
        check_eq(uapi16_file_object_set_gid(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_gid(NULL, &small), -EINVAL);
        check_eq(uapi16_file_object_gid(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_GID);
        check_stated(o, features);

        /* The owner, by its names. A string that is handed out belongs to
         * the object and stays while other fields change. */
        check(!uapi16_file_object_user_name(o));
        check(!uapi16_file_object_group_name(o));
        text[0] = 'c';
        check_eq(uapi16_file_object_set_user_name(o, text), 0);
        check_eq(uapi16_file_object_set_group_name(o, text), 0);
        text[0] = 'C';
        user = uapi16_file_object_user_name(o);
        group = uapi16_file_object_group_name(o);
        check_str(user, "copied");
        check_str(group, "copied");
        check_eq(uapi16_file_object_set_group_name(o, "group"), 0);
        check_str(user, "copied");
        check_str(uapi16_file_object_group_name(o), "group");
        /* A string lives until its field is set again: the one that
         * uapi16_file_object_group_name() handed out before is gone now,
         * and is not read here. The address sanitizer would say so. A
         * string stays where it is while other fields are set, which the
         * line above checks. */
        check_eq(uapi16_file_object_set_user_name(o, "user"), 0);
        check_str(uapi16_file_object_user_name(o), "user");
        check_eq(uapi16_file_object_set_user_name(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_group_name(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_user_name(NULL, "user"), -EINVAL);
        check_eq(uapi16_file_object_set_group_name(NULL, "group"), -EINVAL);
        check_str(uapi16_file_object_user_name(o), "user");
        check_str(uapi16_file_object_group_name(o), "group");
        check(!uapi16_file_object_user_name(NULL));
        check(!uapi16_file_object_group_name(NULL));
        features = WITH(features, UAPI16_FEATURE_USER_NAME, UAPI16_FEATURE_GROUP_NAME);
        check_stated(o, features);

        /* The modification time and the size, which are any number. */
        check_eq(uapi16_file_object_mtime_nsec(o, &number), -ENODATA);
        check_eq(number, 77);
        check_eq(uapi16_file_object_set_mtime_nsec(o, 0), 0);
        check_eq(uapi16_file_object_mtime_nsec(o, &number), 0);
        check_eq(number, 0);
        check_eq(uapi16_file_object_set_mtime_nsec(o, UINT64_MAX), 0);
        check_eq(uapi16_file_object_mtime_nsec(o, &number), 0);
        check_eq(number, UINT64_MAX);
        check_eq(uapi16_file_object_set_mtime_nsec(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_mtime_nsec(NULL, &number), -EINVAL);
        check_eq(uapi16_file_object_mtime_nsec(o, NULL), -EINVAL);
        number = 77;
        check_eq(uapi16_file_object_size(o, &number), -ENODATA);
        check_eq(number, 77);
        check_eq(uapi16_file_object_set_size(o, 0), 0);
        check_eq(uapi16_file_object_size(o, &number), 0);
        check_eq(number, 0);
        check_eq(uapi16_file_object_set_size(o, UINT64_MAX), 0);
        check_eq(uapi16_file_object_size(o, &number), 0);
        check_eq(number, UINT64_MAX);
        check_eq(uapi16_file_object_set_size(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_size(NULL, &number), -EINVAL);
        check_eq(uapi16_file_object_size(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_MTIME, UAPI16_FEATURE_SIZE);
        check_stated(o, features);

        /* The hash, of which the object keeps a copy. */
        unhex(SHA256_OF_HELLO, &hash);
        check_eq(uapi16_file_object_sha256(o, &read_hash), -ENODATA);
        check_eq(read_hash.bytes[0], 0);
        check_eq(uapi16_file_object_set_sha256(o, &hash), 0);
        memset(&hash, 0, sizeof(hash));
        check_eq(uapi16_file_object_sha256(o, &read_hash), 0);
        check_hash(&read_hash, SHA256_OF_HELLO);
        check_eq(uapi16_file_object_set_sha256(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_sha256(NULL, &hash), -EINVAL);
        check_eq(uapi16_file_object_sha256(NULL, &read_hash), -EINVAL);
        check_eq(uapi16_file_object_sha256(o, NULL), -EINVAL);
        memset(&read_hash, 0, sizeof(read_hash));
        check_eq(uapi16_file_object_sha256(o, &read_hash), 0);
        check_hash(&read_hash, SHA256_OF_HELLO);
        features = WITH(features, UAPI16_FEATURE_SHA256);
        check_stated(o, features);

        /* The device numbers, each on its own. */
        number = 77;
        check_eq(uapi16_file_object_major(o, &number), -ENODATA);
        check_eq(uapi16_file_object_minor(o, &number), -ENODATA);
        check_eq(number, 77);
        check_eq(uapi16_file_object_set_major(o, 8), 0);
        check_eq(uapi16_file_object_major(o, &number), 0);
        check_eq(number, 8);
        check_eq(uapi16_file_object_minor(o, &number), -ENODATA);
        check_eq(number, 8);
        features = WITH(features, UAPI16_FEATURE_DEVICE);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_minor(o, UINT64_MAX), 0);
        check_eq(uapi16_file_object_minor(o, &number), 0);
        check_eq(number, UINT64_MAX);
        check_eq(uapi16_file_object_set_major(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_set_minor(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_major(NULL, &number), -EINVAL);
        check_eq(uapi16_file_object_minor(NULL, &number), -EINVAL);
        check_eq(uapi16_file_object_major(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_minor(o, NULL), -EINVAL);
        check_stated(o, features);

        /* The token of the names of one file: any number but 0, and
         * UAPI16_INODE_TOKEN_NONE takes the token away. Without one there
         * is nothing to get. */
        check_eq(uapi16_file_object_inode_token(o, &token), -ENODATA);
        check_eq(token, 77);
        check_eq(uapi16_file_object_set_inode_token(o, UINT64_MAX), 0);
        check_eq(uapi16_file_object_inode_token(o, &token), 0);
        check_eq(token, UINT64_MAX);
        check_stated(o, WITH(features, UAPI16_FEATURE_HARDLINK));
        check_eq(uapi16_file_object_set_inode_token(o, UAPI16_INODE_TOKEN_NONE), 0);
        token = 77;
        check_eq(uapi16_file_object_inode_token(o, &token), -ENODATA);
        check_eq(token, 77);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_inode_token(o, 1), 0);
        check_eq(uapi16_file_object_inode_token(o, &token), 0);
        check_eq(token, 1);
        check_eq(uapi16_file_object_set_inode_token(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_inode_token(NULL, &token), -EINVAL);
        check_eq(uapi16_file_object_inode_token(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_HARDLINK);
        check_stated(o, features);

        /* The extended attributes: none said, then listed and none there,
         * then some, which are read in the order of their names. One that
         * is added again gets the new value. */
        check_eq(uapi16_file_object_user_xattrs(o, &count), -ENODATA);
        check_eq(count, 77);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr_name, &value, &size), -EINVAL);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_user_xattrs(o), 0);
        check_eq(uapi16_file_object_user_xattrs(o, &count), 0);
        check_eq(count, 0);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr_name, &value, &size), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_USER_XATTR);
        check_stated(o, features);
        text[0] = 'c';
        check_eq(uapi16_file_object_add_user_xattr(o, "c", "three", 5), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, "a", NULL, 0), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, text, bytes, sizeof(bytes)), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, "b", "two", 3), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, "c", unreadable(), 0), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, "b", bytes, sizeof(bytes)), 0);
        text[0] = 'C';
        bytes[0] = 'B';
        check_eq(uapi16_file_object_user_xattrs(o, &count), 0);
        check_eq(count, 4);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr_name, &value, &size), 0);
        check_str(xattr_name, "a");
        check_eq(size, 0);
        check_eq(uapi16_file_object_user_xattr(o, 1, &xattr_name, &value, &size), 0);
        check_str(xattr_name, "b");
        check_same(value, size, "b\0c", 3);
        check_eq(uapi16_file_object_user_xattr(o, 2, &xattr_name, &value, &size), 0);
        check_str(xattr_name, "c");
        check_eq(size, 0);
        check_eq(uapi16_file_object_user_xattr(o, 3, &xattr_name, &value, &size), 0);
        check_str(xattr_name, "copied");
        check_same(value, size, "b\0c", 3);
        /* Each of the three places can be NULL, and what was handed out
         * stays while the object is only read. */
        check_eq(uapi16_file_object_user_xattr(o, 1, NULL, NULL, NULL), 0);
        check_eq(uapi16_file_object_user_xattr(o, 1, NULL, NULL, &size), 0);
        check_eq(size, 3);
        check_str(xattr_name, "copied");
        check_same(value, 3, "b\0c", 3);
        /* An attribute beyond the last one stores nothing. */
        xattr_name = NULL;
        value = NULL;
        size = 77;
        check_eq(uapi16_file_object_user_xattr(o, 4, &xattr_name, &value, &size), -EINVAL);
        check_eq(uapi16_file_object_user_xattr(o, SIZE_MAX, &xattr_name, &value, &size), -EINVAL);
        check(!xattr_name && !value && size == 77);
        check_eq(uapi16_file_object_add_user_xattr(o, NULL, "v", 1), -EINVAL);
        check_eq(uapi16_file_object_add_user_xattr(o, "d", NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_add_user_xattr(NULL, "d", "v", 1), -EINVAL);
        check_eq(uapi16_file_object_set_user_xattrs(NULL), -EINVAL);
        check_eq(uapi16_file_object_user_xattrs(NULL, &count), -EINVAL);
        check_eq(uapi16_file_object_user_xattrs(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_user_xattr(NULL, 0, &xattr_name, &value, &size), -EINVAL);
        check_eq(uapi16_file_object_user_xattrs(o, &count), 0);
        check_eq(count, 4);
        /* Listing them again lists none, and an attribute that is added to
         * an object that said nothing makes it list its attributes. */
        check_eq(uapi16_file_object_set_user_xattrs(o), 0);
        check_eq(uapi16_file_object_user_xattrs(o, &count), 0);
        check_eq(count, 0);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr_name, &value, &size), -EINVAL);
        check(!xattr_name && !value && size == 77);
        check_stated(o, features);
        check_eq(uapi16_file_object_new("other", &other, &e), 0);
        check_eq(uapi16_file_object_add_user_xattr(other, "only", "1", 1), 0);
        check_eq(uapi16_file_object_user_xattrs(other, &count), 0);
        check_eq(count, 1);
        check_stated(other, FEATURES(UAPI16_FEATURE_USER_XATTR));
        check_eq(uapi16_file_object_user_xattrs(o, &count), 0);
        check_eq(count, 0);

        /* Whether the file is read-only: three answers, and no other. */
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_UNSTATED);
        check_eq(uapi16_file_object_set_read_only(o, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_YES);
        check_stated(o, WITH(features, UAPI16_FEATURE_READ_ONLY));
        check_eq(uapi16_file_object_set_read_only(o, 3), -EINVAL);
        check_eq(uapi16_file_object_set_read_only(o, UINT64_MAX), -EINVAL);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_YES);
        check_eq(uapi16_file_object_set_read_only(o, UAPI16_READ_ONLY_UNSTATED), 0);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_UNSTATED);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_read_only(o, UAPI16_READ_ONLY_NO), 0);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_NO);
        check_eq(uapi16_file_object_set_read_only(NULL, UAPI16_READ_ONLY_YES), -EINVAL);
        check_eq(uapi16_file_object_read_only(NULL), UAPI16_READ_ONLY_UNSTATED);
        features = WITH(features, UAPI16_FEATURE_READ_ONLY);
        check_stated(o, features);

        /* The Linux inode flags, with the bits of the kernel: the flags the
         * object says something about, and those of them that are set. A
         * flag that is not stated is taken away, and other bits are not
         * read. */
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        for (size_t i = 0; i < ELEMENTSOF(inode_flags); i++) {
                uint32_t flag = inode_flags[i].flag;

                check_eq(uapi16_file_object_set_inode_flags(o, flag | SYNC_FL, UINT32_MAX), 0);
                check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
                check_eq(stated, flag);
                check_eq(set, flag);
                check_stated(o, WITH(features, inode_flags[i].feature));
                /* A flag that is stated and not set is a field as well. */
                check_eq(uapi16_file_object_set_inode_flags(o, flag, 0), 0);
                check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
                check_eq(stated, flag);
                check_eq(set, 0);
                check_stated(o, WITH(features, inode_flags[i].feature));
        }
        check_eq(uapi16_file_object_set_inode_flags(o, 0, UINT32_MAX), 0);
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_inode_flags(o, UINT32_MAX, APPEND_FL | NOCOW_FL | SYNC_FL), 0);
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, APPEND_FL | NOCOW_FL);
        /* Either place can be NULL. */
        stated = set = 77;
        check_eq(uapi16_file_object_inode_flags(o, &stated, NULL), 0);
        check_eq(uapi16_file_object_inode_flags(o, NULL, &set), 0);
        check_eq(uapi16_file_object_inode_flags(o, NULL, NULL), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, APPEND_FL | NOCOW_FL);
        check_eq(uapi16_file_object_set_inode_flags(NULL, 0, 0), -EINVAL);
        check_eq(uapi16_file_object_inode_flags(NULL, &stated, &set), -EINVAL);
        for (size_t i = 0; i < ELEMENTSOF(inode_flags); i++)
                features = WITH(features, inode_flags[i].feature);
        check_stated(o, features);

        /* The DOS attributes hidden, system and archive, with the bits of
         * a directory entry of FAT, the same way. */
        check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        for (size_t i = 0; i < ELEMENTSOF(dos_attributes); i++) {
                uint32_t attribute = dos_attributes[i].flag;

                check_eq(uapi16_file_object_set_dos_attributes(o, attribute | DOS_READ_ONLY, UINT32_MAX), 0);
                check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
                check_eq(stated, attribute);
                check_eq(set, attribute);
                check_stated(o, WITH(features, dos_attributes[i].feature));
                check_eq(uapi16_file_object_set_dos_attributes(o, attribute, 0), 0);
                check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
                check_eq(stated, attribute);
                check_eq(set, 0);
                check_stated(o, WITH(features, dos_attributes[i].feature));
        }
        check_eq(uapi16_file_object_set_dos_attributes(o, 0, UINT32_MAX), 0);
        check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_dos_attributes(o, UINT32_MAX, DOS_ARCHIVE | DOS_DIRECTORY), 0);
        check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
        check_eq(stated, DOS_ATTRIBUTES);
        check_eq(set, DOS_ARCHIVE);
        stated = set = 77;
        check_eq(uapi16_file_object_dos_attributes(o, &stated, NULL), 0);
        check_eq(uapi16_file_object_dos_attributes(o, NULL, &set), 0);
        check_eq(uapi16_file_object_dos_attributes(o, NULL, NULL), 0);
        check_eq(stated, DOS_ATTRIBUTES);
        check_eq(set, DOS_ARCHIVE);
        check_eq(uapi16_file_object_set_dos_attributes(NULL, 0, 0), -EINVAL);
        check_eq(uapi16_file_object_dos_attributes(NULL, &stated, &set), -EINVAL);
        /* The read-only attribute of DOS is the one field for both. */
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_NO);
        for (size_t i = 0; i < ELEMENTSOF(dos_attributes); i++)
                features = WITH(features, dos_attributes[i].feature);
        check_stated(o, features);

        /* Where the data is. That of a regular file is in the file of its
         * name next to the manifest, unless the object refers to another
         * file. */
        size = 77;
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_EXTERNAL);
        check(!uapi16_file_object_literal(o, &size));
        check_eq(size, 0);
        check(!uapi16_file_object_literal(o, NULL));
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), -ENODATA);
        check(!contents_file);
        check_eq(offset, 77);
        check_eq(uapi16_file_object_set_contents_file(o, "blobs/1", &e), 0);
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_EXTERNAL);
        check(!uapi16_file_object_literal(o, &size));
        check_misuse(uapi16_file_object_set_contents_file(o, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_file_object_set_contents_file(NULL, "blobs/1", &e), &e, EINVAL);
        check_stated(o, features);
        /* The object says which file that is, and that the data starts at
         * its beginning. The name is a string of the object, which stays
         * until the object refers to another file. Both places are needed,
         * and a call that fails stores nothing. */
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), 0);
        check_str(contents_file, "blobs/1");
        check_eq(offset, 0);
        offset = 77;
        check_eq(uapi16_file_object_contents_file(o, &other_file, &offset), 0);
        check(other_file == contents_file);
        check_eq(uapi16_file_object_set_contents_file(o, "blobs/2", &e), 0);
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), 0);
        check_str(contents_file, "blobs/2");
        contents_file = NULL;
        offset = 77;
        check_eq(uapi16_file_object_contents_file(NULL, &contents_file, &offset), -EINVAL);
        check_eq(uapi16_file_object_contents_file(o, NULL, &offset), -EINVAL);
        check_eq(uapi16_file_object_contents_file(o, &contents_file, NULL), -EINVAL);
        check_eq(uapi16_file_object_contents_file(o, NULL, NULL), -EINVAL);
        check(!contents_file);
        check_eq(offset, 77);
        /* A file of the object's own name is no other file. */
        check_eq(uapi16_file_object_set_contents_file(o, uapi16_file_object_name(o), &e), 0);
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), -ENODATA);
        check_eq(uapi16_file_object_set_contents_file(o, "blobs/1", &e), 0);
        /* The file stays with any features, as it belongs to none. */
        check_eq(retain_features(o, features), 0);
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), 0);
        check_str(contents_file, "blobs/1");

        /* The target of a symbolic link is in the manifest: bytes, which
         * need not be text and of which the object keeps a copy. They are
         * a field of the feature only on a symbolic link. */
        memcpy(bytes, target, sizeof(bytes));
        check_eq(uapi16_file_object_set_target(o, bytes, sizeof(bytes)), 0);
        memset(bytes, 0, sizeof(bytes));
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_LITERAL);
        /* Data that the manifest carries is in no other file. */
        contents_file = NULL;
        offset = 77;
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), -ENODATA);
        check(!contents_file);
        check_eq(offset, 77);
        value = uapi16_file_object_literal(o, &size);
        check_same(value, size, target, 3);
        check_eq(uapi16_file_object_set_target(o, target, sizeof(target)), 0);
        value = uapi16_file_object_literal(o, &size);
        check_same(value, size, target, sizeof(target));
        check(uapi16_file_object_literal(o, NULL));
        check_stated(o, features);
        check_eq(uapi16_file_object_set_type(o, S_IFLNK), 0);
        features = WITH(features, UAPI16_FEATURE_SYMLINK);
        check_stated(o, features);
        check_eq(uapi16_file_object_set_target(o, NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_set_target(NULL, target, sizeof(target)), -EINVAL);
        value = uapi16_file_object_literal(o, &size);
        check_same(value, size, target, sizeof(target));
        /* A target of no bytes is one, and needs no pointer. */
        check_eq(uapi16_file_object_set_target(o, unreadable(), 0), 0);
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_LITERAL);
        size = 77;
        check(uapi16_file_object_literal(o, &size));
        check_eq(size, 0);
        check_eq(uapi16_file_object_set_target(o, NULL, 0), 0);
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_LITERAL);
        check_stated(o, features);
        /* What is neither a regular file nor a symbolic link with a target
         * has no data, and no object is no data. */
        check_eq(uapi16_file_object_data_location(other), UAPI16_DATA_LOCATION_EXTERNAL);
        for (size_t i = 0; i < ELEMENTSOF(types); i++) {
                check_eq(uapi16_file_object_set_type(other, types[i]), 0);
                check_eq(uapi16_file_object_data_location(other),
                         types[i] == S_IFREG ? UAPI16_DATA_LOCATION_EXTERNAL : 0);
                check(!uapi16_file_object_literal(other, &size));
        }
        check_eq(uapi16_file_object_data_location(NULL), UAPI16_DATA_LOCATION_NONE);
        size = 77;
        check(!uapi16_file_object_literal(NULL, &size));
        check_eq(size, 0);
        check(!uapi16_file_object_literal(NULL, NULL));

        /* The identity of the file system, which only the root has in a
         * manifest. A setter stores it on any object. */
        check(!uapi16_file_object_fs_label(o));
        text[0] = 'c';
        check_eq(uapi16_file_object_set_fs_label(o, text), 0);
        text[0] = 'C';
        label = uapi16_file_object_fs_label(o);
        check_str(label, "copied");
        check_eq(uapi16_file_object_set_fs_label(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_fs_label(NULL, "label"), -EINVAL);
        check(!uapi16_file_object_fs_label(NULL));
        features = WITH(features, UAPI16_FEATURE_FS_LABEL);
        check_stated(o, features);
        check_eq(uapi16_file_object_fs_uuid(o, &read_uuid), -ENODATA);
        check_eq(read_uuid.bytes[0], 0);
        check_eq(uapi16_file_object_set_fs_uuid(o, &uuid), 0);
        memset(&uuid, 0, sizeof(uuid));
        check_eq(uapi16_file_object_fs_uuid(o, &read_uuid), 0);
        for (size_t i = 0; i < UAPI16_UUID_SIZE; i++)
                check_eq(read_uuid.bytes[i], i + 1);
        check_eq(uapi16_file_object_set_fs_uuid(o, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_fs_uuid(NULL, &uuid), -EINVAL);
        check_eq(uapi16_file_object_fs_uuid(NULL, &read_uuid), -EINVAL);
        check_eq(uapi16_file_object_fs_uuid(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_FS_UUID);
        check_stated(o, features);
        small = 77;
        check_eq(uapi16_file_object_fat_serial(o, &small), -ENODATA);
        check_eq(small, 77);
        check_eq(uapi16_file_object_set_fat_serial(o, 0x1234abcd), 0);
        check_eq(uapi16_file_object_fat_serial(o, &small), 0);
        check_eq(small, 0x1234abcd);
        check_eq(uapi16_file_object_set_fat_serial(o, 0), 0);
        check_eq(uapi16_file_object_fat_serial(o, &small), 0);
        check_eq(small, 0);
        check_eq(uapi16_file_object_set_fat_serial(NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_fat_serial(NULL, &small), -EINVAL);
        check_eq(uapi16_file_object_fat_serial(o, NULL), -EINVAL);
        features = WITH(features, UAPI16_FEATURE_FAT_SERIAL);
        check_stated(o, features);

        /* The object has a field of every feature of a tree now, and no
         * object has none. */
        check_same_features(features, FEATURES_OF_TREES);
        check_stated(NULL, FEATURES(UAPI16_FEATURE_NONE));
        check_str(label, "copied");
        check_str(uapi16_file_object_name(o), "dir/file");

        /* A check of when it may be used needs an object. */
        check_misuse(uapi16_file_object_check_validity(NULL, 0, &e), &e, EINVAL);
        check_eq(uapi16_file_object_check_validity(NULL, 0, NULL), -EINVAL);
        check_eq(uapi16_file_object_check_validity(o, 0, &e), 0);
        check(!e);

        /* Freeing returns NULL, and takes NULL. */
        o = uapi16_file_object_free(o);
        check(!o);
        check(!uapi16_file_object_free(NULL));
}

/*
 * uapi16_file_object_retain_features() takes away the fields of every
 * feature that is not in the list it is given, so that a caller sets all it
 * knows of a file and keeps what its manifest records. The name, the type
 * and what belongs to no feature stay. A string the object handed out is
 * where it was as long as its field is there.
 */
static void test_retained_features(void) {
        /* (1 << 32) + UAPI16_FEATURE_MODE is that feature in its low 32 bits. */
        static const uapi16_feature_t no_features[] = {
                NO_FEATURE, UINT64_C(1) << 31, (UINT64_C(1) << 32) + UAPI16_FEATURE_MODE,
                UINT64_C(1) << 63, UINT64_MAX,
        };
        const struct features every = EVERY_FEATURE;
        const struct features kept = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_USER_NAME,
                                              UAPI16_FEATURE_SIZE, UAPI16_FEATURE_FLAG_NO_DUMP);
        static const uapi16_uuid_t uuid = { .bytes = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 } };
        _cleanup_(closep) int written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *options =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = make_hello("file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *link = make_object("link");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *literal = make_object("literal");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *text = NULL;
        uapi16_sha256_digest_t hash = { .bytes = { 0 } };
        uapi16_uuid_t read_uuid = { .bytes = { 0 } };
        uint32_t small = 77, stated = 77, set = 77;
        struct features all;
        uint64_t number = 77, offset = 77;
        uapi16_inode_token_t token = 77;
        size_t count = 77, size = 77, text_size;
        const char *name, *user, *group, *label, *xattr = NULL, *again = NULL;
        const char *contents_file = NULL;
        const void *value = NULL;
        int r;

        /* A regular file with a field of many features, whose data is in
         * another file. */
        check_eq(uapi16_file_object_set_mode(o, 0644), 0);
        check_eq(uapi16_file_object_set_uid(o, 1), 0);
        check_eq(uapi16_file_object_set_gid(o, 2), 0);
        check_eq(uapi16_file_object_set_user_name(o, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(o, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(o, 3), 0);
        check_eq(uapi16_file_object_set_inode_token(o, 4), 0);
        check_eq(uapi16_file_object_add_user_xattr(o, "key", "value", 5), 0);
        check_eq(uapi16_file_object_set_read_only(o, UAPI16_READ_ONLY_NO), 0);
        check_eq(uapi16_file_object_set_inode_flags(o, NODUMP_FL | APPEND_FL, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_dos_attributes(o, DOS_HIDDEN | DOS_ARCHIVE, DOS_HIDDEN), 0);
        check_eq(uapi16_file_object_set_contents_file(o, "blobs/1", &e), 0);
        all = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID,
                       UAPI16_FEATURE_USER_NAME, UAPI16_FEATURE_GROUP_NAME, UAPI16_FEATURE_MTIME,
                       UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256, UAPI16_FEATURE_HARDLINK,
                       UAPI16_FEATURE_USER_XATTR, UAPI16_FEATURE_READ_ONLY,
                       UAPI16_FEATURE_FLAG_NO_DUMP, UAPI16_FEATURE_FLAG_APPEND_ONLY,
                       UAPI16_FEATURE_FLAG_HIDDEN, UAPI16_FEATURE_FLAG_ARCHIVE);
        check_stated(o, all);
        name = uapi16_file_object_name(o);
        user = uapi16_file_object_user_name(o);
        group = uapi16_file_object_group_name(o);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr, &value, &size), 0);
        check(name && user && group && xattr && value);

        /* A manifest that records four features has no room for it as it
         * is: a writer of records refuses it for a field of another one. */
        check_eq(set_features(options, kept), 0);
        w = begin_records(options, written);
        r = uapi16_writer_file(w, o, &e);
        check_eq(r, -EBADMSG);
        check_str(uapi16_error_problem(e), "unlistedFeature");
        e = uapi16_error_free(e);

        /* Every feature it has, and every feature there is: nothing
         * changes, and the strings it handed out are where they were. */
        check_eq(retain_features(o, all), 0);
        check_eq(retain_features(o, every), 0);
        check_stated(o, all);
        check(uapi16_file_object_name(o) == name);
        check(uapi16_file_object_user_name(o) == user);
        check(uapi16_file_object_group_name(o) == group);
        check_eq(uapi16_file_object_user_xattr(o, 0, &again, NULL, NULL), 0);
        check(again == xattr);
        check_str(xattr, "key");
        check_eq(uapi16_file_object_uid(o, &small), 0);
        check_eq(small, 1);

        /* A number that is no feature is refused, also behind one that is
         * a feature, and changes nothing. So is no object. */
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++) {
                check_eq(retain_features(o, FEATURES(no_features[i])), -EINVAL);
                check_eq(retain_features(o, FEATURES(UAPI16_FEATURE_MODE, no_features[i])), -EINVAL);
        }
        check_eq(retain_features(NULL, kept), -EINVAL);
        check_stated(o, all);
        check(uapi16_file_object_group_name(o) == group);

        /* The four features of the manifest: the fields of these stay, and
         * those of the others are gone. The flag of the feature that stays
         * is the one the object says something about still. */
        check_eq(retain_features(o, kept), 0);
        check_stated(o, kept);
        check_eq(uapi16_file_object_mode(o, &small), 0);
        check_eq(small, 0644);
        check_eq(uapi16_file_object_size(o, &number), 0);
        check_eq(number, 5);
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, NODUMP_FL);
        check_eq(set, NODUMP_FL);
        small = 77;
        number = 77;
        check_eq(uapi16_file_object_uid(o, &small), -ENODATA);
        check_eq(uapi16_file_object_gid(o, &small), -ENODATA);
        check_eq(uapi16_file_object_mtime_nsec(o, &number), -ENODATA);
        check_eq(uapi16_file_object_sha256(o, &hash), -ENODATA);
        check_eq(uapi16_file_object_inode_token(o, &token), -ENODATA);
        check_eq(uapi16_file_object_user_xattrs(o, &count), -ENODATA);
        check_eq(uapi16_file_object_user_xattr(o, 0, &again, NULL, NULL), -EINVAL);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_UNSTATED);
        check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        check(small == 77 && number == 77 && token == 77 && count == 77 && hash.bytes[0] == 0);
        /* The string of the field that stays is where it was, and the one
         * of the field that went is none. */
        check(uapi16_file_object_user_name(o) == user);
        check_str(user, "user");
        check(!uapi16_file_object_group_name(o));
        /* The name, the type and where the data is belong to no feature. */
        check(uapi16_file_object_name(o) == name);
        check_str(name, "file");
        check_eq(uapi16_file_object_type(o), S_IFREG);
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_EXTERNAL);

        /* The writer takes it now, with the file its data is in. */
        check_eq(uapi16_writer_file(w, o, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);
        text = read_all(written, &text_size);
        check_manifest(text, text_size);
        check(strstr(text, "\"file\":\"blobs/1\""));
        check(strstr(text, "\"userName\":\"user\""));
        check(!strstr(text, "groupName"));

        /* No feature at all: the name and the type are left, and where
         * the data is. */
        check_eq(retain_features(o, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_stated(o, FEATURES(UAPI16_FEATURE_NONE));
        check(!uapi16_file_object_user_name(o));
        check_eq(uapi16_file_object_mode(o, &small), -ENODATA);
        check_eq(uapi16_file_object_size(o, &number), -ENODATA);
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, 0);
        check(uapi16_file_object_name(o) == name);
        check_eq(uapi16_file_object_type(o), S_IFREG);
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_EXTERNAL);
        /* The file the data of a regular file is in belongs to no feature,
         * and stays. */
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &offset), 0);
        check_str(contents_file, "blobs/1");
        check_eq(offset, 0);

        /* The target of a symbolic link is the field of a feature: it
         * stays with UAPI16_FEATURE_SYMLINK, and goes without it. The link
         * is one still. */
        check_eq(uapi16_file_object_set_type(link, S_IFLNK), 0);
        check_eq(uapi16_file_object_set_target(link, "to", 2), 0);
        check_stated(link, FEATURES(UAPI16_FEATURE_SYMLINK));
        check_eq(retain_features(link, FEATURES(UAPI16_FEATURE_SYMLINK, UAPI16_FEATURE_MODE)), 0);
        value = uapi16_file_object_literal(link, &size);
        check_same(value, size, "to", 2);
        check_eq(uapi16_file_object_data_location(link), UAPI16_DATA_LOCATION_LITERAL);
        check_eq(retain_features(link, FEATURES(UAPI16_FEATURE_MODE)), 0);
        size = 77;
        check(!uapi16_file_object_literal(link, &size));
        check_eq(size, 0);
        check_eq(uapi16_file_object_data_location(link), UAPI16_DATA_LOCATION_NONE);
        check_stated(link, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_type(link), S_IFLNK);
        check_str(uapi16_file_object_name(link), "link");
        /* So does the file a symbolic link has its target in: the object
         * names it with the feature, and names none without it. */
        check_eq(uapi16_file_object_set_contents_file(link, "blobs/target", &e), 0);
        check_stated(link, FEATURES(UAPI16_FEATURE_SYMLINK));
        check_eq(retain_features(link, FEATURES(UAPI16_FEATURE_SYMLINK)), 0);
        check_eq(uapi16_file_object_contents_file(link, &contents_file, &offset), 0);
        check_str(contents_file, "blobs/target");
        check_eq(retain_features(link, FEATURES(UAPI16_FEATURE_MODE)), 0);
        contents_file = NULL;
        offset = 77;
        check_eq(uapi16_file_object_contents_file(link, &contents_file, &offset), -ENODATA);
        check(!contents_file);
        check_eq(offset, 77);

        /* Data that the manifest carries for a regular file belongs to no
         * feature, and stays. */
        check_eq(uapi16_file_object_set_target(literal, "data", 4), 0);
        check_eq(retain_features(literal, FEATURES(UAPI16_FEATURE_NONE)), 0);
        value = uapi16_file_object_literal(literal, &size);
        check_same(value, size, "data", 4);
        check_eq(uapi16_file_object_data_location(literal), UAPI16_DATA_LOCATION_LITERAL);

        /* What only the root has goes and stays by its features as well:
         * the label, the UUID and the volume serial number of the file
         * system. */
        check_eq(uapi16_file_object_set_mode(root, 0755), 0);
        check_eq(uapi16_file_object_set_fs_label(root, "label"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(root, &uuid), 0);
        check_eq(uapi16_file_object_set_fat_serial(root, 7), 0);
        label = uapi16_file_object_fs_label(root);
        check_str(label, "label");
        all = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_FS_LABEL, UAPI16_FEATURE_FS_UUID,
                       UAPI16_FEATURE_FAT_SERIAL);
        check_stated(root, all);
        all = FEATURES(UAPI16_FEATURE_FS_LABEL, UAPI16_FEATURE_FS_UUID);
        check_eq(retain_features(root, all), 0);
        check_stated(root, all);
        check(uapi16_file_object_fs_label(root) == label);
        check_str(label, "label");
        check_eq(uapi16_file_object_fs_uuid(root, &read_uuid), 0);
        check_eq(memcmp(&read_uuid, &uuid, sizeof(uuid)), 0);
        small = 77;
        check_eq(uapi16_file_object_fat_serial(root, &small), -ENODATA);
        check_eq(uapi16_file_object_mode(root, &small), -ENODATA);
        check_eq(small, 77);
        check_eq(retain_features(root, FEATURES(UAPI16_FEATURE_FS_UUID)), 0);
        check(!uapi16_file_object_fs_label(root));
        check_eq(uapi16_file_object_fs_uuid(root, &read_uuid), 0);
        check_stated(root, FEATURES(UAPI16_FEATURE_FS_UUID));
        /* It is the root still. */
        check_str(uapi16_file_object_name(root), "");
        check_eq(uapi16_file_object_type(root), S_IFDIR);
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++)
                check_eq(retain_features(root, FEATURES(no_features[i])), -EINVAL);
        check_stated(root, FEATURES(UAPI16_FEATURE_FS_UUID));
        /* The UUID goes like the label and the serial. */
        check_eq(retain_features(root, FEATURES(UAPI16_FEATURE_FS_LABEL)), 0);
        check_eq(uapi16_file_object_fs_uuid(root, &read_uuid), -ENODATA);
        check_stated(root, FEATURES(UAPI16_FEATURE_NONE));
        check(!e);
}

/*
 * The root is the file object with the empty name: a directory, which
 * keeps its name and its type. A setter stores on it whatever it is given,
 * and a writer refuses a root with what only another file object has, and
 * any other file object with what only the root has. What the root has of
 * its own, a writer of records writes and a reader hands out again.
 */
static void test_roots(void) {
        static const uint32_t no_root_types[] = { S_IFREG, S_IFLNK, S_IFIFO, S_IFCHR, S_IFBLK, S_IFSOCK };
        static const char *const only_files_have[] = {
                "size", "sha256", "contents", "contents", "inodeToken", "major", "minor",
                "flagHidden", "flagSystem", "flagArchive",
        };
        static const char *const only_the_root_has[] = { "fsLabel", "fsUUID", "fatSerial" };
        static const uapi16_uuid_t uuid = { .bytes = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 } };
        _cleanup_(closep) int written = scratch_file(), refused_to = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *listing = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *other = make_object("other");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("plain");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uapi16_sha256_digest_t hash;
        uapi16_uuid_t read_uuid;
        struct features features;
        uint64_t number = 77;
        uapi16_inode_token_t token = 77;
        uint32_t small = 77, stated = 77, set = 77;
        size_t count = 77, size = 77;
        const uapi16_file_object *got;
        const char *name = NULL;
        const void *value = NULL;
        int r;

        check_eq(set_features(o, FEATURES_OF_TREES), 0);
        unhex(SHA256_OF_NOTHING, &hash);

        /* The empty name makes the root, which is a directory. */
        check_eq(uapi16_file_object_new("", &root, &e), 0);
        check(root && !e);
        check_str(uapi16_file_object_name(root), "");
        check_eq(uapi16_file_object_type(root), S_IFDIR);
        check_stated(root, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_data_location(root), UAPI16_DATA_LOCATION_NONE);

        /* It takes the type of a directory and no other. */
        check_eq(uapi16_file_object_set_type(root, S_IFDIR), 0);
        check_eq(uapi16_file_object_set_type(root, S_IFDIR | 0755), 0);
        for (size_t i = 0; i < ELEMENTSOF(no_root_types); i++)
                check_eq(uapi16_file_object_set_type(root, no_root_types[i]), -EINVAL);
        check_eq(uapi16_file_object_set_type(root, 0), -EINVAL);
        check_eq(uapi16_file_object_type(root), S_IFDIR);

        /* It keeps its name, and no other object takes the empty one. */
        check_misuse(uapi16_file_object_set_name(root, "name", &e), &e, EINVAL);
        check_eq(uapi16_file_object_set_name(root, "name", NULL), -EINVAL);
        check_str(uapi16_file_object_name(root), "");
        check_misuse(uapi16_file_object_set_name(other, "", &e), &e, EINVAL);
        check_eq(uapi16_file_object_set_name(other, "", NULL), -EINVAL);
        check_str(uapi16_file_object_name(other), "other");

        /* A setter stores what only another file object has in a manifest,
         * and a writer of records refuses to begin with such a root, for
         * the field. Nothing is written. */
        for (size_t i = 0; i < ELEMENTSOF(only_files_have); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("");

                switch (i) {
                case 0:
                        check_eq(uapi16_file_object_set_size(refused, 1), 0);
                        check_eq(uapi16_file_object_size(refused, &number), 0);
                        check_eq(number, 1);
                        break;
                case 1:
                        check_eq(uapi16_file_object_set_sha256(refused, &hash), 0);
                        break;
                case 2:
                        check_eq(uapi16_file_object_set_target(refused, "target", 6), 0);
                        break;
                case 3:
                        check_eq(uapi16_file_object_set_contents_file(refused, "file", NULL), 0);
                        break;
                case 4:
                        check_eq(uapi16_file_object_set_inode_token(refused, 1), 0);
                        break;
                case 5:
                        check_eq(uapi16_file_object_set_major(refused, 1), 0);
                        break;
                case 6:
                        check_eq(uapi16_file_object_set_minor(refused, 1), 0);
                        break;
                case 7:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_HIDDEN, DOS_HIDDEN), 0);
                        break;
                case 8:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_SYSTEM, 0), 0);
                        break;
                default:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_ARCHIVE, 0), 0);
                        break;
                }
                r = uapi16_writer_begin(o, refused_to, refused, &none, &e);
                check_refused(r, &e, "fieldNotPermitted", "", only_files_have[i]);
                check_eq(uapi16_writer_begin(o, refused_to, refused, &none, NULL), -EBADMSG);
                check(!none);
        }
        check_eq(size_of(refused_to), 0);

        /* What is no root is none for a writer of records to begin with. */
        check_misuse(uapi16_writer_begin(o, refused_to, other, &none, &e), &e, EINVAL);
        check(!none);
        check_eq(size_of(refused_to), 0);

        /* The other way round: a writer of records and a writer refuse any
         * other file object with a part of the identity of a file system,
         * for the field, and go on. */
        w = begin_records(o, refused_to);
        listing = open_writer(o);
        for (size_t i = 0; i < ELEMENTSOF(only_the_root_has); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("other");
                size_t before = size_of(refused_to);

                switch (i) {
                case 0:
                        check_eq(uapi16_file_object_set_fs_label(refused, "label"), 0);
                        break;
                case 1:
                        check_eq(uapi16_file_object_set_fs_uuid(refused, &uuid), 0);
                        break;
                default:
                        check_eq(uapi16_file_object_set_fat_serial(refused, 1), 0);
                        break;
                }
                r = uapi16_writer_file(w, refused, &e);
                check_refused(r, &e, "fieldNotPermitted", "other", only_the_root_has[i]);
                r = uapi16_manifest_writer_add_object(listing, refused, &e);
                check_refused(r, &e, "fieldNotPermitted", "other", only_the_root_has[i]);
                check_eq(size_of(refused_to), before);
        }
        check_eq(uapi16_writer_file(w, other, &e), 0);
        check_eq(uapi16_writer_file(w, plain, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);
        check_eq(uapi16_manifest_writer_add_object(listing, other, &e), 0);
        listing = uapi16_manifest_writer_free(listing);

        /* What the root has: the attributes of its directory, and the
         * identity of its file system. */
        check_eq(uapi16_file_object_set_mode(root, 0555), 0);
        check_eq(uapi16_file_object_set_uid(root, 1), 0);
        check_eq(uapi16_file_object_set_gid(root, 2), 0);
        check_eq(uapi16_file_object_set_user_name(root, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(root, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(root, 3), 0);
        check_eq(uapi16_file_object_add_user_xattr(root, "k", "v", 1), 0);
        check_eq(uapi16_file_object_set_read_only(root, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_set_inode_flags(root, NODUMP_FL | IMMUTABLE_FL, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_fs_label(root, "label"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(root, &uuid), 0);
        check_eq(uapi16_file_object_set_fat_serial(root, 0x1234abcd), 0);
        features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID,
                            UAPI16_FEATURE_USER_NAME, UAPI16_FEATURE_GROUP_NAME,
                            UAPI16_FEATURE_MTIME, UAPI16_FEATURE_USER_XATTR,
                            UAPI16_FEATURE_READ_ONLY, UAPI16_FEATURE_FLAG_NO_DUMP,
                            UAPI16_FEATURE_FLAG_IMMUTABLE, UAPI16_FEATURE_FS_LABEL,
                            UAPI16_FEATURE_FS_UUID, UAPI16_FEATURE_FAT_SERIAL);
        check_stated(root, features);

        /* A writer of records begins with it, and a reader hands it out
         * with every field. The flag the root said was cleared is one the
         * manifest says by its features, as it says the other flags. */
        check_eq(uapi16_writer_begin(o, written, root, &w, &e), 0);
        check_eq(uapi16_writer_file(w, plain, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);
        reader = open_reader(written);
        check_recorded(reader, FEATURES_OF_TREES);
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);
        got = uapi16_reader_root(reader);
        check(got);
        check_str(uapi16_file_object_name(got), "");
        check_eq(uapi16_file_object_type(got), S_IFDIR);
        check_eq(uapi16_file_object_mode(got, &small), 0);
        check_eq(small, 0555);
        check_eq(uapi16_file_object_uid(got, &small), 0);
        check_eq(small, 1);
        check_eq(uapi16_file_object_gid(got, &small), 0);
        check_eq(small, 2);
        check_str(uapi16_file_object_user_name(got), "user");
        check_str(uapi16_file_object_group_name(got), "group");
        check_eq(uapi16_file_object_mtime_nsec(got, &number), 0);
        check_eq(number, 3);
        check_eq(uapi16_file_object_user_xattrs(got, &count), 0);
        check_eq(count, 1);
        check_eq(uapi16_file_object_user_xattr(got, 0, &name, &value, &size), 0);
        check_str(name, "k");
        check_same(value, size, "v", 1);
        check_eq(uapi16_file_object_read_only(got), UAPI16_READ_ONLY_YES);
        check_eq(uapi16_file_object_inode_flags(got, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, NODUMP_FL);
        check_str(uapi16_file_object_fs_label(got), "label");
        check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), 0);
        check_eq(memcmp(&read_uuid, &uuid, sizeof(uuid)), 0);
        check_eq(uapi16_file_object_fat_serial(got, &small), 0);
        check_eq(small, 0x1234abcd);
        features = features_without(features, UAPI16_FEATURE_FLAG_IMMUTABLE);
        check_stated(got, features);
        /* The root has none of what only another file object has. */
        number = 77;
        check_eq(uapi16_file_object_size(got, &number), -ENODATA);
        check_eq(uapi16_file_object_sha256(got, &hash), -ENODATA);
        check_eq(uapi16_file_object_inode_token(got, &token), -ENODATA);
        check_eq(uapi16_file_object_major(got, &number), -ENODATA);
        check_eq(uapi16_file_object_minor(got, &number), -ENODATA);
        check_eq(number, 77);
        check_eq(token, 77);
        check_eq(uapi16_file_object_dos_attributes(got, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(uapi16_file_object_data_location(got), UAPI16_DATA_LOCATION_NONE);
        check(!uapi16_file_object_literal(got, NULL));
        /* It belongs to the reader, and is there while the reader reads
         * on. */
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = next_object(reader, "plain");

                check_ends(reader);
                check_str(uapi16_file_object_fs_label(got), "label");
                check_str(uapi16_file_object_name(uapi16_reader_root(reader)), "");
        }
        check(!uapi16_reader_root(NULL));
        check(!e);
}

/*
 * A writer takes the root as the file object with the empty name, in any
 * order with the other file objects, and the record of the root has what
 * that object says: the attributes of the root directory and the identity
 * of its file system. A root is checked as any file object is: one with a
 * field of a feature the manifest does not record is refused, and so is
 * one with what only another file object has. The first root that is added
 * says what the root is like. Without one, the record of the root says
 * nothing.
 */
static void test_root_adds(void) {
        static const char *const only_files_have[] = {
                "size", "sha256", "contents", "contents", "inodeToken", "major", "minor",
                "flagHidden", "flagSystem", "flagArchive",
        };
        /* Roots as only a reader hands them out: with the times the
         * manifest may be used between, revoked, and with the UUID of a
         * disk. The last one is of a manifest that records that UUID. */
        static const struct {
                const char *manifest, *field, *written;
                uapi16_feature_t features[FEATURES_MAX];
        } read_roots[] = {
                { RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\","
                     "\"validSinceUSec\":1000}\n" TRAILER,
                  "validSinceUSec", "\"validSinceUSec\":1000", { DEFAULT_FEATURES } },
                { RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\","
                     "\"validUntilUSec\":2000}\n" TRAILER,
                  "validUntilUSec", "\"validUntilUSec\":2000", { DEFAULT_FEATURES } },
                { RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\","
                     "\"validity\":\"revoked\"}\n" TRAILER,
                  "validity", "\"validity\":\"revoked\"", { DEFAULT_FEATURES } },
                { RS "{\"features\":[\"gpt-disk-uuid\"],"
                     "\"gptDiskUuid\":\"6f1d0a42-9c1e-4b7a-8d33-520c7e11a905\","
                     "\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n" TRAILER,
                  "gptDiskUuid", "\"gptDiskUuid\":\"6f1d0a42-9c1e-4b7a-8d33-520c7e11a905\"",
                  { UAPI16_FEATURE_GPT_DISK_UUID } },
        };
        static const uapi16_feature_t of_the_root[] = { UAPI16_FEATURE_FS_UUID, UAPI16_FEATURE_FAT_SERIAL };
        static const uapi16_uuid_t uuid = { .bytes = { 16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 } };
        _cleanup_(closep) int listed = scratch_file(), narrow_fd = scratch_file(), bare_fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *all =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *narrow =
                uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *none = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *first = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *second = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *unlisted = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *nothing = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("plain");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *below = make_object("dir/below");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uapi16_sha256_digest_t hash;
        uapi16_uuid_t read_uuid;
        uint32_t small = 77, stated = 77, set = 77;
        struct features features;
        uint64_t number = 77;
        size_t count = 77, size = 77;
        const uapi16_file_object *got;
        const char *name = NULL;
        const void *value = NULL;
        int r;

        unhex(SHA256_OF_NOTHING, &hash);
        check_eq(set_features(all, FEATURES_OF_TREES), 0);
        features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_FS_LABEL, UAPI16_FEATURE_FS_UUID);
        check_eq(set_features(narrow, features), 0);

        /* A root with all a root has: the attributes of its directory and
         * the identity of its file system. */
        check_eq(uapi16_file_object_set_mode(root, 0555), 0);
        check_eq(uapi16_file_object_set_uid(root, 1), 0);
        check_eq(uapi16_file_object_set_gid(root, 2), 0);
        check_eq(uapi16_file_object_set_user_name(root, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(root, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(root, 3), 0);
        check_eq(uapi16_file_object_add_user_xattr(root, "k", "v", 1), 0);
        check_eq(uapi16_file_object_set_read_only(root, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_set_inode_flags(root, NODUMP_FL | IMMUTABLE_FL, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_fs_label(root, "label"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(root, &uuid), 0);
        check_eq(uapi16_file_object_set_fat_serial(root, 0x1234abcd), 0);

        /* A writer whose manifest records every feature of a tree takes
         * it, after a file object here. It is no file the report counts
         * but as the directory it is. */
        check_eq(uapi16_manifest_writer_open(all, listed, &w, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, plain, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, root, &e), 0);

        /* A root with what only another file object has is refused for
         * the field, and the writer is as it was. */
        for (size_t i = 0; i < ELEMENTSOF(only_files_have); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("");

                switch (i) {
                case 0:
                        check_eq(uapi16_file_object_set_size(refused, 1), 0);
                        break;
                case 1:
                        check_eq(uapi16_file_object_set_sha256(refused, &hash), 0);
                        break;
                case 2:
                        check_eq(uapi16_file_object_set_target(refused, "target", 6), 0);
                        break;
                case 3:
                        check_eq(uapi16_file_object_set_contents_file(refused, "file", NULL), 0);
                        break;
                case 4:
                        check_eq(uapi16_file_object_set_inode_token(refused, 1), 0);
                        break;
                case 5:
                        check_eq(uapi16_file_object_set_major(refused, 1), 0);
                        break;
                case 6:
                        check_eq(uapi16_file_object_set_minor(refused, 1), 0);
                        break;
                case 7:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_HIDDEN, DOS_HIDDEN), 0);
                        break;
                case 8:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_SYSTEM, 0), 0);
                        break;
                default:
                        check_eq(uapi16_file_object_set_dos_attributes(refused, DOS_ARCHIVE, 0), 0);
                        break;
                }
                r = uapi16_manifest_writer_add_object(w, refused, &e);
                check_refused(r, &e, "fieldNotPermitted", "", only_files_have[i]);
                check_eq(uapi16_manifest_writer_add_object(w, refused, NULL), -EBADMSG);
        }
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(uapi16_manifest_report_directories(report), 1);
        check_eq(uapi16_manifest_report_others(report), 0);
        report = uapi16_manifest_report_free(report);
        w = uapi16_manifest_writer_free(w);

        /* The root of the manifest has every field the object had. The
         * flag the object said was cleared is one the manifest says by its
         * features, as it says the other flags. */
        reader = open_reader(listed);
        check_recorded(reader, FEATURES_OF_TREES);
        got = uapi16_reader_root(reader);
        check_str(uapi16_file_object_name(got), "");
        check_eq(uapi16_file_object_type(got), S_IFDIR);
        check_eq(uapi16_file_object_mode(got, &small), 0);
        check_eq(small, 0555);
        check_eq(uapi16_file_object_uid(got, &small), 0);
        check_eq(small, 1);
        check_eq(uapi16_file_object_gid(got, &small), 0);
        check_eq(small, 2);
        check_str(uapi16_file_object_user_name(got), "user");
        check_str(uapi16_file_object_group_name(got), "group");
        check_eq(uapi16_file_object_mtime_nsec(got, &number), 0);
        check_eq(number, 3);
        check_eq(uapi16_file_object_user_xattrs(got, &count), 0);
        check_eq(count, 1);
        check_eq(uapi16_file_object_user_xattr(got, 0, &name, &value, &size), 0);
        check_str(name, "k");
        check_same(value, size, "v", 1);
        check_eq(uapi16_file_object_read_only(got), UAPI16_READ_ONLY_YES);
        check_eq(uapi16_file_object_inode_flags(got, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, NODUMP_FL);
        check_str(uapi16_file_object_fs_label(got), "label");
        check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), 0);
        check_eq(memcmp(&read_uuid, &uuid, sizeof(uuid)), 0);
        check_eq(uapi16_file_object_fat_serial(got, &small), 0);
        check_eq(small, 0x1234abcd);
        features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID, UAPI16_FEATURE_GID,
                            UAPI16_FEATURE_USER_NAME, UAPI16_FEATURE_GROUP_NAME,
                            UAPI16_FEATURE_MTIME, UAPI16_FEATURE_USER_XATTR,
                            UAPI16_FEATURE_READ_ONLY, UAPI16_FEATURE_FLAG_NO_DUMP,
                            UAPI16_FEATURE_FS_LABEL, UAPI16_FEATURE_FS_UUID,
                            UAPI16_FEATURE_FAT_SERIAL);
        check_stated(got, features);
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = next_object(reader, "plain");

                check_ends(reader);
        }
        reader = uapi16_reader_free(reader);

        /* A manifest that records the access mode, the label and the UUID
         * of the file system, and no volume serial number. A root with one
         * is refused for the field, and adds nothing. */
        check_eq(uapi16_file_object_set_mode(unlisted, 0700), 0);
        check_eq(uapi16_file_object_set_fat_serial(unlisted, 7), 0);
        check_eq(uapi16_manifest_writer_open(narrow, narrow_fd, &w, &e), 0);
        r = uapi16_manifest_writer_add_object(w, unlisted, &e);
        check_refused(r, &e, "unlistedFeature", "", "fatSerial");
        check_eq(uapi16_manifest_writer_add_object(w, unlisted, NULL), -EBADMSG);

        /* A writer of records does not begin with that root either, for
         * the same field of the same file, and writes nothing. */
        r = uapi16_writer_begin(narrow, bare_fd, unlisted, &none, &e);
        check_refused(r, &e, "unlistedFeature", "", "fatSerial");
        check_eq(uapi16_writer_begin(narrow, bare_fd, unlisted, &none, NULL), -EBADMSG);
        check(!none);
        check_eq(size_of(bare_fd), 0);

        /* Added twice, the first root says what the root is like, as the
         * first object of any directory does. */
        check_eq(uapi16_file_object_set_mode(first, 0750), 0);
        check_eq(uapi16_file_object_set_fs_label(first, "first"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(first, &uuid), 0);
        check_eq(uapi16_file_object_set_mode(second, 0755), 0);
        check_eq(uapi16_file_object_set_fs_label(second, "second"), 0);
        check_eq(uapi16_manifest_writer_add_object(w, first, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, plain, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, second, &e), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 1);
        check_eq(uapi16_manifest_report_directories(report), 1);
        report = uapi16_manifest_report_free(report);
        w = uapi16_manifest_writer_free(w);
        reader = open_reader(narrow_fd);
        got = uapi16_reader_root(reader);
        check_eq(uapi16_file_object_mode(got, &small), 0);
        check_eq(small, 0750);
        check_str(uapi16_file_object_fs_label(got), "first");
        check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), 0);
        check_eq(memcmp(&read_uuid, &uuid, sizeof(uuid)), 0);
        small = 77;
        check_eq(uapi16_file_object_fat_serial(got, &small), -ENODATA);
        check_eq(small, 77);
        reader = uapi16_reader_free(reader);

        /* Without a root, the record of the root says nothing, and so it
         * does with a root that says nothing. */
        for (int with_root = 0; with_root < 2; with_root++) {
                empty(bare_fd);
                check_eq(uapi16_manifest_writer_open(o, bare_fd, &w, &e), 0);
                check_eq(uapi16_manifest_writer_add_object(w, below, &e), 0);
                if (with_root)
                        check_eq(uapi16_manifest_writer_add_object(w, nothing, &e), 0);
                check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
                /* The root, and the directory of the file, which the
                 * writer made up. */
                check_eq(uapi16_manifest_report_directories(report), 2);
                report = uapi16_manifest_report_free(report);
                w = uapi16_manifest_writer_free(w);
                reader = open_reader(bare_fd);
                got = uapi16_reader_root(reader);
                check_stated(got, FEATURES(UAPI16_FEATURE_NONE));
                small = 77;
                check_eq(uapi16_file_object_mode(got, &small), -ENODATA);
                check(!uapi16_file_object_fs_label(got));
                check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), -ENODATA);
                check_eq(uapi16_file_object_fat_serial(got, &small), -ENODATA);
                check_eq(small, 77);
                reader = uapi16_reader_free(reader);
        }

        /* The UUID and the volume serial number of the file system are
         * what the root has, where its file system has one. Without the
         * root, and with a root that says nothing of it, the manifest says
         * nothing of it, and with one that has it, the manifest has it. */
        for (size_t i = 0; i < ELEMENTSOF(of_the_root); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *with = make_object("");

                r = set_features(o, FEATURES(DEFAULT_FEATURES, of_the_root[i]));
                check_eq(r, 0);
                if (of_the_root[i] == UAPI16_FEATURE_FS_UUID)
                        check_eq(uapi16_file_object_set_fs_uuid(with, &uuid), 0);
                else
                        check_eq(uapi16_file_object_set_fat_serial(with, 0xfeedf00d), 0);
                for (int has_it = -1; has_it < 2; has_it++) {
                        empty(bare_fd);
                        check_eq(uapi16_manifest_writer_open(o, bare_fd, &w, &e), 0);
                        check_eq(uapi16_manifest_writer_add_object(w, plain, &e), 0);
                        /* No root at all, one without it, and one with it.
                         * None of them counts as a field that was left out:
                         * only a walk leaves one out. */
                        if (has_it >= 0)
                                check_eq(uapi16_manifest_writer_add_object(w, has_it ? with : nothing, &e), 0);
                        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
                        check_eq(uapi16_manifest_report_fields_omitted(report), 0);
                        report = uapi16_manifest_report_free(report);
                        w = uapi16_manifest_writer_free(w);
                        reader = open_reader(bare_fd);
                        check_recorded(reader, FEATURES(DEFAULT_FEATURES, of_the_root[i]));
                        got = uapi16_reader_root(reader);
                        small = 77;
                        if (has_it <= 0) {
                                check_stated(got, FEATURES(UAPI16_FEATURE_NONE));
                                check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), -ENODATA);
                                check_eq(uapi16_file_object_fat_serial(got, &small), -ENODATA);
                                check_eq(small, 77);
                        } else if (of_the_root[i] == UAPI16_FEATURE_FS_UUID) {
                                check_stated(got, FEATURES(of_the_root[i]));
                                check_eq(uapi16_file_object_fs_uuid(got, &read_uuid), 0);
                                check_eq(memcmp(&read_uuid, &uuid, sizeof(uuid)), 0);
                        } else {
                                check_stated(got, FEATURES(of_the_root[i]));
                                check_eq(uapi16_file_object_fat_serial(got, &small), 0);
                                check_eq(small, 0xfeedf00d);
                        }
                        reader = uapi16_reader_free(reader);
                }
        }
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES)), 0);

        /* A root that a reader read can say what no setter sets: when its
         * manifest may be used, and the UUID of a disk. The manifest of a
         * tree says neither, so a writer refuses such a root for the
         * field. A writer of records takes it, and writes the field. */
        for (size_t i = 0; i < ELEMENTSOF(read_roots); i++) {
                _cleanup_(closep) int from = manifest_file(read_roots[i].manifest), to = scratch_file();
                _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *recording =
                        uapi16_manifest_options_new();
                _cleanup_(uapi16_reader_freep) uapi16_reader *source = open_reader(from);
                _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL;
                _cleanup_(freep) char *text = NULL;
                size_t text_size;

                check_eq(set_features(recording, features_of(read_roots[i].features,
                                                             ELEMENTSOF(read_roots[i].features))),
                         0);
                got = uapi16_reader_root(source);
                check(got);
                w = open_writer(o);
                r = uapi16_manifest_writer_add_object(w, got, &e);
                check_refused(r, &e, "fieldNotPermitted", "", read_roots[i].field);
                check_listed(w, 0, 1, 0);
                w = uapi16_manifest_writer_free(w);

                check_eq(uapi16_writer_begin(recording, to, got, &records, &e), 0);
                check_eq(uapi16_writer_finish(records, &e), 0);
                records = uapi16_writer_free(records);
                text = read_all(to, &text_size);
                check_manifest(text, text_size);
                check(strstr(text, read_roots[i].written));
        }
        check(!e);
}

/*
 * A writer takes the file objects of a caller in any order and lists them
 * in the order of the manifest, with the directories that were not added.
 * It keeps a copy of each. The names of one file carry one token of the
 * caller, and the manifest numbers the files itself. What a reader reads
 * back is what the objects said, field by field.
 */
static void test_added_objects(void) {
        const struct features features = FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME,
                                                  UAPI16_FEATURE_USER_NAME,
                                                  UAPI16_FEATURE_GROUP_NAME);
        /* Those of them that a regular file has fields of: all but the
         * targets of symbolic links and the numbers of device nodes. */
        const struct features of_a_regular_file = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID,
                                                           UAPI16_FEATURE_GID, UAPI16_FEATURE_SIZE,
                                                           UAPI16_FEATURE_SHA256,
                                                           UAPI16_FEATURE_HARDLINK,
                                                           UAPI16_FEATURE_MTIME,
                                                           UAPI16_FEATURE_USER_NAME,
                                                           UAPI16_FEATURE_GROUP_NAME);
        static const uint64_t mtime = UINT64_C(1700000000123456789);
        _cleanup_(closep) int fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *tool = make_hello("usr/bin/tool");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *alias = make_object("usr/bin/alias");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *bin = make_object("usr/bin");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *usr = make_object("usr");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *null = make_object("dev/null");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *fifo = make_object("run/fifo");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *second = make_object("z-second");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *wrong = make_hello("wrong");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *unlisted = make_object("unlisted");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *listed = NULL;
        size_t listed_size;
        int r;

        check_eq(set_features(o, features), 0);
        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);

        /* A regular file with what a manifest says of one, whose data is
         * in a file of another name. It is added first, and its directory
         * after it. */
        check_eq(uapi16_file_object_set_mode(tool, 0755), 0);
        check_eq(uapi16_file_object_set_uid(tool, 0), 0);
        check_eq(uapi16_file_object_set_gid(tool, 12), 0);
        check_eq(uapi16_file_object_set_user_name(tool, "root"), 0);
        check_eq(uapi16_file_object_set_group_name(tool, "staff"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(tool, mtime), 0);
        check_eq(uapi16_file_object_set_contents_file(tool, "blobs/2cf24dba", &e), 0);
        check_eq(uapi16_file_object_set_inode_token(tool, 700), 0);
        check_eq(uapi16_manifest_writer_add_object(w, tool, &e), 0);

        /* A file with the token of another one that says something else
         * of it is no name of that file. The error names the first name of
         * the token, and the writer is as it was. */
        check_eq(uapi16_file_object_set_inode_token(wrong, 700), 0);
        r = uapi16_manifest_writer_add_object(w, wrong, &e);
        check_error(r, e, UAPI16_ERROR_HARDLINK_MISMATCH, ESTALE, "wrong", CHECK_HARDLINK_PATH);
        check_str(uapi16_error_hardlink_path(e), "usr/bin/tool");
        e = uapi16_error_free(e);
        check_eq(uapi16_manifest_writer_add_object(w, wrong, NULL), -ESTALE);

        /* Another file with two names, which come in the other order. */
        check_eq(uapi16_file_object_set_size(second, 3), 0);
        check_eq(uapi16_file_object_set_inode_token(second, 9), 0);
        check_eq(uapi16_manifest_writer_add_object(w, second, &e), 0);

        /* A symbolic link, a device node and a FIFO. */
        check_eq(uapi16_file_object_set_type(alias, S_IFLNK), 0);
        check_eq(uapi16_file_object_set_target(alias, "tool", 4), 0);
        check_eq(uapi16_file_object_set_size(alias, 4), 0);
        check_eq(uapi16_manifest_writer_add_object(w, alias, &e), 0);
        check_eq(uapi16_file_object_set_type(null, S_IFCHR), 0);
        check_eq(uapi16_file_object_set_mode(null, 0666), 0);
        check_eq(uapi16_file_object_set_major(null, 1), 0);
        check_eq(uapi16_file_object_set_minor(null, 3), 0);
        check_eq(uapi16_manifest_writer_add_object(w, null, &e), 0);
        check_eq(uapi16_file_object_set_type(fifo, S_IFIFO), 0);
        check_eq(uapi16_file_object_set_mode(fifo, 0600), 0);
        check_eq(uapi16_manifest_writer_add_object(w, fifo, &e), 0);

        /* The second name of the first file is the same object under the
         * next name. The writer has a copy of what it was given: the
         * object changes after that, and is freed. */
        check_eq(uapi16_file_object_set_name(tool, "usr/libexec/tool", &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, tool, &e), 0);
        check_eq(uapi16_file_object_set_name(tool, "changed", &e), 0);
        check_eq(uapi16_file_object_set_mode(tool, 0600), 0);
        check_eq(uapi16_file_object_set_size(tool, 6), 0);
        tool = uapi16_file_object_free(tool);

        /* An object that is refused is not added: one with a field of a
         * feature the manifest does not record. */
        check_eq(uapi16_file_object_set_read_only(unlisted, UAPI16_READ_ONLY_NO), 0);
        r = uapi16_manifest_writer_add_object(w, unlisted, &e);
        check_refused(r, &e, "unlistedFeature", "unlisted", "readOnly");
        check_eq(uapi16_manifest_writer_add_object(w, unlisted, NULL), -EBADMSG);

        /* Directories, after what is in them. An object that is equal to
         * one that was added is no other object, and the first object of a
         * directory says what the directory is like. */
        check_eq(uapi16_file_object_set_type(usr, S_IFDIR), 0);
        check_eq(uapi16_file_object_set_mode(usr, 0755), 0);
        check_eq(uapi16_manifest_writer_add_object(w, usr, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, usr, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, null, &e), 0);
        check_eq(uapi16_file_object_set_type(bin, S_IFDIR), 0);
        check_eq(uapi16_file_object_set_mode(bin, 0751), 0);
        check_eq(uapi16_manifest_writer_add_object(w, bin, &e), 0);
        check_eq(uapi16_file_object_set_mode(bin, 0700), 0);
        check_eq(uapi16_manifest_writer_add_object(w, bin, &e), 0);

        /* The first name of the second file comes last. */
        check_eq(uapi16_file_object_set_name(second, "b-first", &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, second, &e), 0);
        check(!e);

        /* Nothing is written before the writer finishes. Its report counts
         * every object, the directories that were not added among them:
         * the root, dev, run and usr/libexec. */
        check_eq(size_of(fd), 0);
        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 4);
        check_eq(uapi16_manifest_report_directories(report), 6);
        check_eq(uapi16_manifest_report_others(report), 3);
        check_eq(uapi16_manifest_report_bytes(report), 16);
        w = uapi16_manifest_writer_free(w);
        listed = read_all(fd, &listed_size);
        check_manifest(listed, listed_size);
        check(strstr(listed, "\"file\":\"blobs/2cf24dba\""));
        check(!strstr(listed, "wrong") && !strstr(listed, "unlisted") && !strstr(listed, "changed"));

        /* A reader reads back what the objects said. The root says
         * nothing, as no object was added for it. */
        reader = open_reader(fd);
        check_recorded(reader, features);
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e), 0);
        check_stated(uapi16_reader_root(reader), FEATURES(UAPI16_FEATURE_NONE));
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = next_object(reader, "b-first");
                uapi16_inode_token_t token = 0;
                uint64_t size = 0;

                /* The file that comes first in the manifest is its first
                 * file with more than one name. */
                check_eq(uapi16_file_object_type(got), S_IFREG);
                check_eq(uapi16_file_object_size(got, &size), 0);
                check_eq(size, 3);
                check_eq(uapi16_file_object_inode_token(got, &token), 0);
                check_eq(token, 1);
                check_stated(got, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_HARDLINK));
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = next_object(reader, "dev");
                uint32_t mode = 77;

                /* A directory that was not added says nothing but that it
                 * is one. */
                check_eq(uapi16_file_object_type(got), S_IFDIR);
                check_eq(uapi16_file_object_mode(got, &mode), -ENODATA);
                check_eq(mode, 77);
                check_stated(got, FEATURES(UAPI16_FEATURE_NONE));
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got =
                        next_object(reader, "dev/null");
                uint64_t major = 0, minor = 0, size = 77;
                uint32_t mode = 0;

                check_eq(uapi16_file_object_type(got), S_IFCHR);
                check_eq(uapi16_file_object_mode(got, &mode), 0);
                check_eq(mode, 0666);
                check_eq(uapi16_file_object_major(got, &major), 0);
                check_eq(major, 1);
                check_eq(uapi16_file_object_minor(got, &minor), 0);
                check_eq(minor, 3);
                check_eq(uapi16_file_object_size(got, &size), -ENODATA);
                check_eq(uapi16_file_object_data_location(got), UAPI16_DATA_LOCATION_NONE);
                check_stated(got, FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_DEVICE));
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *run = next_object(reader, "run");
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got =
                        next_object(reader, "run/fifo");
                uint32_t mode = 0;

                check_eq(uapi16_file_object_type(run), S_IFDIR);
                check_eq(uapi16_file_object_type(got), S_IFIFO);
                check_eq(uapi16_file_object_mode(got, &mode), 0);
                check_eq(mode, 0600);
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = next_object(reader, "usr");
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *first =
                        next_object(reader, "usr/bin");
                uint32_t mode = 0;

                /* The directory that was added twice is what its first
                 * object said. */
                check_eq(uapi16_file_object_type(got), S_IFDIR);
                check_eq(uapi16_file_object_mode(got, &mode), 0);
                check_eq(mode, 0755);
                check_eq(uapi16_file_object_type(first), S_IFDIR);
                check_eq(uapi16_file_object_mode(first, &mode), 0);
                check_eq(mode, 0751);
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got =
                        next_object(reader, "usr/bin/alias");
                uint64_t size = 0;
                uint32_t mode = 77;
                size_t target_size = 0;
                const void *target;

                check_eq(uapi16_file_object_type(got), S_IFLNK);
                target = uapi16_file_object_literal(got, &target_size);
                check_same(target, target_size, "tool", 4);
                check_eq(uapi16_file_object_data_location(got), UAPI16_DATA_LOCATION_LITERAL);
                check_eq(uapi16_file_object_size(got, &size), 0);
                check_eq(size, 4);
                check_eq(uapi16_file_object_mode(got, &mode), -ENODATA);
                check_stated(got, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SYMLINK));
        }
        for (size_t i = 0; i < 2; i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = NULL, *got = NULL;
                uapi16_sha256_digest_t hash;
                uapi16_inode_token_t token = 0;
                uint64_t size = 0, time = 0;
                uint32_t mode = 0, uid = 77, gid = 0;

                /* The two names of the first file say the same, as they
                 * were added: with what the object said then, and with the
                 * number the manifest gave the file. */
                if (i == 1)
                        plain = next_object(reader, "usr/libexec");
                got = next_object(reader, i == 0 ? "usr/bin/tool" : "usr/libexec/tool");
                check_eq(uapi16_file_object_type(got), S_IFREG);
                check_eq(uapi16_file_object_mode(got, &mode), 0);
                check_eq(mode, 0755);
                check_eq(uapi16_file_object_uid(got, &uid), 0);
                check_eq(uid, 0);
                check_eq(uapi16_file_object_gid(got, &gid), 0);
                check_eq(gid, 12);
                check_str(uapi16_file_object_user_name(got), "root");
                check_str(uapi16_file_object_group_name(got), "staff");
                check_eq(uapi16_file_object_mtime_nsec(got, &time), 0);
                check_eq(time, mtime);
                check_eq(uapi16_file_object_size(got, &size), 0);
                check_eq(size, 5);
                check_eq(uapi16_file_object_sha256(got, &hash), 0);
                check_hash(&hash, SHA256_OF_HELLO);
                check_eq(uapi16_file_object_inode_token(got, &token), 0);
                check_eq(token, 2);
                check_eq(uapi16_file_object_data_location(got), UAPI16_DATA_LOCATION_EXTERNAL);
                check(!uapi16_file_object_literal(got, NULL));
                check_stated(got, of_a_regular_file);
        }
        {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *got =
                        next_object(reader, "z-second");
                uapi16_inode_token_t token = 0;

                check_eq(uapi16_file_object_inode_token(got, &token), 0);
                check_eq(token, 1);
        }
        check_ends(reader);
        check(!e);
}

/*
 * An object that a writer refuses leaves the writer as it was: what it
 * writes then is what a writer writes that was never given the object.
 */
static void test_refused_objects(void) {
        const struct features without_modes = FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256,
                                                       UAPI16_FEATURE_HARDLINK,
                                                       UAPI16_FEATURE_SYMLINK);
        _cleanup_(closep) int fd = scratch_file(), clean = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL, *never = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *kept = make_hello("kept");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *linked = make_hello("linked");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("refused");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *written = NULL, *expected = NULL;
        size_t written_size, expected_size;
        uint64_t record = 77;
        int r;

        /* A manifest that records sizes and hashes, hard links and the
         * targets of symbolic links, and no access modes. */
        check_eq(set_features(o, without_modes), 0);
        check_eq(uapi16_manifest_writer_open(o, fd, &w, &e), 0);
        check_eq(uapi16_manifest_writer_open(o, clean, &never, &e), 0);
        check_eq(uapi16_file_object_set_inode_token(linked, 5), 0);
        check_eq(uapi16_manifest_writer_add_object(w, kept, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(w, linked, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(never, kept, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(never, linked, &e), 0);

        /* A mode, which the manifest does not record. */
        check_eq(uapi16_file_object_set_mode(refused, 0644), 0);
        r = uapi16_manifest_writer_add_object(w, refused, &e);
        check_eq(uapi16_error_record(e, &record), -ENODATA);
        check_refused(r, &e, "unlistedFeature", "refused", "mode");

        /* A symbolic link without its target, which the manifest
         * records. */
        refused = uapi16_file_object_free(refused);
        refused = make_object("refused");
        check_eq(uapi16_file_object_set_type(refused, S_IFLNK), 0);
        r = uapi16_manifest_writer_add_object(w, refused, &e);
        check_refused(r, &e, "noTarget", "refused", NULL);

        /* A size on a FIFO, which has no data. */
        check_eq(uapi16_file_object_set_type(refused, S_IFIFO), 0);
        check_eq(uapi16_file_object_set_size(refused, 1), 0);
        r = uapi16_manifest_writer_add_object(w, refused, &e);
        check_refused(r, &e, "fieldNotPermitted", "refused", "size");

        /* A name of the file of a token that does not say what its first
         * name said, and so is no name of it. */
        check_eq(uapi16_file_object_set_name(linked, "refused", &e), 0);
        check_eq(uapi16_file_object_set_size(linked, 6), 0);
        r = uapi16_manifest_writer_add_object(w, linked, &e);
        check_error(r, e, UAPI16_ERROR_HARDLINK_MISMATCH, ESTALE, "refused", CHECK_HARDLINK_PATH);
        check_str(uapi16_error_hardlink_path(e), "linked");
        e = uapi16_error_free(e);

        check_eq(uapi16_manifest_writer_finish(w, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 2);
        check_eq(uapi16_manifest_report_others(report), 0);
        check_eq(uapi16_manifest_writer_finish(never, NULL, &e), 0);
        w = uapi16_manifest_writer_free(w);
        never = uapi16_manifest_writer_free(never);
        written = read_all(fd, &written_size);
        expected = read_all(clean, &expected_size);
        check_manifest(written, written_size);
        check_same(written, written_size, expected, expected_size);
        check(!strstr(written, "refused"));
        check(!e);
}

/*
 * The writer of records begins a manifest with the features and the order
 * of its options, and writes every record before its call returns. It
 * refuses a file object that is not where the manifest has it, and goes
 * on. It takes no file object after a signature object, and nothing once
 * it is finished. What it writes is byte for byte what a writer writes for
 * the same objects, and a reader reads it.
 */
static void test_records(void) {
        static const int no_descriptors[] = { -1, AT_FDCWD, INT_MIN };
        static const char data[] = { 's', 0, (char) 0xff, 'g' };
        _cleanup_(closep) int written = scratch_file(), listed = scratch_file(), unfinished = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *listing = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *a = make_object("a");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("a/file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *x = make_object("a/x");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *b = make_object("a-b");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *m = make_object("m");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *refused = make_object("zz/x");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *openpgp = NULL, *pkcs7 = NULL, *signature = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *records = NULL, *expected = NULL;
        size_t records_size, expected_size, before, signed_size, size = 0;
        uapi16_sha256_digest_t hash;
        uapi16_inode_token_t token = 0;
        uint64_t number = 0;
        const void *bytes;
        int r;

        check_eq(uapi16_file_object_set_type(a, S_IFDIR), 0);
        check_eq(uapi16_file_object_set_mode(a, 0755), 0);
        check_eq(uapi16_file_object_set_mode(file, 0644), 0);
        check_eq(uapi16_file_object_set_uid(file, 1), 0);
        check_eq(uapi16_file_object_set_gid(file, 2), 0);
        check_eq(uapi16_file_object_set_type(x, S_IFLNK), 0);
        check_eq(uapi16_file_object_set_target(x, "file", 4), 0);
        check_eq(uapi16_file_object_set_size(b, 0), 0);
        check_eq(uapi16_signature_new("openpgp", &openpgp), 0);
        check_eq(uapi16_signature_set_key(openpgp, "\x01\xab", 2), 0);
        check_eq(uapi16_signature_set_data(openpgp, data, sizeof(data)), 0);
        check_eq(uapi16_signature_new("pkcs7", &pkcs7), 0);

        /* A writer of records needs options, a descriptor and a place to
         * go to, and no call that is not valid writes anything. */
        check_misuse(uapi16_writer_begin(NULL, written, NULL, &none, &e), &e, EINVAL);
        check_misuse(uapi16_writer_begin(o, written, NULL, NULL, &e), &e, EINVAL);
        check_eq(uapi16_writer_begin(NULL, written, NULL, &none, NULL), -EINVAL);
        check_eq(uapi16_writer_begin(o, written, NULL, NULL, NULL), -EINVAL);
        for (size_t i = 0; i < ELEMENTSOF(no_descriptors); i++)
                check_misuse(uapi16_writer_begin(o, no_descriptors[i], NULL, &none, &e), &e, EBADF);
        check(!none);
        check_eq(size_of(written), 0);
        check(!uapi16_writer_free(NULL));

        /* It begins with the root, which says nothing here but what the
         * options say: the features and the order. */
        check_eq(uapi16_writer_begin(o, written, NULL, &w, &e), 0);
        check(w && !e);
        before = size_of(written);
        check(before > 0);
        check_misuse(uapi16_writer_file(NULL, a, &e), &e, EINVAL);
        check_misuse(uapi16_writer_file(w, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_signature(NULL, openpgp, &e), &e, EINVAL);
        check_misuse(uapi16_writer_signature(w, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_finish(NULL, &e), &e, EINVAL);
        check_eq(uapi16_writer_file(NULL, a, NULL), -EINVAL);
        check_eq(uapi16_writer_file(w, NULL, NULL), -EINVAL);
        check_eq(uapi16_writer_signature(NULL, openpgp, NULL), -EINVAL);
        check_eq(uapi16_writer_signature(w, NULL, NULL), -EINVAL);
        check_eq(uapi16_writer_finish(NULL, NULL), -EINVAL);
        check_eq(size_of(written), before);

        /* A file object whose directory was not written is not where the
         * manifest has it. It is not written, and the writer goes on. */
        r = uapi16_writer_file(w, file, &e);
        check_refused(r, &e, "misplaced", "a/file", NULL);
        check_eq(uapi16_writer_file(w, file, NULL), -EBADMSG);
        check_eq(size_of(written), before);

        /* The file objects in the order of the manifest: a directory, what
         * is in it, and what comes after it. The two names of one file
         * carry the number of the file, which the caller gives it. Every
         * record is written before its call returns. */
        check_eq(uapi16_writer_file(w, a, &e), 0);
        check(size_of(written) > before);
        before = size_of(written);
        check_eq(uapi16_file_object_set_inode_token(file, 1), 0);
        check_eq(uapi16_writer_file(w, file, &e), 0);
        check(size_of(written) > before);
        check_eq(uapi16_writer_file(w, x, &e), 0);
        check_eq(uapi16_writer_file(w, b, &e), 0);
        check_eq(uapi16_file_object_set_name(file, "link", &e), 0);
        check_eq(uapi16_writer_file(w, file, &e), 0);
        before = size_of(written);

        /* What is refused, each for its rule: a file in a directory that
         * is not there, one in a directory whose files have ended, one
         * that comes before the last one, and one with a field of a
         * feature the manifest does not record. */
        r = uapi16_writer_file(w, refused, &e);
        check_refused(r, &e, "misplaced", "zz/x", NULL);
        check_eq(uapi16_file_object_set_name(refused, "a/late", &e), 0);
        r = uapi16_writer_file(w, refused, &e);
        check_refused(r, &e, "misplaced", "a/late", NULL);
        check_eq(uapi16_file_object_set_name(refused, "b", &e), 0);
        r = uapi16_writer_file(w, refused, &e);
        check_refused(r, &e, "outOfOrder", "b", NULL);
        check_eq(uapi16_file_object_set_name(refused, "unlisted", &e), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(refused, 1), 0);
        r = uapi16_writer_file(w, refused, &e);
        check_refused(r, &e, "unlistedFeature", "unlisted", "mTimeNSec");
        check_eq(size_of(written), before);
        check_eq(uapi16_writer_file(w, m, &e), 0);
        check(size_of(written) > before);

        /* A signature object signs what was written before the first of
         * them. No file object can follow one, and another signature
         * object can. */
        signed_size = size_of(written);
        check_eq(uapi16_writer_signature(w, openpgp, &e), 0);
        before = size_of(written);
        check(before > signed_size);
        check_eq(uapi16_file_object_set_name(m, "n", &e), 0);
        r = uapi16_writer_file(w, m, &e);
        check_refused(r, &e, "fileAfterSignature", "n", NULL);
        check_eq(size_of(written), before);
        check_eq(uapi16_writer_signature(w, pkcs7, &e), 0);
        check(size_of(written) > before);
        before = size_of(written);

        /* The trailer ends the manifest, and the writer takes nothing
         * more. A call that is not valid fails for that still. */
        check_eq(uapi16_writer_finish(w, &e), 0);
        check_eq(size_of(written), before + strlen(TRAILER));
        check_ended(uapi16_writer_file(w, m, &e), &e);
        check_ended(uapi16_writer_signature(w, pkcs7, &e), &e);
        check_ended(uapi16_writer_finish(w, &e), &e);
        check_eq(uapi16_writer_file(w, m, NULL), -ESTALE);
        check_eq(uapi16_writer_signature(w, pkcs7, NULL), -ESTALE);
        check_eq(uapi16_writer_finish(w, NULL), -ESTALE);
        check_misuse(uapi16_writer_file(w, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_writer_signature(w, NULL, &e), &e, EINVAL);
        check_eq(size_of(written), before + strlen(TRAILER));
        w = uapi16_writer_free(w);
        check(!w);
        records = read_all(written, &records_size);
        check_manifest(records, records_size);

        /* A writer that is given the same file objects in another order,
         * with a number of the caller for the file with two names, writes
         * the same records. */
        check_eq(uapi16_manifest_writer_open(o, listed, &listing, &e), 0);
        check_eq(uapi16_file_object_set_name(m, "m", &e), 0);
        check_eq(uapi16_file_object_set_inode_token(file, 42), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, m, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, file, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, b, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, x, &e), 0);
        check_eq(uapi16_file_object_set_name(file, "a/file", &e), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, file, &e), 0);
        check_eq(uapi16_manifest_writer_add_object(listing, a, &e), 0);
        check_eq(uapi16_manifest_writer_finish(listing, NULL, &e), 0);
        listing = uapi16_manifest_writer_free(listing);
        expected = read_all(listed, &expected_size);
        check_eq(expected_size, signed_size + strlen(TRAILER));
        check_eq(memcmp(records, expected, signed_size), 0);
        check_manifest(expected, expected_size);

        /* A reader reads the file objects, and then the signature objects
         * with what they sign: all that was written before the first of
         * them. */
        reader = open_reader(written);
        check_recorded(reader, FEATURES(DEFAULT_FEATURES));
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);
        got = next_object(reader, "a");
        got = uapi16_file_object_free(got);
        got = next_object(reader, "a/file");
        check_eq(uapi16_file_object_inode_token(got, &token), 0);
        check_eq(token, 1);
        got = uapi16_file_object_free(got);
        /* The size of a symbolic link follows from its target, and the
         * hash of no data from the size 0. A reader fills them in, and they
         * are none of the fields of the object. */
        got = next_object(reader, "a/x");
        check_eq(uapi16_file_object_size(got, &number), 0);
        check_eq(number, 4);
        check_stated(got, FEATURES(UAPI16_FEATURE_SYMLINK));
        got = uapi16_file_object_free(got);
        got = next_object(reader, "a-b");
        check_eq(uapi16_file_object_sha256(got, &hash), 0);
        check_hash(&hash, SHA256_OF_NOTHING);
        check_stated(got, FEATURES(UAPI16_FEATURE_SIZE));
        got = uapi16_file_object_free(got);
        got = next_object(reader, "link");
        token = 0;
        check_eq(uapi16_file_object_inode_token(got, &token), 0);
        check_eq(token, 1);
        got = uapi16_file_object_free(got);
        got = next_object(reader, "m");
        got = uapi16_file_object_free(got);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_signed_len(reader, &number), 0);
        check_eq(number, signed_size);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        bytes = uapi16_signature_key(signature, &size);
        check_same(bytes, size, "\x01\xab", 2);
        bytes = uapi16_signature_data(signature, &size);
        check_same(bytes, size, data, sizeof(data));
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "pkcs7");
        check(!uapi16_signature_key(signature, &size));
        check(!uapi16_signature_data(signature, &size));
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);

        /* A writer of records that is freed before it finished leaves no
         * trailer, and a reader takes what it wrote as incomplete. */
        check_eq(uapi16_writer_begin(o, unfinished, NULL, &w, &e), 0);
        check_eq(uapi16_writer_file(w, a, &e), 0);
        w = uapi16_writer_free(w);
        reader = open_reader(unfinished);
        got = next_object(reader, "a");
        got = uapi16_file_object_free(got);
        r = uapi16_reader_next(reader, &got, &e);
        check_refused(r, &e, "noTrailer", NULL, NULL);
        check(!e);
}

/*
 * The fields of the features that say something of a file by not being
 * there: whether it is read-only, its extended attributes, its inode flags
 * and its DOS attributes. A writer of records writes them, and what a
 * reader hands out has them, also where the record left them out because
 * the features of the manifest say them.
 */
static void test_record_fields(void) {
        _cleanup_(closep) int written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *d = make_object("d");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *f = make_hello("d/f");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("plain");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        static const char binary[] = { 0, (char) 0xfe, 'x' };
        uapi16_sha256_digest_t hash;
        uint32_t stated = 77, set = 77, mode = 0;
        struct features features;
        uint64_t size = 0;
        size_t count = 77, value_size = 77;
        const char *name = NULL;
        const void *value = NULL;

        check_eq(set_features(o, FEATURES_OF_TREES), 0);

        /* A directory that is not read-only, with extended attributes, an
         * inode flag that is set and one that is not, and DOS attributes
         * the same way. */
        check_eq(uapi16_file_object_set_type(d, S_IFDIR), 0);
        check_eq(uapi16_file_object_set_mode(d, 0755), 0);
        check_eq(uapi16_file_object_set_read_only(d, UAPI16_READ_ONLY_NO), 0);
        check_eq(uapi16_file_object_add_user_xattr(d, "text", "a value", 7), 0);
        check_eq(uapi16_file_object_add_user_xattr(d, "binary", binary, sizeof(binary)), 0);
        check_eq(uapi16_file_object_add_user_xattr(d, "empty", NULL, 0), 0);
        check_eq(uapi16_file_object_set_inode_flags(d, NODUMP_FL | APPEND_FL, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_dos_attributes(d, DOS_HIDDEN | DOS_ARCHIVE, DOS_HIDDEN), 0);

        /* A regular file that is read-only and lists no extended
         * attributes. */
        check_eq(uapi16_file_object_set_mode(f, 0444), 0);
        check_eq(uapi16_file_object_set_read_only(f, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_set_user_xattrs(f), 0);

        w = begin_records(o, written);
        check_eq(uapi16_writer_file(w, d, &e), 0);
        check_eq(uapi16_writer_file(w, f, &e), 0);
        check_eq(uapi16_writer_file(w, plain, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);

        reader = open_reader(written);
        check_recorded(reader, FEATURES_OF_TREES);
        /* The root said nothing. The manifest says by its features that
         * it is not read-only, has no extended attributes and none of the
         * flags, which is none of its fields. */
        check_eq(uapi16_file_object_read_only(uapi16_reader_root(reader)), UAPI16_READ_ONLY_NO);
        check_eq(uapi16_file_object_user_xattrs(uapi16_reader_root(reader), &count), 0);
        check_eq(count, 0);
        check_eq(uapi16_file_object_inode_flags(uapi16_reader_root(reader), &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, 0);
        check_stated(uapi16_reader_root(reader), FEATURES(UAPI16_FEATURE_NONE));

        got = next_object(reader, "d");
        check_eq(uapi16_file_object_read_only(got), UAPI16_READ_ONLY_NO);
        check_eq(uapi16_file_object_user_xattrs(got, &count), 0);
        check_eq(count, 3);
        check_eq(uapi16_file_object_user_xattr(got, 0, &name, &value, &value_size), 0);
        check_str(name, "binary");
        check_same(value, value_size, binary, sizeof(binary));
        check_eq(uapi16_file_object_user_xattr(got, 1, &name, &value, &value_size), 0);
        check_str(name, "empty");
        check_eq(value_size, 0);
        check_eq(uapi16_file_object_user_xattr(got, 2, &name, &value, &value_size), 0);
        check_str(name, "text");
        check_same(value, value_size, "a value", 7);
        check_eq(uapi16_file_object_inode_flags(got, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, NODUMP_FL);
        check_eq(uapi16_file_object_dos_attributes(got, &stated, &set), 0);
        check_eq(stated, DOS_ATTRIBUTES);
        check_eq(set, DOS_HIDDEN);
        /* Of these it has the fields that its record has: the flags that
         * are set, and the extended attributes. */
        features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_USER_XATTR,
                            UAPI16_FEATURE_FLAG_NO_DUMP, UAPI16_FEATURE_FLAG_HIDDEN);
        check_stated(got, features);
        got = uapi16_file_object_free(got);

        got = next_object(reader, "d/f");
        check_eq(uapi16_file_object_mode(got, &mode), 0);
        check_eq(mode, 0444);
        check_eq(uapi16_file_object_read_only(got), UAPI16_READ_ONLY_YES);
        check_eq(uapi16_file_object_user_xattrs(got, &count), 0);
        check_eq(count, 0);
        check_eq(uapi16_file_object_inode_flags(got, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, 0);
        check_eq(uapi16_file_object_dos_attributes(got, &stated, &set), 0);
        check_eq(stated, DOS_ATTRIBUTES);
        check_eq(set, 0);
        check_eq(uapi16_file_object_size(got, &size), 0);
        check_eq(size, 5);
        check_eq(uapi16_file_object_sha256(got, &hash), 0);
        check_hash(&hash, SHA256_OF_HELLO);
        features = FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256,
                            UAPI16_FEATURE_READ_ONLY);
        check_stated(got, features);
        got = uapi16_file_object_free(got);

        /* The file that said nothing has what the features say, and no
         * field of them. */
        got = next_object(reader, "plain");
        check_eq(uapi16_file_object_read_only(got), UAPI16_READ_ONLY_NO);
        check_eq(uapi16_file_object_user_xattrs(got, &count), 0);
        check_eq(count, 0);
        check_eq(uapi16_file_object_inode_flags(got, &stated, &set), 0);
        check_eq(stated, INODE_FLAGS);
        check_eq(set, 0);
        check_eq(uapi16_file_object_dos_attributes(got, &stated, &set), 0);
        check_eq(stated, DOS_ATTRIBUTES);
        check_eq(set, 0);
        check_stated(got, FEATURES(UAPI16_FEATURE_NONE));
        check_ends(reader);
        check(!e);
}

/*
 * What a reader hands out, a writer of records writes back: the root and
 * every file object of the manifest of a tree, to the same bytes. What the
 * reader filled in for the features of the manifest is left out again.
 */
static void test_copies(void) {
        const struct features features = FEATURES(DEFAULT_FEATURES, UAPI16_FEATURE_MTIME,
                                                  UAPI16_FEATURE_READ_ONLY,
                                                  UAPI16_FEATURE_USER_NAME,
                                                  UAPI16_FEATURE_GROUP_NAME);
        _cleanup_(closep) int tree = make_tree("copies"), original = scratch_file(), copy = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *generated = NULL, *copied = NULL;
        size_t generated_size, copied_size, files = 0;
        bool read_only = false;

        /* A tree with a file that is read-only, which its record says, and
         * files that are not, which the features say. */
        check_eq(fchmodat(tree, "a/file", 0444, 0), 0);
        check_eq(set_features(o, features), 0);
        check_eq(uapi16_manifest_generate(o, original, tree, UAPI16_ADD_NONE, NULL, &e), 0);

        reader = open_reader(original);
        check_recorded(reader, features);
        check_eq(uapi16_writer_begin(o, copy, uapi16_reader_root(reader), &w, &e), 0);
        for (;;) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
                int r = uapi16_reader_next(reader, &file, &e);

                if (r == UAPI16_READ_END)
                        break;
                check_eq(r, UAPI16_READ_FILE);
                if (strcmp(uapi16_file_object_name(file), "a/file") == 0) {
                        check_eq(uapi16_file_object_read_only(file), UAPI16_READ_ONLY_YES);
                        check(uapi16_file_object_has_stated_feature(file, UAPI16_FEATURE_READ_ONLY));
                        read_only = true;
                } else {
                        check_eq(uapi16_file_object_read_only(file), UAPI16_READ_ONLY_NO);
                        check(!uapi16_file_object_has_stated_feature(file, UAPI16_FEATURE_READ_ONLY));
                }
                check_eq(uapi16_writer_file(w, file, &e), 0);
                files++;
        }
        check_eq(uapi16_writer_finish(w, &e), 0);
        check_eq(files, 6);
        check(read_only);
        reader = uapi16_reader_free(reader);
        w = uapi16_writer_free(w);

        generated = read_all(original, &generated_size);
        copied = read_all(copy, &copied_size);
        check_manifest(generated, generated_size);
        check(strstr(generated, "\"readOnly\":true"));
        check(!strstr(generated, "\"readOnly\":false"));
        check_same(copied, copied_size, generated, generated_size);
        check(!e);
}

/*
 * A manifest that declares no order. Options take UAPI16_ORDER_NONE for a
 * writer of records, which then writes the file objects in the order of
 * the caller and checks what it can without an order: that each comes
 * right after the object of its directory, and that no name comes again
 * right after the entries of the directory it names. A name that comes
 * again later is not found. The functions that sort refuse such options.
 */
static void test_no_order(void) {
        /* File objects as a caller that does not sort has them, and the
         * rule a writer of records refuses each for: without an order, and
         * with the code point order. */
        static const struct {
                const char *name;
                uint32_t type;
                const char *unordered, *ordered;
        } steps[] = {
                { "b", S_IFDIR, NULL, NULL },
                { "b/z", S_IFREG, NULL, NULL },
                /* After b/z, which it sorts before. */
                { "b/y", S_IFREG, NULL, "outOfOrder" },
                /* A name that comes twice, with another one in between. */
                { "b/z", S_IFREG, NULL, "duplicateName" },
                /* The directory again, right after its entries. */
                { "b", S_IFDIR, "duplicateName", "duplicateName" },
                { "a", S_IFREG, NULL, "outOfOrder" },
                /* The same name again, right away. */
                { "a", S_IFREG, "duplicateName", "outOfOrder" },
                /* Not right after the object of its directory. */
                { "b/x", S_IFREG, "misplaced", "outOfOrder" },
        };
        static const char *const unordered_names[] = { "b", "b/z", "b/y", "b/z", "a" };
        static const char *const ordered_names[] = { "b", "b/z" };
        _cleanup_(closep) int tree = make_tree("no-order"), out = make_dir(tmp_fd, "no-order-out");
        _cleanup_(closep) int unsorted = scratch_file(), sorted = scratch_file(), into = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *listing = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *text = NULL;
        size_t text_size;
        struct stat st;
        int r;

        /* Options take no order, and take the code point order back. */
        check_eq(uapi16_manifest_options_set_order(o, UAPI16_ORDER_NONE), 0);

        /* A writer of records for such options writes the file objects as
         * they come. It lets the name through that comes twice with
         * another one in between, and refuses the three it can tell
         * without an order. What it refuses is not written. */
        check_eq(uapi16_writer_begin(o, unsorted, NULL, &w, &e), 0);
        check(w && !e);
        for (size_t i = 0; i < ELEMENTSOF(steps); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object(steps[i].name);
                size_t before = size_of(unsorted);

                check_eq(uapi16_file_object_set_type(file, steps[i].type), 0);
                r = uapi16_writer_file(w, file, &e);
                if (steps[i].unordered) {
                        check_refused(r, &e, steps[i].unordered, steps[i].name, NULL);
                        check_eq(size_of(unsorted), before);
                } else {
                        check_eq(r, 0);
                        check(size_of(unsorted) > before);
                }
        }
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);

        /* The manifest declares no order: its root has none, a reader says
         * so, and a caller that relies on the code point order is told
         * that it can't. No order is none to require, of any manifest. The
         * reader takes the file objects in the order they are in. */
        text = read_all(unsorted, &text_size);
        check_manifest(text, text_size);
        check(!strstr(text, "\"order\""));
        reader = open_reader(unsorted);
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_NONE);
        r = uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e);
        check_eq(uapi16_error_kind(e), UAPI16_ERROR_MANIFEST);
        check_refused(r, &e, "noOrder", "", "order");
        check_misuse(uapi16_reader_require_order(reader, UAPI16_ORDER_NONE, &e), &e, EINVAL);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_NONE, NULL), -EINVAL);
        for (size_t i = 0; i < ELEMENTSOF(unordered_names); i++) {
                check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
                check_str(uapi16_file_object_name(got), unordered_names[i]);
        }
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);

        /* The functions that sort take no options without an order: each
         * of the four fails for them as a call that is not valid does,
         * makes no file, writes nothing and stores no object. */
        check_misuse(uapi16_manifest_writer_create_at(o, out, "m", &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_writer_open(o, into, &none, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);
        check_misuse(uapi16_manifest_generate(o, into, tree, UAPI16_ADD_NONE, &report, &e), &e, EINVAL);
        check_eq(uapi16_manifest_writer_create_at(o, out, "m", &none, NULL), -EINVAL);
        check_eq(uapi16_manifest_writer_open(o, into, &none, NULL), -EINVAL);
        check_eq(uapi16_manifest_generate_at(o, out, "m", tree, UAPI16_ADD_NONE, NULL, NULL), -EINVAL);
        check_eq(uapi16_manifest_generate(o, into, tree, UAPI16_ADD_NONE, NULL, NULL), -EINVAL);
        check(!none && !report);
        check_eq(size_of(into), 0);
        check_eq(count_entries(tmp_fd, "no-order-out"), 0);
        check_eq(fstatat(out, "m", &st, 0), -1);
        check_eq(errno, ENOENT);

        /* With the code point order the names have to be in it, and every
         * name that comes twice is found. */
        check_eq(uapi16_manifest_options_set_order(o, UAPI16_ORDER_CODEPOINT), 0);
        check_eq(uapi16_writer_begin(o, sorted, NULL, &w, &e), 0);
        for (size_t i = 0; i < ELEMENTSOF(steps); i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object(steps[i].name);
                size_t before = size_of(sorted);

                check_eq(uapi16_file_object_set_type(file, steps[i].type), 0);
                r = uapi16_writer_file(w, file, &e);
                if (steps[i].ordered) {
                        check_refused(r, &e, steps[i].ordered, steps[i].name, NULL);
                        check_eq(size_of(sorted), before);
                } else {
                        check_eq(r, 0);
                        check(size_of(sorted) > before);
                }
        }
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);
        reader = open_reader(sorted);
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e), 0);
        check_misuse(uapi16_reader_require_order(reader, UAPI16_ORDER_NONE, &e), &e, EINVAL);
        for (size_t i = 0; i < ELEMENTSOF(ordered_names); i++) {
                check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
                check_str(uapi16_file_object_name(got), ordered_names[i]);
        }
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);

        /* And the four that sort work again. */
        check_eq(uapi16_manifest_writer_create_at(o, out, "m", &listing, &e), 0);
        check_eq(uapi16_manifest_writer_finish(listing, NULL, &e), 0);
        listing = uapi16_manifest_writer_free(listing);
        check_eq(fstatat(out, "m", &st, 0), 0);
        check_eq(uapi16_manifest_writer_open(o, into, &listing, &e), 0);
        check_eq(uapi16_manifest_writer_finish(listing, NULL, &e), 0);
        listing = uapi16_manifest_writer_free(listing);
        check(size_of(into) > 0);
        empty(into);
        check_eq(uapi16_manifest_generate_at(o, out, "generated", tree, UAPI16_ADD_NONE, &report, &e), 0);
        report = uapi16_manifest_report_free(report);
        check_eq(uapi16_manifest_generate(o, into, tree, UAPI16_ADD_NONE, &report, &e), 0);
        check_eq(uapi16_manifest_report_files(report), 3);
        check(size_of(into) > 0);
        check(!e);
}

/* A manifest with a file object and two signature objects, and how many
 * bytes of it the signature objects sign: all before the first of them. */
#define SIGNED_PART ROOT FILE_OBJECT("a")
#define SIGNED SIGNED_PART SIGNATURE_OBJECT("openpgp") SIGNATURE_OBJECT("pkcs7") TRAILER

/* A manifest with a file object after a signature object, which is in
 * record 3: the root is in record 0. */
#define FILE_AFTER_SIGNATURE ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp") FILE_OBJECT("b") TRAILER
#define RECORD_AFTER_SIGNATURE 3

/* What a reader fails with that a manifest breaks the rule `problem` for:
 * an error of the kind UAPI16_ERROR_MANIFEST that names the rule. */
static void check_broken(int r, uapi16_error **e, const char *problem) {
        check_eq(r, -EBADMSG);
        check(*e);
        check_eq(uapi16_error_kind(*e), UAPI16_ERROR_MANIFEST);
        check_eq(uapi16_error_errno(*e), EBADMSG);
        check_str(uapi16_error_problem(*e), problem);
        *e = uapi16_error_free(*e);
}

/*
 * The read flow: the file objects come from uapi16_reader_next(), which
 * says where they end, with signature objects to follow or with the
 * trailer. The signature objects come from uapi16_reader_next_signature(),
 * or are passed over by uapi16_reader_next(). A reader that failed to read
 * an object takes nothing more.
 */
static void test_reading(void) {
        static const int no_descriptors[] = { -1, AT_FDCWD, INT_MIN };
        _cleanup_(closep) int plain = manifest_pipe(ROOT FILE_OBJECT("a") FILE_OBJECT("b") TRAILER);
        _cleanup_(closep) int passed = manifest_file(SIGNED), taken = manifest_pipe(SIGNED);
        _cleanup_(closep) int one = manifest_file(SIGNED);
        _cleanup_(closep) int late = manifest_file(FILE_AFTER_SIGNATURE);
        _cleanup_(closep) int late_passed = manifest_pipe(FILE_AFTER_SIGNATURE);
        _cleanup_(closep) int cut = manifest_file(ROOT FILE_OBJECT("a"));
        _cleanup_(closep) int cut_taken = manifest_file(ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp"));
        _cleanup_(closep) int cut_passed = manifest_pipe(ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp"));
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *none = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const uapi16_signature *mine;
        uint64_t length = 77;
        int r;

        /* A reader needs a descriptor and a place to go to. */
        check_misuse(uapi16_reader_open(plain, NULL, &e), &e, EINVAL);
        check_eq(uapi16_reader_open(plain, NULL, NULL), -EINVAL);
        for (size_t i = 0; i < ELEMENTSOF(no_descriptors); i++)
                check_misuse(uapi16_reader_open(no_descriptors[i], &none, &e), &e, EBADF);
        check(!none);
        check(!uapi16_reader_free(NULL));

        /* A manifest without signature objects, which comes through a
         * pipe: its file objects, and its end. It signs nothing. A caller
         * can't ask for signature objects while its file objects come, and
         * a call that is not valid reads nothing. At its end it has none: a
         * caller that asks is told that the manifest ended, as often as it
         * asks, and keeps the object it has, as it is. */
        check_eq(uapi16_reader_open(plain, &reader, &e), 0);
        check(reader && !e);
        check_eq(uapi16_reader_signed_len(reader, &length), -ENODATA);
        check_misuse(uapi16_reader_next_signature(reader, &signature, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next(NULL, &file, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next(reader, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next_signature(NULL, &signature, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next_signature(reader, NULL, &e), &e, EINVAL);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(file), "a");
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next_signature(reader, &signature, NULL), -EINVAL);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(file), "b");
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        check_eq(uapi16_reader_signed_len(reader, &length), -ENODATA);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_END);
        check(!signature && !e);
        check_eq(uapi16_signature_new("mine", &signature), 0);
        mine = signature;
        for (int again = 0; again < 2; again++) {
                check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_END);
                check(signature == mine);
                check_str(uapi16_signature_mechanism(signature), "mine");
        }
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        check(!file && !e);
        check_eq(length, 77);
        check_eq(uapi16_reader_signed_len(NULL, &length), -EINVAL);
        check_eq(uapi16_reader_signed_len(reader, NULL), -EINVAL);
        reader = uapi16_reader_free(reader);
        check(!reader);

        /* Signature objects that are passed over: the file objects end
         * where they begin, what they sign is known from there on, and the
         * next call reads on to the trailer. */
        check_eq(uapi16_reader_open(passed, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_signed_len(reader, &length), -ENODATA);
        check_eq(length, 77);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_signed_len(reader, &length), 0);
        check_eq(length, strlen(SIGNED_PART));
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        length = 77;
        check_eq(uapi16_reader_signed_len(reader, &length), 0);
        check_eq(length, strlen(SIGNED_PART));
        reader = uapi16_reader_free(reader);

        /* Signature objects that are read, each once, up to the trailer. */
        check_eq(uapi16_reader_open(taken, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "pkcs7");
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_END);
        length = 77;
        check_eq(uapi16_reader_signed_len(reader, &length), 0);
        check_eq(length, strlen(SIGNED_PART));
        reader = uapi16_reader_free(reader);

        /* One that is read, and the rest passed over. */
        check_eq(uapi16_reader_open(one, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        signature = uapi16_signature_free(signature);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);
        check(!e);

        /* A file object after a signature object is one that no signature
         * covers. A reader that reads the signature objects refuses it,
         * and takes nothing more. */
        check_eq(uapi16_reader_open(late, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        signature = uapi16_signature_free(signature);
        r = uapi16_reader_next_signature(reader, &signature, &e);
        check_record(e, RECORD_AFTER_SIGNATURE);
        check_broken(r, &e, "fileAfterSignature");
        check_ended(uapi16_reader_next_signature(reader, &signature, &e), &e);
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        check_eq(uapi16_reader_next_signature(reader, &signature, NULL), -ESTALE);
        check_eq(uapi16_reader_next(reader, &file, NULL), -ESTALE);
        /* A call that is not valid fails for that still. */
        check_misuse(uapi16_reader_next(reader, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_reader_next_signature(reader, NULL, &e), &e, EINVAL);
        reader = uapi16_reader_free(reader);

        /* So does one that passes over them. */
        check_eq(uapi16_reader_open(late_passed, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        r = uapi16_reader_next(reader, &file, &e);
        check_record(e, RECORD_AFTER_SIGNATURE);
        check_broken(r, &e, "fileAfterSignature");
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        check_ended(uapi16_reader_next_signature(reader, &signature, &e), &e);
        reader = uapi16_reader_free(reader);

        /* A manifest that ends without its trailer is not complete: after
         * its file objects, and after its signature objects, read or
         * passed over. */
        check_eq(uapi16_reader_open(cut, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_broken(uapi16_reader_next(reader, &file, &e), &e, "noTrailer");
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        check_ended(uapi16_reader_next_signature(reader, &signature, &e), &e);
        reader = uapi16_reader_free(reader);
        check_eq(uapi16_reader_open(cut_taken, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        signature = uapi16_signature_free(signature);
        check_broken(uapi16_reader_next_signature(reader, &signature, &e), &e, "noTrailer");
        check_ended(uapi16_reader_next_signature(reader, &signature, &e), &e);
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        reader = uapi16_reader_free(reader);
        check_eq(uapi16_reader_open(cut_passed, &reader, &e), 0);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_broken(uapi16_reader_next(reader, &file, &e), &e, "noTrailer");
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        check(!e);
}

/* A reader of a descriptor that does not block fails with EAGAIN while
 * there is nothing to read. That does not end it: it lost nothing, and it
 * reads on with the next call, also where half a record came in between.
 * The object of the caller stays as it is until then. The open is another
 * matter: it loses what it read where it fails with EAGAIN, so it needs the
 * root and the start of the next record in the descriptor. */
static void test_no_blocking(void) {
        static const char *const too_little[] = { "\x1e{\"mediaType\":", ROOT };
        static const char enough[] = ROOT RS;
        static const char begin[] = "{\"name\":\"a\"}\n" RS;
        static const char half[] = "{\"name\":\"b\",";
        static const char rest[] = "\"size\":7}\n" TRAILER;
        _cleanup_(closep) int from = -1, into = -1;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uint64_t size = 0;
        int ends[2], r;
        char byte;

        /* The open reads the root and looks at what comes after it. With
         * less than that in the pipe it fails with EAGAIN, and what it read
         * is lost: half of the root, and the root alone. */
        for (size_t i = 0; i < ELEMENTSOF(too_little); i++) {
                int lost[2];

                check_eq(pipe2(lost, O_CLOEXEC | O_NONBLOCK), 0);
                check_eq(write(lost[1], too_little[i], strlen(too_little[i])), (ssize_t) strlen(too_little[i]));
                r = uapi16_reader_open(lost[0], &reader, &e);
                check_error(r, e, UAPI16_ERROR_IO, EAGAIN, NULL, CHECK_RECORD);
                e = uapi16_error_free(e);
                check(!reader);
                check_eq(read(lost[0], &byte, 1), -1);
                check_eq(errno, EAGAIN);
                check_eq(close(lost[0]), 0);
                check_eq(close(lost[1]), 0);
        }

        /* With the root and the start of the next record it opens. */
        check_eq(pipe2(ends, O_CLOEXEC | O_NONBLOCK), 0);
        from = ends[0];
        into = ends[1];
        check_eq(write(into, enough, strlen(enough)), (ssize_t) strlen(enough));
        check_eq(uapi16_reader_open(from, &reader, &e), 0);
        check_eq(write(into, begin, strlen(begin)), (ssize_t) strlen(begin));
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(file), "a");
        for (int with_half = 0; with_half < 2; with_half++) {
                if (with_half)
                        check_eq(write(into, half, strlen(half)), (ssize_t) strlen(half));
                r = uapi16_reader_next(reader, &file, &e);
                check_error(r, e, UAPI16_ERROR_IO, EAGAIN, NULL, CHECK_RECORD);
                e = uapi16_error_free(e);
                check_eq(uapi16_reader_next(reader, &file, NULL), -EAGAIN);
                check_str(uapi16_file_object_name(file), "a");
        }
        check_eq(write(into, rest, strlen(rest)), (ssize_t) strlen(rest));
        check_eq(close(into), 0);
        into = -1;
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(file), "b");
        check_eq(uapi16_file_object_size(file, &size), 0);
        check_eq(size, 7);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        check(!e);
}

/*
 * What a reader says of its manifest as a whole: its root, what it
 * records, the order it declares and whether it may be used. And what it
 * says of a manifest that breaks a rule: which rule, in which record, of
 * which file and in which field.
 */
static void test_manifests(void) {
        _cleanup_(closep) int ordered = manifest_file(ROOT FILE_OBJECT("a") FILE_OBJECT("b") TRAILER);
        _cleanup_(closep) int unordered =
                manifest_file(ROOT_WITHOUT_ORDER FILE_OBJECT("b") FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int out_of_order = manifest_file(ROOT FILE_OBJECT("b") FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int misplaced = manifest_file(ROOT FILE_OBJECT("a") FILE_OBJECT("b/c") TRAILER);
        _cleanup_(closep) int featured =
                manifest_file(RS "{\"features\":[\"size\",\"mtime\"],"
                                 "\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n"
                              RS "{\"mTimeNSec\":7,\"name\":\"a\",\"size\":3}\n"
                              RS "{\"mode\":420,\"name\":\"b\"}\n" TRAILER);
        _cleanup_(closep) int empty_file = scratch_file();
        _cleanup_(closep) int no_separator =
                manifest_file("{\"mediaType\":\"application/vnd.uapi.16.manifest\"}\n" TRAILER);
        _cleanup_(closep) int no_manifest =
                manifest_file(RS "{\"mediaType\":\"application/x-other\"}\n" TRAILER);
        _cleanup_(closep) int root_with_size =
                manifest_file(RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\",\"size\":1}\n"
                              TRAILER);
        _cleanup_(closep) int data =
                manifest_file(ROOT RS "{\"contents\":[{\"literal\":\"aGVsbG8=\"}],\"name\":\"literal\"}\n"
                              RS "{\"name\":\"none\",\"size\":0}\n"
                              RS "{\"contents\":[{\"file\":\"blobs/1\"}],\"name\":\"other\"}\n"
                              RS "{\"name\":\"own\"}\n"
                              RS "{\"contents\":[{\"url\":\"https://example.com/x\"}],\"name\":\"remote\"}\n"
                              RS "{\"name\":\"without\",\"type\":\"fifo\"}\n" TRAILER);
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *none = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *again = NULL;
        const char *field, *problem;
        uapi16_sha256_digest_t hash;
        uint64_t number = 77;
        size_t size = 77;
        const void *literal;
        int r;

        /* A manifest that declares its order and lists no features: it
         * records the default ones. Its root is the object with the empty
         * name, which says nothing here. */
        reader = open_reader(ordered);
        check_recorded(reader, FEATURES(DEFAULT_FEATURES));
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_CODEPOINT);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e), 0);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, NULL), 0);
        check_str(uapi16_file_object_name(uapi16_reader_root(reader)), "");
        check_eq(uapi16_file_object_type(uapi16_reader_root(reader)), S_IFDIR);
        check_stated(uapi16_reader_root(reader), FEATURES(UAPI16_FEATURE_NONE));
        /* An order that is none is no order to require. */
        check_misuse(uapi16_reader_require_order(reader, UAPI16_ORDER_NONE, &e), &e, EINVAL);
        check_misuse(uapi16_reader_require_order(reader, 2, &e), &e, EINVAL);
        check_misuse(uapi16_reader_require_order(NULL, UAPI16_ORDER_CODEPOINT, &e), &e, EINVAL);
        check_eq(uapi16_reader_require_order(reader, UINT64_MAX, NULL), -EINVAL);
        reader = uapi16_reader_free(reader);

        /* No reader says nothing. */
        check(!uapi16_reader_root(NULL));
        check_recorded(NULL, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_reader_order(NULL), UAPI16_ORDER_NONE);

        /* A manifest that declares no order has none, and a caller that
         * relies on one is told: the rule, and the root with its field and
         * its record. Its file objects come in the order they are in. */
        reader = open_reader(unordered);
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_NONE);
        r = uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e);
        check_record(e, 0);
        check_refused(r, &e, "noOrder", "", "order");
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, NULL), -EBADMSG);
        file = next_object(reader, "b");
        file = uapi16_file_object_free(file);
        file = next_object(reader, "a");
        file = uapi16_file_object_free(file);
        check_ends(reader);
        reader = uapi16_reader_free(reader);

        /* The reader holds the file objects to the order the manifest
         * declares: one that comes after one it sorts before is refused,
         * with the number of its record and its name. */
        reader = open_reader(out_of_order);
        file = next_object(reader, "b");
        file = uapi16_file_object_free(file);
        r = uapi16_reader_next(reader, &file, &e);
        check_record(e, 2);
        check_refused(r, &e, "outOfOrder", "a", NULL);
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        reader = uapi16_reader_free(reader);

        /* So is one that does not come right after the object of its
         * directory. */
        reader = open_reader(misplaced);
        file = next_object(reader, "a");
        file = uapi16_file_object_free(file);
        r = uapi16_reader_next(reader, &file, &e);
        check_record(e, 2);
        check_refused(r, &e, "misplaced", "b/c", NULL);
        reader = uapi16_reader_free(reader);

        /* A manifest that lists its features records those, and a file
         * object with a field of another one is refused for the field. The
         * names of a field and of a rule are constants of the library: the
         * same string every time, also once the error is freed. */
        reader = open_reader(featured);
        check_recorded(reader, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        check_eq(uapi16_reader_order(reader), UAPI16_ORDER_NONE);
        file = next_object(reader, "a");
        check_eq(uapi16_file_object_mtime_nsec(file, &number), 0);
        check_eq(number, 7);
        check_stated(file, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        file = uapi16_file_object_free(file);
        r = uapi16_reader_next(reader, &file, &e);
        check_eq(r, -EBADMSG);
        check_eq(uapi16_error_kind(e), UAPI16_ERROR_MANIFEST);
        check_record(e, 2);
        check_str(uapi16_error_path(e), "b");
        field = uapi16_error_field(e);
        problem = uapi16_error_problem(e);
        check_str(field, "mode");
        check_str(problem, "unlistedFeature");
        check(uapi16_error_field(e) == field && uapi16_error_problem(e) == problem);
        reader = uapi16_reader_free(reader);
        reader = open_reader(featured);
        file = next_object(reader, "a");
        file = uapi16_file_object_free(file);
        check_eq(uapi16_reader_next(reader, &file, &again), -EBADMSG);
        check(again && again != e);
        check(uapi16_error_field(again) == field && uapi16_error_problem(again) == problem);
        e = uapi16_error_free(e);
        again = uapi16_error_free(again);
        check_str(field, "mode");
        check_str(problem, "unlistedFeature");
        reader = uapi16_reader_free(reader);

        /* What is no manifest makes no reader: a file that holds nothing,
         * one that does not start with a record separator, one whose first
         * object is not the root of a manifest, and one whose root has what
         * only another file object has. */
        check_broken(uapi16_reader_open(empty_file, &none, &e), &e, "empty");
        r = uapi16_reader_open(no_separator, &none, &e);
        check_record(e, 0);
        check_broken(r, &e, "recordSeparator");
        r = uapi16_reader_open(no_manifest, &none, &e);
        check_record(e, 0);
        check_broken(r, &e, "mediaType");
        r = uapi16_reader_open(root_with_size, &none, &e);
        check_record(e, 0);
        check_str(uapi16_error_field(e), "size");
        /* The error is about the root, which is the empty string, as for
         * a root that uapi16_writer_begin() and
         * uapi16_manifest_writer_add_object() refuse for the same rule. */
        check_str(uapi16_error_path(e), "");
        check_broken(r, &e, "fieldNotPermitted");
        check_eq(uapi16_reader_open(empty_file, &none, NULL), -EBADMSG);
        check(!none);

        /* Where the data of a file object is: in the manifest, in a file
         * next to it that the object names, in the file of its own name,
         * or at a URL, which is not supported. A FIFO has none. The size
         * of data that is in the manifest follows from it, and the hash of
         * no data from the size 0: the reader fills them in, and they are
         * none of the fields of the object. */
        reader = open_reader(data);
        file = next_object(reader, "literal");
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_LITERAL);
        literal = uapi16_file_object_literal(file, &size);
        check_same(literal, size, "hello", 5);
        check_eq(uapi16_file_object_size(file, &number), 0);
        check_eq(number, 5);
        check_stated(file, FEATURES(UAPI16_FEATURE_NONE));
        file = uapi16_file_object_free(file);
        file = next_object(reader, "none");
        check_eq(uapi16_file_object_sha256(file, &hash), 0);
        check_hash(&hash, SHA256_OF_NOTHING);
        check_stated(file, FEATURES(UAPI16_FEATURE_SIZE));
        file = uapi16_file_object_free(file);
        file = next_object(reader, "other");
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_EXTERNAL);
        check(!uapi16_file_object_literal(file, &size));
        check_eq(size, 0);
        file = uapi16_file_object_free(file);
        file = next_object(reader, "own");
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_EXTERNAL);
        file = uapi16_file_object_free(file);
        file = next_object(reader, "remote");
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_UNSUPPORTED);
        check(!uapi16_file_object_literal(file, &size));
        number = 77;
        check_eq(uapi16_file_object_size(file, &number), -ENODATA);
        check_eq(number, 77);
        file = uapi16_file_object_free(file);
        file = next_object(reader, "without");
        check_eq(uapi16_file_object_type(file), S_IFIFO);
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_NONE);
        file = uapi16_file_object_free(file);
        check_ends(reader);
        check(!e);
}

/*
 * When a manifest and a file object may be used: not once they are
 * revoked, not before the time they are valid from, and not from the time
 * on that they are valid until.
 */
static void test_validity(void) {
        _cleanup_(closep) int windows =
                manifest_file(RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\","
                                 "\"validSinceUSec\":1000,\"validUntilUSec\":2000}\n"
                              RS "{\"name\":\"a\",\"validity\":\"revoked\"}\n"
                              RS "{\"name\":\"b\",\"validSinceUSec\":10,\"validUntilUSec\":20}\n"
                              RS "{\"name\":\"c\"}\n" TRAILER);
        _cleanup_(closep) int revoked =
                manifest_file(RS "{\"mediaType\":\"application/vnd.uapi.16.manifest\","
                                 "\"validity\":\"revoked\"}\n" TRAILER);
        _cleanup_(closep) int always = manifest_file(ROOT TRAILER);
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        const uapi16_file_object *root;
        int r;

        /* The window of the root is that of the manifest: the reader and
         * its root say the same of it. */
        reader = open_reader(windows);
        root = uapi16_reader_root(reader);
        /* An error about when a manifest may be used is about its root,
         * which is the empty string. */
        r = uapi16_reader_check_validity(reader, 999, &e);
        check_error(r, e, UAPI16_ERROR_NOT_YET_VALID, EKEYEXPIRED, "", 0);
        e = uapi16_error_free(e);
        r = uapi16_file_object_check_validity(root, 999, &e);
        check_error(r, e, UAPI16_ERROR_NOT_YET_VALID, EKEYEXPIRED, "", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_reader_check_validity(reader, 0, NULL), -EKEYEXPIRED);
        check_eq(uapi16_reader_check_validity(reader, 1000, &e), 0);
        check_eq(uapi16_reader_check_validity(reader, 1999, &e), 0);
        check_eq(uapi16_file_object_check_validity(root, 1000, &e), 0);
        check_eq(uapi16_file_object_check_validity(root, 1999, &e), 0);
        r = uapi16_reader_check_validity(reader, 2000, &e);
        check_error(r, e, UAPI16_ERROR_EXPIRED, EKEYEXPIRED, "", 0);
        e = uapi16_error_free(e);
        r = uapi16_file_object_check_validity(root, UINT64_MAX, &e);
        check_error(r, e, UAPI16_ERROR_EXPIRED, EKEYEXPIRED, "", 0);
        e = uapi16_error_free(e);

        /* A file object that is revoked is that at any time, and the error
         * is about it. */
        file = next_object(reader, "a");
        r = uapi16_file_object_check_validity(file, 0, &e);
        check_error(r, e, UAPI16_ERROR_REVOKED, EKEYREVOKED, "a", 0);
        e = uapi16_error_free(e);
        r = uapi16_file_object_check_validity(file, UINT64_MAX, &e);
        check_error(r, e, UAPI16_ERROR_REVOKED, EKEYREVOKED, "a", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_check_validity(file, 15, NULL), -EKEYREVOKED);
        file = uapi16_file_object_free(file);

        /* One with a window of its own: the time it is valid from is in
         * it, and the time it is valid until is not. */
        file = next_object(reader, "b");
        r = uapi16_file_object_check_validity(file, 9, &e);
        check_error(r, e, UAPI16_ERROR_NOT_YET_VALID, EKEYEXPIRED, "b", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_check_validity(file, 10, &e), 0);
        check_eq(uapi16_file_object_check_validity(file, 19, &e), 0);
        r = uapi16_file_object_check_validity(file, 20, &e);
        check_error(r, e, UAPI16_ERROR_EXPIRED, EKEYEXPIRED, "b", 0);
        e = uapi16_error_free(e);
        file = uapi16_file_object_free(file);

        /* One that says nothing may be used at any time: the check looks
         * at the object alone, and not at the manifest it is in. */
        file = next_object(reader, "c");
        check_eq(uapi16_file_object_check_validity(file, 0, &e), 0);
        check_eq(uapi16_file_object_check_validity(file, UINT64_MAX, &e), 0);
        file = uapi16_file_object_free(file);
        check_ends(reader);
        reader = uapi16_reader_free(reader);

        /* A manifest that is revoked, and one that says nothing. */
        reader = open_reader(revoked);
        r = uapi16_reader_check_validity(reader, 0, &e);
        check_error(r, e, UAPI16_ERROR_REVOKED, EKEYREVOKED, "", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_reader_check_validity(reader, UINT64_MAX, NULL), -EKEYREVOKED);
        check_eq(uapi16_file_object_check_validity(uapi16_reader_root(reader), 1500, NULL), -EKEYREVOKED);
        reader = uapi16_reader_free(reader);
        reader = open_reader(always);
        check_eq(uapi16_reader_check_validity(reader, 0, &e), 0);
        check_eq(uapi16_reader_check_validity(reader, UINT64_MAX, &e), 0);
        check_misuse(uapi16_reader_check_validity(NULL, 0, &e), &e, EINVAL);
        check_eq(uapi16_reader_check_validity(NULL, 0, NULL), -EINVAL);
        check(!e);
}

/* Checks that `a` and `b` are both no string, or the same string. */
static void check_same_text(const char *a, const char *b) {
        check(!a == !b);
        if (a)
                check_str(a, b);
}

/*
 * Checks that the file objects `a` and `b` say the same, through every
 * getter a file object has: uapi16_file_object_name(), _type(), _mode(),
 * _uid(), _gid(), _user_name(), _group_name(), _mtime_nsec(), _size(),
 * _sha256(), _major(), _minor(), _inode_token(), _user_xattrs(),
 * _user_xattr(), _read_only(), _inode_flags(), _dos_attributes(),
 * _data_location(), _contents_file(), _literal(), _fs_label(),
 * _fs_uuid(), _fat_serial(), _stated_feature() and _check_validity(). A
 * getter that fails for one fails the same way for the other.
 */
static void check_same_object(const uapi16_file_object *a, const uapi16_file_object *b) {
        static const uint64_t times[] = { 0, 15, 25, UINT64_MAX };
        uapi16_sha256_digest_t hash_a = { .bytes = { 0 } }, hash_b = { .bytes = { 0 } };
        uapi16_uuid_t uuid_a = { .bytes = { 0 } }, uuid_b = { .bytes = { 0 } };
        uint32_t small_a = 77, small_b = 77, set_a = 77, set_b = 77;
        uint64_t number_a = 77, number_b = 77;
        uapi16_inode_token_t token_a = 77, token_b = 77;
        size_t count_a = 0, count_b = 0, size_a = 77, size_b = 77;
        const void *bytes_a, *bytes_b;
        int r;

        check(a && b && a != b);
        check_same_text(uapi16_file_object_name(a), uapi16_file_object_name(b));
        check_eq(uapi16_file_object_type(a), uapi16_file_object_type(b));
        r = uapi16_file_object_mode(a, &small_a);
        check_eq(uapi16_file_object_mode(b, &small_b), r);
        check_eq(small_a, small_b);
        r = uapi16_file_object_uid(a, &small_a);
        check_eq(uapi16_file_object_uid(b, &small_b), r);
        check_eq(small_a, small_b);
        r = uapi16_file_object_gid(a, &small_a);
        check_eq(uapi16_file_object_gid(b, &small_b), r);
        check_eq(small_a, small_b);
        check_same_text(uapi16_file_object_user_name(a), uapi16_file_object_user_name(b));
        check_same_text(uapi16_file_object_group_name(a), uapi16_file_object_group_name(b));
        r = uapi16_file_object_mtime_nsec(a, &number_a);
        check_eq(uapi16_file_object_mtime_nsec(b, &number_b), r);
        check_eq(number_a, number_b);
        r = uapi16_file_object_size(a, &number_a);
        check_eq(uapi16_file_object_size(b, &number_b), r);
        check_eq(number_a, number_b);
        r = uapi16_file_object_sha256(a, &hash_a);
        check_eq(uapi16_file_object_sha256(b, &hash_b), r);
        check_eq(memcmp(&hash_a, &hash_b, sizeof(hash_a)), 0);
        r = uapi16_file_object_major(a, &number_a);
        check_eq(uapi16_file_object_major(b, &number_b), r);
        check_eq(number_a, number_b);
        r = uapi16_file_object_minor(a, &number_a);
        check_eq(uapi16_file_object_minor(b, &number_b), r);
        check_eq(number_a, number_b);
        r = uapi16_file_object_inode_token(a, &token_a);
        check_eq(uapi16_file_object_inode_token(b, &token_b), r);
        check_eq(token_a, token_b);
        r = uapi16_file_object_user_xattrs(a, &count_a);
        check_eq(uapi16_file_object_user_xattrs(b, &count_b), r);
        check_eq(count_a, count_b);
        /* One more than there are: both have none of that number. */
        for (size_t i = 0; i <= count_a; i++) {
                const char *name_a = NULL, *name_b = NULL;

                bytes_a = bytes_b = NULL;
                size_a = size_b = 77;
                r = uapi16_file_object_user_xattr(a, i, &name_a, &bytes_a, &size_a);
                check_eq(r, i < count_a ? 0 : -EINVAL);
                check_eq(uapi16_file_object_user_xattr(b, i, &name_b, &bytes_b, &size_b), r);
                check_same_text(name_a, name_b);
                check_eq(size_a, size_b);
                if (r == 0)
                        check_same(bytes_a, size_a, bytes_b, size_b);
        }
        check_eq(uapi16_file_object_read_only(a), uapi16_file_object_read_only(b));
        r = uapi16_file_object_inode_flags(a, &small_a, &set_a);
        check_eq(uapi16_file_object_inode_flags(b, &small_b, &set_b), r);
        check_eq(small_a, small_b);
        check_eq(set_a, set_b);
        r = uapi16_file_object_dos_attributes(a, &small_a, &set_a);
        check_eq(uapi16_file_object_dos_attributes(b, &small_b, &set_b), r);
        check_eq(small_a, small_b);
        check_eq(set_a, set_b);
        check_eq(uapi16_file_object_data_location(a), uapi16_file_object_data_location(b));
        {
                const char *file_a = NULL, *file_b = NULL;

                number_a = number_b = 77;
                r = uapi16_file_object_contents_file(a, &file_a, &number_a);
                check_eq(uapi16_file_object_contents_file(b, &file_b, &number_b), r);
                check_same_text(file_a, file_b);
                check_eq(number_a, number_b);
        }
        size_a = size_b = 77;
        bytes_a = uapi16_file_object_literal(a, &size_a);
        bytes_b = uapi16_file_object_literal(b, &size_b);
        check(!bytes_a == !bytes_b);
        check_eq(size_a, size_b);
        if (bytes_a)
                check_same(bytes_a, size_a, bytes_b, size_b);
        check_same_text(uapi16_file_object_fs_label(a), uapi16_file_object_fs_label(b));
        r = uapi16_file_object_fs_uuid(a, &uuid_a);
        check_eq(uapi16_file_object_fs_uuid(b, &uuid_b), r);
        check_eq(memcmp(&uuid_a, &uuid_b, sizeof(uuid_a)), 0);
        small_a = small_b = 77;
        r = uapi16_file_object_fat_serial(a, &small_a);
        check_eq(uapi16_file_object_fat_serial(b, &small_b), r);
        check_eq(small_a, small_b);
        check_same_stated(a, b);
        for (size_t i = 0; i < ELEMENTSOF(times); i++) {
                r = uapi16_file_object_check_validity(a, times[i], NULL);
                check_eq(uapi16_file_object_check_validity(b, times[i], NULL), r);
        }
}

/*
 * Checks that the file object `o` has the name `name`, is a regular file,
 * and has nothing else: every getter of a field says that there is none,
 * each in its way.
 */
static void check_bare_object(const uapi16_file_object *o, const char *name) {
        uapi16_sha256_digest_t hash = { .bytes = { 0 } };
        uapi16_uuid_t uuid = { .bytes = { 0 } };
        uint32_t small = 77, stated = 77, set = 77;
        uint64_t number = 77;
        uapi16_inode_token_t token = 77;
        size_t count = 77, size = 77;
        const char *xattr = NULL, *contents_file = NULL;
        const void *value = NULL;

        check_str(uapi16_file_object_name(o), name);
        check_eq(uapi16_file_object_type(o), S_IFREG);
        check_eq(uapi16_file_object_mode(o, &small), -ENODATA);
        check_eq(uapi16_file_object_uid(o, &small), -ENODATA);
        check_eq(uapi16_file_object_gid(o, &small), -ENODATA);
        check(!uapi16_file_object_user_name(o));
        check(!uapi16_file_object_group_name(o));
        check_eq(uapi16_file_object_mtime_nsec(o, &number), -ENODATA);
        check_eq(uapi16_file_object_size(o, &number), -ENODATA);
        check_eq(uapi16_file_object_sha256(o, &hash), -ENODATA);
        check_eq(uapi16_file_object_major(o, &number), -ENODATA);
        check_eq(uapi16_file_object_minor(o, &number), -ENODATA);
        check_eq(uapi16_file_object_inode_token(o, &token), -ENODATA);
        check_eq(uapi16_file_object_user_xattrs(o, &count), -ENODATA);
        check_eq(uapi16_file_object_user_xattr(o, 0, &xattr, &value, &size), -EINVAL);
        check_eq(uapi16_file_object_read_only(o), UAPI16_READ_ONLY_UNSTATED);
        check_eq(uapi16_file_object_inode_flags(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        stated = set = 77;
        check_eq(uapi16_file_object_dos_attributes(o, &stated, &set), 0);
        check_eq(stated, 0);
        check_eq(set, 0);
        /* The data of a regular file that says nothing is in the file of
         * its own name, so it names no other file. */
        check_eq(uapi16_file_object_data_location(o), UAPI16_DATA_LOCATION_EXTERNAL);
        check_eq(uapi16_file_object_contents_file(o, &contents_file, &number), -ENODATA);
        check(!uapi16_file_object_literal(o, &size));
        check_eq(size, 0);
        check(!uapi16_file_object_fs_label(o));
        check_eq(uapi16_file_object_fs_uuid(o, &uuid), -ENODATA);
        check_eq(uapi16_file_object_fat_serial(o, &small), -ENODATA);
        check_stated(o, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_check_validity(o, 0, NULL), 0);
        check_eq(uapi16_file_object_check_validity(o, UINT64_MAX, NULL), 0);
        /* None of the getters that failed stored anything. */
        check_eq(small, 77);
        check_eq(number, 77);
        check_eq(token, 77);
        check_eq(count, 77);
        check(!xattr && !contents_file && !value && hash.bytes[0] == 0 && uuid.bytes[0] == 0);
}

/* How many records fill_writer() writes at most, and how many it writes
 * at least before a pipe or a small file system is full. */
#define FILL_RECORDS_MAX 100000
#define FILL_RECORDS_MIN 1

/* How many bytes there are in the file `fd`, or to read from it if it is
 * a pipe. */
static off_t bytes_in(int fd) {
        struct stat st;
        int n;

        check_eq(fstat(fd, &st), 0);
        if (S_ISREG(st.st_mode))
                return st.st_size;
        check_eq(ioctl(fd, FIONREAD, &n), 0);
        return n;
}

/* Writes file objects with names of `size` bytes to `w` until a write
 * fails, which it does with the errno `full`: an error of the kind
 * UAPI16_ERROR_IO that is about no file. The writer takes nothing more
 * after that: the object that failed, another one and the end are all
 * UAPI16_ERROR_ENDED, and none of them writes anything to what `look`
 * shows, the file of the writer or the other end of its pipe. Stores in
 * `written` how many bytes are there, and returns how many records were
 * written. */
static int fill_writer(uapi16_writer *w, size_t size, int full, int look, off_t *written) {
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *other = make_object("zz");
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL;
        char name[NAME_OF_OBJECT_MAX + 1];

        check(size >= 8 && size <= NAME_OF_OBJECT_MAX);
        check_eq(uapi16_signature_new("mechanism", &signature), 0);
        for (int i = 0; i < FILL_RECORDS_MAX; i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
                uint64_t record = 0;
                int r;

                memset(name, 'x', size);
                name[size] = 0;
                check_eq(snprintf(name, 8, "%07d", i), 7);
                name[7] = 'x';
                o = make_object(name);
                r = uapi16_writer_file(w, o, &e);
                if (r == 0)
                        continue;
                /* The error names the record that was not written, the
                 * root being record 0. */
                check_error(r, e, UAPI16_ERROR_IO, full, NULL, CHECK_RECORD);
                check_eq(uapi16_error_record(e, &record), 0);
                check_eq(record, (uint64_t) i + 1);
                e = uapi16_error_free(e);
                *written = bytes_in(look);
                check_ended(uapi16_writer_file(w, o, &e), &e);
                check_ended(uapi16_writer_file(w, other, &e), &e);
                check_ended(uapi16_writer_signature(w, signature, &e), &e);
                check_ended(uapi16_writer_finish(w, &e), &e);
                check_eq(bytes_in(look), *written);
                return i;
        }
        check(false);
        return -1;
}

/* Reads what a writer wrote to `fd` before a write of it failed. It is no
 * manifest: a reader does not come to its end. */
static void check_no_manifest(int fd) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        int r = uapi16_reader_open(fd, &reader, &e);

        while (r >= 0) {
                r = uapi16_reader_next(reader, &o, &e);
                check(r != UAPI16_READ_END && r != UAPI16_READ_SIGNATURES);
        }
        check(e);
}

/* A writer of records on a pipe that does not block, which is full after
 * a while: with records that fit the pipe, and with one that is larger
 * than the pipe, of which a part is written. */
static void failed_write_to_a_pipe(size_t size, int least) {
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(closep) int out = -1, in = -1;
        off_t written;
        int ends[2];

        check_eq(pipe2(ends, O_CLOEXEC | O_NONBLOCK), 0);
        in = ends[0];
        out = ends[1];
        check(fcntl(out, F_SETPIPE_SZ, sysconf(_SC_PAGESIZE)) > 0);
        check_eq(uapi16_writer_begin(o, out, NULL, &w, &e), 0);
        check(fill_writer(w, size, EAGAIN, in, &written) >= least);
        w = uapi16_writer_free(w);
        check_eq(bytes_in(in), written);
        check_eq(close(out), 0);
        out = -1;
        check_eq(fcntl(in, F_SETFL, 0), 0);
        check_no_manifest(in);
}

/* What the child of test_failed_writes() does: in a user and a mount
 * namespace of its own it mounts a small tmpfs at `target`, and writes
 * records to a file on it until the file system is full. */
static int failed_write_in_namespace(const char *target, uid_t uid, gid_t gid) {
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(closep) int dir = -1, out = -1;
        off_t written;

        if (!own_namespace(uid, gid) || mount("none", target, "tmpfs", 0, "size=64k") < 0)
                return EXIT_SKIPPED;
        dir = open(target, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(dir >= 0);
        out = openat(dir, "manifest", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
        check(out >= 0);
        check_eq(uapi16_writer_begin(o, out, NULL, &w, &e), 0);
        check(fill_writer(w, NAME_OF_OBJECT_MAX, ENOSPC, out, &written) >= FILL_RECORDS_MIN);
        w = uapi16_writer_free(w);
        check_eq(bytes_in(out), written);
        check_eq(lseek(out, 0, SEEK_SET), 0);
        check_no_manifest(out);
        return EXIT_SUCCESS;
}

/* A write of a writer of records that fails ends the writer: on a pipe
 * that does not block and is full, and on a file system that is full. The
 * call that failed says why, and every call after it fails as after
 * uapi16_writer_finish(), so that nothing passes for a manifest that lacks
 * a record. */
static void test_failed_writes(void) {
        _cleanup_(closep) int target = make_dir(tmp_fd, "failed-writes");
        char path[PATH_MAX];
        int status;
        pid_t pid;

        failed_write_to_a_pipe(16, FILL_RECORDS_MIN);
        failed_write_to_a_pipe(NAME_OF_OBJECT_MAX, 0);

        check((size_t) snprintf(path, sizeof(path), "%s/failed-writes", tmp_path) < sizeof(path));
        fflush(NULL);
        pid = fork();
        check(pid >= 0);
        if (pid == 0) {
                int code = failed_write_in_namespace(path, getuid(), getgid());

                fflush(NULL);
                _exit(code);
        }
        check_eq(waitpid(pid, &status, 0), pid);
        check(WIFEXITED(status));
        if (WEXITSTATUS(status) == EXIT_SKIPPED)
                fprintf(stderr, "skipping a file system that is full: no user namespace that can mount here\n");
        else
                check_eq(WEXITSTATUS(status), EXIT_SUCCESS);
}

/*
 * uapi16_reader_next() and uapi16_reader_next_signature() take an object
 * as getline() takes its buffer: where `ret` points to an object of the
 * caller, that object is cleared and filled again, and nothing of what it
 * held is left. So one object serves a whole manifest, and after every
 * read it says what a new object of that record says.
 */
static void test_refilled_objects(void) {
        static const uapi16_uuid_t uuid = { .bytes = { 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6 } };
        static const char binary[] = { 0, (char) 0xfe, 'x' };
        static const char *const names[] = { "a", "b", "c", "d", "e", "f", "g", "h" };
        _cleanup_(closep) int written = scratch_file(), reused = -1, fresh = -1;
        _cleanup_(closep) int bare =
                manifest_file(ROOT FILE_OBJECT("bare") SIGNATURE_OBJECT("pkcs7") TRAILER);
        _cleanup_(closep) int windows =
                manifest_file(ROOT RS "{\"name\":\"a\",\"validSinceUSec\":10,\"validUntilUSec\":20}\n"
                              RS "{\"name\":\"b\",\"validity\":\"revoked\"}\n"
                              RS "{\"name\":\"c\"}\n" TRAILER);
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reusing = NULL, *renewing = NULL, *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *a = make_hello("a");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *c = make_object("c");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *link = make_object("e");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *g = make_object("g");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("b");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *kept = NULL, *full = make_object("full");
        _cleanup_(uapi16_signature_freep) uapi16_signature *openpgp = NULL, *pkcs7 = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL, *mine = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        _cleanup_(freep) char *text = NULL;
        const uapi16_file_object *first = NULL;
        const uapi16_signature *first_signature = NULL;
        uapi16_sha256_digest_t hash;
        uint32_t stated = 77, set = 77;
        uint64_t number = 77;
        uapi16_inode_token_t token = 77;
        size_t text_size, count = 77, size = 77;
        const char *name = NULL;
        const void *bytes = NULL;
        int r;

        /* A manifest of file objects with fields, each of them before one
         * with none: a regular file with all a regular file can have, a
         * device, a symbolic link and a file whose data is elsewhere. Two
         * signature objects follow, one with a key and data and one
         * without. */
        check_eq(set_features(o, FEATURES_OF_TREES), 0);
        check_eq(uapi16_file_object_set_mode(a, 0444), 0);
        check_eq(uapi16_file_object_set_uid(a, 1), 0);
        check_eq(uapi16_file_object_set_gid(a, 2), 0);
        check_eq(uapi16_file_object_set_user_name(a, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(a, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(a, 3), 0);
        check_eq(uapi16_file_object_set_inode_token(a, 7), 0);
        check_eq(uapi16_file_object_add_user_xattr(a, "text", "a value", 7), 0);
        check_eq(uapi16_file_object_add_user_xattr(a, "binary", binary, sizeof(binary)), 0);
        check_eq(uapi16_file_object_set_read_only(a, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_set_inode_flags(a, INODE_FLAGS, NODUMP_FL | IMMUTABLE_FL), 0);
        check_eq(uapi16_file_object_set_dos_attributes(a, DOS_ATTRIBUTES, DOS_HIDDEN), 0);
        check_eq(uapi16_file_object_set_target(a, "hello", 5), 0);
        check_eq(uapi16_file_object_set_type(c, S_IFCHR), 0);
        check_eq(uapi16_file_object_set_mode(c, 0600), 0);
        check_eq(uapi16_file_object_set_major(c, 4), 0);
        check_eq(uapi16_file_object_set_minor(c, 5), 0);
        check_eq(uapi16_file_object_set_type(link, S_IFLNK), 0);
        check_eq(uapi16_file_object_set_target(link, "to/somewhere", 12), 0);
        check_eq(uapi16_file_object_set_size(g, 10), 0);
        check_eq(uapi16_file_object_set_contents_file(g, "blobs/1", &e), 0);
        check_eq(uapi16_signature_new("openpgp", &openpgp), 0);
        check_eq(uapi16_signature_set_key(openpgp, "key", 3), 0);
        check_eq(uapi16_signature_set_data(openpgp, binary, sizeof(binary)), 0);
        check_eq(uapi16_signature_new("pkcs7", &pkcs7), 0);

        w = begin_records(o, written);
        for (size_t i = 0; i < ELEMENTSOF(names); i++) {
                const uapi16_file_object *with_fields[] = { a, c, link, g };

                if (i % 2 == 0) {
                        check_eq(uapi16_writer_file(w, with_fields[i / 2], &e), 0);
                        continue;
                }
                check_eq(uapi16_file_object_set_name(plain, names[i], &e), 0);
                check_eq(uapi16_writer_file(w, plain, &e), 0);
        }
        check_eq(uapi16_writer_signature(w, openpgp, &e), 0);
        check_eq(uapi16_writer_signature(w, pkcs7, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);
        text = read_all(written, &text_size);
        check_eq(strlen(text), text_size);
        reused = manifest_file(text);
        fresh = manifest_file(text);

        /* One object for the whole manifest, next to a new one for every
         * record: the object is the same one after every file object, and
         * says what the new one says, whatever the record before it had.
         * Every getter is called on it before it is filled again, so what
         * it handed out, strings and bytes, is gone with what it held. */
        reusing = open_reader(reused);
        renewing = open_reader(fresh);
        for (size_t i = 0;; i++) {
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *renewed = NULL;

                r = uapi16_reader_next(reusing, &kept, &e);
                check_eq(uapi16_reader_next(renewing, &renewed, &e), r);
                if (r != UAPI16_READ_FILE) {
                        check_eq(i, ELEMENTSOF(names));
                        break;
                }
                check(i < ELEMENTSOF(names));
                if (i == 0)
                        first = kept;
                check(kept && kept == first);
                check_str(uapi16_file_object_name(kept), names[i]);
                check_same_object(kept, renewed);
                if (i == 0) {
                        /* The first one is not what the writer was given
                         * for nothing: it has its fields. */
                        check_str(uapi16_file_object_user_name(kept), "user");
                        check_eq(uapi16_file_object_user_xattrs(kept, &count), 0);
                        check_eq(count, 2);
                        check_eq(uapi16_file_object_read_only(kept), UAPI16_READ_ONLY_YES);
                        bytes = uapi16_file_object_literal(kept, &size);
                        check_same(bytes, size, "hello", 5);
                }
                if (i % 2 == 0)
                        continue;
                /* A record without a field leaves the object without it.
                 * This manifest records every feature of a tree, so the
                 * reader fills in what the features say of a file that
                 * says nothing: it is not read-only, it has no extended
                 * attributes, and none of its flags is set. */
                check_eq(uapi16_file_object_type(kept), S_IFREG);
                check_eq(uapi16_file_object_mode(kept, &stated), -ENODATA);
                check(!uapi16_file_object_user_name(kept));
                check(!uapi16_file_object_group_name(kept));
                check_eq(uapi16_file_object_size(kept, &number), -ENODATA);
                check_eq(uapi16_file_object_sha256(kept, &hash), -ENODATA);
                check_eq(uapi16_file_object_major(kept, &number), -ENODATA);
                check_eq(uapi16_file_object_inode_token(kept, &token), -ENODATA);
                check_eq(number, 77);
                check_eq(token, 77);
                check_eq(uapi16_file_object_user_xattrs(kept, &count), 0);
                check_eq(count, 0);
                check_eq(uapi16_file_object_user_xattr(kept, 0, &name, &bytes, &size), -EINVAL);
                check_eq(uapi16_file_object_read_only(kept), UAPI16_READ_ONLY_NO);
                check_eq(uapi16_file_object_inode_flags(kept, &stated, &set), 0);
                check_eq(stated, INODE_FLAGS);
                check_eq(set, 0);
                check_eq(uapi16_file_object_dos_attributes(kept, &stated, &set), 0);
                check_eq(stated, DOS_ATTRIBUTES);
                check_eq(set, 0);
                stated = 77;
                check_eq(uapi16_file_object_data_location(kept), UAPI16_DATA_LOCATION_EXTERNAL);
                check(!uapi16_file_object_literal(kept, &size));
                check_eq(size, 0);
                check_stated(kept, FEATURES(UAPI16_FEATURE_NONE));
        }
        check_eq(r, UAPI16_READ_SIGNATURES);
        check(kept == first);

        /* The same for the signature objects: one object for both, which
         * has the key and the data of the first, and neither once it holds
         * the second. */
        check_eq(uapi16_reader_next_signature(reusing, &signature, &e), UAPI16_READ_SIGNATURE);
        first_signature = signature;
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        bytes = uapi16_signature_key(signature, &size);
        check_same(bytes, size, "key", 3);
        bytes = uapi16_signature_data(signature, &size);
        check_same(bytes, size, binary, sizeof(binary));
        check_eq(uapi16_reader_next_signature(reusing, &signature, &e), UAPI16_READ_SIGNATURE);
        check(signature == first_signature);
        check_str(uapi16_signature_mechanism(signature), "pkcs7");
        size = 77;
        check(!uapi16_signature_key(signature, &size));
        check_eq(size, 0);
        size = 77;
        check(!uapi16_signature_data(signature, &size));
        check_eq(size, 0);
        check_eq(uapi16_reader_next_signature(reusing, &signature, &e), UAPI16_READ_END);
        check(signature == first_signature);
        check_str(uapi16_signature_mechanism(signature), "pkcs7");

        /* An object the caller made itself is one to fill as well. This
         * one has every field a setter sets, and every string and all the
         * bytes it hands out were asked for. Filled from a record that has
         * a name and nothing else, in a manifest that records the default
         * features, it has the name of the record and nothing else. */
        unhex(SHA256_OF_HELLO, &hash);
        check_eq(uapi16_file_object_set_type(full, S_IFCHR), 0);
        check_eq(uapi16_file_object_set_mode(full, 0444), 0);
        check_eq(uapi16_file_object_set_uid(full, 1), 0);
        check_eq(uapi16_file_object_set_gid(full, 2), 0);
        check_eq(uapi16_file_object_set_user_name(full, "user"), 0);
        check_eq(uapi16_file_object_set_group_name(full, "group"), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(full, 3), 0);
        check_eq(uapi16_file_object_set_size(full, 6), 0);
        check_eq(uapi16_file_object_set_sha256(full, &hash), 0);
        check_eq(uapi16_file_object_set_major(full, 4), 0);
        check_eq(uapi16_file_object_set_minor(full, 5), 0);
        check_eq(uapi16_file_object_set_inode_token(full, 6), 0);
        check_eq(uapi16_file_object_add_user_xattr(full, "text", "a value", 7), 0);
        check_eq(uapi16_file_object_add_user_xattr(full, "binary", binary, sizeof(binary)), 0);
        check_eq(uapi16_file_object_set_read_only(full, UAPI16_READ_ONLY_YES), 0);
        check_eq(uapi16_file_object_set_inode_flags(full, INODE_FLAGS, NODUMP_FL), 0);
        check_eq(uapi16_file_object_set_dos_attributes(full, DOS_ATTRIBUTES, DOS_HIDDEN), 0);
        check_eq(uapi16_file_object_set_target(full, "target", 6), 0);
        check_eq(uapi16_file_object_set_fs_label(full, "label"), 0);
        check_eq(uapi16_file_object_set_fs_uuid(full, &uuid), 0);
        check_eq(uapi16_file_object_set_fat_serial(full, 7), 0);
        check_str(uapi16_file_object_name(full), "full");
        check_str(uapi16_file_object_user_name(full), "user");
        check_str(uapi16_file_object_group_name(full), "group");
        check_str(uapi16_file_object_fs_label(full), "label");
        check_eq(uapi16_file_object_user_xattrs(full, &count), 0);
        check_eq(count, 2);
        for (size_t i = 0; i < count; i++) {
                check_eq(uapi16_file_object_user_xattr(full, i, &name, &bytes, &size), 0);
                check(name && bytes && size > 0);
        }
        bytes = uapi16_file_object_literal(full, &size);
        check_same(bytes, size, "target", 6);
        check_eq(uapi16_file_object_sha256(full, &hash), 0);
        check(uapi16_file_object_stated_feature(full, 0) != UAPI16_FEATURE_NONE);
        first = full;
        reader = open_reader(bare);
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_FILE);
        check(full == first);
        check_bare_object(full, "bare");

        /* A signature object of the caller with a key and data, filled
         * from a record that has a mechanism alone. */
        check_eq(uapi16_signature_new("openpgp", &mine), 0);
        check_eq(uapi16_signature_set_key(mine, "mine", 4), 0);
        check_eq(uapi16_signature_set_data(mine, binary, sizeof(binary)), 0);
        check_str(uapi16_signature_mechanism(mine), "openpgp");
        check(uapi16_signature_key(mine, &size));
        check(uapi16_signature_data(mine, &size));
        first_signature = mine;
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &mine, &e), UAPI16_READ_SIGNATURE);
        check(mine == first_signature);
        check_str(uapi16_signature_mechanism(mine), "pkcs7");
        size = 77;
        check(!uapi16_signature_key(mine, &size));
        check_eq(size, 0);
        size = 77;
        check(!uapi16_signature_data(mine, &size));
        check_eq(size, 0);
        check_eq(uapi16_reader_next_signature(reader, &mine, &e), UAPI16_READ_END);
        reader = uapi16_reader_free(reader);

        /* When a file object may be used is a field no getter reads: it
         * shows in the check of it. A window is gone once the object holds
         * a record that is revoked, and both are once it holds one that
         * says nothing. */
        reader = open_reader(windows);
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_FILE);
        check(full == first);
        check_eq(uapi16_file_object_check_validity(full, 5, NULL), -EKEYEXPIRED);
        check_eq(uapi16_file_object_check_validity(full, 15, NULL), 0);
        check_eq(uapi16_file_object_check_validity(full, 25, NULL), -EKEYEXPIRED);
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_FILE);
        check(full == first);
        check_eq(uapi16_file_object_check_validity(full, 5, NULL), -EKEYREVOKED);
        check_eq(uapi16_file_object_check_validity(full, 15, NULL), -EKEYREVOKED);
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_FILE);
        check(full == first);
        check_bare_object(full, "c");
        check_eq(uapi16_file_object_check_validity(full, 5, NULL), 0);
        check_eq(uapi16_file_object_check_validity(full, 15, NULL), 0);
        check_eq(uapi16_file_object_check_validity(full, 25, NULL), 0);
        check_eq(uapi16_reader_next(reader, &full, &e), UAPI16_READ_END);
        check(full == first);
        check(!e);
}

/*
 * The object a read is given stays the caller's, whatever the read
 * returns. A read that reads no object leaves `*ret` exactly as it was, the
 * pointer and what the object holds: at the end of the file objects, at the
 * trailer, and where it fails. A NULL there stays NULL. A caller that
 * wants to keep an object sets its pointer to NULL before the next read,
 * and has two objects then.
 */
static void test_kept_objects(void) {
        _cleanup_(closep) int signed_fd = manifest_file(
                ROOT FILE_OBJECT("a") FILE_OBJECT("b") SIGNATURE_OBJECT("openpgp") TRAILER);
        _cleanup_(closep) int plain = manifest_file(ROOT FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int out_of_order = manifest_file(ROOT FILE_OBJECT("b") FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int late =
                manifest_file(ROOT FILE_OBJECT("a") SIGNATURE_OBJECT("openpgp") FILE_OBJECT("b") TRAILER);
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL, *kept = NULL, *none = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *own = make_hello("own");
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL, *no_signature = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *mine = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *held = NULL;
        const uapi16_file_object *was;
        const uapi16_signature *was_signature, *was_mine;
        const void *bytes;
        uint64_t number = 0;
        size_t size = 0;
        int r;

        check_eq(uapi16_file_object_new("a//b", &none, &held), -EINVAL);
        check(held && !none);
        check_eq(uapi16_signature_new("mine", &mine), 0);
        check_eq(uapi16_signature_set_key(mine, "key", 3), 0);

        /* A caller keeps an object by setting its pointer to NULL before
         * the next read: the read makes a new one, and both are there,
         * each with its record. */
        reader = open_reader(signed_fd);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(file), "a");
        kept = file;
        file = NULL;
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check(file && file != kept);
        check_str(uapi16_file_object_name(kept), "a");
        check_str(uapi16_file_object_name(file), "b");
        was = file;

        /* A read that is not valid leaves the object as it is: one whose
         * `reterr` points to something, and one for a signature object
         * while file objects come, which leaves the signature object of
         * the caller as it is. */
        check_eq(uapi16_reader_next(reader, &file, &held), -EINVAL);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");
        was_signature = mine;
        check_misuse(uapi16_reader_next_signature(reader, &mine, &e), &e, EINVAL);
        check(mine == was_signature);
        check_str(uapi16_signature_mechanism(mine), "mine");
        bytes = uapi16_signature_key(mine, &size);
        check_same(bytes, size, "key", 3);
        check_misuse(uapi16_reader_next_signature(reader, &no_signature, &e), &e, EINVAL);
        check(!no_signature);

        /* The end of the file objects leaves it, and stores nothing where
         * there is no object. */
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");

        /* A signature object, and the trailer, which leaves the signature
         * object and the file object as they are, whichever of the two
         * reads it and however often. */
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        was_signature = signature;
        check_eq(uapi16_reader_next_signature(reader, &signature, &held), -EINVAL);
        check(signature == was_signature);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_END);
        check(signature == was_signature);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        check_eq(uapi16_reader_next_signature(reader, &no_signature, &e), UAPI16_READ_END);
        check(!no_signature);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_END);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");
        check_eq(uapi16_reader_next(reader, &none, &e), UAPI16_READ_END);
        check(!none);
        check_str(uapi16_file_object_name(kept), "a");
        reader = uapi16_reader_free(reader);

        /* At the end of a manifest without signature objects a caller
         * that asks for one is told that the manifest ended, and its
         * signature object stays as it is. So does an object the caller
         * made itself and that the end of the manifest is read into. */
        reader = open_reader(plain);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check(file == was);
        check_str(uapi16_file_object_name(file), "a");
        was = own;
        check_eq(uapi16_reader_next(reader, &own, &e), UAPI16_READ_END);
        check(own == was);
        check_str(uapi16_file_object_name(own), "own");
        check_eq(uapi16_file_object_size(own, &number), 0);
        check_eq(number, 5);
        was_mine = mine;
        check_eq(uapi16_reader_next_signature(reader, &mine, &e), UAPI16_READ_END);
        check(mine == was_mine);
        check_str(uapi16_signature_mechanism(mine), "mine");
        check_eq(uapi16_reader_next_signature(reader, &no_signature, &e), UAPI16_READ_END);
        check(!no_signature && !e);
        reader = uapi16_reader_free(reader);

        /* A read that fails for the manifest leaves the object with the
         * record it had, and so does every read after it, which the reader
         * takes no more of. */
        reader = open_reader(out_of_order);
        was = file;
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");
        r = uapi16_reader_next(reader, &file, &e);
        check_refused(r, &e, "outOfOrder", "a", NULL);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");
        check_ended(uapi16_reader_next(reader, &file, &e), &e);
        check(file == was);
        check_str(uapi16_file_object_name(file), "b");
        check_eq(uapi16_reader_next(reader, &none, NULL), -ESTALE);
        check(!none);
        check_ended(uapi16_reader_next_signature(reader, &mine, &e), &e);
        check_str(uapi16_signature_mechanism(mine), "mine");
        reader = uapi16_reader_free(reader);

        /* The same for a signature object: a file object after it fails
         * the read, which leaves the one of the caller as it was. */
        reader = open_reader(late);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &signature, &e), UAPI16_READ_SIGNATURE);
        check(signature == was_signature);
        r = uapi16_reader_next_signature(reader, &signature, &e);
        check_refused(r, &e, "fileAfterSignature", NULL, NULL);
        check(signature == was_signature);
        check_str(uapi16_signature_mechanism(signature), "openpgp");
        check_ended(uapi16_reader_next_signature(reader, &signature, &e), &e);
        check(signature == was_signature);
        check_eq(uapi16_reader_next_signature(reader, &no_signature, NULL), -ESTALE);
        check(!no_signature);

        /* Every object here is the caller's still, and is freed once: the
         * two file objects of the first manifest, the one the caller made,
         * and the signature objects. */
        check(file == was && file != kept);
        file = uapi16_file_object_free(file);
        kept = uapi16_file_object_free(kept);
        check(!file && !kept && !e);
}

/*
 * uapi16_error_record() stores the number of the record of a manifest that
 * an error is about, counting from 0, which is the record of the root. For
 * a reader that is the record that failed, and for a writer of records the
 * number the record it refused would have had. An error about no record
 * has none, as no error of a manifest writer has, and the call fails with
 * -ENODATA. It needs an error and a place, and stores nothing where it
 * fails.
 */
static void test_error_records(void) {
        _cleanup_(closep) int written = scratch_file(), listed = scratch_file();
        _cleanup_(closep) int no_manifest =
                manifest_file(RS "{\"mediaType\":\"application/x-other\"}\n" TRAILER);
        _cleanup_(closep) int unordered = manifest_file(ROOT_WITHOUT_ORDER TRAILER);
        _cleanup_(closep) int out_of_order =
                manifest_file(ROOT FILE_OBJECT("b") FILE_OBJECT("c") FILE_OBJECT("a") TRAILER);
        _cleanup_(closep) int cut = manifest_file(ROOT FILE_OBJECT("a"));
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL, *none = NULL;
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL;
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_manifest_report_freep) uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL, *no_object = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *given = make_object("b");
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uint64_t record = 77;
        int r;

        /* The root is record 0: an error about a first record that is no
         * root of a manifest, and one about a root that declares no order
         * where a caller relies on one. */
        check_eq(uapi16_reader_open(no_manifest, &none, &e), -EBADMSG);
        check(e && !none);
        check_eq(uapi16_error_record(e, &record), 0);
        check_eq(record, 0);
        e = uapi16_error_free(e);
        reader = open_reader(unordered);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, &e), -EBADMSG);
        record = 77;
        check_eq(uapi16_error_record(e, &record), 0);
        check_eq(record, 0);
        e = uapi16_error_free(e);
        reader = uapi16_reader_free(reader);

        /* A later record: the third file object of a manifest, which is
         * out of order, is record 3. A call without a place for the number
         * is not valid. */
        reader = open_reader(out_of_order);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_eq(uapi16_reader_next(reader, &file, &e), -EBADMSG);
        check_str(uapi16_error_problem(e), "outOfOrder");
        record = 77;
        check_eq(uapi16_error_record(e, &record), 0);
        check_eq(record, 3);
        check_eq(uapi16_error_record(e, NULL), -EINVAL);
        e = uapi16_error_free(e);
        reader = uapi16_reader_free(reader);

        /* An error about no record has none: one about a manifest as a
         * whole, which ends without its trailer, and one about a call. The
         * number of before is where it was. */
        reader = open_reader(cut);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_FILE);
        check_eq(uapi16_reader_next(reader, &file, &e), -EBADMSG);
        check_str(uapi16_error_problem(e), "noTrailer");
        record = 77;
        check_eq(uapi16_error_record(e, &record), -ENODATA);
        check_eq(record, 77);
        check_eq(uapi16_error_record(e, NULL), -EINVAL);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_new("a//b", &no_object, &e), -EINVAL);
        check(e && !no_object);
        check_eq(uapi16_error_record(e, &record), -ENODATA);
        check_eq(record, 77);
        e = uapi16_error_free(e);

        /* A writer of records names the record it refuses by the number
         * the record would have had. For the root that is 0, whichever rule
         * refuses it: a field that only another file object has, and a
         * field of a feature the manifest does not record. Nothing is
         * written, and no writer is made. */
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_MODE)), 0);
        check_eq(uapi16_file_object_set_size(root, 1), 0);
        r = uapi16_writer_begin(o, written, root, &records, &e);
        check_record(e, 0);
        check_refused(r, &e, "fieldNotPermitted", "", "size");
        check_eq(retain_features(root, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_file_object_set_fs_label(root, "label"), 0);
        r = uapi16_writer_begin(o, written, root, &records, &e);
        check_record(e, 0);
        check_refused(r, &e, "unlistedFeature", "", "fsLabel");
        check(!records);
        check_eq(size_of(written), 0);

        /* A file object that is refused would have been the next record,
         * whichever rule refuses it: one that is out of order, and one
         * with a field that only the root has. The writer is as it was, so
         * the next one that is refused has that number as well. */
        check_eq(retain_features(root, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_writer_begin(o, written, root, &records, &e), 0);
        check_eq(uapi16_writer_file(records, given, &e), 0);
        check_eq(uapi16_file_object_set_name(given, "a", &e), 0);
        r = uapi16_writer_file(records, given, &e);
        check_record(e, 2);
        check_refused(r, &e, "outOfOrder", "a", NULL);
        check_eq(uapi16_file_object_set_name(given, "c", &e), 0);
        check_eq(uapi16_file_object_set_fs_label(given, "label"), 0);
        r = uapi16_writer_file(records, given, &e);
        check_record(e, 2);
        check_refused(r, &e, "fieldNotPermitted", "c", "fsLabel");
        check_eq(retain_features(given, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_writer_file(records, given, &e), 0);
        check_eq(uapi16_file_object_set_fs_label(given, "label"), 0);
        r = uapi16_writer_file(records, given, &e);
        check_record(e, 3);
        check_refused(r, &e, "fieldNotPermitted", "c", "fsLabel");
        check_eq(uapi16_writer_finish(records, &e), 0);

        /* An error of a manifest writer is about no record: it has no
         * records before it finishes, and writes them in its own order.
         * That holds for an object it refuses, for a root it refuses, and
         * for what it finds when it finishes. */
        check_eq(set_features(o, FEATURES(DEFAULT_FEATURES)), 0);
        check_eq(uapi16_manifest_writer_open(o, listed, &w, &e), 0);
        r = uapi16_manifest_writer_add_object(w, given, &e);
        check_eq(uapi16_error_record(e, &record), -ENODATA);
        check_refused(r, &e, "fieldNotPermitted", "c", "fsLabel");
        check_eq(retain_features(root, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_file_object_set_size(root, 1), 0);
        r = uapi16_manifest_writer_add_object(w, root, &e);
        check_eq(uapi16_error_record(e, &record), -ENODATA);
        check_refused(r, &e, "fieldNotPermitted", "", "size");
        check_eq(retain_features(given, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_file_object_set_size(given, 1), 0);
        check_eq(uapi16_manifest_writer_add_object(w, given, &e), 0);
        check_eq(uapi16_file_object_set_size(given, 2), 0);
        check_eq(uapi16_manifest_writer_add_object(w, given, &e), 0);
        r = uapi16_manifest_writer_finish(w, &report, &e);
        check_error(r, e, UAPI16_ERROR_DUPLICATE, EEXIST, "c", 0);
        e = uapi16_error_free(e);
        check_eq(record, 77);

        /* No error is none to ask. */
        check_eq(uapi16_error_record(NULL, &record), -EINVAL);
        check_eq(uapi16_error_record(NULL, NULL), -EINVAL);
        check_eq(record, 77);
}

/*
 * A signature object: its mechanism, what identifies its key and its
 * data, each of which it has, has as no bytes at all, or does not have. A
 * writer of records writes it, and a reader hands it out as it was.
 */
static void test_signatures(void) {
        static const char binary[] = { 0, 'k', (char) 0xff, 0 };
        _cleanup_(closep) int written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *s = NULL, *none = NULL, *got = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        char key[] = "a key", mechanism[] = "openpgp";
        const char *name;
        const void *bytes;
        size_t size = 77;

        /* A new one has its mechanism, of which it keeps a copy, and
         * neither a key nor data. */
        check_eq(uapi16_signature_new(mechanism, &s), 0);
        check(s);
        mechanism[0] = 'O';
        name = uapi16_signature_mechanism(s);
        check_str(name, "openpgp");
        check(!uapi16_signature_key(s, &size));
        check_eq(size, 0);
        size = 77;
        check(!uapi16_signature_data(s, &size));
        check_eq(size, 0);
        check(!uapi16_signature_key(s, NULL));
        check(!uapi16_signature_data(s, NULL));

        /* It needs a mechanism, and a place to go to. */
        check_eq(uapi16_signature_new(NULL, &none), -EINVAL);
        check_eq(uapi16_signature_new("openpgp", NULL), -EINVAL);
        check(!none);

        /* The key and the data are bytes, of which it keeps a copy. */
        check_eq(uapi16_signature_set_key(s, key, strlen(key)), 0);
        key[0] = 'A';
        bytes = uapi16_signature_key(s, &size);
        check_same(bytes, size, "a key", 5);
        check(uapi16_signature_key(s, NULL));
        check(!uapi16_signature_data(s, &size));
        check_eq(uapi16_signature_set_data(s, binary, sizeof(binary)), 0);
        bytes = uapi16_signature_data(s, &size);
        check_same(bytes, size, binary, sizeof(binary));
        check(uapi16_signature_data(s, NULL));
        bytes = uapi16_signature_key(s, &size);
        check_same(bytes, size, "a key", 5);
        check_str(name, "openpgp");

        /* Bytes of a size of 0 are a key, and data, that is there and
         * empty. The pointer is not looked at. */
        check_eq(uapi16_signature_set_key(s, unreadable(), 0), 0);
        size = 77;
        check(uapi16_signature_key(s, &size));
        check_eq(size, 0);
        check_eq(uapi16_signature_set_data(s, "", 0), 0);
        size = 77;
        check(uapi16_signature_data(s, &size));
        check_eq(size, 0);

        /* NULL takes them away, whatever the size. */
        check_eq(uapi16_signature_set_key(s, NULL, 0), 0);
        size = 77;
        check(!uapi16_signature_key(s, &size));
        check_eq(size, 0);
        check_eq(uapi16_signature_set_data(s, NULL, 5), 0);
        size = 77;
        check(!uapi16_signature_data(s, &size));
        check_eq(size, 0);

        /* No object is none to set anything on, and has nothing. */
        check_eq(uapi16_signature_set_key(NULL, "k", 1), -EINVAL);
        check_eq(uapi16_signature_set_data(NULL, "d", 1), -EINVAL);
        check(!uapi16_signature_mechanism(NULL));
        size = 77;
        check(!uapi16_signature_key(NULL, &size));
        check_eq(size, 0);
        size = 77;
        check(!uapi16_signature_data(NULL, &size));
        check_eq(size, 0);
        check(!uapi16_signature_key(NULL, NULL));
        check(!uapi16_signature_data(NULL, NULL));

        /* Written and read back: one with a key and data, one with a key
         * that is empty and no data, and one with neither. */
        w = begin_records(o, written);
        check_eq(uapi16_signature_set_key(s, binary, sizeof(binary)), 0);
        check_eq(uapi16_signature_set_data(s, "data", 4), 0);
        check_eq(uapi16_writer_signature(w, s, &e), 0);
        check_eq(uapi16_signature_set_key(s, "", 0), 0);
        check_eq(uapi16_signature_set_data(s, NULL, 0), 0);
        check_eq(uapi16_writer_signature(w, s, &e), 0);
        s = uapi16_signature_free(s);
        check(!s);
        check_eq(uapi16_signature_new("pkcs7", &s), 0);
        check_eq(uapi16_writer_signature(w, s, &e), 0);
        check_eq(uapi16_writer_finish(w, &e), 0);
        w = uapi16_writer_free(w);

        reader = open_reader(written);
        check_eq(uapi16_reader_next(reader, &file, &e), UAPI16_READ_SIGNATURES);
        check_eq(uapi16_reader_next_signature(reader, &got, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(got), "openpgp");
        bytes = uapi16_signature_key(got, &size);
        check_same(bytes, size, binary, sizeof(binary));
        bytes = uapi16_signature_data(got, &size);
        check_same(bytes, size, "data", 4);
        got = uapi16_signature_free(got);
        check_eq(uapi16_reader_next_signature(reader, &got, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(got), "openpgp");
        size = 77;
        check(uapi16_signature_key(got, &size));
        check_eq(size, 0);
        check(!uapi16_signature_data(got, &size));
        got = uapi16_signature_free(got);
        check_eq(uapi16_reader_next_signature(reader, &got, &e), UAPI16_READ_SIGNATURE);
        check_str(uapi16_signature_mechanism(got), "pkcs7");
        check(!uapi16_signature_key(got, &size));
        check(!uapi16_signature_data(got, &size));
        /* What a reader handed out is the caller's, to change and to
         * free. */
        check_eq(uapi16_signature_set_key(got, "mine", 4), 0);
        bytes = uapi16_signature_key(got, &size);
        check_same(bytes, size, "mine", 4);
        got = uapi16_signature_free(got);
        check_eq(uapi16_reader_next_signature(reader, &got, &e), UAPI16_READ_END);
        check(!e);

        /* Freeing returns NULL, and takes NULL. */
        check(!uapi16_signature_free(NULL));
}

/* The SHA-256 hash of data that comes in pieces. */
static void test_sha256(void) {
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *s = uapi16_sha256_new();
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *abc = uapi16_sha256_new();
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *blocks = uapi16_sha256_new();
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *million = uapi16_sha256_new();
        static const char two_blocks[] = TWO_BLOCKS;
        uapi16_sha256_digest_t hash, again;
        char thousand[1000];

        check(s && abc && blocks && million);

        /* The hash of no data, which takes no pointer. */
        check_eq(uapi16_sha256_update(s, NULL, 0), 0);
        check_eq(uapi16_sha256_update(s, unreadable(), 0), 0);
        check_eq(uapi16_sha256_finish(s, &hash), 0);
        check_hash(&hash, SHA256_OF_NOTHING);

        /* A computation that is finished takes nothing more, and gives its
         * hash once. Nothing is stored for a call that fails. */
        memset(&again, 0, sizeof(again));
        check_eq(uapi16_sha256_finish(s, &again), -ESTALE);
        check_eq(uapi16_sha256_update(s, "abc", 3), -ESTALE);
        check_eq(uapi16_sha256_update(s, NULL, 0), -ESTALE);
        check_eq(again.bytes[0], 0);
        /* A call that is not valid fails for that still. */
        check_eq(uapi16_sha256_update(s, NULL, 3), -EINVAL);
        check_eq(uapi16_sha256_finish(s, NULL), -EINVAL);

        /* "abc" in one piece, and with data that is missing in between,
         * or of a size that no data has, which is refused and not taken. */
        check_eq(uapi16_sha256_update(abc, "ab", 2), 0);
        check_eq(uapi16_sha256_update(abc, NULL, 1), -EINVAL);
        check_eq(uapi16_sha256_update(abc, "c", (size_t) SSIZE_MAX + 1), -EINVAL);
        check_eq(uapi16_sha256_update(abc, "c", SIZE_MAX), -EINVAL);
        check_eq(uapi16_sha256_finish(abc, NULL), -EINVAL);
        check_eq(uapi16_sha256_update(abc, "c", 1), 0);
        check_eq(uapi16_sha256_finish(abc, &hash), 0);
        check_hash(&hash, SHA256_OF_ABC);

        /* Two blocks of data in pieces of every size from one byte on. */
        for (size_t done = 0, piece = 1; done < strlen(two_blocks); done += piece, piece++) {
                if (piece > strlen(two_blocks) - done)
                        piece = strlen(two_blocks) - done;
                check_eq(uapi16_sha256_update(blocks, two_blocks + done, piece), 0);
        }
        check_eq(uapi16_sha256_finish(blocks, &hash), 0);
        check_hash(&hash, SHA256_OF_TWO_BLOCKS);

        /* A million bytes, a thousand at a time. */
        memset(thousand, 'a', sizeof(thousand));
        for (int i = 0; i < 1000; i++)
                check_eq(uapi16_sha256_update(million, thousand, sizeof(thousand)), 0);
        check_eq(uapi16_sha256_finish(million, &hash), 0);
        check_hash(&hash, SHA256_OF_A_MILLION_A);

        /* No computation is none to give data to. */
        check_eq(uapi16_sha256_update(NULL, "abc", 3), -EINVAL);
        check_eq(uapi16_sha256_finish(NULL, &hash), -EINVAL);
        check_hash(&hash, SHA256_OF_A_MILLION_A);

        /* Freeing returns NULL, and takes NULL. */
        s = uapi16_sha256_free(s);
        check(!s);
        check(!uapi16_sha256_free(NULL));
}

/*
 * A check holds the data of a file object against the size and the hash
 * the object gives, as the data passes. It has what it needs of its
 * object, which can go before the data comes.
 */
static void test_data_checks(void) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = make_hello("data");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *sized = make_object("sized");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *hashed = make_object("hashed");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("plain");
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *c = NULL, *none = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *wrong = NULL, *little = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *unfinished = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;
        uapi16_sha256_digest_t hash;
        uint64_t size = 77;
        int r;

        /* A check needs an object, and a place to go to. */
        check_eq(uapi16_data_check_new(NULL, &none), -EINVAL);
        check_eq(uapi16_data_check_new(o, NULL), -EINVAL);
        check(!none);

        /* Three checks of one object, which is changed and freed before
         * any data comes. */
        check_eq(uapi16_data_check_new(o, &c), 0);
        check_eq(uapi16_data_check_new(o, &wrong), 0);
        check_eq(uapi16_data_check_new(o, &little), 0);
        check(c && wrong && little);
        check_eq(uapi16_file_object_set_size(o, 99), 0);
        check_eq(uapi16_file_object_set_name(o, "changed", NULL), 0);
        o = uapi16_file_object_free(o);

        /* Data that matches, in pieces, some of them empty. More data than
         * the object says is refused, and none of it is taken. */
        check_eq(uapi16_data_check_update(c, "hel", 3, &e), 0);
        check_eq(uapi16_data_check_update(c, NULL, 0, &e), 0);
        check_eq(uapi16_data_check_update(c, unreadable(), 0, &e), 0);
        r = uapi16_data_check_update(c, "lo!", 3, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "data", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_data_check_update(c, "lo!", 3, NULL), -EBADMSG);
        check_misuse(uapi16_data_check_update(c, NULL, 2, &e), &e, EINVAL);
        check_misuse(uapi16_data_check_update(NULL, "lo", 2, &e), &e, EINVAL);
        check_misuse(uapi16_data_check_finish(NULL, &size, &e), &e, EINVAL);
        check_eq(uapi16_data_check_update(c, "lo", 2, &e), 0);
        check_eq(uapi16_data_check_finish(c, &size, &e), 0);
        check_eq(size, 5);

        /* A check that is finished takes nothing more. */
        size = 77;
        check_ended(uapi16_data_check_finish(c, &size, &e), &e);
        check_ended(uapi16_data_check_update(c, "x", 1, &e), &e);
        check_eq(uapi16_data_check_finish(c, NULL, NULL), -ESTALE);
        check_eq(uapi16_data_check_update(c, NULL, 0, NULL), -ESTALE);
        check_eq(size, 77);
        /* A call that is not valid fails for that still. */
        check_misuse(uapi16_data_check_update(c, NULL, 1, &e), &e, EINVAL);

        /* Data of the size the object says and of another hash, which
         * shows when the check finishes. The check is finished then, as
         * one that succeeded is. */
        check_eq(uapi16_data_check_update(wrong, "hallo", 5, &e), 0);
        r = uapi16_data_check_finish(wrong, &size, &e);
        check_error(r, e, UAPI16_ERROR_HASH_MISMATCH, EBADMSG, "data", 0);
        e = uapi16_error_free(e);
        check_eq(size, 77);
        check_ended(uapi16_data_check_finish(wrong, &size, &e), &e);
        check_ended(uapi16_data_check_update(wrong, "x", 1, &e), &e);

        /* Less data than the object says, which shows when the check
         * finishes as well. */
        check_eq(uapi16_data_check_update(little, "hell", 4, &e), 0);
        r = uapi16_data_check_finish(little, NULL, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "data", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_data_check_finish(little, NULL, NULL), -ESTALE);

        /* An object that gives a size alone, one that gives a hash alone,
         * and one that gives neither, which any data matches. No place
         * for the size is fine. */
        check_eq(uapi16_file_object_set_size(sized, 3), 0);
        check_eq(uapi16_data_check_new(sized, &unfinished), 0);
        check_eq(uapi16_data_check_update(unfinished, "any", 3, &e), 0);
        check_eq(uapi16_data_check_finish(unfinished, NULL, &e), 0);
        unfinished = uapi16_data_check_free(unfinished);
        check(!unfinished);
        unhex(SHA256_OF_ABC, &hash);
        check_eq(uapi16_file_object_set_sha256(hashed, &hash), 0);
        check_eq(uapi16_data_check_new(hashed, &unfinished), 0);
        check_eq(uapi16_data_check_update(unfinished, "abc", 3, &e), 0);
        check_eq(uapi16_data_check_finish(unfinished, &size, &e), 0);
        check_eq(size, 3);
        unfinished = uapi16_data_check_free(unfinished);
        check_eq(uapi16_data_check_new(hashed, &unfinished), 0);
        check_eq(uapi16_data_check_update(unfinished, "abcd", 4, &e), 0);
        r = uapi16_data_check_finish(unfinished, &size, &e);
        check_error(r, e, UAPI16_ERROR_HASH_MISMATCH, EBADMSG, "hashed", 0);
        e = uapi16_error_free(e);
        unfinished = uapi16_data_check_free(unfinished);
        check_eq(uapi16_data_check_new(plain, &unfinished), 0);
        check_eq(uapi16_data_check_update(unfinished, "whatever", 8, &e), 0);
        check_eq(uapi16_data_check_finish(unfinished, &size, &e), 0);
        check_eq(size, 8);
        unfinished = uapi16_data_check_free(unfinished);

        /* A check that is freed before it finished. */
        check_eq(uapi16_data_check_new(sized, &unfinished), 0);
        check_eq(uapi16_data_check_update(unfinished, "an", 2, &e), 0);
        check(!e);

        /* Freeing returns NULL, and takes NULL. */
        check(!uapi16_data_check_free(NULL));
}

/* The directory the files of a manifest are taken from: a descriptor of
 * it, which may be one that only names it, and how its names are looked
 * up. */
static void test_directories(void) {
        static const int no_descriptors[] = { -1, AT_FDCWD, INT_MIN };
        static const uint64_t no_flags[] = { UINT64_C(1) << 1, UINT64_C(1) << 63, UINT64_MAX };
        _cleanup_(closep) int dir = make_dir(tmp_fd, "directory");
        _cleanup_(closep) int path = openat(tmp_fd, "directory", O_PATH | O_DIRECTORY | O_CLOEXEC);
        _cleanup_(uapi16_directory_freep) uapi16_directory *d = NULL, *following = NULL, *named = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *none = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL;

        check(path >= 0);
        check_eq(uapi16_directory_new(dir, UAPI16_DIRECTORY_NONE, &d, &e), 0);
        check(d && !e);
        check_eq(uapi16_directory_new(dir, UAPI16_DIRECTORY_FOLLOW_SYMLINKS, &following, &e), 0);
        check(following);
        check_eq(uapi16_directory_new(path, UAPI16_DIRECTORY_NONE, &named, NULL), 0);
        check(named);

        /* It needs a descriptor, flags that are some, and a place to go
         * to. */
        for (size_t i = 0; i < ELEMENTSOF(no_descriptors); i++)
                check_misuse(uapi16_directory_new(no_descriptors[i], UAPI16_DIRECTORY_NONE, &none, &e), &e, EBADF);
        for (size_t i = 0; i < ELEMENTSOF(no_flags); i++)
                check_misuse(uapi16_directory_new(dir, no_flags[i], &none, &e), &e, EINVAL);
        check_misuse(uapi16_directory_new(dir, UAPI16_DIRECTORY_NONE, NULL, &e), &e, EINVAL);
        check_eq(uapi16_directory_new(-1, UAPI16_DIRECTORY_NONE, &none, NULL), -EBADF);
        check_eq(uapi16_directory_new(dir, UINT64_C(1) << 1, &none, NULL), -EINVAL);
        check_eq(uapi16_directory_new(dir, UAPI16_DIRECTORY_NONE, NULL, NULL), -EINVAL);
        check(!none);

        /* Freeing returns NULL, and takes NULL. */
        d = uapi16_directory_free(d);
        check(!d);
        check(!uapi16_directory_free(NULL));
}

/* What qsort() compares two names with. */
static int compare_names(const void *a, const void *b) {
        return uapi16_name_compare(*(const char *const *) a, *(const char *const *) b);
}

/* Checks that the options `o` record the features of `expected`: those of
 * a manifest that a writer of records writes for them. */
static void check_options_record(const uapi16_manifest_options *o, struct features expected) {
        _cleanup_(closep) int fd = scratch_file();
        _cleanup_(uapi16_writer_freep) uapi16_writer *w = begin_records(o, fd);
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;

        check_eq(uapi16_writer_finish(w, NULL), 0);
        reader = open_reader(fd);
        check_recorded(reader, expected);
}

/*
 * A list of features is an array and its length. A call that takes one
 * passes over UAPI16_FEATURE_NONE, takes a feature that is there more than
 * once as one, and reads nothing of a list without a length. Where one
 * number of the list is no feature the call fails and changes nothing.
 * uapi16_feature_probe() turns the numbers that are no features into
 * UAPI16_FEATURE_NONE where they are, and says how many they were. The
 * getters give the features by their place, and none past the last one.
 */
static void test_feature_lists(void) {
        static const uapi16_feature_t twice[] = {
                UAPI16_FEATURE_MTIME, UAPI16_FEATURE_NONE, UAPI16_FEATURE_SIZE,
                UAPI16_FEATURE_MTIME, UAPI16_FEATURE_NONE, UAPI16_FEATURE_SIZE,
        };
        static const uapi16_feature_t none[] = { UAPI16_FEATURE_NONE, UAPI16_FEATURE_NONE };
        /* (1 << 32) + UAPI16_FEATURE_MODE is that feature in its low 32 bits. */
        static const uapi16_feature_t no_features[] = {
                NO_FEATURE, UINT64_C(1) << 31, (UINT64_C(1) << 32) + UAPI16_FEATURE_MODE,
                UINT64_C(1) << 63, UINT64_MAX,
        };
        _cleanup_(closep) int fd = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_hello("file");
        _cleanup_(uapi16_writer_freep) uapi16_writer *records = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        uapi16_feature_t probed[] = {
                UAPI16_FEATURE_SIZE, NO_FEATURE, UAPI16_FEATURE_NONE,
                UAPI16_FEATURE_FAT_SERIAL, UINT64_MAX, UAPI16_FEATURE_MODE,
        };
        struct features every = EVERY_FEATURE, stated;

        /* The probe turns off what is no feature, where it is, and counts
         * it. What is a feature and what is none already stays. */
        check_eq(uapi16_feature_probe(probed, ELEMENTSOF(probed)), 2);
        check_eq(probed[0], UAPI16_FEATURE_SIZE);
        check_eq(probed[1], UAPI16_FEATURE_NONE);
        check_eq(probed[2], UAPI16_FEATURE_NONE);
        check_eq(probed[3], UAPI16_FEATURE_FAT_SERIAL);
        check_eq(probed[4], UAPI16_FEATURE_NONE);
        check_eq(probed[5], UAPI16_FEATURE_MODE);
        check_eq(uapi16_feature_probe(probed, ELEMENTSOF(probed)), 0);
        check_eq(uapi16_feature_probe(probed, 0), 0);
        check_eq(uapi16_feature_probe(NULL, 0), 0);
        check_eq(uapi16_feature_probe(NULL, ELEMENTSOF(probed)), 0);
        /* The library has every feature of its own header, and the list of
         * UAPI16_FEATURES() is one the probe can write to. */
        check_eq(uapi16_feature_probe(every.list, every.n), 0);
        check_same_features(every, EVERY_FEATURE);
        check_eq(uapi16_feature_probe(UAPI16_FEATURES(UAPI16_FEATURE_FS_UUID, UAPI16_FEATURE_FS_LABEL)), 0);
        check_eq(uapi16_feature_probe(UAPI16_FEATURES(UAPI16_FEATURE_FS_UUID, NO_FEATURE, NO_FEATURE)), 2);

        /* New options record the default features. What the probe left is
         * a list for them: UAPI16_FEATURE_NONE in it is passed over. */
        check_options_record(o, FEATURES(DEFAULT_FEATURES));
        check_eq(uapi16_manifest_options_set_features(o, probed, ELEMENTSOF(probed)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE, UAPI16_FEATURE_FAT_SERIAL));

        /* A feature that is in a list more than once is in it once, in the
         * three calls of the options. */
        check_eq(uapi16_manifest_options_set_features(o, twice, ELEMENTSOF(twice)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        check_eq(uapi16_manifest_options_add_features(o, twice, ELEMENTSOF(twice)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        check_eq(uapi16_manifest_options_add_features(
                         o, UAPI16_FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_MODE, UAPI16_FEATURE_NONE)),
                 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        check_eq(uapi16_manifest_options_remove_features(o, twice, ELEMENTSOF(twice)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_MODE));
        /* Taking away what is not there takes nothing away. */
        check_eq(uapi16_manifest_options_remove_features(o, twice, ELEMENTSOF(twice)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_MODE));

        /* A list of UAPI16_FEATURE_NONE alone and a list without a length
         * are lists of no feature. Nothing is read of the second one. */
        check_eq(uapi16_manifest_options_add_features(o, none, ELEMENTSOF(none)), 0);
        check_eq(uapi16_manifest_options_remove_features(o, none, ELEMENTSOF(none)), 0);
        check_eq(uapi16_manifest_options_add_features(o, NULL, 0), 0);
        check_eq(uapi16_manifest_options_remove_features(o, NULL, 0), 0);
        check_eq(uapi16_manifest_options_add_features(o, twice, 0), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_MODE));
        check_eq(uapi16_manifest_options_set_features(o, none, ELEMENTSOF(none)), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_manifest_options_add_features(o, UAPI16_FEATURES(UAPI16_FEATURE_UID)), 0);
        check_eq(uapi16_manifest_options_set_features(o, NULL, 0), 0);
        check_options_record(o, FEATURES(UAPI16_FEATURE_NONE));

        /* A number that is no feature fails the whole call, wherever it is
         * in the list, and the options are as they were. So does a list
         * that is not there, and so do options that are not there. */
        check_eq(uapi16_manifest_options_set_features(o, UAPI16_FEATURES(UAPI16_FEATURE_GID)), 0);
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++) {
                uapi16_feature_t first[] = { no_features[i], UAPI16_FEATURE_MTIME, UAPI16_FEATURE_GID };
                uapi16_feature_t last[] = { UAPI16_FEATURE_MTIME, UAPI16_FEATURE_GID, no_features[i] };

                check_eq(uapi16_manifest_options_set_features(o, first, ELEMENTSOF(first)), -EINVAL);
                check_eq(uapi16_manifest_options_set_features(o, last, ELEMENTSOF(last)), -EINVAL);
                check_eq(uapi16_manifest_options_add_features(o, first, ELEMENTSOF(first)), -EINVAL);
                check_eq(uapi16_manifest_options_add_features(o, last, ELEMENTSOF(last)), -EINVAL);
                check_eq(uapi16_manifest_options_remove_features(o, first, ELEMENTSOF(first)), -EINVAL);
                check_eq(uapi16_manifest_options_remove_features(o, last, ELEMENTSOF(last)), -EINVAL);
                check_options_record(o, FEATURES(UAPI16_FEATURE_GID));
        }
        check_eq(uapi16_manifest_options_set_features(o, NULL, 1), -EINVAL);
        check_eq(uapi16_manifest_options_add_features(o, NULL, 1), -EINVAL);
        check_eq(uapi16_manifest_options_remove_features(o, NULL, 1), -EINVAL);
        check_options_record(o, FEATURES(UAPI16_FEATURE_GID));
        check_eq(uapi16_manifest_options_set_features(NULL, twice, ELEMENTSOF(twice)), -EINVAL);
        check_eq(uapi16_manifest_options_add_features(NULL, twice, ELEMENTSOF(twice)), -EINVAL);
        check_eq(uapi16_manifest_options_remove_features(NULL, twice, ELEMENTSOF(twice)), -EINVAL);

        /* The object keeps the fields of the features of a list, in the
         * same way: it has the size and the hash of its data, and gets a
         * time. */
        check_eq(uapi16_file_object_set_mtime_nsec(file, 1), 0);
        stated = FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_SHA256, UAPI16_FEATURE_MTIME);
        check_stated(file, stated);
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++) {
                uapi16_feature_t first[] = { no_features[i], UAPI16_FEATURE_SIZE };
                uapi16_feature_t last[] = { UAPI16_FEATURE_SIZE, no_features[i] };

                check_eq(uapi16_file_object_retain_features(file, first, ELEMENTSOF(first)), -EINVAL);
                check_eq(uapi16_file_object_retain_features(file, last, ELEMENTSOF(last)), -EINVAL);
                check_stated(file, stated);
        }
        check_eq(uapi16_file_object_retain_features(file, NULL, 1), -EINVAL);
        check_eq(uapi16_file_object_retain_features(NULL, twice, ELEMENTSOF(twice)), -EINVAL);
        check_stated(file, stated);
        check_eq(uapi16_file_object_retain_features(file, twice, ELEMENTSOF(twice)), 0);
        check_stated(file, FEATURES(UAPI16_FEATURE_SIZE, UAPI16_FEATURE_MTIME));
        check_eq(uapi16_file_object_retain_features(file, none, ELEMENTSOF(none)), 0);
        check_stated(file, FEATURES(UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_set_mtime_nsec(file, 1), 0);
        check_eq(uapi16_file_object_retain_features(file, NULL, 0), 0);
        check_stated(file, FEATURES(UAPI16_FEATURE_NONE));

        /* The getters by place: the features in the order of their
         * numbers, and none past the last one. A number that is no feature
         * is no feature of a manifest or of an object, and neither has one
         * where there is no reader and no object. */
        check_eq(uapi16_manifest_options_set_features(
                         o, UAPI16_FEATURES(UAPI16_FEATURE_MTIME, UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE)),
                 0);
        records = begin_records(o, fd);
        check_eq(uapi16_writer_finish(records, NULL), 0);
        reader = open_reader(fd);
        check_eq(uapi16_reader_feature(reader, 0), UAPI16_FEATURE_MODE);
        check_eq(uapi16_reader_feature(reader, 1), UAPI16_FEATURE_SIZE);
        check_eq(uapi16_reader_feature(reader, 2), UAPI16_FEATURE_MTIME);
        check_eq(uapi16_reader_feature(reader, 3), UAPI16_FEATURE_NONE);
        check_eq(uapi16_reader_feature(reader, 4), UAPI16_FEATURE_NONE);
        check_eq(uapi16_reader_feature(reader, SIZE_MAX), UAPI16_FEATURE_NONE);
        check(uapi16_reader_has_feature(reader, UAPI16_FEATURE_MTIME));
        check(!uapi16_reader_has_feature(reader, UAPI16_FEATURE_UID));
        check(!uapi16_reader_has_feature(reader, UAPI16_FEATURE_NONE));
        check_eq(uapi16_file_object_set_mode(file, 0644), 0);
        check_eq(uapi16_file_object_set_mtime_nsec(file, 1), 0);
        check_eq(uapi16_file_object_stated_feature(file, 0), UAPI16_FEATURE_MODE);
        check_eq(uapi16_file_object_stated_feature(file, 1), UAPI16_FEATURE_MTIME);
        check_eq(uapi16_file_object_stated_feature(file, 2), UAPI16_FEATURE_NONE);
        check_eq(uapi16_file_object_stated_feature(file, SIZE_MAX), UAPI16_FEATURE_NONE);
        check(uapi16_file_object_has_stated_feature(file, UAPI16_FEATURE_MODE));
        check(!uapi16_file_object_has_stated_feature(file, UAPI16_FEATURE_SIZE));
        check(!uapi16_file_object_has_stated_feature(file, UAPI16_FEATURE_NONE));
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++) {
                check(!uapi16_reader_has_feature(reader, no_features[i]));
                check(!uapi16_file_object_has_stated_feature(file, no_features[i]));
        }
        check(!uapi16_reader_has_feature(NULL, UAPI16_FEATURE_MODE));
        check_eq(uapi16_reader_feature(NULL, 0), UAPI16_FEATURE_NONE);
        check(!uapi16_file_object_has_stated_feature(NULL, UAPI16_FEATURE_MODE));
        check_eq(uapi16_file_object_stated_feature(NULL, 0), UAPI16_FEATURE_NONE);
}

/*
 * The order of names, which is that of a manifest, and the names of the
 * features, which are those of the specification.
 */
static void test_names_and_features(void) {
        /* The names of the files of a tree in the order of a manifest: a
         * directory right before what is in it, which is not the order of
         * their bytes. */
        static const char *const sorted[] = {
                "a",  "a/x", "a/x/y", "a/y", "a-b", "a-b/c", "a.b", "a0",
                "b", "\xc3\xa9", "\xef\xbd\xa1", "\xf0\x9f\x98\x80",
        };
        static const struct {
                uapi16_feature_t feature;
                const char *name;
        } features[] = {
                { UAPI16_FEATURE_MODE, "mode" },
                { UAPI16_FEATURE_UID, "uid" },
                { UAPI16_FEATURE_GID, "gid" },
                { UAPI16_FEATURE_USER_NAME, "user-name" },
                { UAPI16_FEATURE_GROUP_NAME, "group-name" },
                { UAPI16_FEATURE_SIZE, "size" },
                { UAPI16_FEATURE_SHA256, "sha256" },
                { UAPI16_FEATURE_SYMLINK, "symlink" },
                { UAPI16_FEATURE_DEVICE, "device" },
                { UAPI16_FEATURE_HARDLINK, "hardlink" },
                { UAPI16_FEATURE_MTIME, "mtime" },
                { UAPI16_FEATURE_USER_XATTR, "user-xattr" },
                { UAPI16_FEATURE_FLAG_HIDDEN, "flag-hidden" },
                { UAPI16_FEATURE_FLAG_SYSTEM, "flag-system" },
                { UAPI16_FEATURE_FLAG_ARCHIVE, "flag-archive" },
                { UAPI16_FEATURE_FLAG_APPEND_ONLY, "flag-append-only" },
                { UAPI16_FEATURE_FLAG_IMMUTABLE, "flag-immutable" },
                { UAPI16_FEATURE_FLAG_NO_ATIME, "flag-no-atime" },
                { UAPI16_FEATURE_FLAG_NO_COW, "flag-no-cow" },
                { UAPI16_FEATURE_FLAG_NO_DUMP, "flag-no-dump" },
                { UAPI16_FEATURE_READ_ONLY, "read-only" },
                { UAPI16_FEATURE_FS_UUID, "fs-uuid" },
                { UAPI16_FEATURE_FS_LABEL, "fs-label" },
                { UAPI16_FEATURE_FAT_SERIAL, "fat-serial" },
                { UAPI16_FEATURE_GPT_LABEL, "gpt-label" },
                { UAPI16_FEATURE_GPT_UUID, "gpt-uuid" },
                { UAPI16_FEATURE_GPT_TYPE_UUID, "gpt-type-uuid" },
                { UAPI16_FEATURE_GPT_DISK_UUID, "gpt-disk-uuid" },
                { UAPI16_FEATURE_GPT_FLAGS, "gpt-flags" },
                { UAPI16_FEATURE_GPT_FLAG_NO_AUTO, "gpt-flag-no-auto" },
                { UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM, "gpt-flag-grow-file-system" },
        };
        /* (1 << 32) + UAPI16_FEATURE_MODE is that feature in its low 32 bits. */
        static const uapi16_feature_t no_features[] = {
                UAPI16_FEATURE_NONE, NO_FEATURE, UINT64_C(1) << 31,
                (UINT64_C(1) << 32) + UAPI16_FEATURE_MODE, UINT64_C(1) << 63, UINT64_MAX,
        };
        static const char *const no_feature_names[] = { "", "none", "MODE", "mode ", "user_xattr", "\xff" };
        _cleanup_(closep) int written = scratch_file();
        _cleanup_(uapi16_manifest_options_freep) uapi16_manifest_options *o = uapi16_manifest_options_new();
        _cleanup_(uapi16_manifest_writer_freep) uapi16_manifest_writer *w = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        const char *names[ELEMENTSOF(sorted)];

        /* Two names compare as one of three numbers, those of the
         * comparison function of qsort(). */
        check_eq(uapi16_name_compare("a/x", "a-b"), UAPI16_NAME_BEFORE);
        check_eq(uapi16_name_compare("a-b", "a/x"), UAPI16_NAME_AFTER);
        check_eq(uapi16_name_compare("a/x", "a/x"), UAPI16_NAME_SAME);
        check(strcmp("a/x", "a-b") > 0);
        for (size_t i = 0; i < ELEMENTSOF(sorted); i++)
                for (size_t j = 0; j < ELEMENTSOF(sorted); j++) {
                        int order = uapi16_name_compare(sorted[i], sorted[j]);

                        if (i < j)
                                check_eq(order, UAPI16_NAME_BEFORE);
                        else if (i > j)
                                check_eq(order, UAPI16_NAME_AFTER);
                        else
                                check_eq(order, UAPI16_NAME_SAME);
                }

        /* No name is the empty name, which is that of the root and comes
         * first. */
        check_eq(uapi16_name_compare(NULL, NULL), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare(NULL, ""), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare("", NULL), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare(NULL, "a"), UAPI16_NAME_BEFORE);
        check_eq(uapi16_name_compare("a", NULL), UAPI16_NAME_AFTER);
        check_eq(uapi16_name_compare("", "a"), UAPI16_NAME_BEFORE);

        /* Strings that are not UTF-8 are no names. What is not UTF-8 in
         * them is replaced by U+FFFD, and they are compared after that, so
         * two different ones can be the same. */
        check_eq(uapi16_name_compare("\xff", "\xfe"), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare("a\xff" "b", "a\xfe" "b"), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare("\xff", "\xef\xbf\xbd"), UAPI16_NAME_SAME);
        check_eq(uapi16_name_compare("\xff", "a"), UAPI16_NAME_AFTER);
        check_eq(uapi16_name_compare("a", "\xff"), UAPI16_NAME_BEFORE);

        /* Names in any order are put into the order of a manifest with
         * qsort(). */
        for (size_t i = 0; i < ELEMENTSOF(sorted); i++)
                names[i] = sorted[(i * 7 + 3) % ELEMENTSOF(sorted)];
        qsort(names, ELEMENTSOF(names), sizeof(names[0]), compare_names);
        for (size_t i = 0; i < ELEMENTSOF(sorted); i++)
                check_str(names[i], sorted[i]);

        /* That is the order a writer lists file objects of these names
         * in, whatever order they came in, and the order a reader takes
         * them in. */
        check_eq(set_features(o, FEATURES(UAPI16_FEATURE_NONE)), 0);
        check_eq(uapi16_manifest_writer_open(o, written, &w, NULL), 0);
        for (size_t i = 0; i < ELEMENTSOF(sorted); i++) {
                const char *name = sorted[(i * 5 + 1) % ELEMENTSOF(sorted)];
                _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object(name);
                bool directory = strcmp(name, "a") == 0 || strcmp(name, "a/x") == 0;

                /* What has files below it is a directory. */
                directory = directory || strcmp(name, "a-b") == 0;
                check_eq(uapi16_file_object_set_type(file, directory ? S_IFDIR : S_IFREG), 0);
                check_eq(uapi16_manifest_writer_add_object(w, file, NULL), 0);
        }
        check_eq(uapi16_manifest_writer_finish(w, NULL, NULL), 0);
        w = uapi16_manifest_writer_free(w);
        reader = open_reader(written);
        check_eq(uapi16_reader_require_order(reader, UAPI16_ORDER_CODEPOINT, NULL), 0);
        for (size_t i = 0; i < ELEMENTSOF(sorted); i++) {
                uapi16_file_object *file = next_object(reader, sorted[i]);

                check(!uapi16_file_object_free(file));
        }
        check_ends(reader);

        /* Every feature has the name the specification has for it, which
         * leads back to the feature. The name is a constant of the
         * library: the same string every time. The features are numbered
         * from 1 without a gap, so these are all of them. */
        check_eq(ELEMENTSOF(features), LAST_FEATURE_OF_PARTITIONS);
        for (size_t i = 0; i < ELEMENTSOF(features); i++) {
                const char *name = uapi16_feature_name(features[i].feature);

                check_eq(features[i].feature, i + 1);
                check_str(name, features[i].name);
                check(uapi16_feature_name(features[i].feature) == name);
                check_eq(uapi16_feature_from_name(name), features[i].feature);
                check_eq(uapi16_feature_from_name(features[i].name), features[i].feature);
        }

        /* A number that is no feature has no name, and a name that no
         * feature has is no feature. */
        for (size_t i = 0; i < ELEMENTSOF(no_features); i++)
                check(!uapi16_feature_name(no_features[i]));
        for (size_t i = 0; i < ELEMENTSOF(no_feature_names); i++)
                check_eq(uapi16_feature_from_name(no_feature_names[i]), UAPI16_FEATURE_NONE);
        check_eq(uapi16_feature_from_name(NULL), UAPI16_FEATURE_NONE);
}

/*
 * The numbers of the enums never change, so every one of them is pinned
 * here: a change of any fails this test. Every enum is 64 bits wide, and
 * uapi16_name_order_t is the one that is signed.
 */
static void test_numbers(void) {
        /* uapi16_feature_t: a number each from 1, in the order of the header. */
        check_eq(UAPI16_FEATURE_NONE, 0);
        check_eq(UAPI16_FEATURE_MODE, 1);
        check_eq(UAPI16_FEATURE_UID, 2);
        check_eq(UAPI16_FEATURE_GID, 3);
        check_eq(UAPI16_FEATURE_USER_NAME, 4);
        check_eq(UAPI16_FEATURE_GROUP_NAME, 5);
        check_eq(UAPI16_FEATURE_SIZE, 6);
        check_eq(UAPI16_FEATURE_SHA256, 7);
        check_eq(UAPI16_FEATURE_SYMLINK, 8);
        check_eq(UAPI16_FEATURE_DEVICE, 9);
        check_eq(UAPI16_FEATURE_HARDLINK, 10);
        check_eq(UAPI16_FEATURE_MTIME, 11);
        check_eq(UAPI16_FEATURE_USER_XATTR, 12);
        check_eq(UAPI16_FEATURE_FLAG_HIDDEN, 13);
        check_eq(UAPI16_FEATURE_FLAG_SYSTEM, 14);
        check_eq(UAPI16_FEATURE_FLAG_ARCHIVE, 15);
        check_eq(UAPI16_FEATURE_FLAG_APPEND_ONLY, 16);
        check_eq(UAPI16_FEATURE_FLAG_IMMUTABLE, 17);
        check_eq(UAPI16_FEATURE_FLAG_NO_ATIME, 18);
        check_eq(UAPI16_FEATURE_FLAG_NO_COW, 19);
        check_eq(UAPI16_FEATURE_FLAG_NO_DUMP, 20);
        check_eq(UAPI16_FEATURE_READ_ONLY, 21);
        check_eq(UAPI16_FEATURE_FS_UUID, 22);
        check_eq(UAPI16_FEATURE_FS_LABEL, 23);
        check_eq(UAPI16_FEATURE_FAT_SERIAL, 24);
        check_eq(UAPI16_FEATURE_GPT_LABEL, 25);
        check_eq(UAPI16_FEATURE_GPT_UUID, 26);
        check_eq(UAPI16_FEATURE_GPT_TYPE_UUID, 27);
        check_eq(UAPI16_FEATURE_GPT_DISK_UUID, 28);
        check_eq(UAPI16_FEATURE_GPT_FLAGS, 29);
        check_eq(UAPI16_FEATURE_GPT_FLAG_NO_AUTO, 30);
        check_eq(UAPI16_FEATURE_GPT_FLAG_GROW_FILE_SYSTEM, 31);

        /* uapi16_order_t. */
        check_eq(UAPI16_ORDER_NONE, 0);
        check_eq(UAPI16_ORDER_CODEPOINT, 1);

        /* uapi16_add_flag_t. */
        check_eq(UAPI16_ADD_NONE, 0);
        check_eq(UAPI16_ADD_CROSS_MOUNTS, 1 << 0);
        check_eq(UAPI16_ADD_GRACEFUL, 1 << 1);

        /* uapi16_error_kind_t: 1 to 21, without a gap. */
        check_eq(UAPI16_ERROR_IO, 1);
        check_eq(UAPI16_ERROR_EXISTS, 2);
        check_eq(UAPI16_ERROR_DUPLICATE, 3);
        check_eq(UAPI16_ERROR_CHANGED, 4);
        check_eq(UAPI16_ERROR_HARDLINK_MISMATCH, 5);
        check_eq(UAPI16_ERROR_UNWRITABLE_NAME, 6);
        check_eq(UAPI16_ERROR_NOT_DIRECTORY, 7);
        check_eq(UAPI16_ERROR_UNSUPPORTED, 8);
        check_eq(UAPI16_ERROR_INVALID_ARGUMENT, 9);
        check_eq(UAPI16_ERROR_LOOP, 10);
        check_eq(UAPI16_ERROR_MISSING_PARENT, 11);
        check_eq(UAPI16_ERROR_TOO_LARGE, 12);
        check_eq(UAPI16_ERROR_ENDED, 13);
        check_eq(UAPI16_ERROR_MANIFEST, 14);
        check_eq(UAPI16_ERROR_SOURCE_MISSING, 15);
        check_eq(UAPI16_ERROR_SOURCE_NOT_REGULAR, 16);
        check_eq(UAPI16_ERROR_SIZE_MISMATCH, 17);
        check_eq(UAPI16_ERROR_HASH_MISMATCH, 18);
        check_eq(UAPI16_ERROR_REVOKED, 19);
        check_eq(UAPI16_ERROR_NOT_YET_VALID, 20);
        check_eq(UAPI16_ERROR_EXPIRED, 21);

        /* uapi16_name_problem_t. */
        check_eq(UAPI16_NAME_PROBLEM_NOT_UTF8, 1);
        check_eq(UAPI16_NAME_PROBLEM_EMPTY, 2);
        check_eq(UAPI16_NAME_PROBLEM_TOO_LONG, 3);
        check_eq(UAPI16_NAME_PROBLEM_RESERVED, 4);
        check_eq(UAPI16_NAME_PROBLEM_CONTROL_CHARACTER, 5);
        check_eq(UAPI16_NAME_PROBLEM_NONCHARACTER, 6);
        check_eq(UAPI16_NAME_PROBLEM_EMPTY_COMPONENT, 7);
        check_eq(UAPI16_NAME_PROBLEM_DOT_COMPONENT, 8);

        /* uapi16_read_only_t. */
        check_eq(UAPI16_READ_ONLY_UNSTATED, 0);
        check_eq(UAPI16_READ_ONLY_NO, 1);
        check_eq(UAPI16_READ_ONLY_YES, 2);

        /* uapi16_name_order_t: what a comparison function of qsort()
         * returns. */
        check_eq(UAPI16_NAME_BEFORE, -1);
        check_eq(UAPI16_NAME_SAME, 0);
        check_eq(UAPI16_NAME_AFTER, 1);

        /* uapi16_read_t. */
        check_eq(UAPI16_READ_END, 0);
        check_eq(UAPI16_READ_FILE, 1);
        check_eq(UAPI16_READ_SIGNATURES, 2);
        check_eq(UAPI16_READ_SIGNATURE, 3);

        /* uapi16_data_location_t. */
        check_eq(UAPI16_DATA_LOCATION_NONE, 0);
        check_eq(UAPI16_DATA_LOCATION_LITERAL, 1);
        check_eq(UAPI16_DATA_LOCATION_EXTERNAL, 2);
        check_eq(UAPI16_DATA_LOCATION_UNSUPPORTED, 3);

        /* uapi16_directory_flag_t. */
        check_eq(UAPI16_DIRECTORY_NONE, 0);
        check_eq(UAPI16_DIRECTORY_FOLLOW_SYMLINKS, 1 << 0);

        /* Every enum is 64 bits wide. */
        check_eq(sizeof(uapi16_feature_t), 8);
        check_eq(sizeof(uapi16_order_t), 8);
        check_eq(sizeof(uapi16_add_flag_t), 8);
        check_eq(sizeof(uapi16_error_kind_t), 8);
        check_eq(sizeof(uapi16_name_problem_t), 8);
        check_eq(sizeof(uapi16_read_only_t), 8);
        check_eq(sizeof(uapi16_name_order_t), 8);
        check_eq(sizeof(uapi16_read_t), 8);
        check_eq(sizeof(uapi16_data_location_t), 8);
        check_eq(sizeof(uapi16_directory_flag_t), 8);

        /* One of them is signed, and the others are not. */
        check((uapi16_name_order_t) -1 < 0);
        check((uapi16_feature_t) -1 > 0 && (uapi16_order_t) -1 > 0 && (uapi16_add_flag_t) -1 > 0);
        check((uapi16_error_kind_t) -1 > 0 && (uapi16_name_problem_t) -1 > 0);
        check((uapi16_read_only_t) -1 > 0 && (uapi16_read_t) -1 > 0);
        check((uapi16_data_location_t) -1 > 0 && (uapi16_directory_flag_t) -1 > 0);

        /* A set of flags is as wide as a flag, and has no sign. */
        check_eq(sizeof(uapi16_add_flags_t), sizeof(uapi16_add_flag_t));
        check_eq(sizeof(uapi16_directory_flags_t), sizeof(uapi16_directory_flag_t));
        check((uapi16_add_flags_t) -1 > 0 && (uapi16_directory_flags_t) -1 > 0);

        /* The token of a file is as wide and has no sign, and 0 is none. */
        check_eq(sizeof(uapi16_inode_token_t), 8);
        check((uapi16_inode_token_t) -1 > 0);
        check_eq(UAPI16_INODE_TOKEN_NONE, 0);

        /* A UUID is as large as its constant says, and aligned as the
         * larger of its two members is. So is a hash. */
        check_eq(sizeof(uapi16_uuid_t), UAPI16_UUID_SIZE);
        check_eq(_Alignof(uapi16_uuid_t), _Alignof(uint64_t));
        check_eq(sizeof(uapi16_sha256_digest_t), UAPI16_SHA256_SIZE);
        check_eq(_Alignof(uapi16_sha256_digest_t), _Alignof(uint64_t));
}

/* The SHA-256 hashes of one zero byte, of a block of them and of 1 MiB of
 * them, and of data with a hole in it: "head", 70000 zero bytes, "tail". */
#define SHA256_OF_A_ZERO "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
#define SHA256_OF_A_BLOCK_OF_ZEROS "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"
#define SHA256_OF_A_MEBIBYTE_OF_ZEROS "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
#define SHA256_OF_SPARSE "dc88e94cb1c1c9c8d87cddab651038ca0bd748af7e7e8a7b714a26f842a9acd6"
#define HOLE 70000
#define SPARSE_SIZE (4 + HOLE + 4)

/*
 * Zero bytes that a caller did not read, such as a hole of a sparse file,
 * count as data: uapi16_sha256_update_zeros() hashes them as
 * uapi16_sha256_update() hashes as many bytes that are zero, and
 * uapi16_data_check_update_zeros() holds them against the size and the hash
 * of a file object as uapi16_data_check_update() holds such bytes.
 */
static void test_zeros(void) {
        /* None, one, and the sizes around the 64 bytes of a block of the
         * hash and around the 56 its padding starts at. */
        static const uint64_t sizes[] = { 0, 1, 2, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129,
                                          4095, 4096, 4097, HOLE, 1024 * 1024 + 3 };
        static const char zeros[4096];
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *s = NULL, *finished = uapi16_sha256_new();
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *sparse = make_object("sparse");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *sized = make_object("sized");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *plain = make_object("plain");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *no_object = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *c = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *held = NULL;
        uapi16_sha256_digest_t hash, expected;
        uint64_t size = 77;
        int r;

        /* Known hashes of zero bytes alone: one, a block, and 1 MiB in
         * pieces of many sizes. No zero bytes are no data. */
        s = uapi16_sha256_new();
        check_eq(uapi16_sha256_update_zeros(s, 0), 0);
        check_eq(uapi16_sha256_finish(s, &hash), 0);
        check_hash(&hash, SHA256_OF_NOTHING);
        s = uapi16_sha256_free(s);
        s = uapi16_sha256_new();
        check_eq(uapi16_sha256_update_zeros(s, 1), 0);
        check_eq(uapi16_sha256_finish(s, &hash), 0);
        check_hash(&hash, SHA256_OF_A_ZERO);
        s = uapi16_sha256_free(s);
        s = uapi16_sha256_new();
        check_eq(uapi16_sha256_update_zeros(s, 64), 0);
        check_eq(uapi16_sha256_finish(s, &hash), 0);
        check_hash(&hash, SHA256_OF_A_BLOCK_OF_ZEROS);
        s = uapi16_sha256_free(s);
        s = uapi16_sha256_new();
        for (uint64_t done = 0, piece = 1; done < 1024 * 1024; done += piece, piece = piece * 3 + 1) {
                if (piece > 1024 * 1024 - done)
                        piece = 1024 * 1024 - done;
                check_eq(uapi16_sha256_update_zeros(s, piece), 0);
        }
        check_eq(uapi16_sha256_finish(s, &hash), 0);
        check_hash(&hash, SHA256_OF_A_MEBIBYTE_OF_ZEROS);
        s = uapi16_sha256_free(s);

        /* Zero bytes between other data, for every size: the hash is the
         * one of the same bytes through uapi16_sha256_update(). */
        for (size_t i = 0; i < ELEMENTSOF(sizes); i++) {
                _cleanup_(uapi16_sha256_freep) uapi16_sha256 *skipped = uapi16_sha256_new();
                _cleanup_(uapi16_sha256_freep) uapi16_sha256 *read = uapi16_sha256_new();

                check_eq(uapi16_sha256_update(skipped, "head", 4), 0);
                check_eq(uapi16_sha256_update_zeros(skipped, sizes[i]), 0);
                check_eq(uapi16_sha256_update(skipped, "tail", 4), 0);
                check_eq(uapi16_sha256_finish(skipped, &hash), 0);
                check_eq(uapi16_sha256_update(read, "head", 4), 0);
                for (uint64_t left = sizes[i]; left > 0;) {
                        size_t piece = left < sizeof(zeros) ? (size_t) left : sizeof(zeros);

                        check_eq(uapi16_sha256_update(read, zeros, piece), 0);
                        left -= piece;
                }
                check_eq(uapi16_sha256_update(read, "tail", 4), 0);
                check_eq(uapi16_sha256_finish(read, &expected), 0);
                check_eq(memcmp(&hash, &expected, sizeof(hash)), 0);
                if (sizes[i] == HOLE)
                        check_hash(&hash, SHA256_OF_SPARSE);
        }

        /* A computation that is finished takes no zero bytes, not even
         * none, and no computation is none to give them to. */
        check_eq(uapi16_sha256_finish(finished, &hash), 0);
        check_eq(uapi16_sha256_update_zeros(finished, 1), -ESTALE);
        check_eq(uapi16_sha256_update_zeros(finished, 0), -ESTALE);
        check_eq(uapi16_sha256_update_zeros(NULL, 1), -EINVAL);
        check_eq(uapi16_sha256_update_zeros(NULL, 0), -EINVAL);

        /* A file with a hole: its object gives the size and the hash of
         * all its bytes. The check takes the hole as the zero bytes it
         * is, between the data that was read. */
        unhex(SHA256_OF_SPARSE, &hash);
        check_eq(uapi16_file_object_set_size(sparse, SPARSE_SIZE), 0);
        check_eq(uapi16_file_object_set_sha256(sparse, &hash), 0);
        check_eq(uapi16_data_check_new(sparse, &c), 0);
        check_eq(uapi16_data_check_update(c, "head", 4, &e), 0);
        check_eq(uapi16_data_check_update_zeros(c, HOLE, &e), 0);
        check_eq(uapi16_data_check_update_zeros(c, 0, &e), 0);
        check_eq(uapi16_data_check_update(c, "tail", 4, &e), 0);
        check_eq(uapi16_data_check_finish(c, &size, &e), 0);
        check_eq(size, SPARSE_SIZE);

        /* A check that is finished takes no zero bytes. */
        check_ended(uapi16_data_check_update_zeros(c, 1, &e), &e);
        check_ended(uapi16_data_check_update_zeros(c, 0, &e), &e);
        check_eq(uapi16_data_check_update_zeros(c, 1, NULL), -ESTALE);
        c = uapi16_data_check_free(c);

        /* More zero bytes than the object has room for are refused, as
         * other bytes are, and none of them is taken: the check goes on
         * with the hole as it is. */
        check_eq(uapi16_data_check_new(sparse, &c), 0);
        check_eq(uapi16_data_check_update(c, "head", 4, &e), 0);
        r = uapi16_data_check_update_zeros(c, HOLE + 5, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "sparse", 0);
        e = uapi16_error_free(e);
        r = uapi16_data_check_update_zeros(c, UINT64_MAX, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "sparse", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_data_check_update_zeros(c, HOLE + 5, NULL), -EBADMSG);
        check_eq(uapi16_data_check_update_zeros(c, HOLE, &e), 0);
        check_eq(uapi16_data_check_update(c, "tail", 4, &e), 0);
        check_eq(uapi16_data_check_finish(c, &size, &e), 0);
        check_eq(size, SPARSE_SIZE);
        c = uapi16_data_check_free(c);

        /* Zero bytes where the data has other bytes are data of the size
         * the object says and of another hash, which shows when the check
         * finishes. */
        check_eq(uapi16_data_check_new(sparse, &c), 0);
        check_eq(uapi16_data_check_update_zeros(c, SPARSE_SIZE, &e), 0);
        size = 77;
        r = uapi16_data_check_finish(c, &size, &e);
        check_error(r, e, UAPI16_ERROR_HASH_MISMATCH, EBADMSG, "sparse", 0);
        e = uapi16_error_free(e);
        check_eq(size, 77);
        c = uapi16_data_check_free(c);

        /* A call that is not valid fails for that, and takes nothing: no
         * check, and a `reterr` that points to something, which is looked
         * at first, also on a check that is finished. */
        check_eq(uapi16_file_object_new("a//b", &no_object, &held), -EINVAL);
        check(held && !no_object);
        check_misuse(uapi16_data_check_update_zeros(NULL, 1, &e), &e, EINVAL);
        check_eq(uapi16_data_check_update_zeros(NULL, 1, NULL), -EINVAL);
        check_eq(uapi16_file_object_set_size(sized, 3), 0);
        check_eq(uapi16_data_check_new(sized, &c), 0);
        {
                uapi16_error *place = held;

                check_eq(uapi16_data_check_update_zeros(c, 1, &place), -EINVAL);
                check_eq(uapi16_data_check_update_zeros(NULL, 1, &place), -EINVAL);
                check(place == held);
                /* An object that gives a size alone: zero bytes count for
                 * it as any bytes do. The one that was refused did not. */
                check_eq(uapi16_data_check_update_zeros(c, 2, &e), 0);
                check_eq(uapi16_data_check_update(c, "x", 1, &e), 0);
                check_eq(uapi16_data_check_finish(c, &size, &e), 0);
                check_eq(size, 3);
                check_eq(uapi16_data_check_update_zeros(c, 1, &place), -EINVAL);
                check(place == held);
        }
        c = uapi16_data_check_free(c);

        /* One that gives neither a size nor a hash: any number of them
         * passes. */
        check_eq(uapi16_data_check_new(plain, &c), 0);
        check_eq(uapi16_data_check_update_zeros(c, 1024 * 1024, &e), 0);
        check_eq(uapi16_data_check_update_zeros(c, 5, &e), 0);
        check_eq(uapi16_data_check_finish(c, &size, &e), 0);
        check_eq(size, 1024 * 1024 + 5);
        check(!e);
}

/* Everything the file `fd` holds from `offset` on, up to `room` bytes, and
 * how much that is. */
static size_t read_from(int fd, uint64_t offset, char *data, size_t room) {
        size_t done = 0;

        while (done < room) {
                ssize_t n = pread(fd, data + done, room - done, (off_t) (offset + done));

                check(n >= 0);
                if (n == 0)
                        break;
                done += (size_t) n;
        }
        return done;
}

/* How many threads open files from one directory at the same time, and how
 * often each does. */
#define OPENERS 4
#define OPENINGS 100

/* The directory the threads open their files from, what lets them start
 * together, and what each has of its own: the name and the data of its
 * file. */
struct opening {
        pthread_barrier_t start;
        const uapi16_directory *directory;
};

struct opener {
        struct opening *opening;
        char name[32], data[32];
};

static void *open_in_thread(void *argument) {
        struct opener *opener = argument;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = make_object(opener->name);
        int r = pthread_barrier_wait(&opener->opening->start);

        check(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        for (int i = 0; i < OPENINGS; i++) {
                uapi16_error *e = NULL;
                uint64_t offset = 77;
                char data[32];
                int fd = -1;

                check_eq(uapi16_directory_open_data(opener->opening->directory, o, &fd, &offset, &e), 0);
                check(fd >= 0 && !e);
                check_eq(offset, 0);
                check_eq(read_from(fd, offset, data, sizeof(data)), strlen(opener->data));
                check_eq(memcmp(data, opener->data, strlen(opener->data)), 0);
                check_eq(close(fd), 0);
        }
        return NULL;
}

/*
 * A directory opens the file the data of a file object is in, below the
 * descriptor it was made from, and says where the data starts in it. The
 * descriptor it stores is new, read-only and the caller's. What is no
 * regular file below the directory, and an object whose data is not in a
 * file, is refused, each for what it is.
 */
static void test_opened_data(void) {
        static const char manifest[] =
                ROOT RS "{\"contents\":[{\"file\":\"blobs/1\",\"originalSize\":11}],\"name\":\"longer\"}\n"
                RS "{\"contents\":[{\"file\":\"blobs/1\",\"offset\":2}],\"name\":\"part\",\"size\":3}\n"
                RS "{\"contents\":[{\"file\":\"blobs/1\",\"offset\":4}],\"name\":\"rest\"}\n"
                RS "{\"contents\":[{\"file\":\"blobs/1\",\"originalSize\":9}],\"name\":\"shorter\"}\n"
                RS "{\"contents\":[{\"url\":\"https://example.com/x\"}],\"name\":\"url\"}\n"
                RS "{\"contents\":[{\"file\":\"blobs/1\",\"originalSize\":10}],\"name\":\"whole\"}\n"
                RS "{\"contents\":[{\"file\":\"blobs/2\",\"offset\":1}],\"name\":\"zz\"}\n" TRAILER;
        _cleanup_(closep) int top = make_tree("opened"), blobs = make_dir(top, "blobs");
        _cleanup_(closep) int path = openat(tmp_fd, "opened", O_PATH | O_DIRECTORY | O_CLOEXEC);
        _cleanup_(closep) int from = manifest_file(manifest), fd = -1, second = -1;
        _cleanup_(uapi16_directory_freep) uapi16_directory *d = NULL, *following = NULL, *named = NULL;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = make_object("a/file");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *blob = make_object("elsewhere");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *sparse = make_object("sparse");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *other = make_object("a/none");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = make_object("");
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *got = NULL;
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *c = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *e = NULL, *held = NULL;
        struct opening opening;
        struct opener openers[OPENERS];
        pthread_t threads[OPENERS];
        uapi16_sha256_digest_t hash;
        uint64_t offset = 77, size = 0, contents_offset = 77;
        const char *contents_file = NULL;
        size_t before, n;
        struct stat st;
        char data[64];
        int r;

        /* The files below the directory: one that other files hold data
         * in, one with a hole, and symbolic links that lead to a file, at
         * the end of a name and on the way, by a name of the root and by
         * one that goes up. make_tree() made a/file, a FIFO and the link
         * to a directory. */
        check(path >= 0);
        make_file(blobs, "1", "0123456789");
        check_eq(symlinkat("a/file", top, "to-file"), 0);
        check_eq(symlinkat("/a/file", top, "absolute"), 0);
        check_eq(symlinkat("../../a/file", top, "up"), 0);
        check_eq(symlinkat("nowhere", top, "dangling"), 0);
        {
                _cleanup_(closep) int holed = -1;

                holed = openat(top, "sparse", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
                check(holed >= 0);
                check_eq(pwrite(holed, "head", 4, 0), 4);
                check_eq(pwrite(holed, "tail", 4, 4 + HOLE), 4);
        }
        check_eq(uapi16_directory_new(top, UAPI16_DIRECTORY_NONE, &d, &e), 0);
        check_eq(uapi16_directory_new(top, UAPI16_DIRECTORY_FOLLOW_SYMLINKS, &following, &e), 0);
        check_eq(uapi16_directory_new(path, UAPI16_DIRECTORY_NONE, &named, &e), 0);
        before = open_descriptors();

        /* The file of the name of the object, which gives no size: the
         * data is all the file holds, from its start. The descriptor is a
         * new one, for reading alone, one that blocks, and closed in a
         * process that executes another program. */
        check_eq(uapi16_directory_open_data(d, file, &fd, &offset, &e), 0);
        check(fd >= 0 && fd != top && !e);
        check_eq(offset, 0);
        check_eq(open_descriptors(), before + 1);
        check_eq(fcntl(fd, F_GETFL) & O_ACCMODE, O_RDONLY);
        check(!(fcntl(fd, F_GETFL) & O_NONBLOCK));
        check(fcntl(fd, F_GETFD) & FD_CLOEXEC);
        check_eq(write(fd, "x", 1), -1);
        check_eq(errno, EBADF);
        check_eq(fstat(fd, &st), 0);
        check(S_ISREG(st.st_mode));
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "hello", 5);

        /* Every call opens the file again: a second descriptor is another
         * one, and both are the caller's to close. */
        check_eq(uapi16_directory_open_data(d, file, &second, &offset, &e), 0);
        check(second >= 0 && second != fd);
        check_eq(close(second), 0);
        second = -1;
        check_eq(close(fd), 0);
        fd = -1;
        check_eq(open_descriptors(), before);

        /* The size the object gives is how much of the file is its data.
         * A file that holds more is fine, and one that is too short for
         * it is not. Nothing is stored for a call that fails, here and
         * below. */
        check_eq(uapi16_file_object_set_size(file, 5), 0);
        check_eq(uapi16_directory_open_data(d, file, &fd, &offset, &e), 0);
        check_eq(close(fd), 0);
        check_eq(uapi16_file_object_set_size(file, 4), 0);
        check_eq(uapi16_directory_open_data(d, file, &fd, &offset, &e), 0);
        check_eq(close(fd), 0);
        fd = -7;
        offset = 7;
        check_eq(uapi16_file_object_set_size(file, 6), 0);
        r = uapi16_directory_open_data(d, file, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "a/file", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_directory_open_data(d, file, &fd, &offset, NULL), -EBADMSG);

        /* A file that is not there, and what is there and no regular file:
         * a directory and a FIFO, which nothing waits for a writer of. */
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_MISSING, ENOENT, "a/none", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_set_name(other, "a/file/below", &e), 0);
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_MISSING, ENOENT, "a/file/below", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_set_name(other, "a", &e), 0);
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_NOT_REGULAR, EINVAL, "a", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_set_name(other, "fifo", &e), 0);
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_NOT_REGULAR, EINVAL, "fifo", 0);
        e = uapi16_error_free(e);

        /* A symbolic link is not followed, at the end of the name and on
         * the way to it: the file can't be opened, and the error has the
         * errno of the system call. */
        check_eq(uapi16_file_object_set_name(other, "to-file", &e), 0);
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_IO, ELOOP, "to-file", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_set_name(other, "link/file", &e), 0);
        r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_IO, ELOOP, "link/file", 0);
        e = uapi16_error_free(e);
        check_eq(fd, -7);
        check_eq(offset, 7);

        /* A directory that follows symbolic links follows them as if it
         * were the root: a name of the root and one that goes up above
         * the directory stay below it. A link that leads nowhere is a
         * file that is not there, and one to a directory is no regular
         * file. */
        check_eq(uapi16_directory_open_data(following, other, &fd, &offset, &e), 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "hello", 5);
        check_eq(close(fd), 0);
        check_eq(uapi16_file_object_set_name(other, "to-file", &e), 0);
        check_eq(uapi16_directory_open_data(following, other, &fd, &offset, &e), 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "hello", 5);
        check_eq(close(fd), 0);
        check_eq(uapi16_file_object_set_name(other, "absolute", &e), 0);
        check_eq(uapi16_directory_open_data(following, other, &fd, &offset, &e), 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "hello", 5);
        check_eq(close(fd), 0);
        check_eq(uapi16_file_object_set_name(other, "up", &e), 0);
        check_eq(uapi16_directory_open_data(following, other, &fd, &offset, &e), 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "hello", 5);
        check_eq(close(fd), 0);
        fd = -7;
        offset = 7;
        check_eq(uapi16_file_object_set_name(other, "dangling", &e), 0);
        r = uapi16_directory_open_data(following, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_MISSING, ENOENT, "dangling", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_set_name(other, "link", &e), 0);
        r = uapi16_directory_open_data(following, other, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SOURCE_NOT_REGULAR, EINVAL, "link", 0);
        e = uapi16_error_free(e);

        /* An object whose data is not in a file has none to open: a file
         * that has no data, the root, data that the manifest carries, for
         * a regular file and for a symbolic link, and data at a URL, which
         * comes from the manifest below. */
        check_eq(uapi16_file_object_set_name(file, "fifo", &e), 0);
        check_eq(uapi16_file_object_set_type(file, S_IFIFO), 0);
        check_eq(uapi16_file_object_data_location(file), UAPI16_DATA_LOCATION_NONE);
        r = uapi16_directory_open_data(d, file, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_UNSUPPORTED, EOPNOTSUPP, "fifo", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_file_object_data_location(root), UAPI16_DATA_LOCATION_NONE);
        r = uapi16_directory_open_data(d, root, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_UNSUPPORTED, EOPNOTSUPP, "", 0);
        e = uapi16_error_free(e);
        check_eq(uapi16_directory_open_data(d, root, &fd, &offset, NULL), -EOPNOTSUPP);
        check_eq(uapi16_file_object_set_name(other, "carried", &e), 0);
        check_eq(uapi16_file_object_set_target(other, "data", 4), 0);
        check_eq(uapi16_file_object_data_location(other), UAPI16_DATA_LOCATION_LITERAL);
        for (int is_link = 0; is_link < 2; is_link++) {
                check_eq(uapi16_file_object_set_type(other, is_link ? S_IFLNK : S_IFREG), 0);
                r = uapi16_directory_open_data(d, other, &fd, &offset, &e);
                check_eq(r, -EOPNOTSUPP);
                check_eq(uapi16_error_kind(e), UAPI16_ERROR_UNSUPPORTED);
                check_eq(uapi16_error_errno(e), EOPNOTSUPP);
                /* The error names the object, as the one about an object
                 * without data does, above. */
                check_str(uapi16_error_path(e), "carried");
                e = uapi16_error_free(e);
        }

        /* A call that is not valid: no directory, no object, and no place
         * for the descriptor or for where the data starts. Both places are
         * needed: without one of them, and without both, the call fails,
         * and stores nothing in the one that is there. One whose `reterr`
         * points to something fails for that first. None of them opens
         * anything, also where the object has a file that could be
         * opened. */
        check_eq(uapi16_file_object_set_contents_file(blob, "blobs/1", &e), 0);
        check_misuse(uapi16_directory_open_data(NULL, blob, &fd, &offset, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(d, NULL, &fd, &offset, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(d, blob, NULL, &offset, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(d, blob, &fd, NULL, &e), &e, EINVAL);
        check_misuse(uapi16_directory_open_data(d, blob, NULL, NULL, &e), &e, EINVAL);
        check_eq(uapi16_directory_open_data(d, blob, NULL, &offset, NULL), -EINVAL);
        check_eq(uapi16_directory_open_data(d, blob, &fd, NULL, NULL), -EINVAL);
        check_eq(uapi16_directory_open_data(d, blob, NULL, NULL, NULL), -EINVAL);
        check_eq(fd, -7);
        check_eq(offset, 7);
        check_eq(open_descriptors(), before);
        check_eq(uapi16_file_object_new("a//b", &got, &held), -EINVAL);
        check(held && !got);
        {
                uapi16_error *place = held;

                check_eq(uapi16_directory_open_data(d, blob, &fd, &offset, &place), -EINVAL);
                check_eq(uapi16_directory_open_data(NULL, blob, &fd, &offset, &place), -EINVAL);
                check(place == held);
        }
        check_eq(fd, -7);
        check_eq(offset, 7);
        check_eq(open_descriptors(), before);

        /* The file the object refers to, under another name than its
         * own. */
        check_eq(uapi16_directory_open_data(d, blob, &fd, &offset, &e), 0);
        check_eq(offset, 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "0123456789", 10);
        check_eq(close(fd), 0);

        /* A manifest can say where in that file the data starts: such an
         * object comes from a reader, and its data starts there. One
         * gives a size, and its data is that many bytes. The other gives
         * none, and its data reaches to the end of the file. */
        reader = open_reader(from);
        /* A manifest can also say how long that file is. A file of another
         * size is not the one it means: this one has 10 bytes, and the
         * manifest says 11. Nothing is stored. */
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "longer");
        /* The object says which file its data is in and where it starts
         * there, as the manifest has it. */
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), 0);
        check_str(contents_file, "blobs/1");
        check_eq(contents_offset, 0);
        fd = -7;
        offset = 7;
        r = uapi16_directory_open_data(d, got, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "longer", 0);
        e = uapi16_error_free(e);
        check_eq(fd, -7);
        check_eq(offset, 7);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "part");
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), 0);
        check_str(contents_file, "blobs/1");
        check_eq(contents_offset, 2);
        check_eq(uapi16_directory_open_data(d, got, &fd, &offset, &e), 0);
        check_eq(offset, 2);
        check_eq(uapi16_file_object_size(got, &size), 0);
        check_eq(size, 3);
        n = read_from(fd, offset, data, (size_t) size);
        check_same(data, n, "234", 3);
        check_eq(close(fd), 0);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "rest");
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), 0);
        check_str(contents_file, "blobs/1");
        check_eq(contents_offset, 4);
        check_eq(uapi16_directory_open_data(d, got, &fd, &offset, &e), 0);
        check_eq(offset, 4);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "456789", 6);
        check_eq(close(fd), 0);
        /* The manifest says 9 bytes, and the file is longer. */
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "shorter");
        fd = -7;
        offset = 7;
        r = uapi16_directory_open_data(d, got, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_SIZE_MISMATCH, EBADMSG, "shorter", 0);
        e = uapi16_error_free(e);
        check_eq(fd, -7);
        check_eq(offset, 7);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "url");
        check_eq(uapi16_file_object_data_location(got), UAPI16_DATA_LOCATION_UNSUPPORTED);
        /* Data that is in no file is in no other file: the object that was
         * filled again names none, and nothing is stored. */
        contents_file = NULL;
        contents_offset = 77;
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), -ENODATA);
        check(!contents_file);
        check_eq(contents_offset, 77);
        fd = -7;
        r = uapi16_directory_open_data(d, got, &fd, &offset, &e);
        check_error(r, e, UAPI16_ERROR_UNSUPPORTED, EOPNOTSUPP, "url", 0);
        e = uapi16_error_free(e);
        check_eq(fd, -7);
        /* A file that is as long as the manifest says is opened. */
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "whole");
        check_eq(uapi16_directory_open_data(d, got, &fd, &offset, &e), 0);
        check_eq(offset, 0);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "0123456789", 10);
        check_eq(close(fd), 0);
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), 0);
        check_str(contents_file, "blobs/1");
        /* The same object, filled again, names the file of its record. */
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_FILE);
        check_str(uapi16_file_object_name(got), "zz");
        check_eq(uapi16_file_object_contents_file(got, &contents_file, &contents_offset), 0);
        check_str(contents_file, "blobs/2");
        check_eq(contents_offset, 1);
        check_eq(uapi16_reader_next(reader, &got, &e), UAPI16_READ_END);

        /* What was opened is read and held against a check of the same
         * object: a file with a hole, of which the caller reads the data
         * at its start and at its end, and passes the hole as the zero
         * bytes it is. */
        unhex(SHA256_OF_SPARSE, &hash);
        check_eq(uapi16_file_object_set_size(sparse, SPARSE_SIZE), 0);
        check_eq(uapi16_file_object_set_sha256(sparse, &hash), 0);
        check_eq(uapi16_directory_open_data(d, sparse, &fd, &offset, &e), 0);
        check_eq(offset, 0);
        check_eq(uapi16_data_check_new(sparse, &c), 0);
        check_eq(read_from(fd, offset, data, 4), 4);
        check_eq(uapi16_data_check_update(c, data, 4, &e), 0);
        check_eq(uapi16_data_check_update_zeros(c, HOLE, &e), 0);
        check_eq(read_from(fd, offset + 4 + HOLE, data, sizeof(data)), 4);
        check_eq(uapi16_data_check_update(c, data, 4, &e), 0);
        check_eq(uapi16_data_check_finish(c, &size, &e), 0);
        check_eq(size, SPARSE_SIZE);
        check_eq(close(fd), 0);

        /* A directory that was made from a descriptor that only names it
         * opens files as well. What it opened stays open once it is
         * freed, and so does the descriptor it was made from. */
        check_eq(uapi16_directory_open_data(named, blob, &fd, &offset, &e), 0);
        named = uapi16_directory_free(named);
        check_open(fd);
        check_open(path);
        n = read_from(fd, offset, data, sizeof(data));
        check_same(data, n, "0123456789", 10);
        check_eq(close(fd), 0);
        fd = -1;
        check_eq(fstatat(path, "blobs/1", &st, 0), 0);

        /* Several threads open files from one directory at the same time,
         * each with an object of its own. */
        opening.directory = d;
        check_eq(pthread_barrier_init(&opening.start, NULL, OPENERS), 0);
        for (size_t i = 0; i < OPENERS; i++) {
                openers[i].opening = &opening;
                snprintf(openers[i].name, sizeof(openers[i].name), "thread-%zu", i);
                snprintf(openers[i].data, sizeof(openers[i].data), "data of %zu", i);
                make_file(top, openers[i].name, openers[i].data);
        }
        for (size_t i = 0; i < OPENERS; i++)
                check_eq(pthread_create(&threads[i], NULL, open_in_thread, &openers[i]), 0);
        for (size_t i = 0; i < OPENERS; i++)
                check_eq(pthread_join(threads[i], NULL), 0);
        check_eq(pthread_barrier_destroy(&opening.start), 0);
        check_eq(open_descriptors(), before);
        check(!e);
}

int main(int argc, char *argv[]) {
        static const struct {
                const char *name;
                void (*run)(void);
        } tests[] = {
                { "example", test_example },
                { "report", test_report },
                { "options", test_options },
                { "misuse", test_misuse },
                { "walk", test_walk },
                { "extended attributes", test_walk_xattrs },
                { "error places", test_error_places },
                { "names", test_names },
                { "unwritable names", test_unwritable_names },
                { "changes", test_changes },
                { "errors", test_errors },
                { "too large", test_too_large },
                { "loop", test_loop },
                { "no uuid", test_no_uuid },
                { "fat", test_fat },
                { "descriptors", test_descriptors },
                { "no descriptors", test_no_descriptors },
                { "signals", test_signals },
                { "fork", test_fork },
                { "scratch files", test_scratch_files },
                { "failed walks", test_failed_walks },
                { "failed sync", test_failed_sync },
                { "forks", test_forks },
                { "linked names", test_linked_names },
                { "threads", test_threads },
                { "file objects", test_file_objects },
                { "retained features", test_retained_features },
                { "feature lists", test_feature_lists },
                { "roots", test_roots },
                { "root adds", test_root_adds },
                { "added objects", test_added_objects },
                { "refused objects", test_refused_objects },
                { "records", test_records },
                { "record fields", test_record_fields },
                { "no order", test_no_order },
                { "copies", test_copies },
                { "reading", test_reading },
                { "no blocking", test_no_blocking },
                { "failed writes", test_failed_writes },
                { "refilled objects", test_refilled_objects },
                { "kept objects", test_kept_objects },
                { "manifests", test_manifests },
                { "error records", test_error_records },
                { "validity", test_validity },
                { "signatures", test_signatures },
                { "sha256", test_sha256 },
                { "data checks", test_data_checks },
                { "zeros", test_zeros },
                { "directories", test_directories },
                { "opened data", test_opened_data },
                { "names and features", test_names_and_features },
                { "numbers", test_numbers },
        };
        const char *tmpdir = getenv("TMPDIR");
        char path[PATH_MAX], *name;
        _cleanup_(closep) int parent = -1;

        /* The test runs itself once more for test_forks() and
         * test_linked_names(), and such a process does only what it is
         * told. */
        if (argc == 2 && strcmp(argv[1], WITHOUT_WIPE_ON_FORK) == 0)
                return without_wipe_on_fork();
        if (argc == 2 && strcmp(argv[1], FORK_IN_THE_FIRST_CALL) == 0)
                return fork_in_the_first_call();
        if (argc == 2 && strcmp(argv[1], FIRST_CALLS_AT_ONCE) == 0)
                return first_calls_at_once();
        if (argc == 2 && strcmp(argv[1], FORK_IN_THE_FIRST_ASK) == 0)
                return fork_in_the_first_ask();
        if (argc == 2 && strcmp(argv[1], WITHOUT_TMPFILE) == 0)
                return without_tmpfile();
        if (argc == 3 && strcmp(argv[1], WITH_A_LINKED_NAME) == 0)
                return linked_name(argv[2], LINKED);
        if (argc == 3 && strcmp(argv[1], WITH_A_NAME_LEFT) == 0)
                return linked_name(argv[2], LINKED_AND_LEFT);
        if (argc == 3 && strcmp(argv[1], WITH_A_NAME_THROUGH_PROCFS) == 0)
                return linked_name(argv[2], LINKED_THROUGH_PROCFS);
        check(argc == 1);
        self_path = argv[0];

        /* What ran is said at once, also to a pipe. */
        setvbuf(stdout, NULL, _IOLBF, 0);
        snprintf(path, sizeof(path), "%s/uapi16-capi-XXXXXX", tmpdir && *tmpdir ? tmpdir : "/tmp");
        check(mkdtemp(path));
        tmp_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(tmp_fd >= 0);
        check(realpath(path, tmp_path));
        name = strrchr(path, '/');
        *name++ = 0;
        parent = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        check(parent >= 0);
        null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        check(null_fd >= 0);

        /* The trees of the tests have a hard link. Where the temporary
         * directory can hold none, as on FAT, nothing is tested. */
        make_file(tmp_fd, "linked", "");
        if (linkat(tmp_fd, "linked", tmp_fd, "linked-too", 0) < 0) {
                check_eq(errno, EPERM);
                fprintf(stderr, "skipping every test: %s can hold no hard link\n", path);
                close(null_fd);
                close(tmp_fd);
                remove_tree(parent, name);
                return EXIT_SUCCESS;
        }
        check_eq(unlinkat(tmp_fd, "linked-too", 0), 0);
        check_eq(unlinkat(tmp_fd, "linked", 0), 0);

        for (size_t i = 0; i < ELEMENTSOF(tests); i++) {
                /* These fork and count on the child being told, which
                 * takes memory that is wiped in a child. */
                bool forks = tests[i].run == test_fork || tests[i].run == test_scratch_files ||
                             tests[i].run == test_forks;

                if (forks && !wipes_on_fork()) {
                        /* ci.yml matches the start of this line for
                         * "forks", which has two parts under a seccomp
                         * filter. */
                        fprintf(stderr, "skipping %s: no memory that is wiped in a child here, so no child is told\n",
                                tests[i].name);
                        continue;
                }
                tests[i].run();
                printf("ok %s\n", tests[i].name);
        }

        close(null_fd);
        close(tmp_fd);
        remove_tree(parent, name);
        return EXIT_SUCCESS;
}
