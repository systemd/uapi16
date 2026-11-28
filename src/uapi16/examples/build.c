/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Copies a tree into an image and writes the manifest of the image while
 * it does, as a mkfs tool does for an option like --write-manifest:
 * build SOURCE-DIR IMAGE-DIR, with the manifest on standard output.
 *
 * The image is a new directory here. It stands in for the file system a
 * tool makes. Every file goes into the manifest when it has gone into the
 * image, with the hash of the data that was copied.
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

/* A file with more than one name: its inode in the source, and its file
 * object, which goes into the manifest again under every later name. */
struct link {
        dev_t dev;
        ino_t ino;
        uapi16_file_object *object;
};

struct build {
        uapi16_manifest_writer *manifest;
        int image_fd;
        void *links; /* the links, in a tree of tsearch() */
        uapi16_inode_token_t tokens;
};

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static void closedirp(DIR **d) {
        if (*d)
                closedir(*d);
}

static int compare_links(const void *a, const void *b) {
        const struct link *x = a, *y = b;

        if (x->dev != y->dev)
                return x->dev < y->dev ? -1 : 1;
        if (x->ino != y->ino)
                return x->ino < y->ino ? -1 : 1;
        return 0;
}

static void free_link(void *p) {
        struct link *link = p;

        uapi16_file_object_free(link->object);
        free(link);
}

/* Copies the `size` bytes of `in` to `out` and stores their hash. A hole is
 * not read: it stays a hole in the image and goes into the hash as zeros. */
static int copy_and_hash(int in, int out, off_t size,
                         uapi16_sha256_digest_t *ret_hash) {
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *sha = NULL;
        static char buffer[1 << 16];
        off_t at = 0;
        int r;

        sha = uapi16_sha256_new();
        while (at < size) {
                off_t data, end;

                data = lseek(in, at, SEEK_DATA);
                if (data < 0 && errno != ENXIO)
                        return -errno;
                if (data < 0 || data > size)
                        data = size; /* a hole up to the end */
                if (data > at) {
                        r = uapi16_sha256_update_zeros(sha,
                                                       (uint64_t) (data - at));
                        if (r < 0)
                                return r;
                        at = data;
                        continue;
                }
                end = lseek(in, at, SEEK_HOLE);
                if (end < 0)
                        return -errno;
                if (end > size)
                        end = size;
                while (at < end) {
                        size_t want = (size_t) (end - at) < sizeof(buffer)
                                      ? (size_t) (end - at)
                                      : sizeof(buffer);
                        ssize_t n = pread(in, buffer, want, at);

                        if (n < 0 && errno == EINTR)
                                continue;
                        if (n < 0)
                                return -errno;
                        if (n == 0)
                                return -ESTALE; /* the file changed */
                        for (ssize_t done = 0; done < n;) {
                                ssize_t w = pwrite(out, buffer + done,
                                                   (size_t) (n - done),
                                                   at + done);

                                if (w < 0 && errno == EINTR)
                                        continue;
                                if (w <= 0)
                                        return w < 0 ? -errno : -EIO;
                                done += w;
                        }
                        r = uapi16_sha256_update(sha, buffer, (size_t) n);
                        if (r < 0)
                                return r;
                        at += n;
                }
        }
        if (ftruncate(out, size) < 0)
                return -errno;
        return uapi16_sha256_finish(sha, ret_hash);
}

/* Makes the file object of `name` from what stat() says of the file. */
static int describe(const char *name, const struct stat *st,
                    uapi16_file_object **ret, uapi16_error **reterr) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        int r;

        /* A name that a manifest can't hold fails here, and
         * uapi16_error_name_problem() says why. */
        r = uapi16_file_object_new(name, &o, reterr);
        if (r < 0)
                return r;

        /* The setters store what they get, and fail only for a call that
         * is not valid. The root is a directory already. A symbolic link
         * has no mode. The IDs 65535 and 4294967295 and a time before 1970
         * are not what a manifest holds, so they are left out. */
        r = 0;
        if (*name)
                r = uapi16_file_object_set_type(o, st->st_mode);
        if (r >= 0 && !S_ISLNK(st->st_mode))
                r = uapi16_file_object_set_mode(o, st->st_mode);
        if (r >= 0 && st->st_uid != 65535 && st->st_uid != UINT32_MAX)
                r = uapi16_file_object_set_uid(o, st->st_uid);
        if (r >= 0 && st->st_gid != 65535 && st->st_gid != UINT32_MAX)
                r = uapi16_file_object_set_gid(o, st->st_gid);
        /* A time after 2554 is left out too, since its nanoseconds don't
         * fit in 64 bits. */
        if (r >= 0 && st->st_mtim.tv_sec >= 0 &&
            (uint64_t) st->st_mtim.tv_sec <=
                    (UINT64_MAX - (uint64_t) st->st_mtim.tv_nsec) / 1000000000)
                r = uapi16_file_object_set_mtime_nsec(
                                o,
                                (uint64_t) st->st_mtim.tv_sec * 1000000000 +
                                        (uint64_t) st->st_mtim.tv_nsec);
        if (r >= 0 && (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode))) {
                r = uapi16_file_object_set_major(o, major(st->st_rdev));
                if (r >= 0)
                        r = uapi16_file_object_set_minor(o, minor(st->st_rdev));
        }
        if (r < 0)
                return r;

        *ret = o;
        o = NULL;
        return 0;
}

static int add_directory(struct build *b, int dir_fd, const char *name,
                         uapi16_error **reterr);

/* Puts the file `component` of the directory `dir_fd` into the image as
 * `name`, and adds its file object to the manifest. */
static int add_file(struct build *b, int dir_fd, const char *component,
                    const char *name, uapi16_error **reterr) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        struct link key = { 0 }, *link;
        struct stat st;
        int r;

        if (fstatat(dir_fd, component, &st, AT_SYMLINK_NOFOLLOW) < 0)
                return -errno;
        key.dev = st.st_dev;
        key.ino = st.st_ino;

        if (!S_ISDIR(st.st_mode) && st.st_nlink > 1) {
                void *found = tfind(&key, &b->links, compare_links);

                if (found) {
                        /* A later name of a file. The image gets a link, and
                         * the manifest the same object under the new name.
                         * Nothing is read again. */
                        link = *(struct link **) found;
                        if (linkat(b->image_fd,
                                   uapi16_file_object_name(link->object),
                                   b->image_fd, name, 0) < 0)
                                return -errno;
                        r = uapi16_file_object_set_name(
                                        link->object, name, reterr);
                        if (r < 0)
                                return r;
                        return uapi16_manifest_writer_add_object(
                                        b->manifest, link->object, reterr);
                }
        }

        r = describe(name, &st, &o, reterr);
        if (r < 0)
                return r;

        if (S_ISDIR(st.st_mode)) {
                int fd;

                if (mkdirat(b->image_fd, name, 0700) < 0)
                        return -errno;
                r = uapi16_manifest_writer_add_object(b->manifest, o, reterr);
                if (r < 0)
                        return r;
                fd = openat(dir_fd, component,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                if (fd < 0)
                        return -errno;
                /* add_directory() closes the descriptor. */
                return add_directory(b, fd, name, reterr);
        }

        if (S_ISREG(st.st_mode)) {
                _cleanup_(closep) int in = -1;
                _cleanup_(closep) int out = -1;
                uapi16_sha256_digest_t hash;

                in = openat(dir_fd, component,
                            O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
                out = openat(b->image_fd, name,
                             O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (in < 0 || out < 0)
                        return -errno;
                r = copy_and_hash(in, out, st.st_size, &hash);
                if (r < 0)
                        return r;
                r = uapi16_file_object_set_size(o, (uint64_t) st.st_size);
                if (r >= 0)
                        r = uapi16_file_object_set_sha256(o, &hash);
                if (r < 0)
                        return r;
        } else if (S_ISLNK(st.st_mode)) {
                char target[4096];
                ssize_t n;

                n = readlinkat(dir_fd, component, target, sizeof(target) - 1);
                if (n < 0)
                        return -errno;
                target[n] = 0;
                if (symlinkat(target, b->image_fd, name) < 0)
                        return -errno;
                /* The target is bytes with a size. No NUL ends it. */
                r = uapi16_file_object_set_target(o, target, (size_t) n);
                if (r >= 0)
                        r = uapi16_file_object_set_size(o, (uint64_t) n);
                if (r < 0)
                        return r;
        } else if (mknodat(b->image_fd, name, st.st_mode, st.st_rdev) < 0)
                return -errno;

        if (st.st_nlink > 1) {
                /* The first name of a file with several. Its names share
                 * one token, which is any number: the manifest gets its
                 * own. The object is kept for the later names. */
                r = uapi16_file_object_set_inode_token(o, ++b->tokens);
                if (r < 0)
                        return r;
                link = malloc(sizeof(*link));
                if (!link)
                        return -ENOMEM;
                *link = key;
                if (!tsearch(link, &b->links, compare_links)) {
                        free(link);
                        return -ENOMEM;
                }
                link->object = o;
                o = NULL;
                return uapi16_manifest_writer_add_object(
                                b->manifest, link->object, reterr);
        }

        /* The writer keeps a copy, so the object can go. */
        return uapi16_manifest_writer_add_object(b->manifest, o, reterr);
}

/* Copies what is in the directory `dir_fd`, whose name in the image is
 * `name`, and closes the descriptor. */
static int add_directory(struct build *b, int dir_fd, const char *name,
                         uapi16_error **reterr) {
        _cleanup_(closedirp) DIR *d = NULL;
        struct dirent *entry;

        d = fdopendir(dir_fd);
        if (!d) {
                int e = errno;

                close(dir_fd);
                return -e;
        }
        for (;;) {
                char child[4096];
                int r;

                errno = 0;
                entry = readdir(d);
                if (!entry)
                        return -errno;
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                        continue;
                r = snprintf(child, sizeof(child), "%s%s%s", name,
                             *name ? "/" : "", entry->d_name);
                if (r < 0 || (size_t) r >= sizeof(child))
                        return -ENAMETOOLONG;
                r = add_file(b, dirfd(d), entry->d_name, child, reterr);
                if (r < 0)
                        return r;
        }
}

int main(int argc, char *argv[]) {
        static const uapi16_uuid_t uuid = { .bytes = {
                0x6f, 0x1d, 0x0a, 0x42, 0x9c, 0x1e, 0x4b, 0x7a,
                0x8d, 0x33, 0x52, 0x0c, 0x7e, 0x11, 0xa9, 0x05
        } };
        _cleanup_(uapi16_manifest_options_freep)
                uapi16_manifest_options *options = NULL;
        _cleanup_(uapi16_manifest_writer_freep)
                uapi16_manifest_writer *manifest = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *root = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        _cleanup_(closep) int source_fd = -1;
        _cleanup_(closep) int image_fd = -1;
        struct build b = { .image_fd = -1 };
        struct stat st;
        int r;

        if (argc != 3) {
                fprintf(stderr, "usage: %s SOURCE-DIR IMAGE-DIR\n", argv[0]);
                return 2;
        }
        source_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (source_fd < 0 || fstat(source_fd, &st) < 0 ||
            mkdir(argv[2], 0700) < 0) {
                perror("build");
                return 1;
        }
        image_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (image_fd < 0) {
                perror(argv[2]);
                return 1;
        }

        /* What this tool records: the default features, the times, and the
         * identity of the file system it makes. */
        options = uapi16_manifest_options_new();
        r = uapi16_manifest_options_add_features(options,
                UAPI16_FEATURES(UAPI16_FEATURE_MTIME, UAPI16_FEATURE_FS_UUID,
                                UAPI16_FEATURE_FS_LABEL));
        /* Nothing is written to standard output before the finish. */
        if (r >= 0)
                r = uapi16_manifest_writer_open(options, STDOUT_FILENO,
                                                &manifest, &error);

        /* The root is the object with the empty name. It has the attributes
         * of the top directory, and the identity the tool gave the file
         * system. The adds can come in any order. */
        if (r >= 0)
                r = describe("", &st, &root, &error);
        if (r >= 0)
                r = uapi16_file_object_set_fs_uuid(root, &uuid);
        if (r >= 0)
                r = uapi16_file_object_set_fs_label(root, "example");
        if (r >= 0)
                r = uapi16_manifest_writer_add_object(manifest, root, &error);

        if (r >= 0) {
                b.manifest = manifest;
                b.image_fd = image_fd;
                r = add_directory(&b, source_fd, "", &error);
                source_fd = -1; /* add_directory() closed it */
                tdestroy(b.links, free_link);
        }

        /* What the adds left open fails here, such as two different files
         * of one name. The manifest is complete once this returns 0. */
        if (r >= 0)
                r = uapi16_manifest_writer_finish(manifest, NULL, &error);
        if (r < 0) {
                fprintf(stderr, "%s: %s", argv[0], strerror(-r));
                if (error) {
                        const char *path = uapi16_error_path(error);
                        const char *problem = uapi16_error_problem(error);
                        const char *field = uapi16_error_field(error);

                        if (path)
                                fprintf(stderr, ", file '%s'", path);
                        if (problem)
                                fprintf(stderr, ", %s", problem);
                        if (field)
                                fprintf(stderr, ", field %s", field);
                }
                fputc('\n', stderr);
                return 1;
        }
        return 0;
}
