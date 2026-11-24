/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Writes the records of a manifest in the order of the manifest, for a
 * builder whose own walk is sorted already, and writes each record when
 * the builder has stored the file: sorted SOURCE-DIR, with the
 * manifest on standard output.
 *
 * Nothing is kept on disk, and every record is written before its call
 * returns.
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

struct names {
        char **names;
        size_t count;
};

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static void free_names(struct names *n) {
        for (size_t i = 0; i < n->count; i++)
                free(n->names[i]);
        free(n->names);
}

static int by_bytes(const void *a, const void *b) {
        /* The names of one directory by their bytes: strcmp(), and not the
         * order of the locale. */
        return strcmp(*(char *const *) a, *(char *const *) b);
}

/* The names in the directory `dir_fd`, sorted by their bytes. */
static int list(int dir_fd, struct names *ret) {
        struct names n = { 0 };
        struct dirent *entry;
        size_t room = 0;
        int fd, r;
        DIR *d;

        /* readdir() gets a descriptor of its own, which closedir() closes. */
        fd = openat(dir_fd, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        d = fdopendir(fd);
        if (!d) {
                r = -errno;
                close(fd);
                return r;
        }
        for (;;) {
                errno = 0;
                entry = readdir(d);
                if (!entry) {
                        r = -errno;
                        break;
                }
                if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                        continue;
                if (n.count == room) {
                        char **larger;

                        room = room ? 2 * room : 64;
                        larger = realloc(n.names, room * sizeof(char *));
                        if (!larger) {
                                r = -ENOMEM;
                                break;
                        }
                        n.names = larger;
                }
                n.names[n.count] = strdup(entry->d_name);
                if (!n.names[n.count]) {
                        r = -ENOMEM;
                        break;
                }
                n.count++;
        }
        closedir(d);
        if (r < 0) {
                free_names(&n);
                return r;
        }
        /* An empty directory has no names, and qsort() takes no NULL. */
        if (n.count > 0)
                qsort(n.names, n.count, sizeof(char *), by_bytes);
        *ret = n;
        return 0;
}

/* Stores what is in the directory `dir_fd`, whose name in the image is
 * `name`, and writes the record of every file right after it stored it.
 * This closes the descriptor. */
static int build(uapi16_writer *writer, int dir_fd, const char *name,
                 uapi16_error **reterr) {
        _cleanup_(closep) int fd = dir_fd;
        _cleanup_(free_names) struct names n = { 0 };
        int r;

        r = list(fd, &n);
        if (r < 0)
                return r;

        /* Every directory is followed by what is in it. With the names of
         * each directory sorted by their bytes, that is the code point
         * order of the manifest. */
        for (size_t i = 0; i < n.count; i++) {
                _cleanup_(uapi16_file_object_freep)
                        uapi16_file_object *o = NULL;
                char child[4096];
                struct stat st;

                if (fstatat(fd, n.names[i], &st, AT_SYMLINK_NOFOLLOW) < 0)
                        return -errno;
                /* This builder stores directories and regular files only. */
                if (!S_ISDIR(st.st_mode) && !S_ISREG(st.st_mode))
                        continue;
                r = snprintf(child, sizeof(child), "%s%s%s", name,
                             *name ? "/" : "", n.names[i]);
                if (r < 0 || (size_t) r >= sizeof(child))
                        return -ENAMETOOLONG;

                r = uapi16_file_object_new(child, &o, reterr);
                if (r < 0)
                        return r;
                r = uapi16_file_object_set_type(o, st.st_mode);
                if (r >= 0)
                        r = uapi16_file_object_set_mode(o, st.st_mode);
                if (r >= 0 && S_ISREG(st.st_mode))
                        r = uapi16_file_object_set_size(o,
                                                        (uint64_t) st.st_size);
                if (r < 0)
                        return r;

                /* The builder stores the file in its image here. */

                /* The record goes out now. The writer refuses an object
                 * that is not where the order has it, and goes on. */
                r = uapi16_writer_file(writer, o, reterr);
                if (r < 0)
                        return r;

                if (S_ISDIR(st.st_mode)) {
                        int sub = openat(fd, n.names[i],
                                         O_RDONLY | O_DIRECTORY |
                                         O_NOFOLLOW | O_CLOEXEC);

                        if (sub < 0)
                                return -errno;
                        r = build(writer, sub, child, reterr);
                        if (r < 0)
                                return r;
                }
        }
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(uapi16_manifest_options_freep)
                uapi16_manifest_options *options = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *writer = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        _cleanup_(closep) int source_fd = -1;
        int r;

        if (argc != 2) {
                fprintf(stderr, "usage: %s SOURCE-DIR\n", argv[0]);
                return 2;
        }
        source_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (source_fd < 0) {
                perror(argv[1]);
                return 1;
        }

        /* The options say what the manifest records. The order is the code
         * point order unless set. */
        options = uapi16_manifest_options_new();
        r = uapi16_manifest_options_set_features(options,
                UAPI16_FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_SIZE));
        /* This writes the root, which says nothing here. The writer borrows
         * standard output until it is freed, and never closes it. */
        if (r >= 0)
                r = uapi16_writer_begin(options, STDOUT_FILENO, NULL,
                                        &writer, &error);
        if (r >= 0) {
                r = build(writer, source_fd, "", &error);
                source_fd = -1; /* build() closed it */
        }
        /* The trailer ends the manifest. A reader refuses one without it. */
        if (r >= 0)
                r = uapi16_writer_finish(writer, &error);
        if (r < 0) {
                fprintf(stderr, "%s: %s", argv[0], strerror(-r));
                if (error && uapi16_error_path(error))
                        fprintf(stderr, ", file '%s'",
                                uapi16_error_path(error));
                if (error && uapi16_error_problem(error))
                        fprintf(stderr, ", %s", uapi16_error_problem(error));
                fputc('\n', stderr);
                return 1;
        }
        return 0;
}
