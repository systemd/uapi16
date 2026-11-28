/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Builds an image from a manifest and the files next to it, as a mkfs tool
 * does for an option like --manifest: assemble SOURCE-DIR IMAGE-DIR, with
 * the manifest on standard input.
 *
 * The image is a new directory here. It stands in for the file system a
 * tool makes. The tool reads the data itself, through a descriptor of the
 * library, and has the library check what it read.
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <search.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

/* The first name of a file with several, by its token in the manifest. */
struct link {
        uapi16_inode_token_t token;
        char *name;
};

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static int compare_links(const void *a, const void *b) {
        const struct link *x = a, *y = b;

        return x->token < y->token ? -1 : x->token > y->token;
}

static void free_link(void *p) {
        struct link *link = p;

        free(link->name);
        free(link);
}

static int write_all(int fd, const void *data, size_t size) {
        const char *p = data;

        while (size > 0) {
                ssize_t n = write(fd, p, size);

                if (n < 0 && errno == EINTR)
                        continue;
                if (n <= 0)
                        return n < 0 ? -errno : -EIO;
                p += n;
                size -= (size_t) n;
        }
        return 0;
}

/* Copies the data of `o` from `in`, where it starts at `offset`, to `out`.
 * The check sees every byte before it is written on. */
static int copy_checked(int in, uint64_t offset, int out,
                        const uapi16_file_object *o, uapi16_error **reterr) {
        _cleanup_(uapi16_data_check_freep) uapi16_data_check *check = NULL;
        static char buffer[1 << 16];
        uint64_t left = UINT64_MAX;
        int r;

        /* Without a size the data reaches to the end of its file. */
        (void) uapi16_file_object_size(o, &left);
        r = uapi16_data_check_new(o, &check);
        if (r < 0)
                return r;

        while (left > 0) {
                size_t want = left < sizeof(buffer)
                              ? (size_t) left
                              : sizeof(buffer);
                ssize_t n = pread(in, buffer, want, (off_t) offset);

                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        return -errno;
                if (n == 0)
                        break; /* the end of the file: the finish says if
                                * that is too early */
                r = uapi16_data_check_update(check, buffer, (size_t) n, reterr);
                if (r < 0)
                        return r;
                r = write_all(out, buffer, (size_t) n);
                if (r < 0)
                        return r;
                offset += (uint64_t) n;
                left -= (uint64_t) n;
        }

        /* The size and the hash the manifest gives for the file. If this
         * fails, what `out` got is not the data of the file. */
        return uapi16_data_check_finish(check, NULL, reterr);
}

/* Makes the regular file `o` in the image. */
static int place_file(int image_fd, const uapi16_directory *source,
                      const uapi16_file_object *o, uapi16_error **reterr) {
        _cleanup_(closep) int in = -1;
        _cleanup_(closep) int out = -1;
        const char *name = uapi16_file_object_name(o);
        uint64_t offset, mtime;
        const void *literal;
        uint32_t mode;
        size_t size;
        int r;

        out = openat(image_fd, name,
                     O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                     0600);
        if (out < 0)
                return -errno;

        switch (uapi16_file_object_data_location(o)) {
        case UAPI16_DATA_LOCATION_LITERAL:
                /* The manifest carries the data, and the reader has checked
                 * it against the hash. */
                literal = uapi16_file_object_literal(o, &size);
                r = write_all(out, literal, size);
                break;
        case UAPI16_DATA_LOCATION_EXTERNAL:
                /* The file is opened below the directory and nowhere else,
                 * whatever its name is. */
                r = uapi16_directory_open_data(source, o, &in, &offset, reterr);
                if (r >= 0)
                        r = copy_checked(in, offset, out, o, reterr);
                break;
        default:
                /* Data at a URL or in an encoding. */
                r = -EOPNOTSUPP;
                break;
        }
        if (r < 0)
                return r;

        /* A getter of a field the object does not have fails with -ENODATA. */
        if (uapi16_file_object_mode(o, &mode) >= 0 && fchmod(out, mode) < 0)
                return -errno;
        if (uapi16_file_object_mtime_nsec(o, &mtime) >= 0) {
                struct timespec times[2] = {
                        { .tv_nsec = UTIME_OMIT },
                        { .tv_sec = (time_t) (mtime / 1000000000),
                          .tv_nsec = (long) (mtime % 1000000000) },
                };

                if (futimens(out, times) < 0)
                        return -errno;
        }
        return 0;
}

/* Makes the file `o` in the image. */
static int place(int image_fd, const uapi16_directory *source, void **links,
                 const uapi16_file_object *o, uapi16_error **reterr) {
        const char *name = uapi16_file_object_name(o);
        const void *target;
        char buffer[4096];
        uapi16_inode_token_t token;
        size_t size;

        /* -ENODATA says that the file has no other name. */
        if (uapi16_file_object_inode_token(o, &token) >= 0) {
                struct link key = { .token = token }, *link;
                void *found = tfind(&key, links, compare_links);

                if (found) {
                        /* A later name of a file that is there already. */
                        link = *(struct link **) found;
                        return linkat(image_fd, link->name,
                                      image_fd, name, 0) < 0 ? -errno : 0;
                }
                link = malloc(sizeof(*link));
                if (!link)
                        return -ENOMEM;
                link->token = token;
                link->name = strdup(name);
                if (!link->name || !tsearch(link, links, compare_links)) {
                        free_link(link);
                        return -ENOMEM;
                }
        }

        switch (uapi16_file_object_type(o)) {
        case S_IFDIR:
                return mkdirat(image_fd, name, 0700) < 0 ? -errno : 0;
        case S_IFREG:
                return place_file(image_fd, source, o, reterr);
        case S_IFLNK:
                /* The target is the data of a symbolic link. No NUL ends it. */
                target = uapi16_file_object_literal(o, &size);
                if (!target || size >= sizeof(buffer))
                        return -EOPNOTSUPP;
                memcpy(buffer, target, size);
                buffer[size] = 0;
                return symlinkat(buffer, image_fd, name) < 0 ? -errno : 0;
        default:
                /* This image holds no device nodes, FIFOs or sockets. */
                return -EOPNOTSUPP;
        }
}

int main(int argc, char *argv[]) {
        /* The directory borrows its descriptor until it is freed. So the
         * descriptor is declared first, and is closed last. */
        _cleanup_(closep) int source_fd = -1;
        _cleanup_(closep) int image_fd = -1;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_directory_freep) uapi16_directory *source = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        void *links = NULL;
        struct timespec ts;
        uint64_t now;
        int r;

        if (argc != 3) {
                fprintf(stderr, "usage: %s SOURCE-DIR IMAGE-DIR\n", argv[0]);
                return 2;
        }
        source_fd = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (source_fd < 0 || mkdir(argv[2], 0700) < 0) {
                perror("assemble");
                return 1;
        }
        image_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (image_fd < 0) {
                perror(argv[2]);
                return 1;
        }
        clock_gettime(CLOCK_REALTIME, &ts);
        now = (uint64_t) ts.tv_sec * 1000000 + (uint64_t) ts.tv_nsec / 1000;

        /* The reader reads its descriptor once, so the manifest can come
         * through a pipe. It borrows the descriptor and never closes it.
         * This reads and checks the root. */
        r = uapi16_reader_open(STDIN_FILENO, &reader, &error);
        /* Two checks are the caller's. The loop below relies on the order,
         * so the manifest has to declare it. And the manifest may be used
         * now. */
        if (r >= 0)
                r = uapi16_reader_require_order(
                                reader, UAPI16_ORDER_CODEPOINT, &error);
        if (r >= 0)
                r = uapi16_reader_check_validity(reader, now, &error);
        /* The files next to the manifest. Without a flag, a name that leads
         * through a symbolic link fails. */
        if (r >= 0)
                r = uapi16_directory_new(source_fd, UAPI16_DIRECTORY_NONE,
                                         &source, &error);

        /* One file object serves the whole loop, as the buffer of getline()
         * does: the first call makes it, and every later call clears it and
         * fills it again. */
        while (r >= 0) {
                /* What the call returns says what it read. */
                r = uapi16_reader_next(reader, &o, &error);
                if (r != UAPI16_READ_FILE)
                        break;

                /* The reader has checked the record: its fields, where it
                 * comes and its order. A directory comes before what is in
                 * it, so its directory is there when a file comes. */
                r = uapi16_file_object_check_validity(o, now, &error);
                if (r >= 0)
                        r = place(image_fd, source, &links, o, &error);
                if (r < 0 && !error)
                        fprintf(stderr, "'%s': ", uapi16_file_object_name(o));
        }
        tdestroy(links, free_link);

        /* Signature objects follow the file objects. This tool has no use
         * for them: the next call passes over them, and checks them. */
        if (r == UAPI16_READ_SIGNATURES)
                r = uapi16_reader_next(reader, &o, &error);

        if (r < 0) {
                fprintf(stderr, "%s", strerror(-r));
                if (error) {
                        const char *path = uapi16_error_path(error);
                        const char *problem = uapi16_error_problem(error);
                        const char *field = uapi16_error_field(error);
                        uint64_t record;

                        /* -ENODATA says that the error is about no record. */
                        if (uapi16_error_record(error, &record) >= 0)
                                fprintf(stderr, ", record %llu",
                                        (unsigned long long) record);
                        if (path)
                                fprintf(stderr, ", file '%s'", path);
                        if (problem)
                                fprintf(stderr, ", %s", problem);
                        if (field)
                                fprintf(stderr, ", field %s", field);
                }
                fputc('\n', stderr);
                /* A real tool removes the image it made. */
                return 1;
        }
        /* UAPI16_READ_END: the trailer was read and checked, and the
         * manifest is complete. A later library can return a number that
         * this program does not know, which is an error here. */
        if (r != UAPI16_READ_END) {
                fprintf(stderr,
                        "uapi16_reader_next() returned %d, which this program "
                        "does not know\n",
                        r);
                return 1;
        }
        return 0;
}
