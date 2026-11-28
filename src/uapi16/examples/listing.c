/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Writes the manifest of a store from the records a tool has of its files,
 * as an image builder does that keeps the data of every file under the
 * name of its hash: listing OUT-DIR NAME
 *
 * The records come in no order. The manifest lists them in its own.
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

/* One record of the tool. */
struct record {
        const char *name;   /* the empty name is the root */
        uint32_t type;      /* S_IFREG, S_IFDIR or S_IFLNK */
        uint32_t mode;
        uint64_t size;
        const char *sha256; /* 64 hex digits, for a regular file with data */
        const char *target; /* for a symbolic link */
        uint64_t inode;     /* the same number for the names of one file,
                             * or 0 */
};

static const struct record records[] = {
        { "usr/bin/tool", S_IFREG, 0755, 5,
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
          NULL, 7 },
        { "usr/bin/alias", S_IFLNK, 0, 4, NULL, "tool", 0 },
        { "usr/bin", S_IFDIR, 0755, 0, NULL, NULL, 0 },
        { "usr/libexec/tool", S_IFREG, 0755, 5,
          "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
          NULL, 7 },
        { "usr/libexec", S_IFDIR, 0755, 0, NULL, NULL, 0 },
        { "usr", S_IFDIR, 0755, 0, NULL, NULL, 0 },
        { "", S_IFDIR, 0755, 0, NULL, NULL, 0 },
};

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

static int unhex(const char *hex, uapi16_sha256_digest_t *ret) {
        for (size_t i = 0; i < UAPI16_SHA256_SIZE; i++) {
                unsigned byte;

                if (sscanf(hex + 2 * i, "%2x", &byte) != 1)
                        return -1;
                ret->bytes[i] = (uint8_t) byte;
        }
        return 0;
}

/* Makes the file object of one record and adds it. */
static int add(uapi16_manifest_writer *writer, const struct record *record,
               uapi16_error **reterr) {
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        int r;

        /* A name that a manifest can't hold fails here. */
        r = uapi16_file_object_new(record->name, &o, reterr);
        if (r < 0)
                return r;

        /* The setters store what they get. The add checks the object. The
         * root is a directory already, and a symbolic link has no mode. */
        r = 0;
        if (*record->name)
                r = uapi16_file_object_set_type(o, record->type);
        if (r >= 0 && !S_ISLNK(record->type))
                r = uapi16_file_object_set_mode(o, record->mode);
        if (r >= 0)
                r = uapi16_file_object_set_uid(o, 0);
        if (r >= 0)
                r = uapi16_file_object_set_gid(o, 0);
        if (r >= 0 && !S_ISDIR(record->type))
                r = uapi16_file_object_set_size(o, record->size);
        if (r >= 0 && record->target)
                r = uapi16_file_object_set_target(o, record->target,
                                                  strlen(record->target));
        if (r >= 0 && record->inode)
                /* Any number will do: the manifest gets its own. */
                r = uapi16_file_object_set_inode_token(o, record->inode);
        if (r < 0)
                return r;

        if (record->sha256) {
                char blob[sizeof("blobs/") + 2 * UAPI16_SHA256_SIZE];
                uapi16_sha256_digest_t hash;

                if (unhex(record->sha256, &hash) < 0)
                        return -EINVAL;
                r = uapi16_file_object_set_sha256(o, &hash);
                if (r < 0)
                        return r;
                /* The store has the data under the name of its hash, next to
                 * the manifest. */
                snprintf(blob, sizeof(blob), "blobs/%s", record->sha256);
                r = uapi16_file_object_set_contents_file(o, blob, reterr);
                if (r < 0)
                        return r;
        }

        /* An object that is refused is not added, and the writer goes on. */
        return uapi16_manifest_writer_add_object(writer, o, reterr);
}

int main(int argc, char *argv[]) {
        /* The writer borrows the descriptor of the directory until it is
         * freed. So the descriptor is declared first, and is closed last. */
        _cleanup_(closep) int out_fd = -1;
        _cleanup_(uapi16_manifest_options_freep)
                uapi16_manifest_options *options = NULL;
        _cleanup_(uapi16_manifest_writer_freep)
                uapi16_manifest_writer *writer = NULL;
        _cleanup_(uapi16_manifest_report_freep)
                uapi16_manifest_report *report = NULL;
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        int r;

        if (argc != 3) {
                fprintf(stderr, "usage: %s OUT-DIR NAME\n", argv[0]);
                return 2;
        }
        out_fd = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (out_fd < 0) {
                perror(argv[1]);
                return 1;
        }

        /* What this tool records of every file. */
        options = uapi16_manifest_options_new();
        r = uapi16_manifest_options_set_features(options,
                UAPI16_FEATURES(UAPI16_FEATURE_MODE, UAPI16_FEATURE_UID,
                                UAPI16_FEATURE_GID, UAPI16_FEATURE_SIZE,
                                UAPI16_FEATURE_SHA256, UAPI16_FEATURE_SYMLINK,
                                UAPI16_FEATURE_HARDLINK));
        if (r < 0) {
                fprintf(stderr, "options: %s\n", strerror(-r));
                return 1;
        }

        /* The file appears when the finish gives it its name. A writer that
         * is freed before that leaves nothing behind. */
        r = uapi16_manifest_writer_create_at(options, out_fd, argv[2],
                                             &writer, &error);
        for (size_t i = 0; r >= 0 && i < sizeof(records) / sizeof(records[0]);
             i++) {
                r = add(writer, &records[i], &error);
                if (r < 0)
                        fprintf(stderr, "'%s': ", records[i].name);
        }
        /* Two different records of one name, and a directory that is
         * missing, fail here. */
        if (r >= 0)
                r = uapi16_manifest_writer_finish(writer, &report, &error);
        if (r < 0) {
                fprintf(stderr, "%s", strerror(-r));
                /* A call that takes a `reterr` stored an error. A setter
                 * takes none and fails with its return value alone. */
                if (error) {
                        const char *path = uapi16_error_path(error);
                        const char *field = uapi16_error_field(error);
                        const char *problem = uapi16_error_problem(error);

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

        printf("%" PRIu64 " records\n",
               uapi16_manifest_report_files(report) +
                               uapi16_manifest_report_directories(report) +
                               uapi16_manifest_report_others(report));
        return 0;
}
