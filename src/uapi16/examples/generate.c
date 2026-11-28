/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Writes the manifest of a directory to a new file:
 * generate DIR OUT-DIR NAME
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

int main(int argc, char *argv[]) {
        _cleanup_(uapi16_manifest_options_freep)
                uapi16_manifest_options *options = NULL;
        _cleanup_(uapi16_manifest_report_freep)
                uapi16_manifest_report *report = NULL;
        /* `reterr` has to point to NULL before a call. */
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        _cleanup_(closep) int top_fd = -1;
        _cleanup_(closep) int out_fd = -1;
        int r;

        if (argc != 4) {
                fprintf(stderr, "usage: %s DIR OUT-DIR NAME\n", argv[0]);
                return 2;
        }

        /* The tree is read through the descriptor of its top, and the new
         * file is made below the descriptor of its directory. */
        top_fd = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC);
        out_fd = open(argv[2], O_PATH | O_DIRECTORY | O_CLOEXEC);
        if (top_fd < 0 || out_fd < 0) {
                perror("open");
                return 1;
        }

        /* A setter of options fails only for a call that is not valid. */
        options = uapi16_manifest_options_new();
        r = uapi16_manifest_options_add_features(options,
                UAPI16_FEATURES(UAPI16_FEATURE_MTIME,
                                UAPI16_FEATURE_USER_XATTR));
        if (r >= 0)
                /* The file is on disk before it has its name. */
                r = uapi16_manifest_options_set_sync(options, true);
        if (r < 0) {
                fprintf(stderr, "options: %s\n", strerror(-r));
                return 1;
        }

        /* Nothing has the name until the whole manifest is in the file. */
        r = uapi16_manifest_generate_at(options, out_fd, argv[3], top_fd,
                                        UAPI16_ADD_GRACEFUL, &report, &error);
        if (r < 0) {
                /* The library has no messages. The return value is the
                 * errno, and the error has the kind and the file. */
                const char *path = uapi16_error_path(error);

                switch (uapi16_error_kind(error)) {
                case UAPI16_ERROR_EXISTS:
                        fprintf(stderr,
                                "%s: there is a file of that name already\n",
                                argv[3]);
                        break;
                case UAPI16_ERROR_CHANGED:
                        fprintf(stderr, "%s/%s: changed while it was read\n",
                                argv[1], path ? path : "");
                        break;
                default:
                        /* An enum grows, so a switch has a default. */
                        fprintf(stderr, "%s/%s: %s\n", argv[1],
                                path ? path : "", strerror(-r));
                        break;
                }
                return 1;
        }

        printf("%" PRIu64 " files, %" PRIu64 " directories, %" PRIu64
               " others, %" PRIu64 " bytes\n",
               uapi16_manifest_report_files(report),
               uapi16_manifest_report_directories(report),
               uapi16_manifest_report_others(report),
               uapi16_manifest_report_bytes(report));
        if (uapi16_manifest_report_entries_omitted(report) > 0)
                fprintf(stderr,
                        "%" PRIu64 " files have names a manifest can't hold "
                        "and were left out\n",
                        uapi16_manifest_report_entries_omitted(report));
        return 0;
}
