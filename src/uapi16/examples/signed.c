/* SPDX-License-Identifier: LGPL-2.1-or-later */

/*
 * Writes a manifest with a signature object, then reads it back with what
 * the signature objects sign: signed MANIFEST
 *
 * The library reads and writes signature objects. It neither makes nor
 * verifies a signature: sign() stands in for an OpenPGP or an X.509
 * implementation here.
 */
#define _GNU_SOURCE
/* Inode numbers and sizes of 64 bits, also where long has 32. */
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <uapi16.h>

#define _cleanup_(f) __attribute__((cleanup(f)))

static void closep(int *fd) {
        if (*fd >= 0)
                close(*fd);
}

/* Stands in for a signer: what it stores is no signature. */
static void sign(const uapi16_sha256_digest_t *digest,
                 uint8_t ret[UAPI16_SHA256_SIZE]) {
        for (size_t i = 0; i < UAPI16_SHA256_SIZE; i++)
                ret[i] = digest->bytes[UAPI16_SHA256_SIZE - 1 - i];
}

/* Hashes the first `size` bytes of the file `fd`. */
static int hash_start(int fd, uint64_t size, uapi16_sha256_digest_t *ret) {
        _cleanup_(uapi16_sha256_freep) uapi16_sha256 *sha = NULL;
        static char buffer[1 << 16];
        uint64_t at = 0;
        int r;

        sha = uapi16_sha256_new();
        while (at < size) {
                size_t want = size - at < sizeof(buffer)
                              ? (size_t) (size - at)
                              : sizeof(buffer);
                ssize_t n = pread(fd, buffer, want, (off_t) at);

                if (n < 0 && errno == EINTR)
                        continue;
                if (n < 0)
                        return -errno;
                if (n == 0)
                        return -EIO; /* the file is shorter than that */
                r = uapi16_sha256_update(sha, buffer, (size_t) n);
                if (r < 0)
                        return r;
                at += (uint64_t) n;
        }
        return uapi16_sha256_finish(sha, ret);
}

static int write_signed(const char *path, uapi16_error **reterr) {
        static const uapi16_sha256_digest_t hello = { .bytes = {
                0x2c, 0xf2, 0x4d, 0xba, 0x5f, 0xb0, 0xa3, 0x0e,
                0x26, 0xe8, 0x3b, 0x2a, 0xc5, 0xb9, 0xe2, 0x9e,
                0x1b, 0x16, 0x1e, 0x5c, 0x1f, 0xa7, 0x42, 0x5e,
                0x73, 0x04, 0x33, 0x62, 0x93, 0x8b, 0x98, 0x24
        } };
        /* The writer borrows the descriptor until it is freed. So the
         * descriptor is declared first, and is closed last. */
        _cleanup_(closep) int fd = -1;
        _cleanup_(uapi16_manifest_options_freep)
                uapi16_manifest_options *options = NULL;
        _cleanup_(uapi16_writer_freep) uapi16_writer *writer = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *file = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *signature = NULL;
        uapi16_sha256_digest_t digest;
        uint8_t signed_digest[UAPI16_SHA256_SIZE];
        struct stat st;
        int r;

        fd = open(path, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
        if (fd < 0)
                return -errno;

        /* The default features record sizes and hashes. */
        options = uapi16_manifest_options_new();
        r = uapi16_writer_begin(options, fd, NULL, &writer, reterr);
        if (r < 0)
                return r;
        r = uapi16_file_object_new("hello.txt", &file, reterr);
        if (r < 0)
                return r;
        r = uapi16_file_object_set_size(file, 5);
        if (r >= 0)
                r = uapi16_file_object_set_sha256(file, &hello);
        if (r >= 0)
                r = uapi16_writer_file(writer, file, reterr);
        if (r < 0)
                return r;

        /* Every record is written before its call returns. So the file
         * holds the manifest up to here, and that is what the signature
         * objects sign. */
        if (fstat(fd, &st) < 0)
                return -errno;
        r = hash_start(fd, (uint64_t) st.st_size, &digest);
        if (r < 0)
                return r;
        sign(&digest, signed_digest);

        r = uapi16_signature_new("openpgp", &signature);
        if (r >= 0)
                r = uapi16_signature_set_key(signature, "an example key",
                                             strlen("an example key"));
        if (r >= 0)
                r = uapi16_signature_set_data(signature, signed_digest,
                                              sizeof(signed_digest));
        /* No file object can follow a signature object. */
        if (r >= 0)
                r = uapi16_writer_signature(writer, signature, reterr);
        /* The trailer ends the manifest. */
        if (r >= 0)
                r = uapi16_writer_finish(writer, reterr);
        return r;
}

static int read_signed(const char *path, uapi16_error **reterr) {
        /* The reader borrows the descriptor until it is freed. */
        _cleanup_(closep) int fd = -1;
        _cleanup_(uapi16_reader_freep) uapi16_reader *reader = NULL;
        _cleanup_(uapi16_file_object_freep) uapi16_file_object *o = NULL;
        _cleanup_(uapi16_signature_freep) uapi16_signature *s = NULL;
        uapi16_sha256_digest_t digest;
        uint8_t expected[UAPI16_SHA256_SIZE];
        uint64_t signed_len;
        int r;

        fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0)
                return -errno;
        r = uapi16_reader_open(fd, &reader, reterr);
        if (r < 0)
                return r;

        /* The file objects come first. One object serves the whole loop:
         * each call clears it and fills it again. */
        while ((r = uapi16_reader_next(reader, &o, reterr)) == UAPI16_READ_FILE)
                printf("%s\n", uapi16_file_object_name(o));
        if (r < 0)
                return r;
        if (r == UAPI16_READ_END) {
                /* The trailer was read: the manifest is complete. */
                printf("no signature object\n");
                return 0;
        }
        /* A later library can return a number that this program does not
         * know, which is an error here. */
        if (r != UAPI16_READ_SIGNATURES) {
                fprintf(stderr,
                        "uapi16_reader_next() returned %d, which this program "
                        "does not know\n",
                        r);
                return -EOPNOTSUPP;
        }

        /* UAPI16_READ_SIGNATURES: signature objects follow, and the reader
         * has what they sign. That is the start of the manifest, up to the
         * first of them. pread() leaves alone where the reader reads on. */
        r = uapi16_reader_signed_len(reader, &signed_len);
        if (r >= 0)
                r = hash_start(fd, signed_len, &digest);
        if (r < 0)
                return r;
        sign(&digest, expected);

        while ((r = uapi16_reader_next_signature(reader, &s, reterr)) ==
               UAPI16_READ_SIGNATURE) {
                size_t size;
                const void *data = uapi16_signature_data(s, &size);

                printf("a signature by %s: %s\n", uapi16_signature_mechanism(s),
                       data && size == sizeof(expected) &&
                               !memcmp(data, expected, size) ? "good" : "bad");
        }
        if (r < 0)
                return r;
        /* UAPI16_READ_END: the trailer was read and checked, and the
         * manifest is complete. Any other number is one that this program
         * does not know. */
        if (r != UAPI16_READ_END) {
                fprintf(stderr,
                        "uapi16_reader_next_signature() returned %d, which "
                        "this program does not know\n",
                        r);
                return -EOPNOTSUPP;
        }
        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(uapi16_error_freep) uapi16_error *error = NULL;
        int r;

        if (argc != 2) {
                fprintf(stderr, "usage: %s MANIFEST\n", argv[0]);
                return 2;
        }
        r = write_signed(argv[1], &error);
        if (r >= 0)
                r = read_signed(argv[1], &error);
        if (r < 0) {
                fprintf(stderr, "%s: %s", argv[1], strerror(-r));
                if (error && uapi16_error_problem(error))
                        fprintf(stderr, ", %s", uapi16_error_problem(error));
                fputc('\n', stderr);
                return 1;
        }
        return 0;
}
