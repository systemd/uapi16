# uapi16

This repository holds uapi16, a Rust crate that reads, checks and
writes [UAPI.16 file manifests][spec], and its C library, libuapi16. The
crate is in src/uapi16, and its README describes both.

## C library

From the top of the repository, these build the C library and install
it into /usr:

    src/uapi16/build.sh
    src/uapi16/install.sh --prefix=/usr

## Submitting changes

Changes go in as pull requests on GitHub. Every commit carries a
`Signed-off-by:` line from its author. `git commit -s` adds one. With
it the author certifies the Developer Certificate of Origin in the file
DCO. Merge commits don't need one.

## License

LGPL-2.1-or-later, see LICENSE.

[spec]: https://uapi-group.org/specifications/specs/file_manifest/
