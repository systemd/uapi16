# uapi16

uapi16 reads, checks and writes [UAPI.16 file manifests][spec].

A file manifest describes a tree of files. It is a JSON text sequence as
RFC 7464 defines it. The first object describes the root of the tree. An
object for every file follows, with its name, its type, its size, its
hash, its owner, its mode and its modification time. Signature objects
can follow the file objects, and a trailer object ends the manifest.

uapi16 can:

- read a manifest and check every object against the rules of the
  specification,
- write a manifest and check it the same way,
- do both without doing any I/O itself, for example in an async runtime,
- copy the data of the files a manifest describes and check its size and
  hash.

A manifest is read one record at a time. Memory use does not grow with
the size of the manifest.

Two checks are up to the caller: whether a manifest declares the order
of its file objects (RootObject::require_order) and whether an object
may be used at a given time (check_validity).

Signature objects are read and not verified. Data that is stored in an
encoding or that has to be fetched from a URL is not supported.

uapi16 reads JSON with serde_json. If another crate in the same build
turns on serde_json's arbitrary_precision feature, numbers are read
differently, see the crate documentation.

uapi16 supports Linux 5.10 or newer, the minimum baseline of systemd,
and Android. Reading the data of the files from the directory next to
the manifest works on Linux only. uapi16 needs Rust 1.85 or newer. Some
of its dependencies need a newer Rust in later releases, such as sha2
from version 0.11.1 on. With an older Rust, use resolver 3, the default
of edition 2024, so that cargo picks versions that build, or pin such a
dependency, for example with `cargo update -p sha2 --precise 0.11.0`.

A new minor release, such as 0.2.0, may change the API in ways that
break callers. Releases within a minor version, such as 0.1.1 after
0.1.0, stay compatible.

## License

LGPL-2.1-or-later, see LICENSE.

[spec]: https://uapi-group.org/specifications/specs/file_manifest/
