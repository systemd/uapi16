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
- copy the data of the files a manifest describes and check its size and
  hash,
- build a manifest from the file objects a tool makes, in any order, for
  example while it writes a file system image,
- build the manifest of a tree of files on the host, which it reads
  through descriptors.

A manifest is read one record at a time. Memory use does not grow with
the size of the manifest. Building a large manifest takes room on disk
instead of memory.

Two checks are up to the caller: whether a manifest declares the order
of its file objects (RootObject::require_order) and whether an object
may be used at a given time (check_validity).

Signature objects are read and not verified. Data that is stored in an
encoding or that has to be fetched from a URL is not supported.

uapi16 reads JSON with serde_json. If another crate in the same build
turns on serde_json's arbitrary_precision feature, numbers are read
differently, see the crate documentation.

uapi16 supports Linux 5.10 or newer, the minimum baseline of systemd. It
does not build for any other system, Android included. uapi16 needs Rust
1.85 or newer. Some of its dependencies need a newer Rust in later
releases, such as sha2 from version 0.11.1 on. With an older Rust, use
resolver 3, the default of edition 2024, so that cargo picks versions
that build, or pin such a dependency, for example with
`cargo update -p sha2 --precise 0.11.0`.

A new minor release, such as 0.2.0, may change the API in ways that
break callers. Releases within a minor version, such as 0.1.1 after
0.1.0, stay compatible.

## Building a manifest

ManifestOptions says what a manifest records, and makes the
ManifestWriter that takes the file objects it lists. generate_at() writes
the manifest of a directory and everything below it to a new file:

```rust
use std::fs::File;
use std::path::Path;
use uapi16::{AddFlags, Features, ManifestOptions};

let esp = File::open("/efi")?;
let out_dir = File::open("/var/lib/manifests")?;
let report = ManifestOptions::new()
    .features(Features::DEFAULT | Features::MTIME)
    .generate_at(&out_dir, Path::new("esp.manifest"), &esp, AddFlags::NONE)?;
println!("{} files, {} bytes", report.files(), report.bytes());
```

The new file appears once the manifest is complete.
examples/mkmanifest.rs is a program that does this for the directory
and the file it is given:

    cargo run --example mkmanifest -- /efi esp.manifest

A tool that builds an image writes the manifest while it does: it gives
the writer the root with add_root() and a file object for every file
with add_object(), in any order, and finish() writes the manifest.

## C library

With the feature capi, the crate is also a C library, libuapi16. It
builds manifests, reads and writes them record by record, and checks the
data of the files they list. uapi16.h declares its functions and says
what each of them does. What holds for all of them is at its top.

examples/ has six programs that use it:

- generate.c writes the manifest of a directory.
- listing.c writes the manifest of a store from the records a tool has
  of its files.
- build.c copies a tree into an image and writes the manifest of the
  image while it does.
- assemble.c builds an image from a manifest and the files next to it.
- sorted.c writes a manifest record by record, in the order of the
  manifest.
- signed.c writes a manifest with a signature object and reads it back.

tests/capi.sh builds and runs them.

build.sh builds the static library with cargo and links the shared one
from it with the C compiler. install.sh installs both with uapi16.h and
uapi16.pc:

    ./build.sh
    ./install.sh --prefix=/usr

build.sh works from any directory of the tree. Its default --builddir
is in the target directory of cargo. install.sh looks in target/release
below the current directory, or in the release directory of
CARGO_TARGET_DIR where that is set. So run it from the top of the crate,
or pass --builddir. In the repository the scripts are
src/uapi16/build.sh and src/uapi16/install.sh, and the top is the top of
the repository. Both list their options with --help.

A program that uses the library gets the flags for it from pkg-config:

    cc -o program program.c $(pkg-config --cflags --libs uapi16)

## License

LGPL-2.1-or-later, see LICENSE.

[spec]: https://uapi-group.org/specifications/specs/file_manifest/
