# TODO

Work that is planned for a later release, and ideas that are not decided
yet.

## Manifest builder

- A flag that leaves out every mount point a walk doesn't cross. Without
  `CROSS_MOUNTS`, `generate_at()` and `generate()` record a directory
  that is a mount point as an empty directory with the attributes of the
  mounted root, and a file or a device node that is a mount point as the
  mount shows it. The flag leaves out all of them, directories and files
  alike. It could be `AddFlags::DROP_LEAF_MOUNTS` and
  `UAPI16_ADD_DROP_LEAF_MOUNTS`, or have a name such as
  `ONE_FILE_SYSTEM`. What it means together with `CROSS_MOUNTS` is still
  open, and so is whether it also leaves out an automount point that
  isn't triggered, which a walk records as an empty directory.

- Add and finish in steps, so that a caller can stop an add between
  two of them or keep each call short, as an event loop has to. The
  builder works in steps inside already, so this is an addition to the
  API in Rust and C: a call that sets up an add or the finish, a step
  with a budget, and an end that says how the add ended. For every step
  to stay short, more has to work in parts first:
  - The doubling of the table of hard links. The step that begins one
    writes about 0.9 MiB whatever its budget, every step that copies
    writes twice its budget, and the step that ends one truncates the
    old file, in 3 to 45 ms for tables of 128 MiB to 2 GiB.
  - A merge. One step can read up to 32 MiB into the buffers of its
    runs.
  - The stages of a step. One that goes on from one stage to the next
    can do two or three times its budget.
  - Very small file objects of a caller. A budget in bytes lets a step
    over them take ten times as long as one over files, and a weight
    per record would even that out.

- Read no page of a new table of hard links while it is still a hole.
  Today the copy of a doubling reads every new page from its file before
  it writes it, so the copy reads three times what it copies. Knowing
  which pages are still holes needs no memory that grows with the table:
  the copy touches the pages of each half of the new table in order,
  except for groups that wrapped around the end of the old table.

- Keep the table of hard links on disk in one file. Today a table on
  disk doubles into a second file, and the two take turns, so the table
  holds one more descriptor and is copied at every doubling. Two designs
  could manage with a single pages file:
  - The new table appended past the old one, with the old part punched
    out afterwards. FAT can't punch holes, so there the space would
    double.
  - Linear hashing, which splits one page at a time in place, so there's
    no doubling copy at all. It would mean a different table.

- Check and escape the bytes of a name a word at a time. Today the split
  of a name into its components, the check of the order of names and the
  escape of a record's strings, which serde_json does, go through a name
  a byte at a time. Over long names the adds and the finish take up to a
  third longer in one build than in another of the same source, by where
  these loops land.

- Give the room of a run back on a tmpfs with huge pages. statx() says
  2 MiB there, and the sort gives back only whole blocks of that size,
  so a run keeps up to 2 MiB of its file until the merge is over: 1256
  MiB for the 627 runs of 1.2e8 records, where xfs keeps 2 MiB. The
  kernel frees smaller holes there too, so the page size would do as
  the block.

- Close the window between the check of a directory for an automount
  point and its open by name. A directory that becomes an automount
  point in between is triggered, and `generate_at()` or `generate()`
  fails with `TreeProblem::Changed`. Where the kernel has `O_EMPTYPATH`,
  the handle can be reopened without a lookup, and since Linux 6.18
  `openat2()` with `RESOLVE_NO_XDEV` doesn't trigger an automount.

- Signing the manifest a builder writes. systemd-manifest make feeds the
  text of every record into its signer as it writes the record, and
  appends the signature record at the end.

- A CI job with privileges for what the FAT job doesn't cover: block
  devices and device nodes made with mknod, the append-only and
  immutable flags, NOCOW, btrfs subvolumes, an mtime after 2554 on
  btrfs, automount points, and a file system that keeps a file that was
  unlinked while it is open, as NFS does.

- An add of a descriptor that takes the hash of the data of a regular
  file from its caller and doesn't read the data. A tool that builds an
  image hashes the data while it copies it, with `Sha256Context`, and
  adds it with `add_object()`. But then it reads the attributes of the
  file itself, extended attributes and flags included, and numbers the
  hard links. The new add reads everything but the data from the
  descriptor. It could be
  `ManifestWriter::add_hashed(entry, name, sha256)` and
  `uapi16_manifest_writer_add_hashed()`. The hash is taken as it is,
  like the hash of a file object of a caller. Still open: whether the
  add also takes how many bytes were hashed and what `statx()` said of
  the file before they were read, so that a file that changed while it
  was copied fails with `TreeProblem::Changed`, and whether the hasher
  comes from the writer, so that it hashes only what the manifest
  records.

## C API

- A second way to pass features, such as one call per feature, once
  there are more than 64 of them.
- Options for the install script to leave out the static or the shared
  library.

## pathrs

- Dropping pathrs remains an option. When a call of pathrs fails, pathrs
  looks up the path of the descriptor of the call in /proc for its
  error, and it panics where it can't: where /proc is missing or is not
  a procfs, and on a real procfs where no descriptor is left to open
  /proc with. Both panics are in pathrs 0.2.6, the latest release, and
  gone from the main branch of libpathrs since 2026-11-27 (8e60d5f
  "procfs: drop panic in ProcfsBase::into_path", 0ce0614 "*: get rid of
  silly panics"). Until a release has that, in both cases
  `PinnedDirectory` panics for a name it can't resolve, and it and the
  builder panic when they reopen a file on a kernel without
  `O_EMPTYPATH`. A release of pathrs that returns an error there instead
  of panicking takes care of this.

- Without pathrs, `PinnedDirectory` resolves a name with `openat2()`,
  `RESOLVE_IN_ROOT` and `RESOLVE_NO_MAGICLINKS`, plus
  `RESOLVE_NO_SYMLINKS` unless it follows symbolic links, and tries
  again on `EAGAIN`. Where the kernel has no `O_EMPTYPATH`, a file is
  reopened through /proc/thread-self/fd and checked to be the inode of
  its descriptor once it is open. That fails where /proc is not usable
  instead of panicking, but unlike pathrs it opens what the link leads
  to before it checks it. The builder's reopen, its only use of pathrs,
  changes the same way.

- Still open: where seccomp refuses `openat2()`, a walk of one
  component at a time with `O_NOFOLLOW` still works, but
  `follow_symlinks(true)` needs a resolver of our own, or fails there.

## Maybe

- Accepting `AT_FDCWD` as the directory descriptor of `create_at()` and
  `generate_at()`, in C and as rustix's `CWD` in Rust.
  Today it is refused with `EBADF`, like any other negative descriptor.
