// SPDX-License-Identifier: LGPL-2.1-or-later
//! Manifests written by systemd's own tool, read and written back. They
//! are copies of the fixtures of ufat, whose tests/fixtures/README.md says
//! how they were made.

use std::path::{Path, PathBuf};

use uapi16::{Error, FileObject, InodeType, Object, Order, Reader, RootObject, Signature, Writer};

/// A manifest read to its end: its root file object, its file objects and
/// its signature objects.
#[derive(Debug, PartialEq)]
struct Manifest {
    root: RootObject,
    files: Vec<FileObject>,
    signatures: Vec<Signature>,
}

impl Manifest {
    /// Reads the manifest `bytes` to its end.
    fn read(bytes: &[u8]) -> Result<Manifest, Error> {
        let mut reader = Reader::open(bytes)?;
        let mut manifest = Manifest {
            root: reader.root().clone(),
            files: Vec::new(),
            signatures: Vec::new(),
        };
        for object in &mut reader {
            match object? {
                Object::File(file) => manifest.files.push(*file),
                Object::Signature(signature) => manifest.signatures.push(signature),
                other => panic!("{:?} is neither a file object nor a signature", other),
            }
        }
        Ok(manifest)
    }

    /// Reads the fixture `name` of the case `case`.
    fn load(case: &str, name: &str) -> Manifest {
        let path = fixture(case, name);
        let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
        Manifest::read(&bytes).unwrap_or_else(|e| panic!("{}: {}", path.display(), e))
    }

    /// The manifest the writer writes for the objects.
    fn write(&self) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::begin(Vec::new(), &self.root)?;
        for file in &self.files {
            writer.file(file)?;
        }
        for signature in &self.signatures {
            writer.signature(signature)?;
        }
        writer.finish()
    }

    /// The names of the file objects, in the order of the manifest.
    fn names(&self) -> Vec<&str> {
        self.files.iter().map(|file| file.name.as_str()).collect()
    }
}

/// The path of the fixture `name` of the case `case`.
fn fixture(case: &str, name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(case)
        .join(name)
}

#[test]
fn every_fixture_parses() {
    let esp = Manifest::load("esp", "Uapi16Manifest");
    assert_eq!(esp.files.len(), 13);
    assert_eq!(
        esp.files
            .iter()
            .filter(|e| e.inode_type == InodeType::Directory)
            .count(),
        6
    );
    assert_eq!(esp.root.inode.mtime_nsec, Some(1_699_999_000_000_000_000));
    assert!(esp.signatures.is_empty());
    assert_eq!(
        esp.names(),
        vec![
            "EFI",
            "EFI/BOOT",
            "EFI/BOOT/BOOTX64.EFI",
            "EFI/Linux",
            "EFI/Linux/linux-6.12.4-200.fc41.x86_64+3.efi",
            "EFI/systemd",
            "EFI/systemd/systemd-bootx64.efi",
            "loader",
            "loader/entries",
            "loader/entries/fedora.conf",
            "loader/entries.srel",
            "loader/loader.conf",
            "loader/random-seed",
        ]
    );
    let uki = &esp.files[4];
    assert_eq!(uki.size, Some(6395));
    assert_eq!(uki.inode.mode.map(u32::from), Some(0o664));
    assert_eq!(uki.inode.mtime_nsec, Some(1_700_000_002_000_000_000));
    assert!(!uki.inode.is_read_only());
    assert!(uki.contents.is_empty());

    // The signature does not change the file objects.
    let signed = Manifest::load("esp", "signed.Uapi16Manifest");
    assert_eq!(signed.signatures.len(), 1);
    assert_eq!(signed.files, esp.files);
    assert_eq!(signed.root, esp.root);

    // Fewer fields, same tree.
    let lean = Manifest::load("esp", "size-hash-mtime.Uapi16Manifest");
    assert_eq!(lean.names(), esp.names());
    assert!(lean.files.iter().all(|e| e.inode.mode.is_none()));
    assert!(lean
        .files
        .iter()
        .zip(&esp.files)
        .all(|(a, b)| a.size == b.size && a.sha256 == b.sha256 && a.inode.mtime_nsec == b.inode.mtime_nsec));
    let none = Manifest::load("esp", "none.Uapi16Manifest");
    assert_eq!(none.names(), esp.names());
    assert!(none
        .files
        .iter()
        .all(|e| e.size.is_none() && e.sha256.is_none() && e.inode.mtime_nsec.is_none()));

    let special = Manifest::load("special", "Uapi16Manifest");
    assert_eq!(special.files.len(), 13);
    let types: Vec<InodeType> = special.files.iter().map(|e| e.inode_type).collect();
    assert_eq!(types.iter().filter(|&&t| t == InodeType::Symlink).count(), 1);
    assert_eq!(types.iter().filter(|&&t| t == InodeType::Fifo).count(), 1);
    let link = special
        .files
        .iter()
        .find(|e| e.inode_type == InodeType::Symlink)
        .unwrap();
    assert_eq!(link.contents[0].literal(), Some(&b"a.txt"[..]));
    let hardlinks: Vec<&str> = special
        .files
        .iter()
        .filter(|e| e.inode_token.is_some())
        .map(|e| e.name.as_str())
        .collect();
    assert_eq!(hardlinks, vec!["sub/hl_a", "sub/hl_b"]);
    let readonly = special.files.iter().find(|e| e.name == "sub/readonly.bin").unwrap();
    assert_eq!(readonly.inode.mode.map(u32::from), Some(0o444));
    assert!(readonly.inode.is_read_only());
    assert!(special.names().contains(&"sub/\u{fc}mlaut \u{221e}.txt"));

    let empty = Manifest::load("empty", "Uapi16Manifest");
    assert!(empty.files.is_empty());
    assert_eq!(empty.root.inode.mtime_nsec, Some(1_700_000_200_000_000_000));
}

/// The reader reads every manifest systemd-manifest wrote, and what the
/// writer writes for one reads back as the same manifest. That holds since
/// ufat's make-fixtures.sh took the hash of no data out of the empty file
/// of the special case: the writer leaves out a hash given next to the
/// size 0, and the reader marks the one it fills in as filled in, so the
/// objects would differ in that mark.
#[test]
fn reads_and_writes_back_every_fixture() {
    for (case, name, files, signatures) in [
        ("esp", "Uapi16Manifest", 13, 0),
        ("esp", "signed.Uapi16Manifest", 13, 1),
        ("esp", "size-hash-mtime.Uapi16Manifest", 13, 0),
        ("esp", "none.Uapi16Manifest", 13, 0),
        ("special", "Uapi16Manifest", 13, 0),
        ("empty", "Uapi16Manifest", 0, 0),
    ] {
        let path = fixture(case, name);
        let read = Manifest::load(case, name);
        assert_eq!(
            (read.files.len(), read.signatures.len()),
            (files, signatures),
            "{}",
            path.display()
        );
        assert_eq!(read.root.order, Some(Order::CodePoint), "{}", path.display());
        let written = read.write().unwrap_or_else(|e| panic!("{}: {}", path.display(), e));
        assert_eq!(Manifest::read(&written).unwrap(), read, "{}", path.display());
    }
}
