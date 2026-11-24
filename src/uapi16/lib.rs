// SPDX-License-Identifier: LGPL-2.1-or-later
//! UAPI.16 file manifests: reading, checking and writing them.
//!
//! A [UAPI.16 file manifest] describes a tree of files. It is an RFC 7464
//! JSON text sequence: one JSON object per record, each record after an
//! ASCII record separator. The first object describes the root of the
//! tree. One object for every file follows, with its name, its type and
//! what else is known of it: size, hash, owner, mode, time. Signature
//! objects can come after the file objects, and a trailer object ends the
//! manifest.
//!
//! - [`Reader`] reads a manifest record by record from a [`Read`]. It
//!   checks every object against the rules of the specification, and
//!   where it comes: right after the object of its directory, in the order
//!   the manifest declares, and with the fields of the [`Features`] the
//!   manifest records.
//! - [`Writer`] writes a manifest record by record to a [`Write`], and
//!   checks it the way the reader does. [`Sha256Context`] computes the
//!   hash of data the caller passes it, such as a file while the caller
//!   copies it, and does no I/O of its own. [`Sha256Context::finalize`]
//!   returns the hash.
//! - [`ManifestOptions`] builds the manifest of a tree of files on the
//!   host, which it reads through descriptors, and [`ManifestWriter`] one
//!   of file objects that the caller made. [`ManifestReport`] says what it
//!   lists.
//! - [`RootObject`], [`FileObject`], [`ContentsObject`] and
//!   [`SignatureObject`] are the objects, and [`Name`], [`InodeType`],
//!   [`Mode`], [`Sha256`] and [`Uuid`] what their fields hold. Each field
//!   has a getter named after it, and most have a setter. The inode
//!   attributes and the identity of the file system are changed in place
//!   instead, through [`FileObject::inode_mut`], [`RootObject::inode_mut`]
//!   and [`RootObject::file_system_mut`], and the marks of what a reader
//!   filled in, [`FilledIn`], can only be read. What the root file object
//!   and a file object both have is in [`InodeAttributes`] and
//!   [`ValidityWindow`].
//! - [`DataProvider`] is where the data of the files comes from when a
//!   manifest is applied. [`StreamProvider`] takes it from one stream
//!   that carries it all. [`DirectoryProvider`] takes it from the files
//!   next to the manifest, in a [`PinnedDirectory`].
//!   [`FileObject::copy_data`] copies the data of a file and checks it
//!   against the manifest with a [`DataCheck`].
//!
//! Data that does not go through a [`Write`] is checked with a
//! [`DataCheck`]: [`DataCheck::update`] takes it as it comes, and
//! [`DataCheck::finish`] says whether it has the size and the hash the
//! manifest gives.
//!
//! A manifest is input from outside and can be very large. Reading one
//! takes time in proportion to its size, and keeps one record without its
//! separator and the name of the file object before it in memory: less
//! than [`MAX_RECORD_SIZE`] and at most [`Name::MAX_LEN`] bytes. Nothing
//! grows with the manifest. Writing one keeps the record it puts together,
//! its separator included, and the name of the file object before it.
//!
//! Two checks are up to the caller: whether a manifest declares the order
//! of its file objects, [`RootObject::require_order`], and whether an
//! object may be used at a given time, [`RootObject::check_validity`] and
//! [`FileObject::check_validity`]. What is true of a directory is true of
//! everything in it, but the validity of a directory does not carry over
//! to its entries: [`FileObject::check_validity`] looks at the object
//! alone. A caller that uses an entry checks the objects of the
//! directories it is in as well, which come before it in the manifest.
//!
//! Signature objects are read and not verified: that takes an OpenPGP or
//! an X.509 implementation. [`Reader::signed_len`] says how much of the
//! manifest they sign. Data that is stored in an encoding or that has to
//! be fetched from a URL is not taken.
//!
//! The reader takes every field the specification has. A field it does
//! not know is passed over, as the specification asks, unless it holds a
//! number too large for a double, such as 1E400, or more arrays and
//! objects inside each other than serde_json reads. serde_json reads 127,
//! the object of the record included.
//!
//! The reader reads JSON with serde_json. The features of serde_json are
//! the same for every crate of a build, and uapi16 cannot turn one off that
//! another crate turns on. With arbitrary_precision, serde_json hands every
//! number with a fraction or an exponent, -0 and every integer that does
//! not fit into 64 bits to the reader as an object. Then a field the reader
//! does not know may hold a number too large for a double. A field it knows
//! that holds such a number has a value of the wrong type instead of not
//! being JSON. A record that is one of these numbers, such as 1.5 or -0, is
//! read as an object without a name.
//!
//! [UAPI.16 file manifest]: https://uapi-group.org/specifications/specs/file_manifest/
//! [`Read`]: std::io::Read
//! [`Write`]: std::io::Write

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(not(target_os = "linux"))]
compile_error!("uapi16 supports Linux only");

mod base64;
mod blocking;
// The C API, which is unsafe code as well: C hands over pointers that nothing
// checks. The module says what it relies on.
#[cfg(feature = "capi")]
#[allow(unsafe_code)]
mod capi;
mod content;
mod decode;
mod digest;
mod directory;
mod error;
mod features;
mod hardlink;
mod hex;
// The ioctls rustix has no call for and the lookups in the user database
// are the only unsafe code of the crate without the C API, but for the one
// cast of the module name. Each is in a module of its own, which says what
// it makes sure of. Only the module sys calls them.
#[allow(unsafe_code)]
mod ioctl;
mod listing;
mod manifest;
mod metadata;
mod name;
#[allow(unsafe_code)]
mod nss;
mod object;
mod optional;
mod reader;
mod record;
mod scratch;
mod sequence;
mod sort;
mod strict;
mod sys;
mod tree;
mod walk;
mod writer;

pub use blocking::{Reader, Writer};
pub use content::{DataCheck, DataLocation, DataProvider, DirectoryProvider, ExternalFile, StreamProvider};
pub use digest::{InvalidDigest, Sha256, Sha256Context};
pub use directory::PinnedDirectory;
pub use error::{
    DataProblem, Error, ErrorKind, Field, Problem, SourceProblem, TreeProblem, UnsupportedData, ValidityProblem,
};
pub use features::{Features, Order, UnknownFeature};
pub use manifest::{ManifestOptions, ManifestReport, ManifestWriter};
pub use name::{Name, NameBuf, NameError, NameProblem};
pub use object::{
    ContentsObject, ContentsSource, FatSerial, FileObject, FileSystemIdentity, FilledIn, GptPartition, InodeAttributes,
    InodeType, InvalidFatSerial, InvalidMode, InvalidUuid, Mode, RootObject, SignatureObject, UnknownInodeType, Uuid,
    Validity, ValidityWindow,
};
pub use reader::Object;
pub use walk::AddFlags;

/// The media type of a manifest, which its first object carries.
pub const MEDIA_TYPE: &str = "application/vnd.uapi.16.manifest";
/// The media type of a signature object.
pub const SIGNATURE_MEDIA_TYPE: &str = "application/vnd.uapi.16.signature";
/// The media type of the trailer object.
pub const TRAILER_MEDIA_TYPE: &str = "application/vnd.uapi.16.trailer";
/// The name of a manifest that is stored in the tree it describes.
pub const FILENAME: &str = "Uapi16Manifest";
/// What the name of a manifest ends in that is stored next to what it
/// describes.
pub const SUFFIX: &str = ".Uapi16Manifest";
/// The byte every record starts with, the ASCII record separator.
pub const RECORD_SEPARATOR: u8 = 0x1E;
/// The byte that ends a record behind its JSON text, a newline.
pub(crate) const RECORD_END: u8 = b'\n';
/// The namespace of the extended attributes of a file object, the one the
/// specification defines.
pub(crate) const USER_NAMESPACE: &str = "user";
/// The largest record a reader takes and a writer writes, from its record
/// separator up to the next one as the specification counts it, the same
/// as systemd's.
pub const MAX_RECORD_SIZE: usize = 4 * 1024 * 1024;
/// The most contents objects a file object can have, the same as for
/// systemd.
pub const MAX_CONTENTS: usize = 256;

/// What the strings of a manifest may not hold beyond what JSON forbids:
/// noncharacters and the NUL character, escaped or not.
pub(crate) const STRING_RULES: strict::StringRules =
    strict::StringRules::NO_NONCHARACTERS.union(strict::StringRules::NO_NUL);

/// What the tests of this crate build manifests from.
#[cfg(test)]
pub(crate) mod testing {
    use super::blocking::READ_SIZE;
    use super::object::{DosFlags, InodeFlags};
    use super::{
        ContentsObject, ContentsSource, Error, Features, FileObject, GptPartition, InodeType, Mode, NameBuf, Object,
        Reader, RootObject, Sha256, SignatureObject, Uuid, Validity, Writer, RECORD_END, RECORD_SEPARATOR,
    };
    use crate::strict::{ParseError, Skip, Strict};
    use crate::tree::{InodeId, Status};
    use rustix::fs::OFlags;
    use serde_core::de::DeserializeSeed;
    use std::collections::BTreeMap;
    use std::fs;
    use std::num::NonZeroU64;
    use std::os::fd::{AsFd, AsRawFd, RawFd};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::{Mutex, PoisonError};

    /// Whether the kernel has O_EMPTYPATH, asked of the kernel itself. What
    /// the process found out about it is no answer while tests run: those
    /// that open a file both ways set it for a while.
    pub(crate) fn has_empty_path() -> bool {
        use rustix::fs::{Mode, OFlags};
        let handle = rustix::fs::open(".", OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).unwrap();
        let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::from_bits_retain(crate::sys::EmptyPath::FLAG);
        match rustix::fs::openat(&handle, "", flags, Mode::empty()) {
            Ok(_) => true,
            Err(rustix::io::Errno::NOENT) => false,
            Err(e) => panic!("{}", e),
        }
    }

    /// A directory of its own below the temporary directory, removed with
    /// everything in it when the test ends.
    pub(crate) struct TempDir(pub(crate) PathBuf);

    /// The unit `st_blocks` counts the room of a file in, in bytes.
    pub(crate) const ST_BLOCKS_UNIT: u64 = 512;

    impl TempDir {
        /// What the script of [`TempDir::rerun_on`] exits with where it
        /// cannot mount the file system.
        const NOT_MOUNTED: i32 = 77;

        pub(crate) fn new(name: &str) -> TempDir {
            let path = std::env::temp_dir().join(format!("uapi16-{}-{}", name, std::process::id()));
            // What a test of the same name in a process of the same number
            // left behind.
            let _ = fs::remove_dir_all(&path);
            fs::create_dir(&path).unwrap();
            TempDir(path)
        }

        /// Runs the test `test` of the test binary again in a process for
        /// which a file system of the type `file_system` is mounted over
        /// this directory, with the mount options `options` if there are
        /// any, and with the directory as the value of the variable
        /// `variable`.
        ///
        /// The mount takes a user and a mount namespace, which unshare(1)
        /// makes. Where it cannot, or where the file system can't be
        /// mounted in them, the test is skipped.
        pub(crate) fn rerun_on(&self, file_system: &str, options: Option<&str>, test: &str, variable: &str) {
            let works = Command::new("unshare").args(["-Urm", "true"]).output();
            if !works.is_ok_and(|output| output.status.success()) {
                eprintln!("skipping: unshare -Urm does not work here");
                return;
            }
            // What is mounted has the name of its type, as for every file
            // system without a device, and -o is there only with options.
            let script = format!(
                r#"mount -t "$1" ${{2:+-o "$2"}} "$1" "$3" || exit {}; exec "$4" --exact "$5" --nocapture"#,
                TempDir::NOT_MOUNTED
            );
            let output = Command::new("unshare")
                .args(["-Urm", "sh", "-c", &script, "sh", file_system])
                .arg(options.unwrap_or_default())
                .arg(&self.0)
                .arg(std::env::current_exe().unwrap())
                .arg(test)
                .env(variable, &self.0)
                .output()
                .unwrap();
            if output.status.code() == Some(TempDir::NOT_MOUNTED) {
                eprintln!("skipping: no {} can be mounted here", file_system);
                return;
            }
            // A test binary that runs no test succeeds as well.
            let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
            assert!(output.status.success() && ran, "{:?}", output);
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A file this process has open: its status, as a walk finds it, with
    /// the inode and the size the status has.
    #[derive(Clone, Copy, Debug)]
    pub(crate) struct OpenFile {
        pub(crate) inode: InodeId,
        pub(crate) size: u64,
        pub(crate) status: Status,
        /// The descriptor the process has of it.
        pub(crate) descriptor: RawFd,
    }

    impl OpenFile {
        /// The files this process has open that were made in the directory
        /// `dir`, which are the scratch files made there where a test opens
        /// nothing else in it. procfs says of every descriptor where its
        /// file was made.
        ///
        /// Looking takes a handle of every file the process has open, for
        /// a moment. So one test looks at a time: another one would take
        /// such a handle for one more descriptor of a file of its own.
        pub(crate) fn made_in(dir: &Path) -> Vec<OpenFile> {
            static LOOKING: Mutex<()> = Mutex::new(());
            let _looking = LOOKING.lock().unwrap_or_else(PoisonError::into_inner);
            let dir = fs::canonicalize(dir).unwrap();
            let flags = OFlags::PATH | OFlags::CLOEXEC;
            let mut files = Vec::new();
            for entry in fs::read_dir("/proc/self/fd").unwrap() {
                let entry = entry.unwrap();
                // Other tests close their descriptors meanwhile. A handle
                // of the file stays the file it is while it is looked at.
                let Ok(handle) = rustix::fs::open(entry.path(), flags, rustix::fs::Mode::empty()) else {
                    continue;
                };
                // Another test can have a file open that is so deep in a
                // tree that procfs cannot say where: that is none of these.
                let Ok(made_at) = fs::read_link(format!("/proc/self/fd/{}", handle.as_raw_fd())) else {
                    continue;
                };
                if made_at.parent() == Some(dir.as_path()) {
                    let status = Status::of(handle.as_fd()).unwrap();
                    files.push(OpenFile {
                        inode: status.identity.inode_id(),
                        size: status.size,
                        status,
                        descriptor: entry.file_name().to_str().unwrap().parse().unwrap(),
                    });
                }
            }
            files
        }
    }

    /// The root file object that says nothing but that this is a manifest.
    pub(crate) const ROOT: &str = r#"{"mediaType":"application/vnd.uapi.16.manifest"}"#;
    /// The trailer object.
    pub(crate) const TRAILER: &str = r#"{"mediaType":"application/vnd.uapi.16.trailer"}"#;
    /// A signature object.
    pub(crate) const SIGNATURE: &str =
        r#"{"mediaType":"application/vnd.uapi.16.signature","mechanism":"pkcs7","data":"AAAA"}"#;
    /// The hash of "hello", in hex.
    pub(crate) const HELLO: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
    /// The hash of "world", in hex.
    pub(crate) const WORLD: &str = "486ea46224d1bb4fb680f34f7c9ad96a8f24ec88be73ea8e5a6c65260e9cb8a7";
    /// The hash of no data, in hex.
    pub(crate) const EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// How many bytes the tests feed a decoder at a time. The pieces end
    /// anywhere: inside a record, inside a character, right in front of a
    /// separator, and around the size a reader reads at a time.
    pub(crate) const PIECES: [usize; 8] = [1, 2, 3, 7, 4096, READ_SIZE - 1, READ_SIZE, READ_SIZE + 1];

    /// The JSON text sequence of `records`.
    pub(crate) fn sequence(records: &[&str]) -> Vec<u8> {
        let mut out = Vec::new();
        for record in records {
            out.push(RECORD_SEPARATOR);
            out.extend_from_slice(record.as_bytes());
            out.push(RECORD_END);
        }
        out
    }

    /// The manifest with the file objects `records` between the root file
    /// object and the trailer.
    pub(crate) fn manifest(records: &[&str]) -> Vec<u8> {
        sequence(&[&[ROOT][..], records, &[TRAILER]].concat())
    }

    /// A manifest read to its end: what the tests look at.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub(crate) struct Whole {
        pub(crate) root: RootObject,
        pub(crate) objects: Vec<FileObject>,
        pub(crate) signatures: Vec<SignatureObject>,
    }

    /// How many arrays and objects serde_json reads inside each other.
    pub(crate) const MAX_NESTING: usize = 127;

    /// Reads the JSON text `text` the way a reader reads a value it passes
    /// over: every key and every string held to the rules of a manifest.
    pub(crate) fn read_json(text: &str) -> Result<(), ParseError> {
        let mut strict = Strict::default();
        let mut json = serde_json::Deserializer::from_str(text);
        let read = Skip(&mut strict).deserialize(&mut json).and_then(|()| json.end());
        read.map_err(|e| strict.error(text, &e))
    }

    /// The JSON value of `text`, none for a text a reader refuses, see
    /// [`read_json`]: one with a key twice in an object too, which
    /// serde_json's own Value takes.
    pub(crate) fn json(text: &str) -> Option<serde_json::Value> {
        read_json(text).ok()?;
        serde_json::from_str(text).ok()
    }

    /// Reads the manifest `bytes` to its end.
    pub(crate) fn read_whole(bytes: &[u8]) -> Result<Whole, Error> {
        read_whole_from(bytes)
    }

    /// Reads the manifest that `input` holds to its end.
    pub(crate) fn read_whole_from(input: impl std::io::Read) -> Result<Whole, Error> {
        let mut reader = Reader::open(input)?;
        let mut whole = Whole {
            root: reader.root().clone(),
            objects: Vec::new(),
            signatures: Vec::new(),
        };
        for object in &mut reader {
            match object? {
                Object::File(object) => whole.objects.push(*object),
                Object::Signature(signature) => whole.signatures.push(signature),
            }
        }
        Ok(whole)
    }

    /// The names of the full tree in which every directory has an entry
    /// for each of `pieces`, down to `depth` components: every name of at
    /// most `depth` components made of `pieces`, the root among them.
    pub(crate) fn full_tree_names(pieces: &[&str], depth: usize) -> Vec<NameBuf> {
        let mut names = vec![NameBuf::default()];
        let mut level = vec![NameBuf::default()];
        for _ in 0..depth {
            level = level
                .iter()
                .flat_map(|parent| pieces.iter().map(move |piece| parent.join(piece).unwrap()))
                .collect();
            names.extend(level.iter().cloned());
        }
        names
    }

    /// Writes the manifest `whole`.
    pub(crate) fn write_whole(whole: &Whole) -> Result<Vec<u8>, Error> {
        let mut writer = Writer::begin(Vec::new(), &whole.root)?;
        for object in &whole.objects {
            writer.file(object)?;
        }
        for signature in &whole.signatures {
            writer.signature(signature)?;
        }
        writer.finish()
    }

    pub(crate) fn name(name: &str) -> NameBuf {
        NameBuf::new(name).unwrap()
    }

    /// The records `writer` wrote after `root`, without the frame of
    /// each: the separator in front and the newline behind.
    pub(crate) fn written(root: &RootObject, write: impl FnOnce(&mut Writer<Vec<u8>>)) -> Vec<String> {
        let mut writer = Writer::begin(Vec::new(), root).unwrap();
        write(&mut writer);
        let text = String::from_utf8(writer.finish().unwrap()).unwrap();
        let separator = char::from(RECORD_SEPARATOR);
        assert!(text.starts_with(separator));
        text.split(separator)
            .skip(1)
            .map(|record| record.strip_suffix(char::from(RECORD_END)).unwrap().to_string())
            .collect()
    }

    /// The root file object of a manifest that records every feature, and
    /// its record.
    pub(crate) fn recording_all() -> (RootObject, String) {
        let root = RootObject {
            features: Some(Features::ALL),
            ..RootObject::default()
        };
        let names: Vec<String> = Features::ALL.names().map(|name| format!("\"{}\"", name)).collect();
        let text = format!(
            r#"{{"features":[{}],"mediaType":"application/vnd.uapi.16.manifest"}}"#,
            names.join(",")
        );
        (root, text)
    }

    /// A directory that says nothing else about itself.
    pub(crate) fn directory(name_of: &str) -> FileObject {
        let mut directory = FileObject::new(name(name_of));
        directory.inode_type = InodeType::Directory;
        directory
    }

    /// The record the writer writes for `object`, in a manifest that
    /// records every feature, after the objects of the directories it is
    /// in.
    pub(crate) fn record(object: &FileObject) -> String {
        let (root, root_text) = recording_all();
        let directories: Vec<FileObject> = object
            .name
            .as_str()
            .match_indices('/')
            .map(|(end, _)| directory(&object.name.as_str()[..end]))
            .collect();
        let mut records = written(&root, |writer| {
            for directory in &directories {
                writer.file(directory).unwrap();
            }
            writer.file(object).unwrap();
        });
        assert_eq!(records.len(), directories.len() + 3);
        assert_eq!(records[0], root_text);
        assert_eq!(records.pop().as_deref(), Some(TRAILER));
        records.pop().unwrap()
    }

    /// An object with every field there is, and one of its contents
    /// objects with every field.
    pub(crate) fn everything() -> FileObject {
        let uuid = |last: u8| {
            let mut bytes = [0x11; Uuid::SIZE];
            bytes[Uuid::SIZE - 1] = last;
            Uuid::new(bytes)
        };
        let mut encoded = ContentsObject::new(ContentsSource::File(name("blob.gz")));
        encoded.encoding = Some("gzip".into());
        encoded.encoded_size = Some(3);
        encoded.encoded_sha256 = Some(Sha256::digest(b"gz"));
        encoded.original_size = Some(9);
        encoded.original_sha256 = Some(Sha256::digest(b"original"));
        encoded.offset = 4;
        let mut object = FileObject::new(name("a/\u{e9} \"quoted\"\\"));
        object.size = Some(5);
        object.inode.mode = Some(Mode::new(0o440).unwrap());
        object.inode.uid = Some(1);
        object.inode.gid = Some(2);
        object.inode.user_name = Some("user".into());
        object.inode.group_name = Some("group".into());
        object.inode.mtime_nsec = Some(u64::MAX);
        object.inode_token = NonZeroU64::new(3);
        object.inode.user_xattrs = Some(Box::new(BTreeMap::from([
            ("text".to_string(), b"value".to_vec()),
            ("empty".to_string(), Vec::new()),
            ("binary".to_string(), vec![0xff, 0x00]),
            ("nul".to_string(), b"a\0b".to_vec()),
            ("noncharacter".to_string(), "a\u{fffe}".as_bytes().to_vec()),
        ])));
        // Flags of both kinds, which mix in the order of their names.
        object.inode.flags.put(InodeFlags::APPEND_ONLY, Some(true));
        object.dos_flags.put(DosFlags::ARCHIVE, Some(false));
        object.dos_flags.put(DosFlags::HIDDEN, Some(true));
        object.inode.flags.put(InodeFlags::IMMUTABLE, Some(true));
        object.inode.flags.put(InodeFlags::NO_COW, Some(false));
        object.dos_flags.put(DosFlags::SYSTEM, Some(true));
        // The partition is read-only, which gptFlags says as well where the
        // manifest records both.
        object.gpt = Some(Box::new(GptPartition {
            label: Some("label".into()),
            uuid: Some(uuid(1)),
            type_uuid: Some(uuid(2)),
            flags: Some(
                GptPartition::FLAG_NO_AUTO | GptPartition::FLAG_GROW_FILE_SYSTEM | GptPartition::FLAG_READ_ONLY,
            ),
            no_auto: Some(true),
            grow_file_system: Some(true),
        }));
        object.inode.read_only = Some(true);
        object.contents = vec![
            encoded,
            ContentsObject {
                http_headers: vec![
                    ("X-Foo".into(), "bar".into()),
                    ("Authorization".into(), "Bearer x".into()),
                ],
                ..ContentsObject::new(ContentsSource::Url("https://example.com/blob".into()))
            },
            ContentsObject::new(ContentsSource::Literal(b"hello".to_vec())),
            ContentsObject::default(),
        ];
        object.sha256 = HELLO.parse().ok();
        object.validity.since_usec = 6;
        object.validity.until_usec = Some(7);
        object.validity.state = Validity::Revoked;
        object
    }
}
