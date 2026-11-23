// SPDX-License-Identifier: LGPL-2.1-or-later
//! The names of file objects: [`Name`] borrows one, and [`NameBuf`] owns
//! one.
//!
//! The crate denies unsafe code. One of the exceptions is here: the cast
//! that makes a `&Name` of a `&str`, in `Name::from_str_unchecked()`. The
//! others are the modules ioctl and nss.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::iter;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::str::{self, FromStr};

use crate::strict::StringRules;
use crate::{InodeType, FILENAME, STRING_RULES};

/// What separates the components of a name.
const SEPARATOR: char = '/';
/// The separator as the one byte it is in UTF-8. Being ASCII, that byte is
/// in no other character, so the components of a name are found by
/// looking at its bytes.
const SEPARATOR_BYTE: u8 = SEPARATOR as u8;
/// The components that stand for a directory itself and for the one above
/// it. A name has neither.
const CURRENT: &str = ".";
const PARENT: &str = "..";
/// What follows [`FILENAME`] in the name of a file that belongs to the
/// manifest, such as its signature or a compressed copy.
const SUFFIX_SEPARATOR: char = '.';
/// The control characters a name may not have are the bytes below the
/// space, ASCII 0 to 31, and delete, ASCII 127.
const SPACE: u8 = b' ';
const DELETE: u8 = 0x7f;
/// What the text of a name may not hold besides control characters: what
/// the strings of a manifest may not hold, except for the NUL character,
/// which is a control character. That leaves the noncharacters.
const RULES: StringRules = STRING_RULES.without(StringRules::NO_NUL);

/// The name of a file object: the path of the file below the root of the
/// tree the manifest describes.
///
/// A `Name` is used behind a reference, like a `str` or a `Path`: a `&Name`
/// borrows a name, and a [`NameBuf`] owns one. [`Name::new`] checks a
/// string where it is, and [`NameBuf::new`] makes an owned name.
///
/// A name is a normalized relative path. Its components are separated by
/// single slashes, and none of them is empty, `.` or `..`. It has no
/// control characters and no noncharacters, and it is at most
/// [`Name::MAX_LEN`] bytes long. Its components are not limited on their
/// own. Its first component is not `Uapi16Manifest` and does not begin
/// with `Uapi16Manifest.`, the names the manifest itself and what belongs
/// to it have inside the tree.
///
/// Names are ordered the way the specification orders the file objects of
/// a manifest in code point order: component by component, each compared
/// by its bytes, so that the name of a directory comes right before the
/// names below it. That is not the order of the names as strings: `a/x`
/// comes before `a-b`.
///
/// The root file object has no name. Its name here is the empty one,
/// [`Name::ROOT`], which no file has, and which comes before every other
/// name. It is the default of a `&Name` and of a [`NameBuf`], so an owned
/// root is `NameBuf::default()`.
///
/// ```
/// use uapi16::{Name, NameBuf, NameProblem};
///
/// let name = Name::new("EFI/BOOT")?;
/// let file: NameBuf = name.join("BOOTX64.EFI")?;
/// assert_eq!(file, "EFI/BOOT/BOOTX64.EFI");
/// assert_eq!(file.parent(), Some(name));
/// assert_eq!(Name::new("EFI//BOOT"), Err(NameProblem::EmptyComponent));
/// assert_eq!(Name::new("../etc/passwd"), Err(NameProblem::ContainsDotComponent));
/// assert!(Name::new("a/x")? < Name::new("a-b")?);
/// # Ok::<(), NameProblem>(())
/// ```
#[derive(PartialEq, Eq, Hash)]
#[repr(transparent)]
pub struct Name(str);

/// The name of a file object, owned. It is a [`Name`] wherever one is
/// borrowed, and has its methods.
///
/// ```
/// use uapi16::{FileObject, Name, NameBuf};
///
/// let owned = NameBuf::new("EFI/BOOT/BOOTX64.EFI")?;
/// assert_eq!(owned.file_name(), Some("BOOTX64.EFI"));
/// let name: &Name = &owned;
/// assert_eq!(name.to_owned(), owned);
/// // A file object keeps the name it is given, and lends it.
/// let object = FileObject::new(owned);
/// assert_eq!(object.name(), "EFI/BOOT/BOOTX64.EFI");
/// # Ok::<(), uapi16::NameError>(())
/// ```
#[derive(Clone, Default, PartialEq, Eq)]
pub struct NameBuf(String);

/// Why a string or the name of a file is not the name of a file object, see
/// [`Name`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum NameProblem {
    /// The name of a file on the host is not UTF-8, which every name of a
    /// manifest is, see [`Name::join_os`]. A name made from a string never
    /// has this problem.
    NotUtf8,
    /// The string is empty. No file object has that name: [`Name::ROOT`]
    /// only stands in for the root file object, which has no name.
    Empty,
    /// It is longer than [`Name::MAX_LEN`] bytes.
    TooLong,
    /// Its first component is `Uapi16Manifest` or begins with
    /// `Uapi16Manifest.`, which the specification reserves for the manifest
    /// and what belongs to it. A file below a directory of such a name
    /// cannot be listed, since its directory cannot be.
    Reserved,
    /// It contains a control character: ASCII 0 to 31 or 127.
    ContainsControlCharacter,
    /// It contains a noncharacter, which no string of a manifest may have.
    ContainsNoncharacter,
    /// One of its components is empty: it begins or ends with a slash, or
    /// it has two slashes in a row.
    EmptyComponent,
    /// It contains a component that is `.` or `..`.
    ContainsDotComponent,
    /// The component given to [`Name::join`] contains a slash, so it is
    /// more than one component.
    ContainsSeparator,
}

impl fmt::Display for NameProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NameProblem::NotUtf8 => f.write_str("name is not UTF-8"),
            NameProblem::Empty => f.write_str("name is empty"),
            NameProblem::TooLong => write!(f, "name is longer than {} bytes", Name::MAX_LEN),
            NameProblem::Reserved => f.write_str("name is reserved for the manifest"),
            NameProblem::ContainsControlCharacter => f.write_str("name contains a control character"),
            NameProblem::ContainsNoncharacter => f.write_str("name contains a noncharacter"),
            NameProblem::EmptyComponent => f.write_str("name has an empty component"),
            NameProblem::ContainsDotComponent => write!(f, "name contains a '{}' or '{}' component", CURRENT, PARENT),
            NameProblem::ContainsSeparator => write!(f, "name component contains '{}'", SEPARATOR),
        }
    }
}

impl std::error::Error for NameProblem {}

/// A string that is not the name of a file object. It is the error of
/// [`NameBuf::new`] and of the conversions of a string into a [`NameBuf`].
/// It says why the string is not a name, and hands the string back.
///
/// ```
/// use uapi16::{NameBuf, NameProblem};
///
/// let error = NameBuf::new(String::from("EFI//BOOT")).unwrap_err();
/// assert_eq!(error.name_problem(), NameProblem::EmptyComponent);
/// assert_eq!(error.to_string(), "name has an empty component");
/// assert_eq!(error.into_string(), "EFI//BOOT");
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameError {
    /// The string that is not a name.
    name: String,
    /// Why it is not one.
    problem: NameProblem,
}

impl NameError {
    /// Why the string is not a name.
    pub fn name_problem(&self) -> NameProblem {
        self.problem
    }

    /// The string that is not a name.
    pub fn as_str(&self) -> &str {
        &self.name
    }

    /// The string that is not a name, handed back without a copy.
    pub fn into_string(self) -> String {
        self.name
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.problem, f)
    }
}

impl std::error::Error for NameError {}

impl Name {
    /// The name of the root file object: the empty one.
    pub const ROOT: &'static Name = Name::from_str_unchecked("");

    /// The most bytes a name has, as the specification says.
    pub const MAX_LEN: usize = 4095;

    /// Takes `name` as the name of a file object, if it is one, without a
    /// copy. If it is not, the error says why.
    pub fn new(name: &str) -> Result<&Name, NameProblem> {
        if name.is_empty() {
            return Err(NameProblem::Empty);
        }
        if name.len() > Name::MAX_LEN {
            return Err(NameProblem::TooLong);
        }
        if Name::is_reserved(name) {
            return Err(NameProblem::Reserved);
        }
        // The separator is neither a control character nor a noncharacter,
        // so the text of the components is checked all at once.
        Name::check_text(name)?;
        for component in name.as_bytes().split(|&b| b == SEPARATOR_BYTE) {
            Name::check_component(component)?;
        }
        Ok(Name::from_str_unchecked(name))
    }

    /// The string `name` as a name. Nothing is checked: the caller knows
    /// that it is a name, or the empty string of the root.
    #[allow(unsafe_code)]
    const fn from_str_unchecked(name: &str) -> &Name {
        // SAFETY: `Name` is `#[repr(transparent)]` over `str`, so the two
        // have the same layout, and a pointer to either carries the same
        // length. The pointer comes from a reference, so it is valid for
        // reads for as long as that reference is. The reference made of it
        // is shared as well, and has the lifetime of the argument by the
        // signature of this function. No unsafe code relies on a `Name`
        // being a valid name, so a string that is none makes a wrong name
        // and nothing worse.
        unsafe { &*(name as *const str as *const Name) }
    }

    /// The name of the entry `component` of the directory this name is
    /// the name of. Only the new component is looked at, so the names of
    /// a deep tree are cheap to make on the way down.
    pub fn join(&self, component: &str) -> Result<NameBuf, NameProblem> {
        if component.contains(SEPARATOR) {
            return Err(NameProblem::ContainsSeparator);
        }
        if self.is_root() {
            return Name::new(component).map(Name::to_owned);
        }
        let len = self.0.len() + SEPARATOR.len_utf8() + component.len();
        if len > Name::MAX_LEN {
            return Err(NameProblem::TooLong);
        }
        // In the order of Name::new(), so that a component is refused for
        // the reason the whole name would be refused for.
        Name::check_text(component)?;
        Name::check_component(component.as_bytes())?;
        let mut name = String::with_capacity(len);
        name.push_str(&self.0);
        name.push(SEPARATOR);
        name.push_str(component);
        Ok(NameBuf(name))
    }

    /// The name of the entry `component` of the directory this name is
    /// the name of, where `component` is the name of a file on the host,
    /// which is bytes. One that is not UTF-8 fails with
    /// [`NameProblem::NotUtf8`], and anything else is checked as
    /// [`Name::join`] checks it.
    pub fn join_os(&self, component: &OsStr) -> Result<NameBuf, NameProblem> {
        let component = str::from_utf8(component.as_bytes()).map_err(|_| NameProblem::NotUtf8)?;
        self.join(component)
    }

    /// Checks that `text` can be in a name: it has no control characters,
    /// and nothing that the strings of a manifest may not hold.
    fn check_text(text: &str) -> Result<(), NameProblem> {
        // Every byte is looked at, not only those up to the first control
        // character, and with two comparisons instead of is_ascii_control(),
        // which the compiler turns into a branch. Without an early end and
        // without a branch the compiler looks at many bytes at a time.
        let control = text
            .bytes()
            .fold(false, |control, b| control | (b < SPACE) | (b == DELETE));
        if control {
            return Err(NameProblem::ContainsControlCharacter);
        }
        if !RULES.admits(text) {
            return Err(NameProblem::ContainsNoncharacter);
        }
        Ok(())
    }

    /// Checks the bytes `component` between two separators as a component
    /// as far as its shape goes: it is not empty, and it does not stand
    /// for a directory itself or for the one above it.
    fn check_component(component: &[u8]) -> Result<(), NameProblem> {
        if component.is_empty() {
            return Err(NameProblem::EmptyComponent);
        }
        if component == CURRENT.as_bytes() || component == PARENT.as_bytes() {
            return Err(NameProblem::ContainsDotComponent);
        }
        Ok(())
    }

    /// The components of the name, the first one first. The root has none.
    pub fn components(&self) -> impl DoubleEndedIterator<Item = &str> {
        // The root's empty name would make one empty component.
        self.0.split(SEPARATOR).filter(|component| !component.is_empty())
    }

    /// The name of the directory the file is in, [`Name::ROOT`] for a file
    /// at the top. The root has none.
    pub fn parent(&self) -> Option<&Name> {
        if self.is_root() {
            return None;
        }
        // The first component of a name is not reserved, and that is the
        // only check a part of a name could fail. So every directory a name
        // is in has a name, which is not checked again.
        let parent = self.0.rsplit_once(SEPARATOR);
        Some(parent.map_or(Name::ROOT, |(parent, _)| Name::from_str_unchecked(parent)))
    }

    /// The name of the file in its directory, its last component. The
    /// root has none.
    pub fn file_name(&self) -> Option<&str> {
        self.components().next_back()
    }

    /// Whether `name` is one the specification reserves for the manifest
    /// and what belongs to it: one whose first component is `Uapi16Manifest`
    /// or begins with `Uapi16Manifest.`. A file of such a name is not listed
    /// in a manifest, and neither is a file below a directory of such a
    /// name.
    pub fn is_reserved(name: &str) -> bool {
        name.strip_prefix(FILENAME)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(SUFFIX_SEPARATOR) || rest.starts_with(SEPARATOR))
    }

    /// Whether this is the name of the root file object.
    pub fn is_root(&self) -> bool {
        self.0.is_empty()
    }

    /// The name as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl NameBuf {
    /// Takes `name` as the name of a file object, if it is one. A `String`
    /// is taken as it is. If it is not a name, the error says why and hands
    /// the string back.
    pub fn new(name: impl Into<String>) -> Result<NameBuf, NameError> {
        let name = name.into();
        match Name::new(&name) {
            Ok(_) => Ok(NameBuf(name)),
            Err(problem) => Err(NameError { name, problem }),
        }
    }

    /// The name, borrowed.
    pub fn as_name(&self) -> &Name {
        Name::from_str_unchecked(&self.0)
    }
}

impl Ord for Name {
    fn cmp(&self, other: &Name) -> Ordering {
        NamePair::new(&self.0, &other.0).ordering()
    }
}

/// Two names, looked at from the first byte in which they differ. If one
/// name is the first part of the other, that is where it ends.
///
/// The names are the same in all bytes before that one, so the bytes from
/// there on settle both how the names are ordered and whether the second
/// one may follow the first in a manifest. That is why one pass over the
/// bytes the names share answers all the questions
/// [`SequenceCheck`](crate::sequence::SequenceCheck) asks of a file object
/// and the one before it. The root's empty name is a name here, too.
pub(crate) struct NamePair<'a> {
    /// The bytes of the first name from the first byte in which the names
    /// differ on, and those of the second one.
    first: &'a [u8],
    second: &'a [u8],
}

impl<'a> NamePair<'a> {
    /// The pair of the names `first` and `second`.
    pub(crate) fn new(first: &'a str, second: &'a str) -> NamePair<'a> {
        let (first, second) = (first.as_bytes(), second.as_bytes());
        let common = iter::zip(first, second).take_while(|(a, b)| a == b).count();
        NamePair {
            first: &first[common..],
            second: &second[common..],
        }
    }

    /// How the names are ordered, see [`Name`]: component by component,
    /// each compared by its bytes.
    ///
    /// That is the order of the bytes of the whole names with the separator
    /// taken as lower than any other byte, so the first bytes in which the
    /// names differ decide it. All components that end before those bytes
    /// are the same in both names, and the one they are in starts at the
    /// same byte in both:
    /// - If one name ends there, its component there is the first part of
    ///   the other's, or the other name goes on with a separator to a
    ///   component it does not have at all. Either way it comes first.
    /// - If one name has the separator there, its component ends there and
    ///   is the first part of the other's, which goes on. It comes first,
    ///   as the separator is lowest.
    /// - Otherwise both components go on, and the bytes there are the first
    ///   ones in which they differ.
    pub(crate) fn ordering(&self) -> Ordering {
        let rank = |rest: &[u8]| rest.first().map(|&b| (b != SEPARATOR_BYTE, b));
        rank(self.first).cmp(&rank(self.second))
    }

    /// Whether the second name is that of a file in a directory that can
    /// still have entries after the first file, the last one so far: the
    /// root, a directory the first file is in, or the first file itself if
    /// its type, `first_type`, is a directory.
    ///
    /// The directory of the second file is the root or one the first file
    /// is in if every separator of the second name comes before the first
    /// byte in which the names differ, where the first name has the same
    /// separators. It is the first file itself if the first name ends there
    /// and the second name has its last separator right there.
    pub(crate) fn second_is_in_open_directory(&self, first_type: InodeType) -> bool {
        let first_is_directory = first_type == InodeType::Directory;
        let rest = match self.second.split_first() {
            Some((&SEPARATOR_BYTE, inside)) if first_is_directory && self.first.is_empty() => inside,
            _ => self.second,
        };
        !rest.contains(&SEPARATOR_BYTE)
    }

    /// Whether the second name is the first one, or that of a directory
    /// the first file is in.
    pub(crate) fn second_is_first_or_above(&self) -> bool {
        self.second.is_empty() && self.first.first().is_none_or(|&b| b == SEPARATOR_BYTE)
    }
}

impl PartialOrd for Name {
    fn partial_cmp(&self, other: &Name) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// An owned name is ordered and hashed as the borrowed name it is, which
// `Borrow` asks for: a map with owned names as its keys is looked up with
// a borrowed one.
impl Ord for NameBuf {
    fn cmp(&self, other: &NameBuf) -> Ordering {
        self.as_name().cmp(other.as_name())
    }
}

impl PartialOrd for NameBuf {
    fn partial_cmp(&self, other: &NameBuf) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Hash for NameBuf {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_name().hash(state);
    }
}

/// An owned name and a borrowed one are compared and ordered as two
/// borrowed names are, with either one on the left. These are the
/// comparisons std has between `PathBuf` and `Path`.
macro_rules! compare_as_names {
    ($left:ty, $right:ty) => {
        impl PartialEq<$right> for $left {
            fn eq(&self, other: &$right) -> bool {
                <Name as PartialEq>::eq(self, other)
            }
        }

        impl PartialEq<$left> for $right {
            fn eq(&self, other: &$left) -> bool {
                <Name as PartialEq>::eq(self, other)
            }
        }

        impl PartialOrd<$right> for $left {
            fn partial_cmp(&self, other: &$right) -> Option<Ordering> {
                <Name as PartialOrd>::partial_cmp(self, other)
            }
        }

        impl PartialOrd<$left> for $right {
            fn partial_cmp(&self, other: &$left) -> Option<Ordering> {
                <Name as PartialOrd>::partial_cmp(self, other)
            }
        }
    };
}

compare_as_names!(NameBuf, Name);
compare_as_names!(NameBuf, &Name);

/// A name is equal to the string it is, with either one on the left, as
/// std has it for `String` and `str`. `&Name == &str` and `&str == &Name`
/// follow from the first of these through the impl std has for two
/// references. Written out they would clash with it. A name is not ordered
/// against a string, since names are not in the order of their strings.
macro_rules! equal_to_strings {
    ($name:ty, $string:ty) => {
        impl PartialEq<$string> for $name {
            fn eq(&self, other: &$string) -> bool {
                self.as_str() == &other[..]
            }
        }

        impl PartialEq<$name> for $string {
            fn eq(&self, other: &$name) -> bool {
                &self[..] == other.as_str()
            }
        }
    };
}

equal_to_strings!(Name, str);
equal_to_strings!(NameBuf, str);
equal_to_strings!(NameBuf, &str);

impl Deref for NameBuf {
    type Target = Name;

    fn deref(&self) -> &Name {
        self.as_name()
    }
}

impl Borrow<Name> for NameBuf {
    fn borrow(&self) -> &Name {
        self.as_name()
    }
}

impl ToOwned for Name {
    type Owned = NameBuf;

    fn to_owned(&self) -> NameBuf {
        NameBuf(self.0.to_owned())
    }
}

impl AsRef<Name> for Name {
    fn as_ref(&self) -> &Name {
        self
    }
}

impl AsRef<Name> for NameBuf {
    fn as_ref(&self) -> &Name {
        self.as_name()
    }
}

impl AsRef<str> for Name {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for NameBuf {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl From<&Name> for NameBuf {
    fn from(name: &Name) -> NameBuf {
        name.to_owned()
    }
}

impl From<NameBuf> for String {
    fn from(name: NameBuf) -> String {
        name.0
    }
}

impl Default for &Name {
    fn default() -> Self {
        Name::ROOT
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.pad(self.as_str())
    }
}

impl fmt::Display for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_name(), f)
    }
}

// Both forms print the same, so that a name reads the same wherever it
// is printed, such as on the two sides of a failed assertion.
impl fmt::Debug for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Name").field(&self.as_str()).finish()
    }
}

impl fmt::Debug for NameBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_name(), f)
    }
}

impl<'a> TryFrom<&'a str> for &'a Name {
    type Error = NameProblem;

    fn try_from(name: &'a str) -> Result<&'a Name, NameProblem> {
        Name::new(name)
    }
}

impl FromStr for NameBuf {
    type Err = NameError;

    fn from_str(name: &str) -> Result<NameBuf, NameError> {
        NameBuf::new(name)
    }
}

impl TryFrom<String> for NameBuf {
    type Error = NameError;

    fn try_from(name: String) -> Result<NameBuf, NameError> {
        NameBuf::new(name)
    }
}

impl TryFrom<&str> for NameBuf {
    type Error = NameError;

    fn try_from(name: &str) -> Result<NameBuf, NameError> {
        NameBuf::new(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::full_tree_names;
    use std::borrow::Cow;
    use std::collections::hash_map::DefaultHasher;
    use std::collections::{BTreeMap, HashMap};
    use std::error::Error as _;
    use std::ops::Bound;

    #[test]
    fn names() {
        for name in [
            "a",
            "a/b",
            "EFI/BOOT/BOOTX64.EFI",
            "with space",
            "\u{fc}mlaut \u{221e}.txt",
            "...",
            "a/...",
            ".hidden",
            "a.",
            "Uapi16Manifest2",
            "Uapi16Manifes",
            "uapi16manifest",
            "sub/Uapi16Manifest",
            "sub/Uapi16Manifest.sig",
            "xUapi16Manifest.sig",
        ] {
            let parsed = Name::new(name).unwrap_or_else(|_| panic!("{:?}", name));
            check_parent(parsed);
            assert_eq!(parsed, name);
            assert_eq!(parsed.as_str(), name);
            assert_eq!(parsed.to_string(), name);
            assert!(!parsed.is_root());
            assert_eq!(<&Name>::try_from(name), Ok(parsed));
            // The owned form is made of the same strings.
            let owned = NameBuf::new(name).unwrap_or_else(|_| panic!("{:?}", name));
            assert_eq!(owned, parsed);
            assert_eq!(name.parse::<NameBuf>(), Ok(owned.clone()));
            assert_eq!(NameBuf::try_from(name), Ok(owned.clone()));
            assert_eq!(NameBuf::try_from(name.to_string()), Ok(owned.clone()));
            assert_eq!(String::from(owned), name);
        }
        for (name, reason) in [
            ("", NameProblem::Empty),
            ("/", NameProblem::EmptyComponent),
            ("/abs", NameProblem::EmptyComponent),
            ("a/", NameProblem::EmptyComponent),
            ("a//b", NameProblem::EmptyComponent),
            (".", NameProblem::ContainsDotComponent),
            ("..", NameProblem::ContainsDotComponent),
            ("a/.", NameProblem::ContainsDotComponent),
            ("a/..", NameProblem::ContainsDotComponent),
            ("./a", NameProblem::ContainsDotComponent),
            ("../a", NameProblem::ContainsDotComponent),
            ("a/./b", NameProblem::ContainsDotComponent),
            ("a/../b", NameProblem::ContainsDotComponent),
            ("a\nb", NameProblem::ContainsControlCharacter),
            ("a\0b", NameProblem::ContainsControlCharacter),
            ("a/\u{1}", NameProblem::ContainsControlCharacter),
            ("a\u{7f}", NameProblem::ContainsControlCharacter),
            ("\u{fdd0}", NameProblem::ContainsNoncharacter),
            ("a\u{fffe}", NameProblem::ContainsNoncharacter),
            ("a/\u{10ffff}", NameProblem::ContainsNoncharacter),
            ("Uapi16Manifest", NameProblem::Reserved),
            ("Uapi16Manifest.", NameProblem::Reserved),
            ("Uapi16Manifest.sig", NameProblem::Reserved),
            ("Uapi16Manifest.gz", NameProblem::Reserved),
            ("Uapi16Manifest.d/inside", NameProblem::Reserved),
            ("Uapi16Manifest/inside", NameProblem::Reserved),
            ("Uapi16Manifest/a/b", NameProblem::Reserved),
        ] {
            assert_eq!(Name::new(name), Err(reason), "{:?}", name);
            assert_eq!(<&Name>::try_from(name), Err(reason), "{:?}", name);
            // The owned form refuses the same strings for the same reasons.
            let error = NameBuf::new(name).unwrap_err();
            assert_eq!((error.name_problem(), error.as_str()), (reason, name));
            assert_eq!(name.parse::<NameBuf>(), Err(error.clone()), "{:?}", name);
            assert_eq!(NameBuf::try_from(name), Err(error.clone()), "{:?}", name);
            assert_eq!(NameBuf::try_from(name.to_string()), Err(error), "{:?}", name);
        }
        // The control characters of Latin-1 are not ASCII control
        // characters.
        assert!(Name::new("a\u{85}b").is_ok());
    }

    /// The error says what is wrong with the name.
    #[test]
    fn messages() {
        for (reason, text) in [
            (NameProblem::NotUtf8, "name is not UTF-8"),
            (NameProblem::Empty, "name is empty"),
            (NameProblem::TooLong, "name is longer than 4095 bytes"),
            (NameProblem::Reserved, "name is reserved for the manifest"),
            (
                NameProblem::ContainsControlCharacter,
                "name contains a control character",
            ),
            (NameProblem::ContainsNoncharacter, "name contains a noncharacter"),
            (NameProblem::EmptyComponent, "name has an empty component"),
            (
                NameProblem::ContainsDotComponent,
                "name contains a '.' or '..' component",
            ),
            (NameProblem::ContainsSeparator, "name component contains '/'"),
        ] {
            assert_eq!(reason.to_string(), text);
        }
    }

    #[test]
    fn lengths() {
        // The whole name is limited, its components are not on their own.
        let longest = "x".repeat(Name::MAX_LEN);
        assert!(Name::new(longest.as_str()).is_ok());
        assert_eq!(Name::new(&format!("{}x", longest)), Err(NameProblem::TooLong));
        let component = "y".repeat(1000);
        let deep = [component.as_str(); 4].join("/");
        assert!(Name::new(deep.as_str()).is_ok());
        let fits = format!("{}/{}", deep, "z".repeat(Name::MAX_LEN - deep.len() - 1));
        assert_eq!(fits.len(), Name::MAX_LEN);
        assert!(Name::new(fits.as_str()).is_ok());
        assert_eq!(Name::new(&format!("{}z", fits)), Err(NameProblem::TooLong));
        // The limit counts bytes, not characters.
        let euro = '\u{20ac}';
        assert_eq!(euro.len_utf8(), 3);
        assert!(Name::new(&euro.to_string().repeat(Name::MAX_LEN / 3)).is_ok());
        assert_eq!(
            Name::new(&euro.to_string().repeat(Name::MAX_LEN / 3 + 1)),
            Err(NameProblem::TooLong)
        );
    }

    #[test]
    fn order() {
        // In the order the specification sorts the names of a manifest in.
        let names: Vec<&Name> = [
            "",
            "a",
            "a/b",
            "a/b/c",
            "a/x",
            "a-b",
            "a.b",
            "a0",
            "b",
            "\u{e9}",
            "\u{ff61}",
            "\u{1f600}",
        ]
        .into_iter()
        .map(|name| {
            if name.is_empty() {
                Name::ROOT
            } else {
                Name::new(name).unwrap()
            }
        })
        .collect();
        let owned: Vec<NameBuf> = names.iter().map(|&name| name.to_owned()).collect();
        for (i, a) in names.iter().enumerate() {
            for (j, b) in names.iter().enumerate() {
                let order = i.cmp(&j);
                assert_eq!(a.cmp(b), order, "{:?} {:?}", a, b);
                assert_eq!(a.partial_cmp(b), Some(order));
                // The owned form is in the same order.
                assert_eq!(owned[i].cmp(&owned[j]), order);
                assert_eq!(owned[i].partial_cmp(&owned[j]), Some(order));
                // So are the two forms against each other, with either one
                // on the left, and the borrowed one behind a reference or
                // not.
                assert_eq!(PartialOrd::partial_cmp(&owned[i], *b), Some(order));
                assert_eq!(PartialOrd::partial_cmp(&owned[i], b), Some(order));
                assert_eq!(PartialOrd::partial_cmp(*a, &owned[j]), Some(order));
                assert_eq!(PartialOrd::partial_cmp(a, &owned[j]), Some(order));
                assert_eq!(owned[i] < *b, i < j);
                assert_eq!(*a < owned[j], i < j);
                assert_eq!(owned[i] == **b, i == j);
                assert_eq!(owned[i] == *b, i == j);
                assert_eq!(**a == owned[j], i == j);
                assert_eq!(*a == owned[j], i == j);
                assert_eq!(owned[i] == owned[j], i == j);
                assert_eq!(a == b, i == j);
            }
        }
        // As strings they are not in that order.
        assert!(names[5].as_str() < names[4].as_str());
        // Sorting puts both forms in the order of a manifest.
        let mut sorted: Vec<&Name> = names.iter().rev().copied().collect();
        sorted.sort();
        assert_eq!(sorted, names);
        let mut sorted: Vec<NameBuf> = owned.iter().rev().cloned().collect();
        sorted.sort();
        assert_eq!(sorted, owned);
    }

    /// The components the names of the tests below are made of: one that
    /// is the first part of others, bytes below the separator and above
    /// it, and characters beyond ASCII.
    const PIECES: [&str; 8] = ["a", "ab", "a b", "a-b", "a.b", "a0", "\u{e9}", "\u{1f600}"];

    /// Names are in the order of their components, whatever order the
    /// bytes of the whole names are in.
    #[test]
    fn order_of_components() {
        let names = full_tree_names(&PIECES, 3);
        for a in &names {
            for b in &names {
                assert_eq!(a.cmp(b), a.components().cmp(b.components()), "{:?} {:?}", a, b);
            }
        }
        // The separator comes before any other byte, also before those
        // that are lower as bytes: the space to the full stop.
        for byte in b' '..SEPARATOR_BYTE {
            let other = NameBuf::new(format!("a{}b", char::from(byte))).unwrap();
            for name in ["a/b", "a/x", "a/b/c", "a/\u{e9}"] {
                assert!(Name::new(name).unwrap() < other, "{:?} {:?}", name, other);
            }
            let other = NameBuf::new(format!("a{}", char::from(byte))).unwrap();
            assert!(Name::new("a/b").unwrap() < other, "{:?}", other);
        }
        // A name comes before the names it is the first part of.
        for (first, second) in [
            ("a", "a/b"),
            ("a", "ab"),
            ("a", "a b"),
            ("a/b", "a/bc"),
            ("a/b", "a/b/c"),
            ("a/b/c", "a/bc"),
            ("a/b", "ab"),
            ("\u{e9}", "\u{e9}/a"),
        ] {
            let (first, second) = (Name::new(first).unwrap(), Name::new(second).unwrap());
            assert_eq!(first.cmp(second), Ordering::Less, "{:?} {:?}", first, second);
            assert_eq!(second.cmp(first), Ordering::Greater, "{:?} {:?}", first, second);
        }
    }

    /// Everything that makes `name` not a name by the definition of
    /// [`Name`], with every component and every character of it looked at
    /// on its own. Nothing if it is a name.
    fn reasons(name: &str) -> Vec<NameProblem> {
        let mut reasons = Vec::new();
        if name.is_empty() {
            reasons.push(NameProblem::Empty);
        }
        if name.len() > Name::MAX_LEN {
            reasons.push(NameProblem::TooLong);
        }
        let first = name.split(SEPARATOR).next().unwrap_or_default();
        if first
            .strip_prefix(FILENAME)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with(SUFFIX_SEPARATOR))
        {
            reasons.push(NameProblem::Reserved);
        }
        if name.chars().any(|c| c.is_ascii_control()) {
            reasons.push(NameProblem::ContainsControlCharacter);
        }
        // The NUL character, which the strings of a manifest may not hold
        // either, is a control character.
        let noncharacter = |c: char| !c.is_ascii_control() && !STRING_RULES.admits(c.encode_utf8(&mut [0; 4]));
        if name.chars().any(noncharacter) {
            reasons.push(NameProblem::ContainsNoncharacter);
        }
        for component in name.split(SEPARATOR) {
            if component.is_empty() {
                reasons.push(NameProblem::EmptyComponent);
            }
            if component == CURRENT || component == PARENT {
                reasons.push(NameProblem::ContainsDotComponent);
            }
        }
        reasons
    }

    /// Every string of a few of the characters below is a name if the
    /// definition says so, and only then: on its own and in long names,
    /// whose bytes are looked at many at a time. If it is not one, the
    /// reason given is one of the reasons it is not.
    #[test]
    fn names_by_the_definition() {
        let characters = [
            'a',
            '.',
            SEPARATOR,
            ' ',
            '\0',
            '\u{1f}',
            '\u{7f}',
            '\u{85}',
            '\u{e9}',
            '\u{fdd0}',
            '\u{fffe}',
            '\u{10ffff}',
        ];
        let mut strings = vec![String::new()];
        let mut level = vec![String::new()];
        for _ in 0..4 {
            level = level
                .iter()
                .flat_map(|string| characters.iter().map(move |c| format!("{}{}", string, c)))
                .collect();
            strings.extend(level.iter().cloned());
        }
        let head = "abcdefgh/".repeat(8);
        let tail = "/abcdefgh".repeat(8);
        let mut valid = [0; 2];
        for string in &strings {
            for name in [
                string.clone(),
                format!("{}{}", head, string),
                format!("{}{}", string, tail),
                format!("{}{}{}", head, string, tail),
            ] {
                let reasons = reasons(&name);
                match Name::new(name.as_str()) {
                    Ok(valid) => {
                        assert!(reasons.is_empty(), "{:?} {:?}", name, reasons);
                        check_parent(valid);
                    }
                    Err(reason) => assert!(reasons.contains(&reason), "{:?} {:?} {:?}", name, reason, reasons),
                }
                valid[usize::from(reasons.is_empty())] += 1;
            }
        }
        // Both kinds come up.
        assert!(valid.iter().all(|&count| count > 0), "{:?}", valid);
        // A character a name may not have is found wherever it is.
        let name = format!("{}end", head);
        for at in 0..=name.len() {
            for (c, reason) in [
                ('\0', Some(NameProblem::ContainsControlCharacter)),
                ('\u{1f}', Some(NameProblem::ContainsControlCharacter)),
                ('\u{7f}', Some(NameProblem::ContainsControlCharacter)),
                ('\u{fdd0}', Some(NameProblem::ContainsNoncharacter)),
                ('\u{10ffff}', Some(NameProblem::ContainsNoncharacter)),
                (' ', None),
                ('\u{85}', None),
                ('\u{e9}', None),
            ] {
                let mut with = name.clone();
                with.insert(at, c);
                assert_eq!(Name::new(with.as_str()).err(), reason, "{:?}", with);
            }
        }
    }

    #[test]
    fn components_and_parents() {
        let name = Name::new("a/b/c").unwrap();
        assert_eq!(name.components().collect::<Vec<_>>(), ["a", "b", "c"]);
        assert_eq!(name.components().next_back(), Some("c"));
        assert_eq!(name.parent(), Some(Name::new("a/b").unwrap()));
        // The parent is a part of the name itself. Nothing is copied.
        assert_eq!(name.parent().unwrap().as_str().as_ptr(), name.as_str().as_ptr());
        assert_eq!(name.file_name(), Some("c"));
        let top = Name::new("a").unwrap();
        assert_eq!(top.parent(), Some(Name::ROOT));
        assert_eq!(top.file_name(), Some("a"));
        assert_eq!(Name::ROOT.components().count(), 0);
        assert_eq!(Name::ROOT.parent(), None);
        assert_eq!(Name::ROOT.file_name(), None);
        // Every directory a name is in has a parent, up to the root.
        let up: Vec<&Name> = iter::successors(Some(name), |name| name.parent()).collect();
        assert_eq!(up, ["a/b/c", "a/b", "a", ""]);
        // The parent of an owned name borrows from it. A copy outlives it.
        let owned = NameBuf::new("x/y").unwrap();
        let kept: NameBuf = owned.parent().unwrap().to_owned();
        drop(owned);
        assert_eq!(kept, "x");
        // The root has no parent. The default of a borrowed name, which is
        // the root, can stand in for it.
        assert!(Name::ROOT.parent().unwrap_or_default().is_root());
        // A component is not always a name: the last one of a name can be
        // one that is reserved at the top.
        let below = Name::new("a/Uapi16Manifest").unwrap();
        assert_eq!(below.file_name(), Some("Uapi16Manifest"));
        assert_eq!(Name::new("Uapi16Manifest"), Err(NameProblem::Reserved));
        for name in full_tree_names(&["a", "...", ".hidden", "Uapi16Manifest2", "b c"], 3) {
            check_parent(&name);
        }
    }

    /// Checks that the directory `name` is in has a name, which is why
    /// [`Name::parent`] does not check it again.
    fn check_parent(name: &Name) {
        match name.parent() {
            None => assert!(name.is_root()),
            Some(parent) if parent.is_root() => assert_eq!(name.components().count(), 1, "{:?}", name),
            Some(parent) => assert_eq!(Name::new(parent.as_str()), Ok(parent), "{:?}", name),
        }
    }

    #[test]
    fn the_root() {
        // The root lives as long as the program, so whatever borrows a name
        // can keep it.
        let root: &'static Name = Name::ROOT;
        assert!(root.is_root());
        assert_eq!(Name::ROOT, "");
        assert_eq!(Name::ROOT.as_str(), "");
        // It is the default of both forms.
        assert_eq!(<&Name>::default(), Name::ROOT);
        assert_eq!(NameBuf::default(), Name::ROOT);
        assert!(NameBuf::default().is_root());
        assert_eq!(Name::ROOT.to_owned(), NameBuf::default());
        // The empty string is not a name: the root is not made of a string.
        assert_eq!(Name::new(""), Err(NameProblem::Empty));
        assert_eq!(NameBuf::new("").unwrap_err().name_problem(), NameProblem::Empty);
    }

    #[test]
    fn reserved() {
        for name in [
            "Uapi16Manifest",
            "Uapi16Manifest.",
            "Uapi16Manifest.sig",
            "Uapi16Manifest.d/x",
            "Uapi16Manifest/x",
            "Uapi16Manifest/x/y",
        ] {
            assert!(Name::is_reserved(name), "{:?}", name);
        }
        for name in [
            "",
            "Uapi16Manifest2",
            "Uapi16Manifest2/x",
            "Uapi16Manifes",
            "sub/Uapi16Manifest",
            "sub/Uapi16Manifest/x",
            "x.Uapi16Manifest",
        ] {
            assert!(!Name::is_reserved(name), "{:?}", name);
        }
    }

    /// Joining gives the name the whole path gives, and refuses what the
    /// whole path is refused for, for the same reason. A component with a
    /// separator is more than one and refused.
    #[test]
    fn joining() {
        let long = "x".repeat(1000);
        let parents = [
            Name::ROOT,
            Name::new("a").unwrap(),
            Name::new("a/b c").unwrap(),
            Name::new("Uapi16Manifest2").unwrap(),
        ];
        for parent in &parents {
            for component in [
                "c",
                "c d",
                ".x",
                "...",
                long.as_str(),
                "",
                ".",
                "..",
                "a/b",
                "/",
                "a/..",
                "a\tb",
                "a\u{fffe}",
                "Uapi16Manifest",
                "Uapi16Manifest.sig",
                "Uapi16Manifest2",
            ] {
                let whole = if parent.is_root() {
                    component.to_string()
                } else {
                    format!("{}/{}", parent, component)
                };
                let expected = if component.contains(SEPARATOR) {
                    Err(NameProblem::ContainsSeparator)
                } else {
                    Name::new(&whole).map(Name::to_owned)
                };
                assert_eq!(parent.join(component), expected, "{:?} {:?}", parent, component);
            }
        }
        assert_eq!(Name::ROOT.join("a").unwrap().join("b").unwrap(), "a/b");
        // The length of the whole name counts.
        let mut deep = NameBuf::default();
        while deep.as_str().len() + 2 * (long.len() + 1) <= Name::MAX_LEN {
            deep = deep.join(&long).unwrap();
        }
        let room = Name::MAX_LEN - (deep.as_str().len() + 1);
        assert!(room > 0);
        assert_eq!(deep.join(&"y".repeat(room)).unwrap().as_str().len(), Name::MAX_LEN);
        assert_eq!(deep.join(&"y".repeat(room + 1)), Err(NameProblem::TooLong));
        // A component that is too long, and wrong in another way too, is
        // refused for its length, as the whole name is.
        let wrong = format!("{}\n", "y".repeat(room));
        assert_eq!(deep.join(&wrong), Err(NameProblem::TooLong));
        assert_eq!(Name::new(&format!("{}/{}", deep, wrong)), Err(NameProblem::TooLong));
    }

    /// A borrowed name is the string it was checked in, and nothing is
    /// copied. An owned name is made of a `String` as it is, and of a copy
    /// of anything else.
    #[test]
    fn construction() {
        let text = String::from("EFI/BOOT/BOOTX64.EFI");
        let borrowed = Name::new(&text).unwrap();
        assert_eq!(borrowed.as_str().as_ptr(), text.as_ptr());
        assert_eq!(borrowed.as_str().len(), text.len());
        let copied = NameBuf::new(text.as_str()).unwrap();
        assert_ne!(copied.as_str().as_ptr(), text.as_ptr());
        assert_eq!(copied, borrowed);
        let at = text.as_ptr();
        let taken = NameBuf::new(text).unwrap();
        assert_eq!(taken.as_str().as_ptr(), at);
        assert_eq!(taken, copied);
        // An owned name gives its string back as it is.
        let back = String::from(taken);
        assert_eq!(back.as_ptr(), at);
    }

    /// What makes an owned name of a string says why a string is not a
    /// name, and hands the string back.
    #[test]
    fn owned_errors() {
        let text = String::from("a//b");
        let at = text.as_ptr();
        let error = NameBuf::new(text).unwrap_err();
        assert_eq!(error.name_problem(), NameProblem::EmptyComponent);
        assert_eq!(error.as_str(), "a//b");
        // The error prints as its reason, and has no other error behind it.
        assert_eq!(error.to_string(), "name has an empty component");
        assert!(error.source().is_none());
        assert_eq!(error.clone(), error);
        assert_ne!(error, NameBuf::new("a//c").unwrap_err());
        assert_ne!(error, NameBuf::new("").unwrap_err());
        // The string comes back as it went in, without a copy.
        let back = error.into_string();
        assert_eq!(back, "a//b");
        assert_eq!(back.as_ptr(), at);
        // Every way to an owned name fails the same way.
        for (text, problem) in [
            ("", NameProblem::Empty),
            ("../a", NameProblem::ContainsDotComponent),
            ("a\nb", NameProblem::ContainsControlCharacter),
            ("a\u{fffe}", NameProblem::ContainsNoncharacter),
            ("Uapi16Manifest", NameProblem::Reserved),
        ] {
            let error = NameBuf::new(text).unwrap_err();
            assert_eq!(error.name_problem(), problem, "{:?}", text);
            assert_eq!(error.as_str(), text);
            assert_eq!(error.to_string(), problem.to_string());
            assert_eq!(text.parse::<NameBuf>(), Err(error.clone()));
            assert_eq!(NameBuf::try_from(text), Err(error.clone()));
            assert_eq!(NameBuf::try_from(text.to_string()), Err(error.clone()));
            assert_eq!(error.into_string(), text);
        }
        let too_long = "x".repeat(Name::MAX_LEN + 1);
        let error = NameBuf::new(too_long.clone()).unwrap_err();
        assert_eq!(error.name_problem(), NameProblem::TooLong);
        assert_eq!(error.into_string(), too_long);
        // The error goes wherever an error of any kind goes.
        let boxed: Box<dyn std::error::Error + Send + Sync> = NameBuf::new("a/").unwrap_err().into();
        assert_eq!(boxed.to_string(), "name has an empty component");
    }

    /// An owned name is a borrowed one wherever one is taken, and a
    /// borrowed name is copied into an owned one where one is kept.
    #[test]
    fn between_the_forms() {
        fn len_of(name: &Name) -> usize {
            name.as_str().len()
        }
        fn len_of_either(name: impl AsRef<Name>) -> usize {
            name.as_ref().as_str().len()
        }
        let owned = NameBuf::new("EFI/BOOT").unwrap();
        let borrowed: &Name = &owned;
        assert_eq!(borrowed.as_str().as_ptr(), owned.as_str().as_ptr());
        assert_eq!(owned.as_name(), borrowed);
        assert_eq!(len_of(&owned), 8);
        assert_eq!(len_of(owned.as_name()), 8);
        assert_eq!(len_of_either(&owned), 8);
        assert_eq!(len_of_either(borrowed), 8);
        let lent: &Name = owned.borrow();
        assert_eq!(lent, borrowed);
        let text: &str = owned.as_ref();
        assert_eq!(text, "EFI/BOOT");
        let text: &str = borrowed.as_ref();
        assert_eq!(text, "EFI/BOOT");
        // The methods of the borrowed form are there on the owned one.
        assert_eq!(owned.components().collect::<Vec<_>>(), ["EFI", "BOOT"]);
        assert_eq!(owned.file_name(), Some("BOOT"));
        assert_eq!(owned.parent(), Some(Name::new("EFI").unwrap()));
        assert_eq!(owned.join("BOOTX64.EFI").unwrap(), "EFI/BOOT/BOOTX64.EFI");
        assert!(!owned.is_root());
        // A copy of a borrowed name is an owned one.
        assert_eq!(borrowed.to_owned(), owned);
        assert_eq!(NameBuf::from(borrowed), owned);
        assert_ne!(borrowed.to_owned().as_str().as_ptr(), owned.as_str().as_ptr());
        // A list of owned names lends a list of borrowed ones, and an
        // owned name that may be missing lends one that may be missing.
        let list = [owned.clone(), NameBuf::default()];
        let lent: Vec<&Name> = list.iter().map(NameBuf::as_name).collect();
        assert_eq!(lent, [borrowed, Name::ROOT]);
        let maybe = Some(owned.clone());
        assert_eq!(maybe.as_deref(), Some(borrowed));
        // A name that is borrowed or owned, as it comes.
        let cow: Cow<'_, Name> = Cow::Borrowed(borrowed);
        assert_eq!(cow.into_owned(), owned);
    }

    /// The value `value`, hashed.
    fn hash_of<T: Hash + ?Sized>(value: &T) -> u64 {
        let mut hasher = DefaultHasher::new();
        value.hash(&mut hasher);
        hasher.finish()
    }

    /// Both forms are equal, ordered and hashed the same, so a map with
    /// owned names as its keys is looked up with a borrowed one.
    #[test]
    fn maps() {
        // In the order of a manifest.
        let texts = ["a", "a/b", "a/b/c", "a/x", "a-b", "b", "\u{e9}"];
        let owned: Vec<NameBuf> = texts.iter().map(|text| NameBuf::new(*text).unwrap()).collect();
        let by_hash: HashMap<NameBuf, usize> = owned.iter().cloned().zip(0..).collect();
        let by_order: BTreeMap<NameBuf, usize> = owned.iter().cloned().zip(0..).collect();
        for (i, text) in texts.iter().enumerate() {
            let name = Name::new(text).unwrap();
            assert_eq!(hash_of(name), hash_of(&owned[i]), "{:?}", name);
            assert_eq!(by_hash.get(name), Some(&i), "{:?}", name);
            assert_eq!(by_order.get(name), Some(&i), "{:?}", name);
        }
        assert_eq!(hash_of(Name::ROOT), hash_of(&NameBuf::default()));
        assert_eq!(by_hash.get(Name::ROOT), None);
        assert_eq!(by_order.get(Name::new("c").unwrap()), None);
        // The map is in the order of a manifest, so the names below a
        // directory are one range of it.
        let keys: Vec<&NameBuf> = by_order.keys().collect();
        assert_eq!(keys, owned.iter().collect::<Vec<_>>());
        let below = (
            Bound::Excluded(Name::new("a").unwrap()),
            Bound::Excluded(Name::new("a-b").unwrap()),
        );
        let below: Vec<&str> = by_order
            .range::<Name, _>(below)
            .map(|(name, _)| name.as_str())
            .collect();
        assert_eq!(below, ["a/b", "a/b/c", "a/x"]);
    }

    /// A name is equal to the string it is, with either one on the left.
    #[test]
    fn equal_to_strings() {
        let owned = NameBuf::new("a/b").unwrap();
        let borrowed: &Name = &owned;
        let text = "a/b";
        assert_eq!(*borrowed, *text);
        assert_eq!(borrowed, text);
        assert_eq!(owned, *text);
        assert_eq!(owned, text);
        // The string on the left.
        assert_eq!(*text, *borrowed);
        assert_eq!(text, borrowed);
        assert_eq!(*text, owned);
        assert_eq!(text, owned);
        for other in ["a/c", "a", "a/b/c", "a/B", ""] {
            assert_ne!(*borrowed, *other);
            assert_ne!(borrowed, other);
            assert_ne!(owned, *other);
            assert_ne!(owned, other);
            assert_ne!(*other, *borrowed);
            assert_ne!(other, borrowed);
            assert_ne!(*other, owned);
            assert_ne!(other, owned);
        }
        assert_eq!(Name::ROOT, "");
        assert_eq!("", Name::ROOT);
        assert_eq!(NameBuf::default(), "");
        assert_eq!("", NameBuf::default());
        // A string of its own is compared as the string it is.
        let string = String::from("a/b");
        assert_eq!(borrowed, string.as_str());
        assert_eq!(string.as_str(), borrowed);
        assert_eq!(owned, string.as_str());
        assert_eq!(string.as_str(), owned);
        // Lists of names and lists of strings, either way round.
        let names = vec![NameBuf::new("a").unwrap(), NameBuf::new("b").unwrap()];
        assert_eq!(names, ["a", "b"]);
        assert_eq!(vec!["a", "b"], names);
        let lent: Vec<&Name> = names.iter().map(NameBuf::as_name).collect();
        assert_eq!(lent, ["a", "b"]);
        assert_eq!(vec!["a", "b"], lent);
    }

    /// Both forms print the same: the name itself, and for debugging the
    /// name as a `Name`.
    #[test]
    fn printing() {
        let owned = NameBuf::new("a/\"b\" \u{e9}").unwrap();
        let borrowed: &Name = &owned;
        assert_eq!(owned.to_string(), "a/\"b\" \u{e9}");
        assert_eq!(borrowed.to_string(), "a/\"b\" \u{e9}");
        assert_eq!(format!("{}/{}", borrowed, owned), "a/\"b\" \u{e9}/a/\"b\" \u{e9}");
        assert_eq!(format!("{:?}", owned), "Name(\"a/\\\"b\\\" \u{e9}\")");
        assert_eq!(format!("{:?}", borrowed), format!("{:?}", owned));
        assert_eq!(format!("{:#?}", borrowed), format!("{:#?}", owned));
        assert_eq!(format!("{:#?}", Name::new("a").unwrap()), "Name(\n    \"a\",\n)");
        assert_eq!(Name::ROOT.to_string(), "");
        assert_eq!(format!("{:?}", Name::ROOT), "Name(\"\")");
        assert_eq!(format!("{:?}", NameBuf::default()), "Name(\"\")");
    }

    /// Both forms are padded and truncated as a string is: the width and
    /// the precision count characters.
    #[test]
    fn padding() {
        let text = "EFI/\u{e9}";
        let owned = NameBuf::new(text).unwrap();
        let borrowed: &Name = &owned;
        let padded = "       EFI/\u{e9}|EFI/\u{e9}       |EFI|***EFI/****";
        assert_eq!(format!("{0:>12}|{0:<12}|{0:.3}|{0:*^11.4}", borrowed), padded);
        assert_eq!(format!("{0:>12}|{0:<12}|{0:.3}|{0:*^11.4}", owned), padded);
        assert_eq!(format!("{0:>12}|{0:<12}|{0:.3}|{0:*^11.4}", text), padded);
        // A name that is as wide as asked for, or wider, is printed as it is.
        assert_eq!(format!("{:5}", borrowed), text);
        assert_eq!(format!("{:>2}", owned), text);
        assert_eq!(format!("{:.5}", borrowed), text);
        // The root is all padding.
        assert_eq!(format!("{0:>3}|{0:<3}|{0:.3}|", Name::ROOT), "   |   ||");
        assert_eq!(format!("{0:>3}|{0:<3}|{0:.3}|", NameBuf::default()), "   |   ||");
    }

    /// A borrowed name is as large as a `&str` and an owned one as large as
    /// a `String`, and both go to other threads, as the error of an owned
    /// name does.
    #[test]
    fn sizes_and_threads() {
        assert_eq!(size_of::<&Name>(), size_of::<&str>());
        assert_eq!(size_of::<Option<&Name>>(), size_of::<&str>());
        assert_eq!(size_of::<NameBuf>(), size_of::<String>());
        fn send_and_sync<T: Send + Sync>() {}
        send_and_sync::<&'static Name>();
        send_and_sync::<NameBuf>();
        send_and_sync::<NameError>();
    }

    /// The name of a file on the host joins as the string of its bytes
    /// does. One that is not UTF-8 is refused for that before anything
    /// else, also when it is too long or has a slash.
    #[test]
    fn joining_names_of_files() {
        let parents = [Name::ROOT, Name::new("a").unwrap(), Name::new("a/b c").unwrap()];
        let too_long: Vec<u8> = iter::repeat_n(b'x', Name::MAX_LEN).chain([0xff]).collect();
        for parent in &parents {
            for component in [
                "c",
                "...",
                "\u{e9}",
                "",
                ".",
                "..",
                "a/b",
                "a\tb",
                "a\u{fffe}",
                "Uapi16Manifest",
            ] {
                let joined = parent.join_os(OsStr::new(component));
                assert_eq!(joined, parent.join(component), "{:?} {:?}", parent, component);
            }
            for bytes in [&b"\x80"[..], b"\xff", b"a\xe2\x82", b"a/\xff", &too_long] {
                let joined = parent.join_os(OsStr::from_bytes(bytes));
                assert_eq!(joined, Err(NameProblem::NotUtf8), "{:?} {:?}", parent, bytes);
            }
        }
    }
}
