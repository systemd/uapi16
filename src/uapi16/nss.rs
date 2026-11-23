// SPDX-License-Identifier: LGPL-2.1-or-later
//! The names of users and groups in the user database of the host, which
//! getpwuid_r() and getgrgid_r() of the C library look up. Only the module
//! sys calls them.
//!
//! This module and the module ioctl have the unsafe code of the crate, but
//! for the one cast of the module name. The two functions write an entry
//! into a struct of the caller and its strings into a buffer of the caller,
//! and point from the one into the other. Nothing is read through such a
//! pointer here. It only says where in the buffer the name starts, and the
//! name is read from the buffer, which has to hold it up to its end. A name
//! that a manifest cannot hold is none.

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::CStr;
use std::mem;
use std::ptr;

use libc::{c_char, c_int};

use crate::object::FileObject;
use crate::STRING_RULES;

/// How large the buffer for an entry is where sysconf() gives no size, the
/// same as for systemd.
const DEFAULT_BUFFER_SIZE: usize = 4096;
/// The largest buffer an entry is looked up with. An entry that needs
/// more, such as a group of very many members, has no name here.
const MAX_BUFFER_SIZE: usize = 16 * 1024 * 1024;

/// An entry of the user database: `struct passwd` or `struct group`.
trait Record: Sized {
    /// What sysconf() is asked for the size a buffer for an entry needs.
    const BUFFER_SIZE: c_int;

    /// Looks up the entry of the ID `id`, as getpwuid_r() and getgrgid_r()
    /// do: writes it into `record` and its strings into `buffer`, and
    /// stores `record` in `found`, or null if there is none. Returns 0 or
    /// an error number.
    ///
    /// # Safety
    ///
    /// `record` and `found` are valid for writes, and `buffer` is valid for
    /// writes of `size` bytes.
    unsafe fn look_up(id: u32, record: *mut Self, buffer: *mut c_char, size: usize, found: *mut *mut Self) -> c_int;

    /// Where the entry says its name is.
    fn name(&self) -> *const c_char;
}

impl Record for libc::passwd {
    const BUFFER_SIZE: c_int = libc::_SC_GETPW_R_SIZE_MAX;

    unsafe fn look_up(id: u32, record: *mut Self, buffer: *mut c_char, size: usize, found: *mut *mut Self) -> c_int {
        // SAFETY: getpwuid_r() writes one `struct passwd` through `record`,
        // at most `size` bytes through `buffer` and one pointer through
        // `found`, all of which the caller guarantees to be valid for
        // that. It keeps none of them.
        unsafe { libc::getpwuid_r(id, record, buffer, size, found) }
    }

    fn name(&self) -> *const c_char {
        self.pw_name
    }
}

impl Record for libc::group {
    const BUFFER_SIZE: c_int = libc::_SC_GETGR_R_SIZE_MAX;

    unsafe fn look_up(id: u32, record: *mut Self, buffer: *mut c_char, size: usize, found: *mut *mut Self) -> c_int {
        // SAFETY: getgrgid_r() writes one `struct group` through `record`,
        // at most `size` bytes through `buffer` and one pointer through
        // `found`, all of which the caller guarantees to be valid for
        // that. It keeps none of them.
        unsafe { libc::getgrgid_r(id, record, buffer, size, found) }
    }

    fn name(&self) -> *const c_char {
        self.gr_name
    }
}

/// The user database of the host, as the C library sees it: /etc/passwd
/// and /etc/group, and whatever else its name service switch is set up
/// with. It keeps the buffer the entries are read into from one lookup to
/// the next.
#[derive(Debug, Default)]
pub(crate) struct UserDatabase {
    /// What an entry is read into: nothing before the first lookup, then
    /// as much as the largest entry so far took.
    buffer: Vec<u8>,
}

impl UserDatabase {
    /// The user database, with nothing looked up yet.
    pub(crate) fn new() -> UserDatabase {
        UserDatabase::default()
    }

    /// The name of the user `uid`, as a manifest can hold it. A user that
    /// the database does not have or that cannot be looked up has none,
    /// and neither has one whose name is not a `userName` of a manifest.
    pub(crate) fn user_name(&mut self, uid: u32) -> Option<String> {
        self.name_of::<libc::passwd>(uid, MAX_BUFFER_SIZE)
    }

    /// The name of the group `gid`, as [`UserDatabase::user_name`] gives
    /// that of a user.
    pub(crate) fn group_name(&mut self, gid: u32) -> Option<String> {
        self.name_of::<libc::group>(gid, MAX_BUFFER_SIZE)
    }

    /// How large a buffer the lookup of an entry starts with: what
    /// sysconf() says, which is a first guess and not a limit.
    fn first_buffer_size<R: Record>() -> usize {
        // SAFETY: sysconf() takes a number and returns one, and reads and
        // writes no memory of its caller.
        let size = unsafe { libc::sysconf(R::BUFFER_SIZE) };
        match usize::try_from(size) {
            Ok(size) if size > 0 => size.min(MAX_BUFFER_SIZE),
            _ => DEFAULT_BUFFER_SIZE,
        }
    }

    /// The name of the entry of the ID `id`, looked up with a buffer of at
    /// most `max_size` bytes. The buffer doubles while the entry does not
    /// fit into it, as for systemd's getpwuid_malloc().
    fn name_of<R: Record>(&mut self, id: u32, max_size: usize) -> Option<String> {
        // The two IDs that stand for no ID are not looked up.
        if !FileObject::is_valid_id(id) {
            return None;
        }
        if self.buffer.is_empty() {
            self.buffer
                .resize(UserDatabase::first_buffer_size::<R>().min(max_size), 0);
        }
        loop {
            // SAFETY: `struct passwd` and `struct group` are integers and
            // pointers, for which all zeroes are a value: 0 and the null
            // pointer.
            let mut record: R = unsafe { mem::zeroed() };
            let mut found: *mut R = ptr::null_mut();
            // SAFETY: `record` and `found` are locals, valid for writes
            // through the call, and the buffer is valid for writes of the
            // bytes it holds, whose number is the size passed.
            let error = unsafe {
                R::look_up(
                    id,
                    &mut record,
                    self.buffer.as_mut_ptr().cast(),
                    self.buffer.len(),
                    &mut found,
                )
            };
            match error {
                // Found: the entry is the one that was passed in.
                0 if ptr::eq(found, &record) => return self.name_at(record.name()),
                libc::ERANGE if self.buffer.len() < max_size => {
                    let size = self.buffer.len().saturating_mul(2).min(max_size);
                    self.buffer.resize(size, 0);
                }
                libc::EINTR => {}
                // No entry, or an error, which systemd passes over as
                // well.
                _ => return None,
            }
        }
    }

    /// The name an entry says starts at `name`, which is a pointer into the
    /// buffer. It is not read through: it has to lead into the buffer, the
    /// name is read from there, and it has to end inside the buffer.
    fn name_at(&self, name: *const c_char) -> Option<String> {
        let start = name.addr().checked_sub(self.buffer.as_ptr().addr())?;
        let name = CStr::from_bytes_until_nul(self.buffer.get(start..)?).ok()?;
        UserDatabase::checked(name.to_str().ok()?)
    }

    /// `name` if a manifest can hold it as the name of a user or of a
    /// group: one systemd's relaxed rules take, without what the strings of
    /// a manifest may not have.
    fn checked(name: &str) -> Option<String> {
        (FileObject::is_owner_name(name) && STRING_RULES.admits(name)).then(|| name.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::fs;
    use std::process::Command;

    /// The names the file `path` gives the IDs it lists, /etc/passwd or
    /// /etc/group: the first entry of each ID, which is the one a lookup
    /// finds where the C library looks into these files first.
    fn listed(path: &str) -> BTreeMap<u32, String> {
        let mut names = BTreeMap::new();
        for line in fs::read_to_string(path).unwrap_or_default().lines() {
            let mut fields = line.split(':');
            let (Some(name), Some(_), Some(id)) = (fields.next(), fields.next(), fields.next()) else {
                continue;
            };
            if let Ok(id) = id.parse() {
                names.entry(id).or_insert_with(|| name.to_owned());
            }
        }
        names
    }

    /// An ID that the user database has no user for, found by asking id(1),
    /// which looks users up as this module does, from an unlikely one on.
    fn unknown_id() -> u32 {
        let known = |id: &u32| {
            let output = Command::new("id").args(["-u", &id.to_string()]).output();
            output.is_ok_and(|output| output.status.success())
        };
        (4_000_000_000..4_000_000_100)
            .find(|id| !known(id))
            .expect("an ID without a user")
    }

    /// The users and the groups /etc/passwd and /etc/group list have the
    /// names these files give them, if a manifest can hold them. An ID
    /// nobody has and the two IDs that stand for none have no name.
    #[test]
    fn names() {
        let mut database = UserDatabase::new();
        let (users, groups) = (listed("/etc/passwd"), listed("/etc/group"));
        if users.is_empty() || groups.is_empty() {
            eprintln!("skipping: /etc/passwd or /etc/group lists nothing");
        }
        // Twice: the second lookup goes through the buffer of the first.
        for _ in 0..2 {
            for (&uid, name) in &users {
                assert_eq!(database.user_name(uid), UserDatabase::checked(name), "{}", uid);
            }
            for (&gid, name) in &groups {
                assert_eq!(database.group_name(gid), UserDatabase::checked(name), "{}", gid);
            }
        }
        assert_eq!(database.user_name(unknown_id()), None);
        for invalid in [u32::MAX, u32::from(u16::MAX)] {
            assert_eq!(database.user_name(invalid), None);
            assert_eq!(database.group_name(invalid), None);
        }
    }

    /// An entry that does not fit into the buffer is looked up again with
    /// twice the buffer, until it fits or the buffer may not grow any
    /// more. Then it has no name.
    #[test]
    fn buffers_grow() {
        let users = listed("/etc/passwd");
        let groups = listed("/etc/group");
        let (Some((&uid, user)), Some((&gid, group))) = (users.iter().next(), groups.iter().next()) else {
            eprintln!("skipping: /etc/passwd or /etc/group lists nothing");
            return;
        };
        for first in [1, 2, 3, 7] {
            let mut database = UserDatabase { buffer: vec![0; first] };
            assert_eq!(database.user_name(uid), UserDatabase::checked(user), "{}", first);
            assert!(database.buffer.len() > first);
            let mut database = UserDatabase { buffer: vec![0; first] };
            assert_eq!(database.group_name(gid), UserDatabase::checked(group), "{}", first);
            assert!(database.buffer.len() > first);
        }
        // A buffer that may not grow to the size of the entry.
        let mut database = UserDatabase { buffer: vec![0; 1] };
        assert_eq!(database.name_of::<libc::passwd>(uid, 2), None);
        assert_eq!(database.buffer.len(), 2);
        assert_eq!(database.name_of::<libc::group>(gid, 2), None);
        assert_eq!(database.buffer.len(), 2);
    }

    /// A name is only read from the buffer: a pointer that leads elsewhere
    /// or to a name that does not end in the buffer gives none.
    #[test]
    fn names_come_from_the_buffer() {
        let mut database = UserDatabase {
            buffer: b"root\0bin\0no end".to_vec(),
        };
        let at =
            |database: &UserDatabase, offset: usize| database.buffer.as_ptr().wrapping_add(offset).cast::<c_char>();
        assert_eq!(database.name_at(at(&database, 0)).as_deref(), Some("root"));
        assert_eq!(database.name_at(at(&database, 2)).as_deref(), Some("ot"));
        assert_eq!(database.name_at(at(&database, 5)).as_deref(), Some("bin"));
        // The empty name, the name without an end, and the end of the
        // buffer.
        assert_eq!(database.name_at(at(&database, 4)), None);
        assert_eq!(database.name_at(at(&database, 9)), None);
        assert_eq!(database.name_at(at(&database, database.buffer.len())), None);
        assert_eq!(database.name_at(at(&database, database.buffer.len() + 1)), None);
        assert_eq!(database.name_at(database.buffer.as_ptr().wrapping_sub(1).cast()), None);
        assert_eq!(database.name_at(ptr::null()), None);
        let elsewhere = c"elsewhere";
        assert_eq!(database.name_at(elsewhere.as_ptr()), None);
        // Bytes that are not UTF-8 are not a name.
        database.buffer = b"\xff\xfe\0".to_vec();
        assert_eq!(database.name_at(at(&database, 0)), None);
    }

    /// The names a manifest holds are those systemd's relaxed rules take,
    /// which its reader holds `userName` and `groupName` to, without
    /// noncharacters.
    #[test]
    fn names_a_manifest_holds() {
        for name in [
            "root",
            "systemd-network",
            "user@example.com",
            "a b",
            "J\u{f6}rg",
            "_apt",
            "0day",
            "1.5",
        ] {
            assert_eq!(UserDatabase::checked(name).as_deref(), Some(name));
        }
        for name in [
            "",
            " a",
            "a ",
            ".",
            "..",
            "0",
            "12345",
            "-1",
            "a:b",
            "a/b",
            "a\nb",
            "a\u{7f}",
            "a\u{fffe}",
        ] {
            assert_eq!(UserDatabase::checked(name), None, "{:?}", name);
        }
    }
}
