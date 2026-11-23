// SPDX-License-Identifier: LGPL-2.1-or-later
//! The sort of the manifest builder: records that come in any order go
//! out in the order of their keys, and records with the same key in the
//! order they came.
//!
//! It is an external merge sort. The records gather in memory, up to a
//! fixed size. Where a manifest is complete before that, they are sorted
//! there and nothing touches a disk. Otherwise they are sorted and written
//! to a scratch file as a run, and the next ones gather. In the end the
//! runs and what is still in memory are merged: the next record is always
//! the smallest of those the runs have next, which a heap of the runs
//! finds. Each run is read through a buffer of its own.
//!
//! A merge takes so many runs at once that their buffers fit into the
//! memory the records took. A sort that wrote more runs merges them in
//! passes first: runs that follow each other become one longer run, which
//! is appended to the scratch file and stands where they stood. A pass
//! does not merge every run. It merges just enough of them for the merges
//! after it to be full ones, in a smaller merge first and then in full
//! ones, and leaves the other runs as they are. So the memory is the fixed
//! size and as much again for the buffers, however many records there are.
//! A record is written once and read once, and once more for every pass it
//! is in.
//!
//! Records with the same key stay in the order they came through all of
//! this: a merge takes the record of the earlier run first, a pass merges
//! only runs that follow each other, and what was in memory at the end
//! came last.
//!
//! What a merge has read of a run is not read again, and its room is given
//! back to the file system while the merge goes on, as holes in the scratch
//! file. So the data of the scratch file takes about the room of the
//! records also while a pass writes them again, and it gives that room back
//! while the manifest is written. A file system can take more room for the
//! file than its data takes: xfs takes up to 8 GiB past the end of a file
//! that grows at its end, for what it expects to be written there. Once the
//! passes are over nothing is, and a hole past the end of the file gives
//! that room back before the last merge. A file system that cannot punch
//! holes keeps the room until the file is closed, and what every pass
//! writes comes on top of it: the room of the records once more for every
//! pass they are in.
//!
//! Nothing here does an unbounded amount of work at once. Writing a run can
//! be done in parts, and so can what is to do before the first record goes
//! out. Then the merge hands out one record at a time. The records in
//! memory are sorted in one go, before they are written as a run and at the
//! end. That takes longer than a part of a run, but there are never more of
//! them than the fixed size of memory holds and the one record that went
//! over it. And a step of a merge reads more than its budget where the
//! buffers of its runs run low, a buffer of every run at most, see
//! [`Merge::prepare`].

use std::io;
use std::mem;
use std::num::NonZeroU64;
use std::ops::Range;

use crate::scratch::Scratch;
use crate::sys::ScratchFile;
use crate::{Name, MAX_RECORD_SIZE};

/// How many bytes of records gather in memory before they are written out
/// as a run, with what says where each starts.
const MEMORY_LIMIT: usize = 32 * 1024 * 1024;
/// How many bytes of a run memory holds while runs are merged.
const RUN_BUFFER: usize = 64 * 1024;
/// How many runs are merged at once at most: as many as have their buffers
/// in the memory the records take.
const MOST_RUNS: usize = MEMORY_LIMIT / RUN_BUFFER;
/// How many runs a merge takes at least: with fewer it leaves as many runs
/// as it found.
const FEWEST_RUNS: usize = 2;
/// How many bytes of a run are put together before they are written.
const WRITE_BUFFER: usize = 256 * 1024;
/// How many bytes of a run a merge reads before it gives their room back to
/// the file system. A hole is a system call and work for the file system,
/// and until it is punched the room of what was read is held back: by a
/// merge about that much for each of its runs.
const HOLE_SIZE: u64 = 1024 * 1024;
/// What memory is first taken for records.
const FIRST_MEMORY: usize = 64 * 1024;
/// The size of what a record starts with: the length of its body in four
/// bytes and that of its key in two.
const HEADER_SIZE: usize = 6;
/// The longest key: a name.
const MAX_KEY: usize = Name::MAX_LEN;
/// The longest body: twice what a record of a manifest may take. A file
/// object a writer takes is shorter than that, see the module record: what
/// it has for a field is never a third longer here than in the record of
/// the manifest, but for the fixed part of a contents object, and an
/// object has few of those.
pub(crate) const MAX_BODY: usize = 2 * MAX_RECORD_SIZE;

/// An error for a scratch file that does not hold what was written to it.
fn damaged() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "a scratch file of the sort was changed")
}

/// The lengths of the body and of the key of the record that starts with
/// `header`.
fn lengths(header: [u8; HEADER_SIZE]) -> (usize, usize) {
    let [b0, b1, b2, b3, k0, k1] = header;
    (
        u32::from_le_bytes([b0, b1, b2, b3]) as usize,
        usize::from(u16::from_le_bytes([k0, k1])),
    )
}

/// The key and the body of the record that starts at `start` in `records`,
/// which this module wrote there.
fn record_at(records: &[u8], start: u32) -> (&[u8], &[u8]) {
    let record = &records[start as usize..];
    let (header, rest) = record.split_first_chunk().expect("a record has its header");
    let (body, key) = lengths(*header);
    (&rest[..key], &rest[key..key + body])
}

/// A run: records in order, from `start` to `end` in the scratch file.
#[derive(Clone, Copy, Debug)]
struct Run {
    start: u64,
    end: u64,
}

/// A run that is being written.
#[derive(Debug)]
struct Spill {
    /// How many of the records, in order, are in the file.
    written: usize,
    /// Where the next ones go in the file.
    at: u64,
    /// The records that are written next.
    pending: Vec<u8>,
}

/// How much memory a sort takes, and how it merges.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// How many bytes of records gather in memory.
    pub(crate) memory: usize,
    /// How many bytes of each run memory holds in a merge.
    pub(crate) run_buffer: usize,
    /// How many bytes of a run are written at a time.
    pub(crate) write_buffer: usize,
    /// How many runs are merged at once at most.
    pub(crate) runs: usize,
    /// How many bytes of a run a merge reads before it gives their room
    /// back to the file system.
    pub(crate) hole: u64,
}

impl Limits {
    /// How many bytes of a run a merge holds in memory: what the limits
    /// say, and the header and the key of a record at least.
    fn buffer_size(&self) -> usize {
        self.run_buffer.max(HEADER_SIZE + MAX_KEY)
    }

    /// How many runs a merge takes at once at most: what the limits say,
    /// and as many as a merge takes at least.
    fn most_runs(&self) -> usize {
        self.runs.max(FEWEST_RUNS)
    }
}

/// Takes records in any order, see the documentation of this module.
#[derive(Debug)]
pub(crate) struct Sorter {
    /// The records that are not in a run yet, one behind the other: each
    /// with its header, its key and its body.
    records: Vec<u8>,
    /// Where each of them starts.
    starts: Vec<u32>,
    /// The scratch file of the runs, once there is a run.
    file: Option<ScratchFile>,
    /// The runs, in the order they were written.
    runs: Vec<Run>,
    spill: Option<Spill>,
    limits: Limits,
}

impl Sorter {
    /// A sort without records, which takes no room yet.
    pub(crate) fn new() -> Sorter {
        Sorter::with_limits(Limits {
            memory: MEMORY_LIMIT,
            run_buffer: RUN_BUFFER,
            write_buffer: WRITE_BUFFER,
            runs: MOST_RUNS,
            hole: HOLE_SIZE,
        })
    }

    /// A sort that takes as much memory as `limits` says.
    pub(crate) fn with_limits(limits: Limits) -> Sorter {
        Sorter {
            records: Vec::new(),
            starts: Vec::new(),
            file: None,
            runs: Vec::new(),
            spill: None,
            limits,
        }
    }

    /// Sorts where the records start by their keys. Records with the same
    /// key stay in the order they came, which is that of where they
    /// start.
    fn sort(records: &[u8], starts: &mut [u32]) {
        starts.sort_unstable_by(|&one, &other| {
            let (key, other_key) = (record_at(records, one).0, record_at(records, other).0);
            key.cmp(other_key).then(one.cmp(&other))
        });
    }

    /// Whether the records in memory have reached their limit.
    fn is_full(&self) -> bool {
        self.records.len() + size_of_val(&self.starts[..]) >= self.limits.memory
    }

    /// Does a part of what is to do before another record is taken, and
    /// returns whether it is done: once the records in memory have reached
    /// their limit, they are sorted and written to the scratch file as a
    /// run. `budget` is about how many bytes are written for it now: the
    /// records are sorted in one go before the first of them are written,
    /// see the documentation of this module. The scratch file comes from
    /// `scratch` when the first run is written.
    ///
    /// A caller that works in steps calls this until it returns true
    /// before it pushes a record. [`Sorter::push`] does all that is left of
    /// it at once. A scratch file that cannot be made or written fails
    /// this and leaves the sort as it was.
    pub(crate) fn make_room(&mut self, scratch: &mut Scratch, budget: u64) -> io::Result<bool> {
        if self.spill.is_none() {
            if !self.is_full() {
                return Ok(true);
            }
            // Without a budget nothing is done, also not the sorting.
            if budget == 0 {
                return Ok(false);
            }
            if self.file.is_none() {
                self.file = Some(scratch.file()?);
            }
            Sorter::sort(&self.records, &mut self.starts);
            self.spill = Some(Spill {
                written: 0,
                at: self.runs.last().map_or(0, |run| run.end),
                pending: Vec::with_capacity(self.limits.write_buffer),
            });
        }
        let mut left = budget;
        self.write_run(&mut left)
    }

    /// Goes on writing the run that is being written until it is written to
    /// its end or `left` is used up, and returns whether it is written.
    /// `left` is how many bytes may still be written.
    fn write_run(&mut self, left: &mut u64) -> io::Result<bool> {
        let (Some(spill), Some(file)) = (&mut self.spill, &self.file) else {
            return Err(damaged());
        };
        while spill.written < self.starts.len() {
            if *left == 0 {
                return Ok(false);
            }
            // Something is always written, however small the budget.
            let most = usize::try_from(*left)
                .unwrap_or(usize::MAX)
                .min(self.limits.write_buffer);
            spill.pending.clear();
            let mut gathered = spill.written;
            while gathered < self.starts.len() && (spill.pending.len() < most || gathered == spill.written) {
                let (key, body) = record_at(&self.records, self.starts[gathered]);
                let start = self.starts[gathered] as usize;
                spill
                    .pending
                    .extend_from_slice(&self.records[start..start + HEADER_SIZE + key.len() + body.len()]);
                gathered += 1;
            }
            file.write_all_at(&spill.pending, spill.at)?;
            spill.at += spill.pending.len() as u64;
            spill.written = gathered;
            *left = left.saturating_sub(spill.pending.len() as u64);
        }
        self.runs.push(Run {
            start: self.runs.last().map_or(0, |run| run.end),
            end: spill.at,
        });
        self.spill = None;
        self.records.clear();
        self.records.shrink_to(self.limits.memory);
        self.starts.clear();
        Ok(true)
    }

    /// Takes the record with the key `key` and the body `body`. The key is
    /// at most as long as a name and the body at most [`MAX_BODY`] bytes.
    /// Longer ones are refused as invalid input.
    pub(crate) fn push(&mut self, scratch: &mut Scratch, key: &[u8], body: &[u8]) -> io::Result<()> {
        let (Ok(key_len), Ok(body_len)) = (u16::try_from(key.len()), u32::try_from(body.len())) else {
            return Err(io::ErrorKind::InvalidInput.into());
        };
        if key.len() > MAX_KEY || body.len() > MAX_BODY {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        while !self.make_room(scratch, u64::MAX)? {}
        let start = u32::try_from(self.records.len()).map_err(|_| io::Error::from(io::ErrorKind::OutOfMemory))?;
        // The memory for the records doubles up to its limit, and takes
        // what the one record needs that goes over it.
        let size = HEADER_SIZE + key.len() + body.len();
        if self.records.capacity() - self.records.len() < size {
            let doubled = (self.records.capacity() * 2).clamp(FIRST_MEMORY, self.limits.memory.max(FIRST_MEMORY));
            let capacity = doubled.max(self.records.len() + size);
            self.records.reserve_exact(capacity - self.records.len());
        }
        self.records.extend_from_slice(&body_len.to_le_bytes());
        self.records.extend_from_slice(&key_len.to_le_bytes());
        self.records.extend_from_slice(key);
        self.records.extend_from_slice(body);
        self.starts.push(start);
        Ok(())
    }

    /// Ends the sort: no more records come, and those that came go out
    /// through the merge this returns. Nothing is done for that yet. A run
    /// that is half written is written to its end, what is still in memory
    /// is sorted there, and the runs are read by [`Merge::prepare`].
    pub(crate) fn finish(self) -> Merge {
        Merge {
            limits: self.limits,
            sorter: Some(self),
            file: None,
            passes: None,
            last: RunMerge::default(),
            memory: InMemory::default(),
            taken: None,
            body: Vec::new(),
            failed: false,
        }
    }
}

/// The scratch file of the runs while they are merged. What a merge has
/// read of a run is not read again, and its room is given back to the file
/// system where the file system can do that.
#[derive(Debug)]
struct RunFile {
    scratch: ScratchFile,
    /// The size of a block of the file, while holes are punched into it.
    /// There is none where the file system does not say one, and from the
    /// first hole on that could not be punched.
    block: Option<NonZeroU64>,
    /// How many bytes of a run are read before their room is given back.
    hole: u64,
}

impl RunFile {
    /// How far past its end a file system can have taken room for a file
    /// that grows at its end, for what it expects to be written there: xfs
    /// takes up to 2^21 blocks, 8 GiB with blocks of 4 KiB and 128 GiB with
    /// the largest ones.
    const AHEAD: u64 = 128 * 1024 * 1024 * 1024;

    /// The scratch file `scratch`, whose runs are merged as `limits` says.
    fn new(scratch: ScratchFile, limits: &Limits) -> RunFile {
        RunFile {
            block: scratch.block_size().ok().and_then(NonZeroU64::new),
            scratch,
            hole: limits.hole,
        }
    }

    /// Gives the room of a run back as far as the run was read, and
    /// returns up to where it is given back then. `released` is up to
    /// where it was given back before, which is where the run starts at
    /// first, `read` up to where the run was read, and `ended` whether that
    /// is all of it.
    ///
    /// Only whole blocks are given back: of a block that is not all in the
    /// hole a file system merely writes over the part that is, and what a
    /// run shares a block with is another run. They are given back once
    /// they are as many bytes as a hole is to have, or once the run ended.
    ///
    /// A hole that cannot be punched is no error, and it is the last one
    /// that is tried: the file system cannot punch holes, or cannot punch
    /// this one, and the room stays taken until the file is closed.
    fn release(&mut self, released: u64, read: u64, ended: bool) -> u64 {
        let Some(block) = self.block else {
            return released;
        };
        let Some(start) = released.checked_next_multiple_of(block.get()) else {
            return released;
        };
        let end = read - read % block;
        if end <= start || (end - start < self.hole && !ended) {
            return released;
        }
        match self.scratch.punch_hole(start, end - start) {
            Ok(()) => end,
            Err(_) => {
                self.block = None;
                released
            }
        }
    }

    /// Gives back the room the file system took for the file past `end`,
    /// where the runs end, for what it expected to be written there. Once
    /// the passes are over nothing is. That is a hole past the end of the
    /// file, which stays as long as it is, and it is tried as the holes of
    /// the runs are, see [`RunFile::release`].
    fn release_past(&mut self, end: u64) {
        let Some(block) = self.block else {
            return;
        };
        let Some(start) = end.checked_next_multiple_of(block.get()) else {
            return;
        };
        if self.scratch.punch_hole(start, RunFile::AHEAD).is_err() {
            self.block = None;
        }
    }
}

/// The passes of a sort that wrote more runs than a merge takes at once,
/// see the documentation of this module. A pass goes over the runs in the
/// order of their records and merges runs that follow each other into one
/// run each, from the first run on, until as many runs are left as it is
/// to leave. The runs behind those stay as they are.
#[derive(Debug)]
struct Passes {
    /// The runs in the order of their records. While a pass is under way,
    /// the runs it made come first, up to `made`, and the runs it did not
    /// get to yet start at `next`. Those in between were merged.
    runs: Vec<Run>,
    made: usize,
    next: usize,
    /// How many runs the pass that is under way leaves.
    target: usize,
    /// How many runs a merge takes at once at most.
    most: usize,
    /// The merge that is under way.
    merge: Option<PassMerge>,
    /// Where the next run goes in the scratch file: behind all the others.
    end: u64,
}

impl Passes {
    /// The passes over the runs `runs`, which follow each other in the
    /// scratch file, of a sort that merges as `limits` says. There are none
    /// where the runs are few enough for one merge.
    fn new(runs: Vec<Run>, limits: &Limits) -> Passes {
        Passes {
            // No pass is under way: the first one begins with the first
            // merge that is asked for.
            target: runs.len(),
            end: runs.last().map_or(0, |run| run.end),
            runs,
            made: 0,
            next: 0,
            most: limits.most_runs(),
            merge: None,
        }
    }

    /// How many runs there are: those the pass that is under way made, and
    /// those it did not get to yet.
    fn count(&self) -> usize {
        self.made + (self.runs.len() - self.next)
    }

    /// How many runs a pass leaves that finds `runs` runs, which are more
    /// than `most`, the most a merge takes at once: the largest power of
    /// `most` below `runs`. Then every merge after the pass is a full one:
    /// the last merge of `most` runs, the `most` merges of a pass before
    /// it, and so on.
    fn target(runs: usize, most: usize) -> usize {
        let mut target = most;
        while let Some(larger) = target.checked_mul(most).filter(|&larger| larger < runs) {
            target = larger;
        }
        target
    }

    /// Which of the runs the next merge takes, or nothing once the runs
    /// are few enough for one merge.
    ///
    /// A merge of n runs leaves n - 1 runs fewer. So a pass gets to the
    /// number of runs it leaves in full merges, but for what the runs it
    /// has to lose are not a multiple of: a smaller merge loses those, and
    /// it comes first.
    fn next_merge(&mut self) -> Option<Range<usize>> {
        if self.count() == self.target {
            // The pass is over. The runs it made stand where those stood
            // that they were made of.
            self.runs.drain(self.made..self.next);
            (self.made, self.next) = (0, 0);
            if self.runs.len() <= self.most {
                return None;
            }
            self.target = Passes::target(self.runs.len(), self.most);
        }
        let over = self.count() - self.target;
        let size = match over % (self.most - 1) {
            0 => self.most,
            rest => rest + 1,
        };
        let merged = self.next..self.next + size;
        self.next = merged.end;
        Some(merged)
    }

    /// Takes the run `run`, which a merge made and wrote behind all the
    /// others, in place of the runs that merge took.
    fn put(&mut self, run: Run) {
        self.runs[self.made] = run;
        self.made += 1;
        self.end = run.end;
    }

    /// Goes on with the passes until they are over or `left` is used up,
    /// and returns the runs that are left once they are over: few enough
    /// for one merge, in the order of their records. `left` is how many
    /// bytes may still be read from the runs.
    fn advance(&mut self, file: &mut Option<RunFile>, limits: &Limits, left: &mut u64) -> io::Result<Option<Vec<Run>>> {
        loop {
            let mut merge = match self.merge.take() {
                Some(merge) => merge,
                None => match self.next_merge() {
                    Some(merged) => PassMerge::new(&self.runs[merged], self.end, limits),
                    None => return Ok(Some(mem::take(&mut self.runs))),
                },
            };
            match merge.advance(file, limits, left)? {
                Some(run) => self.put(run),
                None => {
                    self.merge = Some(merge);
                    return Ok(None);
                }
            }
        }
    }
}

/// A merge of a pass: runs that follow each other become one run, which is
/// written to the scratch file behind all the others.
#[derive(Debug)]
struct PassMerge {
    runs: RunMerge,
    /// The run that is written, as far as it is written.
    made: Run,
    /// The records that are written next.
    pending: Vec<u8>,
}

impl PassMerge {
    /// A merge of the runs `runs` into a run that starts at `start` in the
    /// scratch file.
    fn new(runs: &[Run], start: u64, limits: &Limits) -> PassMerge {
        PassMerge {
            runs: RunMerge::new(runs, limits),
            made: Run { start, end: start },
            pending: Vec::with_capacity(limits.write_buffer),
        }
    }

    /// Goes on with the merge until all records are in the new run or
    /// `left` is used up, and returns the run once they are. `left` is how
    /// many bytes may still be read from the runs. Each record is read and
    /// written once.
    fn advance(&mut self, file: &mut Option<RunFile>, limits: &Limits, left: &mut u64) -> io::Result<Option<Run>> {
        if !self.runs.open(file, left)? {
            return Ok(None);
        }
        let file = file.as_mut().ok_or_else(damaged)?;
        while *left > 0 {
            let most = usize::try_from(*left).unwrap_or(usize::MAX).min(limits.write_buffer);
            self.pending.clear();
            // Something is always written, however small the budget.
            while self.pending.len() < most || self.pending.is_empty() {
                let Some(run) = self.runs.top() else {
                    break;
                };
                self.runs.readers[run].copy_record(file, &mut self.pending)?;
                self.runs.advance_top(file)?;
            }
            // No record was left.
            if self.pending.is_empty() {
                return Ok(Some(self.made));
            }
            file.scratch.write_all_at(&self.pending, self.made.end)?;
            self.made.end += self.pending.len() as u64;
            *left = left.saturating_sub(self.pending.len() as u64);
        }
        Ok(None)
    }
}

/// A run as a merge reads it: from front to back, a buffer at a time.
#[derive(Debug)]
struct RunReader {
    /// Where the bytes behind those of the buffer are in the file.
    at: u64,
    /// Where the run ends in the file.
    end: u64,
    /// Up to where the room of the run was given back to the file system.
    released: u64,
    /// The bytes of the run that were read and not used yet, from `read`
    /// on.
    buffer: Vec<u8>,
    read: usize,
    /// How many bytes the buffer holds at most.
    size: usize,
    /// The header and the key of the record the run has next.
    header: [u8; HEADER_SIZE],
    key: Vec<u8>,
    /// The length of its body, which comes next in the run.
    body: usize,
}

impl RunReader {
    /// What reads the run `run` through a buffer of `size` bytes.
    fn new(run: Run, size: usize) -> RunReader {
        RunReader {
            at: run.start,
            end: run.end,
            released: run.start,
            buffer: Vec::new(),
            read: 0,
            size,
            header: [0; HEADER_SIZE],
            key: Vec::new(),
            body: 0,
        }
    }

    /// How many bytes of the run are not used yet.
    fn left(&self) -> u64 {
        (self.buffer.len() - self.read) as u64 + (self.end - self.at)
    }

    /// Gives the room of what was read of the run back to the file system,
    /// see [`RunFile::release`]. All that was read is in memory or went
    /// out.
    fn release(&mut self, file: &mut RunFile) {
        self.released = file.release(self.released, self.at, self.at == self.end);
    }

    /// Makes the buffer hold the next `size` bytes of the run, which is at
    /// most what a buffer holds. A run that ends before that was changed.
    fn fill(&mut self, file: &mut RunFile, size: usize) -> io::Result<()> {
        if self.buffer.len() - self.read >= size {
            return Ok(());
        }
        if self.left() < size as u64 {
            return Err(damaged());
        }
        self.buffer.drain(..self.read);
        self.read = 0;
        let have = self.buffer.len();
        // As much as the buffer holds, or what is left of the run.
        let more = (self.size - have).min(usize::try_from(self.end - self.at).unwrap_or(usize::MAX));
        self.buffer.resize(have + more, 0);
        file.scratch.read_exact_at(&mut self.buffer[have..], self.at)?;
        self.at += more as u64;
        self.release(file);
        Ok(())
    }

    /// Reads the header and the key of the next record, and returns
    /// whether there is one.
    fn next_key(&mut self, file: &mut RunFile) -> io::Result<bool> {
        if self.left() == 0 {
            return Ok(false);
        }
        self.fill(file, HEADER_SIZE)?;
        let header = self.buffer[self.read..].first_chunk().ok_or_else(damaged)?;
        let (body, key) = lengths(*header);
        if key > MAX_KEY || body > MAX_BODY {
            return Err(damaged());
        }
        self.header = *header;
        self.read += HEADER_SIZE;
        self.fill(file, key)?;
        self.key.clear();
        self.key.extend_from_slice(&self.buffer[self.read..self.read + key]);
        self.read += key;
        if self.left() < body as u64 {
            return Err(damaged());
        }
        self.body = body;
        Ok(true)
    }

    /// Appends the body of the record whose key was read to `records`.
    /// What of it the buffer does not hold is read from the file directly,
    /// so the buffer never grows for a large record.
    fn append_body(&mut self, file: &mut RunFile, records: &mut Vec<u8>) -> io::Result<()> {
        let buffered = (self.buffer.len() - self.read).min(self.body);
        records.extend_from_slice(&self.buffer[self.read..self.read + buffered]);
        self.read += buffered;
        let rest = self.body - buffered;
        if rest > 0 {
            let have = records.len();
            records.resize(have + rest, 0);
            file.scratch.read_exact_at(&mut records[have..], self.at)?;
            self.at += rest as u64;
            self.release(file);
        }
        self.body = 0;
        Ok(())
    }

    /// Appends the record whose key was read to `records` as the run has
    /// it: its header, its key and its body.
    fn copy_record(&mut self, file: &mut RunFile, records: &mut Vec<u8>) -> io::Result<()> {
        records.extend_from_slice(&self.header);
        records.extend_from_slice(&self.key);
        self.append_body(file, records)
    }
}

/// The runs a merge reads at once, and which of them has the record that
/// goes out next.
#[derive(Debug, Default)]
struct RunMerge {
    /// The runs in the order of their records.
    readers: Vec<RunReader>,
    /// The runs that have a record, as a heap: the one whose next record
    /// goes out first is at the top.
    heap: Vec<usize>,
    /// How many of the runs were looked at for their first record. The
    /// heap is in order once all of them were.
    opened: usize,
}

impl RunMerge {
    /// A merge of the runs `runs`, each read as `limits` says.
    fn new(runs: &[Run], limits: &Limits) -> RunMerge {
        let size = limits.buffer_size();
        RunMerge {
            readers: runs.iter().map(|run| RunReader::new(*run, size)).collect(),
            heap: Vec::new(),
            opened: 0,
        }
    }

    /// Whether the next record of the run `one` goes out before that of
    /// the run `other`: its key is smaller, or it is the same and the run
    /// is the earlier one.
    fn before(&self, one: usize, other: usize) -> bool {
        let (key, other_key) = (&self.readers[one].key, &self.readers[other].key);
        key.cmp(other_key).then(one.cmp(&other)).is_lt()
    }

    /// Moves the run at `at` in the heap down to where it belongs.
    fn sift_down(&mut self, mut at: usize) {
        loop {
            let mut first = at;
            for child in [2 * at + 1, 2 * at + 2] {
                if child < self.heap.len() && self.before(self.heap[child], self.heap[first]) {
                    first = child;
                }
            }
            if first == at {
                break;
            }
            self.heap.swap(at, first);
            at = first;
        }
    }

    /// Looks at the first record of the runs that were not looked at yet,
    /// one run after the other until `left` is used up, and returns whether
    /// all of them were looked at now. `left` is how many bytes may still
    /// be read from the runs, and a run takes what its buffer holds of it.
    fn open(&mut self, file: &mut Option<RunFile>, left: &mut u64) -> io::Result<bool> {
        while self.opened < self.readers.len() {
            if *left == 0 {
                return Ok(false);
            }
            let reader = &mut self.readers[self.opened];
            if reader.next_key(file.as_mut().ok_or_else(damaged)?)? {
                self.heap.push(self.opened);
            }
            // Every run counts, also one without a record.
            *left = left.saturating_sub((reader.buffer.len() as u64).max(1));
            self.opened += 1;
            if self.opened == self.readers.len() {
                for at in (0..self.heap.len() / 2).rev() {
                    self.sift_down(at);
                }
            }
        }
        Ok(true)
    }

    /// The run whose next record goes out next, or nothing once all went
    /// out. The first record of every run was looked at.
    fn top(&self) -> Option<usize> {
        self.heap.first().copied()
    }

    /// Moves the run at the top of the heap on to its next record: the one
    /// it had went out.
    fn advance_top(&mut self, file: &mut RunFile) -> io::Result<()> {
        let Some(&run) = self.heap.first() else {
            return Ok(());
        };
        if !self.readers[run].next_key(file)? {
            self.heap.swap_remove(0);
        }
        self.sift_down(0);
        Ok(())
    }
}

/// The records that were still in memory when a sort ended, in order.
#[derive(Debug, Default)]
struct InMemory {
    /// The records, one behind the other, and where each starts, in the
    /// order of their keys.
    records: Vec<u8>,
    starts: Vec<u32>,
    /// How many of them went out.
    next: usize,
}

impl InMemory {
    /// The key and the body of the record that goes out next, if all did
    /// not go out yet.
    fn record(&self) -> Option<(&[u8], &[u8])> {
        let start = self.starts.get(self.next)?;
        Some(record_at(&self.records, *start))
    }
}

/// Where the record came from that a merge handed out.
#[derive(Clone, Copy, Debug)]
enum Taken {
    /// From the run at the top of the heap.
    Run(usize),
    /// From the records in memory.
    Memory,
}

/// The records of a sort in the order of their keys, one at a time, see
/// the documentation of this module.
#[derive(Debug)]
pub(crate) struct Merge {
    /// The sort as it ended, until the run it was writing is written to its
    /// end and what it has in memory is sorted. A sort whose run cannot be
    /// written stays here as well, with the scratch file of the runs.
    sorter: Option<Sorter>,
    /// The scratch file of the runs, if the sort wrote one.
    file: Option<RunFile>,
    limits: Limits,
    /// The passes over the runs, once the sort is wound up and until they
    /// are over.
    passes: Option<Passes>,
    /// The last merge: of the runs the passes left, which it has once they
    /// are over.
    last: RunMerge,
    /// The records that were still in memory when the sort ended. They
    /// came last, and the last merge takes them with the runs.
    memory: InMemory,
    /// Where the record came from that went out last. That one has to move
    /// on before the next record goes out.
    taken: Option<Taken>,
    /// The body of the record that went out last, if it came from a run.
    body: Vec<u8>,
    /// Whether a run could not be read or written. The merge fails from
    /// there on: it does not know any more where it is in that run.
    failed: bool,
}

impl Merge {
    /// Fails if the merge failed before.
    fn check(&self) -> io::Result<()> {
        if self.failed {
            return Err(io::Error::other("the sort failed before"));
        }
        Ok(())
    }

    /// Winds the sort up, which ended with a run half written and with
    /// records in memory, and returns whether that is done: the run is
    /// written to its end, as far as `left` allows, and then the records in
    /// memory are sorted, in one go. Without anything left nothing is done,
    /// also not the sorting.
    fn wind_up(&mut self, left: &mut u64) -> io::Result<bool> {
        let Some(sorter) = &mut self.sorter else {
            return Ok(true);
        };
        // The sort stays where it is until it is wound up, also where its
        // run can't be written: it has the scratch file of the runs.
        if (sorter.spill.is_some() && !sorter.write_run(left)?) || *left == 0 {
            return Ok(false);
        }
        Sorter::sort(&sorter.records, &mut sorter.starts);
        self.file = sorter.file.take().map(|file| RunFile::new(file, &self.limits));
        self.passes = Some(Passes::new(mem::take(&mut sorter.runs), &self.limits));
        self.memory = InMemory {
            records: mem::take(&mut sorter.records),
            starts: mem::take(&mut sorter.starts),
            next: 0,
        };
        self.sorter = None;
        Ok(true)
    }

    /// Goes on with what is to do before the first record goes out until
    /// it is done or `left` is used up, and returns whether it is done.
    fn advance(&mut self, left: &mut u64) -> io::Result<bool> {
        if !self.wind_up(left)? {
            return Ok(false);
        }
        if let Some(passes) = &mut self.passes {
            let Some(runs) = passes.advance(&mut self.file, &self.limits, left)? else {
                return Ok(false);
            };
            // Nothing is written to the scratch file from here on.
            if let Some(file) = &mut self.file {
                file.release_past(passes.end);
            }
            self.last = RunMerge::new(&runs, &self.limits);
            self.passes = None;
        }
        self.last.open(&mut self.file, left)
    }

    /// Does a part of what is to do before the first record goes out, and
    /// returns whether it is done. First the sort is wound up: a run it
    /// was still writing is written to its end, and what it has in memory
    /// is sorted. Where the sort wrote more runs than a merge takes at
    /// once, passes merge them into fewer and longer ones, see the
    /// documentation of this module. Then the first record of every run
    /// that is left is looked at.
    ///
    /// `budget` is about how many bytes of records are written to the run
    /// and read from the runs for it now, each of which a pass writes
    /// again. The records in memory are sorted in one go, whatever the
    /// budget. A run whose buffer runs low on the way reads as much as the
    /// buffer holds on top of that, so a step of a merge of many runs reads
    /// up to a buffer of each more: the step is bounded, but not held to
    /// its budget. With any budget it gets further, and without one nothing
    /// is sorted, read or written.
    ///
    /// A caller that works in steps calls this until it returns true
    /// before it takes a record. [`Merge::next`] does all that is left of
    /// it at once. Once it failed it fails whenever it is asked again, and
    /// so does [`Merge::next`].
    pub(crate) fn prepare(&mut self, budget: u64) -> io::Result<bool> {
        self.check()?;
        let mut left = budget;
        let prepared = self.advance(&mut left);
        self.failed = prepared.is_err();
        prepared
    }

    /// Moves on to the next record and returns where it comes from, or
    /// nothing once all went out. The body of a record of a run is read
    /// into the merge.
    fn move_on(&mut self) -> io::Result<Option<Taken>> {
        while !self.prepare(u64::MAX)? {}
        match self.taken.take() {
            Some(Taken::Run(_)) => self.last.advance_top(self.file.as_mut().ok_or_else(damaged)?)?,
            Some(Taken::Memory) => self.memory.next += 1,
            None => {}
        }
        let taken = match (self.last.top(), self.memory.record()) {
            (None, None) => return Ok(None),
            (Some(run), None) => Taken::Run(run),
            (None, Some(_)) => Taken::Memory,
            // What was in memory at the end came after every run, so a
            // run goes first where the keys are the same.
            (Some(run), Some((key, _))) if self.last.readers[run].key.as_slice() <= key => Taken::Run(run),
            (Some(_), Some(_)) => Taken::Memory,
        };
        if let Taken::Run(run) = taken {
            self.body.clear();
            let file = self.file.as_mut().ok_or_else(damaged)?;
            self.last.readers[run].append_body(file, &mut self.body)?;
        }
        self.taken = Some(taken);
        Ok(Some(taken))
    }

    /// The key and the body of the next record, or nothing once all went
    /// out. Once [`Merge::prepare`] is done it reads at most a buffer of
    /// one run and the body of one record from the scratch file. Before
    /// that it does what is left of it first. Once it failed it fails
    /// whenever it is asked again.
    pub(crate) fn next(&mut self) -> io::Result<Option<(&[u8], &[u8])>> {
        self.check()?;
        let taken = match self.move_on() {
            Ok(Some(taken)) => taken,
            Ok(None) => return Ok(None),
            Err(e) => {
                self.failed = true;
                return Err(e);
            }
        };
        match taken {
            Taken::Run(run) => Ok(Some((&self.last.readers[run].key, &self.body))),
            Taken::Memory => Ok(self.memory.record()),
        }
    }

    /// Gives the merge up: the scratch file of the runs goes back to
    /// `scratch`, which empties it, if the sort wrote one. The sort has the
    /// file until it is wound up, also where that failed, and the merge
    /// from then on. A merge that is dropped leaves the file as it is.
    pub(crate) fn give_back(self, scratch: &mut Scratch) {
        let of_sort = self.sorter.and_then(|sorter| sorter.file);
        let file = of_sort.or(self.file.map(|file| file.scratch));
        if let Some(file) = file {
            scratch.take_back(file);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::{OpenFile, TempDir, ST_BLOCKS_UNIT};
    use rustix::fs::SeekFrom;
    use std::env;
    use std::fmt;
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::Path;
    use std::process::Command;
    use std::str::FromStr;
    use std::time::{Duration, Instant};

    /// Scratch space in the directory `dir`.
    fn scratch_in(dir: &Path) -> Scratch {
        Scratch::beside(ScratchFile::open_directory(dir).unwrap().into())
    }

    /// Scratch space in a directory of its own.
    fn scratch(name: &str) -> (TempDir, Scratch) {
        let tmp = TempDir::new(name);
        let scratch = scratch_in(&tmp.0);
        (tmp, scratch)
    }

    /// A sort that writes a run for every few records, merges `runs` of
    /// them at once through buffers of the smallest size, and gives back
    /// every block it has read.
    fn small(memory: usize, runs: usize) -> Sorter {
        Sorter::with_limits(Limits {
            memory,
            run_buffer: 1,
            write_buffer: 64,
            runs,
            hole: 1,
        })
    }

    /// A number that is as good as random, from the number `seed`.
    fn mix(seed: u64) -> u64 {
        let mut x = seed.wrapping_add(0x9e37_79b9_7f4a_7c15);
        x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        x ^ (x >> 31)
    }

    /// Everything a merge hands out, each key with its body.
    fn drain(mut merge: Merge) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut all = Vec::new();
        while let Some((key, body)) = merge.next().unwrap() {
            all.push((key.to_vec(), body.to_vec()));
        }
        assert!(merge.next().unwrap().is_none());
        all
    }

    /// Records go out in the order of their keys, and those with the same
    /// key in the order they came, whether they all fit into memory, take
    /// a few runs or take so many that passes merge them first, a few at a
    /// time or two at a time, and whatever sizes the records have. So the
    /// same records go out the same however they were kept.
    #[test]
    fn sorts() {
        let (tmp, mut scratch) = scratch("sort-sorts");
        for (memory, count, most, runs, passes) in [
            (usize::MAX, 3000, MOST_RUNS, false, false),
            (4096, 3000, MOST_RUNS, true, false),
            (4096, 3000, 5, true, true),
            (4096, 3000, 2, true, true),
            (1, 300, MOST_RUNS, true, false),
            (1, 300, 298, true, true),
            (1, 300, 17, true, true),
            (1, 300, 3, true, true),
            (1, 300, 2, true, true),
            (1, 300, 0, true, true),
            (100_000, 3000, 2, true, true),
        ] {
            let mut sorter = small(memory, most);
            let mut expected = Vec::new();
            for index in 0..count {
                // Few keys, so that many records have the same one, and a
                // body that says in which order they came.
                let random = mix(index);
                let key = format!("{:03}", random % 97).into_bytes();
                let key = &key[..(random % 4) as usize];
                let mut body = index.to_le_bytes().to_vec();
                body.resize(8 + (random >> 8) as usize % 300, 0xab);
                if index % 1000 == 999 {
                    body.resize(200_000, 0xcd);
                }
                sorter.push(&mut scratch, key, &body).unwrap();
                expected.push((key.to_vec(), body));
            }
            assert_eq!(!sorter.runs.is_empty(), runs, "{}", memory);
            assert_eq!(sorter.file.is_some(), runs);
            assert_eq!(sorter.runs.len() > most.max(FEWEST_RUNS), passes, "{} {}", memory, most);
            // A stable sort is what this comes to.
            expected.sort_by(|one, other| one.0.cmp(&other.0));
            let sorted = drain(sorter.finish());
            assert_eq!(sorted.len(), expected.len());
            assert!(sorted == expected, "{} {}", memory, most);
        }
        // Nothing has a name in the directory of the scratch file.
        assert_eq!(fs::read_dir(&tmp.0).unwrap().count(), 0);
    }

    /// A sort without records hands out nothing, and one record comes back
    /// as it went in, also the largest one and one without a key or a
    /// body. A key or a body that is too long is refused.
    #[test]
    fn records() {
        let (_tmp, mut scratch) = scratch("sort-records");
        assert!(drain(Sorter::new().finish()).is_empty());
        assert!(drain(small(1, MOST_RUNS).finish()).is_empty());
        let largest = (vec![b'k'; MAX_KEY], vec![b'b'; MAX_BODY]);
        let records = [
            (Vec::new(), Vec::new()),
            (b"key".to_vec(), Vec::new()),
            (Vec::new(), b"body".to_vec()),
            largest,
        ];
        for memory in [usize::MAX, 1] {
            for (key, body) in &records {
                // Four records: with as little memory that is three runs
                // and a record in memory, and with two runs in a merge a
                // pass that merges two of them.
                for most in [MOST_RUNS, FEWEST_RUNS] {
                    let mut sorter = small(memory, most);
                    for _ in 0..4 {
                        sorter.push(&mut scratch, key, body).unwrap();
                    }
                    assert_eq!(sorter.runs.len(), if memory == 1 { 3 } else { 0 });
                    let sorted = drain(sorter.finish());
                    assert!(sorted == vec![(key.clone(), body.clone()); 4]);
                }
            }
        }
        let mut sorter = Sorter::new();
        let too_long = sorter.push(&mut scratch, &vec![0; MAX_KEY + 1], b"").unwrap_err();
        assert_eq!(too_long.kind(), io::ErrorKind::InvalidInput);
        let too_long = sorter.push(&mut scratch, b"", &vec![0; MAX_BODY + 1]).unwrap_err();
        assert_eq!(too_long.kind(), io::ErrorKind::InvalidInput);
        assert!(drain(sorter.finish()).is_empty());
    }

    /// The records in memory take what they need up to their limit and
    /// what the one record takes that goes over it, and give that back
    /// once they are written. A sort that fits never makes a scratch
    /// file.
    #[test]
    fn memory() {
        let (_tmp, mut scratch) = scratch("sort-memory");
        let limit = 1024 * 1024;
        let mut sorter = Sorter::with_limits(Limits {
            memory: limit,
            run_buffer: RUN_BUFFER,
            write_buffer: WRITE_BUFFER,
            runs: MOST_RUNS,
            hole: HOLE_SIZE,
        });
        let mut most = 0;
        for index in 0u64..40_000 {
            sorter.push(&mut scratch, &index.to_be_bytes(), &[0; 100]).unwrap();
            assert!(sorter.records.len() + size_of_val(&sorter.starts[..]) < limit + 200);
            most = most.max(sorter.records.capacity());
        }
        assert!(most <= limit + 200, "{}", most);
        assert!(sorter.runs.len() >= 4, "{:?}", sorter.runs);
        // A record of several megabytes goes over the limit alone, and the
        // next push writes it out.
        sorter.push(&mut scratch, b"large", &vec![0; MAX_BODY]).unwrap();
        assert!(sorter.records.capacity() > MAX_BODY);
        sorter.push(&mut scratch, b"small", b"").unwrap();
        assert!(sorter.records.capacity() <= limit, "{}", sorter.records.capacity());
        assert_eq!(drain(sorter.finish()).len(), 40_002);
        let mut sorter = Sorter::new();
        for index in 0u64..1000 {
            sorter.push(&mut scratch, &index.to_be_bytes(), &[0; 100]).unwrap();
        }
        assert!(sorter.file.is_none() && sorter.runs.is_empty());
        assert_eq!(sorter.records.capacity(), 128 * 1024);
    }

    /// The merges of the passes over `count` runs where a merge takes
    /// `most` runs at once: how many runs each takes, pass by pass. The
    /// runs it is tried with are one byte long each, so that what a merge
    /// makes of them shows which ones it took.
    fn merges(count: usize, most: usize) -> Vec<Vec<usize>> {
        let runs = (0..count as u64).map(|start| Run { start, end: start + 1 });
        let limits = Limits {
            memory: MEMORY_LIMIT,
            run_buffer: RUN_BUFFER,
            write_buffer: WRITE_BUFFER,
            runs: most,
            hole: HOLE_SIZE,
        };
        let mut passes = Passes::new(runs.collect(), &limits);
        let mut sizes: Vec<Vec<usize>> = Vec::new();
        loop {
            let begins = passes.count() == passes.target;
            let Some(merged) = passes.next_merge() else {
                break;
            };
            if begins {
                sizes.push(Vec::new());
            }
            sizes.last_mut().unwrap().push(merged.len());
            let merged = &passes.runs[merged];
            // The runs of a merge follow each other.
            assert!(merged.windows(2).all(|pair| pair[0].end == pair[1].start));
            let (first, last) = (merged[0], merged[merged.len() - 1]);
            passes.put(Run {
                start: first.start,
                end: last.end,
            });
        }
        // The runs that are left are all the runs in their order, and few
        // enough for one merge: a full one where there were more.
        let left = passes.runs;
        assert!(left.windows(2).all(|pair| pair[0].end == pair[1].start));
        assert_eq!(left.first().map_or(0, |run| run.start), 0);
        assert_eq!(left.last().map_or(0, |run| run.end), count as u64);
        assert_eq!(left.len(), count.min(most.max(FEWEST_RUNS)), "{} {}", count, most);
        sizes
    }

    /// A pass merges just enough runs for the merges after it to be full
    /// ones: a smaller merge first, then full ones. Runs that are few
    /// enough for one merge get no pass. Runs that are too many for a pass
    /// of full merges to leave few enough get another pass before it.
    #[test]
    fn passes() {
        assert_eq!(MOST_RUNS, 512);
        for few in [0, 1, 2, 511, 512] {
            assert!(merges(few, MOST_RUNS).is_empty(), "{}", few);
        }
        assert_eq!(merges(513, MOST_RUNS), [[2]]);
        assert_eq!(merges(600, MOST_RUNS), [[89]]);
        assert_eq!(merges(1023, MOST_RUNS), [[512]]);
        assert_eq!(merges(1024, MOST_RUNS), [[2, 512]]);
        let ten_thousand = merges(10_000, MOST_RUNS);
        assert_eq!(ten_thousand.len(), 1);
        assert_eq!((ten_thousand[0][0], &ten_thousand[0][1..]), (291, &[512; 18][..]));
        // As many runs as a pass of full merges takes, and one more.
        assert_eq!(merges(512 * 512, MOST_RUNS), [vec![512; 512]]);
        let another = merges(512 * 512 + 1, MOST_RUNS);
        assert_eq!(another, [vec![2], vec![512; 512]]);
        // Two runs at a time.
        assert_eq!(merges(11, 2), [vec![2; 3], vec![2; 4], vec![2; 2]]);
        assert_eq!(merges(3, 2), [[2]]);
        // A merge never takes fewer than two runs, whatever it is told.
        assert_eq!(merges(5, 0), merges(5, 2));
        for most in 2..=9 {
            for count in 0..=1000 {
                let sizes = merges(count, most);
                for (pass, sizes) in sizes.iter().enumerate() {
                    // Only the first merge of the first pass is smaller.
                    let full = sizes.iter().skip(usize::from(pass == 0));
                    assert!(full.clone().all(|&size| size == most), "{} {} {:?}", count, most, sizes);
                    assert!(
                        (FEWEST_RUNS..=most).contains(&sizes[0]),
                        "{} {} {:?}",
                        count,
                        most,
                        sizes
                    );
                }
                // A pass before the last one leaves a power of what a
                // merge takes: the next pass takes all of them.
                let mut runs = count;
                for (pass, sizes) in sizes.iter().enumerate() {
                    let merged: usize = sizes.iter().sum();
                    if pass > 0 {
                        assert_eq!(merged, runs, "{} {}", count, most);
                    }
                    runs -= merged - sizes.len();
                }
            }
        }
    }

    /// The passes are done a part at a time, with as much reading and
    /// writing as the budget of each step allows, and nothing is read or
    /// written without a budget. No merge takes more runs than it may, and
    /// each run is read through a buffer of the one size, however many
    /// runs there are. What a pass makes is appended to the scratch file.
    #[test]
    fn merges_in_steps() {
        /// How many bytes a record of this test takes in a run.
        const RECORD: u64 = (HEADER_SIZE + size_of::<u64>() + BODY) as u64;
        const BODY: usize = 40;
        let (_tmp, mut scratch) = scratch("sort-passes");
        let size = HEADER_SIZE + MAX_KEY;
        for (most, budget) in [(2, 1), (3, 100), (4, 10_000), (7, 1_000_000), (2, u64::MAX)] {
            let mut sorter = small(2000, most);
            let mut expected = Vec::new();
            for index in 0u64..2000 {
                // Few keys, so that many records have the same one.
                let key = (mix(index) % 500).to_be_bytes();
                sorter.push(&mut scratch, &key, &[index as u8; BODY]).unwrap();
                expected.push((key.to_vec(), vec![index as u8; BODY]));
            }
            expected.sort_by(|one, other| one.0.cmp(&other.0));
            let (runs, written) = (sorter.runs.len(), sorter.runs.last().unwrap().end);
            // More runs than a pass of full merges takes, also for the
            // widest merge: two passes at least.
            assert!(runs > 7 * 7, "{}", runs);
            let mut merge = sorter.finish();
            // Where the scratch file ends, with what a merge has written
            // of the run it makes.
            let end = |merge: &Merge| {
                let passes = merge.passes.as_ref()?;
                Some(passes.merge.as_ref().map_or(passes.end, |under_way| under_way.made.end))
            };
            // Without a budget the sort is not even wound up.
            assert!(!merge.prepare(0).unwrap());
            assert!(merge.sorter.is_some() && end(&merge).is_none());
            let (mut steps, mut last) = (0u64, written);
            while !merge.prepare(budget).unwrap() {
                steps += 1;
                assert!(!merge.prepare(0).unwrap());
                let Some(passes) = &merge.passes else {
                    continue;
                };
                // A step writes what its budget allows, and less than one
                // record more.
                let now = end(&merge).unwrap();
                assert!(
                    now >= last && now - last < budget.saturating_add(RECORD),
                    "{} {}",
                    budget,
                    now - last
                );
                last = now;
                if let Some(under_way) = &passes.merge {
                    let readers = &under_way.runs.readers;
                    assert!((FEWEST_RUNS..=most).contains(&readers.len()), "{}", readers.len());
                    assert!(readers.iter().all(|reader| reader.buffer.capacity() <= size));
                    assert!(under_way.made.start >= written);
                }
            }
            // The passes wrote every record once more for each pass that
            // took it, behind the runs of the sort, and left a full merge.
            assert!(merge.passes.is_none());
            assert_eq!(merge.last.readers.len(), most);
            let end = merge.last.readers.iter().map(|reader| reader.end).max().unwrap();
            assert!(end >= last && end >= 2 * written, "{} {} {}", written, last, end);
            // The smallest budget looks at one run or moves one record in
            // a step, and the largest does it all in one.
            match budget {
                1 => assert!(steps > (end - written) / RECORD, "{}", steps),
                u64::MAX => assert_eq!(steps, 0),
                _ => assert!(steps >= (end - written) / (budget + RECORD), "{} {}", budget, steps),
            }
            let (mut sorted, mut most_buffer) = (Vec::new(), 0);
            while let Some((key, body)) = merge.next().unwrap() {
                sorted.push((key.to_vec(), body.to_vec()));
                let buffers = merge.last.readers.iter().map(|reader| reader.buffer.capacity());
                most_buffer = most_buffer.max(buffers.max().unwrap());
            }
            assert_eq!(most_buffer, size);
            assert!(sorted == expected, "{}", most);
        }
    }

    /// Every run is merged through a buffer of the size the limits say,
    /// whether the runs are few or so many that passes merge them, and a
    /// merge never has more of them than it may. So the buffers of a merge
    /// together take no more than that many buffers.
    #[test]
    fn buffers_of_the_runs() {
        let (_tmp, mut scratch) = scratch("sort-buffers");
        for (memory, most, passes) in [(1024 * 1024, 16, false), (256 * 1024, 8, true), (16 * 1024, 4, true)] {
            let mut sorter = Sorter::with_limits(Limits {
                memory,
                run_buffer: RUN_BUFFER,
                write_buffer: WRITE_BUFFER,
                runs: most,
                hole: HOLE_SIZE,
            });
            for index in 0u64..3000 {
                sorter
                    .push(&mut scratch, &mix(index).to_be_bytes(), &[0; 1000])
                    .unwrap();
            }
            let runs = sorter.runs.len();
            assert_eq!(runs > most, passes, "{} {}", memory, runs);
            let mut merge = sorter.finish();
            // How many bytes the buffers of a merge take together. None is
            // larger than a buffer may be, and a run that is shorter than
            // that has a smaller one.
            let buffers = |readers: &[RunReader]| {
                assert!(readers.len() <= most, "{} {}", memory, readers.len());
                let sizes = readers.iter().map(|reader| reader.buffer.capacity());
                assert!(sizes.clone().all(|size| size <= RUN_BUFFER), "{}", memory);
                sizes.sum::<usize>()
            };
            let mut largest = 0;
            while !merge.prepare(100_000).unwrap() {
                let under_way = merge.passes.as_ref().and_then(|passes| passes.merge.as_ref());
                largest = largest.max(under_way.map_or(0, |under_way| buffers(&under_way.runs.readers)));
                // The last merge has no run before the passes are over.
                assert!(merge.passes.is_none() || merge.last.readers.is_empty());
            }
            assert_eq!(largest > 0, passes);
            assert_eq!(merge.last.readers.len(), runs.min(most));
            let (mut last, mut count) = (Vec::new(), 0);
            while let Some((key, _)) = merge.next().unwrap() {
                assert!(last.as_slice() < key);
                (last, count) = (key.to_vec(), count + 1);
                largest = largest.max(buffers(&merge.last.readers));
            }
            assert_eq!(count, 3000);
            assert_eq!(largest, runs.min(most) * RUN_BUFFER, "{}", memory);
        }
    }

    /// A run that cannot be written fails the step and loses nothing: the
    /// records of the write that failed are written when the run is
    /// written on, and all of them go out in the end. Here every part of a
    /// run fails once, with the run moved to where no file reaches.
    #[test]
    fn failed_writes_of_a_run() {
        /// An offset no file has.
        const NOWHERE: u64 = i64::MAX as u64;
        let (_tmp, mut scratch) = scratch("sort-failed-write");
        let mut sorter = small(4000, MOST_RUNS);
        let (mut expected, mut failed) = (Vec::new(), 0);
        for index in 0u64..1500 {
            loop {
                let moved = sorter.spill.as_mut().map(|spill| mem::replace(&mut spill.at, NOWHERE));
                if let Some(at) = moved {
                    assert!(sorter.make_room(&mut scratch, 100).is_err());
                    sorter.spill.as_mut().unwrap().at = at;
                    failed += 1;
                }
                if sorter.make_room(&mut scratch, 100).unwrap() {
                    break;
                }
            }
            let key = (mix(index) % 400).to_be_bytes();
            sorter.push(&mut scratch, &key, &index.to_le_bytes()).unwrap();
            expected.push((key.to_vec(), index.to_le_bytes().to_vec()));
        }
        assert!(
            failed > 100 && sorter.runs.len() > 3,
            "{} {}",
            failed,
            sorter.runs.len()
        );
        expected.sort_by(|one, other| one.0.cmp(&other.0));
        assert!(drain(sorter.finish()) == expected);
    }

    /// A merge keeps the sort where the rest of a run that was half
    /// written cannot be written, and the scratch file of the runs with
    /// it: the file stays open as it is, and the merge fails from there
    /// on. A merge that is given up gives the file back from there, which
    /// empties it, and so does one that is wound up, which has the file
    /// itself.
    #[test]
    fn failed_wind_ups() {
        /// An offset no file has.
        const NOWHERE: u64 = i64::MAX as u64;
        let (tmp, mut scratch) = scratch("sort-failed-wind-up");
        let mut sorter = small(2000, MOST_RUNS);
        // Until a run is begun, of which this budget writes one record.
        while sorter.make_room(&mut scratch, 1).unwrap() {
            sorter.push(&mut scratch, b"key", b"").unwrap();
        }
        sorter.spill.as_mut().unwrap().at = NOWHERE;
        let mut merge = sorter.finish();
        assert!(merge.prepare(u64::MAX).is_err());
        assert!(merge.sorter.as_ref().is_some_and(|sorter| sorter.file.is_some()));
        assert!(merge.prepare(u64::MAX).is_err());
        let files = OpenFile::made_in(&tmp.0);
        assert!(files.len() == 1 && files[0].size > 0, "{:?}", files);
        merge.give_back(&mut scratch);
        let files = OpenFile::made_in(&tmp.0);
        assert!(files.len() == 1 && files[0].size == 0, "{:?}", files);
        // The next sort takes the file that was given back, and its merge
        // has it once it is wound up.
        let mut sorter = small(2000, MOST_RUNS);
        while sorter.runs.is_empty() {
            sorter.push(&mut scratch, b"key", b"").unwrap();
        }
        let mut merge = sorter.finish();
        assert!(merge.prepare(u64::MAX).unwrap() && merge.file.is_some());
        assert!(OpenFile::made_in(&tmp.0).iter().all(|file| file.size > 0));
        merge.give_back(&mut scratch);
        let files = OpenFile::made_in(&tmp.0);
        assert!(files.len() == 1 && files[0].size == 0, "{:?}", files);
    }

    /// A run is written a part at a time, with as much writing as the
    /// budget of each step allows, and nothing is written without a
    /// budget. A record is taken whatever is left to write before.
    #[test]
    fn writes_runs_in_steps() {
        let (_tmp, mut scratch) = scratch("sort-steps");
        for budget in [1, 100, 10_000] {
            let mut sorter = small(20_000, MOST_RUNS);
            let mut expected = Vec::new();
            let (mut steps, mut most) = (0, 0);
            for index in 0u64..2000 {
                let mut now = 0;
                while !sorter.make_room(&mut scratch, budget).unwrap() {
                    assert!(!sorter.make_room(&mut scratch, 0).unwrap());
                    now += 1;
                }
                (steps, most) = (steps + now, most.max(now));
                let key = mix(index).to_be_bytes();
                sorter.push(&mut scratch, &key, &[index as u8; 40]).unwrap();
                expected.push((key.to_vec(), vec![index as u8; 40]));
            }
            // A run of about 20000 bytes takes a step for every record
            // with the smallest budget, and two steps with the largest.
            assert!(most >= 20_000 / budget.max(64) / 2, "{} {}", budget, most);
            assert!(steps >= most * 3, "{} {} {}", budget, steps, most);
            expected.sort();
            assert!(drain(sorter.finish()) == expected);
        }
        // Without a budget a run is not begun either: nothing is sorted,
        // and no scratch file is made.
        let mut sorter = small(2000, MOST_RUNS);
        while !sorter.is_full() {
            sorter.push(&mut scratch, b"key", b"").unwrap();
        }
        assert!(!sorter.make_room(&mut scratch, 0).unwrap());
        assert!(sorter.spill.is_none() && sorter.file.is_none());
        assert!(!sorter.make_room(&mut scratch, 1).unwrap());
        assert!(sorter.spill.is_some() && sorter.file.is_some());
        let mut sorter = small(2000, MOST_RUNS);
        for index in 0u64..2000 {
            let _ = sorter.make_room(&mut scratch, 1).unwrap();
            sorter.push(&mut scratch, &mix(index).to_be_bytes(), b"").unwrap();
        }
        // The sort ends with a run half written. Ending it does nothing:
        // the merge writes the run to its end, a part in each step, and
        // sorts what is in memory once it is written, and nothing without
        // a budget.
        while sorter.make_room(&mut scratch, 1).unwrap() {
            sorter.push(&mut scratch, b"more", b"").unwrap();
        }
        assert!(sorter.spill.is_some());
        let written = |merge: &Merge| {
            let spill = merge.sorter.as_ref()?.spill.as_ref()?;
            Some(spill.written)
        };
        let mut merge = sorter.finish();
        let (begun, mut steps) = (written(&merge).unwrap(), 0);
        assert!(!merge.prepare(0).unwrap());
        assert_eq!(written(&merge), Some(begun));
        while let Some(before) = written(&merge) {
            let _ = merge.prepare(1).unwrap();
            assert!(written(&merge).is_none_or(|now| now == before + 1));
            steps += 1;
        }
        assert!(steps > 1, "{}", steps);
        // The step that wrote the last of the run has no budget left, and
        // the next one that has winds the sort up.
        assert!(merge.sorter.is_some() && merge.passes.is_none());
        assert!(!merge.prepare(0).unwrap());
        assert!(merge.sorter.is_some());
        let _ = merge.prepare(1).unwrap();
        assert!(merge.sorter.is_none());
        let sorted = drain(merge);
        assert!(sorted.len() > 2000 && sorted.is_sorted());
    }

    /// Checks the blocks of `block` bytes of the scratch file `file` that
    /// are all in the run `run`: those in front of `released` are holes,
    /// and the others are not. A block that a run shares with the run next
    /// to it is none of its own.
    fn check_blocks(file: &ScratchFile, block: u64, run: Run, released: u64) {
        let whole = run.start.next_multiple_of(block)..run.end - run.end % block;
        let mut data = vec![0; usize::try_from(block).unwrap()];
        for start in whole.step_by(data.len()) {
            file.read_exact_at(&mut data, start).unwrap();
            let hole = data.iter().all(|&byte| byte == 0);
            assert_eq!(
                hole,
                start < released,
                "{:?} at {}, given back up to {}",
                run,
                start,
                released
            );
        }
    }

    /// Checks what the reader `reader` of the run `run` gave back of it in
    /// the scratch file `file`, whose blocks are `block` bytes, where a hole
    /// is to have `hole` bytes, 1 or more than any run: with `punched`
    /// every whole block it has read once that makes a hole or the run
    /// ended, and without it nothing. Returns whether the reader has read
    /// enough for a hole to be tried, punched or not.
    fn check_reader(file: &ScratchFile, block: u64, run: Run, reader: &RunReader, punched: bool, hole: u64) -> bool {
        assert_eq!(reader.end, run.end);
        let read = reader.at - reader.at % block;
        let start = run.start.next_multiple_of(block);
        let ended = reader.at == reader.end;
        let tried = read > start && (read - start >= hole || ended);
        let released = if punched && tried { read } else { run.start };
        assert_eq!(reader.released, released, "{:?} read up to {}", run, reader.at);
        check_blocks(file, block, run, released);
        tried
    }

    /// Sorts records in the directory `dir` whose runs take several blocks
    /// of the scratch file each: ten runs, of which a pass merges four and
    /// four, and a last merge of what they made and of the two runs that
    /// are left. It checks the scratch file all along. With `punched` the
    /// file system can punch holes, and what a merge has read of a run is
    /// a hole up to the last whole block, while the rest of the run is
    /// there. Without it the first hole that cannot be punched is the last
    /// one tried, every run stays as it was written, and the records go out
    /// all the same. A hole is to have `hole` bytes: 1, which gives back
    /// every block as soon as it was read, or more than any run, which gives
    /// back a run only once it ended.
    fn merge_with_holes(dir: &Path, punched: bool, hole: u64) {
        const COUNT: usize = 10;
        const MOST: usize = 4;
        let mut scratch = scratch_in(dir);
        let probe = scratch.file().unwrap();
        let block = probe.block_size().unwrap();
        scratch.take_back(probe);
        // A record takes a quarter of a block and a run six blocks and a
        // bit, so that the runs start and end anywhere in a block.
        let body = usize::try_from(block / 4).unwrap();
        if body > MAX_BODY {
            eprintln!("skipping: blocks of {} bytes are too large for a record", block);
            return;
        }
        let mut sorter = Sorter::with_limits(Limits {
            memory: 6 * usize::try_from(block).unwrap(),
            run_buffer: 1,
            write_buffer: 1,
            runs: MOST,
            hole,
        });
        // No record has a block of zeroes. A few records stay in memory.
        let mut count = 0u64;
        while sorter.runs.len() < COUNT || sorter.starts.len() < MOST {
            sorter
                .push(&mut scratch, &mix(count).to_be_bytes(), &vec![count as u8 | 1; body])
                .unwrap();
            count += 1;
        }
        let mut runs = sorter.runs.clone();
        assert_eq!(runs.len(), COUNT);
        let written = runs[COUNT - 1].end;
        let run_of = |runs: &[Run], reader: &RunReader| *runs.iter().find(|run| run.end == reader.end).unwrap();
        let mut merge = sorter.finish();
        // The size of a block is known once the sort is wound up, until a
        // hole fails. Without holes, the first one that fails is the last
        // one tried, so once a reader has read enough for one the scratch
        // file has no block size any more.
        let mut tried = false;
        while !merge.prepare(block).unwrap() {
            let file = merge.file.as_ref().unwrap();
            let under_way = merge.passes.as_ref().and_then(|passes| passes.merge.as_ref());
            for reader in under_way.iter().flat_map(|under_way| &under_way.runs.readers) {
                tried |= check_reader(&file.scratch, block, run_of(&runs, reader), reader, punched, hole);
            }
            assert_eq!(file.block.map(NonZeroU64::get), (punched || !tried).then_some(block));
        }
        assert!(tried);
        // The pass read the first eight runs to their ends, and the last
        // merge looked at the two runs the pass made and at the two it
        // left.
        let file = merge.file.as_ref().unwrap();
        assert_eq!(file.block.is_some(), punched);
        let last = &merge.last.readers;
        assert_eq!(last.len(), MOST);
        runs.push(Run {
            start: written,
            end: last[0].end,
        });
        runs.push(Run {
            start: last[0].end,
            end: last[1].end,
        });
        assert!(written < last[0].end && last[0].end < last[1].end);
        for run in &runs[..COUNT - 2] {
            check_blocks(&file.scratch, block, *run, if punched { run.end } else { run.start });
        }
        for reader in last {
            check_reader(&file.scratch, block, run_of(&runs, reader), reader, punched, hole);
        }
        let mut last_key = Vec::new();
        let mut merged = 0;
        while let Some((key, record)) = merge.next().unwrap() {
            assert!(last_key.as_slice() < key && record.len() == body);
            last_key = key.to_vec();
            merged += 1;
        }
        assert_eq!(merged, count);
        // Every run was read to its end now, also those the pass made.
        let file = merge.file.as_ref().unwrap();
        assert_eq!(file.block.is_some(), punched);
        for run in &runs {
            check_blocks(&file.scratch, block, *run, if punched { run.end } else { run.start });
        }
    }

    /// What a merge has read of a run it gives back to the file system as
    /// it goes: the blocks it has read are holes in the scratch file, in
    /// a pass and in the last merge, and the blocks it has not read are
    /// there. Where a hole is to have more bytes than a run has, a run is
    /// given back once it ended. Where the temporary directory cannot punch
    /// holes, the same is tried without them.
    #[test]
    fn gives_room_back() {
        let tmp = TempDir::new("sort-holes");
        let probe = scratch_in(&tmp.0).file().unwrap();
        let block = probe.block_size().unwrap();
        probe.write_all_at(&[1], block).unwrap();
        let punched = probe.punch_hole(0, block).is_ok();
        if !punched {
            eprintln!("skipping the holes: the temporary directory cannot punch them");
        }
        for hole in [1, u64::MAX] {
            merge_with_holes(&tmp.0, punched, hole);
        }
    }

    /// The variable that names a directory of a file system that cannot
    /// punch holes, in which the test binary runs
    /// [`keeps_room_without_holes`] again.
    const NO_HOLES_DIR: &str = "UAPI16_TEST_SORT_NO_HOLES_DIR";

    /// A scratch file that no hole can be punched into keeps its room, and
    /// the sort goes on as it does with holes: the first hole that fails is
    /// the last one it tries. The test binary runs this test again with its
    /// directory on a ramfs, which cannot punch holes, and it is skipped
    /// where that cannot be mounted.
    #[test]
    fn keeps_room_without_holes() {
        let Some(dir) = env::var_os(NO_HOLES_DIR) else {
            let tmp = TempDir::new("sort-no-holes");
            tmp.rerun_on("ramfs", None, "sort::tests::keeps_room_without_holes", NO_HOLES_DIR);
            return;
        };
        for hole in [1, u64::MAX] {
            merge_with_holes(Path::new(&dir), false, hole);
        }
    }

    /// The variable that names the directory in which the test binary runs
    /// [`gives_back_the_room_past_the_end`] again.
    const PAST_THE_END_DIR: &str = "UAPI16_TEST_SORT_PAST_THE_END_DIR";

    /// Once the passes are over nothing is written to the scratch file any
    /// more, and the room the file system took past its end for what it
    /// expected to be written there is given back before the last merge
    /// begins. The test takes such room itself, 4 MiB with fallocate() and
    /// FALLOC_FL_KEEP_SIZE, far past what the runs and the passes take, and
    /// takes it again once the last merge begins, which takes room again
    /// only where it was given back. It runs again in a process of its own,
    /// in which the scratch file is the one file without a name, and it is
    /// skipped where the file system can't take room past the end of a
    /// file, can't punch holes, or leaves a hole past the end of a file
    /// alone, as ext4 does.
    #[test]
    fn gives_back_the_room_past_the_end() {
        let Some(dir) = env::var_os(PAST_THE_END_DIR) else {
            let tmp = TempDir::new("sort-past-the-end");
            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "sort::tests::gives_back_the_room_past_the_end",
                    "--nocapture",
                ])
                .env(PAST_THE_END_DIR, &tmp.0)
                .output()
                .unwrap();
            // A test binary that runs no test succeeds as well.
            let ran = String::from_utf8_lossy(&output.stdout).contains("1 passed");
            assert!(output.status.success() && ran, "{:?}", output);
            for line in String::from_utf8_lossy(&output.stderr).lines() {
                if line.starts_with("skipping") {
                    eprintln!("{}", line);
                }
            }
            return;
        };
        const TAKEN: u64 = 4 * 1024 * 1024;
        let dir = Path::new(&dir);
        let mut scratch = scratch_in(dir);
        // A file of a scratch space of its own, which is closed once it is
        // dropped: one of the scratch space of the sort would stay open.
        let probe = scratch_in(dir).file().unwrap();
        let block = probe.block_size().unwrap();
        probe.write_all_at(&[1], block).unwrap();
        if probe.punch_hole(0, block).is_err() {
            eprintln!("skipping: the temporary directory cannot punch holes");
            return;
        }
        // The one file without a name this process has in the directory,
        // opened again through procfs.
        let device = fs::metadata(dir).unwrap().dev();
        let unnamed = || {
            let unnamed: Vec<_> = fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(|entry| {
                    let path = entry.unwrap().path();
                    let file = fs::metadata(&path).ok()?;
                    (file.is_file() && file.nlink() == 0 && file.dev() == device).then_some(path)
                })
                .collect();
            assert_eq!(unnamed.len(), 1, "{:?}", unnamed);
            fs::OpenOptions::new().write(true).open(&unnamed[0]).unwrap()
        };
        let take = |file: &fs::File, past: u64| {
            rustix::fs::fallocate(file, rustix::fs::FallocateFlags::KEEP_SIZE, past, TAKEN)
        };
        // Not every file system gives the room a file has past its end back
        // to a hole there: ext4 leaves a hole past the end of a file alone.
        let past = (16 * TAKEN).next_multiple_of(block);
        if let Err(e) = take(&unnamed(), past) {
            eprintln!(
                "skipping: the temporary directory takes no room past the end of a file: {}",
                e
            );
            return;
        }
        let taken = room(dir);
        probe.punch_hole(past, TAKEN).unwrap();
        if room(dir) + TAKEN > taken {
            eprintln!("skipping: the temporary directory gives no room past the end of a file back");
            return;
        }
        drop(probe);
        // Four runs to a merge, of which there are ten: a pass before the
        // last merge.
        let mut sorter = small(24 * 1024, 4);
        let mut count = 0u64;
        while sorter.runs.len() < 10 {
            sorter
                .push(&mut scratch, &mix(count).to_be_bytes(), &[0x5a; 100])
                .unwrap();
            count += 1;
        }
        let written = sorter.runs.last().unwrap().end;
        let mut merge = sorter.finish();
        let file = unnamed();
        let past = (16 * (written + TAKEN)).next_multiple_of(block);
        let before = room(dir);
        take(&file, past).unwrap();
        let taken = room(dir);
        assert!(taken >= before + TAKEN, "{} bytes of room, {} before", taken, before);
        while !merge.prepare(u64::MAX).unwrap() {}
        let left = room(dir);
        take(&file, past).unwrap();
        let again = room(dir);
        assert!(
            again >= left + TAKEN,
            "{} bytes of room taken again, {} before",
            again,
            left
        );
        assert_eq!(drain(merge).len() as u64, count);
    }

    /// A pass that failed fails every step after it, whatever the budget,
    /// without reading anything again, and so does the merge.
    #[test]
    fn failed_passes() {
        let (_tmp, mut scratch) = scratch("sort-failed-pass");
        let mut sorter = small(1000, 3);
        for index in 0u64..500 {
            sorter.push(&mut scratch, &mix(index).to_be_bytes(), &[7; 50]).unwrap();
        }
        assert!(sorter.runs.len() > 3);
        let len = sorter.runs.last().unwrap().end;
        let lengths = vec![0xff; usize::try_from(len).unwrap()];
        sorter.file.as_ref().unwrap().write_all_at(&lengths, 0).unwrap();
        let mut merge = sorter.finish();
        let e = loop {
            match merge.prepare(64) {
                Ok(done) => assert!(!done),
                Err(e) => break e,
            }
        };
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        for budget in [u64::MAX, 0, 64] {
            let e = merge.prepare(budget).unwrap_err();
            assert_eq!(
                (e.kind(), e.to_string()),
                (io::ErrorKind::Other, "the sort failed before".to_string())
            );
        }
        assert_eq!(merge.next().unwrap_err().kind(), io::ErrorKind::Other);
    }

    /// A scratch file that does not hold what was written to it is an
    /// error, whatever it holds instead, and never more than that: in the
    /// last merge and in a pass before it.
    #[test]
    fn changed_scratch_files() {
        type Damage = fn(&ScratchFile, u64);
        let damages: [(&str, Damage); 4] = [
            ("lengths", |file, len| {
                file.write_all_at(&vec![0xff; len as usize], 0).unwrap()
            }),
            ("zeroes", |file, len| {
                file.write_all_at(&vec![0; len as usize], 0).unwrap()
            }),
            ("a shorter file", |file, len| file.set_len(len / 2).unwrap()),
            ("an empty file", |file, _| file.set_len(0).unwrap()),
        ];
        for (what, damage) in damages {
            for most in [MOST_RUNS, 3] {
                let (_tmp, mut scratch) = scratch("sort-damage");
                let mut sorter = small(1000, most);
                for index in 0u64..500 {
                    sorter.push(&mut scratch, &mix(index).to_be_bytes(), &[7; 50]).unwrap();
                }
                let len = sorter.runs.last().unwrap().end;
                let passes = sorter.runs.len() > most;
                assert_eq!(passes, most == 3);
                damage(sorter.file.as_ref().unwrap(), len);
                let mut merge = sorter.finish();
                let mut read = 0;
                let failed = loop {
                    match merge.next() {
                        Ok(Some(_)) => read += 1,
                        Ok(None) => break false,
                        Err(_) => break true,
                    }
                    // No record takes less than its header.
                    assert!(read <= len, "{}", what);
                };
                // Zeroes are records without keys and bodies, which fail
                // only where a run does not end with one. A file that a
                // pass appends to has zeroes where it was cut off.
                let zeroes = what == "zeroes" || passes && what.ends_with("file");
                assert!(failed || zeroes, "{} after {} records", what, read);
                // A merge that failed does not go on with what it has.
                for _ in 0..3 {
                    match merge.next() {
                        Err(e) => assert_eq!((failed, e.kind()), (true, io::ErrorKind::Other), "{}", what),
                        Ok(next) => assert!(!failed && next.is_none(), "{}", what),
                    }
                    match merge.prepare(u64::MAX) {
                        Err(e) => assert_eq!((failed, e.kind()), (true, io::ErrorKind::Other), "{}", what),
                        Ok(prepared) => assert!(!failed && prepared, "{}", what),
                    }
                }
            }
        }
    }

    /// The variables that tell the test binary, run again by [`measured`],
    /// how many records to sort, how many bytes of them to keep in memory
    /// and how many runs to merge at once.
    const RECORDS: &str = "UAPI16_TEST_SORT_RECORDS";
    const MEMORY: &str = "UAPI16_TEST_SORT_MEMORY";
    const RUNS: &str = "UAPI16_TEST_SORT_RUNS";
    /// What the line starts with that says what was measured, which the
    /// harness does not say of a test of this module, such as one that has
    /// been running for over 60 seconds.
    const MEASURED: &str = "sorted:";
    /// How many bytes of the runs a step of the measured sort reads before
    /// its first record.
    const STEP: u64 = 4 * 1024 * 1024;

    /// The resident memory of this process that is its own, in bytes, which
    /// the kernel reports in kilobytes: RssAnon, without the pages of the
    /// files it has mapped. Those of the test binary come and go with the
    /// file system it is on, and are none of the sort's. A kernel before
    /// Linux 4.5 does not tell the two apart, and all that is resident is
    /// taken there.
    fn resident() -> u64 {
        let status = fs::read_to_string("/proc/self/status").unwrap();
        let field = |name: &str| status.lines().find_map(|line| line.strip_prefix(name));
        let line = field("RssAnon:").or_else(|| field("VmRSS:")).unwrap();
        let kilobytes: u64 = line.trim().trim_end_matches("kB").trim().parse().unwrap();
        kilobytes * 1024
    }

    /// How many bytes of room the files without a name take that this
    /// process has open in the file system of the directory `dir`: its
    /// scratch files there.
    fn room(dir: &Path) -> u64 {
        let device = fs::metadata(dir).unwrap().dev();
        let open = fs::read_dir("/proc/self/fd").unwrap();
        // The descriptor of the listing itself is gone by the time it is
        // looked at.
        let files = open.filter_map(|entry| fs::metadata(entry.unwrap().path()).ok());
        files
            .filter(|file| file.is_file() && file.nlink() == 0 && file.dev() == device)
            .map(|file| file.blocks() * ST_BLOCKS_UNIT)
            .sum()
    }

    /// How many bytes of data the files without a name hold that this
    /// process has open in the file system of the directory `dir`, as
    /// SEEK_DATA and SEEK_HOLE find them: what of its scratch files there
    /// is not a hole. Unlike their room it leaves out what the file system
    /// took for them past their ends.
    fn data(dir: &Path) -> u64 {
        let device = fs::metadata(dir).unwrap().dev();
        let open = fs::read_dir("/proc/self/fd").unwrap();
        // The descriptor of the listing itself is gone by the time it is
        // looked at.
        let files = open.filter_map(|entry| {
            let path = entry.unwrap().path();
            let file = fs::metadata(&path).ok()?;
            let scratch = file.is_file() && file.nlink() == 0 && file.dev() == device;
            scratch.then(|| fs::File::open(&path).ok()).flatten()
        });
        let mut total = 0;
        for file in files {
            let mut at = 0;
            while let Ok(start) = rustix::fs::seek(&file, SeekFrom::Data(at)) {
                let end = rustix::fs::seek(&file, SeekFrom::Hole(start)).unwrap();
                total += end - start;
                at = end;
            }
        }
        total
    }

    /// Sorts `count` records with a key of 25 bytes and a body of 140
    /// bytes, which come in an order that is as good as random, with
    /// `memory` bytes of them in memory and `most` runs in a merge. Checks
    /// that they go out in order and that the memory of the process stays
    /// within what the records in memory and the buffers of a merge take,
    /// however many runs and passes that comes to. Where the scratch file
    /// takes holes, its data stays within that of the records and what the
    /// merges did not give back yet.
    fn sort_records(count: u64, memory: usize, most: usize) {
        let (tmp, mut scratch) = scratch("sort-measure");
        let before = resident();
        let mut sorter = Sorter::with_limits(Limits {
            memory,
            run_buffer: RUN_BUFFER,
            write_buffer: WRITE_BUFFER,
            runs: most,
            hole: HOLE_SIZE,
        });
        let started = Instant::now();
        let (mut most_resident, mut most_room, mut most_data) = (0, 0, 0);
        let mut key = Vec::new();
        for index in 0..count {
            let random = mix(index);
            key.clear();
            key.extend_from_slice(format!("usr\0share\0p{:05}\0f{:07}", random % 50_000, random >> 40).as_bytes());
            sorter.push(&mut scratch, &key, &[0x5a; 140]).unwrap();
            if index % 4096 == 0 {
                most_resident = most_resident.max(resident());
            }
        }
        let pushed = started.elapsed();
        let runs = sorter.runs.len();
        let written = sorter.runs.last().map_or(0, |run| run.end);
        most_room = most_room.max(room(&tmp.0));
        most_data = most_data.max(data(&tmp.0));
        let mut merge = sorter.finish();
        // The passes, a step at a time. What is measured between the steps
        // takes time of its own, which is not that of the passes: data()
        // seeks through every hole of the scratch file.
        let (mut passed, mut again) = (pushed, written);
        let (mut measuring_passes, mut measuring_merge) = (Duration::ZERO, Duration::ZERO);
        while !merge.prepare(STEP).unwrap() {
            let measuring = Instant::now();
            most_resident = most_resident.max(resident());
            most_room = most_room.max(room(&tmp.0));
            most_data = most_data.max(data(&tmp.0));
            if let Some(passes) = &merge.passes {
                again = passes.merge.as_ref().map_or(passes.end, |under_way| under_way.made.end);
                measuring_passes += measuring.elapsed();
                passed = started.elapsed();
            }
        }
        let last_merge = room(&tmp.0);
        let mut last = Vec::new();
        let mut merged = 0u64;
        while let Some((key, body)) = merge.next().unwrap() {
            assert!(last.as_slice() <= key && body.len() == 140);
            last.clear();
            last.extend_from_slice(key);
            merged += 1;
            if merged % 4096 == 0 {
                most_resident = most_resident.max(resident());
            }
            if merged % (1 << 20) == 0 {
                let measuring = Instant::now();
                most_room = most_room.max(room(&tmp.0));
                most_data = most_data.max(data(&tmp.0));
                measuring_merge += measuring.elapsed();
            }
        }
        assert_eq!(merged, count);
        let holes = merge.file.as_ref().is_some_and(|file| file.block.is_some());
        println!(
            "{} {} records, {} runs of which a merge takes {}, {} MiB written and {} MiB again in passes, \
             {:.2} s to take them, {:.2} s for the passes and {:.2} s to merge, \
             resident {} KiB before and {} KiB at most, scratch file with {} MiB of data at most, \
             in {} MiB of room at most, {} MiB as the last merge began and {} MiB at the end, {}",
            MEASURED,
            count,
            runs,
            most,
            written >> 20,
            (again - written) >> 20,
            pushed.as_secs_f64(),
            (passed - pushed - measuring_passes).as_secs_f64(),
            (started.elapsed() - passed - measuring_merge).as_secs_f64(),
            before / 1024,
            most_resident / 1024,
            most_data >> 20,
            most_room >> 20,
            last_merge >> 20,
            room(&tmp.0) >> 20,
            if holes { "with holes" } else { "without holes" },
        );
        // The data of the records, and what the readers of a merge did not
        // give back yet: what each read since its last hole, and a block at
        // either end of every run, of which a pass makes fewer than it
        // reads.
        if holes {
            let block = merge
                .file
                .as_ref()
                .and_then(|file| file.block)
                .map_or(0, NonZeroU64::get);
            let held = runs.min(most) as u64 * (HOLE_SIZE + 2 * block) + 4 * runs as u64 * block;
            assert!(
                most_data <= written + held,
                "{} bytes of data for {} of records",
                most_data,
                written
            );
        }
        // The records in memory with where they start, a buffer and a key
        // for each run of a merge, what a pass writes at a time, and room
        // for what an allocator keeps around.
        let buffers = runs.min(most) * (RUN_BUFFER + MAX_KEY);
        let allowed = (memory + FIRST_MEMORY + buffers + WRITE_BUFFER) as u64;
        const SLACK: u64 = 8 * 1024 * 1024;
        assert!(
            most_resident <= before + allowed + SLACK,
            "{} -> {}",
            before,
            most_resident
        );
    }

    /// The number the variable `variable` says, if it is set.
    fn number<T: FromStr<Err: fmt::Debug>>(variable: &str) -> Option<T> {
        env::var(variable).ok().map(|value| value.parse().unwrap())
    }

    /// Runs the test binary again to sort `count` records in a process
    /// that does nothing else, so that its memory is that of the sort. It
    /// keeps `memory` bytes of records in memory and merges `most` runs at
    /// once.
    fn measured(count: u64, memory: usize, most: usize) {
        let output = Command::new(env::current_exe().unwrap())
            .args(["--exact", "sort::tests::memory_is_bounded", "--nocapture"])
            .env(RECORDS, count.to_string())
            .env(MEMORY, memory.to_string())
            .env(RUNS, most.to_string())
            .output()
            .unwrap();
        let said = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "{}\n{}",
            said,
            String::from_utf8_lossy(&output.stderr)
        );
        // The harness can have its own words in front on the same line.
        if let Some(measured) = said.lines().find_map(|line| line.find(MEASURED).map(|at| &line[at..])) {
            println!("{}", measured);
        }
    }

    /// The memory of a sort is that of the records it holds and of a
    /// buffer for each run of a merge, however many records it sorts.
    #[test]
    fn memory_is_bounded() {
        match number(RECORDS) {
            Some(count) => sort_records(
                count,
                number(MEMORY).unwrap_or(MEMORY_LIMIT),
                number(RUNS).unwrap_or(MOST_RUNS),
            ),
            None => measured(250_000, MEMORY_LIMIT, MOST_RUNS),
        }
    }

    /// The same where the runs are so many that three passes merge them
    /// before the last merge: a quarter of a megabyte of records in
    /// memory, and four runs in a merge.
    #[test]
    fn memory_is_bounded_through_passes() {
        measured(250_000, 256 * 1024, 4);
    }

    /// The same for a million records.
    #[test]
    #[ignore = "sorts a million records"]
    fn memory_is_bounded_for_a_million_records() {
        measured(1_000_000, MEMORY_LIMIT, MOST_RUNS);
    }

    /// The same for ten million records, with a scratch file of
    /// gigabytes.
    #[test]
    #[ignore = "sorts ten million records"]
    fn memory_is_bounded_for_ten_million_records() {
        measured(10_000_000, MEMORY_LIMIT, MOST_RUNS);
    }

    /// The same for ten million records in runs of a megabyte, eight of
    /// which a merge takes: three passes before the last merge.
    #[test]
    #[ignore = "sorts ten million records in three passes"]
    fn memory_is_bounded_for_ten_million_records_through_passes() {
        measured(10_000_000, 1024 * 1024, 8);
    }

    /// The same for a hundred and twenty million records, which are more
    /// runs than a merge takes at once: a pass before the last merge, and
    /// a scratch file of twenty gigabytes.
    #[test]
    #[ignore = "sorts a hundred and twenty million records"]
    fn memory_is_bounded_for_more_runs_than_a_merge_takes() {
        measured(120_000_000, MEMORY_LIMIT, MOST_RUNS);
    }

    /// A sort and a merge can go to another thread.
    #[test]
    fn send() {
        fn send<T: Send>() {}
        send::<Sorter>();
        send::<Merge>();
    }
}
