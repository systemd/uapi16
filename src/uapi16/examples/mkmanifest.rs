// SPDX-License-Identifier: LGPL-2.1-or-later
//! Writes the manifest of a directory and everything below it to a new
//! file, and says what it lists:
//!
//!     cargo run --example mkmanifest -- DIRECTORY OUTPUT

use std::fs::File;
use std::path::Path;
use std::process::ExitCode;

use uapi16::{AddFlags, Error, Features, ManifestOptions, ManifestReport};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    let [tree, output] = &args[..] else {
        eprintln!("usage: mkmanifest DIRECTORY OUTPUT");
        return ExitCode::FAILURE;
    };
    match mkmanifest(Path::new(tree), Path::new(output)) {
        Ok(report) => {
            println!(
                "{} files, {} directories, {} other files, {} bytes",
                report.files(),
                report.directories(),
                report.others(),
                report.bytes()
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("mkmanifest: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Writes the manifest of the directory `tree` to the new file `output`,
/// with the default features and the modification times.
fn mkmanifest(tree: &Path, output: &Path) -> Result<ManifestReport, Error> {
    // The new file is a name in a directory: the one `output` is in, or
    // the current one.
    let dir = match output.parent() {
        Some(dir) if !dir.as_os_str().is_empty() => dir,
        _ => Path::new("."),
    };
    let name = Path::new(output.file_name().unwrap_or_default());
    ManifestOptions::new()
        .features(Features::DEFAULT | Features::MTIME)
        .generate_at(File::open(dir)?, name, File::open(tree)?, AddFlags::NONE)
}
