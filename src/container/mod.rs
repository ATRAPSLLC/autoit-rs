//! Container discovery helpers.
//!
//! These submodules locate an AutoIt payload inside its host container before
//! decoding begins. [`pe`] walks a PE file's resource directory to find the
//! embedded `RT_RCDATA/SCRIPT` resource, while [`raw`] scans arbitrary bytes for
//! the AutoIt signature and version markers (EA04/EA05/EA06/JB01).

pub mod pe;
pub mod raw;
