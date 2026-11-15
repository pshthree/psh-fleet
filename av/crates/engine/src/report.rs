use serde::Serialize;

use crate::filetype::FileType;

/// Outcome for an object or a whole scan. Ordered so the worst verdict wins.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

/// Which detection layer produced a detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    Blocklist,
    Yara,
}

#[derive(Debug, Clone, Serialize)]
pub struct Detection {
    pub layer: Layer,
    pub name: String,
    pub verdict: Verdict,
    /// SHA-256 of the object that matched, which may be a container child.
    pub sha256: String,
    /// Path inside the scanned file, parts joined with `!`. Empty for the file itself.
    pub object: String,
    pub file_type: FileType,
}

/// Why part of a scan was skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    FileTooLarge,
    DepthLimit,
    EntryLimit,
    UnpackedBytesLimit,
    RatioLimit,
    EncryptedEntry,
    CorruptArchive,
    UnsupportedCompression,
    YaraTimeout,
    YaraError,
}

#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub reason: Reason,
    /// Same format as [`Detection::object`].
    pub object: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanReport {
    pub path: String,
    pub sha256: String,
    pub size: u64,
    pub file_type: FileType,
    pub verdict: Verdict,
    /// False when a limit or an error skipped part of the content. A `clean`
    /// verdict with `complete: false` means "nothing found in what was read".
    pub complete: bool,
    /// True when the file's own hash is on the allowlist. Nothing else ran.
    pub allowlisted: bool,
    pub detections: Vec<Detection>,
    pub notes: Vec<Note>,
    /// Objects examined, counting the file itself and every unpacked child.
    pub objects_scanned: u32,
    pub definitions_version: u64,
    pub elapsed_ms: u64,
}
