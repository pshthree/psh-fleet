use std::time::Duration;

/// Hard caps applied to every scan. A scan that hits one reports
/// `complete: false` with the reason instead of failing or running on.
#[derive(Debug, Clone)]
pub struct Limits {
    /// Largest object, on disk or unpacked, whose content is scanned.
    /// Larger files are still hashed and checked against the hash lists.
    pub max_file_size: u64,
    /// How deep containers may nest. The root object is depth 0.
    pub max_depth: u32,
    /// Container entries visited per root scan, across all nesting levels.
    pub max_entries: u32,
    /// Bytes unpacked per root scan, across all nesting levels.
    pub max_unpacked_bytes: u64,
    /// Declared uncompressed/compressed ratio above which a ZIP entry is skipped.
    pub max_ratio: u64,
    /// YARA time budget per object.
    pub yara_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_size: 64 * 1024 * 1024,
            max_depth: 8,
            max_entries: 10_000,
            max_unpacked_bytes: 512 * 1024 * 1024,
            max_ratio: 200,
            yara_timeout: Duration::from_secs(20),
        }
    }
}
