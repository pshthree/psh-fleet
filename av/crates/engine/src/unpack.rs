//! Bounded container unpacking. Nothing here trusts sizes declared by the
//! container: every read is capped, and the caps come out of a budget shared
//! by the whole scan.

use std::io::{Cursor, Read};

use zip::result::ZipError;

use crate::filetype::{has_zip_trailer, FileType};
use crate::limits::Limits;
use crate::report::Reason;

const MAX_NAME_LEN: usize = 256;

pub(crate) struct Budget {
    pub entries_left: u32,
    pub bytes_left: u64,
}

pub(crate) enum Container {
    /// `declared` is true when the leading bytes say ZIP. When only a trailer
    /// was spotted, a parse failure means "not a ZIP" and isn't reported.
    Zip {
        declared: bool,
    },
    Gzip,
}

pub(crate) trait Visitor {
    fn budget(&mut self) -> &mut Budget;
    /// `child` is empty when the note is about the container itself.
    fn note(&mut self, reason: Reason, child: &str);
    fn child(&mut self, name: &str, data: Vec<u8>);
    /// True once the scan has a decisive verdict and more children add nothing.
    fn stop(&self) -> bool;
}

pub(crate) fn detect(file_type: FileType, data: &[u8]) -> Option<Container> {
    match file_type {
        FileType::Zip => Some(Container::Zip { declared: true }),
        FileType::Gzip => Some(Container::Gzip),
        _ if has_zip_trailer(data) => Some(Container::Zip { declared: false }),
        _ => None,
    }
}

pub(crate) fn walk(container: Container, data: &[u8], limits: &Limits, visitor: &mut dyn Visitor) {
    match container {
        Container::Zip { declared } => walk_zip(data, declared, limits, visitor),
        Container::Gzip => walk_gzip(data, limits, visitor),
    }
}

/// Largest child we may read right now, and the reason to give if it's exceeded.
fn read_cap(limits: &Limits, visitor: &mut dyn Visitor) -> (u64, Reason) {
    let left = visitor.budget().bytes_left;
    if left < limits.max_file_size {
        (left, Reason::UnpackedBytesLimit)
    } else {
        (limits.max_file_size, Reason::FileTooLarge)
    }
}

fn take_entry(visitor: &mut dyn Visitor) -> bool {
    let budget = visitor.budget();
    if budget.entries_left == 0 {
        return false;
    }
    budget.entries_left -= 1;
    true
}

fn walk_zip(data: &[u8], declared: bool, limits: &Limits, visitor: &mut dyn Visitor) {
    let mut archive = match zip::ZipArchive::new(Cursor::new(data)) {
        Ok(archive) => archive,
        Err(_) => {
            if declared {
                visitor.note(Reason::CorruptArchive, "");
            }
            return;
        }
    };

    for index in 0..archive.len() {
        if visitor.stop() {
            return;
        }
        if !take_entry(visitor) {
            visitor.note(Reason::EntryLimit, "");
            return;
        }

        // Raw access reads metadata without needing a password.
        let (name, is_dir, encrypted, size, compressed) = match archive.by_index_raw(index) {
            Ok(entry) => (
                display_name(entry.name()),
                entry.is_dir(),
                entry.encrypted(),
                entry.size(),
                entry.compressed_size(),
            ),
            Err(_) => {
                visitor.note(Reason::CorruptArchive, &format!("#{index}"));
                continue;
            }
        };
        if is_dir {
            continue;
        }
        if encrypted {
            visitor.note(Reason::EncryptedEntry, &name);
            continue;
        }
        if compressed > 0 && size / compressed > limits.max_ratio {
            visitor.note(Reason::RatioLimit, &name);
            continue;
        }
        let (cap, over_cap) = read_cap(limits, visitor);
        if size > cap {
            visitor.note(over_cap, &name);
            continue;
        }

        let mut buf = Vec::new();
        let read = match archive.by_index(index) {
            // The declared size can lie, so the cap is enforced on the stream.
            Ok(mut entry) => entry.by_ref().take(cap + 1).read_to_end(&mut buf),
            Err(ZipError::UnsupportedArchive(_)) => {
                visitor.note(Reason::UnsupportedCompression, &name);
                continue;
            }
            Err(_) => {
                visitor.note(Reason::CorruptArchive, &name);
                continue;
            }
        };
        if buf.len() as u64 > cap {
            visitor.note(over_cap, &name);
            continue;
        }
        if read.is_err() {
            visitor.note(Reason::CorruptArchive, &name);
            continue;
        }
        visitor.budget().bytes_left -= buf.len() as u64;
        visitor.child(&name, buf);
    }
}

fn walk_gzip(data: &[u8], limits: &Limits, visitor: &mut dyn Visitor) {
    if !take_entry(visitor) {
        visitor.note(Reason::EntryLimit, "");
        return;
    }
    let (cap, over_cap) = read_cap(limits, visitor);
    let mut buf = Vec::new();
    let read = flate2::read::MultiGzDecoder::new(data)
        .take(cap + 1)
        .read_to_end(&mut buf);
    if buf.len() as u64 > cap {
        visitor.note(over_cap, "");
        return;
    }
    if read.is_err() {
        visitor.note(Reason::CorruptArchive, "");
        // A truncated stream still yields a usable prefix. Scan what we got.
        if buf.is_empty() {
            return;
        }
    }
    visitor.budget().bytes_left -= buf.len() as u64;
    visitor.child("gzip-content", buf);
}

/// Entry names end up in logs and terminals, so control characters go.
fn display_name(name: &str) -> String {
    name.chars()
        .take(MAX_NAME_LEN)
        .map(|c| if c.is_control() { '?' } else { c })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_name_strips_control_characters_and_truncates() {
        assert_eq!(display_name("a\x1b[31mb\n.exe"), "a?[31mb?.exe");
        assert_eq!(display_name(&"x".repeat(1000)).len(), MAX_NAME_LEN);
    }
}
