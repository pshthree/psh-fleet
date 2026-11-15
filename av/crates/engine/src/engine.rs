use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::defs::{Definitions, Sha256Digest};
use crate::filetype::{sniff, FileType};
use crate::limits::Limits;
use crate::report::{Detection, Layer, Note, Reason, ScanReport, Verdict};
use crate::unpack::{self, Budget};
use crate::yara::{self, ScanFailure};

const SNIFF_LEN: usize = 16;

#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    #[error("{path}: {source}")]
    Io { path: String, source: io::Error },
}

/// Immutable after construction, so one instance serves many threads.
pub struct Engine {
    defs: Definitions,
    limits: Limits,
}

impl Engine {
    pub fn new(defs: Definitions, limits: Limits) -> Self {
        Self { defs, limits }
    }

    pub fn definitions(&self) -> &Definitions {
        &self.defs
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Scans a buffer. `name` only labels the report.
    pub fn scan_bytes(&self, name: &str, data: &[u8]) -> ScanReport {
        let started = Instant::now();
        let mut state = State::new(self);
        let digest = state.scan_object(data);
        state.finish(name, digest, data.len() as u64, sniff(data), started)
    }

    /// Scans a file. Files over `max_file_size` are hashed and checked against
    /// the hash lists only, and the report says so.
    pub fn scan_path(&self, path: &Path) -> Result<ScanReport, ScanError> {
        let started = Instant::now();
        let name = path.display().to_string();
        let io_err = |source| ScanError::Io {
            path: name.clone(),
            source,
        };

        let mut file = File::open(path).map_err(io_err)?;
        let size = file.metadata().map_err(io_err)?.len();
        let max = self.limits.max_file_size;

        let mut data = Vec::new();
        if size <= max {
            data.reserve_exact(size as usize);
            // The file can grow between the size check and the read.
            file.by_ref()
                .take(max + 1)
                .read_to_end(&mut data)
                .map_err(io_err)?;
            if data.len() as u64 <= max {
                return Ok(self.scan_bytes(&name, &data));
            }
        }
        self.scan_oversized(&name, file, &data, started)
            .map_err(io_err)
    }

    fn scan_oversized(
        &self,
        name: &str,
        mut file: File,
        already_read: &[u8],
        started: Instant,
    ) -> io::Result<ScanReport> {
        let mut hasher = Sha256::new();
        hasher.update(already_read);
        let mut head = already_read[..already_read.len().min(SNIFF_LEN)].to_vec();
        let mut size = already_read.len() as u64;
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            let n = file.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            if head.len() < SNIFF_LEN {
                let want = (SNIFF_LEN - head.len()).min(n);
                head.extend_from_slice(&chunk[..want]);
            }
            hasher.update(&chunk[..n]);
            size += n as u64;
        }
        let digest: Sha256Digest = hasher.finalize().into();
        let file_type = sniff(&head);

        let mut state = State::new(self);
        state.objects = 1;
        if self.defs.allowed(&digest) {
            state.allowlisted = true;
        } else if let Some(label) = self.defs.blocked(&digest) {
            state.detect(
                Layer::Blocklist,
                label.to_owned(),
                Verdict::Malicious,
                &digest,
                file_type,
            );
        } else {
            state.push_note(Reason::FileTooLarge);
        }
        Ok(state.finish(name, digest, size, file_type, started))
    }
}

struct State<'e> {
    engine: &'e Engine,
    scanner: yara_x::Scanner<'e>,
    budget: Budget,
    detections: Vec<Detection>,
    notes: Vec<Note>,
    objects: u32,
    /// Names of the containers we're inside, outermost first.
    stack: Vec<String>,
    allowlisted: bool,
    malicious_found: bool,
}

impl<'e> State<'e> {
    fn new(engine: &'e Engine) -> Self {
        Self {
            engine,
            scanner: engine.defs.rules().scanner(engine.limits.yara_timeout),
            budget: Budget {
                entries_left: engine.limits.max_entries,
                bytes_left: engine.limits.max_unpacked_bytes,
            },
            detections: Vec::new(),
            notes: Vec::new(),
            objects: 0,
            stack: Vec::new(),
            allowlisted: false,
            malicious_found: false,
        }
    }

    fn object_path(&self, child: &str) -> String {
        let mut path = self.stack.join("!");
        if !child.is_empty() {
            if !path.is_empty() {
                path.push('!');
            }
            path.push_str(child);
        }
        path
    }

    fn push_note(&mut self, reason: Reason) {
        let object = self.object_path("");
        self.notes.push(Note { reason, object });
    }

    fn detect(
        &mut self,
        layer: Layer,
        name: String,
        verdict: Verdict,
        digest: &Sha256Digest,
        file_type: FileType,
    ) {
        self.malicious_found |= verdict == Verdict::Malicious;
        self.detections.push(Detection {
            layer,
            name,
            verdict,
            sha256: hex::encode(digest),
            object: self.object_path(""),
            file_type,
        });
    }

    fn scan_object(&mut self, data: &[u8]) -> Sha256Digest {
        self.objects += 1;
        let engine = self.engine;
        let digest: Sha256Digest = Sha256::digest(data).into();

        if engine.defs.allowed(&digest) {
            // Only the file's own hash marks the report. An allowlisted child is just skipped.
            self.allowlisted |= self.stack.is_empty();
            return digest;
        }
        let file_type = sniff(data);
        if let Some(label) = engine.defs.blocked(&digest) {
            self.detect(
                Layer::Blocklist,
                label.to_owned(),
                Verdict::Malicious,
                &digest,
                file_type,
            );
            return digest;
        }

        match yara::scan(&mut self.scanner, data) {
            Ok(hits) => {
                for hit in hits {
                    self.detect(Layer::Yara, hit.name, hit.verdict, &digest, file_type);
                }
            }
            Err(ScanFailure::Timeout) => self.push_note(Reason::YaraTimeout),
            Err(ScanFailure::Other) => self.push_note(Reason::YaraError),
        }
        if self.malicious_found {
            return digest;
        }

        if let Some(container) = unpack::detect(file_type, data) {
            if self.stack.len() as u32 >= engine.limits.max_depth {
                self.push_note(Reason::DepthLimit);
            } else {
                unpack::walk(container, data, &engine.limits, self);
            }
        }
        digest
    }

    fn finish(
        self,
        path: &str,
        digest: Sha256Digest,
        size: u64,
        file_type: FileType,
        started: Instant,
    ) -> ScanReport {
        let verdict = self
            .detections
            .iter()
            .map(|d| d.verdict)
            .max()
            .unwrap_or(Verdict::Clean);
        ScanReport {
            path: path.to_owned(),
            sha256: hex::encode(digest),
            size,
            file_type,
            verdict,
            complete: self.notes.is_empty(),
            allowlisted: self.allowlisted,
            detections: self.detections,
            notes: self.notes,
            objects_scanned: self.objects,
            definitions_version: self.engine.defs.version(),
            elapsed_ms: started.elapsed().as_millis() as u64,
        }
    }
}

impl unpack::Visitor for State<'_> {
    fn budget(&mut self) -> &mut Budget {
        &mut self.budget
    }

    fn note(&mut self, reason: Reason, child: &str) {
        let object = self.object_path(child);
        self.notes.push(Note { reason, object });
    }

    fn child(&mut self, name: &str, data: Vec<u8>) {
        self.stack.push(name.to_owned());
        self.scan_object(&data);
        self.stack.pop();
    }

    fn stop(&self) -> bool {
        self.malicious_found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_is_shareable_across_threads() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
    }
}
