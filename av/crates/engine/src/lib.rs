//! Scan engine core.
//!
//! Layers run in this order on every object: allowlist by SHA-256, blocklist
//! by SHA-256, YARA-X rules, then container unpacking with the same layers
//! applied to each child. Every resource is capped by [`Limits`], and a scan
//! that hits a cap says so in [`ScanReport::complete`].
//!
//! The engine parses hostile input. Host it in a low-privilege worker process.

#![forbid(unsafe_code)]

mod defs;
mod engine;
mod filetype;
mod limits;
mod report;
mod unpack;
mod yara;

pub use defs::{
    decode_signing_key, decode_verifying_key, encode_signing_key, encode_verifying_key,
    generate_keypair, sign_dir, Definitions, DefsError, Manifest, ManifestFile, Trust,
    MANIFEST_FILE, SIGNATURE_FILE,
};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
pub use engine::{Engine, ScanError};
pub use filetype::{sniff, FileType};
pub use limits::Limits;
pub use report::{Detection, Layer, Note, Reason, ScanReport, Verdict};
