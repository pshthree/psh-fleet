//! Definition bundles: a directory of YARA rules and hash lists, described by
//! `manifest.json` and authenticated by an Ed25519 signature in `manifest.sig`.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::yara::{RuleSet, RuleSource};

pub const MANIFEST_FILE: &str = "manifest.json";
pub const SIGNATURE_FILE: &str = "manifest.sig";

const FORMAT: u32 = 1;
const RULES_DIR: &str = "rules";
const HASHES_DIR: &str = "hashes";
const MAX_LABEL_LEN: usize = 128;

pub(crate) type Sha256Digest = [u8; 32];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub format: u32,
    /// Must only ever increase. Agents refuse to move to a lower version.
    pub version: u64,
    pub created_unix: u64,
    pub files: Vec<ManifestFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFile {
    /// Relative path with forward slashes, `rules/<name>` or `hashes/<name>`.
    pub path: String,
    pub sha256: String,
    pub size: u64,
}

/// How much to trust a bundle on disk.
pub enum Trust<'a> {
    /// Require a valid signature and matching hashes for every file.
    Verify(&'a VerifyingKey),
    /// Load whatever is in the directory. For development only.
    AllowUnsigned,
}

#[derive(Debug, thiserror::Error)]
pub enum DefsError {
    #[error("{path}: {source}")]
    Io { path: PathBuf, source: io::Error },
    #[error("manifest.sig is missing")]
    MissingSignature,
    #[error("manifest.sig is not a base64 Ed25519 signature")]
    BadSignatureEncoding,
    #[error("signature does not match manifest.json for this public key")]
    SignatureMismatch,
    #[error("manifest.json: {0}")]
    BadManifest(String),
    #[error("unsupported manifest format {0}")]
    UnsupportedFormat(u32),
    #[error("not allowed in a definition bundle: {0}")]
    BadPath(String),
    #[error("listed in the manifest but missing on disk: {0}")]
    MissingFile(String),
    #[error("on disk but not listed in the manifest: {0}")]
    UnlistedFile(String),
    #[error("content does not match the manifest: {0}")]
    HashMismatch(String),
    #[error("{file} line {line}: {msg}")]
    BadHashList {
        file: String,
        line: usize,
        msg: &'static str,
    },
    #[error("YARA rules failed to compile: {0}")]
    Rules(String),
    #[error("bad key: {0}")]
    BadKey(&'static str),
}

/// A loaded, compiled definition bundle.
pub struct Definitions {
    version: u64,
    created_unix: u64,
    signed: bool,
    rules: RuleSet,
    block: HashMap<Sha256Digest, String>,
    allow: HashSet<Sha256Digest>,
}

impl Definitions {
    /// A bundle with no rules and no hashes.
    pub fn empty() -> Self {
        build(0, 0, false, Vec::new()).expect("an empty bundle always builds")
    }

    pub fn load(dir: &Path, trust: Trust<'_>) -> Result<Self, DefsError> {
        let on_disk = list_payload(dir)?;
        match trust {
            Trust::Verify(key) => {
                let manifest_path = dir.join(MANIFEST_FILE);
                let manifest_bytes = fs::read(&manifest_path).map_err(io_err(&manifest_path))?;
                let sig_path = dir.join(SIGNATURE_FILE);
                let sig_text = match fs::read_to_string(&sig_path) {
                    Ok(text) => text,
                    Err(e) if e.kind() == io::ErrorKind::NotFound => {
                        return Err(DefsError::MissingSignature)
                    }
                    Err(e) => return Err(io_err(&sig_path)(e)),
                };
                let sig_bytes: [u8; 64] = B64
                    .decode(sig_text.trim())
                    .ok()
                    .and_then(|b| b.try_into().ok())
                    .ok_or(DefsError::BadSignatureEncoding)?;
                // Verify before parsing, so unauthenticated JSON never reaches the parser.
                key.verify_strict(&manifest_bytes, &Signature::from_bytes(&sig_bytes))
                    .map_err(|_| DefsError::SignatureMismatch)?;

                let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
                    .map_err(|e| DefsError::BadManifest(e.to_string()))?;
                if manifest.format != FORMAT {
                    return Err(DefsError::UnsupportedFormat(manifest.format));
                }

                let mut listed = HashSet::new();
                for file in &manifest.files {
                    validate_rel_path(&file.path)?;
                    if !listed.insert(file.path.as_str()) {
                        return Err(DefsError::BadManifest(format!(
                            "{} is listed twice",
                            file.path
                        )));
                    }
                }
                if let Some(extra) = on_disk.iter().find(|p| !listed.contains(p.as_str())) {
                    return Err(DefsError::UnlistedFile(extra.clone()));
                }

                let mut payload = Vec::with_capacity(manifest.files.len());
                for file in &manifest.files {
                    let path = dir.join(&file.path);
                    let bytes = match fs::read(&path) {
                        Ok(bytes) => bytes,
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            return Err(DefsError::MissingFile(file.path.clone()))
                        }
                        Err(e) => return Err(io_err(&path)(e)),
                    };
                    if bytes.len() as u64 != file.size
                        || !hex::encode(Sha256::digest(&bytes)).eq_ignore_ascii_case(&file.sha256)
                    {
                        return Err(DefsError::HashMismatch(file.path.clone()));
                    }
                    payload.push((file.path.clone(), bytes));
                }
                build(manifest.version, manifest.created_unix, true, payload)
            }
            Trust::AllowUnsigned => {
                let (version, created_unix) = fs::read(dir.join(MANIFEST_FILE))
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Manifest>(&b).ok())
                    .map(|m| (m.version, m.created_unix))
                    .unwrap_or((0, 0));
                let payload = read_payload(dir, on_disk)?;
                build(version, created_unix, false, payload)
            }
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn created_unix(&self) -> u64 {
        self.created_unix
    }

    /// True only when the bundle was loaded with [`Trust::Verify`].
    pub fn is_signed(&self) -> bool {
        self.signed
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn blocklist_len(&self) -> usize {
        self.block.len()
    }

    pub fn allowlist_len(&self) -> usize {
        self.allow.len()
    }

    pub(crate) fn rules(&self) -> &RuleSet {
        &self.rules
    }

    pub(crate) fn blocked(&self, digest: &Sha256Digest) -> Option<&str> {
        self.block.get(digest).map(String::as_str)
    }

    pub(crate) fn allowed(&self, digest: &Sha256Digest) -> bool {
        self.allow.contains(digest)
    }
}

/// Writes `manifest.json` and `manifest.sig` for the payload in `dir`.
/// Refuses to sign a bundle that would fail to load.
pub fn sign_dir(
    dir: &Path,
    key: &SigningKey,
    version: u64,
    created_unix: u64,
) -> Result<Manifest, DefsError> {
    let payload = read_payload(dir, list_payload(dir)?)?;
    let files = payload
        .iter()
        .map(|(path, bytes)| ManifestFile {
            path: path.clone(),
            sha256: hex::encode(Sha256::digest(bytes)),
            size: bytes.len() as u64,
        })
        .collect();
    build(version, created_unix, true, payload)?;

    let manifest = Manifest {
        format: FORMAT,
        version,
        created_unix,
        files,
    };
    let mut bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| DefsError::BadManifest(e.to_string()))?;
    bytes.push(b'\n');
    let signature = key.sign(&bytes);

    let manifest_path = dir.join(MANIFEST_FILE);
    fs::write(&manifest_path, &bytes).map_err(io_err(&manifest_path))?;
    let sig_path = dir.join(SIGNATURE_FILE);
    fs::write(&sig_path, format!("{}\n", B64.encode(signature.to_bytes())))
        .map_err(io_err(&sig_path))?;
    Ok(manifest)
}

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing = SigningKey::generate(&mut rand_core::OsRng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

pub fn encode_signing_key(key: &SigningKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn encode_verifying_key(key: &VerifyingKey) -> String {
    B64.encode(key.to_bytes())
}

pub fn decode_signing_key(text: &str) -> Result<SigningKey, DefsError> {
    let bytes = decode_key_bytes(text)?;
    Ok(SigningKey::from_bytes(&bytes))
}

pub fn decode_verifying_key(text: &str) -> Result<VerifyingKey, DefsError> {
    let bytes = decode_key_bytes(text)?;
    VerifyingKey::from_bytes(&bytes).map_err(|_| DefsError::BadKey("not a valid Ed25519 point"))
}

fn decode_key_bytes(text: &str) -> Result<[u8; 32], DefsError> {
    B64.decode(text.trim())
        .map_err(|_| DefsError::BadKey("not base64"))?
        .try_into()
        .map_err(|_| DefsError::BadKey("expected 32 bytes"))
}

fn io_err(path: &Path) -> impl FnOnce(io::Error) -> DefsError + '_ {
    move |source| DefsError::Io {
        path: path.to_path_buf(),
        source,
    }
}

/// Relative paths of every payload file on disk, sorted.
fn list_payload(dir: &Path) -> Result<Vec<String>, DefsError> {
    let mut found = Vec::new();
    for sub in [RULES_DIR, HASHES_DIR] {
        let sub_path = dir.join(sub);
        let entries = match fs::read_dir(&sub_path) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => return Err(io_err(&sub_path)(e)),
        };
        for entry in entries {
            let entry = entry.map_err(io_err(&sub_path))?;
            let name = entry.file_name();
            let rel = format!("{sub}/{}", name.to_string_lossy());
            if entry.file_type().map_err(io_err(&entry.path()))?.is_dir() {
                return Err(DefsError::BadPath(format!("{rel} (subdirectory)")));
            }
            validate_rel_path(&rel)?;
            found.push(rel);
        }
    }
    found.sort();
    Ok(found)
}

fn read_payload(dir: &Path, paths: Vec<String>) -> Result<Vec<(String, Vec<u8>)>, DefsError> {
    paths
        .into_iter()
        .map(|rel| {
            let path = dir.join(&rel);
            let bytes = fs::read(&path).map_err(io_err(&path))?;
            Ok((rel, bytes))
        })
        .collect()
}

/// Manifest paths are attacker-controlled until the signature is checked and
/// stay untrusted after, so only a fixed shape is accepted.
fn validate_rel_path(rel: &str) -> Result<(), DefsError> {
    let bad = || DefsError::BadPath(rel.to_owned());
    let (dir, name) = rel.split_once('/').ok_or_else(bad)?;
    let name_ok = !name.is_empty()
        && !name.starts_with('.')
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    let shape_ok = match dir {
        RULES_DIR => name.ends_with(".yar") || name.ends_with(".yara"),
        HASHES_DIR => {
            (name.starts_with("block") || name.starts_with("allow")) && name.ends_with(".sha256")
        }
        _ => false,
    };
    if name_ok && shape_ok {
        Ok(())
    } else {
        Err(bad())
    }
}

fn build(
    version: u64,
    created_unix: u64,
    signed: bool,
    payload: Vec<(String, Vec<u8>)>,
) -> Result<Definitions, DefsError> {
    let mut sources = Vec::new();
    let mut block = HashMap::new();
    let mut allow = HashSet::new();

    for (path, bytes) in payload {
        validate_rel_path(&path)?;
        let (dir, name) = path.split_once('/').expect("validated above");
        if dir == RULES_DIR {
            let source = String::from_utf8(bytes)
                .map_err(|_| DefsError::Rules(format!("{path}: not UTF-8")))?;
            let namespace = name
                .rsplit_once('.')
                .map_or(name, |(stem, _)| stem)
                .to_owned();
            sources.push(RuleSource {
                namespace,
                origin: path,
                source,
            });
        } else {
            let text = String::from_utf8(bytes).map_err(|_| DefsError::BadHashList {
                file: path.clone(),
                line: 0,
                msg: "not UTF-8",
            })?;
            let is_block = name.starts_with("block");
            for (digest, label) in parse_hash_list(&path, &text)? {
                if is_block {
                    let label = label
                        .unwrap_or_else(|| format!("Blocklist.{}", &hex::encode(digest)[..12]));
                    block.insert(digest, label);
                } else {
                    allow.insert(digest);
                }
            }
        }
    }

    let rules = RuleSet::compile(&sources).map_err(DefsError::Rules)?;
    Ok(Definitions {
        version,
        created_unix,
        signed,
        rules,
        block,
        allow,
    })
}

/// One entry per line: 64 hex characters, then an optional detection name.
/// Blank lines and lines starting with `#` are skipped.
fn parse_hash_list(
    file: &str,
    text: &str,
) -> Result<Vec<(Sha256Digest, Option<String>)>, DefsError> {
    let mut entries = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let err = |msg| DefsError::BadHashList {
            file: file.to_owned(),
            line: index + 1,
            msg,
        };
        let (hash, rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
        if hash.len() != 64 {
            return Err(err("expected 64 hex characters"));
        }
        let mut digest = [0u8; 32];
        hex::decode_to_slice(hash, &mut digest).map_err(|_| err("not hexadecimal"))?;
        let label = rest.trim();
        let label = if label.is_empty() {
            None
        } else if label.len() > MAX_LABEL_LEN || label.chars().any(char::is_control) {
            return Err(err("name is too long or has control characters"));
        } else {
            Some(label.to_owned())
        };
        entries.push((digest, label));
    }
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_expected_path_shapes() {
        for good in [
            "rules/a.yar",
            "rules/win_loader-2.yara",
            "hashes/block.sha256",
            "hashes/allow_ms.sha256",
        ] {
            assert!(validate_rel_path(good).is_ok(), "{good}");
        }
        for bad in [
            "rules/../x.yar",
            "/etc/passwd",
            "rules/a.txt",
            "rules/.hidden.yar",
            "rules/sub/a.yar",
            "hashes/other.sha256",
            "hashes/block.txt",
            "manifest.json",
            "rules\\a.yar",
            "rules/",
            "",
        ] {
            assert!(validate_rel_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_hash_lists() {
        let h = "a".repeat(64);
        let text = format!("# comment\n\n{h}\n{h}  Trojan.Test.A  \n");
        let entries = parse_hash_list("hashes/block.sha256", &text).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].1, None);
        assert_eq!(entries[1].1.as_deref(), Some("Trojan.Test.A"));

        assert!(parse_hash_list("f", "abc").is_err());
        assert!(parse_hash_list("f", &"z".repeat(64)).is_err());
        let err = parse_hash_list("f", &format!("{h}\nshort")).unwrap_err();
        assert!(err.to_string().contains("line 2"), "{err}");
    }

    #[test]
    fn keys_round_trip() {
        let (signing, verifying) = generate_keypair();
        let s = decode_signing_key(&encode_signing_key(&signing)).unwrap();
        let v = decode_verifying_key(&encode_verifying_key(&verifying)).unwrap();
        assert_eq!(s.to_bytes(), signing.to_bytes());
        assert_eq!(v, verifying);
        assert!(decode_verifying_key("not base64!").is_err());
        assert!(decode_verifying_key("AAAA").is_err());
    }
}
