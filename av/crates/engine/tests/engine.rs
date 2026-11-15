//! End-to-end tests for the scan engine. No malware here: detections are
//! exercised with the EICAR test file, built at runtime, and with rules that
//! match harmless marker strings.

use std::fs;
use std::io::{Cursor, Write};
use std::path::Path;

use pshav_engine::{
    generate_keypair, sign_dir, Definitions, DefsError, Engine, FileType, Layer, Limits, Reason,
    ScanReport, Trust, Verdict, MANIFEST_FILE, SIGNATURE_FILE,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use zip::write::SimpleFileOptions;
use zip::CompressionMethod;

const EICAR_RULE: &str = include_str!("../../../defs/rules/test_eicar.yar");
const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

const MARKER_RULE: &str = r#"
rule Marker
{
    strings:
        $m = "pshav-test-marker-7f3a"
    condition:
        $m
}

rule Soft_Marker
{
    meta:
        verdict = "suspicious"
        name = "Test.SoftMarker"
    strings:
        $m = "pshav-soft-marker-91c2"
    condition:
        $m
}
"#;

/// Assembled at runtime so no file in the repository holds the test string.
fn eicar() -> Vec<u8> {
    [
        "X5O!P%@AP[4\\PZX54(P^)7CC)7}$",
        "EICAR-STANDARD-",
        "ANTIVIRUS-TEST-FILE!",
        "$H+H*",
    ]
    .concat()
    .into_bytes()
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn bundle(rules: &[(&str, &str)], block: &str, allow: &str) -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::create_dir(dir.path().join("rules")).unwrap();
    fs::create_dir(dir.path().join("hashes")).unwrap();
    for (name, source) in rules {
        fs::write(dir.path().join("rules").join(name), source).unwrap();
    }
    fs::write(dir.path().join("hashes/block.sha256"), block).unwrap();
    fs::write(dir.path().join("hashes/allow.sha256"), allow).unwrap();
    dir
}

fn standard_bundle() -> TempDir {
    bundle(
        &[("test_eicar.yar", EICAR_RULE), ("markers.yar", MARKER_RULE)],
        "",
        "",
    )
}

fn engine_from(dir: &Path, limits: Limits) -> Engine {
    Engine::new(
        Definitions::load(dir, Trust::AllowUnsigned).unwrap(),
        limits,
    )
}

fn engine() -> Engine {
    engine_from(standard_bundle().path(), Limits::default())
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    zip_with(entries, CompressionMethod::Deflated)
}

fn zip_with(entries: &[(&str, &[u8])], method: CompressionMethod) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(method);
    for (name, data) in entries {
        writer.start_file(*name, options).unwrap();
        writer.write_all(data).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

fn gzip_of(data: &[u8]) -> Vec<u8> {
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    encoder.write_all(data).unwrap();
    encoder.finish().unwrap()
}

/// Bytes that don't compress, so ratio limits stay out of the way.
fn noise(len: usize) -> Vec<u8> {
    let mut state = 0x9E37_79B9_7F4A_7C15u64;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn reasons(report: &ScanReport) -> Vec<Reason> {
    report.notes.iter().map(|n| n.reason).collect()
}

// ---- detection layers -------------------------------------------------------

#[test]
fn eicar_bytes_have_the_hash_the_rule_expects() {
    assert_eq!(eicar().len(), 68);
    assert_eq!(sha256_hex(&eicar()), EICAR_SHA256);
}

#[test]
fn detects_eicar() {
    let report = engine().scan_bytes("eicar.com", &eicar());
    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report.complete);
    assert_eq!(report.sha256, EICAR_SHA256);
    assert_eq!(report.detections.len(), 1);
    let d = &report.detections[0];
    assert_eq!(
        (d.layer, d.name.as_str(), d.object.as_str()),
        (Layer::Yara, "Test.EICAR", "")
    );
}

#[test]
fn detects_eicar_with_trailing_whitespace_but_not_with_other_content_appended() {
    let mut padded = eicar();
    padded.extend_from_slice(b"\r\n");
    assert_eq!(
        engine().scan_bytes("a", &padded).verdict,
        Verdict::Malicious
    );

    let mut long = eicar();
    long.extend_from_slice(&[b'x'; 200]);
    assert_eq!(engine().scan_bytes("b", &long).verdict, Verdict::Clean);
}

#[test]
fn clean_file_is_clean_and_complete() {
    let report = engine().scan_bytes("readme.txt", b"just some ordinary text\n");
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.complete && !report.allowlisted);
    assert!(report.detections.is_empty() && report.notes.is_empty());
    assert_eq!(report.objects_scanned, 1);
}

#[test]
fn rule_metadata_sets_verdict_and_name() {
    let soft = engine().scan_bytes("a", b"xx pshav-soft-marker-91c2 xx");
    assert_eq!(soft.verdict, Verdict::Suspicious);
    assert_eq!(soft.detections[0].name, "Test.SoftMarker");

    let hard = engine().scan_bytes("b", b"xx pshav-test-marker-7f3a xx");
    assert_eq!(hard.verdict, Verdict::Malicious);
    assert_eq!(hard.detections[0].name, "markers.Marker");
}

#[test]
fn worst_verdict_wins() {
    let both = b"pshav-soft-marker-91c2 and pshav-test-marker-7f3a";
    let report = engine().scan_bytes("a", both);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.detections.len(), 2);
}

#[test]
fn blocklist_detects_by_hash() {
    let named = b"blocked file one".as_slice();
    let unnamed = b"blocked file two".as_slice();
    let block = format!(
        "{}  Trojan.Test.Named\n{}\n",
        sha256_hex(named),
        sha256_hex(unnamed)
    );
    let dir = bundle(&[], &block, "");
    let engine = engine_from(dir.path(), Limits::default());

    let report = engine.scan_bytes("a", named);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.detections[0].layer, Layer::Blocklist);
    assert_eq!(report.detections[0].name, "Trojan.Test.Named");

    let report = engine.scan_bytes("b", unnamed);
    assert_eq!(
        report.detections[0].name,
        format!("Blocklist.{}", &sha256_hex(unnamed)[..12])
    );

    assert_eq!(
        engine.scan_bytes("c", b"something else").verdict,
        Verdict::Clean
    );
}

#[test]
fn allowlist_wins_over_rules_and_blocklist() {
    let hash = sha256_hex(&eicar());
    let dir = bundle(
        &[("test_eicar.yar", EICAR_RULE)],
        &format!("{hash}\n"),
        &format!("{hash}\n"),
    );
    let report = engine_from(dir.path(), Limits::default()).scan_bytes("a", &eicar());
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.allowlisted && report.complete);
    assert!(report.detections.is_empty());
}

#[test]
fn allowlisted_child_is_skipped_without_marking_the_file() {
    let hash = sha256_hex(&eicar());
    let dir = bundle(&[("test_eicar.yar", EICAR_RULE)], "", &format!("{hash}\n"));
    let archive = zip_of(&[("eicar.com", &eicar()), ("note.txt", b"hello")]);
    let report = engine_from(dir.path(), Limits::default()).scan_bytes("a.zip", &archive);
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(!report.allowlisted);
    assert_eq!(report.objects_scanned, 3);
}

// ---- containers -------------------------------------------------------------

#[test]
fn detects_eicar_inside_zip() {
    let archive = zip_of(&[("docs/readme.txt", b"hello"), ("eicar.com", &eicar())]);
    let report = engine().scan_bytes("a.zip", &archive);
    assert_eq!(report.file_type, FileType::Zip);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.detections[0].object, "eicar.com");
    assert_eq!(report.detections[0].sha256, EICAR_SHA256);
    assert_eq!(report.objects_scanned, 3);
}

#[test]
fn reports_the_path_through_nested_containers() {
    let inner = zip_of(&[("payload/eicar.com", &eicar())]);
    let middle = gzip_of(&inner);
    let outer = zip_of(&[("stage.gz", &middle)]);
    let report = engine().scan_bytes("outer.zip", &outer);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(
        report.detections[0].object,
        "stage.gz!gzip-content!payload/eicar.com"
    );
}

#[test]
fn detects_eicar_inside_gzip() {
    let report = engine().scan_bytes("a.gz", &gzip_of(&eicar()));
    assert_eq!(report.file_type, FileType::Gzip);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.detections[0].object, "gzip-content");
}

#[test]
fn stops_unpacking_after_a_malicious_detection() {
    let archive = zip_of(&[("eicar.com", &eicar()), ("b.txt", b"b"), ("c.txt", b"c")]);
    let report = engine().scan_bytes("a.zip", &archive);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(
        report.objects_scanned, 2,
        "siblings after the hit aren't read"
    );
}

#[test]
fn unpacks_a_zip_hidden_behind_other_leading_bytes() {
    let mut data = b"MZ pretend this is an executable stub ".to_vec();
    data.extend_from_slice(&zip_of(&[("eicar.com", &eicar())]));
    let report = engine().scan_bytes("setup.exe", &data);
    assert_eq!(report.file_type, FileType::Pe);
    assert_eq!(report.verdict, Verdict::Malicious);
}

#[test]
fn a_stray_zip_trailer_in_a_non_zip_file_is_not_reported() {
    let mut data = b"ordinary data ".to_vec();
    data.extend_from_slice(b"PK\x05\x06 not really a central directory");
    let report = engine().scan_bytes("a.bin", &data);
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(report.complete, "{:?}", report.notes);
}

// ---- limits -----------------------------------------------------------------

#[test]
fn depth_limit_is_reported_and_never_silently_clean() {
    let level3 = zip_of(&[("eicar.com", &eicar())]);
    let level2 = zip_of(&[("c.zip", &level3)]);
    let level1 = zip_of(&[("b.zip", &level2)]);

    let shallow = Limits {
        max_depth: 2,
        ..Limits::default()
    };
    let report = engine_from(standard_bundle().path(), shallow).scan_bytes("a.zip", &level1);
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(!report.complete);
    assert_eq!(reasons(&report), vec![Reason::DepthLimit]);
    assert_eq!(report.notes[0].object, "b.zip!c.zip");

    let report = engine().scan_bytes("a.zip", &level1);
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.detections[0].object, "b.zip!c.zip!eicar.com");
}

#[test]
fn highly_compressed_entry_is_skipped_by_ratio() {
    let zeros = vec![0u8; 8 * 1024 * 1024];
    let archive = zip_of(&[("bomb.bin", &zeros), ("eicar.com", &eicar())]);
    assert!(
        archive.len() < 64 * 1024,
        "test premise: zeros compress well"
    );

    let report = engine().scan_bytes("a.zip", &archive);
    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "later entries are still scanned"
    );
    assert_eq!(reasons(&report), vec![Reason::RatioLimit]);
    assert_eq!(report.notes[0].object, "bomb.bin");
}

#[test]
fn oversized_entry_is_skipped() {
    let big = noise(300 * 1024);
    let archive = zip_with(
        &[("big.bin", &big), ("small.txt", b"hi")],
        CompressionMethod::Stored,
    );
    let limits = Limits {
        max_file_size: 100 * 1024,
        ..Limits::default()
    };
    // The archive itself is over the limit as a buffer, which scan_bytes accepts:
    // the size cap for the root applies when reading from disk.
    let report = engine_from(standard_bundle().path(), limits).scan_bytes("a.zip", &archive);
    assert_eq!(reasons(&report), vec![Reason::FileTooLarge]);
    assert_eq!(report.objects_scanned, 2);
    assert!(!report.complete);
}

#[test]
fn unpacked_bytes_budget_is_shared_across_entries() {
    let chunk = noise(400 * 1024);
    let entries: Vec<(&str, &[u8])> = vec![
        ("1.bin", &chunk),
        ("2.bin", &chunk),
        ("3.bin", &chunk),
        ("4.bin", &chunk),
    ];
    let archive = zip_with(&entries, CompressionMethod::Stored);
    let limits = Limits {
        max_unpacked_bytes: 1024 * 1024,
        ..Limits::default()
    };
    let report = engine_from(standard_bundle().path(), limits).scan_bytes("a.zip", &archive);
    assert_eq!(
        report.objects_scanned, 3,
        "root plus the two entries that fit"
    );
    assert_eq!(
        reasons(&report),
        vec![Reason::UnpackedBytesLimit, Reason::UnpackedBytesLimit]
    );
}

#[test]
fn entry_limit_is_reported() {
    let entries: Vec<(String, Vec<u8>)> = (0..6)
        .map(|i| (format!("{i}.txt"), vec![b'a' + i as u8; 10]))
        .collect();
    let borrowed: Vec<(&str, &[u8])> = entries
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect();
    let archive = zip_of(&borrowed);
    let limits = Limits {
        max_entries: 4,
        ..Limits::default()
    };
    let report = engine_from(standard_bundle().path(), limits).scan_bytes("a.zip", &archive);
    assert_eq!(reasons(&report), vec![Reason::EntryLimit]);
    assert_eq!(report.objects_scanned, 5);
}

#[test]
fn a_lying_size_header_cannot_exceed_the_cap() {
    // Declare 10 bytes in the central directory for an entry that inflates to 4 MiB.
    let zeros = vec![0u8; 4 * 1024 * 1024];
    let mut archive = zip_of(&[("liar.bin", &zeros)]);
    let cd = archive
        .windows(4)
        .rposition(|w| w == b"PK\x01\x02")
        .unwrap();
    // Offset 24 in a central directory header is the uncompressed size.
    archive[cd + 24..cd + 28].copy_from_slice(&10u32.to_le_bytes());

    let limits = Limits {
        max_file_size: 64 * 1024,
        max_ratio: u64::MAX,
        ..Limits::default()
    };
    let report = engine_from(standard_bundle().path(), limits).scan_bytes("a.zip", &archive);
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(
        !report.complete,
        "the entry must be flagged, not scanned as 10 bytes"
    );
    assert_eq!(report.objects_scanned, 1);
}

#[test]
fn encrypted_entry_is_reported() {
    let mut archive = zip_with(&[("secret.bin", b"0123456789")], CompressionMethod::Stored);
    let cd = archive
        .windows(4)
        .rposition(|w| w == b"PK\x01\x02")
        .unwrap();
    // Offset 8 in a central directory header is the flags word. Bit 0 means encrypted.
    archive[cd + 8] |= 1;
    let report = engine().scan_bytes("a.zip", &archive);
    assert_eq!(reasons(&report), vec![Reason::EncryptedEntry]);
    assert_eq!(report.notes[0].object, "secret.bin");
    assert!(!report.complete);
}

#[test]
fn corrupt_zip_is_reported() {
    let report = engine().scan_bytes("a.zip", b"PK\x03\x04 this is not a real archive");
    assert_eq!(report.verdict, Verdict::Clean);
    assert_eq!(reasons(&report), vec![Reason::CorruptArchive]);
}

#[test]
fn truncated_gzip_is_reported_and_its_prefix_still_scanned() {
    const MARKER: &[u8] = b"pshav-test-marker-7f3a";
    let mut body = MARKER.to_vec();
    // A 16-letter alphabet compresses, so deflate Huffman-codes the stream
    // instead of storing it and the marker isn't visible in the .gz bytes.
    body.extend(noise(64 * 1024).iter().map(|b| b'a' + (b & 0x0F)));
    let mut gz = gzip_of(&body);
    gz.truncate(gz.len() - 2048);
    assert!(
        !gz.windows(MARKER.len()).any(|w| w == MARKER),
        "test premise: the marker is only reachable by decompressing"
    );
    let report = engine().scan_bytes("a.gz", &gz);
    assert_eq!(reasons(&report), vec![Reason::CorruptArchive]);
    assert_eq!(
        report.verdict,
        Verdict::Malicious,
        "marker sits in the readable prefix"
    );
}

// ---- files on disk ----------------------------------------------------------

#[test]
fn scan_path_reads_files_and_reports_io_errors() {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("eicar.com");
    fs::write(&path, eicar()).unwrap();
    let report = engine().scan_path(&path).unwrap();
    assert_eq!(report.verdict, Verdict::Malicious);
    assert_eq!(report.size, 68);
    assert!(report.path.ends_with("eicar.com"));

    assert!(engine().scan_path(&dir.path().join("missing")).is_err());
}

#[test]
fn oversized_file_is_checked_by_hash_only() {
    let content = {
        let mut c = b"MZ".to_vec();
        c.extend_from_slice(&noise(8000));
        c
    };
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("big.exe");
    fs::write(&path, &content).unwrap();
    let limits = || Limits {
        max_file_size: 1024,
        ..Limits::default()
    };

    let report = engine_from(standard_bundle().path(), limits())
        .scan_path(&path)
        .unwrap();
    assert_eq!(report.verdict, Verdict::Clean);
    assert!(!report.complete);
    assert_eq!(reasons(&report), vec![Reason::FileTooLarge]);
    assert_eq!(report.sha256, sha256_hex(&content));
    assert_eq!(report.size, content.len() as u64);
    assert_eq!(report.file_type, FileType::Pe);

    let blocked = bundle(
        &[],
        &format!("{} Trojan.Test.Big\n", sha256_hex(&content)),
        "",
    );
    let report = engine_from(blocked.path(), limits())
        .scan_path(&path)
        .unwrap();
    assert_eq!(report.verdict, Verdict::Malicious);
    assert!(report.complete);

    let allowed = bundle(&[], "", &format!("{}\n", sha256_hex(&content)));
    let report = engine_from(allowed.path(), limits())
        .scan_path(&path)
        .unwrap();
    assert!(report.allowlisted && report.complete);
}

#[test]
fn report_serializes_with_stable_field_names() {
    let json = serde_json::to_value(engine().scan_bytes("eicar.com", &eicar())).unwrap();
    assert_eq!(json["verdict"], "malicious");
    assert_eq!(json["file_type"], "unknown");
    assert_eq!(json["detections"][0]["layer"], "yara");
    assert_eq!(json["complete"], true);
}

// ---- definition bundles -----------------------------------------------------

#[test]
fn repository_definitions_load_and_detect_eicar() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../defs");
    let engine = engine_from(&dir, Limits::default());
    assert!(engine.definitions().rule_count() >= 1);
    assert!(!engine.definitions().is_signed());
    assert_eq!(
        engine.scan_bytes("eicar.com", &eicar()).verdict,
        Verdict::Malicious
    );
}

#[test]
fn empty_definitions_find_nothing() {
    let engine = Engine::new(Definitions::empty(), Limits::default());
    assert_eq!(
        engine.scan_bytes("eicar.com", &eicar()).verdict,
        Verdict::Clean
    );
}

#[test]
fn signed_bundle_loads_and_reports_its_version() {
    let dir = standard_bundle();
    let (signing, verifying) = generate_keypair();
    let manifest = sign_dir(dir.path(), &signing, 7, 1_700_000_000).unwrap();
    assert_eq!(manifest.files.len(), 4);

    let defs = Definitions::load(dir.path(), Trust::Verify(&verifying)).unwrap();
    assert!(defs.is_signed());
    assert_eq!(
        (defs.version(), defs.created_unix(), defs.rule_count()),
        (7, 1_700_000_000, 3)
    );
    let report = Engine::new(defs, Limits::default()).scan_bytes("eicar.com", &eicar());
    assert_eq!(report.definitions_version, 7);
    assert_eq!(report.verdict, Verdict::Malicious);
}

fn signed_bundle() -> (TempDir, pshav_engine::VerifyingKey) {
    let dir = standard_bundle();
    let (signing, verifying) = generate_keypair();
    sign_dir(dir.path(), &signing, 1, 0).unwrap();
    (dir, verifying)
}

fn load_err(dir: &Path, key: &pshav_engine::VerifyingKey) -> DefsError {
    match Definitions::load(dir, Trust::Verify(key)) {
        Ok(_) => panic!("bundle loaded but should have been rejected"),
        Err(e) => e,
    }
}

#[test]
fn rejects_a_tampered_rule_file() {
    let (dir, key) = signed_bundle();
    let path = dir.path().join("rules/markers.yar");
    let mut source = fs::read_to_string(&path).unwrap();
    source.push_str("\nrule Injected { condition: true }\n");
    fs::write(&path, source).unwrap();
    assert!(
        matches!(load_err(dir.path(), &key), DefsError::HashMismatch(p) if p == "rules/markers.yar")
    );
}

#[test]
fn rejects_a_file_the_manifest_does_not_list() {
    let (dir, key) = signed_bundle();
    fs::write(
        dir.path().join("rules/extra.yar"),
        "rule Extra { condition: true }",
    )
    .unwrap();
    assert!(
        matches!(load_err(dir.path(), &key), DefsError::UnlistedFile(p) if p == "rules/extra.yar")
    );
}

#[test]
fn rejects_a_missing_file() {
    let (dir, key) = signed_bundle();
    fs::remove_file(dir.path().join("hashes/allow.sha256")).unwrap();
    assert!(matches!(
        load_err(dir.path(), &key),
        DefsError::MissingFile(_)
    ));
}

#[test]
fn rejects_a_tampered_manifest() {
    let (dir, key) = signed_bundle();
    let path = dir.path().join(MANIFEST_FILE);
    let edited = fs::read_to_string(&path)
        .unwrap()
        .replace("\"version\": 1", "\"version\": 99");
    fs::write(&path, edited).unwrap();
    assert!(matches!(
        load_err(dir.path(), &key),
        DefsError::SignatureMismatch
    ));
}

#[test]
fn rejects_another_key_and_a_missing_or_garbled_signature() {
    let (dir, key) = signed_bundle();
    let (_, other_key) = generate_keypair();
    assert!(matches!(
        load_err(dir.path(), &other_key),
        DefsError::SignatureMismatch
    ));

    fs::write(dir.path().join(SIGNATURE_FILE), "not a signature").unwrap();
    assert!(matches!(
        load_err(dir.path(), &key),
        DefsError::BadSignatureEncoding
    ));

    fs::remove_file(dir.path().join(SIGNATURE_FILE)).unwrap();
    assert!(matches!(
        load_err(dir.path(), &key),
        DefsError::MissingSignature
    ));
}

#[test]
fn rejects_an_unsigned_bundle_when_a_key_is_required() {
    let dir = standard_bundle();
    let (_, key) = generate_keypair();
    assert!(matches!(load_err(dir.path(), &key), DefsError::Io { .. }));
}

#[test]
fn refuses_to_sign_a_bundle_that_would_not_load() {
    let (signing, _) = generate_keypair();

    let broken_rule = bundle(&[("bad.yar", "rule Broken { condition: ")], "", "");
    assert!(matches!(
        sign_dir(broken_rule.path(), &signing, 1, 0),
        Err(DefsError::Rules(_))
    ));
    assert!(
        !broken_rule.path().join(MANIFEST_FILE).exists(),
        "nothing is written on failure"
    );

    let broken_hashes = bundle(&[], "not-a-hash\n", "");
    assert!(matches!(
        sign_dir(broken_hashes.path(), &signing, 1, 0),
        Err(DefsError::BadHashList { line: 1, .. })
    ));
}

#[test]
fn rejects_unexpected_files_and_folders_in_a_bundle() {
    let dir = standard_bundle();
    fs::write(dir.path().join("rules/notes.txt"), "hello").unwrap();
    assert!(matches!(
        Definitions::load(dir.path(), Trust::AllowUnsigned),
        Err(DefsError::BadPath(_))
    ));

    let dir = standard_bundle();
    fs::create_dir(dir.path().join("rules/nested")).unwrap();
    assert!(matches!(
        Definitions::load(dir.path(), Trust::AllowUnsigned),
        Err(DefsError::BadPath(_))
    ));
}

#[test]
fn rules_cannot_include_other_files() {
    let dir = bundle(
        &[(
            "inc.yar",
            "include \"/etc/passwd\"\nrule A { condition: true }",
        )],
        "",
        "",
    );
    assert!(matches!(
        Definitions::load(dir.path(), Trust::AllowUnsigned),
        Err(DefsError::Rules(_))
    ));
}
