use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use pshav_engine::{
    decode_signing_key, decode_verifying_key, encode_signing_key, encode_verifying_key,
    generate_keypair, sign_dir, Definitions, Engine, Limits, ScanReport, Trust, Verdict,
};
use walkdir::WalkDir;

const SIGNING_KEY_FILE: &str = "pshav-signing.key";
const PUBLIC_KEY_FILE: &str = "pshav-signing.pub";

#[derive(Parser)]
#[command(name = "pshav", version, about = "File scanner and definition tooling")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan files and folders
    ///
    /// Exit codes: 0 nothing found, 1 detections, 2 could not run,
    /// 3 nothing found but some content was skipped or unreadable.
    Scan {
        /// Files or folders to scan
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Definition bundle directory
        #[arg(long, default_value = "defs")]
        defs: PathBuf,
        /// Public key file. The bundle must carry a valid signature for it.
        #[arg(long, conflicts_with = "allow_unsigned")]
        pubkey: Option<PathBuf>,
        /// Load the bundle without checking a signature. Development only.
        #[arg(long)]
        allow_unsigned: bool,
        /// Print one JSON report per line instead of text
        #[arg(long)]
        json: bool,
        /// Also print files with nothing to report
        #[arg(long, short)]
        verbose: bool,
        /// Largest file whose content is scanned, in MiB
        #[arg(long)]
        max_file_mb: Option<u64>,
    },
    /// Create, sign, and check definition bundles
    Defs {
        #[command(subcommand)]
        command: DefsCommand,
    },
}

#[derive(Subcommand)]
enum DefsCommand {
    /// Generate an Ed25519 signing key pair
    Keygen {
        /// Directory to write the two key files into
        #[arg(long, default_value = ".")]
        out: PathBuf,
    },
    /// Write manifest.json and manifest.sig for a bundle directory
    Sign {
        dir: PathBuf,
        /// Private key file from `defs keygen`
        #[arg(long)]
        key: PathBuf,
        /// Bundle version. Must be higher than every earlier release.
        #[arg(long)]
        version: u64,
    },
    /// Check a bundle's signature and contents
    Verify {
        dir: PathBuf,
        #[arg(long)]
        pubkey: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Scan {
            paths,
            defs,
            pubkey,
            allow_unsigned,
            json,
            verbose,
            max_file_mb,
        } => scan(
            &paths,
            &defs,
            pubkey.as_deref(),
            allow_unsigned,
            json,
            verbose,
            max_file_mb,
        ),
        Command::Defs { command } => defs_command(command).map(|()| ExitCode::SUCCESS),
    };
    result.unwrap_or_else(|message| {
        eprintln!("error: {message}");
        ExitCode::from(2)
    })
}

fn load_definitions(
    dir: &Path,
    pubkey: Option<&Path>,
    allow_unsigned: bool,
) -> Result<Definitions, String> {
    let loaded = match (pubkey, allow_unsigned) {
        (Some(path), _) => {
            let text = fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
            let key = decode_verifying_key(&text).map_err(|e| e.to_string())?;
            Definitions::load(dir, Trust::Verify(&key))
        }
        (None, true) => Definitions::load(dir, Trust::AllowUnsigned),
        (None, false) => {
            return Err("pass --pubkey <file>, or --allow-unsigned for development".into())
        }
    };
    loaded.map_err(|e| format!("definitions in {}: {e}", dir.display()))
}

fn scan(
    paths: &[PathBuf],
    defs_dir: &Path,
    pubkey: Option<&Path>,
    allow_unsigned: bool,
    json: bool,
    verbose: bool,
    max_file_mb: Option<u64>,
) -> Result<ExitCode, String> {
    let defs = load_definitions(defs_dir, pubkey, allow_unsigned)?;
    let mut limits = Limits::default();
    if let Some(mb) = max_file_mb {
        limits.max_file_size = mb.saturating_mul(1024 * 1024);
    }
    let engine = Engine::new(defs, limits);
    if !json {
        let d = engine.definitions();
        eprintln!(
            "definitions v{} ({}): {} rules, {} blocked hashes, {} allowed hashes",
            d.version(),
            if d.is_signed() { "signed" } else { "UNSIGNED" },
            d.rule_count(),
            d.blocklist_len(),
            d.allowlist_len(),
        );
    }

    let mut totals = Totals::default();
    for root in paths {
        // Symlinks aren't followed, so a link can't pull the scan outside the tree.
        for entry in WalkDir::new(root).follow_links(false) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(e) => {
                    totals.errors += 1;
                    eprintln!("error: {e}");
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            match engine.scan_path(entry.path()) {
                Ok(report) => {
                    totals.add(&report);
                    print_report(&report, json, verbose);
                }
                Err(e) => {
                    totals.errors += 1;
                    eprintln!("error: {e}");
                }
            }
        }
    }

    if !json {
        eprintln!(
            "scanned {} files: {} malicious, {} suspicious, {} incomplete, {} errors",
            totals.files, totals.malicious, totals.suspicious, totals.incomplete, totals.errors
        );
    }
    Ok(if totals.malicious + totals.suspicious > 0 {
        ExitCode::from(1)
    } else if totals.incomplete + totals.errors > 0 {
        ExitCode::from(3)
    } else {
        ExitCode::SUCCESS
    })
}

#[derive(Default)]
struct Totals {
    files: u64,
    malicious: u64,
    suspicious: u64,
    incomplete: u64,
    errors: u64,
}

impl Totals {
    fn add(&mut self, report: &ScanReport) {
        self.files += 1;
        match report.verdict {
            Verdict::Malicious => self.malicious += 1,
            Verdict::Suspicious => self.suspicious += 1,
            Verdict::Clean => {}
        }
        if !report.complete {
            self.incomplete += 1;
        }
    }
}

fn print_report(report: &ScanReport, json: bool, verbose: bool) {
    if json {
        println!(
            "{}",
            serde_json::to_string(report).expect("reports serialize")
        );
        return;
    }
    let quiet = report.verdict == Verdict::Clean && report.complete;
    if quiet && !verbose {
        return;
    }
    let verdict = match report.verdict {
        Verdict::Malicious => "MALICIOUS",
        Verdict::Suspicious => "SUSPICIOUS",
        Verdict::Clean if report.allowlisted => "allowlisted",
        Verdict::Clean if !report.complete => "incomplete",
        Verdict::Clean => "clean",
    };
    println!("{verdict:<11} {}", report.path);
    for d in &report.detections {
        let at = if d.object.is_empty() {
            String::new()
        } else {
            format!(" in {}", d.object)
        };
        println!("            {:?}: {}{at}", d.layer, d.name);
    }
    for n in &report.notes {
        let at = if n.object.is_empty() {
            String::new()
        } else {
            format!(" at {}", n.object)
        };
        println!("            skipped: {:?}{at}", n.reason);
    }
}

fn defs_command(command: DefsCommand) -> Result<(), String> {
    match command {
        DefsCommand::Keygen { out } => {
            let private_path = out.join(SIGNING_KEY_FILE);
            let public_path = out.join(PUBLIC_KEY_FILE);
            let (signing, verifying) = generate_keypair();
            write_new(&private_path, &encode_signing_key(&signing), true)?;
            write_new(&public_path, &encode_verifying_key(&verifying), false)?;
            println!(
                "private key: {}  (keep offline, never commit)",
                private_path.display()
            );
            println!("public key:  {}", public_path.display());
            Ok(())
        }
        DefsCommand::Sign { dir, key, version } => {
            let text = fs::read_to_string(&key).map_err(|e| format!("{}: {e}", key.display()))?;
            let key = decode_signing_key(&text).map_err(|e| e.to_string())?;
            let created = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| e.to_string())?
                .as_secs();
            let manifest = sign_dir(&dir, &key, version, created).map_err(|e| e.to_string())?;
            println!(
                "signed v{} with {} files",
                manifest.version,
                manifest.files.len()
            );
            Ok(())
        }
        DefsCommand::Verify { dir, pubkey } => {
            let defs = load_definitions(&dir, Some(&pubkey), false)?;
            println!(
                "ok: v{}, {} rules, {} blocked hashes, {} allowed hashes",
                defs.version(),
                defs.rule_count(),
                defs.blocklist_len(),
                defs.allowlist_len()
            );
            Ok(())
        }
    }
}

/// Never overwrites: replacing a signing key by accident orphans every agent
/// that trusts the old public key.
fn write_new(path: &Path, content: &str, private: bool) -> Result<(), String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    #[cfg(not(unix))]
    let _ = private;
    let mut file = options
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    use std::io::Write;
    writeln!(file, "{content}").map_err(|e| format!("{}: {e}", path.display()))
}
