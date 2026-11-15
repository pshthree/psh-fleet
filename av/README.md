# pshav

A free, open source endpoint detection layer for Windows and Android, managed through Fleet. It runs beside Microsoft Defender and Play Protect and adds its own detections, quarantine, and central reporting.

Status: early. The scan engine core and a command-line scanner work. No agent, server, or Android app yet.

## What's here

| Path | What |
|---|---|
| `DECISIONS.md` | Why this is the free, user-mode design, and what that rules out |
| `phase-0-research.md` | Microsoft, Google, and Fleet requirements, with sources |
| `phase-1-architecture.md` | Components, event flow, definitions format, threat model, test strategy |
| `crates/engine` | Scan engine library |
| `crates/cli` | `pshav` command-line scanner and definition tooling |
| `defs/` | Starter definition bundle. Holds one rule: the EICAR test file. |

## Build and test

Needs Rust 1.95 or later.

```sh
cd av
cargo test
cargo build --release
```

## Scan something

```sh
# Development: load the unsigned bundle in this repo
./target/release/pshav scan ~/Downloads --defs defs --allow-unsigned

# JSON, one report per line
./target/release/pshav scan ~/Downloads --defs defs --allow-unsigned --json
```

Exit codes: `0` nothing found, `1` detections, `2` couldn't run, `3` nothing found but some content was skipped or unreadable.

## Sign a definition bundle

```sh
pshav defs keygen --out ~/keys            # once. Keep the .key file offline.
pshav defs sign defs --key ~/keys/pshav-signing.key --version 1
pshav defs verify defs --pubkey ~/keys/pshav-signing.pub
pshav scan ~/Downloads --defs defs --pubkey ~/keys/pshav-signing.pub
```

With `--pubkey`, the scanner refuses a bundle whose signature, file hashes, or file list don't match.

## Writing definitions

- `rules/*.yar`: YARA-X rules. Optional metadata: `name` sets the detection name, `verdict = "suspicious"` reports without treating the file as malicious.
- `hashes/block*.sha256`: one SHA-256 per line, then an optional detection name.
- `hashes/allow*.sha256`: one SHA-256 per line. An allowed file isn't scanned further.

## What the engine does today

- Types files by magic bytes, never by extension.
- Checks SHA-256 against allow and block lists.
- Runs YARA-X rules with a time budget.
- Unpacks ZIP-family archives and gzip, recursively, and finds ZIPs hidden behind other leading bytes.
- Caps file size, nesting depth, entry count, total unpacked bytes, and compression ratio.
- Says `complete: false` with a reason whenever a cap, an encrypted entry, or a corrupt archive kept it from reading something.

## What it doesn't do yet

- Detect real malware. The bundle holds only the EICAR test rule.
- Unpack tar, 7z, RAR, CAB, MSI, ISO, or OLE documents.
- Check Authenticode signatures, fuzzy hashes, or a machine learning model.
- Run on Windows as a service, watch files, or quarantine anything.
- Fuzz testing. The parsers come from the `zip`, `flate2`, and `yara-x` crates, and our own fuzz targets aren't written.
