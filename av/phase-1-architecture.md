# Phase 1: architecture for the free build

Date: 2026-11-15
Scope: user-mode endpoint detection for Windows 10/11 and Android 10+, managed through Fleet Free, built from free parts only. See `DECISIONS.md` for what the free path removed.

## 1. What this product is

A detection and response layer that runs beside Microsoft Defender on Windows and beside Play Protect on Android.

- Defender and Play Protect keep doing kernel-level and store-level blocking.
- We add our own detections, script blocking through AMSI, quarantine, central reporting, and response actions.
- One console shows our detections and Defender's, linked to Fleet hosts.

It doesn't replace Defender. Without a signed kernel driver, nothing in user mode can stop a file from being opened or executed.

## 2. Components

```
Windows PC                                Server                      Admin
+--------------------------------+        +--------------------+      +---------+
| pshav-agent (service, SYSTEM)  |  TLS   | pshav-server       |      | Console |
|  - watchers: USN journal, dirs |<------>|  - ingest API      |<---->| (web)   |
|  - ETW process events          |        |  - detections DB   |      +---------+
|  - Defender event log reader   |        |  - definitions     |
|  - quarantine, response        |        |  - response queue  |
|        | named pipe            |        +---------+----------+
|  pshav-scand (low privilege)   |                  | REST
|  - pshav-engine                |        +---------v----------+
|  pshav-amsi.dll (in host apps) |        | Fleet Free         |
+--------------------------------+        |  - inventory, MDM  |
                                          |  - scripts, policy |
Android phone                             +--------------------+
+--------------------------------+
| pshav app (Kotlin)             |
|  - APK and storage scans       |----> pshav-server ingest API
|  - DNS filter, posture         |
+--------------------------------+
```

| Component | Language | Runs as | Job |
|---|---|---|---|
| `pshav-engine` | Rust library | In the scan worker | File typing, hashing, hash lists, YARA-X, bounded unpacking, verdicts |
| `pshav` CLI | Rust | User | On-demand scans, definition signing and verification |
| `pshav-scand` | Rust | Low-privilege account, job object, no network | Hosts the engine. Parses hostile input, so it holds no privileges. |
| `pshav-agent` | Rust | LocalSystem service | Collects events, asks the worker for verdicts, quarantines, talks to the server |
| `pshav-amsi.dll` | Rust, COM | Inside PowerShell, WSH, Office, .NET hosts | Sends script content to the worker, returns block or allow |
| `pshav-server` | Rust (axum), PostgreSQL | Linux host | Ingest, detections, definitions, response queue, console API |
| Console | Server-rendered web UI | Browser | Detections, host view, response, rule bundles, audit log |
| Android app | Kotlin, engine through JNI later | App sandbox | APK and storage scans, DNS filter, posture, reporting |

## 3. Windows event flow

1. **File written.** The agent reads the NTFS change journal for every fixed volume and watches hot folders (Downloads, Desktop, Temp, AppData, Startup, removable drives) for faster pickup.
2. **Debounce.** The agent waits for the file handle to close, then sends the path to the worker.
3. **Verdict.** The worker runs the engine and replies with a report.
4. **Action.** On `malicious`: move the file to quarantine, record original path and hash, notify the server. On `suspicious`: report only.
5. **Process started.** An ETW session on the kernel process provider reports new processes. The agent checks the image hash against the verdict cache. If malicious, it ends the process tree and quarantines the image.
6. **Script executed.** The AMSI provider gets the content before it runs and can block it.
7. **Defender detections.** The agent reads event IDs 1116 and 1117 from Defender's operational log and forwards them, tagged `source: defender`.

Race to be clear about: steps 1 to 5 react after the write or the launch. A fast payload can run before we act. Defender covers that gap. AMSI is the one place we block inline.

## 4. Engine

Detection layers, in order. The first decisive layer wins.

| # | Layer | Status |
|---|---|---|
| 1 | Allowlist by SHA-256 | Built |
| 2 | Blocklist by SHA-256 | Built |
| 3 | YARA-X rules | Built |
| 4 | Container unpacking, then layers 1 to 3 on each child | ZIP family and gzip built. Tar, 7z, RAR, CAB, MSI, ISO, OLE pending. |
| 5 | Signer trust (Authenticode) | Phase 3 |
| 6 | Fuzzy hashes (TLSH, imphash) | Phase 5 |
| 7 | Static ML on PE features | Phase 8 |
| 8 | Optional ClamAV through `clamd` | Phase 5, separate process because of GPL |
| 9 | Server reputation lookup | Phase 6 |

Rules for every layer:

- Bounded: file size, depth, entry count, total unpacked bytes, compression ratio, and YARA time are all capped.
- Honest: when a cap stops a scan, the report says `complete: false` with the reason. A capped scan never reports `clean` silently.
- No `unsafe` in our code without a written reason next to it.

## 5. Definitions

A definition bundle is a directory:

```
manifest.json     version, created time, and SHA-256 of every file
manifest.sig      Ed25519 signature over the exact bytes of manifest.json
rules/*.yar       YARA-X rules
hashes/block.sha256
hashes/allow.sha256
```

- The agent holds the public key. It verifies the signature, then every file hash, and refuses files the manifest doesn't list.
- The private key lives offline with whoever builds definitions.
- Unsigned bundles load only with an explicit development flag.
- Version numbers only go up. The agent rejects a bundle older than the one it runs, to stop rollback attacks. (Agent side, Phase 3.)
- Delta updates come later. Bundles are small while rules are few.

YARA rule metadata we read: `verdict` (`malicious` or `suspicious`, default `malicious`) and `name` (detection name, default is the rule identifier).

## 6. Data model (server)

| Table | Key fields |
|---|---|
| `hosts` | id, fleet_host_id, platform, hostname, agent_version, defs_version, last_seen |
| `detections` | id, host_id, time, source (`engine`, `amsi`, `defender`, `android`), layer, name, verdict, sha256, path, container_path, process, user, status |
| `quarantine_items` | id, host_id, detection_id, sha256, original_path, size, state |
| `actions` | id, host_id, kind (`quarantine`, `restore`, `delete`, `scan`, `kill`), requested_by, state, result |
| `definition_bundles` | version, created, sha256, ring, state |
| `audit_log` | id, time, actor, action, target |

File contents never leave the endpoint in this phase. The server stores paths, hashes, and rule names.

## 7. IPC and protocols

| Link | Transport | Auth |
|---|---|---|
| agent to worker | Named pipe, length-prefixed JSON | Pipe ACL limited to the service SID |
| AMSI DLL to worker | Named pipe, same framing, 200 ms budget, fail open | Pipe ACL allows authenticated users to write requests only |
| agent to server | HTTPS, JSON | Per-host token issued at enrollment, pinned server certificate |
| Android to server | HTTPS, JSON | Per-device token |
| server to Fleet | Fleet REST API | API-only user token |
| response actions | Agent polls the server's action queue | Same host token |

Fail-open rule: if the worker is down or slow, the agent and the AMSI provider allow the operation and log the miss. The PC keeps working.

## 8. Fleet integration (Free tier)

- **Deploy:** Fleet installs the agent as a software package or through a script.
- **Health:** an osquery extension table `pshav_status` (agent version, definitions version, last scan, worker state). A Fleet policy fails when the agent is missing or stale, and a policy automation webhook tells our server.
- **Defender posture:** Fleet policies check that Defender is on and signatures are fresh.
- **Host link:** the agent reports the osquery host UUID, and the server maps it to the Fleet host ID through the API.
- **Response fallback:** Fleet's run-script can restart or reinstall an agent that stopped.
- **Tenancy:** Fleet Free has no per-group separation. One Fleet server and one pshav server per organization.

## 9. Threat model

| Threat | Mitigation |
|---|---|
| Malicious file exploits a parser | Worker runs unprivileged, no network, in a job object. Memory-safe code, fuzzing, hard limits. A crash restarts the worker. |
| Attacker with admin rights stops the agent | We can't prevent it without PPL. Fleet policy plus server heartbeat alert within minutes. |
| Tampered or rolled-back definitions | Ed25519 signature, per-file hashes, monotonic version. |
| Fake server or stolen host token | Pinned certificate, per-host tokens, revocation on the server. |
| Malicious admin of the console | Roles, audit log, restore and delete need the higher role. |
| Bad definition quarantines good files | Clean-corpus test before release, rollout rings, restore action, kill switch per rule. |
| Quarantine store abused to stash files | Store is ACL-locked and files are XOR-wrapped so nothing in it executes. |
| Our AMSI DLL crashes a host process | Tiny DLL, no parsing inside it, timeouts, fail open. |

Out of scope by design: kernel-mode malware, bootkits, attackers who already hold SYSTEM.

## 10. Test strategy

| Level | What | Where |
|---|---|---|
| Unit and integration | Engine layers, limits, definition verification | `cargo test`, runs anywhere |
| Fuzzing | Unpackers and the definition loader, `cargo-fuzz` | CI, nightly |
| Windows integration | Agent, worker, AMSI, quarantine on real Windows | Needs a Windows runner or VM. I can't run Windows here. |
| Detection measurement | Recent public samples in an isolated lab, never in the repo | Lab VM only |
| False positive measurement | A clean Windows install plus common apps | Lab VM |
| Performance | File copy, app launch, build benchmark, with Defender on | Lab VM |
| Safe test content | EICAR, built at runtime in tests so no test string sits in the repo | Everywhere |

Each release reports measured detection rate, false positives per 100,000 clean files, and benchmark deltas. No targets are promised until we have a first measurement.

## 11. Open items for later phases

- Verify the WDAC hash-deny route through Fleet's Windows MDM profiles.
- Review the licence of every open YARA rule set before bundling it.
- Decide whether to ship ClamAV integration on by default.
- Pick the Windows CI route: GitHub Actions on a public repo is free.
