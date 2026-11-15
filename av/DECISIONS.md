# Decisions

Newest first. Each entry says who decided and what it changes.

## 2026-11-15: free path, full build

**Decided by:** Pasha, after reading `phase-0-research.md`.

**Decision:** No licensed engine and no paid programs. Everything is built here from free and open source parts.

**What this removes from the original spec**

| Spec item | Why it's out |
|---|---|
| Kernel minifilter, WFP callout, kernel callbacks | Windows loads only Microsoft-signed drivers. Signing needs an EV certificate, a Partner Center account, and an HLK lab. |
| ELAM driver, antimalware PPL service, Windows Security Center registration | All three need Microsoft Virus Initiative membership, which needs a paid lab certification and an eligible legal entity. |
| Third-party lab certification (AV-TEST, AV-Comparatives) | Paid. |
| Detection targets of 99% and 95%, false positives under 1 per 100,000 | These came from commercial engines with research teams and telemetry. We'll measure and publish our own numbers instead of promising these. |
| Licensed OEM engine | Rejected. |

**What replaces it**

| Need | Free replacement | Limit |
|---|---|---|
| Block files before they run | Microsoft Defender stays on. Candidate: push hash deny rules through App Control (WDAC) policy from Fleet. Not verified yet. | Our own file detections act after the write, by quarantine. |
| Block scripts inline | Our AMSI provider DLL | Loads in normal processes. Some protected processes may reject it. |
| Process and file telemetry | ETW, the NTFS change journal, directory watchers. Sysmon if the admin installs it. | User mode sees events after they happen. |
| Tamper protection | Service hardening plus a Fleet policy that alerts when the agent stops | An attacker with admin rights can stop the agent. |
| Signature breadth | Our YARA-X rules, open rule sets with compatible licences, hash feeds, optional ClamAV as a separate process | Lower than commercial engines. |
| Code signing | Self-signed certificate, with its root pushed to managed PCs through Fleet MDM | Unmanaged PCs show SmartScreen warnings. |
| Android distribution | Sideloaded APK, or a free limited-distribution developer account | Managed Google Play needs a one-time USD 25 Play Console fee, and Fleet deploys custom apps only on Premium. |

**Defaults I picked, change any of them**

- Licence for our code: MIT, matching the fork's root `LICENSE`.
- Code lives in `av/` on this fork until a separate repo exists.
- Fleet tier: Free.
- Language: Rust for engine, agent, and server. Kotlin for Android.

**Revised phases**

1. Architecture for the free build. Done: `phase-1-architecture.md`.
2. Scan engine core. Started: `crates/engine`, `crates/cli`.
3. Windows user-mode agent: service, on-demand and scheduled scans, quarantine, file and process watchers.
4. AMSI provider and Defender event ingestion.
5. Behavior rules and ransomware canaries. Rollback stays out until we have a safe design without a filter driver.
6. Server, console, Fleet integration, rollout rings.
7. Android app.
8. Static ML model trained on EMBER2024 features.
9. Hardening, measured detection and false positive report.
