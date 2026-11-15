# Phase 0: research report

Date: 2026-11-15
Fleet commit read: `058c60e` (fork of fleetdm/fleet, main)
Status: waiting for approval. No product code exists yet.

## Reading I took

- "Phase 0" means research only: Microsoft and Google requirements, engine build-versus-license, risks. I stopped there.
- Where the spec and a platform rule disagree, I report the rule and propose the closest workable option.
- Prices are missing throughout. No vendor or lab publishes them. Section 9 lists everything I couldn't verify.

## 1. Bottom line

1. **The spec can't ship in the order written.** ELAM, the antimalware PPL service, and Windows Security Center registration all require Microsoft Virus Initiative (MVI) membership. MVI requires a commercially available product with real-time protection that an independent lab certified in the last 12 months. Version 1 has to ship without those three features, pass a lab test, then apply.
2. **MVI also requires Microsoft's Artifact Signing service** (formerly Trusted Signing). Microsoft limits it to organizations in a short list of countries. A company registered outside that list can't meet this requirement without a legal entity inside it.
3. **Production kernel drivers need WHCP signing**, which means passing HLK tests. Microsoft documents attestation signing as "for testing purposes only". Both paths need an EV certificate on a Partner Center account.
4. **Microsoft's user-mode platform isn't usable yet.** It's in private preview for MVI partners. An October 2026 teardown of the preview binaries found notify-only process events with no way to block. We still need our own minifilter for now.
5. **Android is feasible within limits.** Google lists antivirus as a permitted use for every restricted permission we need. Each one needs a Play Console declaration. Real-time interception of other apps isn't possible on Android.
6. **Fleet adds three constraints.** Its Android MDM runs through a proxy at fleetdm.com. Custom Android app deployment, fully managed Android, RBAC, and per-tenant grouping are Premium. Windows real-time events aren't available from osquery.
7. **Engine: I recommend licensing for version 1.** A public benchmark model reaches 94.48% detection at a 1% false positive rate. Our target is under 0.001%. I can't defend a plan that closes a 1,000x gap with a new engine.

## 2. Microsoft requirements

### 2.1 What each capability depends on

| Capability | Gate | Available before MVI? |
|---|---|---|
| Minifilter altitude | Email request to Microsoft. Anti-virus group is 320000 to 329999. Allow 30 business days. | Yes |
| Kernel driver loads on customer PCs | EV certificate registered in Partner Center, then Microsoft signs the driver. Attestation is documented as test-only, works on Windows 10 desktop and later, and can't go to retail Windows Update. Windows Server 2016 and later load only HLK-passed drivers. | Yes, with an HLK lab |
| ELAM driver | MVI membership. The WHQL submission fails for non-members. | No |
| Antimalware PPL service | An installed ELAM driver that carries the hashes of our signing certificates. | No |
| Windows Security Center registration | Private API, callable only by MVI members under NDA. | No |
| AMSI provider | Public. In-process COM DLL registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers`. | Yes, with a caveat below |
| WFP callout driver | Same signing path as any kernel driver. | Yes |
| ETW Threat Intelligence | I believe this needs antimalware PPL. Not verified in this pass. | Probably no |

AMSI caveat: since Windows 10 1903 an optional registry setting enforces Authenticode checks on providers. Microsoft's docs also list a known issue where a provider DLL fails to load into protected processes because it doesn't meet the antimalware signing level. Before MVI, expect our provider to load in normal processes and be rejected by some protected ones.

### 2.2 MVI membership criteria

Source: Microsoft Learn, page last updated 2026-09-10. All eight must be met.

1. A commercially available security product with real-time protection that detects, prevents, and remediates malware.
2. Your organization develops and distributes its own Windows compatibility updates.
3. A positive industry reputation, shown through conferences, industry membership, or reviews such as AV-Comparatives, OPSWAT, or Gartner.
4. A signed NDA.
5. A signed program license agreement.
6. Active participation in the program.
7. Use of Trusted Signing (now Artifact Signing).
8. Certification in the last 12 months by one listed lab, renewed yearly.

| Lab | Test | Minimum |
|---|---|---|
| AV-Comparatives | Real-World Protection or Malware Protection Test | Certified, Approved, or Standard |
| AVLab | Advanced In-The-Wild Malware Test | Excellent (99.6%) |
| AV-TEST | Real-World Protection test for MVI, or Home/Enterprise certification | 97%, or Certified, or Approved |
| MRG Effitas | 360 Assessment and Certification | Level 2 |
| SE Labs | Endpoint Security or Enterprise Advanced Security | AAA |
| SKD Labs | Starcheck real-time protection and cleaning | Starcheck Certified |
| VB100 | VB100 | 95% detection, Grade B or higher |
| West Coast Labs | WCL Validated, detection and remediation | Product Rating A |

Microsoft reviews applications monthly and doesn't accept every applicant.

### 2.3 Artifact Signing eligibility

- Microsoft Learn's current code signing page lists organizations in the USA, Canada, the EU, and the UK. Individual developers: USA and Canada only.
- Two third-party write-ups from autumn 2026 list 12 countries and regions, adding Japan, Australia, New Zealand, South Korea, Singapore, Switzerland, Norway, and Israel.
- Sources disagree on whether the three-year business history rule still applies after general availability.
- If the company sits outside every list, plan for a subsidiary or parent in an eligible country. This also affects who holds the EV certificate and the Partner Center account.

### 2.4 Kernel trust policy, April 2026

Trade press reports that Windows 11 24H2, 25H2, 26H1 and Windows Server 2025 now trust only WHCP-signed drivers or drivers on a Microsoft allow list by default, and that the old cross-signed program is no longer trusted. I found this in secondary sources only. Confidence: medium. It doesn't change our plan, since we'd use WHCP anyway.

### 2.5 Windows Resiliency Initiative and the user-mode platform

- June 2025: Microsoft announced a private preview of the "Windows endpoint security platform" for a set of MVI partners, so they can build products that run outside the kernel.
- A Microsoft spokesperson told CSO the preview is "not an announcement of future plans for kernel access".
- October 2026: Elastic Security Labs examined two preview binaries in Insider builds. `wesp.sys` is a Microsoft minifilter at altitude 329500. `espclient.dll` is the user-mode API. The client imports no reply function, so it can observe process creation and can't veto it.

What this means for us: no public API, MVI-gated access, and no blocking in the preview. Build the minifilter. Keep the kernel-to-user protocol narrow so a later swap to Microsoft's driver changes one module.

### 2.6 Consequence: two stages

**Stage A, before MVI**

- User-mode service, minifilter (WHCP), WFP callout, AMSI provider, console.
- No ELAM, no PPL, no Security Center registration.
- Self-protection comes from our driver's object callbacks. That stops ordinary tampering and won't stop an attacker with a kernel exploit or a vulnerable signed driver.
- Defender stays active, because only a registered product puts it into passive mode. Two products scan every file. This threatens the 10% slowdown target and needs measuring early.

**Stage B, after MVI**

- ELAM, PPL service, Security Center registration, ETW Threat Intelligence.
- Access to the user-mode platform preview, if Microsoft admits us.

Getting from A to B needs: a shipping product, one lab certification, an eligible legal entity, and Microsoft's approval.

## 3. Google requirements

| Need | Rule | Verdict |
|---|---|---|
| Scan shared storage | All-files access. Permitted uses include anti-virus apps. Needs a Permissions Declaration Form and approval. Private managed Google Play apps may request it for the same uses. | Allowed with declaration |
| List installed apps | `QUERY_ALL_PACKAGES`. Permitted uses include antivirus apps. Needs a declaration. | Allowed with declaration |
| DNS and web filtering | `VpnService`. Device security apps, including anti-virus and firewall, are a permitted category. Needs a declaration and a separate prominent disclosure. | Allowed with declaration |
| Accessibility service | Allowed for non-accessibility tools with declaration and disclosure. Android's Advanced Protection Mode is testing a block on such apps. AMAPI also forbids Device Trust signals in apps that use it. | Avoid |
| Play Protect state | Play Integrity API returns `playProtectVerdict`: `NO_ISSUES`, `NO_DATA`, `POSSIBLE_RISK` (Play Protect off), `MEDIUM_RISK`, `HIGH_RISK`, `UNEVALUATED`. Default quota is 10,000 requests per app per day. | Available |
| Install on devices | Developer verification has been enforced since 2026-09-30 in Brazil, Indonesia, Singapore, and Thailand, with global rollout planned for 2027. Unverified apps still install through ADB or a high-friction advanced flow. | Register as a verified developer |

**Android Management API (AMAPI)**

- Restricted to commercial EMM developers and Device Trust providers. Google's definition of Device Trust providers includes mobile threat defense and EDR vendors.
- Requires direct agreements with end customers.
- A quota of up to 500 devices needs a business justification. More than 500 needs an application to Android Enterprise.

**What the sandbox prevents**

- Reading another app's private data.
- Intercepting another app's file or network activity at the OS level. The local VPN sees traffic only.
- Blocking or removing another app from inside our app. That action has to go through MDM policy.

So on Android "real-time protection" means: scan on install and update, scan shared storage when files appear, filter DNS, and report posture. I'll say that plainly in the product.

## 4. Fleet facts, read from this fork

**Licence**

- Core is MIT. `ee/` is under the Fleet EE licence, which needs a paid subscription for production use. `docs/` is CC BY-SA 4.0.
- The root `LICENSE` says content outside `ee/` and `docs/` is MIT. New code we add here inherits that unless we add our own licence notice.
- This fork is public.

**Free versus Premium** (from `handbook/company/pricing-features-table.yml`)

| Free | Premium |
|---|---|
| REST API, webhooks, GitOps | Fleets (per-group separation of hosts) |
| Script execution, run-script policy automation | Role-based access control |
| YARA malware detection | Audit logging |
| Enforce OS settings, multi-platform MDM | Fully managed (company-owned) Android |
| Android BYOD work profiles | Custom Android app deployment |
| Custom logging, reports | Lock and wipe commands, zero-touch setup |

"Multi-tenant from day one" doesn't fit Fleet Free, because fleets and RBAC are Premium. Options: one Fleet server per tenant, or Fleet Premium.

**Windows event sources in osquery**

- `yara_events`, `file_events`, and `process_events` are macOS and Linux only.
- On Windows, YARA runs on demand through `yara_file` and `yara_process`. Evented tables are `ntfs_journal_events` and `process_etw_events`.
- Real-time detection on Windows has to come from our agent. Fleet is the inventory, policy, and response channel.

**Android MDM**

- Fleet calls Google through a proxy at `https://fleetdm.com/api/android/`, which holds Fleet's Google Cloud credentials. Fleet's own guide says there's no failover: if fleetdm.com is unreachable, new enrollments and admin actions fail.
- A direct Google client exists behind `FLEET_DEV_ANDROID_GOOGLE_CLIENT`, a development flag.
- A commercial product either depends on fleetdm.com for every Android admin action or gets its own AMAPI approval from Google.
- Custom apps go out as private managed Google Play apps. Fleet's guide notes Google now needs `.aab` bundles for new packages.
- Fleet ships its own Android agent in `android/`. It starts through the companion-app role and wakes every 15 minutes with WorkManager. It's a useful reference for our app's lifecycle.

## 5. Engine: build versus license

| | A. Build | B. License an OEM SDK | C. Hybrid |
|---|---|---|---|
| File verdicts | Our parsers, signatures, ML, emulator | Vendor engine and signatures | Vendor engine |
| Our own layers | Everything | Thin wrapper | YARA-X rules, behavior engine, ransomware rollback, console |
| Detection on day one | Low | Commercial grade | Commercial grade |
| Signature research team | Required | Vendor's | Vendor's, plus our rules |
| Lab certification odds | Poor | Good | Good |
| Cost | Salaries for years | Per-seat or flat licence, unknown | Licence plus a smaller team |
| Lock-in | None | High | Medium, behind an engine interface |

**Evidence**

- EMBER2024, a 3.2 million file public benchmark, reports its LightGBM model at 94.48% detection at a 1% false positive rate on the test set, with a large drop on the evasive challenge set. A 1% rate is 1,000 false positives per 100,000 clean files. Our target is under 1.
- ClamAV is GPL-2.0-only, so we can't link it into a proprietary engine. A 2022 Splunk study of about 400,000 samples measured 59.94% detection on commodity malware.
- YARA-X reached stable 1.0 in June 2025 and classic YARA is in maintenance mode. YARA-X fits the spec's Rust engine.
- Bitdefender licenses SDKs to more than 150 vendors, including an Antimalware SDK, an Endpoint SDK for Windows, Linux and macOS on x86_64 and ARM64, and a Mobile Security SDK. Sophos sells an Anti-malware SDK that covers Android. Datto AV ships an AMSI provider signed by Avira, which shows a licensed engine inside another vendor's product.

**Recommendation: C, hybrid.** Put a narrow engine interface in the scan worker. Version 1 plugs in a licensed engine. Our YARA-X layer, behavior rules, and cloud lookups run beside it. The emulator and ML model from Phase 8 become optional research, started only if you want to replace the licensed engine later.

**Sample data**

- MalwareBazaar's terms changed. Since 2025-11-04, commercial or for-profit use of MalwareBazaar, URLhaus, and ThreatFox may require a paid subscription through Spamhaus, unless the user contributes consistently for six months. The spec assumes free use. Budget for it or plan to contribute.
- EMBER2024 ships hashes, feature vectors, and labels, with an Apache-2.0 tag on its dataset card. It doesn't ship the full sample files.
- I didn't check VirusShare's terms.

## 6. Can the success targets be met?

| Target | Verdict |
|---|---|
| 99% prevalent, 95% zero-day | Reachable with a licensed engine plus cloud lookups. I don't see a path with a new engine in version 1. |
| Under 1 false positive per 100,000 clean files | Same answer. This is the hardest number in the spec. |
| Under 10% slowdown, 200 MB idle | Plausible in Stage B. In Stage A we run beside Defender, so measure in Phase 4 before promising it. |
| Zero boot failures | A design goal we test for, with fail-open scanning, no boot-start driver in Stage A, staged rollout, and a kill switch. Testing can't prove zero. |

## 7. Risks

| # | Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| 1 | MVI needs a shipped, lab-certified product first. Stage B slips by a year or more. | High | High | Plan Stage A as a complete product. Pick the lab early. |
| 2 | Legal entity isn't eligible for Artifact Signing. | Depends on country | High | Decide the entity before buying certificates. |
| 3 | A kernel bug bluescreens customers. | Medium | Severe | Experienced Windows kernel engineer reviews every change. Driver Verifier, HLK, fail-open, no boot-start in Stage A. |
| 4 | Microsoft moves AV out of the kernel and our driver becomes dead weight. | Medium | Medium | Thin driver, narrow protocol, swap-ready. |
| 5 | Our own engine detects poorly. | High if built | High | License for version 1. |
| 6 | A false positive quarantines OS or popular app files. | Medium | Severe | Clean-corpus gate, signer allowlist, rollout rings, kill switch. |
| 7 | Running beside Defender in Stage A causes slowdowns and conflicts. | High | Medium | Measure early. Document exclusions. Ask a lab how they'd test this setup. |
| 8 | Fleet dependencies: Android proxy, Premium gating, EE licence, upstream drift across 20,928 files. | High | Medium | Keep Fleet changes minimal. Integrate through the API. |
| 9 | Google approvals: AMAPI quota, Play declarations, developer verification. | Medium | Medium | Apply early. Avoid the accessibility API. |
| 10 | The agent is an attack surface: parsers on hostile input inside a SYSTEM service. | Medium | Severe | Sandboxed scan worker, memory-safe parsers, fuzzing, signed updates. |
| 11 | Scope exceeds the team. This is multi-year work for several specialists. | High | High | Cut version 1 to Stage A with a licensed engine. |
| 12 | Public fork exposes the design and puts new code under MIT by default. | Certain today | Medium | Move product code to a private repo. |
| 13 | Sample feeds need commercial licences. | Medium | Low | Budget or contribute. |

## 8. Recommended changes to the plan

1. Split Windows into Stage A and Stage B as in section 2.6. Move ELAM, PPL, and Security Center registration out of Phases 3 to 5 and into a post-MVI phase.
2. Add a certification track: choose a lab in Phase 1, run a private test once real-time protection works, apply to MVI after the first pass.
3. Use a licensed engine behind an interface. Keep Phase 2 for parsers we need ourselves (YARA-X integration, hashing, archive limits, fuzzing). Make the emulator and ML model optional.
4. Use this fork only for Fleet configuration and any small integration changes. Put the agent, driver, engine, and console in a private repo.
5. Scope Android to what the sandbox allows, with no accessibility service.
6. Hire or contract a Windows kernel engineer before Phase 4 starts. I can write driver code, and I shouldn't be its only reviewer.

## 9. Not verified

- Prices: OEM engine licences, lab fees, EV certificates, Spamhaus subscription.
- The April 2026 kernel trust policy from a Microsoft primary source.
- Whether ETW Threat Intelligence strictly needs antimalware PPL.
- The HLK test list for file system filter drivers.
- Whether MVI accepts products built on a licensed engine. Existing OEM-based products suggest yes.
- How labs test a product that can't put Defender into passive mode.
- AMAPI's app-blocking policy fields, YARA-X's licence text, VirusShare's terms.
- I read Microsoft's driver signing requirements through search excerpts of the page, including a localized copy. A direct fetch of the English page didn't complete.

## 10. Decisions I need from you

1. **Engine:** hybrid with a licensed engine (my recommendation), full build, or pure OEM.
2. **Legal entity:** which country will hold the certificates, Partner Center account, and MVI application?
3. **Repos:** approve a private repo for product code, and tell me the licence you want on it.
4. **Fleet tier:** Free or Premium. This decides tenant separation and Android deployment.
5. **Android MDM path:** depend on the fleetdm.com proxy, or apply to Google for our own AMAPI access.
6. **People and budget:** a kernel engineer, an HLK lab, lab certification fees.
7. **First customers:** who they are and how many devices. This sizes the AMAPI quota and the tenancy model.

## Sources

Microsoft
- [Microsoft Virus Initiative criteria](https://learn.microsoft.com/en-us/defender-xdr/virus-initiative-criteria)
- [ELAM prerequisites](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/elam-prerequisites)
- [Protecting anti-malware services](https://learn.microsoft.com/en-us/windows/desktop/Services/protecting-anti-malware-services-)
- [Driver code signing requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/dashboard/code-signing-reqs)
- [Load order groups and altitudes for minifilter drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers)
- [Minifilter altitude request](https://learn.microsoft.com/en-in/windows-hardware/drivers/ifs/minifilter-altitude-request)
- [IAntimalwareProvider interface](https://learn.microsoft.com/en-us/windows/win32/api/amsi/nn-amsi-iantimalwareprovider)
- [AMSI developer audience and known issues](https://learn.microsoft.com/en-us/windows/win32/amsi/dev-audience)
- [Code signing options for Windows app developers](https://learn.microsoft.com/en-us/windows/apps/package-and-deploy/code-signing-options)
- [The Windows Resiliency Initiative, June 2025](https://blogs.windows.com/windowsexperience/2025/06/26/the-windows-resiliency-initiative-building-resilience-for-a-future-ready-enterprise/)
- [The Windows Security App, Eric Lawrence](https://textslashplain.com/2026/08/31/the-windows-security-app/)
- [Elastic Security Labs: inside wesp.sys](https://www.elastic.co/security-labs/blog/windows-endpoint-security-platform-wesp)
- [CSO: Microsoft hints at revoking kernel access](https://www.csoonline.com/article/4014241/microsoft-hints-at-revoking-access-to-the-windows-kernel-eventually.html)
- [April 2026 kernel driver trust change, WindowsForum](https://windowsforum.com/news/april-2026-windows-update-ends-cross-signed-kernel-driver-trust.410487/)
- [Artifact Signing eligibility write-up, note.com](https://note.com/mahamo/n/n0dd9377d1357?hl=en)
- [Artifact Signing versus CA certificates, My-SSL](https://my-ssl.com/learn/azure-trusted-signing-vs-code-signing-certificate)

Google
- [All files access policy](https://support.google.com/googleplay/android-developer/answer/10467955)
- [QUERY_ALL_PACKAGES policy](https://support.google.com/googleplay/android-developer/answer/10158779?hl=en-GB)
- [VpnService policy](https://support.google.com/googleplay/android-developer/answer/12564964?hl=en)
- [AccessibilityService API policy](https://support.google.com/googleplay/android-developer/answer/10964491?hl=en)
- [Android Authority: Advanced Protection Mode and accessibility](https://www.androidauthority.com/p-3640742/)
- [Play Integrity and Play Protect signal](https://developer.android.com/security/fraud-prevention/environment)
- [Android developer verification](https://developer.android.com/developer-verification)
- [Android developer verification timeline, June 2026](https://android-developers.googleblog.com/2026/06/android-developer-verification.html)
- [Android Management API permissible usage](https://developers.google.com/android/management/permissible-usage?authuser=0)

Engine and data
- [EMBER2024 paper](https://arxiv.org/abs/2506.05074)
- [EMBER2024 dataset card](https://huggingface.co/datasets/joyce8/EMBER2024/blob/main/README.md)
- [EMBER2024 benchmark figures cited in arXiv 2605.25937](https://arxiv.org/pdf/2605.25937)
- [ClamAV licence and third-party components](https://cdn.jsdelivr.net/gh/cisco-talos/clamav@main/README.md)
- [TechSpot on ClamAV 1.0 and the Splunk study](https://www.techspot.com/community/topics/open-source-antivirus-clamav-finally-goes-1-0-some-20-years-after-launch.278140/)
- [YARA-X is stable](https://virustotal.github.io/yara-x/blog/yara-x-is-stable)
- [Bitdefender technology licensing](https://download.bitdefender.com/resources/media/materials/2019/pan/en/Bitdefender-OEM-PartnerWithUs-crea1834-en_EN-interactive.pdf)
- [Bitdefender Endpoint SDK datasheet](https://bitdefender.com/content/dam/bitdefender/oem/Bitdefender-OEM-ENDP_SDK-datasheet-creat7898-en_EN-interactive-2.pdf)
- [Sophos Anti-malware SDK](https://Sophos.Com/en-us/oem/antivirus)
- [Datto AV AMSI provider signed by Avira](https://edr.datto.com/help/Content/03-deploying-managing-datto-endpoint-security-agent/managing-agent/understanding-av-audit-logs.htm)
- [abuse.ch terms of use](https://abuse.ch/terms-of-use/)

Fleet, read from this repository
- `LICENSE`, `ee/LICENSE`
- `handbook/company/pricing-features-table.yml`
- `schema/osquery_fleet_schema.json`
- `articles/how-fleets-android-mdm-connects-to-google.md`
- `articles/deploy-custom-android-app-apk.md`
- `articles/remote-yara-rules.md`, `articles/policy-automation-run-script.md`
- `server/mdm/android/service/service.go`, `server/mdm/android/service/androidmgmt/google_client.go`
- `android/README.md`
