# Signal iOS Metadata Comparison Lab

A structured lab for comparing a captured Signal App Store IPA against locally built Signal-iOS release artifacts. The goal is to separate **production packaging/signing/capability differences** from **source-level differences** and **local build noise**.

This kit is designed for cybersecurity research, app-assessment documentation, and repeatable release sweeps. It is deliberately scoped to metadata, package structure, signing metadata, entitlements, privacy manifests, resources, and Mach-O load metadata.

It does **not** decrypt FairPlay, bypass DRM, patch code signatures, dump process memory, or recover protected App Store executable code.

---

## Table of contents

1. [Executive summary](#executive-summary)
2. [Research model](#research-model)
3. [Scope and boundaries](#scope-and-boundaries)
4. [What the kit compares](#what-the-kit-compares)
5. [What the kit does not compare](#what-the-kit-does-not-compare)
6. [Directory layout](#directory-layout)
7. [Prerequisites](#prerequisites)
8. [End-to-end workflow](#end-to-end-workflow)
9. [Capturing the App Store reference IPA](#capturing-the-app-store-reference-ipa)
10. [Harvesting a large Signal-iOS release set](#harvesting-a-large-signal-ios-release-set)
11. [Building local release archives](#building-local-release-archives)
12. [Generating a config from successful builds](#generating-a-config-from-successful-builds)
13. [Running the comparison engine](#running-the-comparison-engine)
14. [Understanding the output](#understanding-the-output)
15. [Interpreting results](#interpreting-results)
16. [Recommended release-sweep strategy](#recommended-release-sweep-strategy)
17. [Using Codex with this kit](#using-codex-with-this-kit)
18. [Troubleshooting](#troubleshooting)
19. [Quality gates](#quality-gates)
20. [Roadmap for extending the kit](#roadmap-for-extending-the-kit)
21. [Reference links](#reference-links)

---

## Executive summary

The core idea is simple:

```text
Captured App Store IPA  --->  production reference
Local source builds     --->  analyzable comparison candidates
Diff reports            --->  package/capability/signing drift map
```

For Signal iOS, the App Store IPA is useful as a production packaging artifact, while the public `signalapp/Signal-iOS` source tree is the better artifact for code-level review. This lab bridges those two worlds by answering questions like:

- Does the App Store build contain app extensions that my local build does not?
- Are the entitlements materially different after normalizing Team ID and bundle-prefix noise?
- Did privacy manifests change between releases?
- Did URL schemes, associated domains, app groups, background modes, ATS policy, or linked frameworks drift?
- Is the local release tag actually close to the App Store build I captured?
- Which differences are expected signing/build noise versus real production capability differences?

The kit generates:

```text
report.md
report.html
manifests/*.manifest.json
diffs/<reference>_vs_<candidate>/*.diff
csv/artifacts.csv
csv/findings.csv
csv/pair_outputs.csv
```

The intended high-confidence workflow is:

```text
1. Capture Signal App Store IPA.
2. Read version/build metadata from the IPA.
3. Harvest many Signal-iOS GitHub releases.
4. Build a small set of local Release/device archives first.
5. Expand to a larger release sweep once the build process is stable.
6. Generate a config containing only successful local builds.
7. Compare the App Store reference against all local candidates.
8. Triage high-signal diffs and ignore expected noise.
```

---

## Research model

### Why compare many releases?

The objective is **not** to claim that every historical Signal-iOS release should match the current App Store IPA. They will not.

The objective is to build a structured comparison matrix:

| Artifact class | Role | How to interpret it |
|---|---|---|
| Captured App Store IPA | Production reference | Ground truth for packaging, signing, entitlements, resources, extensions, and app-thinned distribution slice |
| Matching local release archive | Primary comparator | Best source-built approximation of the App Store release |
| Nearby local release archives | Control group | Shows expected release-to-release drift around the production build |
| Large historical release sweep | Timeline/drift map | Shows when metadata/capabilities changed over time |
| Current `main` build | Source drift comparator | Shows how far current source has moved from the captured production version |
| Additional App Store captures from other devices/iOS versions | Distribution-slice controls | Helps distinguish real package differences from App Store thinning/device slicing |

A large sweep helps answer evolutionary questions:

- When did a particular extension appear?
- When did an entitlement appear or disappear?
- When did a privacy manifest first show up?
- When did a linked framework or system capability become part of the package?
- Is a difference in the current App Store IPA unique, or has it been present for many releases?

### Correct mental model

Use the App Store IPA as the **production reference**, not as a source of decrypted code.

Use local Release/device archives as the **code-review-compatible comparison candidates**.

Use historical local builds to map **drift**, not to force equality against the current App Store package.

---

## Scope and boundaries

This kit stays inside a metadata and package-comparison boundary.

Allowed/comparative surfaces:

- app bundle structure,
- `Info.plist` values,
- nested bundle `Info.plist` files,
- entitlements,
- provisioning profile metadata when present,
- signing display metadata,
- app extensions,
- embedded frameworks,
- embedded dynamic libraries,
- privacy manifests,
- resource inventory,
- localized resource inventory,
- Mach-O load commands,
- linked libraries,
- architectures,
- rpaths,
- SDK/minimum OS/build metadata,
- App Store FairPlay encryption flag values such as `cryptid`.

Explicitly out of scope:

- FairPlay decryption,
- DRM circumvention,
- jailbreak dumping workflows,
- process-memory dumping,
- patching App Store binaries,
- bypassing code signing,
- bypassing TLS pinning,
- bypassing app protections,
- recovering or redistributing protected App Store executable code.

The scripts inspect what is already present in lawful local artifacts. They do not modify App Store packages.

---

## What the kit compares

The main comparison engine is:

```text
scripts/ios_multiversion_meta_compare.py
```

It accepts:

```text
.ipa
.app
.xcarchive
an extracted Payload/*.app directory
```

It produces normalized manifests and pairwise diffs for these categories:

| Diff file | Purpose |
|---|---|
| `main_info.diff` | Top-level app metadata: bundle ID, executable, versions, OS/SDK metadata, background modes, URL schemes, ATS, usage descriptions |
| `all_info_plists.diff` | All discovered `Info.plist` files, including extensions, frameworks, and nested bundles |
| `signing_high_value.diff` | High-value signing/entitlement fields such as app groups, keychain groups, associated domains, APNs, `get-task-allow` |
| `signing_full.diff` | Full signing display and entitlement metadata |
| `privacy_manifests.diff` | All `PrivacyInfo.xcprivacy` files and their plist contents |
| `provisioning_profiles.diff` | Decoded `embedded.mobileprovision` summaries where present |
| `binary_summary.diff` | Mach-O architectures, linked libraries, rpaths, build metadata, encryption info |
| `inventory_summary.diff` | Counts and notable file inventory by extension/type |
| `full_inventory.diff` | Full file inventory, optionally with hashes |

High-value fields include:

```text
CFBundleIdentifier
CFBundleExecutable
CFBundleShortVersionString
CFBundleVersion
MinimumOSVersion
DTSDKName
DTXcode
DTXcodeBuild
UIDeviceFamily
UIRequiredDeviceCapabilities
UIBackgroundModes
CFBundleURLTypes
LSApplicationQueriesSchemes
NSUserActivityTypes
NSAppTransportSecurity
PrivacyInfo.xcprivacy
application-identifier
com.apple.developer.team-identifier
keychain-access-groups
com.apple.security.application-groups
aps-environment
com.apple.developer.associated-domains
get-task-allow
LC_ENCRYPTION_INFO / LC_ENCRYPTION_INFO_64
linked libraries
rpaths
architectures
```

---

## What the kit does not compare

This kit does not provide meaningful static disassembly of encrypted App Store code.

For an App Store IPA, the main executable will commonly report:

```text
cryptid 1
```

That means the Mach-O is FairPlay-protected. The package is still useful for metadata, resources, signing state, bundle structure, app extensions, privacy manifests, and load-command metadata, but it is not a clean static-reversing target.

For code-level analysis of Signal, use:

```text
https://github.com/signalapp/Signal-iOS
```

Build your own local Release/debug/research artifacts from source and compare their package metadata against the App Store IPA.

---

## Directory layout

```text
signal_ios_metadata_lab/
  README.md
  QUICKSTART.md
  CODEX_CONTEXT.md
  config.example.json
  .gitignore

  artifacts/
    appstore/
      # Place captured App Store IPAs here.
      # Expected default: Signal-AppStore.ipa
    local/
      # Local .xcarchive/.app/.ipa builds go here.
      # Expected examples: Signal-8.13.0.1623.xcarchive

  scripts/
    watch_configurator_cache.sh
    harvest_signal_ios_releases.py
    build_signal_release_matrix.sh
    build_signal_release_sweep.sh
    config_from_existing_archives.py
    ios_multiversion_meta_compare.py

  matrices/
    signal_release_matrix_seed.csv
    expected_noise.csv
    high_signal_fields.csv
    release_page_snapshot_2026-06-01.md

  reports/
    STARTER_REPORT.md
    REPORT_TEMPLATE.md

  docs/
    references.md
    release_sweep_runbook.md

  prompts/
    codex_continue_signal_sweep.md
    codex_triage_failed_builds.md

  out/
    .keep
    # Generated reports/logs go here.
```

---

## Prerequisites

The comparison engine runs on **macOS or Linux/WSL**. It uses a backend abstraction:

- **native** backend (macOS): Apple's `otool`/`lipo`/`vtool`/`codesign`/`security`.
- **portable** backend (Linux/WSL, or anywhere Apple tools are absent): a built-in,
  dependency-free Mach-O + code-signature reader (`scripts/macho.py`,
  `scripts/macho_backend.py`). It extracts Info.plist data, entitlements (parsed
  straight from the embedded code-signature blob), linked libraries, rpaths,
  encryption flags (`cryptid`), build/version load commands, and bundle
  identifiers/team ids. It does not reconstruct certificate chains or CDHashes.

The backend is auto-selected; override with `--backend native|portable` or
`IOS_META_BACKEND=native|portable`.

Note that **building** local Signal-iOS archives (`xcodebuild`) and capturing
IPAs via **Apple Configurator** still require macOS. Acquisition via `ipatool`
and the metadata/signing comparison work on Linux.

Run `python3 -m unittest discover -s tests` to verify the portable reader.

Required for full functionality (native/build/capture on macOS):

```text
macOS
Xcode
Xcode command line tools
Python 3.10+
git
make
Apple Configurator, if capturing App Store IPA packages
```

Required command-line tools, normally available on macOS with Xcode/CLT:

```text
plutil
codesign
security
otool
lipo
vtool
file
shasum
xcodebuild
```

Verify basics:

```bash
xcode-select -p
xcodebuild -version
python3 --version
git --version
which codesign security otool lipo vtool plutil file
```

The Python scripts intentionally use the standard library only.

---

## End-to-end workflow

From the project root:

```bash
cd signal_ios_metadata_lab
```

### 1. Capture or place the App Store IPA

Default expected path:

```bash
artifacts/appstore/Signal-AppStore.ipa
```

You can use another path, but update the config or pass it through CLI arguments.

### 2. Harvest release metadata

Start with 20 releases while validating the workflow:

```bash
python3 scripts/harvest_signal_ios_releases.py \
  --limit 20 \
  --out matrices \
  --config-out config.signal_releases_20.json
```

Scale later:

```bash
python3 scripts/harvest_signal_ios_releases.py \
  --limit 80 \
  --out matrices \
  --config-out config.signal_releases_80.json
```

Or fetch all available releases from the GitHub releases API:

```bash
python3 scripts/harvest_signal_ios_releases.py \
  --all \
  --out matrices \
  --config-out config.signal_releases_all.json
```

### 3. Dry-run the build sweep

```bash
DRY_RUN=1 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

### 4. Build a small batch

```bash
LIMIT=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

### 5. Expand the batch

```bash
LIMIT=20 OFFSET=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

### 6. Generate a config for builds that actually exist

```bash
python3 scripts/config_from_existing_archives.py \
  --matrix matrices/signal_releases_selected.csv \
  --appstore-path artifacts/appstore/Signal-AppStore.ipa \
  --out config.signal_releases_existing.json
```

### 7. Run the comparison

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_existing.json \
  --out out/signal_release_sweep_existing
```

### 8. Open the report

```bash
open out/signal_release_sweep_existing/report.html
```

---

## Capturing the App Store reference IPA

There are two acquisition paths. Both yield the production, FairPlay-encrypted
IPA (`cryptid 1` on the main executable); neither decrypts anything.

### Option A — ipatool (scriptable, cross-platform)

[`ipatool`](https://github.com/majd/ipatool) authenticates with your own Apple
ID and downloads the same package the App Store delivers, from Linux or macOS:

```bash
APPLE_ID=you@example.com ./scripts/acquire_ipatool.sh
# fresh Apple ID with no prior Signal install? acquire the free license first:
APPLE_ID=you@example.com PURCHASE=1 ./scripts/acquire_ipatool.sh
```

It saves `artifacts/appstore/Signal-AppStore.ipa` and prints the captured
`CFBundleShortVersionString`/`CFBundleVersion` so you can pick the matching
Signal-iOS release tag to build.

### Option B — Apple Configurator (macOS)

The helper script watches common Apple Configurator cache locations and copies `.ipa` files before temporary cleanup:

```bash
bash scripts/watch_configurator_cache.sh "$PWD/artifacts/appstore"
```

Then, in Apple Configurator:

```text
1. Connect a physical iPhone over USB.
2. Select the device.
3. Choose Add -> Apps.
4. Sign in if prompted.
5. Search for Signal.
6. Install Signal.
7. Stop the watcher after the IPA is captured.
```

The watcher writes a checksum file:

```text
artifacts/appstore/SHA256SUMS
```

Rename the captured IPA to the default expected path:

```bash
ls -lah artifacts/appstore/*.ipa
mv artifacts/appstore/<captured-file>.ipa artifacts/appstore/Signal-AppStore.ipa
shasum -a 256 artifacts/appstore/Signal-AppStore.ipa
```

Important notes:

- This preserves the IPA package as downloaded by Apple Configurator.
- It does not decrypt FairPlay.
- The main App Store executable will likely remain encrypted.
- App Store delivery may be app-thinned for the connected device/iOS version.
- Capture device model, iOS version, Apple Configurator version, date/time, and Apple ID/account context in your research notes.

Suggested note template:

```text
App: Signal
Capture date:
Apple Configurator version:
macOS version:
iPhone model:
iOS version:
Apple ID region:
IPA SHA-256:
Observed IPA filename before rename:
Notes:
```

---

## Harvesting a large Signal-iOS release set

The release harvester is:

```text
scripts/harvest_signal_ios_releases.py
```

It uses GitHub release metadata to generate CSV/JSON/config files.

Basic usage:

```bash
python3 scripts/harvest_signal_ios_releases.py \
  --owner signalapp \
  --repo Signal-iOS \
  --limit 80 \
  --out matrices \
  --config-out config.signal_releases_80.json
```

Useful options:

```text
--limit N              Select newest N fetched releases.
--all                  Select all fetched releases.
--max-pages N          Cap GitHub API pagination; each page is up to 100 releases.
--include-prereleases  Include prerelease GitHub release records.
--include-drafts       Include draft GitHub release records, if visible.
--appstore-path PATH   Set reference IPA path in generated config.
--project TEXT         Set generated report title.
```

Generated files:

```text
matrices/signal_releases_all.csv
matrices/signal_releases_selected.csv
matrices/signal_release_tags_selected.txt
matrices/signal_releases_raw.json
config.signal_releases_80.json
```

`signal_releases_selected.csv` is the input to the bulk build script.

### Recommended release counts

| Stage | Count | Purpose |
|---|---:|---|
| Smoke test | 3-5 | Validate local signing/build assumptions |
| Initial sweep | 10-20 | Catch obvious build failures and script problems |
| Working sweep | 50-80 | Useful historical capability map |
| Full sweep | all fetched releases | Only after build and reporting paths are stable |

Do not jump directly to all releases. Old iOS projects can fail due to Xcode version drift, dependency changes, signing assumptions, submodule behavior, or build-system changes.

---

## Building local release archives

The bulk build script is:

```text
scripts/build_signal_release_sweep.sh
```

Default behavior:

```bash
bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Default paths:

```text
REPO_DIR=$PWD/Signal-iOS
OUT_DIR=$PWD/artifacts/local
LOG_DIR=$PWD/out/build_logs
WORKSPACE=Signal.xcworkspace
SCHEME=Signal
CONFIGURATION=Release
DESTINATION=generic/platform=iOS
```

Important environment variables:

```text
LIMIT=0                         # 0 means no limit
OFFSET=0                        # Skip first N selected releases
DRY_RUN=0                       # 1 prints actions without building
SKIP_EXISTING=1                 # Do not rebuild existing archives
CONTINUE_ON_ERROR=1             # Continue after a failed tag
RUN_MAKE_DEPENDENCIES=auto      # auto|always|never
CLEAN_WORKTREE=0                # 1 runs git clean -xdf after checkout
XCODEBUILD_EXTRA_ARGS=""         # extra args appended to xcodebuild
REPO_DIR="$PWD/Signal-iOS"
OUT_DIR="$PWD/artifacts/local"
LOG_DIR="$PWD/out/build_logs"
WORKSPACE="Signal.xcworkspace"
SCHEME="Signal"
CONFIGURATION="Release"
DESTINATION="generic/platform=iOS"
```

Start with a dry run:

```bash
DRY_RUN=1 LIMIT=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Build first five releases:

```bash
LIMIT=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Build the next twenty:

```bash
LIMIT=20 OFFSET=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Build everything selected, skipping existing archives:

```bash
SKIP_EXISTING=1 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Build status is written to:

```text
out/build_logs/build_status.csv
out/build_logs/Signal-<tag>.log
```

Expected archive path pattern:

```text
artifacts/local/Signal-<tag>.xcarchive
```

Example:

```text
artifacts/local/Signal-8.13.0.1623.xcarchive
```

### Signing and bundle identifiers

You generally cannot build Signal with Signal's production Team ID, production bundle ID, production APNs certificate, or production app groups. That is expected.

Treat these differences as expected noise unless the shape of the entitlement changed beyond prefix substitutions.

Common expected substitutions:

```text
<Signal Team ID>       -> <Your Team ID>
org.whispersystems...  -> your research bundle prefix
Signal app group prefix -> your app group prefix
Signal keychain prefix  -> your keychain group prefix
```

The config supports normalization rules:

```json
"normalization": {
  "expected_substitutions": [
    {"from": "YOURTEAMID", "to": "<TEAM_ID>"},
    {"from": "SIGNALTEAMID", "to": "<TEAM_ID>"},
    {"from": "com.yourorg.research.signal", "to": "<BUNDLE_ID>"},
    {"from": "org.whispersystems.signal", "to": "<BUNDLE_ID>"}
  ],
  "ignore_line_regex": [
    "Authority=",
    "Signature size=",
    "Timestamp=",
    "CDHash=",
    "TeamIdentifier=",
    "CMSDigest=",
    "CMSDigestType=",
    "^\\s*\\\"sha256\\\""
  ]
}
```

Update this for your actual local signing/team/bundle mapping.

---

## Generating a config from successful builds

Large sweeps will produce failed builds. Do not manually edit giant configs every time.

Use:

```bash
python3 scripts/config_from_existing_archives.py \
  --matrix matrices/signal_releases_selected.csv \
  --appstore-path artifacts/appstore/Signal-AppStore.ipa \
  --out config.signal_releases_existing.json
```

This scans the expected archive paths and includes only archives that exist.

Then compare:

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_existing.json \
  --out out/signal_release_sweep_existing
```

This prevents one failed historical release from blocking the entire metadata analysis.

---

## Running the comparison engine

### Config-based multi-artifact mode

Preferred:

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_existing.json \
  --out out/signal_release_sweep_existing
```

### Direct CLI mode

Useful for a quick comparison:

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --reference artifacts/appstore/Signal-AppStore.ipa \
  --reference-id signal_appstore \
  --candidate artifacts/local/Signal-8.13.0.1623.xcarchive \
  --candidate artifacts/local/Signal-8.12.1.1616.xcarchive \
  --project "Signal iOS metadata comparison" \
  --hash-mode notable \
  --out out/signal_compare_direct
```

### Hash modes

```text
--hash-mode full       Hash every file in the inventory. Slowest, most detailed.
--hash-mode notable    Hash only notable files. Default/recommended.
--hash-mode none       Skip file hashes. Fastest.
```

Use `notable` for most work. Use `full` only when exact resource/file drift matters.

---

## Understanding the output

Example output tree:

```text
out/signal_release_sweep_existing/
  report.md
  report.html
  manifests/
    signal_appstore_reference.manifest.json
    signal_local_8_13_0_1623.manifest.json
    signal_local_8_12_1_1616.manifest.json
  diffs/
    signal_appstore_reference_vs_signal_local_8_13_0_1623/
      main_info.diff
      all_info_plists.diff
      signing_high_value.diff
      signing_full.diff
      privacy_manifests.diff
      provisioning_profiles.diff
      binary_summary.diff
      inventory_summary.diff
      full_inventory.diff
  csv/
    artifacts.csv
    findings.csv
    pair_outputs.csv
```

### `report.html`

Start here. It summarizes:

- artifacts compared,
- versions/builds,
- bundle IDs,
- minimum OS/SDK metadata,
- `cryptid` values,
- APNs environment,
- `get-task-allow`,
- Mach-O count,
- app-extension count,
- framework count,
- privacy-manifest count,
- automated findings,
- changed diff categories.

### `csv/artifacts.csv`

Use this for spreadsheet filtering across many releases.

Useful questions:

- Which releases include privacy manifests?
- Which releases include app extensions?
- Which releases changed minimum OS?
- Which releases report `get-task-allow=true` locally?
- Which releases have unexpected APNs environment values?
- Which releases changed framework or Mach-O counts?

### `csv/findings.csv`

Automated findings are a triage accelerator. They are not a substitute for reviewing raw diffs.

Use findings to prioritize:

```text
high severity first
capability changes before signing boilerplate
extension/framework changes before file-hash changes
privacy manifest changes before resource-only changes
```

### `csv/pair_outputs.csv`

Maps each candidate to its diff folder and changed categories.

This is useful for batch processing:

```bash
column -s, -t < out/signal_release_sweep_existing/csv/pair_outputs.csv | less -S
```

### `manifests/*.manifest.json`

Full per-artifact manifests. Use these for exact evidence.

### `diffs/*/*.diff`

Unified JSON diffs, normalized according to config rules.

Review in this order:

```text
1. signing_high_value.diff
2. main_info.diff
3. privacy_manifests.diff
4. inventory_summary.diff
5. binary_summary.diff
6. all_info_plists.diff
7. provisioning_profiles.diff
8. signing_full.diff
9. full_inventory.diff
```

---

## Interpreting results

### High-signal differences

Investigate these first:

| Difference | Why it matters |
|---|---|
| Extra or missing `.appex` | Separate executable surface, entitlements, Info.plist, resources, and runtime behavior |
| Extra embedded `.framework` or `.dylib` | Additional code/package dependency not present in comparator |
| Different associated domains | Universal links, web credentials, app-site association trust surface |
| Different app groups | Cross-process/container sharing model changed |
| Different keychain groups beyond Team ID prefix | Credential-sharing model changed |
| Different `aps-environment` | Push-notification environment changed |
| Different `UIBackgroundModes` | Background execution capability changed |
| Different URL schemes | Deep-link/inter-app invocation surface changed |
| Different `LSApplicationQueriesSchemes` | Inter-app discovery surface changed |
| Different ATS policy | Network transport policy changed |
| Different privacy manifests | Privacy disclosure or required-reason API usage changed |
| Different linked libraries | Capability/API dependency changed |
| Different minimum OS/SDK | Runtime/hardening/API baseline changed |
| App Store `cryptid` unexpected value | Confirms whether the reference is App Store-protected or not |

### Expected noise

Normalize or ignore these unless they reveal an unexpected pattern:

| Difference | Why it is expected |
|---|---|
| Team ID | You are not Signal's production signing team |
| `application-identifier` prefix | Derived from Team ID |
| keychain/app group prefix | Derived from Team ID and local bundle choices |
| provisioning UUID/expiration | Local profile differs from App Store distribution profile |
| certificate chain | Local signing identity differs |
| signing timestamp | Build-time artifact |
| `_CodeSignature` content | Re-signing changes hashes |
| `embedded.mobileprovision` | Local versus App Store signing/distribution path |
| App Store receipt files | Distribution-channel artifact |
| App Store `cryptid 1` | FairPlay protection on App Store binary |
| file hashes for encrypted main executable | Not meaningful for code-level comparison |
| app-thinning resource differences | App Store may deliver device/OS-specific variants |

### Warning signs

Treat these as suspicious or at least worth validating:

```text
Matching-release local build has many app-extension differences.
Matching-release local build has unexpected embedded frameworks.
Local Release archive has get-task-allow=true.
App Store reference does not look encrypted when it should.
Version/build in local archive does not match the target tag.
Privacy manifests are missing locally but present in App Store artifact.
URL schemes or associated domains differ after expected bundle-prefix normalization.
MinimumOSVersion differs unexpectedly for the same release tag.
The generated config points at nonexistent archives.
```

---

## Recommended release-sweep strategy

### Phase 0: Establish the reference

Capture the App Store IPA and record:

```text
IPA SHA-256
Signal short version
Signal build version
Bundle ID
Main executable name
App Store capture date
Device model
iOS version
Configurator version
```

Quick inspection:

```bash
mkdir -p /tmp/signal_ref
unzip -q artifacts/appstore/Signal-AppStore.ipa -d /tmp/signal_ref
APP="$(find /tmp/signal_ref/Payload -maxdepth 1 -type d -name '*.app' | head -1)"
plutil -p "$APP/Info.plist" | egrep 'CFBundleIdentifier|CFBundleShortVersionString|CFBundleVersion|CFBundleExecutable'
BIN="$APP/$(plutil -extract CFBundleExecutable raw -o - "$APP/Info.plist")"
otool -l "$BIN" | grep -A5 -E 'LC_ENCRYPTION_INFO|LC_ENCRYPTION_INFO_64'
```

### Phase 1: Exact/nearby build set

Harvest 10-20 releases. Build the exact matching tag and nearby tags first.

```bash
python3 scripts/harvest_signal_ios_releases.py --limit 20 --out matrices --config-out config.signal_releases_20.json
LIMIT=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Run comparison on existing builds:

```bash
python3 scripts/config_from_existing_archives.py \
  --matrix matrices/signal_releases_selected.csv \
  --out config.signal_releases_existing.json

python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_existing.json \
  --out out/signal_exact_nearby
```

### Phase 2: Working sweep

Expand to 50-80 releases:

```bash
python3 scripts/harvest_signal_ios_releases.py --limit 80 --out matrices --config-out config.signal_releases_80.json
LIMIT=20 OFFSET=0  bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
LIMIT=20 OFFSET=20 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
LIMIT=20 OFFSET=40 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
LIMIT=20 OFFSET=60 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Generate config from successful builds and compare:

```bash
python3 scripts/config_from_existing_archives.py \
  --matrix matrices/signal_releases_selected.csv \
  --out config.signal_releases_existing.json

python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_existing.json \
  --out out/signal_release_sweep_existing
```

### Phase 3: Full historical sweep

Only after the workflow is stable:

```bash
python3 scripts/harvest_signal_ios_releases.py --all --out matrices --config-out config.signal_releases_all.json
SKIP_EXISTING=1 CONTINUE_ON_ERROR=1 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Full sweeps are noisy. Preserve logs and avoid rebuilding existing successes.

### Phase 4: Multi-reference App Store captures

Optional but valuable:

```text
artifacts/appstore/Signal-AppStore-iPhone15-iOS18.ipa
artifacts/appstore/Signal-AppStore-iPhone12-iOS17.ipa
artifacts/appstore/Signal-AppStore-iPad-iPadOS18.ipa
```

Run separate comparisons for each reference to distinguish true production package differences from app thinning/device slicing.

---

## Using Codex with this kit

The kit includes files intended to make continuation with Codex straightforward:

```text
CODEX_CONTEXT.md
prompts/codex_continue_signal_sweep.md
prompts/codex_triage_failed_builds.md
docs/release_sweep_runbook.md
```

### Recommended Codex startup prompt

From inside the project directory, paste this into Codex:

```text
Read README.md, CODEX_CONTEXT.md, QUICKSTART.md, docs/release_sweep_runbook.md, prompts/codex_continue_signal_sweep.md, and prompts/codex_triage_failed_builds.md.

Continue the Signal-iOS metadata release sweep. Preserve the no-FairPlay-decryption boundary. Use scripts/harvest_signal_ios_releases.py to generate a large release matrix, help me build or ingest local Signal-iOS release archives, generate a reduced config for successful builds, run scripts/ios_multiversion_meta_compare.py, and improve the report only if needed.

Do not add DRM bypass, FairPlay decryption, jailbreak dumping, third-party App Store binary dumping, process-memory dumping, or code-signature bypass logic.
```

### What Codex should work on first

Good first tasks:

```text
1. Validate the project tree and script help output.
2. Run the release harvester with --limit 20.
3. Dry-run the build sweep.
4. Inspect build_status.csv after a small batch.
5. Generate config.signal_releases_existing.json.
6. Run the comparison engine.
7. Summarize high-signal findings from report.html and csv/findings.csv.
```

### What Codex should not do

Do not ask Codex to implement:

```text
FairPlay decryption
DRM bypass
jailbreak dumping
process-memory dumping
signature bypass
anti-tamper bypass
TLS pinning bypass
extraction of decrypted third-party App Store code
```

Keep it focused on source builds, local artifacts, metadata extraction, reporting, and build-pipeline hardening.

---

## Troubleshooting

### The App Store IPA was not captured

Check:

```text
Apple Configurator is installed and signed in.
The iPhone is trusted and visible in Configurator.
Signal was installed through Configurator while watcher was running.
The watcher output directory is writable.
The Configurator cache path changed on your macOS version.
```

Run the watcher and manually search cache roots:

```bash
bash scripts/watch_configurator_cache.sh "$PWD/artifacts/appstore"
find "$HOME/Library" -type f -name '*.ipa' 2>/dev/null | grep -i signal
```

### The local build fails immediately

Open the workspace manually:

```bash
open Signal-iOS/Signal.xcworkspace
```

Check:

```text
Xcode version compatibility
Apple Developer account/team configured
bundle ID changes applied where necessary
signing profiles exist
submodules initialized
make dependencies completed
workspace and scheme names are still correct for that release
```

Then retry one tag manually before running the bulk script.

### Older releases fail but newer releases build

That is expected. Continue the sweep and use only existing archives.

```bash
python3 scripts/config_from_existing_archives.py \
  --matrix matrices/signal_releases_selected.csv \
  --out config.signal_releases_existing.json
```

### The comparison script says required tools are missing

Verify:

```bash
xcode-select -p
sudo xcode-select --switch /Applications/Xcode.app/Contents/Developer
which codesign security otool lipo vtool plutil file
```

### `get-task-allow` is true in local archive

You are probably comparing a development/debug-style artifact, not a production-like Release archive.

Rebuild with:

```text
CONFIGURATION=Release
DESTINATION=generic/platform=iOS
archive action
```

Then re-run the comparison.

### The App Store and local bundle IDs differ everywhere

Expected unless you can build with Signal's production identifiers. Normalize Team ID and bundle-prefix noise in config before triage.

### There are many file hash differences

Use `--hash-mode notable` or `--hash-mode none`.

File hashes are often low-signal when comparing App Store packages against locally signed builds.

### The App Store IPA appears device-specific

That may be app thinning. Capture additional App Store IPAs from different devices/iOS versions and compare them as separate references.

---

## Quality gates

Before trusting a report, verify these items.

### Reference IPA quality gate

```text
[ ] App Store IPA SHA-256 recorded.
[ ] Capture device/iOS/Configurator version recorded.
[ ] IPA extracts to Payload/*.app.
[ ] Info.plist version/build recorded.
[ ] Main executable identified.
[ ] Main executable encryption info recorded.
[ ] `cryptid 1` expected for App Store executable.
```

### Local build quality gate

```text
[ ] Local archive is .xcarchive or exported .app from device Release build.
[ ] Local build is not simulator.
[ ] Local build is not Debug unless intentionally comparing Debug.
[ ] Local version/build matches intended Signal-iOS tag.
[ ] `get-task-allow` is false for production-like Release archive.
[ ] Signing/team/bundle differences documented.
[ ] Build log retained.
```

### Comparison quality gate

```text
[ ] Config paths resolve.
[ ] At least one local candidate exists.
[ ] Reference and candidate manifests were generated.
[ ] report.html opens.
[ ] findings.csv exists.
[ ] signing_high_value.diff reviewed.
[ ] main_info.diff reviewed.
[ ] privacy_manifests.diff reviewed.
[ ] inventory_summary.diff reviewed.
[ ] binary_summary.diff reviewed.
[ ] Expected noise documented separately from true findings.
```

### Reporting quality gate

```text
[ ] Findings distinguish high-signal differences from expected signing noise.
[ ] Each material finding cites the specific diff file or manifest path.
[ ] App Store thinning limitations are acknowledged.
[ ] FairPlay limitation is acknowledged.
[ ] Source-build limitations are acknowledged.
[ ] Build failures are summarized, not hidden.
```

---

## Roadmap for extending the kit

Good next improvements for Codex or manual development:

1. **Build-status ingestion**
   - Read `out/build_logs/build_status.csv` and include success/failure counts in `report.html`.

2. **Window selector**
   - Add `--around-version 8.13 --before 5 --after 5` to the release harvester.

3. **Artifact existence mode**
   - Add `--skip-missing` directly to `ios_multiversion_meta_compare.py`.

4. **Release timeline report**
   - Generate a table showing capability changes over time.

5. **High-signal timeline CSV**
   - Create one row per release for entitlements, extensions, frameworks, privacy manifests, URL schemes, background modes, and ATS policy.

6. **Normalization profiles**
   - Add `normalization.signal.example.json` for common Signal production-vs-local Team ID/bundle substitutions.

7. **Build failure classifier**
   - Parse logs into categories: signing, dependency, Xcode incompatibility, missing scheme, submodule, Swift compiler, provisioning.

8. **Multi-reference support**
   - Compare multiple captured App Store IPAs against each other before comparing to local builds.

9. **Report evidence links**
   - Link findings directly to exact diff and manifest files.

10. **Config validator**
    - Validate paths, duplicate IDs, missing artifacts, malformed normalization rules, and unsupported hash modes before expensive extraction.

Keep all extensions inside the metadata/source-build comparison boundary.

---

## Reference links

Official/project references:

```text
Signal-iOS source:
https://github.com/signalapp/Signal-iOS

GitHub REST API releases documentation:
https://docs.github.com/en/rest/releases/releases

Apple Xcode distribution documentation:
https://developer.apple.com/documentation/xcode/distributing-your-app-for-beta-testing-and-releases

Apple app-size/app-thinning documentation:
https://developer.apple.com/documentation/xcode/reducing-your-app-s-size

Apple privacy manifest documentation:
https://developer.apple.com/documentation/bundleresources/privacy-manifest-files

OpenAI Codex CLI repository:
https://github.com/openai/codex

OpenAI Codex app documentation:
https://developers.openai.com/codex/app
```

Local kit references:

```text
QUICKSTART.md
CODEX_CONTEXT.md
docs/release_sweep_runbook.md
reports/STARTER_REPORT.md
reports/REPORT_TEMPLATE.md
matrices/expected_noise.csv
matrices/high_signal_fields.csv
prompts/codex_continue_signal_sweep.md
prompts/codex_triage_failed_builds.md
```

---

## Final operating principle

Use the App Store IPA to understand **what Apple distributed**.

Use Signal-iOS source builds to understand **what the code and local package should look like**.

Use the release sweep to understand **how package metadata and capabilities changed over time**.

Do not force every historical release to match the current App Store IPA. Instead, use historical releases to classify drift, isolate expected noise, and identify production-only differences worth deeper review.
