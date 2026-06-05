# Signal-iOS release sweep runbook

## Purpose

Run a large structured comparison between one captured Signal App Store IPA and many locally built Signal-iOS release archives.

This is useful for:

- finding the release tag closest to the App Store IPA,
- distinguishing production packaging from local signing noise,
- mapping metadata/capability drift over time,
- identifying production-only app extensions, privacy manifests, frameworks, URL schemes, associated domains, ATS changes, and background modes.

It is not a FairPlay decryption workflow.

## Artifact roles

| Role | Meaning |
|---|---|
| App Store IPA | Production package reference captured from Apple Configurator or other lawful workflow |
| Exact local release | Local archive built from the Signal-iOS tag matching the App Store short/build version |
| Nearby local releases | Regression/control comparators around the App Store version |
| Large historical sweep | Timeline/drift comparators, not expected to match current App Store version |
| Current main | Source drift comparator |

## Step 1: capture App Store IPA

Place the captured IPA here:

```bash
artifacts/appstore/Signal-AppStore.ipa
```

## Step 2: harvest releases

Fetch many release records from GitHub and generate matrix/config files:

```bash
python3 scripts/harvest_signal_ios_releases.py \
  --limit 80 \
  --out matrices \
  --config-out config.signal_releases_80.json
```

Outputs:

```text
matrices/signal_releases_all.csv
matrices/signal_releases_selected.csv
matrices/signal_release_tags_selected.txt
matrices/signal_releases_raw.json
config.signal_releases_80.json
```

## Step 3: build local archives

```bash
bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Important environment variables:

```bash
REPO_DIR=$PWD/Signal-iOS
OUT_DIR=$PWD/artifacts/local
SCHEME=Signal
WORKSPACE=Signal.xcworkspace
LIMIT=20
OFFSET=0
DRY_RUN=1
SKIP_EXISTING=1
CONTINUE_ON_ERROR=1
```

Start with dry run:

```bash
DRY_RUN=1 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

Then build a small window first:

```bash
LIMIT=5 bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
```

## Step 4: run comparison

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_80.json \
  --out out/signal_release_sweep_80
```

Open:

```bash
open out/signal_release_sweep_80/report.html
```

## Step 5: interpret results

Review in this order:

1. `report.html`
2. `csv/findings.csv`
3. `diffs/*/signing_high_value.diff`
4. `diffs/*/main_info.diff`
5. `diffs/*/privacy_manifests.diff`
6. `diffs/*/inventory_summary.diff`
7. `diffs/*/binary_summary.diff`

High-signal changes:

- `.appex` additions/removals,
- embedded frameworks/dylibs,
- app groups/keychain groups beyond prefix changes,
- `aps-environment`,
- associated domains,
- URL schemes,
- `LSApplicationQueriesSchemes`,
- `UIBackgroundModes`,
- ATS policy,
- privacy manifests,
- linked libraries,
- SDK/minimum OS changes.

Expected noise:

- Team ID,
- app identifier prefixes,
- provisioning UUIDs,
- certificate chains,
- signing timestamps,
- `_CodeSignature`,
- App Store `cryptid 1`,
- app thinning differences,
- resource slicing differences.

## Practical scale advice

Start with 5-10 releases. Then expand to 25, 50, and 100. Old releases may fail under a modern Xcode or dependency stack. This is normal; capture failures and keep the successful archives moving through comparison.
