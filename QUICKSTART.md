# Quickstart

> **Platform note:** the comparison engine now runs on Linux/WSL as well as
> macOS. On macOS it uses Apple's `otool`/`codesign`; elsewhere it falls back to
> a built-in pure-Python Mach-O + code-signature reader (entitlements, load
> commands, linked libraries, encryption flags, identifiers). Force a backend
> with `--backend native|portable` or `IOS_META_BACKEND=...`.

## 0. Preflight

Confirm the machine can run the workflow, and (once you have an IPA) find the
source tag to compare against:

```bash
python3 scripts/doctor.py
python3 scripts/ipa_version.py artifacts/appstore/Signal-AppStore.ipa \
    --nearby 2 --suggest-config config.poc.json
```

`doctor.py` lists tools, the active backend, and any blockers. `ipa_version.py`
reads the captured build, picks the exact Signal-iOS tag plus nearby controls,
and can emit a ready-to-run config.

## 1. Capture the App Store IPA

### Option A — ipatool (scriptable, cross-platform)

```bash
APPLE_ID=you@example.com ./scripts/acquire_ipatool.sh
# first time on a fresh Apple ID? acquire the free license first:
APPLE_ID=you@example.com PURCHASE=1 ./scripts/acquire_ipatool.sh
```

This downloads the production (FairPlay-encrypted) IPA to
`artifacts/appstore/Signal-AppStore.ipa` and prints its version/build. Use that
`CFBundleVersion` to pick the matching Signal-iOS tag to build.

### Option B — Apple Configurator (macOS)

On macOS, start the cache watcher:

```bash
cd signal_ios_metadata_lab
./scripts/watch_configurator_cache.sh "$PWD/artifacts/appstore"
```

Then open Apple Configurator, connect the iPhone, and use **Add → Apps → Signal**. Stop the watcher once the IPA is copied.

Rename the captured IPA:

```bash
mv artifacts/appstore/*Signal*.ipa artifacts/appstore/Signal-AppStore.ipa
```

If the captured filename does not contain `Signal`, list by timestamp and size:

```bash
ls -lah artifacts/appstore/*.ipa
```

## 2. Build local comparison artifacts

Recommended matrix:

```bash
./scripts/build_signal_release_matrix.sh \
  8.13.0.1623 \
  8.12.1.1616 \
  8.12.0.1599
```

If automated signing/building fails, build in Xcode manually:

1. Clone Signal-iOS with submodules.
2. Check out the target tag.
3. Configure your Apple Developer Team for each target.
4. Build a Release/device archive.
5. Copy the `.xcarchive` into `artifacts/local/`.

## 3. Update config paths

Edit `config.example.json` so every `path` exists.

Check:

```bash
python3 - <<'PY'
import json, pathlib
c=json.load(open('config.example.json'))
paths=[c['reference']['path']]+[a['path'] for a in c['artifacts']]
for p in paths:
    print(('OK   ' if pathlib.Path(p).exists() else 'MISS ')+p)
PY
```

## 4. Generate report

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.example.json \
  --out out/signal_compare
```

Open:

```bash
open out/signal_compare/report.html
```

## 5. Review order

1. `out/signal_compare/report.html`
2. `out/signal_compare/csv/findings.csv`
3. `out/signal_compare/diffs/*/main_info.diff`
4. `out/signal_compare/diffs/*/signing_high_value.diff`
5. `out/signal_compare/diffs/*/privacy_manifests.diff`
6. `out/signal_compare/diffs/*/inventory_summary.diff`
7. `out/signal_compare/diffs/*/binary_summary.diff`

## 6. Important boundary

If the App Store main binary reports `cryptid 1`, that is expected. Do not treat encrypted-code disassembly/string output as useful static-analysis data. Compare metadata/package structure and use a local unencrypted build for code-level analysis.
