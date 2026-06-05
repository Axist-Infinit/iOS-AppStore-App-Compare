# Codex context: Signal iOS App Store metadata comparison lab

## Objective

Continue a lawful iOS app package metadata comparison workflow for Signal iOS. The goal is to compare a captured App Store IPA against locally built Signal-iOS release artifacts, then produce structured manifests, diffs, CSV findings, and a report.

This is a metadata/package-structure workflow. It intentionally does **not** decrypt FairPlay, bypass DRM, or extract protected code from App Store binaries.

## User intent and constraints

- The user is a cybersecurity researcher.
- The user wants to analyze the Signal App Store IPA and compare it against builds from Signal's public source.
- The App Store IPA is the production reference artifact.
- Local source-built archives are comparison candidates.
- The useful comparison surface is package metadata, not decrypted App Store code.
- High-signal surfaces: entitlements, app extensions, embedded frameworks, dylibs, privacy manifests, Info.plist keys, URL schemes, background modes, associated domains, ATS config, linked libraries, SDK/minimum OS, and Mach-O load metadata.
- Expected noise: Team ID, application identifier prefixes, keychain/app group prefixes, provisioning UUIDs, signing timestamps, certificate chains, `_CodeSignature`, App Store FairPlay `cryptid`, and App Store thinning differences.

## Existing kit

Important files:

```text
scripts/ios_multiversion_meta_compare.py   # main comparison engine
scripts/watch_configurator_cache.sh        # helps capture Apple Configurator IPA cache
scripts/build_signal_release_matrix.sh     # small starter build wrapper
config.example.json                        # example config for reference + candidates
reports/STARTER_REPORT.md                  # initial guidance
matrices/expected_noise.csv                # known low-signal diffs
matrices/high_signal_fields.csv            # fields worth investigating
```

Added in this continuation:

```text
scripts/harvest_signal_ios_releases.py     # harvest many GitHub releases into CSV/JSON/config
scripts/build_signal_release_sweep.sh      # bulk build local release archives from matrix CSV
prompts/codex_continue_signal_sweep.md     # prompt to paste into Codex CLI
prompts/codex_triage_failed_builds.md       # prompt for fixing build failures version-by-version
docs/release_sweep_runbook.md              # operational workflow
```

Added for cross-platform support (RE upgrade, Phase 0):

```text
scripts/macho.py            # dependency-free Mach-O + code-signature reader
scripts/macho_backend.py    # native (macOS tools) / portable (pure-Python) backend selector
scripts/acquire_ipatool.sh  # scriptable App Store IPA acquisition via ipatool
tests/test_macho.py         # crafted-binary unit + integration tests (stdlib unittest)
requirements-optional.txt   # optional LIEF accelerator (not required)
```

The engine now runs on Linux/WSL as well as macOS. Tool functions
(`otool_*`, `codesign_*`, `vtool_build`, `lipo_archs`, `provisioning_profile`)
delegate to `BACKEND` (`macho_backend.select_backend()`). The portable backend
parses Mach-O load commands and the embedded code-signature SuperBlob directly,
so entitlements/linked-libs/rpaths/cryptid/build-version/identifiers work with no
Apple tools. Select with `--backend native|portable` or `IOS_META_BACKEND`. The
portable path is stdlib-only; LIEF stays optional. Run `python3 -m unittest
discover -s tests` after changes.

## Core comparison model

Do not treat many historical local releases as all expected to match the current App Store IPA. Use this interpretation model:

1. Exact local release matching App Store version/build: primary comparator.
2. Nearby prior releases: regression/control comparators.
3. Large release sweep: evolution/drift map, not exact-match validation.
4. Current `main`: source drift comparator.
5. Multiple captured App Store IPAs from different devices/iOS versions: app-thinning/slice controls.

## Main command shape

```bash
python3 scripts/ios_multiversion_meta_compare.py \
  --config config.signal_releases_20.json \
  --out out/signal_compare_20
```

The config file must contain:

```json
{
  "project": "Signal iOS metadata release sweep",
  "hash_mode": "notable",
  "reference": {
    "id": "signal_appstore_reference",
    "role": "appstore_reference",
    "label": "Signal App Store IPA captured with Apple Configurator",
    "path": "artifacts/appstore/Signal-AppStore.ipa"
  },
  "artifacts": [
    {
      "id": "signal_local_8_13_0_1623_release",
      "role": "local_release_tag",
      "label": "Signal-iOS 8.13.0.1623 local Release/device archive",
      "path": "artifacts/local/Signal-8.13.0.1623.xcarchive",
      "expected_version": "8.13",
      "expected_build": "8.13.0.1623",
      "expected_git_ref": "8.13.0.1623"
    }
  ]
}
```

## Suggested high-level CLI sequence

```bash
cd signal_ios_metadata_lab
python3 scripts/harvest_signal_ios_releases.py --limit 80 --out matrices --config-out config.signal_releases_80.json
bash scripts/build_signal_release_sweep.sh matrices/signal_releases_selected.csv
python3 scripts/ios_multiversion_meta_compare.py --config config.signal_releases_80.json --out out/signal_release_sweep_80
open out/signal_release_sweep_80/report.html
```

## Important implementation notes for Codex

- Preserve `ios_multiversion_meta_compare.py` behavior unless explicitly asked to refactor.
- Do not add FairPlay decryption logic or jailbreak dumping logic.
- When adding fields to manifests, keep output stable and JSON-serializable.
- Prefer additive scripts over invasive changes.
- Bulk building old iOS releases is fragile. Add retry/logging/reporting instead of assuming every tag builds.
- Support dry-run modes.
- Use no non-stdlib Python dependencies unless the user explicitly approves them.
- Keep generated config paths relative to the kit root.
- Continue-on-error is preferable for large sweeps.

## Useful next improvements

1. Add per-tag build status ingestion into the final report.
2. Add an `only_existing_artifacts` mode to configs/runs to skip tags that failed to build.
3. Add a `--window around <version>` selector to choose N releases before/after an App Store version.
4. Add HTML report sections for release timeline and high-signal field changes.
5. Add normalization profiles for Signal production vs local Team ID/bundle prefix substitutions.
