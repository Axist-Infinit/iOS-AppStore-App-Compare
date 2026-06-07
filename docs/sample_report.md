# Sample report (synthetic / redacted)

> Generated from synthetic fixtures, not real Signal artifacts, so you can
> see the shape of the output without running the full macOS workflow.
> Produced by `scripts/run_poc.py` on crafted .ipa/.app inputs.

Generated: `2026-06-07T02:29:18Z`

## Scope

This report compares iOS App Store/local build metadata and package structure. It does not decrypt FairPlay-protected executables, bypass DRM, or analyze decrypted App Store code.

Metadata backend: `portable`. Signing/binary metadata extracted with the built-in pure-Python Mach-O + code-signature reader (no Apple tools required). Code-signature certificate chains and CDHashes are not reconstructed; entitlements, load commands, linked libraries, encryption flags, and identifiers are.

Reference artifact: `signal_appstore_reference`

## Artifact matrix

| artifact_id | role | bundle_id | short_version | build_version | min_os | sdk_name | main_cryptid | aps_environment | get_task_allow | macho_count | extension_count | framework_count | privacy_manifest_count |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| signal_appstore_reference | appstore_reference | org.whispersystems.signal | 8.9 | 8.9.0.1558 |  |  | 1 | production | False | 1 | 0 | 0 | 0 |
| signal_local_8_9_0_1558_release | local_release_tag_exact | org.whispersystems.signal | 8.9.0 | 8.9.0.1558 |  |  | 0 | production | False | 1 | 0 | 0 | 0 |
| signal_local_8_10_0_1570_release | local_release_tag_control | org.whispersystems.signal | 8.10.0 | 8.10.0.1570 |  |  | 0 | production | False | 1 | 0 | 0 | 0 |


## Provenance

Evidence identity per artifact (file SHA-256, or a structure digest for directory artifacts), plus the backend and any operator-declared capture metadata.

| artifact_id | kind | identity_sha256 | size_bytes | git_ref | backend | declared |
| --- | --- | --- | --- | --- | --- | --- |
| signal_appstore_reference | file | dbbbf7bba457c38050eddec933827dcf | 1707 |  | portable |  |
| signal_local_8_9_0_1558_release | directory | 9ff1e5cf4844b5d3cc7e27ad9a0cd027 | 1500 | 8.9.0.1558 | portable |  |
| signal_local_8_10_0_1570_release | directory | f258fdd2270df191d478eab65d2161b5 | 1502 | 8.10.0.1570 | portable |  |


## Conclusion

Primary comparator: `signal_local_8_9_0_1558_release` vs reference `signal_appstore_reference`.

- Version/build: **DIFFERS** (ref 8.9/8.9.0.1558, cmp 8.9.0/8.9.0.1558)
- Extension + framework counts: **MATCH** (ref 0/0, cmp 0/0)
- High-signal unexplained findings: **2** (review these first)
- FairPlay: reference main executable is encrypted (`cryptid 1`); App Store code/string analysis requires a lawful unencrypted build or an on-device decrypted copy. Metadata/package comparison above is unaffected.

_Fill in: privacy-manifest deltas, entitlement deltas beyond signing noise, and any production-only extension/framework before signing off._

## Triage summary

Findings grouped so signing/build noise is separated from real package/capability differences.

| triage_class | count |
| --- | --- |
| High-signal (investigate) | 2 |
| App Store packaging | 2 |
| Release-to-release drift | 3 |
| Expected local-build noise | 0 |
| Expected signing noise | 0 |


Artifacts skipped (missing/unbuildable): **3** — see `csv/skipped.csv`.

## Local build status

From `/home/axis/signal_ios_metadata_lab/out/build_logs/build_status.csv` — 20 tag(s): dry_run: 20.

| status | count |
| --- | --- |
| dry_run | 20 |


## Findings

| severity | triage | category | compared | summary | detail | evidence |
| --- | --- | --- | --- | --- | --- | --- |
| medium | high_signal_unexplained | Info.plist | signal_local_8_9_0_1558_release | UIBackgroundModes differs | reference=None; compared=['voip'] | [main_info.diff](diffs/signal_appstore_reference_vs_signal_local_8_9_0_1558_release/main_info.diff) |
| medium | high_signal_unexplained | Info.plist | signal_local_8_10_0_1570_release | UIBackgroundModes differs | reference=None; compared=['voip'] | [main_info.diff](diffs/signal_appstore_reference_vs_signal_local_8_10_0_1570_release/main_info.diff) |
| info | appstore_packaging | FairPlay boundary | signal_local_8_9_0_1558_release | Reference main executable reports cryptid 1 | Treat App Store main executable code/string diffs as non-actionable unless you have a lawful unencrypted build. This report focuses on me... | [binary_summary.diff](diffs/signal_appstore_reference_vs_signal_local_8_9_0_1558_release/binary_summary.diff) |
| info | appstore_packaging | FairPlay boundary | signal_local_8_10_0_1570_release | Reference main executable reports cryptid 1 | Treat App Store main executable code/string diffs as non-actionable unless you have a lawful unencrypted build. This report focuses on me... | [binary_summary.diff](diffs/signal_appstore_reference_vs_signal_local_8_10_0_1570_release/binary_summary.diff) |
| high | release_drift | Info.plist | signal_local_8_9_0_1558_release | CFBundleShortVersionString differs | reference='8.9'; compared='8.9.0' | [main_info.diff](diffs/signal_appstore_reference_vs_signal_local_8_9_0_1558_release/main_info.diff) |
| high | release_drift | Info.plist | signal_local_8_10_0_1570_release | CFBundleShortVersionString differs | reference='8.9'; compared='8.10.0' | [main_info.diff](diffs/signal_appstore_reference_vs_signal_local_8_10_0_1570_release/main_info.diff) |
| high | release_drift | Info.plist | signal_local_8_10_0_1570_release | CFBundleVersion differs | reference='8.9.0.1558'; compared='8.10.0.1570' | [main_info.diff](diffs/signal_appstore_reference_vs_signal_local_8_10_0_1570_release/main_info.diff) |


## Pairwise diff outputs

| reference | compared | diff_dir | changed_categories |
| --- | --- | --- | --- |
| signal_appstore_reference | signal_local_8_9_0_1558_release | diffs/signal_appstore_reference_vs_signal_local_8_9_0_1558_release | main_info;all_info_plists;signing_high_value;signing_full;binary_summary;full_inventory |
| signal_appstore_reference | signal_local_8_10_0_1570_release | diffs/signal_appstore_reference_vs_signal_local_8_10_0_1570_release | main_info;all_info_plists;signing_high_value;signing_full;binary_summary;full_inventory |


## Review priority

1. `main_info.diff` — version/build, background modes, URL schemes, ATS, privacy usage strings.
2. `signing_high_value.diff` — entitlements, app groups, keychain groups, associated domains, APNs, `get-task-allow`.
3. `privacy_manifests.diff` — collected data declarations and required-reason APIs.
4. `inventory_summary.diff` — extensions, frameworks, dylibs, resource structure.
5. `binary_summary.diff` — architectures, linked libraries, rpaths, Mach-O build metadata, encryption flags.

## Interpretation notes

Expected noise includes Team ID, provisioning UUIDs, certificate details, app/keychain group prefixes, App Store receipts, code-signature blobs, and app-thinned resource variants. High-signal differences include extra app extensions, extra embedded frameworks/dylibs, different associated domains, background modes, URL schemes, LSApplicationQueriesSchemes, ATS policy, privacy manifests, linked system frameworks, and minimum OS/SDK deltas.

## Files

- `manifests/*.json`: full per-artifact manifests
- `diffs/<reference>_vs_<candidate>/*.diff`: category-level JSON unified diffs
- `csv/artifacts.csv`: compact artifact matrix
- `csv/findings.csv`: automated finding list
- `report.md` / `report.html`: this report
