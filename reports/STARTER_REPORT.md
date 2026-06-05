# Signal iOS metadata comparison — starter report

Generated: 2026-06-01

## Current baseline discovered from public sources

As of this report seed, the Apple App Store listing shows Signal iOS version `8.13` in the visible version history. The official GitHub releases page shows `8.13` as the latest Signal-iOS release, tagged `8.13.0.1623`, with nearby prior releases `8.12.1.1616`, `8.12.0.1599`, `8.11.0.1584`, `8.10.0.1570`, `8.9.0.1558`, `8.8.0.1549`, and `8.7.0.1523`.

Treat the captured App Store IPA's own `Info.plist` as authoritative. App Store listings and GitHub pages can update after this package was generated.

## Proposed comparison matrix

| Role | Artifact | Purpose |
|---|---|---|
| Production reference | Captured App Store IPA, version 8.13 if current | Establish production package/signing/capability baseline |
| Exact source comparator | Local Release/device archive from `8.13.0.1623` | Check whether the public source release packages like the App Store build, except expected signing/thinning differences |
| Previous release comparator | Local Release/device archive from `8.12.1.1616` | Separate normal release-to-release drift from production-only differences |
| Previous minor comparator | Local Release/device archive from `8.12.0.1599` | Confirm whether 8.12.1 patch introduced package/capability changes |
| Current source comparator | Local Release/device archive from `main` | Identify post-App-Store drift, not production parity |
| Optional second App Store slice | Captured IPA from another iPhone/iOS version | Detect app-thinning differences |

## High-value review questions

1. Does the App Store build include app extensions that the local build lacks?
2. Do App Store and local builds request the same sensitive entitlements?
3. Are app groups and keychain groups structurally equivalent after Team ID normalization?
4. Are associated domains identical after bundle-prefix normalization?
5. Are APNs, communication notification, Siri, iCloud, or Network Extension entitlements present only in one artifact?
6. Do privacy manifests declare the same collected-data categories and required-reason APIs?
7. Are background modes, URL schemes, `LSApplicationQueriesSchemes`, and ATS policy identical?
8. Are embedded frameworks/dylibs equivalent?
9. Are linked system libraries equivalent?
10. Is any difference explained by App Store thinning rather than source/package divergence?

## Expected noise

- Team ID and application identifier prefix
- keychain/app-group prefix
- provisioning profile UUID, creation date, expiration date
- certificate chain and signing timestamp
- code-signature hashes
- App Store receipt files
- FairPlay encryption flag on App Store main binary
- resource slices from App Store thinning

## Next action

Place the captured App Store IPA and local `.xcarchive` builds under `artifacts/`, edit `config.example.json`, and run:

```bash
python3 scripts/ios_multiversion_meta_compare.py --config config.example.json --out out/signal_compare
```
