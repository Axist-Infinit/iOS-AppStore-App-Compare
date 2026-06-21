# Android manifest capability diffing

This document covers the **Android manifest** arm of the kit: parsing the
compiled `AndroidManifest.xml` out of an APK into a structured **capability
profile**, and **diffing** two APKs' capability surfaces — for example a
Play-Store APK against an F-Droid/source build, or one release against the next.

It is the Android analogue of the iOS `Info.plist` + entitlements comparison: the
same *metadata/capability-diffing* idea, applied to the surface Android declares
in its manifest. Implemented in `scripts/android_manifest.py`, exercised by
`tests/test_android_manifest.py`, and — like the rest of the kit — **standard
library only**.

---

## 1. What binary AXML is

Inside an APK, `AndroidManifest.xml` is **not** text. The build pipeline (`aapt2`)
compiles it into **Android binary XML ("AXML")**: a chunk-based resource format
defined in `frameworks/base` `ResourceTypes.h`. A file is a `RES_XML_TYPE`
wrapper containing a sequence of chunks:

| Chunk | Type | Role |
|---|---|---|
| `RES_STRING_POOL_TYPE` | `0x0001` | every string in the document, UTF-8 or UTF-16 |
| `RES_XML_RESOURCE_MAP_TYPE` | `0x0180` | maps attribute indices to framework resource IDs (optional for us) |
| `START_NAMESPACE` / `END_NAMESPACE` | `0x0100` / `0x0101` | namespace prefix declarations |
| `RES_XML_START_ELEMENT_TYPE` | `0x0102` | an element with its typed attributes |
| `RES_XML_END_ELEMENT_TYPE` | `0x0103` | element close |
| `RES_XML_CDATA_TYPE` | `0x0104` | element text |

Each attribute carries a **typed value** (`Res_value`: a `dataType` byte plus a
`u32`), so a boolean is recovered as `True`/`False`, an int as an int, and a
string as a string-pool reference — no XML re-serialization or `aapt` required.

The parser in `scripts/android_manifest.py` reads these chunks directly,
**bounding every read to the buffer length** and collecting any malformed-chunk
problem into a structured `errors` list rather than crashing. Both the UTF-8 and
UTF-16 string-pool encodings are implemented; most modern manifests are UTF-8.

---

## 2. Capability surfaces extracted

`extract_capabilities()` distils the parsed tree into a JSON-serializable profile:

```text
package, versionCode, versionName
uses_sdk:        minSdkVersion, targetSdkVersion
uses_permission: [sorted permission names]
uses_feature:    [sorted]                 uses_library: [sorted]
application:     debuggable, allowBackup, usesCleartextTraffic, networkSecurityConfig
components:      activity / service / receiver / provider
                 each: name, exported, permission, intent_filters[{actions,categories,schemes}]
exported_components: [names exported, or exposed via an intent-filter]
errors:          [structured parse notes]
```

Attributes are resolved **by their local name** from the string pool (e.g.
`name`, `exported`, `debuggable`). Real manifests almost always carry attribute
names in the pool, so a full hardcoded resource-ID map is unnecessary; when a
name string is genuinely absent the attribute is skipped gracefully (see limits).

"Exported" follows the platform rule: an explicit `android:exported="true"` is
exported; an explicit `false` is not; and a component **with an intent-filter and
no explicit `exported`** is treated as exposed (the historical default).

---

## 3. High-signal vs informational framing

This mirrors the iOS engine's philosophy (`ios_multiversion_meta_compare.py`):
separate **capability/attack-surface regressions** from **expected build/release
drift**, so a reviewer reads the few rows that matter first.

`diff_manifests(a, b)` (a = reference, b = compared) emits findings tagged
`high` / `medium` / `info`:

| Delta | Severity | Why |
|---|---|---|
| New **dangerous/sensitive** permission (CAMERA, RECORD_AUDIO, READ_SMS, ACCESS_FINE_LOCATION, READ_CONTACTS, …) | **high** | widened attack surface |
| Newly **exported** component | **high** | new externally-reachable entry point |
| `debuggable` → true | **high** | ships a debuggable build |
| `usesCleartextTraffic` → true | **high** | permits plaintext network traffic |
| Dropped `networkSecurityConfig` | **high** | removes pinning/cleartext policy |
| **Lowered** `minSdkVersion` | **high** | exposes app to older, weaker OS versions |
| `allowBackup` → true | **high** | data extractable via ADB backup |
| Lowered `targetSdkVersion` | **medium** | relaxes platform-enforced hardening |
| Non-sensitive permission added/removed, feature churn, version/package id | **info** | expected release/flavor drift |

The kit ships a small, curated `DANGEROUS_PERMISSIONS` set for tagging (the
Android runtime-permission groups plus a few notable-capability extras such as
`INTERNET`, `QUERY_ALL_PACKAGES`, and `REQUEST_INSTALL_PACKAGES`). This is a
tagging heuristic, **not** a hardcoded resource-ID table.

---

## 4. Honest limits

- **Resource-ID-only attributes.** If a manifest omits attribute *name* strings
  and carries only numeric resource IDs (rare, but producible by some tooling),
  name-based lookup cannot resolve those attributes and they are skipped. The
  kit deliberately does not embed a full, version-drifting resource-ID map.
- **The manifest is a declaration, not behaviour.** A permission can be declared
  yet unused; a component can be `exported` yet guarded by a signature-level
  permission. Treat findings as *leads*, corroborated by the bundled-library
  (`android_lib_match.py`) and binary evidence elsewhere in the kit.
- **AAB base vs split manifests.** An Android App Bundle splits the manifest
  across the base module and configuration/feature splits; the merged manifest in
  an *installed* APK is the complete picture. Compare like-for-like artifacts
  (e.g. a universal/installed APK on both sides), not a base-module manifest
  against a fully-merged one.
- **Merged-manifest provenance.** What ships is the *merged* result of the app
  manifest plus every library/AAR manifest; a permission may originate from a
  dependency rather than first-party code.

---

## 5. Scope boundary

This is **read-only metadata extraction**. The parser decodes a structure that is
already present in a lawful artifact. It performs **no decryption, deobfuscation,
repackaging, or execution**, matching the kit's overall scope boundary and the
iOS arm's "metadata/package comparison only" stance.

---

## 6. CLI workflow

`scripts/android_manifest.py` exposes two subcommands, mirroring the structure of
`android_lib_match.py`.

### Extract one APK's capability profile

```bash
python3 scripts/android_manifest.py extract --apk app-release.apk
# write the JSON profile to a file:
python3 scripts/android_manifest.py extract --apk app-release.apk -o out/app.manifest.json
```

The `--apk` argument accepts an `.apk`/`.zip`, a raw binary `AndroidManifest.xml`,
or a directory containing one.

### Diff two APKs

```bash
python3 scripts/android_manifest.py diff \
  --a playstore.apk \
  --b fdroid.apk \
  --out out/manifest_diff
```

Outputs (parallel to the iOS report):

```text
out/manifest_diff/
  report.md / report.html         findings table (severity, category, summary)
                                  + full capability/permission/component tables,
                                  high-signal first
  csv/manifest_findings.csv       the findings table as CSV
  a.manifest.json                 reference capability profile
  b.manifest.json                 compared capability profile
```

High-signal findings are also echoed to stdout so a CI run surfaces them without
opening the report.

---

## 7. Validation

`tests/test_android_manifest.py` builds a small, spec-correct binary AXML blob in
memory (UTF-8 string pool, `<manifest>` with `package`/`versionName`/
`versionCode`, a `uses-permission` for `android.permission.INTERNET`, an
`<application android:debuggable="true">`, and an exported `<activity>`), and
asserts the parser recovers each of those. A second blob adds
`android.permission.RECORD_AUDIO` and removes the exported flag; the test asserts
`diff_manifests` flags the added `RECORD_AUDIO` as a **high-signal** finding and
reports the activity as no longer exported.

```bash
python3 -m unittest tests.test_android_manifest -v
python3 -m unittest discover -s tests
```

---

## 8. Relationship to the iOS arm

| | iOS metadata comparison | Android manifest diffing |
|---|---|---|
| Source of truth | `Info.plist` + entitlements | compiled `AndroidManifest.xml` (AXML) |
| Capability surface | background modes, URL schemes, ATS, usage strings, entitlements | permissions, exported components, app security flags, SDK levels |
| Reference vs compared | App Store IPA vs local Release build | Play-Store APK vs F-Droid/source build |
| Triage | high-signal vs expected signing/build noise | high-signal vs informational release drift |
| Encryption barrier | FairPlay (`cryptid 1`) limits code work | none — AXML is plainly readable |

Same engine philosophy, same scope boundary, now spanning both platforms.
