# iOS bundled open-source library matching (symbol-based)

This document covers the **iOS** counterpart to `docs/android_library_matching.md`:
identifying which open-source library or framework — and which **version** — is
compiled into an iOS app or embedded framework, using the one fingerprint that
is stable across an App Store binary and a locally built reference: the set of
**exported symbol names** in the Mach-O symbol table.

It complements the kit's metadata-diff engine
(`scripts/ios_multiversion_meta_compare.py`), which compares Info.plist /
entitlements / Mach-O load-command metadata between a captured App Store build
and local release builds. The metadata diff answers *"is this the build I think
it is, and what changed at the package level"*; the symbol matcher answers
*"which third-party component, and which version of it, is linked in"* — the
Software Composition Analysis question — even when no version string survives.

---

## 1. The technique: exported-symbol-set containment

iOS app and framework code is **not** name-obfuscated the way Android code is
shrunk by R8/ProGuard. C, C++ and Swift exported symbol names are stable per
source version:

- C/C++ exported symbols are the (optionally `_Z`-mangled) source names.
- Swift exported symbols are mangled (`_$s…`), but **deterministically** — the
  same source compiled with the same toolchain produces the same mangled name.
- Objective-C class symbols appear as `_OBJC_CLASS_$_<ClassName>`.

So a Mach-O binary's set of **defined external symbols** is a structural
fingerprint of "which library, which version". Matching reduces to set
containment, exactly as on the Android side:

```text
containment(ref, candidate) = |ref.symbols ∩ candidate.symbols| / |ref.symbols|
```

The app is a *superset* — app code plus many linked frameworks — so **presence is
measured by containment, not Jaccard**. Among versions of one library above a
presence threshold, the highest containment (tie-broken by Jaccard, then
MinHash) is the bundled version. A clear single peak is high confidence; a flat
plateau across adjacent versions means those versions export an identical symbol
set and cannot be distinguished from the symbol table alone.

| | Android library matching | iOS library matching |
|---|---|---|
| Fingerprint | Per-class structural signatures | **Defined exported symbol names** |
| Why stable | Obfuscation can't rename framework refs or change code shape | Apple code is not name-obfuscated; symbol names are per-version stable |
| Match metric | Set containment of class signatures | **Set containment of symbol hashes** |
| Encryption barrier | None (DEX/JVM readable) | FairPlay encrypts `__TEXT` only — symbol table in `__LINKEDIT` stays readable |

---

## 2. Why this complements the metadata-diff engine

The metadata engine and the symbol matcher are orthogonal:

- **Metadata diff** operates on bundle/signing metadata (Info.plist keys,
  entitlements, dylib lists, build-version load commands, code-directory
  identity). It tells you whether two *whole artifacts* line up and what drifted.
- **Symbol matching** operates *inside* a binary at the component level. It tells
  you which open-source dependency is statically or dynamically linked, and at
  what version, for vulnerability/license mapping — information that bundle
  metadata does not carry once a version string has been stripped.

Together they give the iOS arm the same one-two punch the Android arm has:
artifact-level comparison plus component/version identification.

---

## 3. The FairPlay note (works at `cryptid 1`)

App Store main executables are FairPlay-encrypted, reported by the Mach-O parser
as `LC_ENCRYPTION_INFO[_64]` with `cryptid 1`. **FairPlay encrypts only the
`__TEXT` segment.** The symbol table (`nlist`/`nlist_64`) and the string table it
references live in `__LINKEDIT`, which is **not** part of the encrypted region.

Consequently:

- The defined/undefined external symbols of an encrypted App Store **main
  executable** are still readable, so symbol matching works without any
  decryption.
- **Embedded frameworks and dylibs** (`*.app/Frameworks/*.framework/*`,
  `*.dylib`) are usually not FairPlay-encrypted at all, so their symbols are
  fully available.

The reader (`scripts/macho.py`, `LC_SYMTAB` handling) extracts only what is
already present in a lawful artifact. It performs **no FairPlay decryption, no
signature/DRM bypass, and no repackaging** — consistent with the kit's hard
scope boundary.

---

## 4. Honest limits

- **Swift symbol-mangling stability.** Swift mangled names are stable for a given
  source *and toolchain*. A different Swift/compiler version, or ABI-affecting
  build settings, can change mangled names even when the source is identical.
  Build your reference corpus with a comparable toolchain where possible, and
  treat Swift-heavy matches with a wider confidence band than C/Objective-C ones.
  The leading-underscore normalisation (strip one `_`) handles the C convention
  but does **not** demangle Swift — names are compared as-is.
- **Stripped binaries.** Release builds run with `-Wl,-x` strip **local**
  symbols; `strip -s` / fully stripped builds remove more. The matcher uses only
  **exported external** symbols (`N_EXT` set, type `N_SECT`), which survive
  `-Wl,-x`. A library reduced to a tiny exported surface yields a smaller
  reference set and noisier containment — still usable, but lower resolution.
- **Static vs dynamic linking.** A *statically* linked dependency contributes its
  exported symbols into the host binary's symbol table, so it is matched against
  the host's symbols. A *dynamically* linked framework is matched as its own
  Mach-O. The walker handles both: point `--candidate` at a `.app` to sweep the
  main executable *and* every embedded framework/dylib, or at a single Mach-O for
  the static-link case.
- **Symbol-set collisions on tiny libraries.** Very small libraries (few
  exported symbols) collide more easily and produce weak, low-confidence matches.
  Treat low-containment results as leads, not proof.

---

## 5. The pieces

```text
scripts/macho.py               Dependency-free Mach-O reader. LC_SYMTAB parsing
                               extracts defined_symbols / undefined_symbols from
                               the __LINKEDIT symbol+string tables.

scripts/ios_lib_fingerprint.py CLI: fingerprint / build-corpus / match, plus the
                               report.md / report.html renderer. Reuses the
                               generic MinHash from android_fingerprint.

scripts/android_fingerprint.py Source of the generic, format-agnostic MinHash /
                               minhash_similarity helpers (shared, not modified).
```

Everything is **standard library only** — no `otool`, `nm`, `lipo`, or any Apple
tool is required, so the workflow runs on Linux/WSL.

---

## 6. End-to-end workflow

### Step 1 — Build the reference corpus

Collect known reference versions of the library/framework — one bundle, dylib,
or directory per version. Apple frameworks rarely carry a Maven-style version in
the filename, so name them so the version can be inferred, e.g.:

```text
refs/MyLib-1.0.0.framework
refs/MyLib-2.0.0.framework
refs/MyLib-2.1.0.framework
```

(or a `refs/<version>/...` layout — each immediate subdirectory is treated as one
reference). Versions with no inferable numeric token get an empty version label.

### Step 2 — Fingerprint the corpus

```bash
python3 scripts/ios_lib_fingerprint.py build-corpus \
  --in refs \
  --name MyLib \
  --out corpus/mylib.corpus.jsonl
```

`--name` forces one library identity for every artifact; omit it to infer the
name per file from the bundle/file stem. Each profile is the sorted set of
blake2b-64 hashes of the normalised symbol names, plus a 64-permutation MinHash
for fast pre-screening. Schema: `ios-symbol-structural-profile-v1`.

You can fingerprint a single artifact directly:

```bash
python3 scripts/ios_lib_fingerprint.py fingerprint \
  --artifact refs/MyLib-2.0.0.framework \
  --name MyLib --version 2.0.0 \
  --out corpus/mylib-2.0.0.json
```

### Step 3 — Match the unknown app

```bash
python3 scripts/ios_lib_fingerprint.py match \
  --candidate Payload/TheApp.app \
  --corpus corpus/mylib.corpus.jsonl \
  --out out/mylib_match
```

The candidate can be a `Payload/*.app`, a `.framework`/`.dylib`/`.xcarchive`, a
single Mach-O file, or a plain directory; the walker finds every Mach-O inside
and unions their exported symbols. Use `--raw-symbols` to disable the
leading-underscore normalisation, and `--min-containment` / `--strong-threshold`
to tune the presence and "strong" thresholds (defaults 0.10 / 0.70).

### Step 4 — Read the report

```bash
open out/mylib_match/report.html
```

Outputs (mirroring the Android matcher):

```text
out/mylib_match/
  report.md / report.html        verdict + per-library version-drift tables
  csv/library_matches.csv        best version per library
  csv/version_scores.csv         every reference version score
  candidate.libprofile.json      the candidate's fingerprint
```

---

## 7. Interpreting results

| Observation | Reading |
|---|---|
| containment ≈ 1.0 at one version, lower on neighbours | Strong: that version is bundled |
| high containment across a *run* of versions (plateau) | Those versions export identical symbol sets; narrow with changelog / metadata diff |
| moderate containment (0.4–0.7), single peak | Library present but partly stripped or partially linked; version peak still informative |
| low containment everywhere | Library probably absent, OR heavily stripped, OR missing from the corpus |
| Swift-heavy library, partial match | Possible toolchain-version mangling drift — widen the confidence band |

This is **read-only Mach-O metadata extraction** for component/version
identification. It performs no FairPlay decryption, no signature/DRM bypass, and
no repackaging, matching the kit's overall scope boundary.

---

## 8. Validation

The approach is exercised by `tests/test_macho.py` (LC_SYMTAB extraction of a
defined export and an undefined import from a synthetic Mach-O) and
`tests/test_ios_fingerprint.py`, which builds real in-memory Mach-O binaries and
asserts:

- defined exported symbols are recovered and fingerprinted;
- containment ranking picks the correct bundled version (the app is a superset of
  the bundled library plus unrelated app symbols);
- a library with disjoint symbols is filtered out by `--min-containment`;
- the profile JSON round-trips.

```bash
python3 -m unittest tests.test_macho tests.test_ios_fingerprint -v
python3 -m unittest discover -s tests
```
