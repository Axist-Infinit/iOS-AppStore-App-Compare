# Android bundled open-source library matching

This document covers the **Android** extension of the kit: identifying which
open-source library — and which **version** — is compiled into an app, even when
the library's version metadata has been stripped and its symbols obfuscated by
R8/ProGuard.

It answers three questions the kit is often asked:

1. The iOS workflow matches a whole open-source *app* against a captured
   binary. Can the same idea match an open-source *library bundled inside* an
   app? **Yes.**
2. Does it work for **Android**? **Yes — and Android is an easier target than
   iOS**, because APK/AAR bytecode is not FairPlay-encrypted; DEX and JVM
   bytecode are fully readable.
3. Can it cope with a **compiled library whose version was removed and that is
   obfuscated**? **Yes**, by matching on obfuscation-resilient *structural
   fingerprints* instead of names, strings, or version metadata.

---

## 1. Why the same idea transfers

The iOS engine's method is:

```text
collect known reference versions -> fingerprint each -> match the unknown
artifact against the corpus -> report best match + drift
```

That is library-agnostic. For iOS the fingerprint is *package/signing/Mach-O
metadata*. For an obfuscated Android library the metadata is gone, so the
fingerprint becomes the one thing obfuscation cannot erase: the **structure of
the compiled code**.

| | iOS app comparison | Android library matching |
|---|---|---|
| Reference corpus | Local Release builds of every Signal tag | Every published version of `group:artifact` from Maven, or a folder of AAR/JAR/APK you supply |
| Unknown artifact | Captured App Store IPA | The app's APK (or an extracted library) |
| Fingerprint | Info.plist / entitlements / Mach-O load metadata | Per-class **structural signatures** (+ surviving string anchors) |
| Match metric | High-signal field diffs | **Set containment** of class signatures |
| "Which version" | Nearest release tag | Containment peak across versions |
| Encryption barrier | FairPlay (`cryptid 1`) limits code-level work | None — DEX/JVM bytecode is readable |

---

## 2. Why obfuscation doesn't defeat it

R8/ProGuard (the normal Android shrinkers) rename a library's **own** packages,
classes, and members, and strip debug info and unused code. They do **not**, and
structurally **cannot**:

- **rename references to the platform/runtime SDK** — `java/*`, `javax/*`,
  `android/*`, `androidx/*`, `kotlin/*`, `org/w3c/*`, `org/json/*`, … — because
  those symbols resolve against code the obfuscator does not own;
- **change the shape of the code** — how many methods/fields each class has, how
  many arguments each method takes, the primitive-vs-reference shape of every
  signature, or the class/interface relationships.

So we build each class's signature out of *exactly* what survives:

```text
class signature = hash(
    sorted methods:  (normalized-access, descriptor with internal types -> L*;)
    sorted fields:   (normalized-access, type with internal types -> L*;)
    super/interface shape: framework name kept, internal -> "*"
)
# the class's own name is discarded; members are sorted (reorder-resilient)
```

Concretely, a method `String doWork(Helper, int)` compiles to descriptor
`(Lcom/lib/Helper;I)Ljava/lang/String;`. After obfuscation the library's
`Helper` becomes `a/b/q`, but the framework `java/lang/String` is untouched, so
the descriptor normalizes to:

```text
(L*;I)Ljava/lang/String;
```

— identical before and after obfuscation. The class signature is therefore
**stable across renaming, member reordering, and debug-info stripping**, and
because JVM `.class` and Dalvik `.dex` share the same type-descriptor grammar,
**identical across the two bytecode formats**. That cross-format equality is what
lets a JVM-bytecode reference (an AAR/JAR from Maven) match a DEX candidate
(extracted from an APK). It is verified directly in
`tests/test_android.py::test_cross_format_signature_equal`.

### What this is robust to
- Class/member/package renaming (the core of R8/ProGuard).
- Member reordering, debug/line-number stripping.
- JVM-vs-DEX compilation differences.
- Partial shrinking (tree-shaking unused classes) — handled by *containment*
  rather than equality (see §4).

### What lowers confidence (honest limits)
- **Dead-code elimination** removes some library classes from the app, lowering
  containment. Expected and tolerated; the version peak usually still stands.
- **String encryption** removes the string-anchor corroboration (secondary
  signal only — the structural signatures still work).
- **Aggressive control-flow obfuscation, class merging/repackaging, or
  virtualization** (DexGuard-class commercial tooling, rare on normal OSS
  shrinking) can alter structure and reduce containment. Treat low-containment
  results as leads, not proof.
- **Structurally identical adjacent versions** cannot be told apart from
  bytecode alone — the report shows this as a containment *plateau* rather than a
  single peak, and says so.

---

## 3. The pieces

```text
scripts/harvest_maven_library.py   Download every published version of a
                                   group:artifact (AAR/JAR) from Maven Central
                                   or Google Maven -> reference corpus folder.

scripts/android_bytecode.py        Pure-Python JVM .class and Dalvik .dex
                                   structural readers (no external tools).

scripts/android_fingerprint.py     Obfuscation-resilient signatures, MinHash,
                                   profiles, and containment scoring.

scripts/android_lib_match.py       CLI: fingerprint / build-corpus / match,
                                   plus the report.md / report.html renderer.

config.android.example.json        Example pointing at corpus + candidate.
```

Everything is **standard library only**, consistent with the rest of the kit.
No `apktool`, `dex2jar`, `baksmali`, or JVM is required.

---

## 4. The matching metric

The app is a *superset*: app code + many libraries. So presence is measured by
**containment**, not similarity:

```text
containment(ref, candidate) = |ref.class_sigs ∩ candidate.class_sigs| / |ref.class_sigs|
```

- **Is the library present?** containment ≥ threshold (`--strong-threshold`,
  default 0.70 for a strong call; `--min-containment`, default 0.10, to surface
  partials).
- **Which version?** Among versions of one library above the threshold, the
  highest containment — tie-broken by Jaccard, then surviving string anchors —
  is the bundled version. The report prints the **containment-by-version curve**;
  a single clear peak is high confidence, a flat plateau means those versions are
  structurally indistinguishable.

MinHash (64-permutation) pre-screens large corpora quickly; exact set
intersection on survivors gives the precise containment.

---

## 5. End-to-end workflow

### Step 1 — Build the reference corpus

From Maven (the common case):

```bash
# Maven Central
python3 scripts/harvest_maven_library.py \
  --coordinate com.squareup.okhttp3:okhttp \
  --out corpus/okhttp

# Google Maven (AndroidX etc.)
python3 scripts/harvest_maven_library.py \
  --coordinate androidx.core:core --repo google \
  --limit 25 --out corpus/androidx-core
```

…or from a folder of artifacts you already have (the harvester is optional):

```text
corpus/okhttp/okhttp-4.9.0.jar
corpus/okhttp/okhttp-4.9.1.jar
corpus/okhttp/okhttp-4.10.0.jar
```

The harvester also accepts a full base URL via `--repo https://…` for private
or mirrored repositories, and `--list-only` to preview versions without
downloading.

### Step 2 — Fingerprint the corpus

```bash
python3 scripts/android_lib_match.py build-corpus \
  --in corpus/okhttp \
  --out corpus/okhttp.corpus.jsonl
```

Version labels are inferred from the Maven filename
(`okhttp-4.9.3.jar` → version `4.9.3`). Override the library identity for an
entire folder with `--name group:artifact`.

You can concatenate multiple `*.corpus.jsonl` files (or point `--corpus` at a
directory of profile JSONs) to match several libraries in one pass.

### Step 3 — Match the unknown app

```bash
python3 scripts/android_lib_match.py match \
  --candidate app-release.apk \
  --corpus corpus/okhttp.corpus.jsonl \
  --out out/okhttp_match
```

The candidate can be an `.apk`, `.aar`, `.jar`, `.dex`, `.class`, or a
directory. To narrow an APK to a suspected sub-package first, extract it and
point `--candidate` at the relevant `classes*.dex` or extracted tree.

### Step 4 — Read the report

```bash
open out/okhttp_match/report.html
```

Outputs:

```text
out/okhttp_match/
  report.md / report.html        verdict + per-library version-drift tables
  csv/library_matches.csv        best version per library
  csv/version_scores.csv         every reference version score
  candidate.libprofile.json      the candidate's fingerprint
```

### Config-driven mode (optional)

`config.android.example.json` is a convenience pointer for repeatable runs; the
three subcommands above are the canonical interface.

---

## 6. Interpreting results

| Observation | Reading |
|---|---|
| containment ≈ 1.0 at one version, lower on neighbours | Strong: that version is bundled |
| high containment across a *run* of versions (plateau) | Those versions are structurally identical; narrow with changelog/string anchors |
| moderate containment (0.4–0.7), single peak | Library present but partially shrunk (dead-code elimination); version peak still informative |
| low containment everywhere | Library probably absent, OR heavily/commercially obfuscated, OR missing from the corpus |
| string-anchor overlap corroborates the structural peak | Higher confidence |
| string overlap 0 but structural containment high | Normal under string encryption — trust the structure |

This is **read-only Software Composition Analysis**. It identifies components for
vulnerability/license assessment. It performs no decryption, deobfuscation,
repackaging, or execution, matching the kit's overall scope boundary.

---

## 7. Runnable demo

A committed, offline worked example lives in `examples/android_demo/`:

```bash
bash examples/android_demo/run_demo.sh
```

It ships a synthetic library `demolib` as three JVM JARs (the corpus) and an
obfuscated, version-stripped DEX-in-APK candidate that bundles 1.1.0 under
renamed packages/classes/members. The matcher recovers `demolib 1.1.0` at
containment 1.000 across the JVM→DEX format gap. See
`examples/android_demo/README.md` for the per-version score table and how the
1.0.0-vs-1.1.0 plateau and the 2.0.0 structural change are resolved.

## 8. Validation

The approach is exercised by `tests/test_android.py`, which builds a real JVM
`.class` and a real Dalvik `.dex` in memory and asserts:

- both parsers recover identical structure;
- the structural signature is **identical across JVM and DEX**;
- the signature **survives renaming** of the class and its internal type
  references (obfuscation resilience) yet **changes on a genuine structural
  change**;
- containment ranking picks the correct bundled version and filters absent
  libraries.

```bash
python3 -m unittest discover -s tests
```

---

## 9. Relationship to prior art

The structural-signature approach is the standard, peer-reviewed technique for
obfuscation-resilient third-party-library detection on Android — the
LibScout / LibRadar / LibPecker / OSSPolice family. This kit implements the
core, dependency-free: framework-anchored structural class signatures with
containment-based version identification, plus surviving string constants as a
secondary anchor.
