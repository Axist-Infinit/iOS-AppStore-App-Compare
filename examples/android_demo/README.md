# Worked example: identifying an obfuscated, version-stripped Android library

This is a runnable, fully offline demo of the Android bundled-library matcher
(see [`../../docs/android_library_matching.md`](../../docs/android_library_matching.md)).
It demonstrates the exact hard case the framework is built for:

> A compiled Android library is bundled inside an app. Its version metadata is
> gone and its packages/classes/members are obfuscated. Which library — and which
> version — is it?

## What the demo contains

A small synthetic library, **`demolib`**, in two roles:

| Role | Form | Why this form |
|---|---|---|
| Reference corpus (`lib_versions/`) | **JVM `.class` JARs** — `demolib-1.0.0.jar`, `-1.1.0.jar`, `-2.0.0.jar` | Exactly how Maven Central / Google Maven ship a library |
| Candidate (`app/obfuscated-app.apk`) | **Dalvik `.dex` inside an APK**, packages/classes/members renamed, no version field, mixed with 40 unrelated "app" classes | Exactly how an obfuscated library lands in a shipped app |

The candidate bundles **demolib 1.1.0**, but nothing in it *says* so — the names
are scrambled (`com/demolib/HttpClient` → `a/a`, members → `m0`, `f1`, …) and it
is a *different bytecode format* (DEX) from the references (JVM). Matching
therefore relies entirely on obfuscation-resilient structural signatures.

The three versions differ structurally on purpose:
- `1.0.0` — 5 classes (base)
- `1.1.0` — adds `Interceptor` + `Cache` (7 classes) ← **bundled**
- `2.0.0` — adds `Dispatcher` **and changes `HttpClient`'s shape** (8 classes)

## Run it

```bash
bash examples/android_demo/run_demo.sh
```

(or `python3 examples/android_demo/generate_demo_artifacts.py` to (re)generate
the artifacts, then drive `scripts/android_lib_match.py` yourself.)

## Expected result

```text
[=] demolib: best version 1.1.0 containment=1.000 jaccard=0.259 -> PRESENT (strong)
```

`out/match/csv/version_scores.csv`:

| version | containment | jaccard | matched/ref | reading |
|---|---:|---:|---|---|
| **1.1.0** | **1.000** | **0.259** | 7/7 | **bundled version** — all classes present, best Jaccard |
| 1.0.0 | 1.000 | 0.185 | 5/5 | a *subset* of 1.1.0, so also fully contained → the tie-break (Jaccard) correctly demotes it |
| 2.0.0 | 0.750 | 0.207 | 6/8 | `HttpClient` changed + `Dispatcher` absent → 2 classes missing |

This is the version-identification logic in action:

- **Containment** found the library present despite obfuscation and the JVM→DEX
  format change.
- **1.0.0 vs 1.1.0** is the "plateau" case (both 100% contained because 1.0.0 ⊂
  1.1.0); the Jaccard tie-break picks the more complete, correct version.
- **2.0.0** is excluded by the structural change a real version bump introduces.

`string_overlap` is `0.000` here because these tiny synthetic classes carry no
string constants — the demo is resolved by **structure alone**, which is the
point: structural signatures are the primary signal, string anchors only
corroborate.

## Files

```text
generate_demo_artifacts.py   builds the JARs (JVM) and APK (obfuscated DEX) from one shared spec
run_demo.sh                  generate (if needed) -> build-corpus -> match -> report
lib_versions/*.jar           reference corpus (committed)
app/obfuscated-app.apk       candidate (committed)
out/                         generated corpus + report (gitignored)
```
