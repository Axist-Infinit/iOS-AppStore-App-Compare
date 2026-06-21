#!/usr/bin/env python3
"""
iOS bundled open-source library / framework version matcher (symbol-based).

This is the iOS counterpart to ``android_lib_match.py``. Where the Android arm
fingerprints obfuscation-resilient *structural class signatures*, the iOS arm
fingerprints the one thing that is stable across an App Store binary and a
locally built reference: the set of **exported symbol names** in the Mach-O
symbol table.

Why exported symbols work as a version fingerprint
--------------------------------------------------
iOS app/framework code is **not** name-obfuscated the way Android code is shrunk
by R8/ProGuard. C, C++ and Swift exported symbol names are stable per source
version (Swift names are mangled, but deterministically — the same source
compiles to the same mangled name). So the set of a binary's defined external
symbols is a structural fingerprint of "which library, which version".

Crucially this survives FairPlay: ``cryptid 1`` only encrypts ``__TEXT``. The
symbol table (``nlist``) and string table live in ``__LINKEDIT`` and are
normally readable even for an encrypted App Store main executable — and embedded
frameworks/dylibs are usually not encrypted at all. So symbol-set containment
works where code-level analysis cannot.

The matching reduces to set containment, exactly like the Android arm:

  * ``containment = |ref ∩ cand| / |ref|`` -> "is this library present, and how
    completely?" (the app is a superset: app code + many frameworks).
  * Among versions of one library above a presence threshold, the highest
    containment — tie-broken by Jaccard then MinHash — is the bundled version.

Subcommands
-----------
  fingerprint   Fingerprint one Mach-O artifact (.dylib/.framework/.app/dir)
                -> profile JSON
  build-corpus  Fingerprint a directory of reference versions -> corpus JSONL
  match         Match a candidate app/framework against a corpus -> report + CSV

Scope:
  Read-only metadata extraction. No FairPlay decryption, no signature/DRM
  bypass, no repackaging. Pure standard library.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import html
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import macho  # noqa: E402
# minhash / minhash_similarity are generic over a set of 64-bit ints.
from android_fingerprint import minhash, minhash_similarity  # noqa: E402

PROFILE_SCHEMA = "ios-symbol-structural-profile-v1"

# Directory suffixes that denote a Mach-O-bearing bundle we should walk into.
_BUNDLE_SUFFIXES = (".framework", ".app", ".xcarchive", ".appex", ".dylib")
# File suffixes worth probing as reference artifacts in build-corpus.
_CORPUS_SUFFIXES = (".dylib", ".a", "")


# ---------------------------------------------------------------------------
# Symbol normalization + hashing
# ---------------------------------------------------------------------------

def normalize_symbol(sym: str) -> str:
    """Normalize an exported symbol name for cross-toolchain stability.

    A single leading underscore is the C symbol convention added by the
    assembler (``_foo`` for C ``foo``); stripping exactly one leading underscore
    makes a name comparable regardless of which side recorded the underscore.
    Swift/C++ mangled names (``_$s...``, ``__Z...``) keep their remaining
    structure intact — only the first underscore is removed. Names are otherwise
    left verbatim, since they are already the stable per-version anchor.
    """
    if sym.startswith("_"):
        return sym[1:]
    return sym


def _symbol_hash(sym: str) -> int:
    digest = hashlib.blake2b(sym.encode("utf-8", "replace"), digest_size=8).digest()
    return int.from_bytes(digest, "big")


# ---------------------------------------------------------------------------
# Mach-O symbol collection
# ---------------------------------------------------------------------------

def _looks_macho(path: Path) -> bool:
    """Cheap magic check so we only fully parse real Mach-O files."""
    try:
        with path.open("rb") as f:
            head = f.read(4)
    except OSError:
        return False
    if len(head) < 4:
        return False
    magic = int.from_bytes(head, "big")
    return magic in macho._FAT_MAGICS or magic in macho._THIN_MAGICS


def iter_macho_files(root: Path) -> Iterable[Path]:
    """Yield Mach-O files under ``root``.

    Accepts a single Mach-O file, a ``.framework``/``.dylib``/``.app``/
    ``.xcarchive`` bundle, an extracted ``Payload/*.app``, or a plain directory.
    """
    if root.is_file():
        if _looks_macho(root):
            yield root
        return
    if root.is_dir():
        for p in sorted(root.rglob("*")):
            if p.is_file() and _looks_macho(p):
                yield p


def collect_defined_symbols(path: Path, normalize: bool = True) -> tuple[set[str], int, int]:
    """Collect the defined exported symbols of a Mach-O artifact.

    Walks ``path`` for Mach-O binaries, reads each binary's primary slice's
    ``defined_symbols`` (the symbol table is read-only and works at ``cryptid
    1``), and returns ``(symbols, n_binaries, n_raw_symbols)``. When
    ``normalize`` is set, a single leading underscore is stripped per the C
    convention (see :func:`normalize_symbol`).
    """
    symbols: set[str] = set()
    n_binaries = 0
    n_raw = 0
    for binary in iter_macho_files(path):
        parsed = macho.parse_path(binary)
        if not parsed.get("is_macho"):
            continue
        sl = macho.primary_slice(parsed)
        defined = sl.get("defined_symbols") or []
        if not defined:
            # A Mach-O with no exported defined symbols (fully stripped) still
            # counts as a scanned binary; it just contributes nothing.
            n_binaries += 1
            continue
        n_binaries += 1
        n_raw += len(defined)
        for s in defined:
            symbols.add(normalize_symbol(s) if normalize else s)
    return symbols, n_binaries, n_raw


# ---------------------------------------------------------------------------
# Profiles
# ---------------------------------------------------------------------------

@dataclass
class IOSLibProfile:
    name: str                  # library identity, e.g. "SignalCoreKit" or a framework name
    version: str               # version label ("" if unknown)
    n_binaries: int            # Mach-O binaries that contributed symbols
    n_symbols: int             # unique normalized symbols contributing signatures
    symbol_sigs: list[int]     # sorted blake2b-64 hashes of normalized symbol names
    minhash: list[int]         # MinHash of symbol_sigs (fast pre-screen)
    source: str = ""           # artifact path the profile came from

    def to_json(self) -> dict[str, Any]:
        return {
            "schema": PROFILE_SCHEMA,
            "name": self.name,
            "version": self.version,
            "n_binaries": self.n_binaries,
            "n_symbols": self.n_symbols,
            "source": self.source,
            # hex strings keep the JSON compact and language-agnostic.
            "symbol_sigs": [f"{s:016x}" for s in self.symbol_sigs],
            "minhash": [f"{s:016x}" for s in self.minhash],
        }

    @classmethod
    def from_json(cls, obj: dict[str, Any]) -> "IOSLibProfile":
        return cls(
            name=obj.get("name", ""),
            version=obj.get("version", ""),
            n_binaries=int(obj.get("n_binaries", 0)),
            n_symbols=int(obj.get("n_symbols", 0)),
            symbol_sigs=[int(x, 16) for x in obj.get("symbol_sigs", [])],
            minhash=[int(x, 16) for x in obj.get("minhash", [])],
            source=obj.get("source", ""),
        )


def build_profile_from_symbols(symbols: set[str], name: str, version: str = "",
                               source: str = "", n_binaries: int = 0) -> IOSLibProfile:
    sigs = {_symbol_hash(s) for s in symbols}
    return IOSLibProfile(
        name=name,
        version=version,
        n_binaries=n_binaries,
        n_symbols=len(sigs),
        symbol_sigs=sorted(sigs),
        minhash=minhash(sigs),
        source=source,
    )


def build_profile(path: Path, name: str, version: str = "", source: str = "",
                  normalize: bool = True) -> IOSLibProfile:
    """Fingerprint a Mach-O artifact path into an :class:`IOSLibProfile`."""
    symbols, n_binaries, _n_raw = collect_defined_symbols(path, normalize=normalize)
    return build_profile_from_symbols(symbols, name=name, version=version,
                                      source=source or str(path), n_binaries=n_binaries)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

@dataclass
class MatchScore:
    name: str
    version: str
    containment: float        # |ref ∩ cand| / |ref|  -- primary presence metric
    jaccard: float            # |ref ∩ cand| / |ref ∪ cand|
    matched_symbols: int
    ref_symbols: int
    minhash_est: float        # MinHash containment estimate (pre-screen)

    def to_row(self) -> dict[str, Any]:
        return {
            "library": self.name,
            "version": self.version,
            "containment": f"{self.containment:.4f}",
            "jaccard": f"{self.jaccard:.4f}",
            "matched_symbols": self.matched_symbols,
            "ref_symbols": self.ref_symbols,
            "minhash_est": f"{self.minhash_est:.4f}",
        }


def score_profile(reference: IOSLibProfile, candidate_sigs: set[int],
                  cand_minhash: list[int]) -> MatchScore:
    ref_sigs = set(reference.symbol_sigs)
    inter = ref_sigs & candidate_sigs
    containment = len(inter) / len(ref_sigs) if ref_sigs else 0.0
    union = len(ref_sigs | candidate_sigs)
    jaccard = len(inter) / union if union else 0.0
    # MinHash similarity is symmetric (Jaccard-like) corroboration of the exact
    # intersection, not the decision metric.
    mh = minhash_similarity(reference.minhash, cand_minhash)
    return MatchScore(
        name=reference.name,
        version=reference.version,
        containment=containment,
        jaccard=jaccard,
        matched_symbols=len(inter),
        ref_symbols=len(ref_sigs),
        minhash_est=mh,
    )


def rank_versions(references: list[IOSLibProfile], candidate: IOSLibProfile,
                  min_containment: float = 0.10) -> list[MatchScore]:
    """Score every reference profile against the candidate, best first.

    Ranking key models the version-identification logic:
      1. containment (is the library present, how completely)
      2. jaccard     (penalize versions carrying symbols the app lacks)
      3. minhash_est (cheap corroboration as a final tie-breaker)
    """
    cand_sigs = set(candidate.symbol_sigs)
    scores = [score_profile(ref, cand_sigs, candidate.minhash) for ref in references]
    scores = [s for s in scores if s.containment >= min_containment]
    scores.sort(key=lambda s: (s.containment, s.jaccard, s.minhash_est, s.matched_symbols),
                reverse=True)
    return scores


def group_best_by_library(scores: list[MatchScore]) -> list[MatchScore]:
    """Collapse to the single best-scoring version per library identity."""
    best: dict[str, MatchScore] = {}
    for s in scores:
        cur = best.get(s.name)
        if cur is None or (s.containment, s.jaccard, s.minhash_est) > \
                (cur.containment, cur.jaccard, cur.minhash_est):
            best[s.name] = s
    out = list(best.values())
    out.sort(key=lambda s: (s.containment, s.jaccard), reverse=True)
    return out


# ---------------------------------------------------------------------------
# Version inference from filenames
# ---------------------------------------------------------------------------

# <name>-<version>.<dylib|a> or <name>-<version> ; version starts at first numeric token.
_VERSION_IN_NAME_RE = re.compile(
    r"^(?P<name>.+?)[-_](?P<version>\d[\w.+]*?)(?:\.(?:dylib|a|framework))?$"
)


def infer_name_version(path: Path, default_name: str = "") -> tuple[str, str]:
    """Infer (library name, version) from a framework/dylib/dir filename.

    Apple frameworks rarely carry a Maven-style version in the filename, so we
    fall back to the bundle/file stem as the name and an empty version when no
    numeric token is present.
    """
    # For a bundle like Foo.framework, prefer the bundle name without suffix.
    stem = path.name
    for suf in (".framework", ".dylib", ".a", ".app", ".xcarchive", ".appex"):
        if stem.endswith(suf):
            stem = stem[: -len(suf)]
            break
    m = _VERSION_IN_NAME_RE.match(stem)
    if m:
        return (default_name or m.group("name")), m.group("version")
    return (default_name or stem), ""


# ---------------------------------------------------------------------------
# fingerprint
# ---------------------------------------------------------------------------

def cmd_fingerprint(args: argparse.Namespace) -> int:
    path = Path(args.artifact)
    if not path.exists():
        eprint(f"[!] artifact not found: {path}")
        return 2
    name, version = infer_name_version(path, args.name or "")
    if args.version:
        version = args.version
    profile = build_profile(path, name=name or path.stem, version=version,
                            source=str(path), normalize=not args.raw_symbols)
    if profile.n_symbols == 0:
        eprint(f"[!] no exported defined symbols found in {path} "
               f"(scanned {profile.n_binaries} Mach-O binaries)")
        return 1
    out = Path(args.out) if args.out else path.with_suffix(".libprofile.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile.to_json(), indent=2), encoding="utf-8")
    print(f"[+] {profile.name} {profile.version or '(unknown version)'}: "
          f"{profile.n_symbols} symbols across {profile.n_binaries} binaries")
    print(f"[+] wrote profile: {out}")
    return 0


# ---------------------------------------------------------------------------
# build-corpus
# ---------------------------------------------------------------------------

def _corpus_reference_roots(in_dir: Path) -> list[Path]:
    """Pick the reference artifacts under ``in_dir``.

    Prefer top-level bundles (``*.framework``/``*.dylib``/``*.app``) and direct
    Mach-O files; each is treated as one reference version. Falls back to
    immediate subdirectories so a layout of ``corpus/<version>/...`` works.
    """
    roots: list[Path] = []
    for p in sorted(in_dir.iterdir()):
        if p.is_dir() and p.name.endswith(_BUNDLE_SUFFIXES):
            roots.append(p)
        elif p.is_file() and (_looks_macho(p) or p.suffix.lower() in _CORPUS_SUFFIXES):
            if _looks_macho(p):
                roots.append(p)
        elif p.is_dir():
            roots.append(p)
    return roots


def cmd_build_corpus(args: argparse.Namespace) -> int:
    in_dir = Path(args.in_dir)
    if not in_dir.is_dir():
        eprint(f"[!] not a directory: {in_dir}")
        return 2
    roots = _corpus_reference_roots(in_dir)
    if not roots:
        eprint(f"[!] no Mach-O reference artifacts/bundles under {in_dir}")
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    with out.open("w", encoding="utf-8") as fh:
        for root in roots:
            name, version = infer_name_version(root, args.name or "")
            profile = build_profile(root, name=name or root.stem, version=version,
                                    source=str(root), normalize=not args.raw_symbols)
            if profile.n_symbols == 0:
                eprint(f"[-] skip (no exported symbols): {root.name}")
                skipped += 1
                continue
            fh.write(json.dumps(profile.to_json()) + "\n")
            written += 1
            print(f"[+] {profile.name} {profile.version or '?'}: "
                  f"{profile.n_symbols} symbols [{profile.n_binaries} binaries]")
    print(f"[+] corpus written: {out} ({written} profiles, {skipped} skipped)")
    return 0 if written else 1


# ---------------------------------------------------------------------------
# match
# ---------------------------------------------------------------------------

def load_corpus(path: Path) -> list[IOSLibProfile]:
    profiles: list[IOSLibProfile] = []
    if path.is_dir():
        files = sorted(path.glob("*.json")) + sorted(path.glob("*.jsonl"))
    else:
        files = [path]
    for f in files:
        text = f.read_text(encoding="utf-8")
        if f.suffix == ".jsonl" or "\n{" in text.strip():
            for line in text.splitlines():
                line = line.strip()
                if line:
                    profiles.append(IOSLibProfile.from_json(json.loads(line)))
        else:
            obj = json.loads(text)
            if isinstance(obj, list):
                profiles.extend(IOSLibProfile.from_json(o) for o in obj)
            else:
                profiles.append(IOSLibProfile.from_json(obj))
    return profiles


def cmd_match(args: argparse.Namespace) -> int:
    cand_path = Path(args.candidate)
    corpus_path = Path(args.corpus)
    if not cand_path.exists():
        eprint(f"[!] candidate not found: {cand_path}")
        return 2
    if not corpus_path.exists():
        eprint(f"[!] corpus not found: {corpus_path}")
        return 2

    references = load_corpus(corpus_path)
    if not references:
        eprint(f"[!] corpus is empty: {corpus_path}")
        return 1

    print(f"[*] fingerprinting candidate {cand_path} ...")
    candidate = build_profile(cand_path, name=args.candidate_name or cand_path.stem,
                              version="", source=str(cand_path),
                              normalize=not args.raw_symbols)
    if candidate.n_symbols == 0:
        eprint(f"[!] no exported defined symbols in candidate {cand_path}")
        return 1
    print(f"[*] candidate: {candidate.n_symbols} symbols across "
          f"{candidate.n_binaries} binaries, {len(references)} reference profiles")

    all_scores = rank_versions(references, candidate, min_containment=args.min_containment)
    best_per_lib = group_best_by_library(all_scores)

    out_dir = Path(args.out)
    (out_dir / "csv").mkdir(parents=True, exist_ok=True)

    write_csv(out_dir / "csv" / "version_scores.csv", [s.to_row() for s in all_scores])
    write_csv(out_dir / "csv" / "library_matches.csv", [s.to_row() for s in best_per_lib])
    (out_dir / "candidate.libprofile.json").write_text(
        json.dumps(candidate.to_json(), indent=2), encoding="utf-8")

    md = render_report(candidate, references, all_scores, best_per_lib, args)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.html").write_text(report_to_html(md), encoding="utf-8")

    print()
    if best_per_lib:
        for s in best_per_lib[:args.top]:
            verdict = classify(s, args)
            print(f"[=] {s.name}: best version {s.version or '?'} "
                  f"containment={s.containment:.3f} jaccard={s.jaccard:.3f} -> {verdict}")
    else:
        print("[=] no reference library cleared the presence threshold "
              f"(min-containment={args.min_containment}).")
    print(f"[+] wrote report: {out_dir / 'report.html'}")
    return 0


# ---------------------------------------------------------------------------
# Verdicts + reporting
# ---------------------------------------------------------------------------

def classify(score: MatchScore, args: argparse.Namespace) -> str:
    if score.containment >= args.strong_threshold:
        return "PRESENT (strong)"
    if score.containment >= args.min_containment:
        return "likely present (partial)"
    return "weak / inconclusive"


def best_versions_for(library: str, scores: list[MatchScore], limit: int) -> list[MatchScore]:
    rows = [s for s in scores if s.name == library]
    return rows[:limit]


def render_report(candidate: IOSLibProfile, references: list[IOSLibProfile],
                  all_scores: list[MatchScore], best_per_lib: list[MatchScore],
                  args: argparse.Namespace) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    libs = sorted({r.name for r in references})
    versions_total = len(references)

    t: list[str] = []
    t.append("# iOS bundled-library symbol-match report")
    t.append("")
    t.append(f"- Generated: {now}")
    t.append(f"- Candidate: `{candidate.source}`")
    t.append(f"- Candidate symbols fingerprinted: {candidate.n_symbols} "
             f"across {candidate.n_binaries} Mach-O binaries")
    t.append(f"- Reference corpus: {versions_total} version profiles across "
             f"{len(libs)} libr[y/ies] ({', '.join(libs[:8])}"
             f"{' ...' if len(libs) > 8 else ''})")
    t.append(f"- Presence threshold (min containment): {args.min_containment}; "
             f"strong threshold: {args.strong_threshold}")
    t.append("")
    t.append("## Verdict: best version per library")
    t.append("")
    if best_per_lib:
        t.append("| Library | Best version | Verdict | Containment | Jaccard | "
                 "Matched/Ref symbols | MinHash |")
        t.append("|---|---|---|---:|---:|---|---:|")
        for s in best_per_lib:
            verdict = classify(s, args)
            t.append(f"| {s.name} | {s.version or '?'} | {verdict} | "
                     f"{s.containment:.3f} | {s.jaccard:.3f} | "
                     f"{s.matched_symbols}/{s.ref_symbols} | {s.minhash_est:.3f} |")
    else:
        t.append("No reference library cleared the presence threshold. The candidate "
                 "either does not bundle a corpus library, or the corpus lacks the "
                 "right library/versions.")
    t.append("")

    # Per-library version drift -- the "which version" evidence.
    for library in [s.name for s in best_per_lib]:
        rows = best_versions_for(library, all_scores, args.top)
        if not rows:
            continue
        t.append(f"## Version drift: {library}")
        t.append("")
        t.append("Containment by version (higher = more of this version's exported "
                 "symbols are present in the candidate). The peak identifies the "
                 "bundled version; neighbouring versions show release-to-release drift.")
        t.append("")
        t.append("| Version | Containment | Jaccard | Matched/Ref | MinHash |")
        t.append("|---|---:|---:|---|---:|")
        for s in rows:
            t.append(f"| {s.version or '?'} | {s.containment:.3f} | {s.jaccard:.3f} | "
                     f"{s.matched_symbols}/{s.ref_symbols} | {s.minhash_est:.3f} |")
        t.append("")

    t.append("## How to read this")
    t.append("")
    t.append("- **Containment** = fraction of a reference version's exported symbol "
             "names found in the candidate. The app is a superset (app code + many "
             "frameworks), so containment, not Jaccard, decides presence.")
    t.append("- **Version pick** = among versions of one library above the threshold, "
             "the highest containment (tie-broken by Jaccard then MinHash) is the "
             "bundled version. A clear single peak is high confidence; a flat plateau "
             "across several versions means those versions export identical symbol sets "
             "and cannot be told apart from the symbol table alone.")
    t.append("- **FairPlay** (`cryptid 1`) only encrypts `__TEXT`; the symbol/string "
             "tables live in `__LINKEDIT` and stay readable, so this works on encrypted "
             "App Store main executables and on embedded frameworks/dylibs.")
    t.append("- **Stripped binaries** (`-Wl,-x`) lose *local* symbols, but exported "
             "external symbols — the ones used here — remain. Statically linked code "
             "keeps its symbols; only fully stripped/`-s` release builds erode the set.")
    t.append("")
    t.append("## Scope")
    t.append("")
    t.append("Read-only Mach-O metadata extraction. No FairPlay decryption, no "
             "signature/DRM bypass, no repackaging was performed.")
    t.append("")
    t.append("## Outputs")
    t.append("- `report.md` / `report.html`: this report")
    t.append("- `csv/library_matches.csv`: best version per library")
    t.append("- `csv/version_scores.csv`: every reference version score")
    t.append("- `candidate.libprofile.json`: the candidate fingerprint")
    return "\n".join(t)


def report_to_html(md: str) -> str:
    """Minimal, self-contained markdown-ish renderer (matches the Android report)."""
    lines = md.splitlines()
    out = ["<!doctype html><html><head><meta charset='utf-8'>",
           "<title>iOS bundled-library symbol-match report</title>",
           "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;"
           "max-width:1100px;margin:40px auto;padding:0 24px;line-height:1.45} "
           "code{background:#f4f4f4;padding:2px 4px;border-radius:4px} "
           "table{border-collapse:collapse;width:100%;font-size:13px} "
           "td,th{border:1px solid #ddd;padding:6px;vertical-align:top} "
           "th{background:#f6f6f6} h1,h2,h3{line-height:1.2}</style>",
           "</head><body>"]
    in_table = False
    rows: list[str] = []

    def flush() -> None:
        nonlocal rows, in_table
        if not in_table:
            return
        out.append("<table>")
        header_done = False
        for row in rows:
            cells = [c.strip() for c in row.strip().strip("|").split("|")]
            if all(set(c) <= {"-", ":"} and c for c in cells):
                continue
            tag = "th" if not header_done else "td"
            out.append("<tr>" + "".join(f"<{tag}>{_inline(c)}</{tag}>" for c in cells) + "</tr>")
            header_done = True
        out.append("</table>")
        rows = []
        in_table = False

    for line in lines:
        if line.startswith("|") and line.endswith("|"):
            in_table = True
            rows.append(line)
            continue
        flush()
        if line.startswith("# "):
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            out.append(f"<p>&bull; {_inline(line[2:])}</p>")
        elif not line.strip():
            out.append("")
        else:
            out.append(f"<p>{_inline(line)}</p>")
    flush()
    out.append("</body></html>")
    return "\n".join(out)


def _inline(s: str) -> str:
    s = html.escape(s)
    s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return s


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Match an iOS open-source library/framework bundled in an app "
                    "against a corpus of known versions, using Mach-O exported "
                    "symbol-set containment.")
    sub = parser.add_subparsers(dest="command", required=True)

    fp = sub.add_parser("fingerprint", help="Fingerprint one Mach-O artifact into a profile JSON.")
    fp.add_argument("--artifact", required=True,
                    help="Mach-O file, or a .framework/.dylib/.app/.xcarchive/dir to walk.")
    fp.add_argument("--name", help="Library identity. Inferred from the filename if omitted.")
    fp.add_argument("--version", help="Version label. Inferred from filename if omitted.")
    fp.add_argument("--raw-symbols", action="store_true",
                    help="Do not strip the leading underscore from symbol names.")
    fp.add_argument("-o", "--out", help="Output profile path (default: <artifact>.libprofile.json).")
    fp.set_defaults(func=cmd_fingerprint)

    bc = sub.add_parser("build-corpus", help="Fingerprint a folder of reference versions into a corpus.")
    bc.add_argument("--in", dest="in_dir", required=True,
                    help="Directory of reference frameworks/dylibs/dirs (one per version).")
    bc.add_argument("--name", help="Force one library identity for every artifact (else inferred).")
    bc.add_argument("--raw-symbols", action="store_true",
                    help="Do not strip the leading underscore from symbol names.")
    bc.add_argument("--out", required=True, help="Output corpus JSONL path.")
    bc.set_defaults(func=cmd_build_corpus)

    mt = sub.add_parser("match", help="Match a candidate app/framework against a corpus.")
    mt.add_argument("--candidate", required=True,
                    help="App/framework to identify (.app/.framework/.dylib/Mach-O/dir).")
    mt.add_argument("--candidate-name", help="Label for the candidate in the report.")
    mt.add_argument("--corpus", required=True,
                    help="Corpus JSONL/JSON, or a directory of profile JSON files.")
    mt.add_argument("--out", required=True, help="Output directory for the report.")
    mt.add_argument("--min-containment", type=float, default=0.10,
                    help="Presence threshold (default 0.10).")
    mt.add_argument("--strong-threshold", type=float, default=0.70,
                    help="Containment at/above which a match is reported as strong (default 0.70).")
    mt.add_argument("--top", type=int, default=12, help="Versions to show per library (default 12).")
    mt.add_argument("--raw-symbols", action="store_true",
                    help="Do not strip the leading underscore from symbol names.")
    mt.set_defaults(func=cmd_match)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
