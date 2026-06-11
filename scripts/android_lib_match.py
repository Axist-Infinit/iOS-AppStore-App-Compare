#!/usr/bin/env python3
"""
Android bundled-library matcher.

Identify which open-source library -- and which *version* -- is compiled into an
app, even when the library has been stripped of version metadata and obfuscated
by R8/ProGuard. This is the Android counterpart to the iOS metadata-comparison
engine in this kit: build a corpus of known reference versions, fingerprint each,
then match an unknown artifact against the corpus and report the best version
plus the drift around it.

Methodology and obfuscation-resilience rationale: see
``scripts/android_fingerprint.py`` and ``docs/android_library_matching.md``.

Subcommands
-----------
  fingerprint   Fingerprint one artifact (.aar/.jar/.apk/.dex/.class/dir) -> profile JSON
  build-corpus  Fingerprint a directory of reference versions             -> corpus JSONL
  match         Match a candidate app/library against a corpus            -> report + CSV

Scope:
  Read-only Software Composition Analysis. No decryption, deobfuscation,
  repackaging, or execution. Pure standard library.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import json
import re
import sys
from pathlib import Path
from typing import Any, Iterable

sys.path.insert(0, str(Path(__file__).resolve().parent))

import android_bytecode as abc  # noqa: E402
import android_fingerprint as afp  # noqa: E402
from android_fingerprint import LibraryProfile, MatchScore  # noqa: E402


# ---------------------------------------------------------------------------
# Version inference from filenames (Maven artifact naming convention).
# ---------------------------------------------------------------------------

# <artifact>-<version>.<aar|jar>, version starts at the first numeric token.
_VERSION_IN_NAME_RE = re.compile(
    r"^(?P<artifact>.+?)-(?P<version>\d[\w.+\-]*?)(?:-(?:sources|javadoc))?\.(?:aar|jar|apk)$"
)


def infer_name_version(path: Path, default_name: str = "") -> tuple[str, str]:
    m = _VERSION_IN_NAME_RE.match(path.name)
    if m:
        return (default_name or m.group("artifact")), m.group("version")
    return (default_name or path.stem), ""


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
    units = abc.load_units(path, max_classes=args.max_classes)
    if not units.classes:
        eprint(f"[!] no parseable JVM/DEX classes found in {path}")
        return 1
    profile = afp.build_profile(units, name=name or path.stem, version=version, source=str(path))
    out = Path(args.out) if args.out else path.with_suffix(".libprofile.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(profile.to_json(), indent=2), encoding="utf-8")
    print(f"[+] {profile.name} {profile.version or '(unknown version)'}: "
          f"{profile.n_classes} classes, {len(profile.string_sigs)} string anchors "
          f"[{','.join(profile.formats) or 'none'}]")
    print(f"[+] wrote profile: {out}")
    return 0


# ---------------------------------------------------------------------------
# build-corpus
# ---------------------------------------------------------------------------

def cmd_build_corpus(args: argparse.Namespace) -> int:
    in_dir = Path(args.in_dir)
    if not in_dir.is_dir():
        eprint(f"[!] not a directory: {in_dir}")
        return 2
    artifacts = sorted(p for p in in_dir.rglob("*")
                       if p.suffix.lower() in (".aar", ".jar", ".apk", ".dex"))
    if not artifacts:
        eprint(f"[!] no .aar/.jar/.apk/.dex reference artifacts under {in_dir}")
        return 1

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    written = 0
    skipped = 0
    with out.open("w", encoding="utf-8") as fh:
        for path in artifacts:
            name, version = infer_name_version(path, args.name or "")
            units = abc.load_units(path, max_classes=args.max_classes)
            if not units.classes:
                eprint(f"[-] skip (no classes): {path.name}")
                skipped += 1
                continue
            profile = afp.build_profile(units, name=name or path.stem,
                                        version=version, source=str(path))
            fh.write(json.dumps(profile.to_json()) + "\n")
            written += 1
            print(f"[+] {profile.name} {profile.version or '?'}: "
                  f"{profile.n_classes} classes [{','.join(profile.formats)}]")
    print(f"[+] corpus written: {out} ({written} profiles, {skipped} skipped)")
    return 0 if written else 1


# ---------------------------------------------------------------------------
# match
# ---------------------------------------------------------------------------

def load_corpus(path: Path) -> list[LibraryProfile]:
    profiles: list[LibraryProfile] = []
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
                    profiles.append(LibraryProfile.from_json(json.loads(line)))
        else:
            obj = json.loads(text)
            if isinstance(obj, list):
                profiles.extend(LibraryProfile.from_json(o) for o in obj)
            else:
                profiles.append(LibraryProfile.from_json(obj))
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
    units = abc.load_units(cand_path, max_classes=args.max_classes)
    if not units.classes:
        eprint(f"[!] no parseable JVM/DEX classes in candidate {cand_path}")
        return 1
    candidate = afp.build_profile(units, name=args.candidate_name or cand_path.stem,
                                  version="", source=str(cand_path))
    print(f"[*] candidate: {candidate.n_classes} classes "
          f"[{','.join(candidate.formats)}], {len(references)} reference profiles")

    all_scores = afp.rank_versions(references, candidate, min_containment=args.min_containment)
    best_per_lib = afp.group_best_by_library(all_scores)

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


def render_report(candidate: LibraryProfile, references: list[LibraryProfile],
                  all_scores: list[MatchScore], best_per_lib: list[MatchScore],
                  args: argparse.Namespace) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    libs = sorted({r.name for r in references})
    versions_total = len(references)

    t: list[str] = []
    t.append(f"# Android bundled-library match report")
    t.append("")
    t.append(f"- Generated: {now}")
    t.append(f"- Candidate: `{candidate.source}`")
    t.append(f"- Candidate classes fingerprinted: {candidate.n_classes} "
             f"(formats: {', '.join(candidate.formats) or 'none'})")
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
                 "Matched/Ref classes | String anchors |")
        t.append("|---|---|---|---:|---:|---|---:|")
        for s in best_per_lib:
            verdict = classify(s, args)
            t.append(f"| {s.name} | {s.version or '?'} | {verdict} | "
                     f"{s.containment:.3f} | {s.jaccard:.3f} | "
                     f"{s.matched_classes}/{s.ref_classes} | {s.string_overlap:.3f} |")
    else:
        t.append("No reference library cleared the presence threshold. The candidate "
                 "either does not bundle a corpus library, or the corpus lacks the "
                 "right library/versions.")
    t.append("")

    # Per-library version drift -- the "which version" evidence. The containment
    # curve peaking at one version is the version-identification signal.
    for library in [s.name for s in best_per_lib]:
        rows = best_versions_for(library, all_scores, args.top)
        if not rows:
            continue
        t.append(f"## Version drift: {library}")
        t.append("")
        t.append("Containment by version (higher = more of this version's classes are "
                 "present in the candidate). The peak identifies the bundled version; "
                 "neighbouring versions show the release-to-release drift.")
        t.append("")
        t.append("| Version | Containment | Jaccard | Matched/Ref | String anchors |")
        t.append("|---|---:|---:|---|---:|")
        for s in rows:
            t.append(f"| {s.version or '?'} | {s.containment:.3f} | {s.jaccard:.3f} | "
                     f"{s.matched_classes}/{s.ref_classes} | {s.string_overlap:.3f} |")
        t.append("")

    t.append("## How to read this")
    t.append("")
    t.append("- **Containment** = fraction of a reference version's class signatures "
             "found in the candidate. The app is a superset (app code + many libraries), "
             "so containment, not Jaccard, decides presence.")
    t.append("- **Version pick** = among versions of one library above the threshold, "
             "the highest containment (tie-broken by Jaccard then string anchors) is the "
             "bundled version. A clear single peak is high confidence; a flat plateau "
             "across several versions means those versions are structurally identical "
             "(no distinguishing class changes) and can't be told apart from bytecode "
             "alone.")
    t.append("- **Obfuscation** renames the library's own symbols but not framework "
             "types or code shape, so signatures survive R8/ProGuard. Heavy control-flow "
             "flattening / string encryption / class virtualization (rare for normal OSS "
             "library shrinking) will lower containment.")
    t.append("- **String anchors** are surviving literal constants; treat them as "
             "corroboration, not proof, since string encryption can remove them.")
    t.append("")
    t.append("## Scope")
    t.append("")
    t.append("Read-only structural Software Composition Analysis. No decryption, "
             "deobfuscation, repackaging, or execution was performed.")
    t.append("")
    t.append("## Outputs")
    t.append("- `report.md` / `report.html`: this report")
    t.append("- `csv/library_matches.csv`: best version per library")
    t.append("- `csv/version_scores.csv`: every reference version score")
    t.append("- `candidate.libprofile.json`: the candidate fingerprint")
    return "\n".join(t)


def report_to_html(md: str) -> str:
    """Minimal, self-contained markdown-ish renderer (matches the iOS report style)."""
    lines = md.splitlines()
    out = ["<!doctype html><html><head><meta charset='utf-8'>",
           "<title>Android bundled-library match report</title>",
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
        description="Match obfuscated, version-stripped Android/JVM open-source "
                    "libraries bundled in an app against a corpus of known versions.")
    sub = parser.add_subparsers(dest="command", required=True)

    fp = sub.add_parser("fingerprint", help="Fingerprint one artifact into a profile JSON.")
    fp.add_argument("artifact", help=".aar/.jar/.apk/.dex/.class or a directory")
    fp.add_argument("--name", help="Library identity (e.g. group:artifact). Inferred if omitted.")
    fp.add_argument("--version", help="Version label. Inferred from filename if omitted.")
    fp.add_argument("--max-classes", type=int, default=0, help="Cap classes parsed (0=all).")
    fp.add_argument("-o", "--out", help="Output profile path (default: <artifact>.libprofile.json).")
    fp.set_defaults(func=cmd_fingerprint)

    bc = sub.add_parser("build-corpus", help="Fingerprint a folder of reference versions into a corpus.")
    bc.add_argument("--in", dest="in_dir", required=True, help="Directory of reference .aar/.jar/.apk/.dex.")
    bc.add_argument("--name", help="Force one library identity for every artifact (else inferred per file).")
    bc.add_argument("--max-classes", type=int, default=0, help="Cap classes parsed per artifact (0=all).")
    bc.add_argument("--out", required=True, help="Output corpus JSONL path.")
    bc.set_defaults(func=cmd_build_corpus)

    mt = sub.add_parser("match", help="Match a candidate app/library against a corpus.")
    mt.add_argument("--candidate", required=True, help="App/library to identify (.apk/.aar/.jar/.dex/dir).")
    mt.add_argument("--candidate-name", help="Label for the candidate in the report.")
    mt.add_argument("--corpus", required=True, help="Corpus JSONL/JSON, or a directory of profile JSON files.")
    mt.add_argument("--out", required=True, help="Output directory for the report.")
    mt.add_argument("--min-containment", type=float, default=0.10,
                    help="Presence threshold (default 0.10).")
    mt.add_argument("--strong-threshold", type=float, default=0.70,
                    help="Containment at/above which a match is reported as strong (default 0.70).")
    mt.add_argument("--top", type=int, default=12, help="Versions to show per library (default 12).")
    mt.add_argument("--max-classes", type=int, default=0, help="Cap classes parsed in the candidate (0=all).")
    mt.set_defaults(func=cmd_match)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
