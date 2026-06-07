#!/usr/bin/env python3
"""
One-command PoC driver for the Signal iOS metadata comparison lab.

Given a captured App Store IPA, this:
  1. runs the preflight (doctor) and prints blockers,
  2. reads the IPA's version/build and selects the matching Signal-iOS tag plus
     N nearby control tags,
  3. writes a comparison config (exact + control comparators),
  4. runs the comparison over whatever local archives already exist,
  5. prints the report path (and the build plan for any missing comparators).

It never builds or signs anything; building local archives is a macOS/Xcode step
(scripts/build_signal_release_sweep.sh). On a host with no local archives yet,
this still produces the config and the exact list of tags to build.

Example:
  python3 scripts/run_poc.py --appstore artifacts/appstore/Signal-AppStore.ipa --limit-nearby 2
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import doctor  # noqa: E402
import ios_multiversion_meta_compare as engine  # noqa: E402
import ipa_version  # noqa: E402
import macho_backend  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent


def _print_doctor(appstore_dir: Path, local_dir: Path) -> int:
    results = doctor.gather(appstore_dir, local_dir)
    blockers = [r for r in results if r["status"] == doctor.BLOCK]
    print("== preflight ==")
    for r in results:
        if r["status"] in (doctor.WARN, doctor.BLOCK):
            print(f"  {doctor._MARK[r['status']]:7} {r['check']}: {r['detail']}")
    print(f"  backend: {macho_backend.select_backend().name}")
    return len(blockers)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="One-command Signal iOS metadata PoC.")
    ap.add_argument("--appstore", required=True, help="Captured App Store IPA path.")
    ap.add_argument("--matrix", default=str(ipa_version.DEFAULT_MATRIX), help="Release matrix CSV.")
    ap.add_argument("--limit-nearby", type=int, default=2, help="Nearby control tags on each side (default 2).")
    ap.add_argument("--config-out", default=str(ROOT / "config.poc.json"))
    ap.add_argument("--out", default=str(ROOT / "out" / "poc"))
    ap.add_argument("--local-dir", default=str(ROOT / "artifacts" / "local"))
    ap.add_argument("--hash-mode", choices=["full", "notable", "none"], default="notable")
    ap.add_argument("--jobs", type=int, default=4)
    args = ap.parse_args(argv)

    appstore = Path(args.appstore).expanduser()
    if not appstore.exists():
        print(f"[x] App Store IPA not found: {appstore}", file=sys.stderr)
        print("    Acquire it first: APPLE_ID=you@example.com ./scripts/acquire_ipatool.sh", file=sys.stderr)
        return 2

    blockers = _print_doctor(appstore.parent, Path(args.local_dir))
    if blockers:
        print(f"[x] {blockers} preflight blocker(s); resolve before running.", file=sys.stderr)
        return 1

    # 2-3. Identity + comparator selection + config.
    print("\n== version / comparators ==")
    info = ipa_version.read_info_plist(appstore)
    build = str(info.get("CFBundleVersion") or "")
    rows = ipa_version.load_matrix(Path(args.matrix))
    matched = ipa_version.find_matching_release(rows, build)
    controls = ipa_version.nearby_releases(rows, matched, args.limit_nearby) if matched else []
    print(f"  build {build} -> "
          + (f"exact tag {matched['tag_name']}" if matched else "no matching tag in matrix"))
    if controls:
        print("  controls: " + ", ".join(r["tag_name"] for r in controls))

    cfg = ipa_version.build_suggested_config(info, matched, controls, str(appstore))
    Path(args.config_out).write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
    print(f"  wrote config: {args.config_out}")

    # 4. Which comparators exist on disk?
    base = Path(args.config_out).resolve().parent
    present, missing = [], []
    for art in cfg["artifacts"]:
        p = Path(art["path"])
        p = p if p.is_absolute() else (base / p)
        (present if p.exists() else missing).append(art)
    if missing:
        print("\n== build plan (missing local comparators) ==")
        for art in missing:
            print(f"  build Signal-iOS tag {art['expected_git_ref']} -> {art['path']}")
        print("  (macOS) ./scripts/build_signal_release_sweep.sh, then copy .xcarchive into artifacts/local/")

    if not present:
        print("\n[!] No local comparator archives exist yet; nothing to compare.")
        print(f"    Build at least the exact tag, then re-run, or run the engine directly with --config {args.config_out} --skip-missing.")
        return 0

    # 5. Compare.
    print("\n== comparison ==")
    config_path = Path(args.config_out).resolve()
    config = engine.load_json(config_path)
    project, reference, candidates, normalization, hash_mode = engine.specs_from_config(config, config_path.parent)
    out_dir = Path(args.out).expanduser().resolve()
    engine.compare_all(project, reference, candidates, normalization, args.hash_mode, out_dir,
                       jobs=args.jobs, skip_missing=True,
                       build_status_path=_default_build_status())
    print(f"\n[+] Report: {out_dir / 'report.html'}")
    return 0


def _default_build_status() -> Path | None:
    p = ROOT / "out" / "build_logs" / "build_status.csv"
    return p if p.exists() else None


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
