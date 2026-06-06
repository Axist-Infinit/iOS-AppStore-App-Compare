#!/usr/bin/env python3
"""
Read version/build identity from an iOS artifact and pick the comparators.

Given an App Store IPA (or a local .app/.xcarchive), this prints:
  * CFBundleShortVersionString, CFBundleVersion, CFBundleIdentifier
  * the matching Signal-iOS GitHub release tag (build == CFBundleVersion)
  * N nearby releases to use as control comparators

Optionally it emits a ready-to-run comparison config containing the matched tag
plus the nearby controls, so you can go straight from "captured IPA" to "which
source tags do I build and compare".

No third-party dependencies.

Examples:
  python3 scripts/ipa_version.py artifacts/appstore/Signal-AppStore.ipa
  python3 scripts/ipa_version.py artifacts/appstore/Signal-AppStore.ipa \
      --nearby 2 --suggest-config config.poc.json
"""
from __future__ import annotations

import argparse
import csv
import fnmatch
import json
import plistlib
import sys
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_MATRIX = ROOT / "matrices" / "signal_releases_all.csv"


def read_info_plist(path: Path) -> dict[str, Any]:
    """Read the top-level app Info.plist from an .ipa, .app, or .xcarchive."""
    if path.is_dir() and path.suffix == ".app":
        return plistlib.loads((path / "Info.plist").read_bytes())
    if path.is_dir() and path.suffix == ".xcarchive":
        apps = sorted(path.glob("Products/Applications/*.app"))
        if not apps:
            raise ValueError(f"no .app inside xcarchive: {path}")
        return plistlib.loads((apps[0] / "Info.plist").read_bytes())
    if path.is_file() and path.suffix.lower() == ".ipa":
        with zipfile.ZipFile(path) as z:
            names = [n for n in z.namelist()
                     if fnmatch.fnmatch(n, "Payload/*.app/Info.plist") and n.count("/") == 2]
            if not names:
                raise ValueError(f"no Payload/*.app/Info.plist in IPA: {path}")
            return plistlib.loads(z.read(sorted(names)[0]))
    if path.is_dir():  # already-extracted Payload root
        apps = sorted(path.glob("Payload/*.app")) + sorted(path.glob("Products/Applications/*.app"))
        if apps:
            return plistlib.loads((apps[0] / "Info.plist").read_bytes())
    raise ValueError(f"unsupported artifact: {path}")


def load_matrix(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def find_matching_release(rows: list[dict[str, str]], build: str) -> dict[str, str] | None:
    """Find the release whose tag/build equals the IPA's CFBundleVersion."""
    if not build:
        return None
    for row in rows:
        if (row.get("tag_name") or "").strip() == build or (row.get("expected_build") or "").strip() == build:
            return row
    return None


def nearby_releases(rows: list[dict[str, str]], matched: dict[str, str], n: int) -> list[dict[str, str]]:
    """N releases immediately before and after the matched one, ordered by index."""
    if n <= 0 or not matched:
        return []
    ordered = sorted(rows, key=lambda r: _index(r))
    idx = next((i for i, r in enumerate(ordered) if r.get("tag_name") == matched.get("tag_name")), None)
    if idx is None:
        return []
    lo = max(0, idx - n)
    hi = min(len(ordered), idx + n + 1)
    return [r for i, r in enumerate(ordered[lo:hi], start=lo) if i != idx]


def _index(row: dict[str, str]) -> int:
    try:
        return int(row.get("index") or 0)
    except ValueError:
        return 0


def build_suggested_config(info: dict[str, Any], matched: dict[str, str] | None,
                           controls: list[dict[str, str]], appstore_path: str) -> dict[str, Any]:
    def artifact(row: dict[str, str], role: str) -> dict[str, Any]:
        tag = row.get("tag_name") or row.get("expected_build") or ""
        safe = tag.replace("/", "_")
        return {
            "id": row.get("artifact_id") or f"signal_local_{safe}",
            "role": role,
            "label": f"Signal-iOS {tag} local Release/device archive",
            "path": row.get("local_archive_path") or f"artifacts/local/Signal-{safe}.xcarchive",
            "expected_version": row.get("expected_version") or "",
            "expected_build": row.get("expected_build") or tag,
            "expected_git_ref": row.get("expected_git_ref") or tag,
        }

    artifacts = []
    if matched:
        artifacts.append(artifact(matched, "local_release_tag_exact"))
    artifacts.extend(artifact(r, "local_release_tag_control") for r in controls)
    return {
        "project": f"Signal iOS PoC comparison ({info.get('CFBundleVersion')})",
        "hash_mode": "notable",
        "reference": {
            "id": "signal_appstore_reference",
            "role": "appstore_reference",
            "label": f"Signal App Store IPA {info.get('CFBundleShortVersionString')} ({info.get('CFBundleVersion')})",
            "path": appstore_path,
        },
        "artifacts": artifacts,
        "normalization": {
            "expected_substitutions": [],
            "ignore_line_regex": ["Authority=", "Timestamp=", "CDHash=", "TeamIdentifier=", "^\\s*\"sha256\""],
        },
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Extract version/build and pick Signal-iOS comparator tags.")
    ap.add_argument("artifact", help="Path to .ipa / .app / .xcarchive")
    ap.add_argument("--matrix", default=str(DEFAULT_MATRIX), help="Release matrix CSV from harvest_signal_ios_releases.py")
    ap.add_argument("--nearby", type=int, default=2, help="Number of nearby control releases on each side (default 2).")
    ap.add_argument("--suggest-config", help="Write a ready-to-run comparison config JSON to this path.")
    ap.add_argument("--appstore-path", default="artifacts/appstore/Signal-AppStore.ipa")
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = ap.parse_args(argv)

    info = read_info_plist(Path(args.artifact).expanduser())
    build = str(info.get("CFBundleVersion") or "")
    rows = load_matrix(Path(args.matrix))
    matched = find_matching_release(rows, build)
    controls = nearby_releases(rows, matched, args.nearby) if matched else []

    payload = {
        "artifact": args.artifact,
        "CFBundleIdentifier": info.get("CFBundleIdentifier"),
        "CFBundleShortVersionString": info.get("CFBundleShortVersionString"),
        "CFBundleVersion": build,
        "matched_tag": matched.get("tag_name") if matched else None,
        "control_tags": [r.get("tag_name") for r in controls],
        "matrix_rows": len(rows),
    }

    if args.suggest_config:
        cfg = build_suggested_config(info, matched, controls, args.appstore_path)
        Path(args.suggest_config).write_text(json.dumps(cfg, indent=2, sort_keys=True), encoding="utf-8")
        payload["suggested_config"] = args.suggest_config

    if args.json:
        print(json.dumps(payload, indent=2))
        return 0

    print(f"Artifact:          {args.artifact}")
    print(f"Bundle identifier: {info.get('CFBundleIdentifier')}")
    print(f"Short version:     {info.get('CFBundleShortVersionString')}")
    print(f"Build (CFBundleVersion): {build}")
    if not rows:
        print(f"\n[!] No release matrix at {args.matrix}.")
        print("    Run: python3 scripts/harvest_signal_ios_releases.py --all --out matrices")
    elif matched:
        print(f"\nExact comparator tag:  {matched.get('tag_name')}  (build local from this Signal-iOS tag)")
        if controls:
            print("Nearby control tags:")
            for r in controls:
                print(f"  - {r.get('tag_name')}  ({r.get('published_at', '')[:10]})")
    else:
        print(f"\n[!] No release in the matrix matches build {build!r}.")
        print("    The capture may be newer/older than the harvested set; re-run the harvester.")
    if args.suggest_config:
        print(f"\nWrote suggested config: {args.suggest_config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
