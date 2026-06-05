#!/usr/bin/env python3
"""Create a reduced config JSON containing only local archives that exist."""
from __future__ import annotations

import argparse
import csv
import json
import re
from pathlib import Path


def sanitize_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_").lower()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--matrix", default="matrices/signal_releases_selected.csv")
    ap.add_argument("--appstore-path", default="artifacts/appstore/Signal-AppStore.ipa")
    ap.add_argument("--out", default="config.signal_releases_existing.json")
    ap.add_argument("--project", default="Signal iOS metadata release sweep - existing archives only")
    args = ap.parse_args()

    root = Path.cwd()
    artifacts = []
    with open(args.matrix, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            path = row.get("local_archive_path") or f"artifacts/local/Signal-{row.get('tag_name')}.xcarchive"
            if (root / path).exists():
                tag = row.get("expected_git_ref") or row.get("tag_name") or Path(path).stem
                artifacts.append({
                    "id": row.get("artifact_id") or sanitize_id(f"signal_local_{tag}_release"),
                    "role": row.get("role") or "local_release_tag",
                    "label": f"Signal-iOS {tag} local Release/device archive",
                    "path": path,
                    "expected_version": row.get("expected_version") or "",
                    "expected_build": row.get("expected_build") or tag,
                    "expected_git_ref": tag,
                })

    config = {
        "project": args.project,
        "hash_mode": "notable",
        "reference": {
            "id": "signal_appstore_reference",
            "role": "appstore_reference",
            "label": "Signal App Store IPA captured from the App Store",
            "path": args.appstore_path,
        },
        "artifacts": artifacts,
        "normalization": {
            "expected_substitutions": [
                {"from": "org.whispersystems.signal", "to": "<BUNDLE_ID>"},
                {"from": "group.org.whispersystems.signal", "to": "<APP_GROUP>"},
                {"from": "YOURTEAMID", "to": "<TEAM_ID>"},
                {"from": "SIGNALTEAMID", "to": "<TEAM_ID>"},
            ],
            "ignore_line_regex": ["Authority=", "Timestamp=", "CDHash=", "TeamIdentifier=", "^\\s*\"sha256\""],
        },
    }
    Path(args.out).write_text(json.dumps(config, indent=2, sort_keys=True), encoding="utf-8")
    print(f"Existing archives found: {len(artifacts)}")
    print(f"Wrote: {args.out}")


if __name__ == "__main__":
    main()
