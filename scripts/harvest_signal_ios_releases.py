#!/usr/bin/env python3
"""Harvest Signal-iOS GitHub releases into matrix/config files.

No third-party dependencies. Uses GitHub REST API over urllib.

Examples:
  python3 scripts/harvest_signal_ios_releases.py --limit 80 --out matrices --config-out config.signal_releases_80.json
  GITHUB_TOKEN=ghp_xxx python3 scripts/harvest_signal_ios_releases.py --all --out matrices
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable

API_BASE = "https://api.github.com"
OWNER = "signalapp"
REPO = "Signal-iOS"

SEMVER_TAG_RE = re.compile(r"^(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)\.(?P<build>\d+)$")
SHORT_VERSION_RE = re.compile(r"^\d+(?:\.\d+){1,2}$")

@dataclass
class ReleaseRow:
    index: int
    release_name: str
    tag_name: str
    expected_version: str
    expected_build: str
    expected_git_ref: str
    published_at: str
    created_at: str
    prerelease: bool
    draft: bool
    html_url: str
    tarball_url: str
    zipball_url: str
    local_archive_path: str
    artifact_id: str
    role: str
    notes: str


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def request_json(url: str, token: str | None, retries: int = 3) -> Any:
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "signal-ios-metadata-lab/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"

    last_error: Exception | None = None
    for attempt in range(1, retries + 1):
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            last_error = e
            body = e.read().decode("utf-8", errors="replace")[:1000]
            if e.code in {403, 429, 500, 502, 503, 504} and attempt < retries:
                delay = 2 ** attempt
                eprint(f"[!] HTTP {e.code}; retrying in {delay}s: {body}")
                time.sleep(delay)
                continue
            raise SystemExit(f"HTTP {e.code} from GitHub API: {body}") from e
        except Exception as e:
            last_error = e
            if attempt < retries:
                delay = 2 ** attempt
                eprint(f"[!] request failed; retrying in {delay}s: {e}")
                time.sleep(delay)
                continue
            raise SystemExit(f"GitHub API request failed: {e}") from e
    raise SystemExit(f"GitHub API request failed: {last_error}")


def fetch_releases(owner: str, repo: str, token: str | None, max_pages: int | None) -> list[dict[str, Any]]:
    releases: list[dict[str, Any]] = []
    page = 1
    while True:
        if max_pages is not None and page > max_pages:
            break
        params = urllib.parse.urlencode({"per_page": 100, "page": page})
        url = f"{API_BASE}/repos/{owner}/{repo}/releases?{params}"
        data = request_json(url, token)
        if not isinstance(data, list):
            raise SystemExit(f"Unexpected GitHub response for releases page {page}: {type(data).__name__}")
        if not data:
            break
        releases.extend(data)
        eprint(f"[*] fetched releases page {page}: {len(data)} rows")
        page += 1
    return releases


def expected_version_from_release(release_name: str, tag_name: str) -> str:
    name = (release_name or "").strip().lstrip("v")
    if SHORT_VERSION_RE.match(name):
        return name
    m = SEMVER_TAG_RE.match(tag_name.strip().lstrip("v"))
    if not m:
        return name or tag_name
    major, minor, patch = m.group("major"), m.group("minor"), m.group("patch")
    return f"{major}.{minor}" if patch == "0" else f"{major}.{minor}.{patch}"


def sanitize_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s).strip("_").lower()


def release_to_row(index: int, r: dict[str, Any]) -> ReleaseRow:
    tag = str(r.get("tag_name") or "").strip()
    name = str(r.get("name") or tag).strip()
    expected_version = expected_version_from_release(name, tag)
    safe_tag = tag.replace("/", "_")
    artifact_id = sanitize_id(f"signal_local_{safe_tag}_release")
    notes = ""
    if r.get("prerelease"):
        notes = "GitHub prerelease"
    if r.get("draft"):
        notes = "GitHub draft release"
    return ReleaseRow(
        index=index,
        release_name=name,
        tag_name=tag,
        expected_version=expected_version,
        expected_build=tag,
        expected_git_ref=tag,
        published_at=str(r.get("published_at") or ""),
        created_at=str(r.get("created_at") or ""),
        prerelease=bool(r.get("prerelease")),
        draft=bool(r.get("draft")),
        html_url=str(r.get("html_url") or ""),
        tarball_url=str(r.get("tarball_url") or ""),
        zipball_url=str(r.get("zipball_url") or ""),
        local_archive_path=f"artifacts/local/Signal-{safe_tag}.xcarchive",
        artifact_id=artifact_id,
        role="local_release_tag",
        notes=notes,
    )


def write_csv(path: Path, rows: Iterable[ReleaseRow]) -> None:
    rows = list(rows)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(asdict(rows[0]).keys()) if rows else list(ReleaseRow.__dataclass_fields__.keys()))
        writer.writeheader()
        for row in rows:
            writer.writerow(asdict(row))


def write_tags(path: Path, rows: Iterable[ReleaseRow]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(r.tag_name for r in rows if r.tag_name) + "\n", encoding="utf-8")


def make_config(rows: list[ReleaseRow], appstore_path: str, project: str) -> dict[str, Any]:
    return {
        "project": project,
        "hash_mode": "notable",
        "reference": {
            "id": "signal_appstore_reference",
            "role": "appstore_reference",
            "label": "Signal App Store IPA captured from the App Store",
            "path": appstore_path,
            "notes": "Place the captured App Store IPA at this path before running comparison. This is the production reference. Do not attempt FairPlay decryption.",
        },
        "artifacts": [
            {
                "id": row.artifact_id,
                "role": row.role,
                "label": f"Signal-iOS {row.tag_name} local Release/device archive",
                "path": row.local_archive_path,
                "expected_version": row.expected_version,
                "expected_build": row.expected_build,
                "expected_git_ref": row.expected_git_ref,
                "notes": row.notes,
            }
            for row in rows
        ],
        "normalization": {
            "expected_substitutions": [
                {"from": "org.whispersystems.signal", "to": "<BUNDLE_ID>"},
                {"from": "group.org.whispersystems.signal", "to": "<APP_GROUP>"},
                {"from": "YOURTEAMID", "to": "<TEAM_ID>"},
                {"from": "SIGNALTEAMID", "to": "<TEAM_ID>"},
            ],
            "ignore_line_regex": [
                "Authority=",
                "Signature size=",
                "Timestamp=",
                "CDHash=",
                "TeamIdentifier=",
                "CMSDigest=",
                "CMSDigestType=",
                "^\\s*\"sha256\"",
                "embedded.mobileprovision",
                "_CodeSignature",
            ],
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Harvest Signal-iOS releases into matrix/config files.")
    ap.add_argument("--owner", default=OWNER)
    ap.add_argument("--repo", default=REPO)
    ap.add_argument("--limit", type=int, default=50, help="Number of newest releases to select. Ignored with --all.")
    ap.add_argument("--all", action="store_true", help="Select all fetched releases.")
    ap.add_argument("--max-pages", type=int, default=None, help="Optional GitHub API page cap. Each page is 100 releases.")
    ap.add_argument("--include-prereleases", action="store_true")
    ap.add_argument("--include-drafts", action="store_true")
    ap.add_argument("--out", default="matrices", help="Output directory for CSV/JSON/tag files.")
    ap.add_argument("--config-out", default=None, help="Optional config JSON output path.")
    ap.add_argument("--appstore-path", default="artifacts/appstore/Signal-AppStore.ipa")
    ap.add_argument("--project", default="Signal iOS metadata release sweep")
    args = ap.parse_args()

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    raw = fetch_releases(args.owner, args.repo, token, args.max_pages)

    filtered = []
    for r in raw:
        if r.get("draft") and not args.include_drafts:
            continue
        if r.get("prerelease") and not args.include_prereleases:
            continue
        tag = str(r.get("tag_name") or "")
        if not tag:
            continue
        filtered.append(r)

    rows_all = [release_to_row(i + 1, r) for i, r in enumerate(filtered)]
    selected = rows_all if args.all else rows_all[: max(args.limit, 0)]

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    write_csv(out / "signal_releases_all.csv", rows_all)
    write_csv(out / "signal_releases_selected.csv", selected)
    write_tags(out / "signal_release_tags_selected.txt", selected)
    (out / "signal_releases_raw.json").write_text(json.dumps(raw, indent=2, sort_keys=True), encoding="utf-8")

    if args.config_out:
        config_path = Path(args.config_out)
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(json.dumps(make_config(selected, args.appstore_path, args.project), indent=2, sort_keys=True), encoding="utf-8")

    print(f"Fetched releases: {len(raw)}")
    print(f"Filtered releases: {len(rows_all)}")
    print(f"Selected releases: {len(selected)}")
    print(f"Wrote: {out / 'signal_releases_all.csv'}")
    print(f"Wrote: {out / 'signal_releases_selected.csv'}")
    print(f"Wrote: {out / 'signal_release_tags_selected.txt'}")
    if args.config_out:
        print(f"Wrote: {args.config_out}")


if __name__ == "__main__":
    main()
