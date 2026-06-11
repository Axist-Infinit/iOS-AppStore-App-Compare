#!/usr/bin/env python3
"""Harvest published versions of an open-source library from a Maven repository.

This is the Android counterpart to ``harvest_signal_ios_releases.py``: it builds
the *reference corpus* of known versions that the bundled-library matcher scores
an unknown app against. It downloads each version's primary artifact (``.aar``,
falling back to ``.jar``) so ``android_lib_match.py build-corpus`` can fingerprint
them.

No third-party dependencies. Uses Maven repository HTTP layout over urllib.

Default repositories:
  Maven Central : https://repo1.maven.org/maven2
  Google Maven  : https://dl.google.com/dl/android/maven2   (--repo google)

Examples:
  python3 scripts/harvest_maven_library.py --coordinate com.squareup.okhttp3:okhttp \
      --out corpus/okhttp
  python3 scripts/harvest_maven_library.py --coordinate androidx.core:core \
      --repo google --limit 25 --out corpus/androidx-core
"""
from __future__ import annotations

import argparse
import csv
import sys
import time
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

REPOS = {
    "central": "https://repo1.maven.org/maven2",
    "google": "https://dl.google.com/dl/android/maven2",
}


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def fetch(url: str, retries: int = 4) -> bytes:
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "android-lib-corpus/1.0"})
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            last = e
        except Exception as e:  # noqa: BLE001 - network resilience
            last = e
        if attempt < retries:
            time.sleep(2 ** attempt)
    raise RuntimeError(f"failed to fetch {url}: {last}")


def coordinate_path(group: str, artifact: str) -> str:
    return f"{group.replace('.', '/')}/{artifact}"


def list_versions(base: str, group: str, artifact: str) -> list[str]:
    url = f"{base}/{coordinate_path(group, artifact)}/maven-metadata.xml"
    root = ET.fromstring(fetch(url))
    versions = [v.text for v in root.findall(".//versions/version") if v.text]
    return versions


def is_release(version: str) -> bool:
    low = version.lower()
    return not any(tag in low for tag in
                   ("-alpha", "-beta", "-rc", "-snapshot", "-dev", "-m", "-preview"))


def download_artifact(base: str, group: str, artifact: str, version: str,
                      out_dir: Path) -> tuple[Path | None, str]:
    cpath = coordinate_path(group, artifact)
    for ext in ("aar", "jar"):
        url = f"{base}/{cpath}/{version}/{artifact}-{version}.{ext}"
        try:
            blob = fetch(url)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                continue
            return None, f"http {e.code}"
        except Exception as e:  # noqa: BLE001
            return None, str(e)
        dest = out_dir / f"{artifact}-{version}.{ext}"
        dest.write_bytes(blob)
        return dest, ext
    return None, "no aar/jar"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Harvest Maven library versions into a reference corpus directory.")
    p.add_argument("--coordinate", required=True, help="group:artifact, e.g. com.squareup.okhttp3:okhttp")
    p.add_argument("--repo", default="central", help="Repository: central|google|<full base url> (default central).")
    p.add_argument("--out", required=True, help="Output directory for downloaded artifacts.")
    p.add_argument("--limit", type=int, default=0, help="Download only the newest N versions (0=all).")
    p.add_argument("--include-prereleases", action="store_true", help="Include alpha/beta/rc/snapshot versions.")
    p.add_argument("--list-only", action="store_true", help="List versions without downloading.")
    args = p.parse_args(argv)

    if ":" not in args.coordinate:
        eprint("[!] --coordinate must be group:artifact")
        return 2
    group, artifact = args.coordinate.split(":", 1)
    base = REPOS.get(args.repo, args.repo).rstrip("/")

    try:
        versions = list_versions(base, group, artifact)
    except Exception as e:  # noqa: BLE001
        eprint(f"[!] could not list versions for {args.coordinate} at {base}: {e}")
        return 1

    if not args.include_prereleases:
        versions = [v for v in versions if is_release(v)]
    # maven-metadata lists oldest->newest; newest first for --limit.
    versions = list(reversed(versions))
    if args.limit:
        versions = versions[:args.limit]

    print(f"[*] {args.coordinate}: {len(versions)} versions selected from {base}")
    if args.list_only:
        for v in versions:
            print(v)
        return 0

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_rows: list[dict[str, str]] = []
    ok = 0
    for v in versions:
        dest, info = download_artifact(base, group, artifact, v, out_dir)
        if dest:
            ok += 1
            print(f"[+] {v} -> {dest.name} ({info})")
            manifest_rows.append({"coordinate": args.coordinate, "version": v,
                                  "ext": info, "file": dest.name})
        else:
            eprint(f"[-] {v}: {info}")
            manifest_rows.append({"coordinate": args.coordinate, "version": v,
                                  "ext": "", "file": ""})

    manifest = out_dir / "corpus_manifest.csv"
    with manifest.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["coordinate", "version", "ext", "file"])
        w.writeheader()
        w.writerows(manifest_rows)
    print(f"[+] downloaded {ok}/{len(versions)} artifacts into {out_dir}")
    print(f"[+] manifest: {manifest}")
    print(f"[*] next: python3 scripts/android_lib_match.py build-corpus "
          f"--in {out_dir} --out {out_dir}.corpus.jsonl")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
