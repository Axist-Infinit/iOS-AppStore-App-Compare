#!/usr/bin/env python3
"""
Generate a normalization profile from a local build's signing identity.

Comparing a locally-signed archive against the App Store IPA produces a lot of
expected signing noise: a different Apple Developer Team ID, team-prefixed
keychain groups, app groups, and application-identifier. This tool reads those
values out of a local artifact's entitlements/Info.plist and emits a
``normalization`` block that maps each one to a stable placeholder
(``<TEAM_ID>``, ``<APP_GROUP>``, ``<KEYCHAIN_GROUP>``, ``<BUNDLE_ID>``), so the
comparison engine can subtract that noise before judging real differences.

It detects values; it does not change or re-sign anything.

Examples:
  python3 scripts/make_normalization_profile.py artifacts/local/Signal-8.13.0.1623.xcarchive
  python3 scripts/make_normalization_profile.py artifacts/local/Signal.app -o normalization.signal.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho_backend  # noqa: E402

DEFAULT_IGNORE_REGEX = [
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
]


def _resolve_app(path: Path) -> Path:
    if path.is_dir() and path.suffix == ".app":
        return path
    if path.is_dir() and path.suffix == ".xcarchive":
        apps = sorted(path.glob("Products/Applications/*.app"))
        if apps:
            return apps[0]
    if path.is_dir():
        apps = sorted(path.glob("Payload/*.app")) + sorted(path.glob("Products/Applications/*.app"))
        if apps:
            return apps[0]
    raise ValueError(f"could not find a .app inside: {path}")


def detect_identity(entitlements: dict[str, Any], bundle_id: str | None) -> dict[str, Any]:
    """Pull the noisy, signer-specific values out of an entitlements dict."""
    ident: dict[str, Any] = {"team_id": None, "app_groups": [], "keychain_groups": [], "bundle_id": bundle_id}

    team = entitlements.get("com.apple.developer.team-identifier")
    app_id = entitlements.get("application-identifier") or ""
    if not team and "." in app_id:
        team = app_id.split(".", 1)[0]
    ident["team_id"] = team or None

    groups = entitlements.get("com.apple.security.application-groups") or []
    ident["app_groups"] = list(groups) if isinstance(groups, list) else [groups]

    keychain = entitlements.get("keychain-access-groups") or []
    ident["keychain_groups"] = list(keychain) if isinstance(keychain, list) else [keychain]
    return ident


def build_profile(identity: dict[str, Any]) -> dict[str, Any]:
    subs: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(value: str | None, placeholder: str) -> None:
        if value and value not in seen:
            subs.append({"from": value, "to": placeholder})
            seen.add(value)

    add(identity.get("team_id"), "<TEAM_ID>")
    add(identity.get("bundle_id"), "<BUNDLE_ID>")
    for g in identity.get("app_groups", []):
        add(g, "<APP_GROUP>")
    # Keychain groups are usually "<TEAM_ID>.<bundle>"; map the full value, the
    # TEAM_ID prefix substitution above also collapses the prefix elsewhere.
    for k in identity.get("keychain_groups", []):
        add(k, "<KEYCHAIN_GROUP>")

    return {
        "expected_substitutions": subs,
        "ignore_line_regex": list(DEFAULT_IGNORE_REGEX),
    }


def profile_from_artifact(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    import plistlib

    app = _resolve_app(path)
    info = plistlib.loads((app / "Info.plist").read_bytes())
    bundle_id = info.get("CFBundleIdentifier")
    backend = macho_backend.select_backend()
    ent = backend.codesign_entitlements(app)
    if not isinstance(ent, dict):
        ent = {}
    identity = detect_identity(ent, bundle_id)
    return identity, build_profile(identity)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Generate a normalization profile from a local build's signing identity.")
    ap.add_argument("artifact", help="Local .app / .xcarchive to read signing identity from")
    ap.add_argument("-o", "--out", help="Write the profile JSON here (else print to stdout).")
    ap.add_argument("--wrap", action="store_true",
                    help="Wrap under a top-level 'normalization' key (ready to splice into a config).")
    args = ap.parse_args(argv)

    identity, profile = profile_from_artifact(Path(args.artifact).expanduser())
    print(f"[*] team_id={identity['team_id']} bundle_id={identity['bundle_id']} "
          f"app_groups={identity['app_groups']} keychain_groups={identity['keychain_groups']}",
          file=sys.stderr)

    out_obj = {"normalization": profile} if args.wrap else profile
    text = json.dumps(out_obj, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
        print(f"[+] Wrote {args.out}", file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
