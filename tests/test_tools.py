#!/usr/bin/env python3
"""
Tests for the PoC helper tools: doctor, ipa_version (extraction + comparator
selection), and make_normalization_profile.

Run: python3 -m unittest discover -s tests
"""
from __future__ import annotations

import csv
import plistlib
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import doctor  # noqa: E402
import ipa_version  # noqa: E402
import make_normalization_profile as nprof  # noqa: E402
from test_macho import build_macho, IDENT, TEAM  # noqa: E402


def _write_ipa(path: Path, short: str, build: str) -> Path:
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("Payload/Signal.app/Signal", build_macho())
        z.writestr("Payload/Signal.app/Info.plist", plistlib.dumps({
            "CFBundleExecutable": "Signal", "CFBundleIdentifier": IDENT,
            "CFBundleShortVersionString": short, "CFBundleVersion": build,
        }))
    return path


def _matrix_rows() -> list[dict[str, str]]:
    # Newest first, index 1..5 (mirrors harvest output ordering).
    tags = ["8.13.0.1623", "8.12.1.1616", "8.12.0.1599", "8.11.0.1584", "8.10.0.1570"]
    rows = []
    for i, tag in enumerate(tags, start=1):
        rows.append({
            "index": str(i), "tag_name": tag, "expected_version": tag.rsplit(".", 1)[0],
            "expected_build": tag, "expected_git_ref": tag,
            "published_at": f"2026-0{i}-01T00:00:00Z",
            "local_archive_path": f"artifacts/local/Signal-{tag}.xcarchive",
            "artifact_id": f"signal_local_{tag}",
        })
    return rows


class IpaVersionTests(unittest.TestCase):
    def test_read_info_plist_from_ipa(self):
        with tempfile.TemporaryDirectory() as td:
            ipa = _write_ipa(Path(td) / "S.ipa", "8.12", "8.12.0.1599")
            info = ipa_version.read_info_plist(ipa)
            self.assertEqual(info["CFBundleVersion"], "8.12.0.1599")
            self.assertEqual(info["CFBundleIdentifier"], IDENT)

    def test_read_info_plist_from_app_dir(self):
        with tempfile.TemporaryDirectory() as td:
            app = Path(td) / "Signal.app"
            app.mkdir()
            (app / "Signal").write_bytes(build_macho())
            with (app / "Info.plist").open("wb") as f:
                plistlib.dump({"CFBundleExecutable": "Signal", "CFBundleVersion": "8.13.0.1623"}, f)
            self.assertEqual(ipa_version.read_info_plist(app)["CFBundleVersion"], "8.13.0.1623")

    def test_exact_match_and_controls(self):
        rows = _matrix_rows()
        matched = ipa_version.find_matching_release(rows, "8.12.0.1599")
        self.assertIsNotNone(matched)
        self.assertEqual(matched["tag_name"], "8.12.0.1599")
        controls = [r["tag_name"] for r in ipa_version.nearby_releases(rows, matched, 1)]
        self.assertEqual(controls, ["8.12.1.1616", "8.11.0.1584"])  # one each side, index order

    def test_no_match(self):
        self.assertIsNone(ipa_version.find_matching_release(_matrix_rows(), "9.99.9.9999"))

    def test_suggested_config_roles(self):
        rows = _matrix_rows()
        matched = ipa_version.find_matching_release(rows, "8.12.0.1599")
        controls = ipa_version.nearby_releases(rows, matched, 1)
        info = {"CFBundleVersion": "8.12.0.1599", "CFBundleShortVersionString": "8.12"}
        cfg = ipa_version.build_suggested_config(info, matched, controls, "artifacts/appstore/Signal.ipa")
        roles = [a["role"] for a in cfg["artifacts"]]
        self.assertEqual(roles[0], "local_release_tag_exact")
        self.assertTrue(all(r == "local_release_tag_control" for r in roles[1:]))
        self.assertEqual(cfg["reference"]["path"], "artifacts/appstore/Signal.ipa")


class NormalizationProfileTests(unittest.TestCase):
    def test_detect_identity(self):
        ent = {
            "application-identifier": f"{TEAM}.{IDENT}",
            "com.apple.security.application-groups": [f"group.{IDENT}"],
            "keychain-access-groups": [f"{TEAM}.{IDENT}"],
        }
        ident = nprof.detect_identity(ent, IDENT)
        self.assertEqual(ident["team_id"], TEAM)
        self.assertEqual(ident["app_groups"], [f"group.{IDENT}"])

    def test_team_id_falls_back_to_app_id_prefix(self):
        ident = nprof.detect_identity({"application-identifier": "Z9Z9Z9Z9Z9.com.x"}, "com.x")
        self.assertEqual(ident["team_id"], "Z9Z9Z9Z9Z9")

    def test_build_profile_substitutions(self):
        ident = {"team_id": TEAM, "bundle_id": IDENT,
                 "app_groups": [f"group.{IDENT}"], "keychain_groups": [f"{TEAM}.{IDENT}"]}
        profile = nprof.build_profile(ident)
        froms = {s["from"]: s["to"] for s in profile["expected_substitutions"]}
        self.assertEqual(froms[TEAM], "<TEAM_ID>")
        self.assertEqual(froms[IDENT], "<BUNDLE_ID>")
        self.assertEqual(froms[f"group.{IDENT}"], "<APP_GROUP>")
        self.assertIn("Authority=", profile["ignore_line_regex"])

    def test_profile_from_artifact(self):
        with tempfile.TemporaryDirectory() as td:
            app = Path(td) / "Signal.app"
            app.mkdir()
            (app / "Signal").write_bytes(build_macho())  # carries entitlements w/ TEAM
            with (app / "Info.plist").open("wb") as f:
                plistlib.dump({"CFBundleExecutable": "Signal", "CFBundleIdentifier": IDENT}, f)
            identity, profile = nprof.profile_from_artifact(app)
            self.assertEqual(identity["team_id"], TEAM)
            self.assertTrue(any(s["to"] == "<TEAM_ID>" for s in profile["expected_substitutions"]))


class DoctorTests(unittest.TestCase):
    def test_gather_runs_and_flags_missing_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            results = doctor.gather(Path(td) / "appstore", Path(td) / "local")
            checks = {r["check"]: r for r in results}
            self.assertEqual(checks["metadata backend"]["status"], doctor.OK)  # always available
            self.assertEqual(checks["artifact: App Store IPA"]["status"], doctor.WARN)

    def test_no_blockers_on_this_host(self):
        with tempfile.TemporaryDirectory() as td:
            results = doctor.gather(Path(td) / "appstore", Path(td) / "local")
            self.assertEqual([r for r in results if r["status"] == doctor.BLOCK], [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
