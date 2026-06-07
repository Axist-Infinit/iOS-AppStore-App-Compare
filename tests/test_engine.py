#!/usr/bin/env python3
"""
Tests for the Phase 1 engine features: zip-slip-safe extraction, content-
addressed caching, config validation, --skip-missing, build-status ingestion,
finding-evidence links, and HTML rendering.

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

import ios_multiversion_meta_compare as engine  # noqa: E402
from test_macho import build_macho, IDENT  # noqa: E402


def _make_app(root: Path, name: str, version: str, build: str, cryptid: int = 0) -> Path:
    app = root / f"{name}.app"
    app.mkdir(parents=True, exist_ok=True)
    (app / name).write_bytes(build_macho(cryptid=cryptid))
    with (app / "Info.plist").open("wb") as f:
        plistlib.dump({
            "CFBundleExecutable": name,
            "CFBundleIdentifier": IDENT,
            "CFBundleShortVersionString": version,
            "CFBundleVersion": build,
            "MinimumOSVersion": "15.0",
        }, f)
    return app


def _make_ipa(path: Path, name: str = "Signal") -> Path:
    """A well-formed IPA: Payload/<name>.app/{Info.plist,<name>}."""
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(f"Payload/{name}.app/{name}", build_macho())
        z.writestr(f"Payload/{name}.app/Info.plist",
                   plistlib.dumps({"CFBundleExecutable": name, "CFBundleIdentifier": IDENT}))
    return path


class ExtractionSafetyTests(unittest.TestCase):
    def test_zip_slip_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            evil = root / "evil.ipa"
            with zipfile.ZipFile(evil, "w") as z:
                z.writestr("Payload/App.app/Info.plist", b"x")
                z.writestr("../../escape.txt", b"pwned")  # path traversal
            with self.assertRaises(ValueError):
                engine.resolve_artifact(evil, root / "work", "evil")
            self.assertFalse((root.parent / "escape.txt").exists())

    def test_ipa_extraction_is_cached(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ipa = _make_ipa(root / "Signal.ipa")
            work = root / "work"
            app1 = engine.resolve_artifact(ipa, work, "signal")
            marker = app1.parent.parent / ".extracted_ok"   # <work>/<digest>/.extracted_ok
            self.assertTrue(marker.exists())
            mtime = marker.stat().st_mtime_ns
            app2 = engine.resolve_artifact(ipa, work, "signal")  # second call reuses
            self.assertEqual(app1, app2)
            self.assertEqual(marker.stat().st_mtime_ns, mtime)  # not re-extracted


class ConfigValidationTests(unittest.TestCase):
    def _base_config(self, root: Path) -> dict:
        ref = _make_app(root, "ref", "8.13", "8.13.0.1623", cryptid=1)
        return {
            "hash_mode": "notable",
            "reference": {"id": "ref", "path": str(ref)},
            "artifacts": [],
            "normalization": {"ignore_line_regex": []},
        }

    def test_clean_config_has_no_errors(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._base_config(root)
            cfg["artifacts"].append({"id": "c1", "path": str(_make_app(root, "c1", "8.12", "8.12.0.1"))})
            errors, warnings = engine.validate_config(cfg, root)
            self.assertEqual(errors, [])

    def test_bad_hash_mode(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._base_config(Path(td))
            cfg["hash_mode"] = "bogus"
            errors, _ = engine.validate_config(cfg, Path(td))
            self.assertTrue(any("hash_mode" in e for e in errors))

    def test_duplicate_ids(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._base_config(root)
            a = _make_app(root, "dup", "8.12", "8.12.0.1")
            cfg["artifacts"] = [{"id": "dup", "path": str(a)}, {"id": "dup", "path": str(a)}]
            errors, _ = engine.validate_config(cfg, root)
            self.assertTrue(any("duplicate" in e for e in errors))

    def test_bad_regex(self):
        with tempfile.TemporaryDirectory() as td:
            cfg = self._base_config(Path(td))
            cfg["normalization"]["ignore_line_regex"] = ["valid", "([unclosed"]
            errors, _ = engine.validate_config(cfg, Path(td))
            self.assertTrue(any("ignore_line_regex" in e for e in errors))

    def test_missing_candidate_is_error_then_warning(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = self._base_config(root)
            cfg["artifacts"] = [{"id": "ghost", "path": str(root / "nope.app")}]
            errors, _ = engine.validate_config(cfg, root, skip_missing=False)
            self.assertTrue(any("does not exist" in e for e in errors))
            errors2, warnings2 = engine.validate_config(cfg, root, skip_missing=True)
            self.assertEqual(errors2, [])
            self.assertTrue(any("does not exist" in w for w in warnings2))

    def test_missing_reference_always_error(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            cfg = {"hash_mode": "notable", "reference": {"id": "ref", "path": str(root / "absent.app")}, "artifacts": []}
            errors, _ = engine.validate_config(cfg, root, skip_missing=True)
            self.assertTrue(any("reference path does not exist" in e for e in errors))


class BuildStatusTests(unittest.TestCase):
    def test_read_build_status_counts(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "build_status.csv"
            with p.open("w", newline="") as f:
                w = csv.writer(f)
                w.writerow(["timestamp", "tag", "archive_path", "status", "exit_code", "log_path"])
                w.writerow(["t", "8.13", "a", "built", "0", "l"])
                w.writerow(["t", "8.12", "a", "built", "0", "l"])
                w.writerow(["t", "8.11", "a", "failed", "65", "l"])
            status = engine.read_build_status(p)
            self.assertEqual(status["total"], 3)
            self.assertEqual(status["counts"]["built"], 2)
            self.assertEqual(status["counts"]["failed"], 1)

    def test_missing_file_returns_none(self):
        self.assertIsNone(engine.read_build_status(Path("/no/such/file.csv")))


class FindingEvidenceTests(unittest.TestCase):
    def test_evidence_paths(self):
        f = engine.Finding("high", "Entitlements", "ref", "cand", "x", "y")
        self.assertEqual(engine.finding_evidence(f), "diffs/ref_vs_cand/signing_high_value.diff")
        f2 = engine.Finding("high", "Binaries", "ref", "cand", "x", "y")
        self.assertEqual(engine.finding_evidence(f2), "diffs/ref_vs_cand/binary_summary.diff")


class HtmlRenderingTests(unittest.TestCase):
    def test_links_and_severity_colors(self):
        md = (
            "## Findings\n\n"
            "| severity | evidence |\n| --- | --- |\n"
            "| high | [main_info.diff](diffs/ref_vs_cand/main_info.diff) |\n"
            "| medium | [x.diff](diffs/a/x.diff) |\n"
        )
        html = engine.report_to_html(md)
        self.assertIn('<a href="diffs/ref_vs_cand/main_info.diff">main_info.diff</a>', html)
        self.assertIn("color:#b00020", html)   # high
        self.assertIn("color:#b26a00", html)   # medium

    def test_inline_escaping_is_safe(self):
        html = engine._inline_md("plain <script> & `code`")
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("<code>code</code>", html)


class ParallelDeterminismTests(unittest.TestCase):
    def test_parallel_matches_serial_ordering(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            ref = _make_app(root, "ref", "8.13", "8.13.0.1623", cryptid=1)
            cands = [_make_app(root, f"c{i}", "8.12", f"8.12.0.{i}") for i in range(5)]
            ref_spec = engine.ArtifactSpec(artifact_id="ref", path=ref, role="appstore_reference")
            cand_specs = [engine.ArtifactSpec(artifact_id=f"c{i}", path=c, role="candidate") for i, c in enumerate(cands)]
            out = root / "out"
            engine.compare_all("test", ref_spec, cand_specs, {}, "none", out, jobs=4)
            with (out / "csv" / "artifacts.csv").open(newline="") as f:
                ids = [r["artifact_id"] for r in csv.DictReader(f)]
            self.assertEqual(ids, ["ref", "c0", "c1", "c2", "c3", "c4"])  # config order preserved


class ProvenanceTests(unittest.TestCase):
    def test_file_identity_is_sha256(self):
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / "a.ipa"
            f.write_bytes(b"hello")
            ident = engine.artifact_identity(f)
            self.assertEqual(ident["input_kind"], "file")
            self.assertEqual(len(ident["artifact_sha256"]), 64)
            self.assertEqual(ident["size_bytes"], 5)

    def test_dir_identity_is_structure_digest(self):
        with tempfile.TemporaryDirectory() as td:
            d = Path(td) / "x.app"
            d.mkdir()
            (d / "f1").write_bytes(b"aa")
            (d / "f2").write_bytes(b"bbb")
            ident = engine.artifact_identity(d)
            self.assertEqual(ident["input_kind"], "directory")
            self.assertEqual(ident["file_count"], 2)
            self.assertEqual(len(ident["structure_digest_sha256"]), 64)

    def test_declared_provenance_flows_into_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            app = _make_app(Path(td), "ref", "8.13", "8.13.0.1623", cryptid=1)
            spec = engine.ArtifactSpec(
                artifact_id="ref", path=app, role="appstore_reference",
                expected_git_ref="8.13.0.1623",
                declared_provenance={"capture_device": "iPhone15,2", "ios_version": "17.4", "capture_date": "2026-06-01"},
            )
            work = Path(td) / "work"; work.mkdir()
            manifest = engine.build_manifest(spec, work, "none")
            prov = manifest["provenance"]
            self.assertEqual(prov["declared"]["capture_device"], "iPhone15,2")
            self.assertEqual(prov["git_ref"], "8.13.0.1623")
            self.assertIn("structure_digest_sha256", prov)


class TriageTests(unittest.TestCase):
    def _f(self, category, summary):
        return engine.Finding("high", category, "ref", "cand", summary, "")

    def test_classification(self):
        self.assertEqual(engine.classify_finding(self._f("FairPlay boundary", "x")), "appstore_packaging")
        self.assertEqual(engine.classify_finding(self._f("Info.plist", "CFBundleVersion differs")), "release_drift")
        self.assertEqual(engine.classify_finding(self._f("Info.plist", "DTSDKName differs")), "expected_build_noise")
        self.assertEqual(engine.classify_finding(self._f("Entitlements", "get-task-allow differs")), "expected_build_noise")
        self.assertEqual(engine.classify_finding(self._f("Entitlements", "keychain-access-groups differs")), "expected_signing_noise")
        self.assertEqual(engine.classify_finding(self._f("Entitlements", "com.apple.developer.associated-domains differs")), "high_signal_unexplained")
        self.assertEqual(engine.classify_finding(self._f("Binaries", "Mach-O file set differs")), "high_signal_unexplained")

    def test_finding_row_has_triage(self):
        row = engine.finding_to_row(self._f("Entitlements", "get-task-allow differs"))
        self.assertEqual(row["triage"], "expected_build_noise")

    def test_class_counts(self):
        findings = [
            self._f("Info.plist", "CFBundleVersion differs"),
            self._f("Info.plist", "CFBundleShortVersionString differs"),
            self._f("Binaries", "Mach-O file set differs"),
        ]
        counts = engine.finding_class_counts(findings)
        self.assertEqual(counts["release_drift"], 2)
        self.assertEqual(counts["high_signal_unexplained"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
