#!/usr/bin/env python3
"""
Tests for the iOS symbol-based bundled-library matcher.

These build real (in-memory) Mach-O binaries -- reusing the synthetic builder
from ``tests/test_macho.py`` with custom exported-symbol sets -- then assert:

  * a Mach-O's defined exported symbols are recovered and fingerprinted;
  * containment-based version ranking picks the correct bundled version
    (the app is a superset of the bundled library plus unrelated app symbols);
  * a library whose symbols are disjoint from the candidate is filtered out by
    ``--min-containment``;
  * the profile JSON round-trips.

Mirrors ``tests/test_android.py::TestRanking``.

Run: python3 -m unittest discover -s tests   (no third-party deps)
"""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
TESTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(TESTS))

import macho  # noqa: E402
import ios_lib_fingerprint as ilf  # noqa: E402
from test_macho import build_macho  # noqa: E402


# Symbol sets for two "library versions" plus unrelated app symbols.
SYMS_V1 = [f"_lib_func_{i}" for i in range(10)]
SYMS_V2_EXTRA = ["_lib_func_new_a", "_lib_func_new_b"]
APP_NOISE = [f"_app_symbol_{i}" for i in range(40)]
DISJOINT = [f"_other_lib_{i}" for i in range(10)]


def _write_macho(path: Path, defined: list[str], undefined: list[str] | None = None) -> Path:
    path.write_bytes(build_macho(defined_symbols=defined,
                                 undefined_symbols=undefined or ["_objc_msgSend"]))
    return path


class TestSymbolCollection(unittest.TestCase):
    def test_collect_defined_symbols(self):
        with tempfile.TemporaryDirectory() as td:
            p = _write_macho(Path(td) / "Lib", SYMS_V1)
            syms, n_bin, n_raw = ilf.collect_defined_symbols(p, normalize=True)
            self.assertEqual(n_bin, 1)
            # normalize strips a single leading underscore
            self.assertIn("lib_func_0", syms)
            self.assertEqual(n_raw, len(SYMS_V1))
            # the undefined import must not appear in defined symbols
            self.assertNotIn("objc_msgSend", syms)

    def test_raw_vs_normalized(self):
        with tempfile.TemporaryDirectory() as td:
            p = _write_macho(Path(td) / "Lib", SYMS_V1)
            raw, _, _ = ilf.collect_defined_symbols(p, normalize=False)
            self.assertIn("_lib_func_0", raw)

    def test_walks_directory_of_binaries(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "Stuff.framework"
            root.mkdir()
            _write_macho(root / "BinA", SYMS_V1[:5])
            _write_macho(root / "BinB", SYMS_V1[5:])
            syms, n_bin, _ = ilf.collect_defined_symbols(root, normalize=True)
            self.assertEqual(n_bin, 2)
            self.assertEqual(syms, {ilf.normalize_symbol(s) for s in SYMS_V1})


class TestRanking(unittest.TestCase):
    def _profiles(self, td: Path):
        # v1: symbol set A ; v2 (bundled): A plus extra symbols.
        v1_bin = _write_macho(td / "libv1", SYMS_V1)
        v2_bin = _write_macho(td / "libv2", SYMS_V1 + SYMS_V2_EXTRA)
        v1 = ilf.build_profile(v1_bin, name="lib", version="1.0.0")
        v2 = ilf.build_profile(v2_bin, name="lib", version="2.0.0")
        # candidate app: v2's symbols plus unrelated app symbols.
        app_bin = _write_macho(td / "TheApp", SYMS_V1 + SYMS_V2_EXTRA + APP_NOISE)
        candidate = ilf.build_profile(app_bin, name="app", version="")
        return v1, v2, candidate

    def test_containment_picks_correct_version(self):
        with tempfile.TemporaryDirectory() as td:
            v1, v2, candidate = self._profiles(Path(td))
            scores = ilf.rank_versions([v1, v2], candidate, min_containment=0.1)
            best = ilf.group_best_by_library(scores)
            self.assertTrue(best)
            self.assertEqual(best[0].name, "lib")
            self.assertEqual(best[0].version, "2.0.0")
            # the bundled version's symbols are all present -> containment ~1.0
            self.assertAlmostEqual(best[0].containment, 1.0, places=6)
            # v1 is a subset of v2, so it is also fully contained but ranks below
            # v2 (lower jaccard: it lacks the extra symbols the candidate has).
            v1_score = next(s for s in scores if s.version == "1.0.0")
            self.assertAlmostEqual(v1_score.containment, 1.0, places=6)
            self.assertGreaterEqual(best[0].jaccard, v1_score.jaccard)

    def test_absent_library_is_filtered(self):
        with tempfile.TemporaryDirectory() as td:
            v1_bin = _write_macho(Path(td) / "libv1", SYMS_V1)
            v1 = ilf.build_profile(v1_bin, name="lib", version="1.0.0")
            # candidate shares nothing with lib.
            other_bin = _write_macho(Path(td) / "Other", DISJOINT + APP_NOISE)
            candidate = ilf.build_profile(other_bin, name="app", version="")
            scores = ilf.rank_versions([v1], candidate, min_containment=0.5)
            self.assertEqual(scores, [])

    def test_profile_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            b = _write_macho(Path(td) / "Lib", SYMS_V1)
            p = ilf.build_profile(b, name="lib", version="1.2.3", source="src.framework")
            back = ilf.IOSLibProfile.from_json(p.to_json())
            self.assertEqual(back.name, "lib")
            self.assertEqual(back.version, "1.2.3")
            self.assertEqual(back.n_symbols, p.n_symbols)
            self.assertEqual(set(back.symbol_sigs), set(p.symbol_sigs))
            self.assertEqual(back.minhash, p.minhash)
            self.assertEqual(p.to_json()["schema"], "ios-symbol-structural-profile-v1")


class TestNameVersionInference(unittest.TestCase):
    def test_infers_version_from_filename(self):
        name, version = ilf.infer_name_version(Path("SignalCoreKit-1.2.3.dylib"))
        self.assertEqual(name, "SignalCoreKit")
        self.assertEqual(version, "1.2.3")

    def test_framework_bundle_without_version(self):
        name, version = ilf.infer_name_version(Path("Foundation.framework"))
        self.assertEqual(name, "Foundation")
        self.assertEqual(version, "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
