#!/usr/bin/env python3
"""
Tests for the dependency-free Mach-O reader and the portable tool backend.

These build a minimal but real Mach-O 64 binary in memory -- load commands plus
an embedded code-signature SuperBlob carrying an entitlements plist and a
CodeDirectory with identifier/team id -- then assert the parser, the portable
backend, and the comparison engine's text parsers all agree on the bytes.

Run: python3 -m unittest discover -s tests   (no third-party deps)
"""
from __future__ import annotations

import plistlib
import struct
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import macho  # noqa: E402
import macho_backend  # noqa: E402
import ios_multiversion_meta_compare as engine  # noqa: E402

MH_MAGIC_64 = 0xFEEDFACF
CPU_TYPE_ARM64 = 0x0100000C
MH_EXECUTE = 2

IDENT = "org.whispersystems.signal"
TEAM = "ABCDE12345"
ENTITLEMENTS = {
    "application-identifier": f"{TEAM}.{IDENT}",
    "com.apple.developer.team-identifier": TEAM,
    "keychain-access-groups": [f"{TEAM}.{IDENT}"],
    "get-task-allow": False,
    "aps-environment": "production",
}


def _lc(cmd: int, payload: bytes) -> bytes:
    """Wrap a load-command payload with cmd/cmdsize, padded to 8 bytes."""
    size = 8 + len(payload)
    pad = (-size) % 8
    return struct.pack("<II", cmd, size + pad) + payload + b"\x00" * pad


def _dylib(name: str) -> bytes:
    nb = name.encode() + b"\x00"
    payload = struct.pack("<IIII", 24, 2, 0x10000, 0x10000) + nb
    return _lc(macho.LC_LOAD_DYLIB, payload)


def _rpath(path: str) -> bytes:
    return _lc(macho.LC_RPATH, struct.pack("<I", 12) + path.encode() + b"\x00")


def _enc_info(cryptid: int) -> bytes:
    return _lc(macho.LC_ENCRYPTION_INFO_64, struct.pack("<IIII", 0x4000, 0x120000, cryptid, 0))


def _build_version(minos: tuple[int, int, int], sdk: tuple[int, int, int]) -> bytes:
    def enc(v: tuple[int, int, int]) -> int:
        return (v[0] << 16) | (v[1] << 8) | v[2]
    return _lc(macho.LC_BUILD_VERSION, struct.pack("<IIII", 2, enc(minos), enc(sdk), 0))


def _code_directory(ident: str, team: str) -> bytes:
    ident_b = ident.encode() + b"\x00"
    team_b = team.encode() + b"\x00"
    ident_off = 52
    team_off = 52 + len(ident_b)
    strings = ident_b + team_b
    length = 52 + len(strings)
    hdr = struct.pack(
        ">IIIIIIIII", macho.CSMAGIC_CODEDIRECTORY, length, 0x00020200, 0,
        0, ident_off, 0, 0, 0,
    )
    hdr += struct.pack(">BBBB", 32, 2, 0, 12)   # hashSize, hashType, platform, pageSize
    hdr += struct.pack(">I", 0)                  # spare2
    hdr += struct.pack(">I", 0)                  # scatterOffset
    hdr += struct.pack(">I", team_off)           # teamOffset
    return hdr + strings


def _symtab_tables(defined: list[str], undefined: list[str]) -> tuple[bytes, bytes, int]:
    """Build a 64-bit nlist symbol table + string table.

    Returns ``(symbol_table_bytes, string_table_bytes, nsyms)``. The string
    table conventionally starts with a NUL byte (index 0 = empty name), so real
    names get nonzero ``n_strx``. Defined externals use ``n_type`` =
    ``N_EXT|N_SECT`` with a nonzero section index; undefined externals use
    ``n_type`` = ``N_EXT|N_UNDF`` with section 0.
    """
    strtab = bytearray(b"\x00")
    str_offsets: dict[str, int] = {}

    def add(name: str) -> int:
        if name not in str_offsets:
            str_offsets[name] = len(strtab)
            strtab.extend(name.encode("utf-8") + b"\x00")
        return str_offsets[name]

    symtab = bytearray()
    N_EXT = 0x01
    N_SECT = 0x0E
    N_UNDF = 0x00
    for name in defined:
        n_strx = add(name)
        # n_strx(u32), n_type(u8), n_sect(u8), n_desc(u16), n_value(u64)
        symtab += struct.pack("<IBBHQ", n_strx, N_EXT | N_SECT, 1, 0, 0x4000)
    for name in undefined:
        n_strx = add(name)
        symtab += struct.pack("<IBBHQ", n_strx, N_EXT | N_UNDF, 0, 0, 0)
    return bytes(symtab), bytes(strtab), len(defined) + len(undefined)


def _code_signature(entitlements: dict) -> bytes:
    cd = _code_directory(IDENT, TEAM)
    xml = plistlib.dumps(entitlements, fmt=plistlib.FMT_XML)
    ent = struct.pack(">II", macho.CSMAGIC_EMBEDDED_ENTITLEMENTS, 8 + len(xml)) + xml
    index_count = 2
    blobs_start = 12 + index_count * 8
    off_cd = blobs_start
    off_ent = blobs_start + len(cd)
    total = blobs_start + len(cd) + len(ent)
    sb = struct.pack(">III", macho.CSMAGIC_EMBEDDED_SIGNATURE, total, index_count)
    sb += struct.pack(">II", 0, off_cd)   # slot 0 = CodeDirectory
    sb += struct.pack(">II", 5, off_ent)  # slot 5 = Entitlements
    sb += cd + ent
    return sb


# Default synthetic symbol sets: one defined external (an exported class) plus a
# Swift export, and one undefined external import resolved by the runtime.
DEFINED_SYMBOLS = ["_OBJC_CLASS_$_SignalFoo", "_swift_demo"]
UNDEFINED_SYMBOLS = ["_objc_msgSend"]


def build_macho(entitlements: dict = ENTITLEMENTS, cryptid: int = 1,
                defined_symbols: list[str] | None = None,
                undefined_symbols: list[str] | None = None) -> bytes:
    defined = DEFINED_SYMBOLS if defined_symbols is None else defined_symbols
    undefined = UNDEFINED_SYMBOLS if undefined_symbols is None else undefined_symbols
    symtab_bytes, strtab_bytes, nsyms = _symtab_tables(defined, undefined)

    lcs = [
        _dylib("/usr/lib/libSystem.B.dylib"),
        _dylib("/System/Library/Frameworks/Foundation.framework/Foundation"),
        _rpath("@executable_path/Frameworks"),
        _enc_info(cryptid),
        _build_version((15, 0, 0), (17, 4, 0)),
        _lc(macho.LC_UUID, bytes(range(16))),
    ]
    sig = _code_signature(entitlements)

    # Two-pass layout: the symbol table, string table, and code-signature
    # SuperBlob all live past the load commands. Build placeholder LCs first to
    # learn sizeofcmds, then recompute file offsets and rebuild.
    def assemble(symoff: int, stroff: int, cs_dataoff: int) -> tuple[bytes, int]:
        symtab_lc = _lc(macho.LC_SYMTAB,
                        struct.pack("<IIII", symoff, nsyms, stroff, len(strtab_bytes)))
        cs_lc = _lc(macho.LC_CODE_SIGNATURE, struct.pack("<II", cs_dataoff, len(sig)))
        all_lcs = lcs + [symtab_lc, cs_lc]
        sizeofcmds = sum(len(x) for x in all_lcs)
        return b"".join(all_lcs), sizeofcmds

    _, sizeofcmds = assemble(0, 0, 0)
    sym_off = 32 + sizeofcmds
    str_off = sym_off + len(symtab_bytes)
    cs_off = str_off + len(strtab_bytes)
    lc_blob, sizeofcmds = assemble(sym_off, str_off, cs_off)

    header = struct.pack(
        "<IIIIIIII", MH_MAGIC_64, CPU_TYPE_ARM64, 0, MH_EXECUTE,
        len(lcs) + 2, sizeofcmds, 0, 0,
    )
    return header + lc_blob + symtab_bytes + strtab_bytes + sig


class MachOParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.bin_path = Path(cls.tmp.name) / "MyApp"
        cls.bin_path.write_bytes(build_macho())
        cls.parsed = macho.parse_path(cls.bin_path)
        cls.slice = macho.primary_slice(cls.parsed)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_is_macho_and_arch(self):
        self.assertTrue(self.parsed["is_macho"])
        self.assertFalse(self.parsed["fat"])
        self.assertEqual(self.parsed["architectures"], ["arm64"])

    def test_no_parse_errors(self):
        self.assertEqual(self.slice["errors"], [])

    def test_dylibs(self):
        self.assertIn("/usr/lib/libSystem.B.dylib", self.slice["dylibs"])
        self.assertIn("/System/Library/Frameworks/Foundation.framework/Foundation", self.slice["dylibs"])

    def test_rpaths(self):
        self.assertEqual(self.slice["rpaths"], ["@executable_path/Frameworks"])

    def test_encryption_info(self):
        enc = self.slice["encryption_info"]
        self.assertEqual(len(enc), 1)
        self.assertEqual(enc[0]["cryptid"], 1)
        self.assertEqual(enc[0]["command"], "LC_ENCRYPTION_INFO_64")

    def test_build_version(self):
        bv = self.slice["build_versions"][0]
        self.assertEqual(bv["platform"], "iOS")
        self.assertEqual(bv["minos"], "15.0")
        self.assertEqual(bv["sdk"], "17.4")

    def test_uuid(self):
        self.assertEqual(self.slice["uuid"], "00010203-0405-0607-0809-0A0B0C0D0E0F")

    def test_code_directory_identity(self):
        self.assertEqual(self.slice["identifier"], IDENT)
        self.assertEqual(self.slice["team_identifier"], TEAM)

    def test_entitlements(self):
        ent = self.slice["entitlements"]
        self.assertEqual(ent["application-identifier"], f"{TEAM}.{IDENT}")
        self.assertEqual(ent["get-task-allow"], False)
        self.assertEqual(ent["aps-environment"], "production")

    def test_symtab_defined_symbols(self):
        defined = self.slice["defined_symbols"]
        self.assertIn("_OBJC_CLASS_$_SignalFoo", defined)
        self.assertIn("_swift_demo", defined)
        # defined externals must be sorted and exclude the imports
        self.assertEqual(defined, sorted(defined))
        self.assertNotIn("_objc_msgSend", defined)

    def test_symtab_undefined_symbols(self):
        undefined = self.slice["undefined_symbols"]
        self.assertIn("_objc_msgSend", undefined)
        self.assertNotIn("_OBJC_CLASS_$_SignalFoo", undefined)
        self.assertEqual(self.slice["nsyms"], 3)

    def test_non_macho(self):
        p = Path(self.tmp.name) / "notmacho"
        p.write_bytes(b"this is not a mach-o file at all")
        self.assertFalse(macho.parse_path(p)["is_macho"])


class PortableBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        cls.bin_path = root / "MyApp"
        cls.bin_path.write_bytes(build_macho())
        # A minimal .app bundle so bundle-level signing resolution works.
        cls.app = root / "MyApp.app"
        cls.app.mkdir()
        (cls.app / "MyApp").write_bytes(build_macho())
        with (cls.app / "Info.plist").open("wb") as f:
            plistlib.dump({"CFBundleExecutable": "MyApp", "CFBundleIdentifier": IDENT}, f)
        cls.backend = macho_backend.PortableBackend()

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_lipo_archs(self):
        self.assertEqual(self.backend.lipo_archs(self.bin_path)["stdout"].strip(), "arm64")

    def test_otool_libraries_roundtrips_through_engine_parser(self):
        text = self.backend.otool_libraries(self.bin_path)["stdout"]
        libs = engine.parse_otool_libraries(text)
        self.assertIn("/usr/lib/libSystem.B.dylib", libs)

    def test_otool_load_commands_roundtrip(self):
        text = self.backend.otool_load_commands(self.bin_path)["stdout"]
        self.assertEqual(engine.parse_rpaths(text), ["@executable_path/Frameworks"])
        enc = engine.parse_encryption_info(text)
        self.assertEqual(enc[0]["cryptid"], "1")
        bv = engine.parse_build_version(text)
        self.assertEqual(bv[0]["minos"], "15.0")

    def test_codesign_entitlements_on_bundle(self):
        ent = self.backend.codesign_entitlements(self.app)
        self.assertEqual(ent["com.apple.developer.team-identifier"], TEAM)

    def test_codesign_display_on_bundle(self):
        parsed = self.backend.codesign_display(self.app)["parsed"]
        self.assertEqual(parsed["Identifier"], IDENT)
        self.assertEqual(parsed["TeamIdentifier"], TEAM)

    def test_mobileprovision_cleartext_plist(self):
        mp = Path(self.tmp.name) / "embedded.mobileprovision"
        payload = plistlib.dumps({"Name": "Signal Dev", "TeamName": "Signal", "UUID": "x"})
        mp.write_bytes(b"\x30\x82PKCS7-ish-prefix" + payload + b"trailing-cms-bytes")
        parsed = self.backend.mobileprovision(mp)
        self.assertEqual(parsed["Name"], "Signal Dev")


class EngineIntegrationTests(unittest.TestCase):
    """The full manifest path must surface backend data into the artifact matrix."""

    def test_manifest_and_matrix_row(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            app = root / "Signal.app"
            app.mkdir()
            (app / "Signal").write_bytes(build_macho())
            with (app / "Info.plist").open("wb") as f:
                plistlib.dump({
                    "CFBundleExecutable": "Signal",
                    "CFBundleIdentifier": IDENT,
                    "CFBundleShortVersionString": "8.13",
                    "CFBundleVersion": "8.13.0.1623",
                    "MinimumOSVersion": "15.0",
                }, f)
            spec = engine.ArtifactSpec(artifact_id="signal_test", path=app, role="candidate")
            work = root / "work"
            work.mkdir()
            manifest = engine.build_manifest(spec, work, "none")

            # binary metadata
            self.assertEqual(len(manifest["binaries"]), 1)
            bin_rec = next(iter(manifest["binaries"].values()))
            self.assertEqual(bin_rec["architectures"], "arm64")
            self.assertEqual(bin_rec["encryption_info"][0]["cryptid"], "1")

            # signing/entitlements at the .app root
            ent = engine.read_entitlement_for_main(manifest)
            self.assertEqual(ent["aps-environment"], "production")

            # compact matrix row
            row = engine.artifact_matrix_row(manifest)
            self.assertEqual(row["short_version"], "8.13")
            self.assertEqual(row["main_cryptid"], "1")
            self.assertEqual(row["team_identifier"], TEAM)
            self.assertEqual(row["main_architectures"], "arm64")


if __name__ == "__main__":
    unittest.main(verbosity=2)
