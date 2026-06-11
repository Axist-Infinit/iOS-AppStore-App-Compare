#!/usr/bin/env python3
"""
Tests for the Android/JVM bundled-library matcher.

These build a minimal but real JVM ``.class`` and a minimal but real Dalvik
``.dex`` in memory for the *same* logical class, then assert:

  * both parsers recover the same structure (name, super, members, descriptors);
  * the structural class signature is identical across the two bytecode formats
    (the cross-format matching claim);
  * the signature survives obfuscation -- renaming the class and its internal
    type references does not change it (the obfuscation-resilience claim);
  * containment-based version ranking picks the correct bundled version.

Run: python3 -m unittest discover -s tests   (no third-party deps)
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import android_bytecode as abc  # noqa: E402
import android_fingerprint as afp  # noqa: E402
from android_bytecode import ClassUnit, MethodInfo, FieldInfo  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal real bytecode builders
# ---------------------------------------------------------------------------

def build_jvm_class() -> bytes:
    """A real JVM class file: public class com/foo/Bar extends java/lang/Object
    { public String name; public static int add(int,int); }"""
    out = bytearray()
    out += b"\xca\xfe\xba\xbe"          # magic
    out += struct.pack(">HH", 0, 52)    # minor, major (Java 8)
    cp = [
        (1, b"com/foo/Bar"),            # 1 Utf8
        ("class", 1),                   # 2 Class -> 1
        (1, b"java/lang/Object"),       # 3 Utf8
        ("class", 3),                   # 4 Class -> 3
        (1, b"name"),                   # 5 Utf8
        (1, b"Ljava/lang/String;"),     # 6 Utf8
        (1, b"add"),                    # 7 Utf8
        (1, b"(II)I"),                  # 8 Utf8
    ]
    out += struct.pack(">H", len(cp) + 1)  # constant_pool_count
    for entry in cp:
        if entry[0] == 1:
            out += struct.pack(">B", 1) + struct.pack(">H", len(entry[1])) + entry[1]
        elif entry[0] == "class":
            out += struct.pack(">BH", 7, entry[1])
    out += struct.pack(">H", 0x0021)    # access_flags (public super)
    out += struct.pack(">H", 2)         # this_class -> Class #2
    out += struct.pack(">H", 4)         # super_class -> Class #4
    out += struct.pack(">H", 0)         # interfaces_count
    out += struct.pack(">H", 1)         # fields_count
    out += struct.pack(">HHHH", 0x0001, 5, 6, 0)   # field: public name : String, 0 attrs
    out += struct.pack(">H", 1)         # methods_count
    out += struct.pack(">HHHH", 0x0009, 7, 8, 0)   # method: public static add (II)I, 0 attrs
    out += struct.pack(">H", 0)         # class attributes_count
    return bytes(out)


def build_dex_class() -> bytes:
    """A real (minimal) DEX for the same logical class as build_jvm_class()."""
    strings = [
        "Lcom/foo/Bar;",        # 0
        "Ljava/lang/Object;",   # 1
        "Ljava/lang/String;",   # 2
        "I",                    # 3
        "add",                  # 4
        "name",                 # 5
        "III",                  # 6 shorty for (II)I
    ]
    type_to_string = [0, 1, 2, 3]   # t0..t3

    # --- fixed-section sizes -> data section start ---
    n_str = len(strings)
    string_ids_off = 112
    type_ids_off = string_ids_off + n_str * 4
    proto_ids_off = type_ids_off + 4 * 4
    field_ids_off = proto_ids_off + 1 * 12
    method_ids_off = field_ids_off + 1 * 8
    class_defs_off = method_ids_off + 1 * 8
    data_off = class_defs_off + 1 * 32      # 4-byte aligned by construction

    # --- data section: type_list, string_data, class_data ---
    data = bytearray()
    type_list_off = data_off + len(data)
    data += struct.pack("<I", 2) + struct.pack("<HH", 3, 3)   # (I, I)

    string_data_offs = []
    for s in strings:
        string_data_offs.append(data_off + len(data))
        raw = s.encode("utf-8")
        data += struct.pack("<B", len(raw)) + raw + b"\x00"   # uleb size (ascii<128) + MUTF8 + NUL

    class_data_off = data_off + len(data)
    # static=0, instance=1, direct=1, virtual=0
    data += bytes([0, 1, 1, 0])
    data += bytes([0, 0x01])           # instance field: idx_diff=0, access=public
    data += bytes([0, 0x09, 0])        # direct method: idx_diff=0, access=public|static, code_off=0

    # --- fixed sections ---
    string_ids = b"".join(struct.pack("<I", off) for off in string_data_offs)
    type_ids = b"".join(struct.pack("<I", type_to_string[i]) for i in range(4))
    proto_ids = struct.pack("<III", 6, 3, type_list_off)         # shorty=6, return=t3, params
    field_ids = struct.pack("<HHI", 0, 2, 5)                     # class t0, type t2, name "name"
    method_ids = struct.pack("<HHI", 0, 0, 4)                    # class t0, proto0, name "add"
    class_defs = struct.pack("<IIIIIIII",
                             0, 0x1, 1, 0, 0xFFFFFFFF, 0, class_data_off, 0)

    file_size = data_off + len(data)
    header = bytearray(112)
    header[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", header, 32, file_size)               # file_size
    struct.pack_into("<I", header, 36, 112)                     # header_size
    struct.pack_into("<I", header, 40, 0x12345678)              # endian_tag
    struct.pack_into("<I", header, 56, n_str)
    struct.pack_into("<I", header, 60, string_ids_off)
    struct.pack_into("<I", header, 64, 4)
    struct.pack_into("<I", header, 68, type_ids_off)
    struct.pack_into("<I", header, 72, 1)
    struct.pack_into("<I", header, 76, proto_ids_off)
    struct.pack_into("<I", header, 80, 1)
    struct.pack_into("<I", header, 84, field_ids_off)
    struct.pack_into("<I", header, 88, 1)
    struct.pack_into("<I", header, 92, method_ids_off)
    struct.pack_into("<I", header, 96, 1)
    struct.pack_into("<I", header, 100, class_defs_off)
    struct.pack_into("<I", header, 104, len(data))             # data_size
    struct.pack_into("<I", header, 108, data_off)              # data_off

    return bytes(header) + string_ids + type_ids + proto_ids + field_ids + method_ids + class_defs + bytes(data)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------

class TestParsers(unittest.TestCase):
    def test_jvm_parse(self):
        cu = abc.parse_classfile(build_jvm_class())
        self.assertEqual(cu.name, "com/foo/Bar")
        self.assertEqual(cu.super_name, "java/lang/Object")
        self.assertEqual(cu.source_format, "jvm")
        self.assertEqual([(m.name, m.descriptor, m.access) for m in cu.methods],
                         [("add", "(II)I", 0x0009)])
        self.assertEqual([(f.name, f.descriptor) for f in cu.fields],
                         [("name", "Ljava/lang/String;")])

    def test_dex_parse(self):
        classes = abc.parse_dex(build_dex_class())
        self.assertEqual(len(classes), 1)
        cu = classes[0]
        self.assertEqual(cu.name, "com/foo/Bar")
        self.assertEqual(cu.super_name, "java/lang/Object")
        self.assertEqual(cu.source_format, "dex")
        self.assertEqual([(m.name, m.descriptor, m.access) for m in cu.methods],
                         [("add", "(II)I", 0x0009)])
        self.assertEqual([(f.name, f.descriptor) for f in cu.fields],
                         [("name", "Ljava/lang/String;")])

    def test_bad_magic(self):
        with self.assertRaises(abc.BytecodeError):
            abc.parse_classfile(b"not a class")
        with self.assertRaises(abc.BytecodeError):
            abc.parse_dex(b"not a dex file" + b"\x00" * 200)


# ---------------------------------------------------------------------------
# Fingerprint tests
# ---------------------------------------------------------------------------

class TestFingerprint(unittest.TestCase):
    def test_cross_format_signature_equal(self):
        """Same logical class, compiled to JVM vs DEX, must hash identically."""
        jvm = abc.parse_classfile(build_jvm_class())
        dex = abc.parse_dex(build_dex_class())[0]
        self.assertEqual(afp.class_signature(jvm), afp.class_signature(dex))

    def test_descriptor_normalization(self):
        # Framework types survive; internal types collapse; primitives/arrays kept.
        self.assertEqual(afp.normalize_descriptor("(Landroid/os/Bundle;I)Ljava/lang/String;"),
                         "(Landroid/os/Bundle;I)Ljava/lang/String;")
        self.assertEqual(afp.normalize_descriptor("(Lcom/secret/Internal;[I)V"),
                         "(L*;[I)V")
        self.assertEqual(afp.normalize_type("[[Lcom/x/Y;"), "[[L*;")
        self.assertEqual(afp.normalize_type("[Ljava/lang/String;"), "[Ljava/lang/String;")

    def test_obfuscation_resilience(self):
        """Renaming the class + its internal type references must not change the sig."""
        original = ClassUnit(
            name="com/foo/Bar",
            super_name="com/foo/Base",            # internal -> wildcarded anchor
            interfaces=["java/io/Serializable", "com/foo/Listener"],
            methods=[
                MethodInfo("doWork", "(Lcom/foo/Helper;I)Ljava/lang/String;", 0x0001),
                MethodInfo("<init>", "()V", 0x0001),
            ],
            fields=[FieldInfo("count", "I", 0x0002),
                    FieldInfo("helper", "Lcom/foo/Helper;", 0x0002)],
            source_format="jvm",
        )
        obfuscated = ClassUnit(
            name="a/b/c",                         # renamed
            super_name="a/b/d",                   # renamed internal super
            interfaces=["java/io/Serializable", "a/b/e"],   # one renamed
            methods=[
                # members renamed and reordered; internal type refs renamed.
                MethodInfo("<init>", "()V", 0x0001),
                MethodInfo("p", "(La/b/q;I)Ljava/lang/String;", 0x0001),
            ],
            fields=[FieldInfo("z", "La/b/q;", 0x0002),
                    FieldInfo("y", "I", 0x0002)],
            source_format="dex",
        )
        self.assertEqual(afp.class_signature(original), afp.class_signature(obfuscated))

    def test_signature_distinguishes_real_changes(self):
        """A genuine structural change (extra method) must change the signature."""
        a = ClassUnit("com/foo/Bar", "java/lang/Object",
                      methods=[MethodInfo("m", "(I)V", 1)])
        b = ClassUnit("com/foo/Bar", "java/lang/Object",
                      methods=[MethodInfo("m", "(I)V", 1),
                               MethodInfo("n", "(J)V", 1)])
        self.assertNotEqual(afp.class_signature(a), afp.class_signature(b))


# ---------------------------------------------------------------------------
# Profile + ranking tests
# ---------------------------------------------------------------------------

def _units(classes):
    u = abc.ArtifactUnits()
    u.classes = classes
    u.formats = {c.source_format for c in classes if c.source_format}
    return u


def _make_class(seed: int) -> ClassUnit:
    # Encode the seed into the *structure* (descriptor shape) so each class has a
    # distinct signature -- class names are deliberately ignored by the matcher.
    return ClassUnit(
        name=f"com/lib/C{seed}",
        super_name="java/lang/Object",
        methods=[MethodInfo("m", f"({'J' * seed})Ljava/lang/String;", 1)],
        fields=[FieldInfo("f", "Ljava/lang/Object;", 2)],
        source_format="jvm",
    )


class TestRanking(unittest.TestCase):
    def test_containment_picks_correct_version(self):
        # v1: classes 0..9 ; v2 (bundled): 0..9 plus 10,11 ; v3: 0..9 plus 20,21
        v1 = afp.build_profile(_units([_make_class(i) for i in range(10)]), "lib", "1.0.0")
        v2 = afp.build_profile(_units([_make_class(i) for i in list(range(10)) + [10, 11]]), "lib", "2.0.0")
        v3 = afp.build_profile(_units([_make_class(i) for i in list(range(10)) + [20, 21]]), "lib", "3.0.0")

        # The app bundles v2 plus unrelated app classes.
        app_classes = [_make_class(i) for i in list(range(10)) + [10, 11]]
        app_classes += [ClassUnit(f"app/A{i}", "java/lang/Object",
                                  methods=[MethodInfo("x", "(D)V", 1)]) for i in range(50)]
        candidate = afp.build_profile(_units(app_classes), "app", "")

        scores = afp.rank_versions([v1, v2, v3], candidate, min_containment=0.1)
        best = afp.group_best_by_library(scores)
        self.assertTrue(best)
        self.assertEqual(best[0].name, "lib")
        self.assertEqual(best[0].version, "2.0.0")
        self.assertAlmostEqual(best[0].containment, 1.0, places=6)

    def test_absent_library_is_filtered(self):
        v1 = afp.build_profile(_units([_make_class(i) for i in range(10)]), "lib", "1.0.0")
        # Candidate shares nothing structurally with lib.
        other = afp.build_profile(_units([
            ClassUnit(f"x/Y{i}", "java/lang/Object",
                      methods=[MethodInfo("q", "(F)Z", 1)]) for i in range(10)]), "app", "")
        scores = afp.rank_versions([v1], other, min_containment=0.5)
        self.assertEqual(scores, [])

    def test_profile_roundtrip(self):
        p = afp.build_profile(_units([_make_class(i) for i in range(5)]), "lib", "1.2.3", "src.aar")
        back = afp.LibraryProfile.from_json(p.to_json())
        self.assertEqual(back.name, "lib")
        self.assertEqual(back.version, "1.2.3")
        self.assertEqual(set(back.class_sigs), set(p.class_sigs))
        self.assertEqual(back.minhash, p.minhash)


if __name__ == "__main__":
    unittest.main()
