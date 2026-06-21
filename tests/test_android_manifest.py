#!/usr/bin/env python3
"""
Tests for the Android binary-manifest (AXML) capability reader + diff engine.

These build a small but spec-correct binary AXML blob in memory (a UTF-8 string
pool plus start/end-element chunks with typed attributes), then assert:

  * the parser recovers package / versionName from <manifest>;
  * a <uses-permission android:name=android.permission.INTERNET> is recovered;
  * <application android:debuggable=true> resolves to a boolean True;
  * an exported <activity> is recovered as an exported component;
  * diff_manifests() flags a newly-added android.permission.RECORD_AUDIO as a
    high-signal finding and reports the component as no longer exported.

Building a correct minimal AXML is the crux: the chunk byte layout below is
constructed directly with struct, mirroring frameworks/base ResourceTypes.h. The
optional RES_XML_RESOURCE_MAP_TYPE chunk is omitted (the parser tolerates its
absence).

Run: python3 -m unittest discover -s tests   (no third-party deps)
"""
from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS))

import android_manifest as am  # noqa: E402


# ---------------------------------------------------------------------------
# Minimal real AXML builder
# ---------------------------------------------------------------------------

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# Res_value data types (must match android_manifest).
_TYPE_STRING = 0x03
_TYPE_INT_DEC = 0x10
_TYPE_INT_BOOLEAN = 0x12

_NO_ENTRY = 0xFFFFFFFF


def _build_string_pool(strings: list[str]) -> bytes:
    """Build a UTF-8 RES_STRING_POOL_TYPE chunk for the given strings."""
    # Encode each string as: u8 char-len, u8 byte-len, UTF-8 bytes, NUL.
    encoded = bytearray()
    offsets = []
    for s in strings:
        offsets.append(len(encoded))
        raw = s.encode("utf-8")
        # char/byte lengths fit in one byte for our short ASCII strings.
        encoded += struct.pack("<B", len(s)) + struct.pack("<B", len(raw)) + raw + b"\x00"

    # Pad the string data to a 4-byte boundary.
    while len(encoded) % 4 != 0:
        encoded += b"\x00"

    string_count = len(strings)
    header_size = 28
    offsets_size = string_count * 4
    strings_start = header_size + offsets_size
    chunk_size = strings_start + len(encoded)

    flags = 1 << 8  # UTF8_FLAG
    chunk = bytearray()
    chunk += struct.pack("<HH", 0x0001, header_size)   # type, headerSize
    chunk += struct.pack("<I", chunk_size)             # chunkSize
    chunk += struct.pack("<I", string_count)           # stringCount
    chunk += struct.pack("<I", 0)                      # styleCount
    chunk += struct.pack("<I", flags)                  # flags (UTF-8)
    chunk += struct.pack("<I", strings_start)          # stringsStart
    chunk += struct.pack("<I", 0)                      # stylesStart
    for off in offsets:
        chunk += struct.pack("<I", off)
    chunk += encoded
    assert len(chunk) == chunk_size
    return bytes(chunk)


def _attr(ns_ref: int, name_ref: int, raw_value_ref: int,
          data_type: int, data: int) -> bytes:
    """One ResXMLTree_attribute (20 bytes)."""
    return (struct.pack("<I", ns_ref)
            + struct.pack("<I", name_ref)
            + struct.pack("<I", raw_value_ref)
            + struct.pack("<H", 8)            # Res_value size
            + struct.pack("<B", 0)            # res0
            + struct.pack("<B", data_type)    # dataType
            + struct.pack("<I", data))        # data


def _start_element(name_ref: int, attrs: list[bytes],
                   ns_ref: int = _NO_ENTRY) -> bytes:
    """Build a RES_XML_START_ELEMENT_TYPE chunk."""
    header_size = 16  # type/headerSize/size + lineNumber + comment
    attribute_count = len(attrs)
    # Element body: ns, name, attributeStart, attributeSize, attributeCount,
    # idIndex, classIndex, styleIndex.
    body = bytearray()
    body += struct.pack("<I", ns_ref)        # ns
    body += struct.pack("<I", name_ref)      # name
    body += struct.pack("<H", 20)            # attributeStart (after these 20 bytes)
    body += struct.pack("<H", 20)            # attributeSize
    body += struct.pack("<H", attribute_count)
    body += struct.pack("<H", 0)             # idIndex
    body += struct.pack("<H", 0)             # classIndex
    body += struct.pack("<H", 0)             # styleIndex
    body += b"".join(attrs)

    chunk_size = 8 + 8 + len(body)  # chunk header + node(line,comment) + body
    chunk = bytearray()
    chunk += struct.pack("<HH", 0x0102, header_size)
    chunk += struct.pack("<I", chunk_size)
    chunk += struct.pack("<I", 0)            # lineNumber
    chunk += struct.pack("<I", _NO_ENTRY)    # comment
    chunk += body
    assert len(chunk) == chunk_size
    return bytes(chunk)


def _end_element(name_ref: int, ns_ref: int = _NO_ENTRY) -> bytes:
    """Build a RES_XML_END_ELEMENT_TYPE chunk."""
    header_size = 16
    body = struct.pack("<I", ns_ref) + struct.pack("<I", name_ref)
    chunk_size = 8 + 8 + len(body)
    chunk = bytearray()
    chunk += struct.pack("<HH", 0x0103, header_size)
    chunk += struct.pack("<I", chunk_size)
    chunk += struct.pack("<I", 0)            # lineNumber
    chunk += struct.pack("<I", _NO_ENTRY)    # comment
    chunk += body
    return bytes(chunk)


def build_axml(*, include_record_audio: bool, activity_exported: bool) -> bytes:
    """Build a minimal manifest AXML.

    Structure:
      <manifest package=.. versionName=.. versionCode=..>
        <uses-permission android:name=android.permission.INTERNET/>
        [<uses-permission android:name=android.permission.RECORD_AUDIO/>]
        <application android:debuggable=true>
          <activity android:name=.MainActivity [android:exported=true]/>
        </application>
      </manifest>
    """
    # String pool. Indices are referenced below.
    strings = [
        "android",                      # 0  (ns prefix string, unused by parser)
        ANDROID_NS,                     # 1  android namespace URI
        "package",                      # 2
        "versionCode",                  # 3
        "versionName",                  # 4
        "name",                         # 5
        "debuggable",                   # 6
        "exported",                     # 7
        "manifest",                     # 8
        "uses-permission",              # 9
        "application",                  # 10
        "activity",                     # 11
        "com.example.app",              # 12  package value
        "1.2.3",                        # 13  versionName value
        "android.permission.INTERNET",  # 14
        "android.permission.RECORD_AUDIO",  # 15
        ".MainActivity",                # 16  activity name value
    ]
    S = {s: i for i, s in enumerate(strings)}
    NS = S[ANDROID_NS]

    pool = _build_string_pool(strings)

    chunks = bytearray()
    chunks += pool

    # <manifest package="com.example.app" android:versionCode=7 versionName="1.2.3">
    manifest_attrs = [
        # package lives in the *default* (no) namespace in real manifests.
        _attr(_NO_ENTRY, S["package"], S["com.example.app"], _TYPE_STRING, S["com.example.app"]),
        _attr(NS, S["versionCode"], _NO_ENTRY, _TYPE_INT_DEC, 7),
        _attr(NS, S["versionName"], S["1.2.3"], _TYPE_STRING, S["1.2.3"]),
    ]
    chunks += _start_element(S["manifest"], manifest_attrs)

    # <uses-permission android:name="android.permission.INTERNET"/>
    chunks += _start_element(S["uses-permission"], [
        _attr(NS, S["name"], S["android.permission.INTERNET"],
              _TYPE_STRING, S["android.permission.INTERNET"]),
    ])
    chunks += _end_element(S["uses-permission"])

    if include_record_audio:
        chunks += _start_element(S["uses-permission"], [
            _attr(NS, S["name"], S["android.permission.RECORD_AUDIO"],
                  _TYPE_STRING, S["android.permission.RECORD_AUDIO"]),
        ])
        chunks += _end_element(S["uses-permission"])

    # <application android:debuggable="true">
    chunks += _start_element(S["application"], [
        _attr(NS, S["debuggable"], _NO_ENTRY, _TYPE_INT_BOOLEAN, 1),
    ])

    # <activity android:name=".MainActivity" [android:exported="true"]/>
    activity_attrs = [
        _attr(NS, S["name"], S[".MainActivity"], _TYPE_STRING, S[".MainActivity"]),
    ]
    if activity_exported:
        activity_attrs.append(
            _attr(NS, S["exported"], _NO_ENTRY, _TYPE_INT_BOOLEAN, 1))
    chunks += _start_element(S["activity"], activity_attrs)
    chunks += _end_element(S["activity"])

    chunks += _end_element(S["application"])
    chunks += _end_element(S["manifest"])

    # RES_XML_TYPE wrapper header (8 bytes): type, headerSize, total size.
    total = 8 + len(chunks)
    head = struct.pack("<HH", 0x0003, 8) + struct.pack("<I", total)
    return head + bytes(chunks)


# ---------------------------------------------------------------------------
# Parser tests
# ---------------------------------------------------------------------------


class TestAxmlParser(unittest.TestCase):
    def setUp(self):
        self.blob = build_axml(include_record_audio=False, activity_exported=True)
        self.parsed = am.parse_axml(self.blob)
        self.profile = am.extract_capabilities(self.parsed)

    def test_no_parse_errors(self):
        self.assertEqual(self.parsed.errors, [],
                         f"unexpected parse errors: {self.parsed.errors}")
        self.assertEqual(self.profile["errors"], [])

    def test_recovers_package_and_version(self):
        self.assertEqual(self.profile["package"], "com.example.app")
        self.assertEqual(self.profile["versionName"], "1.2.3")
        self.assertEqual(self.profile["versionCode"], 7)

    def test_recovers_internet_permission(self):
        self.assertIn("android.permission.INTERNET", self.profile["uses_permission"])

    def test_debuggable_true(self):
        self.assertIs(self.profile["application"]["debuggable"], True)

    def test_exported_activity_recovered(self):
        self.assertIn(".MainActivity", self.profile["exported_components"])
        activities = self.profile["components"]["activity"]
        self.assertEqual(len(activities), 1)
        self.assertEqual(activities[0]["name"], ".MainActivity")
        self.assertIs(activities[0]["exported"], True)

    def test_load_from_apk_zip(self):
        import io
        import zipfile
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("AndroidManifest.xml", self.blob)
            zf.writestr("classes.dex", b"dummy")
        extracted = am.manifest_bytes_from_zip_bytes(buf.getvalue())
        self.assertEqual(extracted, self.blob)

    def test_malformed_does_not_crash(self):
        # Truncated / garbage input must yield errors, not raise.
        parsed = am.parse_axml(b"\x03\x00\x08\x00\xff\xff\xff\xff" + b"\x99" * 32)
        self.assertIsInstance(parsed.errors, list)
        self.assertTrue(parsed.errors)
        # A wholly empty input is also tolerated.
        self.assertTrue(am.parse_axml(b"").errors)


# ---------------------------------------------------------------------------
# Diff tests
# ---------------------------------------------------------------------------


class TestManifestDiff(unittest.TestCase):
    def setUp(self):
        a_blob = build_axml(include_record_audio=False, activity_exported=True)
        b_blob = build_axml(include_record_audio=True, activity_exported=False)
        self.a = am.extract_capabilities(am.parse_axml(a_blob))
        self.b = am.extract_capabilities(am.parse_axml(b_blob))
        self.findings = am.diff_manifests(self.a, self.b)

    def test_record_audio_is_high_signal_added_permission(self):
        matches = [f for f in self.findings
                   if f.category == "Permission added"
                   and "RECORD_AUDIO" in f.summary]
        self.assertEqual(len(matches), 1, "expected one RECORD_AUDIO added finding")
        self.assertEqual(matches[0].severity, "high")

    def test_record_audio_classified_dangerous(self):
        self.assertTrue(am.is_dangerous_permission("android.permission.RECORD_AUDIO"))

    def test_component_no_longer_exported(self):
        matches = [f for f in self.findings
                   if f.category == "Component unexported"
                   and ".MainActivity" in f.summary]
        self.assertEqual(len(matches), 1,
                         "expected the activity to be reported as no longer exported")
        # And it should no longer appear in b's exported set.
        self.assertIn(".MainActivity", self.a["exported_components"])
        self.assertNotIn(".MainActivity", self.b["exported_components"])

    def test_no_spurious_high_findings(self):
        # The only high-signal delta should be the added RECORD_AUDIO permission.
        highs = [f for f in self.findings if f.severity == "high"]
        self.assertEqual(len(highs), 1, f"unexpected high findings: {[h.summary for h in highs]}")
        self.assertIn("RECORD_AUDIO", highs[0].summary)


if __name__ == "__main__":
    unittest.main()
