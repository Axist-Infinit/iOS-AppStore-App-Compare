#!/usr/bin/env python3
"""
Dependency-free Android binary-manifest (AXML) capability reader + diff engine.

Purpose:
  Bring the iOS metadata/capability-comparison technique to Android. The iOS arm
  compares an App Store build's ``Info.plist`` + entitlements against a local or
  source build and triages the high-signal capability deltas from the expected
  packaging/signing noise. This module is the Android analogue: it parses the
  *compiled* ``AndroidManifest.xml`` (Android binary XML, "AXML") out of an APK,
  distils it into a JSON-serializable capability profile, and diffs two profiles
  (e.g. a Play-Store APK vs an F-Droid/source build, or across versions),
  classifying each delta as high-signal vs informational.

What this reads:
  Binary AXML is a chunk-based resource format: a string pool plus a tree of
  start/end-element events with typed attributes. We recover the manifest's
  declared *surface* -- package identity, SDK levels, permissions, declared
  features/libraries, the ``application`` security flags (debuggable,
  allowBackup, usesCleartextTraffic, networkSecurityConfig) and every component
  (activity/service/receiver/provider) with its exported state and intent
  filters. That surface is exactly the capability/attack-surface evidence a
  reviewer compares between two builds.

Scope:
  Read-only metadata extraction. This parser decodes a structure that is already
  present in a lawful artifact. It does not decrypt, deobfuscate, repackage, or
  execute anything, matching the kit's overall scope boundary. Component byte
  layout is read defensively and bounded to the buffer; a malformed chunk is
  recorded as a structured error rather than crashing.

Pure standard library only.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import html
import io
import json
import re
import struct
import sys
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# AXML chunk type constants (frameworks/base ResourceTypes.h).
# ---------------------------------------------------------------------------

RES_NULL_TYPE = 0x0000
RES_STRING_POOL_TYPE = 0x0001
RES_XML_TYPE = 0x0003
RES_XML_FIRST_CHUNK_TYPE = 0x0100
RES_XML_START_NAMESPACE_TYPE = 0x0100
RES_XML_END_NAMESPACE_TYPE = 0x0101
RES_XML_START_ELEMENT_TYPE = 0x0102
RES_XML_END_ELEMENT_TYPE = 0x0103
RES_XML_CDATA_TYPE = 0x0104
RES_XML_RESOURCE_MAP_TYPE = 0x0180

# String-pool flags.
_SORTED_FLAG = 1 << 0
_UTF8_FLAG = 1 << 8

# Typed-value data types (Res_value::dataType).
TYPE_NULL = 0x00
TYPE_REFERENCE = 0x01
TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03
TYPE_FLOAT = 0x04
TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11
TYPE_INT_BOOLEAN = 0x12

_NO_ENTRY = 0xFFFFFFFF  # -1 string reference / sentinel

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class ManifestError(Exception):
    """Raised when an input cannot be located or read as an AndroidManifest."""


# ===========================================================================
# Parsed-tree data model
# ===========================================================================


@dataclass
class XmlAttribute:
    namespace: str | None
    name: str
    value: Any            # resolved Python value (str/int/bool) or raw token
    raw_type: int         # Res_value dataType


@dataclass
class XmlElement:
    tag: str
    attributes: list[XmlAttribute] = field(default_factory=list)
    children: list["XmlElement"] = field(default_factory=list)
    text: str = ""

    def attr(self, name: str, namespace: str | None = ANDROID_NS) -> Any:
        """Return the value of an attribute by local name.

        Namespace match is by-name primarily (real manifests carry attribute
        names in the pool); the ``namespace`` argument is a soft preference --
        an exact namespace hit wins, otherwise the first name match is returned.
        """
        fallback: Any = None
        have_fallback = False
        for a in self.attributes:
            if a.name == name:
                if namespace is None or a.namespace == namespace:
                    return a.value
                if not have_fallback:
                    fallback = a.value
                    have_fallback = True
        return fallback

    def iter_descendants(self) -> "Iterable[XmlElement]":
        for child in self.children:
            yield child
            yield from child.iter_descendants()


@dataclass
class ParsedManifest:
    root: XmlElement | None
    strings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# ===========================================================================
# Low-level bounded readers
# ===========================================================================


def _u16(data: bytes, pos: int) -> int:
    return struct.unpack_from("<H", data, pos)[0]


def _u32(data: bytes, pos: int) -> int:
    return struct.unpack_from("<I", data, pos)[0]


def _s32(data: bytes, pos: int) -> int:
    return struct.unpack_from("<i", data, pos)[0]


# ===========================================================================
# String pool
# ===========================================================================


class StringPool:
    """Decoded AXML string pool with bounded, defensive access."""

    def __init__(self, strings: list[str]):
        self.strings = strings

    def get(self, ref: int) -> str | None:
        """Resolve a string reference (-1 / 0xFFFFFFFF means *no string*)."""
        if ref == _NO_ENTRY or ref < 0:
            return None
        if 0 <= ref < len(self.strings):
            return self.strings[ref]
        return None


def _decode_utf8_string(data: bytes, pos: int) -> str:
    """Decode a UTF-8 pool entry: u16-ish char-len, u16-ish byte-len, NUL-term."""
    # Two length prefixes (in characters then bytes). Each uses a high-bit
    # extension scheme on the *first* byte: if the top bit is set, a second byte
    # extends the value.
    _char_len, pos = _decode_len8(data, pos)
    byte_len, pos = _decode_len8(data, pos)
    raw = data[pos:pos + byte_len]
    return raw.decode("utf-8", "replace")


def _decode_len8(data: bytes, pos: int) -> tuple[int, int]:
    val = data[pos]
    pos += 1
    if val & 0x80:
        val = ((val & 0x7F) << 8) | data[pos]
        pos += 1
    return val, pos


def _decode_utf16_string(data: bytes, pos: int) -> str:
    """Decode a UTF-16LE pool entry: u16 char-len (high-bit extension), then chars."""
    val = _u16(data, pos)
    pos += 2
    if val & 0x8000:
        val = ((val & 0x7FFF) << 16) | _u16(data, pos)
        pos += 2
    byte_len = val * 2
    raw = data[pos:pos + byte_len]
    return raw.decode("utf-16-le", "replace")


def parse_string_pool(data: bytes, chunk_off: int, errors: list[str]) -> list[str]:
    """Parse a RES_STRING_POOL_TYPE chunk into a list of strings.

    The pool header layout (all little-endian):
        u16 type, u16 headerSize, u32 chunkSize,
        u32 stringCount, u32 styleCount, u32 flags,
        u32 stringsStart, u32 stylesStart
    followed by ``stringCount`` u32 offsets (relative to stringsStart).
    """
    try:
        header_size = _u16(data, chunk_off + 2)
        chunk_size = _u32(data, chunk_off + 4)
        string_count = _u32(data, chunk_off + 8)
        flags = _u32(data, chunk_off + 16)
        strings_start = _u32(data, chunk_off + 20)
    except struct.error as exc:
        errors.append(f"string pool header truncated: {exc}")
        return []

    is_utf8 = bool(flags & _UTF8_FLAG)
    offsets_base = chunk_off + 28
    data_base = chunk_off + strings_start
    chunk_end = min(chunk_off + chunk_size, len(data))

    strings: list[str] = []
    for i in range(string_count):
        off_pos = offsets_base + i * 4
        if off_pos + 4 > len(data):
            errors.append(f"string offset table truncated at index {i}")
            break
        rel = _u32(data, off_pos)
        start = data_base + rel
        if start < 0 or start >= len(data) or start >= chunk_end:
            errors.append(f"string {i} offset out of bounds")
            strings.append("")
            continue
        try:
            if is_utf8:
                strings.append(_decode_utf8_string(data, start))
            else:
                strings.append(_decode_utf16_string(data, start))
        except (struct.error, IndexError) as exc:
            errors.append(f"string {i} decode failed: {exc}")
            strings.append("")
    return strings


# ===========================================================================
# Typed-value resolution
# ===========================================================================


def _resolve_typed_value(data_type: int, raw_data: int, pool: StringPool,
                         raw_value_ref: int) -> Any:
    """Map a Res_value (dataType, data) to a Python value."""
    if data_type == TYPE_STRING:
        s = pool.get(raw_data)
        if s is None:
            s = pool.get(raw_value_ref)
        return s if s is not None else ""
    if data_type == TYPE_INT_BOOLEAN:
        return raw_data != 0
    if data_type in (TYPE_INT_DEC, TYPE_INT_HEX):
        # Interpret as signed 32-bit for human-friendly values.
        return raw_data - (1 << 32) if raw_data >= (1 << 31) else raw_data
    if data_type == TYPE_REFERENCE:
        return f"@0x{raw_data:08x}"
    if data_type == TYPE_ATTRIBUTE:
        return f"?0x{raw_data:08x}"
    if data_type == TYPE_NULL:
        # A non-string raw value can still carry text (rare); prefer it.
        s = pool.get(raw_value_ref)
        return s if s is not None else None
    if data_type == TYPE_FLOAT:
        return struct.unpack("<f", struct.pack("<I", raw_data))[0]
    # Unknown/dimension/fraction etc: fall back to the raw value string if any.
    s = pool.get(raw_value_ref)
    return s if s is not None else raw_data


# ===========================================================================
# AXML document parser
# ===========================================================================


def parse_axml(data: bytes) -> ParsedManifest:
    """Parse a compiled ``AndroidManifest.xml`` (binary AXML) into a tree.

    Always returns a :class:`ParsedManifest`; parse problems are collected in
    ``errors`` rather than raised, so a partially-malformed manifest still yields
    whatever surface could be recovered.
    """
    errors: list[str] = []
    if len(data) < 8:
        return ParsedManifest(root=None, errors=["file too small to be AXML"])

    file_type = _u16(data, 0)
    if file_type != RES_XML_TYPE:
        errors.append(f"unexpected root chunk type 0x{file_type:04x} "
                      f"(expected RES_XML_TYPE 0x0003)")
        # Some tooling omits the wrapper; try to proceed by scanning chunks.

    pool: StringPool = StringPool([])
    root: XmlElement | None = None
    stack: list[XmlElement] = []

    # Walk top-level chunks after the 8-byte RES_XML header.
    pos = 8 if file_type == RES_XML_TYPE else 0
    n = len(data)
    guard = 0
    while pos + 8 <= n:
        guard += 1
        if guard > 1_000_000:  # pathological loop guard
            errors.append("chunk iteration guard tripped")
            break
        try:
            ctype = _u16(data, pos)
            header_size = _u16(data, pos + 2)
            csize = _u32(data, pos + 4)
        except struct.error as exc:
            errors.append(f"chunk header truncated at {pos}: {exc}")
            break

        if csize < 8 or pos + csize > n:
            errors.append(f"chunk size {csize} at {pos} out of bounds; stopping")
            break

        if ctype == RES_STRING_POOL_TYPE:
            pool = StringPool(parse_string_pool(data, pos, errors))
        elif ctype == RES_XML_RESOURCE_MAP_TYPE:
            pass  # optional; not needed for name-based attribute lookup
        elif ctype in (RES_XML_START_NAMESPACE_TYPE, RES_XML_END_NAMESPACE_TYPE):
            pass  # namespace declarations are not needed for capability extraction
        elif ctype == RES_XML_START_ELEMENT_TYPE:
            elem = _parse_start_element(data, pos, header_size, pool, errors)
            if elem is not None:
                if stack:
                    stack[-1].children.append(elem)
                elif root is None:
                    root = elem
                stack.append(elem)
        elif ctype == RES_XML_END_ELEMENT_TYPE:
            if stack:
                stack.pop()
        elif ctype == RES_XML_CDATA_TYPE:
            text = _parse_cdata(data, pos, header_size, pool)
            if text and stack:
                stack[-1].text = (stack[-1].text + text) if stack[-1].text else text
        # else: RES_NULL / unknown -> skip by chunk size.

        pos += csize

    if root is None and not errors:
        errors.append("no start element found")
    return ParsedManifest(root=root, strings=pool.strings, errors=errors)


def _parse_start_element(data: bytes, chunk_off: int, header_size: int,
                         pool: StringPool, errors: list[str]) -> XmlElement | None:
    """Parse a RES_XML_START_ELEMENT_TYPE chunk.

    After the common 8-byte chunk header + (lineNumber u32, comment u32) which
    make up the ResXMLTree_node, the start-element body is:
        u32 ns, u32 name,
        u16 attributeStart, u16 attributeSize, u16 attributeCount,
        u16 idIndex, u16 classIndex, u16 styleIndex,
    then ``attributeCount`` attribute records of:
        u32 ns, u32 name, u32 rawValue,
        u16 size, u8 res0, u8 dataType, u32 data
    """
    # The element body starts after the ResXMLTree_node (header_size covers
    # type/headerSize/size/lineNumber/comment = 16 bytes typically).
    body = chunk_off + (header_size if header_size >= 16 else 16)
    try:
        name_ref = _u32(data, body + 4)
        attribute_start = _u16(data, body + 8)
        attribute_count = _u16(data, body + 12)
    except struct.error as exc:
        errors.append(f"start element header truncated at {chunk_off}: {exc}")
        return None

    tag = pool.get(name_ref) or ""
    elem = XmlElement(tag=tag)

    attr_base = body + attribute_start
    for i in range(attribute_count):
        rec = attr_base + i * 20
        if rec + 20 > len(data):
            errors.append(f"attribute {i} of <{tag}> out of bounds")
            break
        try:
            a_ns = _s32(data, rec)
            a_name = _u32(data, rec + 4)
            a_raw_value = _u32(data, rec + 8)
            a_data_type = data[rec + 15]
            a_data = _u32(data, rec + 16)
        except struct.error as exc:
            errors.append(f"attribute {i} of <{tag}> truncated: {exc}")
            break
        namespace = pool.get(a_ns)
        local_name = pool.get(a_name) or ""
        value = _resolve_typed_value(a_data_type, a_data, pool, a_raw_value)
        elem.attributes.append(XmlAttribute(
            namespace=namespace, name=local_name, value=value, raw_type=a_data_type))
    return elem


def _parse_cdata(data: bytes, chunk_off: int, header_size: int, pool: StringPool) -> str:
    body = chunk_off + (header_size if header_size >= 16 else 16)
    try:
        text_ref = _u32(data, body)
    except struct.error:
        return ""
    return pool.get(text_ref) or ""


# ===========================================================================
# Capability extraction
# ===========================================================================

# A small, deliberately-curated set of Android permissions whose addition is a
# meaningful capability/attack-surface change. Stored without the standard
# ``android.permission.`` prefix; lookups strip the prefix first.
DANGEROUS_PERMISSIONS = {
    "ACCESS_BACKGROUND_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_FINE_LOCATION",
    "ACTIVITY_RECOGNITION",
    "ANSWER_PHONE_CALLS",
    "BLUETOOTH_CONNECT",
    "BLUETOOTH_SCAN",
    "BODY_SENSORS",
    "CALL_PHONE",
    "CAMERA",
    "GET_ACCOUNTS",
    "MANAGE_EXTERNAL_STORAGE",
    "POST_NOTIFICATIONS",
    "PROCESS_OUTGOING_CALLS",
    "READ_CALENDAR",
    "READ_CALL_LOG",
    "READ_CONTACTS",
    "READ_EXTERNAL_STORAGE",
    "READ_MEDIA_AUDIO",
    "READ_MEDIA_IMAGES",
    "READ_MEDIA_VIDEO",
    "READ_PHONE_NUMBERS",
    "READ_PHONE_STATE",
    "READ_SMS",
    "RECEIVE_MMS",
    "RECEIVE_SMS",
    "RECEIVE_WAP_PUSH",
    "RECORD_AUDIO",
    "SEND_SMS",
    "SYSTEM_ALERT_WINDOW",
    "USE_SIP",
    "WRITE_CALENDAR",
    "WRITE_CALL_LOG",
    "WRITE_CONTACTS",
    "WRITE_EXTERNAL_STORAGE",
    "REQUEST_INSTALL_PACKAGES",
    "QUERY_ALL_PACKAGES",
    # Network reach -- not a "dangerous"-level Android permission, but a notable
    # capability surface when newly added to a build that previously lacked it.
    "INTERNET",
}


def _short_permission(name: str) -> str:
    """``android.permission.RECORD_AUDIO`` -> ``RECORD_AUDIO`` (else unchanged)."""
    if not name:
        return name
    return name.rsplit(".", 1)[-1]


def is_dangerous_permission(name: str) -> bool:
    return _short_permission(name).upper() in DANGEROUS_PERMISSIONS


def _as_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        try:
            return int(value, 0)
        except ValueError:
            return None
    return None


def _as_bool(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "1"):
            return True
        if low in ("false", "0"):
            return False
    return None


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _intent_filter_profile(elem: XmlElement) -> dict[str, Any]:
    actions: list[str] = []
    categories: list[str] = []
    schemes: list[str] = []
    for child in elem.children:
        if child.tag == "action":
            name = _as_str(child.attr("name"))
            if name:
                actions.append(name)
        elif child.tag == "category":
            name = _as_str(child.attr("name"))
            if name:
                categories.append(name)
        elif child.tag == "data":
            scheme = _as_str(child.attr("scheme"))
            if scheme:
                schemes.append(scheme)
    return {
        "actions": sorted(set(actions)),
        "categories": sorted(set(categories)),
        "schemes": sorted(set(schemes)),
    }


def _component_profile(elem: XmlElement) -> dict[str, Any]:
    name = _as_str(elem.attr("name"))
    exported_raw = elem.attr("exported")
    exported = _as_bool(exported_raw)
    permission = _as_str(elem.attr("permission"))
    intent_filters = [_intent_filter_profile(c) for c in elem.children
                      if c.tag == "intent-filter"]
    return {
        "name": name,
        "exported": exported,
        "permission": permission,
        "intent_filters": intent_filters,
    }


def _is_effectively_exported(comp: dict[str, Any]) -> bool:
    """An explicit ``exported=true``, or an intent-filter with no explicit false.

    A component with an intent-filter is exported by default unless
    ``exported=false`` is set; an explicit ``exported=true`` is exported
    regardless of filters.
    """
    if comp.get("exported") is True:
        return True
    if comp.get("exported") is False:
        return False
    return bool(comp.get("intent_filters"))


def extract_capabilities(parsed: ParsedManifest) -> dict[str, Any]:
    """Distil a parsed manifest tree into a JSON-serializable capability profile."""
    profile: dict[str, Any] = {
        "package": None,
        "versionCode": None,
        "versionName": None,
        "uses_sdk": {"minSdkVersion": None, "targetSdkVersion": None},
        "uses_permission": [],
        "uses_feature": [],
        "uses_library": [],
        "application": {
            "debuggable": None,
            "allowBackup": None,
            "usesCleartextTraffic": None,
            "networkSecurityConfig": None,
        },
        "components": {"activity": [], "service": [], "receiver": [], "provider": []},
        "exported_components": [],
        "errors": list(parsed.errors),
    }

    root = parsed.root
    if root is None or root.tag != "manifest":
        if root is not None:
            profile["errors"].append(f"root element is <{root.tag}>, expected <manifest>")
        return profile

    profile["package"] = _as_str(root.attr("package", namespace=None))
    profile["versionCode"] = _as_int(root.attr("versionCode"))
    profile["versionName"] = _as_str(root.attr("versionName"))

    permissions: set[str] = set()
    features: set[str] = set()
    libraries: set[str] = set()

    for child in root.children:
        if child.tag == "uses-permission" or child.tag == "uses-permission-sdk-23":
            name = _as_str(child.attr("name"))
            if name:
                permissions.add(name)
        elif child.tag == "uses-feature":
            name = _as_str(child.attr("name"))
            if name:
                features.add(name)
        elif child.tag == "uses-sdk":
            profile["uses_sdk"]["minSdkVersion"] = _as_int(child.attr("minSdkVersion"))
            profile["uses_sdk"]["targetSdkVersion"] = _as_int(child.attr("targetSdkVersion"))
        elif child.tag == "application":
            _extract_application(child, profile, libraries)

    profile["uses_permission"] = sorted(permissions)
    profile["uses_feature"] = sorted(features)
    profile["uses_library"] = sorted(libraries)

    exported: list[str] = []
    for kind in ("activity", "service", "receiver", "provider"):
        for comp in profile["components"][kind]:
            if _is_effectively_exported(comp) and comp.get("name"):
                exported.append(comp["name"])
    profile["exported_components"] = sorted(set(exported))
    return profile


def _extract_application(app: XmlElement, profile: dict[str, Any],
                         libraries: set[str]) -> None:
    appdict = profile["application"]
    appdict["debuggable"] = _as_bool(app.attr("debuggable"))
    appdict["allowBackup"] = _as_bool(app.attr("allowBackup"))
    appdict["usesCleartextTraffic"] = _as_bool(app.attr("usesCleartextTraffic"))
    appdict["networkSecurityConfig"] = _as_str(app.attr("networkSecurityConfig"))

    tag_map = {
        "activity": "activity",
        "activity-alias": "activity",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }
    for child in app.children:
        if child.tag == "uses-library":
            name = _as_str(child.attr("name"))
            if name:
                libraries.add(name)
        elif child.tag in tag_map:
            profile["components"][tag_map[child.tag]].append(_component_profile(child))


# ===========================================================================
# Artifact loading
# ===========================================================================

_MANIFEST_ENTRY = "AndroidManifest.xml"


def load_manifest(path: Path | str) -> tuple[ParsedManifest, dict[str, Any]]:
    """Load and parse an ``AndroidManifest.xml`` from any supported input.

    Supported inputs:
      * ``.apk``/``.zip`` -- archive containing ``AndroidManifest.xml``;
      * a raw binary ``AndroidManifest.xml`` file;
      * a directory containing one of the above.

    Returns ``(ParsedManifest, capability_profile)``.
    """
    path = Path(path)
    data = _read_manifest_bytes(path)
    parsed = parse_axml(data)
    profile = extract_capabilities(parsed)
    return parsed, profile


def _read_manifest_bytes(path: Path) -> bytes:
    if not path.exists():
        raise ManifestError(f"path does not exist: {path}")

    if path.is_dir():
        # Prefer a top-level AndroidManifest.xml, else the first APK/zip found.
        direct = path / _MANIFEST_ENTRY
        if direct.is_file():
            return direct.read_bytes()
        archives = sorted(p for p in path.rglob("*")
                          if p.suffix.lower() in (".apk", ".zip") and p.is_file())
        if archives:
            return _read_from_zip(archives[0])
        loose = sorted(path.rglob(_MANIFEST_ENTRY))
        if loose:
            return loose[0].read_bytes()
        raise ManifestError(f"no AndroidManifest.xml or .apk found under {path}")

    suffix = path.suffix.lower()
    if suffix in (".apk", ".zip"):
        return _read_from_zip(path)

    # Raw file. If it is itself a zip (mis-named APK), handle that; else treat
    # as a raw binary manifest.
    raw = path.read_bytes()
    if raw[:2] == b"PK":
        return _read_from_zip(path)
    return raw


def _read_from_zip(path: Path) -> bytes:
    try:
        with zipfile.ZipFile(path) as zf:
            return _read_manifest_from_zipfile(zf, str(path))
    except zipfile.BadZipFile as exc:
        raise ManifestError(f"{path} is not a readable zip/APK: {exc}") from exc


def _read_manifest_from_zipfile(zf: zipfile.ZipFile, label: str) -> bytes:
    names = zf.namelist()
    if _MANIFEST_ENTRY in names:
        return zf.read(_MANIFEST_ENTRY)
    # Case-insensitive / nested fallback.
    for n in names:
        if n.rsplit("/", 1)[-1] == _MANIFEST_ENTRY:
            return zf.read(n)
    raise ManifestError(f"no {_MANIFEST_ENTRY} entry in {label}")


def manifest_bytes_from_zip_bytes(blob: bytes) -> bytes:
    """Extract the manifest bytes from in-memory APK/zip bytes (helper/testing)."""
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        return _read_manifest_from_zipfile(zf, "<bytes>")


# ===========================================================================
# Diff engine
# ===========================================================================


@dataclass
class Finding:
    severity: str       # "high" | "medium" | "info"
    category: str
    summary: str
    detail: str

    def to_row(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "category": self.category,
            "summary": self.summary,
            "detail": self.detail,
        }


def _exported_set(profile: dict[str, Any]) -> set[str]:
    return set(profile.get("exported_components", []) or [])


def diff_manifests(a: dict[str, Any], b: dict[str, Any]) -> list[Finding]:
    """Diff two capability profiles (a = reference, b = compared).

    Produces high-signal-oriented findings in the spirit of the iOS engine:
    newly-added sensitive permissions, newly-exported components, security-flag
    regressions (debuggable/cleartext/allowBackup), lowered minSdk and SDK
    drift, and added/removed features.
    """
    findings: list[Finding] = []

    # --- Permissions ---
    a_perms = set(a.get("uses_permission", []) or [])
    b_perms = set(b.get("uses_permission", []) or [])
    for perm in sorted(b_perms - a_perms):
        dangerous = is_dangerous_permission(perm)
        findings.append(Finding(
            severity="high" if dangerous else "info",
            category="Permission added",
            summary=f"Added permission {perm}",
            detail=("dangerous/sensitive permission newly requested"
                    if dangerous else "non-sensitive permission added"),
        ))
    for perm in sorted(a_perms - b_perms):
        findings.append(Finding(
            severity="info",
            category="Permission removed",
            summary=f"Removed permission {perm}",
            detail="permission present in reference but not in compared build",
        ))

    # --- Exported components ---
    a_exp = _exported_set(a)
    b_exp = _exported_set(b)
    for comp in sorted(b_exp - a_exp):
        findings.append(Finding(
            severity="high",
            category="Component exported",
            summary=f"Newly exported component {comp}",
            detail="component is exported (or filter-exposed) in compared but not reference",
        ))
    for comp in sorted(a_exp - b_exp):
        findings.append(Finding(
            severity="info",
            category="Component unexported",
            summary=f"Component no longer exported {comp}",
            detail="component was exported in reference but is not in compared",
        ))

    # --- Application security flags ---
    a_app = a.get("application", {}) or {}
    b_app = b.get("application", {}) or {}

    def flag_finding(key: str, label: str, risky_value: bool) -> None:
        av = a_app.get(key)
        bv = b_app.get(key)
        if av == bv:
            return
        # A regression toward the risky value is high-signal; otherwise info.
        if bv is risky_value:
            sev = "high"
            detail = f"{label} set to {bv!r} (was {av!r}) -- security-relevant"
        else:
            sev = "info"
            detail = f"{label} changed {av!r} -> {bv!r}"
        findings.append(Finding(
            severity=sev, category="Application flag",
            summary=f"{label} differs", detail=detail))

    flag_finding("debuggable", "android:debuggable", True)
    flag_finding("usesCleartextTraffic", "android:usesCleartextTraffic", True)
    flag_finding("allowBackup", "android:allowBackup", True)

    a_nsc = a_app.get("networkSecurityConfig")
    b_nsc = b_app.get("networkSecurityConfig")
    if a_nsc != b_nsc:
        # Losing a network-security-config (None in compared) is the risky case.
        sev = "high" if b_nsc is None and a_nsc is not None else "info"
        findings.append(Finding(
            severity=sev, category="Application flag",
            summary="networkSecurityConfig differs",
            detail=f"reference={a_nsc!r}; compared={b_nsc!r}"))

    # --- SDK levels ---
    a_sdk = a.get("uses_sdk", {}) or {}
    b_sdk = b.get("uses_sdk", {}) or {}
    a_min = a_sdk.get("minSdkVersion")
    b_min = b_sdk.get("minSdkVersion")
    if a_min != b_min:
        lowered = (isinstance(a_min, int) and isinstance(b_min, int) and b_min < a_min)
        findings.append(Finding(
            severity="high" if lowered else "info",
            category="SDK level",
            summary="minSdkVersion differs",
            detail=(f"lowered {a_min} -> {b_min} (widens exposure to older OS)"
                    if lowered else f"reference={a_min}; compared={b_min}")))
    a_tgt = a_sdk.get("targetSdkVersion")
    b_tgt = b_sdk.get("targetSdkVersion")
    if a_tgt != b_tgt:
        lowered = (isinstance(a_tgt, int) and isinstance(b_tgt, int) and b_tgt < a_tgt)
        findings.append(Finding(
            severity="medium" if lowered else "info",
            category="SDK level",
            summary="targetSdkVersion differs",
            detail=(f"lowered {a_tgt} -> {b_tgt} (relaxes platform hardening)"
                    if lowered else f"reference={a_tgt}; compared={b_tgt}")))

    # --- Features ---
    a_feat = set(a.get("uses_feature", []) or [])
    b_feat = set(b.get("uses_feature", []) or [])
    for feat in sorted(b_feat - a_feat):
        findings.append(Finding(
            severity="info", category="Feature added",
            summary=f"Added feature {feat}", detail="declared hardware/software feature added"))
    for feat in sorted(a_feat - b_feat):
        findings.append(Finding(
            severity="info", category="Feature removed",
            summary=f"Removed feature {feat}", detail="declared feature present only in reference"))

    # --- Package / version identity (informational) ---
    if a.get("package") != b.get("package"):
        findings.append(Finding(
            severity="info", category="Identity",
            summary="package differs",
            detail=f"reference={a.get('package')!r}; compared={b.get('package')!r}"))
    if a.get("versionName") != b.get("versionName") or a.get("versionCode") != b.get("versionCode"):
        findings.append(Finding(
            severity="info", category="Identity",
            summary="version differs",
            detail=(f"reference={a.get('versionName')!r}({a.get('versionCode')}); "
                    f"compared={b.get('versionName')!r}({b.get('versionCode')})")))

    return findings


_SEVERITY_ORDER = {"high": 0, "medium": 1, "info": 2, "low": 1}


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_ORDER.get(f.severity, 9),
                                           f.category, f.summary))


# ===========================================================================
# Reporting
# ===========================================================================


def _md_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "_None._\n"

    def cell(v: Any) -> str:
        s = "" if v is None else (json.dumps(v) if isinstance(v, (list, dict)) else str(v))
        s = s.replace("\n", " ").replace("|", "\\|")
        return s[:160]

    lines = ["| " + " | ".join(columns) + " |",
             "| " + " | ".join("---" for _ in columns) + " |"]
    for row in rows:
        lines.append("| " + " | ".join(cell(row.get(c)) for c in columns) + " |")
    return "\n".join(lines) + "\n"


def _capability_summary_rows(profile: dict[str, Any]) -> list[dict[str, Any]]:
    app = profile.get("application", {}) or {}
    sdk = profile.get("uses_sdk", {}) or {}
    return [
        {"field": "package", "value": profile.get("package")},
        {"field": "versionName", "value": profile.get("versionName")},
        {"field": "versionCode", "value": profile.get("versionCode")},
        {"field": "minSdkVersion", "value": sdk.get("minSdkVersion")},
        {"field": "targetSdkVersion", "value": sdk.get("targetSdkVersion")},
        {"field": "debuggable", "value": app.get("debuggable")},
        {"field": "allowBackup", "value": app.get("allowBackup")},
        {"field": "usesCleartextTraffic", "value": app.get("usesCleartextTraffic")},
        {"field": "networkSecurityConfig", "value": app.get("networkSecurityConfig")},
        {"field": "permission_count", "value": len(profile.get("uses_permission", []) or [])},
        {"field": "exported_component_count",
         "value": len(profile.get("exported_components", []) or [])},
    ]


def render_report(a_profile: dict[str, Any], b_profile: dict[str, Any],
                  findings: list[Finding], a_label: str, b_label: str) -> str:
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ordered = sort_findings(findings)
    high = [f for f in ordered if f.severity == "high"]
    finding_rows = [f.to_row() for f in ordered]

    t: list[str] = []
    t.append("# Android manifest capability-diff report")
    t.append("")
    t.append(f"- Generated: {now}")
    t.append(f"- Reference (a): `{a_label}`")
    t.append(f"- Compared (b): `{b_label}`")
    t.append(f"- High-signal findings: {len(high)} (review first); "
             f"total findings: {len(ordered)}")
    t.append("")
    t.append("## Scope")
    t.append("")
    t.append("Read-only capability comparison of two compiled `AndroidManifest.xml` "
             "files (binary AXML) extracted from APKs. This decodes declared "
             "permissions, component export surface, and application security flags. "
             "It does not decrypt, deobfuscate, repackage, or execute anything, "
             "mirroring the iOS Info.plist/entitlements comparison and the kit's "
             "scope boundary.")
    t.append("")
    t.append("## Findings (high-signal first)")
    t.append("")
    t.append("High-signal deltas are capability/attack-surface regressions: newly "
             "requested sensitive permissions, newly-exported components, "
             "`debuggable`/cleartext enabled, a dropped network-security-config, or a "
             "lowered `minSdkVersion`. Informational deltas are expected build/release "
             "drift (version strings, package id, benign feature/permission churn).")
    t.append("")
    t.append(_md_table(finding_rows, ["severity", "category", "summary", "detail"]))
    t.append("")
    t.append("## Capability surface")
    t.append("")
    t.append("| Field | Reference (a) | Compared (b) |")
    t.append("|---|---|---|")
    a_rows = {r["field"]: r["value"] for r in _capability_summary_rows(a_profile)}
    b_rows = {r["field"]: r["value"] for r in _capability_summary_rows(b_profile)}
    for field_name in a_rows:
        av = a_rows.get(field_name)
        bv = b_rows.get(field_name)
        t.append(f"| {field_name} | {av} | {bv} |")
    t.append("")
    t.append("## Permissions")
    t.append("")
    a_perms = set(a_profile.get("uses_permission", []) or [])
    b_perms = set(b_profile.get("uses_permission", []) or [])
    perm_rows = []
    for perm in sorted(a_perms | b_perms):
        perm_rows.append({
            "permission": perm,
            "in_a": "yes" if perm in a_perms else "",
            "in_b": "yes" if perm in b_perms else "",
            "sensitive": "yes" if is_dangerous_permission(perm) else "",
        })
    t.append(_md_table(perm_rows, ["permission", "in_a", "in_b", "sensitive"]))
    t.append("")
    t.append("## Exported components")
    t.append("")
    a_exp = _exported_set(a_profile)
    b_exp = _exported_set(b_profile)
    exp_rows = []
    for comp in sorted(a_exp | b_exp):
        exp_rows.append({
            "component": comp,
            "in_a": "yes" if comp in a_exp else "",
            "in_b": "yes" if comp in b_exp else "",
        })
    t.append(_md_table(exp_rows, ["component", "in_a", "in_b"]))
    t.append("")
    t.append("## How to read this")
    t.append("")
    t.append("- **High-signal** rows are the ones to investigate: they widen the "
             "attack surface or weaken hardening relative to the reference build.")
    t.append("- **Informational** rows are usually expected release-to-release or "
             "build-flavor drift; confirm they match your expectations and move on.")
    t.append("- The manifest is a *declaration*, not proof of runtime behaviour. A "
             "permission can be declared but unused, or a component exported but "
             "guarded by a signature-level permission -- corroborate with the "
             "bundled-library and binary evidence in the rest of the kit.")
    t.append("")
    t.append("## Outputs")
    t.append("- `report.md` / `report.html`: this report")
    t.append("- `csv/manifest_findings.csv`: the findings table")
    t.append("- `a.manifest.json` / `b.manifest.json`: the full capability profiles")
    return "\n".join(t)


_SEVERITY_COLORS = {"high": "#b00020", "medium": "#b26a00", "low": "#555555", "info": "#0061a8"}


def _inline(s: str) -> str:
    out = html.escape(s)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    return out


def report_to_html(md: str) -> str:
    """Minimal, self-contained markdown-ish renderer (mirrors android_lib_match)."""
    lines = md.splitlines()
    out = ["<!doctype html><html><head><meta charset='utf-8'>",
           "<title>Android manifest capability-diff report</title>",
           "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;"
           "max-width:1100px;margin:40px auto;padding:0 24px;line-height:1.45} "
           "code{background:#f4f4f4;padding:2px 4px;border-radius:4px} "
           "table{border-collapse:collapse;width:100%;font-size:13px} "
           "td,th{border:1px solid #ddd;padding:6px;vertical-align:top} "
           "th{background:#f6f6f6} h1,h2,h3{line-height:1.2}</style>",
           "</head><body>"]
    in_table = False
    rows: list[str] = []

    def flush() -> None:
        nonlocal rows, in_table
        if not in_table:
            return
        out.append("<table>")
        header_done = False
        for row in rows:
            cells = [c.strip().replace("\\|", "|") for c in row.strip().strip("|").split("|")]
            if all(set(c) <= {"-", ":"} and c for c in cells):
                continue
            tag = "th" if not header_done else "td"
            rendered = []
            for c in cells:
                if tag == "td" and c.lower() in _SEVERITY_COLORS:
                    rendered.append(
                        f'<td><span style="color:{_SEVERITY_COLORS[c.lower()]};'
                        f'font-weight:600">{html.escape(c)}</span></td>')
                else:
                    rendered.append(f"<{tag}>{_inline(c)}</{tag}>")
            out.append("<tr>" + "".join(rendered) + "</tr>")
            header_done = True
        out.append("</table>")
        rows = []
        in_table = False

    for line in lines:
        if line.startswith("|") and line.endswith("|"):
            in_table = True
            rows.append(line)
            continue
        flush()
        if line.startswith("# "):
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            out.append(f"<p>&bull; {_inline(line[2:])}</p>")
        elif not line.strip():
            out.append("")
        else:
            out.append(f"<p>{_inline(line)}</p>")
    flush()
    out.append("</body></html>")
    return "\n".join(out)


# ===========================================================================
# CLI
# ===========================================================================


def cmd_extract(args: argparse.Namespace) -> int:
    path = Path(args.apk)
    if not path.exists():
        eprint(f"[!] artifact not found: {path}")
        return 2
    try:
        _parsed, profile = load_manifest(path)
    except ManifestError as exc:
        eprint(f"[!] {exc}")
        return 1

    text = json.dumps(profile, indent=2, sort_keys=True, ensure_ascii=False)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"[+] wrote capability profile: {out}")
    if args.json or not args.out:
        print(text)
    else:
        pkg = profile.get("package")
        nperm = len(profile.get("uses_permission", []) or [])
        nexp = len(profile.get("exported_components", []) or [])
        print(f"[+] {pkg}: {nperm} permissions, {nexp} exported components")
    if profile.get("errors"):
        eprint(f"[i] {len(profile['errors'])} parse note(s); see 'errors' in profile")
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    a_path = Path(args.a)
    b_path = Path(args.b)
    for p in (a_path, b_path):
        if not p.exists():
            eprint(f"[!] artifact not found: {p}")
            return 2

    try:
        _a_parsed, a_profile = load_manifest(a_path)
        _b_parsed, b_profile = load_manifest(b_path)
    except ManifestError as exc:
        eprint(f"[!] {exc}")
        return 1

    findings = diff_manifests(a_profile, b_profile)

    out_dir = Path(args.out)
    (out_dir / "csv").mkdir(parents=True, exist_ok=True)

    (out_dir / "a.manifest.json").write_text(
        json.dumps(a_profile, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")
    (out_dir / "b.manifest.json").write_text(
        json.dumps(b_profile, indent=2, sort_keys=True, ensure_ascii=False), encoding="utf-8")

    write_csv(out_dir / "csv" / "manifest_findings.csv",
              [f.to_row() for f in sort_findings(findings)])

    md = render_report(a_profile, b_profile, findings, str(a_path), str(b_path))
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.html").write_text(report_to_html(md), encoding="utf-8")

    high = sum(1 for f in findings if f.severity == "high")
    print(f"[=] {len(findings)} findings ({high} high-signal)")
    for f in sort_findings(findings):
        if f.severity == "high":
            print(f"    [HIGH] {f.category}: {f.summary}")
    print(f"[+] wrote report: {out_dir / 'report.html'}")
    return 0


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(rows)


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Parse the binary AndroidManifest.xml out of an APK into a "
                    "capability profile, and diff two APKs' capability surfaces "
                    "(the Android analogue of the iOS Info.plist/entitlements diff).")
    sub = parser.add_subparsers(dest="command", required=True)

    ex = sub.add_parser("extract", help="Extract one APK's manifest capability profile.")
    ex.add_argument("--apk", required=True,
                    help="APK/zip, a raw AndroidManifest.xml, or a directory containing one.")
    ex.add_argument("--json", action="store_true",
                    help="Always print the full JSON profile to stdout.")
    ex.add_argument("-o", "--out", help="Write the JSON profile to this path.")
    ex.set_defaults(func=cmd_extract)

    df = sub.add_parser("diff", help="Diff two APKs' manifest capability surfaces.")
    df.add_argument("--a", required=True, help="Reference APK/manifest/dir (e.g. App Store build).")
    df.add_argument("--b", required=True, help="Compared APK/manifest/dir (e.g. source/F-Droid build).")
    df.add_argument("--out", required=True, help="Output directory for the report.")
    df.set_defaults(func=cmd_diff)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
