#!/usr/bin/env python3
"""
Dependency-free Android/JVM bytecode reader for the bundled-library matcher.

Purpose:
  Extract the structural shape of compiled classes from the two formats an
  Android open-source library is distributed and shipped in:

    * JVM ``.class`` bytecode  -- how Maven/Google-Maven ship a library
      (``.jar`` directly, or ``.aar`` -> ``classes.jar`` -> ``*.class``).
    * Dalvik ``.dex`` bytecode -- how the library actually lands inside a
      shipped ``.apk`` after dexing (and after R8/ProGuard renaming).

  Both formats use the *same* JVM type-descriptor grammar
  (``Lcom/foo/Bar;``, ``[I``, ``(Landroid/os/Bundle;I)Ljava/lang/String;``),
  which is what makes cross-format structural matching possible.

Scope:
  This reads what is already present in a lawful artifact -- class/method/field
  structure, type descriptors, access flags and surviving string constants. It
  does not decrypt, deobfuscate, modify, repackage, or execute anything. It is a
  read-only Software-Composition-Analysis primitive.

  Parsing is deliberately limited to the *structural* level (the constant pool,
  the class/field/method tables and their descriptors). Per-instruction opcode
  decoding is intentionally not performed: structural signatures are both the
  obfuscation-resilient signal and the lower-risk parse.

Pure standard library only.
"""
from __future__ import annotations

import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

# ---------------------------------------------------------------------------
# Common code model -- both parsers normalize into these.
# ---------------------------------------------------------------------------


@dataclass
class MethodInfo:
    name: str            # original member name (often obfuscated; never trusted)
    descriptor: str      # JVM descriptor grammar, e.g. "(Landroid/os/Bundle;)V"
    access: int          # access flags (a normalized subset is used downstream)


@dataclass
class FieldInfo:
    name: str            # original member name (often obfuscated; never trusted)
    descriptor: str      # type descriptor, e.g. "Ljava/lang/String;"
    access: int


@dataclass
class ClassUnit:
    name: str                       # internal name, e.g. "com/foo/Bar"
    super_name: str                 # internal name of the superclass ("" for none)
    interfaces: list[str] = field(default_factory=list)
    methods: list[MethodInfo] = field(default_factory=list)
    fields: list[FieldInfo] = field(default_factory=list)
    string_constants: list[str] = field(default_factory=list)
    source_format: str = ""         # "jvm" or "dex"


@dataclass
class ArtifactUnits:
    classes: list[ClassUnit] = field(default_factory=list)
    formats: set[str] = field(default_factory=set)   # {"jvm"}, {"dex"}, or both
    sources: list[str] = field(default_factory=list)  # member paths parsed


class BytecodeError(Exception):
    """Raised when an input is not parseable as JVM/DEX bytecode."""


# ===========================================================================
# JVM .class parser
# ===========================================================================

# Constant-pool tags (JVMS 4.4).
_CP_UTF8 = 1
_CP_INTEGER = 3
_CP_FLOAT = 4
_CP_LONG = 5
_CP_DOUBLE = 6
_CP_CLASS = 7
_CP_STRING = 8
_CP_FIELDREF = 9
_CP_METHODREF = 10
_CP_INTERFACEMETHODREF = 11
_CP_NAMEANDTYPE = 12
_CP_METHODHANDLE = 15
_CP_METHODTYPE = 16
_CP_DYNAMIC = 17
_CP_INVOKEDYNAMIC = 18
_CP_MODULE = 19
_CP_PACKAGE = 20


def parse_classfile(data: bytes) -> ClassUnit:
    """Parse a single JVM ``.class`` file into a :class:`ClassUnit`."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        raise BytecodeError("not a JVM class file (bad magic)")

    pos = 8  # skip magic(4) + minor(2) + major(2)
    cp_count = struct.unpack_from(">H", data, pos)[0]
    pos += 2

    # Constant pool is 1-indexed; entry 0 is unused. Long/Double take two slots.
    utf8: dict[int, str] = {}
    class_ref: dict[int, int] = {}        # cp_index(Class) -> name_utf8_index
    string_ref: dict[int, int] = {}       # cp_index(String) -> utf8_index
    i = 1
    while i < cp_count:
        tag = data[pos]
        pos += 1
        if tag == _CP_UTF8:
            length = struct.unpack_from(">H", data, pos)[0]
            pos += 2
            raw = data[pos:pos + length]
            pos += length
            utf8[i] = _decode_mutf8(raw)
        elif tag in (_CP_INTEGER, _CP_FLOAT):
            pos += 4
        elif tag in (_CP_LONG, _CP_DOUBLE):
            pos += 8
            i += 1  # occupies two pool slots
        elif tag == _CP_CLASS:
            class_ref[i] = struct.unpack_from(">H", data, pos)[0]
            pos += 2
        elif tag == _CP_STRING:
            string_ref[i] = struct.unpack_from(">H", data, pos)[0]
            pos += 2
        elif tag in (_CP_FIELDREF, _CP_METHODREF, _CP_INTERFACEMETHODREF,
                     _CP_NAMEANDTYPE, _CP_DYNAMIC, _CP_INVOKEDYNAMIC):
            pos += 4
        elif tag == _CP_METHODHANDLE:
            pos += 3
        elif tag in (_CP_METHODTYPE, _CP_MODULE, _CP_PACKAGE):
            pos += 2
        else:
            raise BytecodeError(f"unknown constant pool tag {tag}")
        i += 1

    def class_name(idx: int) -> str:
        if idx == 0:
            return ""
        return utf8.get(class_ref.get(idx, 0), "")

    access_flags, this_class, super_class = struct.unpack_from(">HHH", data, pos)
    pos += 6
    name = class_name(this_class)
    super_name = class_name(super_class)

    iface_count = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    interfaces = []
    for _ in range(iface_count):
        iface_idx = struct.unpack_from(">H", data, pos)[0]
        pos += 2
        interfaces.append(class_name(iface_idx))

    fields: list[FieldInfo] = []
    field_count = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    for _ in range(field_count):
        f_access, f_name_i, f_desc_i = struct.unpack_from(">HHH", data, pos)
        pos += 6
        pos = _skip_attributes(data, pos)
        fields.append(FieldInfo(utf8.get(f_name_i, ""), utf8.get(f_desc_i, ""), f_access))

    methods: list[MethodInfo] = []
    method_count = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    for _ in range(method_count):
        m_access, m_name_i, m_desc_i = struct.unpack_from(">HHH", data, pos)
        pos += 6
        pos = _skip_attributes(data, pos)
        methods.append(MethodInfo(utf8.get(m_name_i, ""), utf8.get(m_desc_i, ""), m_access))

    # Surviving string literals: CONSTANT_String entries point at a Utf8 value.
    string_constants = sorted({utf8.get(u, "") for u in string_ref.values()} - {""})

    return ClassUnit(
        name=name,
        super_name=super_name,
        interfaces=interfaces,
        methods=methods,
        fields=fields,
        string_constants=string_constants,
        source_format="jvm",
    )


def _skip_attributes(data: bytes, pos: int) -> int:
    count = struct.unpack_from(">H", data, pos)[0]
    pos += 2
    for _ in range(count):
        _name_i, length = struct.unpack_from(">HI", data, pos)
        pos += 6 + length
    return pos


def _decode_mutf8(raw: bytes) -> str:
    """Decode JVM modified UTF-8. Falls back to a lenient decode on oddities."""
    try:
        # Standard UTF-8 covers the common ASCII/BMP case; modified UTF-8 only
        # diverges on NUL and supplementary characters, which are rare in the
        # descriptors and literals we care about.
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("utf-8", "replace")


# ===========================================================================
# Dalvik .dex parser (structural)
# ===========================================================================

_DEX_MAGICS = (b"dex\n035\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00",
               b"dex\n040\x00")

# DexFile access-flag normalization: Dalvik and JVM share the low-order
# access-flag bits we care about (public/private/protected/static/final/
# abstract/interface), so descriptors and flags compare directly across formats.


def _uleb128(data: bytes, pos: int) -> tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = data[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, pos


def _dex_mutf8(data: bytes, pos: int) -> str:
    # string_data_item: uleb128 utf16_size, then NUL-terminated MUTF-8 bytes.
    _utf16_size, pos = _uleb128(data, pos)
    end = data.index(0, pos)
    return _decode_mutf8(data[pos:end])


def parse_dex(data: bytes) -> list[ClassUnit]:
    """Parse a Dalvik ``.dex`` image into a list of :class:`ClassUnit`."""
    if len(data) < 112 or data[:8] not in _DEX_MAGICS:
        raise BytecodeError("not a DEX file (bad magic)")

    # Header offsets we use (little-endian). See the Dalvik dex-format spec.
    (string_ids_size, string_ids_off,
     type_ids_size, type_ids_off,
     proto_ids_size, proto_ids_off,
     field_ids_size, field_ids_off,
     method_ids_size, method_ids_off,
     class_defs_size, class_defs_off) = struct.unpack_from("<IIIIIIIIIIII", data, 56)

    # string_ids -> resolved strings (lazily; resolve all, dex strings are small).
    strings: list[str] = []
    for k in range(string_ids_size):
        data_off = struct.unpack_from("<I", data, string_ids_off + 4 * k)[0]
        strings.append(_dex_mutf8(data, data_off))

    # type_ids[i] -> descriptor string
    type_descs: list[str] = []
    for k in range(type_ids_size):
        desc_idx = struct.unpack_from("<I", data, type_ids_off + 4 * k)[0]
        type_descs.append(strings[desc_idx])

    def type_desc(idx: int) -> str:
        return type_descs[idx] if 0 <= idx < len(type_descs) else ""

    # proto_ids[i] -> (return descriptor, [param descriptors]) -> JVM descriptor
    proto_descriptor: list[str] = []
    for k in range(proto_ids_size):
        _shorty_idx, return_type_idx, params_off = struct.unpack_from(
            "<III", data, proto_ids_off + 12 * k)
        params: list[str] = []
        if params_off:
            size = struct.unpack_from("<I", data, params_off)[0]
            for j in range(size):
                t_idx = struct.unpack_from("<H", data, params_off + 4 + 2 * j)[0]
                params.append(type_desc(t_idx))
        proto_descriptor.append("(" + "".join(params) + ")" + type_desc(return_type_idx))

    # field_ids[i] -> (class_idx, type descriptor, name)
    field_type: list[str] = []
    field_name: list[str] = []
    for k in range(field_ids_size):
        _class_idx, type_idx, name_idx = struct.unpack_from(
            "<HHI", data, field_ids_off + 8 * k)
        field_type.append(type_desc(type_idx))
        field_name.append(strings[name_idx])

    # method_ids[i] -> (proto descriptor, name)
    method_descriptor: list[str] = []
    method_name: list[str] = []
    for k in range(method_ids_size):
        _class_idx, proto_idx, name_idx = struct.unpack_from(
            "<HHI", data, method_ids_off + 8 * k)
        method_descriptor.append(proto_descriptor[proto_idx] if proto_idx < len(proto_descriptor) else "")
        method_name.append(strings[name_idx])

    classes: list[ClassUnit] = []
    for k in range(class_defs_size):
        base = class_defs_off + 32 * k
        (class_idx, _access_flags, superclass_idx, interfaces_off,
         _source_file_idx, _annotations_off, class_data_off,
         _static_values_off) = struct.unpack_from("<IIIIIIII", data, base)

        cls = ClassUnit(
            name=_strip_desc(type_desc(class_idx)),
            super_name=_strip_desc(type_desc(superclass_idx)) if superclass_idx != 0xFFFFFFFF else "",
            source_format="dex",
        )

        if interfaces_off:
            size = struct.unpack_from("<I", data, interfaces_off)[0]
            for j in range(size):
                t_idx = struct.unpack_from("<H", data, interfaces_off + 4 + 2 * j)[0]
                cls.interfaces.append(_strip_desc(type_desc(t_idx)))

        if class_data_off:
            _read_class_data(data, class_data_off, cls,
                             field_type, field_name, method_descriptor, method_name)

        classes.append(cls)

    return classes


def _read_class_data(data: bytes, pos: int, cls: ClassUnit,
                     field_type: list[str], field_name: list[str],
                     method_descriptor: list[str], method_name: list[str]) -> None:
    static_fields_size, pos = _uleb128(data, pos)
    instance_fields_size, pos = _uleb128(data, pos)
    direct_methods_size, pos = _uleb128(data, pos)
    virtual_methods_size, pos = _uleb128(data, pos)

    def read_fields(count: int) -> int:
        nonlocal pos
        idx = 0
        for _ in range(count):
            delta, pos = _uleb128(data, pos)
            access, pos = _uleb128(data, pos)
            idx += delta
            if 0 <= idx < len(field_type):
                cls.fields.append(FieldInfo(field_name[idx], field_type[idx], access))
        return pos

    def read_methods(count: int) -> int:
        nonlocal pos
        idx = 0
        for _ in range(count):
            delta, pos = _uleb128(data, pos)
            access, pos = _uleb128(data, pos)
            _code_off, pos = _uleb128(data, pos)
            idx += delta
            if 0 <= idx < len(method_descriptor):
                cls.methods.append(MethodInfo(method_name[idx], method_descriptor[idx], access))
        return pos

    pos = read_fields(static_fields_size)
    pos = read_fields(instance_fields_size)
    pos = read_methods(direct_methods_size)
    pos = read_methods(virtual_methods_size)


def _strip_desc(desc: str) -> str:
    """Turn a class type descriptor ``Lcom/foo/Bar;`` into ``com/foo/Bar``."""
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1]
    return desc


# ===========================================================================
# Artifact loading (.class/.jar/.aar/.apk/.dex/directory)
# ===========================================================================

def load_units(path: Path, max_classes: int = 0) -> ArtifactUnits:
    """Load all classes from a supported artifact.

    Supported inputs:
      * ``.class``          -- single JVM class
      * ``.jar``            -- zip of JVM classes (library publication form)
      * ``.aar``            -- zip containing ``classes.jar`` (+ optional ``libs/*.jar``)
      * ``.apk``            -- zip containing one or more ``classes*.dex``
      * ``.dex``            -- raw Dalvik image
      * directory           -- recursively scans for any of the above
    """
    path = Path(path)
    units = ArtifactUnits()
    _load_into(path, units, max_classes)
    return units


def _load_into(path: Path, units: ArtifactUnits, max_classes: int) -> None:
    if max_classes and len(units.classes) >= max_classes:
        return
    if path.is_dir():
        for child in sorted(path.rglob("*")):
            if child.is_file():
                _load_file(child, units, max_classes)
        return
    _load_file(path, units, max_classes)


def _load_file(path: Path, units: ArtifactUnits, max_classes: int) -> None:
    suffix = path.suffix.lower()
    if suffix == ".class":
        _add_jvm(path.read_bytes(), str(path), units)
    elif suffix == ".dex":
        _add_dex(path.read_bytes(), str(path), units, max_classes)
    elif suffix in (".jar", ".aar", ".apk", ".zip"):
        _load_zip(path, units, max_classes)


def _load_zip(path: Path, units: ArtifactUnits, max_classes: int) -> None:
    with zipfile.ZipFile(path) as zf:
        names = zf.namelist()
        # AAR: bytecode lives inside classes.jar (+ optional libs/*.jar).
        nested_jars = [n for n in names if n == "classes.jar" or
                       (n.startswith("libs/") and n.lower().endswith(".jar"))]
        for n in nested_jars:
            _load_zip_bytes(zf.read(n), f"{path}!{n}", units, max_classes)
        for n in names:
            low = n.lower()
            if low.endswith(".class"):
                _add_jvm(zf.read(n), f"{path}!{n}", units)
            elif low.endswith(".dex") or (low.startswith("classes") and low.endswith(".dex")):
                _add_dex(zf.read(n), f"{path}!{n}", units, max_classes)
            if max_classes and len(units.classes) >= max_classes:
                return


def _load_zip_bytes(blob: bytes, label: str, units: ArtifactUnits, max_classes: int) -> None:
    import io
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        for n in zf.namelist():
            if n.lower().endswith(".class"):
                _add_jvm(zf.read(n), f"{label}!{n}", units)
            if max_classes and len(units.classes) >= max_classes:
                return


def _add_jvm(data: bytes, label: str, units: ArtifactUnits) -> None:
    try:
        cu = parse_classfile(data)
    except (BytecodeError, struct.error, IndexError, ValueError):
        return
    if not cu.name or _is_synthetic_noise(cu.name):
        return
    units.classes.append(cu)
    units.formats.add("jvm")
    units.sources.append(label)


def _add_dex(data: bytes, label: str, units: ArtifactUnits, max_classes: int) -> None:
    try:
        classes = parse_dex(data)
    except (BytecodeError, struct.error, IndexError, ValueError):
        return
    for cu in classes:
        if not cu.name or _is_synthetic_noise(cu.name):
            continue
        units.classes.append(cu)
        if max_classes and len(units.classes) >= max_classes:
            break
    units.formats.add("dex")
    units.sources.append(label)


def _is_synthetic_noise(internal_name: str) -> bool:
    """Drop classes that add nothing to a structural fingerprint."""
    leaf = internal_name.rsplit("/", 1)[-1]
    # R8 sometimes emits empty marker classes; module-info / package-info carry
    # no member structure worth matching.
    return leaf in ("module-info", "package-info")
