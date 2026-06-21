#!/usr/bin/env python3
"""
Dependency-free Mach-O reader for the iOS metadata comparison lab.

Purpose:
  Extract the same load-command / signing metadata that ``otool``, ``lipo``,
  ``vtool`` and ``codesign`` expose, but without Apple's command line tools, so
  the comparison engine works on Linux/WSL where those tools do not exist.

Scope:
  Parses fat headers, per-architecture Mach-O headers, the load commands that
  matter for capability comparison (dylibs, rpaths, encryption info, build
  version), and the embedded code-signature SuperBlob (entitlements plist and
  the CodeDirectory identifier/team id).

  This reads what is already present in a lawful artifact. It does not decrypt
  FairPlay, modify the binary, or bypass any protection. If ``cryptid`` is 1 the
  executable text is still encrypted; this parser only reports that fact.
"""
from __future__ import annotations

import json
import mmap
import plistlib
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# --- Mach-O magics ---------------------------------------------------------
MH_MAGIC = 0xFEEDFACE
MH_CIGAM = 0xCEFAEDFE
MH_MAGIC_64 = 0xFEEDFACF
MH_CIGAM_64 = 0xCFFAEDFE
FAT_MAGIC = 0xCAFEBABE
FAT_CIGAM = 0xBEBAFECA
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

_THIN_MAGICS = {MH_MAGIC, MH_CIGAM, MH_MAGIC_64, MH_CIGAM_64}
_FAT_MAGICS = {FAT_MAGIC, FAT_CIGAM, FAT_MAGIC_64, FAT_CIGAM_64}

# --- load commands ---------------------------------------------------------
LC_REQ_DYLD = 0x80000000
LC_SEGMENT = 0x01
LC_SEGMENT_64 = 0x19
LC_ID_DYLIB = 0x0D
LC_LOAD_DYLIB = 0x0C
LC_LOAD_WEAK_DYLIB = 0x18 | LC_REQ_DYLD
LC_REEXPORT_DYLIB = 0x1F | LC_REQ_DYLD
LC_LOAD_UPWARD_DYLIB = 0x23 | LC_REQ_DYLD
LC_LAZY_LOAD_DYLIB = 0x20
LC_RPATH = 0x1C | LC_REQ_DYLD
LC_UUID = 0x1B
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2C
LC_BUILD_VERSION = 0x32
LC_VERSION_MIN_MACOSX = 0x24
LC_VERSION_MIN_IPHONEOS = 0x25
LC_VERSION_MIN_TVOS = 0x2F
LC_VERSION_MIN_WATCHOS = 0x30
LC_CODE_SIGNATURE = 0x1D
LC_SYMTAB = 0x02

# --- nlist (symbol table) constants ----------------------------------------
N_STAB = 0xE0   # debug-symbol mask: any of these bits -> a STABS debug entry
N_TYPE = 0x0E   # mask selecting the type field of n_type
N_EXT = 0x01    # external-symbol bit
N_SECT = 0x0E   # type: defined in the section given by n_sect
N_UNDF = 0x00   # type: undefined (an import to be resolved at load)
# Cap to keep a pathological/corrupt symtab from exhausting memory.
_MAX_SYMBOLS = 200000

_DYLIB_COMMANDS = {
    LC_LOAD_DYLIB: "LC_LOAD_DYLIB",
    LC_LOAD_WEAK_DYLIB: "LC_LOAD_WEAK_DYLIB",
    LC_REEXPORT_DYLIB: "LC_REEXPORT_DYLIB",
    LC_LOAD_UPWARD_DYLIB: "LC_LOAD_UPWARD_DYLIB",
    LC_LAZY_LOAD_DYLIB: "LC_LAZY_LOAD_DYLIB",
}
_VERSION_MIN_PLATFORM = {
    LC_VERSION_MIN_MACOSX: 1,
    LC_VERSION_MIN_IPHONEOS: 2,
    LC_VERSION_MIN_TVOS: 3,
    LC_VERSION_MIN_WATCHOS: 4,
}

# --- cpu types -------------------------------------------------------------
CPU_ARCH_ABI64 = 0x01000000
CPU_ARCH_ABI64_32 = 0x02000000
CPU_TYPE_X86 = 7
CPU_TYPE_X86_64 = CPU_TYPE_X86 | CPU_ARCH_ABI64
CPU_TYPE_ARM = 12
CPU_TYPE_ARM64 = CPU_TYPE_ARM | CPU_ARCH_ABI64
CPU_TYPE_ARM64_32 = CPU_TYPE_ARM | CPU_ARCH_ABI64_32

_ARM_SUBTYPES = {6: "armv6", 9: "armv7", 11: "armv7s", 12: "armv7k", 14: "armv6m", 15: "armv7m", 16: "armv7em"}
_ARM64_SUBTYPES = {0: "arm64", 1: "arm64v8", 2: "arm64e"}

PLATFORMS = {
    1: "macOS", 2: "iOS", 3: "tvOS", 4: "watchOS", 5: "bridgeOS",
    6: "macCatalyst", 7: "iOSSimulator", 8: "tvOSSimulator",
    9: "watchOSSimulator", 10: "driverKit",
}

# --- code signature --------------------------------------------------------
CSMAGIC_EMBEDDED_SIGNATURE = 0xFADE0CC0
CSMAGIC_CODEDIRECTORY = 0xFADE0C02
CSMAGIC_EMBEDDED_ENTITLEMENTS = 0xFADE7171
CSMAGIC_EMBEDDED_DER_ENTITLEMENTS = 0xFADE7172


def arch_name(cputype: int, cpusubtype: int) -> str:
    sub = cpusubtype & 0x00FFFFFF
    if cputype == CPU_TYPE_ARM64:
        return _ARM64_SUBTYPES.get(sub & 0xFF, "arm64")
    if cputype == CPU_TYPE_ARM64_32:
        return "arm64_32"
    if cputype == CPU_TYPE_ARM:
        return _ARM_SUBTYPES.get(sub, "arm")
    if cputype == CPU_TYPE_X86_64:
        return "x86_64"
    if cputype == CPU_TYPE_X86:
        return "i386"
    return f"cpu({cputype}.{sub})"


def decode_version(v: int) -> str:
    x = (v >> 16) & 0xFFFF
    y = (v >> 8) & 0xFF
    z = v & 0xFF
    return f"{x}.{y}" if z == 0 else f"{x}.{y}.{z}"


@dataclass
class Slice:
    arch: str
    cputype: int
    cpusubtype: int
    filetype: int
    is_64: bool = False
    offset: int = 0
    dylibs: list[str] = field(default_factory=list)
    rpaths: list[str] = field(default_factory=list)
    encryption_info: list[dict[str, Any]] = field(default_factory=list)
    build_versions: list[dict[str, Any]] = field(default_factory=list)
    uuid: str | None = None
    code_signature: dict[str, int] | None = None
    identifier: str | None = None
    team_identifier: str | None = None
    cs_flags: int | None = None
    entitlements: Any = None
    der_entitlements_present: bool = False
    defined_symbols: list[str] = field(default_factory=list)
    undefined_symbols: list[str] = field(default_factory=list)
    nsyms: int = 0
    errors: list[str] = field(default_factory=list)


def _cstr(buf: bytes, start: int, limit: int) -> str:
    end = buf.find(b"\x00", start, limit)
    if end == -1:
        end = limit
    return buf[start:end].decode("utf-8", errors="replace")


def _parse_code_signature(mm: mmap.mmap, base: int, dataoff: int, datasize: int, sl: Slice) -> None:
    """Parse the embedded CS_SuperBlob. All code-signature fields are big-endian."""
    abs_off = base + dataoff
    if datasize <= 8 or abs_off + 8 > len(mm):
        sl.errors.append("code_signature: out of range")
        return
    blob = mm[abs_off:abs_off + datasize]
    magic, length, count = struct.unpack_from(">III", blob, 0)
    if magic != CSMAGIC_EMBEDDED_SIGNATURE:
        sl.errors.append(f"code_signature: unexpected superblob magic 0x{magic:08x}")
        return
    for i in range(count):
        try:
            _btype, boff = struct.unpack_from(">II", blob, 12 + i * 8)
        except struct.error:
            break
        if boff + 8 > len(blob):
            continue
        bmagic, blen = struct.unpack_from(">II", blob, boff)
        if bmagic == CSMAGIC_EMBEDDED_ENTITLEMENTS:
            payload = blob[boff + 8: boff + blen]
            try:
                sl.entitlements = plistlib.loads(payload)
            except Exception as e:  # noqa: BLE001 - record, keep going
                sl.entitlements = {"__parse_error__": str(e)}
        elif bmagic == CSMAGIC_EMBEDDED_DER_ENTITLEMENTS:
            sl.der_entitlements_present = True
        elif bmagic == CSMAGIC_CODEDIRECTORY:
            _parse_code_directory(blob, boff, blen, sl)


def _parse_code_directory(blob: bytes, off: int, length: int, sl: Slice) -> None:
    try:
        version, flags = struct.unpack_from(">II", blob, off + 8)
        ident_offset = struct.unpack_from(">I", blob, off + 20)[0]
    except struct.error:
        return
    # Prefer the first CodeDirectory's flags; later (alternate) ones repeat them.
    if sl.cs_flags is None:
        sl.cs_flags = flags
    if ident_offset and not sl.identifier:
        sl.identifier = _cstr(blob, off + ident_offset, off + length)
    if version >= 0x20200 and not sl.team_identifier:
        team_offset = struct.unpack_from(">I", blob, off + 48)[0]
        if team_offset:
            sl.team_identifier = _cstr(blob, off + team_offset, off + length)


def _mm_cstr(mm: mmap.mmap, start: int, limit: int) -> str:
    """Read a NUL-terminated string from the mmap, bounded by ``limit``."""
    if start < 0 or start >= limit:
        return ""
    end = mm.find(b"\x00", start, limit)
    if end == -1:
        end = limit
    return mm[start:end].decode("utf-8", errors="replace")


def _parse_symtab(mm: mmap.mmap, base: int, endian: str, sl: Slice,
                  symoff: int, nsyms: int, stroff: int, strsize: int) -> None:
    """Parse an ``LC_SYMTAB`` symbol/string table into defined/undefined sets.

    The symbol table (``nlist``/``nlist_64``) and string table live in
    ``__LINKEDIT`` at file offsets relative to the slice base. This reads only
    what is already present in a lawful artifact; it never modifies anything and
    works even when ``__TEXT`` is FairPlay-encrypted (``cryptid 1``), since the
    string and symbol tables are not part of the encrypted region.
    """
    sl.nsyms = nsyms
    if nsyms <= 0:
        return
    entry_size = 16 if sl.is_64 else 12
    sym_base = base + symoff
    str_base = base + stroff
    mm_len = len(mm)
    if sym_base < 0 or str_base < 0:
        sl.errors.append("symtab: negative offset")
        return
    if sym_base + entry_size > mm_len:
        sl.errors.append("symtab: symbol table out of range")
        return
    # The string table is bounded by stroff..stroff+strsize, but never past EOF.
    str_limit = min(str_base + max(strsize, 0), mm_len)
    count = min(nsyms, _MAX_SYMBOLS)
    defined: set[str] = set()
    undefined: set[str] = set()
    nlist_fmt = endian + ("IBBHQ" if sl.is_64 else "IBBHI")
    for i in range(count):
        off = sym_base + i * entry_size
        if off + entry_size > mm_len:
            break
        try:
            n_strx, n_type, _n_sect, _n_desc, _n_value = struct.unpack_from(nlist_fmt, mm, off)
        except struct.error:
            break
        if n_type & N_STAB:
            continue  # debug (STABS) entry -- not an export/import
        if not (n_type & N_EXT):
            continue  # only external symbols are obfuscation-stable anchors
        name = _mm_cstr(mm, str_base + n_strx, str_limit)
        if not name:
            continue
        typ = n_type & N_TYPE
        if typ == N_SECT:
            defined.add(name)
        elif typ == N_UNDF:
            undefined.add(name)
    sl.defined_symbols = sorted(defined)
    sl.undefined_symbols = sorted(undefined)


def _parse_slice(mm: mmap.mmap, base: int) -> Slice:
    magic = struct.unpack_from(">I", mm, base)[0]
    if magic in (MH_MAGIC_64, MH_MAGIC):
        endian = ">"
    else:
        endian = "<"
    raw_magic = struct.unpack_from(endian + "I", mm, base)[0]
    is_64 = raw_magic in (MH_MAGIC_64, MH_CIGAM_64)

    cputype, cpusubtype, filetype, ncmds, sizeofcmds, _flags = struct.unpack_from(endian + "IIIIII", mm, base + 4)
    header_size = 32 if is_64 else 28

    sl = Slice(
        arch=arch_name(cputype, cpusubtype),
        cputype=cputype,
        cpusubtype=cpusubtype,
        filetype=filetype,
        offset=base,
    )
    sl.is_64 = is_64

    pos = base + header_size
    for _ in range(ncmds):
        if pos + 8 > len(mm):
            sl.errors.append("load commands truncated")
            break
        cmd, cmdsize = struct.unpack_from(endian + "II", mm, pos)
        if cmdsize < 8 or pos + cmdsize > len(mm):
            sl.errors.append(f"bad cmdsize {cmdsize} for cmd 0x{cmd:08x}")
            break
        body = mm[pos:pos + cmdsize]
        try:
            _parse_load_command(cmd, body, endian, mm, base, sl)
        except Exception as e:  # noqa: BLE001 - never let one command kill the parse
            sl.errors.append(f"cmd 0x{cmd:08x}: {e}")
        pos += cmdsize
    return sl


def _parse_load_command(cmd: int, body: bytes, endian: str, mm: mmap.mmap, base: int, sl: Slice) -> None:
    if cmd in _DYLIB_COMMANDS:
        name_off = struct.unpack_from(endian + "I", body, 8)[0]
        if 0 < name_off < len(body):
            sl.dylibs.append(_cstr(body, name_off, len(body)))
        return
    if cmd == LC_RPATH:
        path_off = struct.unpack_from(endian + "I", body, 8)[0]
        if 0 < path_off < len(body):
            sl.rpaths.append(_cstr(body, path_off, len(body)))
        return
    if cmd in (LC_ENCRYPTION_INFO, LC_ENCRYPTION_INFO_64):
        cryptoff, cryptsize, cryptid = struct.unpack_from(endian + "III", body, 8)
        entry = {
            "command": "LC_ENCRYPTION_INFO_64" if cmd == LC_ENCRYPTION_INFO_64 else "LC_ENCRYPTION_INFO",
            "cryptoff": cryptoff,
            "cryptsize": cryptsize,
            "cryptid": cryptid,
        }
        if cmd == LC_ENCRYPTION_INFO_64:
            entry["pad"] = struct.unpack_from(endian + "I", body, 20)[0]
        sl.encryption_info.append(entry)
        return
    if cmd == LC_BUILD_VERSION:
        platform, minos, sdk, ntools = struct.unpack_from(endian + "IIII", body, 8)
        sl.build_versions.append({
            "source": "LC_BUILD_VERSION",
            "platform": PLATFORMS.get(platform, str(platform)),
            "platform_id": platform,
            "minos": decode_version(minos),
            "sdk": decode_version(sdk),
            "ntools": ntools,
        })
        return
    if cmd in _VERSION_MIN_PLATFORM:
        version, sdk = struct.unpack_from(endian + "II", body, 8)
        platform = _VERSION_MIN_PLATFORM[cmd]
        sl.build_versions.append({
            "source": "LC_VERSION_MIN",
            "platform": PLATFORMS.get(platform, str(platform)),
            "platform_id": platform,
            "minos": decode_version(version),
            "sdk": decode_version(sdk),
        })
        return
    if cmd == LC_UUID:
        raw = body[8:24]
        sl.uuid = "-".join([
            raw[0:4].hex(), raw[4:6].hex(), raw[6:8].hex(), raw[8:10].hex(), raw[10:16].hex(),
        ]).upper()
        return
    if cmd == LC_CODE_SIGNATURE:
        dataoff, datasize = struct.unpack_from(endian + "II", body, 8)
        sl.code_signature = {"dataoff": dataoff, "datasize": datasize}
        _parse_code_signature(mm, base, dataoff, datasize, sl)
        return
    if cmd == LC_SYMTAB:
        symoff, nsyms, stroff, strsize = struct.unpack_from(endian + "IIII", body, 8)
        _parse_symtab(mm, base, endian, sl, symoff, nsyms, stroff, strsize)
        return


def parse_path(path: str | Path) -> dict[str, Any]:
    """Parse a Mach-O (thin or fat) file into a structured dict.

    Returns ``{"is_macho": False}`` for non-Mach-O input so callers can skip
    cleanly.
    """
    p = Path(path)
    size = p.stat().st_size if p.exists() else 0
    if size < 4:
        return {"is_macho": False}
    with p.open("rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            head = struct.unpack_from(">I", mm, 0)[0]
            if head in _FAT_MAGICS:
                slices = _parse_fat(mm, head)
            elif head in _THIN_MAGICS:
                slices = [_parse_slice(mm, 0)]
            else:
                return {"is_macho": False}
        finally:
            mm.close()
    return {
        "is_macho": True,
        "fat": head in _FAT_MAGICS,
        "size": size,
        "architectures": [s.arch for s in slices],
        "slices": [_slice_to_dict(s) for s in slices],
    }


def _parse_fat(mm: mmap.mmap, head: int) -> list[Slice]:
    # fat_header and fat_arch are always big-endian.
    is_64 = head in (FAT_MAGIC_64, FAT_CIGAM_64)
    nfat = struct.unpack_from(">I", mm, 4)[0]
    slices: list[Slice] = []
    pos = 8
    for _ in range(nfat):
        if is_64:
            _ct, _cs, offset, _sz, _al = struct.unpack_from(">iiQQI", mm, pos)
            pos += 32
        else:
            _ct, _cs, offset, _sz, _al = struct.unpack_from(">iiIII", mm, pos)
            pos += 20
        if offset + 4 <= len(mm) and struct.unpack_from(">I", mm, offset)[0] in _THIN_MAGICS:
            slices.append(_parse_slice(mm, offset))
    return slices


def _slice_to_dict(s: Slice) -> dict[str, Any]:
    return {
        "arch": s.arch,
        "cputype": s.cputype,
        "cpusubtype": s.cpusubtype,
        "filetype": s.filetype,
        "is_64": s.is_64,
        "file_offset": s.offset,
        "uuid": s.uuid,
        "dylibs": s.dylibs,
        "rpaths": s.rpaths,
        "encryption_info": s.encryption_info,
        "build_versions": s.build_versions,
        "code_signature": s.code_signature,
        "identifier": s.identifier,
        "team_identifier": s.team_identifier,
        "cs_flags": s.cs_flags,
        "entitlements": s.entitlements,
        "der_entitlements_present": s.der_entitlements_present,
        "defined_symbols": s.defined_symbols,
        "undefined_symbols": s.undefined_symbols,
        "nsyms": s.nsyms,
        "errors": s.errors,
    }


def primary_slice(parsed: dict[str, Any]) -> dict[str, Any]:
    """Pick the most informative slice (prefer arm64/arm64e, else the first)."""
    slices = parsed.get("slices") or []
    if not slices:
        return {}
    for pref in ("arm64e", "arm64"):
        for s in slices:
            if s.get("arch") == pref:
                return s
    return slices[0]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: macho.py <binary> [...]", file=sys.stderr)
        return 2
    for path in argv[1:]:
        print(json.dumps({"path": path, **parse_path(path)}, indent=2, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
