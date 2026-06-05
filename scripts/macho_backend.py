#!/usr/bin/env python3
"""
Tool backend abstraction for the iOS metadata comparison engine.

Two interchangeable backends provide the same metadata-extraction surface:

* ``NativeBackend``   - shells out to Apple's ``otool``/``lipo``/``vtool``/
                        ``codesign``/``security`` (macOS with Xcode tools).
* ``PortableBackend`` - parses Mach-O and the embedded code signature directly
                        with the dependency-free :mod:`macho` reader, so the
                        engine produces real signing/binary metadata on Linux/WSL
                        where Apple's tools do not exist.

Each method returns the SAME shape the comparison engine already consumes, so
``ios_multiversion_meta_compare.py`` keeps its parsers, manifest layout, diff
categories, and findings unchanged.

Selection order (``select_backend``):
  1. ``IOS_META_BACKEND=native|portable`` env override.
  2. Native if both ``codesign`` and ``otool`` are on PATH.
  3. Portable otherwise.
"""
from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
from pathlib import Path
from typing import Any

import macho

BUNDLE_SUFFIXES = {".app", ".appex", ".framework", ".bundle", ".watchkitapp", ".xpc"}


# --------------------------------------------------------------------------
# shared helpers
# --------------------------------------------------------------------------
def _run(cmd: list[str], timeout: int = 90) -> dict[str, Any]:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        return {"cmd": cmd, "returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
    except FileNotFoundError as e:
        return {"cmd": cmd, "returncode": 127, "stdout": "", "stderr": str(e)}
    except subprocess.TimeoutExpired as e:
        return {"cmd": cmd, "returncode": 124, "stdout": e.stdout or "", "stderr": e.stderr or str(e)}


def _run_first(commands: list[list[str]], timeout: int = 90) -> dict[str, Any]:
    last: dict[str, Any] | None = None
    for cmd in commands:
        result = _run(cmd, timeout=timeout)
        last = result
        if result.get("returncode") != 127:
            return result
    assert last is not None
    return last


def _plist_from_text(text: str) -> bytes | None:
    start = text.find("<?xml")
    if start == -1:
        start = text.find("<plist")
    end = text.rfind("</plist>")
    if start != -1 and end != -1:
        return text[start:end + len("</plist>")].encode("utf-8", errors="replace")
    return None


def _parse_plist_from_command(result: dict[str, Any]) -> Any:
    text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
    blob = _plist_from_text(text)
    if not blob:
        return {
            "__parse_error__": "no plist found in command output",
            "__returncode__": result.get("returncode"),
            "__stderr__": (result.get("stderr") or "")[:4000],
        }
    try:
        return plistlib.loads(blob)
    except Exception as e:  # noqa: BLE001
        return {"__parse_error__": str(e), "__returncode__": result.get("returncode")}


def _looks_macho(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            head = f.read(4)
    except OSError:
        return False
    return head in {
        b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
        b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    }


def _bundle_executable(path: Path) -> Path | None:
    """Resolve a bundle directory to its main Mach-O, the way ``codesign`` does."""
    if path.is_file():
        return path
    if not path.is_dir():
        return None
    info = path / "Info.plist"
    if info.is_file():
        try:
            with info.open("rb") as f:
                exe = plistlib.load(f).get("CFBundleExecutable")
            if exe and (path / exe).is_file():
                return path / exe
        except Exception:  # noqa: BLE001
            pass
    cand = path / path.stem
    if cand.is_file() and _looks_macho(cand):
        return cand
    for child in sorted(path.iterdir()):
        if child.is_file() and _looks_macho(child):
            return child
    return None


# --------------------------------------------------------------------------
# native (macOS) backend
# --------------------------------------------------------------------------
class NativeBackend:
    name = "native"

    def otool_libraries(self, path: Path) -> dict[str, Any]:
        return _run_first([["xcrun", "otool", "-L", str(path)], ["otool", "-L", str(path)]], timeout=120)

    def otool_load_commands(self, path: Path) -> dict[str, Any]:
        return _run_first([["xcrun", "otool", "-l", str(path)], ["otool", "-l", str(path)]], timeout=120)

    def vtool_build(self, path: Path) -> dict[str, Any]:
        return _run_first([["xcrun", "vtool", "-show-build", str(path)], ["vtool", "-show-build", str(path)]], timeout=60)

    def lipo_archs(self, path: Path) -> dict[str, Any]:
        return _run(["lipo", "-archs", str(path)], timeout=30)

    def file_type(self, path: Path) -> str:
        result = _run(["file", "-b", str(path)], timeout=20)
        return ((result.get("stdout") or "") + (result.get("stderr") or "")).strip()

    def codesign_display(self, path: Path) -> dict[str, Any]:
        result = _run(["codesign", "-dvvv", str(path)], timeout=90)
        text = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
        parsed: dict[str, str] = {}
        for line in text.splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                parsed[key.strip()] = value.strip()
        return {"parsed": parsed, "returncode": result.get("returncode"), "raw": text[:12000]}

    def codesign_entitlements(self, path: Path) -> Any:
        result = _run(["codesign", "-d", "--entitlements", ":-", str(path)], timeout=90)
        return _parse_plist_from_command(result)

    def mobileprovision(self, path: Path) -> Any:
        result = _run(["security", "cms", "-D", "-i", str(path)], timeout=90)
        return _parse_plist_from_command(result)


# --------------------------------------------------------------------------
# portable (pure-Python) backend
# --------------------------------------------------------------------------
class PortableBackend:
    name = "portable"

    def __init__(self) -> None:
        self._cache: dict[tuple[str, int, int], dict[str, Any]] = {}

    # -- parsing/caching --
    def _parse(self, path: Path) -> dict[str, Any]:
        try:
            st = path.stat()
            key = (str(path), st.st_mtime_ns, st.st_size)
        except OSError as e:
            return {"is_macho": False, "errors": [str(e)]}
        cached = self._cache.get(key)
        if cached is None:
            try:
                cached = macho.parse_path(path)
            except Exception as e:  # noqa: BLE001 - degrade gracefully
                cached = {"is_macho": False, "errors": [f"parse failed: {e}"]}
            self._cache[key] = cached
        return cached

    def _primary(self, path: Path) -> dict[str, Any]:
        return macho.primary_slice(self._parse(path))

    # -- otool/lipo/vtool equivalents (return run()-shaped dicts) --
    def otool_libraries(self, path: Path) -> dict[str, Any]:
        sl = self._primary(path)
        lines = [f"{path}:"]
        for dylib in sl.get("dylibs", []) or []:
            lines.append(f"\t{dylib} (compatibility version 0.0.0, current version 0.0.0)")
        return {"stdout": "\n".join(lines) + "\n", "stderr": "", "returncode": 0}

    def otool_load_commands(self, path: Path) -> dict[str, Any]:
        sl = self._primary(path)
        blocks: list[str] = [f"{path}:"]
        n = 0
        for rp in sl.get("rpaths", []) or []:
            blocks.append(f"Load command {n}\n          cmd LC_RPATH\n      cmdsize 0\n         path {rp} (offset 12)")
            n += 1
        for enc in sl.get("encryption_info", []) or []:
            cmd = enc.get("command", "LC_ENCRYPTION_INFO")
            blocks.append(
                f"Load command {n}\n          cmd {cmd}\n      cmdsize 0\n"
                f"     cryptoff {enc.get('cryptoff', 0)}\n    cryptsize {enc.get('cryptsize', 0)}\n"
                f"      cryptid {enc.get('cryptid', 0)}"
            )
            n += 1
        for bv in sl.get("build_versions", []) or []:
            if bv.get("source") == "LC_BUILD_VERSION":
                blocks.append(
                    f"Load command {n}\n          cmd LC_BUILD_VERSION\n      cmdsize 0\n"
                    f"     platform {bv.get('platform')}\n        minos {bv.get('minos')}\n"
                    f"          sdk {bv.get('sdk')}\n       ntools {bv.get('ntools', 0)}"
                )
            else:
                blocks.append(
                    f"Load command {n}\n          cmd LC_VERSION_MIN_IPHONEOS\n      cmdsize 0\n"
                    f"      version {bv.get('minos')}\n          sdk {bv.get('sdk')}"
                )
            n += 1
        return {"stdout": "\n".join(blocks) + "\n", "stderr": "", "returncode": 0}

    def vtool_build(self, path: Path) -> dict[str, Any]:
        sl = self._primary(path)
        lines = [f"{path}:"]
        for bv in sl.get("build_versions", []) or []:
            lines.append(
                f"Version info:\n    platform {bv.get('platform')}\n    minos {bv.get('minos')}\n    sdk {bv.get('sdk')}"
            )
        if not sl.get("build_versions"):
            lines.append("no build version load command")
        return {"stdout": "\n".join(lines) + "\n", "stderr": "", "returncode": 0}

    def lipo_archs(self, path: Path) -> dict[str, Any]:
        archs = self._parse(path).get("architectures", []) or []
        return {"stdout": " ".join(archs) + ("\n" if archs else ""), "stderr": "", "returncode": 0}

    def file_type(self, path: Path) -> str:
        # `file` exists on Linux; prefer it, then fall back to a synthesized line.
        if shutil.which("file"):
            result = _run(["file", "-b", str(path)], timeout=20)
            out = ((result.get("stdout") or "") + (result.get("stderr") or "")).strip()
            if out and result.get("returncode") == 0:
                return out
        parsed = self._parse(path)
        if not parsed.get("is_macho"):
            return "data"
        sl = self._primary(path)
        bits = "64-bit" if sl.get("is_64") else "32-bit"
        kind = {2: "executable", 6: "dynamically linked shared library", 8: "bundle"}.get(sl.get("filetype"), "object")
        fat = "Mach-O universal binary" if parsed.get("fat") else f"Mach-O {bits} {sl.get('arch')}"
        return f"{fat} {kind}"

    # -- signing equivalents --
    def codesign_display(self, path: Path) -> dict[str, Any]:
        exe = _bundle_executable(Path(path))
        if exe is None:
            return {"parsed": {}, "returncode": 1, "raw": "no executable found in bundle"}
        sl = self._primary(exe)
        parsed: dict[str, str] = {}
        if sl.get("identifier"):
            parsed["Identifier"] = sl["identifier"]
        parsed["TeamIdentifier"] = sl.get("team_identifier") or "not set"
        if sl.get("cs_flags") is not None:
            parsed["CodeDirectoryFlags"] = hex(sl["cs_flags"])
        if sl.get("arch"):
            parsed["Executable"] = f"{exe} ({sl['arch']})"
        raw = "\n".join(f"{k}={v}" for k, v in parsed.items())
        return {"parsed": parsed, "returncode": 0, "raw": raw}

    def codesign_entitlements(self, path: Path) -> Any:
        exe = _bundle_executable(Path(path))
        if exe is None:
            return {}
        ent = self._primary(exe).get("entitlements")
        return ent if isinstance(ent, dict) else {}

    def mobileprovision(self, path: Path) -> Any:
        p = Path(path)
        try:
            data = p.read_bytes()
        except OSError as e:
            return {"__parse_error__": str(e)}
        # The plist payload sits in cleartext inside the PKCS#7 SignedData.
        blob = _plist_from_text(data.decode("latin-1"))
        if not blob:
            return {"__parse_error__": "no plist found in mobileprovision"}
        try:
            return plistlib.loads(blob)
        except Exception as e:  # noqa: BLE001
            return {"__parse_error__": str(e)}


# --------------------------------------------------------------------------
# selection
# --------------------------------------------------------------------------
def _native_tools_present() -> bool:
    return bool(shutil.which("codesign") and shutil.which("otool"))


def select_backend(force: str | None = None):
    choice = (force or os.environ.get("IOS_META_BACKEND") or "auto").strip().lower()
    if choice == "native":
        return NativeBackend()
    if choice == "portable":
        return PortableBackend()
    return NativeBackend() if _native_tools_present() else PortableBackend()


if __name__ == "__main__":  # tiny manual probe
    import json
    import sys

    backend = select_backend()
    print(f"backend: {backend.name}", file=sys.stderr)
    for arg in sys.argv[1:]:
        ap = Path(arg)
        print(json.dumps({
            "path": arg,
            "file_type": backend.file_type(ap),
            "lipo": backend.lipo_archs(ap).get("stdout", "").strip(),
            "entitlements": backend.codesign_entitlements(ap),
            "display": backend.codesign_display(ap).get("parsed"),
        }, indent=2, default=str))
