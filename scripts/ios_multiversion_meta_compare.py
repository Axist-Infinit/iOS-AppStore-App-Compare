#!/usr/bin/env python3
"""
Multi-artifact iOS IPA/.app metadata comparison tool.

Purpose:
  Compare a production App Store IPA/.app reference against one or more local
  Release/device builds, nearby source-tag builds, or additional App Store slices.

Scope:
  Metadata, package structure, signing/entitlements, privacy manifests, binary
  load metadata, linked libraries, extensions, frameworks, and resource inventory.
  This tool does not decrypt FairPlay, bypass DRM, patch binaries, or dump memory.

Platform:
  Best run on macOS with Xcode command line tools installed. The script is written
  with graceful degradation for non-macOS environments, but codesign/otool/security
  output will be incomplete off macOS.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import csv
import datetime as dt
import difflib
import hashlib
import html
import json
import os
import plistlib
import re
import shutil
import sys
import tempfile
import threading
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

# Make sibling modules importable whether run as a script or imported elsewhere.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho_backend  # noqa: E402

# Active metadata backend (native macOS tools, or the portable pure-Python
# reader). Reassigned in main() once CLI args are known.
BACKEND = macho_backend.select_backend()

SCHEMA_VERSION = "ios-multiversion-metadata-compare-v1"

INFO_KEYS = [
    "CFBundleIdentifier",
    "CFBundleExecutable",
    "CFBundleName",
    "CFBundleDisplayName",
    "CFBundlePackageType",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "MinimumOSVersion",
    "DTPlatformName",
    "DTPlatformVersion",
    "DTSDKName",
    "DTSDKBuild",
    "DTXcode",
    "DTXcodeBuild",
    "UIDeviceFamily",
    "UIRequiredDeviceCapabilities",
    "UISupportedInterfaceOrientations",
    "UISupportedInterfaceOrientations~ipad",
    "UIBackgroundModes",
    "UIApplicationSceneManifest",
    "UIApplicationSupportsIndirectInputEvents",
    "CFBundleURLTypes",
    "LSApplicationQueriesSchemes",
    "NSUserActivityTypes",
    "NSAppTransportSecurity",
    "NSUserTrackingUsageDescription",
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSContactsUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSPhotoLibraryAddUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSLocationAlwaysAndWhenInUseUsageDescription",
    "NSFaceIDUsageDescription",
    "NFCReaderUsageDescription",
    "ITSAppUsesNonExemptEncryption",
]

PROFILE_KEYS = [
    "AppIDName",
    "ApplicationIdentifierPrefix",
    "CreationDate",
    "ExpirationDate",
    "Name",
    "Platform",
    "TeamIdentifier",
    "TeamName",
    "TimeToLive",
    "UUID",
    "Version",
    "ProvisionsAllDevices",
    "ProvisionedDevices",
    "Entitlements",
]

HIGH_VALUE_INFO_KEYS = [
    "CFBundleIdentifier",
    "CFBundleShortVersionString",
    "CFBundleVersion",
    "MinimumOSVersion",
    "DTSDKName",
    "DTXcodeBuild",
    "UIDeviceFamily",
    "UIRequiredDeviceCapabilities",
    "UIBackgroundModes",
    "CFBundleURLTypes",
    "LSApplicationQueriesSchemes",
    "NSUserActivityTypes",
    "NSAppTransportSecurity",
    "ITSAppUsesNonExemptEncryption",
]

HIGH_VALUE_ENTITLEMENT_KEYS = [
    "application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
    "com.apple.security.application-groups",
    "aps-environment",
    "com.apple.developer.associated-domains",
    "com.apple.developer.networking.networkextension",
    "com.apple.developer.usernotifications.communication",
    "com.apple.developer.siri",
    "com.apple.developer.icloud-container-identifiers",
    "com.apple.developer.default-data-protection",
    "get-task-allow",
]

EXPECTED_NOISE_KEYS = {
    "application-identifier",
    "com.apple.developer.team-identifier",
    "keychain-access-groups",
    "com.apple.security.application-groups",
    "com.apple.developer.icloud-container-identifiers",
}

INTERESTING_SUFFIXES = {
    ".plist", ".xcprivacy", ".entitlements", ".appex", ".framework", ".dylib",
    ".bundle", ".car", ".nib", ".storyboardc", ".mom", ".momd", ".strings",
    ".stringsdict", ".json", ".db", ".sqlite", ".sqlite3", ".cer", ".der",
    ".pem", ".mobileconfig", ".wasm", ".js", ".appex", ".intentdefinition",
}

BUNDLE_SUFFIXES = [".app", ".appex", ".framework", ".bundle", ".watchkitapp", ".xpc"]

MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",  # MH_MAGIC big-endian 32
    b"\xce\xfa\xed\xfe",  # MH_CIGAM little-endian 32
    b"\xfe\xed\xfa\xcf",  # MH_MAGIC_64 big-endian 64
    b"\xcf\xfa\xed\xfe",  # MH_CIGAM_64 little-endian 64
    b"\xca\xfe\xba\xbe",  # FAT_MAGIC
    b"\xbe\xba\xfe\xca",  # FAT_CIGAM
    b"\xca\xfe\xba\xbf",  # FAT_MAGIC_64
    b"\xbf\xba\xfe\xca",  # FAT_CIGAM_64
}

@dataclass(frozen=True)
class ArtifactSpec:
    artifact_id: str
    path: Path
    role: str = "candidate"
    label: str | None = None
    expected_version: str | None = None
    expected_build: str | None = None
    expected_git_ref: str | None = None
    notes: str | None = None

@dataclass
class Finding:
    severity: str
    category: str
    reference: str
    compared: str
    summary: str
    detail: str


def normalize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {str(k): normalize(v) for k, v in sorted(obj.items(), key=lambda kv: str(kv[0]))}
    if isinstance(obj, (list, tuple)):
        return [normalize(v) for v in obj]
    if isinstance(obj, (dt.datetime, dt.date)):
        return obj.isoformat()
    if isinstance(obj, bytes):
        return obj.hex()
    return obj


def dump_json(obj: Any) -> str:
    return json.dumps(normalize(obj), indent=2, sort_keys=True, ensure_ascii=False)


def sanitize_id(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", value).strip("_") or "artifact"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_plist_file(path: Path) -> Any:
    try:
        with path.open("rb") as f:
            return plistlib.load(f)
    except Exception as e:
        return {"__parse_error__": str(e), "__path__": str(path)}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def maybe_rel(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


# Serializes IPA extraction so parallel workers can't race on the same
# content-addressed cache directory.
_EXTRACT_LOCK = threading.Lock()


def _safe_extractall(zf: zipfile.ZipFile, dest: Path) -> None:
    """Extract a zip, rejecting members that escape ``dest`` (zip-slip / absolute
    paths / symlink traversal)."""
    dest = dest.resolve()
    base = str(dest) + os.sep
    for member in zf.infolist():
        target = (dest / member.filename).resolve()
        if target != dest and not str(target).startswith(base):
            raise ValueError(f"Unsafe path in archive (zip slip): {member.filename!r}")
    zf.extractall(dest)


def resolve_artifact(input_path: Path, work_dir: Path, artifact_id: str) -> Path:
    input_path = input_path.expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Artifact path does not exist: {input_path}")

    if input_path.is_dir() and input_path.suffix == ".app":
        return input_path

    if input_path.is_dir() and input_path.suffix == ".xcarchive":
        candidates = sorted(input_path.glob("Products/Applications/*.app"))
        if not candidates:
            raise ValueError(f"No .app found in xcarchive: {input_path}")
        return candidates[0]

    if input_path.is_file() and input_path.suffix.lower() == ".ipa":
        # Content-addressed extraction: identical IPAs extract once, and a
        # persistent --ipa-cache reuses the result across runs.
        digest = sha256_file(input_path)
        extract_dir = work_dir / digest
        marker = extract_dir / ".extracted_ok"
        if not marker.exists():
            with _EXTRACT_LOCK:
                if not marker.exists():  # re-check inside the lock
                    if extract_dir.exists():
                        shutil.rmtree(extract_dir)
                    extract_dir.mkdir(parents=True)
                    with zipfile.ZipFile(input_path) as z:
                        _safe_extractall(z, extract_dir)
                    marker.write_text(digest, encoding="utf-8")
        candidates = sorted(extract_dir.glob("Payload/*.app"))
        if not candidates:
            raise ValueError(f"No Payload/*.app found in IPA: {input_path}")
        return candidates[0]

    if input_path.is_dir():
        candidates = sorted(input_path.glob("Payload/*.app")) + sorted(input_path.glob("Products/Applications/*.app"))
        if candidates:
            return candidates[0]

    raise ValueError(f"Unsupported artifact or no .app found: {input_path}")


def is_macho(path: Path) -> bool:
    try:
        with path.open("rb") as f:
            return f.read(4) in MACHO_MAGICS
    except Exception:
        return False


# The following metadata extractors delegate to the active backend so the
# manifest/diff/finding logic below is identical on macOS (native Apple tools)
# and on Linux/WSL (portable pure-Python Mach-O + code-signature reader).
def file_type(path: Path) -> str:
    return BACKEND.file_type(path)


def codesign_display(path: Path) -> dict[str, Any]:
    return BACKEND.codesign_display(path)


def codesign_entitlements(path: Path) -> Any:
    return BACKEND.codesign_entitlements(path)


def provisioning_profile(path: Path) -> Any:
    if not path.exists():
        return {"__missing__": True}
    parsed = BACKEND.mobileprovision(path)
    if isinstance(parsed, dict) and "__parse_error__" not in parsed:
        return {k: parsed.get(k) for k in PROFILE_KEYS if k in parsed}
    return parsed


def otool_libraries(path: Path) -> dict[str, Any]:
    return BACKEND.otool_libraries(path)


def otool_load_commands(path: Path) -> dict[str, Any]:
    return BACKEND.otool_load_commands(path)


def vtool_build(path: Path) -> dict[str, Any]:
    return BACKEND.vtool_build(path)


def lipo_archs(path: Path) -> dict[str, Any]:
    return BACKEND.lipo_archs(path)


def parse_otool_libraries(text: str) -> list[str]:
    libs: list[str] = []
    for line in text.splitlines()[1:]:
        s = line.strip()
        if not s:
            continue
        libs.append(s.split(" (", 1)[0])
    return sorted(set(libs))


def parse_encryption_info(otool_l: str) -> list[dict[str, Any]]:
    lines = otool_l.splitlines()
    out: list[dict[str, Any]] = []
    for i, line in enumerate(lines):
        if "LC_ENCRYPTION_INFO" in line:
            block = lines[i:i + 10]
            item: dict[str, Any] = {"command": line.strip(), "raw": "\n".join(block)}
            for b in block:
                m = re.match(r"\s*(cryptoff|cryptsize|cryptid|pad)\s+(.+?)\s*$", b)
                if m:
                    item[m.group(1)] = m.group(2)
            out.append(item)
    return out


def parse_rpaths(otool_l: str) -> list[str]:
    lines = otool_l.splitlines()
    rpaths: list[str] = []
    for i, line in enumerate(lines):
        if "cmd LC_RPATH" in line:
            for b in lines[i:i + 8]:
                m = re.search(r"\spath\s+(.+?)\s+\(offset", b)
                if m:
                    rpaths.append(m.group(1))
    return sorted(set(rpaths))


def parse_build_version(otool_l: str) -> list[dict[str, str]]:
    # Lightweight parser for LC_BUILD_VERSION blocks.
    lines = otool_l.splitlines()
    blocks: list[dict[str, str]] = []
    for i, line in enumerate(lines):
        if "cmd LC_BUILD_VERSION" in line:
            block: dict[str, str] = {"raw": "\n".join(lines[i:i + 12])}
            for b in lines[i:i + 12]:
                m = re.match(r"\s*(platform|minos|sdk|ntools)\s+(.+?)\s*$", b)
                if m:
                    block[m.group(1)] = m.group(2)
            blocks.append(block)
    return blocks


def binary_manifest(path: Path, app_root: Path, hash_mode: str) -> dict[str, Any]:
    otool_L = otool_libraries(path)
    otool_l = otool_load_commands(path)
    lipo = lipo_archs(path)
    vtool = vtool_build(path)
    otool_l_text = otool_l.get("stdout", "") or ""
    record: dict[str, Any] = {
        "path": maybe_rel(path, app_root),
        "size": path.stat().st_size if path.exists() else None,
        "file_type": file_type(path),
        "architectures": (lipo.get("stdout") or "").strip(),
        "linked_libraries": parse_otool_libraries(otool_L.get("stdout") or ""),
        "rpaths": parse_rpaths(otool_l_text),
        "encryption_info": parse_encryption_info(otool_l_text),
        "build_version": parse_build_version(otool_l_text),
        "vtool_show_build": (vtool.get("stdout") or "")[:12000],
        "tool_returncodes": {
            "otool_L": otool_L.get("returncode"),
            "otool_l": otool_l.get("returncode"),
            "lipo": lipo.get("returncode"),
            "vtool": vtool.get("returncode"),
        },
    }
    if hash_mode in ("full", "notable"):
        record["sha256"] = sha256_file(path)
    return record


def bundle_dirs(app_root: Path) -> list[Path]:
    dirs = [app_root]
    for p in app_root.rglob("*"):
        if p.is_dir() and p.suffix in BUNDLE_SUFFIXES:
            dirs.append(p)
    return sorted(set(dirs), key=lambda p: str(p))


def discover_macho_files(app_root: Path) -> list[Path]:
    macho: list[Path] = []
    for p in app_root.rglob("*"):
        if p.is_file() and "_CodeSignature" not in p.parts and is_macho(p):
            macho.append(p)
    return sorted(macho, key=lambda p: str(p))


def inventory(app_root: Path, hash_mode: str) -> dict[str, Any]:
    files: list[dict[str, Any]] = []
    extension_counts: dict[str, int] = {}
    notable: list[str] = []
    bundle_paths: list[str] = []

    for p in sorted(app_root.rglob("*"), key=lambda x: str(x)):
        rp = maybe_rel(p, app_root)
        if p.is_dir() and p.suffix in BUNDLE_SUFFIXES:
            bundle_paths.append(rp)
        if p.is_symlink():
            files.append({"path": rp, "type": "symlink", "target": os.readlink(p)})
            continue
        if not p.is_file():
            continue
        suffix = p.suffix.lower()
        extension_counts[suffix or "<none>"] = extension_counts.get(suffix or "<none>", 0) + 1
        stat = p.stat()
        record: dict[str, Any] = {"path": rp, "size": stat.st_size}
        is_notable = suffix in INTERESTING_SUFFIXES or any(part.endswith(".lproj") for part in p.parts)
        if hash_mode == "full" or (hash_mode == "notable" and is_notable):
            record["sha256"] = sha256_file(p)
        files.append(record)
        if is_notable:
            notable.append(rp)

    return {
        "file_count": len(files),
        "extension_counts": dict(sorted(extension_counts.items())),
        "bundle_paths": sorted(bundle_paths),
        "notable_files": notable,
        "files": files,
    }


def info_subset(info: Any) -> Any:
    if not isinstance(info, dict):
        return info
    return {k: info.get(k) for k in INFO_KEYS if k in info}


def high_value_entitlements(ent: Any) -> Any:
    if not isinstance(ent, dict):
        return ent
    return {k: ent.get(k) for k in HIGH_VALUE_ENTITLEMENT_KEYS if k in ent}


def read_entitlement_for_main(manifest: dict[str, Any]) -> dict[str, Any]:
    signing = manifest.get("signing", {})
    root = signing.get(".") or signing.get("") or {}
    ent = root.get("entitlements")
    return ent if isinstance(ent, dict) else {}


def build_manifest(spec: ArtifactSpec, work_dir: Path, hash_mode: str) -> dict[str, Any]:
    app_root = resolve_artifact(spec.path, work_dir, spec.artifact_id)
    info_path = app_root / "Info.plist"
    info = parse_plist_file(info_path)
    executable = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    main_binary = app_root / executable if executable else None

    all_info: dict[str, Any] = {}
    for p in sorted(app_root.rglob("Info.plist")):
        all_info[maybe_rel(p, app_root)] = parse_plist_file(p)

    privacy: dict[str, Any] = {}
    for p in sorted(app_root.rglob("PrivacyInfo.xcprivacy")):
        privacy[maybe_rel(p, app_root)] = parse_plist_file(p)

    profiles: dict[str, Any] = {}
    for p in sorted(app_root.rglob("embedded.mobileprovision")):
        profiles[maybe_rel(p, app_root)] = provisioning_profile(p)

    signing: dict[str, Any] = {}
    for b in bundle_dirs(app_root):
        ent = codesign_entitlements(b)
        signing[maybe_rel(b, app_root)] = {
            "display": codesign_display(b),
            "entitlements": ent,
            "entitlements_high_value": high_value_entitlements(ent),
        }

    machos = discover_macho_files(app_root)
    binaries = {maybe_rel(p, app_root): binary_manifest(p, app_root, hash_mode) for p in machos}

    manifest = {
        "schema": SCHEMA_VERSION,
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "artifact": {
            "id": spec.artifact_id,
            "role": spec.role,
            "label": spec.label,
            "input_path": str(spec.path),
            "expected_version": spec.expected_version,
            "expected_build": spec.expected_build,
            "expected_git_ref": spec.expected_git_ref,
            "notes": spec.notes,
        },
        "app_root_resolved": str(app_root),
        "main": {
            "info_subset": info_subset(info),
            "info_full": info,
            "executable": executable,
            "main_binary": maybe_rel(main_binary, app_root) if main_binary else None,
        },
        "all_info_plists": all_info,
        "privacy_manifests": privacy,
        "provisioning_profiles": profiles,
        "signing": signing,
        "binaries": binaries,
        "inventory": inventory(app_root, hash_mode),
    }
    return manifest


def object_at(manifest: dict[str, Any], path: str) -> Any:
    current: Any = manifest
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def apply_substitutions_text(text: str, substitutions: list[dict[str, str]]) -> str:
    for item in substitutions:
        old = item.get("from", "")
        new = item.get("to", "")
        if old:
            text = text.replace(old, new)
    return text


def ignore_lines(text: str, ignore_regex: list[str]) -> str:
    if not ignore_regex:
        return text
    compiled = [re.compile(x) for x in ignore_regex]
    kept = []
    for line in text.splitlines():
        if any(rx.search(line) for rx in compiled):
            continue
        kept.append(line)
    return "\n".join(kept) + ("\n" if text.endswith("\n") else "")


def normalized_text(obj: Any, normalization: dict[str, Any]) -> str:
    text = dump_json(obj)
    text = apply_substitutions_text(text, normalization.get("expected_substitutions", []))
    text = ignore_lines(text, normalization.get("ignore_line_regex", []))
    return text


def write_diff(out_path: Path, name: str, ref_obj: Any, cand_obj: Any, ref_id: str, cand_id: str, normalization: dict[str, Any]) -> bool:
    ref_text = normalized_text(ref_obj, normalization).splitlines(keepends=True)
    cand_text = normalized_text(cand_obj, normalization).splitlines(keepends=True)
    diff = list(difflib.unified_diff(ref_text, cand_text, fromfile=f"{ref_id}/{name}", tofile=f"{cand_id}/{name}"))
    out_path.write_text("".join(diff), encoding="utf-8")
    return bool(diff)


def binary_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for path, b in manifest.get("binaries", {}).items():
        out[path] = {
            "file_type": b.get("file_type"),
            "architectures": b.get("architectures"),
            "linked_libraries": b.get("linked_libraries"),
            "rpaths": b.get("rpaths"),
            "encryption_info": b.get("encryption_info"),
            "build_version": b.get("build_version"),
            "vtool_show_build": b.get("vtool_show_build"),
        }
    return out


def signing_high_value(manifest: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for path, s in manifest.get("signing", {}).items():
        out[path] = {
            "codesign_display_parsed": (s.get("display") or {}).get("parsed"),
            "entitlements_high_value": s.get("entitlements_high_value"),
        }
    return out


def inventory_summary(manifest: dict[str, Any]) -> dict[str, Any]:
    inv = manifest.get("inventory", {})
    return {
        "file_count": inv.get("file_count"),
        "extension_counts": inv.get("extension_counts"),
        "bundle_paths": inv.get("bundle_paths"),
        "notable_files": inv.get("notable_files"),
    }


def artifact_matrix_row(m: dict[str, Any]) -> dict[str, Any]:
    info = m.get("main", {}).get("info_subset", {}) if isinstance(m.get("main", {}).get("info_subset"), dict) else {}
    ent = read_entitlement_for_main(m)
    main_binary = m.get("main", {}).get("main_binary")
    bin_info = m.get("binaries", {}).get(main_binary, {}) if main_binary else {}
    cryptids = []
    for enc in bin_info.get("encryption_info", []) or []:
        if "cryptid" in enc:
            cryptids.append(str(enc.get("cryptid")))
    inv = m.get("inventory", {})
    bundle_paths = inv.get("bundle_paths", []) or []
    appex = [p for p in bundle_paths if p.endswith(".appex")]
    frameworks = [p for p in bundle_paths if p.endswith(".framework")]
    return {
        "artifact_id": m.get("artifact", {}).get("id"),
        "role": m.get("artifact", {}).get("role"),
        "label": m.get("artifact", {}).get("label"),
        "input_path": m.get("artifact", {}).get("input_path"),
        "bundle_id": info.get("CFBundleIdentifier"),
        "short_version": info.get("CFBundleShortVersionString"),
        "build_version": info.get("CFBundleVersion"),
        "min_os": info.get("MinimumOSVersion"),
        "sdk_name": info.get("DTSDKName"),
        "xcode_build": info.get("DTXcodeBuild"),
        "main_executable": info.get("CFBundleExecutable"),
        "main_binary": main_binary,
        "main_architectures": bin_info.get("architectures"),
        "main_cryptid": ",".join(cryptids) if cryptids else "",
        "aps_environment": ent.get("aps-environment"),
        "get_task_allow": ent.get("get-task-allow"),
        "team_identifier": ent.get("com.apple.developer.team-identifier"),
        "file_count": inv.get("file_count"),
        "macho_count": len(m.get("binaries", {})),
        "extension_count": len(appex),
        "framework_count": len(frameworks),
        "privacy_manifest_count": len(m.get("privacy_manifests", {})),
        "extension_paths": ";".join(appex),
        "framework_paths": ";".join(frameworks),
    }


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fields: list[str] = []
    for row in rows:
        for k in row.keys():
            if k not in fields:
                fields.append(k)
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: serialize_csv_value(row.get(k)) for k in fields})


def serialize_csv_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(normalize(value), sort_keys=True, ensure_ascii=False)
    return str(value)


def symmetric_key_diff(a: dict[str, Any], b: dict[str, Any]) -> tuple[set[str], set[str], set[str]]:
    akeys = set(a.keys())
    bkeys = set(b.keys())
    return akeys - bkeys, bkeys - akeys, {k for k in akeys & bkeys if normalize(a.get(k)) != normalize(b.get(k))}


def collect_findings(ref: dict[str, Any], cand: dict[str, Any]) -> list[Finding]:
    ref_id = str(ref.get("artifact", {}).get("id"))
    cand_id = str(cand.get("artifact", {}).get("id"))
    out: list[Finding] = []

    ref_info = ref.get("main", {}).get("info_subset", {}) if isinstance(ref.get("main", {}).get("info_subset"), dict) else {}
    cand_info = cand.get("main", {}).get("info_subset", {}) if isinstance(cand.get("main", {}).get("info_subset"), dict) else {}
    for key in HIGH_VALUE_INFO_KEYS:
        if normalize(ref_info.get(key)) != normalize(cand_info.get(key)):
            severity = "medium"
            if key in {"CFBundleShortVersionString", "CFBundleVersion"}:
                severity = "high"
            if key == "CFBundleIdentifier":
                severity = "info"
            out.append(Finding(
                severity=severity,
                category="Info.plist",
                reference=ref_id,
                compared=cand_id,
                summary=f"{key} differs",
                detail=f"reference={ref_info.get(key)!r}; compared={cand_info.get(key)!r}",
            ))

    ref_ent = read_entitlement_for_main(ref)
    cand_ent = read_entitlement_for_main(cand)
    for key in HIGH_VALUE_ENTITLEMENT_KEYS:
        if normalize(ref_ent.get(key)) != normalize(cand_ent.get(key)):
            severity = "info" if key in EXPECTED_NOISE_KEYS else "high"
            if key == "get-task-allow":
                severity = "high"
            out.append(Finding(
                severity=severity,
                category="Entitlements",
                reference=ref_id,
                compared=cand_id,
                summary=f"{key} differs",
                detail=f"reference={ref_ent.get(key)!r}; compared={cand_ent.get(key)!r}",
            ))

    ref_priv = ref.get("privacy_manifests", {})
    cand_priv = cand.get("privacy_manifests", {})
    missing, added, changed = symmetric_key_diff(ref_priv, cand_priv)
    if missing or added or changed:
        out.append(Finding(
            severity="high",
            category="Privacy manifests",
            reference=ref_id,
            compared=cand_id,
            summary="Privacy manifest set/content differs",
            detail=f"missing_from_compared={sorted(missing)}; added_in_compared={sorted(added)}; changed={sorted(changed)}",
        ))

    ref_inv = ref.get("inventory", {})
    cand_inv = cand.get("inventory", {})
    ref_bundles = set(ref_inv.get("bundle_paths", []) or [])
    cand_bundles = set(cand_inv.get("bundle_paths", []) or [])
    missing_bundles = sorted(ref_bundles - cand_bundles)
    added_bundles = sorted(cand_bundles - ref_bundles)
    if missing_bundles or added_bundles:
        out.append(Finding(
            severity="high",
            category="Bundle inventory",
            reference=ref_id,
            compared=cand_id,
            summary="Bundle/extension/framework set differs",
            detail=f"missing_from_compared={missing_bundles}; added_in_compared={added_bundles}",
        ))

    ref_bins = binary_summary(ref)
    cand_bins = binary_summary(cand)
    missing_bins, added_bins, changed_bins = symmetric_key_diff(ref_bins, cand_bins)
    if missing_bins or added_bins:
        out.append(Finding(
            severity="high",
            category="Binaries",
            reference=ref_id,
            compared=cand_id,
            summary="Mach-O file set differs",
            detail=f"missing_from_compared={sorted(missing_bins)}; added_in_compared={sorted(added_bins)}",
        ))
    for bpath in sorted(changed_bins):
        r = ref_bins.get(bpath, {})
        c = cand_bins.get(bpath, {})
        if normalize(r.get("linked_libraries")) != normalize(c.get("linked_libraries")):
            out.append(Finding(
                severity="medium",
                category="Binaries",
                reference=ref_id,
                compared=cand_id,
                summary=f"Linked libraries differ for {bpath}",
                detail="Review binary_summary.diff for library-level delta.",
            ))

    # Explicit App Store encryption observation.
    ref_main = ref.get("main", {}).get("main_binary")
    ref_bin = ref.get("binaries", {}).get(ref_main, {}) if ref_main else {}
    cryptids = [str(e.get("cryptid")) for e in (ref_bin.get("encryption_info") or []) if "cryptid" in e]
    if "1" in cryptids:
        out.append(Finding(
            severity="info",
            category="FairPlay boundary",
            reference=ref_id,
            compared=cand_id,
            summary="Reference main executable reports cryptid 1",
            detail="Treat App Store main executable code/string diffs as non-actionable unless you have a lawful unencrypted build. This report focuses on metadata/package comparison.",
        ))

    return out


# Maps a finding category to the diff file that holds its supporting evidence.
_CATEGORY_DIFF_FILE = {
    "Info.plist": "main_info",
    "Entitlements": "signing_high_value",
    "Privacy manifests": "privacy_manifests",
    "Bundle inventory": "inventory_summary",
    "Binaries": "binary_summary",
    "FairPlay boundary": "binary_summary",
}


def finding_evidence(f: Finding) -> str:
    """Relative path (from the report) to the diff file backing a finding."""
    fname = _CATEGORY_DIFF_FILE.get(f.category)
    if not fname:
        return ""
    return f"diffs/{f.reference}_vs_{f.compared}/{fname}.diff"


def finding_to_row(f: Finding) -> dict[str, str]:
    return {
        "severity": f.severity,
        "category": f.category,
        "reference": f.reference,
        "compared": f.compared,
        "summary": f.summary,
        "detail": f.detail,
        "evidence": finding_evidence(f),
    }


def markdown_table(rows: list[dict[str, Any]], columns: list[str]) -> str:
    if not rows:
        return "_No rows._\n"
    def cell(v: Any) -> str:
        s = serialize_csv_value(v)
        s = s.replace("\n", " ").replace("|", "\\|")
        if len(s) > 140:
            s = s[:137] + "..."
        return s
    lines = []
    lines.append("| " + " | ".join(columns) + " |")
    lines.append("| " + " | ".join(["---"] * len(columns)) + " |")
    for row in rows:
        lines.append("| " + " | ".join(cell(row.get(c)) for c in columns) + " |")
    return "\n".join(lines) + "\n"


def render_report(project: str, reference_id: str, manifests: dict[str, dict[str, Any]], pair_outputs: list[dict[str, str]], findings: list[Finding], out_dir: Path,
                  build_status: dict[str, Any] | None = None, skipped: list[dict[str, str]] | None = None) -> str:
    generated = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    rows = [artifact_matrix_row(m) for m in manifests.values()]
    # Findings table links each row to the diff file backing it.
    finding_rows = []
    for f in findings:
        row = finding_to_row(f)
        ev = row.get("evidence") or ""
        row["evidence"] = f"[{ev.rsplit('/', 1)[-1]}]({ev})" if ev else ""
        finding_rows.append(row)

    text = []
    text.append(f"# {project}: iOS metadata comparison report")
    text.append("")
    text.append(f"Generated: `{generated}`")
    text.append("")
    text.append("## Scope")
    text.append("")
    text.append("This report compares iOS App Store/local build metadata and package structure. It does not decrypt FairPlay-protected executables, bypass DRM, or analyze decrypted App Store code.")
    text.append("")
    backend_note = {
        "native": "Signing/binary metadata extracted with Apple's native tools (otool/lipo/vtool/codesign/security).",
        "portable": "Signing/binary metadata extracted with the built-in pure-Python Mach-O + code-signature reader (no Apple tools required). Code-signature certificate chains and CDHashes are not reconstructed; entitlements, load commands, linked libraries, encryption flags, and identifiers are.",
    }.get(BACKEND.name, "")
    text.append(f"Metadata backend: `{BACKEND.name}`. {backend_note}")
    text.append("")
    text.append(f"Reference artifact: `{reference_id}`")
    text.append("")
    text.append("## Artifact matrix")
    text.append("")
    text.append(markdown_table(rows, [
        "artifact_id", "role", "bundle_id", "short_version", "build_version",
        "min_os", "sdk_name", "main_cryptid", "aps_environment",
        "get_task_allow", "macho_count", "extension_count", "framework_count", "privacy_manifest_count",
    ]))
    text.append("")
    if skipped:
        text.append(f"Artifacts skipped (missing/unbuildable): **{len(skipped)}** — see `csv/skipped.csv`.")
        text.append("")
    if build_status:
        text.append("## Local build status")
        text.append("")
        summary = ", ".join(f"{k}: {v}" for k, v in build_status["counts"].items())
        text.append(f"From `{build_status['path']}` — {build_status['total']} tag(s): {summary}.")
        text.append("")
        text.append(markdown_table(
            [{"status": k, "count": v} for k, v in build_status["counts"].items()],
            ["status", "count"],
        ))
        text.append("")
    text.append("## Findings")
    text.append("")
    if finding_rows:
        text.append(markdown_table(finding_rows, ["severity", "category", "reference", "compared", "summary", "detail", "evidence"]))
    else:
        text.append("No automated findings were generated. That usually means either the artifacts are highly similar or the tools needed to extract signing/binary metadata were unavailable. Review raw diffs.")
    text.append("")
    text.append("## Pairwise diff outputs")
    text.append("")
    if pair_outputs:
        text.append(markdown_table(pair_outputs, ["reference", "compared", "diff_dir", "changed_categories"]))
    else:
        text.append("No pairwise outputs generated.")
    text.append("")
    text.append("## Review priority")
    text.append("")
    text.append("1. `main_info.diff` — version/build, background modes, URL schemes, ATS, privacy usage strings.")
    text.append("2. `signing_high_value.diff` — entitlements, app groups, keychain groups, associated domains, APNs, `get-task-allow`.")
    text.append("3. `privacy_manifests.diff` — collected data declarations and required-reason APIs.")
    text.append("4. `inventory_summary.diff` — extensions, frameworks, dylibs, resource structure.")
    text.append("5. `binary_summary.diff` — architectures, linked libraries, rpaths, Mach-O build metadata, encryption flags.")
    text.append("")
    text.append("## Interpretation notes")
    text.append("")
    text.append("Expected noise includes Team ID, provisioning UUIDs, certificate details, app/keychain group prefixes, App Store receipts, code-signature blobs, and app-thinned resource variants. High-signal differences include extra app extensions, extra embedded frameworks/dylibs, different associated domains, background modes, URL schemes, LSApplicationQueriesSchemes, ATS policy, privacy manifests, linked system frameworks, and minimum OS/SDK deltas.")
    text.append("")
    text.append("## Files")
    text.append("")
    text.append("- `manifests/*.json`: full per-artifact manifests")
    text.append("- `diffs/<reference>_vs_<candidate>/*.diff`: category-level JSON unified diffs")
    text.append("- `csv/artifacts.csv`: compact artifact matrix")
    text.append("- `csv/findings.csv`: automated finding list")
    text.append("- `report.md` / `report.html`: this report")
    text.append("")
    return "\n".join(text)


_SEVERITY_COLORS = {"high": "#b00020", "medium": "#b26a00", "low": "#555555", "info": "#0061a8"}


def _inline_md(s: str) -> str:
    """Render inline `code`, **bold**, and [label](url) links to HTML."""
    out = html.escape(s)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"\[([^\]]+)\]\(([^)]+)\)",
                 lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>', out)
    return out


def report_to_html(md: str) -> str:
    # Minimal markdown-ish rendering. Keeps the file self-contained without external dependencies.
    lines = md.splitlines()
    out = ["<!doctype html><html><head><meta charset='utf-8'>",
           "<title>iOS metadata comparison report</title>",
           "<style>body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;max-width:1200px;margin:40px auto;padding:0 24px;line-height:1.45} code{background:#f4f4f4;padding:2px 4px;border-radius:4px} pre{background:#f4f4f4;padding:12px;overflow:auto} table{border-collapse:collapse;width:100%;font-size:13px} td,th{border:1px solid #ddd;padding:6px;vertical-align:top} th{background:#f6f6f6} h1,h2,h3{line-height:1.2} a{color:#0061a8}</style>",
           "</head><body>"]
    in_table = False
    table_rows: list[str] = []

    def flush_table() -> None:
        nonlocal table_rows, in_table
        if not in_table:
            return
        out.append("<table>")
        header_done = False
        for row in table_rows:
            cells = [c.strip().replace("\\|", "|") for c in row.strip().strip("|").split("|")]
            if all(c == "---" for c in cells):
                continue
            tag = "th" if not header_done else "td"
            rendered = []
            for c in cells:
                if tag == "td" and c.lower() in _SEVERITY_COLORS:
                    rendered.append(
                        f'<td><span style="color:{_SEVERITY_COLORS[c.lower()]};font-weight:600">{html.escape(c)}</span></td>'
                    )
                else:
                    rendered.append(f"<{tag}>{_inline_md(c)}</{tag}>")
            out.append("<tr>" + "".join(rendered) + "</tr>")
            header_done = True
        out.append("</table>")
        table_rows = []
        in_table = False

    for line in lines:
        if line.startswith("| ") and line.endswith("|"):
            in_table = True
            table_rows.append(line)
            continue
        flush_table()
        if line.startswith("# "):
            out.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("## "):
            out.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("### "):
            out.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("- "):
            out.append(f"<p>• {_inline_md(line[2:])}</p>")
        elif re.match(r"^\d+\. ", line):
            out.append(f"<p>{_inline_md(line)}</p>")
        elif not line.strip():
            out.append("")
        else:
            out.append(f"<p>{_inline_md(line)}</p>")
    flush_table()
    out.append("</body></html>")
    return "\n".join(out)


def specs_from_config(config: dict[str, Any], base_dir: Path) -> tuple[str, ArtifactSpec, list[ArtifactSpec], dict[str, Any], str]:
    project = config.get("project", "iOS metadata comparison")
    hash_mode = config.get("hash_mode", "notable")
    if hash_mode not in {"full", "notable", "none"}:
        raise ValueError("hash_mode must be full, notable, or none")

    reference_raw = config.get("reference")
    if not reference_raw:
        raise ValueError("config requires a reference artifact")

    def spec(item: dict[str, Any], default_role: str) -> ArtifactSpec:
        raw_path = Path(item["path"])
        if not raw_path.is_absolute():
            raw_path = (base_dir / raw_path).resolve()
        return ArtifactSpec(
            artifact_id=sanitize_id(item.get("id") or raw_path.stem),
            path=raw_path,
            role=item.get("role", default_role),
            label=item.get("label"),
            expected_version=item.get("expected_version"),
            expected_build=item.get("expected_build"),
            expected_git_ref=item.get("expected_git_ref"),
            notes=item.get("notes"),
        )

    reference = spec(reference_raw, "appstore_reference")
    artifacts = [spec(x, "candidate") for x in config.get("artifacts", [])]
    normalization = config.get("normalization", {})
    return project, reference, artifacts, normalization, hash_mode


def specs_from_args(args: argparse.Namespace) -> tuple[str, ArtifactSpec, list[ArtifactSpec], dict[str, Any], str]:
    reference_path = Path(args.reference).expanduser().resolve()
    reference = ArtifactSpec(artifact_id=sanitize_id(args.reference_id or reference_path.stem), path=reference_path, role="appstore_reference")
    candidates = []
    for i, value in enumerate(args.candidate or [], start=1):
        p = Path(value).expanduser().resolve()
        candidates.append(ArtifactSpec(artifact_id=sanitize_id(p.stem or f"candidate_{i}"), path=p, role="candidate"))
    normalization = {
        "expected_substitutions": [],
        "ignore_line_regex": [],
    }
    return args.project, reference, candidates, normalization, args.hash_mode


def validate_config(config: dict[str, Any], base_dir: Path, skip_missing: bool = False) -> tuple[list[str], list[str]]:
    """Preflight a config before expensive extraction. Returns (errors, warnings)."""
    errors: list[str] = []
    warnings: list[str] = []

    hash_mode = config.get("hash_mode", "notable")
    if hash_mode not in {"full", "notable", "none"}:
        errors.append(f"hash_mode must be one of full|notable|none, got {hash_mode!r}")

    reference = config.get("reference")
    if not reference:
        errors.append("config requires a 'reference' artifact")

    def _resolve(raw: str) -> Path:
        p = Path(raw)
        return p if p.is_absolute() else (base_dir / p)

    ids: list[str] = []
    entries: list[tuple[dict[str, Any], bool]] = []
    if isinstance(reference, dict):
        entries.append((reference, True))
    for art in config.get("artifacts", []) or []:
        entries.append((art, False))

    for item, is_reference in entries:
        if not isinstance(item, dict) or "path" not in item:
            errors.append(f"artifact entry missing 'path': {item!r}")
            continue
        ids.append(str(item.get("id") or Path(item["path"]).stem))
        if not _resolve(item["path"]).exists():
            msg = f"{'reference' if is_reference else 'candidate'} path does not exist: {item['path']}"
            if is_reference or not skip_missing:
                errors.append(msg)
            else:
                warnings.append(msg + " (will be skipped)")

    seen: dict[str, int] = {}
    for raw in ids:
        sid = sanitize_id(raw)
        seen[sid] = seen.get(sid, 0) + 1
    dups = sorted(k for k, v in seen.items() if v > 1)
    if dups:
        errors.append(f"duplicate artifact ids after sanitization: {dups}")

    for rx in config.get("normalization", {}).get("ignore_line_regex", []) or []:
        try:
            re.compile(rx)
        except re.error as e:
            errors.append(f"invalid ignore_line_regex {rx!r}: {e}")

    return errors, warnings


def read_build_status(path: Path) -> dict[str, Any] | None:
    """Summarize a build_signal_release_sweep.sh status CSV, if present."""
    if not path or not path.exists():
        return None
    counts: dict[str, int] = {}
    total = 0
    try:
        with path.open(newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                total += 1
                status = (row.get("status") or "unknown").strip() or "unknown"
                counts[status] = counts.get(status, 0) + 1
    except OSError:
        return None
    return {"path": str(path), "total": total, "counts": dict(sorted(counts.items()))}


def compare_all(project: str, reference: ArtifactSpec, candidates: list[ArtifactSpec], normalization: dict[str, Any],
                hash_mode: str, out_dir: Path, jobs: int = 1, skip_missing: bool = False,
                ipa_cache: Path | None = None, build_status_path: Path | None = None) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    manifests_dir = out_dir / "manifests"
    diffs_dir = out_dir / "diffs"
    csv_dir = out_dir / "csv"
    for d in [manifests_dir, diffs_dir, csv_dir]:
        d.mkdir(parents=True, exist_ok=True)

    manifests: dict[str, dict[str, Any]] = {}
    pair_outputs: list[dict[str, str]] = []
    all_findings: list[Finding] = []
    skipped: list[dict[str, str]] = []

    specs = [reference] + candidates
    tmp_ctx = tempfile.TemporaryDirectory(prefix="ios_multi_compare_") if ipa_cache is None else None
    work = Path(tmp_ctx.name) if tmp_ctx is not None else ipa_cache
    if ipa_cache is not None:
        ipa_cache.mkdir(parents=True, exist_ok=True)
    try:
        # Build manifests concurrently (each artifact spawns many subprocess/IO
        # calls), then collect on the main thread to keep file writes serial.
        with cf.ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            futures = {ex.submit(build_manifest, spec, work, hash_mode): spec for spec in specs}
            for fut in cf.as_completed(futures):
                spec = futures[fut]
                try:
                    manifest = fut.result()
                except FileNotFoundError as e:
                    if spec is reference:
                        raise SystemExit(f"Reference artifact could not be built: {e}")
                    if skip_missing:
                        print(f"[!] skipping {spec.artifact_id}: {e}", file=sys.stderr)
                        skipped.append({"artifact_id": spec.artifact_id, "reason": str(e)})
                        continue
                    raise
                manifests[spec.artifact_id] = manifest
                (manifests_dir / f"{spec.artifact_id}.manifest.json").write_text(dump_json(manifest), encoding="utf-8")
                print(f"[+] manifest: {spec.artifact_id}")
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()

    if reference.artifact_id not in manifests:
        raise SystemExit("Reference manifest was not produced; cannot compare.")
    # Restore deterministic (config) ordering and drop any skipped candidates.
    manifests = {s.artifact_id: manifests[s.artifact_id] for s in specs if s.artifact_id in manifests}
    candidates = [c for c in candidates if c.artifact_id in manifests]

    ref_manifest = manifests[reference.artifact_id]
    diff_categories = {
        "main_info": lambda m: m.get("main", {}).get("info_subset"),
        "all_info_plists": lambda m: m.get("all_info_plists"),
        "signing_high_value": signing_high_value,
        "signing_full": lambda m: m.get("signing"),
        "privacy_manifests": lambda m: m.get("privacy_manifests"),
        "provisioning_profiles": lambda m: m.get("provisioning_profiles"),
        "binary_summary": binary_summary,
        "inventory_summary": inventory_summary,
        "full_inventory": lambda m: m.get("inventory", {}).get("files"),
    }

    for cand in candidates:
        cand_manifest = manifests[cand.artifact_id]
        pair_dir = diffs_dir / f"{reference.artifact_id}_vs_{cand.artifact_id}"
        pair_dir.mkdir(parents=True, exist_ok=True)
        changed: list[str] = []
        for name, fn in diff_categories.items():
            did_change = write_diff(
                pair_dir / f"{name}.diff",
                name,
                fn(ref_manifest),
                fn(cand_manifest),
                reference.artifact_id,
                cand.artifact_id,
                normalization,
            )
            if did_change:
                changed.append(name)
        pair_outputs.append({
            "reference": reference.artifact_id,
            "compared": cand.artifact_id,
            "diff_dir": str(pair_dir.relative_to(out_dir)),
            "changed_categories": ";".join(changed) if changed else "none",
        })
        all_findings.extend(collect_findings(ref_manifest, cand_manifest))

    write_csv(csv_dir / "artifacts.csv", [artifact_matrix_row(m) for m in manifests.values()])
    write_csv(csv_dir / "findings.csv", [finding_to_row(f) for f in all_findings])
    write_csv(csv_dir / "pair_outputs.csv", pair_outputs)
    if skipped:
        write_csv(csv_dir / "skipped.csv", skipped)

    build_status = read_build_status(build_status_path) if build_status_path else None
    md = render_report(project, reference.artifact_id, manifests, pair_outputs, all_findings, out_dir,
                       build_status=build_status, skipped=skipped)
    (out_dir / "report.md").write_text(md, encoding="utf-8")
    (out_dir / "report.html").write_text(report_to_html(md), encoding="utf-8")
    print(f"[+] Wrote report: {out_dir / 'report.md'}")
    print(f"[+] Wrote HTML report: {out_dir / 'report.html'}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare App Store/local iOS package metadata across multiple artifacts.")
    parser.add_argument("--config", help="Path to config JSON. Preferred for multi-artifact comparisons.")
    parser.add_argument("--reference", help="Reference App Store IPA/.app/.xcarchive path. Used when --config is not supplied.")
    parser.add_argument("--reference-id", help="Optional reference artifact ID.")
    parser.add_argument("--candidate", action="append", help="Candidate IPA/.app/.xcarchive path. Repeatable. Used when --config is not supplied.")
    parser.add_argument("--project", default="iOS metadata comparison", help="Project/report title.")
    parser.add_argument("--hash-mode", choices=["full", "notable", "none"], default="notable", help="Hash all files, notable files only, or no inventory hashes.")
    parser.add_argument("--backend", choices=["auto", "native", "portable"], default="auto",
                        help="Metadata backend. 'native' uses Apple's otool/codesign (macOS); "
                             "'portable' uses the built-in pure-Python reader (works on Linux/WSL); "
                             "'auto' picks native when those tools are present. Also settable via IOS_META_BACKEND.")
    parser.add_argument("--jobs", "-j", type=int, default=4, help="Parallel manifest-building workers (default 4).")
    parser.add_argument("--skip-missing", action="store_true", help="Skip candidate artifacts whose paths do not exist instead of failing.")
    parser.add_argument("--ipa-cache", help="Persistent directory for content-addressed IPA extraction (reused across runs).")
    parser.add_argument("--build-status", help="Path to a build_status.csv to summarize in the report (default: out/build_logs/build_status.csv if present).")
    parser.add_argument("--out", required=True, help="Output directory.")
    args = parser.parse_args()

    global BACKEND
    BACKEND = macho_backend.select_backend(None if args.backend == "auto" else args.backend)
    print(f"[*] Metadata backend: {BACKEND.name}")

    out_dir = Path(args.out).expanduser().resolve()

    if args.config:
        config_path = Path(args.config).expanduser().resolve()
        config = load_json(config_path)
        errors, warnings = validate_config(config, config_path.parent, skip_missing=args.skip_missing)
        for w in warnings:
            print(f"[!] config warning: {w}", file=sys.stderr)
        if errors:
            for e in errors:
                print(f"[x] config error: {e}", file=sys.stderr)
            raise SystemExit("Config validation failed. Fix the errors above (or pass --skip-missing for absent candidates).")
        project, reference, candidates, normalization, hash_mode = specs_from_config(config, config_path.parent)
    else:
        if not args.reference:
            parser.error("Either --config or --reference is required")
        project, reference, candidates, normalization, hash_mode = specs_from_args(args)

    if not candidates:
        raise SystemExit("At least one candidate artifact is required.")

    ipa_cache = Path(args.ipa_cache).expanduser().resolve() if args.ipa_cache else None
    if args.build_status:
        build_status_path = Path(args.build_status).expanduser()
    else:
        default_status = Path("out/build_logs/build_status.csv")
        build_status_path = default_status if default_status.exists() else None

    compare_all(project, reference, candidates, normalization, hash_mode, out_dir,
                jobs=args.jobs, skip_missing=args.skip_missing, ipa_cache=ipa_cache,
                build_status_path=build_status_path)


if __name__ == "__main__":
    main()
