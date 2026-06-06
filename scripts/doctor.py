#!/usr/bin/env python3
"""
Preflight / doctor for the Signal iOS metadata comparison lab.

Answers "can this machine run the workflow?" by checking the tools, the active
metadata backend, and the artifacts on disk, then printing exact blockers.

It is cross-platform aware: on Linux/WSL the Apple command line tools are
*expected* to be absent, and the built-in portable backend covers metadata and
signing extraction, so their absence is reported as informational rather than a
blocker. Building local archives and capturing via Apple Configurator still
require macOS, and those are reported per-capability.

Usage:
  python3 scripts/doctor.py
  python3 scripts/doctor.py --json
"""
from __future__ import annotations

import argparse
import json
import platform
import shutil
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import macho_backend  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent

OK, WARN, BLOCK, INFO = "ok", "warn", "blocker", "info"
_MARK = {OK: "[ OK ]", WARN: "[WARN]", BLOCK: "[BLOCK]", INFO: "[ -- ]"}


def _check(name: str, status: str, detail: str = "") -> dict:
    return {"check": name, "status": status, "detail": detail}


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def gather(appstore_dir: Path, local_dir: Path) -> list[dict]:
    results: list[dict] = []
    is_macos = platform.system() == "Darwin"

    # --- runtime ---
    pyver = sys.version_info
    results.append(_check(
        "python>=3.9",
        OK if pyver >= (3, 9) else BLOCK,
        f"{pyver.major}.{pyver.minor}.{pyver.micro}",
    ))

    # --- metadata backend (the engine always has one) ---
    backend = macho_backend.select_backend()
    results.append(_check(
        "metadata backend",
        OK,
        f"'{backend.name}' active"
        + ("" if backend.name == "native"
           else " (pure-Python; Apple otool/codesign not required)"),
    ))

    # --- Apple tools (native backend ingredients) ---
    apple_tools = ["codesign", "otool", "lipo", "vtool", "security", "plutil"]
    present = [t for t in apple_tools if _have(t)]
    missing = [t for t in apple_tools if not _have(t)]
    if missing and backend.name == "portable":
        results.append(_check(
            "apple signing/mach-o tools", INFO,
            f"missing {missing} — fine; portable backend is handling extraction",
        ))
    elif missing:
        results.append(_check("apple signing/mach-o tools", WARN, f"missing {missing}"))
    else:
        results.append(_check("apple signing/mach-o tools", OK, f"present {present}"))

    results.append(_check("file(1)", OK if _have("file") else WARN,
                          "present" if _have("file") else "absent (synthesized fallback used)"))

    # --- acquisition ---
    if _have("ipatool"):
        results.append(_check("acquisition: ipatool", OK, "scriptable App Store download available"))
    else:
        results.append(_check("acquisition: ipatool", WARN,
                              "absent — install majd/ipatool or use Apple Configurator (macOS)"))
    if is_macos:
        results.append(_check("acquisition: Apple Configurator", INFO,
                              "macOS detected; watch_configurator_cache.sh usable"))

    # --- local build capability (macOS only) ---
    if is_macos:
        for tool in ("xcodebuild", "git", "make"):
            results.append(_check(
                f"build: {tool}", OK if _have(tool) else WARN,
                "present" if _have(tool) else "absent — needed to build local Signal-iOS archives",
            ))
    else:
        results.append(_check("build: local archives", INFO,
                              "non-macOS host — build Signal-iOS archives on a Mac, then copy "
                              "the .xcarchive/.app into artifacts/local/"))
        results.append(_check("git", OK if _have("git") else WARN,
                              "present" if _have("git") else "absent"))

    # --- optional accelerators ---
    try:
        import lief  # noqa: F401
        results.append(_check("optional: LIEF", OK, "installed (enables richer code-surface phase)"))
    except Exception:
        results.append(_check("optional: LIEF", INFO, "not installed (optional; not required)"))

    # --- artifacts on disk ---
    ipas = sorted(appstore_dir.glob("*.ipa")) if appstore_dir.exists() else []
    results.append(_check(
        "artifact: App Store IPA",
        OK if ipas else WARN,
        f"{len(ipas)} IPA(s) in {_rel(appstore_dir)}" if ipas
        else f"none in {_rel(appstore_dir)} — acquire one first (ipatool/Configurator)",
    ))
    locals_found = []
    if local_dir.exists():
        locals_found = sorted(p for p in local_dir.iterdir()
                              if p.suffix in (".xcarchive", ".app", ".ipa"))
    results.append(_check(
        "artifact: local archives",
        OK if locals_found else WARN,
        f"{len(locals_found)} in {_rel(local_dir)}" if locals_found
        else f"none in {_rel(local_dir)} — build/copy at least one comparator",
    ))
    return results


def _rel(p: Path) -> str:
    try:
        return str(p.relative_to(ROOT))
    except ValueError:
        return str(p)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Preflight checks for the metadata comparison lab.")
    ap.add_argument("--appstore-dir", default=str(ROOT / "artifacts" / "appstore"))
    ap.add_argument("--local-dir", default=str(ROOT / "artifacts" / "local"))
    ap.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = ap.parse_args(argv)

    results = gather(Path(args.appstore_dir), Path(args.local_dir))
    blockers = [r for r in results if r["status"] == BLOCK]
    warns = [r for r in results if r["status"] == WARN]

    if args.json:
        print(json.dumps({"results": results, "blockers": len(blockers), "warnings": len(warns)}, indent=2))
    else:
        print("Signal iOS metadata lab — preflight\n")
        for r in results:
            line = f"  {_MARK[r['status']]:7} {r['check']}"
            if r["detail"]:
                line += f": {r['detail']}"
            print(line)
        print()
        if blockers:
            print(f"{len(blockers)} blocker(s) must be resolved before running the workflow.")
        elif warns:
            print(f"No blockers. {len(warns)} warning(s) — review above for the workflow steps you intend to run.")
        else:
            print("All clear.")
    return 1 if blockers else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
