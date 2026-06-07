#!/usr/bin/env bash
set -u -o pipefail

# ============================================================================
# OPT-IN, OWNED-DEVICE ONLY. On-device decryption of an app you lawfully obtained.
# ============================================================================
#
# App Store binaries are FairPlay-encrypted at rest and decrypted in memory by
# iOS at launch. To analyze the *shipped* binary (rather than a source build),
# security research dumps that already-in-memory-decrypted image from a device
# you control. This script ORCHESTRATES a standard open-source dumper
# (bagbak or frida-ios-dump) to do exactly that and drops the result in
# artifacts/decrypted/ so the comparison engine can read it like any other .app.
#
# This script:
#   * does NOT bypass code signing, DRM, or any app protection,
#   * does NOT patch or re-sign binaries,
#   * only captures the decrypted image iOS itself produces at runtime.
#
# Use it ONLY on:
#   * a jailbroken iOS device you own,
#   * an Apple ID you control,
#   * an app you lawfully downloaded,
#   * for analysis you are authorized to perform.
# Do NOT redistribute decrypted binaries or any protected App Store code.
#
# Requirements on the host:
#   * bagbak (`npm i -g bagbak`)  OR  frida-ios-dump (AloneMonkey fork)
#   * frida + frida-server running on the jailbroken device, reachable over USB
#
# Usage:
#   ./scripts/decrypt_on_device.sh --i-own-this-device [--bundle org.whispersystems.signal]
# Environment:
#   DUMPER          bagbak | frida-ios-dump   (default: auto-detect)
#   FRIDA_IOS_DUMP  path to frida-ios-dump's dump.py (if not on PATH)
#   OUT             output IPA (default: artifacts/decrypted/Signal-decrypted.ipa)
# ============================================================================

BUNDLE_ID="org.whispersystems.signal"
CONFIRM=0
OUT="${OUT:-artifacts/decrypted/Signal-decrypted.ipa}"
DUMPER="${DUMPER:-auto}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --i-own-this-device) CONFIRM=1; shift ;;
    --bundle) BUNDLE_ID="$2"; shift 2 ;;
    --out) OUT="$2"; shift 2 ;;
    --dumper) DUMPER="$2"; shift 2 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "[!] unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ "$CONFIRM" != "1" ]]; then
  cat >&2 <<'EOF'
[x] Refusing to run without explicit confirmation.

This performs on-device decryption of an installed app. Run it ONLY on a
jailbroken device you own, with an app you lawfully obtained, for authorized
analysis, and do not redistribute the output. Re-run with:

    ./scripts/decrypt_on_device.sh --i-own-this-device
EOF
  exit 3
fi

mkdir -p "$(dirname "$OUT")"
HERE="$(cd "$(dirname "$0")/.." && pwd)"

resolve_dumper() {
  if [[ "$DUMPER" == "auto" ]]; then
    if command -v bagbak >/dev/null 2>&1; then DUMPER="bagbak"
    elif [[ -n "${FRIDA_IOS_DUMP:-}" || -f dump.py ]]; then DUMPER="frida-ios-dump"
    else DUMPER="none"; fi
  fi
}
resolve_dumper

case "$DUMPER" in
  bagbak)
    echo "[*] Using bagbak to dump $BUNDLE_ID (device must be jailbroken, frida-server running)."
    # bagbak writes an .ipa; -o selects the output path/name.
    bagbak "$BUNDLE_ID" -o "$OUT" || { echo "[!] bagbak failed" >&2; exit 1; }
    ;;
  frida-ios-dump)
    DUMP_PY="${FRIDA_IOS_DUMP:-dump.py}"
    echo "[*] Using frida-ios-dump ($DUMP_PY) to dump $BUNDLE_ID."
    python3 "$DUMP_PY" -o "$OUT" "$BUNDLE_ID" || { echo "[!] frida-ios-dump failed" >&2; exit 1; }
    ;;
  *)
    cat >&2 <<'EOF'
[x] No dumper found. Install one of:
      bagbak:          npm i -g bagbak
      frida-ios-dump:  https://github.com/AloneMonkey/frida-ios-dump
    Both require frida + frida-server running on the jailbroken device over USB.
EOF
    exit 127
    ;;
esac

[[ -f "$OUT" ]] || { echo "[!] expected output not found: $OUT" >&2; exit 1; }
echo "[+] Decrypted IPA: $OUT"
sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT" 2>/dev/null || true

# Confirm the dump is actually decrypted (cryptid should now be 0) using the
# kit's own dependency-free reader.
echo "[*] Verifying decryption (expect cryptid 0 on the main executable):"
python3 - "$OUT" <<PY
import sys, zipfile, plistlib, fnmatch, tempfile, os
sys.path.insert(0, os.path.join("$HERE", "scripts"))
import macho
ipa = sys.argv[1]
with zipfile.ZipFile(ipa) as z:
    info_name = next(n for n in z.namelist()
                     if fnmatch.fnmatch(n, "Payload/*.app/Info.plist") and n.count("/") == 2)
    app_dir = info_name.rsplit("/", 1)[0]
    exe = plistlib.loads(z.read(info_name)).get("CFBundleExecutable")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(z.read(f"{app_dir}/{exe}"))
        path = tf.name
sl = macho.primary_slice(macho.parse_path(path))
os.unlink(path)
crypt = [e.get("cryptid") for e in sl.get("encryption_info", [])]
print(f"    main={exe} arch={sl.get('arch')} cryptid={crypt or 'none'}")
if crypt and all(c == 0 for c in crypt):
    print("    OK: binary is decrypted; analyzable as an unencrypted Mach-O.")
elif crypt:
    print("    [!] cryptid still 1 — dump may have failed; re-run on the device.")
else:
    print("    note: no LC_ENCRYPTION_INFO present (already unencrypted).")
PY

cat <<EOF

Next:
  Add this artifact to a comparison config with role "appstore_decrypted":
    { "id": "signal_appstore_decrypted", "role": "appstore_decrypted",
      "path": "$OUT" }
  then run scripts/ios_multiversion_meta_compare.py. The decrypted main binary
  now exposes its real linked libraries / load commands for code-surface review.
EOF
