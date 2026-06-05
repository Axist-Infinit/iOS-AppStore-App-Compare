#!/usr/bin/env bash
set -u -o pipefail

# Acquire the Signal App Store IPA with ipatool (https://github.com/majd/ipatool).
#
# ipatool authenticates with your own Apple ID and downloads the same package the
# App Store delivers. This is a scriptable, cross-platform alternative to the
# macOS-only Apple Configurator capture (scripts/watch_configurator_cache.sh).
#
# Boundary note: like Configurator, ipatool downloads the production FairPlay-
# encrypted IPA. The main executable still reports `cryptid 1`; this script does
# not decrypt anything. Use it as the production *reference* artifact, or pair it
# with the opt-in on-device decryption workflow (a later phase) if you own a
# device for that.
#
# Usage:
#   APPLE_ID=you@example.com ./scripts/acquire_ipatool.sh
# Environment:
#   APPLE_ID     Apple ID email (optional; ipatool will prompt/store auth)
#   BUNDLE_ID    App bundle identifier        (default: org.whispersystems.signal)
#   OUT          Output IPA path             (default: artifacts/appstore/Signal-AppStore.ipa)
#   PURCHASE     1 to acquire a (free) license first via `ipatool download --purchase`

BUNDLE_ID="${BUNDLE_ID:-org.whispersystems.signal}"
OUT="${OUT:-artifacts/appstore/Signal-AppStore.ipa}"
APPLE_ID="${APPLE_ID:-}"
PURCHASE="${PURCHASE:-0}"

if ! command -v ipatool >/dev/null 2>&1; then
  cat >&2 <<'EOF'
[!] ipatool not found. Install it, then re-run:
      macOS:        brew install ipatool
      Go toolchain: go install github.com/majd/ipatool/v2@latest
      Releases:     https://github.com/majd/ipatool/releases
EOF
  exit 127
fi

mkdir -p "$(dirname "$OUT")"

# Authenticate if there is no active session. ipatool stores the session in its
# keychain after the first login (it will prompt for password and 2FA).
if ! ipatool auth info >/dev/null 2>&1; then
  echo "[*] No active ipatool session; logging in."
  if [[ -n "$APPLE_ID" ]]; then
    ipatool auth login -e "$APPLE_ID" || { echo "[!] ipatool login failed" >&2; exit 1; }
  else
    echo "[!] Set APPLE_ID=you@example.com or run 'ipatool auth login' first." >&2
    exit 1
  fi
fi

purchase_flag=()
if [[ "$PURCHASE" == "1" ]]; then
  purchase_flag=(--purchase)
fi

echo "[*] Downloading $BUNDLE_ID -> $OUT"
if ! ipatool download -b "$BUNDLE_ID" -o "$OUT" "${purchase_flag[@]}"; then
  echo "[!] Download failed. If you have never installed Signal on this Apple ID," >&2
  echo "    re-run with PURCHASE=1 to acquire the free license first." >&2
  exit 1
fi

echo "[+] Saved: $OUT"
shasum -a 256 "$OUT" 2>/dev/null || sha256sum "$OUT" 2>/dev/null || true

# Record the captured version/build from the IPA's Info.plist (stdlib only).
python3 - "$OUT" <<'PY'
import sys, zipfile, plistlib, fnmatch
ipa = sys.argv[1]
try:
    with zipfile.ZipFile(ipa) as z:
        info = next(n for n in z.namelist()
                    if fnmatch.fnmatch(n, "Payload/*.app/Info.plist") and n.count("/") == 2)
        plist = plistlib.loads(z.read(info))
    print(f"[+] CFBundleShortVersionString: {plist.get('CFBundleShortVersionString')}")
    print(f"[+] CFBundleVersion:            {plist.get('CFBundleVersion')}")
    print(f"[+] CFBundleIdentifier:         {plist.get('CFBundleIdentifier')}")
    print("[*] Use CFBundleVersion to select the matching Signal-iOS release tag to build.")
except Exception as e:  # noqa: BLE001
    print(f"[!] Could not read version from IPA: {e}", file=sys.stderr)
PY
