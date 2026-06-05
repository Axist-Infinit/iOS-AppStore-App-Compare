#!/usr/bin/env bash
set -euo pipefail

# Watch Apple Configurator's app-asset cache and copy IPA files out before
# temporary cache cleanup. This does not decrypt FairPlay and does not modify
# the IPA. It only preserves the package Apple Configurator downloads for install.

OUT_DIR="${1:-$HOME/Desktop/ipa_capture}"
mkdir -p "$OUT_DIR"

CANDIDATE_ROOTS=(
  "$HOME/Library/Group Containers/K36BKF7T3D.group.com.apple.configurator/Library/Caches/Assets"
  "$HOME/Library/Group Containers/K36BKF7T3D.group.com.apple.configurator/Library/Caches"
  "$HOME/Library/Containers/com.apple.configurator.ui/Data/Library/Caches"
)

echo "[*] Output directory: $OUT_DIR"
echo "[*] Candidate Configurator cache roots:"
for r in "${CANDIDATE_ROOTS[@]}"; do
  echo "    $r"
done

echo "[*] Start Apple Configurator now, connect the iPhone, and Add -> Apps -> Signal."
echo "[*] Press Ctrl+C after the IPA has been copied."

seen_file="$OUT_DIR/.seen_ipa_paths"
touch "$seen_file"

while true; do
  for root in "${CANDIDATE_ROOTS[@]}"; do
    [[ -d "$root" ]] || continue
    while IFS= read -r -d '' ipa; do
      if grep -Fqx "$ipa" "$seen_file"; then
        continue
      fi
      base="$(basename "$ipa")"
      stamp="$(date +%Y%m%d_%H%M%S)"
      dest="$OUT_DIR/${stamp}_${base}"
      echo "[+] Capturing: $ipa"
      cp -p "$ipa" "$dest"
      shasum -a 256 "$dest" | tee -a "$OUT_DIR/SHA256SUMS"
      echo "$ipa" >> "$seen_file"
    done < <(find "$root" -type f -name '*.ipa' -print0 2>/dev/null)
  done
  sleep 0.25
done
