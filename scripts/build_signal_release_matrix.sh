#!/usr/bin/env bash
set -euo pipefail

# Build a small local Release/device matrix from Signal-iOS release tags.
# This is a convenience wrapper. Signal's repo has project-specific build/signing
# requirements; if xcodebuild fails, open Signal.xcworkspace in Xcode and archive manually.

REPO_DIR="${REPO_DIR:-$PWD/Signal-iOS}"
OUT_DIR="${OUT_DIR:-$PWD/artifacts/local}"
WORKSPACE="${WORKSPACE:-Signal.xcworkspace}"
SCHEME="${SCHEME:-Signal}"
TAGS=("${@:-}")

if [[ ${#TAGS[@]} -eq 0 || -z "${TAGS[0]}" ]]; then
  echo "Usage: $0 <tag> [tag...]"
  echo "Example: $0 8.13.0.1623 8.12.1.1616 8.12.0.1599"
  exit 2
fi

mkdir -p "$OUT_DIR"

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "[*] Cloning Signal-iOS into $REPO_DIR"
  git clone --recurse-submodules https://github.com/signalapp/Signal-iOS.git "$REPO_DIR"
fi

cd "$REPO_DIR"
git fetch --tags --recurse-submodules

for tag in "${TAGS[@]}"; do
  echo "[*] Building tag: $tag"
  git checkout "$tag"
  git submodule update --init --recursive
  if [[ -f Makefile ]]; then
    make dependencies || true
  fi
  archive_path="$OUT_DIR/Signal-$tag.xcarchive"
  xcodebuild \
    -workspace "$WORKSPACE" \
    -scheme "$SCHEME" \
    -configuration Release \
    -destination 'generic/platform=iOS' \
    clean archive \
    -archivePath "$archive_path"
  echo "[+] Archive: $archive_path"
done
