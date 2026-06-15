#!/usr/bin/env bash
# Runnable, offline demo of the Android bundled-library matcher.
#
# Identifies an obfuscated, version-stripped library bundled (in DEX form) inside
# an APK by matching it against a corpus of known versions shipped (in JVM form)
# as JARs -- the cross-format, obfuscation-resilient path.
#
# Usage: bash examples/android_demo/run_demo.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
OUT="$HERE/out"

# 1. Generate the artifacts if they are not already committed/present.
if [ ! -f "$HERE/app/obfuscated-app.apk" ]; then
  echo "[*] generating demo artifacts ..."
  python3 "$HERE/generate_demo_artifacts.py"
fi

mkdir -p "$OUT"

# 2. Fingerprint the reference corpus (the JVM JARs = 'known versions').
echo "[*] building corpus from JVM JARs ..."
python3 "$ROOT/scripts/android_lib_match.py" build-corpus \
  --in "$HERE/lib_versions" \
  --out "$OUT/demolib.corpus.jsonl"

# 3. Match the obfuscated DEX-in-APK candidate against the corpus.
echo "[*] matching the obfuscated candidate APK ..."
python3 "$ROOT/scripts/android_lib_match.py" match \
  --candidate "$HERE/app/obfuscated-app.apk" \
  --candidate-name "obfuscated-app" \
  --corpus "$OUT/demolib.corpus.jsonl" \
  --out "$OUT/match"

echo
echo "[=] expected verdict: demolib 1.1.0, containment 1.000 (PRESENT, strong)"
echo "[+] full report: $OUT/match/report.html"
echo "[+] per-version scores: $OUT/match/csv/version_scores.csv"
