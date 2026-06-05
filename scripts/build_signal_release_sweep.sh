#!/usr/bin/env bash
set -u -o pipefail

# Bulk build Signal-iOS Release/device archives from a release matrix CSV.
# Continue-on-error by default. This is intentionally conservative: old releases
# may fail with modern Xcode/dependency stacks.

MATRIX_CSV="${1:-matrices/signal_releases_selected.csv}"
REPO_DIR="${REPO_DIR:-$PWD/Signal-iOS}"
OUT_DIR="${OUT_DIR:-$PWD/artifacts/local}"
LOG_DIR="${LOG_DIR:-$PWD/out/build_logs}"
WORKSPACE="${WORKSPACE:-Signal.xcworkspace}"
SCHEME="${SCHEME:-Signal}"
CONFIGURATION="${CONFIGURATION:-Release}"
DESTINATION="${DESTINATION:-generic/platform=iOS}"
LIMIT="${LIMIT:-0}"          # 0 means no limit
OFFSET="${OFFSET:-0}"
DRY_RUN="${DRY_RUN:-0}"
SKIP_EXISTING="${SKIP_EXISTING:-1}"
CONTINUE_ON_ERROR="${CONTINUE_ON_ERROR:-1}"
RUN_MAKE_DEPENDENCIES="${RUN_MAKE_DEPENDENCIES:-auto}" # auto|always|never
CLEAN_WORKTREE="${CLEAN_WORKTREE:-0}"
XCODEBUILD_EXTRA_ARGS="${XCODEBUILD_EXTRA_ARGS:-}"

mkdir -p "$OUT_DIR" "$LOG_DIR"
STATUS_CSV="$LOG_DIR/build_status.csv"

echo "timestamp,tag,archive_path,status,exit_code,log_path" > "$STATUS_CSV"

if [[ ! -f "$MATRIX_CSV" ]]; then
  echo "[!] Matrix CSV not found: $MATRIX_CSV" >&2
  exit 2
fi

# Extract expected_git_ref/tag_name from CSV using Python's csv module so quoted commas are safe.
mapfile -t TAGS < <(python3 - "$MATRIX_CSV" <<'PY'
import csv, sys
path = sys.argv[1]
with open(path, newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    for row in reader:
        tag = (row.get('expected_git_ref') or row.get('tag_name') or '').strip()
        if tag:
            print(tag)
PY
)

if [[ ${#TAGS[@]} -eq 0 ]]; then
  echo "[!] No tags found in $MATRIX_CSV" >&2
  exit 2
fi

if [[ ! -d "$REPO_DIR/.git" ]]; then
  echo "[*] Cloning Signal-iOS into $REPO_DIR"
  if [[ "$DRY_RUN" == "1" ]]; then
    echo "DRY_RUN: git clone --recurse-submodules https://github.com/signalapp/Signal-iOS.git '$REPO_DIR'"
  else
    git clone --recurse-submodules https://github.com/signalapp/Signal-iOS.git "$REPO_DIR" || exit $?
  fi
fi

if [[ "$DRY_RUN" != "1" ]]; then
  git -C "$REPO_DIR" fetch --tags --recurse-submodules
fi

count=0
seen=0
for tag in "${TAGS[@]}"; do
  seen=$((seen + 1))
  if (( seen <= OFFSET )); then
    continue
  fi
  if (( LIMIT > 0 && count >= LIMIT )); then
    break
  fi
  count=$((count + 1))

  safe_tag="${tag//\//_}"
  archive_path="$OUT_DIR/Signal-$safe_tag.xcarchive"
  log_path="$LOG_DIR/Signal-$safe_tag.log"
  timestamp="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  echo "[*] [$count] tag=$tag archive=$archive_path"

  if [[ "$SKIP_EXISTING" == "1" && -d "$archive_path" ]]; then
    echo "[=] exists; skipping: $archive_path"
    echo "$timestamp,$tag,$archive_path,skipped_existing,0,$log_path" >> "$STATUS_CSV"
    continue
  fi

  if [[ "$DRY_RUN" == "1" ]]; then
    echo "DRY_RUN: git -C '$REPO_DIR' checkout -f '$tag'"
    echo "DRY_RUN: git -C '$REPO_DIR' submodule update --init --recursive"
    echo "DRY_RUN: xcodebuild -workspace '$WORKSPACE' -scheme '$SCHEME' -configuration '$CONFIGURATION' -destination '$DESTINATION' clean archive -archivePath '$archive_path' $XCODEBUILD_EXTRA_ARGS"
    echo "$timestamp,$tag,$archive_path,dry_run,0,$log_path" >> "$STATUS_CSV"
    continue
  fi

  (
    set -e
    cd "$REPO_DIR"
    echo "== tag $tag =="
    git checkout -f "$tag"
    if [[ "$CLEAN_WORKTREE" == "1" ]]; then
      git clean -xdf
    fi
    git submodule sync --recursive
    git submodule update --init --recursive

    if [[ "$RUN_MAKE_DEPENDENCIES" == "always" || ( "$RUN_MAKE_DEPENDENCIES" == "auto" && -f Makefile ) ]]; then
      echo "== make dependencies =="
      make dependencies
    fi

    echo "== xcodebuild archive =="
    # shellcheck disable=SC2086
    xcodebuild \
      -workspace "$WORKSPACE" \
      -scheme "$SCHEME" \
      -configuration "$CONFIGURATION" \
      -destination "$DESTINATION" \
      clean archive \
      -archivePath "$archive_path" \
      $XCODEBUILD_EXTRA_ARGS
  ) >"$log_path" 2>&1
  code=$?

  if [[ $code -eq 0 ]]; then
    echo "[+] built: $archive_path"
    echo "$timestamp,$tag,$archive_path,built,0,$log_path" >> "$STATUS_CSV"
  else
    echo "[!] failed tag=$tag exit=$code log=$log_path" >&2
    echo "$timestamp,$tag,$archive_path,failed,$code,$log_path" >> "$STATUS_CSV"
    if [[ "$CONTINUE_ON_ERROR" != "1" ]]; then
      exit "$code"
    fi
  fi
 done

echo "[*] Build status: $STATUS_CSV"
