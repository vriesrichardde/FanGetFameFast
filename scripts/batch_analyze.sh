#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# batch_analyze.sh — Batch evidence investigation orchestrator.
#
# Walks an evidence directory, extracts any .7z/.zip archives to a temporary
# directory, routes each evidence file to the appropriate investigation module
# (FAME / FAST / FAN), then generates an overall batch report once all files
# have been processed.
#
# Archives are kept intact; extracted files are deleted immediately after the
# investigation for that file completes.  Non-archive evidence files (e.g.
# bare .E01 disk images) are never deleted.
#
# Usage:
#   ./scripts/batch_analyze.sh [evidence_dir]
#   ./scripts/batch_analyze.sh /path/to/evidence --batch-id BATCH-2026-001
#   ./scripts/batch_analyze.sh /path/to/evidence --batch-id BATCH-001 --no-vault --no-upload

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Defaults ───────────────────────────────────────────────────────────────────
EVIDENCE_DIR="/home/vscode/evidence"
BATCH_ID=""
NO_VAULT=0
NO_UPLOAD=0

# ── Usage ──────────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
Usage: batch_analyze.sh [evidence_dir] [OPTIONS]

Arguments:
  evidence_dir      Directory containing evidence files (default: /home/vscode/evidence)

Options:
  --batch-id ID     Batch / case ID prefix (default: BATCH-YYYYMMDD-HHMMSS)
  --no-vault        Skip all Obsidian vault writes
  --no-upload       Skip upload to investigations vault (FAME and FAST only)
  -h, --help        Show this help

Supported file types:
  Compressed  : .7z  .zip  (archives are kept; extracted files deleted after analysis)
  FAME        : .mem  .img  .raw  .lime  .vmem  .dmp
  FAST        : .E01  .ewf  .vmdk  .vdi  .qcow2  .vhd  .vhdx
  FAN         : .pcap  .pcapng  .cap
EOF
    exit 0
}

# ── Argument parsing ───────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --batch-id)  BATCH_ID="$2"; shift 2 ;;
        --no-vault)  NO_VAULT=1;    shift   ;;
        --no-upload) NO_UPLOAD=1;   shift   ;;
        -h|--help)   usage          ;;
        -*)          echo "[batch] Unknown option: $1" >&2; exit 1 ;;
        *)           EVIDENCE_DIR="$1"; shift ;;
    esac
done

if [[ ! -d "$EVIDENCE_DIR" ]]; then
    echo "[batch] ERROR: Evidence directory not found: $EVIDENCE_DIR" >&2
    exit 1
fi

[[ -z "$BATCH_ID" ]] && BATCH_ID="BATCH-$(date -u +%Y%m%d-%H%M%S)"

# ── Batch work directories ─────────────────────────────────────────────────────
BATCH_WORK_DIR="$PROJECT_ROOT/batch_work/$BATCH_ID"
EXTRACTED_DIR="$BATCH_WORK_DIR/extracted"
MANIFEST="$BATCH_WORK_DIR/manifest.json"
ERRORS_LOG="$BATCH_WORK_DIR/errors.log"
PROCESSED_FILE="$BATCH_WORK_DIR/processed_stems.txt"

mkdir -p "$BATCH_WORK_DIR" "$EXTRACTED_DIR"
touch "$PROCESSED_FILE"

# ── Manifest initialisation ────────────────────────────────────────────────────
python3 - "$MANIFEST" "$BATCH_ID" "$EVIDENCE_DIR" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" <<'PYEOF'
import json, sys
manifest_path, batch_id, evidence_dir, started = sys.argv[1:]
with open(manifest_path, "w") as f:
    json.dump({
        "batch_id":     batch_id,
        "evidence_dir": evidence_dir,
        "started_utc":  started,
        "completed_utc": None,
        "cases":  [],
        "errors": [],
    }, f, indent=2)
PYEOF

PASS=0
FAIL=0

# ── Helpers ────────────────────────────────────────────────────────────────────

# Append one case entry to manifest.json
_manifest_add_case() {
    local case_id="$1" source="$2" extracted_as="$3" module="$4" hostname="$5" status="$6"
    python3 - "$MANIFEST" "$case_id" "$source" "$extracted_as" "$module" "$hostname" "$status" <<'PYEOF'
import json, sys
path, case_id, source, extracted_as, module, hostname, status = sys.argv[1:]
with open(path) as f:
    data = json.load(f)
data["cases"].append({
    "case_id":      case_id,
    "source_file":  source,
    "extracted_as": extracted_as,
    "module":       module,
    "hostname":     hostname,
    "status":       status,
})
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PYEOF
}

# Append an error message to manifest.json and errors.log
_manifest_add_error() {
    local message="$1"
    echo "[batch] ERROR: $message" | tee -a "$ERRORS_LOG"
    python3 - "$MANIFEST" "$message" <<'PYEOF'
import json, sys
path, message = sys.argv[1:]
with open(path) as f:
    data = json.load(f)
data["errors"].append(message)
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PYEOF
}

# Mark a module:stem pair as processed (prevents re-analysis of the same file
# extracted from an archive, while still allowing different evidence types with
# the same stem — e.g. host.mem and host.E01 — to each be analyzed)
_mark_processed() {
    echo "$1" >> "$PROCESSED_FILE"
}

_is_processed() {
    grep -qxF "$1" "$PROCESSED_FILE" 2>/dev/null
}

# Derive module type from file extension
_detect_module() {
    local ext
    ext="${1##*.}"
    ext="${ext,,}"
    case "$ext" in
        mem|img|raw|lime|vmem|dmp)          echo "FAME" ;;
        e01|ewf|vmdk|vdi|qcow2|vhd|vhdx)   echo "FAST" ;;
        pcap|pcapng|cap)                     echo "FAN"  ;;
        *)                                   echo "UNKNOWN" ;;
    esac
}

# ── Core: investigate one evidence file ────────────────────────────────────────
_process_file() {
    local file="$1"
    local source_archive="${2:-}"   # non-empty when file was extracted from an archive

    local module
    module="$(_detect_module "$file")"

    if [[ "$module" == "UNKNOWN" ]]; then
        echo "[batch] Skipping unsupported file type: $(basename "$file")"
        return 0
    fi

    local stem
    stem="$(basename "$file" | sed 's/\.[^.]*$//')"
    local processed_key="${module}:${stem}"

    if _is_processed "$processed_key"; then
        echo "[batch] Skipping already-processed ${module} stem: $stem"
        return 0
    fi

    local case_id="${BATCH_ID}-${stem}"
    echo "[batch] ── $module  case: $case_id  file: $(basename "$file")"

    # Build common flags
    local common_flags=()
    [[ $NO_VAULT -eq 1 ]] && common_flags+=("--no-vault")

    local upload_flags=()
    [[ $NO_UPLOAD -eq 1 ]] && upload_flags+=("--no-upload")

    local status="success"

    case "$module" in
        FAME)
            if bash "$SCRIPT_DIR/fame_analyze.sh" "$file" \
                    --case-id  "$case_id" \
                    --hostname "$stem" \
                    "${common_flags[@]+"${common_flags[@]}"}" \
                    "${upload_flags[@]+"${upload_flags[@]}"}"; then
                PASS=$((PASS + 1))
            else
                status="failed"
                FAIL=$((FAIL + 1))
                _manifest_add_error "FAME analysis failed for: $file"
            fi
            ;;
        FAST)
            if bash "$SCRIPT_DIR/fast_analyze.sh" "$file" \
                    --case-id  "$case_id" \
                    --hostname "$stem" \
                    "${common_flags[@]+"${common_flags[@]}"}" \
                    "${upload_flags[@]+"${upload_flags[@]}"}"; then
                PASS=$((PASS + 1))
            else
                status="failed"
                FAIL=$((FAIL + 1))
                _manifest_add_error "FAST analysis failed for: $file"
            fi
            ;;
        FAN)
            # Pass --reports-persist-dir so FAN reports land in ./reports/ and
            # are available to the batch report generator after WIP cleanup.
            if bash "$SCRIPT_DIR/analyze_pcap.sh" "$file" \
                    --case-id "$case_id" \
                    --reports-persist-dir "$PROJECT_ROOT/reports" \
                    "${common_flags[@]+"${common_flags[@]}"}"; then
                PASS=$((PASS + 1))
            else
                status="failed"
                FAIL=$((FAIL + 1))
                _manifest_add_error "FAN analysis failed for: $file"
            fi
            ;;
    esac

    _mark_processed "$processed_key"
    _manifest_add_case \
        "$case_id" \
        "${source_archive:-$file}" \
        "$file" \
        "$module" \
        "$stem" \
        "$status"
}

# ── Archive handler ────────────────────────────────────────────────────────────
_process_archive() {
    local archive="$1"
    local ext="${archive##*.}"
    ext="${ext,,}"

    # Create a per-archive temp dir under batch_work so cleanup is scoped
    local extract_dir
    extract_dir="$(mktemp -d "$EXTRACTED_DIR/XXXXXX")"

    echo "[batch] Extracting: $(basename "$archive")"

    local extract_ok=1
    case "$ext" in
        7z)
            7z x "$archive" -o"$extract_dir" -y >/dev/null 2>&1 || extract_ok=0 ;;
        zip)
            unzip -o "$archive" -d "$extract_dir" >/dev/null 2>&1 || extract_ok=0 ;;
    esac

    if [[ $extract_ok -eq 0 ]]; then
        _manifest_add_error "Extraction failed for: $archive"
        rm -rf "$extract_dir"
        return 0
    fi

    # Investigate each evidence file found inside the archive
    local evidence_exts="mem|img|raw|lime|vmem|dmp|e01|ewf|vmdk|vdi|qcow2|vhd|vhdx|pcap|pcapng|cap"
    while IFS= read -r -d '' extracted_file; do
        local file_ext
        file_ext="${extracted_file##*.}"
        file_ext="${file_ext,,}"
        if echo "$file_ext" | grep -qE "^($evidence_exts)$"; then
            _process_file "$extracted_file" "$archive"
            # Remove the extracted evidence file immediately after analysis
            rm -f "$extracted_file"
        fi
    done < <(find "$extract_dir" -type f -print0)

    # Remove the temp extraction directory (any remaining non-evidence files)
    rm -rf "$extract_dir"
}

# ── Banner ─────────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  BATCH — FanGetFameFast Evidence Batch Processor                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Evidence dir : $EVIDENCE_DIR"
echo "  Batch ID     : $BATCH_ID"
echo "  No-vault     : $( [[ $NO_VAULT -eq 1 ]]  && echo yes || echo no )"
echo "  No-upload    : $( [[ $NO_UPLOAD -eq 1 ]] && echo yes || echo no )"
echo ""

# ── Phase 1: Archives ─────────────────────────────────────────────────────────
echo "[batch] Phase 1: Processing archives (.7z / .zip)..."
archive_count=0
while IFS= read -r -d '' archive; do
    archive_count=$((archive_count + 1))
    _process_archive "$archive"
done < <(find "$EVIDENCE_DIR" -type f \( -name "*.7z" -o -name "*.zip" \) -print0 | sort -z)

echo "[batch] Phase 1 complete — $archive_count archive(s) processed."

# ── Phase 2: Direct evidence files ────────────────────────────────────────────
echo "[batch] Phase 2: Processing direct evidence files..."
direct_count=0
while IFS= read -r -d '' file; do
    direct_count=$((direct_count + 1))
    _process_file "$file"
done < <(find "$EVIDENCE_DIR" -type f \
    \(  -iname "*.mem"    -o -iname "*.img"    -o -iname "*.raw"  \
     -o -iname "*.lime"   -o -iname "*.vmem"   -o -iname "*.dmp"  \
     -o -iname "*.E01"    -o -iname "*.ewf"    -o -iname "*.vmdk" \
     -o -iname "*.vdi"    -o -iname "*.qcow2"  -o -iname "*.vhd"  \
     -o -iname "*.vhdx"   -o -iname "*.pcap"   -o -iname "*.pcapng" \
     -o -iname "*.cap" \) \
    -print0 | sort -z)

echo "[batch] Phase 2 complete — $direct_count direct file(s) considered."

# ── Finalise manifest ─────────────────────────────────────────────────────────
python3 - "$MANIFEST" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" <<'PYEOF'
import json, sys
path, completed = sys.argv[1:]
with open(path) as f:
    data = json.load(f)
data["completed_utc"] = completed
with open(path, "w") as f:
    json.dump(data, f, indent=2)
PYEOF

# ── Phase 3: Batch report ─────────────────────────────────────────────────────
echo ""
echo "[batch] Phase 3: Generating overall batch report..."

report_flags=()
[[ $NO_UPLOAD -eq 1 ]] && report_flags+=("--no-upload")

python3 "$PROJECT_ROOT/lib/generate_batch_report.py" \
    --batch-id    "$BATCH_ID" \
    --manifest    "$MANIFEST" \
    --reports-dir "$PROJECT_ROOT/reports" \
    --output-dir  "$PROJECT_ROOT/reports" \
    "${report_flags[@]+"${report_flags[@]}"}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Batch complete                                                  ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Batch ID  : $BATCH_ID"
echo "  Succeeded : $PASS"
echo "  Failed    : $FAIL"
echo "  Manifest  : $MANIFEST"
[[ -f "$ERRORS_LOG" && -s "$ERRORS_LOG" ]] && \
    echo "  Errors    : $ERRORS_LOG"
echo ""
