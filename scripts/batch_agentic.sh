#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# batch_agentic.sh — Agentic batch evidence investigation orchestrator.
#
# Identical orchestration to batch_analyze.sh (archive extraction, file routing,
# manifest tracking, batch report) but routes each evidence file through the
# Claude agentic path — /fame or /fast skills — rather than calling the shell
# scripts directly.  This means every case receives:
#
#   • Step-by-step research notes  (<case_id>_research_notes.md)
#   • Interpreted findings and analytical pivots per tool output
#   • MITRE ATT&CK context written by Claude in real time
#
# Requires: claude CLI (Claude Code) available in PATH.
#
# Usage:
#   ./scripts/batch_agentic.sh [evidence_dir]
#   ./scripts/batch_agentic.sh /path/to/evidence --batch-id BATCH-2026-001
#   ./scripts/batch_agentic.sh /path/to/evidence --batch-id BATCH-001 --no-vault --no-upload

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
Usage: batch_agentic.sh [evidence_dir] [OPTIONS]

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
  FAN         : .pcap  .pcapng  .cap  (uses bash path — no /fan skill yet)

Each FAME and FAST case is driven by Claude via 'claude -p "/fame ..."' or
'claude -p "/fast ..."', producing research notes alongside the formal report.
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

if ! command -v claude &>/dev/null; then
    echo "[batch] ERROR: 'claude' CLI not found in PATH — required for agentic mode" >&2
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

# Mark a module:stem.ext triplet as processed (prevents re-analysis of the same
# file extracted from an archive, while still allowing different evidence types
# with the same stem — e.g. host.mem and host.E01 — to each be analyzed)
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

# ── Core: investigate one evidence file via the agentic path ──────────────────
_process_file() {
    local file="$1"
    local source_archive="${2:-}"   # non-empty when file was extracted from an archive

    local module
    module="$(_detect_module "$file")"

    if [[ "$module" == "UNKNOWN" ]]; then
        echo "[batch] Skipping unsupported file type: $(basename "$file")"
        return 0
    fi

    # Guard against filenames that could break out of the `claude -p` prompt
    # string or inject instructions into the agentic prompt (the basename flows
    # into the natural-language prompt via $stem/$case_id below). Names may
    # originate inside extracted archives, so they are not fully trusted.
    # Legitimate evidence basenames use only alphanumerics, space, dot, dash,
    # underscore — anything else is skipped and recorded in the manifest.
    local base
    base="$(basename "$file")"
    if [[ "$base" =~ [^[:alnum:][:space:]._-] ]]; then
        echo "[batch] Skipping file with unsafe characters in name: $base" >&2
        _manifest_add_error "Unsafe filename skipped (prompt-injection guard): $file"
        return 0
    fi
    # The FULL path (not just the basename) is interpolated into the `claude -p`
    # prompt below. Directory components can originate inside extracted archives,
    # so validate the whole path too — allow '/' as separator but reject any
    # quote/backtick/$/; metacharacter that could break out of the prompt string
    # or inject agent instructions via a crafted sub-directory name.
    if [[ "$file" =~ [^[:alnum:][:space:]./_-] ]]; then
        echo "[batch] Skipping file with unsafe characters in path: $file" >&2
        _manifest_add_error "Unsafe path skipped (prompt-injection guard): $file"
        return 0
    fi

    local stem ext
    stem="$(basename "$file" | sed 's/\.[^.]*$//')"
    ext="${file##*.}"
    local processed_key="${module}:${stem}.${ext}"

    if _is_processed "$processed_key"; then
        echo "[batch] Skipping already-processed ${module} stem: $stem"
        return 0
    fi

    local case_id="${BATCH_ID}-${stem}"
    echo "[batch] ── $module (agentic)  case: $case_id  file: $(basename "$file")"

    # Build extra args string for the skill invocation
    local extra_args=""
    [[ $NO_VAULT   -eq 1 ]] && extra_args="$extra_args --no-vault"
    [[ $NO_UPLOAD  -eq 1 ]] && extra_args="$extra_args --no-upload"

    local status="success"

    case "$module" in
        FAME)
            if claude -p "/fame \"$file\" --case-id \"$case_id\" --hostname \"$stem\"$extra_args"; then
                PASS=$((PASS + 1))
            else
                status="failed"
                FAIL=$((FAIL + 1))
                _manifest_add_error "FAME agentic analysis failed for: $file"
            fi
            ;;
        FAST)
            if claude -p "/fast \"$file\" --case-id \"$case_id\" --hostname \"$stem\"$extra_args"; then
                PASS=$((PASS + 1))
            else
                status="failed"
                FAIL=$((FAIL + 1))
                _manifest_add_error "FAST agentic analysis failed for: $file"
            fi
            ;;
        FAN)
            # FAN has no single agentic skill yet — fall back to the shell script.
            # Pass --reports-persist-dir so FAN reports land in ./reports/ and
            # are available to the batch report generator after WIP cleanup.
            local common_flags=()
            [[ $NO_VAULT -eq 1 ]] && common_flags+=("--no-vault")
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
echo "║  BATCH (AGENTIC) — FanGetFameFast Evidence Batch Processor       ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Evidence dir : $EVIDENCE_DIR"
echo "  Batch ID     : $BATCH_ID"
echo "  No-vault     : $( [[ $NO_VAULT -eq 1 ]]  && echo yes || echo no )"
echo "  No-upload    : $( [[ $NO_UPLOAD -eq 1 ]] && echo yes || echo no )"
echo "  Mode         : agentic (claude -p per case)"
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

# ── Phase 4: Campaign report ──────────────────────────────────────────────────
echo ""
echo "[batch] Phase 4: Generating campaign report..."

# Generate narrative files for all successfully completed cases
while IFS= read -r case_id; do
    [[ -z "$case_id" ]] && continue
    python3 "$PROJECT_ROOT/lib/narrative_generator.py" \
        --case-id     "$case_id" \
        --reports-dir "$PROJECT_ROOT/reports" 2>/dev/null || true
done < <(python3 - "$MANIFEST" <<'PYEOF'
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
for c in data.get("cases", []):
    if c.get("status") == "success":
        print(c["case_id"])
PYEOF
)

CAMPAIGN_TITLE="${CAMPAIGN_TITLE:-Campaign Investigation — $BATCH_ID}"
python3 "$PROJECT_ROOT/lib/generate_campaign_report.py" \
    --campaign-id "$BATCH_ID" \
    --title       "$CAMPAIGN_TITLE" \
    --reports-dir "$PROJECT_ROOT/reports" \
    --output-dir  "$PROJECT_ROOT/reports"

echo "[batch] Phase 4 complete — campaign report written."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  Agentic batch complete                                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Batch ID  : $BATCH_ID"
echo "  Succeeded : $PASS"
echo "  Failed    : $FAIL"
echo "  Manifest  : $MANIFEST"
[[ -f "$ERRORS_LOG" && -s "$ERRORS_LOG" ]] && \
    echo "  Errors    : $ERRORS_LOG"
echo ""
