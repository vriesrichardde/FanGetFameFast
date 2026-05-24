#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# fame_analyze.sh — FAME (Forensic Analysis Memory) orchestration script.
#
# Runs Volatility 3 / Memory Baseliner against a memory image, generates
# Markdown + PDF + PPTX + DOCX reports, checks for existing FAN / FAST
# data in the same case folder, triggers a combined report when found,
# and uploads all artefacts to the investigations vault via MCP.
#
# Usage:
#   ./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001
#   ./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234
#   ./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --no-vault
#
# Environment variables (set in ~/.soc_env):
#   INVESTIGATIONS_SSH_HOST  — default: sansforensics@ubuntudesktop
#   INVESTIGATIONS_ROOT      — default: /home/sansforensics/cases
#   OPENCTI_URL              — OpenCTI API endpoint
#   OPENCTI_API_KEY          — OpenCTI API key

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VOL="${VOL:-/opt/volatility3-2.20.0/vol.py}"
[[ -x "$VOL" ]] || VOL="/opt/volatility3/vol.py"
BASELINE="/opt/memory-baseliner/baseline.py"

MEMORY_IMAGE=""
CASE_ID=""
HOSTNAME_ARG="unknown"
NO_VAULT=0
SKIP_UPLOAD=0
ANALYSIS_DIR="$PROJECT_ROOT/analysis/memory"
EXPORTS_DIR="$PROJECT_ROOT/exports"
REPORTS_DIR="$PROJECT_ROOT/reports"

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --case-id)   CASE_ID="$2";       shift 2 ;;
        --hostname)  HOSTNAME_ARG="$2";  shift 2 ;;
        --no-vault)  NO_VAULT=1;         shift   ;;
        --no-upload) SKIP_UPLOAD=1;      shift   ;;
        -*)
            echo "[fame] Unknown option: $1" >&2
            exit 1
            ;;
        *)
            MEMORY_IMAGE="$1"
            shift
            ;;
    esac
done

if [[ -z "$MEMORY_IMAGE" ]]; then
    echo "[fame] ERROR: No memory image specified." >&2
    echo "Usage: $0 /path/to/image.mem --case-id CASE-2026-001" >&2
    exit 1
fi

if [[ ! -f "$MEMORY_IMAGE" ]]; then
    echo "[fame] ERROR: Memory image not found: $MEMORY_IMAGE" >&2
    exit 1
fi

# Prompt for case ID if not provided
if [[ -z "$CASE_ID" ]]; then
    echo -n "[fame] Case ID (e.g. FAME-2026-001): "
    read -r CASE_ID
fi

# Auto-detect hostname from image filename stem if not provided
if [[ "$HOSTNAME_ARG" == "unknown" ]]; then
    HOSTNAME_ARG="$(basename "$MEMORY_IMAGE" | sed 's/\.[^.]*$//')"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  FAME — Forensic Analysis Memory                                 ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Image    : $MEMORY_IMAGE"
echo "  Case ID  : $CASE_ID"
echo "  Hostname : $HOSTNAME_ARG"
echo ""

# ── Directory setup ───────────────────────────────────────────────────────────
mkdir -p \
    "$ANALYSIS_DIR" \
    "$ANALYSIS_DIR/autotimeliner" \
    "$ANALYSIS_DIR/evtxtract" \
    "$EXPORTS_DIR/dumpfiles" \
    "$EXPORTS_DIR/malfind" \
    "$EXPORTS_DIR/memdump" \
    "$REPORTS_DIR"

# ── Volatility 3 analysis ─────────────────────────────────────────────────────
echo "[fame] Starting Volatility 3 analysis..."

run_vol() {
    local plugin="$1"
    local outfile="$2"
    local extra_args="${3:-}"
    echo "[fame] Running $plugin..."
    if python3 "$VOL" -f "$MEMORY_IMAGE" $extra_args "$plugin" \
        > "$ANALYSIS_DIR/$outfile" 2>&1; then
        echo "[fame] $plugin → $outfile"
    else
        echo "[fame] WARNING: $plugin exited with errors (see $outfile)"
    fi
}

# Detect OS type from image
IMAGE_TYPE="$(file "$MEMORY_IMAGE" 2>/dev/null || echo "")"

if echo "$IMAGE_TYPE" | grep -qi "ELF"; then
    echo "[fame] Linux memory image detected."
    run_vol "linux.pslist"     "linux_pslist.txt"
    run_vol "linux.pstree"     "linux_pstree.txt"
    run_vol "linux.netstat"    "linux_netstat.txt"
    run_vol "linux.malfind"    "linux_malfind.txt"
    run_vol "banners.Banners"  "banners.txt"
    # Linux kernel strings for images without ISF symbols
    echo "[fame] Extracting strings from memory image..."
    strings -a -n 8 "$MEMORY_IMAGE" > "$ANALYSIS_DIR/strings_all.txt" 2>/dev/null || true
    strings -a -el -n 8 "$MEMORY_IMAGE" > "$ANALYSIS_DIR/strings_unicode.txt" 2>/dev/null || true
    # Extract syslog/auth patterns
    grep -E "(pam_unix|sudo:|login\[|FAILED|TERM signal|shutdown|reboot|PostgreSQL|mysql)" \
        "$ANALYSIS_DIR/strings_all.txt" \
        > "$ANALYSIS_DIR/syslog_patterns.txt" 2>/dev/null || true
    echo "[fame] Strings extraction complete."
else
    echo "[fame] Windows memory image detected (or unknown — attempting Windows plugins)."
    run_vol "windows.pslist"   "pslist.txt"
    run_vol "windows.psscan"   "psscan.txt"
    run_vol "windows.pstree"   "pstree.txt"       "-r pretty"
    run_vol "windows.cmdline"  "cmdline.txt"
    run_vol "windows.netstat"  "netstat.txt"
    run_vol "windows.netscan"  "netscan.txt"
    run_vol "windows.malfind"  "malfind.txt"
    run_vol "windows.svcscan"  "svcscan.txt"
    run_vol "windows.modules"  "modules.txt"
    run_vol "windows.modscan"  "modscan.txt"
    run_vol "windows.filescan" "filescan.txt"
    run_vol "windows.registry.userassist" "userassist.txt"
    run_vol "windows.registry.hivelist"   "hivelist.txt"
    run_vol "windows.info"     "windows_info.txt"
    # Memory timeline
    echo "[fame] Generating memory timeline..."
    python3 "$VOL" -f "$MEMORY_IMAGE" timeliner --create-bodyfile \
        > "$ANALYSIS_DIR/mem_bodyfile.txt" 2>/dev/null || true
    mactime -b "$ANALYSIS_DIR/mem_bodyfile.txt" -z UTC \
        > "$ANALYSIS_DIR/mem_timeline.txt" 2>/dev/null || true
fi

# ── Memory Baseliner (if baseline JSON available) ─────────────────────────────
BASELINE_JSON="${PROJECT_ROOT}/baselines/baseline.json"
if [[ -f "$BASELINE_JSON" ]] && [[ -f "$BASELINE" ]]; then
    echo "[fame] Running Memory Baseliner comparison..."
    python3 "$BASELINE" -proc -i "$MEMORY_IMAGE" \
        --loadbaseline --jsonbaseline "$BASELINE_JSON" \
        -o "$ANALYSIS_DIR/proc_baseline.csv" 2>/dev/null || true
    python3 "$BASELINE" -drv  -i "$MEMORY_IMAGE" \
        --loadbaseline --jsonbaseline "$BASELINE_JSON" \
        -o "$ANALYSIS_DIR/drv_baseline.csv" 2>/dev/null || true
    python3 "$BASELINE" -svc  -i "$MEMORY_IMAGE" \
        --loadbaseline --jsonbaseline "$BASELINE_JSON" \
        -o "$ANALYSIS_DIR/svc_baseline.csv" 2>/dev/null || true
    # Convert pipe delimiters to CSV
    for f in proc drv svc; do
        [[ -f "$ANALYSIS_DIR/${f}_baseline.csv" ]] && \
            sed -i 's/|/,/g' "$ANALYSIS_DIR/${f}_baseline.csv"
    done
    echo "[fame] Memory Baseliner complete."
else
    echo "[fame] No baseline JSON found — skipping Memory Baseliner comparison."
fi

# ── AutoTimeliner (super-timeline from memory) ────────────────────────────────
# AutoTimeliner correlates multiple Volatility plugin outputs into a single
# MACB super-timeline using the bodyfile format + mactime.
AUTOTIMELINER_BIN=""
for candidate in \
    /opt/autotimeliner/autotimeliner.py \
    /opt/AutoTimeliner/autotimeliner.py \
    /usr/local/share/autotimeliner/autotimeliner.py \
    "$(command -v autotimeliner 2>/dev/null)"; do
    [[ -f "$candidate" ]] && { AUTOTIMELINER_BIN="$candidate"; break; }
done

if [[ -n "$AUTOTIMELINER_BIN" ]]; then
    echo "[fame] Running AutoTimeliner super-timeline..."
    mkdir -p "$ANALYSIS_DIR/autotimeliner"
    python3 "$AUTOTIMELINER_BIN" \
        -f "$MEMORY_IMAGE" \
        -v "$VOL" \
        --output "$ANALYSIS_DIR/autotimeliner/supertimeline.csv" \
        2> "$ANALYSIS_DIR/autotimeliner/autotimeliner.log" || {
        echo "[fame] WARNING: AutoTimeliner failed — see autotimeliner.log"
    }
    [[ -f "$ANALYSIS_DIR/autotimeliner/supertimeline.csv" ]] && \
        echo "[fame] Super-timeline → $ANALYSIS_DIR/autotimeliner/supertimeline.csv"
else
    echo "[fame] AutoTimeliner not found — skipping."
    echo "[fame]   Install: git clone https://github.com/andreafortuna/autotimeliner /opt/autotimeliner"
    echo "[fame]            pip3 install -r /opt/autotimeliner/requirements.txt"
fi

# ── EVTXtract (recover EVTX records from memory) ─────────────────────────────
# EVTXtract parses raw binary (memory images, disk images) and recovers intact
# Windows Event Log records even when the EVTX file is fragmented or deleted.
EVTXTRACT_BIN=""
for candidate in \
    /opt/EVTXtract/evtxtract.py \
    /opt/evtxtract/evtxtract.py \
    "$(command -v evtxtract 2>/dev/null)"; do
    [[ -f "$candidate" ]] || [[ -x "$candidate" ]] && { EVTXTRACT_BIN="$candidate"; break; }
done

if [[ -n "$EVTXTRACT_BIN" ]]; then
    echo "[fame] Running EVTXtract to recover Event Log records from memory..."
    mkdir -p "$ANALYSIS_DIR/evtxtract"
    python3 "$EVTXTRACT_BIN" "$MEMORY_IMAGE" \
        > "$ANALYSIS_DIR/evtxtract/recovered_events.xml" \
        2> "$ANALYSIS_DIR/evtxtract/evtxtract.log" || {
        echo "[fame] WARNING: EVTXtract failed — see evtxtract.log"
    }
    # Convert XML to a flat text summary for quick review
    if [[ -s "$ANALYSIS_DIR/evtxtract/recovered_events.xml" ]]; then
        python3 - <<'PYEOF' 2>/dev/null || true
import sys, xml.etree.ElementTree as ET, pathlib

xml_path = pathlib.Path("$ANALYSIS_DIR/evtxtract/recovered_events.xml")
out_path  = pathlib.Path("$ANALYSIS_DIR/evtxtract/events_summary.txt")
try:
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    lines = []
    for evt in root.findall(".//e:Event", ns)[:500]:
        sys_node = evt.find("e:System", ns)
        if sys_node is None:
            continue
        eid  = (sys_node.findtext("e:EventID", namespaces=ns) or "?")
        ts   = (sys_node.findtext("e:TimeCreated", namespaces=ns) or "")
        chan = (sys_node.findtext("e:Channel", namespaces=ns) or "")
        comp = (sys_node.findtext("e:Computer", namespaces=ns) or "")
        lines.append(f"{ts}  EventID={eid}  Channel={chan}  Computer={comp}")
    out_path.write_text("\n".join(lines) + "\n")
except Exception:
    pass
PYEOF
        echo "[fame] EVTXtract recovered events → $ANALYSIS_DIR/evtxtract/recovered_events.xml"
        [[ -f "$ANALYSIS_DIR/evtxtract/events_summary.txt" ]] && \
            echo "[fame] Event summary → $ANALYSIS_DIR/evtxtract/events_summary.txt"
    fi
else
    echo "[fame] EVTXtract not found — skipping."
    echo "[fame]   Install: git clone https://github.com/williballenthin/EVTXtract /opt/EVTXtract"
    echo "[fame]            pip3 install -r /opt/EVTXtract/requirements.txt"
fi

# ── Report generation ─────────────────────────────────────────────────────────
echo "[fame] Generating reports (Markdown, PDF, PPTX, DOCX)..."

# Check for existing FAN report to include cross-module summary
FAN_MD=""
FAST_MD=""
STEM="${CASE_ID//[[:space:]]/_}"
[[ -f "$REPORTS_DIR/${STEM}_incident_report.md" ]] && \
    FAN_MD="$(head -60 "$REPORTS_DIR/${STEM}_incident_report.md")"
[[ -f "$REPORTS_DIR/${STEM}_fast_report.md" ]] && \
    FAST_MD="$(head -60 "$REPORTS_DIR/${STEM}_fast_report.md")"

python3 "$PROJECT_ROOT/lib/generate_fame_report.py" \
    --case-id      "$CASE_ID" \
    --hostname     "$HOSTNAME_ARG" \
    --image-path   "$MEMORY_IMAGE" \
    --analysis-dir "$ANALYSIS_DIR" \
    --output-dir   "$REPORTS_DIR" \
    ${FAN_MD:+--fan-summary  "$FAN_MD"} \
    ${FAST_MD:+--fast-summary "$FAST_MD"}

# ── Combined report (if multiple modules have run) ────────────────────────────
FAN_EXISTS=0
FAST_EXISTS=0
[[ -f "$REPORTS_DIR/${STEM}_incident_report.md" || -f "$REPORTS_DIR/${STEM}_fan_report.md" ]] && FAN_EXISTS=1
[[ -f "$REPORTS_DIR/${STEM}_fast_report.md" ]] && FAST_EXISTS=1

if [[ $FAN_EXISTS -eq 1 || $FAST_EXISTS -eq 1 ]]; then
    echo "[fame] Other module reports detected — generating combined unified report..."
    python3 "$PROJECT_ROOT/lib/generate_combined_report.py" \
        --case-id    "$CASE_ID" \
        --hostname   "$HOSTNAME_ARG" \
        --reports-dir "$REPORTS_DIR" \
        --output-dir  "$REPORTS_DIR"
fi

# ── Upload to investigations vault ────────────────────────────────────────────
if [[ $SKIP_UPLOAD -eq 0 ]]; then
    echo "[fame] Uploading reports to investigations vault..."

    MD_PATH="$REPORTS_DIR/${STEM}_fame_report.md"
    PDF_PATH="$REPORTS_DIR/${STEM}_fame_report.pdf"
    PPTX_PATH="$REPORTS_DIR/${STEM}_fame_presentation.pptx"
    DOCX_PATH="$REPORTS_DIR/${STEM}_fame_report.docx"

    UPLOAD_ARGS="--case-id $CASE_ID --md $MD_PATH"
    [[ -f "$PDF_PATH"  ]] && UPLOAD_ARGS+=" --pdf $PDF_PATH"
    [[ -f "$PPTX_PATH" ]] && UPLOAD_ARGS+=" --pptx $PPTX_PATH"
    [[ -f "$DOCX_PATH" ]] && UPLOAD_ARGS+=" --docx $DOCX_PATH"

    python3 "$PROJECT_ROOT/lib/investigations_upload.py" $UPLOAD_ARGS || \
        echo "[fame] WARNING: Upload failed — check SSH connectivity to ubuntudesktop."

    # Upload combined report if generated
    COMBINED_MD="$REPORTS_DIR/${STEM}_combined_report.md"
    if [[ -f "$COMBINED_MD" ]]; then
        COMB_ARGS="--case-id $CASE_ID --md $COMBINED_MD"
        [[ -f "$REPORTS_DIR/${STEM}_combined_report.pdf"  ]] && \
            COMB_ARGS+=" --pdf $REPORTS_DIR/${STEM}_combined_report.pdf"
        [[ -f "$REPORTS_DIR/${STEM}_combined_presentation.pptx" ]] && \
            COMB_ARGS+=" --pptx $REPORTS_DIR/${STEM}_combined_presentation.pptx"
        [[ -f "$REPORTS_DIR/${STEM}_combined_report.docx" ]] && \
            COMB_ARGS+=" --docx $REPORTS_DIR/${STEM}_combined_report.docx"
        python3 "$PROJECT_ROOT/lib/investigations_upload.py" $COMB_ARGS || \
            echo "[fame] WARNING: Combined report upload failed."
    fi
else
    echo "[fame] Upload skipped (--no-upload)."
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  FAME Analysis Complete                                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Case ID  : $CASE_ID"
echo "  Host     : $HOSTNAME_ARG"
echo ""
echo "  Reports:"
for ext in md pdf pptx docx; do
    f="$REPORTS_DIR/${STEM}_fame_report.$ext"
    [[ "$ext" == "pptx" ]] && f="$REPORTS_DIR/${STEM}_fame_presentation.pptx"
    [[ -f "$f" ]] && echo "    $ext  → $f"
done
[[ -f "$REPORTS_DIR/${STEM}_combined_report.md" ]] && \
    echo "    combined → $REPORTS_DIR/${STEM}_combined_report.md"
echo ""
echo "  Analysis : $ANALYSIS_DIR/"
echo ""
echo "  Next steps:"
echo "    1. Review $REPORTS_DIR/${STEM}_fame_report.md"
echo "    2. Review super-timeline: $ANALYSIS_DIR/autotimeliner/supertimeline.csv"
echo "    3. Review recovered events: $ANALYSIS_DIR/evtxtract/recovered_events.xml"
echo "    4. Run /fan-opencti-lookup for CTI enrichment"
echo "    5. Run /fast to analyse the disk image if not yet done"
echo "    6. Record confirmed findings: /obsidian-record"
echo ""
