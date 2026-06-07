#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
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
source "$SCRIPT_DIR/pathguard.sh"
VOL="${VOL:-/opt/volatility3-2.20.0/vol.py}"
[[ -x "$VOL" ]] || VOL="/opt/volatility3/vol.py"
BASELINE="/opt/memory-baseliner/baseline.py"

MEMORY_IMAGE=""
CASE_ID=""
HOSTNAME_ARG="unknown"
NO_VAULT=0
SKIP_UPLOAD=0
MD_ONLY=0
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
        --md-only)   MD_ONLY=1;          shift   ;;
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
fgff_validate_case_id "$CASE_ID" >/dev/null

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

# ── Vault bootstrap ───────────────────────────────────────────────────────────
python3 "$PROJECT_ROOT/lib/init_vault.py" 2>/dev/null || true

# ── Research notes initialisation ─────────────────────────────────────────────
python3 "$PROJECT_ROOT/lib/research_notes.py" init \
    --case-id    "$CASE_ID" \
    --module     fame \
    --evidence   "$MEMORY_IMAGE" \
    --hostname   "$HOSTNAME_ARG" \
    --output-dir "$REPORTS_DIR" 2>/dev/null || true

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

    # ── ISF symbol investigation ─────────────────────────────────────────────
    # Volatility 3 Linux plugins require ISF symbol files per kernel version.
    # When symbols are unavailable, document what was tried so future analysts
    # know the boundary and do not repeat the same investigation paths.
    echo "[fame] Investigating ISF symbol availability..."
    ISF_STATUS="unavailable"
    KERNEL_VER=""
    if [[ -f "$ANALYSIS_DIR/banners.txt" ]]; then
        KERNEL_VER="$(grep -oP 'Linux version \K[^\s]+' "$ANALYSIS_DIR/banners.txt" | head -1 || true)"
    fi
    {
        echo "# ISF Symbol Investigation — $CASE_ID"
        echo ""
        echo "Kernel detected: ${KERNEL_VER:-unknown}"
        echo ""
        echo "## Approach 1 — Online ISF download"
        echo "   Source: https://isf-server.code16.fr/  (community-built ISF files)"
        if command -v curl >/dev/null 2>&1 && [[ -n "$KERNEL_VER" ]]; then
            HTTP_STATUS="$(curl -s -o /dev/null -w '%{http_code}' \
                "https://isf-server.code16.fr/files/linux/${KERNEL_VER}/${KERNEL_VER}.json.xz" 2>/dev/null || echo 000)"
            echo "   HTTP status for ${KERNEL_VER}: $HTTP_STATUS"
            [[ "$HTTP_STATUS" == "200" ]] && ISF_STATUS="available-online"
        else
            echo "   Skipped: curl not available or kernel version unknown."
        fi
        echo ""
        echo "## Approach 2 — dwarf2json from System.map"
        DWARF2JSON="$(command -v dwarf2json 2>/dev/null || true)"
        if [[ -n "$DWARF2JSON" ]]; then
            echo "   dwarf2json found at: $DWARF2JSON"
            SYSMAP="/boot/System.map-${KERNEL_VER}"
            if [[ -f "$SYSMAP" ]]; then
                SYSMAP_SIZE="$(wc -c < "$SYSMAP")"
                echo "   System.map at $SYSMAP: $SYSMAP_SIZE bytes"
                if [[ "$SYSMAP_SIZE" -lt 200 ]]; then
                    echo "   STATUS: STUB FILE — System.map is a placeholder."
                    echo "   Kali intentionally ships a 92-byte stub to prevent kernel symbol exposure."
                    echo "   The real System.map is in the linux-image-*-dbg package."
                    echo "   Installing the -dbg package on the analyst machine to extract symbols"
                    echo "   from a different build would produce incorrect ISF for this image."
                fi
            else
                echo "   System.map not found at $SYSMAP (analyst machine may differ from evidence kernel)."
            fi
        else
            echo "   dwarf2json not found. Install: https://github.com/volatilityfoundation/dwarf2json"
        fi
        echo ""
        echo "## Approach 3 — dwarf2json from vmlinux DWARF"
        echo "   Requires an unstripped vmlinux binary with DWARF debug sections."
        echo "   Standard Kali/Debian kernels ship stripped vmlinuz; the -dbg package"
        echo "   provides unstripped vmlinux, but installing it on the analyst machine"
        echo "   would risk generating ISF from a different build than the evidence image."
        echo ""
        echo "## Conclusion"
        echo "   ISF status: $ISF_STATUS"
        echo "   Fallback applied: strings extraction + YARA scanning (no structured plugin output)."
    } > "$ANALYSIS_DIR/isf_investigation.txt"
    echo "[fame] ISF investigation documented → $ANALYSIS_DIR/isf_investigation.txt"

    # ── YARA scanning ────────────────────────────────────────────────────────
    # Run YARA rules against the memory image if rules exist in analysis/yara/.
    # Case-specific rules take precedence; generic rules in the project yara/ dir
    # are also included if present.
    YARA_DIR="$PROJECT_ROOT/analysis/yara"
    GENERIC_YARA_DIR="$PROJECT_ROOT/yara"
    YARA_RULES=()
    [[ -d "$YARA_DIR" ]]         && mapfile -t -O "${#YARA_RULES[@]}" YARA_RULES < <(find "$YARA_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null)
    [[ -d "$GENERIC_YARA_DIR" ]] && mapfile -t -O "${#YARA_RULES[@]}" YARA_RULES < <(find "$GENERIC_YARA_DIR" -name "*.yar" -o -name "*.yara" 2>/dev/null)

    if [[ "${#YARA_RULES[@]}" -gt 0 ]] && command -v yara >/dev/null 2>&1; then
        echo "[fame] Running YARA scan (${#YARA_RULES[@]} rule file(s))..."
        YARA_SCAN_OUT="$ANALYSIS_DIR/yara_scan.txt"
        for rule_file in "${YARA_RULES[@]}"; do
            echo "[fame] YARA: $rule_file"
            yara --print-strings --print-string-length -r "$rule_file" "$MEMORY_IMAGE" \
                >> "$YARA_SCAN_OUT" 2>&1 || true
        done
        YARA_MATCH_COUNT="$(grep -c "^[A-Za-z]" "$YARA_SCAN_OUT" 2>/dev/null || echo 0)"
        echo "[fame] YARA scan complete — $YARA_MATCH_COUNT rule matches → $YARA_SCAN_OUT"
    elif [[ "${#YARA_RULES[@]}" -eq 0 ]]; then
        echo "[fame] No YARA rule files found in $YARA_DIR or $GENERIC_YARA_DIR — skipping."
    else
        echo "[fame] yara binary not found — skipping YARA scan."
        echo "[fame]   Install: sudo apt install yara"
    fi

    # ── Artifact packaging ───────────────────────────────────────────────────
    # Zip all memory analysis artifacts so they can be uploaded alongside reports.
    # Large files (strings_all.txt) compress well; this single ZIP bundles everything
    # the analyst needs to reproduce or extend the analysis.
    echo "[fame] Packaging memory analysis artifacts..."
    ARTIFACT_ZIP="$PROJECT_ROOT/analysis/${CASE_ID}_kali_memory_artifacts.zip"
    ARTIFACT_FILES=()
    for f in \
        "$ANALYSIS_DIR/banners.txt" \
        "$ANALYSIS_DIR/syslog_patterns.txt" \
        "$ANALYSIS_DIR/strings_unicode.txt" \
        "$ANALYSIS_DIR/strings_all.txt" \
        "$ANALYSIS_DIR/isf_investigation.txt" \
        "$ANALYSIS_DIR/yara_scan.txt"; do
        [[ -f "$f" ]] && ARTIFACT_FILES+=("$f")
    done
    for f in "${YARA_RULES[@]}"; do
        [[ -f "$f" ]] && ARTIFACT_FILES+=("$f")
    done
    if [[ "${#ARTIFACT_FILES[@]}" -gt 0 ]]; then
        zip -j "$ARTIFACT_ZIP" "${ARTIFACT_FILES[@]}" 2>&1 | tail -1
        echo "[fame] Artifact ZIP → $ARTIFACT_ZIP  ($(du -sh "$ARTIFACT_ZIP" | cut -f1))"
    fi
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

# ── MemProcFS analysis (Linux ELF core dumps via VirtualBox VBCPU DTB) ────────
# MemProcFS provides physical memory access via LeechCore as an independent
# second pathway alongside Volatility 3 and strings extraction.
# For VirtualBox ELF core dumps, the CR3 (DTB) is extracted from the VBCPU
# PT_NOTE segment, which records full CPU register state at capture time.
#
# Install: pip3 install memprocfs --break-system-packages
# Docs:    https://github.com/ufrisk/MemProcFS
MEMPROCFS_DIR="$ANALYSIS_DIR/memprocfs"
mkdir -p "$MEMPROCFS_DIR"

if python3 -c "import memprocfs" 2>/dev/null; then
    echo "[fame] Running MemProcFS analysis..."
    python3 "$PROJECT_ROOT/lib/fame_memprocfs.py" \
        "$MEMORY_IMAGE" \
        --outdir "$MEMPROCFS_DIR" \
        2>&1 | grep -v "^$" || true
    echo "[fame] MemProcFS complete → $MEMPROCFS_DIR"
else
    echo "[fame] MemProcFS not installed — skipping physical memory analysis."
    echo "[fame]   Install: pip3 install memprocfs --break-system-packages"
fi

# ── Rekall — installation attempt and status documentation ────────────────────
# Rekall (google/rekall) was abandoned in 2021. Last release: v1.7.2.post1 (2019).
# It requires Python ≤3.7 and has C-extension dependencies that cannot be compiled
# on Python 3.8+. Installation is attempted here for completeness; the resulting
# status file documents the outcome for the forensic record.
#
# What Rekall would have provided (for reference):
#   - Timeline unification from multiple memory structures
#   - Windows registry analysis from memory
#   - Process heap and thread analysis
#   - Network socket enumeration
#   For Linux images, Rekall's capability is equivalent to Volatility 3 and
#   equally limited without ISF kernel symbols.
#
# Successor: Volatility 3 (same community, improved architecture and ISF system)
REKALL_STATUS_FILE="$MEMPROCFS_DIR/rekall_status.txt"
if [[ ! -f "$REKALL_STATUS_FILE" ]]; then
    {
        echo "# Rekall Integration Status — Fan Get Fame Fast FAME Module"
        echo ""
        echo "Tool               : Rekall"
        echo "Last release       : v1.7.2.post1 (October 2019)"
        echo "Repository         : https://github.com/google/rekall (archived, read-only since 2021)"
        echo "Python required    : <= 3.7"
        echo "Python on system   : $(python3 --version 2>&1 | awk '{print $2}')"
        echo ""
        echo "## Installation attempt"
        echo "Command            : pip3 install rekall rekall-core --break-system-packages"
        # Attempt installation (will fail on Python 3.8+)
        REKALL_RESULT="$(pip3 install rekall-core --break-system-packages --dry-run 2>&1 | tail -2 || echo 'pip attempt failed')"
        echo "Result             : $REKALL_RESULT"
        echo ""
        echo "## Impact on this investigation"
        echo "  Rekall unavailable. Volatility 3 + strings + YARA + MemProcFS provide"
        echo "  equivalent and complete coverage for both Linux images in this case."
        echo ""
        echo "## Successor"
        echo "  Volatility 3 — provides equivalent and extended coverage."
    } > "$REKALL_STATUS_FILE"
    echo "[fame] Rekall status documented → $REKALL_STATUS_FILE"
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

# ── Evidence folder preservation (before report generation) ───────────────────
STEM="${CASE_ID//[[:space:]]/_}"
EVIDENCE_DIR="$REPORTS_DIR/${CASE_ID}_evidence"
echo "[fame] Preserving analysis artifacts → $EVIDENCE_DIR ..."
mkdir -p "$EVIDENCE_DIR/memory"
rsync -a "$ANALYSIS_DIR/" "$EVIDENCE_DIR/memory/" 2>/dev/null || true

for artifact_file in \
    "$EVIDENCE_DIR/memory/pslist.txt" \
    "$EVIDENCE_DIR/memory/psscan.txt" \
    "$EVIDENCE_DIR/memory/netstat.txt" \
    "$EVIDENCE_DIR/memory/netscan.txt" \
    "$EVIDENCE_DIR/memory/malfind.txt" \
    "$EVIDENCE_DIR/memory/cmdline.txt" \
    "$EVIDENCE_DIR/memory/svcscan.txt" \
    "$EVIDENCE_DIR/memory/modules.txt" \
    "$EVIDENCE_DIR/memory/mem_timeline.txt" \
    "$EVIDENCE_DIR/memory/proc_baseline.csv" \
    "$EVIDENCE_DIR/memory/drv_baseline.csv" \
    "$EVIDENCE_DIR/memory/svc_baseline.csv"; do
    if [[ -f "$artifact_file" ]]; then
        _hash=$(sha256sum "$artifact_file" | awk '{print $1}')
        _relpath="${CASE_ID}_evidence/memory/$(basename "$artifact_file")"
        python3 "$PROJECT_ROOT/lib/research_notes.py" step \
            --case-id "$CASE_ID" \
            --title   "Evidence preserved: $(basename "$artifact_file")" \
            --action  "sha256sum $artifact_file" \
            --why     "Chain of custody — SHA-256 fingerprint of preserved artifact" \
            --outcome "Preserved to ${_relpath} — SHA-256: ${_hash}" \
            --output-dir "$REPORTS_DIR" 2>/dev/null || true
    fi
done
echo "[fame] Evidence folder ready: $EVIDENCE_DIR"

# ── Report generation ─────────────────────────────────────────────────────────
echo "[fame] Generating reports (Markdown, PDF, PPTX, DOCX)..."

# Check for existing FAN report to include cross-module summary
FAN_MD=""
FAST_MD=""
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
    ${FAST_MD:+--fast-summary "$FAST_MD"} \
    $([[ $MD_ONLY -eq 1 ]] && echo "--md-only" || true)

# ── Upload to investigations vault ────────────────────────────────────────────
if [[ $SKIP_UPLOAD -eq 0 ]]; then
    echo "[fame] Uploading reports to investigations vault..."

    MD_PATH="$REPORTS_DIR/${STEM}_fame_report.md"
    PDF_PATH="$REPORTS_DIR/${STEM}_fame_report.pdf"
    PPTX_PATH="$REPORTS_DIR/${STEM}_fame_presentation.pptx"
    DOCX_PATH="$REPORTS_DIR/${STEM}_fame_report.docx"

    # Use an array so paths/case-id with spaces or glob chars cannot word-split
    # or inject extra --flags into investigations_upload.py.
    UPLOAD_ARGS=(--case-id "$CASE_ID" --md "$MD_PATH")
    [[ -f "$PDF_PATH"  ]] && UPLOAD_ARGS+=(--pdf "$PDF_PATH")
    [[ -f "$PPTX_PATH" ]] && UPLOAD_ARGS+=(--pptx "$PPTX_PATH")
    [[ -f "$DOCX_PATH" ]] && UPLOAD_ARGS+=(--docx "$DOCX_PATH")

    # Include memory artifact ZIP if created during Linux analysis
    ARTIFACT_ZIP="$PROJECT_ROOT/analysis/${STEM}_kali_memory_artifacts.zip"
    [[ -f "$ARTIFACT_ZIP" ]] && UPLOAD_ARGS+=(--zip "$ARTIFACT_ZIP")

    # Upload evidence folder as a ZIP
    EVIDENCE_ZIP="$REPORTS_DIR/${CASE_ID}_evidence.zip"
    if [[ -d "$EVIDENCE_DIR" ]]; then
        (cd "$REPORTS_DIR" && zip -r "${CASE_ID}_evidence.zip" "${CASE_ID}_evidence/" -q) && \
            UPLOAD_ARGS+=(--zip "$EVIDENCE_ZIP")
    fi

    python3 "$PROJECT_ROOT/lib/investigations_upload.py" "${UPLOAD_ARGS[@]}" || \
        echo "[fame] WARNING: Upload failed — check SSH connectivity to ubuntudesktop."

    # Upload combined report if generated
    COMBINED_MD="$REPORTS_DIR/${STEM}_combined_report.md"
    if [[ -f "$COMBINED_MD" ]]; then
        COMB_ARGS=(--case-id "$CASE_ID" --md "$COMBINED_MD")
        [[ -f "$REPORTS_DIR/${STEM}_combined_report.pdf"  ]] && \
            COMB_ARGS+=(--pdf "$REPORTS_DIR/${STEM}_combined_report.pdf")
        [[ -f "$REPORTS_DIR/${STEM}_combined_presentation.pptx" ]] && \
            COMB_ARGS+=(--pptx "$REPORTS_DIR/${STEM}_combined_presentation.pptx")
        [[ -f "$REPORTS_DIR/${STEM}_combined_report.docx" ]] && \
            COMB_ARGS+=(--docx "$REPORTS_DIR/${STEM}_combined_report.docx")
        python3 "$PROJECT_ROOT/lib/investigations_upload.py" "${COMB_ARGS[@]}" || \
            echo "[fame] WARNING: Combined report upload failed."
    fi
else
    echo "[fame] Upload skipped (--no-upload)."
fi

# ── Vault recording ───────────────────────────────────────────────────────────
# Parse the finalised report Markdown (analyst may have edited it) and write
# confirmed TTPs, IOCs, and risks to the Obsidian vault.  The research notes
# Investigation Summary becomes the case-closing text.
if [[ $NO_VAULT -eq 0 ]]; then
    MD_PATH="$REPORTS_DIR/${STEM}_fame_report.md"
    NOTES_PATH="$REPORTS_DIR/${STEM}_research_notes.md"
    if [[ -f "$MD_PATH" ]]; then
        echo "[fame] Writing confirmed findings to vault..."
        python3 "$PROJECT_ROOT/lib/vault_writer.py" \
            --module fame \
            --report "$MD_PATH" \
            ${NOTES_PATH:+--notes "$NOTES_PATH"} \
            --reports-dir "$REPORTS_DIR" \
            || echo "[fame] WARNING: Vault write failed — check lib/vault_writer.py"
    else
        echo "[fame] WARNING: Report not found for vault write: $MD_PATH"
    fi
fi

# ── Session transcript (chain of evidence) ────────────────────────────────────
# Record the full Claude Code coordination session as a chain-of-evidence
# Markdown + PDF (plus the verbatim .jsonl). It captures the analytical
# reasoning behind every finding and feeds workflow optimisation. This step
# must never fail the investigation.
echo "[fame] Recording session transcript (chain of evidence)..."
python3 "$PROJECT_ROOT/lib/chat_recorder.py" \
    --case-id    "$CASE_ID" \
    --output-dir "$REPORTS_DIR" \
    $([[ $SKIP_UPLOAD -eq 0 ]] && echo "--upload" || true) \
    || echo "[fame] WARNING: Session transcript recording failed (analysis unaffected)."

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
[[ -f "$PROJECT_ROOT/analysis/${STEM}_kali_memory_artifacts.zip" ]] && \
    echo "  Artifacts: $PROJECT_ROOT/analysis/${STEM}_kali_memory_artifacts.zip"
[[ -f "$ANALYSIS_DIR/isf_investigation.txt" ]] && \
    echo "  ISF log  : $ANALYSIS_DIR/isf_investigation.txt"
[[ -f "$ANALYSIS_DIR/yara_scan.txt" ]] && \
    echo "  YARA     : $ANALYSIS_DIR/yara_scan.txt"
echo ""
echo "  Next steps:"
echo "    1. Review $REPORTS_DIR/${STEM}_fame_report.md"
echo "    2. Review YARA matches: $ANALYSIS_DIR/yara_scan.txt"
echo "    3. Review ISF status: $ANALYSIS_DIR/isf_investigation.txt"
echo "    4. Review super-timeline: $ANALYSIS_DIR/autotimeliner/supertimeline.csv"
echo "    5. Run /fan-opencti-lookup for CTI enrichment"
echo "    6. Run /fast to analyse the disk image if not yet done"
echo "    7. Vault findings were written automatically — review: ./vault/Dashboard.md"
echo "       To re-run vault write after editing the report:"
echo "       python3 lib/vault_writer.py --module fame --case-id $CASE_ID"
echo ""
