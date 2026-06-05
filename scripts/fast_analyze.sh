#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# fast_analyze.sh — FAST (Forensic Analysis Storage) orchestration script.
#
# Mounts and analyses a disk image using The Sleuth Kit / EWF tools, generates
# Markdown + PDF + PPTX + DOCX reports, checks for existing FAN / FAME data
# in the same case folder, triggers a combined report when found, and uploads
# all artefacts to the investigations vault via MCP.
#
# Usage:
#   ./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001
#   ./scripts/fast_analyze.sh /path/to/image.vmdk --case-id FAST-2026-001 --hostname SERVER1234
#   ./scripts/fast_analyze.sh /path/to/image.E01  --case-id FAST-2026-001 --no-vault
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

DISK_IMAGE=""
CASE_ID=""
HOSTNAME_ARG="unknown"
NO_VAULT=0
SKIP_UPLOAD=0
SKIP_MOUNT=0
MD_ONLY=0
ANALYSIS_DIR="$PROJECT_ROOT/analysis/storage"
EXPORTS_DIR="$PROJECT_ROOT/exports"
REPORTS_DIR="$PROJECT_ROOT/reports"
EWF_MOUNT="/mnt/ewf"
FS_MOUNT="/mnt/windows_mount"
NBD_DEV=""
NBD_CONNECTED=0

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --case-id)    CASE_ID="$2";       shift 2 ;;
        --hostname)   HOSTNAME_ARG="$2";  shift 2 ;;
        --no-vault)   NO_VAULT=1;         shift   ;;
        --no-upload)  SKIP_UPLOAD=1;      shift   ;;
        --no-mount)   SKIP_MOUNT=1;       shift   ;;
        --md-only)    MD_ONLY=1;          shift   ;;
        -*)
            echo "[fast] Unknown option: $1" >&2
            exit 1
            ;;
        *)
            DISK_IMAGE="$1"
            shift
            ;;
    esac
done

if [[ -z "$DISK_IMAGE" ]]; then
    echo "[fast] ERROR: No disk image specified." >&2
    echo "Usage: $0 /path/to/image.E01 --case-id CASE-2026-001" >&2
    exit 1
fi

if [[ ! -f "$DISK_IMAGE" ]]; then
    echo "[fast] ERROR: Disk image not found: $DISK_IMAGE" >&2
    exit 1
fi

if [[ -z "$CASE_ID" ]]; then
    echo -n "[fast] Case ID (e.g. FAST-2026-001): "
    read -r CASE_ID
fi
fgff_validate_case_id "$CASE_ID" >/dev/null

if [[ "$HOSTNAME_ARG" == "unknown" ]]; then
    HOSTNAME_ARG="$(basename "$DISK_IMAGE" | sed 's/\.[^.]*$//')"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  FAST — Forensic Analysis Storage                                ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Image    : $DISK_IMAGE"
echo "  Case ID  : $CASE_ID"
echo "  Hostname : $HOSTNAME_ARG"
echo ""

# ── Research notes initialisation ─────────────────────────────────────────────
python3 "$PROJECT_ROOT/lib/research_notes.py" init \
    --case-id    "$CASE_ID" \
    --module     fast \
    --evidence   "$DISK_IMAGE" \
    --hostname   "$HOSTNAME_ARG" \
    --output-dir "$REPORTS_DIR" 2>/dev/null || true

# ── Directory setup ───────────────────────────────────────────────────────────
mkdir -p \
    "$ANALYSIS_DIR" \
    "$EXPORTS_DIR/files" \
    "$EXPORTS_DIR/registry" \
    "$EXPORTS_DIR/evtx" \
    "$EXPORTS_DIR/prefetch" \
    "$EXPORTS_DIR/mft" \
    "$EXPORTS_DIR/srum" \
    "$EXPORTS_DIR/browser" \
    "$EXPORTS_DIR/carved" \
    "$EXPORTS_DIR/tsk_recover" \
    "$EXPORTS_DIR/recyclebin" \
    "$EXPORTS_DIR/autopsy" \
    "$REPORTS_DIR"

# ── Helper functions ──────────────────────────────────────────────────────────
_cleanup_local_artifacts() {
    echo "[fast] Removing local analysis artifacts..."
    sudo find "$ANALYSIS_DIR" -mindepth 1 ! -name '.fast_session.json' -delete 2>/dev/null || true
    sudo find "$EXPORTS_DIR"  -mindepth 1 -delete 2>/dev/null || true
    echo "[fast] Local artifacts removed."
}

_upload_reports() {
    local cid="$1"
    local stem="${cid//[[:space:]]/_}"
    local md="$REPORTS_DIR/${stem}_fast_report.md"
    [[ ! -f "$md" ]] && { echo "[fast] No reports found for case $cid — skipping upload."; return 0; }
    local args="--case-id $cid --md $md"
    [[ -f "$REPORTS_DIR/${stem}_fast_report.pdf"        ]] && args+=" --pdf  $REPORTS_DIR/${stem}_fast_report.pdf"
    [[ -f "$REPORTS_DIR/${stem}_fast_presentation.pptx" ]] && args+=" --pptx $REPORTS_DIR/${stem}_fast_presentation.pptx"
    [[ -f "$REPORTS_DIR/${stem}_fast_report.docx"       ]] && args+=" --docx $REPORTS_DIR/${stem}_fast_report.docx"
    python3 "$PROJECT_ROOT/lib/investigations_upload.py" $args \
        || echo "[fast] WARNING: Upload for case $cid failed."
}

# ── Session guard: upload + clean when switching evidence ─────────────────────
SESSION_FILE="$ANALYSIS_DIR/.fast_session.json"

if [[ -f "$SESSION_FILE" ]]; then
    PREV_IMAGE="$(python3 -c "import json; print(json.load(open('$SESSION_FILE')).get('disk_image',''))" 2>/dev/null || true)"
    PREV_CASE="$(python3  -c "import json; print(json.load(open('$SESSION_FILE')).get('case_id',''))"   2>/dev/null || true)"
    if [[ -n "$PREV_IMAGE" && "$PREV_IMAGE" != "$DISK_IMAGE" ]]; then
        echo "[fast] Evidence switch detected (previous: $(basename "$PREV_IMAGE"))."
        if [[ $SKIP_UPLOAD -eq 0 ]]; then
            echo "[fast] Uploading artifacts from previous investigation (case: $PREV_CASE)..."
            _upload_reports "$PREV_CASE"
        fi
        _cleanup_local_artifacts
    fi
fi

printf '{"case_id":"%s","hostname":"%s","disk_image":"%s","started":"%s"}\n' \
    "$CASE_ID" "$HOSTNAME_ARG" "$DISK_IMAGE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$SESSION_FILE"

# ── Image verification ────────────────────────────────────────────────────────
IMAGE_EXT="${DISK_IMAGE##*.}"
IMAGE_EXT_LOWER="${IMAGE_EXT,,}"

echo "[fast] Verifying image..."
if [[ "$IMAGE_EXT_LOWER" == "e01" ]] || [[ "$IMAGE_EXT_LOWER" == "ewf" ]]; then
    ewfinfo  "$DISK_IMAGE" > "$ANALYSIS_DIR/ewfinfo.txt"  2>&1 || true
    ewfverify "$DISK_IMAGE" > "$ANALYSIS_DIR/ewfverify.txt" 2>&1 || true
    echo "[fast] ewfinfo → $ANALYSIS_DIR/ewfinfo.txt"
    echo "[fast] ewfverify → $ANALYSIS_DIR/ewfverify.txt"
else
    img_stat "$DISK_IMAGE" > "$ANALYSIS_DIR/img_stat.txt" 2>&1 || true
    echo "[fast] img_stat → $ANALYSIS_DIR/img_stat.txt"
fi

# ── Mount image ───────────────────────────────────────────────────────────────
MOUNTED_FS=0
if [[ $SKIP_MOUNT -eq 0 ]]; then
    mkdir -p "$EWF_MOUNT" "$FS_MOUNT" 2>/dev/null || sudo mkdir -p "$EWF_MOUNT" "$FS_MOUNT" 2>/dev/null || true

    if [[ "$IMAGE_EXT_LOWER" == "e01" ]] || [[ "$IMAGE_EXT_LOWER" == "ewf" ]]; then
        echo "[fast] Mounting E01 via ewfmount..."
        sudo ewfmount "$DISK_IMAGE" "$EWF_MOUNT"/ || { echo "[fast] WARNING: ewfmount failed"; SKIP_MOUNT=1; }
        RAW_DEVICE="$EWF_MOUNT/ewf1"
    elif [[ "$IMAGE_EXT_LOWER" =~ ^(vdi|vmdk|qcow2|vhd|vhdx)$ ]]; then
        echo "[fast] VM image ($IMAGE_EXT_LOWER) — exposing via qemu-nbd..."
        sudo modprobe nbd max_part=8 2>/dev/null || true
        for _nbd in /dev/nbd{0..15}; do
            _sz="$(lsblk -n -o SIZE "$_nbd" 2>/dev/null | tr -d ' ')"
            if [[ "$_sz" == "" || "$_sz" == "0B" || "$_sz" == "0" ]]; then
                NBD_DEV="$_nbd"; break
            fi
        done
        if [[ -z "$NBD_DEV" ]]; then
            echo "[fast] ERROR: No free NBD device — is qemu-utils installed?" >&2
            exit 1
        fi
        sudo qemu-nbd --connect="$NBD_DEV" "$DISK_IMAGE"
        NBD_CONNECTED=1
        sleep 2
        sudo partprobe "$NBD_DEV" 2>/dev/null || true
        echo "[fast] Exposed as $NBD_DEV"
        RAW_DEVICE="$NBD_DEV"
    else
        RAW_DEVICE="$DISK_IMAGE"
    fi

    if [[ $SKIP_MOUNT -eq 0 ]]; then
        # Inspect partition table
        sudo mmls "$RAW_DEVICE" > "$ANALYSIS_DIR/mmls.txt" 2>&1 || true
        echo "[fast] mmls → $ANALYSIS_DIR/mmls.txt"

        # Detect sector size
        SECTOR_SIZE=$(sudo img_stat "$RAW_DEVICE" 2>/dev/null | grep -i "Sector Size" | awk '{print $NF}' || echo "512")
        SECTOR_SIZE="${SECTOR_SIZE:-512}"
        echo "[fast] Sector size: $SECTOR_SIZE bytes"

        # Find NTFS/ext partition start sector (largest non-recovery partition)
        START_SECTOR=$(grep -E "NTFS|ext|Linux" "$ANALYSIS_DIR/mmls.txt" 2>/dev/null | \
            awk '{print $3}' | sort -n | head -1 || echo "2048")
        START_SECTOR="${START_SECTOR:-2048}"
        OFFSET=$(( START_SECTOR * SECTOR_SIZE ))
        echo "[fast] Partition start: sector $START_SECTOR (offset $OFFSET bytes)"

        # Mount filesystem read-only
        echo "[fast] Mounting filesystem (read-only)..."
        sudo mount -o ro,loop,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
        sudo mount -o ro,loop,norecovery,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
        { echo "[fast] WARNING: Filesystem mount failed — continuing without mount."; SKIP_MOUNT=2; }

        # Verify the mount really is read-only before any analysis touches it.
        [[ $SKIP_MOUNT -eq 0 ]] && fgff_assert_ro_mount "$FS_MOUNT"
        [[ $SKIP_MOUNT -eq 0 ]] && MOUNTED_FS=1 && echo "[fast] Mounted at $FS_MOUNT (verified read-only)"
    fi
fi

# ── TSK analysis ──────────────────────────────────────────────────────────────
RAW_FOR_TSK="${RAW_DEVICE:-$DISK_IMAGE}"

echo "[fast] Running TSK file listing (fls)..."
sudo fls -r -p "$RAW_FOR_TSK" \
    > "$ANALYSIS_DIR/fls_output.txt" 2>/dev/null || \
sudo fls -r -p -o "${START_SECTOR:-2048}" "$RAW_FOR_TSK" \
    > "$ANALYSIS_DIR/fls_output.txt" 2>/dev/null || \
    echo "[fast] WARNING: fls failed — continuing."
echo "[fast] fls → $ANALYSIS_DIR/fls_output.txt"

echo "[fast] Generating bodyfile (fls -m)..."
sudo fls -r -m / "$RAW_FOR_TSK" \
    > "$ANALYSIS_DIR/bodyfile.txt" 2>/dev/null || \
sudo fls -r -m / -o "${START_SECTOR:-2048}" "$RAW_FOR_TSK" \
    > "$ANALYSIS_DIR/bodyfile.txt" 2>/dev/null || \
    echo "[fast] WARNING: bodyfile generation failed."

echo "[fast] Converting bodyfile to timeline (mactime)..."
mactime -b "$ANALYSIS_DIR/bodyfile.txt" -z UTC \
    > "$EXPORTS_DIR/fs_timeline.txt" 2>/dev/null || true
mactime -b "$ANALYSIS_DIR/bodyfile.txt" -z UTC -d \
    > "$EXPORTS_DIR/fs_timeline.csv" 2>/dev/null || true
echo "[fast] Timeline → $EXPORTS_DIR/fs_timeline.txt"

echo "[fast] Running fsstat..."
sudo fsstat "$RAW_FOR_TSK" > "$ANALYSIS_DIR/fsstat.txt" 2>/dev/null || \
sudo fsstat -o "${START_SECTOR:-2048}" "$RAW_FOR_TSK" > "$ANALYSIS_DIR/fsstat.txt" 2>/dev/null || true

echo "[fast] Running ils (inode listing)..."
sudo ils "$RAW_FOR_TSK" > "$ANALYSIS_DIR/ils_output.txt" 2>/dev/null || true
sudo ils -p "$RAW_FOR_TSK" > "$ANALYSIS_DIR/ils_orphan.txt" 2>/dev/null || true

# ── Artefact extraction (from mounted filesystem) ─────────────────────────────
if [[ $MOUNTED_FS -eq 1 ]]; then
    echo "[fast] Extracting Windows artefacts..."

    # Event logs
    find "$FS_MOUNT/Windows/System32/winevt/Logs/" -name "*.evtx" \
        -exec sudo cp {} "$EXPORTS_DIR/evtx/" \; 2>/dev/null || true

    # Registry hives
    for hive in SYSTEM SOFTWARE SECURITY SAM; do
        sudo cp "$FS_MOUNT/Windows/System32/config/$hive" \
            "$EXPORTS_DIR/registry/" 2>/dev/null || true
    done
    sudo find "$FS_MOUNT/Users/" -name "NTUSER.DAT" \
        -exec sudo cp --parents {} "$EXPORTS_DIR/registry/" \; 2>/dev/null || true
    sudo find "$FS_MOUNT/Users/" -name "UsrClass.dat" \
        -exec sudo cp --parents {} "$EXPORTS_DIR/registry/" \; 2>/dev/null || true

    # Prefetch
    sudo cp -r "$FS_MOUNT/Windows/Prefetch/." "$EXPORTS_DIR/prefetch/" 2>/dev/null || true

    # SRUM
    sudo cp "$FS_MOUNT/Windows/System32/sru/SRUDB.dat" \
        "$EXPORTS_DIR/srum/" 2>/dev/null || true

    # Amcache
    sudo cp "$FS_MOUNT/Windows/AppCompat/Programs/Amcache.hve" \
        "$EXPORTS_DIR/registry/" 2>/dev/null || true

    # Browser history
    sudo find "$FS_MOUNT/Users/" \
        -path "*/Google/Chrome/User Data/Default/History" \
        -exec sudo cp --parents {} "$EXPORTS_DIR/browser/" \; 2>/dev/null || true
    sudo find "$FS_MOUNT/Users/" \
        -path "*/Microsoft/Edge/User Data/Default/History" \
        -exec sudo cp --parents {} "$EXPORTS_DIR/browser/" \; 2>/dev/null || true

    # Recycle Bin
    sudo cp -r "$FS_MOUNT/\$Recycle.Bin/." "$EXPORTS_DIR/recyclebin/" 2>/dev/null || true

    # Scheduled tasks
    sudo cp -r "$FS_MOUNT/Windows/System32/Tasks/." "$EXPORTS_DIR/tasks/" 2>/dev/null || true

    echo "[fast] Artefact extraction complete."
fi

# ── MFT and UsnJrnl via icat ──────────────────────────────────────────────────
echo "[fast] Extracting MFT (\$MFT, inode 0)..."
sudo icat "$RAW_FOR_TSK" 0 > "$EXPORTS_DIR/mft/\$MFT" 2>/dev/null || \
sudo icat -o "${START_SECTOR:-2048}" "$RAW_FOR_TSK" 0 > "$EXPORTS_DIR/mft/\$MFT" 2>/dev/null || \
    echo "[fast] WARNING: MFT extraction failed."

echo "[fast] Extracting USN Change Journal (\$J, inode 11)..."
sudo icat "$RAW_FOR_TSK" 11-128-4 > "$EXPORTS_DIR/mft/\$J" 2>/dev/null || \
sudo icat "$RAW_FOR_TSK" 11 > "$EXPORTS_DIR/mft/\$J" 2>/dev/null || \
    echo "[fast] WARNING: USN journal extraction failed."

# ── File hash manifest ────────────────────────────────────────────────────────
if [[ -d "$EXPORTS_DIR/files" ]] && [[ "$(ls -A "$EXPORTS_DIR/files" 2>/dev/null)" ]]; then
    find "$EXPORTS_DIR/files/" -type f \
        -exec md5sum {} \; > "$EXPORTS_DIR/files/md5_manifest.txt" 2>/dev/null || true
    echo "[fast] MD5 manifest → $EXPORTS_DIR/files/md5_manifest.txt"
fi

# ── Bulk extractor carving (on a size budget — skip if image > 20 GB) ─────────
IMAGE_SIZE=$(stat -c%s "$DISK_IMAGE" 2>/dev/null || echo "0")
if [[ "$IMAGE_SIZE" -lt 21474836480 ]]; then
    echo "[fast] Running bulk_extractor..."
    rm -rf "$EXPORTS_DIR/carved" && mkdir -p "$EXPORTS_DIR/carved"
    sudo bulk_extractor -o "$EXPORTS_DIR/carved" -j 4 \
        "$RAW_FOR_TSK" 2>/dev/null || \
        echo "[fast] WARNING: bulk_extractor failed — continuing."
else
    echo "[fast] Image > 20 GB — skipping bulk_extractor (run manually if needed)."
fi

# ── Autopsy headless analysis ─────────────────────────────────────────────────
# Locate the Autopsy binary (multiple installation paths on SIFT / Ubuntu).
AUTOPSY_BIN=""
for candidate in \
    /opt/autopsy/bin/autopsy \
    /usr/share/autopsy/bin/autopsy \
    /usr/local/bin/autopsy \
    "$(command -v autopsy 2>/dev/null)"; do
    # Require Java-based Autopsy 4.x (supports --createCase); skip Perl v2.x
    [[ -x "$candidate" ]] && "$candidate" --help 2>&1 | grep -q -- "--createCase" \
        && { AUTOPSY_BIN="$candidate"; break; }
done

AUTOPSY_OUT="$EXPORTS_DIR/autopsy"
mkdir -p "$AUTOPSY_OUT"

if [[ -n "$AUTOPSY_BIN" ]]; then
    echo "[fast] Running Autopsy headless analysis ($AUTOPSY_BIN)..."
    AUTOPSY_CASE_DIR="$AUTOPSY_OUT/case"
    mkdir -p "$AUTOPSY_CASE_DIR"

    # Autopsy 4.x headless: create a case, add the image, run ingest modules.
    # The --ingestModules flag accepts a comma-separated list of module names.
    "$AUTOPSY_BIN" \
        --nosplash \
        --nogui \
        --createCase "FAST_${CASE_ID}" \
        --caseDir    "$AUTOPSY_CASE_DIR" \
        --addImage   "$RAW_FOR_TSK" \
        --ingestModules \
            "org.sleuthkit.autopsy.modules.fileextmismatch.FileExtMismatchDetectorModuleFactory,\
org.sleuthkit.autopsy.modules.hashdatabase.HashLookupModuleFactory,\
org.sleuthkit.autopsy.modules.recentactivity.RecentActivityExtracterModuleFactory,\
org.sleuthkit.autopsy.timeline.TimeLineModuleFactory,\
org.sleuthkit.autopsy.modules.exif.ExifParserModuleFactory,\
org.sleuthkit.autopsy.keywordsearch.KeywordSearchModuleFactory" \
        2> "$AUTOPSY_OUT/autopsy.log" || {
        echo "[fast] WARNING: Autopsy exited with errors — see $AUTOPSY_OUT/autopsy.log"
    }

    # Export Autopsy results to CSV / text where possible.
    if [[ -d "$AUTOPSY_CASE_DIR" ]]; then
        find "$AUTOPSY_CASE_DIR" \
            \( -name "*.csv" -o -name "*.txt" -o -name "*.html" \) \
            -exec cp {} "$AUTOPSY_OUT/" \; 2>/dev/null || true
        echo "[fast] Autopsy case → $AUTOPSY_CASE_DIR"
        echo "[fast] Autopsy exports → $AUTOPSY_OUT/"
    fi
else
    echo "[fast] Autopsy not found — skipping."
    echo "[fast]   Install: sudo apt-get install autopsy"
    echo "[fast]             or download from https://www.autopsy.com/download/"
    echo "autopsy_not_available" > "$AUTOPSY_OUT/AUTOPSY_NOT_RUN.txt"
fi

# ── Unmount ───────────────────────────────────────────────────────────────────
if [[ $MOUNTED_FS -eq 1 ]]; then
    echo "[fast] Unmounting filesystem..."
    sudo umount "$FS_MOUNT" 2>/dev/null || true
fi
if [[ "$IMAGE_EXT_LOWER" == "e01" ]] || [[ "$IMAGE_EXT_LOWER" == "ewf" ]]; then
    sudo umount "$EWF_MOUNT" 2>/dev/null || true
fi
if [[ $NBD_CONNECTED -eq 1 ]]; then
    echo "[fast] Disconnecting qemu-nbd ($NBD_DEV)..."
    sudo qemu-nbd --disconnect "$NBD_DEV" 2>/dev/null || true
    NBD_CONNECTED=0
fi

# ── Evidence folder preservation (before report generation) ───────────────────
STEM="${CASE_ID//[[:space:]]/_}"
EVIDENCE_DIR="$REPORTS_DIR/${CASE_ID}_evidence"
echo "[fast] Preserving analysis artifacts → $EVIDENCE_DIR ..."
mkdir -p "$EVIDENCE_DIR/storage" "$EVIDENCE_DIR/exports"
rsync -a "$ANALYSIS_DIR/" "$EVIDENCE_DIR/storage/" 2>/dev/null || true
rsync -a "$EXPORTS_DIR/"  "$EVIDENCE_DIR/exports/"  2>/dev/null || true

for artifact_file in \
    "$EVIDENCE_DIR/storage/ewfinfo.txt" \
    "$EVIDENCE_DIR/storage/mmls.txt" \
    "$EVIDENCE_DIR/storage/fsstat.txt" \
    "$EVIDENCE_DIR/storage/fls_output.txt" \
    "$EVIDENCE_DIR/storage/bodyfile.txt" \
    "$EVIDENCE_DIR/exports/fs_timeline.csv"; do
    if [[ -f "$artifact_file" ]]; then
        _hash=$(sha256sum "$artifact_file" | awk '{print $1}')
        _relname="${CASE_ID}_evidence/$(realpath --relative-to="$EVIDENCE_DIR/.." "$artifact_file")"
        python3 "$PROJECT_ROOT/lib/research_notes.py" step \
            --case-id "$CASE_ID" \
            --title   "Evidence preserved: $(basename "$artifact_file")" \
            --action  "sha256sum $artifact_file" \
            --why     "Chain of custody — SHA-256 fingerprint of preserved artifact" \
            --outcome "Preserved to ${_relname} — SHA-256: ${_hash}" \
            --output-dir "$REPORTS_DIR" 2>/dev/null || true
    fi
done
echo "[fast] Evidence folder ready: $EVIDENCE_DIR"

# ── Report generation ─────────────────────────────────────────────────────────
echo "[fast] Generating reports (Markdown, PDF, PPTX, DOCX)..."
FAN_MD=""
FAME_MD=""
[[ -f "$REPORTS_DIR/${STEM}_incident_report.md" ]] && \
    FAN_MD="$(head -60 "$REPORTS_DIR/${STEM}_incident_report.md")"
[[ -f "$REPORTS_DIR/${STEM}_fame_report.md" ]] && \
    FAME_MD="$(head -60 "$REPORTS_DIR/${STEM}_fame_report.md")"

python3 "$PROJECT_ROOT/lib/generate_fast_report.py" \
    --case-id      "$CASE_ID" \
    --hostname     "$HOSTNAME_ARG" \
    --disk-image   "$DISK_IMAGE" \
    --analysis-dir "$ANALYSIS_DIR" \
    --exports-dir  "$EXPORTS_DIR" \
    --output-dir   "$REPORTS_DIR" \
    ${FAN_MD:+--fan-summary  "$FAN_MD"} \
    ${FAME_MD:+--fame-summary "$FAME_MD"} \
    $([[ $MD_ONLY -eq 1 ]] && echo "--md-only" || true)

# ── Upload to investigations vault ────────────────────────────────────────────
if [[ $SKIP_UPLOAD -eq 0 ]]; then
    echo "[fast] Uploading reports to investigations vault..."

    MD_PATH="$REPORTS_DIR/${STEM}_fast_report.md"
    PDF_PATH="$REPORTS_DIR/${STEM}_fast_report.pdf"
    PPTX_PATH="$REPORTS_DIR/${STEM}_fast_presentation.pptx"
    DOCX_PATH="$REPORTS_DIR/${STEM}_fast_report.docx"

    # Use an array so paths/case-id with spaces or glob chars cannot word-split
    # or inject extra --flags into investigations_upload.py.
    UPLOAD_ARGS=(--case-id "$CASE_ID" --md "$MD_PATH")
    [[ -f "$PDF_PATH"  ]] && UPLOAD_ARGS+=(--pdf "$PDF_PATH")
    [[ -f "$PPTX_PATH" ]] && UPLOAD_ARGS+=(--pptx "$PPTX_PATH")
    [[ -f "$DOCX_PATH" ]] && UPLOAD_ARGS+=(--docx "$DOCX_PATH")

    # Upload evidence folder as ZIP
    EVIDENCE_ZIP="$REPORTS_DIR/${CASE_ID}_evidence.zip"
    if [[ -d "$EVIDENCE_DIR" ]]; then
        (cd "$REPORTS_DIR" && zip -r "${CASE_ID}_evidence.zip" "${CASE_ID}_evidence/" -q) && \
            UPLOAD_ARGS+=(--zip "$EVIDENCE_ZIP")
    fi

    python3 "$PROJECT_ROOT/lib/investigations_upload.py" "${UPLOAD_ARGS[@]}" || \
        echo "[fast] WARNING: Upload failed — check SSH connectivity to ubuntudesktop."

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
            echo "[fast] WARNING: Combined report upload failed."
    fi
else
    echo "[fast] Upload skipped (--no-upload)."
fi

# ── Session transcript (chain of evidence) ────────────────────────────────────
# Record the full Claude Code coordination session as a chain-of-evidence
# Markdown + PDF (plus the verbatim .jsonl). It captures the analytical
# reasoning behind every finding and feeds workflow optimisation. This step
# must never fail the investigation, and runs before local cleanup so the
# transcript is uploaded with the rest of the artefacts.
echo "[fast] Recording session transcript (chain of evidence)..."
python3 "$PROJECT_ROOT/lib/chat_recorder.py" \
    --case-id    "$CASE_ID" \
    --output-dir "$REPORTS_DIR" \
    $([[ $SKIP_UPLOAD -eq 0 ]] && echo "--upload" || true) \
    || echo "[fast] WARNING: Session transcript recording failed (analysis unaffected)."

# ── Clean up local artifacts ───────────────────────────────────────────────────
echo "[fast] Cleaning up local artifacts (preserved in investigations vault)..."
_cleanup_local_artifacts
rm -f "$SESSION_FILE"
echo "[fast] Local cleanup complete."

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║  FAST Analysis Complete                                          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""
echo "  Case ID  : $CASE_ID"
echo "  Host     : $HOSTNAME_ARG"
echo ""
echo "  Reports:"
for ext in md pdf pptx docx; do
    f="$REPORTS_DIR/${STEM}_fast_report.$ext"
    [[ "$ext" == "pptx" ]] && f="$REPORTS_DIR/${STEM}_fast_presentation.pptx"
    [[ -f "$f" ]] && echo "    $ext  → $f"
done
[[ -f "$REPORTS_DIR/${STEM}_combined_report.md" ]] && \
    echo "    combined → $REPORTS_DIR/${STEM}_combined_report.md"
echo ""
echo "  Analysis : $ANALYSIS_DIR/"
echo "  Exports  : $EXPORTS_DIR/"
echo ""
echo "  Next steps:"
echo "    1. Review $REPORTS_DIR/${STEM}_fast_report.md"
echo "    2. Parse MFT: MFTECmd.exe --csv ./exports/mft/ -o ./exports/mft_parsed.csv"
echo "    3. Parse Prefetch: PECmd.exe -d ./exports/prefetch/ --csv ./exports/"
echo "    4. Review Autopsy results: $EXPORTS_DIR/autopsy/"
echo "    5. Run /fan-opencti-lookup for CTI enrichment"
echo "    6. Record confirmed findings: /obsidian-record"
echo ""
