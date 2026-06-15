#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
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
# Environment variables (set via ./scripts/configure_vault.sh, persisted in ~/.soc_env):
#   INVESTIGATIONS_SSH_HOST  — vault SSH target; if unset, upload is skipped with guidance
#   INVESTIGATIONS_ROOT      — vault remote root path
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
DIRECT_E01=0

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
# Pre-compute CASE_DIR early so research_notes are written to the correct
# per-module subdir from the first step (full layout is set again below).
_EARLY_CASE_DIR="$REPORTS_DIR/$CASE_ID/FAST/${HOSTNAME_ARG:-$(basename "$DISK_IMAGE" | sed 's/\.[^.]*$//')}"
mkdir -p "$_EARLY_CASE_DIR" 2>/dev/null || true
python3 "$PROJECT_ROOT/lib/research_notes.py" init \
    --case-id    "$CASE_ID" \
    --module     fast \
    --evidence   "$DISK_IMAGE" \
    --hostname   "$HOSTNAME_ARG" \
    --case-dir   "$_EARLY_CASE_DIR" 2>/dev/null || true

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

# ── Session guard: upload leftovers from a previous run, then always clean ────
# A previous run's exports/registry, exports/evtx, exports/prefetch, etc. must
# never be picked up by generate_fast_report.py's globs for THIS run — even if
# that previous run crashed before its own cleanup ran. So: best-effort upload
# of any previous case's reports first, then unconditionally wipe analysis/
# and exports/ before this run creates anything.
SESSION_FILE="$ANALYSIS_DIR/.fast_session.json"

if [[ -f "$SESSION_FILE" ]]; then
    PREV_IMAGE="$(python3 -c "import json; print(json.load(open('$SESSION_FILE')).get('disk_image',''))" 2>/dev/null || true)"
    PREV_CASE="$(python3  -c "import json; print(json.load(open('$SESSION_FILE')).get('case_id',''))"   2>/dev/null || true)"
    if [[ -n "$PREV_IMAGE" && "$PREV_IMAGE" != "$DISK_IMAGE" && $SKIP_UPLOAD -eq 0 ]]; then
        echo "[fast] Evidence switch detected (previous: $(basename "$PREV_IMAGE"))."
        echo "[fast] Uploading artifacts from previous investigation (case: $PREV_CASE)..."
        _upload_reports "$PREV_CASE"
    fi
fi
_cleanup_local_artifacts

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
    "$EXPORTS_DIR/machine_details" \
    "$EXPORTS_DIR/tasks" \
    "$EXPORTS_DIR/autopsy" \
    "$REPORTS_DIR"

printf '{"case_id":"%s","hostname":"%s","disk_image":"%s","started":"%s"}\n' \
    "$CASE_ID" "$HOSTNAME_ARG" "$DISK_IMAGE" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    > "$SESSION_FILE"

# ── Image verification ────────────────────────────────────────────────────────
IMAGE_EXT="${DISK_IMAGE##*.}"
IMAGE_EXT_LOWER="${IMAGE_EXT,,}"

# Split raw images (FTK Imager ".001", ".002", ... convention): collect every
# numbered sibling segment so TSK tools can read the image as a whole.
SEGMENTS=()
if [[ "$IMAGE_EXT_LOWER" == "001" ]]; then
    _seg_base="${DISK_IMAGE%.001}"
    _n=1
    while :; do
        _seg="$(printf '%s.%03d' "$_seg_base" "$_n")"
        [[ -f "$_seg" ]] || break
        SEGMENTS+=("$_seg")
        _n=$((_n + 1))
    done
    echo "[fast] Split raw image: ${#SEGMENTS[@]} segment(s) detected."
fi

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
        if sudo ewfmount "$DISK_IMAGE" "$EWF_MOUNT"/ 2>/dev/null; then
            RAW_DEVICE="$EWF_MOUNT/ewf1"
        else
            echo "[fast] WARNING: ewfmount unavailable (no /dev/fuse in this environment)."
            echo "[fast] Falling back to TSK's built-in EWF support — fls/icat/fsstat will"
            echo "[fast] read the .E01 directly, without mounting."
            RAW_DEVICE="$DISK_IMAGE"
            DIRECT_E01=1
        fi
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
    elif [[ ${#SEGMENTS[@]} -gt 1 ]]; then
        echo "[fast] Split raw image (${#SEGMENTS[@]} segments) — partition table read from segment 1."
        RAW_DEVICE="${SEGMENTS[0]}"
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
            awk '{print $3}' | sort -n | head -1 || echo "")
        if [[ -z "$START_SECTOR" ]]; then
            if [[ $DIRECT_E01 -eq 1 ]]; then
                # Logical/volume-level EWF acquisitions have no partition table —
                # the filesystem starts at sector 0 of the image itself.
                START_SECTOR=0
                echo "[fast] No partition table in mmls output — treating as a logical volume image (offset 0)."
            else
                START_SECTOR=2048
            fi
        fi
        OFFSET=$(( START_SECTOR * SECTOR_SIZE ))
        echo "[fast] Partition start: sector $START_SECTOR (offset $OFFSET bytes)"

        if [[ $DIRECT_E01 -eq 1 ]]; then
            echo "[fast] No FUSE-mounted raw device available — skipping loop-mount."
            echo "[fast] TSK tools (fls/fsstat/icat) will read the .E01 directly; Windows"
            echo "[fast] artefacts will be extracted via fls path lookup + icat below."
            SKIP_MOUNT=2
        else
        # Mount filesystem read-only. Split raw images can't be loop-mounted as
        # separate segments — concatenate to a temp file first if there's room
        # (OS temp dir is an approved write location per lib/path_guard.py),
        # otherwise degrade gracefully (TSK tools below still read all segments
        # natively via TSK_IMAGES).
        echo "[fast] Mounting filesystem (read-only)..."
        if [[ ${#SEGMENTS[@]} -gt 1 ]]; then
            _total_size=0
            for _seg in "${SEGMENTS[@]}"; do
                _total_size=$(( _total_size + $(stat -c%s "$_seg" 2>/dev/null || echo 0) ))
            done
            _avail=$(df --output=avail -B1 /tmp 2>/dev/null | tail -1 | tr -d ' ')
            if [[ "${_avail:-0}" -gt "$_total_size" ]]; then
                COMBINED_RAW="/tmp/${CASE_ID//[[:space:]]/_}_combined.raw"
                echo "[fast] Concatenating ${#SEGMENTS[@]} segments → $COMBINED_RAW ..."
                cat "${SEGMENTS[@]}" > "$COMBINED_RAW"
                RAW_DEVICE="$COMBINED_RAW"
                sudo mount -o ro,loop,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
                sudo mount -o ro,loop,norecovery,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
                { echo "[fast] WARNING: Filesystem mount failed — continuing without mount."; SKIP_MOUNT=2; }
            else
                echo "[fast] WARNING: Not enough space in /tmp ($_total_size bytes needed) to concatenate split image — continuing without mount."
                SKIP_MOUNT=2
            fi
        else
            sudo mount -o ro,loop,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
            sudo mount -o ro,loop,norecovery,offset="${OFFSET}" "$RAW_DEVICE" "$FS_MOUNT" 2>/dev/null || \
            { echo "[fast] WARNING: Filesystem mount failed — continuing without mount."; SKIP_MOUNT=2; }
        fi

        # Verify the mount really is read-only before any analysis touches it.
        [[ $SKIP_MOUNT -eq 0 ]] && fgff_assert_ro_mount "$FS_MOUNT"
        [[ $SKIP_MOUNT -eq 0 ]] && MOUNTED_FS=1 && echo "[fast] Mounted at $FS_MOUNT (verified read-only)"
        fi
    fi
fi

# ── TSK analysis ──────────────────────────────────────────────────────────────
RAW_FOR_TSK="${RAW_DEVICE:-$DISK_IMAGE}"

# When split segments couldn't be concatenated (no COMBINED_RAW), pass every
# segment to the TSK tools — they natively support split raw images as a list
# of positional image arguments.
if [[ ${#SEGMENTS[@]} -gt 1 && -z "${COMBINED_RAW:-}" ]]; then
    TSK_IMAGES=("${SEGMENTS[@]}")
else
    TSK_IMAGES=("$RAW_FOR_TSK")
fi

echo "[fast] Running TSK file listing (fls)..."
sudo fls -r -p "${TSK_IMAGES[@]}" \
    > "$ANALYSIS_DIR/fls_output.txt" 2>/dev/null || \
sudo fls -r -p -o "${START_SECTOR:-2048}" "${TSK_IMAGES[@]}" \
    > "$ANALYSIS_DIR/fls_output.txt" 2>/dev/null || \
    echo "[fast] WARNING: fls failed — continuing."
echo "[fast] fls → $ANALYSIS_DIR/fls_output.txt"

echo "[fast] Generating bodyfile (fls -m)..."
sudo fls -r -m / "${TSK_IMAGES[@]}" \
    > "$ANALYSIS_DIR/bodyfile.txt" 2>/dev/null || \
sudo fls -r -m / -o "${START_SECTOR:-2048}" "${TSK_IMAGES[@]}" \
    > "$ANALYSIS_DIR/bodyfile.txt" 2>/dev/null || \
    echo "[fast] WARNING: bodyfile generation failed."

echo "[fast] Converting bodyfile to timeline (mactime)..."
mactime -b "$ANALYSIS_DIR/bodyfile.txt" -z UTC \
    > "$EXPORTS_DIR/fs_timeline.txt" 2>/dev/null || true
mactime -b "$ANALYSIS_DIR/bodyfile.txt" -z UTC -d \
    > "$EXPORTS_DIR/fs_timeline.csv" 2>/dev/null || true
echo "[fast] Timeline → $EXPORTS_DIR/fs_timeline.txt"

echo "[fast] Running fsstat..."
sudo fsstat "${TSK_IMAGES[@]}" > "$ANALYSIS_DIR/fsstat.txt" 2>/dev/null || \
sudo fsstat -o "${START_SECTOR:-2048}" "${TSK_IMAGES[@]}" > "$ANALYSIS_DIR/fsstat.txt" 2>/dev/null || true

echo "[fast] Running ils (inode listing)..."
sudo ils "${TSK_IMAGES[@]}" > "$ANALYSIS_DIR/ils_output.txt" 2>/dev/null || true
sudo ils -p "${TSK_IMAGES[@]}" > "$ANALYSIS_DIR/ils_orphan.txt" 2>/dev/null || true

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

    # ── Deep extraction: machine details, recycle bin metadata, IOC seeding ──
    echo "[fast] Running deep extraction (machine details + recycle bin parse)..."
    python3 "$PROJECT_ROOT/lib/fast_machine_details.py" \
        --exports "$EXPORTS_DIR" \
        --fs-mount "$FS_MOUNT" 2>>"$ANALYSIS_DIR/fast_machine_details.log" || \
        echo "[fast] WARNING: fast_machine_details.py failed — see $ANALYSIS_DIR/fast_machine_details.log"

elif [[ $DIRECT_E01 -eq 1 ]]; then
    echo "[fast] Extracting Windows artefacts directly from image (fls path lookup + icat)..."
    FLS="$ANALYSIS_DIR/fls_output.txt"

    # Extract a single file by exact (case-insensitive) fls path.
    _icat_path() {
        local rel_lc="${1,,}" out="$2" meta inode
        meta=$(awk -F'\t' -v p="$rel_lc" \
            '$1 ~ /^r\/r/ { l=tolower($2); if (l==p) { print $1; exit } }' "$FLS" 2>/dev/null)
        [[ -z "$meta" ]] && return 1
        inode=$(echo "$meta" | awk '{print $2}' | tr -d ':')
        sudo icat -o "${START_SECTOR:-0}" "${TSK_IMAGES[@]}" "$inode" > "$out" 2>/dev/null
    }

    # Extract every regular file directly inside an fls directory (non-recursive).
    _icat_dir() {
        local dir_lc="${1,,}/" outdir="$2"
        mkdir -p "$outdir" 2>/dev/null || sudo mkdir -p "$outdir"
        awk -F'\t' -v d="$dir_lc" \
            '$1 ~ /^r\/r/ { l=tolower($2); if (index(l,d)==1 && index(substr(l,length(d)+1),"/")==0) print }' \
            "$FLS" 2>/dev/null | while IFS=$'\t' read -r meta path; do
            local inode fname
            inode=$(echo "$meta" | awk '{print $2}' | tr -d ':')
            fname="$(basename "$path")"
            sudo icat -o "${START_SECTOR:-0}" "${TSK_IMAGES[@]}" "$inode" > "$outdir/$fname" 2>/dev/null || true
        done
    }

    # Event logs
    _icat_dir "Windows/System32/winevt/Logs" "$EXPORTS_DIR/evtx"

    # Registry hives
    for hive in SYSTEM SOFTWARE SECURITY SAM; do
        _icat_path "Windows/System32/config/$hive" "$EXPORTS_DIR/registry/$hive" || true
    done
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (l ~ /^users\/[^\/]+\/ntuser\.dat$/) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/registry/$(echo "$p" | tr '/' '_')" || true
    done
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (l ~ /usrclass\.dat$/) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/registry/$(echo "$p" | tr '/' '_')" || true
    done

    # Prefetch
    _icat_dir "Windows/Prefetch" "$EXPORTS_DIR/prefetch"

    # SRUM
    _icat_path "Windows/System32/sru/SRUDB.dat" "$EXPORTS_DIR/srum/SRUDB.dat" || true

    # Amcache
    _icat_path "Windows/AppCompat/Programs/Amcache.hve" "$EXPORTS_DIR/registry/Amcache.hve" || true

    # Browser history
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (l ~ /chrome\/user data\/default\/history$/) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/browser/$(echo "$p" | tr '/' '_')" || true
    done
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (l ~ /edge\/user data\/default\/history$/) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/browser/$(echo "$p" | tr '/' '_')" || true
    done

    # Recycle Bin
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (l ~ /^\$recycle\.bin\//) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/recyclebin/$(echo "$p" | tr '/' '_')" || true
    done

    # Scheduled tasks
    awk -F'\t' '$1 ~ /^r\/r/ { l=tolower($2); if (index(l,"windows/system32/tasks/")==1) print $2 }' \
        "$FLS" 2>/dev/null | while read -r p; do
        _icat_path "$p" "$EXPORTS_DIR/tasks/$(echo "$p" | tr '/' '_')" || true
    done

    echo "[fast] Direct artefact extraction complete (no mount — fls + icat)."
fi

# ── MFT and UsnJrnl via icat ──────────────────────────────────────────────────
echo "[fast] Extracting MFT (\$MFT, inode 0)..."
sudo icat "${TSK_IMAGES[@]}" 0 > "$EXPORTS_DIR/mft/\$MFT" 2>/dev/null || \
sudo icat -o "${START_SECTOR:-2048}" "${TSK_IMAGES[@]}" 0 > "$EXPORTS_DIR/mft/\$MFT" 2>/dev/null || \
    echo "[fast] WARNING: MFT extraction failed."

echo "[fast] Extracting USN Change Journal (\$J, inode 11)..."
sudo icat "${TSK_IMAGES[@]}" 11-128-4 > "$EXPORTS_DIR/mft/\$J" 2>/dev/null || \
sudo icat "${TSK_IMAGES[@]}" 11 > "$EXPORTS_DIR/mft/\$J" 2>/dev/null || \
    echo "[fast] WARNING: USN journal extraction failed."

# ── File hash manifest ────────────────────────────────────────────────────────
if [[ -d "$EXPORTS_DIR/files" ]] && [[ "$(ls -A "$EXPORTS_DIR/files" 2>/dev/null)" ]]; then
    find "$EXPORTS_DIR/files/" -type f \
        -exec md5sum {} \; > "$EXPORTS_DIR/files/md5_manifest.txt" 2>/dev/null || true
    echo "[fast] MD5 manifest → $EXPORTS_DIR/files/md5_manifest.txt"
fi

# ── Bulk extractor carving (on a size budget — skip if image > 20 GB) ─────────
IMAGE_SIZE=0
for _img in "${TSK_IMAGES[@]}"; do
    IMAGE_SIZE=$(( IMAGE_SIZE + $(stat -c%s "$_img" 2>/dev/null || echo 0) ))
done
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
if [[ -n "${COMBINED_RAW:-}" && -f "$COMBINED_RAW" ]]; then
    echo "[fast] Removing concatenated split-image temp file..."
    rm -f "$COMBINED_RAW"
fi

# ── Evidence folder preservation (before report generation) ───────────────────
STEM="${CASE_ID//[[:space:]]/_}"
# New 3-level layout: reports/<case_id>/FAST/<hostname>/
INVESTIGATION_NAME="${HOSTNAME_ARG:-$STEM}"
CASE_ROOT="$REPORTS_DIR/$CASE_ID"
CASE_DIR="$CASE_ROOT/FAST/$INVESTIGATION_NAME"
DOCS_DIR="$CASE_ROOT/documents"
mkdir -p "$CASE_DIR" "$DOCS_DIR" "$CASE_ROOT/raw"
export FGFF_CASE_DIR="$CASE_ROOT"   # record/package write to CASE_ROOT/documents/
EVIDENCE_DIR="$CASE_DIR/${CASE_ID}_evidence"
echo "[fast] Preserving analysis artifacts → $EVIDENCE_DIR ..."
mkdir -p "$EVIDENCE_DIR/storage" "$EVIDENCE_DIR/exports"
rsync -a "$ANALYSIS_DIR/" "$EVIDENCE_DIR/storage/" 2>/dev/null || true
# exports/carved/ holds bulk_extractor's raw scanner output, which can run into
# tens of GB per image (mostly low-value carved fragments) and is reproducible
# from the source E01 — exclude it from the per-case evidence copy/ZIP, but keep
# the top-level reports (report.xml, *_histogram.txt) for reference.
rsync -a --exclude='carved/' "$EXPORTS_DIR/" "$EVIDENCE_DIR/exports/" 2>/dev/null || true
mkdir -p "$EVIDENCE_DIR/exports/carved"
find "$EXPORTS_DIR/carved" -maxdepth 1 -type f -size -10M -exec cp {} "$EVIDENCE_DIR/exports/carved/" \; 2>/dev/null || true

for artifact_file in \
    "$EVIDENCE_DIR/storage/ewfinfo.txt" \
    "$EVIDENCE_DIR/storage/mmls.txt" \
    "$EVIDENCE_DIR/storage/fsstat.txt" \
    "$EVIDENCE_DIR/storage/fls_output.txt" \
    "$EVIDENCE_DIR/storage/bodyfile.txt" \
    "$EVIDENCE_DIR/exports/fs_timeline.csv"; do
    if [[ -f "$artifact_file" ]]; then
        _hash=$(sha256sum "$artifact_file" | awk '{print $1}')
        _relname="FAST/$INVESTIGATION_NAME/${CASE_ID}_evidence/$(realpath --relative-to="$EVIDENCE_DIR/.." "$artifact_file")"
        python3 "$PROJECT_ROOT/lib/research_notes.py" step \
            --case-id "$CASE_ID" \
            --title   "Evidence preserved: $(basename "$artifact_file")" \
            --action  "sha256sum $artifact_file" \
            --why     "Chain of custody — SHA-256 fingerprint of preserved artifact" \
            --outcome "Preserved to ${_relname} — SHA-256: ${_hash}" \
            --case-dir "$CASE_DIR" 2>/dev/null || true
    fi
done
echo "[fast] Evidence folder ready: $EVIDENCE_DIR"

# ── Report generation ─────────────────────────────────────────────────────────
echo "[fast] Generating reports (Markdown, PDF, PPTX, DOCX)..."
FAN_MD=""
FAME_MD=""
# Check 3-level layout first, then fallback
_fan_cand=$(find "$CASE_ROOT/FAN" -name "*_incident_report.md" -type f 2>/dev/null | head -1)
[[ -n "$_fan_cand" ]] && FAN_MD="$(head -60 "$_fan_cand")"
_fame_cand=$(find "$CASE_ROOT/FAME" -name "*_fame_report.md" -type f 2>/dev/null | head -1)
[[ -n "$_fame_cand" ]] && FAME_MD="$(head -60 "$_fame_cand")"

python3 "$PROJECT_ROOT/lib/generate_fast_report.py" \
    --case-id      "$CASE_ID" \
    --hostname     "$HOSTNAME_ARG" \
    --disk-image   "$DISK_IMAGE" \
    --analysis-dir "$ANALYSIS_DIR" \
    --exports-dir  "$EXPORTS_DIR" \
    --case-dir     "$CASE_DIR" \
    --docs-dir     "$DOCS_DIR" \
    ${FAN_MD:+--fan-summary  "$FAN_MD"} \
    ${FAME_MD:+--fame-summary "$FAME_MD"} \
    $([[ $MD_ONLY -eq 1 ]] && echo "--md-only" || true)

# ── Completeness check ─────────────────────────────────────────────────────────
python3 "$PROJECT_ROOT/lib/report_completeness.py" --check \
    --case-id "$CASE_ID" --module FAST --case-dir "$CASE_DIR" || true
python3 "$PROJECT_ROOT/lib/report_completeness.py" --campaign-check \
    --case-id "$CASE_ID" --reports-dir "$PROJECT_ROOT/reports" || true

# ── Upload to investigations vault ────────────────────────────────────────────
if [[ $SKIP_UPLOAD -eq 0 ]]; then
    echo "[fast] Uploading reports to investigations vault..."

    MD_PATH="$CASE_DIR/${STEM}_fast_report.md"
    PDF_PATH="$DOCS_DIR/${STEM}_fast_report.pdf"
    PPTX_PATH="$DOCS_DIR/${STEM}_fast_presentation.pptx"
    DOCX_PATH="$DOCS_DIR/${STEM}_fast_report.docx"

    # Use an array so paths/case-id with spaces or glob chars cannot word-split
    # or inject extra --flags into investigations_upload.py.
    UPLOAD_ARGS=(--case-id "$CASE_ID" --md "$MD_PATH")
    [[ -f "$PDF_PATH"  ]] && UPLOAD_ARGS+=(--pdf "$PDF_PATH")
    [[ -f "$PPTX_PATH" ]] && UPLOAD_ARGS+=(--pptx "$PPTX_PATH")
    [[ -f "$DOCX_PATH" ]] && UPLOAD_ARGS+=(--docx "$DOCX_PATH")

    # Upload evidence folder as ZIP (written to documents dir)
    EVIDENCE_ZIP="$DOCS_DIR/${CASE_ID}_evidence.zip"
    if [[ -d "$EVIDENCE_DIR" ]]; then
        (cd "$(dirname "$EVIDENCE_DIR")" && zip -r "$EVIDENCE_ZIP" "$(basename "$EVIDENCE_DIR")/" -q) && \
            UPLOAD_ARGS+=(--zip "$EVIDENCE_ZIP")
    fi

    python3 "$PROJECT_ROOT/lib/investigations_upload.py" "${UPLOAD_ARGS[@]}" || \
        echo "[fast] WARNING: Upload failed — check INVESTIGATIONS_SSH_HOST connectivity or run ./scripts/configure_vault.sh."

    CAMPAIGN_MD="$CASE_ROOT/${CASE_ID}_campaign_report.md"
    if [[ -f "$CAMPAIGN_MD" ]]; then
        COMB_ARGS=(--case-id "$CASE_ID" --md "$CAMPAIGN_MD")
        [[ -f "$DOCS_DIR/${CASE_ID}_campaign_report.pdf"  ]] && \
            COMB_ARGS+=(--pdf "$DOCS_DIR/${CASE_ID}_campaign_report.pdf")
        [[ -f "$DOCS_DIR/${CASE_ID}_campaign_presentation.pptx" ]] && \
            COMB_ARGS+=(--pptx "$DOCS_DIR/${CASE_ID}_campaign_presentation.pptx")
        [[ -f "$DOCS_DIR/${CASE_ID}_campaign_report.docx" ]] && \
            COMB_ARGS+=(--docx "$DOCS_DIR/${CASE_ID}_campaign_report.docx")
        python3 "$PROJECT_ROOT/lib/investigations_upload.py" "${COMB_ARGS[@]}" || \
            echo "[fast] WARNING: Campaign report upload failed."
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
source "$PROJECT_ROOT/scripts/record_session.sh"
fgff_record_session "$CASE_ID" "$DOCS_DIR" "$([[ $SKIP_UPLOAD -eq 0 ]] && echo 1 || echo 0)"

# ── Chain-of-custody manifest ─────────────────────────────────────────────────
# Hash every artifact (and the source disk image) into a durable, append-only
# integrity manifest for court use. Best-effort; never fails the investigation.
source "$PROJECT_ROOT/scripts/chain_of_custody.sh"
fgff_update_custody "$CASE_ID" "$CASE_ROOT" "$DISK_IMAGE"

# ── Artifact bundle (chain of evidence) ───────────────────────────────────────
# Package every artifact for this case (reports, transcript, exhibits, …) into a
# timestamped ZIP and upload it to the investigations vault. Runs after the
# transcript so the bundle includes it. Best-effort; never fails the run.
# FGFF_CASE_DIR is already set above; fgff_package_artifacts reads it.
source "$PROJECT_ROOT/scripts/package_artifacts.sh"
fgff_package_artifacts "$CASE_ID" "$CASE_ROOT" "$DOCS_DIR" "$STEM" \
    "$([[ $SKIP_UPLOAD -eq 0 ]] && echo 1 || echo 0)"

# ── Chain-of-custody manifest (post-package) ─────────────────────────────────
# Re-run the custody update so the case ZIP just written above is itself hashed
# into the manifest, and every prior artifact's hash is re-verified immediately
# before upload. update_manifest() is idempotent. Best-effort.
fgff_update_custody "$CASE_ID" "$CASE_ROOT" "$DISK_IMAGE"

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
[[ -f "$CASE_DIR/${STEM}_fast_report.md"        ]] && echo "    md   → $CASE_DIR/${STEM}_fast_report.md"
[[ -f "$DOCS_DIR/${STEM}_fast_report.pdf"        ]] && echo "    pdf  → $DOCS_DIR/${STEM}_fast_report.pdf"
[[ -f "$DOCS_DIR/${STEM}_fast_presentation.pptx" ]] && echo "    pptx → $DOCS_DIR/${STEM}_fast_presentation.pptx"
[[ -f "$DOCS_DIR/${STEM}_fast_report.docx"       ]] && echo "    docx → $DOCS_DIR/${STEM}_fast_report.docx"
[[ -f "$CASE_ROOT/${CASE_ID}_campaign_report.md" ]] && \
    echo "    campaign → $CASE_ROOT/${CASE_ID}_campaign_report.md"
echo ""
echo "  Analysis : $ANALYSIS_DIR/"
echo "  Exports  : $EXPORTS_DIR/"
echo ""
echo "  Next steps:"
echo "    1. Review $CASE_DIR/${STEM}_fast_report.md"
echo "    2. Parse MFT: MFTECmd.exe --csv ./exports/mft/ -o ./exports/mft_parsed.csv"
echo "    3. Parse Prefetch: PECmd.exe -d ./exports/prefetch/ --csv ./exports/"
echo "    4. Review Autopsy results: $EXPORTS_DIR/autopsy/"
echo "    5. Run /fan-opencti-lookup for CTI enrichment"
echo "    6. Record confirmed findings: /obsidian-record"
echo ""
