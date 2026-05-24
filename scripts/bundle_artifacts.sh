#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# bundle_artifacts.sh — Zip all investigation artefacts for a completed case
#
# Collects every file produced during a PCAP investigation:
#   - Incident report (MD + PDF)
#   - PowerPoint presentation
#   - Per-module analysis outputs (all formats)
#   - CTI enrichment data
#
# Usage:
#   bundle_artifacts.sh --stem <stem> --case-id <id>
#                       --reports-dir <path>    (where MD/PDF/PPTX live)
#                       --base-dir <path>       (analysis/ root)
#                       --output-dir <path>     (where to write the zip)
#
# The zip is written to:
#   <output-dir>/<stem>_<case-id>_artifacts.zip

set -euo pipefail

STEM=""
CASE_ID=""
REPORTS_DIR=""
BASE_DIR=""
OUTPUT_DIR=""

usage() {
    cat <<'EOF'
Usage: bundle_artifacts.sh --stem <stem> --case-id <id>
                           --reports-dir <path>
                           --base-dir <path>
                           --output-dir <path>
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stem)         STEM="$2";        shift 2 ;;
        --case-id)      CASE_ID="$2";     shift 2 ;;
        --reports-dir)  REPORTS_DIR="$2"; shift 2 ;;
        --base-dir)     BASE_DIR="$2";    shift 2 ;;
        --output-dir)   OUTPUT_DIR="$2";  shift 2 ;;
        -h|--help)      usage ;;
        *)              echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

[[ -z "$STEM" ]]        && { echo "[bundle] ERROR: --stem required" >&2; exit 1; }
[[ -z "$CASE_ID" ]]     && { echo "[bundle] ERROR: --case-id required" >&2; exit 1; }
[[ -z "$REPORTS_DIR" ]] && { echo "[bundle] ERROR: --reports-dir required" >&2; exit 1; }
[[ -z "$BASE_DIR" ]]    && { echo "[bundle] ERROR: --base-dir required" >&2; exit 1; }
[[ -z "$OUTPUT_DIR" ]]  && { echo "[bundle] ERROR: --output-dir required" >&2; exit 1; }

mkdir -p "$OUTPUT_DIR"

ZIP_NAME="${STEM}_${CASE_ID}_artifacts.zip"
ZIP_PATH="$OUTPUT_DIR/$ZIP_NAME"

# Remove stale zip if present
[[ -f "$ZIP_PATH" ]] && rm -f "$ZIP_PATH"

echo "[bundle] Stem        : $STEM"
echo "[bundle] Case ID     : $CASE_ID"
echo "[bundle] Reports dir : $REPORTS_DIR"
echo "[bundle] Analysis dir: $BASE_DIR"
echo "[bundle] Output zip  : $ZIP_PATH"

# ── Collect files ─────────────────────────────────────────────────────────────

STAGED="$(mktemp -d)"
trap 'rm -rf "$STAGED"' EXIT

BUNDLE="$STAGED/${CASE_ID}_artifacts"
mkdir -p "$BUNDLE"/{reports,network,ftp,iocs,tls,http,dns,file_hashes,suricata,yara,cti}

# Reports (MD, PDF, PPTX)
if [[ -d "$REPORTS_DIR" ]]; then
    find "$REPORTS_DIR" \( -name "*.md" -o -name "*.pdf" -o -name "*.pptx" \) \
        -exec cp {} "$BUNDLE/reports/" \; 2>/dev/null || true
fi

# Per-module analysis outputs — copy each module's stem subdirectory if present
declare -A MODULE_DIRS=(
    [pcap]="network"
    [cti]="cti"
    [dns_threats]="dns"
    [http_threats]="http"
    [tls_inspector]="tls"
    [cert_inspector]="tls"
    [file_hashes]="file_hashes"
    [suricata]="suricata"
    [yara_pcap]="yara"
    [icmp_threats]="network"
    [tcp_threats]="network"
    [udp_threats]="network"
    [arp_threats]="network"
    [dhcp_threats]="network"
    [ntp_threats]="network"
    [mdns_threats]="network"
    [quic_threats]="network"
    [snmp_threats]="network"
    [nbns_threats]="network"
    [llmnr_threats]="network"
    [stun_threats]="network"
    [ssdp_threats]="network"
    [netbios_threats]="network"
)

for mod in "${!MODULE_DIRS[@]}"; do
    dest="${MODULE_DIRS[$mod]}"
    src_stem="$BASE_DIR/$mod/$STEM"
    src_base="$BASE_DIR/$mod"
    # TYPE A: module wrote to <base>/<mod>/<stem>/
    if [[ -d "$src_stem" ]]; then
        find "$src_stem" -type f \
            -exec cp {} "$BUNDLE/$dest/" \; 2>/dev/null || true
    # TYPE B: module wrote directly to <base>/<mod>/ (no stem subdir)
    elif [[ -d "$src_base" ]]; then
        find "$src_base" -maxdepth 1 -type f \
            -exec cp {} "$BUNDLE/$dest/" \; 2>/dev/null || true
    fi
done

# Remove empty subdirs
find "$BUNDLE" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true

# ── Zip ───────────────────────────────────────────────────────────────────────
(
    cd "$STAGED"
    zip -r "$ZIP_PATH" "${CASE_ID}_artifacts/" -x "*.pyc" -x "__pycache__/*" \
        > /dev/null 2>&1
)

echo "[bundle] ZIP created : $ZIP_PATH  ($(du -sh "$ZIP_PATH" | cut -f1))"
