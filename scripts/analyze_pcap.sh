#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# analyze_pcap.sh — Manual PCAP investigation orchestrator (FAN)
#
# Runs all 22 analysis modules against a PCAP, generates a versioned incident
# report, uploads it to the investigations vault via the investigations MCP
# server (SSH), then wipes all WIP analysis directories.
#
# Usage:
#   analyze_pcap.sh /path/to/capture.pcap
#   analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2025-001
#   analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2025-001 --no-vault

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
source "$SCRIPT_DIR/pathguard.sh"
source "$SCRIPT_DIR/record_session.sh"

# ── Argument parsing ──────────────────────────────────────────────────────────
PCAP_FILE=""
CASE_ID=""
CASE_DESC=""
NO_VAULT=0
REPORT_VERSION=1
REPORTS_PERSIST_DIR=""

usage() {
    cat <<'EOF'
Usage: analyze_pcap.sh [OPTIONS] /path/to/capture.pcap

Options:
  --case-id ID             Case ID (default: FAN-YYYYMMDD-HHMMSS)
  --description D          Case description recorded in the report header
  --no-vault               Skip all Obsidian vault writes
  --reports-persist-dir D  Persist final reports to DIR in addition to the vault
  -h, --help               Show this help

All WIP files are written to ./analysis/ and removed after the report
is uploaded to the investigations vault.
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --case-id)             CASE_ID="$2";               shift 2 ;;
        --description)         CASE_DESC="$2";             shift 2 ;;
        --no-vault)            NO_VAULT=1;                 shift   ;;
        --reports-persist-dir) REPORTS_PERSIST_DIR="$2";  shift 2 ;;
        -h|--help)             usage ;;
        -*)                    echo "Unknown option: $1" >&2; exit 1 ;;
        *)                     PCAP_FILE="$1"; shift ;;
    esac
done

# ── Colour helpers ────────────────────────────────────────────────────────────
C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
info()   { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()     { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()   { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()    { echo -e "${C_RED}[✗]${C_RESET} $*" >&2; }
header() {
    echo ""
    echo -e "${C_BOLD}${C_CYAN}══════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}  $*${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}══════════════════════════════════════════${C_RESET}"
}

# ── Require PCAP ──────────────────────────────────────────────────────────────
if [[ -z "$PCAP_FILE" ]]; then
    header "FAN — PCAP Investigation"
    read -r -p "$(echo -e "${C_CYAN}Enter path to PCAP file: ${C_RESET}")" PCAP_FILE
fi
[[ -z "$PCAP_FILE" ]] && { err "No PCAP file provided."; exit 1; }
[[ ! -f "$PCAP_FILE" ]] && { err "File not found: $PCAP_FILE"; exit 1; }

PCAP_ABS="$(realpath "$PCAP_FILE")"
STEM="$(basename "$PCAP_ABS")"
STEM="${STEM%.pcapng}"
STEM="${STEM%.pcap}"

[[ -z "$CASE_ID" ]] && CASE_ID="FAN-$(date -u +%Y%m%d-%H%M%S)"
fgff_validate_case_id "$CASE_ID" >/dev/null

# ── WIP directories (cleaned up after upload) ─────────────────────────────────
ANALYSIS="$PROJECT_ROOT/analysis"
REPORTS_TMP="$ANALYSIS/_reports/$STEM"
mkdir -p "$REPORTS_TMP"

# ── Per-case output directory (persists after WIP cleanup) ───────────────────
# New 3-level layout: reports/<case_id>/FAN/<pcap_stem>/
CASE_ROOT="$PROJECT_ROOT/reports/$CASE_ID"
CASE_DIR="$CASE_ROOT/FAN/$STEM"
DOCS_DIR="$CASE_ROOT/documents"
mkdir -p "$CASE_DIR" "$DOCS_DIR" "$CASE_ROOT/raw"
export FGFF_CASE_DIR="$CASE_ROOT"   # record/package write to CASE_ROOT/documents/

# ── Research notes initialisation ─────────────────────────────────────────────
python3 "$PROJECT_ROOT/lib/research_notes.py" init \
    --case-id    "$CASE_ID" \
    --module     fan \
    --evidence   "$PCAP_ABS" \
    --case-dir   "$CASE_DIR" 2>/dev/null || true

# ── Update Suricata rules ─────────────────────────────────────────────────────
header "Updating Suricata Rules"
if [[ -x "$SCRIPT_DIR/update_suricata_rules.sh" ]]; then
    if "$SCRIPT_DIR/update_suricata_rules.sh" --et-only 2>&1 | sed 's/^/    /'; then
        ok "Suricata rules updated."
    else
        warn "Suricata rule update failed — continuing with existing rules."
    fi
else
    warn "update_suricata_rules.sh not found — skipping rule update."
fi

ok "Case    : $CASE_ID"
ok "PCAP    : $PCAP_ABS"
ok "WIP dir : $ANALYSIS"

# ── Output-dir helpers ────────────────────────────────────────────────────────
# TYPE A — module uses --output-dir as FULL path (stem already included)
# TYPE B — module uses --output-dir as BASE, appends stem internally
full() { echo "$ANALYSIS/$1/$STEM"; }
base() { echo "$ANALYSIS/$1"; }

XFLAGS=()
[[ $NO_VAULT -eq 1 ]] && XFLAGS+=("--no-vault")

# ── Step runner ───────────────────────────────────────────────────────────────
STEP_PASS=0; STEP_FAIL=0
run_step() {
    local label="$1"; shift
    info "[$label]"
    local outbuf
    if outbuf=$("$@" 2>&1); then
        echo "$outbuf" | sed 's/^/    /'
        ok "[$label] complete"
        STEP_PASS=$((STEP_PASS+1))
    else
        echo "$outbuf" | sed 's/^/    /'
        warn "[$label] finished with errors (continuing)"
        STEP_FAIL=$((STEP_FAIL+1))
    fi
}

# ── Analysis modules ──────────────────────────────────────────────────────────
header "Running Analysis  (case: $CASE_ID  stem: $STEM)"

run_step "PCAP netflow / IPs / FQDNs" \
    "$SCRIPT_DIR/pcap_analyze.sh" "$PCAP_ABS" \
    --output-dir "$(full pcap)" \
    --case-id "$CASE_ID"

run_step "SiLK flow analysis" \
    "$SCRIPT_DIR/fan_silk_analysis.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full silk_analysis)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "ICMP threats" \
    "$SCRIPT_DIR/fan_icmp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(base icmp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "DNS threats" \
    "$SCRIPT_DIR/fan_dns_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full dns_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "NTP threats" \
    "$SCRIPT_DIR/fan_ntp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(base ntp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "HTTP(S) unusual patterns" \
    "$SCRIPT_DIR/fan_http_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(base http_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "TLS certificate inspector" \
    "$SCRIPT_DIR/fan_cert_inspector.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full cert_inspector)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "TLS session inspector + JA4" \
    "$SCRIPT_DIR/fan_tls_inspector.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full tls_inspector)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "ARP threats" \
    "$SCRIPT_DIR/fan_arp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full arp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "TCP threats" \
    "$SCRIPT_DIR/fan_tcp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full tcp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "UDP threats" \
    "$SCRIPT_DIR/fan_udp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full udp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "DHCP threats" \
    "$SCRIPT_DIR/fan_dhcp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full dhcp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "mDNS threats" \
    "$SCRIPT_DIR/fan_mdns_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full mdns_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "QUIC threats" \
    "$SCRIPT_DIR/fan_quic_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full quic_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "SNMP threats" \
    "$SCRIPT_DIR/fan_snmp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full snmp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "NBNS threats" \
    "$SCRIPT_DIR/fan_nbns_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full nbns_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "LLMNR threats" \
    "$SCRIPT_DIR/fan_llmnr_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full llmnr_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "STUN threats" \
    "$SCRIPT_DIR/fan_stun_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full stun_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "SSDP threats" \
    "$SCRIPT_DIR/fan_ssdp_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full ssdp_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "NetBIOS threats" \
    "$SCRIPT_DIR/fan_netbios_threats.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full netbios_threats)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "File hash extraction + OSINT" \
    "$SCRIPT_DIR/fan_file_hashes.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full file_hashes)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "Suricata IDS" \
    "$SCRIPT_DIR/fan_suricata.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full suricata)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

run_step "YARA rules (PCAP + extracted files)" \
    "$SCRIPT_DIR/fan_yara_pcap.sh" "$PCAP_ABS" \
    --stem "$STEM" --case-id "$CASE_ID" \
    --output-dir "$(full yara_pcap)" \
    "${XFLAGS[@]:+${XFLAGS[@]}}"

FQDN_FILE="$(full pcap)/unique_fqdns.txt"
IP_FILE="$(full pcap)/unique_ips.txt"
if [[ -f "$FQDN_FILE" && -f "$IP_FILE" ]]; then
    run_step "CTI IP / FQDN enrichment" \
        python3 "$PROJECT_ROOT/lib/fan_ip_lookup.py" \
        "$FQDN_FILE" "$IP_FILE" \
        --output-dir "$(full cti)" \
        --case-id "$CASE_ID"
else
    warn "FQDN / IP files not found — skipping CTI enrichment"
    STEP_FAIL=$((STEP_FAIL+1))
fi

# ── Incident report ───────────────────────────────────────────────────────────
header "Generating Incident Report"

run_step "Incident report v${REPORT_VERSION}" \
    "$SCRIPT_DIR/generate_pcap_report.sh" \
    --stem "$STEM" \
    --case-id "$CASE_ID" \
    --case-dir "$CASE_DIR" \
    --docs-dir "$DOCS_DIR" \
    --base-dir "$ANALYSIS" \
    --report-version "$REPORT_VERSION"

REPORT_MD="$CASE_DIR/${STEM}_incident_report.md"
REPORT_PDF="$DOCS_DIR/${STEM}_incident_report.pdf"
REPORT_PPTX="$DOCS_DIR/${STEM}_management_briefing.pptx"

[[ ! -f "$REPORT_MD" ]] && { err "Report markdown not found — aborting upload."; exit 1; }
ok "Report v${REPORT_VERSION}: $REPORT_MD"

# ── Management PowerPoint ─────────────────────────────────────────────────────
header "Generating Management PowerPoint"

REPORT_PPTX="$DOCS_DIR/${STEM}_incident_briefing_v${REPORT_VERSION}.pptx"

run_step "Management briefing (PPTX)" \
    "$SCRIPT_DIR/generate_pcap_presentation.sh" \
    --stem "$STEM" \
    --case-id "$CASE_ID" \
    --output-dir "$DOCS_DIR" \
    --base-dir "$ANALYSIS" \
    --report-version "$REPORT_VERSION"

# ── Bundle all artefacts into a zip ──────────────────────────────────────────
header "Bundling Artefacts"

run_step "Bundle artefacts (ZIP)" \
    "$SCRIPT_DIR/bundle_artifacts.sh" \
    --stem "$STEM" \
    --case-id "$CASE_ID" \
    --reports-dir "$REPORTS_TMP" \
    --base-dir "$ANALYSIS" \
    --output-dir "$REPORTS_TMP"

REPORT_ZIP="$REPORTS_TMP/${STEM}_${CASE_ID}_artifacts.zip"

# ── Evidence folder preservation ─────────────────────────────────────────────
header "Preserving Analysis Artifacts"
EVIDENCE_DIR="$CASE_DIR/${CASE_ID}_evidence"
mkdir -p "$EVIDENCE_DIR/analysis"
rsync -a "$ANALYSIS/" "$EVIDENCE_DIR/analysis/" 2>/dev/null || true
info "Evidence folder: $EVIDENCE_DIR"

# SHA-256 hashes for key FAN output files
for artifact_file in \
    "$EVIDENCE_DIR/analysis/pcap/${STEM}/netflow.csv" \
    "$EVIDENCE_DIR/analysis/dns_threats/${STEM}/dns_threats.json" \
    "$EVIDENCE_DIR/analysis/http_threats/${STEM}/http_threats.json" \
    "$EVIDENCE_DIR/analysis/tls_inspector/${STEM}/tls_sessions.json" \
    "$EVIDENCE_DIR/analysis/suricata/${STEM}/suricata_results.json"; do
    if [[ -f "$artifact_file" ]]; then
        _hash=$(sha256sum "$artifact_file" | awk '{print $1}')
        _relpath="FAN/$STEM/${CASE_ID}_evidence/analysis/$(realpath --relative-to="$EVIDENCE_DIR/analysis" "$artifact_file" 2>/dev/null || echo "$(basename "$artifact_file")")"
        python3 "$PROJECT_ROOT/lib/research_notes.py" step \
            --case-id "$CASE_ID" \
            --title   "Evidence preserved: $(basename "$artifact_file")" \
            --action  "sha256sum $artifact_file" \
            --why     "Chain of custody — SHA-256 fingerprint of preserved artifact" \
            --outcome "Preserved to ${_relpath} — SHA-256: ${_hash}" \
            --case-dir "$CASE_DIR" 2>/dev/null || true
    fi
done

EVIDENCE_ZIP="$DOCS_DIR/${CASE_ID}_evidence.zip"
(cd "$(dirname "$EVIDENCE_DIR")" && zip -r "$EVIDENCE_ZIP" "$(basename "$EVIDENCE_DIR")/" -q 2>/dev/null) || true

# ── Upload to investigations vault ────────────────────────────────────────────
header "Uploading to Investigations Vault"

run_step "Upload report" \
    python3 "$PROJECT_ROOT/lib/investigations_upload.py" \
    --case-id "$CASE_ID" \
    --md "$REPORT_MD" \
    $( [[ -f "$REPORT_PDF"   ]] && echo "--pdf $REPORT_PDF" ) \
    $( [[ -f "$REPORT_PPTX"  ]] && echo "--pptx $REPORT_PPTX" ) \
    $( [[ -f "$REPORT_ZIP"   ]] && echo "--zip $REPORT_ZIP" ) \
    $( [[ -f "$EVIDENCE_ZIP" ]] && echo "--zip $EVIDENCE_ZIP" )

# ── Session transcript (chain of evidence) ────────────────────────────────────
# Record the full Claude Code coordination session as a chain-of-evidence
# Markdown + PDF (plus the verbatim .jsonl) and upload it. The transcript is
# written to DOCS_DIR (persists after WIP cleanup) and captures the
# analytical reasoning behind every finding, feeding workflow optimisation.
header "Recording Session Transcript"

# Best-effort, shared recorder (never fails the investigation). Uploaded to the
# investigations vault alongside the report. FGFF_CASE_DIR is already exported.
source "$SCRIPT_DIR/record_session.sh"
fgff_record_session "$CASE_ID" "$DOCS_DIR" 1

# ── Artifact bundle (chain of evidence) ───────────────────────────────────────
# Bundle every artifact for this case — incident reports + the analysis bundle
# from the temp reports dir, plus the transcript — and upload it.
# Runs before WIP cleanup so the temp reports dir ($REPORTS_TMP) still exists.
# FGFF_CASE_DIR is already exported; fgff_package_artifacts reads it.
header "Bundling & Uploading Artifacts"
source "$SCRIPT_DIR/package_artifacts.sh"
fgff_package_artifacts "$CASE_ID" "$CASE_ROOT" "$DOCS_DIR" "$STEM" 1 "$REPORTS_TMP"

# ── Cleanup WIP analysis directories ─────────────────────────────────────────
header "Cleaning Up WIP Analysis Directories"

info "Removing analysis WIP for stem: $STEM"

# Remove per-stem subdirectories created by TYPE A modules
find "$ANALYSIS" -mindepth 2 -maxdepth 2 -type d -name "$STEM" -exec rm -rf {} + 2>/dev/null || true

# Remove per-stem subdirectories created by TYPE B modules (named <stem> inside base dir)
for mod_dir in "$ANALYSIS"/*/; do
    [[ -d "${mod_dir}${STEM}" ]] && rm -rf "${mod_dir}${STEM}"
done

# Copy reports to a persistent directory when requested (used by batch_analyze.sh
# so the batch report generator can read FAN reports after WIP cleanup)
if [[ -n "$REPORTS_PERSIST_DIR" ]]; then
    mkdir -p "$REPORTS_PERSIST_DIR"
    cp -f "$CASE_DIR"/*.md   "$REPORTS_PERSIST_DIR/" 2>/dev/null || true
    cp -f "$DOCS_DIR"/*.pdf  "$REPORTS_PERSIST_DIR/" 2>/dev/null || true
    ok "FAN reports copied to: $REPORTS_PERSIST_DIR"
fi

# Remove the temporary reports dir
rm -rf "$REPORTS_TMP"

# Remove any empty module directories left behind
find "$ANALYSIS" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true

ok "Analysis directory cleaned."

# ── Summary ───────────────────────────────────────────────────────────────────
header "Investigation Complete"
ok "Case ID   : $CASE_ID"
ok "Report    : uploaded to investigations vault"
echo ""
info "Steps: ${STEP_PASS} passed, ${STEP_FAIL} failed"
[[ $STEP_FAIL -gt 0 ]] && warn "Some modules had errors — check output above."
