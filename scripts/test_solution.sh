#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# test_solution.sh — End-to-end smoke test for the FAN PCAP analysis pipeline.
#
# Tests every analysis module non-interactively and verifies expected output
# files exist. Does NOT require a Perplexity API key and skips vault writes.
# All WIP output is written to ./analysis/ and cleaned up after the test.
#
# Usage:
#   ./scripts/test_solution.sh /path/to/test.pcap
#   ./scripts/test_solution.sh                     # generates a minimal test PCAP

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# ── Colour helpers ────────────────────────────────────────────────────────────
C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
ok()    { echo -e "${C_GREEN}[PASS]${C_RESET} $*"; PASSED=$((PASSED+1)); }
fail()  { echo -e "${C_RED}[FAIL]${C_RESET} $*"; FAILED=$((FAILED+1)); }
info()  { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
warn()  { echo -e "${C_YELLOW}[ -- ]${C_RESET} $*"; SKIPPED=$((SKIPPED+1)); }
header(){ echo ""; echo -e "${C_BOLD}${C_CYAN}══ $* ══${C_RESET}"; }

PASSED=0; FAILED=0; SKIPPED=0

# ── Accept or generate test PCAP ─────────────────────────────────────────────
TEST_PCAP="${1:-}"
GENERATED=0

if [[ -z "$TEST_PCAP" ]]; then
    info "No PCAP provided — attempting to generate a minimal test PCAP with scapy ..."
    TEST_PCAP="$PROJECT_ROOT/analysis/test_minimal.pcap"
    mkdir -p "$(dirname "$TEST_PCAP")"
    python3 - "$TEST_PCAP" <<'PYEOF'
import sys
out = sys.argv[1]
try:
    from scapy.all import (Ether, IP, TCP, UDP, DNS, DNSQR, ICMP,
                            ARP, wrpcap, RandShort)
    pkts = []
    # ICMP echo
    pkts.append(Ether()/IP(src="10.0.0.1",dst="10.0.0.2")/ICMP())
    # DNS query
    pkts.append(Ether()/IP(src="10.0.0.1",dst="8.8.8.8")/
                UDP(sport=1234,dport=53)/DNS(rd=1,qd=DNSQR(qname="example.com")))
    # HTTP SYN
    pkts.append(Ether()/IP(src="10.0.0.1",dst="93.184.216.34")/
                TCP(sport=int(RandShort()),dport=80,flags="S"))
    # ARP who-has
    pkts.append(Ether(dst="ff:ff:ff:ff:ff:ff")/
                ARP(op=1,psrc="10.0.0.1",pdst="10.0.0.2"))
    # NTP (UDP 123)
    pkts.append(Ether()/IP(src="10.0.0.1",dst="129.6.15.28")/
                UDP(sport=int(RandShort()),dport=123)/b"\x1b"+b"\x00"*47)
    wrpcap(out, pkts)
    print(f"[test] Generated: {out} ({len(pkts)} packets)")
except ImportError:
    import struct
    GLOBAL = struct.pack("<IHHiIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
    frame = b"\xff"*6 + b"\x00"*6 + b"\x08\x00" + b"\x45\x00\x00\x28" + \
            b"\x00\x01\x00\x00\x40\x01\x00\x00" + \
            b"\x0a\x00\x00\x01" + b"\x0a\x00\x00\x02" + \
            b"\x08\x00\x00\x00\x00\x01\x00\x01" + b"\x00"*8
    PKT_HDR = struct.pack("<IIII", 1000000, 0, len(frame), len(frame))
    with open(out, "wb") as f:
        f.write(GLOBAL + PKT_HDR + frame)
    print(f"[test] Generated minimal fallback PCAP: {out}")
PYEOF
    GENERATED=1
fi

if [[ ! -f "$TEST_PCAP" ]]; then
    echo -e "${C_RED}[ERROR]${C_RESET} PCAP not found: $TEST_PCAP"
    exit 1
fi

STEM="$(basename "$TEST_PCAP")"
STEM="${STEM%.pcapng}"
STEM="${STEM%.pcap}"
TEST_CASE_ID="TEST-$(date -u +%Y%m%d-%H%M%S)"

info "PCAP     : $TEST_PCAP"
info "Stem     : $STEM"
info "Case ID  : $TEST_CASE_ID"
info "Project  : $PROJECT_ROOT"
echo ""

# ── Helper: check file exists ─────────────────────────────────────────────────
check_file() {
    local label="$1"; local path="$2"
    if [[ -f "$path" ]]; then
        ok "$label: $(basename "$path")"
    else
        fail "$label: $path (not found)"
    fi
}

# ── 1. Python imports ─────────────────────────────────────────────────────────
header "Python Imports"
for mod in generate_pcap_report fan_file_hashes knowledge_extractor; do
    if python3 -c "import sys; sys.path.insert(0,'lib'); import $mod" 2>/dev/null; then
        ok "import $mod"
    else
        fail "import $mod"
    fi
done

# ── 2. Dependencies ───────────────────────────────────────────────────────────
header "Dependencies"
if command -v tshark &>/dev/null; then
    VER=$(tshark --version 2>/dev/null | head -1)
    ok "tshark: $VER"
else
    fail "tshark: not found (required)"
fi

if command -v python3 &>/dev/null; then
    ok "python3: $(python3 --version 2>&1)"
else
    fail "python3: not found"
fi

# ── WIP analysis dirs ─────────────────────────────────────────────────────────
ANALYSIS="$PROJECT_ROOT/analysis"
REPORTS_TMP="$ANALYSIS/_test_reports/$STEM"
mkdir -p "$REPORTS_TMP"

full() { echo "$ANALYSIS/$1/$STEM"; }
base() { echo "$ANALYSIS/$1"; }

# ── 3. Individual analysis modules ────────────────────────────────────────────
header "Analysis Modules"

run_module() {
    local label="$1"; shift
    local json_path="$1"; shift
    if "$@" >/dev/null 2>&1; then
        check_file "$label" "$json_path"
    else
        fail "$label: script exited with error"
    fi
}

run_module "pcap_analyzer" "$(full pcap)/netflow.csv" \
    "$SCRIPT_DIR/pcap_analyze.sh" "$TEST_PCAP" \
    --output-dir "$(full pcap)" --case-id "$TEST_CASE_ID"

run_module "fan_icmp_threats" "$(base icmp_threats)/$STEM/icmp_threats.json" \
    "$SCRIPT_DIR/fan_icmp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(base icmp_threats)" --no-vault

run_module "fan_dns_threats" "$(full dns_threats)/dns_threats.json" \
    "$SCRIPT_DIR/fan_dns_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full dns_threats)" --no-vault

run_module "fan_ntp_threats" "$(base ntp_threats)/$STEM/ntp_threats.json" \
    "$SCRIPT_DIR/fan_ntp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(base ntp_threats)" --no-vault

run_module "fan_http_threats" "$(base http_threats)/$STEM/http_threats.json" \
    "$SCRIPT_DIR/fan_http_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(base http_threats)" --no-vault

run_module "fan_cert_inspector" "$(full cert_inspector)/certs.json" \
    "$SCRIPT_DIR/fan_cert_inspector.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full cert_inspector)" --no-vault

run_module "fan_tls_inspector" "$(full tls_inspector)/tls_sessions.json" \
    "$SCRIPT_DIR/fan_tls_inspector.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full tls_inspector)" --no-vault

run_module "fan_arp_threats" "$(full arp_threats)/arp_threats.json" \
    "$SCRIPT_DIR/fan_arp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full arp_threats)" --no-vault

run_module "fan_tcp_threats" "$(full tcp_threats)/tcp_threats.json" \
    "$SCRIPT_DIR/fan_tcp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full tcp_threats)" --no-vault

run_module "fan_udp_threats" "$(full udp_threats)/udp_threats.json" \
    "$SCRIPT_DIR/fan_udp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full udp_threats)" --no-vault

run_module "fan_dhcp_threats" "$(full dhcp_threats)/dhcp_threats.json" \
    "$SCRIPT_DIR/fan_dhcp_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full dhcp_threats)" --no-vault

run_module "fan_mdns_threats" "$(full mdns_threats)/mdns_threats.json" \
    "$SCRIPT_DIR/fan_mdns_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full mdns_threats)" --no-vault

run_module "fan_quic_threats" "$(full quic_threats)/quic_threats.json" \
    "$SCRIPT_DIR/fan_quic_threats.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full quic_threats)" --no-vault

run_module "fan_file_hashes" "$(full file_hashes)/file_hashes.json" \
    "$SCRIPT_DIR/fan_file_hashes.sh" "$TEST_PCAP" \
    --stem "$STEM" --case-id "$TEST_CASE_ID" \
    --output-dir "$(full file_hashes)" --no-vault --no-osint

# ── 4. Report generation ──────────────────────────────────────────────────────
header "Report Generation"

if "$SCRIPT_DIR/generate_pcap_report.sh" \
    --stem "$STEM" \
    --case-id "$TEST_CASE_ID" \
    --output-dir "$REPORTS_TMP" \
    --base-dir "$ANALYSIS" \
    --report-version 1 >/dev/null 2>&1; then
    check_file "incident report MD" "$REPORTS_TMP/${STEM}_incident_report.md"
else
    fail "generate_pcap_report: script exited with error"
fi

# ── 5. Script permissions ─────────────────────────────────────────────────────
header "Script Permissions"
for s in "$SCRIPT_DIR"/*.sh; do
    name="$(basename "$s")"
    if [[ -x "$s" ]]; then
        ok "chmod +x $name"
    else
        fail "$name is not executable"
    fi
done

# ── Cleanup WIP ───────────────────────────────────────────────────────────────
header "Cleanup"
find "$ANALYSIS" -mindepth 2 -maxdepth 2 -type d -name "$STEM" -exec rm -rf {} + 2>/dev/null || true
rm -rf "$REPORTS_TMP"
find "$ANALYSIS" -mindepth 1 -maxdepth 1 -type d -empty -delete 2>/dev/null || true
[[ $GENERATED -eq 1 && -f "$TEST_PCAP" ]] && rm -f "$TEST_PCAP"
ok "WIP analysis directories cleaned up"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  Test Results${C_RESET}"
echo -e "${C_BOLD}════════════════════════════════════════${C_RESET}"
echo -e "  ${C_GREEN}Passed : $PASSED${C_RESET}"
[[ $FAILED  -gt 0 ]] && echo -e "  ${C_RED}Failed : $FAILED${C_RESET}"   || echo -e "  Failed : 0"
[[ $SKIPPED -gt 0 ]] && echo -e "  ${C_YELLOW}Skipped: $SKIPPED${C_RESET}" || echo -e "  Skipped: 0"
echo ""

[[ $FAILED -eq 0 ]]
