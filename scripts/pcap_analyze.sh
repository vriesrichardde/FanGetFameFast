#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# pcap_analyze.sh — FAN Extract IP+FQDN
#
# Usage:
#   pcap_analyze.sh <pcap_file> [--case-id <id>] [--output-dir <dir>]
#
# Outputs (written to ./analysis/pcap/<pcap_stem>/):
#   netflow.csv       — per-flow conversation stats
#   unique_ips.txt    — unique IPv4 and IPv6 addresses
#   unique_fqdns.txt  — unique FQDNs (DNS / HTTP Host / TLS SNI)
#   report.md         — summary report

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/pcap_analyzer.py" --help
    exit 0
fi

# Verify tshark is available
if ! command -v tshark &>/dev/null; then
    echo "[pcap_analyze] ERROR: tshark not found. Install with: sudo apt install tshark" >&2
    exit 1
fi

exec python3 "$PROJECT_ROOT/lib/pcap_analyzer.py" "$@"
