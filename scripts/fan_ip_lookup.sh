#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# fan_ip_lookup.sh — CTI IP Lookup
#
# Correlates PCAP-extracted FQDNs and IPs, resolves DNS, enriches with OSINT,
# and caches results in the Obsidian vault (7-day cache).
#
# Usage:
#   fan_ip_lookup.sh --stem <pcap_stem> [--case-id <id>]
#   fan_ip_lookup.sh <fqdn_file> <ip_file> [--case-id <id>] [--output-dir <dir>]
#
# Requires: PERPLEXITY_API_KEY for live OSINT (optional — vault cache used if unset)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_ip_lookup.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/fan_ip_lookup.py" "$@"
