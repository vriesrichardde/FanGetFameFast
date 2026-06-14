#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# fan_silk_analysis.sh — SiLK flow-level threat analyzer
#
# Converts a PCAP to SiLK binary flows (via yaf + rwipfix2silk) and runs
# seven statistical analyses: top talkers, scanners, traffic timeline,
# long-lived connections, protocol distribution, service matrix, and
# bytes-per-flow outliers.
#
# Requires: silk-tools, yaf  (sudo apt install silk-tools yaf)
#
# Usage:
#   fan_silk_analysis.sh <pcap_file> [--case-id <id>] [--stem <name>]
#   fan_silk_analysis.sh <pcap_file> --no-vault
#
# Outputs to ./analysis/silk_analysis/<stem>/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_silk_analysis.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/fan_silk_analysis.py" "$@"
