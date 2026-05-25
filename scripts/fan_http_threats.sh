#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# fan_http_threats.sh — CTI HTTP(S) Unusual Pattern Analyzer
#
# Detects unusual HTTP/HTTPS patterns in a PCAP file.
#
# Usage:
#   fan_http_threats.sh <pcap_file> [--stem NAME] [--case-id ID]
#                       [--output-dir DIR] [--no-vault]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_http_threats.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/fan_http_threats.py" "$@"
