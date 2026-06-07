#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# fan_file_hashes.sh — Extract files from PCAP and compute MD5/SHA256 hashes
#
# Usage:
#   fan_file_hashes.sh /path/to/capture.pcap
#   fan_file_hashes.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001
#   fan_file_hashes.sh /path/to/capture.pcap --output-dir /custom/path --no-vault

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_file_hashes.py" --help
    exit 0
fi

if ! command -v tshark &>/dev/null; then
    echo "[fan_file_hashes] ERROR: tshark not found. Install with: sudo apt install tshark" >&2
    exit 1
fi

exec python3 "$PROJECT_ROOT/lib/fan_file_hashes.py" "$@"
