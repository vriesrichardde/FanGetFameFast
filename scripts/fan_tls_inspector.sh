#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# fan_tls_inspector.sh — TLS Session Inspector
#
# Extracts TLS session metadata and JA4/JA3 fingerprints from a PCAP file.
#
# Usage:
#   fan_tls_inspector.sh <pcap_file> [--stem NAME] [--case-id ID]
#                        [--output-dir DIR] [--no-vault]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_tls_inspector.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/fan_tls_inspector.py" "$@"
