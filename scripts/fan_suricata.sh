#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# fan_suricata.sh — Thin wrapper around lib/fan_suricata.py
#
# Usage:
#   ./scripts/fan_suricata.sh /path/to/capture.pcap
#   ./scripts/fan_suricata.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001
#   ./scripts/fan_suricata.sh /path/to/capture.pcap --output-dir /custom/path --no-vault

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
exec python3 "$PROJECT_ROOT/lib/fan_suricata.py" "$@"
