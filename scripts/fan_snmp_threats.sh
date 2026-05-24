#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/fan_snmp_threats.py" --help
    exit 0
fi
exec python3 "$PROJECT_ROOT/lib/fan_snmp_threats.py" "$@"
