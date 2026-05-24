#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# generate_pcap_presentation.sh — PCAP Incident PowerPoint Briefing Generator
#
# Shell wrapper around lib/generate_presentation.py.
# Accepts the same arguments as generate_pcap_report.sh for pipeline consistency.
#
# Usage:
#   generate_pcap_presentation.sh --stem <stem> [--case-id <id>]
#                                 [--output-dir <dir>] [--base-dir <dir>]
#                                 [--report-version <n>]

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/generate_presentation.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/generate_presentation.py" "$@"
