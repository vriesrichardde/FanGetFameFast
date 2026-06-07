#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# generate_pcap_report.sh — PCAP Incident Report Generator
#
# Aggregates all protocol threat analysis outputs into a structured MD + PDF report.
#
# Usage:
#   generate_pcap_report.sh --stem <stem> [--case-id <id>] [--output-dir <dir>]
#                           [--base-dir <analysis-dir>] [--report-version <n>]
#
# --base-dir    : root of analysis subdirectories (default: ./analysis/)
# --report-version : version number stamped in the report header (default: 1)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

if [[ $# -eq 0 ]]; then
    python3 "$PROJECT_ROOT/lib/generate_pcap_report.py" --help
    exit 0
fi

exec python3 "$PROJECT_ROOT/lib/generate_pcap_report.py" "$@"
