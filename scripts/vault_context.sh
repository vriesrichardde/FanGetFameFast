#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# vault_context.sh — query the SOC Obsidian vault from the shell
# Usage:
#   vault_context.sh search <keyword>
#   vault_context.sh ioc <value>
#   vault_context.sh ttp <mitre_id>
#   vault_context.sh cases
#   vault_context.sh risks [n]
#   vault_context.sh backlinks <note_title>

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VAULT_QUERY="$PROJECT_ROOT/lib/vault_query.py"

if [[ $# -eq 0 ]]; then
    python3 "$VAULT_QUERY" --help
    exit 0
fi

COMMAND="$1"
shift

case "$COMMAND" in
    search)   python3 "$VAULT_QUERY" --search "$*" ;;
    ioc)      python3 "$VAULT_QUERY" --ioc "$1" ;;
    ttp)      python3 "$VAULT_QUERY" --ttp "$1" ;;
    cases)    python3 "$VAULT_QUERY" --cases ;;
    risks)    python3 "$VAULT_QUERY" --risks "${1:-10}" ;;
    backlinks) python3 "$VAULT_QUERY" --backlinks "$1" ;;
    *)
        echo "Unknown command: $COMMAND"
        echo "Valid commands: search | ioc | ttp | cases | risks | backlinks"
        exit 1
        ;;
esac
