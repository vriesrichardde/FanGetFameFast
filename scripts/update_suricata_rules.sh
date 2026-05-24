#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# update_suricata_rules.sh — Update Suricata rules via suricata-update
#
# Runs: sudo suricata-update (NOPASSWD via /etc/sudoers.d/fangetfamefast)
# Then copies /var/lib/suricata/rules/suricata.rules into rules/suricata/
# so fan_suricata analysis picks up the latest rules immediately.
#
# The NOPASSWD sudoers entry is installed by scripts/setup_sudoers.sh (called
# from install_dependencies.sh). Without it, running this script non-interactively
# (e.g., from analyze_pcap.sh) will fail with a "terminal required" error.
#
# Usage:
#   ./scripts/update_suricata_rules.sh            # update ET Open rules
#   ./scripts/update_suricata_rules.sh --et-only  # same — ET Open is the default
#   ./scripts/update_suricata_rules.sh --list     # list available rule sources

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RULES_DIR="$PROJECT_ROOT/rules/suricata"
SYSTEM_RULES="/var/lib/suricata/rules/suricata.rules"

C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_RESET='\033[0m'
info() { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()   { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
err()  { echo -e "${C_RED}[✗]${C_RESET} $*" >&2; }

if ! command -v suricata-update &>/dev/null; then
    err "suricata-update not found. Install: sudo apt install suricata"
    exit 1
fi

# Parse flags
ET_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --list)    suricata-update list-sources; exit 0 ;;
        --et-only) ET_ONLY=1 ;;   # suricata-update uses ET Open by default — no extra action needed
        *) err "Unknown option: $arg"; exit 1 ;;
    esac
done

if [[ $ET_ONLY -eq 1 ]]; then
    info "Running: sudo suricata-update (ET Open rules)"
else
    info "Running: sudo suricata-update"
fi

sudo suricata-update

if [[ ! -f "$SYSTEM_RULES" ]]; then
    err "Expected rules file not found: $SYSTEM_RULES"
    err "Ensure suricata-update ran successfully."
    exit 1
fi

mkdir -p "$RULES_DIR"
cp "$SYSTEM_RULES" "$RULES_DIR/suricata.rules"
RULE_COUNT=$(grep -c "^alert" "$RULES_DIR/suricata.rules" || true)
ok "Rules copied to: $RULES_DIR/suricata.rules ($RULE_COUNT alert rules)"
