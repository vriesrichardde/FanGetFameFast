#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# remove_case.sh — Remove an investigation from the investigations vault.
#
# Deletes the case folder from the remote investigations vault via SSH,
# and removes the Obsidian vault note for the case.
#
# Usage:
#   remove_case.sh                        # interactive: lists cases on remote
#   remove_case.sh FAN-2025-001          # specify case ID directly
#   remove_case.sh FAN-2025-001 --keep-vault   # keep Obsidian note
#   remove_case.sh FAN-2025-001 --force  # skip confirmation prompt

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

SSH_HOST="${INVESTIGATIONS_SSH_HOST:-sansforensics@ubuntudesktop}"
REMOTE_ROOT="${INVESTIGATIONS_ROOT:-/home/sansforensics/cases}"

C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_RED='\033[0;31m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
info()   { echo -e "${C_CYAN}[*]${C_RESET} $*"; }
ok()     { echo -e "${C_GREEN}[+]${C_RESET} $*"; }
warn()   { echo -e "${C_YELLOW}[!]${C_RESET} $*"; }
err()    { echo -e "${C_RED}[✗]${C_RESET} $*" >&2; }
header() {
    echo ""
    echo -e "${C_BOLD}${C_CYAN}══════════════════════════════════════════${C_RESET}"
    echo -e "${C_BOLD}  $*${C_RESET}"
    echo -e "${C_BOLD}${C_CYAN}══════════════════════════════════════════${C_RESET}"
}

CASE_ID=""
KEEP_VAULT=0
FORCE=0

usage() {
    cat <<'EOF'
Usage: remove_case.sh [CASE_ID] [OPTIONS]

Options:
  --keep-vault    Do not remove the Obsidian vault note for this case
  --force         Skip confirmation prompt
  -h, --help      Show this help
EOF
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-vault) KEEP_VAULT=1; shift ;;
        --force)      FORCE=1;      shift ;;
        -h|--help)    usage ;;
        -*)           err "Unknown option: $1"; exit 1 ;;
        *)            CASE_ID="$1"; shift ;;
    esac
done

header "Remove Investigation Case"

# ── Interactive case selection ────────────────────────────────────────────────
if [[ -z "$CASE_ID" ]]; then
    info "Fetching case list from $SSH_HOST:$REMOTE_ROOT ..."
    CASES=()
    while IFS= read -r line; do
        [[ -n "$line" ]] && CASES+=("$line")
    done < <(ssh "$SSH_HOST" "ls -1 $REMOTE_ROOT 2>/dev/null" || true)

    if [[ ${#CASES[@]} -eq 0 ]]; then
        info "No cases found on $SSH_HOST:$REMOTE_ROOT"
        exit 0
    fi

    echo -e "${C_BOLD}Available cases:${C_RESET}"
    for i in "${!CASES[@]}"; do
        printf "  ${C_CYAN}[%2d]${C_RESET} %s\n" "$((i+1))" "${CASES[$i]}"
    done
    echo ""
    read -r -p "$(echo -e "${C_CYAN}Select case to remove [1-${#CASES[@]}]: ${C_RESET}")" CHOICE

    if [[ "$CHOICE" =~ ^[0-9]+$ ]] && \
       [[ "$CHOICE" -ge 1 ]] && [[ "$CHOICE" -le "${#CASES[@]}" ]]; then
        CASE_ID="${CASES[$((CHOICE-1))]}"
    else
        err "Invalid selection."; exit 1
    fi
fi

# ── Show what will be removed ─────────────────────────────────────────────────
echo ""
warn "The following will be permanently deleted:"
echo "  - Remote case folder : $SSH_HOST:$REMOTE_ROOT/$CASE_ID/"
if [[ $KEEP_VAULT -eq 0 ]]; then
    VAULT_NOTE="$PROJECT_ROOT/vault/Cases/${CASE_ID}.md"
    [[ -f "$VAULT_NOTE" ]] && echo "  - Vault note         : $VAULT_NOTE"
fi
echo ""

# ── Confirm ───────────────────────────────────────────────────────────────────
if [[ $FORCE -eq 0 ]]; then
    read -r -p "$(echo -e "${C_RED}Type the case ID to confirm deletion [${CASE_ID}]: ${C_RESET}")" CONFIRM
    if [[ "$CONFIRM" != "$CASE_ID" ]]; then
        info "Cancelled — case ID did not match."
        exit 0
    fi
fi

# ── Remove remote case folder ─────────────────────────────────────────────────
info "Removing $SSH_HOST:$REMOTE_ROOT/$CASE_ID/ ..."
ssh "$SSH_HOST" "rm -rf $REMOTE_ROOT/$CASE_ID" && ok "Remote case folder removed."

# ── Remove vault note ─────────────────────────────────────────────────────────
if [[ $KEEP_VAULT -eq 0 ]]; then
    VAULT_NOTE="$PROJECT_ROOT/vault/Cases/${CASE_ID}.md"
    if [[ -f "$VAULT_NOTE" ]]; then
        rm -f "$VAULT_NOTE"
        ok "Vault note removed: $VAULT_NOTE"
    else
        info "No vault note found for $CASE_ID — nothing to remove."
    fi
fi

ok "Case $CASE_ID removed successfully."
