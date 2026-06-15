#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
#
# configure_vault.sh — persist the investigations vault destination for every future shell
#
# USAGE:
#   ./scripts/configure_vault.sh user@host /remote/root [ssh_key_path]
#
# Writes/updates INVESTIGATIONS_SSH_HOST, INVESTIGATIONS_ROOT, and
# INVESTIGATIONS_SSH_KEY export lines in ~/.soc_env (idempotent — re-running with
# new values replaces the old ones), creating ~/.soc_env from
# templates/set_env_template.sh if it doesn't exist yet, and exports them in the
# current shell immediately.
#
# After running this, lib/investigations_upload.py, lib/case_packager.py, and
# scripts/remove_case.sh will use this destination for all uploads. Open a new
# terminal (or `source ~/.soc_env`) to pick it up in other shells.
set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "Usage: $0 user@host /remote/root [ssh_key_path]" >&2
    exit 1
fi

SSH_HOST="$1"
REMOTE_ROOT="$2"
SSH_KEY="${3:-$HOME/.ssh/id_ed25519}"

if [[ "$SSH_HOST" != *@* ]]; then
    echo "[configure_vault] Warning: '${SSH_HOST}' does not look like user@host (continuing anyway)" >&2
fi

case "$SSH_KEY" in
    ~*) SSH_KEY="${SSH_KEY/#\~/$HOME}" ;;
esac

SOC_ENV="$HOME/.soc_env"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$PROJECT_ROOT/templates/set_env_template.sh"

if [[ ! -f "$SOC_ENV" ]]; then
    if [[ -f "$TEMPLATE" ]]; then
        cp "$TEMPLATE" "$SOC_ENV"
        echo "[configure_vault] Created ${SOC_ENV} from templates/set_env_template.sh"
    else
        : > "$SOC_ENV"
        echo "[configure_vault] Created empty ${SOC_ENV}"
    fi
fi

_set_var() {
    local name="$1" value="$2"
    local line="export ${name}=\"${value}\""
    if grep -qE "^export ${name}=" "$SOC_ENV"; then
        sed -i.bak -E "s|^export ${name}=.*|${line}|" "$SOC_ENV"
        rm -f "${SOC_ENV}.bak"
    else
        {
            echo ""
            echo "# configure_vault.sh: investigations vault destination"
            echo "$line"
        } >> "$SOC_ENV"
    fi
    export "${name}=${value}"
}

_set_var INVESTIGATIONS_SSH_HOST "$SSH_HOST"
_set_var INVESTIGATIONS_ROOT "$REMOTE_ROOT"
_set_var INVESTIGATIONS_SSH_KEY "$SSH_KEY"

echo "[configure_vault] Investigations vault configured:"
echo "[configure_vault]   INVESTIGATIONS_SSH_HOST=${SSH_HOST}"
echo "[configure_vault]   INVESTIGATIONS_ROOT=${REMOTE_ROOT}"
echo "[configure_vault]   INVESTIGATIONS_SSH_KEY=${SSH_KEY}"
echo "[configure_vault] Saved to ${SOC_ENV} and exported for this shell."
echo "[configure_vault] Add 'source ~/.soc_env' to ~/.bashrc if you haven't already,"
echo "[configure_vault] or open a new terminal for it to apply automatically."
