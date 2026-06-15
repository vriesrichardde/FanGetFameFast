#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
#
# ensure_evidence_path.sh — persist EVIDENCE_PATH for every future shell
#
# USAGE:
#   ./scripts/ensure_evidence_path.sh /path/to/evidence
#
# Run this on the HOST (not inside the devcontainer): .devcontainer/devcontainer.json
# resolves "${localEnv:EVIDENCE_PATH}" from the environment of the shell/process
# that launches VS Code, so EVIDENCE_PATH must be set on the host before the
# Dev Containers extension reads it.
#
# This script writes/updates an `export EVIDENCE_PATH=...` line in ~/.bashrc
# (idempotent — re-running with a new path replaces the old one) and exports it
# in the current shell immediately. Open a new terminal (or restart VS Code from
# one) for the devcontainer mount to pick it up.
set -euo pipefail

if [[ $# -ne 1 ]]; then
    echo "Usage: $0 /path/to/evidence" >&2
    exit 1
fi

# Resolve to an absolute path.
EVIDENCE_DIR="$1"
case "$EVIDENCE_DIR" in
    /*) ;;
    ~*) EVIDENCE_DIR="${EVIDENCE_DIR/#\~/$HOME}" ;;
    *)  EVIDENCE_DIR="$(pwd)/$EVIDENCE_DIR" ;;
esac

if [[ ! -d "$EVIDENCE_DIR" ]]; then
    echo "[ensure_evidence_path] Warning: ${EVIDENCE_DIR} does not exist (continuing anyway)" >&2
fi

EXPORT_LINE="export EVIDENCE_PATH=\"${EVIDENCE_DIR}\""

# On macOS, write to ~/.zshenv (always sourced by zsh, including GUI-launched VS Code)
# and ~/.zshrc (interactive shells). On Linux, write to ~/.bashrc.
persist_to_file() {
    local rc_file="$1"
    if [[ -f "$rc_file" ]] && grep -qE '^export EVIDENCE_PATH=' "$rc_file"; then
        sed -i.bak -E "s|^export EVIDENCE_PATH=.*|${EXPORT_LINE}|" "$rc_file"
        rm -f "${rc_file}.bak"
        echo "[ensure_evidence_path] Updated EVIDENCE_PATH in ${rc_file} -> ${EVIDENCE_DIR}"
    else
        {
            echo ""
            echo "# ensure_evidence_path.sh: FanGetFameFast devcontainer evidence mount"
            echo "$EXPORT_LINE"
        } >> "$rc_file"
        echo "[ensure_evidence_path] Added EVIDENCE_PATH to ${rc_file} -> ${EVIDENCE_DIR}"
    fi
}

if [[ "$(uname -s)" == "Darwin" ]]; then
    # macOS: zsh is the default shell. ~/.zshenv is always sourced (including by
    # GUI apps such as VS Code), so the devcontainer extension sees the variable.
    # ~/.zshrc covers interactive terminal sessions.
    persist_to_file "$HOME/.zshenv"
    persist_to_file "$HOME/.zshrc"
    SOURCE_HINT="source $HOME/.zshenv"
else
    persist_to_file "$HOME/.bashrc"
    SOURCE_HINT="source $HOME/.bashrc"
fi

export EVIDENCE_PATH="$EVIDENCE_DIR"

echo "[ensure_evidence_path] EVIDENCE_PATH is set for this shell. Run '${SOURCE_HINT}' or open a new terminal,"
echo "[ensure_evidence_path] then rebuild/reopen the devcontainer for the mount to apply."
