#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# chain_of_custody.sh — shared chain-of-custody manifest updater.
#
# Single source of truth for refreshing an investigation's court-ready
# integrity manifest, reports/<case_id>/documents/<case_id>_chain_of_custody.json,
# via lib/chain_of_custody.py. The manifest records SHA-256/SHA-1/MD5, size and
# timestamps for every file in the case directory (and, when supplied, the
# source evidence file), plus an append-only history of what changed and when.
#
# Every analysis entry-point sources this file and calls fgff_update_custody
# AFTER fgff_record_session and BEFORE fgff_package_artifacts, so the chat
# transcript is captured in the manifest and the manifest itself is bundled
# into the case ZIP.
#
# Updating the manifest must NEVER fail the investigation: all errors are
# downgraded to a warning and the function still returns 0.
#
# Usage:
#   source "<scripts_dir>/chain_of_custody.sh"
#   fgff_update_custody <case_id> <case_dir> [evidence_path ...]
#
#   <case_id>       case identifier
#   <case_dir>      case root directory (reports/<case_id>/) — path-guard enforced
#   [evidence_path] zero or more source evidence files (PCAP/.mem/.E01) to hash
# ─────────────────────────────────────────────────────────────────────────────

fgff_update_custody() {
    local case_id="${1:-}"
    local case_dir="${2:-}"
    [[ $# -ge 2 ]] && shift 2 || shift $#   # remaining args = evidence paths

    if [[ -z "$case_id" || -z "$case_dir" ]]; then
        echo "[custody] WARNING: case_id/case_dir missing; skipping chain-of-custody update (analysis unaffected)." >&2
        return 0
    fi

    local proj
    proj="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    local args=(update --case-id "$case_id" --case-dir "$case_dir" --trigger investigation)
    local ev
    for ev in "$@"; do
        [[ -n "$ev" ]] && args+=(--evidence "$ev")
    done

    echo "[custody] Updating chain-of-custody manifest for ${case_id}..."
    if python3 "$proj/lib/chain_of_custody.py" "${args[@]}"; then
        return 0
    fi
    echo "[custody] WARNING: chain-of-custody manifest update failed (analysis unaffected)." >&2
    return 0
}
