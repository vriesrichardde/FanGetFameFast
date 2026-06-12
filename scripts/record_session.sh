#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# record_session.sh — shared chain-of-evidence session recorder.
#
# Single source of truth for capturing the active Claude Code coordination
# session as a chain-of-evidence document set (Markdown + PDF + verbatim .jsonl,
# SHA-256 fingerprinted) via lib/chat_recorder.py. Every analysis entry-point
# script sources this file and calls fgff_record_session, so that running any
# investigation always saves the chat transcript.
#
# Recording must NEVER fail the investigation: all errors are downgraded to a
# warning and the function still returns 0.
#
# Usage:
#   source "<scripts_dir>/record_session.sh"
#   fgff_record_session <case_id> <output_dir> [upload:0|1]
#
#   <case_id>     case or batch identifier, used in the output filenames
#   <output_dir>  directory for the transcript (must survive WIP cleanup,
#                 e.g. ./reports) — path-guard enforced by chat_recorder.py
#   [upload]      1 = also upload to the investigations vault, 0/omitted = local only
# ─────────────────────────────────────────────────────────────────────────────

fgff_record_session() {
    local case_id="${1:-}"
    local out_dir="${2:-}"
    local do_upload="${3:-0}"
    local case_dir="${4:-${FGFF_CASE_DIR:-}}"

    # Validate gently: a missing argument must not abort the investigation, so
    # warn and return success rather than using ${x:?} (which hard-exits under
    # `set -e` and cannot be caught with `|| true`).
    if [[ -z "$case_id" ]]; then
        echo "[record] WARNING: case_id missing; skipping transcript (analysis unaffected)." >&2
        return 0
    fi
    if [[ -z "$case_dir" && -z "$out_dir" ]]; then
        echo "[record] WARNING: output_dir missing; skipping transcript (analysis unaffected)." >&2
        return 0
    fi

    # Resolve the project root from this file's location, so the helper works
    # regardless of which script (or directory) calls it.
    local proj
    proj="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

    echo "[record] Recording session transcript (chain of evidence) for ${case_id}..."
    local args=(--case-id "$case_id")
    if [[ -n "$case_dir" ]]; then
        args+=(--case-dir "$case_dir")
    else
        args+=(--output-dir "$out_dir")
    fi
    [[ "$do_upload" -eq 1 ]] && args+=(--upload)

    if python3 "$proj/lib/chat_recorder.py" "${args[@]}"; then
        return 0
    fi
    echo "[record] WARNING: session transcript recording failed (analysis unaffected)." >&2
    return 0
}
