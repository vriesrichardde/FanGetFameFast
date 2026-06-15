#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# package_evidence.sh — shared raw-evidence preserver + zipper.
#
# Single source of truth for snapshotting a module's raw ./analysis/ (or
# equivalent) output into reports/<case_id>/<module_path>/<case_id>_evidence/
# and zipping it to reports/<case_id>/documents/<case_id>_evidence.zip, BEFORE
# the analysis WIP directory is cleaned up. This is what makes
# `--source-data` citations in research notes independently verifiable after
# cleanup.
#
# analyze_pcap.sh / fame_analyze.sh / fast_analyze.sh do this inline today;
# the interactive /fan skill (which does not call analyze_pcap.sh) sources
# this file instead so the step is one deterministic command rather than
# hand-typed rsync/zip.
#
# Must NEVER fail the investigation: all errors are downgraded to a warning
# and the function still returns 0.
#
# Usage:
#   source "<scripts_dir>/package_evidence.sh"
#   fgff_package_evidence <case_id> <case_dir> <src_dir> [evidence_subdir]
#
#   <case_id>         case identifier
#   <case_dir>        module's report directory, e.g. ./reports/<case_id>/FAN/<stem>
#   <src_dir>         raw analysis directory to snapshot, e.g. ./analysis
#   [evidence_subdir] subdir name inside <case_id>_evidence/ (default: analysis)
#
# On success, prints the path to <case_id>_evidence.zip on stdout.
# ─────────────────────────────────────────────────────────────────────────────

fgff_package_evidence() {
    local case_id="${1:-}"
    local case_dir="${2:-}"
    local src_dir="${3:-}"
    local evidence_subdir="${4:-analysis}"

    if [[ -z "$case_id" || -z "$case_dir" || -z "$src_dir" ]]; then
        echo "[evidence] WARNING: case_id/case_dir/src_dir missing; skipping evidence preservation (analysis unaffected)." >&2
        return 0
    fi

    if [[ ! -d "$src_dir" ]]; then
        echo "[evidence] WARNING: source directory '$src_dir' not found; skipping evidence preservation (analysis unaffected)." >&2
        return 0
    fi

    local evidence_dir="$case_dir/${case_id}_evidence"
    mkdir -p "$evidence_dir/$evidence_subdir" 2>/dev/null || true
    if ! rsync -a "$src_dir/" "$evidence_dir/$evidence_subdir/" 2>/dev/null; then
        echo "[evidence] WARNING: rsync of '$src_dir' to '$evidence_dir/$evidence_subdir' failed (analysis unaffected)." >&2
        return 0
    fi
    echo "[evidence] Evidence folder ready: $evidence_dir" >&2

    local case_root docs_dir evidence_zip
    case_root="$(cd "$case_dir/.." 2>/dev/null && pwd)" || true
    # Walk up to reports/<case_id>/ to find documents/, since case_dir may be
    # reports/<case_id>/<MODULE>/<stem>.
    docs_dir="$(dirname "$case_dir")"
    while [[ "$(basename "$docs_dir")" != "$case_id" && "$docs_dir" != "/" && "$docs_dir" != "." ]]; do
        docs_dir="$(dirname "$docs_dir")"
    done
    docs_dir="$docs_dir/documents"
    mkdir -p "$docs_dir" 2>/dev/null || true

    # Resolve to an absolute path before the `cd` below, since $evidence_zip
    # is otherwise interpreted relative to the subshell's new working directory.
    evidence_zip="$(cd "$docs_dir" 2>/dev/null && pwd)/${case_id}_evidence.zip"
    if (cd "$(dirname "$evidence_dir")" && zip -r "$evidence_zip" "$(basename "$evidence_dir")/" -q 2>/dev/null); then
        echo "$evidence_zip"
        return 0
    fi
    echo "[evidence] WARNING: zipping '$evidence_dir' failed (analysis unaffected)." >&2
    return 0
}
