#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# package_artifacts.sh — shared artifact bundler + vault uploader.
#
# Single source of truth for packaging an investigation's complete artifact set
# (reports of every type, the chain-of-evidence chat transcript, exhibit images,
# evidence ZIPs, …) into a timestamped <case_id>_<ts>.zip with a SHA-256
# integrity manifest, and uploading it to the investigations vault. Backed by
# `lib/case_packager.py --all`, which is format-agnostic (unlike the legacy
# PCAP-only packager path).
#
# Every analysis entry-point sources this file and calls fgff_package_artifacts
# AFTER the chat transcript is recorded, so the bundle includes the transcript.
#
# Recording/packaging must NEVER fail the investigation: all errors are
# downgraded to a warning and the function still returns 0.
#
# Usage:
#   source "<scripts_dir>/package_artifacts.sh"
#   fgff_package_artifacts <case_id> <reports_dir> <output_dir> <stem> <upload:0|1> [extra_reports_dir...]
#
#   <case_id>      case or batch identifier (also the ZIP name prefix)
#   <reports_dir>  primary directory holding the case artifacts
#   <output_dir>   where to write the ZIP (e.g. ./exports) — path-guard enforced
#   <stem>         evidence stem; pass "" when it equals the case id (FAME/FAST)
#   <upload>       1 = also upload to the investigations vault, 0 = local only
#   [extra ...]    additional report directories to scan (e.g. FAN's temp dir)
# ─────────────────────────────────────────────────────────────────────────────

fgff_package_artifacts() {
    local case_id="${1:-}"
    local reports_dir="${2:-}"
    local output_dir="${3:-}"
    local stem="${4:-}"
    local do_upload="${5:-0}"
    [[ $# -ge 5 ]] && shift 5 || shift $#   # remaining args = extra report dirs

    if [[ -z "$case_id" || -z "$reports_dir" || -z "$output_dir" ]]; then
        echo "[package] WARNING: case_id/reports_dir/output_dir missing; skipping artifact bundle (analysis unaffected)." >&2
        return 0
    fi

    local proj
    proj="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    mkdir -p "$output_dir" 2>/dev/null || true

    # When FGFF_CASE_DIR is set (new hierarchical layout), pass --case-dir so
    # the packager collects from the case tree and writes the ZIP to case_dir/output/.
    local case_dir="${FGFF_CASE_DIR:-}"
    local args=(--all --case-id "$case_id" --reports-dir "$reports_dir")
    if [[ -n "$case_dir" ]]; then
        args+=(--case-dir "$case_dir")
    else
        args+=(--output-dir "$output_dir")
    fi
    [[ -n "$stem" ]] && args+=(--stem "$stem")
    local d
    for d in "$@"; do
        [[ -n "$d" ]] && args+=(--extra-reports-dir "$d")
    done
    [[ "$do_upload" -eq 1 ]] && args+=(--upload)

    echo "[package] Bundling all artifacts for ${case_id}..."
    if python3 "$proj/lib/case_packager.py" "${args[@]}"; then
        return 0
    fi
    echo "[package] WARNING: artifact bundling/upload failed (analysis unaffected)." >&2
    return 0
}
