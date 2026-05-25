#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# yara_sweep.sh — standalone YARA sweep of disk directories or memory images
#
# Usage:
#   ./scripts/yara_sweep.sh --target /mnt/windows_mount/
#   ./scripts/yara_sweep.sh --target /path/to/memory.img
#   ./scripts/yara_sweep.sh --target /mnt/windows_mount/ --rules ./rules/yara/
#   ./scripts/yara_sweep.sh --target /path/to/dir/ --threads 4 --fast --case-id CASE-2025-001
#   ./scripts/yara_sweep.sh --target /path/to/dir/ --fp-test        # false-positive test mode

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

RULES_DIR="$PROJECT_ROOT/rules/yara"
OUTPUT_BASE="$PROJECT_ROOT/analysis/yara_sweep"
YARA_BIN="${YARA_BIN:-/usr/local/bin/yara}"

TARGET=""
CASE_ID=""
THREADS=2
FAST_MODE=0
FP_TEST=0
STRINGS_MODE=0
TIMEOUT=120
CUSTOM_RULES=""
COMPILED_RULES=""

usage() {
    echo "Usage: $0 --target <path> [options]"
    echo ""
    echo "Options:"
    echo "  --target <path>        File, directory, or memory image to scan (required)"
    echo "  --rules <dir>          YARA rules directory (default: ./rules/yara/)"
    echo "  --compiled <file>      Use pre-compiled .rules file (skip .yar parsing)"
    echo "  --threads N            Parallel YARA threads (default: 2)"
    echo "  --fast                 Fast mode: first match per rule only (-f)"
    echo "  --strings              Print matching strings with byte offsets (-s)"
    echo "  --timeout N            Skip target after N seconds (default: 120)"
    echo "  --fp-test              False-positive test: scan /usr/bin/ and /usr/lib/ first"
    echo "  --case-id ID           Case ID prefix for output directory"
    echo "  --output-dir <dir>     Custom output directory"
    echo ""
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)       TARGET="$2";        shift 2 ;;
        --rules)        CUSTOM_RULES="$2";  shift 2 ;;
        --compiled)     COMPILED_RULES="$2"; shift 2 ;;
        --threads)      THREADS="$2";       shift 2 ;;
        --fast)         FAST_MODE=1;        shift   ;;
        --strings)      STRINGS_MODE=1;     shift   ;;
        --timeout)      TIMEOUT="$2";       shift 2 ;;
        --fp-test)      FP_TEST=1;          shift   ;;
        --case-id)      CASE_ID="$2";       shift 2 ;;
        --output-dir)   OUTPUT_BASE="$2";   shift 2 ;;
        -h|--help)      usage ;;
        *)              echo "[yara_sweep] Unknown option: $1" >&2; usage ;;
    esac
done

[[ -z "$TARGET" ]] && { echo "[yara_sweep] ERROR: --target is required." >&2; usage; }

# Locate YARA binary
if [[ ! -x "$YARA_BIN" ]]; then
    YARA_BIN=$(command -v yara 2>/dev/null || true)
fi
if [[ -z "$YARA_BIN" || ! -x "$YARA_BIN" ]]; then
    echo "[yara_sweep] ERROR: YARA not found. Install: sudo apt install yara" >&2
    exit 1
fi
YARAC_BIN=$(command -v yarac 2>/dev/null || echo "")

[[ -n "$CUSTOM_RULES" ]] && RULES_DIR="$CUSTOM_RULES"

STEM=$(basename "$TARGET" | tr ' /' '__')
TIMESTAMP=$(date -u +%Y%m%d_%H%M%S)
PREFIX="${CASE_ID:+${CASE_ID}_}${STEM}_${TIMESTAMP}"
OUT_DIR="$OUTPUT_BASE/$PREFIX"
mkdir -p "$OUT_DIR"

HITS_TXT="$OUT_DIR/yara_hits.txt"
STRINGS_TXT="$OUT_DIR/yara_strings.txt"
SUMMARY_TXT="$OUT_DIR/summary.txt"
COMPILED_OUT="$OUT_DIR/compiled.rules"

echo "[yara_sweep] ======================================================"
echo "[yara_sweep] Target  : $TARGET"
echo "[yara_sweep] Rules   : $RULES_DIR"
echo "[yara_sweep] Output  : $OUT_DIR"
echo "[yara_sweep] Threads : $THREADS"
echo "[yara_sweep] Fast    : $FAST_MODE"
echo "[yara_sweep] ======================================================"

# Build base YARA flags
YARA_FLAGS="-p $THREADS --timeout $TIMEOUT"
[[ $FAST_MODE    -eq 1 ]] && YARA_FLAGS="$YARA_FLAGS -f"
[[ -d "$TARGET"         ]] && YARA_FLAGS="$YARA_FLAGS -r"   # recursive for directories

# Compile rules if yarac available and no pre-compiled file given
RULES_ARG=""
if [[ -n "$COMPILED_RULES" && -f "$COMPILED_RULES" ]]; then
    echo "[yara_sweep] Using pre-compiled rules: $COMPILED_RULES"
    RULES_ARG="-C $COMPILED_RULES"
elif [[ -n "$YARAC_BIN" ]]; then
    echo "[yara_sweep] Compiling rules with yarac ..."
    ALL_YAR=()
    while IFS= read -r -d '' f; do
        ALL_YAR+=("$f")
    done < <(find "$RULES_DIR" -maxdepth 2 -name "*.yar" -print0 2>/dev/null)
    if [[ ${#ALL_YAR[@]} -gt 0 ]]; then
        "$YARAC_BIN" "${ALL_YAR[@]}" "$COMPILED_OUT" 2>/dev/null && \
            echo "[yara_sweep] Compiled ${#ALL_YAR[@]} rule file(s) → $COMPILED_OUT" || \
            echo "[yara_sweep] WARNING: yarac failed — falling back to .yar files" >&2
        [[ -f "$COMPILED_OUT" ]] && RULES_ARG="-C $COMPILED_OUT"
    fi
fi

# Fallback: use .yar files directly (joined as separate -i args not supported; use foreach)
run_scan() {
    local target="$1"
    local hits_out="$2"
    local strings_out="$3"

    > "$hits_out"
    [[ -n "$strings_out" ]] && > "$strings_out"

    if [[ -n "$RULES_ARG" ]]; then
        # Compiled rules — single fast invocation
        # shellcheck disable=SC2086
        "$YARA_BIN" $YARA_FLAGS $RULES_ARG "$target" >> "$hits_out" 2>/dev/null
        if [[ $STRINGS_MODE -eq 1 && -n "$strings_out" ]]; then
            # shellcheck disable=SC2086
            "$YARA_BIN" $YARA_FLAGS -s $RULES_ARG "$target" >> "$strings_out" 2>/dev/null
        fi
    else
        # Iterate .yar files
        while IFS= read -r -d '' yar; do
            # shellcheck disable=SC2086
            "$YARA_BIN" $YARA_FLAGS "$yar" "$target" >> "$hits_out" 2>/dev/null
            if [[ $STRINGS_MODE -eq 1 && -n "$strings_out" ]]; then
                # shellcheck disable=SC2086
                "$YARA_BIN" $YARA_FLAGS -s "$yar" "$target" >> "$strings_out" 2>/dev/null
            fi
        done < <(find "$RULES_DIR" -maxdepth 2 -name "*.yar" -print0 2>/dev/null)
    fi
}

# ── False-positive test ───────────────────────────────────────────────────────
if [[ $FP_TEST -eq 1 ]]; then
    echo "[yara_sweep] Running false-positive test against /usr/bin/ ..."
    FP_OUT="$OUT_DIR/fp_test_usrbin.txt"
    FP_FLAGS="-p $THREADS --timeout 30 -r"
    if [[ -n "$RULES_ARG" ]]; then
        # shellcheck disable=SC2086
        "$YARA_BIN" $FP_FLAGS $RULES_ARG /usr/bin/ > "$FP_OUT" 2>/dev/null || true
    else
        while IFS= read -r -d '' yar; do
            # shellcheck disable=SC2086
            "$YARA_BIN" $FP_FLAGS "$yar" /usr/bin/ >> "$FP_OUT" 2>/dev/null || true
        done < <(find "$RULES_DIR" -maxdepth 2 -name "*.yar" -print0 2>/dev/null)
    fi
    FP_COUNT=$(wc -l < "$FP_OUT" 2>/dev/null || echo 0)
    echo "[yara_sweep] FP test hits on /usr/bin/: $FP_COUNT"
    [[ $FP_COUNT -gt 0 ]] && echo "[yara_sweep] WARNING: Review $FP_OUT for false-positive rules before scanning evidence."
fi

# ── Main scan ─────────────────────────────────────────────────────────────────
echo "[yara_sweep] Scanning $TARGET ..."
run_scan "$TARGET" "$HITS_TXT" "$STRINGS_TXT"

HIT_COUNT=$(sort -u "$HITS_TXT" | wc -l 2>/dev/null || echo 0)
echo "[yara_sweep] Hits: $HIT_COUNT"

# ── Summary ───────────────────────────────────────────────────────────────────
{
    echo "YARA Sweep Summary"
    echo "=================="
    echo "Date       : $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    echo "Target     : $TARGET"
    echo "Rules dir  : $RULES_DIR"
    echo "Threads    : $THREADS"
    echo "Fast mode  : $FAST_MODE"
    echo "Total hits : $HIT_COUNT"
    echo ""
    echo "Top matching rules:"
    awk '{print $1}' "$HITS_TXT" | sort | uniq -c | sort -rn | head -20
    echo ""
    echo "Files with most matches:"
    awk '{print $2}' "$HITS_TXT" | sort | uniq -c | sort -rn | head -20
} > "$SUMMARY_TXT"

echo "[yara_sweep] Summary : $SUMMARY_TXT"
echo "[yara_sweep] Hits    : $HITS_TXT"
[[ $STRINGS_MODE -eq 1 ]] && echo "[yara_sweep] Strings : $STRINGS_TXT"
echo "[yara_sweep] Done."
