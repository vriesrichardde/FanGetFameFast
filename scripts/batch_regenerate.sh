#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# batch_regenerate.sh — Regenerate new-format reports for all cases in ./reports/
#
# For each case:
#   1. Generate {case_id}_narrative.md from existing report + research notes
#   2. Generate {case_id}_timeline.png from research note steps
#   3. Generate {case_id}_{module}_board_deck.pptx (7-slide dark design)
#   4. Re-render PDF from existing markdown with md_to_pdf.py
#
# Usage:
#   ./scripts/batch_regenerate.sh
#   ./scripts/batch_regenerate.sh --dry-run          # list cases, don't generate
#   ./scripts/batch_regenerate.sh --only-pptx        # skip PDF re-render
#   ./scripts/batch_regenerate.sh --case-id FAME-2026-BASE-ADMIN  # single case

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPORTS_DIR="$PROJECT_ROOT/reports"
LIB_DIR="$PROJECT_ROOT/lib"

DRY_RUN=0
ONLY_PPTX=0
SINGLE_CASE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)   DRY_RUN=1;            shift ;;
        --only-pptx) ONLY_PPTX=1;          shift ;;
        --case-id)   SINGLE_CASE="$2";     shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────

green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
red()    { printf '\033[0;31m%s\033[0m\n' "$*"; }
info()   { printf '  %s\n' "$*"; }

count_ok=0
count_fail=0
count_skip=0

# ── Discover cases ────────────────────────────────────────────────────────────

if [[ -n "$SINGLE_CASE" ]]; then
    case_ids=("$SINGLE_CASE")
else
    mapfile -t notes_files < <(find "$REPORTS_DIR" -maxdepth 1 -name "*_research_notes.md" | sort)
    case_ids=()
    for f in "${notes_files[@]}"; do
        base="$(basename "$f" _research_notes.md)"
        case_ids+=("$base")
    done
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Batch Report Regeneration                                   ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Cases found : ${#case_ids[@]}"
echo "  Reports dir : $REPORTS_DIR"
echo "  Dry run     : $([[ $DRY_RUN -eq 1 ]] && echo yes || echo no)"
echo ""

if [[ $DRY_RUN -eq 1 ]]; then
    echo "Cases that would be processed:"
    for cid in "${case_ids[@]}"; do
        echo "  $cid"
    done
    echo ""
    exit 0
fi

# ── Process each case ─────────────────────────────────────────────────────────

for CASE_ID in "${case_ids[@]}"; do

    # Detect module from case_id prefix
    MODULE="fame"
    [[ "$CASE_ID" == FAST-* ]] && MODULE="fast"
    [[ "$CASE_ID" == FAN-*  ]] && MODULE="fan"

    # Extract hostname from research notes header
    NOTES="$REPORTS_DIR/${CASE_ID}_research_notes.md"
    HOSTNAME=""
    if [[ -f "$NOTES" ]]; then
        # Pattern: **Hostname:** base-admin
        HOSTNAME=$(grep -m1 "\*\*Hostname:\*\*" "$NOTES" \
            | sed 's/.*\*\*Hostname:\*\*\s*//' \
            | awk '{print $1}' \
            | tr -d '`*' || true)
    fi

    echo "──────────────────────────────────────────────────────────────"
    yellow "  Case: $CASE_ID  [module: $MODULE  host: ${HOSTNAME:-unknown}]"
    echo ""

    case_failed=0

    # Step 1 — Narrative file
    info "1/3  Generating narrative..."
    python3 "$LIB_DIR/narrative_generator.py" \
        --case-id "$CASE_ID" \
        --reports-dir "$REPORTS_DIR" || {
        red "    WARNING: narrative generation failed for $CASE_ID"
        case_failed=1
    }

    # Step 2 — Board deck PPTX
    info "2/3  Generating board deck PPTX..."
    python3 "$LIB_DIR/generate_pptx_report.py" board-deck \
        --case-id "$CASE_ID" \
        --module "$MODULE" \
        --hostname "${HOSTNAME:-}" \
        --reports-dir "$REPORTS_DIR" || {
        red "    WARNING: board deck failed for $CASE_ID"
        case_failed=1
    }

    # Step 3 — Re-render PDF from existing markdown
    if [[ $ONLY_PPTX -eq 0 ]]; then
        info "3/3  Re-rendering PDF..."
        # Find the best source markdown
        SRC_MD=""
        for candidate in \
            "$REPORTS_DIR/${CASE_ID}_${MODULE}_report_generated.md" \
            "$REPORTS_DIR/${CASE_ID}_${MODULE}_report.md" \
            "$REPORTS_DIR/${CASE_ID}_incident_report.md"; do
            [[ -f "$candidate" ]] && { SRC_MD="$candidate"; break; }
        done

        if [[ -n "$SRC_MD" ]]; then
            OUT_PDF="$REPORTS_DIR/${CASE_ID}_${MODULE}_report_new.pdf"
            MODULE_TITLE="$(echo "$MODULE" | tr '[:lower:]' '[:upper:]') Forensics Report"
            python3 "$LIB_DIR/md_to_pdf.py" \
                "$SRC_MD" \
                --output   "$OUT_PDF" \
                --case-id  "$CASE_ID" \
                --title    "$MODULE_TITLE" \
                --subtitle "${HOSTNAME:-}" \
                2>&1 | sed 's/^/    /' || {
                red "    WARNING: PDF render failed for $CASE_ID"
                case_failed=1
            }
        else
            yellow "    No source markdown found — skipping PDF"
            (( count_skip++ )) || true
        fi
    else
        info "3/3  PDF skipped (--only-pptx)"
        (( count_skip++ )) || true
    fi

    if (( case_failed )); then
        (( count_fail++ )) || true
        red "  Completed with errors: $CASE_ID"
    else
        (( count_ok++ )) || true
        green "  Done: $CASE_ID"
    fi
    echo ""

done

# ── Campaign report ──────────────────────────────────────────────────────────
CAMPAIGN_ID="${CAMPAIGN_ID:-SHIELDBASE-2026}"
CAMPAIGN_TITLE="${CAMPAIGN_TITLE:-}"

if [[ $DRY_RUN -eq 0 ]]; then
    echo "──────────────────────────────────────────────────────────────"
    yellow "  Generating campaign report (all cases) ..."
    echo ""
    python3 "$LIB_DIR/generate_campaign_report.py" \
        --campaign-id "$CAMPAIGN_ID" \
        ${CAMPAIGN_TITLE:+--title "$CAMPAIGN_TITLE"} \
        --reports-dir "$REPORTS_DIR" \
        2>&1 | sed 's/^/  /' || {
        red "  WARNING: Campaign report generation failed"
    }
    echo ""
fi

# ── Summary ───────────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Batch Complete                                              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Cases processed : ${#case_ids[@]}"
echo "  Succeeded       : $count_ok"
echo "  Failed (cases)  : $count_fail"
echo "  Skipped PDF     : $count_skip"
echo ""

narrative_count=$(find "$REPORTS_DIR" -maxdepth 1 -name "*_narrative.md" | grep -v CAMPAIGN | wc -l)
pptx_count=$(find "$REPORTS_DIR" -maxdepth 1 -name "*_board_deck.pptx" | grep -v CAMPAIGN | wc -l)
timeline_count=$(find "$REPORTS_DIR" -maxdepth 1 -name "*_timeline.png" | grep -v CAMPAIGN | wc -l)
pdf_count=$(find "$REPORTS_DIR" -maxdepth 1 -name "*_report_new.pdf" | wc -l)
campaign_md=$(find "$REPORTS_DIR" -maxdepth 1 -name "CAMPAIGN_*_report.md" | wc -l)

echo "  Narrative files : $narrative_count"
echo "  Board deck PPTX : $pptx_count"
echo "  Timeline PNGs   : $timeline_count"
echo "  New PDFs        : $pdf_count"
echo "  Campaign reports: $campaign_md (MD + PDF + PPTX)"
echo ""
