#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# md_to_pdf.sh — Convert a Markdown file to a styled DFIR PDF.
#
# Wraps lib/md_to_pdf.py which uses WeasyPrint for a professional cover page,
# running per-page header stripe, and "Page X of Y" pagination.
#
# Usage:
#   ./scripts/md_to_pdf.sh /path/to/report.md
#   ./scripts/md_to_pdf.sh /path/to/report.md --output /path/to/out.pdf
#   ./scripts/md_to_pdf.sh /path/to/report.md \
#       --title "Incident Report" --case-id CASE-2025-001 --prepared-by "SOC Team"

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
exec python3 "$PROJECT_ROOT/lib/md_to_pdf.py" "$@"
