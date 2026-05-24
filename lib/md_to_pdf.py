#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
md_to_pdf.py — Convert any Markdown file to a styled PDF.

Uses WeasyPrint directly (no pandoc dependency).  Produces a professional
DFIR-branded document with cover page, per-page header stripe, and
"Page X of Y" footer pagination.

Usage (CLI):
    python3 lib/md_to_pdf.py /path/to/report.md
    python3 lib/md_to_pdf.py /path/to/report.md --output /path/to/out.pdf
    python3 lib/md_to_pdf.py /path/to/report.md \
        --title "My Report" --case-id CASE-2025-001 --prepared-by "SOC Team"

Python API:
    from lib.md_to_pdf import convert, build_html
    pdf_path = convert(md_path, title="Incident Report", case_id="CASE-001")
"""
from __future__ import annotations

import argparse
import base64
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&family=Roboto+Mono:wght@400;600&display=swap');

@page {
    size: A4;
    margin: 0;
    @bottom-right {
        content: "Page " counter(page) " of " counter(pages);
        font-family: 'Inter', Arial, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-right: 2cm;
        margin-bottom: 0.55cm;
    }
    @bottom-left {
        content: "CONFIDENTIAL — DFIR INTERNAL USE ONLY";
        font-family: 'Inter', Arial, sans-serif;
        font-size: 8pt;
        color: #9ca3af;
        margin-left: 2cm;
        margin-bottom: 0.55cm;
    }
}

* { box-sizing: border-box; margin: 0; padding: 0; }

body {
    font-family: 'Inter', 'Helvetica Neue', Arial, sans-serif;
    font-size: 9.5pt;
    color: #1f2937;
    background: #ffffff;
    line-height: 1.55;
}

/* ── Cover page ── */
.cover-top-row {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 0.4cm;
}
.cover-logo img {
    width: 96px;
    height: 96px;
    display: block;
    border-radius: 8px;
}
.page-header-logo {
    display: flex;
    align-items: center;
    margin-right: 0.35cm;
    flex-shrink: 0;
}
.page-header-logo img {
    width: 28px;
    height: 28px;
    display: block;
    border-radius: 3px;
}
.cover {
    background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 60%, #1d4ed8 100%);
    color: white;
    padding: 2.8cm 2.2cm 2cm 2.2cm;
    page-break-after: always;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    justify-content: space-between;
}
.org-tag {
    font-size: 8pt;
    font-weight: 600;
    letter-spacing: 0.18em;
    text-transform: uppercase;
    color: #93c5fd;
    margin-bottom: 0.5cm;
}
.report-type {
    font-size: 10pt;
    font-weight: 400;
    color: #bfdbfe;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    margin-bottom: 0.3cm;
}
.cover h1 {
    font-size: 26pt;
    font-weight: 700;
    line-height: 1.15;
    color: #ffffff;
    margin-bottom: 0.4cm;
    border: none;
    padding: 0;
}
.cover-subtitle {
    font-size: 12pt;
    font-weight: 300;
    color: #bfdbfe;
    margin-bottom: 1cm;
}
.cover-divider {
    width: 60px;
    height: 4px;
    background: #3b82f6;
    border-radius: 2px;
    margin: 0.6cm 0 1cm 0;
}
.cover-meta {
    display: table;
    border-collapse: collapse;
    width: 100%;
    margin-top: 0.6cm;
}
.cover-meta-row  { display: table-row; }
.cover-meta-label {
    display: table-cell;
    font-size: 8pt;
    font-weight: 600;
    color: #93c5fd;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 0.12cm 0.6cm 0.12cm 0;
    white-space: nowrap;
    width: 3.2cm;
}
.cover-meta-value {
    display: table-cell;
    font-size: 9pt;
    color: #e0f2fe;
    padding: 0.12cm 0;
}
.cover-bottom {
    border-top: 1px solid rgba(255,255,255,0.15);
    padding-top: 0.4cm;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
}
.cover-classification {
    font-size: 8pt;
    font-weight: 700;
    letter-spacing: 0.15em;
    color: #fbbf24;
    text-transform: uppercase;
}
.cover-date { font-size: 8pt; color: #93c5fd; }

/* ── Per-page running header ── */
.page-header {
    background: #0f172a;
    color: white;
    padding: 0.35cm 2.2cm;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.page-header-title {
    font-size: 8.5pt;
    font-weight: 600;
    letter-spacing: 0.05em;
    color: #93c5fd;
}
.page-header-case { font-size: 8pt; color: #6b7280; }

/* ── Content area ── */
.content {
    padding: 0.8cm 2.2cm 1.5cm 2.2cm;
}

/* ── Headings ── */
h1 {
    font-size: 16pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0.8cm;
    margin-bottom: 0.3cm;
    padding-bottom: 0.15cm;
    border-bottom: 2.5px solid #1d4ed8;
}
h2 {
    font-size: 13pt;
    font-weight: 700;
    color: #0f172a;
    margin-top: 0.8cm;
    margin-bottom: 0.25cm;
    padding-bottom: 0.12cm;
    border-bottom: 2px solid #1d4ed8;
}
h3 {
    font-size: 10.5pt;
    font-weight: 700;
    color: #1e3a5f;
    margin-top: 0.5cm;
    margin-bottom: 0.2cm;
}
h4 {
    font-size: 9.5pt;
    font-weight: 600;
    color: #3949ab;
    margin-top: 0.4cm;
    margin-bottom: 0.15cm;
}

p { margin-bottom: 0.25cm; }

/* ── Tables ── */
table {
    width: 100%;
    border-collapse: collapse;
    margin: 0.25cm 0 0.5cm 0;
    font-size: 8.8pt;
}
thead tr { background: #1e3a5f; color: white; }
thead th {
    padding: 0.18cm 0.28cm;
    text-align: left;
    font-weight: 600;
    font-size: 8pt;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
tbody tr:nth-child(even) { background: #f8fafc; }
tbody tr:nth-child(odd)  { background: #ffffff; }
tbody td {
    padding: 0.15cm 0.28cm;
    border-bottom: 1px solid #e5e7eb;
    vertical-align: top;
}

/* ── Code ── */
code, .mono {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 8pt;
    background: #f1f5f9;
    padding: 0.02cm 0.1cm;
    border-radius: 3px;
    color: #0f172a;
}
pre {
    font-family: 'Roboto Mono', 'Courier New', monospace;
    font-size: 7.8pt;
    background: #0f172a;
    color: #e2e8f0;
    padding: 0.35cm 0.45cm;
    border-radius: 6px;
    margin: 0.2cm 0 0.4cm 0;
    white-space: pre-wrap;
    word-break: break-all;
    line-height: 1.6;
}
pre code { background: none; padding: 0; color: inherit; }

/* ── Blockquote ── */
blockquote {
    background: #eff6ff;
    border-left: 4px solid #1d4ed8;
    border-radius: 0 6px 6px 0;
    padding: 0.4cm 0.6cm;
    margin: 0.3cm 0 0.5cm 0;
    font-size: 9.5pt;
}

/* ── Horizontal rule ── */
hr { border: none; border-top: 1px solid #e5e7eb; margin: 0.6cm 0; }

/* ── Lists ── */
ul, ol { margin: 0.15cm 0 0.3cm 0.7cm; }
li { margin-bottom: 0.1cm; }

/* ── Strong / em ── */
strong { font-weight: 700; }

/* ── Footer note ── */
.footer-note {
    margin-top: 0.8cm;
    padding-top: 0.3cm;
    border-top: 1px solid #e5e7eb;
    font-size: 7.5pt;
    color: #9ca3af;
}

.page-break { page-break-before: always; }
"""


def build_html(
    body_html: str,
    title: str = "DFIR Analysis Report",
    subtitle: str = "",
    case_id: str = "",
    prepared_by: str = "Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin",
    date_str: str = "",
    logo_data_uri: str = "",
) -> str:
    if not date_str:
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")

    logo_cover = (
        f'<div class="cover-logo"><img src="{logo_data_uri}" alt="SOC+ Logo"/></div>'
        if logo_data_uri else ""
    )
    logo_header = (
        f'<div class="page-header-logo"><img src="{logo_data_uri}" alt=""/></div>'
        if logo_data_uri else ""
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<style>{_CSS}</style>
</head>
<body>

<!-- ══ COVER PAGE ══ -->
<div class="cover">
  <div>
    <div class="cover-top-row">
      <div>
        <div class="org-tag">Digital Forensics &amp; Incident Response</div>
        <div class="report-type">Confidential Forensic Analysis</div>
      </div>
      {logo_cover}
    </div>
    <h1>{title}</h1>
    {"<div class='cover-subtitle'>" + subtitle + "</div>" if subtitle else ""}
    <div class="cover-divider"></div>
    <div class="cover-meta">
      {"<div class='cover-meta-row'><div class='cover-meta-label'>Case ID</div><div class='cover-meta-value'>" + case_id + "</div></div>" if case_id else ""}
      <div class="cover-meta-row">
        <div class="cover-meta-label">Prepared By</div>
        <div class="cover-meta-value">{prepared_by}</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Report Date</div>
        <div class="cover-meta-value">{date_str} UTC</div>
      </div>
      <div class="cover-meta-row">
        <div class="cover-meta-label">Classification</div>
        <div class="cover-meta-value" style="color:#fbbf24;font-weight:600;">CONFIDENTIAL — RESTRICTED DISTRIBUTION</div>
      </div>
    </div>
  </div>
  <div class="cover-bottom">
    <div class="cover-classification">&#9632; Confidential</div>
    <div class="cover-date">Generated {date_str}</div>
  </div>
</div>

<!-- ══ RUNNING PAGE HEADER ══ -->
<div class="page-header">
  {logo_header}
  <div class="page-header-title">{title}</div>
  <div class="page-header-case">{"Case: " + case_id if case_id else date_str + " UTC"}</div>
</div>

<!-- ══ BODY ══ -->
<div class="content">
{body_html}
<div class="footer-note">
  This report was produced as part of an active digital forensics investigation.
  All findings are based on evidence present at the time of analysis.
  Evidence integrity maintained per chain-of-custody protocol — source files not modified.
</div>
</div>

</body>
</html>"""


def _svg_data_uri(svg_path: Path) -> str:
    """Read an SVG, strip its outer background rect, return a data: URI for embedding."""
    raw = svg_path.read_text(encoding="utf-8")
    # Remove the solid outer background rect so the logo is transparent-bg
    cleaned = re.sub(
        r'<!--\s*Outer background\s*-->\s*\n?\s*<rect[^/]*/>\n?',
        '', raw, flags=re.IGNORECASE
    )
    encoded = base64.b64encode(cleaned.encode()).decode()
    return f"data:image/svg+xml;base64,{encoded}"


def convert(
    md_path: Path,
    output_path: Path | None = None,
    title: str = "",
    subtitle: str = "",
    case_id: str = "",
    prepared_by: str = "Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin",
    date_str: str = "",
    logo_path: Path | None = None,
) -> Path:
    """Convert *md_path* to a styled PDF.  Returns the output PDF path."""
    try:
        import markdown as md_lib
    except ImportError:
        raise SystemExit(
            "[md_to_pdf] 'markdown' package not found.\n"
            "Install: pip3 install markdown weasyprint"
        )
    try:
        import weasyprint
    except ImportError:
        raise SystemExit(
            "[md_to_pdf] 'weasyprint' package not found.\n"
            "Install: pip3 install markdown weasyprint"
        )

    md_path = Path(md_path)
    if not md_path.exists():
        raise FileNotFoundError(f"Markdown file not found: {md_path}")

    out = output_path or md_path.with_suffix(".pdf")
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)

    inferred_title = title or md_path.stem.replace("_", " ").replace("-", " ").title()

    text = md_path.read_text(encoding="utf-8")
    body_html = md_lib.markdown(
        text,
        extensions=["tables", "fenced_code", "toc", "nl2br"],
    )

    logo_data_uri = _svg_data_uri(Path(logo_path)) if logo_path else ""

    html = build_html(
        body_html=body_html,
        title=inferred_title,
        subtitle=subtitle,
        case_id=case_id,
        prepared_by=prepared_by,
        date_str=date_str,
        logo_data_uri=logo_data_uri,
    )

    weasyprint.HTML(string=html, base_url=str(md_path.parent)).write_pdf(
        str(out), presentational_hints=True
    )
    return out


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Convert a Markdown file to a styled DFIR PDF")
    p.add_argument("markdown",      help="Path to input .md file")
    p.add_argument("--output",  "-o", metavar="PDF", help="Output PDF path (default: same dir, .pdf extension)")
    p.add_argument("--title",       metavar="TITLE",       default="",            help="Report title (default: inferred from filename)")
    p.add_argument("--subtitle",    metavar="SUBTITLE",    default="",            help="Cover page subtitle")
    p.add_argument("--case-id",     metavar="ID",          default="",            help="Case ID shown on cover and page header")
    p.add_argument("--prepared-by", metavar="NAME",        default="Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin", help="Prepared-by field on cover")
    p.add_argument("--date",        metavar="YYYY-MM-DD",  default="",            help="Report date (default: today UTC)")
    p.add_argument("--logo",        metavar="SVG",         default="",            help="Path to SVG logo file to embed on cover and page header")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    out_path = convert(
        md_path=Path(args.markdown),
        output_path=Path(args.output) if args.output else None,
        title=args.title,
        subtitle=args.subtitle,
        case_id=args.case_id,
        prepared_by=args.prepared_by,
        date_str=args.date,
        logo_path=Path(args.logo) if args.logo else None,
    )
    print(f"[md_to_pdf] PDF written: {out_path}")
