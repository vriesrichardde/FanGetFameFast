# Skill: Markdown to PDF Converter

## Overview

Converts any Markdown file to a professionally styled DFIR PDF using WeasyPrint.
Every generated PDF includes:

- **Cover page** — gradient header with org tag, report type, title, case ID, prepared-by, date, and classification banner
- **Running page-header stripe** — dark header with report title and case ID on every body page
- **"Page X of Y" pagination** — CSS `@page` counter printed at bottom-right of every page
- **CONFIDENTIAL footer** — "DFIR INTERNAL USE ONLY" at bottom-left of every page

No pandoc or LaTeX required — only Python `markdown` and `weasyprint`.

| Output | Path |
|--------|------|
| Styled PDF | Same directory as input `.md`, or `--output` path |

---

## Invocation

```bash
# Minimal — infers title from filename, no cover metadata
./scripts/md_to_pdf.sh /path/to/report.md

# With cover page metadata
./scripts/md_to_pdf.sh /path/to/report.md \
    --title "PCAP Incident Report" \
    --subtitle "capture.pcap · 2025-05-06" \
    --case-id CASE-2025-001 \
    --prepared-by "SOC Analyst" \
    --output ./reports/capture_report.pdf

# Custom output path
./scripts/md_to_pdf.sh ./reports/capture_incident_report.md \
    --output ./cases/CASE-001/reports/capture_incident_report.pdf
```

---

## Python API

```python
from lib.md_to_pdf import convert
from pathlib import Path

pdf_path = convert(
    md_path=Path("./reports/capture_incident_report.md"),
    output_path=Path("./reports/capture_incident_report.pdf"),
    title="PCAP Incident Report",
    subtitle="capture.pcap · 2025-05-06",
    case_id="CASE-2025-001",
    prepared_by="SOC / DFIR Team",
    date_str="2025-05-06",
)
print(f"PDF written: {pdf_path}")
```

Build custom HTML body directly (bypasses Markdown conversion):

```python
from lib.md_to_pdf import build_html
import weasyprint

html = build_html(
    body_html="<h1>Custom Report</h1><p>Findings go here.</p>",
    title="Custom Report",
    case_id="CASE-001",
)
weasyprint.HTML(string=html).write_pdf("custom_report.pdf", presentational_hints=True)
```

---

## CLI Flags

| Flag | Description |
|------|-------------|
| `markdown` | Path to input `.md` file (positional, required) |
| `--output`, `-o` | PDF output path (default: same dir as `.md`, `.pdf` extension) |
| `--title` | Cover page title (default: inferred from filename) |
| `--subtitle` | Cover page subtitle (e.g., "capture.pcap · 2025-05-06") |
| `--case-id` | Case ID shown on cover and every page header |
| `--prepared-by` | Prepared-by field on cover (default: "SOC / DFIR Team") |
| `--date` | Report date in `YYYY-MM-DD` (default: today UTC) |

---

## Installation

```bash
pip3 install markdown weasyprint

# Optional — improves font rendering
sudo apt install fonts-dejavu fonts-liberation
```

---

## CSS Design System

| Component | CSS class / mechanism |
|-----------|-----------------------|
| Cover page | `.cover` (gradient `#0f172a → #1d4ed8`) |
| Running header | `.page-header` (dark stripe, flex layout) |
| Page counter | CSS `@page { @bottom-right { content: "Page " counter(page) " of " counter(pages) } }` |
| Classification footer | CSS `@page { @bottom-left { content: "CONFIDENTIAL…" } }` |
| Blockquote | Blue left-border callout box |
| Code block | Dark background `#0f172a`, Roboto Mono |
| Tables | Dark blue header row, alternating zebra-stripe body |
| Headings | Section numbers optional; border-bottom rule on h1/h2 |

---

## Integration with PCAP Report

The PCAP incident report generator (`lib/generate_pcap_report.py`) calls `md_to_pdf`
automatically during report generation. To regenerate the PDF from an existing
Markdown report:

```bash
./scripts/md_to_pdf.sh ./reports/capture_incident_report.md \
    --case-id CASE-2025-001 \
    --title "PCAP Incident Report — capture"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `weasyprint not found` | Not installed | `pip3 install markdown weasyprint` |
| `markdown not found` | Not installed | `pip3 install markdown` |
| Font fallback warnings | Missing system fonts | `sudo apt install fonts-dejavu` |
| Google Fonts not loading | No internet access | Fonts fall back to Arial/Courier gracefully |
| Cover page not full-height | WeasyPrint flex height quirk | Already handled with `min-height: 100vh` |
| Tables overflow page width | Wide tables in source MD | Split table or reduce column count in source |
