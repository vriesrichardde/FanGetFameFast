#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
render_campaign_report.py — Render a hand-authored campaign report MD into
PDF, PPTX, and DOCX.

This is the single call Claude makes after hand-authoring
`<case_id>_campaign_report.md` per docs/campaign_report_template.md. It does
not generate or alter the markdown content — it only renders the existing MD
into the three companion formats, mirroring the per-module report pattern
(MD authored/generated first, then rendered to PDF/PPTX/DOCX).

Usage (CLI):
    python3 lib/render_campaign_report.py \\
        --md ./reports/CASE-2026-001/CASE-2026-001_campaign_report.md \\
        --case-id CASE-2026-001 --hostname SERVER1234

Python API:
    from lib.render_campaign_report import render
    paths = render(md_path, case_id="CASE-2026-001", hostname="SERVER1234")
    # paths: {"md": Path, "pdf": Path|None, "pptx": Path|None, "docx": Path|None}
"""
from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement


def render(md_path: Path, case_id: str, hostname: str = "",
           output_dir: Path | None = None) -> dict[str, Path | None]:
    """Render *md_path* (a hand-authored campaign report) to PDF, PPTX, DOCX.

    Returns a dict with keys "md", "pdf", "pptx", "docx". Each rendering
    step is best-effort: if the relevant package is missing or rendering
    fails, that key is set to None and a warning is printed, but the other
    formats still render.
    """
    md_path = Path(md_path)
    if not md_path.exists():
        raise FileNotFoundError(f"Campaign report markdown not found: {md_path}")

    output_dir = Path(output_dir) if output_dir else md_path.parent / "documents"
    path_guard.guard_output_dir(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    title = f"{case_id} — Campaign Forensics Report"
    subtitle = f"Host: {hostname}" if hostname else ""
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    result: dict[str, Path | None] = {"md": md_path, "pdf": None, "pptx": None, "docx": None}

    from artifact_guard import resolve_output, record_generated

    try:
        from md_to_pdf import convert as pdf_convert
        out_path, diverted = resolve_output(output_dir / f"{case_id}_campaign_report.pdf")
        result["pdf"] = pdf_convert(
            md_path,
            output_path=out_path,
            title=title,
            subtitle=subtitle,
            case_id=case_id,
            date_str=date_str[:10],
        )
        if not diverted:
            record_generated(result["pdf"])
    except Exception as exc:  # noqa: BLE001
        print(f"[render_campaign_report] WARNING: PDF rendering failed — skipping ({exc})")

    try:
        from board_deck import convert as pptx_convert
        out_path, diverted = resolve_output(output_dir / f"{case_id}_campaign_presentation.pptx")
        result["pptx"] = pptx_convert(
            md_path,
            output_path=out_path,
            case_id=case_id,
            title=title,
            date_str=date_str[:10],
        )
        if not diverted:
            record_generated(result["pptx"])
    except Exception as exc:  # noqa: BLE001
        print(f"[render_campaign_report] WARNING: PPTX rendering failed — skipping ({exc})")

    try:
        from md_to_docx import convert as docx_convert
        out_path, diverted = resolve_output(output_dir / f"{case_id}_campaign_report.docx")
        result["docx"] = docx_convert(
            md_path,
            output_path=out_path,
            case_id=case_id,
            title=title,
            date_str=date_str,
        )
        if not diverted:
            record_generated(result["docx"])
    except Exception as exc:  # noqa: BLE001
        print(f"[render_campaign_report] WARNING: DOCX rendering failed — skipping ({exc})")

    return result


# ── CLI ───────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Render a hand-authored campaign report to PDF/PPTX/DOCX")
    p.add_argument("--md", required=True, metavar="MD", help="Path to the hand-authored campaign report markdown")
    p.add_argument("--case-id", required=True, metavar="ID", help="Case ID")
    p.add_argument("--hostname", default="", metavar="HOST", help="Hostname/subject")
    p.add_argument("--output-dir", default="", metavar="DIR", help="Output directory (default: <md_dir>/documents)")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    paths = render(
        md_path=Path(args.md),
        case_id=args.case_id,
        hostname=args.hostname,
        output_dir=Path(args.output_dir) if args.output_dir else None,
    )
    for fmt, p in paths.items():
        print(f"[render_campaign_report] {fmt}: {p}")
