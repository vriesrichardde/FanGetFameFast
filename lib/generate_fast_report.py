#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
generate_fast_report.py — FAST (Forensic Analysis Storage) report generator.

Aggregates The Sleuth Kit / EWF tool outputs from ./analysis/storage/ and
./exports/ into a structured incident report in Markdown, PDF, PPTX, and DOCX.

All sections follow the FanGetFameFast dual-register voice:
  - Management Summary: no technical identifiers; plain business language
  - Technical Body: precise identifiers; scoped conclusions citing evidence source

Claude instructs itself to "enhance and elaborate when necessary" on each section.

Usage (CLI):
    python3 lib/generate_fast_report.py \\
        --case-id FAST-2026-001 \\
        --hostname SERVER1234 \\
        --disk-image /path/to/SERVER1234.vmdk \\
        [--analysis-dir ./analysis/storage] \\
        [--output-dir ./reports]

Python API:
    from lib.generate_fast_report import generate
    paths = generate(case_id="FAST-2026-001", hostname="SERVER1234",
                     disk_image="/path/to/SERVER1234.vmdk")
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
    _CET = ZoneInfo("Europe/Amsterdam")
except ImportError:
    _CET = timezone.utc
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).parent.parent

# ── Colour palette ─────────────────────────────────────────────────────────────
_DARK_NAVY  = (0x0f, 0x17, 0x2a)
_MID_NAVY   = (0x1e, 0x3a, 0x5f)
_BLUE       = (0x1d, 0x4e, 0xd8)
_LIGHT_BLUE = (0x93, 0xc5, 0xfd)
_WHITE      = (0xff, 0xff, 0xff)
_LIGHT_BG   = (0xf8, 0xfa, 0xfc)
_ROW_ALT    = (0xf1, 0xf5, 0xf9)
_TEXT_DARK  = (0x1f, 0x29, 0x37)
_TEXT_MID   = (0x6b, 0x72, 0x80)
_AMBER      = (0xfb, 0xbf, 0x24)
_GREEN      = (0x22, 0xc5, 0x5e)

_SEV_RGB = {
    "critical": (0xef, 0x44, 0x44),
    "high":     (0xf9, 0x73, 0x16),
    "medium":   (0xea, 0xb3, 0x08),
    "low":      (0x22, 0xc5, 0x5e),
    "info":     (0x6b, 0x72, 0x80),
}


# ── Data loading ───────────────────────────────────────────────────────────────

def _load_analysis(analysis_dir: Path, exports_dir: Path) -> dict[str, Any]:
    data: dict[str, Any] = {
        "ewfinfo":         _read_text(analysis_dir / "ewfinfo.txt"),
        "ewfverify":       _read_text(analysis_dir / "ewfverify.txt"),
        "mmls":            _read_text(analysis_dir / "mmls.txt"),
        "fsstat":          _read_text(analysis_dir / "fsstat.txt"),
        "fls_output":      _read_text(analysis_dir / "fls_output.txt"),
        "ils_output":      _read_text(analysis_dir / "ils_output.txt"),
        "ils_orphan":      _read_text(analysis_dir / "ils_orphan.txt"),
        "bodyfile":        _read_text(analysis_dir / "bodyfile.txt"),
        "fs_timeline":     _read_text(exports_dir / "fs_timeline.txt"),
        "fs_timeline_csv": _read_csv(exports_dir / "fs_timeline.csv"),
        "windows_hashes":  _read_text(analysis_dir / "windows_hashes.txt"),
        "bulk_carved":     _list_dir(exports_dir / "carved"),
        "md5_manifest":    _read_text(exports_dir / "files" / "md5_manifest.txt"),
        "mft_extracted":   (exports_dir / "mft" / "$MFT").exists(),
        "usnj_extracted":  (exports_dir / "mft" / "$J").exists(),
        "evtx_list":       _list_dir(exports_dir / "evtx"),
        "registry_list":   _list_dir(exports_dir / "registry"),
        "prefetch_list":   _list_dir(exports_dir / "prefetch"),
        "srum_list":       _list_dir(exports_dir / "srum"),
        "browser_list":    _list_dir(exports_dir / "browser"),
    }
    # Absorb any *.json findings
    for jf in sorted(analysis_dir.glob("*.json")):
        data[jf.stem] = json.loads(jf.read_text())
    return data


def _read_text(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(errors="replace").splitlines()
    if not lines:
        return []
    headers = [h.strip() for h in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        if line.strip():
            cols = [c.strip() for c in line.split(",")]
            rows.append(dict(zip(headers, cols)))
    return rows


def _list_dir(path: Path) -> list[str]:
    if not path.exists():
        return []
    return sorted(p.name for p in path.iterdir())


# ── Markdown ───────────────────────────────────────────────────────────────────

def _build_markdown(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    disk_image: str,
    generated_utc: str,
    opencti_findings: str = "",
    fan_summary: str = "",
    fame_summary: str = "",
) -> str:
    """
    Build the full FAST incident report in Markdown.

    Claude: enhance and elaborate when necessary on each section to ensure
    the analyst receives full contextual depth appropriate to their level.
    """
    lines: list[str] = []
    a = lines.append

    a("# FAST Storage Forensics Report")
    a("")
    a("| Field | Value |")
    a("|-------|-------|")
    a(f"| Case ID | `{case_id}` |")
    a(f"| Hostname | `{hostname}` |")
    a(f"| Disk image | `{disk_image}` |")
    a(f"| Module | FAST — Forensic Analysis Storage |")
    a(f"| Analyst | Claude Code — FAST skill |")
    a(f"| Generated (UTC) | {generated_utc} |")
    a("")

    # ── Cross-Module Intelligence ─────────────────────────────────────────────
    if fan_summary or fame_summary:
        a("---")
        a("")
        a("## Cross-module intelligence")
        a("")
        a("> Claude: enhance and elaborate when necessary — correlate storage findings")
        a("> with network (FAN) and memory (FAME) evidence below.")
        a("")
        if fan_summary:
            a("### Network forensics (FAN) summary")
            a("")
            a(fan_summary.strip())
            a("")
        if fame_summary:
            a("### Memory forensics (FAME) summary")
            a("")
            a(fame_summary.strip())
            a("")

    # ── Management Summary ────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 1. Management summary")
    a("")
    a("> **Audience:** CISO, Legal, Internal Audit — no technical identifiers.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    a("Storage forensic analysis of the subject server disk image was conducted to")
    a("identify file system artifacts, deleted files, and on-disk evidence relevant")
    a("to the investigation. The analysis examined the disk image for signs of attacker")
    a("activity, data staging, persistence mechanisms, and timeline of key file operations.")
    a("")
    fls = data.get("fls_output", "")
    deleted_count = fls.count("\n* ") if fls else 0
    evtx = data.get("evtx_list", [])
    prefetch = data.get("prefetch_list", [])
    if deleted_count > 0:
        a(f"**Key finding:** {deleted_count} deleted file entries identified in the file system.")
    if evtx:
        a(f"**Event logs:** {len(evtx)} Windows Event Log files extracted for further analysis.")
    if prefetch:
        a(f"**Prefetch:** {len(prefetch)} Prefetch execution artifacts extracted.")
    a("")

    # ── Image Verification ────────────────────────────────────────────────────
    ewfinfo   = data.get("ewfinfo", "")
    ewfverify = data.get("ewfverify", "")
    if ewfinfo or ewfverify:
        a("---")
        a("")
        a("## 2. Image verification")
        a("")
        a("> Claude: enhance and elaborate when necessary — confirm hash match and")
        a("> document any acquisition notes embedded in the E01 metadata.")
        a("")
        if ewfinfo:
            a("### ewfinfo")
            a("```")
            a(ewfinfo.strip()[:2000])
            a("```")
            a("")
        if ewfverify:
            a("### ewfverify")
            a("```")
            a(ewfverify.strip()[:500])
            a("```")
            a("")

    # ── Partition Table ───────────────────────────────────────────────────────
    mmls = data.get("mmls", "")
    if mmls:
        a("---")
        a("")
        a("## 3. Partition table (mmls)")
        a("")
        a("> Claude: enhance and elaborate when necessary — identify the primary OS")
        a("> partition, recovery partitions, and any unallocated space.")
        a("")
        a("```")
        a(mmls.strip()[:2000])
        a("```")
        a("")

    # ── Filesystem Metadata ───────────────────────────────────────────────────
    fsstat = data.get("fsstat", "")
    if fsstat:
        a("---")
        a("")
        a("## 4. Filesystem metadata (fsstat)")
        a("")
        a("> Claude: enhance and elaborate when necessary — note NTFS version, cluster")
        a("> size, MFT location, and volume last-written timestamp.")
        a("")
        a("```")
        a(fsstat.strip()[:2000])
        a("```")
        a("")

    # ── File System Timeline ──────────────────────────────────────────────────
    timeline_rows = data.get("fs_timeline_csv", [])
    timeline_txt  = data.get("fs_timeline", "")
    if timeline_rows or timeline_txt:
        a("---")
        a("")
        a("## 5. Filesystem timeline")
        a("")
        a("> Claude: enhance and elaborate when necessary — highlight any file activity")
        a("> that coincides with the network or memory-forensics event timeline.")
        a("")
        if timeline_rows:
            shown = timeline_rows[:40]
            headers = list(shown[0].keys()) if shown else []
            if headers:
                a("| " + " | ".join(headers) + " |")
                a("|" + "|".join(["---"] * len(headers)) + "|")
                for row in shown:
                    a("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
                if len(timeline_rows) > 40:
                    a(f"")
                    a(f"*{len(timeline_rows) - 40} additional timeline entries not shown — see `./exports/fs_timeline.csv`.*")
        elif timeline_txt:
            a("```")
            a(timeline_txt.strip()[:3000])
            a("```")
        a("")

    # ── Deleted Files ─────────────────────────────────────────────────────────
    if fls and deleted_count > 0:
        a("---")
        a("")
        a("## 6. Deleted file entries (fls)")
        a("")
        a("> Claude: enhance and elaborate when necessary — any deleted executable or")
        a("> script in a user-writable path is a high-priority triage candidate.")
        a("")
        deleted_lines = [l for l in fls.splitlines() if l.startswith("* ")][:50]
        a("```")
        for dl in deleted_lines:
            a(dl)
        a("```")
        if deleted_count > 50:
            a(f"")
            a(f"*{deleted_count - 50} additional deleted entries not shown — see `./analysis/storage/fls_output.txt`.*")
        a("")

    # ── MFT / UsnJrnl ─────────────────────────────────────────────────────────
    mft = data.get("mft_extracted", False)
    usn = data.get("usnj_extracted", False)
    if mft or usn:
        a("---")
        a("")
        a("## 7. MFT and USN change journal")
        a("")
        a("> Claude: enhance and elaborate when necessary — parse MFT with MFTECmd and")
        a("> USN journal with MFTeCmd or usnjrnl.py to build a high-resolution file activity log.")
        a("")
        a("| Artifact | Status |")
        a("|----------|--------|")
        a(f"| \\$MFT | {'Extracted — `./exports/mft/$MFT`' if mft else 'Not extracted'} |")
        a(f"| \\$J (UsnJrnl) | {'Extracted — `./exports/mft/$J`' if usn else 'Not extracted'} |")
        a("")

    # ── Extracted Artifacts ───────────────────────────────────────────────────
    artifact_sections = [
        ("evtx_list",     "8. Windows Event Logs",
         "Ingest into Timeline Explorer, Chainsaw, or Hayabusa for rapid log analysis."),
        ("registry_list", "9. Registry Hives",
         "Analyzewith RegRipper, Registry Explorer, or RECmd to extract run keys, services, and user artifacts."),
        ("prefetch_list", "10. Prefetch Execution Artifacts",
         "Parse with PECmd to reconstruct program execution history and first/last run times."),
        ("srum_list",     "11. SRUM Database",
         "Parse SRUDB.dat with srum-dump or SRUM-DUMP2 for per-app network and CPU usage."),
        ("browser_list",  "12. Browser History",
         "AnalyzeHistory files with DB Browser for SQLite or BrowsingHistoryView."),
    ]
    for key, title, note in artifact_sections:
        items = data.get(key, [])
        if items:
            a("---")
            a("")
            a(f"## {title}")
            a("")
            a(f"> Claude: enhance and elaborate when necessary — {note}")
            a("")
            for item in items[:30]:
                a(f"- `{item}`")
            if len(items) > 30:
                a(f"- *… and {len(items) - 30} more*")
            a("")

    # ── Carved Files ──────────────────────────────────────────────────────────
    carved = data.get("bulk_carved", [])
    if carved:
        a("---")
        a("")
        a("## 13. Bulk extractor carved artifacts")
        a("")
        a("> Claude: enhance and elaborate when necessary — email addresses, URLs, and")
        a("> domains found in unallocated space are IOC candidates for CTI enrichment.")
        a("")
        for item in carved[:20]:
            a(f"- `./exports/carved/{item}`")
        a("")

    # ── File Hashes ───────────────────────────────────────────────────────────
    md5_manifest = data.get("md5_manifest", "")
    if md5_manifest:
        a("---")
        a("")
        a("## 14. File hash manifest")
        a("")
        a("> Claude: enhance and elaborate when necessary — submit hashes to VirusTotal")
        a("> or check against the NSRL to filter known-good files.")
        a("")
        a("```")
        a(md5_manifest.strip()[:2000])
        a("```")
        a("")

    # ── OpenCTI Enrichment ────────────────────────────────────────────────────
    if opencti_findings:
        a("---")
        a("")
        a("## 15. OpenCTI threat intelligence enrichment")
        a("")
        a("> Claude: enhance and elaborate when necessary — link matched indicators to")
        a("> known threat actors, malware families, or campaigns in OpenCTI.")
        a("")
        a(opencti_findings.strip())
        a("")

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 16. MITRE ATT&CK coverage")
    a("")
    a("> Claude: enhance and elaborate when necessary — add sub-technique context")
    a("> and procedural examples observed in this investigation.")
    a("")
    techniques = _derive_techniques(data)
    if techniques:
        a("| Technique | Name | Tactic | Observation |")
        a("|-----------|------|--------|-------------|")
        for tid, name, tactic, obs in techniques:
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            a(f"| [{tid}]({url}) | {name} | {tactic} | {obs} |")
    else:
        a("No MITRE ATT&CK techniques mapped — insufficient evidence for attribution.")
    a("")

    # ── IOCs ──────────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 17. Indicators of compromise")
    a("")
    a("> Claude: enhance and elaborate when necessary — defang all IOC values and add")
    a("> OSINT context or OpenCTI attribution where available.")
    a("")
    iocs = _extract_iocs(data)
    if iocs:
        a("| Type | Value | Severity | Context |")
        a("|------|-------|----------|---------|")
        for ioc in iocs:
            a(f"| {ioc['type']} | `{ioc['value']}` | {ioc['severity']} | {ioc['context']} |")
    else:
        a("No malicious indicators of compromise identified from storage analysis.")
    a("")

    # ── Recommendations ───────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 18. Recommendations")
    a("")
    a("> Claude: enhance and elaborate when necessary — prioritise by risk and add")
    a("> implementation detail appropriate to the target environment.")
    a("")
    recs = _build_recommendations(data)
    for i, rec in enumerate(recs, 1):
        a(f"{i}. {rec}")
    a("")

    # ── Appendix ──────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## Appendix A — Analysis source files")
    a("")
    a("| File | Description |")
    a("|------|-------------|")
    a("| `./analysis/storage/ewfinfo.txt` | E01 image metadata |")
    a("| `./analysis/storage/mmls.txt` | Partition table |")
    a("| `./analysis/storage/fsstat.txt` | Filesystem metadata |")
    a("| `./analysis/storage/fls_output.txt` | Full file listing (incl. deleted) |")
    a("| `./analysis/storage/bodyfile.txt` | MAC time bodyfile |")
    a("| `./exports/fs_timeline.csv` | Filesystem timeline (mactime CSV) |")
    a("| `./exports/mft/$MFT` | Master File Table |")
    a("| `./exports/mft/$J` | USN Change Journal |")
    a("| `./exports/evtx/` | Windows Event Logs |")
    a("| `./exports/registry/` | Registry hives |")
    a("| `./exports/prefetch/` | Prefetch files |")
    a("| `./exports/carved/` | bulk_extractor carved artifacts |")
    a("")
    a("*All findings derived from disk image analysis as stated. Evidence integrity preserved.*")
    a("")

    return "\n".join(lines)


def _derive_techniques(data: dict[str, Any]) -> list[tuple[str, str, str, str]]:
    techniques = []
    deleted = data.get("fls_output", "").count("\n* ")
    if deleted > 0:
        techniques.append((
            "T1070.004", "Indicator Removal: File Deletion", "Defense Evasion",
            f"{deleted} deleted file entries found — evidence of file clean-up activity"
        ))
    prefetch = data.get("prefetch_list", [])
    if prefetch:
        techniques.append((
            "T1564.003", "Hide Artifacts: NTFS File Attributes", "Defense Evasion",
            "Prefetch artifacts present — can reveal execution of tools even after deletion"
        ))
    evtx = data.get("evtx_list", [])
    if evtx:
        techniques.append((
            "T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion",
            f"Event logs extracted ({len(evtx)} files) — review for gaps or cleared logs"
        ))
    carved = data.get("bulk_carved", [])
    if "url" in str(carved).lower() or "domain" in str(carved).lower():
        techniques.append((
            "T1048", "Exfiltration Over Alternative Protocol", "Exfiltration",
            "URLs/domains found in carved artifacts — review for data staging or C2 URLs"
        ))
    return techniques


def _extract_iocs(data: dict[str, Any]) -> list[dict]:
    iocs = []
    carved_files = data.get("bulk_carved", [])
    for cf in carved_files:
        if "url" in cf.lower():
            iocs.append({
                "type": "File",
                "value": f"./exports/carved/{cf}",
                "severity": "Medium",
                "context": "bulk_extractor URL feature file — review for C2 or exfiltration endpoints",
            })
            break
        if "domain" in cf.lower():
            iocs.append({
                "type": "File",
                "value": f"./exports/carved/{cf}",
                "severity": "Medium",
                "context": "bulk_extractor domain feature file — cross-reference with FAN DNS findings",
            })
            break
    return iocs


def _build_recommendations(data: dict[str, Any]) -> list[str]:
    recs = []
    evtx = data.get("evtx_list", [])
    if evtx:
        recs.append(
            "**AnalyzeWindows Event Logs** — ingest the extracted EVTX files into "
            "Timeline Explorer or Hayabusa to identify logon events, service installs, "
            "and PowerShell activity around the time of the incident."
        )
    prefetch = data.get("prefetch_list", [])
    if prefetch:
        recs.append(
            "**Parse Prefetch files** — run PECmd against the extracted Prefetch files "
            "to reconstruct which executables ran, their first and last run timestamps, "
            "and what files they accessed."
        )
    if data.get("mft_extracted"):
        recs.append(
            "**Parse the MFT** — run MFTECmd against `./exports/mft/$MFT` and combine "
            "with the USN Change Journal to build a high-resolution file-modification timeline. "
            "Cross-reference with the FAME memory timeline."
        )
    registry = data.get("registry_list", [])
    if registry:
        recs.append(
            "**Analyzeregistry hives** — run RegRipper or RECmd against the extracted "
            "hives to identify Run/RunOnce persistence keys, recently executed programs "
            "(UserAssist), and network share history."
        )
    carved = data.get("bulk_carved", [])
    if carved:
        recs.append(
            "**Review carved artifacts** — examine bulk_extractor output for email addresses, "
            "URLs, and credit card numbers recovered from unallocated space. Submit any "
            "suspicious URLs to OpenCTI for CTI enrichment."
        )
    recs.append(
        "**Cross-reference with FAME and FAN** — correlate disk timeline events with "
        "the memory forensics (FAME) process timeline and network (FAN) packet timeline "
        "to identify the full attack chain."
    )
    recs.append(
        "**Verify image integrity** — confirm ewfverify completed without errors before "
        "any findings are cited as evidence in legal or regulatory proceedings."
    )
    return recs


# ── PPTX ───────────────────────────────────────────────────────────────────────

def _build_pptx(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    disk_image: str,
    generated_utc: str,
    output_path: Path,
    opencti_findings: str = "",
    fan_summary: str = "",
    fame_summary: str = "",
) -> None:
    try:
        from pptx import Presentation
        from pptx.util import Inches, Pt
        from pptx.dml.color import RGBColor
        from pptx.enum.text import PP_ALIGN
    except ImportError:
        print("[fast] WARNING: python-pptx not installed — skipping PPTX. pip3 install python-pptx")
        return

    prs = Presentation()
    prs.slide_width  = Inches(13.33)
    prs.slide_height = Inches(7.5)
    blank = prs.slide_layouts[6]

    def _rgb(t):
        return RGBColor(*t)

    def _rect(slide, l, t, w, h, fill):
        s = slide.shapes.add_shape(1, l, t, w, h)
        s.fill.solid()
        s.fill.fore_color.rgb = _rgb(fill)
        s.line.fill.background()
        return s

    def _txt(slide, text, l, t, w, h, sz, bold=False, color=_WHITE, align=PP_ALIGN.LEFT):
        tb  = slide.shapes.add_textbox(l, t, w, h)
        tf  = tb.text_frame
        tf.word_wrap = True
        p   = tf.paragraphs[0]
        p.alignment = align
        run = p.add_run()
        run.text = str(text)
        run.font.size = Pt(sz)
        run.font.bold = bold
        run.font.color.rgb = _rgb(color)
        return tb

    W = prs.slide_width
    H = prs.slide_height
    M = Inches(0.4)

    # Slide 1 — Cover
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, H, _DARK_NAVY)
    _rect(s, 0, 0, W, Inches(0.08), _BLUE)
    _rect(s, 0, H - Inches(0.08), W, Inches(0.08), _BLUE)
    _txt(s, "FAST", M, Inches(1.2), W - 2*M, Inches(1.2),
         72, bold=True, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _txt(s, "Forensic analysis storage", M, Inches(2.2), W - 2*M, Inches(0.7),
         28, color=_WHITE, align=PP_ALIGN.CENTER)
    _txt(s, "Storage forensics incident report", M, Inches(2.9), W - 2*M, Inches(0.6),
         20, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _rect(s, Inches(3), Inches(3.8), W - Inches(6), Inches(0.04), _BLUE)
    _txt(s, f"Case: {case_id}  |  Host: {hostname}  |  {generated_utc[:10]}",
         M, Inches(4.1), W - 2*M, Inches(0.5), 14, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s, "Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin",
         M, Inches(4.6), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s, "CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY",
         M, H - Inches(0.7), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)

    # Slide 2 — Executive Summary
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Executive summary", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    _txt(s, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3), 12, color=_LIGHT_BLUE)

    fls = data.get("fls_output", "")
    deleted = fls.count("\n* ") if fls else 0
    evtx    = data.get("evtx_list", [])
    prefetch= data.get("prefetch_list", [])

    summary = (
        f"Storage forensic analysis was conducted on the disk image of {hostname}. "
        f"The analysis identified {deleted} deleted file entries, "
        f"{len(evtx)} Windows Event Log file(s), and "
        f"{len(prefetch)} Prefetch execution artifact(s). "
        "The filesystem timeline has been reconstructed for cross-reference with "
        "network and memory forensics findings."
    )
    _txt(s, summary, M, Inches(1.3), W - 2*M, Inches(3.2), 15, color=_TEXT_DARK)

    metrics = [
        ("Deleted Files",  str(deleted)),
        ("Event Logs",     str(len(evtx))),
        ("Prefetch Files", str(len(prefetch))),
        ("MFT Extracted",  "Yes" if data.get("mft_extracted") else "No"),
    ]
    col_w = (W - 2*M) // len(metrics)
    for i, (label, value) in enumerate(metrics):
        cx = M + i * col_w
        _rect(s, cx + Inches(0.05), Inches(4.9), col_w - Inches(0.1), Inches(1.3), _MID_NAVY)
        _txt(s, value, cx + Inches(0.1), Inches(5.0), col_w - Inches(0.2), Inches(0.7),
             18, bold=True, color=_AMBER)
        _txt(s, label, cx + Inches(0.1), Inches(5.7), col_w - Inches(0.2), Inches(0.4),
             10, color=_LIGHT_BLUE)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 3 — Partition Table
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Partition table & filesystem", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    mmls   = data.get("mmls", "Not run — see analysis directory")
    fsstat = data.get("fsstat", "")
    _txt(s, "mmls output:", M, Inches(1.2), W, Inches(0.4), 13, bold=True, color=_TEXT_DARK)
    _txt(s, mmls[:800] or "Not available", M, Inches(1.6), (W - 2*M)//2, Inches(4.0),
         11, color=_TEXT_DARK)
    if fsstat:
        _txt(s, "fsstat excerpt:", M + (W - 2*M)//2 + Inches(0.2), Inches(1.2), (W - 2*M)//2, Inches(0.4),
             13, bold=True, color=_TEXT_DARK)
        _txt(s, fsstat[:600], M + (W - 2*M)//2 + Inches(0.2), Inches(1.6), (W - 2*M)//2 - Inches(0.2), Inches(4.0),
             11, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 4 — Extracted Artifacts
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Extracted artifacts", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)

    artifact_summary = [
        ("Windows Event Logs",  len(evtx),          "evtx/"),
        ("Registry Hives",      len(data.get("registry_list", [])), "registry/"),
        ("Prefetch Files",      len(prefetch),       "prefetch/"),
        ("SRUM Files",          len(data.get("srum_list", [])),     "srum/"),
        ("Browser History",     len(data.get("browser_list", [])),  "browser/"),
        ("Carved Artifacts",    len(data.get("bulk_carved", [])),   "carved/"),
        ("MFT + UsnJrnl",       2 if data.get("mft_extracted") and data.get("usnj_extracted") else
                                 1 if data.get("mft_extracted") else 0, "mft/"),
    ]
    row_h = Inches(0.72)
    for i, (label, count, path) in enumerate(artifact_summary):
        y = Inches(1.2) + i * row_h
        bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
        _rect(s, M, y, W - 2*M, row_h - Inches(0.06), bg)
        _txt(s, label, M + Inches(0.1), y + Inches(0.1), Inches(4.0), row_h, 13, bold=True, color=_TEXT_DARK)
        _txt(s, str(count), M + Inches(4.1), y + Inches(0.1), Inches(1.5), row_h, 13,
             color=_BLUE if count > 0 else _TEXT_MID)
        _txt(s, f"./exports/{path}", M + Inches(5.6), y + Inches(0.1), W - M - Inches(6.0), row_h,
             12, color=_TEXT_MID)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 5 — MITRE ATT&CK
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "MITRE ATT&CK coverage", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    techniques = _derive_techniques(data)
    if techniques:
        headers = ["Technique", "Name", "Tactic", "Observation"]
        col_ws = [Inches(1.4), Inches(2.2), Inches(2.5), W - M - Inches(6.5)]
        row_h = Inches(0.7)
        hx = M
        for h, cw in zip(headers, col_ws):
            _rect(s, hx, Inches(1.2), cw - Inches(0.05), row_h - Inches(0.04), _MID_NAVY)
            _txt(s, h, hx + Inches(0.08), Inches(1.25), cw - Inches(0.13), row_h, 12, bold=True, color=_WHITE)
            hx += cw
        for i, (tid, name, tactic, obs) in enumerate(techniques):
            y = Inches(1.2) + (i+1) * row_h
            bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
            rx = M
            for val, cw in zip([tid, name, tactic, obs[:80]], col_ws):
                _rect(s, rx, y, cw - Inches(0.05), row_h - Inches(0.04), bg)
                _txt(s, val, rx + Inches(0.08), y + Inches(0.08), cw - Inches(0.13), row_h, 11, color=_TEXT_DARK)
                rx += cw
    else:
        _txt(s, "No MITRE ATT&CK techniques mapped — insufficient evidence for attribution.",
             M, Inches(2.0), W - 2*M, Inches(1.0), 16, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 6 — Cross-Module Intelligence
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Cross-module intelligence", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    cols = []
    if fan_summary:
        cols.append(("FAN — Network forensics", fan_summary[:400]))
    if fame_summary:
        cols.append(("FAME — Memory forensics", fame_summary[:400]))
    if opencti_findings:
        cols.append(("OpenCTI enrichment", opencti_findings[:400]))
    if cols:
        col_w_each = (W - 2*M - Inches(0.2) * (len(cols) - 1)) // len(cols)
        for i, (title, body) in enumerate(cols):
            cx = M + i * (col_w_each + Inches(0.1))
            _rect(s, cx, Inches(1.2), col_w_each, Inches(5.8), _LIGHT_BG)
            _txt(s, title, cx + Inches(0.1), Inches(1.3), col_w_each - Inches(0.2), Inches(0.5),
                 13, bold=True, color=_MID_NAVY)
            _txt(s, body or "No data available.", cx + Inches(0.1), Inches(1.9),
                 col_w_each - Inches(0.2), Inches(4.8), 11, color=_TEXT_DARK)
    else:
        _txt(s,
             "Run FAN (/fan-report) and FAME (/fame) for the same case ID to populate "
             "this slide with correlated network and memory findings.",
             M, Inches(2.0), W - 2*M, Inches(2.0), 15, color=_TEXT_MID)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 7 — Recommendations
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Recommendations", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    recs = _build_recommendations(data)
    row_h = Inches(0.72)
    for i, rec in enumerate(recs[:7]):
        y = Inches(1.2) + i * row_h
        _rect(s, M, y, Inches(0.5), row_h - Inches(0.08), _BLUE)
        _txt(s, str(i+1), M + Inches(0.1), y + Inches(0.1), Inches(0.3), row_h,
             16, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec.split(" — ")[0][:120])
        _txt(s, rec_clean, M + Inches(0.6), y + Inches(0.1), W - M - Inches(1.0), row_h, 13, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 8 — Module Coverage
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Investigation coverage", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)

    checks = [
        ("Image verification (ewfverify)", bool(data.get("ewfverify"))),
        ("Partition table (mmls)", bool(data.get("mmls"))),
        ("Filesystem metadata (fsstat)", bool(data.get("fsstat"))),
        ("File listing incl. deleted (fls)", bool(data.get("fls_output"))),
        ("Filesystem timeline (mactime)", bool(data.get("fs_timeline") or data.get("fs_timeline_csv"))),
        ("MFT extraction", data.get("mft_extracted", False)),
        ("USN Change Journal", data.get("usnj_extracted", False)),
        ("Event log extraction", bool(data.get("evtx_list"))),
        ("Registry hive extraction", bool(data.get("registry_list"))),
        ("Prefetch extraction", bool(data.get("prefetch_list"))),
        ("SRUM extraction", bool(data.get("srum_list"))),
        ("Carved artifacts (bulk_extractor)", bool(data.get("bulk_carved"))),
        ("FAN network correlation", bool(fan_summary)),
        ("FAME memory correlation", bool(fame_summary)),
        ("OpenCTI enrichment", bool(opencti_findings)),
    ]
    col_count = 2
    items_per_col = (len(checks) + 1) // col_count
    col_w_each = (W - 2*M - Inches(0.5)) // col_count
    row_h = Inches(0.43)
    for idx, (label, done) in enumerate(checks):
        col = idx // items_per_col
        row = idx % items_per_col
        cx  = M + col * (col_w_each + Inches(0.25))
        cy  = Inches(1.2) + row * row_h
        color = _GREEN if done else _SEV_RGB["medium"]
        mark  = "✓" if done else "–"
        _rect(s, cx, cy, Inches(0.35), row_h - Inches(0.06), color)
        _txt(s, mark, cx + Inches(0.05), cy + Inches(0.04), Inches(0.25), row_h,
             12, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        _txt(s, label, cx + Inches(0.4), cy + Inches(0.07), col_w_each - Inches(0.5), row_h,
             12, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    prs.save(str(output_path))
    print(f"[fast] PPTX saved: {output_path}")


# ── DOCX ───────────────────────────────────────────────────────────────────────

def _build_docx(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    disk_image: str,
    generated_utc: str,
    output_path: Path,
    opencti_findings: str = "",
    fan_summary: str = "",
    fame_summary: str = "",
) -> None:
    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        print("[fast] WARNING: python-docx not installed — skipping DOCX. pip3 install python-docx")
        return

    doc = Document()
    for section in doc.sections:
        section.top_margin    = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin   = Inches(1.2)
        section.right_margin  = Inches(1.2)

    styles = doc.styles

    def _h(text, level):
        p = doc.add_heading(text, level=level)
        p.runs[0].font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)

    def _p(text, bold=False, italic=False):
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.bold   = bold
        run.italic = italic

    def _note(text):
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.italic = True
        run.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)

    def _tbl2(rows):
        tbl = doc.add_table(rows=len(rows)+1, cols=2)
        tbl.style = "Table Grid"
        for i, h in enumerate(["Field", "Value"]):
            tbl.rows[0].cells[i].text = h
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, (k, v) in enumerate(rows):
            tbl.rows[i+1].cells[0].text = k
            tbl.rows[i+1].cells[1].text = str(v)

    # Cover
    doc.add_paragraph()
    t = doc.add_heading("FAST — Storage Forensics Report", 0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("Forensic Analysis Storage  |  FanGetFameFast")
    r.font.size = Pt(14)
    r.font.color.rgb = RGBColor(0x1d, 0x4e, 0xd8)
    doc.add_paragraph()
    _tbl2([
        ("Case ID",      case_id),
        ("Hostname",     hostname),
        ("Disk image",   disk_image),
        ("Module",       "FAST — Forensic Analysis Storage"),
        ("Analyst",      "Claude Code — FAST skill"),
        ("Generated UTC",generated_utc),
    ])
    doc.add_paragraph()
    conf = doc.add_paragraph("CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY")
    conf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    conf.runs[0].font.bold = True
    conf.runs[0].font.color.rgb = RGBColor(0xef, 0x44, 0x44)
    doc.add_page_break()

    # Management Summary
    _h("1. Management summary", 1)
    _note("Audience: CISO, Legal, Internal Audit. Claude: enhance and elaborate when necessary.")
    fls = data.get("fls_output", "")
    deleted = fls.count("\n* ") if fls else 0
    evtx    = data.get("evtx_list", [])
    prefetch= data.get("prefetch_list", [])
    _p(
        f"Storage forensic analysis was conducted on the disk image of {hostname}. "
        f"The analysis identified {deleted} deleted file entries, "
        f"{len(evtx)} Windows Event Log file(s), and {len(prefetch)} Prefetch "
        "execution artifact(s). "
        "The filesystem timeline has been reconstructed and is available for "
        "cross-reference with network and memory forensics findings."
    )
    doc.add_page_break()

    # Cross-module
    if fan_summary or fame_summary or opencti_findings:
        _h("2. Cross-module intelligence", 1)
        _note("Claude: enhance and elaborate when necessary.")
        if fan_summary:
            _h("2.1 Network forensics (FAN)", 2)
            _p(fan_summary.strip())
        if fame_summary:
            _h("2.2 Memory forensics (FAME)", 2)
            _p(fame_summary.strip())
        if opencti_findings:
            _h("2.3 OpenCTI threat intelligence", 2)
            _p(opencti_findings.strip())
        doc.add_page_break()

    # Image verification
    _h("3. Image verification", 1)
    _note("Claude: enhance and elaborate when necessary.")
    ewfinfo = data.get("ewfinfo", "")
    if ewfinfo:
        code_p = doc.add_paragraph()
        run = code_p.add_run(ewfinfo.strip()[:2000])
        run.font.name = "Courier New"
        run.font.size = Pt(9)
    else:
        _p("ewfinfo output not available — run ewfinfo against the source E01 image.")

    # Partition table
    _h("4. Partition table (mmls)", 1)
    _note("Claude: enhance and elaborate when necessary.")
    mmls = data.get("mmls", "")
    code_p = doc.add_paragraph()
    run = code_p.add_run(mmls.strip()[:2000] if mmls else "Not available.")
    run.font.name = "Courier New"
    run.font.size = Pt(9)

    # Artifact summary table
    _h("5. Extracted artifacts summary", 1)
    _note("Claude: enhance and elaborate when necessary.")
    _tbl2([
        ("Deleted file entries",   str(deleted)),
        ("Windows Event Logs",     str(len(evtx))),
        ("Prefetch files",         str(len(prefetch))),
        ("Registry hives",         str(len(data.get("registry_list", [])))),
        ("SRUM files",             str(len(data.get("srum_list", [])))),
        ("Browser history files",  str(len(data.get("browser_list", [])))),
        ("Carved artifacts",       str(len(data.get("bulk_carved", [])))),
        ("MFT extracted",          "Yes" if data.get("mft_extracted") else "No"),
        ("USN Change Journal",     "Yes" if data.get("usnj_extracted") else "No"),
    ])
    doc.add_paragraph()

    # MITRE ATT&CK
    _h("6. MITRE ATT&CK coverage", 1)
    _note("Claude: enhance and elaborate when necessary.")
    techniques = _derive_techniques(data)
    if techniques:
        tbl = doc.add_table(rows=len(techniques)+1, cols=4)
        tbl.style = "Table Grid"
        for i, h in enumerate(["Technique", "Name", "Tactic", "Observation"]):
            tbl.rows[0].cells[i].text = h
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, (tid, name, tactic, obs) in enumerate(techniques):
            tbl.rows[i+1].cells[0].text = tid
            tbl.rows[i+1].cells[1].text = name
            tbl.rows[i+1].cells[2].text = tactic
            tbl.rows[i+1].cells[3].text = obs
    else:
        _p("No MITRE ATT&CK techniques mapped.")
    doc.add_paragraph()

    # IOCs
    _h("7. Indicators of compromise", 1)
    _note("Claude: enhance and elaborate when necessary.")
    iocs = _extract_iocs(data)
    if iocs:
        tbl = doc.add_table(rows=len(iocs)+1, cols=4)
        tbl.style = "Table Grid"
        for i, h in enumerate(["Type", "Value", "Severity", "Context"]):
            tbl.rows[0].cells[i].text = h
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, ioc in enumerate(iocs):
            tbl.rows[i+1].cells[0].text = ioc["type"]
            tbl.rows[i+1].cells[1].text = ioc["value"]
            tbl.rows[i+1].cells[2].text = ioc["severity"]
            tbl.rows[i+1].cells[3].text = ioc["context"]
    else:
        _p("No malicious indicators of compromise identified from storage analysis.")
    doc.add_paragraph()

    # Recommendations
    _h("8. Recommendations", 1)
    _note("Claude: enhance and elaborate when necessary.")
    for i, rec in enumerate(_build_recommendations(data), 1):
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec)
        p = doc.add_paragraph(style="List Number")
        p.add_run(rec_clean)

    doc.add_page_break()

    # Appendix
    _h("Appendix A — Analysis source files", 1)
    _tbl2([
        ("./analysis/storage/ewfinfo.txt",   "E01 image metadata"),
        ("./analysis/storage/mmls.txt",      "Partition table"),
        ("./analysis/storage/fsstat.txt",    "Filesystem metadata"),
        ("./analysis/storage/fls_output.txt","File listing (incl. deleted)"),
        ("./analysis/storage/bodyfile.txt",  "MAC time bodyfile"),
        ("./exports/fs_timeline.csv",        "Filesystem timeline (mactime CSV)"),
        ("./exports/mft/$MFT",              "Master File Table"),
        ("./exports/mft/$J",               "USN Change Journal"),
        ("./exports/evtx/",               "Windows Event Logs"),
        ("./exports/registry/",           "Registry hives"),
        ("./exports/prefetch/",           "Prefetch files"),
        ("./exports/carved/",             "bulk_extractor carved artifacts"),
    ])

    doc.save(str(output_path))
    print(f"[fast] DOCX saved: {output_path}")


# ── Public API ─────────────────────────────────────────────────────────────────

def generate(
    case_id: str,
    hostname: str,
    disk_image: str = "",
    analysis_dir: Path | None = None,
    exports_dir: Path | None = None,
    output_dir: Path | None = None,
    opencti_findings: str = "",
    fan_summary: str = "",
    fame_summary: str = "",
) -> dict[str, Path | None]:
    analysis_dir = analysis_dir or (PROJECT_ROOT / "analysis" / "storage")
    exports_dir  = exports_dir  or (PROJECT_ROOT / "exports")
    output_dir   = output_dir   or (PROJECT_ROOT / "reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    data = _load_analysis(analysis_dir, exports_dir)
    generated_utc = datetime.now(_CET).strftime("%Y-%m-%d %H:%M CET")
    stem = case_id.replace(" ", "_")

    # Markdown
    md_text = _build_markdown(
        data, case_id, hostname, disk_image or str(analysis_dir),
        generated_utc, opencti_findings, fan_summary, fame_summary,
    )
    md_path = output_dir / f"{stem}_fast_report.md"
    md_path.write_text(md_text)
    print(f"[fast] Markdown saved: {md_path}")

    # PDF
    pdf_path: Path | None = None
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from md_to_pdf import convert as md2pdf
        pdf_path = output_dir / f"{stem}_fast_report.pdf"
        md2pdf(md_path, pdf_path)
        print(f"[fast] PDF saved: {pdf_path}")
    except Exception as exc:
        print(f"[fast] WARNING: PDF generation failed: {exc}")

    # PPTX
    pptx_path = output_dir / f"{stem}_fast_presentation.pptx"
    _build_pptx(
        data, case_id, hostname, disk_image or str(analysis_dir),
        generated_utc, pptx_path, opencti_findings, fan_summary, fame_summary,
    )

    # DOCX
    docx_path = output_dir / f"{stem}_fast_report.docx"
    _build_docx(
        data, case_id, hostname, disk_image or str(analysis_dir),
        generated_utc, docx_path, opencti_findings, fan_summary, fame_summary,
    )

    return {
        "md":   md_path,
        "pdf":  pdf_path,
        "pptx": pptx_path if pptx_path.exists() else None,
        "docx": docx_path if docx_path.exists() else None,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FAST — Storage Forensics Report Generator")
    p.add_argument("--case-id",      required=True, metavar="ID")
    p.add_argument("--hostname",     required=True, metavar="HOST")
    p.add_argument("--disk-image",   default="",   metavar="PATH")
    p.add_argument("--analysis-dir", default=None, metavar="DIR")
    p.add_argument("--exports-dir",  default=None, metavar="DIR")
    p.add_argument("--output-dir",   default=None, metavar="DIR")
    p.add_argument("--opencti",      default="",   metavar="TEXT")
    p.add_argument("--fan-summary",  default="",   metavar="TEXT")
    p.add_argument("--fame-summary", default="",   metavar="TEXT")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    paths = generate(
        case_id      = args.case_id,
        hostname     = args.hostname,
        disk_image   = args.disk_image,
        analysis_dir = Path(args.analysis_dir) if args.analysis_dir else None,
        exports_dir  = Path(args.exports_dir)  if args.exports_dir  else None,
        output_dir   = Path(args.output_dir)   if args.output_dir   else None,
        opencti_findings = args.opencti,
        fan_summary  = args.fan_summary,
        fame_summary = args.fame_summary,
    )
    print("[fast] Report suite complete:")
    for fmt, p in paths.items():
        if p:
            print(f"  {fmt.upper():4s}  {p}")
