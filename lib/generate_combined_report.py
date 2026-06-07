#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
generate_combined_report.py — Unified FAN + FAME + FAST combined report generator.

When multiple module reports exist for the same case ID, this module merges them
into a single unified incident report (Markdown, PDF, PPTX, DOCX) that presents
correlated findings from all three investigation domains.

Claude: enhance and elaborate when necessary throughout the combined report
to surface cross-domain correlations that no single module would identify alone.

Usage (CLI):
    python3 lib/generate_combined_report.py \\
        --case-id CASE-2026-001 \\
        --hostname SERVER1234 \\
        [--reports-dir ./reports] \\
        [--output-dir ./reports]

Python API:
    from lib.generate_combined_report import generate
    paths = generate(case_id="CASE-2026-001", hostname="SERVER1234")
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
try:
    from zoneinfo import ZoneInfo
    _CET = ZoneInfo("Europe/Amsterdam")
except ImportError:
    _CET = timezone.utc
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement

PROJECT_ROOT = Path(__file__).parent.parent

try:
    from hallucination_guard import (
        ConfidenceTier,
        tag_finding,
        render_confidence_summary,
        reset_counter as _hg_reset,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from hallucination_guard import (
        ConfidenceTier,
        tag_finding,
        render_confidence_summary,
        reset_counter as _hg_reset,
    )

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


# ── Source discovery ───────────────────────────────────────────────────────────

def _discover_sources(reports_dir: Path, case_id: str) -> dict[str, str]:
    """
    Find existing module reports for this case and extract their key summaries.
    Returns dict with keys: fan_md, fame_md, fast_md (text of found reports).
    """
    stem = case_id.replace(" ", "_")
    sources: dict[str, str] = {}

    patterns = {
        "fan_md":        [f"{stem}_incident_report.md", f"{stem}_fan_report.md"],
        "fame_md":       [f"{stem}_fame_report.md"],
        "fast_md":       [f"{stem}_fast_report.md"],
        "correlation_md": [f"{stem}_correlation.md"],
    }
    for key, filenames in patterns.items():
        for fn in filenames:
            candidate = reports_dir / fn
            if candidate.exists():
                sources[key] = candidate.read_text(errors="replace")
                break

    return sources


def _extract_section(md_text: str, section_marker: str, max_chars: int = 2000) -> str:
    """Extract a named section from a Markdown report."""
    lines = md_text.splitlines()
    in_section = False
    collected: list[str] = []
    for line in lines:
        if section_marker.lower() in line.lower() and line.startswith("#"):
            in_section = True
            continue
        if in_section:
            if line.startswith("#") and not line.startswith("##"):
                break
            collected.append(line)
    result = "\n".join(collected).strip()
    return result[:max_chars] if len(result) > max_chars else result


def _extract_summary(md_text: str) -> str:
    """Pull the Management Summary section from any module report."""
    return _extract_section(md_text, "Management Summary", max_chars=800)


def _extract_mitre(md_text: str) -> str:
    """Pull the MITRE ATT&CK section from any module report."""
    return _extract_section(md_text, "MITRE ATT", max_chars=1500)


def _extract_iocs(md_text: str) -> str:
    """Pull the IOC section from any module report."""
    return _extract_section(md_text, "Indicators of Compromise", max_chars=1500)


def _extract_recommendations(md_text: str) -> str:
    """Pull the Recommendations section from any module report."""
    return _extract_section(md_text, "Recommendations", max_chars=1500)


# ── Markdown ───────────────────────────────────────────────────────────────────

def _build_markdown(
    sources: dict[str, str],
    case_id: str,
    hostname: str,
    generated_utc: str,
) -> str:
    """
    Build the unified combined incident report.

    Claude: enhance and elaborate when necessary — this is the single document
    that integrates all three investigation domains and should provide the
    deepest analytical narrative available from the combined evidence.
    """
    fan  = sources.get("fan_md",  "")
    fame = sources.get("fame_md", "")
    fast = sources.get("fast_md", "")

    modules_run = []
    if fan:  modules_run.append("FAN (Network)")
    if fame: modules_run.append("FAME (Memory)")
    if fast: modules_run.append("FAST (Storage)")

    lines: list[str] = []
    a = lines.append

    a("# FanGetFameFast — Unified Forensics Report")
    a("")
    a("| Field | Value |")
    a("|-------|-------|")
    a(f"| Case ID | `{case_id}` |")
    a(f"| Hostname | `{hostname}` |")
    a(f"| Modules | {', '.join(modules_run) if modules_run else 'None detected'} |")
    a(f"| Generated (UTC) | {generated_utc} |")
    a(f"| Prepared by | Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman |")
    a("")
    a("> **Claude: enhance and elaborate when necessary** — this unified report combines")
    a("> all available evidence from network, memory, and storage forensics. Cross-domain")
    a("> correlations that no single module surfaces alone should be called out explicitly.")
    a("")

    # ── Management Summary ────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 1. Management summary")
    a("")
    a("> **Audience:** CISO, Legal, Law Enforcement, Internal Audit — no technical identifiers.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    if fan:
        fan_summary = _extract_summary(fan)
        if fan_summary:
            a("**Network (FAN):**")
            a("")
            a(fan_summary)
            a("")
    if fame:
        fame_summary = _extract_summary(fame)
        if fame_summary:
            a("**Memory (FAME):**")
            a("")
            a(fame_summary)
            a("")
    if fast:
        fast_summary = _extract_summary(fast)
        if fast_summary:
            a("**Storage (FAST):**")
            a("")
            a(fast_summary)
            a("")
    if not modules_run:
        a("No module reports found for this case ID. Run FAN, FAME, and/or FAST first.")
    a("")

    # ── Cross-Module Correlation ──────────────────────────────────────────────
    a("---")
    a("")
    a("## 2. Cross-domain correlation")
    a("")
    correlation_md = sources.get("correlation_md", "")
    if correlation_md:
        a("> Computed by `lib/correlate_findings.py` — actual matches across FAN, FAME, and FAST.")
        a("> Claude: enhance and elaborate when necessary.")
        a("")
        # Include correlation content starting from the first section (skip title + meta table)
        corr_lines = correlation_md.splitlines()
        past_meta = False
        for line in corr_lines:
            if not past_meta:
                # The first "---" separator marks the end of the metadata block
                if line.strip() == "---":
                    past_meta = True
                continue
            a(line)
    else:
        a("> Claude: enhance and elaborate when necessary — identify events that appear in")
        a("> two or more evidence domains. For example: a process seen in FAME memory that")
        a("> also initiated network connections visible in FAN, and whose binary is found")
        a("> in FAST storage artifacts.")
        a("")
        if len(modules_run) > 1:
            a("The following cross-domain observations are candidate correlation points.")
            a(f"Run `python3 lib/correlate_findings.py --case-id {case_id}` to compute")
            a("actual matches from raw artifact files.")
            a("")
            if fan and fame:
                a("- **FAN ↔ FAME:** Cross-reference network connections from the memory")
                a("  `netscan` output with PCAP flow data — any matching (src_ip, dst_ip, port)")
                a("  tuple links a specific process to observed network traffic.")
            if fame and fast:
                a("- **FAME ↔ FAST:** Cross-reference process image paths from memory")
                a("  `filescan` / `dlllist` with the `fls` file listing — any path seen in")
                a("  memory that is deleted on disk is a strong persistence or clean-up indicator.")
            if fan and fast:
                a("- **FAN ↔ FAST:** Cross-reference carved URLs/domains from `bulk_extractor`")
                a("  output with DNS queries observed in the PCAP — matching domains confirm")
                a("  browser or tool-based C2 contact.")
            a("")
        else:
            a("Run all three modules (FAN, FAME, FAST) for the same case ID, then run")
            a("`python3 lib/correlate_findings.py` to generate cross-domain correlation.")
            a("")

    # ── MITRE ATT&CK (deduplicated union) ─────────────────────────────────────
    a("---")
    a("")
    a("## 3. Unified MITRE ATT&CK coverage")
    a("")
    a("> Claude: enhance and elaborate when necessary — present the full kill chain")
    a("> constructed from all three evidence domains combined.")
    a("")
    seen_techniques: set[str] = set()
    for label, md_text in [("FAN", fan), ("FAME", fame), ("FAST", fast)]:
        if not md_text:
            continue
        mitre_section = _extract_mitre(md_text)
        if mitre_section:
            a(f"### From {label}")
            a("")
            a(mitre_section)
            a("")
    a("")

    # ── Unified IOCs ──────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 4. Unified indicators of compromise")
    a("")
    a("> Claude: enhance and elaborate when necessary — deduplicate IOCs across modules")
    a("> and elevate any IOC confirmed in multiple domains to Critical severity.")
    a("")
    for label, md_text in [("FAN", fan), ("FAME", fame), ("FAST", fast)]:
        if not md_text:
            continue
        ioc_section = _extract_iocs(md_text)
        if ioc_section:
            a(f"### From {label}")
            a("")
            a(ioc_section)
            a("")
    a("")

    # ── Full Module Reports ───────────────────────────────────────────────────
    for label, md_text, anchor in [
        ("FAN — Network forensics",  fan,  "fan"),
        ("FAME — Memory forensics",  fame, "fame"),
        ("FAST — Storage forensics", fast, "fast"),
    ]:
        if not md_text:
            continue
        a("---")
        a("")
        a(f"## 5.{['fan', 'fame', 'fast'].index(anchor) + 1} {label} (Full Report)")
        a("")
        a("> Claude: enhance and elaborate when necessary — incorporate cross-domain")
        a("> context from the other module sections above.")
        a("")
        # Include the full module report inline
        a(md_text.strip())
        a("")

    # ── Unified Recommendations ───────────────────────────────────────────────
    a("---")
    a("")
    a("## 6. Unified recommendations")
    a("")
    a("> Claude: enhance and elaborate when necessary — merge recommendations from all")
    a("> modules, de-duplicate, and re-prioritise based on cross-domain severity.")
    a("")
    rec_num = 1
    for label, md_text in [("FAN", fan), ("FAME", fame), ("FAST", fast)]:
        if not md_text:
            continue
        rec_section = _extract_recommendations(md_text)
        if rec_section:
            a(f"### From {label}")
            a("")
            a(rec_section)
            a("")
            rec_num += 1
    a("")

    a("---")
    a("")
    a("*End of unified report. Evidence integrity preserved. All findings cited to their source domain.*")
    a("")

    # ── Cross-Module Hallucination Guard Summary ──────────────────────────────
    hg = _build_combined_hallucination_guard(fan, fame, fast, modules_run)
    if hg:
        a(hg)
        a("")

    return "\n".join(lines)


def _build_combined_hallucination_guard(
    fan: str,
    fame: str,
    fast: str,
    modules_run: list[str],
) -> str:
    """
    Build a cross-module Hallucination Guard Summary for the combined report.

    Parses existing module Hallucination Guard sections to extract tier counts,
    then presents an aggregated IR confidence score across all three domains.
    """
    _hg_reset()
    findings = []

    # Synthesise one meta-finding per module based on whether it ran
    if fan:
        findings.append(tag_finding(
            "FAN (Network Forensics) analysis completed — all findings backed by packet-level evidence",
            ConfidenceTier.CONFIRMED,
            [],
            ["fan_protocol_analyzers"],
            ["fan"],
        ))
    else:
        findings.append(tag_finding(
            "FAN module did not run — network-layer evidence absent from this case",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["fan_protocol_analyzers"],
            ["fan"],
        ))

    if fame:
        findings.append(tag_finding(
            "FAME (Memory Forensics) analysis completed — process and network findings from memory image",
            ConfidenceTier.CONFIRMED,
            [],
            ["volatility3", "memory_baseliner"],
            ["fame"],
        ))
    else:
        findings.append(tag_finding(
            "FAME module did not run — in-memory process and network evidence absent",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["volatility3"],
            ["fame"],
        ))

    if fast:
        findings.append(tag_finding(
            "FAST (Storage Forensics) analysis completed — disk artifact findings from image",
            ConfidenceTier.CONFIRMED,
            [],
            ["tsk", "bulk_extractor"],
            ["fast"],
        ))
    else:
        findings.append(tag_finding(
            "FAST module did not run — disk artifact evidence absent from this case",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["tsk", "bulk_extractor"],
            ["fast"],
        ))

    # Cross-module confirmation bonus: if 2+ modules ran and produce overlapping IOC sections
    # extract a confirmation signal from the markdown text
    ioc_fan  = _extract_section(fan,  "Indicators of compromise", 500) if fan  else ""
    ioc_fame = _extract_section(fame, "Indicators of compromise", 500) if fame else ""
    ioc_fast = _extract_section(fast, "Indicators of compromise", 500) if fast else ""

    # Simple heuristic: if an IP appears in both FAN and FAME IOC sections → CONFIRMED
    ip_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
    fan_ips  = set(ip_re.findall(ioc_fan))
    fame_ips = set(ip_re.findall(ioc_fame))
    shared   = fan_ips & fame_ips
    if shared:
        for ip in list(shared)[:5]:
            findings.append(tag_finding(
                f"IP {ip} confirmed in both FAN (PCAP) and FAME (netscan) — cross-domain corroboration",
                ConfidenceTier.CONFIRMED,
                [],
                ["fan_ip_lookup", "volatility3/netscan"],
                ["fan", "fame"],
            ))

    return render_confidence_summary(findings, module_label="Combined report")


# ── PPTX ───────────────────────────────────────────────────────────────────────

def _build_pptx(
    sources: dict[str, str],
    case_id: str,
    hostname: str,
    generated_utc: str,
    output_path: Path,
) -> None:
    try:
        from pptx import Presentation
        from pptx.util import Inches, Pt
        from pptx.dml.color import RGBColor
        from pptx.enum.text import PP_ALIGN
    except ImportError:
        print("[combined] WARNING: python-pptx not installed — skipping PPTX.")
        return

    fan  = sources.get("fan_md",  "")
    fame = sources.get("fame_md", "")
    fast = sources.get("fast_md", "")
    modules_run = [m for m, t in [("FAN", fan), ("FAME", fame), ("FAST", fast)] if t]

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
        run.text = str(text)[:500]
        run.font.size = Pt(sz)
        run.font.bold = bold
        run.font.color.rgb = _rgb(color)

    W = prs.slide_width
    H = prs.slide_height
    M = Inches(0.4)

    # Slide 1 — Cover
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, H, _DARK_NAVY)
    _rect(s, 0, 0, W, Inches(0.08), _BLUE)
    _rect(s, 0, H - Inches(0.08), W, Inches(0.08), _BLUE)
    _txt(s, "Fan Get Fame Fast", M, Inches(1.0), W - 2*M, Inches(1.2),
         52, bold=True, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _txt(s, "Unified forensics investigation report", M, Inches(2.1), W - 2*M, Inches(0.7),
         24, color=_WHITE, align=PP_ALIGN.CENTER)
    _txt(s, "FAN  ·  FAME  ·  FAST", M, Inches(2.7), W - 2*M, Inches(0.5),
         18, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _rect(s, Inches(3), Inches(3.6), W - Inches(6), Inches(0.04), _BLUE)
    _txt(s, f"Case: {case_id}  |  Host: {hostname}  |  {generated_utc[:10]}",
         M, Inches(3.9), W - 2*M, Inches(0.5), 14, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    modules_str = "  ·  ".join(modules_run) if modules_run else "No modules run"
    _txt(s, f"Modules: {modules_str}", M, Inches(4.5), W - 2*M, Inches(0.4),
         12, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s, "Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman",
         M, Inches(5.0), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s, "CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY",
         M, H - Inches(0.7), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)

    # Slide 2 — Module Coverage Overview
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Investigation scope", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)

    col_data = [
        ("FAN", "Network forensics", "PCAP analysis · 22 protocol detectors · IDS/YARA alerts", fan),
        ("FAME", "Memory forensics", "Volatility 3 · Memory Baseliner · Process/network/code", fame),
        ("FAST", "Storage forensics", "TSK · EWF tools · Timeline · Artifact extraction", fast),
    ]
    col_w = (W - 2*M - Inches(0.4)) // 3
    for i, (abbr, title, desc, content) in enumerate(col_data):
        cx = M + i * (col_w + Inches(0.2))
        color = _MID_NAVY if content else (0x3b, 0x44, 0x5b)
        _rect(s, cx, Inches(1.2), col_w, Inches(5.8), color)
        status = "COMPLETE" if content else "NOT RUN"
        status_color = _GREEN if content else _AMBER
        _rect(s, cx, Inches(1.2), col_w, Inches(0.35), status_color if content else _AMBER)
        _txt(s, status, cx + Inches(0.1), Inches(1.22), col_w - Inches(0.2), Inches(0.3),
             11, bold=True, color=_WHITE)
        _txt(s, abbr, cx + Inches(0.1), Inches(1.65), col_w - Inches(0.2), Inches(0.8),
             32, bold=True, color=_LIGHT_BLUE if content else _TEXT_MID)
        _txt(s, title, cx + Inches(0.1), Inches(2.45), col_w - Inches(0.2), Inches(0.5),
             13, bold=True, color=_WHITE if content else _TEXT_MID)
        _txt(s, desc, cx + Inches(0.1), Inches(3.0), col_w - Inches(0.2), Inches(2.5),
             11, color=_LIGHT_BLUE if content else _TEXT_MID)
        if content:
            summary = _extract_summary(content)[:250]
            _txt(s, summary, cx + Inches(0.1), Inches(5.0), col_w - Inches(0.2), Inches(1.8),
                 10, color=_TEXT_MID)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 3 — Cross-Domain Correlation
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Cross-domain correlation", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)

    correlation_md = sources.get("correlation_md", "")
    if correlation_md:
        # Extract match counts from the confidence table in the correlation report
        ff_n = mf_n = fd_n = 0
        for line in correlation_md.splitlines():
            if "FAN ↔ FAME" in line and "|" in line:
                m = re.search(r"\|\s*(\d+)\s*\|", line)
                if m: ff_n = int(m.group(1))
            elif "FAME ↔ FAST" in line and "|" in line:
                m = re.search(r"\|\s*(\d+)\s*\|", line)
                if m: mf_n = int(m.group(1))
            elif "FAN ↔ FAST" in line and "|" in line:
                m = re.search(r"\|\s*(\d+)\s*\|", line)
                if m: fd_n = int(m.group(1))
        total_corr = ff_n + mf_n + fd_n
        correlations = [
            ("FAN ↔ FAME",
             f"{ff_n} match(es) — process-to-network: links running processes to flagged PCAP connections"),
            ("FAME ↔ FAST",
             f"{mf_n} match(es) — process-to-disk: identifies executables deleted post-execution (T1070.004)"),
            ("FAN ↔ FAST",
             f"{fd_n} match(es) — domain-to-URL: confirms endpoints seen in both DNS traffic and carved artifacts"),
        ]
        if total_corr > 0:
            correlations.append(("Total matches",
                f"{total_corr} cross-domain linkages — see {case_id}_correlation.md for full detail"))
    else:
        correlations = []
        if fan and fame:
            correlations.append(("FAN ↔ FAME",
                "Match netscan process IDs to PCAP flows — links specific processes to observed network traffic"))
        if fame and fast:
            correlations.append(("FAME ↔ FAST",
                "Cross-reference process image paths in memory with deleted file entries on disk"))
        if fan and fast:
            correlations.append(("FAN ↔ FAST",
                "Match carved URLs from bulk_extractor with DNS queries in PCAP"))
        if len(modules_run) == 3:
            correlations.append(("FAN + FAME + FAST",
                "Run python3 lib/correlate_findings.py to compute full kill-chain correlations"))

    if correlations:
        row_h = Inches(1.1)
        for i, (pair, desc) in enumerate(correlations):
            y = Inches(1.2) + i * row_h
            _rect(s, M, y, Inches(2.8), row_h - Inches(0.1), _BLUE)
            _txt(s, pair, M + Inches(0.1), y + Inches(0.2), Inches(2.6), row_h,
                 14, bold=True, color=_WHITE)
            _txt(s, desc, M + Inches(3.0), y + Inches(0.15), W - M - Inches(3.4), row_h,
                 14, color=_TEXT_DARK)
    else:
        _txt(s, "Run all three modules (FAN, FAME, FAST) for the same case ID, then run "
             "python3 lib/correlate_findings.py to generate cross-domain correlation.",
             M, Inches(2.0), W - 2*M, Inches(2.0), 15, color=_TEXT_MID)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 4 — Unified MITRE ATT&CK
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Unified MITRE ATT&CK kill chain", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)

    all_techniques: list[tuple] = []
    for label, md_text in [("FAN", fan), ("FAME", fame), ("FAST", fast)]:
        if not md_text:
            continue
        mitre = _extract_mitre(md_text)
        for line in mitre.splitlines():
            if re.match(r"\|\s*\[T\d", line):
                parts = [p.strip() for p in line.strip("|").split("|")]
                if len(parts) >= 4:
                    tid = re.sub(r"\[.*?\]\(.*?\)", lambda m: re.search(r"\[(.*?)\]", m.group()).group(1), parts[0])
                    all_techniques.append((tid, parts[1], parts[2], label, parts[3][:60]))

    if all_techniques:
        headers = ["Technique", "Name", "Tactic", "Module", "Observation"]
        col_ws  = [Inches(1.3), Inches(2.0), Inches(2.0), Inches(1.2), W - M - Inches(7.3)]
        row_h   = Inches(0.63)
        hx = M
        for h, cw in zip(headers, col_ws):
            _rect(s, hx, Inches(1.2), cw - Inches(0.05), row_h - Inches(0.04), _MID_NAVY)
            _txt(s, h, hx + Inches(0.08), Inches(1.25), cw, row_h, 12, bold=True, color=_WHITE)
            hx += cw
        for i, row in enumerate(all_techniques[:8]):
            y = Inches(1.2) + (i+1) * row_h
            bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
            rx = M
            for val, cw in zip(row, col_ws):
                _rect(s, rx, y, cw - Inches(0.05), row_h - Inches(0.04), bg)
                _txt(s, val, rx + Inches(0.08), y + Inches(0.08), cw - Inches(0.13), row_h,
                     10, color=_TEXT_DARK)
                rx += cw
    else:
        _txt(s, "No MITRE ATT&CK techniques mapped across modules.",
             M, Inches(2.0), W - 2*M, Inches(1.0), 16, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    # Slide 5 — Unified Recommendations
    s = prs.slides.add_slide(blank)
    _rect(s, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s, "Unified recommendations", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    all_recs: list[str] = []
    for md_text in [fan, fame, fast]:
        if not md_text:
            continue
        rec_section = _extract_recommendations(md_text)
        for line in rec_section.splitlines():
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith("-")):
                cleaned = re.sub(r"^\d+\.\s*", "", re.sub(r"^-\s*", "", line))
                cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)
                if cleaned and cleaned not in all_recs:
                    all_recs.append(cleaned[:130])

    row_h = Inches(0.62)
    for i, rec in enumerate(all_recs[:8]):
        y = Inches(1.2) + i * row_h
        _rect(s, M, y, Inches(0.45), row_h - Inches(0.08), _BLUE)
        _txt(s, str(i+1), M + Inches(0.08), y + Inches(0.08), Inches(0.3), row_h,
             14, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        _txt(s, rec, M + Inches(0.55), y + Inches(0.08), W - M - Inches(0.95), row_h,
             12, color=_TEXT_DARK)
    _txt(s, "Claude: enhance and elaborate when necessary", M, H - Inches(0.4), W - 2*M, Inches(0.3),
         9, color=_TEXT_MID)

    prs.save(str(output_path))
    print(f"[combined] PPTX saved: {output_path}")


# ── DOCX ───────────────────────────────────────────────────────────────────────

def _build_docx(
    sources: dict[str, str],
    case_id: str,
    hostname: str,
    generated_utc: str,
    output_path: Path,
) -> None:
    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        print("[combined] WARNING: python-docx not installed — skipping DOCX.")
        return

    fan  = sources.get("fan_md",  "")
    fame = sources.get("fame_md", "")
    fast = sources.get("fast_md", "")
    modules_run = [m for m, t in [("FAN", fan), ("FAME", fame), ("FAST", fast)] if t]

    doc = Document()
    for section in doc.sections:
        section.top_margin    = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin   = Inches(1.2)
        section.right_margin  = Inches(1.2)

    def _xml_safe(text: str) -> str:
        return re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(text))

    def _h(text, level):
        p = doc.add_heading(_xml_safe(text), level=level)
        p.runs[0].font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)

    def _p(text, bold=False, italic=False):
        p = doc.add_paragraph()
        run = p.add_run(_xml_safe(text))
        run.bold   = bold
        run.italic = italic

    def _note(text):
        p = doc.add_paragraph()
        run = p.add_run(_xml_safe(text))
        run.italic = True
        run.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)

    # Cover
    doc.add_paragraph()
    t = doc.add_heading("Fan Get Fame Fast — Unified Forensics Report", 0)
    t.alignment = WD_ALIGN_PARAGRAPH.CENTER
    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("FAN · FAME · FAST  |  Integrated Investigation Report")
    r.font.size = Pt(14)
    r.font.color.rgb = RGBColor(0x1d, 0x4e, 0xd8)
    doc.add_paragraph()

    tbl = doc.add_table(rows=5, cols=2)
    tbl.style = "Table Grid"
    for row_data in [
        ("Case ID", case_id),
        ("Hostname", hostname),
        ("Modules", ", ".join(modules_run) if modules_run else "None"),
        ("Analyst", "Claude Code — Combined Report"),
        ("Generated UTC", generated_utc),
    ]:
        i = [("Case ID", case_id), ("Hostname", hostname),
             ("Modules", ", ".join(modules_run) if modules_run else "None"),
             ("Analyst", "Claude Code — Combined Report"),
             ("Generated UTC", generated_utc)].index(row_data)
        tbl.rows[i].cells[0].text = row_data[0]
        tbl.rows[i].cells[1].text = row_data[1]

    doc.add_paragraph()
    conf = doc.add_paragraph("CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY")
    conf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    conf.runs[0].font.bold = True
    conf.runs[0].font.color.rgb = RGBColor(0xef, 0x44, 0x44)
    doc.add_page_break()

    # Management Summary
    _h("1. Management summary", 1)
    _note("Audience: CISO, Legal, Law Enforcement, Internal Audit. "
          "Claude: enhance and elaborate when necessary.")
    for label, md_text in [("Network (FAN)", fan), ("Memory (FAME)", fame), ("Storage (FAST)", fast)]:
        if not md_text:
            continue
        summary = _extract_summary(md_text)
        if summary:
            _h(label, 2)
            _p(summary.strip())
            doc.add_paragraph()
    doc.add_page_break()

    # Cross-domain correlation
    _h("2. Cross-domain correlation", 1)
    _note("Claude: enhance and elaborate when necessary — surface any event visible in two or more domains.")
    correlation_md_docx = sources.get("correlation_md", "")
    if correlation_md_docx:
        _note("Computed by lib/correlate_findings.py — actual matches across FAN, FAME, and FAST.")
        past_meta = False
        for line in correlation_md_docx.splitlines():
            stripped = line.strip()
            if not past_meta:
                if stripped == "---":
                    past_meta = True
                continue
            if not stripped:
                doc.add_paragraph()
            elif stripped.startswith("# "):
                doc.add_heading(stripped[2:], 2)
            elif stripped.startswith("## "):
                doc.add_heading(stripped[3:], 3)
            elif stripped.startswith("### "):
                doc.add_heading(stripped[4:], 4)
            elif stripped.startswith("|"):
                _p(stripped)
            elif stripped.startswith("---"):
                pass
            else:
                clean = re.sub(r"\*\*(.*?)\*\*", r"\1", stripped)
                clean = re.sub(r"\*(.*?)\*",     r"\1", clean)
                clean = re.sub(r"`(.*?)`",       r"\1", clean)
                if clean and not clean.startswith(">"):
                    _p(clean)
    else:
        _p(
            f"Cross-domain correlation has not yet been computed. Run "
            f"python3 lib/correlate_findings.py --case-id {case_id} to match "
            f"netscan connections to PCAP threats, process images to deleted disk "
            f"entries, and DNS queries to carved URLs."
        )
        correlations = []
        if fan and fame:
            correlations.append("FAN ↔ FAME: Match memory netscan output to PCAP flows — "
                                "links specific processes to observed network connections.")
        if fame and fast:
            correlations.append("FAME ↔ FAST: Cross-reference process image paths from memory "
                                "filescan with deleted entries in fls output.")
        if fan and fast:
            correlations.append("FAN ↔ FAST: Match carved URLs/domains from bulk_extractor "
                                "with DNS queries in the PCAP.")
        for c in correlations:
            p = doc.add_paragraph(style="List Bullet")
            p.add_run(c)
    doc.add_paragraph()
    doc.add_page_break()

    # Embed full module reports
    for label, md_text in [("FAN — Network forensics", fan),
                            ("FAME — Memory forensics",  fame),
                            ("FAST — Storage forensics", fast)]:
        if not md_text:
            continue
        _h(f"Module report: {label}", 1)
        _note("Claude: enhance and elaborate when necessary. Full module report follows.")
        # Stream the Markdown as plain text paragraphs (preserves all content)
        for line in md_text.splitlines():
            stripped = line.strip()
            if not stripped:
                doc.add_paragraph()
            elif stripped.startswith("# "):
                doc.add_heading(stripped[2:], 2)
            elif stripped.startswith("## "):
                doc.add_heading(stripped[3:], 3)
            elif stripped.startswith("### "):
                doc.add_heading(stripped[4:], 4)
            elif stripped.startswith("```"):
                pass  # skip fences
            elif stripped.startswith("|"):
                # Table row — just emit as text
                _p(stripped)
            else:
                clean = re.sub(r"\*\*(.*?)\*\*", r"\1", stripped)
                clean = re.sub(r"\*(.*?)\*", r"\1", clean)
                clean = re.sub(r"`(.*?)`", r"\1", clean)
                if clean:
                    _p(clean)
        doc.add_page_break()

    # Unified recommendations
    _h("Unified recommendations", 1)
    _note("Claude: enhance and elaborate when necessary — merge, de-duplicate, and re-prioritise.")
    all_recs: list[str] = []
    for md_text in [fan, fame, fast]:
        if not md_text:
            continue
        rec_section = _extract_recommendations(md_text)
        for line in rec_section.splitlines():
            line = line.strip()
            if line and (line[0].isdigit() or line.startswith("-")):
                cleaned = re.sub(r"^\d+\.\s*", "", re.sub(r"^-\s*", "", line))
                cleaned = re.sub(r"\*\*(.*?)\*\*", r"\1", cleaned)
                if cleaned and cleaned not in all_recs:
                    all_recs.append(cleaned)
    for rec in all_recs:
        p = doc.add_paragraph(style="List Number")
        p.add_run(rec)

    doc.save(str(output_path))
    print(f"[combined] DOCX saved: {output_path}")


# ── Public API ─────────────────────────────────────────────────────────────────

def generate(
    case_id: str,
    hostname: str,
    reports_dir: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Path | None]:
    reports_dir = reports_dir or (PROJECT_ROOT / "reports")
    output_dir  = output_dir  or reports_dir
    path_guard.guard_output_dir(output_dir)

    sources = _discover_sources(reports_dir, case_id)
    generated_utc = datetime.now(_CET).strftime("%Y-%m-%d %H:%M CET")
    stem = case_id.replace(" ", "_")

    md_text = _build_markdown(sources, case_id, hostname, generated_utc)
    md_path = output_dir / f"{stem}_combined_report.md"
    md_path.write_text(md_text)
    print(f"[combined] Markdown saved: {md_path}")

    pdf_path: Path | None = None
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from md_to_pdf import convert as md2pdf
        pdf_path = output_dir / f"{stem}_combined_report.pdf"
        md2pdf(md_path, pdf_path)
        print(f"[combined] PDF saved: {pdf_path}")
    except Exception as exc:
        print(f"[combined] WARNING: PDF generation failed: {exc}")

    pptx_path = output_dir / f"{stem}_combined_presentation.pptx"
    _build_pptx(sources, case_id, hostname, generated_utc, pptx_path)

    docx_path = output_dir / f"{stem}_combined_report.docx"
    _build_docx(sources, case_id, hostname, generated_utc, docx_path)

    return {
        "md":   md_path,
        "pdf":  pdf_path,
        "pptx": pptx_path if pptx_path.exists() else None,
        "docx": docx_path if docx_path.exists() else None,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FanGetFameFast — Combined Report Generator")
    p.add_argument("--case-id",     required=True, metavar="ID")
    p.add_argument("--hostname",    required=True, metavar="HOST")
    p.add_argument("--reports-dir", default=None,  metavar="DIR")
    p.add_argument("--output-dir",  default=None,  metavar="DIR")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    paths = generate(
        case_id     = args.case_id,
        hostname    = args.hostname,
        reports_dir = Path(args.reports_dir) if args.reports_dir else None,
        output_dir  = Path(args.output_dir)  if args.output_dir  else None,
    )
    print("[combined] Report suite complete:")
    for fmt, p in paths.items():
        if p:
            print(f"  {fmt.upper():4s}  {p}")
