#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""Shared report-section builders for FAN/FAME/FAST.

Each of lib/generate_pcap_report.py, lib/generate_fame_report.py, and
lib/generate_fast_report.py builds its Markdown report as an ordered list of
section strings. This module holds the section builders that are
conceptually identical across all three modules (severity normalization,
Indicators of Compromise, MITRE ATT&CK coverage, Recommendations, and the
Evidence Trail / Appendix B), so future formatting changes happen in one
place instead of three.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from research_notes import parse_steps as _parse_research_steps, parse_events as _parse_research_events  # noqa: E402

# ── Severity normalization ───────────────────────────────────────────────────

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEVERITY_BADGE = {
    "critical": "**[CRITICAL]**",
    "high":     "**[HIGH]**",
    "medium":   "[MEDIUM]",
    "low":      "[LOW]",
    "info":     "[INFO]",
}


def normalize_severity(value: str) -> str:
    """Map any free-form severity string to the canonical lowercase
    vocabulary: critical|high|medium|low|info. Unrecognized or empty
    values fall back to "info"."""
    if not value:
        return "info"
    v = value.strip().lower()
    return v if v in SEVERITY_ORDER else "info"


def severity_badge(value: str) -> str:
    """normalize_severity(value) then render as a Markdown badge."""
    norm = normalize_severity(value)
    return SEVERITY_BADGE.get(norm, f"[{norm.upper()}]")


def severity_rank(value: str) -> int:
    """Lower = more severe. For sorting findings/IOCs by severity."""
    return SEVERITY_ORDER[normalize_severity(value)]


# ── Generic table helper ──────────────────────────────────────────────────────

def md_table(headers: list[str], rows: list[list[str]]) -> list[str]:
    lines = ["| " + " | ".join(headers) + " |"]
    lines.append("|" + "|".join([" --- " for _ in headers]) + "|")
    for row in rows:
        lines.append("| " + " | ".join(str(c) for c in row) + " |")
    return lines


# ── Indicators of Compromise ────────────────────────────────────────────────

def build_ioc_section(
    iocs: list[dict],
    heading: str = "Indicators of Compromise",
    section_num: str | None = None,
    intro: bool = True,
    empty_message: str = "No indicators of compromise extracted.",
) -> list[str]:
    """Render the canonical IOC table section.

    Each ioc dict is expected to have "type", "value", "severity",
    "category", "source". Optional keys:
      - "confidence" (CONFIRMED|INFERRED|ASSUMED): if ANY ioc has this set,
        a Confidence column is added; rows without it render "—".
      - "context" / "notes": if ANY ioc has either set, a Notes column is
        added; rows without it render "—".
    """
    title = f"## {section_num}. {heading}" if section_num else f"## {heading}"
    lines = [title, ""]

    if not iocs:
        lines += [empty_message, "", "---", ""]
        return lines

    if intro:
        lines.append(f"*{len(iocs)} unique indicator(s) extracted from all analysis outputs.*")
        lines.append("")

    show_notes = any(i.get("context") or i.get("notes") for i in iocs)
    show_confidence = any(i.get("confidence") for i in iocs)

    headers = ["Severity", "Type", "Value", "Category", "Source"]
    if show_notes:
        headers.append("Notes")
    if show_confidence:
        headers.append("Confidence")

    rows = []
    for i in iocs:
        row = [
            severity_badge(i.get("severity", "info")),
            i.get("type", ""),
            f"`{i.get('value', '')}`",
            i.get("category", ""),
            i.get("source", ""),
        ]
        if show_notes:
            row.append(i.get("context") or i.get("notes") or "—")
        if show_confidence:
            row.append(i.get("confidence") or "—")
        rows.append(row)

    lines += md_table(headers, rows)
    lines += ["", "---", ""]
    return lines


# ── MITRE ATT&CK coverage ────────────────────────────────────────────────────

def build_mitre_section(
    techniques: list[dict],
    heading: str = "MITRE ATT&CK Coverage",
    section_num: str | None = None,
    show_severity: bool = True,
    empty_message: str = "No MITRE ATT&CK techniques observed.",
) -> list[str]:
    """Render the MITRE ATT&CK coverage table.

    Each technique dict has keys "id", "name", "tactic", and either:
      - "severity" + "category" (show_severity=True — FAN-style:
        | Technique | Name | Tactic | Severity | Triggered By |), or
      - "observation" (show_severity=False — FAME/FAST-style:
        | Technique | Name | Tactic | Observation |).
    """
    title = f"## {section_num}. {heading}" if section_num else f"## {heading}"
    lines = [title, ""]

    if not techniques:
        lines += [empty_message, "", "---", ""]
        return lines

    if show_severity:
        headers = ["Technique", "Name", "Tactic", "Severity", "Triggered By"]
        rows = [[
            f"[{t['id']}](https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/)",
            t["name"],
            t["tactic"],
            severity_badge(t.get("severity", "info")),
            t.get("category", ""),
        ] for t in techniques]
    else:
        headers = ["Technique", "Name", "Tactic", "Observation"]
        rows = [[
            f"[{t['id']}](https://attack.mitre.org/techniques/{t['id'].replace('.', '/')}/ )",
            t["name"],
            t["tactic"],
            t.get("observation", ""),
        ] for t in techniques]

    lines += md_table(headers, rows)
    lines += ["", "---", ""]
    return lines


# ── Recommendations ──────────────────────────────────────────────────────────

def build_recommendations_section(
    recs: list[str],
    heading: str = "Recommendations",
    section_num: str | None = None,
    numbered: bool = False,
) -> list[str]:
    title = f"## {section_num}. {heading}" if section_num else f"## {heading}"
    lines = [title, ""]
    if numbered:
        for i, r in enumerate(recs, 1):
            lines.append(f"{i}. {r}")
    else:
        for r in recs:
            lines.append(f"- {r}")
    lines += ["", "---", ""]
    return lines


# ── Evidence trail / Appendix B ─────────────────────────────────────────────

def build_evidence_trail_section(
    case_id: str,
    reports_dir: Path | str,
    include_dismissed: bool = True,
) -> list[str]:
    if not case_id:
        return []
    steps  = _parse_research_steps(case_id, str(reports_dir))
    events = _parse_research_events(case_id, str(reports_dir))
    if not steps and not events:
        return []

    lines: list[str] = [
        "---", "",
        "## Appendix B — Investigation Evidence Trail", "",
    ]

    # Attacker timeline — events sorted by evidence timestamp
    if events:
        def _ev_sort(ev: dict) -> tuple:
            ts = ev.get("timestamp", "")
            if ts:
                try:
                    dt = datetime.strptime(ts.replace(" UTC", "").strip(), "%Y-%m-%d %H:%M:%S")
                    return (0, dt.replace(tzinfo=timezone.utc))
                except ValueError:
                    pass
            return (1, datetime.min.replace(tzinfo=timezone.utc))

        sorted_events = sorted(events, key=_ev_sort)
        lines += [
            "### Attacker Timeline", "",
            "Attacker events observed in the evidence, ordered by evidence timestamp.", "",
            "| Timestamp (UTC) | Severity | Event | Source |",
            "|-----------------|----------|-------|--------|",
        ]
        for ev in sorted_events:
            ts   = ev.get("timestamp", "") or "—"
            sev  = ev.get("severity", "info").upper()
            desc = ev.get("description", "")[:160].replace("|", "\\|")
            if len(ev.get("description", "")) > 160:
                desc += "…"
            src = (ev.get("source_detail", "") or "—").replace("|", "\\|")
            lines.append(f"| {ts} | **{sev}** | {desc} | {src} |")
        lines += ["", ""]

    # Analysis timeline — analyst investigation steps
    if steps:
        if include_dismissed:
            lines += [
                "### Analysis Timeline", "",
                "Steps recorded in the research notes during this investigation. "
                f"Preserved artifacts are in `{case_id}_evidence/`.", "",
                "| Step ID | Timestamp | Analysis Step | Outcome | Dismissed |",
                "|---------|-----------|---------------|---------|-----------|",
            ]
        else:
            lines += [
                "### Analysis Timeline", "",
                "Steps recorded in the research notes during this investigation. "
                f"Preserved artifacts are in `{case_id}_evidence/`.", "",
                "| Step ID | Timestamp | Analysis Step | Outcome |",
                "|---------|-----------|---------------|---------|",
            ]
        for s in steps:
            sid = f"`{s['id']}`" if s["id"] else "—"
            outcome = s["outcome"].replace("|", "\\|")
            if include_dismissed:
                dismissed = (s.get("dismissed") or "—").replace("|", "\\|")
                lines.append(f"| {sid} | {s['timestamp']} | {s['title']} | {outcome} | {dismissed} |")
            else:
                lines.append(f"| {sid} | {s['timestamp']} | {s['title']} | {outcome} |")
        lines += [
            "",
            "*Cross-reference step IDs with the research notes and preserved artifacts "
            f"in `{case_id}_evidence/` to verify any conclusion in this report.*",
            "",
        ]
    return lines
