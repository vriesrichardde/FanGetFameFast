#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
narrative_generator.py — Derive narrative sections from existing reports + research notes.

Reads:
  ./reports/{case_id}_research_notes.md    → attack timeline + section narratives
  ./reports/{case_id}_{module}_report*.md  → management summary + recommendations

Writes:
  ./reports/{case_id}_narrative.md         → input for report generators + board PPTX

No Anthropic API calls — pure text extraction and reformatting.

Usage:
    python3 lib/narrative_generator.py --case-id FAME-2026-BASE-ADMIN
    python3 lib/narrative_generator.py --case-id FAST-2026-DMZ-FTP --reports-dir ./reports
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
REPORTS_DIR  = PROJECT_ROOT / "reports"

# --------------------------------------------------------------------------- #
# Helpers                                                                      #
# --------------------------------------------------------------------------- #

def _detect_module(case_id: str) -> str:
    prefix = case_id.upper()
    if prefix.startswith("FAME"):
        return "fame"
    if prefix.startswith("FAST"):
        return "fast"
    if prefix.startswith("FAN"):
        return "fan"
    return "fame"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _strip_md(text: str) -> str:
    """Remove inline markdown formatting."""
    text = re.sub(r"\*\*(.*?)\*\*", r"\1", text)
    text = re.sub(r"\*(.*?)\*",     r"\1", text)
    text = re.sub(r"`(.*?)`",       r"\1", text)
    text = re.sub(r"\[(.*?)\]\(.*?\)", r"\1", text)
    return text


def _extract_section(markdown: str, heading: str) -> str:
    """Extract text between a ## heading and the next ##."""
    pattern = rf"##\s+{re.escape(heading)}(.*?)(?=\n##\s|\Z)"
    m = re.search(pattern, markdown, re.DOTALL | re.IGNORECASE)
    if not m:
        return ""
    return m.group(1).strip()


def _extract_section_by_number(markdown: str, section_num: int) -> str:
    """Extract a numbered section like ## 1. Management summary."""
    pattern = rf"##\s+{section_num}\.\s+.*?\n(.*?)(?=\n##\s+\d+\.|\n##\s+Appendix|\Z)"
    m = re.search(pattern, markdown, re.DOTALL)
    if not m:
        return ""
    return m.group(1).strip()


def _clean_body(text: str, max_chars: int = 1200) -> str:
    """Remove template `>` quote lines and collapse whitespace."""
    lines = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(">"):
            continue
        if stripped.startswith("```") or stripped == "---":
            continue
        lines.append(stripped)
    result = " ".join(lines).strip()
    # Collapse multiple spaces
    result = re.sub(r"  +", " ", result)
    result = _strip_md(result)
    return result[:max_chars].rstrip(",; ")


def _sentences(text: str, n: int = 5) -> str:
    """Return up to n sentences from text."""
    parts = re.split(r"(?<=[.!?])\s+", text.strip())
    return " ".join(parts[:n])


# --------------------------------------------------------------------------- #
# Research notes parsing                                                       #
# --------------------------------------------------------------------------- #

def _load_steps(case_id: str, reports_dir: Path) -> list[dict]:
    sys.path.insert(0, str(PROJECT_ROOT / "lib"))
    from research_notes import parse_steps
    return parse_steps(case_id, str(reports_dir))


def _investigation_summary(notes_text: str) -> str:
    """Extract the Investigation Summary block from research notes, stripped of > markers."""
    raw = _extract_section(notes_text, "Investigation Summary")
    # Strip blockquote markers
    lines = [ln.lstrip(">").strip() for ln in raw.splitlines()]
    return " ".join(ln for ln in lines if ln)


def _build_attack_timeline(steps: list[dict], investigation_summary: str) -> str:
    """Build attack_timeline narrative from research note steps."""
    lines: list[str] = []

    # Lead with the investigation summary if available
    if investigation_summary:
        summary = _strip_md(investigation_summary.replace("> ", "").strip())
        if summary:
            lines.append(summary)
            lines.append("")

    if not steps:
        lines.append("No timestamped investigation steps recorded.")
        return "\n".join(lines)

    # Filter out trivial / bookkeeping steps
    skip_prefixes = ("evidence preserved:", "sha256", "deviation logged")
    significant = [
        s for s in steps
        if s.get("outcome")
        and len(s["outcome"]) > 30
        and not any(s["title"].lower().startswith(p) for p in skip_prefixes)
    ]

    if not significant:
        significant = steps

    for s in significant:
        ts    = s.get("timestamp", "")
        title = _strip_md(s.get("title", ""))
        outcome = _strip_md(s.get("outcome", "")).replace("[ASSUMPTION] ", "[assumed] ")
        sid   = s.get("id", "")

        entry = f"At {ts}, **{title}**."
        if outcome:
            entry += f" {outcome}"
        if sid:
            entry += f" (→ {sid})"
        lines.append(entry)
        lines.append("")

    return "\n".join(lines).strip()


# --------------------------------------------------------------------------- #
# Report markdown parsing                                                      #
# --------------------------------------------------------------------------- #

def _find_report_md(case_id: str, module: str, reports_dir: Path) -> Path | None:
    """Find the best existing report markdown file for this case."""
    candidates = [
        reports_dir / f"{case_id}_{module}_report_generated.md",
        reports_dir / f"{case_id}_{module}_report.md",
        reports_dir / f"{case_id}_incident_report.md",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _extract_management_summary(report_md: str) -> str:
    raw = _extract_section_by_number(report_md, 1)
    if not raw:
        # Try headings like "## 1. Management summary"
        raw = _extract_section(report_md, "Management summary")
    return _clean_body(raw, 800)


def _extract_recommendations(report_md: str) -> list[str]:
    """Return numbered recommendations as a list of strings."""
    for heading in ("Recommendations", "Recommended actions", "15. Recommendations",
                    "16. Recommendations", "18. Recommendations"):
        raw = _extract_section(report_md, heading)
        if raw:
            break
    else:
        raw = ""

    items: list[str] = []
    for line in raw.splitlines():
        line = line.strip()
        m = re.match(r"^\d+\.\s+(.+)", line)
        if m:
            items.append(_strip_md(m.group(1)))
        elif line.startswith("- ") or line.startswith("* "):
            items.append(_strip_md(line[2:]))
    return items[:10]


def _extract_section_narrative(report_md: str, heading_keywords: list[str]) -> str:
    for kw in heading_keywords:
        raw = _extract_section(report_md, kw)
        if raw:
            cleaned = _clean_body(raw, 600)
            if len(cleaned) > 40:
                return cleaned
    return ""


def _extract_severity(report_md: str, summary: str) -> str:
    text = (report_md + " " + summary).upper()
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if sev in text:
            return sev.lower()
    return "medium"


# --------------------------------------------------------------------------- #
# Narrative assembly                                                           #
# --------------------------------------------------------------------------- #

def _derive_risk(module: str, summary: str, steps: list[dict]) -> str:
    """Derive pptx_risk from available content."""
    # Check for high-severity keywords in research notes outcomes
    risks: list[str] = []
    crit_keywords = ["rootkit", "credential", "mimikatz", "c2", "exfil", "ransomware",
                     "lateral", "privilege", "admin", "backdoor"]
    outcomes_text = " ".join(s.get("outcome", "") for s in steps).lower()

    if any(k in outcomes_text for k in ["rootkit", "mnemosyne", "driver"]):
        risks.append("Kernel-level rootkit detected — attacker has persistent, hidden access at OS level.")
    if any(k in outcomes_text for k in ["mimikatz", "credential", "password", "hash dump"]):
        risks.append("Credential theft confirmed — all managed account passwords must be considered compromised.")
    if any(k in outcomes_text for k in ["c2", "command and control", "beacon", "meterpreter"]):
        risks.append("Active or recent command-and-control communication detected — attacker retains remote access capability.")
    if any(k in outcomes_text for k in ["lateral", "rdp", "smb relay"]):
        risks.append("Evidence of lateral movement — other systems on the network may be compromised.")
    if any(k in outcomes_text for k in ["exfil", "staging", "7za", "archive"]):
        risks.append("Data staging or exfiltration artefacts found — sensitive data may have left the organisation.")
    if any(k in outcomes_text for k in ["ransomware", "encrypt"]):
        risks.append("Ransomware artefacts detected — business continuity and data availability are at risk.")

    if not risks:
        if summary:
            risks.append(f"Forensic analysis identified indicators requiring further investigation. {_sentences(summary, 2)}")
        else:
            risks.append("Risk assessment requires review of the full technical report.")

    return "\n".join(f"• {r}" for r in risks)


def _derive_impact(module: str, summary: str, steps: list[dict]) -> str:
    outcomes_text = " ".join(s.get("outcome", "") for s in steps).lower()
    impacts: list[str] = []

    if any(k in outcomes_text for k in ["shutdown", "reboot", "unavailable"]):
        impacts.append("System downtime was observed or caused by the incident.")
    if any(k in outcomes_text for k in ["rdp", "remote desktop", "session"]):
        impacts.append("Remote desktop sessions from non-standard network ranges were active during the incident window.")
    if any(k in outcomes_text for k in ["file server", "share", "smb"]):
        impacts.append("File server access may have exposed shared data to the attacker.")
    if any(k in outcomes_text for k in ["domain controller", "active directory", "dc"]):
        impacts.append("Domain controller compromise would affect authentication for all domain-joined systems.")
    if not impacts:
        impacts.append("The full operational impact is under investigation. Refer to the technical report for details.")

    return "\n".join(f"• {r}" for r in impacts)


def _derive_mitigations(steps: list[dict], recs: list[str]) -> str:
    completed: list[str] = []
    # Derive 'already done' from research notes
    done_keywords = ["contained", "isolated", "preserved", "acquired", "imaged",
                     "evidence collected", "upload", "vault", "notified"]
    outcomes_text = " ".join(s.get("outcome", "") for s in steps).lower()
    if any(k in outcomes_text for k in ["acquired", "imaged", "memory image", "disk image"]):
        completed.append("• Forensic image acquired — evidence integrity preserved.")
    if "vault" in outcomes_text or "upload" in outcomes_text:
        completed.append("• Forensic artifacts uploaded to the investigations vault.")

    in_progress = ["• Forensic analysis ongoing — findings reported as investigation progresses."]

    result = ""
    if completed:
        result += "**Completed:**\n" + "\n".join(completed) + "\n\n"
    result += "**In progress:**\n" + "\n".join(in_progress)
    return result.strip()


def _format_recommendations(recs: list[str]) -> str:
    if not recs:
        return "• Review full technical report and implement findings — CISO / IT"
    owner_hints = {
        "isolat": "IT Operations",
        "contain": "IT Operations",
        "patch": "IT Operations",
        "password": "IT / CISO",
        "credential": "IT / CISO",
        "notif": "CISO / Legal",
        "legal": "Legal",
        "audit": "Internal Audit",
        "monitor": "SOC",
        "review": "CISO",
    }
    lines = []
    for rec in recs[:8]:
        owner = "CISO / IT"
        for kw, ow in owner_hints.items():
            if kw in rec.lower():
                owner = ow
                break
        lines.append(f"• {rec} — {owner}")
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Main generator                                                               #
# --------------------------------------------------------------------------- #

def generate_narrative(case_id: str, reports_dir: Path) -> Path:
    """
    Read existing reports + research notes, write {case_id}_narrative.md.
    Returns the path written.
    """
    module = _detect_module(case_id)

    notes_text = _read(reports_dir / f"{case_id}_research_notes.md")
    steps       = _load_steps(case_id, reports_dir)
    inv_summary = _investigation_summary(notes_text)

    report_path = _find_report_md(case_id, module, reports_dir)
    report_md   = _read(report_path) if report_path else ""

    mgmt_summary = _extract_management_summary(report_md)
    recs         = _extract_recommendations(report_md)

    # Use investigation summary from notes if mgmt summary is just template text
    primary_summary = inv_summary if len(inv_summary) > len(mgmt_summary) else mgmt_summary

    attack_timeline = _build_attack_timeline(steps, inv_summary)

    section_processes = _extract_section_narrative(report_md, [
        "Process List", "Process Analysis", "windows.pslist",
        "4. Process List", "5. Process List",
    ])
    section_network = _extract_section_narrative(report_md, [
        "Network Connections", "windows.netstat", "windows.netscan",
        "5. Network", "6. Network",
    ])
    section_malware = _extract_section_narrative(report_md, [
        "Code Injection", "Malfind", "YARA",
        "6. Code", "7. Code",
    ])
    section_filesystem = _extract_section_narrative(report_md, [
        "Filesystem Timeline", "File System Timeline", "File Listing",
        "5. Filesystem", "6. Filesystem",
    ])
    section_traffic = _extract_section_narrative(report_md, [
        "Network Summary", "Traffic Summary", "Key Findings",
    ])

    pptx_summary = _sentences(primary_summary, 5) if primary_summary else (
        "Forensic analysis was completed. Refer to the full technical report for findings."
    )
    pptx_risk    = _derive_risk(module, primary_summary, steps)
    pptx_impact  = _derive_impact(module, primary_summary, steps)
    pptx_mit     = _derive_mitigations(steps, recs)
    pptx_recs    = _format_recommendations(recs)

    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    content = f"""<!-- narrative:{case_id} generated:{now_utc} model:narrative_generator -->

## attack_timeline

{attack_timeline}

## section_processes

{section_processes or f"Process analysis findings are documented in the {module.upper()} technical report. Refer to the relevant sections for detailed process activity."}

## section_network

{section_network or f"Network connection findings are documented in the {module.upper()} technical report."}

## section_malware

{section_malware or f"Malware and code injection findings are documented in the {module.upper()} technical report."}

## section_filesystem

{section_filesystem or f"Filesystem timeline findings are documented in the {module.upper()} technical report."}

## section_traffic

{section_traffic or f"Network traffic analysis findings are documented in the {module.upper()} technical report."}

## pptx_executive_summary

{pptx_summary}

## pptx_risk

{pptx_risk}

## pptx_impact

{pptx_impact}

## pptx_mitigations

{pptx_mit}

## pptx_recommendations

{pptx_recs}
"""

    out_path = reports_dir / f"{case_id}_narrative.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"[narrative] Written: {out_path}")
    return out_path


# --------------------------------------------------------------------------- #
# CLI                                                                          #
# --------------------------------------------------------------------------- #

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Generate narrative file from existing reports and research notes"
    )
    p.add_argument("--case-id",     required=True, metavar="ID")
    p.add_argument("--reports-dir", default=str(REPORTS_DIR), metavar="DIR")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    generate_narrative(args.case_id, Path(args.reports_dir))
