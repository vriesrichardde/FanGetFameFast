#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
vault_writer.py — Parse module report Markdown files and write confirmed findings
into the Obsidian vault via knowledge_extractor.

The report Markdown is the authoritative, analyst-reviewed source. Vault entries
are derived from its structured tables rather than from raw tool output, so only
findings that made it into the final report are recorded.

Public API:
    write_fame_to_vault(report_md_path, notes_md_path=None)
    write_fast_to_vault(report_md_path, notes_md_path=None)
    write_fan_to_vault(report_md_path,  notes_md_path=None)

CLI:
    python3 lib/vault_writer.py --module fame --case-id FAME-2026-001
    python3 lib/vault_writer.py --module fame \
        --report ./reports/FAME-2026-001_fame_report.md \
        --notes  ./reports/FAME-2026-001_research_notes.md
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import NamedTuple

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "lib"))

from init_vault import init_vault
from knowledge_extractor import (
    close_case,
    open_case,
    record_ioc,
    record_risk,
    record_ttp,
)


# ── MITRE technique name lookup (common IDs used in FAME/FAST/FAN reports) ───
# Used when the report table has no "Name" column (e.g. FAME uses Sub-technique).
_MITRE_NAMES: dict[str, str] = {
    "T1003":     "OS Credential Dumping",
    "T1005":     "Data from Local System",
    "T1012":     "Query Registry",
    "T1014":     "Rootkit",
    "T1021":     "Remote Services",
    "T1027":     "Obfuscated Files or Information",
    "T1036":     "Masquerading",
    "T1046":     "Network Service Discovery",
    "T1047":     "Windows Management Instrumentation",
    "T1048":     "Exfiltration Over Alternative Protocol",
    "T1053":     "Scheduled Task/Job",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1055":     "Process Injection",
    "T1057":     "Process Discovery",
    "T1059":     "Command and Scripting Interpreter",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1059.003": "Command and Scripting Interpreter: Windows Command Shell",
    "T1068":     "Exploitation for Privilege Escalation",
    "T1071":     "Application Layer Protocol",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1078":     "Valid Accounts",
    "T1082":     "System Information Discovery",
    "T1083":     "File and Directory Discovery",
    "T1090":     "Proxy",
    "T1098":     "Account Manipulation",
    "T1105":     "Ingress Tool Transfer",
    "T1112":     "Modify Registry",
    "T1140":     "Deobfuscate/Decode Files or Information",
    "T1190":     "Exploit Public-Facing Application",
    "T1197":     "BITS Jobs",
    "T1218":     "System Binary Proxy Execution",
    "T1486":     "Data Encrypted for Impact",
    "T1489":     "Service Stop",
    "T1490":     "Inhibit System Recovery",
    "T1529":     "System Shutdown/Reboot",
    "T1543":     "Create or Modify System Process",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547":     "Boot or Logon Autostart Execution",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1548":     "Abuse Elevation Control Mechanism",
    "T1548.003": "Abuse Elevation Control Mechanism: Sudo and Sudo Caching",
    "T1562":     "Impair Defenses",
    "T1566":     "Phishing",
    "T1569":     "System Services",
    "T1574":     "Hijack Execution Flow",
}


# ── Tactic normalisation ──────────────────────────────────────────────────────

_TACTIC_MAP = {
    "initial access":        "initial-access",
    "execution":             "execution",
    "persistence":           "persistence",
    "privilege escalation":  "privilege-escalation",
    "privilege-escalation":  "privilege-escalation",
    "defense evasion":       "defense-evasion",
    "defense-evasion":       "defense-evasion",
    "credential access":     "credential-access",
    "discovery":             "discovery",
    "lateral movement":      "lateral-movement",
    "collection":            "collection",
    "command and control":   "command-and-control",
    "command-and-control":   "command-and-control",
    "exfiltration":          "exfiltration",
    "impact":                "impact",
}

# IOC table "Type" column → knowledge_extractor ioc_type
_IOC_TYPE_MAP = {
    "ip":        "ip",
    "domain":    "domain",
    "hostname":  "domain",
    "url":       "url",
    "hash":      "hash",
    "md5":       "hash",
    "sha1":      "hash",
    "sha256":    "hash",
    "filename":  "filename",
    "file":      "filename",
    "process":   "filename",
    "driver":    "filename",
    "email":     "email",
    "registry":  "registry_key",
    "mutex":     "mutex",
    "useragent": "useragent",
    "event":     None,       # "Event" rows (e.g. failed login) — skip
    "condition": None,       # analytical conditions — skip
    "port":      None,       # ports alone are not IOCs
}

_SKIP_SEVERITIES = {"informational", "info"}


# ── Generic Markdown table parser ─────────────────────────────────────────────

class TableRow(NamedTuple):
    cells: list[str]


def _parse_md_table(section_text: str) -> tuple[list[str], list[TableRow]]:
    """
    Parse the first Markdown table found in section_text.
    Returns (headers, rows). Headers and cell values are stripped of
    backtick quotes, bold markers, and leading/trailing whitespace.
    """
    headers: list[str] = []
    rows: list[TableRow] = []
    in_table = False

    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            if in_table:
                break
            continue
        # Separator row (---|---) — skip
        if re.match(r"^\|[-| :]+\|$", stripped):
            in_table = True
            continue
        cells = [_clean_cell(c) for c in stripped.strip("|").split("|")]
        if not headers:
            headers = cells
            in_table = True
        else:
            rows.append(TableRow(cells=cells))

    return headers, rows


def _clean_cell(raw: str) -> str:
    """Strip whitespace, backticks, bold/italic markers from a table cell."""
    s = raw.strip()
    s = re.sub(r"`([^`]*)`", r"\1", s)   # `value` → value
    s = re.sub(r"\*{1,2}([^*]*)\*{1,2}", r"\1", s)  # **bold** / *italic*
    return s.strip()


# ── Section extraction ────────────────────────────────────────────────────────

def _get_section(text: str, heading_pattern: str) -> str:
    """
    Return the text of the first section whose heading matches heading_pattern
    (case-insensitive regex on the heading line).  The section ends at the next
    ## heading or end-of-file.
    """
    lines = text.splitlines()
    start = -1
    for i, line in enumerate(lines):
        if re.search(heading_pattern, line, re.IGNORECASE) and line.startswith("#"):
            start = i + 1
            break
    if start == -1:
        return ""
    end = len(lines)
    for i in range(start, len(lines)):
        if lines[i].startswith("## ") and i > start:
            end = i
            break
    return "\n".join(lines[start:end])


# ── Header table parser ───────────────────────────────────────────────────────

def _parse_report_header(text: str) -> dict[str, str]:
    """Extract key→value pairs from the | Field | Value | table at the top."""
    meta: dict[str, str] = {}
    for line in text.splitlines()[:30]:
        if not line.startswith("|"):
            continue
        parts = [p.strip() for p in line.strip("|").split("|")]
        if len(parts) == 2 and parts[0] and parts[1]:
            meta[parts[0].lower().replace(" ", "_")] = parts[1].strip("`")
    return meta


# ── Management summary extractor ─────────────────────────────────────────────

def _parse_management_summary(text: str) -> str:
    """Return the body of the Management Summary section (§1)."""
    section = _get_section(text, r"management summary")
    # Drop blockquote lines (> Audience: ...) and Claude instructions
    lines = []
    for line in section.splitlines():
        if line.startswith(">"):
            continue
        lines.append(line)
    return "\n".join(lines).strip()


# ── MITRE ATT&CK table parser ─────────────────────────────────────────────────

class MitreTTP(NamedTuple):
    mitre_id: str
    name: str
    tactic: str
    observation: str


def _parse_mitre_table(text: str) -> list[MitreTTP]:
    """
    Extract confirmed MITRE ATT&CK techniques from the ATT&CK coverage section.
    Rows that contain 'not confirmed' in the observation are skipped.
    Rows where the sub-technique column has a real ID (e.g. T1053.005) use that
    as the authoritative identifier.
    """
    section = _get_section(text, r"mitre att&?ck coverage")
    if not section:
        section = _get_section(text, r"mitre att.?ck")
    headers, rows = _parse_md_table(section)

    # Normalise header names to lowercase for column lookup
    h = [x.lower() for x in headers]

    def _col(row: TableRow, *names: str) -> str:
        for name in names:
            for i, header in enumerate(h):
                if name in header and i < len(row.cells):
                    return row.cells[i]
        return ""

    results: list[MitreTTP] = []
    for row in rows:
        if len(row.cells) < 2:
            continue

        # Extract technique ID from Markdown link [T1014](...) or plain T1014
        raw_id = _col(row, "technique", "id")
        match = re.search(r"\[([A-Z]\d{4}(?:\.\d{3})?)\]", raw_id)
        if not match:
            match = re.search(r"([A-Z]\d{4}(?:\.\d{3})?)", raw_id)
        if not match:
            continue
        technique_id = match.group(1)

        # Prefer sub-technique ID when explicitly given
        sub = _col(row, "sub-technique", "sub_technique", "sub")
        sub_match = re.search(r"([A-Z]\d{4}\.\d{3})", sub)
        if sub_match:
            technique_id = sub_match.group(1)

        name = _col(row, "name")
        if not name or name == "—" or re.match(r"[A-Z]\d{4}", name):
            # No Name column (e.g. FAME uses Sub-technique) — look up from dict
            name = _MITRE_NAMES.get(technique_id, technique_id)

        tactic_raw = _col(row, "tactic")
        tactic = _TACTIC_MAP.get(tactic_raw.lower(), tactic_raw.lower().replace(" ", "-"))

        observation = _col(row, "observation", "evidence", "notes", "description")

        # Skip rows explicitly marked as not confirmed
        if "not confirmed" in observation.lower():
            continue

        results.append(MitreTTP(
            mitre_id=technique_id,
            name=name,
            tactic=tactic,
            observation=observation,
        ))

    return results


# ── IOC table parser ──────────────────────────────────────────────────────────

class IOCEntry(NamedTuple):
    ioc_type: str       # knowledge_extractor ioc_type
    value: str          # raw (un-defanged) value
    severity: str
    context: str


def _refang(value: str) -> str:
    """Reverse common defanging so knowledge_extractor can re-defang properly."""
    value = value.replace("[.]", ".").replace("[dot]", ".")
    value = re.sub(r"hxxps?", lambda m: m.group(0).replace("hxxp", "http"), value,
                   flags=re.IGNORECASE)
    return value


def _parse_ioc_table(text: str) -> list[IOCEntry]:
    """
    Extract IOC rows from the Indicators of Compromise section.
    Rows with Severity 'Informational' or 'Info' are skipped.
    Rows whose Type maps to None in _IOC_TYPE_MAP are skipped (Events, Conditions).
    """
    section = _get_section(text, r"indicators? of compromise")
    headers, rows = _parse_md_table(section)

    h = [x.lower() for x in headers]

    def _col(row: TableRow, *names: str) -> str:
        for name in names:
            for i, header in enumerate(h):
                if name in header and i < len(row.cells):
                    return row.cells[i]
        return ""

    results: list[IOCEntry] = []
    for row in rows:
        if len(row.cells) < 2:
            continue

        raw_type = _col(row, "type").lower().strip()
        ioc_type = _IOC_TYPE_MAP.get(raw_type)
        if ioc_type is None:
            continue  # unknown or explicitly skipped type

        severity = _col(row, "severity").lower().strip()
        if severity in _SKIP_SEVERITIES:
            continue

        raw_value = _col(row, "value", "indicator", "ioc")
        # Strip trailing context like "PID 4732" from process entries
        # e.g. "certutil.exe PID 4732" → "certutil.exe"
        if ioc_type == "filename":
            raw_value = raw_value.split(" ")[0]

        value = _refang(raw_value)
        if not value or value == "—":
            continue

        context = _col(row, "context", "description", "notes", "observation")

        results.append(IOCEntry(
            ioc_type=ioc_type,
            value=value,
            severity=severity or "medium",
            context=context,
        ))

    return results


# ── Recommendations parser ────────────────────────────────────────────────────

def _parse_recommendations(text: str) -> list[str]:
    """Return numbered recommendation items from the Recommendations section."""
    section = _get_section(text, r"recommendations?")
    recs = []
    for line in section.splitlines():
        m = re.match(r"^\d+\.\s+(.+)", line.strip())
        if m:
            # Strip markdown bold markers, keep the text clean
            clean = re.sub(r"\*{1,2}([^*]*)\*{1,2}", r"\1", m.group(1))
            recs.append(clean.strip())
    return recs


# ── Research notes: Investigation Summary ────────────────────────────────────

def _parse_investigation_summary(notes_text: str) -> str:
    """Extract the Investigation Summary paragraph from a research notes file."""
    section = _get_section(notes_text, r"investigation summary")
    # The summary is typically a single blockquote paragraph
    lines = []
    for line in section.splitlines():
        stripped = line.lstrip("> ").strip()
        if stripped:
            lines.append(stripped)
    return " ".join(lines).strip()


# ── Module-specific writers ───────────────────────────────────────────────────

def write_fame_to_vault(
    report_md_path: Path,
    notes_md_path: Path | None = None,
) -> dict[str, int]:
    """
    Parse a FAME report Markdown file (and optional research notes) and write
    confirmed findings to the Obsidian vault.

    Returns a summary dict: {"ttps": N, "iocs": N, "risks": N}.
    """
    init_vault()

    text = report_md_path.read_text(encoding="utf-8", errors="replace")
    meta = _parse_report_header(text)

    case_id  = meta.get("case_id", "UNKNOWN")
    hostname = meta.get("hostname", "unknown")

    # Management summary → case opening text
    summary = _parse_management_summary(text)
    if not summary:
        summary = f"FAME memory forensics investigation of {hostname}."

    open_case(case_id, summary, severity="medium")
    print(f"[vault] Case opened: {case_id}")

    # TTPs
    ttps = _parse_mitre_table(text)
    for ttp in ttps:
        record_ttp(
            mitre_id=ttp.mitre_id,
            technique_name=ttp.name,
            evidence_summary=f"{ttp.observation} (host: {hostname}, source: FAME report)",
            case_id=case_id,
            tactic=ttp.tactic,
            severity="high",
        )
        print(f"[vault]   TTP: {ttp.mitre_id} {ttp.name}")

    # IOCs
    iocs = _parse_ioc_table(text)
    ttp_titles = [f"{t.mitre_id} {t.name}" for t in ttps]
    for ioc in iocs:
        record_ioc(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            context=f"{ioc.context} (host: {hostname}, source: FAME report)",
            case_id=case_id,
            severity=ioc.severity,
            related_ttps=ttp_titles or None,
        )
        print(f"[vault]   IOC: {ioc.ioc_type} {ioc.value} [{ioc.severity}]")

    # Risks — one per recommendation
    recs = _parse_recommendations(text)
    for rec in recs:
        record_risk(
            asset=hostname,
            risk_description=rec,
            case_id=case_id,
            severity="medium",
            related_ttps=ttp_titles or None,
        )
    if recs:
        print(f"[vault]   Risks: {len(recs)} recorded for {hostname}")

    # Close case with Investigation Summary from research notes
    closing = f"FAME investigation complete. {len(ttps)} TTPs, {len(iocs)} IOCs recorded."
    if notes_md_path and notes_md_path.exists():
        notes_text = notes_md_path.read_text(encoding="utf-8", errors="replace")
        summary_from_notes = _parse_investigation_summary(notes_text)
        if summary_from_notes:
            closing = summary_from_notes

    close_case(case_id, closing)
    print(f"[vault] Case closed: {case_id}")

    return {"ttps": len(ttps), "iocs": len(iocs), "risks": len(recs)}


def write_fast_to_vault(
    report_md_path: Path,
    notes_md_path: Path | None = None,
) -> dict[str, int]:
    """Parse a FAST report Markdown file and write confirmed findings to the vault."""
    init_vault()

    text = report_md_path.read_text(encoding="utf-8", errors="replace")
    meta = _parse_report_header(text)
    case_id  = meta.get("case_id", "UNKNOWN")
    hostname = meta.get("hostname", "unknown")

    summary = _parse_management_summary(text)
    if not summary:
        summary = f"FAST storage forensics investigation of {hostname}."

    open_case(case_id, summary, severity="medium")
    print(f"[vault] Case opened: {case_id}")

    ttps = _parse_mitre_table(text)
    for ttp in ttps:
        record_ttp(
            mitre_id=ttp.mitre_id,
            technique_name=ttp.name,
            evidence_summary=f"{ttp.observation} (host: {hostname}, source: FAST report)",
            case_id=case_id,
            tactic=ttp.tactic,
            severity="high",
        )
        print(f"[vault]   TTP: {ttp.mitre_id} {ttp.name}")

    iocs = _parse_ioc_table(text)
    ttp_titles = [f"{t.mitre_id} {t.name}" for t in ttps]
    for ioc in iocs:
        record_ioc(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            context=f"{ioc.context} (host: {hostname}, source: FAST report)",
            case_id=case_id,
            severity=ioc.severity,
            related_ttps=ttp_titles or None,
        )
        print(f"[vault]   IOC: {ioc.ioc_type} {ioc.value} [{ioc.severity}]")

    recs = _parse_recommendations(text)
    for rec in recs:
        record_risk(
            asset=hostname,
            risk_description=rec,
            case_id=case_id,
            severity="medium",
            related_ttps=ttp_titles or None,
        )
    if recs:
        print(f"[vault]   Risks: {len(recs)} recorded for {hostname}")

    closing = f"FAST investigation complete. {len(ttps)} TTPs, {len(iocs)} IOCs recorded."
    if notes_md_path and notes_md_path.exists():
        notes_text = notes_md_path.read_text(encoding="utf-8", errors="replace")
        summary_from_notes = _parse_investigation_summary(notes_text)
        if summary_from_notes:
            closing = summary_from_notes

    close_case(case_id, closing)
    print(f"[vault] Case closed: {case_id}")

    return {"ttps": len(ttps), "iocs": len(iocs), "risks": len(recs)}


def write_fan_to_vault(
    report_md_path: Path,
    notes_md_path: Path | None = None,
) -> dict[str, int]:
    """Parse a FAN report Markdown file and write confirmed findings to the vault."""
    init_vault()

    text = report_md_path.read_text(encoding="utf-8", errors="replace")
    meta = _parse_report_header(text)
    case_id  = meta.get("case_id", "UNKNOWN")
    hostname = meta.get("hostname", meta.get("pcap", "unknown"))

    summary = _parse_management_summary(text)
    if not summary:
        summary = f"FAN network forensics investigation — {report_md_path.stem}."

    open_case(case_id, summary, severity="medium")
    print(f"[vault] Case opened: {case_id}")

    ttps = _parse_mitre_table(text)
    for ttp in ttps:
        record_ttp(
            mitre_id=ttp.mitre_id,
            technique_name=ttp.name,
            evidence_summary=f"{ttp.observation} (source: FAN report)",
            case_id=case_id,
            tactic=ttp.tactic,
            severity="high",
        )
        print(f"[vault]   TTP: {ttp.mitre_id} {ttp.name}")

    iocs = _parse_ioc_table(text)
    ttp_titles = [f"{t.mitre_id} {t.name}" for t in ttps]
    for ioc in iocs:
        record_ioc(
            ioc_type=ioc.ioc_type,
            value=ioc.value,
            context=f"{ioc.context} (source: FAN report)",
            case_id=case_id,
            severity=ioc.severity,
            related_ttps=ttp_titles or None,
        )
        print(f"[vault]   IOC: {ioc.ioc_type} {ioc.value} [{ioc.severity}]")

    recs = _parse_recommendations(text)
    for rec in recs:
        record_risk(
            asset=hostname,
            risk_description=rec,
            case_id=case_id,
            severity="medium",
            related_ttps=ttp_titles or None,
        )
    if recs:
        print(f"[vault]   Risks: {len(recs)} recorded")

    closing = f"FAN investigation complete. {len(ttps)} TTPs, {len(iocs)} IOCs recorded."
    if notes_md_path and notes_md_path.exists():
        notes_text = notes_md_path.read_text(encoding="utf-8", errors="replace")
        summary_from_notes = _parse_investigation_summary(notes_text)
        if summary_from_notes:
            closing = summary_from_notes

    close_case(case_id, closing)
    print(f"[vault] Case closed: {case_id}")

    return {"ttps": len(ttps), "iocs": len(iocs), "risks": len(recs)}


# ── Module report path resolvers ─────────────────────────────────────────────

def _resolve_paths(
    module: str,
    case_id: str | None,
    report: str | None,
    notes: str | None,
    reports_dir: Path,
) -> tuple[Path, Path | None]:
    """Return (report_path, notes_path) from CLI arguments."""
    suffixes = {
        "fame": ("_fame_report.md", "_research_notes.md"),
        "fast": ("_fast_report.md",  "_research_notes.md"),
        "fan":  ("_incident_report.md", "_research_notes.md"),
    }
    rep_suffix, notes_suffix = suffixes.get(module, ("_report.md", "_research_notes.md"))

    if report:
        report_path = Path(report)
    elif case_id:
        stem = case_id.replace(" ", "_")
        report_path = reports_dir / f"{stem}{rep_suffix}"
    else:
        raise ValueError("Provide --report or --case-id")

    if notes:
        notes_path = Path(notes)
    elif case_id:
        stem = case_id.replace(" ", "_")
        candidate = reports_dir / f"{stem}{notes_suffix}"
        notes_path = candidate if candidate.exists() else None
    else:
        notes_path = None

    return report_path, notes_path


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Write confirmed forensic findings from a module report into the Obsidian vault."
    )
    p.add_argument("--module", required=True, choices=["fame", "fast", "fan"],
                   help="Module that produced the report")
    p.add_argument("--case-id", default=None, metavar="ID",
                   help="Case ID — used to locate report files automatically")
    p.add_argument("--report", default=None, metavar="PATH",
                   help="Explicit path to the module report Markdown file")
    p.add_argument("--notes", default=None, metavar="PATH",
                   help="Explicit path to the research notes Markdown file")
    p.add_argument("--reports-dir", default=None, metavar="DIR",
                   help="Directory to search for report files (default: ./reports/)")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    reports_dir = Path(args.reports_dir) if args.reports_dir else PROJECT_ROOT / "reports"

    report_path, notes_path = _resolve_paths(
        module=args.module,
        case_id=args.case_id,
        report=args.report,
        notes=args.notes,
        reports_dir=reports_dir,
    )

    if not report_path.exists():
        print(f"[vault] ERROR: Report not found: {report_path}", file=sys.stderr)
        sys.exit(1)

    writers = {
        "fame": write_fame_to_vault,
        "fast": write_fast_to_vault,
        "fan":  write_fan_to_vault,
    }
    counts = writers[args.module](report_path, notes_path)

    print(
        f"\n[vault] Done — {counts['ttps']} TTPs · {counts['iocs']} IOCs · "
        f"{counts['risks']} risks written to vault."
    )
