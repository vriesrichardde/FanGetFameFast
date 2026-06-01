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
import hashlib
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

try:
    from research_notes import (
        parse_steps as _parse_research_steps,
        parse_events as _parse_research_events,
        parse_reflections as _parse_research_reflections,
    )
except ModuleNotFoundError:
    # Imported as a package (e.g. `from lib.generate_fast_report import generate`)
    # rather than run as a script — put lib/ on the path for the sibling import.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from research_notes import (
        parse_steps as _parse_research_steps,
        parse_events as _parse_research_events,
        parse_reflections as _parse_research_reflections,
    )

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

def _load_narrative(case_id: str, reports_dir: Path) -> dict[str, str]:
    """Load Claude-generated narrative sections from {case_id}_narrative.md."""
    path = reports_dir / f"{case_id}_narrative.md"
    if not path.exists():
        return {}
    sections: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = ""
        elif line.startswith("<!--"):
            continue
        elif current is not None:
            sections[current] += line + "\n"
    return {k: v.strip() for k, v in sections.items()}


def _build_evidence_trail(case_id: str, reports_dir: Path) -> list[str]:
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
                    from datetime import datetime, timezone
                    dt = datetime.strptime(ts.replace(" UTC", "").strip(), "%Y-%m-%d %H:%M:%S")
                    return (0, dt.replace(tzinfo=timezone.utc))
                except ValueError:
                    pass
            from datetime import datetime, timezone
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
        lines += [
            "### Analysis Timeline", "",
            "Steps recorded in the research notes during this investigation. "
            f"Preserved artifacts are in `{case_id}_evidence/`.", "",
            "| Step ID | Timestamp | Analysis Step | Outcome | Dismissed |",
            "|---------|-----------|---------------|---------|-----------|",
        ]
        for s in steps:
            sid = f"`{s['id']}`" if s["id"] else "—"
            outcome   = s["outcome"].replace("|", "\\|")
            dismissed = (s.get("dismissed") or "—").replace("|", "\\|")
            lines.append(f"| {sid} | {s['timestamp']} | {s['title']} | {outcome} | {dismissed} |")
        lines += [
            "",
            "*Cross-reference step IDs with the research notes and preserved artifacts "
            f"in `{case_id}_evidence/` to verify any conclusion in this report.*",
            "",
    ]

    reflections = _parse_research_reflections(case_id, str(reports_dir))
    if reflections:
        lines += ["### Reflection log", ""]
        for r in reflections:
            lines.append(f"**{r['id']} — {r['trigger']}** *(recorded {r['timestamp']})*")
            lines.append("")
            if r["reinterpret"] and r["reinterpret"] != "—":
                lines.append(f"> Re-interpretations: {r['reinterpret']}")
                lines.append("")
            if r["open_leads"] and r["open_leads"] != "—":
                lines.append(f"> Open leads: {r['open_leads']}")
                lines.append("")
    else:
        lines += [
            "### Reflection log", "",
            "No reflection entries recorded.",
            "Use `python3 lib/research_notes.py reflect` to log mid-investigation re-assessments.",
            "",
        ]

    return lines


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

    reports_dir = PROJECT_ROOT / "reports"
    narrative = _load_narrative(case_id, reports_dir)

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

    # ── Incident Timeline (Claude-generated) ─────────────────────────────────
    timeline_text = narrative.get("attack_timeline", "")
    a("---")
    a("")
    a("## 2. Incident Timeline")
    a("")
    a("> Chronological reconstruction of the attack path. Each finding references")
    a("> the investigation step (RN-NNN) and the preserved source file in")
    a(f"> `{case_id}_evidence/`.")
    a("")
    if timeline_text:
        a(timeline_text)
    else:
        a("> *Incident timeline not yet generated. Run the FAST skill to produce*")
        a(f"> *`{case_id}_narrative.md` with the `attack_timeline` section.*")
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
        fs_narrative = narrative.get("section_filesystem", "")
        if fs_narrative:
            a(fs_narrative)
            a("")
        else:
            a("> Claude: enhance and elaborate when necessary — highlight any file activity")
            a("> that coincides with the network or memory-forensics event timeline.")
            a("")
        a(f"> **Source file:** [`{case_id}_evidence/exports/fs_timeline.csv`]"
          f"(./{case_id}_evidence/exports/fs_timeline.csv)")
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
    a(f"All artifact files are preserved in `./{case_id}_evidence/` and uploaded")
    a("to the investigations vault alongside this report. SHA-256 hashes are recorded in the")
    a("research notes (Appendix B) for chain-of-custody verification.")
    a("")
    a("| File | Description |")
    a("|------|-------------|")
    a(f"| [`{case_id}_evidence/storage/ewfinfo.txt`](./{case_id}_evidence/storage/ewfinfo.txt) | E01 image metadata |")
    a(f"| [`{case_id}_evidence/storage/mmls.txt`](./{case_id}_evidence/storage/mmls.txt) | Partition table |")
    a(f"| [`{case_id}_evidence/storage/fsstat.txt`](./{case_id}_evidence/storage/fsstat.txt) | Filesystem metadata |")
    a(f"| [`{case_id}_evidence/storage/fls_output.txt`](./{case_id}_evidence/storage/fls_output.txt) | Full file listing (incl. deleted) |")
    a(f"| [`{case_id}_evidence/storage/bodyfile.txt`](./{case_id}_evidence/storage/bodyfile.txt) | MAC time bodyfile |")
    a(f"| [`{case_id}_evidence/exports/fs_timeline.csv`](./{case_id}_evidence/exports/fs_timeline.csv) | Filesystem timeline (mactime CSV) |")
    a(f"| [`{case_id}_evidence/exports/mft/$MFT`](./{case_id}_evidence/exports/mft/) | Master File Table |")
    a(f"| [`{case_id}_evidence/exports/mft/$J`](./{case_id}_evidence/exports/mft/) | USN Change Journal |")
    a(f"| [`{case_id}_evidence/exports/evtx/`](./{case_id}_evidence/exports/evtx/) | Windows Event Logs |")
    a(f"| [`{case_id}_evidence/exports/registry/`](./{case_id}_evidence/exports/registry/) | Registry hives |")
    a(f"| [`{case_id}_evidence/exports/prefetch/`](./{case_id}_evidence/exports/prefetch/) | Prefetch files |")
    a(f"| [`{case_id}_evidence/exports/carved/`](./{case_id}_evidence/exports/carved/) | bulk_extractor carved artifacts |")
    a("")
    a("*All findings derived from disk image analysis as stated. Evidence integrity preserved.*")
    a("")

    # ── Evidence Trail ────────────────────────────────────────────────────────
    lines.extend(_build_evidence_trail(case_id, reports_dir))

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


# ── DOCX utility helpers ──────────────────────────────────────────────────────

def _compute_file_metadata(file_path: Path) -> tuple[str, str]:
    if not file_path.exists():
        return "N/A", "N/A"
    mtime_str = datetime.fromtimestamp(
        file_path.stat().st_mtime, tz=_CET
    ).strftime("%d-%b-%Y %H:%M CET")
    h = hashlib.sha256()
    with open(file_path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return mtime_str, h.hexdigest()


def _set_doc_font(doc: Any, font_name: str = "Arial") -> None:
    for style_name in [
        "Normal", "Heading 1", "Heading 2", "Heading 3", "Heading 4",
        "No Spacing", "Intense Quote", "List Number", "List Bullet", "Table Grid",
    ]:
        try:
            doc.styles[style_name].font.name = font_name
        except Exception:
            pass


def _add_header_footer(section: Any, case_id: str) -> None:
    from docx.shared import Pt, RGBColor
    from docx.enum.text import WD_ALIGN_PARAGRAPH
    from docx.oxml.ns import qn
    from docx.oxml import OxmlElement

    hdr = section.header
    h_para = hdr.paragraphs[0] if hdr.paragraphs else hdr.add_paragraph()
    h_para.clear()
    h_run = h_para.add_run(case_id)
    h_run.font.name = "Arial"
    h_run.font.size = Pt(9)
    h_run.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)
    h_para.alignment = WD_ALIGN_PARAGRAPH.RIGHT

    ftr = section.footer
    f_para = ftr.paragraphs[0] if ftr.paragraphs else ftr.add_paragraph()
    f_para.clear()
    f_para.alignment = WD_ALIGN_PARAGRAPH.CENTER

    def _fld_char(fld_type: str) -> Any:
        r = OxmlElement("w:r")
        fc = OxmlElement("w:fldChar")
        fc.set(qn("w:fldCharType"), fld_type)
        r.append(fc)
        return r

    def _instr(text: str) -> Any:
        r = OxmlElement("w:r")
        it = OxmlElement("w:instrText")
        it.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
        it.text = text
        r.append(it)
        return r

    def _txt_run(text: str) -> Any:
        r = f_para.add_run(text)
        r.font.name = "Arial"
        r.font.size = Pt(9)
        r.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)
        return r

    _txt_run("Page ")
    f_para._p.append(_fld_char("begin"))
    f_para._p.append(_instr(" PAGE "))
    f_para._p.append(_fld_char("end"))
    _txt_run(" of ")
    f_para._p.append(_fld_char("begin"))
    f_para._p.append(_instr(" NUMPAGES "))
    f_para._p.append(_fld_char("end"))


def _add_watermark(section: Any) -> None:
    from lxml import etree

    hdr = section.header
    wm_para = hdr.add_paragraph()
    vml = (
        '<w:r xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
        ' xmlns:v="urn:schemas-microsoft-com:vml"'
        ' xmlns:o="urn:schemas-microsoft-com:office:office">'
        "<w:rPr><w:noProof/></w:rPr>"
        "<w:pict>"
        '<v:shape id="WaterMark" o:spid="_x0000_s2049"'
        ' type="#_x0000_t136"'
        ' style="position:absolute;margin-left:0;margin-top:0;'
        "width:430pt;height:120pt;z-index:-251654144;"
        "rotation:315;"
        "mso-position-horizontal:center;"
        "mso-position-horizontal-relative:page;"
        "mso-position-vertical:center;"
        'mso-position-vertical-relative:page"'
        ' fillcolor="#C0C0C0" stroked="f">'
        "<v:textpath"
        ' on="t" fitshape="t" string="CONFIDENTIAL"'
        " style='font-family:\"Arial\";font-size:1pt;font-weight:bold'"
        "/>"
        "</v:shape>"
        "</w:pict>"
        "</w:r>"
    )
    wm_para._p.append(etree.fromstring(vml))


def _remove_blank_paragraphs(doc: Any) -> None:
    from docx.oxml.ns import qn

    paras = list(doc.paragraphs)
    to_remove = []
    for i, para in enumerate(paras):
        if para.text.strip():
            continue
        if para.style.name.startswith("Heading"):
            continue
        if para._element.find(".//" + qn("w:br")) is not None:
            continue
        prev_heading = i > 0 and paras[i - 1].style.name.startswith("Heading")
        next_heading = i + 1 < len(paras) and paras[i + 1].style.name.startswith("Heading")
        if prev_heading or next_heading:
            continue
        to_remove.append(para._element)
    for elem in to_remove:
        if elem.getparent() is not None:
            elem.getparent().remove(elem)


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
        run.font.name = "Arial"
        run.font.size = Pt(sz)
        run.font.bold = bold
        run.font.color.rgb = _rgb(color)
        return tb

    W = prs.slide_width
    H = prs.slide_height
    M = Inches(0.4)

    fls      = data.get("fls_output", "")
    deleted  = fls.count("\n* ") if fls else 0
    evtx     = data.get("evtx_list", [])
    prefetch = data.get("prefetch_list", [])
    timeline_rows = data.get("fs_timeline_csv", [])

    # ── Slide 1 — Cover ───────────────────────────────────────────────────────
    s1 = prs.slides.add_slide(blank)
    _rect(s1, 0, 0, W, H, _DARK_NAVY)
    _rect(s1, 0, 0, W, Inches(0.08), _BLUE)
    _rect(s1, 0, H - Inches(0.08), W, Inches(0.08), _BLUE)
    _txt(s1, "FAST", M, Inches(1.2), W - 2*M, Inches(1.2),
         72, bold=True, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _txt(s1, "Forensic analysis storage", M, Inches(2.2), W - 2*M, Inches(0.7),
         28, color=_WHITE, align=PP_ALIGN.CENTER)
    _txt(s1, "Storage forensics incident report", M, Inches(2.9), W - 2*M, Inches(0.6),
         20, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _rect(s1, Inches(3), Inches(3.8), W - Inches(6), Inches(0.04), _BLUE)
    _txt(s1, f"Case: {case_id}  |  Host: {hostname}  |  {generated_utc[:10]}",
         M, Inches(4.1), W - 2*M, Inches(0.5), 14, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s1, "Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin",
         M, Inches(4.6), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _txt(s1, "Fan Get Fame Fast  |  FAST module",
         M, H - Inches(0.7), W - 2*M, Inches(0.4), 11, color=_TEXT_MID, align=PP_ALIGN.CENTER)

    # ── Slide 2 — Key findings ────────────────────────────────────────────────
    s2 = prs.slides.add_slide(blank)
    _rect(s2, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s2, "Key findings", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    _txt(s2, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3), 12, color=_LIGHT_BLUE)

    summary = (
        f"Storage forensic analysis was conducted on the disk image of {hostname}. "
        f"The analysis identified {deleted} deleted file entries, "
        f"{len(evtx)} Windows Event Log file(s), and "
        f"{len(prefetch)} Prefetch execution artifact(s). "
        "The filesystem timeline has been reconstructed for cross-reference with "
        "network and memory forensics findings."
    )
    _txt(s2, summary, M, Inches(1.3), W - 2*M, Inches(3.0), 15, color=_TEXT_DARK)

    metrics = [
        ("Deleted files",  str(deleted)),
        ("Event logs",     str(len(evtx))),
        ("Prefetch files", str(len(prefetch))),
        ("MFT extracted",  "Yes" if data.get("mft_extracted") else "No"),
    ]
    col_w = (W - 2*M) // len(metrics)
    for i, (label, value) in enumerate(metrics):
        cx = M + i * col_w
        _rect(s2, cx + Inches(0.05), Inches(4.7), col_w - Inches(0.1), Inches(1.3), _MID_NAVY)
        _txt(s2, value, cx + Inches(0.1), Inches(4.8), col_w - Inches(0.2), Inches(0.7),
             18, bold=True, color=_AMBER)
        _txt(s2, label, cx + Inches(0.1), Inches(5.5), col_w - Inches(0.2), Inches(0.4),
             10, color=_LIGHT_BLUE)

    # ── Slide 3 — Incident timeline ───────────────────────────────────────────
    s3 = prs.slides.add_slide(blank)
    _rect(s3, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s3, "Incident timeline", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    _txt(s3, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3), 12, color=_LIGHT_BLUE)

    if timeline_rows:
        headers_t = list(timeline_rows[0].keys())[:4] if timeline_rows else []
        shown_t   = timeline_rows[:11]
        row_h = Inches(0.46)
        col_ws_t = [Inches(2.0), Inches(1.5), Inches(4.0), W - M - Inches(8.0)]
        hx = M
        for h_t, cw_t in zip(headers_t, col_ws_t):
            _rect(s3, hx, Inches(1.15), cw_t - Inches(0.05), row_h - Inches(0.04), _MID_NAVY)
            _txt(s3, h_t, hx + Inches(0.08), Inches(1.2), cw_t - Inches(0.13), row_h,
                 12, bold=True, color=_WHITE)
            hx += cw_t
        for i, row_t in enumerate(shown_t):
            y = Inches(1.15) + (i + 1) * row_h
            bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
            rx = M
            for h_t, cw_t in zip(headers_t, col_ws_t):
                _rect(s3, rx, y, cw_t - Inches(0.05), row_h - Inches(0.04), bg)
                _txt(s3, str(row_t.get(h_t, ""))[:50], rx + Inches(0.08), y + Inches(0.06),
                     cw_t - Inches(0.13), row_h, 10, color=_TEXT_DARK)
                rx += cw_t
        if len(timeline_rows) > 11:
            _txt(s3, f"… {len(timeline_rows) - 11} additional entries in fs_timeline.csv",
                 M, H - Inches(0.45), W - 2*M, Inches(0.3), 10, color=_TEXT_MID)
    else:
        _txt(s3, "No filesystem timeline available — run mactime against the bodyfile.",
             M, Inches(2.0), W - 2*M, Inches(1.0), 16, color=_TEXT_MID)

    # ── Slide 4 — Key evidence ────────────────────────────────────────────────
    s4 = prs.slides.add_slide(blank)
    _rect(s4, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s4, "Key evidence", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    _txt(s4, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3), 12, color=_LIGHT_BLUE)

    evidence_items = [
        ("Deleted file entries",
         f"{deleted} deleted entries identified in the file system listing (fls)."),
        ("Windows Event Logs",
         f"{len(evtx)} EVTX file(s) extracted — import into Hayabusa or Timeline Explorer."),
        ("Prefetch artifacts",
         f"{len(prefetch)} Prefetch file(s) — parse with PECmd for execution history."),
        ("MFT / USN journal",
         ("Extracted — run MFTECmd for high-resolution file activity."
          if data.get("mft_extracted") else "Not extracted from this image.")),
        ("Carved artifacts",
         (f"{len(data.get('bulk_carved', []))} file(s) recovered by bulk_extractor."
          if data.get("bulk_carved") else "bulk_extractor produced no output.")),
    ]
    row_h = Inches(1.0)
    for i, (label, desc) in enumerate(evidence_items[:5]):
        y = Inches(1.25) + i * row_h
        bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
        _rect(s4, M, y, Inches(3.5), row_h - Inches(0.06), bg)
        _rect(s4, M + Inches(3.5), y, W - M - Inches(3.5) - M, row_h - Inches(0.06), bg)
        _txt(s4, label, M + Inches(0.1), y + Inches(0.1), Inches(3.3), row_h,
             13, bold=True, color=_TEXT_DARK)
        _txt(s4, desc, M + Inches(3.6), y + Inches(0.1), W - M - Inches(4.1), row_h,
             12, color=_TEXT_DARK)

    # ── Slide 5 — Recommendations ─────────────────────────────────────────────
    s5 = prs.slides.add_slide(blank)
    _rect(s5, 0, 0, W, Inches(1.1), _MID_NAVY)
    _txt(s5, "Recommendations", M, Inches(0.2), W, Inches(0.8), 28, bold=True, color=_WHITE)
    _txt(s5, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3), 12, color=_LIGHT_BLUE)
    recs = _build_recommendations(data)
    row_h = Inches(0.72)
    for i, rec in enumerate(recs[:7]):
        y = Inches(1.2) + i * row_h
        _rect(s5, M, y, Inches(0.5), row_h - Inches(0.08), _BLUE)
        _txt(s5, str(i + 1), M + Inches(0.1), y + Inches(0.1), Inches(0.3), row_h,
             16, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec.split(" — ")[0][:120])
        _txt(s5, rec_clean, M + Inches(0.6), y + Inches(0.1), W - M - Inches(1.0), row_h,
             13, color=_TEXT_DARK)

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

    analysis_dir_p = PROJECT_ROOT / "analysis" / "storage"
    exports_dir_p  = PROJECT_ROOT / "exports"
    doc = Document()

    # ── Page setup ────────────────────────────────────────────────────────────
    for section in doc.sections:
        section.top_margin      = Inches(1.0)
        section.bottom_margin   = Inches(1.0)
        section.left_margin     = Inches(1.2)
        section.right_margin    = Inches(1.2)
        section.header_distance = Inches(0.4)
        section.footer_distance = Inches(0.4)

    # ── Default font ──────────────────────────────────────────────────────────
    _set_doc_font(doc, "Arial")
    doc.styles["Normal"].paragraph_format.space_after  = Pt(5)
    doc.styles["Normal"].paragraph_format.space_before = Pt(0)
    for _i in range(1, 5):
        try:
            _hs = doc.styles[f"Heading {_i}"]
            _hs.paragraph_format.space_before = Pt(14 if _i == 1 else 10)
            _hs.paragraph_format.space_after  = Pt(4)
            _hs.font.name = "Arial"
        except Exception:
            pass

    styles = doc.styles

    def _heading(text: str, level: int) -> None:
        p = doc.add_heading(text, level=level)
        if p.runs:
            p.runs[0].font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)
            p.runs[0].font.name = "Arial"

    def _para(text: str, bold: bool = False, italic: bool = False) -> None:
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.bold      = bold
        run.italic    = italic
        run.font.name = "Arial"

    def _note(text: str) -> None:
        p = (doc.add_paragraph(style="Intense Quote")
             if "Intense Quote" in [s.name for s in styles]
             else doc.add_paragraph())
        run = p.add_run(text)
        run.italic = True
        run.font.name = "Arial"
        run.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)

    def _code(text: str) -> None:
        sn = "No Spacing" if "No Spacing" in [s.name for s in styles] else "Normal"
        p  = doc.add_paragraph(style=sn)
        r  = p.add_run(text)
        r.font.name  = "Courier New"
        r.font.size  = Pt(9)
        r.font.color.rgb = RGBColor(0x1e, 0x3a, 0x5f)

    def _table_2col(rows: list[tuple[str, str]], header: bool = True) -> None:
        start = 1 if header else 0
        tbl = doc.add_table(rows=len(rows) + start, cols=2)
        tbl.style = "Table Grid"
        if header:
            for i, h in enumerate(["Field", "Value"]):
                c = tbl.rows[0].cells[i]
                c.text = h
                c.paragraphs[0].runs[0].font.bold = True
                c.paragraphs[0].runs[0].font.name = "Arial"
        for i, (k, v) in enumerate(rows):
            r = tbl.rows[i + start]
            r.cells[0].text = k
            r.cells[1].text = v
            for j in range(2):
                for run in r.cells[j].paragraphs[0].runs:
                    run.font.name = "Arial"

    # ── Header, footer, watermark ─────────────────────────────────────────────
    for section in doc.sections:
        _add_header_footer(section, case_id)
        _add_watermark(section)

    # ── Cover ──────────────────────────────────────────────────────────────────
    title = doc.add_heading("FAST — Storage forensics report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    if title.runs:
        title.runs[0].font.name = "Arial"

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sub.add_run("Forensic Analysis Storage  |  Fan Get Fame Fast")
    r.font.size  = Pt(14)
    r.font.name  = "Arial"
    r.font.color.rgb = RGBColor(0x1d, 0x4e, 0xd8)

    disk_mtime = "N/A"
    if disk_image and Path(disk_image).exists():
        disk_mtime = datetime.fromtimestamp(
            Path(disk_image).stat().st_mtime, tz=_CET
        ).strftime("%d-%b-%Y %H:%M CET")

    _table_2col([
        ("Case ID",              case_id),
        ("Hostname",             hostname),
        ("Disk image",           Path(disk_image).name if disk_image else ""),
        ("Disk image created",   disk_mtime),
        ("Module",               "FAST — Forensic Analysis Storage"),
        ("Analysts",             "Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin"),
        ("Generated",            generated_utc),
        ("Analysis tools",       "The Sleuth Kit (TSK) · ewflib · bulk_extractor · qemu-nbd"),
    ])
    doc.add_page_break()

    # ── Part A — Investigation methodology ───────────────────────────────────
    _heading("Part A — Investigation methodology", 1)
    doc.add_paragraph()

    _heading("A.1  Evidence acquisition and integrity", 2)
    _para(
        f"The disk image {Path(disk_image).name!r} was acquired from the subject machine "
        "and stored as a read-only artifact. All analysis tools in this pipeline open the "
        "image in read-only mode. The image is never modified during analysis. "
        "For E01 (Expert Witness Format) images, ewfverify confirms hash integrity before "
        "any analysis begins. For raw and VM disk formats (VDI, VMDK), the image is "
        "exposed as a block device via qemu-nbd in read-only mode."
    )
    doc.add_paragraph()
    _para(
        "All analysis output files are written to a separate working directory "
        "(analysis/storage/ and exports/) and are archived in the investigations vault "
        "on completion. The evidence image is never stored in the working directory."
    )
    doc.add_paragraph()

    _heading("A.2  Tool suite and versions", 2)
    _table_2col([
        ("The Sleuth Kit (TSK)",  "fls, fsstat, mmls, ils, icat — file system analysis"),
        ("ewflib / libewf",       "ewfinfo, ewfverify — E01 image metadata and integrity"),
        ("bulk_extractor",        "File carving and feature extraction from raw disk"),
        ("qemu-nbd",              "Block device export for VDI/VMDK disk images"),
        ("mactime (TSK)",         "Filesystem timeline generation from bodyfile"),
        ("python-docx",           "Word document generation"),
    ])
    doc.add_paragraph()

    _heading("A.3  Chain of custody summary", 2)
    _para(
        f"Image: {Path(disk_image).name}  →  read-only mount / nbd export  →  "
        "TSK tools extract metadata to analysis/storage/  →  "
        "artifacts exported to exports/  →  "
        "reports generated to reports/  →  "
        "uploaded to investigations vault"
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ── Part B — Artifact extraction catalog ─────────────────────────────────
    _heading("Part B — Artifact extraction catalog", 1)
    _note(
        "For each artifact: extraction method, evidence integrity statement, "
        "contents, and role in the investigation."
    )
    doc.add_paragraph()

    # B.1 EWF
    _heading("B.1  E01 image verification (ewfinfo / ewfverify)", 2)
    _para("Extraction method", bold=True)
    _code(f"ewfinfo {Path(disk_image).name} > analysis/storage/ewfinfo.txt\n"
          f"ewfverify {Path(disk_image).name} > analysis/storage/ewfverify.txt")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "ewfverify reads the embedded MD5 and SHA-1 hashes from the E01 segment headers "
        "and recalculates them over the stored data. A mismatch would indicate image "
        "corruption or tampering. ewfinfo extracts acquisition metadata (examiner, case "
        "notes, acquisition tool, timestamps) embedded by the acquisition software. "
        "These are immutable properties of the E01 container."
    )
    doc.add_paragraph()
    _para("Contents", bold=True)
    ewfinfo = data.get("ewfinfo", "")
    ewfverify = data.get("ewfverify", "")
    if ewfinfo:
        _code(ewfinfo.strip()[:800])
    else:
        _para("ewfinfo.txt: not available (non-E01 image format or tool not run).")
    if ewfverify:
        _code(ewfverify.strip()[:300])
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "Hash verification is the first step before any analysis. Without a confirmed "
        "hash match, no finding can be cited as derived from an intact image. For non-E01 "
        "formats (VDI, VMDK), integrity is established by recording the SHA-256 hash of "
        "the image file at analysis start."
    )
    doc.add_paragraph()

    # B.2 mmls
    _heading("B.2  Partition table analysis (mmls)", 2)
    _para("Extraction method", bold=True)
    _code("mmls -a <device> > analysis/storage/mmls.txt")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "mmls reads the partition table structures (MBR, GPT, or BSD disklabel) from "
        "the first sectors of the block device. The output is a direct representation "
        "of the on-disk partition map with no interpretation beyond sector arithmetic."
    )
    doc.add_paragraph()
    _para("Contents", bold=True)
    mmls = data.get("mmls", "")
    if mmls:
        _code(mmls.strip()[:1000])
    else:
        _para("mmls.txt: not available.")
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "The partition table identifies which sectors contain the primary filesystem, "
        "recovery partitions, and unallocated space. Unallocated space is a high-value "
        "target for carved artifacts and deleted data recovery."
    )
    doc.add_paragraph()

    # B.3 fsstat
    _heading("B.3  Filesystem metadata (fsstat)", 2)
    _para("Extraction method", bold=True)
    _code("fsstat -o <start_sector> <device> > analysis/storage/fsstat.txt")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "fsstat reads the filesystem superblock (ext4) or boot sector / VBR (NTFS/FAT) "
        "and reports volume metadata: filesystem type, cluster size, MFT location, "
        "volume serial number, and last-written timestamp. These are fixed metadata "
        "structures that are not altered by read-only file access."
    )
    doc.add_paragraph()
    _para("Contents", bold=True)
    fsstat = data.get("fsstat", "")
    if fsstat:
        _code(fsstat.strip()[:1000])
    else:
        _para("fsstat.txt: not available.")
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "The filesystem type and cluster size determine which TSK plugins apply. "
        "The volume last-written timestamp is an important corroboration point against "
        "the investigation timeline."
    )
    doc.add_paragraph()

    # B.4 fls
    _heading("B.4  File listing including deleted entries (fls)", 2)
    _para("Extraction method", bold=True)
    _code("fls -r -o <start_sector> <device> > analysis/storage/fls_output.txt\n"
          "ils -o <start_sector> <device> > analysis/storage/ils_output.txt\n"
          "ils -O -o <start_sector> <device> > analysis/storage/ils_orphan.txt")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "fls enumerates all allocated and unallocated directory entries from the "
        "filesystem metadata layer. Deleted entries (marked with *) are directory "
        "entries whose inode has been deallocated but whose name record persists in "
        "the parent directory. ils enumerates all inodes including orphan inodes "
        "(allocated inodes with no directory entry). Both tools operate read-only."
    )
    doc.add_paragraph()
    fls_txt = data.get("fls_output", "")
    deleted = fls_txt.count("\n* ") if fls_txt else 0
    _para("Contents", bold=True)
    _para(f"Total deleted file entries identified: {deleted}")
    if fls_txt:
        deleted_lines = [l for l in fls_txt.splitlines() if l.startswith("* ")][:10]
        if deleted_lines:
            _code("\n".join(deleted_lines))
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "Deleted files in user-writable paths (home directories, temp, downloads) are "
        "high-priority triage candidates. An attacker will often delete tools, scripts, "
        "and logs after use. The presence of deleted executables or scripts in "
        "system paths may indicate persistence mechanism clean-up."
    )
    doc.add_paragraph()

    # B.5 Filesystem timeline
    _heading("B.5  Filesystem timeline (mactime)", 2)
    _para("Extraction method", bold=True)
    _code("fls -r -m '' -o <start> <device> > analysis/storage/bodyfile.txt\n"
          "mactime -b analysis/storage/bodyfile.txt -d > exports/fs_timeline.csv")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "The bodyfile format captures four POSIX timestamps per file entry: modified (M), "
        "accessed (A), changed (C), and born/created (B) — collectively MAC(B) times. "
        "mactime converts these to a human-readable timeline ordered by timestamp. "
        "Timestamps come directly from the filesystem metadata layer and are not "
        "interpreted or modified."
    )
    doc.add_paragraph()
    timeline_rows = data.get("fs_timeline_csv", [])
    _para("Contents", bold=True)
    if timeline_rows:
        _para(f"Timeline contains {len(timeline_rows)} entries. First 10 shown:")
        headers_t = list(timeline_rows[0].keys()) if timeline_rows else []
        tbl = doc.add_table(rows=min(len(timeline_rows), 10) + 1, cols=len(headers_t))
        tbl.style = "Table Grid"
        for i, h in enumerate(headers_t):
            c = tbl.rows[0].cells[i]
            c.text = h
            if c.paragraphs[0].runs:
                c.paragraphs[0].runs[0].font.bold = True
                c.paragraphs[0].runs[0].font.name = "Arial"
        for ri, row_t in enumerate(timeline_rows[:10]):
            for ci, h in enumerate(headers_t):
                c = tbl.rows[ri + 1].cells[ci]
                c.text = str(row_t.get(h, ""))
                for run in c.paragraphs[0].runs:
                    run.font.name = "Arial"
    else:
        _para("fs_timeline.csv: not available — mactime not run or bodyfile empty.")
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "The filesystem timeline is the primary tool for reconstructing the sequence "
        "of file operations during the incident. Sorting by modification time reveals "
        "when files were created, modified, or deleted. Cross-referencing with network "
        "(FAN) and memory (FAME) timelines establishes the full attack chain."
    )
    doc.add_paragraph()
    doc.add_page_break()

    # B.6 Extracted artifacts
    _heading("B.6  Artifact extraction", 2)
    _para(
        "The following artifacts were extracted from the disk image using icat (TSK) "
        "and direct filesystem access. Each category is stored in a dedicated subdirectory "
        "under exports/."
    )
    doc.add_paragraph()
    evtx_l    = data.get("evtx_list", [])
    reg_l     = data.get("registry_list", [])
    pref_l    = data.get("prefetch_list", [])
    srum_l    = data.get("srum_list", [])
    browser_l = data.get("browser_list", [])
    _table_2col([
        ("Windows Event Logs (EVTX)",    f"{len(evtx_l)} file(s) in exports/evtx/"),
        ("Registry hives",               f"{len(reg_l)} file(s) in exports/registry/"),
        ("Prefetch files",               f"{len(pref_l)} file(s) in exports/prefetch/"),
        ("SRUM database",                f"{len(srum_l)} file(s) in exports/srum/"),
        ("Browser history",              f"{len(browser_l)} file(s) in exports/browser/"),
        ("MFT ($MFT)",                   "Extracted" if data.get("mft_extracted") else "Not extracted"),
        ("USN Change Journal ($J)",      "Extracted" if data.get("usnj_extracted") else "Not extracted"),
    ])
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "Windows Event Logs contain logon events (4624/4625), service installs (7045), "
        "PowerShell execution (4103/4104), and process creation (4688). Registry hives "
        "contain run keys, service definitions, and user activity artifacts. Prefetch "
        "files reveal program execution history with first/last run timestamps. The MFT "
        "and USN journal provide a high-resolution file modification log that complements "
        "the bodyfile timeline."
    )
    doc.add_paragraph()

    # B.7 bulk_extractor
    _heading("B.7  File carving — bulk_extractor", 2)
    _para("Extraction method", bold=True)
    _code(f"bulk_extractor -o exports/carved -j 4 <device>")
    doc.add_paragraph()
    _para("Evidence integrity", bold=True)
    _para(
        "bulk_extractor scans the raw disk image sequentially, identifying feature "
        "patterns (email addresses, URLs, credit card numbers, etc.) and carving "
        "file headers. It does not parse filesystem structures — it operates directly "
        "on the raw byte stream, recovering artifacts from both allocated and unallocated "
        "space. Output files are plain text feature lists and carved file fragments."
    )
    doc.add_paragraph()
    carved = data.get("bulk_carved", [])
    _para("Contents", bold=True)
    if carved:
        _para(f"{len(carved)} output file(s) in exports/carved/:")
        for cf in carved[:15]:
            _para(f"  {cf}")
    else:
        _para("bulk_extractor produced no output or was not run.")
    doc.add_paragraph()
    _para("Role in the investigation", bold=True)
    _para(
        "Email addresses, URLs, and domains recovered from unallocated space are IOC "
        "candidates for CTI enrichment. Carved file fragments may reconstruct deleted "
        "executables or documents. Credit card and social security number hits trigger "
        "PII breach notification obligations."
    )
    doc.add_paragraph()
    doc.add_page_break()

    # ── Part C — Findings ──────────────────────────────────────────────────────
    _heading("Part C — Findings", 1)
    doc.add_page_break()

    # C.1 Management summary
    _heading("C.1  Management summary", 2)
    _note("Audience: CISO, Legal, Internal Audit — no technical identifiers.")
    _para(
        f"Storage forensic analysis was conducted on the disk image of {hostname}. "
        f"The analysis identified {deleted} deleted file entries, "
        f"{len(evtx_l)} Windows Event Log file(s), and {len(pref_l)} Prefetch "
        "execution artifact(s). "
        "The filesystem timeline has been reconstructed and is available for "
        "cross-reference with network and memory forensics findings."
    )
    doc.add_paragraph()

    # C.2 Cross-module intelligence
    if fan_summary or fame_summary or opencti_findings:
        _heading("C.2  Cross-module intelligence", 2)
        _note("Claude: enhance and elaborate when necessary.")
        if fan_summary:
            _heading("C.2.1  Network forensics (FAN)", 3)
            _para(fan_summary.strip())
        if fame_summary:
            _heading("C.2.2  Memory forensics (FAME)", 3)
            _para(fame_summary.strip())
        if opencti_findings:
            _heading("C.2.3  OpenCTI threat intelligence", 3)
            _para(opencti_findings.strip())
        doc.add_paragraph()

    # C.3 IOCs
    _heading("C.3  Indicators of compromise", 2)
    _note("All IOC values defanged. Claude: enhance and elaborate when necessary.")
    iocs = _extract_iocs(data)
    if iocs:
        tbl = doc.add_table(rows=len(iocs) + 1, cols=4)
        tbl.style = "Table Grid"
        for i, h in enumerate(["Type", "Value", "Severity", "Context"]):
            c = tbl.rows[0].cells[i]
            c.text = h
            if c.paragraphs[0].runs:
                c.paragraphs[0].runs[0].font.bold = True
                c.paragraphs[0].runs[0].font.name = "Arial"
        for i, ioc in enumerate(iocs):
            for j, val in enumerate([ioc["type"], ioc["value"], ioc["severity"], ioc["context"]]):
                c = tbl.rows[i + 1].cells[j]
                c.text = val
                for run in c.paragraphs[0].runs:
                    run.font.name = "Arial"
    else:
        _para("No malicious indicators of compromise identified from storage analysis.")
    doc.add_paragraph()

    # C.4 Recommendations
    _heading("C.4  Recommendations", 2)
    _note("Claude: enhance and elaborate when necessary.")
    for i, rec in enumerate(_build_recommendations(data), 1):
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec)
        p = doc.add_paragraph(style="List Number")
        run = p.add_run(rec_clean)
        run.font.name = "Arial"
    doc.add_page_break()

    # ── Appendix A — 4-column with CET timestamps + SHA-256 ──────────────────
    _heading("Appendix A — Analysis source files", 1)
    _note("SHA-256 hashes computed at report generation time.")

    artifact_files = [
        (analysis_dir_p / "ewfinfo.txt",       "E01 image metadata (ewfinfo)"),
        (analysis_dir_p / "ewfverify.txt",      "E01 hash verification (ewfverify)"),
        (analysis_dir_p / "mmls.txt",           "Partition table (mmls)"),
        (analysis_dir_p / "fsstat.txt",         "Filesystem metadata (fsstat)"),
        (analysis_dir_p / "fls_output.txt",     "Full file listing incl. deleted (fls)"),
        (analysis_dir_p / "ils_output.txt",     "Inode listing (ils)"),
        (analysis_dir_p / "ils_orphan.txt",     "Orphan inode listing (ils -O)"),
        (analysis_dir_p / "bodyfile.txt",       "MAC time bodyfile (fls -m)"),
        (exports_dir_p  / "fs_timeline.csv",    "Filesystem timeline (mactime)"),
        (exports_dir_p  / "mft" / "$MFT",       "Master File Table"),
        (exports_dir_p  / "mft" / "$J",         "USN Change Journal"),
    ]

    tbl = doc.add_table(rows=len(artifact_files) + 1, cols=4)
    tbl.style = "Table Grid"
    for i, h in enumerate(["Filename", "Description", "Generated (CET)", "SHA-256 (first 32)"]):
        c = tbl.rows[0].cells[i]
        c.text = h
        if c.paragraphs[0].runs:
            c.paragraphs[0].runs[0].font.bold = True
            c.paragraphs[0].runs[0].font.name = "Arial"
    for i, (fp, desc) in enumerate(artifact_files):
        mtime, sha256 = _compute_file_metadata(fp)
        vals = [fp.name, desc, mtime, sha256[:32] if sha256 != "N/A" else "N/A"]
        for j, val in enumerate(vals):
            c = tbl.rows[i + 1].cells[j]
            c.text = val
            for run in c.paragraphs[0].runs:
                run.font.name = "Arial"

    _remove_blank_paragraphs(doc)
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
    md_only: bool = False,
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
    if not md_only:
        try:
            sys.path.insert(0, str(PROJECT_ROOT / "lib"))
            from md_to_pdf import convert as md2pdf
            pdf_path = output_dir / f"{stem}_fast_report.pdf"
            md2pdf(md_path, pdf_path)
            print(f"[fast] PDF saved: {pdf_path}")
        except Exception as exc:
            print(f"[fast] WARNING: PDF generation failed: {exc}")

    # PPTX
    pptx_path: Path | None = None
    if not md_only:
        pptx_path = output_dir / f"{stem}_fast_presentation.pptx"
        _build_pptx(
            data, case_id, hostname, disk_image or str(analysis_dir),
            generated_utc, pptx_path, opencti_findings, fan_summary, fame_summary,
        )

    # DOCX
    docx_path: Path | None = None
    if not md_only:
        docx_path = output_dir / f"{stem}_fast_report.docx"
        _build_docx(
            data, case_id, hostname, disk_image or str(analysis_dir),
            generated_utc, docx_path, opencti_findings, fan_summary, fame_summary,
        )

    return {
        "md":   md_path,
        "pdf":  pdf_path,
        "pptx": pptx_path if (pptx_path and pptx_path.exists()) else None,
        "docx": docx_path if (docx_path and docx_path.exists()) else None,
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
    p.add_argument("--md-only",      action="store_true", help="Generate Markdown only — skip PDF, PPTX, DOCX")
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
        md_only      = args.md_only,
    )
    print("[fast] Report suite complete:")
    for fmt, p in paths.items():
        if p:
            print(f"  {fmt.upper():4s}  {p}")
