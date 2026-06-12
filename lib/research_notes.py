#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
research_notes.py — Timestamped investigative log for FanGetFameFast analyses.

Claude calls this tool via Bash at three points during every FAME / FAST / FAN
investigation:

  init      Create the notes file with a case header and placeholder sections.
  step      Append one timestamped entry (action / why / outcome) after Claude
            reads and interprets each tool output.
  finalize  Replace the summary placeholder with a closing paragraph before
            the file is uploaded to the investigations vault.

Output path: ./reports/<case_id>_research_notes.md
Raw artifacts: preserved individually in ./reports/<case_id>_evidence/ (with SHA-256).
The reports/ directory is in .gitignore — notes are never committed to the repo.
"""
from __future__ import annotations

import argparse
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

REPORTS_DIR = Path(__file__).parent.parent / "reports"
_PLACEHOLDER = "<!-- summary-placeholder -->"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _notes_path(case_id: str, output_dir: str | None, case_dir: str | None = None) -> Path:
    """Resolve the research-notes file path.

    - If *case_dir* is provided, it is treated as the directory that will contain
      `<case_id>_research_notes.md` (often a module directory like `.../FAME/<host>/`).
    - Else if *output_dir* is provided, it is treated as that containing directory.
    - Else defaults to `./reports/<case_id>/`.
    """
    if case_dir:
        d = Path(case_dir)
    elif output_dir:
        d = Path(output_dir)
    else:
        d = REPORTS_DIR / case_id  # default: per-case subdirectory
    return d / f"{case_id}_research_notes.md"



def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _step_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.startswith("### [") and "— Step" in ln)


def _event_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.startswith("### [") and "— Event EVT-" in ln)


def _reflect_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.startswith("### [") and "— Reflect RF-" in ln)


# ---------------------------------------------------------------------------
# Public API — importable by report generators
# ---------------------------------------------------------------------------

def get_findings_with_confidence(case_id: str, output_dir: str | None = None) -> list[dict]:
    """Return steps enriched with machine-readable confidence fields.

    Each dict contains all parse_steps() fields plus:
      confidence  — "direct" | "inferred" | "assumed"
      source_tool — tool name recorded with --source-tool, or ""
    """
    steps = parse_steps(case_id, output_dir)
    for s in steps:
        outcome = s.get("outcome", "")
        if s.get("confidence") in ("direct", "inferred", "assumed"):
            pass  # already set by the new parser
        elif "[ASSUMPTION]" in outcome:
            s["confidence"] = "assumed"
        else:
            s["confidence"] = "direct"
        s.setdefault("source_tool", "")
    return steps


def parse_steps(case_id: str, output_dir: str | None = None) -> list[dict]:
    """Return one dict per recorded step: {id, step_num, timestamp, title, action, why, outcome}.

    Parses the research notes Markdown.  Steps without the [RN-NNN] badge
    (written by older versions) are included with id=None.
    """
    path = _notes_path(case_id, output_dir)
    if not path.exists():
        return []

    steps: list[dict] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    current: dict | None = None

    for line in lines:
        # Detect step header: ### [YYYY-MM-DD HH:MM:SS UTC] — Step N [RN-NNN]: Title
        if line.startswith("### [") and "— Step" in line:
            if current is not None:
                steps.append(current)

            ts_match = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)\]", line)
            id_match  = re.search(r"\[RN-(\d{3})\]", line)
            num_match = re.search(r"— Step (\d+)", line)
            title_match = re.search(r"\[RN-\d{3}\]: (.+)$", line)
            if title_match is None:
                # Older format without RN badge: "— Step N: Title"
                title_match = re.search(r"— Step \d+: (.+)$", line)

            step_num = int(num_match.group(1)) if num_match else len(steps) + 1
            current = {
                "id":          f"RN-{int(id_match.group(1)):03d}" if id_match else None,
                "step_num":    step_num,
                "timestamp":   ts_match.group(1) if ts_match else "",
                "title":       title_match.group(1).strip() if title_match else line,
                "action":      "",
                "why":         "",
                "outcome":     "",
                "dismissed":   "",
                "confidence":  "direct",
                "source_tool": "",
            }
            continue

        if current is None:
            continue

        if "| **Action**" in line:
            current["action"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Why**" in line:
            current["why"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Outcome**" in line:
            current["outcome"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
            if "[ASSUMPTION]" in current["outcome"]:
                current["confidence"] = "assumed"
        elif "| **Dismissed**" in line:
            current["dismissed"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Confidence**" in line:
            current["confidence"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Source tool**" in line:
            current["source_tool"] = line.split("|", 2)[-1].strip().rstrip("|").strip()

    if current is not None:
        steps.append(current)

    return steps


def parse_events(case_id: str, output_dir: str | None = None) -> list[dict]:
    """Return one dict per logged attacker event:
    {id, event_num, timestamp, severity, module, description, source_detail}.

    Events written with --no-timestamp have timestamp='' and are excluded from
    visual timelines but still returned here for the untimed-findings section.
    """
    path = _notes_path(case_id, output_dir)
    if not path.exists():
        return []

    events: list[dict] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    current: dict | None = None

    for line in lines:
        # Header: ### [YYYY-MM-DD HH:MM:SS UTC] — Event EVT-NNN [severity] [module]: Description
        if line.startswith("### [") and "— Event EVT-" in line:
            if current is not None:
                events.append(current)

            ts_match  = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)\]", line)
            id_match  = re.search(r"EVT-(\d+)", line)
            sev_match = re.search(r"\[(critical|high|medium|low|info)\]", line)
            mod_match = re.search(r"\[(FAN|FAME|FAST)\]", line)
            desc_match = re.search(r"\]: (.+)$", line)

            event_num = int(id_match.group(1)) if id_match else len(events) + 1
            current = {
                "id":           f"EVT-{event_num:03d}" if id_match else None,
                "event_num":    event_num,
                "timestamp":    ts_match.group(1) if ts_match else "",
                "severity":     sev_match.group(1) if sev_match else "info",
                "module":       mod_match.group(1) if mod_match else "",
                "description":  desc_match.group(1).strip() if desc_match else line,
                "source_detail": "",
            }
            continue

        if current is None:
            continue

        if "| **Source**" in line:
            current["source_detail"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Detail**" in line:
            detail = line.split("|", 2)[-1].strip().rstrip("|").strip()
            if current["source_detail"]:
                current["source_detail"] += " — " + detail
            else:
                current["source_detail"] = detail

    if current is not None:
        events.append(current)

    return events


def parse_reflections(case_id: str, output_dir: str | None = None) -> list[dict]:
    """Return one dict per reflect entry: {id, reflect_num, timestamp, trigger, reinterpret, open_leads}."""
    path = _notes_path(case_id, output_dir)
    if not path.exists():
        return []

    reflections: list[dict] = []
    lines = path.read_text(encoding="utf-8").splitlines()
    current: dict | None = None

    for line in lines:
        # Header: ### [timestamp] — Reflect RF-NNN: trigger
        if line.startswith("### [") and "— Reflect RF-" in line:
            if current is not None:
                reflections.append(current)

            ts_match   = re.search(r"\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC)\]", line)
            id_match   = re.search(r"RF-(\d+)", line)
            trig_match = re.search(r"RF-\d+: (.+)$", line)

            reflect_num = int(id_match.group(1)) if id_match else len(reflections) + 1
            current = {
                "id":           f"RF-{reflect_num:03d}" if id_match else None,
                "reflect_num":  reflect_num,
                "timestamp":    ts_match.group(1) if ts_match else "",
                "trigger":      trig_match.group(1).strip() if trig_match else line,
                "reinterpret":  "",
                "open_leads":   "",
            }
            continue

        if current is None:
            continue

        if "| **Re-interpretations**" in line:
            current["reinterpret"] = line.split("|", 2)[-1].strip().rstrip("|").strip()
        elif "| **Open leads**" in line:
            current["open_leads"] = line.split("|", 2)[-1].strip().rstrip("|").strip()

    if current is not None:
        reflections.append(current)

    return reflections


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    module_label = args.module.upper()
    hostname = args.hostname or "—"
    evidence = args.evidence or "—"

    content = (
        f"# Research Notes — {args.case_id}\n\n"
        f"**Case ID:** {args.case_id} | **Module:** {module_label}"
        f" | **Started:** {_now_utc()}  \n"
        f"**Evidence:** `{evidence}` | **Hostname:** {hostname}\n\n"
        "---\n\n"
        f"{_PLACEHOLDER}\n\n"
        "---\n\n"
        "## Investigation Log\n\n"
    )
    path.write_text(content, encoding="utf-8")
    print(f"[research_notes] Initialized: {path}")


def cmd_step(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    step_num = _step_count(path) + 1
    step_id  = f"RN-{step_num:03d}"

    # Resolve raw output: --raw-file wins over --raw
    raw_text: str | None = None
    if getattr(args, "raw_file", None):
        raw_file = Path(args.raw_file)
        if raw_file.exists():
            raw_text = raw_file.read_text(encoding="utf-8", errors="replace")
            if getattr(args, "raw", None):
                print("[research_notes] WARNING: --raw-file takes precedence over --raw", file=sys.stderr)
        else:
            print(f"[research_notes] WARNING: --raw-file path not found: {raw_file}", file=sys.stderr)
            raw_text = getattr(args, "raw", None)
    else:
        raw_text = getattr(args, "raw", None)

    # Build inline details block for research notes (key excerpt)
    raw_block = ""
    if raw_text:
        raw_block = (
            "\n<details><summary>Key excerpt</summary>\n\n"
            "```text\n"
            f"{raw_text}\n"
            "```\n\n"
            "</details>\n"
        )

    is_assumption = getattr(args, "assumption", False)
    outcome = f"[ASSUMPTION] {args.outcome}" if is_assumption else args.outcome
    dismissed_row   = f"\n| **Dismissed** | {args.dismissed} |" if getattr(args, "dismissed", None) else ""
    source_tool_val = getattr(args, "source_tool", None) or ""
    # Resolve confidence: explicit flag wins; fall back to assumption detection
    explicit_conf   = getattr(args, "confidence", None)
    if explicit_conf:
        confidence_val = explicit_conf
    elif is_assumption:
        confidence_val = "assumed"
    else:
        confidence_val = "direct"
    confidence_row  = f"\n| **Confidence** | {confidence_val} |"
    source_tool_row = f"\n| **Source tool** | {source_tool_val} |" if source_tool_val else ""

    entry = (
        f"### [{_now_utc()}] — Step {step_num} [{step_id}]: {args.title}\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Action** | {args.action} |\n"
        f"| **Why** | {args.why} |\n"
        f"| **Outcome** | {outcome} |"
        f"{dismissed_row}"
        f"{confidence_row}"
        f"{source_tool_row}"
        f"{raw_block}\n\n"
        "---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    print(f"[research_notes] Step {step_num} [{step_id}] appended: {args.title}")


def cmd_assumption(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    entry = (
        f"### [{_now_utc()}] — Assumption: {args.text}\n\n"
        "---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)
    print(f"[research_notes] Assumption appended.")


def cmd_reflect(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    reflect_num = _reflect_count(path) + 1
    reflect_id  = f"RF-{reflect_num:03d}"

    reinterpret = getattr(args, "reinterpret", None) or "—"
    open_leads  = getattr(args, "open_leads",  None) or "—"

    entry = (
        f"### [{_now_utc()}] — Reflect {reflect_id}: {args.trigger}\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Trigger** | {args.trigger} |\n"
        f"| **Re-interpretations** | {reinterpret} |\n"
        f"| **Open leads** | {open_leads} |\n"
        "\n---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    print(f"[research_notes] Reflect {reflect_num} [{reflect_id}] appended: {args.trigger[:60]}")


def cmd_event(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    event_num = _event_count(path) + 1
    event_id  = f"EVT-{event_num:03d}"
    severity  = args.severity
    module    = args.module

    no_ts = getattr(args, "no_timestamp", False)
    ts    = "" if no_ts else (getattr(args, "timestamp", None) or _now_utc())

    header_ts = ts if ts else "NO-TIMESTAMP"
    note_flag = " [no-timestamp]" if no_ts else ""

    source_row = f"| **Source** | {args.source} |\n" if getattr(args, "source", None) else ""
    detail_row = f"| **Detail** | {args.detail} |\n" if getattr(args, "detail", None) else ""

    entry = (
        f"### [{header_ts}] — Event {event_id} [{severity}] [{module}]: {args.description}{note_flag}\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Timestamp** | {ts or '— (unconfirmed)'} |\n"
        f"{source_row}"
        f"{detail_row}"
        "\n---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    ts_label = ts if ts else "(no confirmed timestamp)"
    print(f"[research_notes] Event {event_num} [{event_id}] [{severity}] appended: {args.description[:60]} — {ts_label}")


def cmd_followup(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    text = path.read_text(encoding="utf-8")
    if "## Follow-up Questions" not in text:
        text += "\n## Follow-up Questions\n\n"
        path.write_text(text, encoding="utf-8")

    output_files = getattr(args, "output_file", None) or []
    outputs_block = ""
    if output_files:
        outputs_block = "\n| **Output file(s)** | " + ", ".join(f"`{f}`" for f in output_files) + " |"

    entry = (
        f"### [{_now_utc()}] — Follow-up\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Question** | {args.question} |\n"
        f"| **Answer / action** | {args.answer_summary} |"
        f"{outputs_block}\n\n"
        "---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    print(f"[research_notes] Follow-up appended: {args.question[:60]}")


def cmd_finalize(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir, case_dir=getattr(args, "case_dir", None))
    if not path.exists():
        print(f"[research_notes] ERROR: notes file not found for {args.case_id}", file=sys.stderr)
        sys.exit(1)

    text = path.read_text(encoding="utf-8")
    if _PLACEHOLDER not in text:
        print("[research_notes] WARNING: summary placeholder not found — summary not inserted", file=sys.stderr)
        return

    summary_block = f"## Investigation Summary\n\n> {args.summary}"
    path.write_text(text.replace(_PLACEHOLDER, summary_block), encoding="utf-8")
    print(f"[research_notes] Finalized: {path}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Research notes writer for FanGetFameFast investigations",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # init
    pi = sub.add_parser("init", help="Create research notes file with case header")
    pi.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pi.add_argument("--module",     required=True, choices=["fame", "fast", "fan"], help="Module name")
    pi.add_argument("--evidence",   metavar="PATH", help="Evidence file path shown in the header")
    pi.add_argument("--hostname",   metavar="NAME", help="Target hostname")
    pi.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    pi.add_argument("--case-dir",   metavar="DIR",  help="Per-case root directory (reports/<case_id>/); takes precedence over --output-dir")

    # step
    ps = sub.add_parser("step", help="Append a timestamped step entry")
    ps.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    ps.add_argument("--title",      required=True, metavar="TEXT", help="Short step title, e.g. 'Process List (windows.pslist)'")
    ps.add_argument("--action",     required=True, metavar="TEXT", help="What was run or checked")
    ps.add_argument("--why",        required=True, metavar="TEXT", help="Forensic rationale for this step")
    ps.add_argument("--outcome",    required=True, metavar="TEXT", help="Summary of findings")
    ps.add_argument("--raw",        metavar="TEXT", help="Raw output to include as inline excerpt and in companion file (optional)")
    ps.add_argument("--raw-file",   metavar="PATH", help="Path to file containing full raw output — wins over --raw (avoids shell arg size limits)")
    ps.add_argument("--assumption", action="store_true",           help="Mark this step's outcome as an assumption (prefixes [ASSUMPTION] for the report generator)")
    ps.add_argument("--dismissed",  metavar="TEXT", help="What was observed in this output but not flagged as significant, and why (optional)")
    ps.add_argument("--confidence", choices=["direct", "inferred", "assumed"],
                    help="Override confidence tier (default: auto-detected from --assumption flag)")
    ps.add_argument("--source-tool", metavar="TOOL",
                    help="Tool that produced this output, e.g. 'volatility3/psscan' or 'suricata' (optional)")
    ps.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    ps.add_argument("--case-dir",   metavar="DIR",  help="Per-case root directory; takes precedence over --output-dir")

    # assumption
    pa = sub.add_parser("assumption", help="Record a standalone analytical assumption")
    pa.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pa.add_argument("--text",       required=True, metavar="TEXT", help="The assumption statement")
    pa.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    pa.add_argument("--case-dir",   metavar="DIR",  help="Per-case root directory; takes precedence over --output-dir")

    # followup — post-report analyst question, logged for chain of custody
    pu = sub.add_parser("followup", help="Log a post-report follow-up question and its answer/output")
    pu.add_argument("--case-id",         required=True, metavar="ID",   help="Case ID")
    pu.add_argument("--question",        required=True, metavar="TEXT", help="The analyst's follow-up question")
    pu.add_argument("--answer-summary",  required=True, metavar="TEXT", help="Summary of the action taken / answer given")
    pu.add_argument("--output-file",     action="append", metavar="PATH",
                    help="Path to a new/changed output file produced for this question (repeatable)")
    pu.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    pu.add_argument("--case-dir",   metavar="DIR",  help="Per-case root directory; takes precedence over --output-dir")

    # finalize
    pf = sub.add_parser("finalize", help="Insert investigation summary and mark complete")
    pf.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pf.add_argument("--summary",    required=True, metavar="TEXT", help="Closing summary paragraph")
    pf.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    pf.add_argument("--case-dir",   metavar="DIR",  help="Per-case root directory; takes precedence over --output-dir")

    # reflect — mid-investigation or pre-finalize structured reflection
    pr = sub.add_parser("reflect", help="Log a structured reflection: re-interpretations and open leads")
    pr.add_argument("--case-id",      required=True, metavar="ID",   help="Case ID")
    pr.add_argument("--trigger",      required=True, metavar="TEXT", help="What prompted this reflection (e.g. 'post-netscan mid-investigation review')")
    pr.add_argument("--reinterpret",  metavar="TEXT", help="How current findings change interpretation of earlier steps (optional)")
    pr.add_argument("--open-leads",   metavar="TEXT", help="What needs follow-up that this investigation cannot resolve alone (optional)")
    pr.add_argument("--output-dir",   metavar="DIR",  help="Output directory (default: ./reports/<case_id>/)")
    pr.add_argument("--case-dir",     metavar="DIR",  help="Per-case root directory; takes precedence over --output-dir")

    # event — log a confirmed attacker action observed in the evidence
    pe = sub.add_parser("event", help="Log a timestamped attacker-observed event from the evidence")
    pe.add_argument("--case-id",      required=True, metavar="ID",   help="Case ID")
    pe.add_argument("--description",  required=True, metavar="TEXT", help="What the attacker did")
    pe.add_argument("--severity",     required=True, choices=["critical", "high", "medium", "low", "info"])
    pe.add_argument("--module",       required=True, choices=["FAN", "FAME", "FAST"],
                    help="Module that observed this event")
    pe.add_argument("--timestamp",    metavar="YYYY-MM-DD HH:MM:SS UTC",
                    help="Evidence timestamp (omit with --no-timestamp if unconfirmed)")
    pe.add_argument("--source",       metavar="TEXT", help="Specific artifact reference (IP, PID, file path)")
    pe.add_argument("--detail",       metavar="TEXT", help="Additional forensic context")
    pe.add_argument("--no-timestamp", action="store_true", dest="no_timestamp",
                    help="Mark as finding without a confirmed timestamp (excluded from visual timeline)")
    pe.add_argument("--output-dir",   metavar="DIR", help="Output directory (default: ./reports/<case_id>/)")
    pe.add_argument("--case-dir",     metavar="DIR", help="Per-case root directory; takes precedence over --output-dir")

    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    {
        "init":       cmd_init,
        "step":       cmd_step,
        "assumption": cmd_assumption,
        "reflect":    cmd_reflect,
        "finalize":   cmd_finalize,
        "event":      cmd_event,
        "followup":   cmd_followup,
    }[args.command](args)
