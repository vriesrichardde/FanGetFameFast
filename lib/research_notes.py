#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
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
Companion:   ./reports/<case_id>_raw_output.md  (full command output, keyed by RN-NNN)
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

def _notes_path(case_id: str, output_dir: str | None) -> Path:
    d = Path(output_dir) if output_dir else REPORTS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{case_id}_research_notes.md"


def _raw_output_path(case_id: str, output_dir: str | None) -> Path:
    d = Path(output_dir) if output_dir else REPORTS_DIR
    d.mkdir(parents=True, exist_ok=True)
    return d / f"{case_id}_raw_output.md"


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _step_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.startswith("### ["))


# ---------------------------------------------------------------------------
# Public API — importable by report generators
# ---------------------------------------------------------------------------

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
                "id":        f"RN-{int(id_match.group(1)):03d}" if id_match else None,
                "step_num":  step_num,
                "timestamp": ts_match.group(1) if ts_match else "",
                "title":     title_match.group(1).strip() if title_match else line,
                "action":    "",
                "why":       "",
                "outcome":   "",
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

    if current is not None:
        steps.append(current)

    return steps


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir)
    raw_path = _raw_output_path(args.case_id, args.output_dir)
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

    raw_content = (
        f"# Raw Command Output — {args.case_id}\n\n"
        f"Companion file to `{args.case_id}_research_notes.md`.  \n"
        "Each section is keyed by step ID (`RN-NNN`) for cross-reference with the research notes and final report.\n\n"
        "---\n\n"
    )
    raw_path.write_text(raw_content, encoding="utf-8")
    print(f"[research_notes] Raw output file initialized: {raw_path}")


def cmd_step(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir)
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

    # Build inline details block for research notes (key excerpt + reference to companion file)
    raw_block = ""
    if raw_text:
        raw_output_filename = f"{args.case_id}_raw_output.md"
        anchor = step_id.lower().replace("-", "")  # e.g. rn001
        raw_block = (
            f"\n<details><summary>Key excerpt (full output → "
            f"[{raw_output_filename}#{anchor}]({raw_output_filename}#{anchor}))</summary>\n\n"
            "```text\n"
            f"{raw_text}\n"
            "```\n\n"
            "</details>\n"
        )

    outcome = f"[ASSUMPTION] {args.outcome}" if getattr(args, "assumption", False) else args.outcome

    entry = (
        f"### [{_now_utc()}] — Step {step_num} [{step_id}]: {args.title}\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Action** | {args.action} |\n"
        f"| **Why** | {args.why} |\n"
        f"| **Outcome** | {outcome} |"
        f"{raw_block}\n\n"
        "---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)

    # Always append to companion raw output file
    raw_path = _raw_output_path(args.case_id, args.output_dir)
    anchor_heading = f"[{step_id}]"
    if raw_path.exists():
        with raw_path.open("a", encoding="utf-8") as fh:
            fh.write(f"## {anchor_heading} — {args.title}\n\n")
            fh.write(f"**Action:** {args.action}  \n")
            fh.write(f"**Timestamp:** {_now_utc()}\n\n")
            if raw_text:
                fh.write("```text\n")
                fh.write(raw_text)
                if not raw_text.endswith("\n"):
                    fh.write("\n")
                fh.write("```\n\n")
            else:
                fh.write("*(No raw output captured for this step.)*\n\n")
            fh.write("---\n\n")

    print(f"[research_notes] Step {step_num} [{step_id}] appended: {args.title}")


def cmd_assumption(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir)
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


def cmd_finalize(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir)
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
    pi.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

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
    ps.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

    # assumption
    pa = sub.add_parser("assumption", help="Record a standalone analytical assumption")
    pa.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pa.add_argument("--text",       required=True, metavar="TEXT", help="The assumption statement")
    pa.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

    # finalize
    pf = sub.add_parser("finalize", help="Insert investigation summary and mark complete")
    pf.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pf.add_argument("--summary",    required=True, metavar="TEXT", help="Closing summary paragraph")
    pf.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    {"init": cmd_init, "step": cmd_step, "assumption": cmd_assumption, "finalize": cmd_finalize}[args.command](args)
