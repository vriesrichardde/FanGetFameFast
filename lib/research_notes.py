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
The reports/ directory is in .gitignore — notes are never committed to the repo.
"""
from __future__ import annotations

import argparse
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


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _step_count(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(encoding="utf-8").splitlines()
               if ln.startswith("### ["))


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> None:
    path = _notes_path(args.case_id, args.output_dir)
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
    path = _notes_path(args.case_id, args.output_dir)
    if not path.exists():
        print(
            f"[research_notes] ERROR: notes file not found for {args.case_id} — run 'init' first",
            file=sys.stderr,
        )
        sys.exit(1)

    step_num = _step_count(path) + 1

    raw_block = ""
    if args.raw:
        raw_block = (
            "\n<details><summary>Significant raw output</summary>\n\n"
            "```text\n"
            f"{args.raw}\n"
            "```\n\n"
            "</details>\n"
        )

    entry = (
        f"### [{_now_utc()}] — Step {step_num}: {args.title}\n\n"
        "| | |\n"
        "|---|---|\n"
        f"| **Action** | {args.action} |\n"
        f"| **Why** | {args.why} |\n"
        f"| **Outcome** | {args.outcome} |"
        f"{raw_block}\n\n"
        "---\n\n"
    )

    with path.open("a", encoding="utf-8") as fh:
        fh.write(entry)
    print(f"[research_notes] Step {step_num} appended: {args.title}")


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
    ps.add_argument("--raw",        metavar="TEXT", help="Significant raw output to include (optional)")
    ps.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

    # finalize
    pf = sub.add_parser("finalize", help="Insert investigation summary and mark complete")
    pf.add_argument("--case-id",    required=True, metavar="ID",   help="Case ID")
    pf.add_argument("--summary",    required=True, metavar="TEXT", help="Closing summary paragraph")
    pf.add_argument("--output-dir", metavar="DIR",  help="Output directory (default: ./reports/)")

    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    {"init": cmd_init, "step": cmd_step, "finalize": cmd_finalize}[args.command](args)
