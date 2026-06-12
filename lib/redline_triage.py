#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
redline_triage.py — lightweight triage for Mandiant Redline ".mans" collections.

A ".mans" file is a SQLite 3 database produced by Mandiant Redline. Its schema
varies by collector version, so this module does not assume a fixed table set:
it lists every table in the database, then dumps the contents of any table
whose name matches a known Redline audit category (processes, network
connections/ports, persistence/autoruns, services, tasks, drivers) as a
Markdown table.

This is intentionally a triage-level summary — table dumps, not a full
Volatility-equivalent analysis — so a ".mans" file is no longer silently
skipped by scripts/batch_agentic.sh and an analyst gets a starting point.

Output:
  reports/<case_id>/FAME/<hostname>/<case_id>_redline_triage.md

CLI usage:
  python3 lib/redline_triage.py --input /path/to/collection.mans \
      --case-id CASE-2026-001 --hostname HOST01
"""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402
from case_manager import validate_case_id  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = PROJECT_ROOT / "reports"

# Substrings matched (case-insensitively) against Redline table names to
# decide which tables are worth dumping in the triage report.
_INTERESTING_KEYWORDS = (
    "process",
    "port",
    "connection",
    "service",
    "persist",
    "autorun",
    "task",
    "driver",
    "startup",
)

_MAX_ROWS_PER_TABLE = 50


def _list_tables(conn: sqlite3.Connection) -> list[tuple[str, int]]:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
    )
    tables = []
    for (name,) in cur.fetchall():
        try:
            count = conn.execute(f'SELECT COUNT(*) FROM "{name}"').fetchone()[0]
        except sqlite3.DatabaseError:
            count = -1
        tables.append((name, count))
    return tables


def _dump_table_markdown(conn: sqlite3.Connection, table: str) -> str:
    cur = conn.execute(f'SELECT * FROM "{table}" LIMIT {_MAX_ROWS_PER_TABLE}')
    cols = [d[0] for d in cur.description]
    rows = cur.fetchall()
    if not rows:
        return "_(table is empty)_\n"

    lines = [
        "| " + " | ".join(cols) + " |",
        "| " + " | ".join(["---"] * len(cols)) + " |",
    ]
    for row in rows:
        cells = [str(v).replace("|", "\\|").replace("\n", " ") if v is not None else "" for v in row]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines) + "\n"


def run_triage(input_path: str, case_id: str, hostname: str) -> Path:
    case_id = validate_case_id(case_id)

    src = Path(input_path)
    conn = sqlite3.connect(f"file:{src}?mode=ro", uri=True)
    try:
        tables = _list_tables(conn)

        sections = []
        interesting = [
            (name, count)
            for name, count in tables
            if any(k in name.lower() for k in _INTERESTING_KEYWORDS)
        ]

        for name, count in interesting:
            if count <= 0:
                continue
            sections.append(f"## {name} ({count} row(s), showing up to {_MAX_ROWS_PER_TABLE})\n")
            sections.append(_dump_table_markdown(conn, name))

        all_tables_md = "\n".join(
            f"- `{name}` — {count if count >= 0 else 'unreadable'} row(s)"
            for name, count in tables
        )

        lines = [
            f"# Redline Collection Triage — {hostname}",
            "",
            f"**Case ID:** {case_id}  ",
            f"**Source file:** `{src.name}`  ",
            f"**Format:** Mandiant Redline collection (SQLite 3 database)",
            "",
            "This is a best-effort triage summary, not a full Volatility-equivalent "
            "analysis. It lists every table found in the collection and dumps the "
            "contents of tables matching known Redline audit categories "
            "(processes, network ports/connections, services, persistence/autoruns, "
            "scheduled tasks, drivers).",
            "",
            "## All tables in collection",
            "",
            all_tables_md,
            "",
        ]

        if sections:
            lines.append("## Audit category dumps")
            lines.append("")
            lines.extend(sections)
        else:
            lines.append("## Audit category dumps")
            lines.append("")
            lines.append("_No tables matched known Redline audit categories — "
                          "see the full table list above for manual review._")
            lines.append("")
    finally:
        conn.close()

    out_dir = REPORTS_DIR / case_id / "FAME" / hostname
    path_guard.safe_mkdir(out_dir)
    out_path = out_dir / f"{case_id}_redline_triage.md"
    path_guard.safe_write_text(out_path, "\n".join(lines), encoding="utf-8")

    print(f"[redline-triage] Wrote {out_path}")
    return out_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="Path to the .mans collection file")
    parser.add_argument("--case-id", required=True, help="Case ID")
    parser.add_argument("--hostname", required=True, help="Hostname for this evidence")
    args = parser.parse_args()

    run_triage(args.input, args.case_id, args.hostname)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
