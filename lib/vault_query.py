# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
Read-path interface to the Obsidian vault.
Returns structured text blocks for direct use in Claude prompts or shell output.
Run standalone: python3 lib/vault_query.py --search <keyword>
                python3 lib/vault_query.py --ioc <value>
                python3 lib/vault_query.py --ttp <mitre_id>
                python3 lib/vault_query.py --cases
                python3 lib/vault_query.py --risks [n]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from obsidian_bridge import (
    list_notes,
    read_note,
    search_vault,
)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Query functions
# ---------------------------------------------------------------------------

def get_context_for_ioc(value: str) -> str:
    """
    Return vault notes relevant to an IOC value.
    Searches across IOCs, TTPs, and Cases.
    """
    hits = search_vault(value)
    if not hits:
        return f"[vault] No prior knowledge for IOC: {value}"

    sections: list[str] = [f"[vault] IOC context for '{value}':"]
    seen: set[str] = set()
    for h in hits:
        note_path = h["path"]
        if note_path in seen:
            continue
        seen.add(note_path)
        parts = note_path.split("/", 1)
        if len(parts) == 2:
            folder, filename = parts
            title = filename.removesuffix(".md")
            result = read_note(folder, title)
            if result:
                fm, _ = result
                sev = fm.get("severity", "?")
                tags = " ".join(f"#{t}" for t in fm.get("tags", []))
                sections.append(f"  - [{folder}/{title}] severity={sev} {tags}")
                if fm.get("related_ttps"):
                    sections.append(f"    related_ttps: {fm['related_ttps']}")
                if fm.get("disposition"):
                    sections.append(f"    disposition: {fm['disposition']}")
    return "\n".join(sections)


def get_context_for_ttp(mitre_id: str) -> str:
    """
    Return all vault knowledge for a MITRE ATT&CK technique ID.
    """
    hits = search_vault(mitre_id)
    notes = [n for n in list_notes("TTPs") if mitre_id.upper() in n.upper()]
    if not hits and not notes:
        return f"[vault] No prior knowledge for TTP: {mitre_id}"

    sections: list[str] = [f"[vault] TTP context for '{mitre_id}':"]
    for title in notes:
        result = read_note("TTPs", title)
        if result:
            fm, body = result
            sections.append(f"\n  TTP: {title}")
            sections.append(f"  tactic: {fm.get('tactic', '?')} | severity: {fm.get('severity', '?')}")
            sections.append(f"  observed in cases: {fm.get('case_refs', [])}")
            sections.append(f"  related actors: {fm.get('related_actors', [])}")
            sections.append(f"  related malware: {fm.get('related_malware', [])}")

    other_paths = {h["path"] for h in hits if "TTPs/" not in h["path"]}
    if other_paths:
        sections.append(f"\n  Also referenced in: {sorted(other_paths)}")
    return "\n".join(sections)


def get_active_cases() -> str:
    """Return a summary of all open cases."""
    titles = list_notes("Cases")
    if not titles:
        return "[vault] No cases recorded."

    lines: list[str] = ["[vault] Active cases:"]
    for title in titles:
        result = read_note("Cases", title)
        if result:
            fm, _ = result
            if fm.get("status") == "open":
                lines.append(
                    f"  - {title} | severity={fm.get('severity', '?')} "
                    f"| ttps={fm.get('ttps_observed', [])} "
                    f"| actors={fm.get('actors_suspected', [])}"
                )
    if len(lines) == 1:
        lines.append("  (none open)")
    return "\n".join(lines)


def get_top_risks(n: int = 10) -> str:
    """Return the top-n open risks sorted by severity."""
    titles = list_notes("Risks")
    risks: list[tuple[int, str, dict]] = []
    for title in titles:
        result = read_note("Risks", title)
        if result:
            fm, _ = result
            if fm.get("status", "open") == "open":
                rank = SEVERITY_ORDER.get(fm.get("severity", "info"), 4)
                risks.append((rank, title, fm))

    risks.sort(key=lambda x: x[0])
    if not risks:
        return "[vault] No open risks recorded."

    lines = [f"[vault] Top {n} open risks:"]
    for rank, title, fm in risks[:n]:
        lines.append(
            f"  - [{fm.get('severity', '?').upper()}] {title} "
            f"| asset={fm.get('asset', '?')} | case={fm.get('case_ref', '?')}"
        )
    return "\n".join(lines)


def get_related_notes(title: str) -> str:
    """
    Return all notes that wikilink back to [[title]].
    Simulates Obsidian backlinks via grep.
    """
    hits = search_vault(f"[[{title}]]")
    if not hits:
        return f"[vault] No backlinks found for '[[{title}]]'."
    paths = sorted({h["path"] for h in hits})
    lines = [f"[vault] Notes linking to [[{title}]]:"]
    for p in paths:
        lines.append(f"  - {p}")
    return "\n".join(lines)


def search_context(query: str) -> str:
    """
    Full-vault keyword search; returns a formatted summary of matching notes.
    """
    hits = search_vault(query)
    if not hits:
        return f"[vault] No results for '{query}'."

    seen: dict[str, list[str]] = {}
    for h in hits:
        seen.setdefault(h["path"], []).append(h["snippet"])

    lines = [f"[vault] Search results for '{query}' ({len(seen)} notes):"]
    for path, snippets in list(seen.items())[:20]:
        lines.append(f"\n  {path}:")
        for s in snippets[:3]:
            lines.append(f"    | {s[:120]}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Query the Obsidian SOC vault",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("--search", metavar="QUERY", help="Full-vault keyword search")
    p.add_argument("--ioc", metavar="VALUE", help="IOC context lookup")
    p.add_argument("--ttp", metavar="MITRE_ID", help="TTP context lookup (e.g. T1071)")
    p.add_argument("--cases", action="store_true", help="List open cases")
    p.add_argument("--risks", metavar="N", nargs="?", const=10, type=int, help="Top N open risks")
    p.add_argument("--backlinks", metavar="TITLE", help="Notes that link to [[TITLE]]")
    return p


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()

    if not any(vars(args).values()):
        parser.print_help()
        sys.exit(0)

    if args.search:
        print(search_context(args.search))
    if args.ioc:
        print(get_context_for_ioc(args.ioc))
    if args.ttp:
        print(get_context_for_ttp(args.ttp))
    if args.cases:
        print(get_active_cases())
    if args.risks is not None:
        print(get_top_risks(args.risks))
    if args.backlinks:
        print(get_related_notes(args.backlinks))
