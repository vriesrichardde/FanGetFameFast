# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
Core read/write interface for the Obsidian vault.
All vault I/O goes through this module so path and frontmatter handling is consistent.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement

VAULT_ROOT = Path(__file__).parent.parent / "vault"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _note_path(folder: str, title: str) -> Path:
    safe = re.sub(r'[\\/:*?"<>|]', "_", title)
    return VAULT_ROOT / folder / f"{safe}.md"


def _parse_note(text: str) -> tuple[dict[str, Any], str]:
    """Split a note into (frontmatter_dict, body_markdown)."""
    if not text.startswith("---"):
        return {}, text
    end = text.find("\n---", 3)
    if end == -1:
        return {}, text
    fm_text = text[3:end].strip()
    body = text[end + 4:].lstrip("\n")
    try:
        fm = yaml.safe_load(fm_text) or {}
    except yaml.YAMLError:
        fm = {}
    return fm, body


def _render_note(fm: dict[str, Any], body: str) -> str:
    fm_text = yaml.dump(fm, default_flow_style=False, allow_unicode=True).rstrip()
    return f"---\n{fm_text}\n---\n\n{body}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def link(title: str) -> str:
    """Return an Obsidian wikilink string."""
    return f"[[{title}]]"


def tag(name: str) -> str:
    return f"#{name}"


def write_note(folder: str, title: str, frontmatter: dict[str, Any], body: str) -> Path:
    """
    Create or fully replace a note.
    If the note already exists, date_created is preserved.
    Returns the path written.
    """
    path = _note_path(folder, title)
    now = _now_utc()

    path_guard.guard_output_dir(path.parent)

    if path.exists():
        existing_fm, _ = _parse_note(path.read_text(encoding="utf-8"))
        frontmatter.setdefault("date_created", existing_fm.get("date_created", now))
    else:
        frontmatter.setdefault("date_created", now)

    frontmatter["date_updated"] = now
    path_guard.safe_write_text(path, _render_note(frontmatter, body), encoding="utf-8")
    return path


def append_to_note(folder: str, title: str, md_content: str) -> Path:
    """
    Append markdown content to an existing note's body.
    Creates the note with an empty frontmatter block if it doesn't exist yet.
    """
    path = _note_path(folder, title)
    now = _now_utc()

    path_guard.guard_output_dir(path.parent)

    if path.exists():
        text = path.read_text(encoding="utf-8")
        fm, body = _parse_note(text)
        fm["date_updated"] = now
        new_body = body.rstrip("\n") + "\n\n" + md_content.strip()
        path_guard.safe_write_text(path, _render_note(fm, new_body), encoding="utf-8")
    else:
        fm = {"date_created": now, "date_updated": now, "tags": []}
        path_guard.safe_write_text(path, _render_note(fm, md_content.strip()), encoding="utf-8")

    return path


def read_note(folder: str, title: str) -> tuple[dict[str, Any], str] | None:
    """Return (frontmatter, body) or None if the note does not exist."""
    path = _note_path(folder, title)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    return _parse_note(text)


def note_exists(folder: str, title: str) -> bool:
    return _note_path(folder, title).exists()


def list_notes(folder: str) -> list[str]:
    """Return note titles (without .md) for every note in a folder."""
    d = VAULT_ROOT / folder
    if not d.is_dir():
        return []
    return [p.stem for p in sorted(d.glob("*.md"))]


def search_vault(query: str, case_insensitive: bool = True) -> list[dict[str, str]]:
    """
    Grep the entire vault for query.
    Returns a list of {path, line_number, snippet} dicts.
    """
    flags = ["-r", "-n", "--include=*.md"]
    if case_insensitive:
        flags.append("-i")
    try:
        result = subprocess.run(
            ["grep"] + flags + [query, str(VAULT_ROOT)],
            capture_output=True, text=True
        )
        hits = []
        for line in result.stdout.splitlines():
            parts = line.split(":", 2)
            if len(parts) == 3:
                hits.append({
                    "path": parts[0].replace(str(VAULT_ROOT) + "/", ""),
                    "line_number": parts[1],
                    "snippet": parts[2].strip(),
                })
        return hits
    except FileNotFoundError:
        return []


def patch_section(folder: str, title: str, marker: str, new_content: str) -> None:
    """
    Replace the content between <!-- AUTO:MARKER --> and <!-- /AUTO:MARKER --> in a note.
    Used to update Dashboard sections without touching the rest of the file.
    """
    path = _note_path(folder, title)
    if not path.exists():
        return
    text = path.read_text(encoding="utf-8")
    open_tag = f"<!-- AUTO:{marker} -->"
    close_tag = f"<!-- /AUTO:{marker} -->"
    pattern = re.compile(
        re.escape(open_tag) + r".*?" + re.escape(close_tag),
        re.DOTALL
    )
    replacement = f"{open_tag}\n{new_content.strip()}\n{close_tag}"
    updated = pattern.sub(replacement, text)
    # Update date_updated in frontmatter
    fm, body = _parse_note(updated)
    fm["date_updated"] = _now_utc()
    path_guard.safe_write_text(path, _render_note(fm, body), encoding="utf-8")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    test_folder = "Concepts"
    test_title = "_selftest_DELETE_ME"
    path = _note_path(test_folder, test_title)

    print("write_note ... ", end="")
    write_note(test_folder, test_title,
               {"tags": ["concept"], "related_ttps": []},
               "## Definition\nSelf-test concept.")
    assert path.exists(), "Note not created"
    print("OK")

    print("read_note  ... ", end="")
    result = read_note(test_folder, test_title)
    assert result is not None
    fm, body = result
    assert "concept" in fm.get("tags", [])
    assert "Self-test" in body
    print("OK")

    print("append_to_note ... ", end="")
    append_to_note(test_folder, test_title, "## Examples Observed\n- test entry")
    _, body2 = read_note(test_folder, test_title)
    assert "test entry" in body2
    print("OK")

    print("search_vault ... ", end="")
    hits = search_vault("Self-test concept")
    assert any(test_title in h["path"] for h in hits), f"Search miss: {hits}"
    print("OK")

    print("cleanup    ... ", end="")
    path.unlink()
    assert not path.exists()
    print("OK")

    print("\nAll self-tests passed.")


if __name__ == "__main__":
    _self_test()
