#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
chat_recorder.py — Capture the Claude Code session transcript as a
chain-of-evidence document (Markdown + PDF) when an investigation completes.

The analyst drives every investigation through Claude (the agentic
coordinator), so the full back-and-forth — the questions asked, the pivots
taken, the tools invoked, and their outputs — *is* the record of how a
conclusion was reached. Preserving it serves two purposes:

  1. Chain of evidence — an auditable account of the analytical reasoning
     behind every finding, suitable for Legal / Law Enforcement / Internal
     Audit review alongside the incident report.
  2. Solution optimisation — the captured sessions show where the workflow
     stalled, which prompts worked, and what can be automated next.

Source of truth: Claude Code stores each session as a JSON-Lines transcript
under ``~/.claude/projects/<encoded-project-dir>/<session-uuid>.jsonl``. This
module locates the active transcript, renders a human-readable Markdown view,
converts it to a styled PDF via :mod:`md_to_pdf`, and preserves the raw
``.jsonl`` verbatim (its SHA-256 is recorded in the document so the rendering
can always be tied back to the original bytes).

Usage (CLI):
    python3 lib/chat_recorder.py --case-id FAME-2026-001
    python3 lib/chat_recorder.py --case-id FAN-2025-001 --output-dir ./reports --upload
    python3 lib/chat_recorder.py --case-id X --transcript /path/to/session.jsonl --md-only

Python API:
    from lib.chat_recorder import record_chat
    paths = record_chat(case_id="FAME-2026-001", upload=False)
    # paths: {"md": Path, "pdf": Path, "jsonl": Path}
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement
import md_to_pdf  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "reports"

# Top-level transcript entry types that carry actual conversation content.
# Everything else (queue-operation, attachment, ai-title, last-prompt,
# file-history-snapshot, …) is harness bookkeeping and is skipped.
_MESSAGE_TYPES = {"user", "assistant"}

# Per-block truncation for the human-readable rendering only. The raw .jsonl
# is preserved verbatim and remains the authoritative, full-fidelity record.
_MAX_BLOCK_CHARS = 6000


# ── Transcript discovery ────────────────────────────────────────────────────
def encode_project_dir(project_dir: Path | str) -> str:
    """Encode a project path the way Claude Code names its transcript folder.

    Every non-alphanumeric character is replaced with a hyphen, e.g.
    ``/home/x/Fan Get Fame Fast`` → ``-home-x-Fan-Get-Fame-Fast``.
    """
    return re.sub(r"[^A-Za-z0-9]", "-", str(Path(project_dir).resolve()))


def transcript_dir_for(project_dir: Path | str | None = None) -> Path:
    """Return the ``~/.claude/projects/<encoded>`` directory for *project_dir*."""
    project_dir = project_dir or os.environ.get("CLAUDE_PROJECT_DIR") or PROJECT_ROOT
    return Path.home() / ".claude" / "projects" / encode_project_dir(project_dir)


def find_active_transcript(
    transcript: Path | str | None = None,
    project_dir: Path | str | None = None,
) -> Path:
    """Locate the session transcript JSONL to record.

    Resolution order:
      1. explicit *transcript* path,
      2. ``CLAUDE_TRANSCRIPT_PATH`` env var (set when invoked from a hook),
      3. ``<transcript_dir>/<CLAUDE_SESSION_ID>.jsonl``,
      4. the most recently modified ``*.jsonl`` in the project transcript dir
         (the active session, since recording runs mid-session).
    """
    if transcript:
        p = Path(transcript).expanduser()
        if not p.exists():
            raise FileNotFoundError(f"Transcript not found: {p}")
        return p

    env_path = os.environ.get("CLAUDE_TRANSCRIPT_PATH")
    if env_path and Path(env_path).expanduser().exists():
        return Path(env_path).expanduser()

    tdir = transcript_dir_for(project_dir)
    session_id = os.environ.get("CLAUDE_SESSION_ID")
    if session_id:
        cand = tdir / f"{session_id}.jsonl"
        if cand.exists():
            return cand

    if not tdir.is_dir():
        raise FileNotFoundError(
            f"No Claude Code transcript directory found at {tdir}. "
            "Run the investigation from within a Claude Code session, or pass "
            "--transcript explicitly."
        )
    jsonls = sorted(
        tdir.glob("*.jsonl"), key=lambda p: p.stat().st_mtime, reverse=True
    )
    if not jsonls:
        raise FileNotFoundError(f"No .jsonl transcripts in {tdir}.")
    return jsonls[0]


# ── Parsing ──────────────────────────────────────────────────────────────────
def parse_transcript(jsonl_path: Path) -> list[dict]:
    """Return the conversation entries (user/assistant) in chronological order.

    Malformed lines are skipped rather than aborting — a transcript may be
    written to concurrently while the active session is still running.
    """
    entries: list[dict] = []
    with open(jsonl_path, "r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") in _MESSAGE_TYPES and isinstance(
                obj.get("message"), dict
            ):
                entries.append(obj)
    return entries


def _truncate(text: str) -> str:
    if len(text) <= _MAX_BLOCK_CHARS:
        return text
    dropped = len(text) - _MAX_BLOCK_CHARS
    return (
        text[:_MAX_BLOCK_CHARS]
        + f"\n[… truncated {dropped:,} characters — see the raw .jsonl for the "
        "full record …]"
    )


def _result_to_text(content) -> str:
    """Flatten a tool_result ``content`` (str | list of blocks) to plain text."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text":
                    parts.append(str(block.get("text", "")))
                elif block.get("type") == "image":
                    parts.append("[image omitted]")
                else:
                    parts.append(str(block.get("text", block)))
            else:
                parts.append(str(block))
        return "\n".join(parts)
    return str(content)


def _fmt_ts(ts: str | None) -> str:
    if not ts:
        return "unknown time"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (ValueError, AttributeError):
        return str(ts)


# ── Rendering ────────────────────────────────────────────────────────────────
def _speaker(entry: dict) -> str:
    """Human label for a transcript entry."""
    role = entry.get("message", {}).get("role")
    if role == "assistant":
        return "🤖 Claude (coordinator)"
    content = entry.get("message", {}).get("content")
    # A user turn that is purely a tool_result is the harness handing tool
    # output back to Claude, not the analyst speaking.
    if isinstance(content, list) and content and all(
        isinstance(b, dict) and b.get("type") == "tool_result" for b in content
    ):
        return "⚙️ Tool output → Claude"
    return "👤 Analyst"


def _render_blocks(content) -> list[str]:
    """Render a message ``content`` (str | list of blocks) to Markdown lines."""
    out: list[str] = []
    if isinstance(content, str):
        if content.strip():
            out.append(_truncate(content.strip()))
        return out

    if not isinstance(content, list):
        return out

    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type")
        if btype == "text":
            text = str(block.get("text", "")).strip()
            if text:
                out.append(_truncate(text))
        elif btype == "thinking":
            thinking = str(block.get("thinking", "")).strip()
            if thinking:  # encrypted/redacted thinking is empty — skip silently
                out.append("> **Reasoning**\n>\n> " + _truncate(thinking).replace("\n", "\n> "))
        elif btype == "tool_use":
            name = block.get("name", "tool")
            try:
                pretty = json.dumps(block.get("input", {}), indent=2, ensure_ascii=False)
            except (TypeError, ValueError):
                pretty = str(block.get("input", ""))
            out.append(f"**🔧 Tool call → `{name}`**\n\n```json\n{_truncate(pretty)}\n```")
        elif btype == "tool_result":
            text = _result_to_text(block.get("content", "")).strip()
            err = " (error)" if block.get("is_error") else ""
            body = _truncate(text) if text else "(no output)"
            out.append(f"**↳ Result{err}:**\n\n```\n{body}\n```")
    return out


def render_markdown(
    entries: list[dict],
    case_id: str,
    source_path: Path,
    source_sha256: str,
    generated_utc: str,
) -> str:
    """Build the full chain-of-evidence Markdown document."""
    tool_calls = sum(
        1
        for e in entries
        for b in (e.get("message", {}).get("content") or [])
        if isinstance(b, dict) and b.get("type") == "tool_use"
    )
    first_ts = _fmt_ts(entries[0].get("timestamp")) if entries else "n/a"
    last_ts = _fmt_ts(entries[-1].get("timestamp")) if entries else "n/a"

    lines: list[str] = []
    lines.append("# Session Transcript — Chain of Evidence")
    lines.append("")
    lines.append(
        "> **CONFIDENTIAL — DFIR INTERNAL USE ONLY.** This document is the "
        "recorded Claude Code coordination session for the investigation named "
        "below. It is retained as part of the chain of evidence and to optimise "
        "the FanGetFameFast workflow."
    )
    lines.append("")
    lines.append("## Record integrity")
    lines.append("")
    lines.append("| Field | Value |")
    lines.append("|-------|-------|")
    lines.append(f"| Case ID | {case_id} |")
    lines.append(f"| Generated (UTC) | {generated_utc} |")
    lines.append(f"| Source transcript | `{source_path.name}` |")
    lines.append(f"| Session ID | `{source_path.stem}` |")
    lines.append(f"| SHA-256 (source `.jsonl`) | `{source_sha256}` |")
    lines.append(f"| Conversation entries | {len(entries)} |")
    lines.append(f"| Tool invocations | {tool_calls} |")
    lines.append(f"| First entry (UTC) | {first_ts} |")
    lines.append(f"| Last entry (UTC) | {last_ts} |")
    lines.append("")
    lines.append(
        "The authoritative raw record is the session transcript JSON-Lines file "
        f"(`{source_path.name}`, SHA-256 above), preserved verbatim alongside "
        "this document. This PDF is a human-readable rendering; long tool "
        "outputs are truncated here but retained in full in the `.jsonl`."
    )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Conversation")
    lines.append("")

    if not entries:
        lines.append("_No conversation entries were found in the transcript._")
        return "\n".join(lines) + "\n"

    for i, entry in enumerate(entries, start=1):
        ts = _fmt_ts(entry.get("timestamp"))
        speaker = _speaker(entry)
        lines.append(f"### Entry {i} · {speaker} · {ts}")
        lines.append("")
        rendered = _render_blocks(entry.get("message", {}).get("content"))
        if rendered:
            lines.append("\n\n".join(rendered))
        else:
            lines.append("_(no rendered content)_")
        lines.append("")
        lines.append("---")
        lines.append("")

    return "\n".join(lines) + "\n"


# ── Orchestration ────────────────────────────────────────────────────────────
def _case_stem(case_id: str) -> str:
    """Filesystem-safe stem mirroring the analyze scripts' STEM convention."""
    return re.sub(r"\s+", "_", case_id.strip())


def record_chat(
    case_id: str,
    transcript: Path | str | None = None,
    project_dir: Path | str | None = None,
    output_dir: Path | str = DEFAULT_REPORTS_DIR,
    md_only: bool = False,
    upload: bool = False,
) -> dict[str, Path]:
    """Record the active Claude Code session as a chain-of-evidence MD + PDF.

    Returns a dict with the produced paths (keys: ``md``, ``pdf``, ``jsonl``).
    Writes are policy-checked through :mod:`path_guard`.
    """
    src = find_active_transcript(transcript=transcript, project_dir=project_dir)
    raw = src.read_bytes()
    sha256 = hashlib.sha256(raw).hexdigest()
    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    entries = parse_transcript(src)
    md_text = render_markdown(entries, case_id, src, sha256, generated_utc)

    out_dir = path_guard.guard_output_dir(output_dir)
    stem = _case_stem(case_id)

    md_path = out_dir / f"{stem}_chat_transcript.md"
    jsonl_path = out_dir / f"{stem}_chat_transcript.jsonl"
    path_guard.safe_write_text(md_path, md_text, encoding="utf-8")
    # Preserve the raw transcript verbatim — the authoritative evidence record.
    path_guard.safe_write_bytes(jsonl_path, raw)

    paths: dict[str, Path] = {"md": md_path, "jsonl": jsonl_path}

    if not md_only:
        pdf_path = out_dir / f"{stem}_chat_transcript.pdf"
        md_to_pdf.convert(
            md_path,
            output_path=pdf_path,
            title="Session Transcript — Chain of Evidence",
            subtitle="Claude Code coordination session",
            case_id=case_id,
        )
        paths["pdf"] = pdf_path

    if upload:
        try:
            import investigations_upload

            investigations_upload.upload(
                case_id,
                md_path=md_path,
                pdf_path=paths.get("pdf"),
                zip_paths=[jsonl_path],
            )
        except Exception as exc:  # noqa: BLE001 — upload must never break analysis
            print(
                f"[chat-recorder] WARNING: transcript upload failed: {exc}",
                file=sys.stderr,
            )

    return paths


# ── CLI ────────────────────────────────────────────────────────────────────────
def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Record the Claude Code session transcript as a "
        "chain-of-evidence Markdown + PDF when an investigation completes."
    )
    p.add_argument("--case-id", required=True, metavar="ID", help="Case ID")
    p.add_argument(
        "--transcript",
        metavar="FILE",
        help="Explicit session .jsonl path (default: active session auto-detected)",
    )
    p.add_argument(
        "--project-dir",
        metavar="DIR",
        help="Project directory whose transcript folder to search "
        "(default: CLAUDE_PROJECT_DIR or the repo root)",
    )
    p.add_argument(
        "--output-dir",
        default=str(DEFAULT_REPORTS_DIR),
        metavar="DIR",
        help="Where to write the transcript artefacts (default: ./reports)",
    )
    p.add_argument(
        "--md-only", action="store_true", help="Skip PDF generation (Markdown only)"
    )
    p.add_argument(
        "--upload",
        action="store_true",
        help="Upload the transcript MD/PDF/JSONL to the investigations vault",
    )
    return p


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    try:
        paths = record_chat(
            case_id=args.case_id,
            transcript=args.transcript,
            project_dir=args.project_dir,
            output_dir=args.output_dir,
            md_only=args.md_only,
            upload=args.upload,
        )
    except FileNotFoundError as exc:
        print(f"[chat-recorder] {exc}", file=sys.stderr)
        return 1

    print("[chat-recorder] Session transcript recorded:")
    for key in ("md", "pdf", "jsonl"):
        if key in paths:
            print(f"[chat-recorder]   {key:5s} → {paths[key]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
