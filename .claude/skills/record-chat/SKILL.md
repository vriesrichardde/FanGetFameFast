# Skill: record-chat — Session Transcript (Chain of Evidence)

## Overview

Captures the current Claude Code coordination session — every question the
analyst asked, every pivot Claude took, every tool invoked, and every tool
output — and saves it as a chain-of-evidence document set:

| Output | Path | Purpose |
|--------|------|---------|
| Markdown | `./reports/<case_id>_chat_transcript.md` | Human-readable rendering |
| PDF | `./reports/<case_id>_chat_transcript.pdf` | Styled DFIR document (cover page, pagination, CONFIDENTIAL banner) |
| Raw JSONL | `./reports/<case_id>_chat_transcript.jsonl` | **Authoritative verbatim record** (SHA-256 printed in the MD/PDF) |

**Why two registers of value:**

1. **Chain of evidence** — an auditable account of the analytical reasoning
   behind every finding, suitable for Legal / Law Enforcement / Internal Audit
   review alongside the incident report. The PDF records the SHA-256 of the raw
   `.jsonl` so the rendering can always be tied back to the original bytes.
2. **Solution optimisation** — captured sessions show where the workflow
   stalled, which prompts worked, and what can be automated next.

The rendering is **complete and verbatim** — tool outputs are reproduced in
full, however long, and nothing is truncated. The raw `.jsonl` is preserved
alongside as the SHA-256-fingerprinted authoritative record.

## When this runs automatically

This is wired into the end of every investigation pipeline — it runs on its own
after the report upload, before final cleanup:

- `scripts/fame_analyze.sh` (FAME)
- `scripts/fast_analyze.sh` (FAST)
- `scripts/analyze_pcap.sh` (FAN)

In all three, the transcript is uploaded to the investigations vault with the
rest of the artefacts (skipped when `--no-upload` is set for FAME/FAST).

Use this skill to **manually re-record** a session — for example when the
session continued after the analysis script finished, or to capture an
in-session investigation that did not run through a shell script.

## Invocation

```bash
# Auto-detect the active session, write MD + PDF + JSONL to ./reports
python3 lib/chat_recorder.py --case-id FAME-2026-001

# Also upload the transcript to the investigations vault
python3 lib/chat_recorder.py --case-id FAME-2026-001 --upload

# Record a specific transcript file (e.g. an older session)
python3 lib/chat_recorder.py --case-id FAN-2025-001 \
    --transcript ~/.claude/projects/<encoded-dir>/<session-uuid>.jsonl

# Markdown only (skip PDF)
python3 lib/chat_recorder.py --case-id X --md-only
```

Python API:

```python
from lib.chat_recorder import record_chat

paths = record_chat(case_id="FAME-2026-001", upload=False)
# paths: {"md": Path, "pdf": Path, "jsonl": Path}
```

## How the active session is located

Resolution order:

1. `--transcript <file>` if given,
2. `CLAUDE_TRANSCRIPT_PATH` env var (set when invoked from a hook),
3. `<transcript_dir>/<CLAUDE_SESSION_ID>.jsonl`,
4. the most recently modified `*.jsonl` in the project transcript folder
   (`~/.claude/projects/<encoded-project-dir>/`) — correct because recording
   runs mid-session, so the active session's transcript is the freshest file.

The project directory is encoded the way Claude Code names its transcript
folder: every non-alphanumeric character becomes a hyphen.

## Constraints

- All writes go to `./reports/` (or `--output-dir`) and are enforced by
  `lib/path_guard.py` — the recorder cannot write to evidence, `/mnt`, or
  `/media`.
- Recording **never fails the investigation**: the analyze scripts treat a
  recording or upload error as a warning and continue.
- The document is classified **CONFIDENTIAL — DFIR INTERNAL USE ONLY** and may
  contain internal identifiers; handle it as evidence, not for external sharing.
