#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
evidence_server.py — Read-only MCP server for the evidence vault.

Exposes PCAP evidence files to Claude without any write capability.
All paths are validated to remain within EVIDENCE_ROOT.

Runs on ubuntudesktop as sansforensics. The server file lives alongside
the evidence at /home/sansforensics/evidence/evidence_server.py.
The local copy at mcp/evidence_server.py is the canonical source — it is
deployed automatically via SCP whenever it is edited.

MCP Protocol: JSON-RPC 2.0 over stdio (MCP v2024-11-05)

Registration (.claude/settings.json):
  "evidence": {
    "command": "ssh",
    "args": [
      "sansforensics@ubuntudesktop",
      "EVIDENCE_ROOT=/home/sansforensics/evidence python3 /home/sansforensics/evidence/evidence_server.py"
    ]
  }
"""
from __future__ import annotations

import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

EVIDENCE_ROOT = Path(os.environ.get("EVIDENCE_ROOT", "~/evidence")).expanduser()
PCAP_SUFFIXES = {".pcap", ".pcapng", ".cap", ".pcap.gz", ".pcapng.gz"}
PROCESSED_MARKER = ".fna_processed"

SERVER_INFO = {"name": "evidence", "version": "1.0.0"}

TOOLS = [
    {
        "name": "evidence_list_directory",
        "description": (
            "List files and directories inside the evidence vault. "
            "Path is relative to the evidence root (~/evidence). "
            "Use '.' or '' for the root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path inside evidence root (e.g. '' or 'subdir')",
                }
            },
            "required": [],
        },
    },
    {
        "name": "evidence_read_file",
        "description": (
            "Read a file from the evidence vault. Text files are returned as UTF-8 strings. "
            "Binary files (PCAPs, images) are returned as base64. "
            "Path is relative to the evidence root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path to the file inside evidence root",
                },
                "max_bytes": {
                    "type": "integer",
                    "description": "Maximum bytes to read (default: 65536 for binary, 1MB for text)",
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "evidence_get_file_info",
        "description": "Get metadata (size, timestamps, type) for a file or directory in the evidence vault.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Relative path inside evidence root",
                }
            },
            "required": ["path"],
        },
    },
    {
        "name": "evidence_find_pcaps",
        "description": (
            "Find PCAP/PCAPNG/CAP files in the evidence vault. "
            "Returns each file's path, size, and whether it has been processed "
            "by the Forensics Network Analyser (presence of .fna_processed marker)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "unprocessed_only": {
                    "type": "boolean",
                    "description": "If true, only return files not yet processed by the analyser",
                }
            },
            "required": [],
        },
    },
]


# ── Path safety ────────────────────────────────────────────────────────────────

def _safe_path(rel: str) -> Path:
    """Resolve *rel* inside EVIDENCE_ROOT. Raises if it escapes the root."""
    root = EVIDENCE_ROOT.resolve()
    resolved = (root / (rel or "")).resolve()
    # Use path-relative containment, not str.startswith: a string prefix match
    # would accept a sibling like ``<root>_exfil`` that escapes the root.
    if resolved != root and not resolved.is_relative_to(root):
        raise ValueError(f"Path outside evidence root: {rel!r}")
    return resolved


# ── Tool handlers ──────────────────────────────────────────────────────────────

def _list_directory(args: dict) -> str:
    target = _safe_path(args.get("path", ""))
    if not target.exists():
        raise FileNotFoundError(f"Not found: {target}")
    entries = []
    for p in sorted(target.iterdir()):
        stat = p.stat()
        entries.append({
            "name":     p.name,
            "type":     "directory" if p.is_dir() else "file",
            "size":     stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    return json.dumps(entries, indent=2)


def _read_file(args: dict) -> str:
    target = _safe_path(args["path"])
    if not target.is_file():
        raise FileNotFoundError(f"Not a file: {target}")

    suffix = target.suffix.lower()
    is_binary = suffix in PCAP_SUFFIXES or suffix in {".bin", ".dat", ".img", ".gz"}
    max_bytes = int(args.get("max_bytes", 65536 if is_binary else 1_048_576))
    raw = target.read_bytes()[:max_bytes]

    if is_binary:
        return json.dumps({
            "path":     str(target.relative_to(EVIDENCE_ROOT)),
            "size":     target.stat().st_size,
            "encoding": "base64",
            "truncated": len(raw) < target.stat().st_size,
            "data":     base64.b64encode(raw).decode(),
        })
    else:
        text = raw.decode("utf-8", errors="replace")
        return json.dumps({
            "path":     str(target.relative_to(EVIDENCE_ROOT)),
            "size":     target.stat().st_size,
            "encoding": "utf-8",
            "truncated": len(raw) < target.stat().st_size,
            "data":     text,
        })


def _get_file_info(args: dict) -> str:
    target = _safe_path(args["path"])
    if not target.exists():
        raise FileNotFoundError(f"Not found: {target}")
    stat = target.stat()
    return json.dumps({
        "path":     str(target.relative_to(EVIDENCE_ROOT)),
        "type":     "directory" if target.is_dir() else "file",
        "size":     stat.st_size,
        "created":  datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        "is_pcap":  target.suffix.lower() in PCAP_SUFFIXES,
    })


def _find_pcaps(args: dict) -> str:
    unprocessed_only = bool(args.get("unprocessed_only", False))
    results = []
    for p in sorted(EVIDENCE_ROOT.rglob("*")):
        if not p.is_file():
            continue
        if p.suffix.lower() not in PCAP_SUFFIXES:
            continue
        processed = (p.parent / (p.name + PROCESSED_MARKER)).exists()
        if unprocessed_only and processed:
            continue
        stat = p.stat()
        results.append({
            "path":      str(p.relative_to(EVIDENCE_ROOT)),
            "name":      p.name,
            "size":      stat.st_size,
            "modified":  datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
            "processed": processed,
        })
    return json.dumps(results, indent=2)


_HANDLERS = {
    "evidence_list_directory": _list_directory,
    "evidence_read_file":      _read_file,
    "evidence_get_file_info":  _get_file_info,
    "evidence_find_pcaps":     _find_pcaps,
}


# ── MCP dispatch ───────────────────────────────────────────────────────────────

def _respond(req_id, result=None, error=None):
    if error:
        msg = {"jsonrpc": "2.0", "id": req_id, "error": error}
    else:
        msg = {"jsonrpc": "2.0", "id": req_id, "result": result}
    sys.stdout.write(json.dumps(msg) + "\n")
    sys.stdout.flush()


def _handle(req: dict):
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params", {})

    if method == "initialize":
        _respond(req_id, {
            "protocolVersion": "2024-11-05",
            "serverInfo": SERVER_INFO,
            "capabilities": {"tools": {}},
        })
        return

    if method == "tools/list":
        _respond(req_id, {"tools": TOOLS})
        return

    if method == "tools/call":
        name = params.get("name", "")
        args = params.get("arguments", {})
        handler = _HANDLERS.get(name)
        if not handler:
            _respond(req_id, error={"code": -32601, "message": f"Unknown tool: {name}"})
            return
        try:
            text = handler(args)
            _respond(req_id, {"content": [{"type": "text", "text": text}]})
        except (FileNotFoundError, ValueError) as exc:
            _respond(req_id, error={"code": -32602, "message": str(exc)})
        except Exception as exc:
            _respond(req_id, error={"code": -32603, "message": f"Internal error: {exc}"})
        return

    if req_id is None:
        return  # notification — ignore
    _respond(req_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
    EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError:
            continue
        _handle(req)


if __name__ == "__main__":
    main()
