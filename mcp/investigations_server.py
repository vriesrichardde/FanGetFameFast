#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
investigations_server.py — Read-write MCP server for the investigations vault.

Exposes the investigations workspace to Claude with full CRUD capability.
All paths are validated to remain within INVESTIGATIONS_ROOT.

Runs on ubuntudesktop as sansforensics. The server file lives alongside
the cases at /home/sansforensics/cases/investigations_server.py.
The local copy at mcp/investigations_server.py is the canonical source — it is
deployed automatically via SCP whenever it is edited.

MCP Protocol: JSON-RPC 2.0 over stdio (MCP v2024-11-05)

Registration (.claude/settings.json):
  "investigations": {
    "command": "ssh",
    "args": [
      "sansforensics@ubuntudesktop",
      "INVESTIGATIONS_ROOT=/home/sansforensics/cases python3 /home/sansforensics/cases/investigations_server.py"
    ]
  }
"""
from __future__ import annotations

import base64
import json
import os
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path

INVESTIGATIONS_ROOT = Path(os.environ.get("INVESTIGATIONS_ROOT", "~/cases")).expanduser()

SERVER_INFO = {"name": "investigations", "version": "1.0.0"}

TOOLS = [
    {
        "name": "investigations_list_directory",
        "description": (
            "List files and directories inside the investigations workspace. "
            "Path is relative to ~/cases. Use '' or '.' for root."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path (default: root)"},
                "recursive": {"type": "boolean", "description": "Recurse into subdirectories"},
            },
            "required": [],
        },
    },
    {
        "name": "investigations_read_file",
        "description": "Read a file from the investigations workspace. Returns UTF-8 text or base64 for binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path to file"},
                "max_bytes": {"type": "integer", "description": "Maximum bytes (default 2MB for text)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "investigations_write_file",
        "description": (
            "Write or create a file in the investigations workspace. "
            "Parent directories are created automatically. "
            "Content is a UTF-8 string (use base64_content for binary)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":           {"type": "string", "description": "Relative path to file"},
                "content":        {"type": "string", "description": "UTF-8 text content"},
                "base64_content": {"type": "string", "description": "Base64-encoded binary content (alternative to content)"},
                "append":         {"type": "boolean", "description": "Append instead of overwrite (default false)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "investigations_create_directory",
        "description": "Create a directory (and parents) in the investigations workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative directory path to create"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "investigations_delete",
        "description": (
            "Delete a file or directory in the investigations workspace. "
            "Directories are deleted recursively when recursive=true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path":      {"type": "string",  "description": "Relative path to delete"},
                "recursive": {"type": "boolean", "description": "Delete directory recursively (default false)"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "investigations_get_file_info",
        "description": "Get metadata (size, timestamps, type) for a path in the investigations workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Relative path"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "investigations_list_cases",
        "description": (
            "List all investigation cases with their metadata (case ID, status, "
            "description, creation date, PCAPsanalysed, report count, archive ZIPs)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "status_filter": {
                    "type": "string",
                    "description": "Filter by status: 'open', 'closed', or '' for all",
                },
            },
            "required": [],
        },
    },
]


# ── Path safety ────────────────────────────────────────────────────────────────

def _safe_path(rel: str) -> Path:
    resolved = (INVESTIGATIONS_ROOT / (rel or "")).resolve()
    if not str(resolved).startswith(str(INVESTIGATIONS_ROOT.resolve())):
        raise ValueError(f"Path outside investigations root: {rel!r}")
    return resolved


# Read-only roots that must never receive a write, even if they somehow fall
# within INVESTIGATIONS_ROOT. Mirrors lib/path_guard.py; kept self-contained so
# this server has no project-library dependency when deployed standalone.
_READONLY_ROOTS = tuple(
    Path(p).expanduser().resolve()
    for p in (
        "/mnt",
        "/media",
        os.environ.get("EVIDENCE_ROOT", "") or "/home/sansforensics/evidence",
    )
    if p
)


def _assert_writable(target: Path) -> Path:
    """Reject writes that resolve under a read-only root (evidence, /mnt, /media)."""
    resolved = target.resolve()
    for ro in _READONLY_ROOTS:
        if resolved == ro or resolved.is_relative_to(ro):
            raise ValueError(
                f"Refusing to write to read-only location: {resolved} "
                f"(under protected root {ro})"
            )
    return target


# ── Tool handlers ──────────────────────────────────────────────────────────────

def _list_directory(args: dict) -> str:
    target = _safe_path(args.get("path", ""))
    recursive = bool(args.get("recursive", False))
    if not target.exists():
        raise FileNotFoundError(f"Not found: {target}")
    it = target.rglob("*") if recursive else target.iterdir()
    entries = []
    for p in sorted(it):
        stat = p.stat()
        entries.append({
            "name":     p.name,
            "path":     str(p.relative_to(INVESTIGATIONS_ROOT)),
            "type":     "directory" if p.is_dir() else "file",
            "size":     stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
        })
    return json.dumps(entries, indent=2)


def _read_file(args: dict) -> str:
    target = _safe_path(args["path"])
    if not target.is_file():
        raise FileNotFoundError(f"Not a file: {target}")
    binary_suffixes = {".zip", ".pcap", ".pcapng", ".cap", ".bin", ".dat", ".pdf", ".gz", ".img"}
    is_binary = target.suffix.lower() in binary_suffixes
    max_bytes = int(args.get("max_bytes", 65536 if is_binary else 2_097_152))
    raw = target.read_bytes()[:max_bytes]
    if is_binary:
        return json.dumps({
            "path": str(target.relative_to(INVESTIGATIONS_ROOT)),
            "size": target.stat().st_size,
            "encoding": "base64",
            "truncated": len(raw) < target.stat().st_size,
            "data": base64.b64encode(raw).decode(),
        })
    text = raw.decode("utf-8", errors="replace")
    return json.dumps({
        "path": str(target.relative_to(INVESTIGATIONS_ROOT)),
        "size": target.stat().st_size,
        "encoding": "utf-8",
        "truncated": len(raw) < target.stat().st_size,
        "data": text,
    })


def _write_file(args: dict) -> str:
    target = _assert_writable(_safe_path(args["path"]))
    target.parent.mkdir(parents=True, exist_ok=True)
    append = bool(args.get("append", False))
    mode = "ab" if append else "wb"

    if "base64_content" in args:
        data = base64.b64decode(args["base64_content"])
    elif "content" in args:
        data = args["content"].encode("utf-8")
    else:
        data = b""

    with target.open(mode) as fh:
        fh.write(data)

    return json.dumps({
        "path":    str(target.relative_to(INVESTIGATIONS_ROOT)),
        "size":    target.stat().st_size,
        "written": len(data),
        "mode":    "append" if append else "overwrite",
    })


def _create_directory(args: dict) -> str:
    target = _assert_writable(_safe_path(args["path"]))
    target.mkdir(parents=True, exist_ok=True)
    return json.dumps({"path": str(target.relative_to(INVESTIGATIONS_ROOT)), "created": True})


def _delete(args: dict) -> str:
    target = _assert_writable(_safe_path(args["path"]))
    if not target.exists():
        raise FileNotFoundError(f"Not found: {target}")
    recursive = bool(args.get("recursive", False))
    if target.is_dir():
        if not recursive:
            raise ValueError(f"Use recursive=true to delete directory: {target}")
        shutil.rmtree(target)
    else:
        target.unlink()
    return json.dumps({"path": str(args["path"]), "deleted": True})


def _get_file_info(args: dict) -> str:
    target = _safe_path(args["path"])
    if not target.exists():
        raise FileNotFoundError(f"Not found: {target}")
    stat = target.stat()
    return json.dumps({
        "path":     str(target.relative_to(INVESTIGATIONS_ROOT)),
        "type":     "directory" if target.is_dir() else "file",
        "size":     stat.st_size,
        "created":  datetime.fromtimestamp(stat.st_ctime, timezone.utc).isoformat(),
        "modified": datetime.fromtimestamp(stat.st_mtime, timezone.utc).isoformat(),
    })


def _list_cases(args: dict) -> str:
    status_filter = args.get("status_filter", "").strip().lower()
    cases = []
    for d in sorted(INVESTIGATIONS_ROOT.iterdir()):
        if not d.is_dir():
            continue
        meta_file = d / "case.json"
        meta: dict = {}
        if meta_file.exists():
            try:
                meta = json.loads(meta_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        status = meta.get("status", "unknown")
        if status_filter and status != status_filter:
            continue
        # Count reports and archives
        reports = list((d / "reports").glob("*.md")) if (d / "reports").exists() else []
        archives = list(d.glob("*.zip"))
        cases.append({
            "case_id":     d.name,
            "status":      status,
            "description": meta.get("description", ""),
            "created_utc": meta.get("created_utc", ""),
            "pcaps":       meta.get("pcaps", []),
            "reports":     len(reports),
            "archives":    len(archives),
        })
    return json.dumps(cases, indent=2)


_HANDLERS = {
    "investigations_list_directory": _list_directory,
    "investigations_read_file":      _read_file,
    "investigations_write_file":     _write_file,
    "investigations_create_directory": _create_directory,
    "investigations_delete":         _delete,
    "investigations_get_file_info":  _get_file_info,
    "investigations_list_cases":     _list_cases,
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
        return
    _respond(req_id, error={"code": -32601, "message": f"Method not found: {method}"})


def main():
    INVESTIGATIONS_ROOT.mkdir(parents=True, exist_ok=True)
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
