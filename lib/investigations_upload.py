#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
investigations_upload.py — Upload incident reports to the investigations vault.

Connects to ubuntudesktop as sansforensics via SSH/SCP and writes the report
files to INVESTIGATIONS_ROOT/<case_id>/reports/, mirroring the path structure
used by investigations_server.py.

SSH host / root are read from environment variables (set in ~/.soc_env):
  INVESTIGATIONS_SSH_HOST  — default: sansforensics@ubuntudesktop
  INVESTIGATIONS_ROOT      — default: /home/sansforensics/cases
  INVESTIGATIONS_SSH_KEY   — default: ~/.ssh/id_ed25519

Pass --no-upload to skip the upload entirely (reports stay in ./reports/).
Pass --interactive to be prompted for each setting with the default pre-filled.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


SSH_HOST    = os.environ.get("INVESTIGATIONS_SSH_HOST", "sansforensics@ubuntudesktop")
REMOTE_ROOT = os.environ.get("INVESTIGATIONS_ROOT",     "/home/sansforensics/cases")
SSH_KEY     = os.environ.get("INVESTIGATIONS_SSH_KEY",  str(Path.home() / ".ssh" / "id_ed25519"))


def _ssh_opts(key: str) -> list[str]:
    opts = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"]
    if Path(key).exists():
        opts += ["-i", key]
    return opts


def _ssh_mkdir(host: str, key: str, remote_dir: str) -> None:
    subprocess.run(
        ["ssh", *_ssh_opts(key), host, f"mkdir -p {remote_dir}"],
        check=True,
        capture_output=True,
    )


def _scp_upload(host: str, key: str, local_path: Path, remote_path: str) -> None:
    subprocess.run(
        ["scp", *_ssh_opts(key), str(local_path), f"{host}:{remote_path}"],
        check=True,
        capture_output=True,
    )


def _prompt(label: str, default: str) -> str:
    """Prompt with a default value; pressing Enter accepts the default."""
    try:
        answer = input(f"  {label} [{default}]: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return answer if answer else default


def _confirm_upload(host: str, key: str, remote_root: str) -> tuple[bool, str, str, str]:
    """
    Ask the analyst whether to proceed with upload and let them adjust
    host / key / remote root. Returns (proceed, host, key, remote_root).
    """
    print()
    print("[upload] ── Upload to investigations vault ─────────────────────────")
    print("[upload] Configure the SSH connection or press Enter to accept defaults.")
    host       = _prompt("SSH target (user@host)", host)
    key        = _prompt("SSH identity file    ", key)
    remote_root = _prompt("Remote root path     ", remote_root)
    print("[upload] ────────────────────────────────────────────────────────────")
    print(f"[upload] Target : {host}:{remote_root}/<case_id>/reports/")
    print(f"[upload] Key    : {key} {'(found)' if Path(key).exists() else '(NOT FOUND — will try agent)'}")
    print()
    try:
        answer = input("[upload] Proceed with upload? [Y/n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        answer = "n"
    if answer in ("", "y", "yes"):
        return True, host, key, remote_root
    print("[upload] Upload skipped — reports saved locally in ./reports/")
    return False, host, key, remote_root


def upload(
    case_id: str,
    md_path: Path,
    pdf_path: Path | None = None,
    pptx_path: Path | None = None,
    docx_path: Path | None = None,
    zip_paths: list[Path] | None = None,
    notes_path: Path | None = None,
    host: str = SSH_HOST,
    key: str = SSH_KEY,
    remote_root: str = REMOTE_ROOT,
) -> None:
    remote_dir = f"{remote_root}/{case_id}/reports"
    _ssh_mkdir(host, key, remote_dir)

    def _up(p: Path, label: str) -> None:
        print(f"[upload] {p.name} → {host}:{remote_dir}/")
        _scp_upload(host, key, p, f"{remote_dir}/{p.name}")
        print(f"[upload] {label} uploaded.")

    _up(md_path, "Markdown")

    if pdf_path and pdf_path.exists():
        _up(pdf_path, "PDF")

    if pptx_path and pptx_path.exists():
        _up(pptx_path, "PowerPoint")

    if docx_path and docx_path.exists():
        _up(docx_path, "Word document")

    for zp in (zip_paths or []):
        if zp.exists():
            _up(zp, "Artefact ZIP")

    if notes_path and notes_path.exists():
        _up(notes_path, "Research notes")

    print(f"[upload] Done — {host}:{remote_dir}/")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Upload incident report to investigations vault via SSH")
    p.add_argument("--case-id",     required=True,  metavar="ID",   help="Case ID (remote subdirectory)")
    p.add_argument("--md",          required=True,  metavar="FILE",  help="Local Markdown report path")
    p.add_argument("--pdf",                         metavar="FILE",  help="Local PDF report path (optional)")
    p.add_argument("--pptx",                        metavar="FILE",  help="Local PowerPoint path (optional)")
    p.add_argument("--docx",                        metavar="FILE",  help="Local Word document path (optional)")
    p.add_argument("--zip",  action="append",        metavar="FILE",  help="Local artefact ZIP path (may be repeated)")
    p.add_argument("--notes",                       metavar="FILE",  help="Local research notes Markdown path (optional)")
    p.add_argument("--host",        default=SSH_HOST,                help=f"SSH target user@host (default: {SSH_HOST}; env: INVESTIGATIONS_SSH_HOST)")
    p.add_argument("--key",         default=SSH_KEY,                 help=f"SSH identity file (default: {SSH_KEY}; env: INVESTIGATIONS_SSH_KEY)")
    p.add_argument("--remote-root", default=REMOTE_ROOT,             help=f"Remote root path (default: {REMOTE_ROOT}; env: INVESTIGATIONS_ROOT)")
    p.add_argument("--interactive", action="store_true",             help="Prompt for SSH settings and upload confirmation before proceeding")
    p.add_argument("--no-upload",   action="store_true",             help="Skip upload entirely; reports stay in ./reports/")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    md = Path(args.md)
    if not md.exists():
        print(f"[upload] ERROR: Markdown file not found: {md}", file=sys.stderr)
        sys.exit(1)

    if args.no_upload:
        print("[upload] --no-upload specified — skipping. Reports are in ./reports/")
        sys.exit(0)

    host        = args.host
    key         = args.key
    remote_root = args.remote_root

    if args.interactive:
        proceed, host, key, remote_root = _confirm_upload(host, key, remote_root)
        if not proceed:
            sys.exit(0)

    try:
        upload(
            args.case_id,
            md,
            pdf_path    = Path(args.pdf)   if args.pdf   else None,
            pptx_path   = Path(args.pptx)  if args.pptx  else None,
            docx_path   = Path(args.docx)  if args.docx  else None,
            zip_paths   = [Path(z) for z in args.zip] if args.zip else None,
            notes_path  = Path(args.notes) if args.notes else None,
            host        = host,
            key         = key,
            remote_root = remote_root,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[upload] ERROR: SSH/SCP failed: {exc.stderr.decode(errors='replace')}", file=sys.stderr)
        print("[upload] Tip: set INVESTIGATIONS_SSH_HOST / INVESTIGATIONS_SSH_KEY in ~/.soc_env,")
        print("[upload]      or re-run with --no-upload to skip.")
        sys.exit(1)
