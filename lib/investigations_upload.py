#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
investigations_upload.py — Upload incident reports to the investigations vault.

Connects to ubuntudesktop as sansforensics via SSH/SCP and writes the report
files to INVESTIGATIONS_ROOT/<case_id>/reports/, mirroring the path structure
used by investigations_server.py.

SSH host / root are read from environment variables (set in ~/.soc_env):
  INVESTIGATIONS_SSH_HOST  — default: sansforensics@ubuntudesktop
  INVESTIGATIONS_ROOT      — default: /home/sansforensics/cases
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path


SSH_HOST       = os.environ.get("INVESTIGATIONS_SSH_HOST", "sansforensics@ubuntudesktop")
REMOTE_ROOT    = os.environ.get("INVESTIGATIONS_ROOT",     "/home/sansforensics/cases")


def _ssh_mkdir(remote_dir: str) -> None:
    subprocess.run(
        ["ssh", SSH_HOST, f"mkdir -p {remote_dir}"],
        check=True,
        capture_output=True,
    )


def _scp_upload(local_path: Path, remote_path: str) -> None:
    subprocess.run(
        ["scp", str(local_path), f"{SSH_HOST}:{remote_path}"],
        check=True,
        capture_output=True,
    )


def upload(
    case_id: str,
    md_path: Path,
    pdf_path: Path | None = None,
    pptx_path: Path | None = None,
    docx_path: Path | None = None,
    zip_path: Path | None = None,
) -> None:
    remote_dir = f"{REMOTE_ROOT}/{case_id}/reports"
    _ssh_mkdir(remote_dir)

    def _up(p: Path, label: str) -> None:
        print(f"[upload] {p.name} → {SSH_HOST}:{remote_dir}/")
        _scp_upload(p, f"{remote_dir}/{p.name}")
        print(f"[upload] {label} uploaded.")

    _up(md_path, "Markdown")

    if pdf_path and pdf_path.exists():
        _up(pdf_path, "PDF")

    if pptx_path and pptx_path.exists():
        _up(pptx_path, "PowerPoint")

    if docx_path and docx_path.exists():
        _up(docx_path, "Word document")

    if zip_path and zip_path.exists():
        _up(zip_path, "Artefact ZIP")

    print(f"[upload] Done — {SSH_HOST}:{remote_dir}/")


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Upload incident report to investigations vault via SSH")
    p.add_argument("--case-id", required=True, metavar="ID",   help="Case ID (remote subdirectory)")
    p.add_argument("--md",      required=True, metavar="FILE",  help="Local Markdown report path")
    p.add_argument("--pdf",                    metavar="FILE",  help="Local PDF report path (optional)")
    p.add_argument("--pptx",                   metavar="FILE",  help="Local PowerPoint path (optional)")
    p.add_argument("--docx",                   metavar="FILE",  help="Local Word document path (optional)")
    p.add_argument("--zip",                    metavar="FILE",  help="Local artefact ZIP path (optional)")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    md = Path(args.md)
    if not md.exists():
        print(f"[upload] ERROR: Markdown file not found: {md}", file=sys.stderr)
        sys.exit(1)
    try:
        upload(
            args.case_id,
            md,
            pdf_path  = Path(args.pdf)  if args.pdf  else None,
            pptx_path = Path(args.pptx) if args.pptx else None,
            docx_path = Path(args.docx) if args.docx else None,
            zip_path  = Path(args.zip)  if args.zip  else None,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[upload] ERROR: SSH/SCP failed: {exc.stderr.decode(errors='replace')}", file=sys.stderr)
        sys.exit(1)
