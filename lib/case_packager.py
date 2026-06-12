#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
case_packager.py — Package all PCAP investigation artifacts into a timestamped ZIP
and upload it to the investigations vault via SSH/SCP.

The ZIP contains:
  reports/<stem>_incident_report.md
  reports/<stem>_incident_report.pdf
  reports/<stem>_management_briefing.pptx
  analysis/<module>/<stem>/...   (all module outputs for this stem)

The ZIP filename includes the UTC creation timestamp:
  <case_id>_<YYYYMMDD-HHMMSS>.zip

Usage (CLI):
  python3 lib/case_packager.py \
      --case-id FAN-2026-001 \
      --stem capture \
      --reports-dir ./analysis/_reports/capture \
      [--analysis-dir ./analysis] \
      [--output-dir ./analysis/_reports/capture]

Python API:
  from lib.case_packager import package, upload_zip
  zip_path = package(case_id, stem, reports_dir, analysis_dir, output_dir)
  upload_zip(case_id, zip_path)
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shlex
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement

SSH_HOST    = os.environ.get("INVESTIGATIONS_SSH_HOST", "sansforensics@ubuntudesktop")
REMOTE_ROOT = os.environ.get("INVESTIGATIONS_ROOT",     "/home/sansforensics/cases")


# ── Packaging ─────────────────────────────────────────────────────────────────

def package(
    case_id: str,
    stem: str,
    reports_dir: Path,
    analysis_dir: Path | None = None,
    output_dir: Path | None = None,
) -> Path:
    """
    Collect all artifacts for *stem* and compress them into a timestamped ZIP.

    Parameters
    ----------
    case_id      : investigation case identifier (used in ZIP filename)
    stem         : PCAP stem — used to locate per-stem analysis subdirectories
    reports_dir  : directory containing the MD / PDF / PPTX reports
    analysis_dir : root of ./analysis/ (default: reports_dir parent's parent)
    output_dir   : where to write the ZIP (default: reports_dir)

    Returns
    -------
    Path of the created ZIP file.
    """
    reports_dir = Path(reports_dir)
    analysis_dir = Path(analysis_dir) if analysis_dir else reports_dir.parent.parent
    output_dir   = Path(output_dir)   if output_dir   else reports_dir

    output_dir = path_guard.guard_output_dir(output_dir)

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    zip_name = f"{case_id}_{ts}.zip"
    zip_path = path_guard.assert_writable(output_dir / zip_name)

    print(f"[package] Creating {zip_path.name} ...")

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        _add_reports(zf, reports_dir, stem)
        _add_analysis(zf, analysis_dir, stem)

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[package] ZIP complete: {zip_path}  ({size_mb:.1f} MB)")
    return zip_path


def package_all(
    case_id: str,
    reports_dirs,
    output_dir: Path | None = None,
    stem: str | None = None,
    case_dir: Path | None = None,
) -> Path | None:
    """
    General, format-agnostic packager: collect EVERY artifact for *case_id*
    across one or more report directories and compress them into a timestamped
    ZIP with a SHA-256 integrity manifest.

    Unlike :func:`package` (which is PCAP/stem specific and only handles
    MD/PDF/PPTX), this captures any file type — DOCX, PPTX, PDF, the chat
    transcript (MD/PDF/JSONL), exhibit images, evidence ZIPs, etc. — so the
    bundle is complete for FAN, FAME, FAST and batch runs alike.

    When *case_dir* is supplied (hierarchical per-case layout):
      * The entire ``case_dir/`` tree is collected (module subdirs, documents/,
        raw/, campaign report MD).
      * The ZIP is written to ``case_dir/documents/``.
      * *reports_dirs* and *output_dir* are ignored.

    Legacy collection rules (when *case_dir* is None), applied to each
    directory in *reports_dirs*:
      * a ``<case_id>/`` subfolder (in-session layout) — added whole,
      * flat ``<case_id>_*`` files,
      * flat ``<stem>_*`` files when *stem* differs from *case_id* (FAN).
    Our own timestamped ``<case_id>_<ts>.zip`` bundles are skipped so repeated
    runs never nest prior bundles.

    Returns the ZIP path, or ``None`` when no artifacts were found.
    """
    bundle_re = re.compile(rf"{re.escape(case_id)}_\d{{8}}-\d{{6}}\.zip$")
    selected: dict[str, Path] = {}

    if case_dir is not None:
        # ── Hierarchical per-case layout ──────────────────────────────────
        case_dir = Path(case_dir)
        zip_out  = path_guard.guard_output_dir(case_dir / "documents")
        base     = case_dir.parent  # e.g. reports/

        def _consider_hier(f: Path) -> None:
            if not f.is_file() or bundle_re.search(f.name) or f.name == "MANIFEST.sha256":
                return
            try:
                rel = f.relative_to(base)
            except ValueError:
                rel = Path(case_id) / f.name
            arc = str(rel)
            selected.setdefault(arc, f)

        for f in case_dir.rglob("*"):
            _consider_hier(f)
    else:
        # ── Legacy flat layout ────────────────────────────────────────────
        dirs = [Path(d) for d in (reports_dirs if isinstance(reports_dirs, (list, tuple)) else [reports_dirs])]
        zip_out = path_guard.guard_output_dir(Path(output_dir) if output_dir else dirs[0])

        def consider(f: Path, base: Path) -> None:
            # Skip non-files, our own timestamped bundles (avoid nesting), and any
            # pre-existing manifest (we regenerate MANIFEST.sha256 ourselves).
            if not f.is_file() or bundle_re.search(f.name) or f.name == "MANIFEST.sha256":
                return
            try:
                rel = f.relative_to(base)
            except ValueError:
                rel = Path(f.name)
            arc = str(rel) if rel.parts and rel.parts[0] == case_id else f"{case_id}/{rel}"
            selected.setdefault(arc, f)

        for rd in dirs:
            if not rd.is_dir():
                continue
            sub = rd / case_id
            if sub.is_dir():
                for f in sub.rglob("*"):
                    consider(f, rd)
            for f in rd.glob(f"{case_id}_*"):
                consider(f, rd)
            if stem and stem != case_id:
                for f in rd.glob(f"{stem}_*"):
                    consider(f, rd)

    if not selected:
        search_desc = str(case_dir) if case_dir is not None else ", ".join(str(d) for d in dirs)  # type: ignore[union-attr]
        print(f"[package] No artifacts found for {case_id} in {search_desc}")
        return None

    ts       = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    zip_name = f"{case_id}_{ts}.zip"
    zip_path = path_guard.assert_writable(zip_out / zip_name)
    print(f"[package] Creating {zip_path.name} ...")
    manifest = []
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for arc in sorted(selected):
            f = selected[arc]
            zf.write(f, arc)
            manifest.append(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {arc}")
            print(f"[package]   + {arc}")
        zf.writestr(f"{case_id}/MANIFEST.sha256", "\n".join(manifest) + "\n")

    size_mb = zip_path.stat().st_size / (1024 * 1024)
    print(f"[package] ZIP complete: {zip_path}  ({len(selected)} files, {size_mb:.1f} MB)")
    return zip_path


def _add_reports(zf: zipfile.ZipFile, reports_dir: Path, stem: str) -> None:
    """Add the MD, PDF, and PPTX report files to the ZIP under reports/."""
    added = 0
    for ext in (".md", ".pdf", ".pptx"):
        candidate = reports_dir / f"{stem}_incident_report{ext}"
        if candidate.exists():
            zf.write(candidate, f"reports/{candidate.name}")
            print(f"[package]   + reports/{candidate.name}")
            added += 1
    # PPTX uses a different naming convention
    pptx_alt = reports_dir / f"{stem}_management_briefing.pptx"
    if pptx_alt.exists():
        arcname = f"reports/{pptx_alt.name}"
        if arcname not in [zi.filename for zi in zf.infolist()]:
            zf.write(pptx_alt, arcname)
            print(f"[package]   + {arcname}")
            added += 1
    if added == 0:
        print(f"[package]   (no report files found in {reports_dir})")


def _add_analysis(zf: zipfile.ZipFile, analysis_dir: Path, stem: str) -> None:
    """Add all per-stem module output files from analysis/ to the ZIP."""
    if not analysis_dir.exists():
        print(f"[package]   (analysis dir not found: {analysis_dir})")
        return

    file_count = 0
    for mod_dir in sorted(analysis_dir.iterdir()):
        if not mod_dir.is_dir():
            continue
        if mod_dir.name == "_reports":
            continue  # already added above
        stem_dir = mod_dir / stem
        if not stem_dir.is_dir():
            continue
        for f in sorted(stem_dir.rglob("*")):
            if f.is_file():
                arcname = f"analysis/{f.relative_to(analysis_dir)}"
                zf.write(f, arcname)
                file_count += 1

    print(f"[package]   + {file_count} analysis artifact file(s)")


# ── Upload ────────────────────────────────────────────────────────────────────

def upload_zip(case_id: str, zip_path: Path) -> None:
    """Upload *zip_path* to <REMOTE_ROOT>/<case_id>/ on the investigations vault."""
    zip_path = Path(zip_path)
    if not zip_path.exists():
        print(f"[upload] ERROR: ZIP not found: {zip_path}", file=sys.stderr)
        sys.exit(1)

    remote_dir  = f"{REMOTE_ROOT}/{case_id}"
    remote_path = f"{remote_dir}/{zip_path.name}"

    print(f"[upload] {zip_path.name} → {SSH_HOST}:{remote_dir}/")

    # accept-new preserves MITM protection (rejects changed host keys) instead
    # of silently trusting any key. remote_dir is shell-quoted: it is built from
    # the operator-supplied case_id and runs in a remote shell via `ssh`.
    ssh_opts = ["-o", "StrictHostKeyChecking=accept-new", "-o", "BatchMode=yes"]
    subprocess.run(
        ["ssh", *ssh_opts, SSH_HOST, f"mkdir -p {shlex.quote(remote_dir)}"],
        check=True, capture_output=True,
    )
    subprocess.run(
        ["scp", *ssh_opts, str(zip_path), f"{SSH_HOST}:{remote_path}"],
        check=True, capture_output=True,
    )
    print(f"[upload] Done — {SSH_HOST}:{remote_path}")


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Package PCAP investigation artifacts into a timestamped ZIP and upload"
    )
    p.add_argument("--case-id",      required=True, metavar="ID",  help="Case ID")
    p.add_argument("--stem",         default="",    metavar="STEM", help="PCAP stem name (required unless --all)")
    p.add_argument("--reports-dir",  required=True, metavar="DIR",  help="Directory with reports/artifacts")
    p.add_argument("--extra-reports-dir", action="append", default=[], metavar="DIR",
                   help="Additional report directory to scan (repeatable; --all mode)")
    p.add_argument("--analysis-dir", default="",    metavar="DIR",  help="Analysis base directory (default: reports-dir/../..)")
    p.add_argument("--output-dir",   default="",    metavar="DIR",  help="Where to write the ZIP (default: reports-dir)")
    p.add_argument("--case-dir",      default="",    metavar="DIR",  help="Case root directory (reports/<case_id>/). When set, ZIP goes to case_dir/documents/ and the entire tree is collected.")
    p.add_argument("--all",          action="store_true",           help="General mode: bundle EVERY artifact for the case (all file types) with a SHA-256 manifest")
    p.add_argument("--upload",       action="store_true",           help="Upload the ZIP after packaging")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.all:
        zip_path = package_all(
            case_id     = args.case_id,
            reports_dirs= [args.reports_dir, *args.extra_reports_dir],
            output_dir  = Path(args.output_dir) if args.output_dir else None,
            stem        = args.stem or None,
            case_dir    = Path(args.case_dir) if args.case_dir else None,
        )
    else:
        if not args.stem:
            print("[package] ERROR: --stem is required unless --all is given", file=sys.stderr)
            sys.exit(2)
        zip_path = package(
            case_id      = args.case_id,
            stem         = args.stem,
            reports_dir  = Path(args.reports_dir),
            analysis_dir = Path(args.analysis_dir) if args.analysis_dir else None,
            output_dir   = Path(args.output_dir)   if args.output_dir   else None,
        )

    if args.upload:
        if zip_path is None:
            print("[upload] Nothing to upload (no artifacts packaged).", file=sys.stderr)
        else:
            try:
                upload_zip(args.case_id, zip_path)
            except subprocess.CalledProcessError as exc:
                print(f"[upload] ERROR: SSH/SCP failed: {exc.stderr.decode(errors='replace')}",
                      file=sys.stderr)
                sys.exit(1)
