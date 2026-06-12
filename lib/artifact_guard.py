#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
artifact_guard.py — Never silently overwrite a hand-edited report artifact.

Generated reports (campaign PDF/PPTX/DOCX) are routinely re-rendered as an
investigation progresses. If an analyst has hand-edited one of those files
(e.g. redesigned the campaign PowerPoint), a plain re-render would silently
clobber that work — and the gitignored `reports/` tree gives no recovery
path.

This module maintains a small per-case manifest,
``reports/<case_id>/documents/.fgff_generated.json``, mapping output
filenames to the SHA-256 of the content this pipeline last wrote. Before
writing a new render of a given file:

- If no manifest entry exists and the file doesn't exist yet -> write normally.
- If the existing file's hash matches the manifest entry -> it's still "ours";
  write normally (and update the manifest).
- If the existing file's hash differs from the manifest entry (or no entry
  exists but the file exists) -> presumed hand-edited. The new render is
  diverted to ``<stem>.new<suffix>`` and a warning is printed; the original
  file is left untouched.

For PPTX files specifically, ``docProps/core.xml`` is also inspected:
python-pptx's default ``lastModifiedBy`` is "Steve Canny" with
``revision == 1``. Any other ``lastModifiedBy`` or ``revision >= 2``
corroborates a hand-edit, even for files that predate the manifest.

Python API:
    from lib.artifact_guard import resolve_output, record_generated

    out_path, diverted = resolve_output(target_path)
    # ... render to out_path ...
    if not diverted:
        record_generated(out_path)
"""
from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from xml.etree import ElementTree as ET

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement

_MANIFEST_NAME = ".fgff_generated.json"

_CORE_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
}
_PPTX_DEFAULT_AUTHOR = "Steve Canny"


def _manifest_path(directory: Path) -> Path:
    return Path(directory) / _MANIFEST_NAME


def _load_manifest(directory: Path) -> dict[str, str]:
    path = _manifest_path(directory)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save_manifest(directory: Path, manifest: dict[str, str]) -> None:
    path_guard.safe_write_text(
        _manifest_path(directory), json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    )


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _pptx_looks_hand_edited(path: Path) -> bool:
    """Inspect docProps/core.xml for signs of a manual PowerPoint edit."""
    try:
        with zipfile.ZipFile(path) as zf:
            data = zf.read("docProps/core.xml")
    except (KeyError, OSError, zipfile.BadZipFile):
        return False
    try:
        root = ET.fromstring(data)
    except ET.ParseError:
        return False
    last_modified_by = root.findtext("cp:lastModifiedBy", default="", namespaces=_CORE_NS)
    revision = root.findtext("cp:revision", default="", namespaces=_CORE_NS)
    if last_modified_by and last_modified_by != _PPTX_DEFAULT_AUTHOR:
        return True
    try:
        if revision and int(revision) >= 2:
            return True
    except ValueError:
        pass
    return False


def resolve_output(path: Path | str) -> tuple[Path, bool]:
    """Return ``(path_to_write, was_diverted)`` for an about-to-be-rendered
    artifact at *path*.

    If *path* doesn't exist, or exists and matches the recorded generated
    hash, returns ``(path, False)`` — write normally.

    If *path* exists but doesn't match the recorded hash (or has no record
    and, for PPTX, looks hand-edited via ``docProps/core.xml``), returns
    ``(<stem>.new<suffix>, True)`` and prints a warning. The hand-edited
    original is left untouched.
    """
    target = Path(path)
    if not target.exists():
        return target, False

    manifest = _load_manifest(target.parent)
    recorded = manifest.get(target.name)
    current = _sha256(target)

    if recorded is not None and recorded == current:
        return target, False

    if recorded is None and target.suffix.lower() == ".pptx" and not _pptx_looks_hand_edited(target):
        # No manifest record, and the PPTX metadata doesn't corroborate a
        # hand-edit either — treat as ours (e.g. first run after this guard
        # was introduced for a machine-generated file).
        return target, False

    diverted = target.with_suffix(f".new{target.suffix}")
    print(
        f"[artifact_guard] WARNING: '{target.name}' appears to be hand-edited "
        f"and will not be overwritten. Writing new render to '{diverted.name}' "
        f"instead — review and manually replace the original if it should be updated."
    )
    return diverted, True


def record_generated(path: Path | str) -> None:
    """Record *path*'s current hash as a pipeline-generated artifact, so
    future renders can detect hand-edits made after this point."""
    target = Path(path)
    if not target.exists():
        return
    manifest = _load_manifest(target.parent)
    manifest[target.name] = _sha256(target)
    _save_manifest(target.parent, manifest)
