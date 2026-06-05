# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
path_guard.py — Central write-path policy for Fan Get Fame Fast.

Single source of truth for the project rule:

    Output is written only to approved folders. Evidence, /mnt, /media and
    everything else are read-only.

Every file-writing chokepoint in the Python library routes through
``assert_writable`` / ``guard_output_dir`` / the ``safe_*`` helpers. A write
outside policy raises ``WritePolicyError`` (a ``PermissionError``) and writes
nothing — there is no silent fallback.

Policy
------
A path is writable iff it resolves **inside an APPROVED root** AND **not inside a
READ-ONLY root**. Read-only roots win over approved roots. Matching is by
resolved path prefix (``Path.resolve()`` + ``is_relative_to``) — never by
substring — so ``reports/<case>_evidence`` stays writable while a real evidence
root does not.

Approved roots (under the project root):
    analysis  exports  reports  archive  vault  cases  demo  docs
plus the OS temp directory. Extend without code changes via
``FGFF_APPROVED_ROOTS`` (a ``:``-separated list of absolute paths).

Read-only roots:
    /mnt  /media  and any evidence root (``EVIDENCE_ROOT`` env, the known
    devcontainer/production defaults, ``<project>/evidence`` if present, and any
    path in ``FGFF_READONLY_ROOTS``).

Self-test::

    python3 lib/path_guard.py --test
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import IO

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Folders under PROJECT_ROOT that may receive output.
_APPROVED_SUBDIRS = (
    "analysis",
    "exports",
    "reports",
    "archive",
    "vault",
    "cases",
    "demo",
    "docs",
)

# Evidence roots that are always read-only, regardless of where they live.
_DEFAULT_EVIDENCE_ROOTS = (
    "/home/vscode/evidence",        # devcontainer
    "/home/sansforensics/evidence",  # production (ubuntudesktop)
)


class WritePolicyError(PermissionError):
    """Raised when a write is attempted outside the approved output folders."""


def _split_env_paths(var: str) -> list[Path]:
    raw = os.environ.get(var, "")
    return [Path(p).expanduser() for p in raw.split(os.pathsep) if p.strip()]


def _approved_roots() -> list[Path]:
    roots = [(PROJECT_ROOT / sub) for sub in _APPROVED_SUBDIRS]
    roots.append(Path(tempfile.gettempdir()))
    roots.extend(_split_env_paths("FGFF_APPROVED_ROOTS"))
    # Resolve so symlinked temp dirs (e.g. macOS /tmp) compare correctly.
    return [_safe_resolve(r) for r in roots]


def _readonly_roots() -> list[Path]:
    roots: list[Path] = [Path("/mnt"), Path("/media")]
    # Evidence root used by the MCP servers.
    ev = os.environ.get("EVIDENCE_ROOT")
    if ev:
        roots.append(Path(ev).expanduser())
    roots.extend(Path(p) for p in _DEFAULT_EVIDENCE_ROOTS)
    project_evidence = PROJECT_ROOT / "evidence"
    if project_evidence.exists():
        roots.append(project_evidence)
    roots.extend(_split_env_paths("FGFF_READONLY_ROOTS"))
    return [_safe_resolve(r) for r in roots]


def _safe_resolve(path: Path | str) -> Path:
    """Resolve *path* without requiring it (or its parents) to exist."""
    return Path(path).expanduser().resolve()


def is_writable(path: Path | str) -> bool:
    """Return True iff writing to *path* is allowed by policy."""
    target = _safe_resolve(path)
    if any(target == ro or target.is_relative_to(ro) for ro in _readonly_roots()):
        return False
    return any(target == ap or target.is_relative_to(ap) for ap in _approved_roots())


def assert_writable(path: Path | str) -> Path:
    """
    Ensure *path* may be written. Return its resolved form, or raise
    ``WritePolicyError`` describing the violation. Nothing is written.
    """
    target = _safe_resolve(path)
    for ro in _readonly_roots():
        if target == ro or target.is_relative_to(ro):
            raise WritePolicyError(
                f"Refusing to write to read-only location: {target} "
                f"(under protected root {ro}). Evidence, /mnt and /media are "
                f"read-only — write output to an approved folder instead."
            )
    if not is_writable(target):
        approved = ", ".join(sorted(str(r) for r in _approved_roots()))
        raise WritePolicyError(
            f"Refusing to write outside approved output folders: {target}. "
            f"Approved roots: {approved}."
        )
    return target


def guard_output_dir(path: Path | str) -> Path:
    """
    Assert *path* is writable, create it (parents, exist_ok), and return the
    resolved directory. Drop-in replacement for ``output_dir.mkdir(...)``.
    """
    target = assert_writable(path)
    target.mkdir(parents=True, exist_ok=True)
    return target


def safe_mkdir(path: Path | str, parents: bool = True, exist_ok: bool = True) -> Path:
    """Policy-checked ``Path.mkdir``."""
    target = assert_writable(path)
    target.mkdir(parents=parents, exist_ok=exist_ok)
    return target


def safe_write_text(path: Path | str, text: str, **kwargs) -> Path:
    """Policy-checked ``Path.write_text``."""
    target = assert_writable(path)
    target.write_text(text, **kwargs)
    return target


def safe_write_bytes(path: Path | str, data: bytes) -> Path:
    """Policy-checked ``Path.write_bytes``."""
    target = assert_writable(path)
    target.write_bytes(data)
    return target


def safe_open(path: Path | str, mode: str = "r", **kwargs) -> IO:
    """
    Policy-checked ``open``. The path is asserted only for write/append/update
    modes ('w', 'a', 'x', or any mode containing '+').
    """
    if any(ch in mode for ch in ("w", "a", "x", "+")):
        path = assert_writable(path)
    return open(path, mode, **kwargs)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _run_self_test() -> int:
    failures = 0

    def check(label: str, path: str, expect_writable: bool) -> None:
        nonlocal failures
        got = is_writable(path)
        ok = got == expect_writable
        if not ok:
            failures += 1
        verdict = "PASS" if ok else "FAIL"
        want = "writable" if expect_writable else "blocked"
        print(f"[{verdict}] {label}: expected {want}, got "
              f"{'writable' if got else 'blocked'}  ({path})")

    # Allowed: inside approved roots.
    check("reports file",        str(PROJECT_ROOT / "reports" / "x.md"), True)
    check("reports _evidence",   str(PROJECT_ROOT / "reports" / "FAN-2025-001_evidence" / "y.txt"), True)
    check("analysis wip",        str(PROJECT_ROOT / "analysis" / "memory" / "pslist.txt"), True)
    check("vault note",          str(PROJECT_ROOT / "vault" / "IOCs" / "evil.md"), True)
    check("exports artifact",    str(PROJECT_ROOT / "exports" / "mft" / "mft.csv"), True)
    check("temp scratch",        str(Path(tempfile.gettempdir()) / "fgff_scratch.txt"), True)

    # Blocked: read-only roots and non-approved locations.
    check("/mnt mount",          "/mnt/windows_mount/secret.txt", False)
    check("/media mount",        "/media/usb/out.txt", False)
    check("evidence (default)",  "/home/vscode/evidence/case.pcap", False)
    check("project lib sibling", str(PROJECT_ROOT / "lib" / "rogue.py"), False)
    check("home dir",            str(Path.home() / "rogue.txt"), False)

    # assert_writable raises on a blocked path and writes nothing.
    try:
        assert_writable("/mnt/x")
        print("[FAIL] assert_writable('/mnt/x') did not raise")
        failures += 1
    except WritePolicyError:
        print("[PASS] assert_writable('/mnt/x') raised WritePolicyError")

    print()
    if failures:
        print(f"path_guard self-test: {failures} FAILURE(S)")
    else:
        print("path_guard self-test: ALL PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    import sys

    if "--test" in sys.argv:
        raise SystemExit(_run_self_test())
    print(__doc__)
    print("Approved roots:")
    for r in _approved_roots():
        print(f"  + {r}")
    print("Read-only roots:")
    for r in _readonly_roots():
        print(f"  - {r}")
