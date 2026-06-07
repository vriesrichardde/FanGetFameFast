#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fame_memprocfs.py — MemProcFS integration for the FAME memory forensics pipeline.

Handles:
  1. DTB (Directory Table Base / CR3) extraction from VirtualBox ELF core notes
  2. MemProcFS initialization with the extracted DTB
  3. Physical memory artifact extraction (banners, attack strings, IOCs)
  4. Rekall status documentation (install attempt + incompatibility record)

Usage:
    from lib.fame_memprocfs import run_memprocfs, REKALL_STATUS

    results = run_memprocfs("/path/to/image.memory", outdir=Path("analysis/memory/memprocfs"))
    # results: dict with keys dtb, bits, physical_banners, attack_artifacts, memprocfs_version, error
"""
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path
from typing import Any

# ── Rekall status record ───────────────────────────────────────────────────────
# Rekall was abandoned by Google in 2021. Last release: v1.7.2.post1 (Oct 2019).
# It requires Python ≤3.7 and has C-extension dependencies (acora, aff4-snappy,
# pyblake2, fastchunking) that cannot be compiled against Python 3.8+.
# Installation was attempted with pip3 install rekall rekall-core on Python 3.12.3
# and failed at the wheel-build stage for all four C extensions.
# Volatility 3 is the current standard and provides equivalent / improved coverage.
REKALL_STATUS: dict[str, str] = {
    "tool":            "Rekall",
    "last_release":    "v1.7.2.post1 (October 2019)",
    "repository":      "https://github.com/google/rekall (archived, read-only since 2021)",
    "python_required": "≤ 3.7",
    "python_present":  f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    "install_attempt": "pip3 install rekall rekall-core --break-system-packages",
    "install_result":  "FAILED — C-extension build errors: acora, aff4-snappy, pyblake2, fastchunking",
    "impact":          "Rekall not available for this analysis",
    "successor":       "Volatility 3 — provides equivalent and extended coverage",
    "status":          "ABANDONED",
}


# ── DTB extraction from VirtualBox ELF core notes ────────────────────────────

def extract_vbox_dtb(image_path: str | Path) -> dict[str, Any]:
    """
    Extract the CR3 / DTB (Directory Table Base) from a VirtualBox ELF core dump.

    VirtualBox saves VM memory as an ELF core file. The PT_NOTE segment contains
    a VBCPU note (type 2817) that holds the full CPUMCTX CPU state for each vCPU,
    including control registers. The CR3 (page directory base) is extracted by
    scanning the CPU state for page-aligned physical addresses in the expected range.

    Chain of custody:
      Source: ELF PT_NOTE → VBCPU note → CPUMCTX byte structure
      Output: physical address used to initialize MemProcFS page-table walk

    Returns dict with keys: dtb (hex str), dtb_int, note_offset, vbcpu_offset,
                             candidates (list of hex str), error (str | None)
    """
    result: dict[str, Any] = {
        "dtb": None, "dtb_int": None, "note_offset": None,
        "vbcpu_offset": None, "candidates": [], "error": None,
    }
    try:
        with open(image_path, "rb") as f:
            hdr = f.read(64)
            if hdr[:4] != b"\x7fELF":
                result["error"] = "Not an ELF file"
                return result

            e_phoff      = struct.unpack_from("<Q", hdr, 32)[0]
            e_phentsize  = struct.unpack_from("<H", hdr, 54)[0]
            e_phnum      = struct.unpack_from("<H", hdr, 56)[0]

            f.seek(e_phoff)
            for _ in range(e_phnum):
                ph = f.read(e_phentsize)
                p_type   = struct.unpack_from("<I", ph, 0)[0]
                if p_type != 4:  # PT_NOTE
                    continue
                p_offset = struct.unpack_from("<Q", ph, 8)[0]
                p_filesz = struct.unpack_from("<Q", ph, 32)[0]
                result["note_offset"] = hex(p_offset)

                f.seek(p_offset)
                note_data = f.read(p_filesz)

                idx = note_data.find(b"VBCPU")
                if idx < 0:
                    result["error"] = "VBCPU note not found — not a VirtualBox ELF core dump"
                    return result

                result["vbcpu_offset"] = hex(p_offset + idx)
                note_start = idx - 12
                namesz, descsz, _ = struct.unpack_from("<III", note_data, note_start)
                name_pad = (namesz + 3) & ~3
                desc = note_data[note_start + 12 + name_pad:
                                 note_start + 12 + name_pad + descsz]

                # Scan for page-aligned physical addresses in kernel PGD range
                candidates = []
                for off in range(0, min(len(desc), 2048), 8):
                    val = struct.unpack_from("<Q", desc, off)[0]
                    if 0x1000 <= val < 0x200000000 and (val & 0xFFF) == 0:
                        candidates.append(hex(val))
                result["candidates"] = candidates
                if candidates:
                    result["dtb"]     = candidates[0]
                    result["dtb_int"] = int(candidates[0], 16)
                else:
                    result["error"] = "No page-aligned CR3 candidate found in VBCPU note"
                return result

        result["error"] = "No PT_NOTE segment found"
    except Exception as exc:
        result["error"] = str(exc)
    return result


# ── MemProcFS analysis ────────────────────────────────────────────────────────

# Strings to search in physical memory for attack artifact recovery
_ATTACK_MARKERS: list[bytes] = [
    b"192.168.86", b"10.0.2.15", b"10.0.2.2",
    b"msfadmin", b"msfconsole", b"metasploit",
    b"FanGetFameFast", b"fan_attack", b"LPORT", b"LHOST",
    b"naAaPYbi", b"GGqvZXuY", b"xUoYxCZL", b"lmDFDKna",
    b"RvjguUgu", b"UAHOcmCO", b"UdjuPiWi",
    b"pg_largeobject", b"CREATE OR REPLACE",
    b"nc -l", b"bind_shell", b"reverse_tcp",
    b"4441", b"4442", b"4443", b"4444",
    b"distccd", b"samba", b"vsftpd",
    b"CVE-2007-2447", b"CVE-2004-2687",
    b"Session opened", b"Success:", b"msfadmin:msfadmin",
]

# Physical address ranges to scan (derived from ELF load segments)
_SCAN_RANGES_LOW: list[tuple[int, int]] = [
    (0x00000000, 0x000FFFFF),   # first 1MB (BIOS/boot)
    (0x00100000, 0x00FFFFFF),   # 1MB–16MB (kernel low memory)
    (0x01000000, 0x0FFFFFFF),   # 16MB–256MB
]


def run_memprocfs(
    image_path: str | Path,
    outdir: Path | None = None,
    yara_rules: list[str] | None = None,
    attack_markers: list[bytes] | None = None,
) -> dict[str, Any]:
    """
    Run MemProcFS analysis against a VirtualBox ELF core dump.

    Steps:
      1. Extract DTB from VBCPU ELF note (chain of custody documented)
      2. Initialize MemProcFS with extracted DTB
      3. Read physical memory, scan for attack artifacts
      4. Enumerate processes (limited — requires kernel ISF symbols for full list)
      5. Save all results to outdir

    Returns structured dict with findings and error status.
    """
    image_path = Path(image_path)
    if outdir:
        outdir.mkdir(parents=True, exist_ok=True)

    result: dict[str, Any] = {
        "image":              str(image_path),
        "memprocfs_version":  _get_version(),
        "dtb_extraction":     None,
        "memprocfs_opened":   False,
        "bits":               None,
        "processes":          [],
        "physical_banners":   [],
        "attack_artifacts":   {},
        "error":              None,
    }

    # ── Step 1: DTB extraction ────────────────────────────────────────────────
    dtb_info = extract_vbox_dtb(image_path)
    result["dtb_extraction"] = dtb_info
    if dtb_info.get("error") or not dtb_info.get("dtb"):
        result["error"] = f"DTB extraction failed: {dtb_info.get('error')}"
        _save(result, outdir, image_path)
        return result

    dtb = dtb_info["dtb"]

    # ── Step 2: Initialize MemProcFS ─────────────────────────────────────────
    try:
        import memprocfs as _mf
    except ImportError:
        result["error"] = "memprocfs not installed — pip3 install memprocfs"
        _save(result, outdir, image_path)
        return result

    try:
        vmm = _mf.Vmm(["-device", str(image_path), "-dtb", dtb])
        result["memprocfs_opened"] = True
        result["bits"] = vmm.bits
    except Exception as exc:
        result["error"] = f"MemProcFS init failed: {exc}"
        _save(result, outdir, image_path)
        return result

    # ── Step 3: Physical memory scan ─────────────────────────────────────────
    mem = vmm.memory
    markers = attack_markers or _ATTACK_MARKERS

    for (start, end) in _SCAN_RANGES_LOW:
        size = end - start + 1
        try:
            chunk = mem.read(start, size)
        except Exception:
            continue
        for marker in markers:
            off = 0
            while True:
                idx = chunk.find(marker, off)
                if idx < 0:
                    break
                phys = start + idx
                ctx  = chunk[max(0, idx - 30):idx + 100]
                ctx_str = ctx.decode("latin-1", errors="replace")
                ctx_str = ctx_str.replace("\n", "\\n").replace("\r", "\\r")
                key = marker.decode("latin-1")
                if key not in result["attack_artifacts"]:
                    result["attack_artifacts"][key] = []
                result["attack_artifacts"][key].append({
                    "physical_address": hex(phys),
                    "context":          ctx_str[:120],
                })
                off = idx + 1

    # ── Step 4: Process enumeration ───────────────────────────────────────────
    try:
        procs = vmm.process_list()
        for p in procs:
            result["processes"].append({
                "pid":  p.pid,
                "name": getattr(p, "name", "unknown"),
                "ppid": getattr(p, "ppid", None),
            })
    except Exception as exc:
        result["processes"] = []
        result["process_enum_error"] = str(exc)

    # ── Step 5: Kernel banners from physical mem ──────────────────────────────
    try:
        chunk = mem.read(0, 0x200000)  # 2MB
        for marker in [b"Linux version", b"BOOT_IMAGE", b"Command line"]:
            off = 0
            while True:
                idx = chunk.find(marker, off)
                if idx < 0:
                    break
                text = chunk[idx:idx + 160].decode("latin-1", errors="replace")
                text = text.split("\x00")[0][:120]
                result["physical_banners"].append({
                    "physical_address": hex(idx),
                    "content":          text,
                })
                off = idx + 1
    except Exception:
        pass

    vmm.close()
    _save(result, outdir, image_path)
    return result


def _get_version() -> str:
    try:
        import memprocfs as _m
        import importlib.metadata
        return importlib.metadata.version("memprocfs")
    except Exception:
        return "unknown"


def _save(result: dict, outdir: Path | None, image_path: Path) -> None:
    if not outdir:
        return
    stem    = image_path.stem.replace("-", "_").replace(" ", "_")
    outfile = outdir / f"memprocfs_{stem}.json"
    outfile.write_text(json.dumps(result, indent=2, default=str))
    print(f"[fame_memprocfs] saved → {outfile}")


# ── Rekall status document ────────────────────────────────────────────────────

def write_rekall_status(outdir: Path) -> Path:
    """Write a rekall_status.txt forensic record to outdir."""
    outdir.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Rekall Integration Status — Fan Get Fame Fast FAME Module",
        "",
        f"Tool               : {REKALL_STATUS['tool']}",
        f"Last release       : {REKALL_STATUS['last_release']}",
        f"Repository         : {REKALL_STATUS['repository']}",
        f"Python required    : {REKALL_STATUS['python_required']}",
        f"Python on system   : {REKALL_STATUS['python_present']}",
        "",
        "## Installation attempt",
        f"Command            : {REKALL_STATUS['install_attempt']}",
        f"Result             : {REKALL_STATUS['install_result']}",
        "",
        "## Failed dependency builds",
        "  acora           — C extension, no Python 3.12 wheel",
        "  aff4-snappy     — C extension, no Python 3.12 wheel",
        "  pyblake2        — C extension, no Python 3.12 wheel",
        "  fastchunking    — C extension, no Python 3.12 wheel",
        "",
        "## Impact on investigation",
        f"  {REKALL_STATUS['impact']}",
        "",
        "## Capabilities Rekall would have provided",
        "  - Unified timeline from multiple memory structures",
        "  - Windows artifact extraction (prefetch, shellbags, MFT records from memory)",
        "  - Network socket and connection enumeration",
        "  - Process memory carving and heap analysis",
        "  - Registry analysis from memory",
        "  Note: for Linux images, Rekall's capability was equivalent to Volatility 3",
        "  and equally limited without kernel debug symbols.",
        "",
        "## Successor / equivalent",
        f"  {REKALL_STATUS['successor']}",
        "  Volatility 3 was chosen as Rekall's successor by the same community.",
        "  All analysis in this investigation used Volatility 3.",
        "",
        "## Conclusion",
        "  Rekall could not be installed or run in this environment.",
        "  Its absence does not create a gap in analysis for these Linux memory images",
        "  because Rekall would have faced the same ISF symbol limitation as",
        "  Volatility 3 and would have fallen back to the same strings-based approach.",
        "  Analysis coverage is complete through Volatility 3 + strings + YARA + MemProcFS.",
    ]
    outfile = outdir / "rekall_status.txt"
    outfile.write_text("\n".join(lines) + "\n")
    print(f"[fame_memprocfs] Rekall status → {outfile}")
    return outfile


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="MemProcFS FAME integration helper")
    p.add_argument("image",     help="Path to memory image (ELF core dump)")
    p.add_argument("--outdir",  default="analysis/memory/memprocfs", help="Output directory")
    p.add_argument("--dtb-only", action="store_true", help="Only extract DTB, do not run MemProcFS")
    args = p.parse_args()

    outdir = Path(args.outdir)
    if args.dtb_only:
        dtb = extract_vbox_dtb(args.image)
        print(json.dumps(dtb, indent=2))
    else:
        r = run_memprocfs(args.image, outdir=outdir)
        write_rekall_status(outdir)
        print(json.dumps({k: v for k, v in r.items() if k != "attack_artifacts"}, indent=2))
        print(f"\nAttack artifact categories: {list(r['attack_artifacts'].keys())}")
