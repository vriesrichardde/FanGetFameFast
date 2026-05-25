# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_file_hashes.py — Extract files from a PCAP and compute MD5/SHA256 hashes.

Supported protocols (via tshark --export-objects):
  http, smb, imf, tftp, dicom

For each extracted file the module:
  1. Computes MD5 and SHA256
  2. Runs an OSINT lookup via Perplexity (optional; skipped when not configured)
  3. Records the file as an IOC in the Obsidian vault (optional)

Usage:
  python3 lib/fan_file_hashes.py /path/to/capture.pcap
  python3 lib/fan_file_hashes.py /path/to/capture.pcap --stem capture --case-id CASE-2025-001
  python3 lib/fan_file_hashes.py /path/to/capture.pcap --output-dir /custom/path --no-vault

Outputs (written to ./analysis/file_hashes/<stem>/):
  file_hashes.json   — findings summary + per-file records
  file_hashes.csv    — flat CSV inventory
  file_hashes_report.md — human-readable Markdown report
  files/             — extracted file artefacts
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
ANALYSIS_DIR = PROJECT_ROOT / "analysis"
OUTPUT_SUBDIR = "file_hashes"

EXPORT_PROTOCOLS = ["http", "smb", "imf", "tftp", "dicom"]

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Hash utilities ────────────────────────────────────────────────────────────

def _hash_file(path: Path) -> tuple[str, str]:
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()


def _safe_filename(s: str) -> str:
    return "".join(c if c.isalnum() or c in ".-_" else "_" for c in s)[:120]


# ── File extraction via tshark ────────────────────────────────────────────────

def extract_files(pcap: Path, export_dir: Path) -> list[dict]:
    """
    Run tshark --export-objects for each protocol and return a list of
    {protocol, filename, path, size_bytes, md5, sha256} dicts.
    """
    export_dir.mkdir(parents=True, exist_ok=True)
    records: list[dict] = []

    for proto in EXPORT_PROTOCOLS:
        proto_dir = export_dir / proto
        proto_dir.mkdir(parents=True, exist_ok=True)
        try:
            result = subprocess.run(
                ["tshark", "-r", str(pcap), "--export-objects", f"{proto},{proto_dir}"],
                capture_output=True, text=True, timeout=120,
            )
            # tshark exits 0 even when no objects found; check for files
        except (FileNotFoundError, subprocess.TimeoutExpired) as e:
            print(f"[file_hashes] tshark export-objects {proto}: {e}", file=sys.stderr)
            continue

        for f in sorted(proto_dir.iterdir()):
            if not f.is_file():
                continue
            try:
                md5, sha256 = _hash_file(f)
                records.append({
                    "protocol":     proto,
                    "filename":     f.name,
                    "path":         str(f),
                    "size_bytes":   f.stat().st_size,
                    "md5":          md5,
                    "sha256":       sha256,
                    "osint_verdict": "",
                    "osint_summary": "",
                    "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                })
            except Exception as e:
                print(f"[file_hashes] Could not hash {f}: {e}", file=sys.stderr)

    return records


# ── OSINT enrichment ──────────────────────────────────────────────────────────

def _enrich_osint(records: list[dict]) -> list[dict]:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from perplexity_client import PerplexityClient
        client = PerplexityClient()
    except Exception:
        return records

    for rec in records:
        sha256 = rec["sha256"]
        if not sha256:
            continue
        try:
            result = client.lookup_ioc(sha256)
            if not result:
                continue
            verdict = "unknown"
            summary_lower = result.lower()
            if any(w in summary_lower for w in ["malicious", "malware", "trojan", "ransomware",
                                                  "backdoor", "rat ", "c2", "command-and-control"]):
                verdict = "malicious"
            elif any(w in summary_lower for w in ["suspicious", "potentially", "pua", "adware",
                                                    "unwanted"]):
                verdict = "suspicious"
            else:
                verdict = "clean"
            rec["osint_verdict"] = verdict
            rec["osint_summary"] = result[:500]
        except Exception as e:
            print(f"[file_hashes] OSINT lookup failed for {sha256[:16]}…: {e}", file=sys.stderr)

    return records


# ── Severity assignment ───────────────────────────────────────────────────────

def _file_severity(rec: dict) -> str:
    verdict = rec.get("osint_verdict", "")
    if verdict == "malicious":
        return "critical"
    if verdict == "suspicious":
        return "high"
    ext = Path(rec.get("filename", "")).suffix.lower()
    risky_exts = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".hta",
                  ".msi", ".jar", ".py", ".sh", ".elf", ".bin", ".iso", ".img"}
    if ext in risky_exts:
        return "high"
    return "info"


# ── Output writers ────────────────────────────────────────────────────────────

def _write_json(records: list[dict], out_dir: Path) -> Path:
    malicious   = sum(1 for r in records if r.get("osint_verdict") == "malicious")
    suspicious  = sum(1 for r in records if r.get("osint_verdict") == "suspicious")
    payload = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "files_found":   len(records),
        "malicious_count":  malicious,
        "suspicious_count": suspicious,
        "files": records,
    }
    p = out_dir / "file_hashes.json"
    p.write_text(json.dumps(payload, indent=2, ensure_ascii=False))
    return p


def _write_csv(records: list[dict], out_dir: Path) -> Path:
    p = out_dir / "file_hashes.csv"
    fields = ["protocol", "filename", "size_bytes", "md5", "sha256",
              "osint_verdict", "osint_summary", "timestamp_utc"]
    with open(p, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(records)
    return p


def _write_report(records: list[dict], out_dir: Path, pcap: Path, stem: str, case_id: str) -> Path:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    malicious   = [r for r in records if r.get("osint_verdict") == "malicious"]
    suspicious  = [r for r in records if r.get("osint_verdict") == "suspicious"]
    risky_exts  = {".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs", ".js", ".hta",
                   ".msi", ".jar", ".py", ".sh", ".elf", ".bin"}

    lines = [
        f"# File Hash Analysis — `{stem}`",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| PCAP | `{pcap}` |",
        f"| Case ID | {case_id or '—'} |",
        f"| Generated | {now} |",
        f"| Files Extracted | {len(records)} |",
        f"| Malicious | {len(malicious)} |",
        f"| Suspicious | {len(suspicious)} |",
        "",
        "---",
        "",
    ]

    if not records:
        lines += ["No files were extracted from this PCAP.", ""]
    else:
        lines += ["## Extracted Files", ""]
        lines += ["| Protocol | Filename | Size | MD5 | SHA256 | Verdict |",
                  "|----------|----------|------|-----|--------|---------|"]
        for r in records:
            sev = _file_severity(r)
            badge = {"critical": "🔴 CRITICAL", "high": "🟠 HIGH",
                     "medium": "🟡 MEDIUM"}.get(sev, r.get("osint_verdict", "—") or "—")
            size = f"{r['size_bytes']:,} B"
            lines.append(
                f"| {r['protocol']} | `{r['filename'][:40]}` | {size} "
                f"| `{r['md5'][:12]}…` | `{r['sha256'][:16]}…` | {badge} |"
            )
        lines.append("")

        if malicious or suspicious:
            lines += ["## Threat Findings", ""]
            for r in malicious + suspicious:
                lines += [
                    f"### {r['filename']}",
                    "",
                    f"- **Protocol**: {r['protocol']}",
                    f"- **Verdict**: {r['osint_verdict'].upper()}",
                    f"- **MD5**: `{r['md5']}`",
                    f"- **SHA256**: `{r['sha256']}`",
                    f"- **Size**: {r['size_bytes']:,} bytes",
                    "",
                    f"**OSINT Summary**: {r.get('osint_summary') or 'No data available.'}",
                    "",
                    "---",
                    "",
                ]

    p = out_dir / "file_hashes_report.md"
    p.write_text("\n".join(lines), encoding="utf-8")
    return p


# ── Vault integration ─────────────────────────────────────────────────────────

def _write_vault(records: list[dict], stem: str, case_id: str) -> None:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from knowledge_extractor import record_ioc
    except ImportError as e:
        print(f"[file_hashes] Vault write skipped: {e}", file=sys.stderr)
        return

    for r in records:
        verdict = r.get("osint_verdict", "")
        if verdict not in ("malicious", "suspicious"):
            continue
        sev = "critical" if verdict == "malicious" else "high"
        context = (
            f"Extracted from PCAP stem '{stem}' via protocol {r['protocol']}. "
            f"Filename: {r['filename']}. Size: {r['size_bytes']} bytes. "
            f"OSINT: {r.get('osint_summary','')[:200]}"
        )
        try:
            record_ioc("hash", r["sha256"], context, case_id or stem, severity=sev)
        except Exception as e:
            print(f"[file_hashes] Vault record failed for {r['sha256'][:16]}…: {e}",
                  file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Extract files from PCAP and compute MD5/SHA256 hashes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s capture.pcap\n"
            "  %(prog)s capture.pcap --case-id CASE-2025-001\n"
            "  %(prog)s capture.pcap --output-dir ./analysis/file_hashes/capture --no-vault\n"
        ),
    )
    ap.add_argument("pcap",          type=Path, help="Path to PCAP file")
    ap.add_argument("--stem",        default=None, help="Output stem (default: PCAP filename stem)")
    ap.add_argument("--case-id",     default="",   dest="case_id",
                    help="Case identifier for vault notes")
    ap.add_argument("--output-dir",  default=None, dest="output_dir", type=Path,
                    help="Full output directory (default: ./analysis/file_hashes/<stem>/)")
    ap.add_argument("--no-osint",    action="store_true", dest="no_osint",
                    help="Skip Perplexity OSINT lookups")
    ap.add_argument("--no-vault",    action="store_true", dest="no_vault",
                    help="Skip Obsidian vault writes")
    args = ap.parse_args()

    pcap = args.pcap.resolve()
    if not pcap.exists():
        print(f"[file_hashes] PCAP not found: {pcap}", file=sys.stderr)
        sys.exit(1)

    stem    = args.stem or pcap.stem
    out_dir = args.output_dir or (ANALYSIS_DIR / OUTPUT_SUBDIR / stem)
    out_dir.mkdir(parents=True, exist_ok=True)

    files_dir = out_dir / "files"
    files_dir.mkdir(exist_ok=True)

    print(f"[file_hashes] PCAP       : {pcap}", file=sys.stderr)
    print(f"[file_hashes] Stem       : {stem}", file=sys.stderr)
    print(f"[file_hashes] Output     : {out_dir}", file=sys.stderr)

    print(f"[file_hashes] Extracting files from PCAP (protocols: {', '.join(EXPORT_PROTOCOLS)}) ...",
          file=sys.stderr)
    records = extract_files(pcap, files_dir)
    print(f"[file_hashes] Extracted  : {len(records)} file(s)", file=sys.stderr)

    if records and not args.no_osint:
        print("[file_hashes] Running OSINT lookups ...", file=sys.stderr)
        records = _enrich_osint(records)
        mal = sum(1 for r in records if r.get("osint_verdict") == "malicious")
        sus = sum(1 for r in records if r.get("osint_verdict") == "suspicious")
        print(f"[file_hashes] OSINT     : {mal} malicious, {sus} suspicious", file=sys.stderr)

    json_path = _write_json(records, out_dir)
    csv_path  = _write_csv(records, out_dir)
    rep_path  = _write_report(records, out_dir, pcap, stem, args.case_id)

    print(f"[file_hashes] JSON       : {json_path}", file=sys.stderr)
    print(f"[file_hashes] CSV        : {csv_path}",  file=sys.stderr)
    print(f"[file_hashes] Report     : {rep_path}",  file=sys.stderr)

    if not args.no_vault and records:
        print("[file_hashes] Writing vault entries ...", file=sys.stderr)
        _write_vault(records, stem, args.case_id)

    if not records:
        print("[file_hashes] No files extracted. Ensure PCAP contains HTTP/SMB/TFTP file transfers.",
              file=sys.stderr)


if __name__ == "__main__":
    main()
