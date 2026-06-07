# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_yara_pcap.py — Scan a PCAP (and extracted files, directories, memory images)
with YARA rules.

Scans:
  1. The raw PCAP file (all packet payloads) against ./rules/yara/*.yar
  2. Any files extracted by fan_file_hashes (./analysis/file_hashes/<stem>/files/)
  3. Optional extra targets: directories (recursive) or memory images (--extra-targets)

Features:
  - yarac pre-compilation for faster repeated scanning
  - -s strings output: captures matching byte offsets per hit
  - -r recursive directory scanning
  - -p N parallel threads
  - -f fast mode (first match per rule only)
  - --timeout N per-target timeout
  - PE / entropy / hash module rules (pe_analysis.yar, entropy_detection.yar)
  - Community rules directory support (--community-rules)
  - False-positive test mode (--fp-test)
  - Memory image scanning (--extra-targets /path/to/memory.img)

Outputs (./analysis/yara_pcap/<stem>/):
  yara_matches.json    — match summary + per-match records
  yara_matches.csv     — flat CSV
  yara_report.md       — human-readable Markdown report
  yara_strings.txt     — matching string offsets (when --strings enabled)
  compiled.rules       — compiled ruleset (when yarac available)

YARA binary: /usr/local/bin/yara (v4.1.0)
Rules path:  ./rules/yara/*.yar
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT  = Path(__file__).parent.parent
ANALYSIS_DIR  = PROJECT_ROOT / "analysis"
RULES_DIR     = PROJECT_ROOT / "rules" / "yara"
OUTPUT_SUBDIR = "yara_pcap"

YARA_BIN  = "/usr/local/bin/yara"
YARAC_BIN_CANDIDATES = ["/usr/local/bin/yarac", "/usr/bin/yarac"]

_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ── Tool detection ────────────────────────────────────────────────────────────

def _yara_bin() -> str | None:
    if Path(YARA_BIN).exists():
        return YARA_BIN
    found = shutil.which("yara")
    return found


def _yarac_bin() -> str | None:
    for c in YARAC_BIN_CANDIDATES:
        if Path(c).exists():
            return c
    return shutil.which("yarac")


# ── Rule metadata parsing ─────────────────────────────────────────────────────

def _parse_rule_metadata(rules_dirs: list[Path]) -> dict[str, dict]:
    """
    Parse severity, description, mitre_att, category from .yar metadata blocks.
    Returns {rule_name: {severity, description, mitre_att, category}}.
    Accepts multiple rule directories (supports community rules).
    """
    meta_re    = re.compile(r'^\s*(severity|description|mitre_att|category)\s*=\s*"([^"]*)"')
    rule_start = re.compile(r'^(?:private\s+)?rule\s+(\w+)')
    meta: dict[str, dict] = {}

    for rules_dir in rules_dirs:
        if not rules_dir.exists():
            continue
        for yar_file in sorted(rules_dir.glob("*.yar")):
            current_rule = None
            current_meta: dict[str, str] = {}
            in_meta = False

            for line in yar_file.read_text(encoding="utf-8", errors="replace").splitlines():
                m = rule_start.match(line)
                if m:
                    if current_rule:
                        meta[current_rule] = current_meta
                    current_rule = m.group(1)
                    current_meta = {}
                    in_meta = False
                    continue
                if line.strip() == "meta:":
                    in_meta = True
                    continue
                if in_meta:
                    if line.strip() in ("strings:", "condition:"):
                        in_meta = False
                        continue
                    m2 = meta_re.match(line)
                    if m2:
                        current_meta[m2.group(1)] = m2.group(2)

            if current_rule:
                meta[current_rule] = current_meta

    return meta


# ── Rule compilation ──────────────────────────────────────────────────────────

def _compile_rules(rules_dirs: list[Path], out_file: Path) -> Path | None:
    """
    Compile all .yar files from *rules_dirs* into a single binary .rules file.
    Returns the compiled path on success, None if yarac is unavailable or fails.
    """
    yarac = _yarac_bin()
    if not yarac:
        return None

    yar_files: list[str] = []
    for d in rules_dirs:
        if d.exists():
            yar_files.extend(str(f) for f in sorted(d.glob("*.yar")))

    if not yar_files:
        return None

    try:
        r = subprocess.run(
            [yarac] + yar_files + [str(out_file)],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0 and out_file.exists():
            print(f"[yara] Compiled {len(yar_files)} rule file(s) → {out_file.name}")
            return out_file
        if r.stderr:
            print(f"[yara] yarac warning: {r.stderr.strip()[:200]}", file=sys.stderr)
    except Exception as exc:
        print(f"[yara] yarac failed ({exc}); using .yar files directly", file=sys.stderr)

    return None


# ── YARA scanning ─────────────────────────────────────────────────────────────

def _run_yara(
    target: Path,
    rules_dirs: list[Path],
    compiled_path: Path | None,
    *,
    threads: int = 2,
    fast: bool = False,
    strings: bool = False,
    timeout: int = 120,
    tags: list[str] | None = None,
) -> tuple[list[tuple[str, str]], list[str]]:
    """
    Run YARA against *target*.
    Returns (matches, string_lines) where matches are (rule_name, target_path) tuples
    and string_lines are raw output lines from -s mode.
    """
    yara = _yara_bin()
    if not yara:
        return [], []

    base_flags: list[str] = [f"-p {threads}", f"--timeout {timeout}"]
    if fast:
        base_flags.append("-f")
    if target.is_dir():
        base_flags.append("-r")
    if tags:
        for t in tags:
            base_flags.extend(["-t", t])

    def _invoke(extra_flags: list[str], rule_arg: str | None, rule_file: Path | None) -> list[str]:
        if rule_arg:
            cmd = [yara] + base_flags + extra_flags + [rule_arg, str(target)]
        elif rule_file:
            cmd = [yara] + base_flags + extra_flags + [str(rule_file), str(target)]
        else:
            return []
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 10)
            return r.stdout.splitlines()
        except subprocess.TimeoutExpired:
            print(f"[yara] Timed out scanning {target.name}", file=sys.stderr)
            return []
        except Exception as exc:
            print(f"[yara] Error: {exc}", file=sys.stderr)
            return []

    rule_arg = f"-C {compiled_path}" if compiled_path else None

    # Primary scan
    if compiled_path:
        raw_lines = _invoke([], f"-C {compiled_path}", None)
    else:
        raw_lines = []
        for d in rules_dirs:
            if not d.exists():
                continue
            for yar_file in sorted(d.glob("*.yar")):
                raw_lines.extend(_invoke([], None, yar_file))

    # String-offset scan (separate invocation with -s)
    string_lines: list[str] = []
    if strings:
        if compiled_path:
            string_lines = _invoke(["-s"], f"-C {compiled_path}", None)
        else:
            for d in rules_dirs:
                if not d.exists():
                    continue
                for yar_file in sorted(d.glob("*.yar")):
                    string_lines.extend(_invoke(["-s"], None, yar_file))

    # Parse match lines: "RuleName [tags] /path/to/target"
    matches: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in raw_lines:
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) < 1:
            continue
        rule_name = re.sub(r'\[.*?\]', '', parts[0]).strip()
        target_str = parts[1].strip() if len(parts) > 1 else str(target)
        if rule_name:
            key = f"{rule_name}:{target_str}"
            if key not in seen:
                seen.add(key)
                matches.append((rule_name, target_str))

    return matches, string_lines


# ── Parallel target scanning ──────────────────────────────────────────────────

def scan_target(
    target: Path,
    rule_meta: dict[str, dict],
    rules_dirs: list[Path],
    compiled_path: Path | None,
    *,
    threads: int = 2,
    fast: bool = False,
    strings: bool = False,
    timeout: int = 120,
) -> tuple[list[dict], list[str]]:
    """Scan one target; return (match_records, string_lines)."""
    if not target.exists():
        return [], []

    matches, string_lines = _run_yara(
        target, rules_dirs, compiled_path,
        threads=threads, fast=fast, strings=strings, timeout=timeout,
    )

    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    records: list[dict] = []
    for rule_name, target_str in matches:
        m = rule_meta.get(rule_name, {})
        records.append({
            "rule":         rule_name,
            "target":       str(target),
            "target_name":  Path(target_str).name,
            "rule_file":    "",
            "severity":     m.get("severity", "medium"),
            "description":  m.get("description", ""),
            "category":     m.get("category", ""),
            "mitre_att":    m.get("mitre_att", ""),
            "timestamp_utc": now,
        })

    return records, string_lines


def _scan_targets_parallel(
    targets: list[Path],
    rule_meta: dict[str, dict],
    rules_dirs: list[Path],
    compiled_path: Path | None,
    *,
    threads: int = 2,
    fast: bool = False,
    strings: bool = False,
    timeout: int = 120,
) -> tuple[list[dict], list[str]]:
    """Scan multiple targets concurrently."""
    all_records: list[dict] = []
    all_strings: list[str] = []

    # Use max 4 worker threads for parallel target scanning
    workers = min(len(targets), 4)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                scan_target, t, rule_meta, rules_dirs, compiled_path,
                threads=threads, fast=fast, strings=strings, timeout=timeout,
            ): t
            for t in targets
        }
        for fut in as_completed(futures):
            records, str_lines = fut.result()
            all_records.extend(records)
            all_strings.extend(str_lines)

    return all_records, all_strings


# ── False-positive testing ────────────────────────────────────────────────────

def run_fp_test(
    rules_dirs: list[Path],
    compiled_path: Path | None,
    output_dir: Path,
) -> int:
    """Scan /usr/bin and /usr/lib for false positives. Returns hit count."""
    fp_targets = [Path("/usr/bin"), Path("/usr/lib")]
    fp_out = output_dir / "fp_test.txt"
    total_hits = 0

    with fp_out.open("w", encoding="utf-8") as fh:
        for fp_dir in fp_targets:
            if not fp_dir.exists():
                continue
            records, _ = scan_target(
                fp_dir, {}, rules_dirs, compiled_path,
                threads=2, fast=True, strings=False, timeout=30,
            )
            for r in records:
                fh.write(f"{r['rule']}\t{r['target_name']}\n")
                total_hits += 1

    if total_hits > 0:
        print(
            f"[yara] FP test: {total_hits} hit(s) on system dirs — "
            f"review {fp_out} before using on evidence",
            file=sys.stderr,
        )
    else:
        print("[yara] FP test: 0 hits on system dirs — rules look clean")

    return total_hits


# ── Output writers ────────────────────────────────────────────────────────────

def _write_json(matches: list[dict], output_dir: Path, stem: str, pcap: Path) -> None:
    critical = sum(1 for m in matches if m["severity"] == "critical")
    high     = sum(1 for m in matches if m["severity"] == "high")
    medium   = sum(1 for m in matches if m["severity"] == "medium")
    low      = sum(1 for m in matches if m["severity"] == "low")
    doc = {
        "generated_utc":  datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pcap":           str(pcap),
        "stem":           stem,
        "total_matches":  len(matches),
        "critical_count": critical,
        "high_count":     high,
        "medium_count":   medium,
        "low_count":      low,
        "matches":        matches,
    }
    (output_dir / "yara_matches.json").write_text(
        json.dumps(doc, indent=2), encoding="utf-8"
    )


def _write_csv(matches: list[dict], output_dir: Path) -> None:
    fields = [
        "rule", "target_name", "rule_file", "severity",
        "description", "category", "mitre_att", "timestamp_utc",
    ]
    with (output_dir / "yara_matches.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(matches)


def _write_report(matches: list[dict], output_dir: Path, stem: str, pcap: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        f"# YARA Scan Report — {stem}",
        "",
        f"**PCAP:** `{pcap}`  ",
        f"**Generated:** {now}  ",
        f"**Total matches:** {len(matches)}  ",
        "",
    ]

    if not matches:
        lines += ["No YARA rule matches detected.", "", "---", ""]
        (output_dir / "yara_report.md").write_text("\n".join(lines), encoding="utf-8")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sev_counts: dict[str, int] = {}
    for m in matches:
        sev_counts[m["severity"]] = sev_counts.get(m["severity"], 0) + 1

    lines += ["## Summary", ""]
    lines.append("| Severity | Matches |")
    lines.append("|----------|---------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
    lines.append("")

    sorted_matches = sorted(
        matches, key=lambda m: (sev_order.get(m["severity"], 4), m["rule"])
    )

    lines += ["## Match Details", ""]
    lines.append("| Severity | Rule | Target | Category | MITRE |")
    lines.append("|----------|------|--------|----------|-------|")
    for m in sorted_matches:
        lines.append(
            f"| {m['severity'].upper()} | {m['rule']} | `{m['target_name']}` "
            f"| {m['category']} | {m['mitre_att']} |"
        )
    lines.append("")

    critical_high = [m for m in sorted_matches if m["severity"] in ("critical", "high")]
    if critical_high:
        lines += ["## Threat Detail", ""]
        for m in critical_high:
            lines += [
                f"**{m['rule']}** — {m['severity'].upper()}",
                "",
                f"- Target: `{m['target_name']}`",
                f"- Rule file: `{m['rule_file'] or '—'}`",
                f"- Description: {m['description'] or '—'}",
                f"- Category: {m['category'] or '—'}",
                f"- MITRE ATT&CK: {m['mitre_att'] or '—'}",
                "",
            ]

    lines += ["---", ""]
    (output_dir / "yara_report.md").write_text("\n".join(lines), encoding="utf-8")


def _write_strings(string_lines: list[str], output_dir: Path) -> None:
    if string_lines:
        (output_dir / "yara_strings.txt").write_text(
            "\n".join(string_lines) + "\n", encoding="utf-8"
        )


def _write_vault(matches: list[dict], stem: str, case_id: str) -> None:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from knowledge_extractor import record_ttp
    except ImportError:
        return

    seen_ttps: set[str] = set()
    for m in matches:
        if m["severity"] not in ("critical", "high"):
            continue
        tid = m.get("mitre_att", "")
        if not tid or tid in seen_ttps:
            continue
        seen_ttps.add(tid)
        ctx = f"YARA rule {m['rule']} matched in {stem}: {m['description']}"
        try:
            record_ttp(tid, m.get("category", "YARA Match"), ctx, case_id)
        except Exception:
            pass


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    pcap: Path,
    stem: str,
    output_dir: Path,
    case_id: str = "",
    no_vault: bool = False,
    extra_targets: list[Path] | None = None,
    community_rules: Path | None = None,
    threads: int = 2,
    fast: bool = False,
    strings: bool = False,
    timeout: int = 120,
    fp_test: bool = False,
) -> dict:
    """
    Scan a PCAP (and optionally extracted files, directories, memory images) with YARA.

    Args:
        pcap:             PCAP file path.
        stem:             Output directory stem.
        output_dir:       Where to write results.
        case_id:          Optional case ID for vault recording.
        no_vault:         Skip Obsidian vault recording.
        extra_targets:    Additional files/directories/memory images to scan.
        community_rules:  Path to extra .yar directory (e.g. /opt/signature-base/).
        threads:          YARA parallel threads (-p).
        fast:             Fast mode — first match per rule only (-f).
        strings:          Capture matching string offsets (-s).
        timeout:          Per-target timeout in seconds.
        fp_test:          Run false-positive test against /usr/bin before main scan.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    yara = _yara_bin()
    if not yara:
        print(
            f"[yara] YARA not found at {YARA_BIN} and not in PATH.\n"
            "[yara] Install: sudo apt install yara",
            file=sys.stderr,
        )
        _write_json([], output_dir, stem, pcap)
        _write_csv([], output_dir)
        _write_report([], output_dir, stem, pcap)
        return {"total": 0, "matches": []}

    # Build list of rule directories
    rules_dirs = [RULES_DIR]
    if community_rules and community_rules.exists():
        rules_dirs.append(community_rules)
        print(f"[yara] Community rules: {community_rules}")

    # Parse metadata from all rule files
    print(f"[yara] Parsing rule metadata …")
    rule_meta = _parse_rule_metadata(rules_dirs)

    # Attempt yarac pre-compilation
    compiled_path = _compile_rules(rules_dirs, output_dir / "compiled.rules")

    # False-positive test
    if fp_test:
        run_fp_test(rules_dirs, compiled_path, output_dir)

    # Build target list
    targets: list[Path] = []

    if pcap.exists():
        targets.append(pcap)

    extracted_root = ANALYSIS_DIR / "file_hashes" / stem / "files"
    if extracted_root.exists():
        extracted = [f for f in extracted_root.rglob("*") if f.is_file()]
        if extracted:
            print(f"[yara] Queuing {len(extracted)} extracted file(s) for scanning …")
            targets.extend(extracted)

    if extra_targets:
        for et in extra_targets:
            et = Path(et)
            if et.exists():
                targets.append(et)
                print(f"[yara] Extra target: {et}")
            else:
                print(f"[yara] WARNING: extra target not found: {et}", file=sys.stderr)

    if not targets:
        print("[yara] No targets to scan.", file=sys.stderr)
        _write_json([], output_dir, stem, pcap)
        _write_csv([], output_dir)
        _write_report([], output_dir, stem, pcap)
        return {"total": 0, "matches": []}

    # Scan
    print(f"[yara] Scanning {len(targets)} target(s) …")
    all_matches, all_strings = _scan_targets_parallel(
        targets, rule_meta, rules_dirs, compiled_path,
        threads=threads, fast=fast, strings=strings, timeout=timeout,
    )

    print(f"[yara] {len(all_matches)} match(es) found")
    _write_json(all_matches, output_dir, stem, pcap)
    _write_csv(all_matches, output_dir)
    _write_report(all_matches, output_dir, stem, pcap)
    if strings:
        _write_strings(all_strings, output_dir)

    if not no_vault and case_id and all_matches:
        _write_vault(all_matches, stem, case_id)

    print(f"[yara] Output: {output_dir}")
    return {"total": len(all_matches), "matches": all_matches}


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="YARA PCAP scanner — scans PCAP, extracted files, dirs, memory images",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/fan_yara_pcap.py capture.pcap\n"
            "  python3 lib/fan_yara_pcap.py capture.pcap --extra-targets /mnt/windows/ memory.img\n"
            "  python3 lib/fan_yara_pcap.py capture.pcap --threads 4 --fast --strings\n"
            "  python3 lib/fan_yara_pcap.py capture.pcap --fp-test --community-rules /opt/signature-base/yara/\n"
        ),
    )
    p.add_argument("pcap",                 help="Path to PCAP file")
    p.add_argument("--stem",               help="Output stem (default: PCAP basename)")
    p.add_argument("--case-id",            default="", metavar="ID")
    p.add_argument("--output-dir",         metavar="DIR")
    p.add_argument("--no-vault",           action="store_true")
    p.add_argument("--extra-targets",      nargs="+", metavar="PATH",
                   help="Additional files, directories, or memory images to scan")
    p.add_argument("--community-rules",    metavar="DIR",
                   help="Path to extra .yar directory (e.g. /opt/signature-base/yara/)")
    p.add_argument("--threads",  "-p",     type=int, default=2, metavar="N",
                   help="YARA parallel threads (default: 2)")
    p.add_argument("--fast",     "-f",     action="store_true",
                   help="Fast mode: stop after first match per rule")
    p.add_argument("--strings",  "-s",     action="store_true",
                   help="Capture matching string offsets (written to yara_strings.txt)")
    p.add_argument("--timeout",            type=int, default=120, metavar="SEC",
                   help="Per-target scan timeout in seconds (default: 120)")
    p.add_argument("--fp-test",            action="store_true",
                   help="Run false-positive test against /usr/bin before main scan")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    pcap = Path(args.pcap).resolve()
    stem = args.stem or pcap.stem
    odir = Path(args.output_dir) if args.output_dir else (ANALYSIS_DIR / OUTPUT_SUBDIR / stem)
    extra = [Path(t) for t in args.extra_targets] if args.extra_targets else None
    comm  = Path(args.community_rules) if args.community_rules else None
    analyze(
        pcap=pcap,
        stem=stem,
        output_dir=odir,
        case_id=args.case_id,
        no_vault=args.no_vault,
        extra_targets=extra,
        community_rules=comm,
        threads=args.threads,
        fast=args.fast,
        strings=args.strings,
        timeout=args.timeout,
        fp_test=args.fp_test,
    )
