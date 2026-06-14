#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
"""
verify_claims.py — Automated claim-traceability audit for FanGetFameFast reports.

For every case found under `reports/` and `archive/`, locates that case's
campaign/incident/module report(s) and finds every line that cites a research
step (RN-NNN, EVT-NNN, RF-NNN, FND-NNN). From each such line, "hard" tokens are
extracted — timestamps, byte counts, IPv4 addresses, hex strings (hashes/MACs),
dates, frame numbers, tcp.stream numbers, and MITRE technique IDs. Each token is
checked for verbatim presence anywhere in that case's research notes / narrative /
correlation files (the "haystack"). Tokens that don't appear anywhere in the
haystack are flagged as UNVERIFIED — candidates for a hallucinated or transposed
detail that need a human read.

This is a narrowing tool, not a verdict: a flagged token may be a legitimate
synthesis (e.g. a number computed from two source numbers) — it just means the
exact string wasn't found verbatim and needs eyes on it.

Cases and files are discovered dynamically from the filesystem, so this script
can simply be re-run as new investigations are added to `reports/` (and later
moved to `archive/` via `/archive-reports`) without any code changes.

Usage:
    python3 accuracy/verify_claims.py
"""
from __future__ import annotations

import re
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ACCURACY_MD = PROJECT_ROOT / "accuracy" / "accuracy.md"

# Both the live case folder and the archive are scanned — completed
# investigations are moved from `reports/` to `archive/` via `/archive-reports`,
# but their reports remain valid audit targets.
ROOTS = [PROJECT_ROOT / "reports", PROJECT_ROOT / "archive"]

# Case IDs in scope for this audit, taken from accuracy.md's scope table
# (`| \`CASE-ID\` | ... |` rows). Keeps the audit aligned with the cases that
# accuracy.md actually discusses — older/duplicate archived runs of the same
# investigations are excluded automatically. Update accuracy.md's scope table
# (not this file) when the audited case set changes.
SCOPE_CASE_RE = re.compile(r"^\|\s*`([A-Za-z0-9._-]+)`\s*\|")


def load_scope_case_ids() -> set[str]:
    text = ACCURACY_MD.read_text(encoding="utf-8", errors="replace") if ACCURACY_MD.exists() else ""
    return {m.group(1) for line in text.splitlines() if (m := SCOPE_CASE_RE.match(line))}

# Directories under a root that are not case folders (raw evidence dumps,
# zipped exports, etc.) and should be skipped.
SKIP_SUFFIXES = ("_evidence", "_raw")

# Sub-paths that should never be treated as audit/haystack sources: working
# copies of analysis output and the chain-of-evidence chat transcript.
EXCLUDED_PARTS = {"analysis", "documents"}

AUDIT_PATTERNS_ROOT = ("*_campaign_report.md", "*_combined_report.md")
AUDIT_PATTERNS_FALLBACK = (
    "*_incident_report.md",
    "*_fast_report.md",
    "*_fame_report.md",
    "*_fan_report.md",
)
HAYSTACK_PATTERNS = ("*_research_notes.md", "*_narrative.md", "*_correlation.md")

CITATION_RE = re.compile(r"\b(?:RN|EVT|RF|FND)-\d{3}\b")

# Token patterns, ordered roughly by specificity (most specific first matters
# less here since we dedupe, but keep hex-hash before plain-hex-ish dates etc.)
TOKEN_PATTERNS = {
    "mac_address": re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b"),
    "ipv4_port": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{2,5}\b"),
    "sha256/hex_hash": re.compile(r"\b[0-9a-fA-F]{16,64}\b"),
    "ipv4": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "date": re.compile(r"\b\d{4}-\d{2}-\d{2}\b"),
    "time": re.compile(r"\b\d{1,2}:\d{2}(?::\d{2}(?:\.\d+)?)?(?:Z|UTC)?\b"),
    "byte_count": re.compile(r"\b\d{1,3}(?:,\d{3})+\b"),
    "frame_number": re.compile(r"\bframe\s+\d+\b", re.IGNORECASE),
    "tcp_stream": re.compile(r"\btcp\.stream\s+\d+\b", re.IGNORECASE),
    "mitre_technique": re.compile(r"\bT\d{4}(?:\.\d{3})?\b"),
}

# Tokens too generic to be meaningful on their own — skip if they match these.
NOISE_VALUES = {
    "00:00", "00:00:00", "01:01", "0.0.0.0", "255.255.255.255",
}


def load_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


def _is_excluded(path: Path, case_dir: Path) -> bool:
    rel_parts = path.relative_to(case_dir).parts
    return any(part in EXCLUDED_PARTS for part in rel_parts)


def find_audit_files(case_dir: Path) -> list[Path]:
    """Campaign/combined report(s) at the case root, else per-module reports."""
    candidates: list[Path] = []
    for pattern in AUDIT_PATTERNS_ROOT:
        candidates.extend(case_dir.glob(pattern))
    if candidates:
        return sorted(set(candidates))

    for pattern in AUDIT_PATTERNS_FALLBACK:
        for p in case_dir.rglob(pattern):
            if not _is_excluded(p, case_dir):
                candidates.append(p)
    return sorted(set(candidates))


def find_haystack_files(case_dir: Path) -> list[Path]:
    files: list[Path] = []
    for pattern in HAYSTACK_PATTERNS:
        for p in case_dir.rglob(pattern):
            if not _is_excluded(p, case_dir):
                files.append(p)
    return sorted(set(files))


def discover_cases() -> dict[str, dict]:
    """Map case label -> {dir, audit: [Path], haystack: [Path]}."""
    scope = load_scope_case_ids()
    cases: dict[str, dict] = {}
    for root in ROOTS:
        if not root.exists():
            continue
        for case_dir in sorted(root.iterdir()):
            if not case_dir.is_dir():
                continue
            name = case_dir.name
            if name.endswith(SKIP_SUFFIXES) or ".zip" in name:
                continue
            if scope and name not in scope:
                continue

            audit = find_audit_files(case_dir)
            if not audit:
                continue
            haystack = find_haystack_files(case_dir)

            label = name
            if label in cases:
                label = f"{name} ({root.name})"
            cases[label] = {"dir": case_dir, "audit": audit, "haystack": haystack}
    return cases


def extract_tokens(line: str) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    seen_values: set[str] = set()
    for kind, pattern in TOKEN_PATTERNS.items():
        matches = []
        for m in pattern.finditer(line):
            v = m.group(0)
            if v in NOISE_VALUES or v in seen_values:
                continue
            seen_values.add(v)
            matches.append(v)
        if matches:
            found[kind] = matches
    return found


def audit_case(label: str, cfg: dict) -> list[str]:
    case_dir: Path = cfg["dir"]
    haystack = "\n".join(load_text(f) for f in cfg["haystack"])

    out: list[str] = []
    out.append(f"## {label}")
    out.append("")
    if cfg["haystack"]:
        out.append(
            "Haystack: "
            + ", ".join(f"`{f.relative_to(case_dir)}`" for f in cfg["haystack"])
        )
    else:
        out.append("Haystack: **none found** — all cited tokens will be flagged.")
    out.append("")

    for audit_path in cfg["audit"]:
        audit_rel = str(audit_path.relative_to(case_dir))
        text = load_text(audit_path)
        if not text:
            out.append(f"- `{audit_rel}`: **NOT FOUND**")
            continue

        cited_lines = [
            line for line in text.splitlines()
            if CITATION_RE.search(line) and "|----" not in line
        ]

        flagged_count = 0
        checked_lines = 0
        verified_rows: list[str] = []
        unverified_blocks: list[str] = []

        for line in cited_lines:
            tokens = extract_tokens(line)
            if not tokens:
                continue
            checked_lines += 1

            line_results: list[tuple[str, str, bool]] = []
            for kind, values in tokens.items():
                for v in values:
                    line_results.append((kind, v, v in haystack))

            citations = ", ".join(sorted(set(CITATION_RE.findall(line))))
            excerpt = line.strip()
            if len(excerpt) > 160:
                excerpt = excerpt[:160] + "…"
            excerpt = excerpt.replace("|", "\\|")

            unverified = [(k, v) for k, v, ok in line_results if not ok]
            verified = [(k, v) for k, v, ok in line_results if ok]

            if unverified:
                flagged_count += 1
                block = []
                block.append(f"### UNVERIFIED — {audit_rel} (cites {citations})")
                block.append("")
                block.append(f"> {line.strip()[:200]}")
                block.append("")
                block.append("Tokens not found verbatim in research notes / narrative / correlation:")
                for kind, v in unverified:
                    block.append(f"- `{v}` ({kind})")
                if verified:
                    block.append("")
                    block.append("Other tokens on this line that *were* verified:")
                    for kind, v in verified:
                        block.append(f"- `{v}` ({kind})")
                block.append("")
                unverified_blocks.append("\n".join(block))
            else:
                token_str = ", ".join(f"`{v}` ({kind})" for kind, v in verified)
                verified_rows.append(f"| {citations} | {token_str} | {excerpt} |")

        out.extend(unverified_blocks)

        if verified_rows:
            out.append(f"### VERIFIED — {audit_rel}")
            out.append("")
            out.append(
                "Every extracted token on these cited lines was found verbatim in "
                "the research notes / narrative / correlation files for this case."
            )
            out.append("")
            out.append("| Citations | Verified tokens | Excerpt |")
            out.append("|-----------|------------------|---------|")
            out.extend(verified_rows)
            out.append("")

        out.append(
            f"- `{audit_rel}`: {len(cited_lines)} cited lines, "
            f"{checked_lines} contained checkable tokens, "
            f"{checked_lines - flagged_count} fully verified, "
            f"{flagged_count} flagged for review"
        )
        out.append("")

    return out


def main() -> None:
    lines: list[str] = []
    lines.append("# Claim Traceability Audit (automated)")
    lines.append("")
    lines.append(
        "Generated by `accuracy/verify_claims.py`. Cases and report/research-note "
        "files are discovered dynamically from `reports/` and `archive/` — re-run "
        "this script after any new investigation to refresh this file. For every "
        "line in a discovered campaign/incident/module report that cites an "
        "`RN-`/`EVT-`/`RF-`/`FND-` step, every timestamp, byte count, IP, hash, "
        "date, frame/stream number, and MITRE technique ID was checked for "
        "verbatim presence in that case's research notes, narrative, and "
        "correlation files. A flag means the exact string was not found — it "
        "does not by itself mean the claim is wrong, but it is a candidate for a "
        "hallucinated or transposed detail and should be read by a human."
    )
    lines.append("")
    lines.append("---")
    lines.append("")

    cases = discover_cases()
    for label, cfg in cases.items():
        lines.extend(audit_case(label, cfg))
        lines.append("---")
        lines.append("")

    out_path = PROJECT_ROOT / "accuracy" / "claim_traceability_audit.md"
    out_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out_path} ({len(cases)} cases)")


if __name__ == "__main__":
    main()
