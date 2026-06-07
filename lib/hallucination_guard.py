#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
hallucination_guard.py — Per-finding confidence tier system for FanGetFameFast.

Provides architectural (code-enforced) evidence quality tracking for every finding
produced by the FAN / FAME / FAST analysis pipeline.

Four tiers (assigned at parse time by report generators, not by Claude prompts):
  CONFIRMED    — Direct tool output (Volatility plugin, TSK artifact, Suricata alert, YARA match)
  INFERRED     — One analytical step from confirmed evidence (parent-child deduction, correlation)
  ASSUMED      — Analytical judgement with no direct tool output ([ASSUMPTION] in research notes)
  UNVERIFIABLE — Evidence unavailable (DKOM active, plugin skipped, image section missing)

Confidence assignment rules (coded, not prompted):
  Source                                            → Tier
  Direct Volatility plugin output (psscan, netscan) → CONFIRMED
  Direct TSK / bulk_extractor output                → CONFIRMED
  Suricata alert or YARA match                      → CONFIRMED
  Derived parent-child / time-proximity relation    → INFERRED
  Cross-module correlation match                    → INFERRED
  [ASSUMPTION] tag in research notes                → ASSUMED
  Plugin skipped / DKOM active / evidence absent    → UNVERIFIABLE

Usage:
    from lib.hallucination_guard import (
        tag_finding, ConfidenceTier, render_badge,
        render_confidence_summary, reset_counter,
    )
    f = tag_finding("PID 3164 (rundll32.exe) spawned by powershell.exe",
                    ConfidenceTier.CONFIRMED, ["RN-002"], ["volatility3/psscan"], ["fame"])
    print(render_badge(f.tier))  # 🟢 CONFIRMED

Self-test:
    python3 lib/hallucination_guard.py
"""
from __future__ import annotations

import sys
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Tuple


class ConfidenceTier(Enum):
    CONFIRMED    = "CONFIRMED"
    INFERRED     = "INFERRED"
    ASSUMED      = "ASSUMED"
    UNVERIFIABLE = "UNVERIFIABLE"


_TIER_ORDER: List[ConfidenceTier] = [
    ConfidenceTier.CONFIRMED,
    ConfidenceTier.INFERRED,
    ConfidenceTier.ASSUMED,
    ConfidenceTier.UNVERIFIABLE,
]

_TIER_BADGE = {
    ConfidenceTier.CONFIRMED:    "🟢 CONFIRMED",
    ConfidenceTier.INFERRED:     "🟡 INFERRED",
    ConfidenceTier.ASSUMED:      "🟠 ASSUMED",
    ConfidenceTier.UNVERIFIABLE: "🔴 UNVERIFIABLE",
}

# Keyword pairs used for lightweight contradiction detection.
# Each tuple is (positive_keywords, negative_keywords). If finding A matches
# a positive set and finding B matches the opposing negative set, they are flagged.
_CONTRADICTION_PAIRS: List[Tuple[set, set]] = [
    (
        {"running", "active", "established", "found", "detected", "present", "observed"},
        {"not found", "absent", "hidden", "not detected", "not running", "no active"},
    ),
    (
        {"connection established", "outbound connection", "c2 connection"},
        {"no network connection", "no connections", "no outbound"},
    ),
    (
        {"process present", "pid found", "in process list"},
        {"process missing", "no process", "dkom", "unlinked"},
    ),
    (
        {"file exists", "artifact found", "carved", "recovered"},
        {"file deleted", "file missing", "no artifact", "not recovered"},
    ),
]


@dataclass
class Finding:
    id: str                          # FND-001
    text: str
    tier: ConfidenceTier
    source_steps: List[str]          # e.g. ["RN-002", "RN-005"]
    source_tools: List[str]          # e.g. ["volatility3/psscan", "suricata"]
    modules: List[str]               # e.g. ["fame", "fan"]
    contradictions: List[str] = field(default_factory=list)   # IDs of contradicting Findings
    single_source_warning: bool = False


_finding_counter: List[int] = [0]


def reset_counter() -> None:
    """Reset finding counter. Call at the start of each report generation run."""
    _finding_counter[0] = 0


def tag_finding(
    text: str,
    tier: ConfidenceTier,
    source_steps: List[str] | None = None,
    source_tools: List[str] | None = None,
    modules: List[str] | None = None,
) -> Finding:
    """Create a tagged Finding with a unique FND-NNN identifier."""
    _finding_counter[0] += 1
    return Finding(
        id=f"FND-{_finding_counter[0]:03d}",
        text=text,
        tier=tier,
        source_steps=source_steps or [],
        source_tools=source_tools or [],
        modules=modules or [],
    )


def render_badge(tier: ConfidenceTier) -> str:
    """Return the markdown badge string for a confidence tier."""
    return _TIER_BADGE[tier]


def degrade_confidence(tiers: List[ConfidenceTier]) -> ConfidenceTier:
    """Return the lowest-confidence tier in the list (worst-case inference chain)."""
    if not tiers:
        return ConfidenceTier.UNVERIFIABLE
    return max(tiers, key=lambda t: _TIER_ORDER.index(t))


def detect_contradictions(findings: List[Finding]) -> List[Tuple[Finding, Finding]]:
    """
    Return pairs of Findings whose text signals a contradiction.

    Uses keyword-based heuristic: finding A contains a positive-assertion keyword
    and finding B contains the opposing negative-assertion keyword. Operates on
    lowercased finding text.
    """
    pairs: List[Tuple[Finding, Finding]] = []
    for i, a in enumerate(findings):
        for b in findings[i + 1:]:
            a_lower = a.text.lower()
            b_lower = b.text.lower()
            for pos_set, neg_set in _CONTRADICTION_PAIRS:
                a_pos = any(kw in a_lower for kw in pos_set)
                a_neg = any(kw in a_lower for kw in neg_set)
                b_pos = any(kw in b_lower for kw in pos_set)
                b_neg = any(kw in b_lower for kw in neg_set)
                if (a_pos and b_neg) or (a_neg and b_pos):
                    if (a, b) not in pairs:
                        pairs.append((a, b))
                    break
    return pairs


def flag_single_source(findings: List[Finding]) -> List[Finding]:
    """
    Mark findings with single_source_warning=True when only one module supports them.
    Returns the flagged subset. Modifies findings in-place.
    """
    flagged = []
    for f in findings:
        if len(set(f.modules)) == 1:
            f.single_source_warning = True
            flagged.append(f)
    return flagged


def render_confidence_summary(
    findings: List[Finding],
    module_label: str = "",
) -> str:
    """
    Render a Markdown section that shows per-finding confidence tiers, source
    references, single-source warnings, and any detected contradictions.

    Append this section at the end of any module or combined report.
    """
    if not findings:
        return ""

    # Tier counts
    counts = {t: 0 for t in ConfidenceTier}
    for f in findings:
        counts[f.tier] += 1
    total = len(findings)
    confirmed_pct = int(100 * counts[ConfidenceTier.CONFIRMED] / total) if total else 0

    contradictions = detect_contradictions(findings)
    flag_single_source(findings)
    single_source = [f for f in findings if f.single_source_warning]

    lines: list[str] = []
    a = lines.append

    a("---")
    a("")
    heading = f"## Hallucination Guard{' — ' + module_label if module_label else ''}"
    a(heading)
    a("")
    a("> Architectural (code-enforced) evidence quality audit. Every finding below was")
    a("> tagged by the report generator at parse time — not by Claude narrative instructions.")
    a("> Tiers: 🟢 direct tool output · 🟡 one inference step · 🟠 no direct evidence · 🔴 data unavailable")
    a("")
    a("### Confidence tier summary")
    a("")
    a("| Tier | Count | % of findings |")
    a("|------|-------|---------------|")
    for tier in _TIER_ORDER:
        pct = int(100 * counts[tier] / total) if total else 0
        badge = _TIER_BADGE[tier]
        a(f"| {badge} | {counts[tier]} | {pct}% |")
    a("")
    a(f"**IR confidence score: {confirmed_pct}% confirmed** "
      f"({counts[ConfidenceTier.CONFIRMED]} of {total} findings backed by direct tool output)")
    a("")

    a("### Finding index")
    a("")
    a("| ID | Tier | Source steps | Source tools | Modules | Finding (excerpt) |")
    a("|----|------|-------------|-------------|---------|------------------|")
    for f in findings:
        steps = ", ".join(f.source_steps) if f.source_steps else "—"
        tools = ", ".join(f.source_tools) if f.source_tools else "—"
        mods  = ", ".join(f.modules) if f.modules else "—"
        badge = _TIER_BADGE[f.tier]
        warn  = " ⚠" if f.single_source_warning else ""
        text  = f.text[:90] + ("…" if len(f.text) > 90 else "")
        # Escape pipes in cell values
        text  = text.replace("|", "\\|")
        a(f"| {f.id} | {badge}{warn} | {steps} | {tools} | {mods} | {text} |")
    a("")

    if contradictions:
        a("### ⚠ Detected contradictions")
        a("")
        a("The following finding pairs contain contradictory signals and require analyst review:")
        a("")
        for fa, fb in contradictions:
            a(f"- **{fa.id}** vs **{fb.id}**")
            a(f"  - {fa.id}: `{fa.text[:80]}`")
            a(f"  - {fb.id}: `{fb.text[:80]}`")
            a("")

    if single_source:
        a("### ⚠ Single-source findings")
        a("")
        a("These findings are supported by only one module — cross-module confirmation is pending:")
        a("")
        for f in single_source:
            a(f"- **{f.id}** [{_TIER_BADGE[f.tier]}]: {f.text[:90]}")
        a("")

    return "\n".join(lines)


# ── Self-test ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("hallucination_guard self-test...", flush=True)
    errors = 0

    reset_counter()

    f1 = tag_finding(
        "PID 3164 (rundll32.exe) spawned by powershell.exe",
        ConfidenceTier.CONFIRMED, ["RN-002"], ["volatility3/psscan"], ["fame"],
    )
    f2 = tag_finding(
        "Process 3164 made outbound connection established to 203.0.113.42:443",
        ConfidenceTier.CONFIRMED, ["RN-005"], ["volatility3/netscan"], ["fame", "fan"],
    )
    f3 = tag_finding(
        "Attacker is assumed to have exfiltrated data before shutdown",
        ConfidenceTier.ASSUMED, ["RN-009"], [], ["fame"],
    )
    f4 = tag_finding(
        "cmdline not found — DKOM suppressed plugin output",
        ConfidenceTier.UNVERIFIABLE, [], ["volatility3/cmdline"], ["fame"],
    )
    f5 = tag_finding(
        "Parent-child relationship inferred from psscan PPID column",
        ConfidenceTier.INFERRED, ["RN-003"], ["volatility3/psscan"], ["fame"],
    )
    findings = [f1, f2, f3, f4, f5]

    # Badge rendering
    for tier in ConfidenceTier:
        assert render_badge(tier).startswith(("🟢", "🟡", "🟠", "🔴")), "Badge prefix wrong"
    print("  ✓ badge rendering")

    # Degrade confidence
    result = degrade_confidence([ConfidenceTier.CONFIRMED, ConfidenceTier.ASSUMED, ConfidenceTier.INFERRED])
    assert result == ConfidenceTier.ASSUMED, f"Expected ASSUMED, got {result}"
    result2 = degrade_confidence([ConfidenceTier.CONFIRMED, ConfidenceTier.CONFIRMED])
    assert result2 == ConfidenceTier.CONFIRMED
    print("  ✓ degrade_confidence")

    # Contradiction detection — f2 has "connection established", f4 has "not found"
    contras = detect_contradictions(findings)
    assert len(contras) >= 1, f"Expected >= 1 contradiction, got {len(contras)}"
    print(f"  ✓ contradiction detection ({len(contras)} pair(s) found)")

    # Single-source flagging — f1, f3, f4, f5 are fame-only; f2 is fame+fan
    flagged = flag_single_source(findings)
    single_ids = {f.id for f in flagged}
    assert f2.id not in single_ids, "f2 (multi-module) should not be flagged"
    assert f1.id in single_ids, "f1 (single-module) should be flagged"
    print(f"  ✓ single-source flagging ({len(flagged)} finding(s) flagged)")

    # Counter isolation
    reset_counter()
    fx = tag_finding("test", ConfidenceTier.CONFIRMED, [], [], [])
    assert fx.id == "FND-001", f"Expected FND-001 after reset, got {fx.id}"
    print("  ✓ counter reset")

    # Summary rendering
    reset_counter()
    findings2 = [
        tag_finding("Suricata alert: ET MALWARE CobaltStrike beacon", ConfidenceTier.CONFIRMED,
                    ["RN-001"], ["suricata"], ["fan"]),
        tag_finding("DNS query to known C2 domain (inferred from pattern)", ConfidenceTier.INFERRED,
                    ["RN-002"], ["tshark/dns"], ["fan"]),
    ]
    summary = render_confidence_summary(findings2, "FAN self-test")
    assert "Hallucination Guard" in summary
    assert "CONFIRMED" in summary
    assert "IR confidence score" in summary
    print("  ✓ render_confidence_summary")

    print("\nPASS", flush=True)
    sys.exit(0)
