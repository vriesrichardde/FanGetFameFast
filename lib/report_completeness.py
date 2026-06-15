# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
report_completeness.py — Shared "is this investigation actually finished?" gate.

Two independent checks, both required for a report to be considered complete:

  1. check_narrative()      — does ``<case_id>_narrative.md`` exist and contain
                               every section the module's report generator and
                               PPTX/board deck expect?
  2. check_research_notes()  — does ``<case_id>_research_notes.md`` show evidence
                               that Claude actually *read, interpreted, reflected
                               on, and pivoted* — not just that the analyze script
                               auto-logged chain-of-custody hashes for preserved
                               artifacts?

``write_incomplete_marker()`` records the combined result as
``<case_id>_INVESTIGATION_INCOMPLETE.json`` in the module/host case directory, and
removes that marker once both checks pass (self-clearing).

``check_campaign_report()`` flags any case with at least one generated module
report that is missing ``<case_id>_campaign_report.md`` — every case gets a
campaign report, single-module or multi-module.

Used by ``generate_fame_report.py``, ``generate_fast_report.py`` and
``generate_pcap_report.py`` right after they load the narrative, and by the
analyze shell scripts (via ``--check`` CLI mode) to print an ``[OK]``/
``[INCOMPLETE]`` status line.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from lib import path_guard  # noqa: E402
from lib.research_notes import (  # noqa: E402
    _PLACEHOLDER,
    parse_reflections,
    parse_steps,
)

REPORTS_DIR = PROJECT_ROOT / "reports"

# Narrative sections shared by every module's pptx_* board-deck rendering.
SHARED_PPTX_KEYS = [
    "pptx_executive_summary",
    "pptx_risk",
    "pptx_impact",
    "pptx_mitigations",
    "pptx_recommendations",
    "pptx_timeline",
    "pptx_root_cause",
    "pptx_lessons_learned",
]

# Module-specific narrative sections, on top of "attack_timeline" + SHARED_PPTX_KEYS.
MODULE_SECTION_KEYS = {
    "FAME": ["section_processes", "section_network", "section_malware"],
    "FAST": ["section_filesystem", "section_network"],
    "FAN":  [],
}

_EVIDENCE_PRESERVED_RE = re.compile(r"^Evidence preserved: ")


@dataclass
class CompletenessResult:
    """Result of check_narrative()."""
    has_narrative: bool
    missing_sections: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return self.has_narrative and not self.missing_sections


@dataclass
class ReasoningResult:
    """Result of check_research_notes()."""
    missing_reasons: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.missing_reasons


def required_narrative_keys(module: str) -> list[str]:
    """Required ``## <section>`` keys in ``<case_id>_narrative.md`` for *module*."""
    return ["attack_timeline", *MODULE_SECTION_KEYS.get(module.upper(), []), *SHARED_PPTX_KEYS]


def _load_narrative_sections(case_id: str, case_dir: Path) -> dict[str, str]:
    """Parse ``## <heading>`` sections from ``<case_dir>/<case_id>_narrative.md``."""
    path = case_dir / f"{case_id}_narrative.md"
    if not path.exists():
        return {}
    sections: dict[str, str] = {}
    current: str | None = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("## "):
            current = line[3:].strip()
            sections[current] = ""
        elif line.startswith("<!--"):
            continue
        elif current is not None:
            sections[current] += line + "\n"
    return {k: v.strip() for k, v in sections.items()}


def check_narrative(case_id: str, module: str, case_dir: Path) -> CompletenessResult:
    """Check ``<case_id>_narrative.md`` in *case_dir* against the module's schema.

    A section "exists" only if it has non-empty content — an empty ``## heading``
    with nothing under it does not satisfy "write every section even if thin."
    """
    sections = _load_narrative_sections(case_id, Path(case_dir))
    if not sections:
        return CompletenessResult(has_narrative=False, missing_sections=required_narrative_keys(module))

    missing = [key for key in required_narrative_keys(module) if not sections.get(key)]
    return CompletenessResult(has_narrative=True, missing_sections=missing)


def check_research_notes(case_id: str, case_dir: Path) -> ReasoningResult:
    """Check ``<case_id>_research_notes.md`` in *case_dir* for evidence of
    actual reasoning: a finalized summary, at least one reflection, and at
    least one Claude-authored interpretation step (not just auto-logged
    chain-of-custody preservation)."""
    case_dir = Path(case_dir)
    notes_path = case_dir / f"{case_id}_research_notes.md"
    reasons: list[str] = []

    if not notes_path.exists():
        return ReasoningResult(missing_reasons=["research notes file does not exist"])

    text = notes_path.read_text(encoding="utf-8")
    if _PLACEHOLDER in text:
        reasons.append("investigation summary placeholder not finalized (run research_notes.py finalize)")

    if not parse_reflections(case_id, output_dir=str(case_dir)):
        reasons.append("no Reflect entries (mandatory mid-investigation/pre-finalize reflection never ran)")

    steps = parse_steps(case_id, output_dir=str(case_dir))
    if steps and all(_EVIDENCE_PRESERVED_RE.match(s.get("title", "")) for s in steps):
        reasons.append("all steps are auto-logged 'Evidence preserved' entries — no Claude-authored interpretation")

    return ReasoningResult(missing_reasons=reasons)


def check_campaign_report(case_id: str, reports_dir: Path | None = None) -> bool:
    """True if >=1 module has a generated report for *case_id* but
    ``<case_id>_campaign_report.md`` does not exist yet."""
    reports_dir = Path(reports_dir) if reports_dir else REPORTS_DIR
    case_root = reports_dir / case_id
    if not case_root.is_dir():
        return False

    modules_with_reports = 0
    for module in ("FAN", "FAME", "FAST"):
        module_dir = case_root / module
        if module_dir.is_dir() and any(module_dir.glob("*/*_report.md")) or \
                (module_dir.is_dir() and any(module_dir.glob("*/*_incident_report.md"))):
            modules_with_reports += 1

    if modules_with_reports < 1:
        return False

    return not (case_root / f"{case_id}_campaign_report.md").exists()


MARKER_NAME_SUFFIX = "_INVESTIGATION_INCOMPLETE.json"


def write_incomplete_marker(
    case_dir: Path,
    case_id: str,
    narrative_result: CompletenessResult,
    reasoning_result: ReasoningResult,
) -> Path | None:
    """Write (or clear) ``<case_id>_INVESTIGATION_INCOMPLETE.json`` in *case_dir*.

    Returns the marker path if it was written, or ``None`` if both checks
    passed and any pre-existing marker was removed.
    """
    case_dir = Path(case_dir)
    marker_path = case_dir / f"{case_id}{MARKER_NAME_SUFFIX}"

    if narrative_result.ok and reasoning_result.ok:
        if marker_path.exists():
            marker_path.unlink()
        return None

    payload = {
        "case_id": case_id,
        "has_narrative": narrative_result.has_narrative,
        "missing_narrative_sections": narrative_result.missing_sections,
        "missing_reasoning": reasoning_result.missing_reasons,
    }
    path_guard.safe_write_text(marker_path, json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return marker_path


def format_incomplete_banner(narrative_result: CompletenessResult, reasoning_result: ReasoningResult) -> list[str]:
    """Markdown lines for the in-report INCOMPLETE banner, or [] if complete."""
    if narrative_result.ok and reasoning_result.ok:
        return []

    parts = []
    if narrative_result.missing_sections:
        parts.append("narrative sections missing: " + ", ".join(narrative_result.missing_sections))
    if reasoning_result.missing_reasons:
        parts.append("reasoning gaps: " + "; ".join(reasoning_result.missing_reasons))

    return [
        "> ⚠️ **INVESTIGATION INCOMPLETE** — " + " | ".join(parts) + ".",
        "> This report does not yet meet the reporting standard; do not finalize/upload",
        "> until the narrative is written, the research notes show interpretation and",
        "> reflection, and this report is regenerated.",
        "",
    ]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _run_check_cli(case_id: str, module: str, case_dir: Path) -> int:
    narrative_result = check_narrative(case_id, module, case_dir)
    reasoning_result = check_research_notes(case_id, case_dir)
    write_incomplete_marker(case_dir, case_id, narrative_result, reasoning_result)

    if narrative_result.ok and reasoning_result.ok:
        print(f"[OK] {case_id}/{module}: investigation complete")
        return 0

    print(f"[INCOMPLETE] {case_id}/{module}: ", end="")
    details = []
    if narrative_result.missing_sections:
        details.append("missing narrative sections: " + ", ".join(narrative_result.missing_sections))
    if reasoning_result.missing_reasons:
        details.append("reasoning gaps: " + "; ".join(reasoning_result.missing_reasons))
    print(" | ".join(details))
    return 1


def _run_self_test() -> int:
    import tempfile

    failures = 0

    def check(label: str, got: bool, expect: bool) -> None:
        nonlocal failures
        ok = got == expect
        if not ok:
            failures += 1
        print(f"[{'PASS' if ok else 'FAIL'}] {label}: expected {expect}, got {got}")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # --- Fixture (a): complete case (WIN764NFURY-like) ---
        complete_dir = tmp_path / "complete"
        complete_dir.mkdir()
        narrative_lines = ["## attack_timeline", "Attacker did X at time Y.", ""]
        for key in [*MODULE_SECTION_KEYS["FAME"], *SHARED_PPTX_KEYS]:
            narrative_lines += [f"## {key}", f"Content for {key}.", ""]
        (complete_dir / "CASEA_narrative.md").write_text("\n".join(narrative_lines), encoding="utf-8")
        (complete_dir / "CASEA_research_notes.md").write_text(
            "# Research Notes — CASEA\n\n---\n\n## Investigation Log\n\n"
            "### [2026-01-01 00:00:00 UTC] — Step 1 [RN-001]: Reviewed pslist output\n\n"
            "| | |\n|---|---|\n| **Action** | reviewed pslist.txt |\n"
            "| **Why** | identify rogue processes |\n| **Outcome** | nothing unusual |\n"
            "| **Confidence** | direct |\n\n---\n\n"
            "### [2026-01-01 00:10:00 UTC] — Reflect RF-001: mid-investigation review\n\n"
            "| | |\n|---|---|\n| **Re-interpretations** | none |\n| **Open leads** | none |\n\n"
            "---\n\n## Investigation Summary\n\nCase closed, nothing found.\n",
            encoding="utf-8",
        )
        nr = check_narrative("CASEA", "FAME", complete_dir)
        rr = check_research_notes("CASEA", complete_dir)
        check("(a) narrative complete", nr.ok, True)
        check("(a) reasoning complete", rr.ok, True)
        marker = write_incomplete_marker(complete_dir, "CASEA", nr, rr)
        check("(a) marker not written", marker is None, True)

        # --- Fixture (b): narrative-only gap ---
        narrative_only_gap_dir = tmp_path / "narrgap"
        narrative_only_gap_dir.mkdir()
        (narrative_only_gap_dir / "CASEB_research_notes.md").write_text(
            "# Research Notes — CASEB\n\n---\n\n## Investigation Log\n\n"
            "### [2026-01-01 00:00:00 UTC] — Step 1 [RN-001]: Reviewed netstat output\n\n"
            "| | |\n|---|---|\n| **Action** | reviewed netstat.txt |\n"
            "| **Why** | identify C2 connections |\n| **Outcome** | found suspicious IP |\n"
            "| **Confidence** | direct |\n\n---\n\n"
            "### [2026-01-01 00:10:00 UTC] — Reflect RF-001: mid-investigation review\n\n"
            "| | |\n|---|---|\n| **Re-interpretations** | none |\n| **Open leads** | none |\n\n"
            "---\n\n## Investigation Summary\n\nCase closed.\n",
            encoding="utf-8",
        )
        nr = check_narrative("CASEB", "FAME", narrative_only_gap_dir)
        rr = check_research_notes("CASEB", narrative_only_gap_dir)
        check("(b) narrative incomplete", nr.ok, False)
        check("(b) reasoning complete", rr.ok, True)
        marker = write_incomplete_marker(narrative_only_gap_dir, "CASEB", nr, rr)
        check("(b) marker written", marker is not None and marker.exists(), True)
        if marker:
            payload = json.loads(marker.read_text(encoding="utf-8"))
            check("(b) marker lists missing sections", bool(payload["missing_narrative_sections"]), True)
            check("(b) marker lists no reasoning gaps", payload["missing_reasoning"] == [], True)

        # --- Fixture (c): SRL2018 pattern (no narrative, evidence-only steps, unfinalized) ---
        srl_dir = tmp_path / "srl"
        srl_dir.mkdir()
        srl_notes = ["# Research Notes — CASEC", "", "---", "", _PLACEHOLDER, "", "---", "", "## Investigation Log", ""]
        for i, fname in enumerate(["pslist.txt", "psscan.txt", "netstat.txt"], start=1):
            srl_notes += [
                f"### [2026-01-01 00:00:0{i} UTC] — Step {i} [RN-{i:03d}]: Evidence preserved: {fname}",
                "",
                "| | |",
                "|---|---|",
                f"| **Action** | sha256sum {fname} |",
                "| **Why** | Chain of custody — SHA-256 fingerprint of preserved artifact |",
                f"| **Outcome** | Preserved to evidence/{fname} — SHA-256: deadbeef |",
                "| **Confidence** | direct |",
                "",
                "---",
                "",
            ]
        (srl_dir / "CASEC_research_notes.md").write_text("\n".join(srl_notes), encoding="utf-8")
        nr = check_narrative("CASEC", "FAME", srl_dir)
        rr = check_research_notes("CASEC", srl_dir)
        check("(c) narrative incomplete (missing entirely)", nr.ok is False and nr.has_narrative is False, True)
        check("(c) reasoning incomplete", rr.ok, False)
        check("(c) flags unfinalized placeholder", any("placeholder" in r for r in rr.missing_reasons), True)
        check("(c) flags no reflections", any("Reflect" in r for r in rr.missing_reasons), True)
        check("(c) flags evidence-only steps", any("Evidence preserved" in r for r in rr.missing_reasons), True)
        marker = write_incomplete_marker(srl_dir, "CASEC", nr, rr)
        check("(c) marker written", marker is not None and marker.exists(), True)

        # --- Self-clearing: re-check (a) after deliberately writing a stale marker ---
        stale_marker = complete_dir / "CASEA_INVESTIGATION_INCOMPLETE.json"
        path_guard.safe_write_text(stale_marker, "{}", encoding="utf-8")
        nr = check_narrative("CASEA", "FAME", complete_dir)
        rr = check_research_notes("CASEA", complete_dir)
        write_incomplete_marker(complete_dir, "CASEA", nr, rr)
        check("(a) stale marker cleared on re-check", stale_marker.exists(), False)

    print()
    if failures:
        print(f"report_completeness self-test: {failures} FAILURE(S)")
    else:
        print("report_completeness self-test: ALL PASS")
    return 1 if failures else 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]

    if "--test" in argv:
        return _run_self_test()

    if "--check" in argv:
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--check", action="store_true")
        parser.add_argument("--case-id", required=True)
        parser.add_argument("--module", required=True, choices=["FAN", "FAME", "FAST"])
        parser.add_argument("--case-dir", required=True)
        args = parser.parse_args(argv)
        return _run_check_cli(args.case_id, args.module, Path(args.case_dir))

    if "--campaign-check" in argv:
        import argparse

        parser = argparse.ArgumentParser()
        parser.add_argument("--campaign-check", action="store_true")
        parser.add_argument("--case-id", required=True)
        parser.add_argument("--reports-dir", default=None)
        args = parser.parse_args(argv)
        reports_dir = Path(args.reports_dir) if args.reports_dir else REPORTS_DIR
        if check_campaign_report(args.case_id, reports_dir):
            print(f"[NEEDS CAMPAIGN REPORT] {args.case_id}: >=2 modules have reports "
                  f"but {args.case_id}_campaign_report.md does not exist")
            return 1
        print(f"[OK] {args.case_id}: campaign report present or not yet needed")
        return 0

    print(__doc__)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
