# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
Maps forensic findings to Obsidian vault entries.
All public functions are idempotent: calling them multiple times with the same
core identifiers updates the existing note rather than creating duplicates.

After each vault write, newly confirmed IOCs, TTPs, and malware families are
also pushed to OpenCTI via opencti_client.create_indicator().
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))
from obsidian_bridge import (
    append_to_note,
    link,
    list_notes,
    note_exists,
    patch_section,
    read_note,
    write_note,
)

try:
    from opencti_client import OpenCTIClient as _OpenCTIClient
    _opencti = _OpenCTIClient()
except Exception:
    _opencti = None


# STIX pattern builders per IOC type
_STIX_PATTERN = {
    "ip":           lambda v: f"[ipv4-addr:value = '{v}']",
    "domain":       lambda v: f"[domain-name:value = '{v}']",
    "url":          lambda v: f"[url:value = '{v}']",
    "email":        lambda v: f"[email-addr:value = '{v}']",
    "hash":         lambda v: f"[file:hashes.MD5 = '{v}']",
    "filename":     lambda v: f"[file:name = '{v}']",
    "registry_key": lambda v: f"[windows-registry-key:key = '{v}']",
}


def _push_ioc_to_opencti(ioc_type: str, raw_value: str, defanged: str,
                          severity: str, case_id: str) -> None:
    if _opencti is None:
        return
    builder = _STIX_PATTERN.get(ioc_type)
    if builder is None:
        return
    try:
        _opencti.create_indicator(
            name=f"{ioc_type}:{defanged}",
            pattern=builder(raw_value),
            pattern_type="stix",
            description=f"Extracted from case {case_id}. Severity: {severity}.",
            labels=["fan-extraction", ioc_type],
        )
    except Exception:
        pass  # OpenCTI push is best-effort; never block vault writes


def _push_ttp_to_opencti(mitre_id: str, technique_name: str,
                          severity: str, case_id: str) -> None:
    if _opencti is None:
        return
    try:
        _opencti.create_indicator(
            name=f"TTP:{mitre_id}",
            pattern=f"[process:name = 'TTP-{mitre_id}']",
            pattern_type="stix",
            description=f"{mitre_id} {technique_name} — observed in case {case_id}. Severity: {severity}.",
            labels=["fan-extraction", "ttp", mitre_id],
        )
    except Exception:
        pass


def _push_malware_to_opencti(family: str, malware_type: str,
                              known_hashes: list[str], case_id: str) -> None:
    if _opencti is None:
        return
    try:
        for h in known_hashes:
            _opencti.create_indicator(
                name=f"malware:{family}:{h}",
                pattern=f"[file:hashes.MD5 = '{h}']",
                pattern_type="stix",
                description=f"Hash associated with malware family {family} ({malware_type}). Case: {case_id}.",
                labels=["fan-extraction", "malware", family.lower()],
            )
        if not known_hashes:
            _opencti.create_indicator(
                name=f"malware:{family}",
                pattern=f"[file:name = '{family}']",
                pattern_type="stix",
                description=f"Malware family {family} ({malware_type}) observed in case {case_id}.",
                labels=["fan-extraction", "malware", family.lower()],
            )
    except Exception:
        pass

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _defang(value: str) -> str:
    """Defang IPs, domains, and URLs to prevent accidental resolution."""
    value = re.sub(r"\.", "[.]", value)
    value = re.sub(r"https?", "hxxp", value, flags=re.IGNORECASE)
    return value


def _safe_title(value: str) -> str:
    """Sanitise a string for use as a note title / filename."""
    return re.sub(r'[\\/:*?"<>|]', "_", value)[:120]


def _add_ref(fm: dict[str, Any], key: str, value: str) -> None:
    lst = fm.setdefault(key, [])
    if value not in lst:
        lst.append(value)


def _merge_severity(existing: str | None, new: str) -> str:
    existing_rank = SEVERITY_ORDER.get(existing or "info", 4)
    new_rank = SEVERITY_ORDER.get(new, 4)
    return existing if existing_rank <= new_rank else new


# ---------------------------------------------------------------------------
# Public record functions
# ---------------------------------------------------------------------------

def record_ioc(
    ioc_type: str,
    value: str,
    context: str,
    case_id: str,
    severity: str = "medium",
    related_ttps: list[str] | None = None,
    related_actors: list[str] | None = None,
) -> str:
    """
    Write or update an IOC note. Returns the note title.
    value is defanged before being stored.
    ioc_type: hash | ip | domain | url | email | filename | registry_key | ...
    """
    defanged = _defang(value) if ioc_type in ("ip", "domain", "url", "email") else value
    title = _safe_title(f"{ioc_type}-{defanged}")
    observation = (
        f"### {_now_utc()} — {case_id}\n"
        f"{context}\n"
    )

    if note_exists("IOCs", title):
        fm, _ = read_note("IOCs", title)
        fm["severity"] = _merge_severity(fm.get("severity"), severity)
        fm["date_updated"] = _now_utc()
        _add_ref(fm, "case_refs", case_id)
        for ttp in (related_ttps or []):
            _add_ref(fm, "related_ttps", ttp)
        for actor in (related_actors or []):
            _add_ref(fm, "related_actors", actor)
        write_note("IOCs", title, fm, _)
        append_to_note("IOCs", title, observation)
    else:
        ttp_links = " ".join(link(t) for t in (related_ttps or []))
        actor_links = " ".join(link(a) for a in (related_actors or []))
        body = f"## Context\nType: `{ioc_type}` | Value: `{defanged}`\n\n## Observations\n{observation}"
        if ttp_links:
            body += f"\n## Related TTPs\n{ttp_links}\n"
        if actor_links:
            body += f"\n## Related Actors\n{actor_links}\n"
        body += "\n## Disposition\nUnder investigation.\n"
        write_note("IOCs", title, {
            "ioc_type": ioc_type,
            "value": defanged,
            "severity": severity,
            "tags": ["ioc", ioc_type],
            "case_refs": [case_id],
            "related_ttps": related_ttps or [],
            "related_actors": related_actors or [],
            "disposition": "unknown",
        }, body)

    _refresh_dashboard()
    _push_ioc_to_opencti(ioc_type, value, defanged, severity, case_id)
    return title


def record_ttp(
    mitre_id: str,
    technique_name: str,
    evidence_summary: str,
    case_id: str,
    tactic: str = "",
    severity: str = "medium",
    related_actors: list[str] | None = None,
    related_malware: list[str] | None = None,
    related_iocs: list[str] | None = None,
) -> str:
    """Write or update a TTP note. Returns the note title."""
    title = _safe_title(f"{mitre_id} {technique_name}")
    observation = (
        f"### {_now_utc()} — {case_id}\n"
        f"{evidence_summary}\n"
    )

    if note_exists("TTPs", title):
        fm, body = read_note("TTPs", title)
        fm["severity"] = _merge_severity(fm.get("severity"), severity)
        fm["date_updated"] = _now_utc()
        _add_ref(fm, "case_refs", case_id)
        for a in (related_actors or []):
            _add_ref(fm, "related_actors", a)
        for m in (related_malware or []):
            _add_ref(fm, "related_malware", m)
        for i in (related_iocs or []):
            _add_ref(fm, "related_iocs", i)
        write_note("TTPs", title, fm, body)
        append_to_note("TTPs", title, observation)
    else:
        actor_links = " ".join(link(a) for a in (related_actors or []))
        malware_links = " ".join(link(m) for m in (related_malware or []))
        body = (
            f"## Summary\nMITRE ATT&CK: [{mitre_id}](https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')})\n\n"
            f"## Observed Evidence\n{observation}"
        )
        if actor_links:
            body += f"\n## Threat Actors\n{actor_links}\n"
        if malware_links:
            body += f"\n## Associated Malware\n{malware_links}\n"
        body += "\n## Mitigations\n\n## References\n"
        write_note("TTPs", title, {
            "mitre_id": mitre_id,
            "technique_name": technique_name,
            "tactic": tactic,
            "severity": severity,
            "tags": ["ttp"],
            "case_refs": [case_id],
            "related_actors": related_actors or [],
            "related_malware": related_malware or [],
            "related_iocs": related_iocs or [],
        }, body)

    _refresh_dashboard()
    _push_ttp_to_opencti(mitre_id, technique_name, severity, case_id)
    return title


def record_threat_actor(
    name: str,
    aliases: list[str] | None = None,
    motivation: str = "",
    observed_ttps: list[str] | None = None,
    known_malware: list[str] | None = None,
    case_id: str = "",
    notes: str = "",
) -> str:
    """Write or update a threat actor note. Returns the note title."""
    title = _safe_title(name)
    observation = f"### {_now_utc()} — {case_id or 'manual'}\n{notes}\n" if notes else ""

    if note_exists("ThreatActors", title):
        fm, body = read_note("ThreatActors", title)
        fm["date_updated"] = _now_utc()
        if case_id:
            _add_ref(fm, "case_refs", case_id)
        for ttp in (observed_ttps or []):
            _add_ref(fm, "observed_ttps", ttp)
        for m in (known_malware or []):
            _add_ref(fm, "known_malware", m)
        write_note("ThreatActors", title, fm, body)
        if observation:
            append_to_note("ThreatActors", title, observation)
    else:
        ttp_links = " ".join(link(t) for t in (observed_ttps or []))
        malware_links = " ".join(link(m) for m in (known_malware or []))
        body = (
            f"## Profile\nMotivation: {motivation or 'Unknown'}\n"
            f"Aliases: {', '.join(aliases or []) or 'None known'}\n\n"
            f"## Observed TTPs\n{ttp_links or 'None recorded yet.'}\n\n"
            f"## Known Malware\n{malware_links or 'None recorded yet.'}\n\n"
            f"## Campaign History\n{observation}"
        )
        write_note("ThreatActors", title, {
            "aliases": aliases or [],
            "motivation": motivation,
            "tags": ["threat-actor"],
            "case_refs": [case_id] if case_id else [],
            "observed_ttps": observed_ttps or [],
            "known_malware": known_malware or [],
            "known_iocs": [],
        }, body)

    _refresh_dashboard()
    return title


def record_malware(
    family: str,
    malware_type: str,
    description: str,
    case_id: str,
    related_actors: list[str] | None = None,
    related_ttps: list[str] | None = None,
    known_hashes: list[str] | None = None,
) -> str:
    """Write or update a malware family note. Returns the note title."""
    title = _safe_title(family)

    if note_exists("Malware", title):
        fm, body = read_note("Malware", title)
        fm["date_updated"] = _now_utc()
        _add_ref(fm, "case_refs", case_id)
        for h in (known_hashes or []):
            _add_ref(fm, "known_hashes", h)
        for a in (related_actors or []):
            _add_ref(fm, "related_actors", a)
        for t in (related_ttps or []):
            _add_ref(fm, "related_ttps", t)
        write_note("Malware", title, fm, body)
    else:
        ttp_links = " ".join(link(t) for t in (related_ttps or []))
        actor_links = " ".join(link(a) for a in (related_actors or []))
        hash_list = "\n".join(f"- `{h}`" for h in (known_hashes or []))
        body = (
            f"## Description\n{description}\n\n"
            f"## Behavior\n\n"
            f"## Indicators\n{hash_list or 'None recorded yet.'}\n\n"
            f"## Associated TTPs\n{ttp_links or 'None recorded yet.'}\n\n"
            f"## Threat Actors\n{actor_links or 'None recorded yet.'}\n\n"
            f"## Capabilities\n"
        )
        write_note("Malware", title, {
            "family": family,
            "type": malware_type,
            "tags": ["malware"],
            "case_refs": [case_id],
            "related_actors": related_actors or [],
            "related_ttps": related_ttps or [],
            "known_hashes": known_hashes or [],
        }, body)

    _push_malware_to_opencti(family, malware_type, known_hashes or [], case_id)
    return title


def record_risk(
    asset: str,
    risk_description: str,
    case_id: str,
    severity: str = "medium",
    likelihood: str = "medium",
    related_ttps: list[str] | None = None,
    mitigations: str = "",
) -> str:
    """Write a risk note. Returns the note title."""
    title = _safe_title(f"{case_id}-{asset}")
    ttp_links = " ".join(link(t) for t in (related_ttps or []))
    body = (
        f"## Risk Description\n{risk_description}\n\n"
        f"## Impact\n\n"
        f"## Likelihood Rationale\nSeverity: {severity} | Likelihood: {likelihood}\n\n"
        f"## Related TTPs\n{ttp_links or 'None recorded.'}\n\n"
        f"## Recommended Mitigations\n{mitigations or 'Not yet assessed.'}\n\n"
        f"## Accepted / Resolved\nOpen as of {_now_utc()}\n"
    )
    write_note("Risks", title, {
        "case_ref": case_id,
        "asset": asset,
        "severity": severity,
        "likelihood": likelihood,
        "status": "open",
        "tags": ["risk"],
        "related_ttps": related_ttps or [],
    }, body)
    _refresh_dashboard()
    return title


def record_concept(
    name: str,
    definition: str,
    related_ttps: list[str] | None = None,
    related_concepts: list[str] | None = None,
    examples: str = "",
) -> str:
    """Write or update a cybersecurity concept note. Returns the note title."""
    title = _safe_title(name)
    ttp_links = " ".join(link(t) for t in (related_ttps or []))
    concept_links = " ".join(link(c) for c in (related_concepts or []))
    body = (
        f"## Definition\n{definition}\n\n"
        f"## How It Works\n\n"
        f"## Defensive Relevance\n\n"
        f"## Related TTPs\n{ttp_links or 'None linked yet.'}\n\n"
        f"## Related Concepts\n{concept_links or 'None linked yet.'}\n\n"
        f"## Examples Observed\n{examples or 'None recorded yet.'}\n"
    )
    write_note("Concepts", title, {
        "tags": ["concept"],
        "related_ttps": related_ttps or [],
        "related_concepts": related_concepts or [],
    }, body)
    return title


def open_case(case_id: str, summary: str, severity: str = "medium") -> str:
    """Create a new case note. Returns the note title."""
    title = _safe_title(case_id)
    body = (
        f"## Summary\n{summary}\n\n"
        f"## Timeline\n\n"
        f"## Findings\n\n"
        f"## Artifacts Examined\n"
        f"*Note: artifact paths are omitted — see case directory for raw evidence.*\n\n"
        f"## Recommendations\n"
    )
    write_note("Cases", title, {
        "case_id": case_id,
        "status": "open",
        "severity": severity,
        "tags": ["case"],
        "ttps_observed": [],
        "iocs_found": [],
        "actors_suspected": [],
    }, body)
    _refresh_dashboard()
    return title


def close_case(case_id: str, findings: str) -> None:
    """Mark a case closed and append final findings."""
    title = _safe_title(case_id)
    if note_exists("Cases", title):
        fm, body = read_note("Cases", title)
        fm["status"] = "closed"
        write_note("Cases", title, fm, body)
        append_to_note("Cases", title,
                       f"## Final Findings ({_now_utc()})\n{findings}")
    _refresh_dashboard()


# ---------------------------------------------------------------------------
# Dashboard refresh
# ---------------------------------------------------------------------------

def _refresh_dashboard() -> None:
    """Regenerate the AUTO sections in Dashboard.md."""
    # Cases
    case_titles = list_notes("Cases")
    cases_md = ""
    for ct in case_titles[-10:]:
        result = read_note("Cases", ct)
        if result:
            fm, _ = result
            status = fm.get("status", "?")
            sev = fm.get("severity", "?")
            cases_md += f"- {link(ct)} — {status} | severity: {sev}\n"
    patch_section(".", "Dashboard", "CASES", cases_md or "*No cases recorded yet.*")

    # IOCs (most recent 10)
    ioc_titles = list_notes("IOCs")
    iocs_md = ""
    for it in ioc_titles[-10:]:
        result = read_note("IOCs", it)
        if result:
            fm, _ = result
            iocs_md += f"- {link(it)} — {fm.get('ioc_type', '?')} | {fm.get('severity', '?')}\n"
    patch_section(".", "Dashboard", "IOCS", iocs_md or "*No IOCs recorded yet.*")

    # Risks (open only)
    risk_titles = list_notes("Risks")
    risks_md = ""
    for rt in risk_titles:
        result = read_note("Risks", rt)
        if result:
            fm, _ = result
            if fm.get("status") == "open":
                risks_md += f"- {link(rt)} — {fm.get('severity', '?')} | asset: {fm.get('asset', '?')}\n"
    patch_section(".", "Dashboard", "RISKS", risks_md or "*No open risks.*")

    # TTPs
    ttp_titles = list_notes("TTPs")
    ttps_md = ""
    for tt in ttp_titles[-10:]:
        result = read_note("TTPs", tt)
        if result:
            fm, _ = result
            ttps_md += f"- {link(tt)} — {fm.get('mitre_id', '?')} | {fm.get('severity', '?')}\n"
    patch_section(".", "Dashboard", "TTPS", ttps_md or "*No TTPs recorded yet.*")

    # Threat actors
    actor_titles = list_notes("ThreatActors")
    actors_md = "".join(f"- {link(a)}\n" for a in actor_titles)
    patch_section(".", "Dashboard", "ACTORS", actors_md or "*No threat actors recorded yet.*")


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

def _self_test() -> None:
    import shutil
    from pathlib import Path
    vault = Path(__file__).parent.parent / "vault"

    print("open_case ... ", end="")
    open_case("CASE-TEST-001", "Automated self-test case.", severity="low")
    assert (vault / "Cases" / "CASE-TEST-001.md").exists()
    print("OK")

    print("record_ioc ... ", end="")
    record_ioc("ip", "10.0.0.1", "Seen beaconing in test.", "CASE-TEST-001",
               severity="high", related_ttps=["T1071"])
    assert any("10" in n for n in list_notes("IOCs"))
    print("OK")

    print("record_ttp ... ", end="")
    record_ttp("T1071", "Application Layer Protocol", "PowerShell HTTPS beacon.",
               "CASE-TEST-001", tactic="command-and-control", severity="high")
    assert any("T1071" in n for n in list_notes("TTPs"))
    print("OK")

    print("record_threat_actor ... ", end="")
    record_threat_actor("TestGroup", aliases=["TG-42"], motivation="espionage",
                        observed_ttps=["T1071 Application Layer Protocol"],
                        case_id="CASE-TEST-001", notes="Seen in test run.")
    assert (vault / "ThreatActors" / "TestGroup.md").exists()
    print("OK")

    print("record_risk ... ", end="")
    record_risk("FileServer01", "Potential lateral movement vector.", "CASE-TEST-001",
                severity="high", related_ttps=["T1071 Application Layer Protocol"])
    assert list_notes("Risks")
    print("OK")

    print("record_concept ... ", end="")
    record_concept("Living off the Land",
                   "Using built-in OS tools for malicious purposes.",
                   related_ttps=["T1071 Application Layer Protocol"])
    assert (vault / "Concepts" / "Living off the Land.md").exists()
    print("OK")

    print("close_case ... ", end="")
    close_case("CASE-TEST-001", "No real threat — self-test only.")
    fm, _ = read_note("Cases", "CASE-TEST-001")
    assert fm.get("status") == "closed"
    print("OK")

    print("Dashboard updated ... ", end="")
    assert (vault / "Dashboard.md").exists()
    print("OK")

    # Cleanup test artefacts
    for folder, stem in [
        ("Cases", "CASE-TEST-001"),
        ("IOCs", "ip-10[.]0[.]0[.]1"),
        ("TTPs", "T1071 Application Layer Protocol"),
        ("ThreatActors", "TestGroup"),
        ("Concepts", "Living off the Land"),
    ]:
        p = vault / folder / f"{stem}.md"
        if p.exists():
            p.unlink()
    for p in (vault / "Risks").glob("CASE-TEST-001*.md"):
        p.unlink()

    print("\nAll knowledge_extractor self-tests passed.")


if __name__ == "__main__":
    _self_test()
