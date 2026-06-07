# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
Perplexity.ai API client for real-time cybersecurity threat intelligence.

Requires: PERPLEXITY_API_KEY environment variable.
Set it once in ~/.bashrc:  export PERPLEXITY_API_KEY="pplx-..."

All query helpers return a dict:
  {
    "answer":     str,           # full response text
    "citations":  list[str],     # source URLs
    "model":      str,
    "query":      str,
    "error":      str | None,    # set on failure, all other fields empty
  }

CLI:
  python3 lib/perplexity_client.py ioc 203.0.113.42
  python3 lib/perplexity_client.py malware "Cobalt Strike"
  python3 lib/perplexity_client.py ttp T1071.001
  python3 lib/perplexity_client.py cve CVE-2024-1234
  python3 lib/perplexity_client.py actor APT29
  python3 lib/perplexity_client.py tool mimikatz
  python3 lib/perplexity_client.py search "LSASS dumping detection evasion techniques"
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from datetime import datetime, timezone

API_URL = "https://api.perplexity.ai/chat/completions"
DEFAULT_MODEL = "sonar-pro"

_SYSTEM_PROMPT = (
    "You are a senior cybersecurity threat intelligence analyst with deep knowledge of "
    "malware, threat actors, MITRE ATT&CK techniques, CVEs, and offensive security tools. "
    "Provide factual, cited, up-to-date information. Structure your answers clearly: "
    "include relevant MITRE ATT&CK IDs, severity context, IOC examples, and defensive "
    "recommendations where applicable. Be concise but complete. "
    "Flag if information is uncertain or contradictory across sources."
)

# ---------------------------------------------------------------------------
# Core API call
# ---------------------------------------------------------------------------

def _api_key() -> str:
    key = os.environ.get("PERPLEXITY_API_KEY", "").strip()
    if not key:
        raise EnvironmentError(
            "PERPLEXITY_API_KEY is not set.\n"
            "Add to ~/.bashrc:  export PERPLEXITY_API_KEY='pplx-...'\n"
            "Then reload:       source ~/.bashrc"
        )
    return key


def _call(query: str, model: str = DEFAULT_MODEL, system: str = _SYSTEM_PROMPT) -> dict:
    """Make one Perplexity chat completion call. Returns a result dict."""
    try:
        key = _api_key()
    except EnvironmentError as e:
        return {"answer": "", "citations": [], "model": model, "query": query, "error": str(e)}

    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": query},
        ],
        "return_citations": True,
        "return_images": False,
        "temperature": 0.1,   # low temperature for factual accuracy
    }).encode("utf-8")

    req = urllib.request.Request(
        API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {key}",
            "User-Agent": "SOC-Orchestrator/1.0",
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            body = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_body = e.read().decode("utf-8", errors="replace")
        return {
            "answer": "", "citations": [], "model": model, "query": query,
            "error": f"HTTP {e.code}: {err_body[:400]}",
        }
    except urllib.error.URLError as e:
        return {
            "answer": "", "citations": [], "model": model, "query": query,
            "error": f"Network error: {e.reason}",
        }

    answer = body.get("choices", [{}])[0].get("message", {}).get("content", "")
    citations = body.get("citations", [])
    return {
        "answer": answer,
        "citations": citations,
        "model": body.get("model", model),
        "query": query,
        "error": None,
    }


# ---------------------------------------------------------------------------
# Typed query helpers
# ---------------------------------------------------------------------------

def lookup_ioc(value: str, ioc_type: str = "indicator") -> dict:
    """Query reputation and threat intel for an IOC."""
    query = (
        f"Cybersecurity threat intelligence lookup for {ioc_type}: {value}\n"
        f"Provide: known malicious activity, associated malware families, threat actors, "
        f"campaigns, first/last seen dates, and any blocklists or feeds that include this indicator. "
        f"If no threat intelligence is available, state that clearly."
    )
    return _call(query)


def lookup_malware(family: str) -> dict:
    """Query a malware family profile."""
    query = (
        f"Provide a threat intelligence profile for the malware family: {family}\n"
        f"Include: malware type (RAT/ransomware/loader/etc.), primary capabilities, "
        f"delivery mechanisms, persistence techniques, C2 protocols, "
        f"MITRE ATT&CK technique IDs, known IOCs (hashes/domains/IPs), "
        f"associated threat actors, and first observed date."
    )
    return _call(query)


def lookup_ttp(mitre_id: str, technique_name: str = "") -> dict:
    """Query implementation details and recent usage of a MITRE ATT&CK technique."""
    label = f"{mitre_id} {technique_name}".strip()
    query = (
        f"Explain MITRE ATT&CK technique {label}.\n"
        f"Include: how attackers implement it in practice, common tools used, "
        f"real-world threat actor examples (2022–present), detection opportunities, "
        f"log sources, and defensive mitigations. "
        f"List any sub-techniques if relevant."
    )
    return _call(query)


def lookup_cve(cve_id: str) -> dict:
    """Query CVE details including exploitation status."""
    query = (
        f"Provide full details on {cve_id}.\n"
        f"Include: affected products and versions, CVSS v3 score and vector, "
        f"vulnerability type (RCE/LPE/SSRF/etc.), technical description, "
        f"whether it has been exploited in the wild (include threat actors if known), "
        f"available patches/mitigations, and PoC/exploit availability."
    )
    return _call(query)


def lookup_actor(name: str) -> dict:
    """Query a threat actor profile."""
    query = (
        f"Provide a threat intelligence profile for threat actor: {name}\n"
        f"Include: known aliases, suspected origin/nation-state attribution, "
        f"motivation (espionage/financial/hacktivism), primary targets and sectors, "
        f"known malware families used, MITRE ATT&CK technique IDs, "
        f"known infrastructure patterns, and notable campaigns (2020–present)."
    )
    return _call(query)


def lookup_tool(tool_name: str) -> dict:
    """Query an unknown tool — determines if it is legitimate, dual-use, or offensive."""
    query = (
        f"In the context of cybersecurity and digital forensics, what is: {tool_name}\n"
        f"Determine: Is this a legitimate system tool, a dual-use security tool, or a "
        f"known offensive/malware tool? Include: capabilities, how attackers misuse it, "
        f"which threat actors or malware families use it, MITRE ATT&CK technique IDs, "
        f"and detection / hunting signatures."
    )
    return _call(query)


def search(query: str) -> dict:
    """General cybersecurity research query — use when no typed helper fits."""
    return _call(query)


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------

def format_result(result: dict, verbose: bool = True) -> str:
    if result.get("error"):
        return f"[perplexity ERROR] {result['error']}"

    lines = [
        f"[perplexity] Query: {result['query'][:120]}",
        f"[perplexity] Model: {result['model']} | {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
        result["answer"],
    ]
    if verbose and result.get("citations"):
        lines += ["", "Sources:"]
        for i, url in enumerate(result["citations"], 1):
            lines.append(f"  [{i}] {url}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Vault auto-save helper
# ---------------------------------------------------------------------------

def save_to_vault(result: dict, note_type: str, title: str) -> None:
    """
    Optionally save a Perplexity result as a concept note in the vault.
    note_type: 'concept' | 'malware' | 'actor' | 'ttp' | 'ioc'
    Only saves if PERPLEXITY_AUTOSAVE_VAULT=1 is set, or called explicitly.
    """
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_concept
        body = (
            f"*Source: Perplexity.ai ({result.get('model', '?')}) — "
            f"{datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}*\n\n"
            f"{result.get('answer', '')}\n\n"
        )
        if result.get("citations"):
            body += "**Sources:**\n" + "\n".join(f"- {u}" for u in result["citations"])
        record_concept(
            name=title,
            definition=f"Auto-captured from Perplexity.ai research on: {result.get('query', '')}",
            examples=body,
        )
        print(f"[perplexity] Saved to vault: Concepts/{title}")
    except Exception as e:
        print(f"[perplexity] Vault save skipped: {e}")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Perplexity.ai cybersecurity research client",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/perplexity_client.py ioc 203.0.113.42\n"
            "  python3 lib/perplexity_client.py malware 'Cobalt Strike'\n"
            "  python3 lib/perplexity_client.py ttp T1071.001\n"
            "  python3 lib/perplexity_client.py cve CVE-2024-1234\n"
            "  python3 lib/perplexity_client.py actor APT29\n"
            "  python3 lib/perplexity_client.py tool mimikatz\n"
            "  python3 lib/perplexity_client.py search 'LSASS dump detection evasion'\n"
        ),
    )
    p.add_argument("type", choices=["ioc", "malware", "ttp", "cve", "actor", "tool", "search"],
                   help="Query type")
    p.add_argument("value", nargs="+", help="Value or query string")
    p.add_argument("--model", default=DEFAULT_MODEL,
                   choices=["sonar", "sonar-pro", "sonar-reasoning", "sonar-reasoning-pro"],
                   help=f"Perplexity model (default: {DEFAULT_MODEL})")
    p.add_argument("--save-vault", action="store_true",
                   help="Save result as a Concept note in the Obsidian vault")
    p.add_argument("--no-citations", action="store_true",
                   help="Suppress source URLs in output")
    return p


if __name__ == "__main__":
    parser = _build_parser()
    args = parser.parse_args()
    value = " ".join(args.value)

    dispatch = {
        "ioc":     lambda v: lookup_ioc(v),
        "malware": lambda v: lookup_malware(v),
        "ttp":     lambda v: lookup_ttp(v),
        "cve":     lambda v: lookup_cve(v),
        "actor":   lambda v: lookup_actor(v),
        "tool":    lambda v: lookup_tool(v),
        "search":  lambda v: search(v),
    }
    result = dispatch[args.type](value)
    # Override model if specified
    result["model"] = args.model if args.model != DEFAULT_MODEL else result.get("model", DEFAULT_MODEL)

    print(format_result(result, verbose=not args.no_citations))

    if args.save_vault and not result.get("error"):
        save_to_vault(result, args.type, value)
