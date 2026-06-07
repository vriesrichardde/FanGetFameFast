# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
CTI IP Lookup — correlates PCAP-extracted FQDNs and IP addresses, performs DNS
resolution, enriches each indicator with OSINT via Perplexity.ai, and caches
results in the Obsidian vault for 7-day reuse.

Inputs:
  unique_fqdns.txt  (from lib/pcap_analyzer.py)
  unique_ips.txt    (from lib/pcap_analyzer.py)

Outputs:
  analysis/fan_ip/<stem>/correlation.csv     — FQDN ↔ IP correlation table
  analysis/fan_ip/<stem>/ip_enrichment.csv   — IP enrichment (reverse DNS + OSINT)
  analysis/fan_ip/<stem>/fan_ip_report.md       — Summary of malicious/suspicious indicators
  vault/IOCs/<ioc>.md                     — Created/updated with ## OSINT section

Requires: PERPLEXITY_API_KEY for live OSINT (falls back to vault cache only if unset)

CLI:
  python3 lib/fan_ip_lookup.py --stem 2026-04-16-Lumma-Stealer --case-id CASE-2025-001
  python3 lib/fan_ip_lookup.py analysis/pcap/capture/unique_fqdns.txt \\
      analysis/pcap/capture/unique_ips.txt --case-id CASE-2025-001
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import re
import socket
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

CACHE_MAX_DAYS = 7

# ---------------------------------------------------------------------------
# IP classification
# ---------------------------------------------------------------------------

def is_public_ip(ip_str: str) -> bool:
    """True if IP is globally routable (not RFC1918/loopback/link-local/multicast)."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return not (
            addr.is_private or addr.is_loopback or addr.is_link_local
            or addr.is_multicast or addr.is_reserved or addr.is_unspecified
        )
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def resolve_fqdn(fqdn: str) -> list[str]:
    """Forward DNS — returns list of IPs (empty on failure)."""
    try:
        results = socket.getaddrinfo(fqdn, None)
        return sorted({r[4][0] for r in results})
    except (socket.gaierror, OSError):
        return []


def resolve_ip(ip: str) -> str:
    """Reverse DNS — returns PTR hostname or '' on failure."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""


# ---------------------------------------------------------------------------
# File parsers
# ---------------------------------------------------------------------------

def _load_fqdns(path: Path) -> list[tuple[str, str]]:
    """Parse unique_fqdns.txt → [(fqdn, source_tags), ...]"""
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 1)
        fqdn = parts[0].strip()
        tags = parts[1].strip("[] ") if len(parts) > 1 else ""
        if fqdn:
            entries.append((fqdn, tags))
    return entries


def _load_ips(path: Path) -> list[str]:
    """Parse unique_ips.txt → [ip, ...]"""
    return [ln.strip() for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]


# ---------------------------------------------------------------------------
# Obsidian vault helpers
# ---------------------------------------------------------------------------

def _ioc_note_title(ioc_type: str, value: str) -> str:
    """Reproduce the note title that knowledge_extractor.record_ioc creates."""
    defanged = re.sub(r"\.", "[.]", value)
    defanged = re.sub(r"https?", "hxxp", defanged, flags=re.IGNORECASE)
    raw = f"{ioc_type}-{defanged}"
    return re.sub(r'[\\/:*?"<>|]', "_", raw)[:120]


def _note_age_days(fm: dict) -> float | None:
    """Age of a vault note in days from date_updated, or None if unparseable."""
    date_str = fm.get("date_updated", "")
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(date_str, fmt).replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - dt).total_seconds() / 86400
        except (ValueError, TypeError):
            continue
    return None


def _extract_osint_section(body: str) -> str:
    """Return text content of ## OSINT section, or '' if absent."""
    lines = body.split("\n")
    in_osint, collected = False, []
    for line in lines:
        if line.strip() == "## OSINT":
            in_osint = True
            continue
        if in_osint and line.startswith("## "):
            break
        if in_osint:
            collected.append(line)
    return "\n".join(collected).strip()


def _vault_cache(ioc_type: str, value: str) -> tuple[str, bool]:
    """
    Check vault for a fresh IOC note with an OSINT section.
    Returns (osint_text, is_fresh).  is_fresh iff < CACHE_MAX_DAYS old.
    """
    try:
        from obsidian_bridge import read_note
        title = _ioc_note_title(ioc_type, value)
        result = read_note("IOCs", title)
        if not result:
            return "", False
        fm, body = result
        age = _note_age_days(fm)
        osint = _extract_osint_section(body)
        is_fresh = age is not None and age < CACHE_MAX_DAYS and bool(osint)
        return osint, is_fresh
    except Exception:
        return "", False


def _upsert_vault_ioc(
    ioc_type: str,
    value: str,
    context: str,
    case_id: str,
    osint_result: dict | None,
    resolved_ips: list[str] | None = None,
    reverse_dns: str = "",
    reputation: str = "unknown",
) -> None:
    """Ensure the IOC exists in the vault and patch/add the ## OSINT section."""
    try:
        from knowledge_extractor import record_ioc
        from obsidian_bridge import read_note, write_note
    except Exception as e:
        print(f"  [vault] Import error: {e}", file=sys.stderr)
        return

    title = record_ioc(ioc_type, value, context, case_id or "CTI-LOOKUP")

    result = read_note("IOCs", title)
    if not result:
        return
    fm, body = result

    if resolved_ips:
        fm["resolved_ips"] = resolved_ips
    if reverse_dns:
        fm["reverse_dns"] = reverse_dns
    if reputation != "unknown":
        fm["reputation"] = reputation

    if osint_result and not osint_result.get("error") and osint_result.get("answer"):
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        model = osint_result.get("model", "sonar-pro")
        answer = osint_result["answer"]
        citations = osint_result.get("citations", [])
        osint_body = f"*{now} via Perplexity.ai ({model})*\n\n{answer}"
        if citations:
            osint_body += "\n\n**Sources:**\n" + "\n".join(f"- {u}" for u in citations)
        osint_block = f"## OSINT\n{osint_body}\n"

        if "## OSINT" in body:
            body = re.sub(
                r"## OSINT\n.*?(?=\n## |\Z)",
                osint_block,
                body,
                flags=re.DOTALL,
            )
        else:
            body = body.rstrip("\n") + f"\n\n{osint_block}"

    write_note("IOCs", title, fm, body)


# ---------------------------------------------------------------------------
# Reputation heuristic
# ---------------------------------------------------------------------------

_MALICIOUS_KW = frozenset([
    "malicious", "malware", "c2 ", "command-and-control", "botnet", "ransomware",
    "phishing", "trojan", "backdoor", "stealer", "remote access tool",
    "cobalt strike", "blocked", "blacklist", "threat actor", "known malicious",
    "abuse.ch", "exploit", "dropper", "loader malware",
])
_LEGIT_KW = frozenset([
    "legitimate", "benign", "cloudflare", "akamai", "fastly", "microsoft",
    "amazon aws", "google cloud", "content delivery", "known good", "cdn provider",
    "no known malicious", "no malicious", "not associated with",
])


def _infer_reputation(osint_text: str) -> str:
    """Heuristic reputation from OSINT: malicious | suspicious | legitimate | unknown."""
    if not osint_text:
        return "unknown"
    text = osint_text.lower()
    mal = sum(1 for kw in _MALICIOUS_KW if kw in text)
    leg = sum(1 for kw in _LEGIT_KW if kw in text)
    if mal >= 2 or (mal >= 1 and leg == 0):
        return "malicious"
    if mal == 1:
        return "suspicious"
    if leg >= 1 and mal == 0:
        return "legitimate"
    return "unknown"


# ---------------------------------------------------------------------------
# Perplexity OSINT
# ---------------------------------------------------------------------------

def _query_perplexity(value: str, ioc_type: str) -> dict | None:
    """Call Perplexity for IOC enrichment. Returns result dict or None on failure."""
    try:
        from perplexity_client import lookup_ioc
        print(f"  [osint] Querying Perplexity: {ioc_type} {value!r} ...", flush=True)
        result = lookup_ioc(value, ioc_type=ioc_type)
        if result.get("error"):
            print(f"  [osint] Perplexity error: {result['error'][:120]}", file=sys.stderr)
            return None
        return result
    except Exception as e:
        print(f"  [osint] Perplexity unavailable: {e}", file=sys.stderr)
        return None


# ---------------------------------------------------------------------------
# Phase 1 — FQDN enrichment
# ---------------------------------------------------------------------------

def enrich_fqdns(
    fqdn_entries: list[tuple[str, str]],
    pcap_ip_set: set[str],
    case_id: str,
) -> list[dict]:
    """
    For each FQDN: vault cache check → forward DNS → PCAP correlation → OSINT → vault write.
    Returns list of result dicts for correlation.csv.
    """
    results = []
    for fqdn, source_tags in fqdn_entries:
        print(f"[fqdn] {fqdn}  [{source_tags}]")

        cached_osint, is_fresh = _vault_cache("domain", fqdn)

        resolved = resolve_fqdn(fqdn)
        matched = [ip for ip in resolved if ip in pcap_ip_set]
        if resolved:
            print(f"  resolved={resolved}  matched={matched}")
        else:
            print(f"  [dns] No resolution")

        osint_result = None
        osint_text = cached_osint
        if is_fresh:
            print(f"  [cache] Vault OSINT fresh (< {CACHE_MAX_DAYS}d) — skipping Perplexity")
        else:
            osint_result = _query_perplexity(fqdn, "domain")
            if osint_result:
                osint_text = osint_result.get("answer", "")

        reputation = _infer_reputation(osint_text)

        context = (
            f"Observed in PCAP. Sources: {source_tags}. "
            f"Resolved: {', '.join(resolved) or 'unresolvable'}. "
            f"Matched PCAP IPs: {', '.join(matched) or 'none'}."
        )
        _upsert_vault_ioc("domain", fqdn, context, case_id, osint_result,
                          resolved_ips=resolved, reputation=reputation)

        results.append({
            "fqdn": fqdn,
            "source_tags": source_tags,
            "resolved_ips": ",".join(resolved),
            "matched_pcap_ips": ",".join(matched),
            "in_pcap": "yes" if matched else ("resolved" if resolved else "no"),
            "reputation": reputation,
            "osint_summary": osint_text[:300].replace("\n", " ") if osint_text else "",
        })
    return results


# ---------------------------------------------------------------------------
# Phase 2 — IP enrichment
# ---------------------------------------------------------------------------

def enrich_ips(
    pcap_ips: list[str],
    fqdn_resolved_map: dict[str, list[str]],
    case_id: str,
) -> list[dict]:
    """
    For each PCAP IP: reverse DNS, FQDN matching, OSINT for public IPs.
    Returns list of result dicts for ip_enrichment.csv.
    """
    ip_to_fqdns: dict[str, list[str]] = {}
    for fqdn, ips in fqdn_resolved_map.items():
        for ip in ips:
            ip_to_fqdns.setdefault(ip, []).append(fqdn)

    results = []
    for ip in pcap_ips:
        public = is_public_ip(ip)
        matched_fqdns = ip_to_fqdns.get(ip, [])
        print(f"[ip] {ip}  public={public}  matched_fqdns={matched_fqdns}")

        cached_osint, is_fresh = _vault_cache("ip", ip) if public else ("", False)

        rdns = ""
        if not matched_fqdns:
            rdns = resolve_ip(ip)
            if rdns:
                print(f"  [rdns] {rdns}")

        osint_result = None
        osint_text = cached_osint
        if public:
            if is_fresh:
                print(f"  [cache] Vault OSINT fresh (< {CACHE_MAX_DAYS}d) — skipping Perplexity")
            else:
                osint_result = _query_perplexity(ip, "IP address")
                if osint_result:
                    osint_text = osint_result.get("answer", "")

        reputation = _infer_reputation(osint_text) if public else "private"

        if public:
            context = (
                f"Observed in PCAP. "
                f"Reverse DNS: {rdns or 'none'}. "
                f"Associated FQDNs: {', '.join(matched_fqdns) or 'none'}."
            )
            _upsert_vault_ioc("ip", ip, context, case_id, osint_result,
                              reverse_dns=rdns, reputation=reputation)

        results.append({
            "ip": ip,
            "is_public": "yes" if public else "no",
            "reverse_dns": rdns or (matched_fqdns[0] if matched_fqdns else ""),
            "matched_fqdns": ",".join(matched_fqdns),
            "reputation": reputation,
            "osint_summary": osint_text[:300].replace("\n", " ") if osint_text else "",
        })
    return results


# ---------------------------------------------------------------------------
# Report + CSV writers
# ---------------------------------------------------------------------------

def write_outputs(
    output_dir: Path,
    stem: str,
    fqdn_results: list[dict],
    ip_results: list[dict],
    case_id: str,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    corr_path = output_dir / "correlation.csv"
    with corr_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "fqdn", "source_tags", "resolved_ips", "matched_pcap_ips",
            "in_pcap", "reputation", "osint_summary",
        ])
        w.writeheader()
        w.writerows(fqdn_results)

    ip_path = output_dir / "ip_enrichment.csv"
    with ip_path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "ip", "is_public", "reverse_dns", "matched_fqdns",
            "reputation", "osint_summary",
        ])
        w.writeheader()
        w.writerows(ip_results)

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    mal_fqdns = [r for r in fqdn_results if r["reputation"] == "malicious"]
    sus_fqdns = [r for r in fqdn_results if r["reputation"] == "suspicious"]
    mal_ips = [r for r in ip_results if r["reputation"] == "malicious"]
    sus_ips = [r for r in ip_results if r["reputation"] == "suspicious"]
    unmatched_ips = [r for r in ip_results if not r["matched_fqdns"]]

    def _fqdn_row(r: dict) -> str:
        return f"| `{r['fqdn']}` | **{r['reputation']}** | {r['source_tags']} | {r['osint_summary'][:120]} |"

    def _ip_row(r: dict) -> str:
        return f"| `{r['ip']}` | **{r['reputation']}** | {r['reverse_dns'] or '—'} | {r['osint_summary'][:120]} |"

    lines = [
        "# CTI IP Lookup Report",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Stem | `{stem}` |",
        f"| Case ID | {case_id or '—'} |",
        f"| Analysed | {now} |",
        f"| FQDNs enriched | {len(fqdn_results)} |",
        f"| IPs enriched | {len(ip_results)} |",
        f"| Malicious FQDNs | **{len(mal_fqdns)}** |",
        f"| Suspicious FQDNs | {len(sus_fqdns)} |",
        f"| Malicious IPs | **{len(mal_ips)}** |",
        f"| Suspicious IPs | {len(sus_ips)} |",
        f"| Unmatched IPs (no FQDN) | {len(unmatched_ips)} |",
        "",
        "## High-Priority Indicators",
        "",
        "### Malicious / Suspicious FQDNs",
        "| FQDN | Reputation | Sources | OSINT (truncated) |",
        "|------|------------|---------|-------------------|",
    ]
    for r in mal_fqdns + sus_fqdns:
        lines.append(_fqdn_row(r))
    if not (mal_fqdns + sus_fqdns):
        lines.append("| — | — | — | — |")

    lines += [
        "",
        "### Malicious / Suspicious IPs",
        "| IP | Reputation | Reverse DNS | OSINT (truncated) |",
        "|----|------------|-------------|-------------------|",
    ]
    for r in mal_ips + sus_ips:
        lines.append(_ip_row(r))
    if not (mal_ips + sus_ips):
        lines.append("| — | — | — | — |")

    lines += [
        "",
        "## Unmatched IPs (No FQDN Correlation)",
        "| IP | Is Public | Reverse DNS | Reputation |",
        "|----|-----------|-------------|------------|",
    ]
    for r in unmatched_ips:
        lines.append(f"| `{r['ip']}` | {r['is_public']} | {r['reverse_dns'] or '—'} | {r['reputation']} |")
    if not unmatched_ips:
        lines.append("| — | — | — | — |")

    lines += [
        "",
        "## Output Files",
        "",
        "| File | Contents |",
        "|------|----------|",
        f"| `correlation.csv` | FQDN enrichment + resolved/matched IPs + reputation |",
        f"| `ip_enrichment.csv` | IP enrichment (reverse DNS + OSINT + reputation) |",
        "",
        "## Next Steps",
        "",
        "- Review malicious/suspicious indicators above; pivot in vault for full OSINT",
        "- Confirm malicious IPs/FQDNs with `record_ioc()` if not already in vault",
        "- For unmatched public IPs, run `./scripts/perplexity_search.sh ioc <ip>`",
        "- Import CSVs into Timeline Explorer for timeline correlation",
    ]

    report_path = output_dir / "fan_ip_report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main(
    fqdn_file: Path,
    ip_file: Path,
    output_dir: Path | None = None,
    case_id: str = "",
) -> None:
    for f in (fqdn_file, ip_file):
        if not f.exists():
            print(f"[fan_lookup] ERROR: file not found: {f}", file=sys.stderr)
            sys.exit(1)

    stem = fqdn_file.parent.name
    if output_dir is None:
        project_root = Path(__file__).parent.parent
        output_dir = project_root / "analysis" / "cti" / stem

    print(f"[fan_lookup] FQDN file : {fqdn_file}")
    print(f"[fan_lookup] IP file   : {ip_file}")
    print(f"[fan_lookup] Output    : {output_dir}")
    print(f"[fan_lookup] Case ID   : {case_id or '(none)'}")
    print()

    fqdn_entries = _load_fqdns(fqdn_file)
    pcap_ips = _load_ips(ip_file)
    pcap_ip_set = set(pcap_ips)
    print(f"[fan_lookup] Loaded {len(fqdn_entries)} FQDNs, {len(pcap_ips)} IPs")
    print()

    print("=== Phase 1: FQDN enrichment ===")
    fqdn_results = enrich_fqdns(fqdn_entries, pcap_ip_set, case_id)

    fqdn_resolved_map = {
        r["fqdn"]: [ip for ip in r["resolved_ips"].split(",") if ip]
        for r in fqdn_results
    }

    print()
    print("=== Phase 2: IP enrichment ===")
    ip_results = enrich_ips(pcap_ips, fqdn_resolved_map, case_id)

    print()
    print("=== Writing outputs ===")
    report_path = write_outputs(output_dir, stem, fqdn_results, ip_results, case_id)

    print(f"\n[fan_lookup] correlation.csv  : {output_dir / 'correlation.csv'}")
    print(f"[fan_lookup] ip_enrichment.csv: {output_dir / 'ip_enrichment.csv'}")
    print(f"[fan_lookup] Report           : {report_path}")
    print(f"[fan_lookup] Done.")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="CTI IP Lookup — FQDN-IP correlation, DNS resolution, OSINT enrichment",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/fan_ip_lookup.py --stem 2026-04-16-Lumma-Stealer --case-id CASE-2025-001\n"
            "  python3 lib/fan_ip_lookup.py analysis/pcap/capture/unique_fqdns.txt \\\n"
            "      analysis/pcap/capture/unique_ips.txt --case-id CASE-2025-001\n"
        ),
    )
    p.add_argument("fqdn_file", metavar="FQDN_FILE", nargs="?",
                   help="Path to unique_fqdns.txt")
    p.add_argument("ip_file", metavar="IP_FILE", nargs="?",
                   help="Path to unique_ips.txt")
    p.add_argument("--stem", metavar="PCAP_STEM",
                   help="PCAP stem — auto-discovers files from ./analysis/pcap/<stem>/")
    p.add_argument("--output-dir", metavar="DIR",
                   help="Output directory (default: ./analysis/fan_ip/<stem>/)")
    p.add_argument("--case-id", metavar="ID", default="",
                   help="Case identifier — stamped into vault notes and the report")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()

    if args.stem:
        base = Path(__file__).parent.parent / "analysis" / "pcap" / args.stem
        fqdn_path = base / "unique_fqdns.txt"
        ip_path = base / "unique_ips.txt"
    elif args.fqdn_file and args.ip_file:
        fqdn_path = Path(args.fqdn_file)
        ip_path = Path(args.ip_file)
    else:
        _build_parser().print_help()
        sys.exit(0)

    out = Path(args.output_dir) if args.output_dir else None
    main(fqdn_path, ip_path, output_dir=out, case_id=args.case_id)
