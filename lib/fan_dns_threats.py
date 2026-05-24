#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_dns_threats.py — CTI DNS Threat Analyzer

Detects DNS-based attack patterns in a PCAP file:
  - DNS amplification / reflection (T1498.002)
  - NXDomain flooding (T1498)
  - Domain Generation Algorithm usage (T1568.002)
  - C&C DNS beaconing (T1071.004)
  - DNS data exfiltration / tunneling (T1048.001 / T1572)
  - Excessive DNS query rates (T1498)
  - Fast flux DNS (T1568.001)
  - Unauthorized / unexpected DNS servers (T1584.002)
  - Unusual DNS record type lookups — ANY, AXFR, TXT, etc. (T1071.004)
  - Typosquatting / domain impersonation (T1583.001)
  - DNS response spoofing / hijacking (T1557)

Outputs (./analysis/dns_threats/<stem>/):
  dns_threats_report.md  — human-readable report with MITRE mappings
  dns_threats.json       — machine-readable structured findings
  dns_flows.csv          — annotated per-packet DNS flow log

Usage:
  python3 lib/fan_dns_threats.py <pcap_file> [--case-id CASE-001]
  python3 lib/fan_dns_threats.py <pcap_file> --stem <name> --output-dir ./out/
  python3 lib/fan_dns_threats.py <pcap_file> --no-vault
"""

import argparse
import csv
import ipaddress
import json
import math
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path


# ── Well-known public DNS servers ────────────────────────────────────────────

KNOWN_DNS_SERVERS = frozenset([
    "8.8.8.8", "8.8.4.4",                    # Google
    "1.1.1.1", "1.0.0.1",                    # Cloudflare
    "9.9.9.9", "149.112.112.112",            # Quad9
    "208.67.222.222", "208.67.220.220",      # OpenDNS
])

# ── DNS record type names ────────────────────────────────────────────────────

QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
    15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 43: "DS",
    46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3",
    64: "SVCB", 65: "HTTPS", 251: "IXFR", 252: "AXFR",
    255: "ANY", 257: "CAA",
}

# Types that warrant additional scrutiny
SUSPICIOUS_QTYPES = {
    255: "ANY",    # classic amplification vector
    252: "AXFR",   # zone transfer
    251: "IXFR",   # incremental zone transfer
    16:  "TXT",    # tunneling vector
}

RCODE_NAMES = {
    0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL",
    3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED",
    9: "NOTAUTH",
}

# ── MITRE ATT&CK ─────────────────────────────────────────────────────────────

MITRE_MAP = {
    "amplification":       ("T1498.002", "Network DoS: Reflection Amplification"),
    "nxdomain_flood":      ("T1498",     "Network Denial of Service"),
    "dga":                 ("T1568.002", "Dynamic Resolution: Domain Generation Algorithms"),
    "beaconing":           ("T1071.004", "Application Layer Protocol: DNS"),
    "exfiltration":        ("T1048.001", "Exfiltration Over Alternative Protocol: DNS"),
    "tunneling":           ("T1572",     "Protocol Tunneling"),
    "excessive_queries":   ("T1498",     "Network Denial of Service"),
    "fast_flux":           ("T1568.001", "Dynamic Resolution: Fast Flux DNS"),
    "unauthorized_server": ("T1584.002", "Compromise Infrastructure: DNS Server"),
    "unusual_types":       ("T1071.004", "Application Layer Protocol: DNS"),
    "typosquatting":       ("T1583.001", "Acquire Infrastructure: Domains"),
    "spoofing":            ("T1557",     "Adversary-in-the-Middle"),
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ── Detection thresholds ──────────────────────────────────────────────────────

DGA_ENTROPY_THRESHOLD  = 3.5   # Shannon entropy bits — high = likely random
DGA_MIN_SLD_LENGTH     = 10    # Short SLDs are rarely DGA
DGA_CONSONANT_RATIO    = 0.65  # Consonant-heavy = less human-readable
BEACON_MIN_QUERIES     = 5     # Minimum queries to analyse timing
BEACON_MAX_CV          = 0.30  # Coefficient of variation — low = regular
BEACON_MIN_INTERVAL    = 5.0   # Ignore sub-5s intervals (DNS retry noise)
EXFIL_LABEL_LEN        = 40    # Single subdomain label character count
EXFIL_TOTAL_LEN        = 100   # Total FQDN character count
EXFIL_UNIQUE_SUBS      = 15    # Unique subdomains for same apex
NXDOMAIN_FLOOD_THRESH  = 20    # NXDOMAINs per source IP
EXCESSIVE_QUERY_THRESH = 200   # Total queries per source IP
AMPLIFICATION_FACTOR   = 5.0   # Response / query byte ratio
FAST_FLUX_MAX_TTL      = 300   # Seconds — suspicious if A record TTL < this
FAST_FLUX_MIN_IPS      = 3     # Unique IPs per domain across capture

# ── Well-known domains for typosquatting comparison ──────────────────────────

WELL_KNOWN_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "facebook.com", "amazon.com",
    "youtube.com", "twitter.com", "instagram.com", "linkedin.com", "github.com",
    "netflix.com", "office.com", "live.com", "outlook.com", "windows.com",
    "adobe.com", "dropbox.com", "paypal.com", "ebay.com", "cloudflare.com",
    "akamai.com", "fastly.com", "cloudfront.net", "amazonaws.com",
    "googleusercontent.com", "gstatic.com", "googleapis.com",
    "windowsupdate.com", "akamaitechnologies.com", "digicert.com",
]

# CDN / infra patterns that legitimately look entropy-heavy
_LEGIT_RE = re.compile(
    r"\b(cdn|edge|static|assets|media|img|api|mail|smtp|imap|pop|s3|ec2|"
    r"akamai|cloudfront|fastly|azure|amazonaws|googleapi|akam|lync|"
    r"sharepoint|onedrive|office365)\b", re.I
)


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ts_str(ts: float) -> str:
    if not ts:
        return ""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _shannon(s: str) -> float:
    if not s:
        return 0.0
    s = s.lower()
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def _consonant_ratio(s: str) -> float:
    s = s.lower()
    alpha = sum(1 for c in s if c.isalpha())
    consonants = sum(1 for c in s if c in "bcdfghjklmnpqrstvwxyz")
    return consonants / alpha if alpha else 0.0


def _apex(fqdn: str) -> str:
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else fqdn


def _sld(fqdn: str) -> str:
    parts = fqdn.rstrip(".").split(".")
    return parts[-2] if len(parts) >= 2 else fqdn


def _subdomain(fqdn: str) -> str:
    parts = fqdn.rstrip(".").split(".")
    return ".".join(parts[:-2]) if len(parts) > 2 else ""


def _is_public(ip_str: str) -> bool:
    try:
        a = ipaddress.ip_address(ip_str)
        return not (a.is_private or a.is_loopback or a.is_link_local
                    or a.is_multicast or a.is_reserved or a.is_unspecified)
    except ValueError:
        return False


def _cv(vals: list) -> float:
    if len(vals) < 2:
        return float("inf")
    mean = sum(vals) / len(vals)
    if mean == 0:
        return 0.0
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    return math.sqrt(var) / mean


def _edit_distance(a: str, b: str) -> int:
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        cur = [i + 1]
        for j, cb in enumerate(b):
            cur.append(min(prev[j + 1] + 1, cur[-1] + 1, prev[j] + (ca != cb)))
        prev = cur
    return prev[-1]


def _first(field_val: str) -> str:
    """Return the first comma-separated value from a tshark multi-occurrence field."""
    return field_val.split(",")[0].strip() if field_val else ""


def _all_vals(field_val: str) -> list[str]:
    return [v.strip() for v in field_val.split(",") if v.strip()]


# ── PCAP Extraction ───────────────────────────────────────────────────────────

def extract_dns_records(pcap_path: Path) -> list[dict]:
    """Extract all DNS packets from PCAP using tshark. Returns list of record dicts."""
    fields = [
        "frame.time_epoch",
        "ip.src", "ip.dst",
        "ipv6.src", "ipv6.dst",
        "dns.id",
        "dns.flags.response",
        "dns.flags.rcode",
        "dns.qry.name",
        "dns.qry.type",
        "dns.a",
        "dns.aaaa",
        "dns.txt",
        "dns.resp.ttl",
        "dns.count.answers",
        "frame.len",
    ]
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "dns",
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=a",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, check=True, timeout=600)
    except subprocess.CalledProcessError as e:
        print(f"[dns_threats] tshark error: {e.stderr[:400]}", file=sys.stderr)
        return []
    except subprocess.TimeoutExpired:
        print("[dns_threats] tshark timed out after 10 minutes.", file=sys.stderr)
        return []

    records = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        p = dict(zip(fields, parts))

        try:
            ts = float(_first(p["frame.time_epoch"]))
        except (ValueError, TypeError):
            ts = 0.0

        is_resp = _first(p["dns.flags.response"]) == "1"

        try:
            rcode = int(_first(p["dns.flags.rcode"]))
        except (ValueError, TypeError):
            rcode = 0

        try:
            qtype = int(_first(p["dns.qry.type"]))
        except (ValueError, TypeError):
            qtype = 0

        try:
            ttl = int(_first(p["dns.resp.ttl"])) if p["dns.resp.ttl"] else None
        except (ValueError, TypeError):
            ttl = None

        try:
            answer_count = int(_first(p["dns.count.answers"])) if p["dns.count.answers"] else 0
        except (ValueError, TypeError):
            answer_count = 0

        try:
            frame_len = int(_first(p["frame.len"])) if p["frame.len"] else 0
        except (ValueError, TypeError):
            frame_len = 0

        # IPv4 preferred; fall back to IPv6
        src = _first(p["ip.src"]) or _first(p["ipv6.src"])
        dst = _first(p["ip.dst"]) or _first(p["ipv6.dst"])

        fqdn = _first(p["dns.qry.name"]).rstrip(".")
        a_records  = _all_vals(p["dns.a"])
        aaaa_recs  = _all_vals(p["dns.aaaa"])
        txt_data   = p["dns.txt"].strip()

        dns_server = src if is_resp else dst

        records.append({
            "ts": ts, "src": src, "dst": dst,
            "dns_id": _first(p["dns.id"]),
            "is_response": is_resp,
            "rcode": rcode, "fqdn": fqdn,
            "qtype": qtype, "a_records": a_records, "aaaa_recs": aaaa_recs,
            "txt": txt_data, "ttl": ttl, "answer_count": answer_count,
            "frame_len": frame_len, "dns_server": dns_server,
        })

    return records


# ── Detection modules ─────────────────────────────────────────────────────────

def detect_amplification(records: list[dict]) -> dict:
    """DNS amplification / reflection: large responses to small queries, ANY queries."""
    # Index queries by (dns_id, fqdn, dns_server) for matching
    queries: dict[tuple, dict] = {}
    for r in records:
        if not r["is_response"]:
            key = (r["dns_id"], r["fqdn"], r["dns_server"])
            queries.setdefault(key, r)

    findings = []
    for r in records:
        if not r["is_response"]:
            continue
        key = (r["dns_id"], r["fqdn"], r["dns_server"])
        q = queries.get(key)
        if q:
            factor = r["frame_len"] / max(q["frame_len"], 1)
            if factor >= AMPLIFICATION_FACTOR or r["qtype"] == 255:
                findings.append({
                    "fqdn": r["fqdn"],
                    "qtype": QTYPE_NAMES.get(r["qtype"], str(r["qtype"])),
                    "src_ip": q["src"],
                    "dns_server": r["dns_server"],
                    "query_bytes": q["frame_len"],
                    "response_bytes": r["frame_len"],
                    "amplification_factor": round(r["frame_len"] / max(q["frame_len"], 1), 1),
                    "ts": _ts_str(r["ts"]),
                })
        elif r["qtype"] == 255:
            # ANY response with no matching query in capture
            findings.append({
                "fqdn": r["fqdn"], "qtype": "ANY",
                "src_ip": "", "dns_server": r["dns_server"],
                "query_bytes": 0, "response_bytes": r["frame_len"],
                "amplification_factor": None, "ts": _ts_str(r["ts"]),
            })

    # Lone ANY queries (no response captured — firewall drop or one-sided capture)
    responded_keys = {(r["dns_id"], r["fqdn"], r["dns_server"]) for r in records if r["is_response"]}
    for q in records:
        if not q["is_response"] and q["qtype"] == 255:
            key = (q["dns_id"], q["fqdn"], q["dns_server"])
            if key not in responded_keys:
                findings.append({
                    "fqdn": q["fqdn"], "qtype": "ANY (no response captured)",
                    "src_ip": q["src"], "dns_server": q["dns_server"],
                    "query_bytes": q["frame_len"], "response_bytes": 0,
                    "amplification_factor": None, "ts": _ts_str(q["ts"]),
                })

    severity = "high" if findings else "info"
    return {
        "name": "DNS Amplification / Reflection",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["amplification"],
        "findings": findings[:50],
        "description": (
            f"{len(findings)} DNS amplification indicator(s) detected "
            f"(amplification factor ≥{AMPLIFICATION_FACTOR}x or ANY queries). "
            "Used in DDoS reflection attacks."
        ) if findings else "No DNS amplification patterns detected.",
    }


def detect_nxdomain_flood(records: list[dict]) -> dict:
    """NXDomain flooding: many NXDOMAIN responses per source IP."""
    by_src: dict[str, list] = defaultdict(list)
    for r in records:
        if r["is_response"] and r["rcode"] == 3:
            by_src[r["src"]].append(r)

    findings = []
    for ip, recs in by_src.items():
        if len(recs) < NXDOMAIN_FLOOD_THRESH:
            continue
        recs.sort(key=lambda x: x["ts"])
        duration = recs[-1]["ts"] - recs[0]["ts"]
        findings.append({
            "source_ip": ip,
            "nxdomain_count": len(recs),
            "duration_sec": round(duration, 1),
            "rate_per_sec": round(len(recs) / max(duration, 1), 2),
            "sample_domains": [r["fqdn"] for r in recs[:10]],
            "start": _ts_str(recs[0]["ts"]),
            "end": _ts_str(recs[-1]["ts"]),
        })

    findings.sort(key=lambda x: x["nxdomain_count"], reverse=True)
    severity = "high" if findings else "info"
    return {
        "name": "NXDomain Flooding",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["nxdomain_flood"],
        "findings": findings[:20],
        "description": (
            f"{len(findings)} source IP(s) generated ≥{NXDOMAIN_FLOOD_THRESH} NXDOMAIN responses. "
            "Indicates DGA malware, DNS amplification recon, or active DoS."
        ) if findings else "No NXDomain flooding detected.",
    }


def detect_dga(records: list[dict]) -> dict:
    """DGA: high-entropy, long, consonant-heavy domain names."""
    queried = {r["fqdn"] for r in records if not r["is_response"] and r["fqdn"]}
    skip_apexes = {_apex(d) for d in WELL_KNOWN_DOMAINS}
    findings = []

    for fqdn in queried:
        if not fqdn:
            continue
        apex = _apex(fqdn)
        if apex in skip_apexes or _LEGIT_RE.search(fqdn):
            continue
        sld = _sld(fqdn)
        if len(sld) < DGA_MIN_SLD_LENGTH:
            continue

        ent   = _shannon(sld)
        cr    = _consonant_ratio(sld)
        digs  = sum(1 for c in sld if c.isdigit())

        score, reasons = 0, []
        if ent >= DGA_ENTROPY_THRESHOLD:
            score += 2; reasons.append(f"entropy={ent:.2f}")
        if cr >= DGA_CONSONANT_RATIO:
            score += 1; reasons.append(f"consonant_ratio={cr:.2f}")
        if len(sld) >= 16:
            score += 1; reasons.append(f"sld_len={len(sld)}")
        if digs >= 4 and digs / len(sld) > 0.25:
            score += 1; reasons.append(f"digit_heavy={digs}/{len(sld)}")

        if score >= 3:
            findings.append({
                "fqdn": fqdn, "sld": sld,
                "entropy": round(ent, 2),
                "consonant_ratio": round(cr, 2),
                "sld_length": len(sld),
                "dga_score": score,
                "reasons": reasons,
            })

    findings.sort(key=lambda x: x["dga_score"], reverse=True)
    severity = "high" if len(findings) > 5 else ("medium" if findings else "info")
    return {
        "name": "Domain Generation Algorithm (DGA)",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["dga"],
        "findings": findings[:30],
        "description": (
            f"{len(findings)} domain(s) exhibit DGA-like characteristics "
            "(high entropy, long consonant-heavy SLD, digit-heavy names). "
            "Indicates malware using DGA for C2 resilience against takedowns."
        ) if findings else "No DGA patterns detected.",
    }


def detect_beaconing(records: list[dict]) -> dict:
    """C&C DNS beaconing: regular-interval queries from the same host to the same domain."""
    query_ts: dict[tuple, list] = defaultdict(list)
    for r in records:
        if not r["is_response"] and r["fqdn"]:
            query_ts[(r["src"], _apex(r["fqdn"]))].append(r["ts"])

    findings = []
    for (src_ip, domain), timestamps in query_ts.items():
        if len(timestamps) < BEACON_MIN_QUERIES:
            continue
        timestamps.sort()
        intervals = [b - a for a, b in zip(timestamps, timestamps[1:])
                     if b - a >= BEACON_MIN_INTERVAL]
        if len(intervals) < 2:
            continue
        cv = _cv(intervals)
        mean_iv = sum(intervals) / len(intervals)
        if cv <= BEACON_MAX_CV:
            findings.append({
                "src_ip": src_ip, "domain": domain,
                "query_count": len(timestamps),
                "mean_interval_sec": round(mean_iv, 1),
                "coefficient_of_variation": round(cv, 3),
                "start": _ts_str(timestamps[0]),
                "end": _ts_str(timestamps[-1]),
                "duration_sec": round(timestamps[-1] - timestamps[0], 1),
            })

    findings.sort(key=lambda x: x["coefficient_of_variation"])
    severity = "high" if findings else "info"
    return {
        "name": "C&C DNS Beaconing",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["beaconing"],
        "findings": findings[:20],
        "description": (
            f"{len(findings)} host+domain pair(s) show regular-interval DNS queries "
            f"(CV ≤ {BEACON_MAX_CV}). Highly regular timing indicates automated C2 check-ins."
        ) if findings else "No DNS beaconing patterns detected.",
    }


def detect_exfiltration(records: list[dict]) -> dict:
    """DNS data exfiltration / tunneling: long labels, high-entropy subdomains, TXT abuse."""
    apex_subs: dict[str, set] = defaultdict(set)
    apex_samples: dict[str, list] = defaultdict(list)
    findings = []
    seen_fqdns: set[str] = set()

    for r in records:
        if r["is_response"] or not r["fqdn"]:
            continue
        fqdn = r["fqdn"]
        sub  = _subdomain(fqdn)
        apex = _apex(fqdn)
        if sub:
            apex_subs[apex].add(sub)
            if len(apex_samples[apex]) < 5:
                apex_samples[apex].append(fqdn)

        if fqdn in seen_fqdns or not sub:
            continue
        seen_fqdns.add(fqdn)

        longest_label = max((len(lbl) for lbl in sub.split(".")), default=0)
        sub_flat      = sub.replace(".", "")
        sub_entropy   = _shannon(sub_flat)

        score, reasons = 0, []
        if longest_label >= EXFIL_LABEL_LEN:
            score += 3; reasons.append(f"label_len={longest_label}")
        if len(fqdn) >= EXFIL_TOTAL_LEN:
            score += 2; reasons.append(f"fqdn_len={len(fqdn)}")
        if sub_entropy >= 4.0:
            score += 2; reasons.append(f"subdomain_entropy={sub_entropy:.2f}")
        if re.fullmatch(r"[A-Za-z0-9+/]{30,}={0,2}", sub_flat):
            score += 3; reasons.append("base64_pattern")
        if re.fullmatch(r"[0-9a-fA-F]{30,}", sub_flat):
            score += 3; reasons.append("hex_pattern")

        if score >= 3:
            findings.append({
                "fqdn": fqdn, "apex": apex, "subdomain": sub,
                "exfil_score": score, "reasons": reasons,
                "src_ip": r["src"], "ts": _ts_str(r["ts"]),
            })

    # Many unique subdomains per apex = sustained tunnel
    for apex, subs in apex_subs.items():
        if len(subs) >= EXFIL_UNIQUE_SUBS:
            findings.append({
                "fqdn": f"*.{apex}", "apex": apex,
                "subdomain": f"{len(subs)} unique subdomains",
                "exfil_score": 5,
                "reasons": [f"unique_subdomains={len(subs)}"],
                "src_ip": "", "ts": "",
                "samples": apex_samples[apex],
            })

    # Bulk TXT queries
    txt_queries = [r for r in records if not r["is_response"] and r["qtype"] == 16]
    if len(txt_queries) > 5:
        findings.append({
            "fqdn": f"{len(txt_queries)} TXT queries total",
            "apex": "", "subdomain": "",
            "exfil_score": 2, "reasons": [f"txt_query_count={len(txt_queries)}"],
            "src_ip": "", "ts": "",
            "samples": [r["fqdn"] for r in txt_queries[:5]],
        })

    findings.sort(key=lambda x: x["exfil_score"], reverse=True)
    severity = ("critical" if any(f["exfil_score"] >= 5 for f in findings)
                else "high" if findings else "info")
    return {
        "name": "DNS Data Exfiltration / Tunneling",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["exfiltration"],
        "findings": findings[:30],
        "description": (
            f"{len(findings)} exfiltration indicator(s): long subdomain labels, "
            "high-entropy or encoded subdomains, many unique subdomains, or TXT abuse."
        ) if findings else "No DNS exfiltration patterns detected.",
    }


def detect_excessive_queries(records: list[dict]) -> dict:
    """Excessive DNS query rate from a single source IP."""
    by_src: dict[str, list] = defaultdict(list)
    for r in records:
        if not r["is_response"]:
            by_src[r["src"]].append(r["ts"])

    findings = []
    for ip, timestamps in by_src.items():
        if len(timestamps) < EXCESSIVE_QUERY_THRESH:
            continue
        timestamps.sort()
        duration = timestamps[-1] - timestamps[0]
        # Peak burst: largest count in any 1-second window
        max_burst = 0
        for i, t0 in enumerate(timestamps):
            window = sum(1 for t in timestamps[i:] if t - t0 <= 1.0)
            if window > max_burst:
                max_burst = window
        findings.append({
            "src_ip": ip,
            "total_queries": len(timestamps),
            "peak_burst_qps": max_burst,
            "avg_qps": round(len(timestamps) / max(duration, 1), 2),
            "duration_sec": round(duration, 1),
            "start": _ts_str(timestamps[0]),
            "end": _ts_str(timestamps[-1]),
        })

    findings.sort(key=lambda x: x["total_queries"], reverse=True)
    severity = "medium" if findings else "info"
    return {
        "name": "Excessive DNS Query Rate",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["excessive_queries"],
        "findings": findings[:20],
        "description": (
            f"{len(findings)} source IP(s) sent ≥{EXCESSIVE_QUERY_THRESH} DNS queries. "
            "May indicate a scanner, infected host, or DoS tool."
        ) if findings else "No excessive DNS query rates detected.",
    }


def detect_fast_flux(records: list[dict]) -> dict:
    """Fast flux DNS: domain resolves to many IPs and/or very short TTL."""
    domain_ips:  dict[str, set]  = defaultdict(set)
    domain_ttls: dict[str, list] = defaultdict(list)

    skip = {_apex(d) for d in WELL_KNOWN_DOMAINS}

    for r in records:
        if not r["is_response"] or not r["a_records"]:
            continue
        apex = _apex(r["fqdn"])
        if apex in skip:
            continue
        for ip in r["a_records"]:
            domain_ips[apex].add(ip)
        if r["ttl"] is not None:
            domain_ttls[apex].append(r["ttl"])

    findings = []
    for domain, ips in domain_ips.items():
        ttls    = domain_ttls.get(domain, [])
        min_ttl = min(ttls) if ttls else None
        avg_ttl = round(sum(ttls) / len(ttls), 0) if ttls else None
        many_ips  = len(ips) >= FAST_FLUX_MIN_IPS
        short_ttl = min_ttl is not None and min_ttl <= FAST_FLUX_MAX_TTL

        if many_ips or short_ttl:
            findings.append({
                "domain": domain,
                "unique_ip_count": len(ips),
                "ips": sorted(ips)[:10],
                "min_ttl_sec": min_ttl,
                "avg_ttl_sec": avg_ttl,
                "flux_score": (2 if many_ips else 0) + (1 if short_ttl else 0),
            })

    findings.sort(key=lambda x: x["flux_score"], reverse=True)
    high_risk = [f for f in findings
                 if f["unique_ip_count"] >= 5 or (f["min_ttl_sec"] or 9999) < 60]
    severity = "high" if high_risk else ("medium" if findings else "info")
    return {
        "name": "Fast Flux DNS",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["fast_flux"],
        "findings": findings[:30],
        "description": (
            f"{len(findings)} domain(s) show fast flux indicators: ≥{FAST_FLUX_MIN_IPS} "
            f"unique IPs and/or TTL ≤{FAST_FLUX_MAX_TTL}s."
        ) if findings else "No fast flux patterns detected.",
    }


def detect_unauthorized_servers(records: list[dict]) -> dict:
    """Public DNS servers not in the known-good list."""
    server_clients: dict[str, set] = defaultdict(set)
    server_queries: dict[str, int] = defaultdict(int)
    for r in records:
        if not r["is_response"] and r["dns_server"]:
            server_clients[r["dns_server"]].add(r["src"])
            server_queries[r["dns_server"]] += 1

    findings = []
    for server, clients in server_clients.items():
        if not _is_public(server) or server in KNOWN_DNS_SERVERS:
            continue
        findings.append({
            "dns_server": server,
            "query_count": server_queries[server],
            "client_count": len(clients),
            "clients": sorted(clients)[:10],
        })

    findings.sort(key=lambda x: x["query_count"], reverse=True)
    severity = "medium" if findings else "info"
    return {
        "name": "Unauthorized / Unexpected DNS Servers",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["unauthorized_server"],
        "findings": findings[:20],
        "description": (
            f"{len(findings)} public DNS server(s) not in the known-good list. "
            "May indicate DNS hijacking, DoH bypass, or policy violation."
        ) if findings else "All observed public DNS servers are in the known-good list.",
    }


def detect_unusual_types(records: list[dict]) -> dict:
    """Unusual DNS record type queries: ANY, AXFR, IXFR, bulk TXT."""
    by_type: dict[int, list] = defaultdict(list)
    for r in records:
        if not r["is_response"] and r["qtype"] in SUSPICIOUS_QTYPES:
            by_type[r["qtype"]].append(r)

    findings = []
    for qtype, recs in by_type.items():
        type_name  = QTYPE_NAMES.get(qtype, f"TYPE{qtype}")
        is_zonetfr = qtype in (251, 252)
        findings.append({
            "qtype": type_name,
            "qtype_code": qtype,
            "query_count": len(recs),
            "unique_domains": sorted({r["fqdn"] for r in recs})[:10],
            "unique_sources": sorted({r["src"] for r in recs})[:10],
            "type_severity": "critical" if is_zonetfr else "medium",
        })

    findings.sort(key=lambda x: SEVERITY_ORDER.get(x["type_severity"], 9))
    severity = ("critical" if any(f["qtype_code"] in (251, 252) for f in findings)
                else "medium" if findings else "info")
    return {
        "name": "Unusual DNS Record Types",
        "severity": severity,
        "count": sum(f["query_count"] for f in findings),
        "mitre": MITRE_MAP["unusual_types"],
        "findings": findings,
        "description": (
            f"{len(findings)} suspicious DNS record type(s): "
            f"{', '.join(f['qtype'] for f in findings)}. "
            "AXFR/IXFR = zone transfer recon; TXT = tunneling vector; ANY = amplification."
        ) if findings else "No unusual DNS record types detected.",
    }


def detect_typosquatting(records: list[dict]) -> dict:
    """Domains within edit distance 1–2 of well-known brands."""
    queried_apexes = {_apex(r["fqdn"]) for r in records if r["fqdn"]}
    skip = set(WELL_KNOWN_DOMAINS)
    findings = []

    for domain in queried_apexes:
        if not domain or domain in skip:
            continue
        best_dist, best_known = 999, ""
        for known in WELL_KNOWN_DOMAINS:
            if domain.endswith("." + known):
                break
            d = _edit_distance(domain, known)
            if d < best_dist:
                best_dist, best_known = d, known
        else:
            if 0 < best_dist <= 2:
                qcount = sum(1 for r in records
                             if not r["is_response"] and _apex(r["fqdn"]) == domain)
                findings.append({
                    "suspicious_domain": domain,
                    "similar_to": best_known,
                    "edit_distance": best_dist,
                    "query_count": qcount,
                })

    findings.sort(key=lambda x: (x["edit_distance"], -x["query_count"]))
    severity = "medium" if findings else "info"
    return {
        "name": "Typosquatting / Domain Impersonation",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["typosquatting"],
        "findings": findings[:30],
        "description": (
            f"{len(findings)} domain(s) are visually similar (edit distance ≤ 2) to "
            "well-known legitimate domains. May indicate phishing or brand impersonation."
        ) if findings else "No typosquatting patterns detected.",
    }


def detect_spoofing(records: list[dict]) -> dict:
    """DNS response spoofing: same domain returns different A records from different servers."""
    # {(fqdn, qtype): {dns_server: frozenset(a_records)}}
    by_domain: dict[tuple, dict] = defaultdict(dict)
    for r in records:
        if not r["is_response"] or not r["a_records"] or not r["fqdn"]:
            continue
        key = (_apex(r["fqdn"]), r["qtype"])
        srv = r["dns_server"]
        existing = by_domain[key].get(srv, frozenset())
        by_domain[key][srv] = existing | frozenset(r["a_records"])

    findings = []
    for (fqdn, qtype), srv_answers in by_domain.items():
        if len(srv_answers) < 2:
            continue
        answer_sets = list(srv_answers.values())
        if len({frozenset(s) for s in answer_sets}) > 1:
            findings.append({
                "fqdn": fqdn,
                "qtype": QTYPE_NAMES.get(qtype, str(qtype)),
                "conflicting_answers": {
                    server: sorted(ips) for server, ips in srv_answers.items()
                },
            })

    severity = "high" if findings else "info"
    return {
        "name": "DNS Response Spoofing / Hijacking",
        "severity": severity, "count": len(findings),
        "mitre": MITRE_MAP["spoofing"],
        "findings": findings[:20],
        "description": (
            f"{len(findings)} domain(s) received conflicting DNS answers from different servers. "
            "May indicate DNS cache poisoning, MITM, or split-horizon misconfiguration."
        ) if findings else "No DNS response spoofing detected.",
    }


# ── Output writers ────────────────────────────────────────────────────────────

def write_report(results: dict, output_dir: Path, pcap_stem: str,
                 case_id: str | None, total_records: int) -> Path:
    now    = _now_utc()
    active = {k: v for k, v in results.items() if v["severity"] != "info"}
    ordered = sorted(active.items(), key=lambda x: SEVERITY_ORDER.get(x[1]["severity"], 9))

    lines = [
        "# DNS Threat Analysis Report", "",
        "| Field | Value |",
        "|-------|-------|",
        f"| PCAP stem | `{pcap_stem}` |",
        f"| Case ID | `{case_id or 'N/A'}` |",
        f"| Generated (UTC) | `{now}` |",
        f"| DNS records analysed | {total_records} |",
        f"| Threat categories triggered | {len(active)} of {len(results)} |",
        "", "---", "", "## Executive Summary", "",
    ]

    if not active:
        lines.append("No DNS threats detected across all detection categories.")
    else:
        lines += [
            "| Severity | Category | Findings | MITRE ATT&CK |",
            "|----------|----------|----------|--------------|",
        ]
        for _, r in ordered:
            mid, mname = r["mitre"]
            lines.append(
                f"| **{r['severity'].upper()}** | {r['name']} | {r['count']} "
                f"| [{mid}] {mname} |"
            )

    lines += ["", "---", ""]

    for _, r in ordered:
        mid, mname = r["mitre"]
        lines += [
            f"## {r['name']}", "",
            f"**Severity:** {r['severity'].upper()}  "
            f"**MITRE:** [{mid}](https://attack.mitre.org/techniques/{mid.replace('.', '/')}) — {mname}",
            "",
            r["description"], "",
        ]
        findings = r.get("findings", [])
        if findings:
            lines.append(f"**Top findings ({min(10, len(findings))} of {len(findings)}):**")
            lines.append("```json")
            for f in findings[:10]:
                lines.append(json.dumps(f, default=str))
            lines.append("```")
        lines += ["", "---", ""]

    clean = [v["name"] for v in results.values() if v["severity"] == "info"]
    if clean:
        lines += ["## Clean Categories", "",
                  "The following threat categories returned no findings:", ""]
        lines += [f"- {n}" for n in clean]
        lines.append("")

    path = output_dir / "dns_threats_report.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"[dns_threats] Report           : {path}")
    return path


def write_json(results: dict, output_dir: Path) -> Path:
    path = output_dir / "dns_threats.json"
    path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"[dns_threats] JSON             : {path}")
    return path


def write_csv(records: list[dict], output_dir: Path) -> Path:
    path = output_dir / "dns_flows.csv"
    fields = [
        "timestamp_utc", "src_ip", "dst_ip", "dns_server",
        "direction", "rcode", "fqdn",
        "qtype_code", "qtype_name",
        "a_records", "ttl_sec", "answer_count", "frame_len_bytes",
    ]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        for r in records:
            w.writerow({
                "timestamp_utc":  _ts_str(r["ts"]),
                "src_ip":         r["src"],
                "dst_ip":         r["dst"],
                "dns_server":     r["dns_server"],
                "direction":      "response" if r["is_response"] else "query",
                "rcode":          RCODE_NAMES.get(r["rcode"], str(r["rcode"])),
                "fqdn":           r["fqdn"],
                "qtype_code":     r["qtype"],
                "qtype_name":     QTYPE_NAMES.get(r["qtype"], str(r["qtype"])),
                "a_records":      ",".join(r["a_records"]),
                "ttl_sec":        r["ttl"] if r["ttl"] is not None else "",
                "answer_count":   r["answer_count"],
                "frame_len_bytes": r["frame_len"],
            })
    print(f"[dns_threats] DNS flows CSV    : {path}")
    return path


# ── Vault integration ─────────────────────────────────────────────────────────

def save_to_vault(results: dict, case_id: str | None):
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ioc, record_ttp
    except ImportError as e:
        print(f"[dns_threats] [vault] Import failed: {e}", file=sys.stderr)
        return

    cid = case_id or "CTI-DNS-THREATS"

    for key, result in results.items():
        if result["severity"] not in ("critical", "high"):
            continue
        mid, mname = result["mitre"]
        try:
            record_ttp(mid, mname,
                       f"DNS threat: {result['name']}. "
                       f"{result['count']} finding(s). "
                       f"{result['description'][:200]}",
                       cid)
        except Exception as e:
            print(f"[dns_threats] [vault] TTP write failed ({mid}): {e}", file=sys.stderr)

        # Record specific suspicious domains as IOCs
        if key in ("dga", "typosquatting", "exfiltration", "fast_flux", "beaconing"):
            for finding in result.get("findings", [])[:5]:
                domain = (finding.get("fqdn") or finding.get("domain")
                          or finding.get("suspicious_domain", ""))
                if domain and "." in domain and not domain.startswith("*"):
                    try:
                        record_ioc("domain", domain,
                                   f"DNS threat: {result['name']}. "
                                   f"Reasons: {finding.get('reasons', finding.get('similar_to', ''))}",
                                   cid, severity=result["severity"])
                    except Exception as e:
                        print(f"[dns_threats] [vault] IOC write failed ({domain}): {e}",
                              file=sys.stderr)


# ── Entry point ───────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="CTI DNS Threat Analyzer — detect DNS-based attack patterns in a PCAP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s capture.pcap\n"
            "  %(prog)s capture.pcap --case-id CASE-2025-001\n"
            "  %(prog)s capture.pcap --stem my-capture --no-vault\n"
        ),
    )
    parser.add_argument("pcap", help="Path to PCAP / PCAPng file")
    parser.add_argument("--stem", default=None,
                        help="Output stem name (default: PCAP filename stem)")
    parser.add_argument("--case-id", dest="case_id", default=None,
                        help="Case ID stamped in report and vault entries")
    parser.add_argument("--output-dir", dest="output_dir", default=None,
                        help="Output directory (default: ./analysis/dns_threats/<stem>/)")
    parser.add_argument("--no-vault", dest="no_vault", action="store_true",
                        help="Skip writing findings to the Obsidian vault")
    args = parser.parse_args()

    pcap_path = Path(args.pcap).resolve()
    if not pcap_path.exists():
        print(f"[dns_threats] ERROR: file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    stem = args.stem or pcap_path.stem
    if args.output_dir:
        output_dir = Path(args.output_dir)
    else:
        output_dir = Path(__file__).parent.parent / "analysis" / "dns_threats" / stem
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[dns_threats] PCAP    : {pcap_path}")
    print(f"[dns_threats] Output  : {output_dir}")
    if args.case_id:
        print(f"[dns_threats] Case ID : {args.case_id}")

    print("[dns_threats] Extracting DNS records via tshark...")
    records = extract_dns_records(pcap_path)
    print(f"[dns_threats] Loaded {len(records)} DNS records")

    if not records:
        print("[dns_threats] No DNS records found in PCAP.", file=sys.stderr)
        sys.exit(0)

    print("[dns_threats] Running detection modules...")
    results = {
        "amplification":       detect_amplification(records),
        "nxdomain_flood":      detect_nxdomain_flood(records),
        "dga":                 detect_dga(records),
        "beaconing":           detect_beaconing(records),
        "exfiltration":        detect_exfiltration(records),
        "excessive_queries":   detect_excessive_queries(records),
        "fast_flux":           detect_fast_flux(records),
        "unauthorized_server": detect_unauthorized_servers(records),
        "unusual_types":       detect_unusual_types(records),
        "typosquatting":       detect_typosquatting(records),
        "spoofing":            detect_spoofing(records),
    }

    active = {k: v for k, v in results.items() if v["severity"] != "info"}
    if active:
        print("\n[dns_threats] === Threats Detected ===")
        for _, r in sorted(active.items(),
                           key=lambda x: SEVERITY_ORDER.get(x[1]["severity"], 9)):
            print(f"  [{r['severity'].upper():8s}] {r['name']}: {r['count']} finding(s)")
    else:
        print("[dns_threats] No DNS threats detected.")

    write_csv(records, output_dir)
    write_report(results, output_dir, stem, args.case_id, len(records))
    write_json(results, output_dir)

    if not args.no_vault:
        print("[dns_threats] Writing high-severity findings to vault...")
        save_to_vault(results, args.case_id)

    print("[dns_threats] Done.")


if __name__ == "__main__":
    main()
