#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_cert_inspector.py — TLS/SSL Certificate Inspector

Extracts X.509 certificates from a PCAP file and analyses their properties.
Detects self-signed certs, expired/invalid validity windows, wildcard subjects,
SNI/CN mismatches, and weak signature algorithms.

Usage:
    python3 lib/fan_cert_inspector.py <pcap_file> [--stem NAME] [--case-id ID]
                                       [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
ANALYSIS_DIR = PROJECT_ROOT / "analysis"

# Validity-period thresholds
SHORT_VALIDITY_DAYS   = 30    # < 30 days → suspiciously short (common in auto-deployed C2 certs)
LONG_VALIDITY_DAYS    = 398   # > 398 days → exceeds browser-policy maximum (Chrome/Apple)

# Known weak OID strings tshark may render as name or raw OID
WEAK_SIG_PATTERNS = {
    "md5WithRSAEncryption",
    "md5",
    "sha1WithRSAEncryption",
    "sha1",
    "id-dsa-with-sha1",
    "ecdsa-with-SHA1",
    "1.2.840.113549.1.1.4",   # md5WithRSAEncryption OID
    "1.2.840.113549.1.1.5",   # sha1WithRSAEncryption OID
    "1.2.840.10040.4.3",      # id-dsa-with-sha1 OID
    "1.2.840.10045.4.1",      # ecdsa-with-SHA1 OID
}

CATEGORIES = {
    "self_signed": {
        "name": "Self-Signed Certificate",
        "description": (
            "Certificates where the issuer is the same entity as the subject — i.e., the "
            "certificate was not signed by a trusted Certificate Authority. Self-signed "
            "certificates are a strong indicator of attacker-deployed infrastructure "
            "(C2 servers, MITM proxies, rogue access points). Legitimate servers rarely use "
            "self-signed certificates for externally accessible services."
        ),
        "severity": "critical",
        "mitre": ["T1587.003", "Develop Capabilities: Digital Certificates"],
    },
    "expired": {
        "name": "Expired Certificate",
        "description": (
            "Certificates whose validity period (notAfter) has elapsed. An expired certificate "
            "indicates either neglected infrastructure (poor security hygiene) or an attacker "
            "reusing old stolen credentials. Expired certificates also suggest the absence of "
            "automated certificate management, which is increasingly rare in legitimate operations."
        ),
        "severity": "high",
        "mitre": ["T1040", "Network Sniffing"],
    },
    "not_yet_valid": {
        "name": "Not Yet Valid Certificate",
        "description": (
            "Certificates whose validity period has not yet started (notBefore > now). "
            "These may indicate clock skew, misconfigured systems, or certificates issued "
            "far in advance of deployment — occasionally seen in staged attacker infrastructure."
        ),
        "severity": "medium",
        "mitre": ["T1040", "Network Sniffing"],
    },
    "short_validity": {
        "name": "Very Short Certificate Validity",
        "description": (
            f"Certificates valid for fewer than {SHORT_VALIDITY_DAYS} days. C2 frameworks "
            "frequently auto-generate short-lived certificates to evade certificate-based "
            "threat intel feeds. Legitimate short-lived certificates from Let's Encrypt "
            "(90-day) are common, but sub-30-day certificates are rare outside of attack "
            "tooling (Cobalt Strike, Sliver, Havoc default configs)."
        ),
        "severity": "high",
        "mitre": ["T1587.003", "Develop Capabilities: Digital Certificates"],
    },
    "long_validity": {
        "name": "Excessive Certificate Validity Period",
        "description": (
            f"Certificates valid for more than {LONG_VALIDITY_DAYS} days (> 13 months). "
            "Browser vendors (Chrome, Safari, Firefox) and the CA/B Forum now cap DV/OV "
            "certificate lifetimes at 398 days. Certificates exceeding this threshold were "
            "issued before these policies took effect, suggesting old infrastructure, or were "
            "issued by non-compliant/private CAs — including attacker-controlled CAs."
        ),
        "severity": "low",
        "mitre": ["T1040", "Network Sniffing"],
    },
    "wildcard_cert": {
        "name": "Wildcard Certificate",
        "description": (
            "Certificates with a wildcard subject (CN or SAN beginning with `*.`). "
            "Wildcard certificates cover an entire subdomain level and are common in "
            "legitimate infrastructure, but are also used by C2 operators to cover "
            "dynamically generated subdomain C2 endpoints without frequent certificate rotation."
        ),
        "severity": "info",
        "mitre": ["T1587.003", "Develop Capabilities: Digital Certificates"],
    },
    "sni_mismatch": {
        "name": "Certificate CN / SNI Mismatch",
        "description": (
            "The certificate subject Common Name (CN) or Subject Alternative Name (SAN) "
            "does not match the TLS Server Name Indication (SNI) provided by the client. "
            "A mismatch means the server is presenting a certificate for a different domain "
            "than was requested — a hallmark of TLS MITM proxies, SSL inspection appliances "
            "with misconfiguration, and attacker-controlled interception infrastructure."
        ),
        "severity": "critical",
        "mitre": ["T1557", "Adversary-in-the-Middle"],
    },
    "weak_signature": {
        "name": "Weak Certificate Signature Algorithm",
        "description": (
            "Certificates or TLS handshakes advertising deprecated signature algorithms "
            "(MD5, SHA-1). MD5-signed certificates are vulnerable to collision attacks that "
            "allow forging certificates. SHA-1 is considered cryptographically broken for "
            "certificates (FIPS deprecated; Chrome removed trust in 2017). Both indicate "
            "either very old infrastructure or deliberate use of weak crypto to enable "
            "interception or forgery."
        ),
        "severity": "high",
        "mitre": ["T1040", "Network Sniffing"],
    },
}


# ── tshark helpers ─────────────────────────────────────────────────────────────

def _tshark(pcap: Path, display_filter: str, fields: list[str],
            occurrence: str = "f") -> list[list[str]]:
    """Run tshark and return parsed rows (tab-separated fields)."""
    cmd = [
        "tshark", "-r", str(pcap),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        f"-E", f"occurrence={occurrence}",
        "-E", "header=n",
    ]
    for f in fields:
        cmd += ["-e", f]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        rows = []
        for line in result.stdout.splitlines():
            if line.strip():
                rows.append(line.split("\t"))
        return rows
    except Exception as exc:
        print(f"[cert_inspector] tshark error: {exc}", file=sys.stderr)
        return []


def _safe(row: list[str], idx: int, default: str = "") -> str:
    return row[idx].strip() if idx < len(row) else default


# ── Date parsing ───────────────────────────────────────────────────────────────

def _parse_cert_date(s: str) -> datetime | None:
    """Parse tshark certificate validity date strings."""
    if not s:
        return None
    # Normalise: collapse multiple spaces, strip leading/trailing whitespace
    s = re.sub(r"\s+", " ", s.strip())
    # Truncate sub-second precision to 6 digits (Python's %f limit)
    s = re.sub(r"(\d{6})\d+", r"\1", s)

    formats = [
        "%b %d, %Y %H:%M:%S.%f UTC",
        "%b %d, %Y %H:%M:%S UTC",
        "%b %d, %Y %H:%M:%S.%f",
        "%b %d, %Y %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S UTC",
        "%Y-%m-%d %H:%M:%S",
        "%Y%m%d%H%M%SZ",    # GeneralizedTime: 20240101000000Z
        "%y%m%d%H%M%SZ",    # UTCTime: 240101000000Z
    ]
    for fmt in formats:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# ── SNI extraction ─────────────────────────────────────────────────────────────

def extract_sni_by_stream(pcap: Path) -> dict[str, str]:
    """Return {tcp_stream_id: sni} from ClientHello messages."""
    rows = _tshark(pcap, "tls.handshake.type == 1",
                   ["tcp.stream", "tls.handshake.extensions_server_name"])
    sni_map: dict[str, str] = {}
    for row in rows:
        stream = _safe(row, 0)
        sni    = _safe(row, 1)
        if stream and sni and stream not in sni_map:
            sni_map[stream] = sni
    return sni_map


# ── Certificate extraction ─────────────────────────────────────────────────────

CERT_FIELDS_LEAF = [
    "frame.time_epoch",
    "ip.src",
    "ip.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "x509sat.commonName",            # first occurrence = leaf subject CN
    "x509sat.organizationName",      # first occurrence = leaf subject Org
    "x509ce.dNSName",                # SANs (all from leaf cert, first field)
    "tls.handshake.cert.validity_not_before",
    "tls.handshake.cert.validity_not_after",
    "x509af.algorithm.id",           # cert signature algorithm OID / name
]

CERT_FIELDS_ALL_CN = [
    "tcp.stream",
    "x509sat.commonName",            # all occurrences = chain of subject/issuer CNs
]


def extract_certificates(pcap: Path) -> tuple[list[dict], dict[str, list[str]]]:
    """
    Return (leaf_records, all_cns_by_stream).
    leaf_records: one dict per Certificate handshake message (leaf cert data).
    all_cns_by_stream: {stream_id: [cn1, cn2, ...]} for self-signed detection.
    """
    leaf_rows = _tshark(pcap, "tls.handshake.type == 11",
                        CERT_FIELDS_LEAF, occurrence="f")
    all_cn_rows = _tshark(pcap, "tls.handshake.type == 11",
                          CERT_FIELDS_ALL_CN, occurrence="a")

    # Build all_cns_by_stream: multiple tshark rows per stream possible;
    # take the first row's CN list (first Certificate message on the stream = server chain)
    all_cns: dict[str, list[str]] = {}
    for row in all_cn_rows:
        stream = _safe(row, 0)
        cn_raw = _safe(row, 1)
        if stream and cn_raw and stream not in all_cns:
            # commas may appear inside org/CN names; accept this approximation
            all_cns[stream] = [c.strip() for c in cn_raw.split(",") if c.strip()]

    leaf_records: list[dict] = []
    for row in leaf_rows:
        time_epoch   = _safe(row, 0)
        src_ip       = _safe(row, 1)
        dst_ip       = _safe(row, 2)
        src_port     = _safe(row, 3)
        dst_port     = _safe(row, 4)
        stream       = _safe(row, 5)
        subject_cn   = _safe(row, 6)
        subject_org  = _safe(row, 7)
        san_raw      = _safe(row, 8)
        not_before_s = _safe(row, 9)
        not_after_s  = _safe(row, 10)
        sig_alg      = _safe(row, 11)

        # SANs: comma-separated domain names from the SAN extension
        san_dns = [s.strip() for s in san_raw.split(",") if s.strip()] if san_raw else []

        # Validity dates
        not_before = _parse_cert_date(not_before_s)
        not_after  = _parse_cert_date(not_after_s)
        valid_days: int | None = None
        if not_before and not_after:
            valid_days = (not_after - not_before).days

        # Timestamp
        ts = ""
        if time_epoch:
            try:
                ts = datetime.fromtimestamp(float(time_epoch), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (ValueError, OSError):
                pass

        leaf_records.append({
            "timestamp_utc": ts,
            "src_ip":       src_ip,
            "dst_ip":       dst_ip,
            "src_port":     src_port,
            "dst_port":     dst_port,
            "stream_id":    stream,
            "subject_cn":   subject_cn,
            "subject_org":  subject_org,
            "san_dns":      san_dns,
            "not_before":   not_before_s,
            "not_after":    not_after_s,
            "_not_before_dt": not_before,
            "_not_after_dt":  not_after,
            "valid_days":   valid_days,
            "sig_alg":      sig_alg,
        })

    return leaf_records, all_cns


# ── Detectors ──────────────────────────────────────────────────────────────────

def detect_self_signed(records: list[dict], all_cns: dict[str, list[str]]) -> list[dict]:
    """Cert is self-signed when the first two CNs in the chain are equal (subject == issuer)."""
    findings = []
    seen: set[str] = set()
    for rec in records:
        stream = rec["stream_id"]
        cns = all_cns.get(stream, [])
        # Single-cert chain (2 CNs: subject + issuer of same cert) where both match
        if len(cns) >= 2 and cns[0] == cns[1]:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{cns[0]}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "dst_port":   rec["dst_port"],
                    "sni":        "",   # filled in by analyze()
                    "subject_cn": cns[0],
                    "issuer_cn":  cns[1],
                    "valid_from": rec["not_before"],
                    "valid_to":   rec["not_after"],
                    "timestamp_utc": rec["timestamp_utc"],
                })
        # Stream has a single cert total (1 CN value = subject only, no issuer chain)
        elif len(cns) == 1:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{cns[0]}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "dst_port":   rec["dst_port"],
                    "sni":        "",
                    "subject_cn": cns[0],
                    "issuer_cn":  "(unknown — single-cert chain)",
                    "valid_from": rec["not_before"],
                    "valid_to":   rec["not_after"],
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_expired(records: list[dict], now: datetime) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        dt = rec["_not_after_dt"]
        if dt and dt < now:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{rec['subject_cn']}"
            if key not in seen:
                seen.add(key)
                days_ago = (now - dt).days
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": rec["subject_cn"],
                    "expired_at": rec["not_after"],
                    "days_expired": days_ago,
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_not_yet_valid(records: list[dict], now: datetime) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        dt = rec["_not_before_dt"]
        if dt and dt > now:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{rec['subject_cn']}"
            if key not in seen:
                seen.add(key)
                days_until = (dt - now).days
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": rec["subject_cn"],
                    "valid_from": rec["not_before"],
                    "days_until_valid": days_until,
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_short_validity(records: list[dict]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        vd = rec["valid_days"]
        if vd is not None and 0 < vd < SHORT_VALIDITY_DAYS:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{rec['subject_cn']}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": rec["subject_cn"],
                    "valid_days": vd,
                    "valid_from": rec["not_before"],
                    "valid_to":   rec["not_after"],
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_long_validity(records: list[dict]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        vd = rec["valid_days"]
        if vd is not None and vd > LONG_VALIDITY_DAYS:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{rec['subject_cn']}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": rec["subject_cn"],
                    "valid_days": vd,
                    "valid_from": rec["not_before"],
                    "valid_to":   rec["not_after"],
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_wildcard(records: list[dict]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        cn = rec["subject_cn"]
        san = rec["san_dns"]
        wildcard_names = [n for n in ([cn] + san) if n.startswith("*.")]
        if wildcard_names:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{cn}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": cn,
                    "wildcards":  wildcard_names[:10],
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_sni_mismatch(records: list[dict], sni_map: dict[str, str]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for rec in records:
        sni = sni_map.get(rec["stream_id"], "")
        if not sni:
            continue
        cn = rec["subject_cn"]
        sans = rec["san_dns"]

        # Check if SNI matches CN or any SAN (support wildcard matching)
        def _matches(pattern: str, name: str) -> bool:
            if pattern == name:
                return True
            if pattern.startswith("*."):
                # *.example.com matches sub.example.com but not example.com
                suffix = pattern[2:]
                if name.endswith("." + suffix) and "." not in name[: -(len(suffix) + 1)]:
                    return True
            return False

        all_names = [cn] + sans
        matched = any(_matches(n, sni) for n in all_names)

        if not matched and cn:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{sni}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":      rec["src_ip"],
                    "dst_ip":      rec["dst_ip"],
                    "sni":         sni,
                    "subject_cn":  cn,
                    "san_dns":     sans[:5],
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


def detect_weak_signature(records: list[dict]) -> list[dict]:
    """Flag certificates using known-weak signature algorithms (MD5, SHA-1)."""
    findings = []
    seen: set[str] = set()
    for rec in records:
        alg = rec["sig_alg"].lower()
        if not alg:
            continue
        matched = next((p for p in WEAK_SIG_PATTERNS if p.lower() in alg), None)
        if matched:
            key = f"{rec['dst_ip']}:{rec['dst_port']}:{rec['subject_cn']}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":     rec["src_ip"],
                    "dst_ip":     rec["dst_ip"],
                    "subject_cn": rec["subject_cn"],
                    "sig_alg":    rec["sig_alg"],
                    "matched_pattern": matched,
                    "timestamp_utc": rec["timestamp_utc"],
                })
    return findings


# ── Main analyze ───────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict, list[dict]]:
    """Run all certificate detectors. Returns (results_dict, cert_records)."""
    now = datetime.now(timezone.utc)

    print("[cert_inspector] Extracting SNI map from ClientHellos …")
    sni_map = extract_sni_by_stream(pcap)

    print("[cert_inspector] Extracting certificate records …")
    records, all_cns = extract_certificates(pcap)

    # Inject SNI into records for convenience
    for rec in records:
        rec["sni"] = sni_map.get(rec["stream_id"], "")

    print(f"[cert_inspector] Found {len(records)} certificate message(s).")

    results: dict[str, dict] = {}
    for key, meta in CATEGORIES.items():
        if key == "self_signed":
            findings = detect_self_signed(records, all_cns)
        elif key == "expired":
            findings = detect_expired(records, now)
        elif key == "not_yet_valid":
            findings = detect_not_yet_valid(records, now)
        elif key == "short_validity":
            findings = detect_short_validity(records)
        elif key == "long_validity":
            findings = detect_long_validity(records)
        elif key == "wildcard_cert":
            findings = detect_wildcard(records)
        elif key == "sni_mismatch":
            findings = detect_sni_mismatch(records, sni_map)
        elif key == "weak_signature":
            findings = detect_weak_signature(records)
        else:
            findings = []

        results[key] = {**meta, "count": len(findings), "findings": findings}
        if findings:
            print(f"[cert_inspector]   {key}: {len(findings)} finding(s) ({meta['severity']})")

    return results, records


# ── Output writers ─────────────────────────────────────────────────────────────

def write_json(results: dict, path: Path) -> None:
    path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(f"[cert_inspector] JSON  → {path}")


CSV_COLUMNS = [
    "timestamp_utc", "src_ip", "dst_ip", "src_port", "dst_port",
    "stream_id", "sni", "subject_cn", "subject_org",
    "san_dns", "not_before", "not_after", "valid_days", "sig_alg",
]


def write_csv(records: list[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for rec in records:
            row = {k: rec.get(k, "") for k in CSV_COLUMNS}
            row["san_dns"] = "|".join(rec.get("san_dns", []))
            w.writerow(row)
    print(f"[cert_inspector] CSV  → {path}")


def write_report(results: dict, path: Path, pcap: Path) -> None:
    SEVERITY_BADGE = {
        "critical": "**[CRITICAL]**", "high": "**[HIGH]**",
        "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]",
    }
    triggered = [v for v in results.values() if v["count"] > 0]
    lines = [
        f"# TLS Certificate Inspector Report",
        f"",
        f"**PCAP:** `{pcap.name}`  |  "
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        "",
    ]
    if not triggered:
        lines.append("No certificate anomalies detected.")
    else:
        rows = [
            [SEVERITY_BADGE.get(c["severity"], c["severity"]),
             c["name"], str(c["count"]),
             c["mitre"][0] if c.get("mitre") else "—"]
            for c in triggered
        ]
        header = "| Severity | Category | Findings | MITRE ATT&CK |"
        sep    = "|----------|----------|----------|--------------|"
        lines += [header, sep]
        for row in rows:
            lines.append("| " + " | ".join(row) + " |")
        lines.append("")

        for cat in triggered:
            sev   = cat["severity"]
            mitre = cat.get("mitre", [])
            mitre_str = (
                f"[{mitre[0]}](https://attack.mitre.org/techniques/{mitre[0].replace('.','/')}/) "
                f"— {mitre[1]}" if len(mitre) >= 2 else (mitre[0] if mitre else "—")
            )
            lines += [
                f"## {cat['name']}",
                "",
                f"**Severity:** {SEVERITY_BADGE.get(sev, sev)}  |  "
                f"**MITRE ATT&CK:** {mitre_str}",
                "",
                cat["description"],
                "",
                f"**Findings ({cat['count']}, showing up to 10):**",
                "",
                "```",
            ]
            for f in cat["findings"][:10]:
                lines.append(json.dumps(f, default=str))
            lines += ["```", ""]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[cert_inspector] MD   → {path}")


def save_to_vault(results: dict, case_id: str, stem: str) -> None:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from knowledge_extractor import record_ioc, record_ttp  # type: ignore
    except ImportError:
        print("[cert_inspector] knowledge_extractor not available; skipping vault writes.",
              file=sys.stderr)
        return

    SCSV = {"critical": "critical", "high": "high"}.get

    for key, cat in results.items():
        if cat["count"] == 0:
            continue
        sev = cat.get("severity", "info")
        if sev not in ("critical", "high"):
            continue

        mitre = cat.get("mitre", [])
        if len(mitre) >= 2:
            record_ttp(mitre[0], mitre[1], f"{cat['name']}: {cat['count']} finding(s).", case_id)

        for f in cat["findings"][:5]:
            dst_ip  = f.get("dst_ip", "")
            sni_val = f.get("sni", "") or f.get("subject_cn", "")
            if dst_ip:
                record_ioc("ip", dst_ip, f"{cat['name']} (cert_inspector)", case_id,
                           severity=sev, related_ttps=[f"{mitre[0]} {mitre[1]}"] if mitre else [])
            if sni_val and "." in sni_val and not sni_val[0].isdigit():
                record_ioc("domain", sni_val, f"{cat['name']} (cert_inspector)", case_id,
                           severity=sev, related_ttps=[f"{mitre[0]} {mitre[1]}"] if mitre else [])


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TLS Certificate Inspector — extract and analyse X.509 certs from a PCAP",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/fan_cert_inspector.py capture.pcap\n"
            "  python3 lib/fan_cert_inspector.py capture.pcap --case-id CASE-2025-001\n"
            "  python3 lib/fan_cert_inspector.py capture.pcap --stem custom --no-vault\n"
        ),
    )
    p.add_argument("pcap",         metavar="PCAP",  help="Input PCAP file")
    p.add_argument("--stem",       metavar="STEM",  help="Output stem (default: PCAP filename without extension)")
    p.add_argument("--case-id",    metavar="ID",    default="", help="Case ID for vault writes")
    p.add_argument("--output-dir", metavar="DIR",   help="Output directory (default: ./analysis/cert_inspector/<stem>/)")
    p.add_argument("--no-vault",   action="store_true", help="Skip Obsidian vault writes")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"[cert_inspector] PCAP not found: {pcap}")

    stem = args.stem or pcap.stem
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = PROJECT_ROOT / "analysis" / "cert_inspector" / stem
    out_dir.mkdir(parents=True, exist_ok=True)

    results, records = analyze(pcap)

    write_json(results, out_dir / "certs.json")
    write_csv(records,  out_dir / "certs.csv")
    write_report(results, out_dir / "cert_inspector_report.md", pcap)

    if not args.no_vault and args.case_id:
        save_to_vault(results, args.case_id, stem)

    triggered = sum(1 for v in results.values() if v["count"] > 0)
    print(f"[cert_inspector] Done. {triggered} category(ies) triggered.")
