#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_icmp_threats.py — CTI ICMP Threat Analyzer

Detects ICMP-based attack patterns in a PCAP file using tshark extraction
and Python-based heuristics. Covers 10 threat categories mapped to MITRE ATT&CK.

Detection categories:
  - ICMP Flood              (T1498.001)
  - Ping of Death           (T1499.002)
  - ICMP Fragmentation      (T1498.001)
  - ICMP Tunneling          (T1572)
  - Smurf / Broadcast Amp.  (T1498.001)
  - ICMP Redirect Attack    (T1557)
  - ICMP Network Sweep      (T1595.001)
  - Unreachable Flood       (T1498)
  - ICMP Recon Types        (T1595)
  - ICMP Data Exfiltration  (T1048)

Usage:
  python3 fan_icmp_threats.py <pcap_file> [--stem NAME] [--case-id ID]
                               [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection thresholds — adjust to environment
# ---------------------------------------------------------------------------
FLOOD_MIN_PACKETS       = 1000    # Total ICMP Echo Requests to flag flood
FLOOD_PPS_THRESHOLD     = 100     # Echo Requests per second from single source
POD_MIN_IP_LEN          = 65000   # IP total length flagging oversized ICMP
TUNNEL_MIN_PAYLOAD      = 128     # Estimated ICMP data bytes indicating tunneling
TUNNEL_MIN_PACKETS      = 10      # Minimum oversized Echo packets before flagging
SWEEP_MIN_HOSTS         = 20      # Unique destination IPs to flag as ping sweep
FRAG_MIN_COUNT          = 10      # Fragmented ICMP packets to flag overall
FRAG_STREAM_MIN         = 3       # Fragments per reassembly stream to flag
REDIR_MIN_COUNT         = 3       # ICMP Redirect messages from single source to flag
UNREACH_FLOOD_THRESH    = 200     # ICMP Type 3 count to flag as flood
EXFIL_PAYLOAD_THRESHOLD = 64      # Minimum ICMP data bytes inspected for exfiltration
EXFIL_ENTROPY_THRESHOLD = 3.5     # Shannon entropy on payload hex indicating encoded data
EXFIL_MIN_PACKETS       = 5       # High-entropy packets needed before exfil flag

# ---------------------------------------------------------------------------
# ICMP type constants
# ---------------------------------------------------------------------------
TYPE_ECHO_REPLY     = 0
TYPE_UNREACH        = 3
TYPE_REDIRECT       = 5
TYPE_ECHO_REQUEST   = 8
TYPE_TIME_EXCEEDED  = 11
TYPE_TIMESTAMP_REQ  = 13
TYPE_TIMESTAMP_REP  = 14
TYPE_INFO_REQ       = 15
TYPE_INFO_REP       = 16
TYPE_ADDRMASK_REQ   = 17
TYPE_ADDRMASK_REP   = 18

RECON_TYPES = {
    TYPE_TIMESTAMP_REQ, TYPE_TIMESTAMP_REP,
    TYPE_INFO_REQ, TYPE_INFO_REP,
    TYPE_ADDRMASK_REQ, TYPE_ADDRMASK_REP,
}

ICMP_TYPE_NAMES = {
    0:  "Echo Reply",
    3:  "Destination Unreachable",
    4:  "Source Quench",
    5:  "Redirect",
    8:  "Echo Request",
    9:  "Router Advertisement",
    10: "Router Solicitation",
    11: "Time Exceeded",
    12: "Parameter Problem",
    13: "Timestamp Request",
    14: "Timestamp Reply",
    15: "Information Request",
    16: "Information Reply",
    17: "Address Mask Request",
    18: "Address Mask Reply",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# tshark extraction
# ---------------------------------------------------------------------------

def extract_icmp_records(pcap_path: Path) -> list[dict]:
    """Extract ICMPv4 packets from a PCAP using tshark."""
    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "icmp.type",
        "icmp.code",
        "ip.len",
        "ip.flags.mf",
        "ip.frag_offset",
        "ip.ttl",
        "frame.len",
        "icmp.seq",
        "icmp.ident",
        "data.len",
        "data",
    ]
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "icmp",
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=a",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] tshark failed: {e.stderr.strip()}", file=sys.stderr)
        return []

    records = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        p = dict(zip(fields, parts))

        def _first(k: str) -> str:
            return p[k].split(",")[0].strip() if p[k] else ""

        def _int(k: str, default: int = 0) -> int:
            try:
                return int(_first(k)) if _first(k) else default
            except ValueError:
                return default

        def _float(k: str) -> float:
            try:
                return float(p[k]) if p[k] else 0.0
            except ValueError:
                return 0.0

        records.append({
            "timestamp":   _float("frame.time_epoch"),
            "src_ip":      _first("ip.src"),
            "dst_ip":      _first("ip.dst"),
            "icmp_type":   _int("icmp.type", -1),
            "icmp_code":   _int("icmp.code"),
            "ip_len":      _int("ip.len"),
            "flags_mf":    _first("ip.flags.mf") == "1",
            "frag_offset": _int("ip.frag_offset"),
            "ttl":         _int("ip.ttl"),
            "frame_len":   _int("frame.len"),
            "icmp_seq":    _int("icmp.seq"),
            "icmp_ident":  _int("icmp.ident"),
            "data_len":    _int("data.len"),
            "data_hex":    _first("data"),
        })

    return records

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


def _is_broadcast(ip: str) -> bool:
    if not ip:
        return False
    if ip == "255.255.255.255":
        return True
    parts = ip.split(".")
    return len(parts) == 4 and parts[-1] == "255"


def _ts_utc(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _estimated_data(r: dict) -> int:
    """Estimate ICMP data payload bytes: ip_len minus standard IP+ICMP headers."""
    return max(r["data_len"], r["ip_len"] - 28)


def _result(name: str, severity: str, mitre: list[str],
            findings: list, description: str) -> dict:
    return {
        "name":        name,
        "severity":    severity,
        "count":       len(findings),
        "mitre":       mitre,
        "findings":    findings,
        "description": description,
    }

# ---------------------------------------------------------------------------
# Detection functions
# ---------------------------------------------------------------------------

def detect_icmp_flood(records: list[dict]) -> dict:
    """High-volume ICMP Echo Request flood from a single source (T1498.001)."""
    src_ts: dict[str, list[float]] = defaultdict(list)
    for r in records:
        if r["icmp_type"] == TYPE_ECHO_REQUEST:
            src_ts[r["src_ip"]].append(r["timestamp"])

    findings = []
    for src, ts in src_ts.items():
        if len(ts) < FLOOD_MIN_PACKETS:
            continue
        ts.sort()
        duration = ts[-1] - ts[0] or 1.0
        pps = len(ts) / duration
        findings.append({
            "src_ip":             src,
            "echo_request_count": len(ts),
            "pps":                round(pps, 1),
            "duration_sec":       round(duration, 1),
        })

    findings.sort(key=lambda x: x["echo_request_count"], reverse=True)
    return _result(
        "ICMP Flood",
        "high" if findings else "info",
        ["T1498.001", "Network DoS: Direct Network Flood"],
        findings,
        f"High-volume ICMP Echo Request flood detected from {len(findings)} source(s). "
        f"Threshold: ≥{FLOOD_MIN_PACKETS} packets or ≥{FLOOD_PPS_THRESHOLD} pps.",
    )


def detect_ping_of_death(records: list[dict]) -> dict:
    """Oversized ICMP packets exceeding safe IPv4 datagram limits (T1499.002)."""
    findings = []
    seen: set[tuple] = set()
    for r in records:
        if r["icmp_type"] not in (TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY):
            continue
        # Flag: single packet near/at IPv4 limit, or late fragment indicating huge reassembly
        if r["ip_len"] >= POD_MIN_IP_LEN or r["frag_offset"] > 65000:
            key = (r["src_ip"], r["dst_ip"], r["ip_len"])
            if key in seen:
                continue
            seen.add(key)
            findings.append({
                "src_ip":        r["src_ip"],
                "dst_ip":        r["dst_ip"],
                "ip_len":        r["ip_len"],
                "frag_offset":   r["frag_offset"],
                "timestamp_utc": _ts_utc(r["timestamp"]),
            })

    return _result(
        "Ping of Death",
        "high" if findings else "info",
        ["T1499.002", "Endpoint DoS: Service Exhaustion Flood"],
        findings,
        f"Oversized ICMP packets detected (IP length ≥ {POD_MIN_IP_LEN} B or "
        "fragment offset > 65000). Indicates Ping of Death or fragmentation DoS.",
    )


def detect_fragmentation_attack(records: list[dict]) -> dict:
    """Abnormal ICMP fragmentation patterns suggesting Teardrop/frag DoS (T1498.001)."""
    fragmented = [r for r in records if r["flags_mf"] or r["frag_offset"] > 0]

    streams: dict[tuple, list] = defaultdict(list)
    for r in fragmented:
        key = (r["src_ip"], r["dst_ip"], r["icmp_ident"])
        streams[key].append(r)

    findings = []
    for (src, dst, ident), frags in streams.items():
        if len(frags) < FRAG_STREAM_MIN:
            continue
        findings.append({
            "src_ip":         src,
            "dst_ip":         dst,
            "icmp_ident":     ident,
            "fragment_count": len(frags),
            "max_frag_offset": max(f["frag_offset"] for f in frags),
            "first_seen_utc": _ts_utc(min(f["timestamp"] for f in frags)),
        })

    total_frag = len(fragmented)
    sev = "info"
    if total_frag >= FRAG_MIN_COUNT:
        sev = "medium"
    if len(findings) >= 3:
        sev = "high"

    findings.sort(key=lambda x: x["fragment_count"], reverse=True)
    return _result(
        "ICMP Fragmentation Attack",
        sev,
        ["T1498.001", "Network DoS: Direct Network Flood"],
        findings,
        f"ICMP fragmentation: {total_frag} fragmented packets across "
        f"{len(findings)} reassembly streams. Possible Teardrop / fragmentation DoS.",
    )


def detect_icmp_tunneling(records: list[dict]) -> dict:
    """ICMP Echo used as covert channel via abnormally large payloads (T1572)."""
    src_pkts: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        if r["icmp_type"] not in (TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY):
            continue
        if _estimated_data(r) >= TUNNEL_MIN_PAYLOAD:
            src_pkts[r["src_ip"]].append(r)

    findings = []
    for src, pkts in src_pkts.items():
        if len(pkts) < TUNNEL_MIN_PACKETS:
            continue
        avg_payload = sum(_estimated_data(p) for p in pkts) / len(pkts)
        total_data  = sum(_estimated_data(p) for p in pkts)
        dst_ips     = list({p["dst_ip"] for p in pkts})
        findings.append({
            "src_ip":                src,
            "dst_ips":               dst_ips[:5],
            "oversized_packet_count": len(pkts),
            "avg_payload_bytes":     round(avg_payload, 1),
            "total_data_bytes":      total_data,
        })

    findings.sort(key=lambda x: x["total_data_bytes"], reverse=True)
    return _result(
        "ICMP Tunneling",
        "critical" if findings else "info",
        ["T1572", "Protocol Tunneling"],
        findings,
        f"ICMP Echo payloads ≥ {TUNNEL_MIN_PAYLOAD} bytes from {len(findings)} source(s). "
        "Normal ping uses ≤56 bytes of data. Large payloads indicate ptunnel / "
        "icmptunnel / PingTunnel covert channel.",
    )


def detect_smurf(records: list[dict]) -> dict:
    """ICMP Echo Requests to broadcast addresses — Smurf amplification attack (T1498.001)."""
    pair_counts: dict[tuple, int] = defaultdict(int)
    for r in records:
        if r["icmp_type"] == TYPE_ECHO_REQUEST and _is_broadcast(r["dst_ip"]):
            pair_counts[(r["src_ip"], r["dst_ip"])] += 1

    findings = [
        {"src_ip": src, "broadcast_dst": dst, "echo_request_count": cnt}
        for (src, dst), cnt in pair_counts.items()
    ]
    findings.sort(key=lambda x: x["echo_request_count"], reverse=True)
    return _result(
        "Smurf Attack / Broadcast Amplification",
        "high" if findings else "info",
        ["T1498.001", "Network DoS: Direct Network Flood"],
        findings,
        f"ICMP Echo Requests to broadcast addresses from {len(findings)} source(s). "
        "All segment hosts reply — amplified DoS (Smurf attack).",
    )


def detect_icmp_redirect(records: list[dict]) -> dict:
    """ICMP Type 5 Redirect messages — potential routing table poisoning (T1557)."""
    redir = [r for r in records if r["icmp_type"] == TYPE_REDIRECT]
    src_counts: dict[str, int] = defaultdict(int)
    src_targets: dict[str, set] = defaultdict(set)
    for r in redir:
        src_counts[r["src_ip"]] += 1
        src_targets[r["src_ip"]].add(r["dst_ip"])

    findings = []
    for src, cnt in src_counts.items():
        if cnt >= REDIR_MIN_COUNT:
            findings.append({
                "redirect_source": src,
                "redirect_count":  cnt,
                "targets":         list(src_targets[src])[:10],
            })

    sev = "info"
    if len(redir) > 0:
        sev = "medium"
    if findings:
        sev = "high"

    return _result(
        "ICMP Redirect Attack",
        sev,
        ["T1557", "Adversary-in-the-Middle"],
        findings,
        f"ICMP Redirect (Type 5) messages: {len(redir)} total from "
        f"{len(findings)} aggressive source(s). Malicious redirects poison "
        "host routing tables to intercept traffic (MITM).",
    )


def detect_icmp_sweep(records: list[dict]) -> dict:
    """Single source ICMP Echo to many unique destinations — ping sweep / recon (T1595.001)."""
    src_dsts: dict[str, set] = defaultdict(set)
    src_ts: dict[str, list[float]] = defaultdict(list)
    for r in records:
        if r["icmp_type"] == TYPE_ECHO_REQUEST:
            src_dsts[r["src_ip"]].add(r["dst_ip"])
            src_ts[r["src_ip"]].append(r["timestamp"])

    findings = []
    for src, dsts in src_dsts.items():
        if len(dsts) < SWEEP_MIN_HOSTS:
            continue
        ts = sorted(src_ts[src])
        duration = ts[-1] - ts[0] or 1.0
        findings.append({
            "src_ip":                   src,
            "unique_dst_count":         len(dsts),
            "duration_sec":             round(duration, 1),
            "sweep_rate_hosts_per_sec": round(len(dsts) / duration, 2),
            "sample_targets":           sorted(dsts)[:10],
        })

    findings.sort(key=lambda x: x["unique_dst_count"], reverse=True)
    return _result(
        "ICMP Network Sweep / Scan",
        "medium" if findings else "info",
        ["T1595.001", "Active Scanning: Scanning IP Blocks"],
        findings,
        f"ICMP ping sweep from {len(findings)} source(s) targeting "
        f"≥{SWEEP_MIN_HOSTS} unique hosts. Indicates host discovery / network mapping.",
    )


def detect_unreachable_flood(records: list[dict]) -> dict:
    """High volume of ICMP Destination Unreachable — DoS side-effect or scan (T1498)."""
    unreach = [r for r in records if r["icmp_type"] == TYPE_UNREACH]
    src_counts: dict[str, int] = defaultdict(int)
    for r in unreach:
        src_counts[r["src_ip"]] += 1

    findings = [
        {"src_ip": src, "unreachable_sent": cnt}
        for src, cnt in src_counts.items()
        if cnt >= UNREACH_FLOOD_THRESH
    ]
    findings.sort(key=lambda x: x["unreachable_sent"], reverse=True)

    sev = "info"
    if len(unreach) >= UNREACH_FLOOD_THRESH:
        sev = "medium"
    if findings:
        sev = "high"

    return _result(
        "Destination Unreachable Flood",
        sev,
        ["T1498", "Network Denial of Service"],
        findings,
        f"High-volume ICMP Destination Unreachable (Type 3): {len(unreach)} total. "
        "Indicates port scan side-effects, deliberate ICMP flooding, or blackhole routes.",
    )


def detect_recon_types(records: list[dict]) -> dict:
    """Obsolete/unusual ICMP types used for fingerprinting and reconnaissance (T1595)."""
    _type_names = {
        13: "Timestamp Request (13)",
        14: "Timestamp Reply (14)",
        15: "Information Request (15)",
        16: "Information Reply (16)",
        17: "Address Mask Request (17)",
        18: "Address Mask Reply (18)",
    }
    recon = [r for r in records if r["icmp_type"] in RECON_TYPES]
    seen: set[tuple] = set()
    findings = []
    for r in recon:
        key = (r["src_ip"], r["icmp_type"])
        if key in seen:
            continue
        seen.add(key)
        cnt = sum(1 for x in recon
                  if x["src_ip"] == r["src_ip"] and x["icmp_type"] == r["icmp_type"])
        findings.append({
            "src_ip":    r["src_ip"],
            "icmp_type": r["icmp_type"],
            "type_name": _type_names.get(r["icmp_type"], f"Type {r['icmp_type']}"),
            "count":     cnt,
        })

    return _result(
        "ICMP Reconnaissance Types",
        "medium" if findings else "info",
        ["T1595", "Active Scanning"],
        findings,
        f"Unusual ICMP message types detected for network fingerprinting: "
        f"{len(recon)} packets. Types 13, 15, 17 are obsolete — rarely legitimate; "
        "presence indicates active recon (nmap OS fingerprinting, etc.).",
    )


def detect_icmp_exfiltration(records: list[dict]) -> dict:
    """High-entropy ICMP Echo payloads indicating data exfiltration (T1048)."""
    candidates = [
        r for r in records
        if r["icmp_type"] in (TYPE_ECHO_REQUEST, TYPE_ECHO_REPLY)
        and _estimated_data(r) >= EXFIL_PAYLOAD_THRESHOLD
        and r["data_hex"]
    ]

    src_hits: dict[str, list[dict]] = defaultdict(list)
    for r in candidates:
        ent = _entropy(r["data_hex"])
        if ent >= EXFIL_ENTROPY_THRESHOLD:
            src_hits[r["src_ip"]].append({
                "src_ip":         r["src_ip"],
                "dst_ip":         r["dst_ip"],
                "data_len":       _estimated_data(r),
                "payload_entropy": round(ent, 2),
                "icmp_type_str":  (
                    "Echo Request" if r["icmp_type"] == TYPE_ECHO_REQUEST
                    else "Echo Reply"
                ),
                "timestamp_utc":  _ts_utc(r["timestamp"]),
            })

    findings = []
    for src, pkts in src_hits.items():
        if len(pkts) < EXFIL_MIN_PACKETS:
            continue
        avg_ent = sum(p["payload_entropy"] for p in pkts) / len(pkts)
        findings.append({
            "src_ip":                src,
            "high_entropy_count":    len(pkts),
            "avg_payload_entropy":   round(avg_ent, 2),
            "avg_payload_bytes":     round(sum(p["data_len"] for p in pkts) / len(pkts), 1),
            "sample":                pkts[:3],
        })

    findings.sort(key=lambda x: x["high_entropy_count"], reverse=True)
    return _result(
        "ICMP Data Exfiltration",
        "critical" if findings else "info",
        ["T1048", "Exfiltration Over Alternative Protocol"],
        findings,
        f"High-entropy ICMP payloads from {len(findings)} source(s): "
        f"≥{EXFIL_PAYLOAD_THRESHOLD} B data, entropy ≥ {EXFIL_ENTROPY_THRESHOLD} bits. "
        "Indicates encoded/encrypted data carried inside ICMP Echo.",
    )

# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

_DETECTOR_KEYS = [
    (detect_icmp_flood,          "icmp_flood"),
    (detect_ping_of_death,       "ping_of_death"),
    (detect_fragmentation_attack, "fragmentation"),
    (detect_icmp_tunneling,      "tunneling"),
    (detect_smurf,               "smurf"),
    (detect_icmp_redirect,       "redirect"),
    (detect_icmp_sweep,          "sweep"),
    (detect_unreachable_flood,   "unreach_flood"),
    (detect_recon_types,         "recon_types"),
    (detect_icmp_exfiltration,   "exfiltration"),
]


def analyze(pcap_path: Path) -> tuple[dict, list[dict]]:
    print(f"[*] Extracting ICMP records from {pcap_path} ...", file=sys.stderr)
    records = extract_icmp_records(pcap_path)
    print(f"[*] {len(records)} ICMP packets extracted.", file=sys.stderr)
    if not records:
        print("[WARN] No ICMP records found — verify PCAP has ICMP traffic.",
              file=sys.stderr)

    results: dict[str, dict] = {}
    for fn, key in _DETECTOR_KEYS:
        print(f"  [*] {fn.__name__} ...", file=sys.stderr)
        results[key] = fn(records)

    return results, records

# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv(records: list[dict], out_path: Path) -> None:
    headers = [
        "timestamp_utc", "src_ip", "dst_ip",
        "icmp_type", "icmp_type_name", "icmp_code",
        "ip_len", "data_len_estimated", "ttl", "frame_len",
        "fragmented", "frag_offset",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in records:
            w.writerow([
                _ts_utc(r["timestamp"]),
                r["src_ip"],
                r["dst_ip"],
                r["icmp_type"],
                ICMP_TYPE_NAMES.get(r["icmp_type"], f"Type {r['icmp_type']}"),
                r["icmp_code"],
                r["ip_len"],
                _estimated_data(r),
                r["ttl"],
                r["frame_len"],
                "1" if (r["flags_mf"] or r["frag_offset"] > 0) else "0",
                r["frag_offset"],
            ])


def write_json(results: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def write_report(results: dict, out_path: Path,
                 pcap_path: Path, case_id: str = "") -> None:
    now_utc = datetime.now(tz=timezone.utc).isoformat()
    lines = [
        "# ICMP Threat Analysis Report",
        "",
        f"**PCAP:** `{pcap_path.name}`  ",
        f"**Generated:** {now_utc}  ",
    ]
    if case_id:
        lines.append(f"**Case ID:** {case_id}  ")

    lines += ["", "---", "", "## Severity Summary", "",
              "| Severity | Category | Count |",
              "|----------|----------|-------|"]

    ordered = sorted(results.items(),
                     key=lambda kv: SEVERITY_ORDER.get(kv[1]["severity"], 99))
    for _, r in ordered:
        if r["severity"] == "info":
            continue
        lines.append(f"| {r['severity'].upper()} | {r['name']} | {r['count']} |")

    lines += ["", "---", ""]

    for _, r in ordered:
        if r["severity"] == "info":
            continue
        mitre_str = " / ".join(r["mitre"])
        lines += [
            f"## {r['name']}",
            "",
            f"**Severity:** {r['severity'].upper()}  ",
            f"**MITRE ATT&CK:** {mitre_str}  ",
            f"**Findings:** {r['count']}  ",
            "",
            r["description"],
            "",
            "```json",
        ]
        for finding in r["findings"][:10]:
            lines.append(json.dumps(finding, default=str))
        lines += ["```", ""]

    clean = [r["name"] for r in results.values() if r["severity"] == "info"]
    if clean:
        lines += ["---", "", "## Clean / No Findings", ""]
        for name in clean:
            lines.append(f"- {name}")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _mitre_tactic(mitre_id: str) -> str:
    mapping = {
        "T1498": "impact",
        "T1499": "impact",
        "T1572": "command-and-control",
        "T1557": "collection",
        "T1595": "reconnaissance",
        "T1048": "exfiltration",
    }
    for prefix, tactic in mapping.items():
        if mitre_id.startswith(prefix):
            return tactic
    return "unknown"


def save_to_vault(results: dict, pcap_path: Path, case_id: str = "") -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp, record_ioc  # type: ignore
    except ImportError:
        print("[WARN] knowledge_extractor not available — skipping vault writes.",
              file=sys.stderr)
        return

    HIGH_SEVS = {"critical", "high"}
    for r in results.values():
        if r["severity"] not in HIGH_SEVS:
            continue
        mitre_id   = r["mitre"][0] if r["mitre"] else ""
        mitre_name = r["mitre"][1] if len(r["mitre"]) > 1 else r["name"]
        evidence   = (f"{r['name']}: {r['count']} finding(s) in {pcap_path.name}. "
                      f"{r['description']}")

        if mitre_id:
            record_ttp(mitre_id, mitre_name, evidence,
                       case_id or "unknown",
                       tactic=_mitre_tactic(mitre_id))

        for finding in r["findings"][:5]:
            ip = (finding.get("src_ip")
                  or finding.get("redirect_source"))
            if ip:
                record_ioc(
                    "ip", ip,
                    f"{r['name']} — {r['description'][:100]}",
                    case_id or "unknown",
                    severity=r["severity"],
                    related_ttps=[f"{mitre_id} {mitre_name}"] if mitre_id else [],
                )

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP file for ICMP-based threat patterns.")
    parser.add_argument("pcap", type=Path, help="Path to PCAP file")
    parser.add_argument("--stem", default="",
                        help="Output directory stem (default: PCAP filename)")
    parser.add_argument("--case-id", default="", dest="case_id",
                        help="Case ID stamped in report and vault entries")
    parser.add_argument("--output-dir", type=Path,
                        default=Path("./analysis/icmp_threats"),
                        dest="output_dir",
                        help="Base output directory (default: ./analysis/icmp_threats)")
    parser.add_argument("--no-vault", action="store_true", dest="no_vault",
                        help="Skip Obsidian vault writes")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"[ERROR] PCAP not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    stem    = args.stem or args.pcap.stem
    out_dir = args.output_dir / stem
    out_dir.mkdir(parents=True, exist_ok=True)

    results, records = analyze(args.pcap)

    json_path   = out_dir / "icmp_threats.json"
    csv_path    = out_dir / "icmp_flows.csv"
    report_path = out_dir / "icmp_threats_report.md"

    write_json(results, json_path)
    write_csv(records, csv_path)
    write_report(results, report_path, args.pcap, args.case_id)

    if not args.no_vault:
        save_to_vault(results, args.pcap, args.case_id)

    print(f"\n[+] Output directory : {out_dir}", file=sys.stderr)
    print(f"    Report           : {report_path}", file=sys.stderr)
    print(f"    JSON             : {json_path}", file=sys.stderr)
    print(f"    CSV              : {csv_path}", file=sys.stderr)

    print("\n[+] Findings summary:", file=sys.stderr)
    for r in sorted(results.values(),
                    key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
        if r["severity"] != "info":
            print(f"    {r['severity'].upper():8s}  {r['name']}: {r['count']}",
                  file=sys.stderr)


if __name__ == "__main__":
    main()
