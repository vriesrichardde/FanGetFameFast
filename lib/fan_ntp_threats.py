#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_ntp_threats.py — CTI NTP Threat Analyzer

Detects NTP-based attack patterns in a PCAP file using tshark extraction
and Python-based heuristics. Covers 7 threat categories mapped to MITRE ATT&CK.

Detection categories:
  - NTP Amplification Attack   (T1498.002)
  - NTP Flood (DoS)            (T1498)
  - Kiss-of-Death (KoD)        (T1499)
  - NTP Mode 7 / Monlist Abuse (T1590)
  - Spoofed NTP Response       (T1557)
  - Time Manipulation          (T1070)
  - NTP Reconnaissance / Scan  (T1595)

Usage:
  python3 fan_ntp_threats.py <pcap_file> [--stem NAME] [--case-id ID]
                              [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
FLOOD_MIN_PACKETS               = 500   # NTP packets from single src to flag flood
FLOOD_PPS_THRESHOLD             = 50    # NTP packets per second from single source
AMPLIFICATION_RESPONSE_MIN_BYTES = 200  # Frame length threshold for "large" NTP response
AMPLIFICATION_MIN_RESPONSES     = 50    # Large responses to single victim IP
AMPLIFICATION_MIN_SOURCES       = 3     # Distinct sources sending large responses to victim
MODE7_MIN_COUNT                 = 5     # Mode 7 packets from single source before flagging
RECON_MIN_SERVERS               = 20    # Unique NTP server IPs queried by single source
TIME_MANIP_ROOTDISP_THRESH      = 16.0  # Root dispersion (seconds) — anomalous above this
TIME_MANIP_ROOTDELAY_THRESH     = 16.0  # Root delay (seconds) — anomalous above this

# ---------------------------------------------------------------------------
# NTP constants
# ---------------------------------------------------------------------------
NTP_MODE_NAMES = {
    0: "Reserved",
    1: "Symmetric Active",
    2: "Symmetric Passive",
    3: "Client",
    4: "Server",
    5: "Broadcast",
    6: "NTP Control",
    7: "Private (deprecated)",
}

# Known Kiss-of-Death reference IDs (ASCII, stratum=0)
KOD_CODES = {
    "DENY", "RSTR", "RATE", "INIT", "STEP", "MAHV",
    "ACTS", "AUTH", "AUTO", "BCST", "CRYPT", "DROP",
    "RSET", "XFAC", "NKEY", "RMOT",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# ---------------------------------------------------------------------------
# tshark extraction
# ---------------------------------------------------------------------------

def extract_ntp_records(pcap_path: Path) -> list[dict]:
    """Extract NTP packets from a PCAP using tshark."""
    fields = [
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "frame.len",
        "ntp.flags.mode",
        "ntp.stratum",
        "ntp.refid",
        "ntp.rootdelay",
        "ntp.rootdispersion",
        "ntp.ppoll",
    ]
    cmd = [
        "tshark", "-r", str(pcap_path),
        "-Y", "ntp",
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]

    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("[ERROR] tshark not found on PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[ERROR] tshark failed: {e.stderr.strip()}", file=sys.stderr)
        return []

    records = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < len(fields):
            parts += [""] * (len(fields) - len(parts))
        p = dict(zip(fields, parts))

        def _str(k: str) -> str:
            return p.get(k, "").strip()

        def _int(k: str, default: int = 0) -> int:
            v = _str(k)
            try:
                return int(v, 0) if v else default
            except (ValueError, TypeError):
                return default

        def _float(k: str) -> float:
            v = _str(k)
            try:
                return float(v) if v else 0.0
            except (ValueError, TypeError):
                return 0.0

        mode = _int("ntp.flags.mode")
        stratum = _int("ntp.stratum", -1)
        refid = _str("ntp.refid")

        # Detect KoD: stratum 0 + refid is a known KoD code
        refid_upper = refid.upper().strip("\x00 ")
        is_kod = (stratum == 0 and refid_upper in KOD_CODES)

        records.append({
            "timestamp":     _float("frame.time_epoch"),
            "src_ip":        _str("ip.src"),
            "dst_ip":        _str("ip.dst"),
            "src_port":      _int("udp.srcport"),
            "dst_port":      _int("udp.dstport"),
            "frame_len":     _int("frame.len"),
            "mode":          mode,
            "mode_name":     NTP_MODE_NAMES.get(mode, f"Mode {mode}"),
            "stratum":       stratum,
            "refid":         refid,
            "rootdelay":     _float("ntp.rootdelay"),
            "rootdispersion": _float("ntp.rootdispersion"),
            "ppoll":         _int("ntp.ppoll"),
            "is_kod":        is_kod,
        })

    return records


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_utc(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


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

def detect_amplification(records: list[dict]) -> dict:
    """
    NTP reflection amplification attack: attacker sends spoofed NTP requests;
    servers respond with large packets to the spoofed (victim) IP (T1498.002).

    Signals: high volume of large NTP server responses (mode 4, frame > threshold)
    aimed at a single destination from multiple distinct sources.
    """
    # Collect large server responses grouped by victim (dst_ip)
    victim_responses: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        if r["mode"] == 4 and r["frame_len"] >= AMPLIFICATION_RESPONSE_MIN_BYTES:
            victim_responses[r["dst_ip"]].append(r)

    findings = []
    for victim, pkts in victim_responses.items():
        distinct_sources = {p["src_ip"] for p in pkts}
        if (len(pkts) >= AMPLIFICATION_MIN_RESPONSES
                and len(distinct_sources) >= AMPLIFICATION_MIN_SOURCES):
            total_bytes = sum(p["frame_len"] for p in pkts)
            findings.append({
                "victim_ip":          victim,
                "large_response_count": len(pkts),
                "distinct_sources":   len(distinct_sources),
                "total_bytes_recv":   total_bytes,
                "avg_response_bytes": round(total_bytes / len(pkts), 1),
                "sample_sources":     sorted(distinct_sources)[:5],
            })

    findings.sort(key=lambda x: x["large_response_count"], reverse=True)
    return _result(
        "NTP Amplification Attack",
        "critical" if findings else "info",
        ["T1498.002", "Network DoS: Reflection Amplification"],
        findings,
        f"NTP amplification/reflection detected: {len(findings)} victim IP(s) receiving "
        f"high volumes of large NTP responses (≥{AMPLIFICATION_RESPONSE_MIN_BYTES} B) from "
        "multiple sources. Classic DDoS amplification pattern using spoofed NTP requests.",
    )


def detect_ntp_flood(records: list[dict]) -> dict:
    """
    High-volume NTP packet flood from a single source (T1498).

    Flags sources sending excessive NTP traffic by total count or packets-per-second.
    """
    src_ts: dict[str, list[float]] = defaultdict(list)
    for r in records:
        src_ts[r["src_ip"]].append(r["timestamp"])

    findings = []
    for src, ts in src_ts.items():
        if not src:
            continue
        ts.sort()
        duration = ts[-1] - ts[0] or 1.0
        pps = len(ts) / duration
        if len(ts) >= FLOOD_MIN_PACKETS or pps >= FLOOD_PPS_THRESHOLD:
            findings.append({
                "src_ip":       src,
                "packet_count": len(ts),
                "pps":          round(pps, 1),
                "duration_sec": round(duration, 1),
            })

    findings.sort(key=lambda x: x["packet_count"], reverse=True)
    return _result(
        "NTP Flood",
        "high" if findings else "info",
        ["T1498", "Network Denial of Service"],
        findings,
        f"High-volume NTP flood from {len(findings)} source(s). "
        f"Threshold: ≥{FLOOD_MIN_PACKETS} packets or ≥{FLOOD_PPS_THRESHOLD} pps.",
    )


def detect_kiss_of_death(records: list[dict]) -> dict:
    """
    NTP Kiss-of-Death (KoD) packets: server responses with stratum=0 carrying
    a KoD reference ID (DENY, RSTR, RATE, etc.) that tell clients to stop querying
    or indicate configuration problems (T1499).

    In adversarial use, KoD packets can be spoofed to deny NTP service to clients.
    """
    kod_records = [r for r in records if r["is_kod"]]

    # Group by KoD code
    code_counts: dict[str, list[dict]] = defaultdict(list)
    for r in kod_records:
        code = r["refid"].upper().strip("\x00 ")
        code_counts[code].append(r)

    findings = []
    for code, pkts in code_counts.items():
        src_ips = list({p["src_ip"] for p in pkts})
        dst_ips = list({p["dst_ip"] for p in pkts})
        findings.append({
            "kod_code":   code,
            "count":      len(pkts),
            "src_ips":    src_ips[:5],
            "dst_ips":    dst_ips[:5],
            "first_seen": _ts_utc(min(p["timestamp"] for p in pkts)),
        })

    findings.sort(key=lambda x: x["count"], reverse=True)
    sev = "info"
    if kod_records:
        # RATE/DENY from many sources to many targets may indicate spoofed KoD DoS
        distinct_srcs = len({r["src_ip"] for r in kod_records})
        sev = "high" if distinct_srcs > 3 else "medium"

    return _result(
        "NTP Kiss-of-Death (KoD)",
        sev,
        ["T1499", "Endpoint Denial of Service"],
        findings,
        f"NTP Kiss-of-Death packets detected: {len(kod_records)} total KoD responses "
        f"across {len(findings)} KoD code(s). Spoofed KoD packets can be used to "
        "force NTP clients off their time source (NTP service disruption).",
    )


def detect_mode7_abuse(records: list[dict]) -> dict:
    """
    NTP Mode 7 (private) packet abuse — deprecated since NTPv4, exploited
    for monlist amplification (returns up to 600 recent clients per request).
    Any mode-7 traffic warrants investigation (T1590).
    """
    mode7 = [r for r in records if r["mode"] == 7]
    src_counts: dict[str, list[dict]] = defaultdict(list)
    for r in mode7:
        src_counts[r["src_ip"]].append(r)

    findings = []
    for src, pkts in src_counts.items():
        if len(pkts) >= MODE7_MIN_COUNT:
            dst_ips = list({p["dst_ip"] for p in pkts})
            findings.append({
                "src_ip":     src,
                "mode7_count": len(pkts),
                "dst_ips":    dst_ips[:5],
                "first_seen": _ts_utc(min(p["timestamp"] for p in pkts)),
            })

    total_mode7 = len(mode7)
    sev = "info"
    if total_mode7 > 0:
        sev = "medium"
    if findings:
        sev = "high"

    findings.sort(key=lambda x: x["mode7_count"], reverse=True)
    return _result(
        "NTP Mode 7 / Monlist Abuse",
        sev,
        ["T1590", "Gather Victim Network Information"],
        findings,
        f"NTP Mode 7 (private/deprecated) traffic detected: {total_mode7} packets from "
        f"{len(findings)} flagged source(s). Mode 7 is disabled in NTPv4; its presence "
        "indicates legacy ntpdc usage or monlist exploitation for DDoS amplification "
        "(each monlist request can elicit ~100x larger response).",
    )


def detect_spoofed_response(records: list[dict]) -> dict:
    """
    Suspicious NTP server responses that deviate from expected characteristics:
    - Responses (mode 4) from non-standard source port (not 123)
    - Unsynchronised NTP servers (stratum 16) sending responses
    - Multiple stratum-1 servers with differing refids to same client

    These patterns are consistent with spoofed/crafted NTP responses (T1557).
    """
    findings = []
    seen_keys: set[tuple] = set()

    # Non-standard source port for NTP responses
    for r in records:
        if r["mode"] == 4 and r["src_port"] != 123 and r["src_port"] != 0:
            key = (r["src_ip"], r["src_port"])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "indicator":    "Non-standard source port",
                    "src_ip":       r["src_ip"],
                    "src_port":     r["src_port"],
                    "dst_ip":       r["dst_ip"],
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    # Stratum 16 (unsynchronised) responses
    for r in records:
        if r["mode"] == 4 and r["stratum"] == 16:
            key = ("stratum16", r["src_ip"])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "indicator":    "Stratum 16 (unsynchronised) response",
                    "src_ip":       r["src_ip"],
                    "src_port":     r["src_port"],
                    "dst_ip":       r["dst_ip"],
                    "stratum":      r["stratum"],
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    # Multiple conflicting stratum-1 servers responding to same client
    client_srcs: dict[str, dict[str, set]] = defaultdict(lambda: defaultdict(set))
    for r in records:
        if r["mode"] == 4 and r["stratum"] == 1:
            client_srcs[r["dst_ip"]][r["src_ip"]].add(r["refid"])

    for client, srcs in client_srcs.items():
        if len(srcs) > 3:
            key = ("multi_stratum1", client)
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "indicator":     "Multiple stratum-1 servers for single client",
                    "client_ip":     client,
                    "server_count":  len(srcs),
                    "servers":       list(srcs.keys())[:5],
                })

    sev = "info"
    if findings:
        sev = "high" if any(f["indicator"] == "Non-standard source port" for f in findings) else "medium"

    return _result(
        "Spoofed NTP Response",
        sev,
        ["T1557", "Adversary-in-the-Middle"],
        findings,
        f"Suspicious NTP server responses suggesting spoofing or MITM: {len(findings)} indicator(s). "
        "Non-standard source ports, unsynchronised servers, and conflicting stratum-1 "
        "responses can indicate NTP-based time poisoning attacks.",
    )


def detect_time_manipulation(records: list[dict]) -> dict:
    """
    NTP responses with anomalously high root dispersion or root delay values,
    indicating a misconfigured or deliberately manipulated time source (T1070).

    Attackers manipulate NTP time to shift log timestamps and evade detection.
    """
    findings = []
    seen: set[str] = set()

    for r in records:
        if r["mode"] not in (4, 5):  # server or broadcast responses
            continue
        flagged_disp = r["rootdispersion"] > TIME_MANIP_ROOTDISP_THRESH
        flagged_delay = r["rootdelay"] > TIME_MANIP_ROOTDELAY_THRESH
        if (flagged_disp or flagged_delay) and r["src_ip"] not in seen:
            seen.add(r["src_ip"])
            findings.append({
                "src_ip":          r["src_ip"],
                "stratum":         r["stratum"],
                "rootdispersion":  round(r["rootdispersion"], 3),
                "rootdelay":       round(r["rootdelay"], 3),
                "flag":            ("high dispersion" if flagged_disp else "") +
                                   (" + high delay" if flagged_delay else ""),
                "timestamp_utc":   _ts_utc(r["timestamp"]),
            })

    findings.sort(key=lambda x: x["rootdispersion"], reverse=True)
    return _result(
        "NTP Time Manipulation",
        "high" if findings else "info",
        ["T1070", "Indicator Removal"],
        findings,
        f"NTP responses with anomalous root dispersion (>{TIME_MANIP_ROOTDISP_THRESH}s) or "
        f"root delay (>{TIME_MANIP_ROOTDELAY_THRESH}s) from {len(findings)} source(s). "
        "Extreme values may indicate a rogue/misconfigured NTP server used to shift "
        "system clocks, causing timestamp-based log evasion.",
    )


def detect_ntp_recon(records: list[dict]) -> dict:
    """
    NTP reconnaissance: single source querying many distinct NTP servers,
    used to enumerate time infrastructure or find vulnerable monlist-enabled servers (T1595).
    """
    # NTP client requests (mode 3) grouped by source
    src_servers: dict[str, set] = defaultdict(set)
    src_ts: dict[str, list[float]] = defaultdict(list)
    for r in records:
        if r["mode"] == 3 and r["src_ip"]:
            src_servers[r["src_ip"]].add(r["dst_ip"])
            src_ts[r["src_ip"]].append(r["timestamp"])

    findings = []
    for src, servers in src_servers.items():
        if len(servers) < RECON_MIN_SERVERS:
            continue
        ts = sorted(src_ts[src])
        duration = ts[-1] - ts[0] or 1.0
        findings.append({
            "src_ip":          src,
            "unique_servers":  len(servers),
            "duration_sec":    round(duration, 1),
            "rate_servers_per_sec": round(len(servers) / duration, 2),
            "sample_targets":  sorted(servers)[:10],
        })

    findings.sort(key=lambda x: x["unique_servers"], reverse=True)
    return _result(
        "NTP Reconnaissance / Server Scan",
        "medium" if findings else "info",
        ["T1595", "Active Scanning"],
        findings,
        f"NTP scanning from {len(findings)} source(s) querying ≥{RECON_MIN_SERVERS} "
        "distinct NTP servers. Indicates NTP infrastructure enumeration or scanning for "
        "servers with monlist enabled (amplification candidate discovery).",
    )


# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

_DETECTOR_KEYS = [
    (detect_amplification,   "amplification"),
    (detect_ntp_flood,       "ntp_flood"),
    (detect_kiss_of_death,   "kiss_of_death"),
    (detect_mode7_abuse,     "mode7_abuse"),
    (detect_spoofed_response, "spoofed_response"),
    (detect_time_manipulation, "time_manipulation"),
    (detect_ntp_recon,       "ntp_recon"),
]


def analyze(pcap_path: Path) -> tuple[dict, list[dict]]:
    print(f"[*] Extracting NTP records from {pcap_path} ...", file=sys.stderr)
    records = extract_ntp_records(pcap_path)
    print(f"[*] {len(records)} NTP packets extracted.", file=sys.stderr)
    if not records:
        print("[WARN] No NTP records found — verify PCAP has NTP traffic (UDP/123).",
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
        "timestamp_utc", "src_ip", "dst_ip", "src_port", "dst_port",
        "frame_len", "ntp_mode", "ntp_mode_name", "stratum",
        "refid", "rootdelay", "rootdispersion", "ppoll",
        "is_kod", "is_mode7", "is_large_response",
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
                r["src_port"],
                r["dst_port"],
                r["frame_len"],
                r["mode"],
                r["mode_name"],
                r["stratum"],
                r["refid"],
                r["rootdelay"],
                r["rootdispersion"],
                r["ppoll"],
                "1" if r["is_kod"] else "0",
                "1" if r["mode"] == 7 else "0",
                "1" if (r["mode"] == 4 and r["frame_len"] >= AMPLIFICATION_RESPONSE_MIN_BYTES) else "0",
            ])


def write_json(results: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def write_report(results: dict, out_path: Path,
                 pcap_path: Path, case_id: str = "") -> None:
    now_utc = datetime.now(tz=timezone.utc).isoformat()
    lines = [
        "# NTP Threat Analysis Report",
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
        "T1590": "reconnaissance",
        "T1557": "credential-access",
        "T1070": "defense-evasion",
        "T1595": "reconnaissance",
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
            ip = (finding.get("src_ip") or finding.get("victim_ip")
                  or finding.get("client_ip"))
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
        description="Analyze a PCAP file for NTP-based threat patterns.")
    parser.add_argument("pcap", type=Path, help="Path to PCAP file")
    parser.add_argument("--stem", default="",
                        help="Output directory stem (default: PCAP filename stem)")
    parser.add_argument("--case-id", default="", dest="case_id",
                        help="Case ID stamped in report and vault entries")
    parser.add_argument("--output-dir", type=Path,
                        default=Path("./analysis/ntp_threats"),
                        dest="output_dir",
                        help="Base output directory (default: ./analysis/ntp_threats)")
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

    json_path   = out_dir / "ntp_threats.json"
    csv_path    = out_dir / "ntp_flows.csv"
    report_path = out_dir / "ntp_threats_report.md"

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
