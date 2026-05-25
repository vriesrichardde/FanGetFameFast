#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_quic_threats.py — QUIC protocol threat detector.

Extracts QUIC traffic from a PCAP and runs five detection categories:
  - QUIC Amplification / DDoS              (T1498.002)
  - 0-RTT Replay Attack                    (T1550)
  - Version Forgery / Negotiation Anomaly  (T1562)
  - Pre-Handshake Exhaustion               (T1499.002)
  - QUIC on Non-Standard Port              (T1571)

Usage:
  python3 fan_quic_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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

# ── Detection categories ─────────────────────────────────────────────────────
CATEGORIES: dict[str, dict] = {
    "quic_amplification": {
        "label": "QUIC Amplification / DDoS",
        "severity": "critical",
        "mitre": ["T1498.002"],
        "mitre_names": ["Network Denial of Service: Reflection Amplification"],
        "tactic": "Impact",
        "description": (
            "QUIC responses significantly larger than the triggering Initial packets "
            "were directed toward victim IP addresses. While QUIC includes address "
            "validation mechanisms, incomplete validation or misuse of Retry packets "
            "can facilitate amplification at initial handshake stages."
        ),
    },
    "quic_0rtt_replay": {
        "label": "0-RTT Replay Attack",
        "severity": "high",
        "mitre": ["T1550"],
        "mitre_names": ["Use Alternate Authentication Material"],
        "tactic": "Defense Evasion / Lateral Movement",
        "description": (
            "Multiple QUIC 0-RTT packets (long header type 0x01) were observed from "
            "the same source to the same destination, which may indicate replay of "
            "previously captured 0-RTT data. QUIC 0-RTT does not provide forward "
            "secrecy and is susceptible to replay attacks."
        ),
    },
    "quic_version_anomaly": {
        "label": "QUIC Version Forgery / Negotiation Anomaly",
        "severity": "medium",
        "mitre": ["T1562"],
        "mitre_names": ["Impair Defenses"],
        "tactic": "Defense Evasion",
        "description": (
            "QUIC packets with unrecognised or reserved version numbers were detected. "
            "Attackers can forge QUIC version fields to trigger Version Negotiation "
            "responses, enumerate supported versions, or exploit version-specific "
            "parsing bugs in QUIC stacks."
        ),
    },
    "quic_handshake_exhaustion": {
        "label": "Pre-Handshake Exhaustion / Incomplete Handshakes",
        "severity": "high",
        "mitre": ["T1499.002"],
        "mitre_names": ["Endpoint Denial of Service: Service Exhaustion Flood"],
        "tactic": "Impact",
        "description": (
            "A source IP sent a large number of QUIC Initial packets without "
            "completing the handshake (no corresponding Handshake or 1-RTT packets "
            "on the same connection). This exhausts server connection state tables "
            "and pre-allocates cryptographic resources."
        ),
    },
    "quic_nonstandard_port": {
        "label": "QUIC on Non-Standard Port",
        "severity": "medium",
        "mitre": ["T1571"],
        "mitre_names": ["Non-Standard Port"],
        "tactic": "Command and Control",
        "description": (
            "QUIC traffic was detected on ports other than 443 or 8443. C2 operators "
            "and malware sometimes encapsulate QUIC channels on arbitrary UDP ports "
            "to evade port-based firewall rules and DPI signatures."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
AMPLIFICATION_RATIO        = 5     # Response bytes / request bytes
AMPLIFICATION_MIN_PKTS     = 10    # Minimum response packets to flag
HANDSHAKE_EXHAUSTION_THRESHOLD = 100  # Initials without completion per src
ZERO_RTT_REPEAT_THRESHOLD  = 3     # Repeated 0-RTT packets from same src→dst

# Standard QUIC ports (not flagged by non-standard port detector)
STANDARD_QUIC_PORTS: frozenset[int] = frozenset({443, 8443})

# Known valid QUIC version numbers
KNOWN_QUIC_VERSIONS: frozenset[int] = frozenset({
    0x00000001,  # QUIC v1 (RFC 9000)
    0x00000002,  # QUIC v2 (RFC 9369)
    0x6b3343cf,  # draft-29
    0xff00001d,  # draft-29 (alternate encoding)
    0xff00001c,  # draft-28
    0xff00001b,  # draft-27
    0x1a2a3a4a,  # QUIC version negotiation probe
    0x0a0a0a0a,  # GREASE version
})

# QUIC long-header packet types
QUIC_INITIAL   = 0   # 0x00
QUIC_0RTT      = 1   # 0x01
QUIC_HANDSHAKE = 2   # 0x02
QUIC_RETRY     = 3   # 0x03

ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "quic_threats"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ) + "Z"
    except (ValueError, TypeError):
        return epoch or ""


def _int(s: str) -> int:
    try:
        v = s.strip()
        return int(v, 16) if v.startswith("0x") else int(v)
    except (ValueError, AttributeError):
        return -1


def _run_tshark(pcap: Path, fields: list[str], display_filter: str = "") -> list[list[str]]:
    cmd = [
        "tshark", "-r", str(pcap),
        "-T", "fields",
        "-E", "separator=\t",
        "-E", "occurrence=f",
        "-E", "header=n",
    ]
    if display_filter:
        cmd += ["-Y", display_filter]
    for f in fields:
        cmd += ["-e", f]
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, text=True)
    except subprocess.CalledProcessError:
        return []
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) == len(fields):
            rows.append(parts)
    return rows


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict[str, list[dict]], list[dict]]:
    """Return (results_by_category, raw_flow_list)."""
    fields = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "quic.version",
        "quic.long.packet_type",
        "quic.header_form",       # 1=long, 0=short
        "quic.connection_number", # connection ID prefix (may be absent)
        "frame.len",
    ]
    rows = _run_tshark(pcap, fields, "quic")

    flows: list[dict] = []
    for r in rows:
        version_raw = r[6].strip()
        pkt_type_raw = r[7].strip()
        flows.append({
            "frame_no":       r[0],
            "timestamp_utc":  _ts(r[1]),
            "src_ip":         r[2].strip(),
            "dst_ip":         r[3].strip(),
            "src_port":       r[4].strip(),
            "dst_port":       r[5].strip(),
            "version_raw":    version_raw,
            "version_int":    _int(version_raw) if version_raw else -1,
            "pkt_type_raw":   pkt_type_raw,
            "pkt_type_int":   _int(pkt_type_raw) if pkt_type_raw else -1,
            "header_form":    r[8].strip(),   # "1"=long
            "conn_id":        r[9].strip(),
            "frame_len":      _int(r[10]) if r[10].strip() else 0,
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    long_hdr = [f for f in flows if f["header_form"] == "1"]
    initials   = [f for f in long_hdr if f["pkt_type_int"] == QUIC_INITIAL]
    zero_rtt   = [f for f in long_hdr if f["pkt_type_int"] == QUIC_0RTT]
    handshakes = [f for f in long_hdr if f["pkt_type_int"] == QUIC_HANDSHAKE]

    # ── 1. Amplification: large QUIC responses vs small requests ──────────
    # Heuristic: server responses are src_port ∈ STANDARD_QUIC_PORTS
    req_bytes:  dict[tuple, int] = defaultdict(int)
    resp_bytes: dict[tuple, int] = defaultdict(int)
    resp_count: dict[tuple, int] = defaultdict(int)
    resp_first: dict[tuple, str] = {}

    for f in flows:
        sport = _int(f["src_port"])
        dport = _int(f["dst_port"])
        if sport in STANDARD_QUIC_PORTS:
            # server → client (response)
            key = (f["src_ip"], sport, f["dst_ip"])
            resp_bytes[key]  += f["frame_len"]
            resp_count[key]  += 1
            if key not in resp_first:
                resp_first[key] = f["timestamp_utc"]
        elif dport in STANDARD_QUIC_PORTS:
            # client → server (request)
            key = (f["dst_ip"], dport, f["src_ip"])
            req_bytes[key] += f["frame_len"]

    for key, rb in resp_bytes.items():
        rq = req_bytes.get(key, 0)
        cnt = resp_count[key]
        if cnt < AMPLIFICATION_MIN_PKTS:
            continue
        ratio = (rb / rq) if rq > 0 else float("inf")
        if ratio >= AMPLIFICATION_RATIO:
            results["quic_amplification"].append({
                "server_ip":       key[0],
                "server_port":     key[1],
                "victim_ip":       key[2],
                "response_packets": cnt,
                "response_bytes":  rb,
                "request_bytes":   rq,
                "amplification_ratio": round(ratio, 1) if ratio != float("inf") else "inf",
                "timestamp_utc":   resp_first.get(key, ""),
            })

    # ── 2. 0-RTT Replay: repeated 0-RTT from same src→dst ─────────────────
    zero_rtt_pairs: dict[tuple, int] = defaultdict(int)
    zero_rtt_first: dict[tuple, str] = {}

    for f in zero_rtt:
        key = (f["src_ip"], f["dst_ip"], f["dst_port"])
        zero_rtt_pairs[key] += 1
        if key not in zero_rtt_first:
            zero_rtt_first[key] = f["timestamp_utc"]

    for (src, dst, dport), cnt in zero_rtt_pairs.items():
        if cnt >= ZERO_RTT_REPEAT_THRESHOLD:
            results["quic_0rtt_replay"].append({
                "src_ip":          src,
                "dst_ip":          dst,
                "dst_port":        dport,
                "zero_rtt_count":  cnt,
                "timestamp_utc":   zero_rtt_first.get((src, dst, dport), ""),
            })

    # ── 3. Version Anomaly: unrecognised QUIC version ─────────────────────
    seen_versions: dict[tuple, dict] = {}
    for f in long_hdr:
        ver = f["version_int"]
        if ver < 0:
            continue
        if ver not in KNOWN_QUIC_VERSIONS:
            key = (f["src_ip"], f["dst_ip"], ver)
            if key not in seen_versions:
                seen_versions[key] = {
                    "src_ip":       f["src_ip"],
                    "dst_ip":       f["dst_ip"],
                    "dst_port":     f["dst_port"],
                    "version_hex":  f["version_raw"],
                    "pkt_type":     f["pkt_type_raw"],
                    "timestamp_utc": f["timestamp_utc"],
                }

    results["quic_version_anomaly"] = list(seen_versions.values())

    # ── 4. Handshake Exhaustion: many Initials, no Handshake completion ───
    initial_count: dict[str, int] = defaultdict(int)
    initial_first: dict[str, str] = {}
    initial_last:  dict[str, str] = {}
    handshake_srcs: set = set()

    for f in initials:
        src = f["src_ip"]
        if not src:
            continue
        initial_count[src] += 1
        if src not in initial_first:
            initial_first[src] = f["timestamp_utc"]
        initial_last[src] = f["timestamp_utc"]

    for f in handshakes:
        handshake_srcs.add(f["src_ip"])
        handshake_srcs.add(f["dst_ip"])

    for src, cnt in initial_count.items():
        if cnt >= HANDSHAKE_EXHAUSTION_THRESHOLD and src not in handshake_srcs:
            results["quic_handshake_exhaustion"].append({
                "src_ip":            src,
                "initial_count":     cnt,
                "handshake_seen":    False,
                "first_timestamp":   initial_first.get(src, ""),
                "last_timestamp":    initial_last.get(src, ""),
                "timestamp_utc":     initial_first.get(src, ""),
            })

    # ── 5. Non-Standard Port: QUIC on ports outside standard set ──────────
    seen_nonstandard: dict[tuple, dict] = {}
    for f in flows:
        sport = _int(f["src_port"])
        dport = _int(f["dst_port"])
        if sport not in STANDARD_QUIC_PORTS and dport not in STANDARD_QUIC_PORTS:
            key = (f["src_ip"], f["dst_ip"], dport if dport > 0 else sport)
            if key not in seen_nonstandard:
                seen_nonstandard[key] = {
                    "src_ip":        f["src_ip"],
                    "dst_ip":        f["dst_ip"],
                    "src_port":      f["src_port"],
                    "dst_port":      f["dst_port"],
                    "version_hex":   f["version_raw"],
                    "timestamp_utc": f["timestamp_utc"],
                }

    results["quic_nonstandard_port"] = list(seen_nonstandard.values())

    return results, flows


# ── Output writers ────────────────────────────────────────────────────────────

def write_json(results: dict, flows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict = {
        "generated_utc": datetime.now(tz=timezone.utc).isoformat(),
        "categories": {},
    }
    for cat, items in results.items():
        meta = CATEGORIES[cat]
        payload["categories"][cat] = {
            "label":       meta["label"],
            "severity":    meta["severity"],
            "mitre":       meta["mitre"],
            "mitre_names": meta["mitre_names"],
            "count":       len(items),
            "findings":    items,
        }
    payload["_flows"] = flows
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(flows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not flows:
        path.write_text("", encoding="utf-8")
        return
    cols = list(flows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        w.writerows(flows)


def write_report(results: dict, path: Path, pcap: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    total = sum(len(v) for v in results.values())
    triggered = [CATEGORIES[k]["severity"] for k, v in results.items() if v]
    highest = min(triggered, key=lambda s: sev_order[s]) if triggered else "info"

    lines: list[str] = [
        "# QUIC Threat Analysis Report",
        "",
        f"**Source:** `{pcap}`  ",
        f"**Generated:** {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Overall Severity:** {highest.upper()}  ",
        f"**Total Findings:** {total}",
        "",
        "---",
        "",
        "## Detection Summary",
        "",
        "| Category | Severity | Count | MITRE ATT&CK |",
        "|----------|----------|-------|--------------|",
    ]
    for cat, meta in CATEGORIES.items():
        cnt   = len(results.get(cat, []))
        badge = "**" if cnt > 0 else ""
        mitre = ", ".join(
            f"[{t}](https://attack.mitre.org/techniques/{t.replace('.', '/')})"
            for t in meta["mitre"]
        )
        lines.append(
            f"| {badge}{meta['label']}{badge} | {meta['severity'].upper()} "
            f"| {cnt} | {mitre} |"
        )

    lines += ["", "---", ""]

    for cat, meta in CATEGORIES.items():
        findings = results.get(cat, [])
        lines += [
            f"## {meta['label']}",
            "",
            f"**Severity:** {meta['severity'].upper()}  ",
            f"**MITRE:** {', '.join(meta['mitre'])} — {', '.join(meta['mitre_names'])}  ",
            f"**Tactic:** {meta['tactic']}  ",
            "",
            f"{meta['description']}",
            "",
            f"**Findings: {len(findings)}**",
        ]
        if findings:
            top = findings[:10]
            cols = list(top[0].keys())
            lines += [
                "",
                "| " + " | ".join(cols) + " |",
                "| " + " | ".join(["---"] * len(cols)) + " |",
            ]
            for row in top:
                vals = [str(row.get(c, "")) for c in cols]
                lines.append("| " + " | ".join(vals) + " |")
            if len(findings) > 10:
                lines.append(f"\n*… and {len(findings) - 10} more findings.*")
        lines += ["", "---", ""]

    path.write_text("\n".join(lines), encoding="utf-8")


def _write_vault(results: dict, stem: str, case_id: str | None) -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp  # noqa: F401
        for cat, items in results.items():
            if not items:
                continue
            meta = CATEGORIES[cat]
            for tid in meta["mitre"]:
                record_ttp(
                    tid,
                    meta["mitre_names"][0],
                    f"{len(items)} instance(s) in PCAP stem '{stem}': {meta['description']}",
                    case_id or stem,
                    tactic=meta["tactic"],
                )
    except Exception:
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="QUIC threat detector for PCAP files.")
    ap.add_argument("pcap", type=Path)
    ap.add_argument("--stem",       default=None)
    ap.add_argument("--case-id",    default=None, dest="case_id")
    ap.add_argument("--output-dir", default=None, dest="output_dir", type=Path)
    ap.add_argument("--no-vault",   action="store_true", dest="no_vault")
    args = ap.parse_args()

    pcap = args.pcap
    if not pcap.exists():
        sys.exit(f"[ERROR] PCAP not found: {pcap}")

    stem    = args.stem or pcap.stem
    out_dir = args.output_dir or (ANALYSIS_DIR / OUTPUT_SUBDIR / stem)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Analysing QUIC traffic in: {pcap}")
    results, flows = analyze(pcap)

    print(f"[*] QUIC packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in results.values())}")

    json_path   = out_dir / "quic_threats.json"
    csv_path    = out_dir / "quic_flows.csv"
    report_path = out_dir / "quic_threats_report.md"

    write_json(results, flows, json_path)
    write_csv(flows, csv_path)
    write_report(results, report_path, pcap)

    if not args.no_vault:
        _write_vault(results, stem, args.case_id)

    print(f"[+] JSON:   {json_path}")
    print(f"[+] CSV:    {csv_path}")
    print(f"[+] Report: {report_path}")


if __name__ == "__main__":
    main()
