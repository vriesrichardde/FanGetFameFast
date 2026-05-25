#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_tcp_threats.py — TCP threat detector.

Extracts TCP traffic from a PCAP and runs six detection categories:
  - SYN Flood                        (T1498.001)
  - TCP Port Scan                    (T1046)
  - RST Flood / Connection Reset DoS (T1499.002)
  - FIN / NULL / Xmas Scan           (T1046)
  - TCP Session Hijacking Indicators (T1563)
  - Suspicious Half-Open Connections (T1499.002)

Usage:
  python3 fan_tcp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "syn_flood": {
        "label": "SYN Flood",
        "severity": "critical",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "A source IP sent an abnormally high number of TCP SYN packets without "
            "completing the three-way handshake, consuming server connection table "
            "resources and potentially causing denial of service."
        ),
    },
    "port_scan": {
        "label": "TCP Port Scan",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "A single source IP initiated TCP SYN connections to an unusually large "
            "number of distinct destination ports on one or more hosts, indicating "
            "automated port enumeration."
        ),
    },
    "rst_flood": {
        "label": "RST Flood / Connection Reset DoS",
        "severity": "high",
        "mitre": ["T1499.002"],
        "mitre_names": ["Endpoint Denial of Service: Service Exhaustion Flood"],
        "tactic": "Impact",
        "description": (
            "A source IP sent a large volume of TCP RST packets, potentially disrupting "
            "established connections and causing service interruption for legitimate "
            "clients (TCP Reset Attack)."
        ),
    },
    "stealth_scan": {
        "label": "TCP Stealth Scan (FIN / NULL / Xmas)",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "Packets with unusual TCP flag combinations (FIN-only, NULL flags, or "
            "FIN+PSH+URG 'Christmas tree') were detected. These bypass some stateless "
            "firewalls and infer port state from the absence of RST responses."
        ),
    },
    "session_hijack": {
        "label": "TCP Session Hijacking Indicators",
        "severity": "critical",
        "mitre": ["T1563"],
        "mitre_names": ["Remote Service Session Hijacking"],
        "tactic": "Lateral Movement",
        "description": (
            "A third IP sent TCP data on a stream previously established between two "
            "other hosts, or injected RST packets into an existing session, which are "
            "characteristic indicators of session hijacking or injection attacks."
        ),
    },
    "half_open_flood": {
        "label": "Half-Open Connection Flood",
        "severity": "high",
        "mitre": ["T1499.002"],
        "mitre_names": ["Endpoint Denial of Service: Service Exhaustion Flood"],
        "tactic": "Impact",
        "description": (
            "A source IP maintained a high ratio of SYN packets to SYN-ACK responses, "
            "leaving a large number of connections in SYN_RCVD state and exhausting "
            "the target's connection backlog."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
SYN_FLOOD_THRESHOLD        = 500   # SYN packets from one src IP to flag as flood
PORT_SCAN_THRESHOLD        = 30    # Unique dst ports from one src IP to flag as scan
RST_FLOOD_THRESHOLD        = 200   # RST packets from one src IP
STEALTH_SCAN_THRESHOLD     = 10    # Stealth probes from one src IP to flag
HALF_OPEN_SYN_THRESHOLD    = 200   # SYN count with ≥90 % half-open ratio

ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "tcp_threats"

# TCP flag bitmask constants (tshark decimal string)
# Flags: CWR=0x80, ECE=0x40, URG=0x20, ACK=0x10, PSH=0x08, RST=0x04, SYN=0x02, FIN=0x01
_FLAG_SYN = 0x02
_FLAG_ACK = 0x10
_FLAG_RST = 0x04
_FLAG_FIN = 0x01
_FLAG_PSH = 0x08
_FLAG_URG = 0x20


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ) + "Z"
    except (ValueError, TypeError):
        return epoch or ""


def _flags(raw: str) -> int:
    try:
        v = raw.strip()
        return int(v, 16) if v.startswith("0x") else int(v)
    except (ValueError, TypeError):
        return 0


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
        "tcp.srcport",
        "tcp.dstport",
        "tcp.flags",
        "tcp.stream",
        "tcp.seq",
        "tcp.ack",
    ]
    rows = _run_tshark(pcap, fields, "tcp")

    flows: list[dict] = []
    for r in rows:
        fval = _flags(r[6])
        flows.append({
            "frame_no":       r[0],
            "timestamp_utc":  _ts(r[1]),
            "src_ip":         r[2].strip(),
            "dst_ip":         r[3].strip(),
            "src_port":       r[4].strip(),
            "dst_port":       r[5].strip(),
            "flags_raw":      r[6].strip(),
            "flags_int":      fval,
            "stream_id":      r[7].strip(),
            "tcp_seq":        r[8].strip(),
            "tcp_ack":        r[9].strip(),
            # Decoded flag booleans
            "flag_syn":       bool(fval & _FLAG_SYN),
            "flag_ack":       bool(fval & _FLAG_ACK),
            "flag_rst":       bool(fval & _FLAG_RST),
            "flag_fin":       bool(fval & _FLAG_FIN),
            "flag_psh":       bool(fval & _FLAG_PSH),
            "flag_urg":       bool(fval & _FLAG_URG),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    # Pre-partition
    syn_only  = [f for f in flows if f["flag_syn"] and not f["flag_ack"]]
    syn_ack   = [f for f in flows if f["flag_syn"] and f["flag_ack"]]
    rst_pkts  = [f for f in flows if f["flag_rst"]]
    fin_only  = [f for f in flows if f["flag_fin"] and not f["flag_ack"] and not f["flag_syn"]]
    null_pkts = [f for f in flows if f["flags_int"] == 0]
    xmas_pkts = [f for f in flows if f["flag_fin"] and f["flag_psh"] and f["flag_urg"]]

    # ── 1. SYN Flood ──────────────────────────────────────────────────────
    syn_count: dict[str, int] = defaultdict(int)
    syn_first: dict[str, str] = {}
    syn_last:  dict[str, str] = {}
    syn_dsts:  dict[str, set] = defaultdict(set)

    for f in syn_only:
        src = f["src_ip"]
        if not src:
            continue
        syn_count[src] += 1
        if src not in syn_first:
            syn_first[src] = f["timestamp_utc"]
        syn_last[src] = f["timestamp_utc"]
        syn_dsts[src].add(f["dst_ip"])

    for src, cnt in syn_count.items():
        if cnt >= SYN_FLOOD_THRESHOLD:
            results["syn_flood"].append({
                "src_ip":          src,
                "syn_count":       cnt,
                "unique_dst_ips":  len(syn_dsts.get(src, set())),
                "first_timestamp": syn_first.get(src, ""),
                "last_timestamp":  syn_last.get(src, ""),
                "timestamp_utc":   syn_first.get(src, ""),
            })

    # ── 2. Port Scan: SYN to many distinct ports ──────────────────────────
    src_ports: dict[tuple, set] = defaultdict(set)
    scan_first: dict[tuple, str] = {}
    scan_last:  dict[tuple, str] = {}

    for f in syn_only:
        src = f["src_ip"]
        dst = f["dst_ip"]
        dport = f["dst_port"]
        if not src or not dst or not dport:
            continue
        key = (src, dst)
        src_ports[key].add(dport)
        if key not in scan_first:
            scan_first[key] = f["timestamp_utc"]
        scan_last[key] = f["timestamp_utc"]

    for (src, dst), ports in src_ports.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            results["port_scan"].append({
                "src_ip":          src,
                "dst_ip":          dst,
                "unique_ports":    len(ports),
                "first_timestamp": scan_first.get((src, dst), ""),
                "last_timestamp":  scan_last.get((src, dst), ""),
                "timestamp_utc":   scan_first.get((src, dst), ""),
            })

    # ── 3. RST Flood ──────────────────────────────────────────────────────
    rst_count: dict[str, int] = defaultdict(int)
    rst_first: dict[str, str] = {}
    rst_last:  dict[str, str] = {}

    for f in rst_pkts:
        src = f["src_ip"]
        if not src:
            continue
        rst_count[src] += 1
        if src not in rst_first:
            rst_first[src] = f["timestamp_utc"]
        rst_last[src] = f["timestamp_utc"]

    for src, cnt in rst_count.items():
        if cnt >= RST_FLOOD_THRESHOLD:
            results["rst_flood"].append({
                "src_ip":          src,
                "rst_count":       cnt,
                "first_timestamp": rst_first.get(src, ""),
                "last_timestamp":  rst_last.get(src, ""),
                "timestamp_utc":   rst_first.get(src, ""),
            })

    # ── 4. Stealth scans (FIN-only, NULL, Xmas) ───────────────────────────
    stealth_src: dict[str, dict] = defaultdict(lambda: {
        "fin_count": 0, "null_count": 0, "xmas_count": 0,
        "first": "", "last": ""
    })

    for f in fin_only + null_pkts + xmas_pkts:
        src = f["src_ip"]
        if not src:
            continue
        d = stealth_src[src]
        if f["flag_fin"] and f["flag_psh"] and f["flag_urg"]:
            d["xmas_count"] += 1
        elif f["flags_int"] == 0:
            d["null_count"] += 1
        else:
            d["fin_count"] += 1
        if not d["first"]:
            d["first"] = f["timestamp_utc"]
        d["last"] = f["timestamp_utc"]

    for src, d in stealth_src.items():
        total_stealth = d["fin_count"] + d["null_count"] + d["xmas_count"]
        if total_stealth >= STEALTH_SCAN_THRESHOLD:
            results["stealth_scan"].append({
                "src_ip":          src,
                "fin_count":       d["fin_count"],
                "null_count":      d["null_count"],
                "xmas_count":      d["xmas_count"],
                "total_probes":    total_stealth,
                "first_timestamp": d["first"],
                "last_timestamp":  d["last"],
                "timestamp_utc":   d["first"],
            })

    # ── 5. Session Hijacking: RST injection into an existing stream ────────
    # Streams where we see SYN→SYN-ACK established, then RST from a third IP
    stream_clients: dict[str, set] = defaultdict(set)
    for f in syn_only + syn_ack:
        if f["stream_id"]:
            stream_clients[f["stream_id"]].add(f["src_ip"])

    for f in rst_pkts:
        sid = f["stream_id"]
        if not sid:
            continue
        established = stream_clients.get(sid, set())
        if established and f["src_ip"] not in established:
            results["session_hijack"].append({
                "stream_id":          sid,
                "injecting_ip":       f["src_ip"],
                "established_parties": sorted(established),
                "dst_ip":             f["dst_ip"],
                "dst_port":           f["dst_port"],
                "timestamp_utc":      f["timestamp_utc"],
            })

    # ── 6. Half-open flood: high SYN count with low SYN-ACK response ──────
    syn_ack_count: dict[str, int] = defaultdict(int)
    for f in syn_ack:
        dst = f["dst_ip"]   # the original SYN sender is dst in SYN-ACK
        if dst:
            syn_ack_count[dst] += 1

    for src, syn_cnt in syn_count.items():
        if syn_cnt < HALF_OPEN_SYN_THRESHOLD:
            continue
        ack_cnt = syn_ack_count.get(src, 0)
        # If >90% of SYNs got no SYN-ACK response, flag as half-open flood
        unanswered = syn_cnt - ack_cnt
        if unanswered > 0 and (unanswered / syn_cnt) >= 0.90:
            results["half_open_flood"].append({
                "src_ip":            src,
                "syn_count":         syn_cnt,
                "syn_ack_received":  ack_cnt,
                "half_open_ratio":   round(unanswered / syn_cnt, 3),
                "first_timestamp":   syn_first.get(src, ""),
                "last_timestamp":    syn_last.get(src, ""),
                "timestamp_utc":     syn_first.get(src, ""),
            })

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
    export_keys = ["frame_no", "timestamp_utc", "src_ip", "dst_ip",
                   "src_port", "dst_port", "flags_raw", "stream_id",
                   "flag_syn", "flag_ack", "flag_rst", "flag_fin"]
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=export_keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(flows)


def write_report(results: dict, path: Path, pcap: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    total = sum(len(v) for v in results.values())
    triggered = [CATEGORIES[k]["severity"] for k, v in results.items() if v]
    highest = min(triggered, key=lambda s: sev_order[s]) if triggered else "info"

    lines: list[str] = [
        "# TCP Threat Analysis Report",
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
            cols = [c for c in top[0].keys() if c != "established_parties"]
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
    ap = argparse.ArgumentParser(description="TCP threat detector for PCAP files.")
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

    print(f"[*] Analysing TCP traffic in: {pcap}")
    results, flows = analyze(pcap)

    print(f"[*] TCP packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in results.values())}")

    json_path   = out_dir / "tcp_threats.json"
    csv_path    = out_dir / "tcp_flows.csv"
    report_path = out_dir / "tcp_threats_report.md"

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
