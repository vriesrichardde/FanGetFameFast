#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_udp_threats.py — UDP threat detector.

Extracts UDP traffic from a PCAP and runs five detection categories:
  - UDP Flood                              (T1498.001)
  - UDP Reflection / Amplification Attack  (T1498.002)
  - UDP Port Scan                          (T1046)
  - UDP Fragmentation Attack               (T1499)
  - IP Spoofing Indicator (low TTL anomaly)(T1001)

Usage:
  python3 fan_udp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "udp_flood": {
        "label": "UDP Flood",
        "severity": "critical",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "A source IP sent an abnormally high volume of UDP datagrams to a "
            "single destination, saturating the target's network bandwidth or "
            "exhausting application receive buffers."
        ),
    },
    "udp_amplification": {
        "label": "UDP Reflection / Amplification Attack",
        "severity": "critical",
        "mitre": ["T1498.002"],
        "mitre_names": ["Network Denial of Service: Reflection Amplification"],
        "tactic": "Impact",
        "description": (
            "A reflector source sent UDP responses that are significantly larger "
            "than the corresponding requests, consistent with a UDP-based "
            "amplification attack using services such as DNS, NTP, SSDP, or Memcached."
        ),
    },
    "udp_port_scan": {
        "label": "UDP Port Scan",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "A single source IP sent UDP datagrams to many distinct destination ports, "
            "characteristic of automated UDP service enumeration."
        ),
    },
    "udp_fragmentation": {
        "label": "UDP Fragmentation Attack",
        "severity": "high",
        "mitre": ["T1499"],
        "mitre_names": ["Endpoint Denial of Service"],
        "tactic": "Impact",
        "description": (
            "Fragmented UDP datagrams (IP more-fragments flag set or non-zero fragment "
            "offset) were detected. Excessive or crafted fragmentation can exhaust "
            "reassembly buffers and disrupt stateful inspection appliances."
        ),
    },
    "udp_spoofing": {
        "label": "IP Spoofing Indicator (UDP)",
        "severity": "high",
        "mitre": ["T1001"],
        "mitre_names": ["Data Obfuscation"],
        "tactic": "Command and Control",
        "description": (
            "UDP packets with anomalously low TTL values (≤5) were detected. "
            "Very low TTL is a strong indicator of IP address spoofing, as "
            "crafted spoofed packets are often injected with artificially small "
            "TTLs to prevent reverse-path detection."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
UDP_FLOOD_THRESHOLD         = 1000   # Datagrams from one src IP to one dst IP
UDP_SCAN_THRESHOLD          = 30     # Unique dst ports from one src IP
AMPLIFICATION_RATIO         = 10     # Response bytes / request bytes
AMPLIFICATION_MIN_RESPONSES = 20     # Minimum response packets to flag
FRAGMENT_THRESHOLD          = 50     # Fragmented packets from one src to flag
SPOOFING_TTL_MAX            = 5      # TTL ≤ this value flagged as spoof indicator

# Well-known UDP amplification ports (reflector source ports)
AMPLIFICATION_PORTS: frozenset[int] = frozenset({
    53,    # DNS
    123,   # NTP
    1900,  # SSDP
    11211, # Memcached
    389,   # LDAP
    5353,  # mDNS
    27960, # Quake/game servers
    19,    # Chargen
    17,    # QOTD
    137,   # NetBIOS-NS
})

ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "udp_threats"


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
        return int(s.strip())
    except (ValueError, AttributeError):
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
        "udp.srcport",
        "udp.dstport",
        "frame.len",
        "ip.ttl",
        "ip.flags.mf",          # more-fragments bit
        "ip.frag_offset",
    ]
    rows = _run_tshark(pcap, fields, "udp")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":      r[0],
            "timestamp_utc": _ts(r[1]),
            "src_ip":        r[2].strip(),
            "dst_ip":        r[3].strip(),
            "src_port":      r[4].strip(),
            "dst_port":      r[5].strip(),
            "frame_len":     _int(r[6]),
            "ttl":           _int(r[7]),
            "more_frags":    r[8].strip(),   # "1" or "0"
            "frag_offset":   _int(r[9]),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    # ── 1. UDP Flood: high packet count src→dst pair ───────────────────────
    pair_count: dict[tuple, int] = defaultdict(int)
    pair_bytes: dict[tuple, int] = defaultdict(int)
    pair_first: dict[tuple, str] = {}
    pair_last:  dict[tuple, str] = {}

    for f in flows:
        key = (f["src_ip"], f["dst_ip"], f["dst_port"])
        pair_count[key] += 1
        pair_bytes[key] += f["frame_len"]
        if key not in pair_first:
            pair_first[key] = f["timestamp_utc"]
        pair_last[key] = f["timestamp_utc"]

    for (src, dst, dport), cnt in pair_count.items():
        if cnt >= UDP_FLOOD_THRESHOLD:
            results["udp_flood"].append({
                "src_ip":          src,
                "dst_ip":          dst,
                "dst_port":        dport,
                "packet_count":    cnt,
                "total_bytes":     pair_bytes[(src, dst, dport)],
                "first_timestamp": pair_first.get((src, dst, dport), ""),
                "last_timestamp":  pair_last.get((src, dst, dport), ""),
                "timestamp_utc":   pair_first.get((src, dst, dport), ""),
            })

    # ── 2. Amplification: compare request size → response size ────────────
    # Response is large UDP from a known amplification port to various victims
    refl_bytes:    dict[tuple, int] = defaultdict(int)
    refl_count:    dict[tuple, int] = defaultdict(int)
    refl_req_bytes: dict[tuple, int] = defaultdict(int)
    refl_first:    dict[tuple, str] = {}

    for f in flows:
        sport = _int(f["src_port"])
        dport = _int(f["dst_port"])
        # Response: from amplification port to victim
        if sport in AMPLIFICATION_PORTS:
            key = (f["src_ip"], sport, f["dst_ip"])
            refl_bytes[key]  += f["frame_len"]
            refl_count[key]  += 1
            if key not in refl_first:
                refl_first[key] = f["timestamp_utc"]
        # Request: to amplification port
        if dport in AMPLIFICATION_PORTS:
            key = (f["dst_ip"], dport, f["src_ip"])
            refl_req_bytes[key] += f["frame_len"]

    for key, resp_bytes in refl_bytes.items():
        req_bytes = refl_req_bytes.get(key, 0)
        cnt = refl_count[key]
        if cnt < AMPLIFICATION_MIN_RESPONSES:
            continue
        ratio = (resp_bytes / req_bytes) if req_bytes > 0 else float("inf")
        if ratio >= AMPLIFICATION_RATIO:
            results["udp_amplification"].append({
                "reflector_ip":    key[0],
                "reflector_port":  key[1],
                "victim_ip":       key[2],
                "response_packets": cnt,
                "response_bytes":  resp_bytes,
                "request_bytes":   req_bytes,
                "amplification_ratio": round(ratio, 1) if ratio != float("inf") else "inf",
                "timestamp_utc":   refl_first.get(key, ""),
            })

    # ── 3. UDP Port Scan: many distinct dst ports from single src ─────────
    src_dports: dict[str, set] = defaultdict(set)
    scan_first: dict[str, str] = {}
    scan_last:  dict[str, str] = {}

    for f in flows:
        src = f["src_ip"]
        dport = f["dst_port"]
        if not src or not dport:
            continue
        src_dports[src].add(dport)
        if src not in scan_first:
            scan_first[src] = f["timestamp_utc"]
        scan_last[src] = f["timestamp_utc"]

    for src, ports in src_dports.items():
        if len(ports) >= UDP_SCAN_THRESHOLD:
            results["udp_port_scan"].append({
                "src_ip":          src,
                "unique_dst_ports": len(ports),
                "first_timestamp": scan_first.get(src, ""),
                "last_timestamp":  scan_last.get(src, ""),
                "timestamp_utc":   scan_first.get(src, ""),
            })

    # ── 4. UDP Fragmentation: fragmented packets per source ───────────────
    frag_count: dict[str, int] = defaultdict(int)
    frag_first: dict[str, str] = {}
    frag_last:  dict[str, str] = {}

    for f in flows:
        if f["more_frags"] == "1" or f["frag_offset"] > 0:
            src = f["src_ip"]
            if not src:
                continue
            frag_count[src] += 1
            if src not in frag_first:
                frag_first[src] = f["timestamp_utc"]
            frag_last[src] = f["timestamp_utc"]

    for src, cnt in frag_count.items():
        if cnt >= FRAGMENT_THRESHOLD:
            results["udp_fragmentation"].append({
                "src_ip":            src,
                "fragment_count":    cnt,
                "first_timestamp":   frag_first.get(src, ""),
                "last_timestamp":    frag_last.get(src, ""),
                "timestamp_utc":     frag_first.get(src, ""),
            })

    # ── 5. IP Spoofing indicator: very low TTL ────────────────────────────
    spoof_src: dict[str, dict] = {}

    for f in flows:
        ttl = f["ttl"]
        src = f["src_ip"]
        if not src or ttl <= 0:
            continue
        if ttl <= SPOOFING_TTL_MAX:
            if src not in spoof_src:
                spoof_src[src] = {
                    "src_ip":        src,
                    "min_ttl":       ttl,
                    "packet_count":  0,
                    "timestamp_utc": f["timestamp_utc"],
                }
            spoof_src[src]["packet_count"] += 1
            spoof_src[src]["min_ttl"] = min(spoof_src[src]["min_ttl"], ttl)

    results["udp_spoofing"] = list(spoof_src.values())

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
        "# UDP Threat Analysis Report",
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
    ap = argparse.ArgumentParser(description="UDP threat detector for PCAP files.")
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

    print(f"[*] Analysing UDP traffic in: {pcap}")
    results, flows = analyze(pcap)

    print(f"[*] UDP packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in results.values())}")

    json_path   = out_dir / "udp_threats.json"
    csv_path    = out_dir / "udp_flows.csv"
    report_path = out_dir / "udp_threats_report.md"

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
