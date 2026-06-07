#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_arp_threats.py — ARP threat detector.

Extracts ARP traffic from a PCAP and runs five detection categories:
  - ARP Cache Poisoning / Spoofing  (T1557.002)
  - Gratuitous ARP Anomaly          (T1557.002)
  - ARP Flood / DoS                 (T1498.001)
  - ARP Reconnaissance Scan         (T1018)
  - ARP Relay / Proxy Anomaly       (T1557)

Usage:
  python3 fan_arp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "arp_poisoning": {
        "label": "ARP Cache Poisoning / Spoofing",
        "severity": "critical",
        "mitre": ["T1557.002"],
        "mitre_names": ["Adversary-in-the-Middle: ARP Cache Poisoning"],
        "tactic": "Collection / Credential Access",
        "description": (
            "Multiple distinct MAC addresses claim ownership of the same IP address "
            "in observed ARP replies, indicating ARP cache poisoning in progress."
        ),
    },
    "gratuitous_arp": {
        "label": "Gratuitous ARP Anomaly",
        "severity": "high",
        "mitre": ["T1557.002"],
        "mitre_names": ["Adversary-in-the-Middle: ARP Cache Poisoning"],
        "tactic": "Collection",
        "description": (
            "High volume of gratuitous ARP announcements (sender IP == target IP) "
            "from a single source. Attackers use gratuitous ARPs to silently "
            "overwrite neighbour cache entries and redirect traffic."
        ),
    },
    "arp_flood": {
        "label": "ARP Flood / DoS",
        "severity": "high",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "Abnormally high rate of ARP requests from a single MAC address, "
            "saturating the local network segment and potentially exhausting "
            "switch ARP table capacity."
        ),
    },
    "arp_scan": {
        "label": "ARP Reconnaissance Scan",
        "severity": "medium",
        "mitre": ["T1018"],
        "mitre_names": ["Remote System Discovery"],
        "tactic": "Discovery",
        "description": (
            "A single source MAC issued ARP requests to an unusually large number "
            "of distinct target IPs, indicative of network-layer host discovery "
            "or asset enumeration."
        ),
    },
    "arp_proxy_anomaly": {
        "label": "ARP Proxy / Relay Anomaly",
        "severity": "medium",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection",
        "description": (
            "ARP reply observed where the replying MAC address (Ethernet source) "
            "differs from the MAC address in the ARP sender hardware field, "
            "suggesting a proxy ARP device or spoofing of the hardware address."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
ARP_FLOOD_THRESHOLD = 200    # ARP requests from one MAC to flag as flood
ARP_SCAN_THRESHOLD  = 20     # Unique target IPs from one MAC to flag as scan
GRAT_ARP_THRESHOLD  = 10     # Gratuitous ARP replies from one MAC to flag

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "arp_threats"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ) + "Z"
    except (ValueError, TypeError):
        return epoch or ""


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
        "arp.opcode",
        "arp.src.hw_mac",
        "arp.src.proto_ipv4",
        "arp.dst.hw_mac",
        "arp.dst.proto_ipv4",
        "eth.src",
    ]
    rows = _run_tshark(pcap, fields, "arp")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":    r[0],
            "timestamp_utc": _ts(r[1]),
            "opcode":      r[2],            # "1"=request "2"=reply
            "sender_mac":  r[3].lower().strip(),
            "sender_ip":   r[4].strip(),
            "target_mac":  r[5].lower().strip(),
            "target_ip":   r[6].strip(),
            "eth_src":     r[7].lower().strip(),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    requests = [f for f in flows if f["opcode"] == "1"]
    replies  = [f for f in flows if f["opcode"] == "2"]

    # ── 1. ARP Cache Poisoning: same IP, multiple MACs in replies ──────────
    ip_to_macs: dict[str, set] = defaultdict(set)
    ip_mac_first: dict[tuple, str] = {}

    for f in replies:
        ip  = f["sender_ip"]
        mac = f["sender_mac"] or f["eth_src"]
        if not ip or ip == "0.0.0.0" or not mac:
            continue
        ip_to_macs[ip].add(mac)
        key = (ip, mac)
        if key not in ip_mac_first:
            ip_mac_first[key] = f["timestamp_utc"]

    for ip, macs in ip_to_macs.items():
        if len(macs) >= 2:
            mac_list = sorted(macs)
            results["arp_poisoning"].append({
                "target_ip":     ip,
                "claiming_macs": mac_list,
                "mac_count":     len(mac_list),
                "timestamp_utc": ip_mac_first.get((ip, mac_list[0]), ""),
            })

    # ── 2. Gratuitous ARP: sender_ip == target_ip in replies ──────────────
    grat_count: dict[str, int]  = defaultdict(int)
    grat_first: dict[str, str]  = {}
    grat_last:  dict[str, str]  = {}

    for f in replies:
        if f["sender_ip"] and f["sender_ip"] == f["target_ip"]:
            mac = f["sender_mac"] or f["eth_src"]
            if not mac:
                continue
            grat_count[mac] += 1
            if mac not in grat_first:
                grat_first[mac] = f["timestamp_utc"]
            grat_last[mac] = f["timestamp_utc"]

    for mac, cnt in grat_count.items():
        if cnt >= GRAT_ARP_THRESHOLD:
            results["gratuitous_arp"].append({
                "src_mac":        mac,
                "grat_arp_count": cnt,
                "first_timestamp": grat_first.get(mac, ""),
                "last_timestamp":  grat_last.get(mac, ""),
                "timestamp_utc":   grat_first.get(mac, ""),
            })

    # ── 3. ARP Flood: high rate ARP requests per source MAC ───────────────
    req_count: dict[str, int] = defaultdict(int)
    req_first: dict[str, str] = {}
    req_last:  dict[str, str] = {}

    for f in requests:
        mac = f["sender_mac"] or f["eth_src"]
        if not mac:
            continue
        req_count[mac] += 1
        if mac not in req_first:
            req_first[mac] = f["timestamp_utc"]
        req_last[mac] = f["timestamp_utc"]

    for mac, cnt in req_count.items():
        if cnt >= ARP_FLOOD_THRESHOLD:
            results["arp_flood"].append({
                "src_mac":       mac,
                "request_count": cnt,
                "first_timestamp": req_first.get(mac, ""),
                "last_timestamp":  req_last.get(mac, ""),
                "timestamp_utc":   req_first.get(mac, ""),
            })

    # ── 4. ARP Scan: single MAC targeting many distinct IPs ───────────────
    src_targets: dict[str, set] = defaultdict(set)
    scan_first:  dict[str, str] = {}
    scan_last:   dict[str, str] = {}

    for f in requests:
        mac = f["sender_mac"] or f["eth_src"]
        tip = f["target_ip"]
        if not mac or not tip or tip == "0.0.0.0":
            continue
        src_targets[mac].add(tip)
        if mac not in scan_first:
            scan_first[mac] = f["timestamp_utc"]
        scan_last[mac] = f["timestamp_utc"]

    for mac, targets in src_targets.items():
        if len(targets) >= ARP_SCAN_THRESHOLD:
            results["arp_scan"].append({
                "src_mac":        mac,
                "unique_targets": len(targets),
                "first_timestamp": scan_first.get(mac, ""),
                "last_timestamp":  scan_last.get(mac, ""),
                "timestamp_utc":   scan_first.get(mac, ""),
            })

    # ── 5. ARP Proxy anomaly: eth.src != arp.src.hw_mac in replies ────────
    proxy_seen: dict[str, dict] = {}

    for f in replies:
        eth  = f["eth_src"]
        arph = f["sender_mac"]
        if eth and arph and eth != arph:
            key = (eth, arph, f["sender_ip"])
            if key not in proxy_seen:
                proxy_seen[key] = {
                    "eth_src_mac":    eth,
                    "arp_sender_mac": arph,
                    "sender_ip":      f["sender_ip"],
                    "timestamp_utc":  f["timestamp_utc"],
                }

    results["arp_proxy_anomaly"] = list(proxy_seen.values())

    return results, flows


# ── Output writers ────────────────────────────────────────────────────────────

def write_json(results: dict, flows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
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
    if total == 0:
        highest = "info"
    else:
        triggered = [CATEGORIES[k]["severity"] for k, v in results.items() if v]
        highest = min(triggered, key=lambda s: sev_order[s]) if triggered else "info"

    lines: list[str] = [
        "# ARP Threat Analysis Report",
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
            # Render top-10
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


# ── Vault integration (optional) ──────────────────────────────────────────────

def _write_vault(results: dict, stem: str, case_id: str | None) -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp, open_case  # noqa: F401
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


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="ARP threat detector for PCAP files.")
    ap.add_argument("pcap", type=Path, help="Path to PCAP file")
    ap.add_argument("--stem",       default=None, help="Output stem (default: pcap filename stem)")
    ap.add_argument("--case-id",    default=None, dest="case_id")
    ap.add_argument("--output-dir", default=None, dest="output_dir", type=Path)
    ap.add_argument("--no-vault",   action="store_true", dest="no_vault")
    args = ap.parse_args()

    pcap = args.pcap
    if not pcap.exists():
        sys.exit(f"[ERROR] PCAP not found: {pcap}")

    stem     = args.stem or pcap.stem
    out_dir  = args.output_dir or (ANALYSIS_DIR / OUTPUT_SUBDIR / stem)
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"[*] Analysing ARP traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] ARP packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "arp_threats.json"
    csv_path    = out_dir / "arp_flows.csv"
    report_path = out_dir / "arp_threats_report.md"

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
