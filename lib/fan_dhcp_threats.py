#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_dhcp_threats.py — DHCP threat detector.

Extracts DHCP traffic from a PCAP and runs six detection categories:
  - DHCP Starvation Attack         (T1499)
  - Rogue DHCP Server              (T1557)
  - DHCP Spoofing                  (T1557)
  - DHCP Release / Decline Flood   (T1499)
  - Unauthorized DHCP Relay        (T1557)
  - DHCP Message Injection         (T1565.001)

Usage:
  python3 fan_dhcp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "dhcp_starvation": {
        "label": "DHCP Starvation Attack",
        "severity": "critical",
        "mitre": ["T1499"],
        "mitre_names": ["Endpoint Denial of Service"],
        "tactic": "Impact",
        "description": (
            "A large number of DHCP DISCOVER messages were sent from many distinct "
            "client MAC addresses (often spoofed), exhausting the DHCP server's "
            "address pool and preventing legitimate clients from obtaining an IP lease."
        ),
    },
    "rogue_dhcp_server": {
        "label": "Rogue DHCP Server",
        "severity": "critical",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection / Credential Access",
        "description": (
            "DHCP OFFER or ACK messages were observed from multiple distinct source "
            "IP addresses, or from an IP address that has not previously been seen as "
            "an authorised DHCP server, indicating a rogue DHCP server on the network."
        ),
    },
    "dhcp_spoofing": {
        "label": "DHCP Spoofing",
        "severity": "critical",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection / Credential Access",
        "description": (
            "DHCP server responses (OFFER/ACK) were sent from the broadcast address "
            "or from a source inconsistent with the server identifier option (option 54), "
            "suggesting that DHCP responses are being crafted or forged."
        ),
    },
    "dhcp_release_flood": {
        "label": "DHCP Release / Decline Flood",
        "severity": "high",
        "mitre": ["T1499"],
        "mitre_names": ["Endpoint Denial of Service"],
        "tactic": "Impact",
        "description": (
            "An abnormally high volume of DHCP RELEASE or DECLINE messages was observed "
            "in a short time window, potentially forcing clients off the network and "
            "flooding the DHCP server's event log."
        ),
    },
    "dhcp_relay_anomaly": {
        "label": "Unauthorized DHCP Relay",
        "severity": "high",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection",
        "description": (
            "DHCP messages with a non-zero GIADDR (gateway IP address) field were "
            "observed originating from a source not previously identified as a "
            "legitimate DHCP relay agent, indicating possible relay manipulation."
        ),
    },
    "dhcp_injection": {
        "label": "DHCP Message Injection / Option Manipulation",
        "severity": "high",
        "mitre": ["T1565.001"],
        "mitre_names": ["Data Manipulation: Stored Data Manipulation"],
        "tactic": "Impact",
        "description": (
            "DHCP messages containing suspicious option 43 (vendor-specific) or "
            "option 82 (relay agent information) data were detected. These options "
            "can be used to inject malicious configuration or redirect DNS/gateway "
            "settings to attacker-controlled infrastructure."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
STARVATION_MAC_THRESHOLD  = 50    # Unique client MACs sending DISCOVER to flag
RELEASE_FLOOD_THRESHOLD   = 100   # RELEASE/DECLINE messages to flag as flood
ROGUE_SERVER_THRESHOLD    = 2     # Distinct server IPs sending OFFER/ACK to flag

# DHCP message types (bootp.option.dhcp / dhcp.option.dhcp)
DHCP_DISCOVER = "1"
DHCP_OFFER    = "2"
DHCP_REQUEST  = "3"
DHCP_DECLINE  = "4"
DHCP_ACK      = "5"
DHCP_NAK      = "6"
DHCP_RELEASE  = "7"
DHCP_INFORM   = "8"

ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "dhcp_threats"


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


def _extract_dhcp(pcap: Path) -> list[dict]:
    """Extract DHCP records — try newer 'dhcp' dissector, fall back to 'bootp'."""
    fields_dhcp = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "dhcp.hw.mac_addr",
        "dhcp.option.dhcp",
        "dhcp.ip.your",
        "dhcp.option.server_id",
        "dhcp.ip.relay",
        "dhcp.option.vendor_class_id",
        "dhcp.option.relay_agent_flags",
        "frame.len",
    ]
    fields_bootp = [
        "frame.number",
        "frame.time_epoch",
        "ip.src",
        "ip.dst",
        "bootp.hw.mac_addr",
        "bootp.option.dhcp",
        "bootp.ip.your",
        "bootp.option.server_id",
        "bootp.ip.relay",
        "bootp.option.vendor_class_id",
        "bootp.option.relay_agent_flags",
        "frame.len",
    ]

    def parse_rows(rows: list[list[str]]) -> list[dict]:
        result = []
        for r in rows:
            result.append({
                "frame_no":        r[0],
                "timestamp_utc":   _ts(r[1]),
                "src_ip":          r[2].strip(),
                "dst_ip":          r[3].strip(),
                "client_mac":      r[4].lower().strip(),
                "msg_type":        r[5].strip(),
                "your_ip":         r[6].strip(),
                "server_id":       r[7].strip(),
                "relay_ip":        r[8].strip(),
                "vendor_class":    r[9].strip(),
                "relay_flags":     r[10].strip(),
                "frame_len":       r[11].strip(),
            })
        return result

    rows = _run_tshark(pcap, fields_dhcp, "dhcp")
    if rows:
        return parse_rows(rows)
    # Fall back to bootp
    rows = _run_tshark(pcap, fields_bootp, "bootp")
    return parse_rows(rows)


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict[str, list[dict]], list[dict]]:
    """Return (results_by_category, raw_flow_list)."""
    flows = _extract_dhcp(pcap)
    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    discovers = [f for f in flows if f["msg_type"] == DHCP_DISCOVER]
    offers    = [f for f in flows if f["msg_type"] == DHCP_OFFER]
    acks      = [f for f in flows if f["msg_type"] == DHCP_ACK]
    releases  = [f for f in flows if f["msg_type"] in (DHCP_RELEASE, DHCP_DECLINE)]

    # ── 1. DHCP Starvation: many unique MACs sending DISCOVER ─────────────
    discover_macs: set = set()
    starvation_first = ""
    starvation_last  = ""
    for f in discovers:
        mac = f["client_mac"]
        if mac and mac != "00:00:00:00:00:00":
            discover_macs.add(mac)
        if not starvation_first:
            starvation_first = f["timestamp_utc"]
        starvation_last = f["timestamp_utc"]

    if len(discover_macs) >= STARVATION_MAC_THRESHOLD:
        results["dhcp_starvation"].append({
            "unique_client_macs": len(discover_macs),
            "total_discovers":    len(discovers),
            "first_timestamp":    starvation_first,
            "last_timestamp":     starvation_last,
            "timestamp_utc":      starvation_first,
        })

    # ── 2. Rogue DHCP Server: multiple distinct IPs sending OFFER/ACK ─────
    server_ips: set = set()
    server_first: dict[str, str] = {}
    for f in offers + acks:
        ip = f["src_ip"]
        if ip and ip not in ("0.0.0.0", "255.255.255.255"):
            server_ips.add(ip)
            if ip not in server_first:
                server_first[ip] = f["timestamp_utc"]

    if len(server_ips) >= ROGUE_SERVER_THRESHOLD:
        results["rogue_dhcp_server"].append({
            "server_ip_count": len(server_ips),
            "server_ips":      sorted(server_ips),
            "timestamp_utc":   min(server_first.values(), default=""),
        })

    # ── 3. DHCP Spoofing: server_id option ≠ src IP in OFFER/ACK ─────────
    for f in offers + acks:
        src = f["src_ip"]
        sid = f["server_id"]
        if src and sid and sid not in ("", "0.0.0.0") and src != sid:
            results["dhcp_spoofing"].append({
                "src_ip":        src,
                "server_id_opt": sid,
                "dst_ip":        f["dst_ip"],
                "msg_type":      "OFFER" if f["msg_type"] == DHCP_OFFER else "ACK",
                "timestamp_utc": f["timestamp_utc"],
            })

    # ── 4. DHCP Release / Decline Flood ───────────────────────────────────
    release_count: dict[str, int] = defaultdict(int)
    release_first: dict[str, str] = {}
    release_last:  dict[str, str] = {}

    for f in releases:
        src = f["client_mac"] or f["src_ip"]
        if not src:
            continue
        release_count[src] += 1
        if src not in release_first:
            release_first[src] = f["timestamp_utc"]
        release_last[src] = f["timestamp_utc"]

    for src, cnt in release_count.items():
        if cnt >= RELEASE_FLOOD_THRESHOLD:
            results["dhcp_release_flood"].append({
                "src_identifier":  src,
                "message_count":   cnt,
                "first_timestamp": release_first.get(src, ""),
                "last_timestamp":  release_last.get(src, ""),
                "timestamp_utc":   release_first.get(src, ""),
            })

    # ── 5. Unauthorized DHCP Relay: non-zero relay_ip from unexpected src ─
    known_servers = server_ips
    for f in flows:
        relay = f["relay_ip"]
        src   = f["src_ip"]
        if relay and relay not in ("", "0.0.0.0") and src not in known_servers:
            results["dhcp_relay_anomaly"].append({
                "src_ip":        src,
                "relay_ip":      relay,
                "msg_type":      f["msg_type"],
                "client_mac":    f["client_mac"],
                "timestamp_utc": f["timestamp_utc"],
            })

    # ── 6. DHCP Injection: vendor-specific or relay-agent options present ─
    for f in flows:
        vendor = f["vendor_class"]
        relay_flags = f["relay_flags"]
        if vendor or relay_flags:
            results["dhcp_injection"].append({
                "src_ip":        f["src_ip"],
                "client_mac":    f["client_mac"],
                "msg_type":      f["msg_type"],
                "vendor_class":  vendor,
                "relay_flags":   relay_flags,
                "timestamp_utc": f["timestamp_utc"],
            })

    # Deduplicate injection findings by (src_ip, vendor_class)
    seen: set = set()
    deduped = []
    for item in results["dhcp_injection"]:
        key = (item["src_ip"], item["vendor_class"])
        if key not in seen:
            seen.add(key)
            deduped.append(item)
    results["dhcp_injection"] = deduped

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
        "# DHCP Threat Analysis Report",
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
            skip = {"server_ips"}
            cols = [c for c in top[0].keys() if c not in skip]
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
    ap = argparse.ArgumentParser(description="DHCP threat detector for PCAP files.")
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

    print(f"[*] Analysing DHCP traffic in: {pcap}")
    results, flows = analyze(pcap)

    print(f"[*] DHCP messages parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in results.values())}")

    json_path   = out_dir / "dhcp_threats.json"
    csv_path    = out_dir / "dhcp_flows.csv"
    report_path = out_dir / "dhcp_threats_report.md"

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
