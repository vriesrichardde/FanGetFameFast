#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_ssdp_threats.py — SSDP / UPnP threat detector.

Extracts SSDP traffic from a PCAP and runs four detection categories:
  - Amplification / Reflection DDoS    (T1498.002)
  - Unauthorized Device Exposure       (T1590)
  - Local Network Manipulation         (T1557)
  - Vulnerable UPnP Implementations    (T1203)

Usage:
  python3 fan_ssdp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "ssdp_amplification": {
        "label": "SSDP Amplification / Reflection DDoS",
        "severity": "high",
        "mitre": ["T1498.002"],
        "mitre_names": ["Network Denial of Service: Reflection Amplification"],
        "tactic": "Impact",
        "description": (
            "SSDP M-SEARCH requests observed originating from non-RFC1918 "
            "or external unicast sources targeting the UPnP multicast address, "
            "or large NOTIFY/response packets directed at unicast IPs with no "
            "matching M-SEARCH, indicating SSDP reflection amplification abuse."
        ),
    },
    "device_exposure": {
        "label": "Unauthorized Device Exposure",
        "severity": "high",
        "mitre": ["T1590"],
        "mitre_names": ["Gather Victim Network Information"],
        "tactic": "Reconnaissance",
        "description": (
            "SSDP NOTIFY or M-SEARCH response advertising device capabilities "
            "from an unexpected source, or LOCATION field referencing an external "
            "URL, exposing internal device profiles to potential attackers."
        ),
    },
    "network_manipulation": {
        "label": "SSDP Local Network Manipulation",
        "severity": "high",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection",
        "description": (
            "SSDP SUBSCRIBE or UNSUBSCRIBE messages observed from unexpected "
            "hosts, or duplicate NOTIFY messages from multiple sources claiming "
            "the same USN, indicating UPnP event subscription hijacking or "
            "device impersonation."
        ),
    },
    "vulnerable_upnp": {
        "label": "Vulnerable UPnP Implementation",
        "severity": "medium",
        "mitre": ["T1203"],
        "mitre_names": ["Exploitation for Client Execution"],
        "tactic": "Initial Access",
        "description": (
            "UPnP/SSDP traffic from devices advertising known vulnerable "
            "implementations (Portable UPnP SDK, MiniUPnP, or devices with "
            "LOCATION pointing to non-RFC1918 addresses, indicating misconfig "
            "that may allow external UPnP exploitation)."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
SSDP_FLOOD_THRESHOLD = 100   # M-SEARCH packets per src IP to flag as flood

# ── Vulnerable signatures in USN/Server/Location fields ───────────────────────
VULNERABLE_SIGNATURES = [
    "portable sdk", "miniupnp", "upnp/1.0", "linux/2.4", "linux/2.6",
    "dlna", "redsonic", "airties",
]

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "ssdp_threats"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(epoch: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        ) + "Z"
    except (ValueError, TypeError):
        return epoch or ""


def _is_rfc1918(ip: str) -> bool:
    try:
        parts = [int(x) for x in ip.split(".")]
        if len(parts) != 4:
            return False
        return (
            parts[0] == 10
            or (parts[0] == 172 and 16 <= parts[1] <= 31)
            or (parts[0] == 192 and parts[1] == 168)
        )
    except (ValueError, TypeError):
        return False


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


def _parse_ssdp_headers(pcap: Path) -> list[dict]:
    """Extract SSDP header fields via raw HTTP field extraction."""
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "udp.dstport",
        "http.request.method",
        "http.request.line",
    ]
    rows = _run_tshark(pcap, fields, "ssdp")
    results = []
    for r in rows:
        method   = r[6].strip()
        raw_line = r[7].strip().lower()
        results.append({
            "frame_no":      r[0],
            "timestamp_utc": _ts(r[1]),
            "frame_len":     r[2],
            "src_ip":        r[3].strip(),
            "dst_ip":        r[4].strip(),
            "dst_port":      r[5].strip(),
            "method":        method,
            "raw_headers":   raw_line,
            # Extract common SSDP header values from raw_line
            "st":            _extract_header(raw_line, "st:"),
            "nt":            _extract_header(raw_line, "nt:"),
            "nts":           _extract_header(raw_line, "nts:"),
            "location":      _extract_header(raw_line, "location:"),
            "usn":           _extract_header(raw_line, "usn:"),
            "server":        _extract_header(raw_line, "server:"),
        })
    return results


def _extract_header(raw: str, prefix: str) -> str:
    for part in raw.split("\\r\\n"):
        part = part.strip()
        if part.lower().startswith(prefix):
            return part[len(prefix):].strip()
    return ""


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict[str, list[dict]], list[dict]]:
    """Return (results_by_category, raw_flow_list)."""
    packets = _parse_ssdp_headers(pcap)

    flows: list[dict] = []
    for p in packets:
        flows.append({
            "frame_no":      p["frame_no"],
            "timestamp_utc": p["timestamp_utc"],
            "src_ip":        p["src_ip"],
            "dst_ip":        p["dst_ip"],
            "method":        p["method"],
            "st":            p["st"],
            "nt":            p["nt"],
            "location":      p["location"],
            "usn":           p["usn"],
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    msearch  = [p for p in packets if p["method"].upper() == "M-SEARCH"]
    notify   = [p for p in packets if p["method"].upper() == "NOTIFY"]

    # ── 1. Amplification: M-SEARCH from non-local sources ────────────────
    msearch_src_count: dict[str, int] = defaultdict(int)
    msearch_first: dict[str, str] = {}
    msearch_last:  dict[str, str] = {}
    for p in msearch:
        ip = p["src_ip"]
        msearch_src_count[ip] += 1
        if ip not in msearch_first:
            msearch_first[ip] = p["timestamp_utc"]
        msearch_last[ip] = p["timestamp_utc"]

    for ip, cnt in msearch_src_count.items():
        # Treat external or high-rate M-SEARCH as potential amplification setup
        if cnt >= SSDP_FLOOD_THRESHOLD or not _is_rfc1918(ip):
            results["ssdp_amplification"].append({
                "src_ip":          ip,
                "msearch_count":   cnt,
                "source_type":     "external" if not _is_rfc1918(ip) else "internal-flood",
                "first_timestamp": msearch_first.get(ip, ""),
                "last_timestamp":  msearch_last.get(ip, ""),
                "timestamp_utc":   msearch_first.get(ip, ""),
            })

    # ── 2. Device exposure: NOTIFY with external LOCATION URL ─────────────
    for p in notify:
        loc = p["location"]
        if not loc:
            continue
        # Extract IP from location URL
        loc_lower = loc.lower()
        for proto in ("http://", "https://"):
            if loc_lower.startswith(proto):
                rest = loc[len(proto):]
                host = rest.split("/")[0].split(":")[0]
                if host and not _is_rfc1918(host):
                    results["device_exposure"].append({
                        "src_ip":        p["src_ip"],
                        "external_location": loc[:80],
                        "usn":           p["usn"][:60],
                        "timestamp_utc": p["timestamp_utc"],
                    })
                break

    # ── 3. Network manipulation: SUBSCRIBE/UNSUBSCRIBE detection ─────────
    sub_fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"]
    sub_rows   = _run_tshark(pcap, sub_fields, "ssdp")
    # Look for SUBSCRIBE in raw packet (tshark may not expose method for SUBSCRIBE)
    sub2_fields = ["frame.number", "frame.time_epoch", "frame.len",
                   "ip.src", "ip.dst", "http.request.method"]
    sub2_rows  = _run_tshark(pcap, sub2_fields, "ssdp")
    for r in sub2_rows:
        if len(r) < 6:
            continue
        method = r[5].strip().upper()
        if method in ("SUBSCRIBE", "UNSUBSCRIBE"):
            results["network_manipulation"].append({
                "src_ip":        r[3].strip(),
                "dst_ip":        r[4].strip(),
                "method":        method,
                "timestamp_utc": _ts(r[1]),
            })

    # Duplicate NOTIFY USN from multiple IPs (device impersonation)
    usn_notifiers: dict[str, set] = defaultdict(set)
    usn_first: dict[str, str] = {}
    for p in notify:
        usn = p["usn"]
        if not usn:
            continue
        usn_notifiers[usn].add(p["src_ip"])
        if usn not in usn_first:
            usn_first[usn] = p["timestamp_utc"]

    for usn, ips in usn_notifiers.items():
        if len(ips) >= 2:
            results["network_manipulation"].append({
                "usn":             usn[:60],
                "duplicate_ips":   sorted(ips),
                "indicator":       "Same USN announced from multiple IPs",
                "timestamp_utc":   usn_first.get(usn, ""),
            })

    # ── 4. Vulnerable UPnP: known weak signatures ─────────────────────────
    for p in notify + msearch:
        combined = (p["server"] + " " + p["usn"] + " " + p["location"]).lower()
        for sig in VULNERABLE_SIGNATURES:
            if sig in combined:
                results["vulnerable_upnp"].append({
                    "src_ip":        p["src_ip"],
                    "signature":     sig,
                    "server":        p["server"][:60],
                    "usn":           p["usn"][:60],
                    "timestamp_utc": p["timestamp_utc"],
                })
                break

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
        "# SSDP / UPnP Threat Analysis Report",
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
            top  = findings[:10]
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


# ── Vault integration ─────────────────────────────────────────────────────────

def _write_vault(results: dict, stem: str, case_id: str | None) -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp  # noqa: F401
        for cat, items in results.items():
            if not items:
                continue
            meta = CATEGORIES[cat]
            if meta["severity"] not in ("critical", "high"):
                continue
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
    ap = argparse.ArgumentParser(description="SSDP/UPnP threat detector for PCAP files.")
    ap.add_argument("pcap",        type=Path, help="Path to PCAP file")
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

    print(f"[*] Analysing SSDP/UPnP traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] SSDP packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "ssdp_threats.json"
    csv_path    = out_dir / "ssdp_flows.csv"
    report_path = out_dir / "ssdp_threats_report.md"

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
