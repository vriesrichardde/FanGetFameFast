#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_stun_threats.py — STUN (Session Traversal Utilities for NAT) threat detector.

Extracts STUN traffic from a PCAP and runs four detection categories:
  - Reflected / Amplification DDoS  (T1498.002)
  - Information Leakage             (T1590.005)
  - Firewall Traversal / Misconfig  (T1599)
  - Service Abuse                   (T1071)

Usage:
  python3 fan_stun_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "amplification_ddos": {
        "label": "STUN Reflected / Amplification DDoS",
        "severity": "high",
        "mitre": ["T1498.002"],
        "mitre_names": ["Network Denial of Service: Reflection Amplification"],
        "tactic": "Impact",
        "description": (
            "Large STUN Binding Responses directed at IPs that sent no "
            "corresponding Binding Request, indicating reflection amplification "
            "abuse where spoofed-source requests trigger oversized responses "
            "toward victim IPs."
        ),
    },
    "info_leakage": {
        "label": "STUN Information Leakage",
        "severity": "medium",
        "mitre": ["T1590.005"],
        "mitre_names": ["Gather Victim Network Information: Network Topology"],
        "tactic": "Reconnaissance",
        "description": (
            "STUN Binding Responses containing XOR-MAPPED-ADDRESS or MAPPED-ADDRESS "
            "attributes that expose private RFC 1918 addresses, revealing internal "
            "network topology to external observers."
        ),
    },
    "firewall_traversal": {
        "label": "STUN Firewall Traversal / Misconfiguration",
        "severity": "medium",
        "mitre": ["T1599"],
        "mitre_names": ["Network Boundary Bridging"],
        "tactic": "Defense Evasion",
        "description": (
            "STUN traffic observed on non-standard ports (other than 3478/5349), "
            "suggesting deliberate firewall evasion or misconfigured TURN/STUN "
            "relay servers permitting unrestricted traversal."
        ),
    },
    "service_abuse": {
        "label": "STUN Service Abuse",
        "severity": "medium",
        "mitre": ["T1071"],
        "mitre_names": ["Application Layer Protocol"],
        "tactic": "Command and Control",
        "description": (
            "Abnormally high rate of STUN requests from a single source, "
            "indicating automated abuse of STUN servers for NAT mapping discovery, "
            "C2 channel establishment via hole-punching, or resource exhaustion."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
STUN_ABUSE_THRESHOLD   = 100   # STUN requests per src IP to flag as abuse
STUN_AMP_SIZE_RATIO    = 3     # Response/request byte ratio to flag as amplification
STUN_LARGE_RESP        = 200   # Minimum bytes for a response to be flagged
STANDARD_STUN_PORTS    = {3478, 5349, 19302}  # Standard STUN/TURN ports

# ── STUN message type constants ────────────────────────────────────────────────
# STUN type field encodes class (2 bits) and method (12 bits)
STUN_BINDING_REQUEST   = "0x0001"
STUN_BINDING_RESPONSE  = "0x0101"

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "stun_threats"


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


# ── Core analysis ─────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict[str, list[dict]], list[dict]]:
    """Return (results_by_category, raw_flow_list)."""
    fields = [
        "frame.number",
        "frame.time_epoch",
        "frame.len",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "stun.type",
        "stun.length",
    ]
    rows = _run_tshark(pcap, fields, "stun")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":      r[0],
            "timestamp_utc": _ts(r[1]),
            "frame_len":     r[2],
            "src_ip":        r[3].strip(),
            "dst_ip":        r[4].strip(),
            "src_port":      r[5].strip(),
            "dst_port":      r[6].strip(),
            "stun_type":     r[7].strip(),
            "stun_length":   r[8].strip(),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    requests  = [f for f in flows if f["stun_type"] == STUN_BINDING_REQUEST]
    responses = [f for f in flows if f["stun_type"] == STUN_BINDING_RESPONSE]

    # ── 1. Amplification: large responses to IPs with no prior request ─────
    request_sources: set[str] = {f["src_ip"] for f in requests if f["src_ip"]}

    for f in responses:
        try:
            flen = int(f["frame_len"])
        except (ValueError, TypeError):
            flen = 0
        if flen >= STUN_LARGE_RESP and f["dst_ip"] and f["dst_ip"] not in request_sources:
            results["amplification_ddos"].append({
                "reflector_ip":  f["src_ip"],
                "victim_ip":     f["dst_ip"],
                "response_bytes": flen,
                "timestamp_utc": f["timestamp_utc"],
            })

    # ── 2. Info leakage: extract XOR-MAPPED-ADDRESS from responses ─────────
    xmap_fields = [
        "frame.number", "frame.time_epoch", "ip.src", "ip.dst",
        "stun.att.xor-mapped-address.ip",
        "stun.att.mapped-address.ip",
    ]
    xmap_rows = _run_tshark(pcap, xmap_fields, "stun")
    leak_seen: dict[str, str] = {}
    for r in xmap_rows:
        if len(r) < 6:
            continue
        mapped_ip = (r[4] or r[5]).strip()
        if mapped_ip and _is_rfc1918(mapped_ip):
            key = f"{r[2].strip()}->{mapped_ip}"
            if key not in leak_seen:
                leak_seen[key] = _ts(r[1])
                results["info_leakage"].append({
                    "responder_ip":  r[2].strip(),
                    "querier_ip":    r[3].strip(),
                    "mapped_ip":     mapped_ip,
                    "note":          "Private RFC1918 address exposed in STUN response",
                    "timestamp_utc": _ts(r[1]),
                })

    # ── 3. Firewall traversal: non-standard STUN ports ────────────────────
    nonstandard_seen: dict[tuple, str] = {}
    for f in flows:
        for port_field in (f["src_port"], f["dst_port"]):
            try:
                p = int(port_field)
            except (ValueError, TypeError):
                continue
            if p not in STANDARD_STUN_PORTS:
                key = (f["src_ip"], f["dst_ip"], port_field)
                if key not in nonstandard_seen:
                    nonstandard_seen[key] = f["timestamp_utc"]

    for (src, dst, port), ts in nonstandard_seen.items():
        results["firewall_traversal"].append({
            "src_ip":        src,
            "dst_ip":        dst,
            "port":          port,
            "timestamp_utc": ts,
        })

    # ── 4. Service abuse: high request rate per source ────────────────────
    req_count: dict[str, int] = defaultdict(int)
    req_first: dict[str, str] = {}
    req_last:  dict[str, str] = {}

    for f in requests:
        ip = f["src_ip"]
        if not ip:
            continue
        req_count[ip] += 1
        if ip not in req_first:
            req_first[ip] = f["timestamp_utc"]
        req_last[ip] = f["timestamp_utc"]

    for ip, cnt in req_count.items():
        if cnt >= STUN_ABUSE_THRESHOLD:
            results["service_abuse"].append({
                "src_ip":          ip,
                "request_count":   cnt,
                "first_timestamp": req_first.get(ip, ""),
                "last_timestamp":  req_last.get(ip, ""),
                "timestamp_utc":   req_first.get(ip, ""),
            })

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
        "# STUN Threat Analysis Report",
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
    ap = argparse.ArgumentParser(description="STUN threat detector for PCAP files.")
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

    print(f"[*] Analysing STUN traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] STUN packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "stun_threats.json"
    csv_path    = out_dir / "stun_flows.csv"
    report_path = out_dir / "stun_threats_report.md"

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
