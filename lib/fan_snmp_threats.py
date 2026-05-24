#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_snmp_threats.py — SNMP threat detector.

Extracts SNMP traffic from a PCAP and runs six detection categories:
  - Default Credentials          (T1078 / T1110.001)
  - Man-in-the-Middle            (T1557)
  - Denial of Service            (T1498.001)
  - Reconnaissance & Mapping     (T1046)
  - Malicious Configuration      (T1565.001)
  - Malware Deployment           (T1105)

Usage:
  python3 fan_snmp_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "default_credentials": {
        "label": "SNMP Default Credentials",
        "severity": "high",
        "mitre": ["T1078", "T1110.001"],
        "mitre_names": ["Valid Accounts", "Brute Force: Password Spraying"],
        "tactic": "Initial Access / Credential Access",
        "description": (
            "SNMP traffic observed using well-known default community strings "
            "(public, private). These defaults grant unauthenticated read or "
            "read-write access to managed devices."
        ),
    },
    "mitm_snmp": {
        "label": "SNMP Man-in-the-Middle",
        "severity": "critical",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection / Credential Access",
        "description": (
            "SNMP GetResponse packets observed from source IPs that were never "
            "recipients of a corresponding GetRequest. This pattern indicates "
            "traffic interception or relay by a third party."
        ),
    },
    "snmp_flood": {
        "label": "SNMP Denial of Service",
        "severity": "high",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "Abnormally high rate of SNMP packets from a single source IP, "
            "saturating managed-device CPU cycles and potentially causing "
            "agent unavailability or network congestion."
        ),
    },
    "snmp_recon": {
        "label": "SNMP Reconnaissance & Mapping",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "Single source IP queried a large number of distinct SNMP targets, "
            "indicating network topology mapping or device enumeration via "
            "systematic SNMP walks (GetNext/GetBulk)."
        ),
    },
    "config_manipulation": {
        "label": "Malicious Configuration Change (SNMP SET)",
        "severity": "critical",
        "mitre": ["T1565.001"],
        "mitre_names": ["Data Manipulation: Stored Data Manipulation"],
        "tactic": "Impact",
        "description": (
            "SNMP SetRequest operations observed, enabling modification of device "
            "configurations such as routing tables, ACLs, SNMP trap destinations, "
            "or community strings."
        ),
    },
    "large_data_transfer": {
        "label": "SNMP Malware / Data Transfer",
        "severity": "high",
        "mitre": ["T1105"],
        "mitre_names": ["Ingress Tool Transfer"],
        "tactic": "Command and Control",
        "description": (
            "Anomalously large SNMP frames observed, potentially indicating "
            "firmware uploads, configuration replacement, or payload delivery "
            "via SNMP SET OctetString operations."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
SNMP_FLOOD_THRESHOLD   = 200   # SNMP packets per src IP to flag as flood
SNMP_SCAN_THRESHOLD    = 15    # Distinct target IPs per src to flag as recon
SNMP_LARGE_THRESHOLD   = 1400  # Frame bytes to flag as large data transfer
DEFAULT_COMMUNITIES    = {"public", "private", ""}

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "snmp_threats"


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
        "frame.len",
        "ip.src",
        "ip.dst",
        "udp.srcport",
        "udp.dstport",
        "snmp.version",
        "snmp.community",
    ]
    rows = _run_tshark(pcap, fields, "snmp")

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
            "snmp_version":  r[7].strip(),
            "community":     r[8].strip(),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    # ── 1. Default credentials ────────────────────────────────────────────
    cred_seen: dict[tuple, str] = {}
    for f in flows:
        comm = f["community"].lower()
        if comm in DEFAULT_COMMUNITIES:
            key = (f["src_ip"], comm)
            if key not in cred_seen:
                cred_seen[key] = f["timestamp_utc"]

    for (src_ip, comm), ts in cred_seen.items():
        results["default_credentials"].append({
            "src_ip":        src_ip,
            "community":     comm if comm else "(empty)",
            "timestamp_utc": ts,
        })

    # ── 2. MitM: responses from IPs never targeted as request destinations ──
    request_dests: set[str] = set()
    for f in flows:
        if f["dst_port"] == "161":
            request_dests.add(f["dst_ip"])

    mitm_seen: dict[str, str] = {}
    for f in flows:
        if f["src_port"] == "161" and f["src_ip"] and f["src_ip"] not in request_dests:
            if f["src_ip"] not in mitm_seen:
                mitm_seen[f["src_ip"]] = f["timestamp_utc"]

    for ip, ts in mitm_seen.items():
        results["mitm_snmp"].append({
            "unexpected_responder": ip,
            "timestamp_utc": ts,
        })

    # ── 3. SNMP flood: high packet count per src IP ───────────────────────
    pkt_count: dict[str, int] = defaultdict(int)
    pkt_first: dict[str, str] = {}
    pkt_last:  dict[str, str] = {}

    for f in flows:
        ip = f["src_ip"]
        if not ip:
            continue
        pkt_count[ip] += 1
        if ip not in pkt_first:
            pkt_first[ip] = f["timestamp_utc"]
        pkt_last[ip] = f["timestamp_utc"]

    for ip, cnt in pkt_count.items():
        if cnt >= SNMP_FLOOD_THRESHOLD:
            results["snmp_flood"].append({
                "src_ip":          ip,
                "packet_count":    cnt,
                "first_timestamp": pkt_first.get(ip, ""),
                "last_timestamp":  pkt_last.get(ip, ""),
                "timestamp_utc":   pkt_first.get(ip, ""),
            })

    # ── 4. Reconnaissance: single source targeting many distinct IPs ───────
    src_targets: dict[str, set] = defaultdict(set)
    recon_first: dict[str, str] = {}
    recon_last:  dict[str, str] = {}

    for f in flows:
        if f["dst_port"] == "161":
            ip  = f["src_ip"]
            dst = f["dst_ip"]
            if not ip or not dst:
                continue
            src_targets[ip].add(dst)
            if ip not in recon_first:
                recon_first[ip] = f["timestamp_utc"]
            recon_last[ip] = f["timestamp_utc"]

    for ip, targets in src_targets.items():
        if len(targets) >= SNMP_SCAN_THRESHOLD:
            results["snmp_recon"].append({
                "src_ip":          ip,
                "unique_targets":  len(targets),
                "first_timestamp": recon_first.get(ip, ""),
                "last_timestamp":  recon_last.get(ip, ""),
                "timestamp_utc":   recon_first.get(ip, ""),
            })

    # ── 5. Config manipulation: SNMP SET requests ─────────────────────────
    set_fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst", "snmp.community"]
    set_rows = _run_tshark(pcap, set_fields, "snmp.setrequest")
    set_seen: dict[tuple, str] = {}
    for r in set_rows:
        key = (r[2].strip(), r[3].strip())
        if key not in set_seen:
            set_seen[key] = _ts(r[1])
    for (src_ip, dst_ip), ts in set_seen.items():
        results["config_manipulation"].append({
            "src_ip":        src_ip,
            "target_ip":     dst_ip,
            "timestamp_utc": ts,
        })

    # ── 6. Large data transfers ────────────────────────────────────────────
    large_seen: dict[tuple, dict] = {}
    for f in flows:
        try:
            flen = int(f["frame_len"])
        except (ValueError, TypeError):
            continue
        if flen >= SNMP_LARGE_THRESHOLD:
            key = (f["src_ip"], f["dst_ip"])
            if key not in large_seen:
                large_seen[key] = {
                    "src_ip":        f["src_ip"],
                    "dst_ip":        f["dst_ip"],
                    "frame_len":     flen,
                    "timestamp_utc": f["timestamp_utc"],
                }
            elif flen > large_seen[key]["frame_len"]:
                large_seen[key]["frame_len"] = flen

    results["large_data_transfer"] = list(large_seen.values())

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
        "# SNMP Threat Analysis Report",
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
    ap = argparse.ArgumentParser(description="SNMP threat detector for PCAP files.")
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

    print(f"[*] Analysing SNMP traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] SNMP packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "snmp_threats.json"
    csv_path    = out_dir / "snmp_flows.csv"
    report_path = out_dir / "snmp_threats_report.md"

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
