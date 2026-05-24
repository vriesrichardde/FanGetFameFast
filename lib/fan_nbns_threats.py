#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_nbns_threats.py — NBNS (NetBIOS Name Service) threat detector.

Extracts NBNS traffic from a PCAP and runs six detection categories:
  - Spoofing / Poisoning         (T1557.001)
  - Credential Theft             (T1557.001)
  - SMB Relay Attack             (T1557.001)
  - Network Enumeration          (T1046)
  - Denial of Service            (T1498.001)
  - WPAD Poisoning               (T1557.001)

Usage:
  python3 fan_nbns_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "nbns_spoofing": {
        "label": "NBNS Spoofing / Poisoning",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Collection / Credential Access",
        "description": (
            "Multiple distinct IPs responded to the same NBNS name query, "
            "indicating a rogue host is injecting forged NBNS responses to "
            "redirect victim traffic (e.g., Responder, NBNSpoof)."
        ),
    },
    "credential_theft": {
        "label": "NBNS Credential Theft",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Credential Access",
        "description": (
            "NBNS response observed pointing to an IP that subsequently received "
            "SMB/NTLM authentication traffic from the querying host, indicating "
            "credential harvesting via name poisoning."
        ),
    },
    "smb_relay": {
        "label": "SMB Relay via NBNS",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Lateral Movement / Credential Access",
        "description": (
            "NBNS spoofing detected alongside SMB connections to the spoofing "
            "host, consistent with an NTLM relay attack chain where captured "
            "credentials are forwarded to a legitimate service."
        ),
    },
    "nbns_enumeration": {
        "label": "NBNS Network Enumeration",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "A single source IP issued NBNS queries for an unusually large number "
            "of distinct NetBIOS names, indicating network enumeration or "
            "reconnaissance scanning activity."
        ),
    },
    "nbns_flood": {
        "label": "NBNS Denial of Service",
        "severity": "high",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "Abnormally high rate of NBNS packets from a single source, "
            "potentially overwhelming WINS servers or causing broadcast storms "
            "on the local network segment."
        ),
    },
    "wpad_poisoning": {
        "label": "WPAD Poisoning via NBNS",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Collection / Credential Access",
        "description": (
            "NBNS query or response detected for the 'WPAD' hostname. "
            "Attackers respond to WPAD NBNS queries to redirect browser proxy "
            "auto-discovery to a malicious PAC file, enabling full HTTP MitM."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
NBNS_FLOOD_THRESHOLD = 200   # NBNS packets per src IP to flag as flood
NBNS_ENUM_THRESHOLD  = 20    # Distinct names queried per src to flag as enum

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "nbns_threats"


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
        "ip.src",
        "ip.dst",
        "nbns.name",
        "nbns.flags.response",
    ]
    rows = _run_tshark(pcap, fields, "nbns")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":      r[0],
            "timestamp_utc": _ts(r[1]),
            "src_ip":        r[2].strip(),
            "dst_ip":        r[3].strip(),
            "name":          r[4].strip(),
            "is_response":   r[5].strip(),  # "0"=query "1"=response
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    queries   = [f for f in flows if f["is_response"] == "0"]
    responses = [f for f in flows if f["is_response"] == "1"]

    # ── 1. NBNS Spoofing: multiple IPs respond to same name query ─────────
    name_responders: dict[str, set] = defaultdict(set)
    name_first: dict[str, str] = {}

    for f in responses:
        name = f["name"].upper()
        if not name:
            continue
        name_responders[name].add(f["src_ip"])
        if name not in name_first:
            name_first[name] = f["timestamp_utc"]

    for name, responders in name_responders.items():
        if len(responders) >= 2:
            results["nbns_spoofing"].append({
                "queried_name":   name,
                "responding_ips": sorted(responders),
                "responder_count": len(responders),
                "timestamp_utc":  name_first.get(name, ""),
            })

    # ── 2. Credential theft: build spoofed-IP set; SMB check is heuristic ─
    spoofed_ips: set[str] = set()
    for f in responses:
        name = f["name"].upper()
        if name in name_responders and len(name_responders[name]) >= 2:
            spoofed_ips.add(f["src_ip"])

    # Pull SMB traffic to see if victims connected to spoofed IPs
    smb_fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"]
    smb_rows   = _run_tshark(pcap, smb_fields, "smb || smb2")
    smb_dests: set[str] = {r[3].strip() for r in smb_rows if len(r) == 4}

    for ip in spoofed_ips:
        if ip in smb_dests:
            results["credential_theft"].append({
                "spoofing_ip":    ip,
                "threat":         "SMB authentication to spoofed IP detected",
                "timestamp_utc":  name_first.get(
                    next((n for n, rs in name_responders.items() if ip in rs), ""), ""
                ),
            })

    # ── 3. SMB Relay: spoofed IP is also SMB destination ─────────────────
    relay_smb_sources: set[str] = {r[2].strip() for r in smb_rows if len(r) == 4}
    for ip in spoofed_ips:
        if ip in smb_dests and ip in relay_smb_sources:
            results["smb_relay"].append({
                "relay_ip":      ip,
                "indicator":     "Received SMB auth from victim AND initiated SMB to target",
                "timestamp_utc": "",
            })

    # ── 4. Enumeration: many distinct names queried by one source ─────────
    src_names:  dict[str, set] = defaultdict(set)
    enum_first: dict[str, str] = {}
    enum_last:  dict[str, str] = {}

    for f in queries:
        src  = f["src_ip"]
        name = f["name"]
        if not src or not name:
            continue
        src_names[src].add(name)
        if src not in enum_first:
            enum_first[src] = f["timestamp_utc"]
        enum_last[src] = f["timestamp_utc"]

    for src, names in src_names.items():
        if len(names) >= NBNS_ENUM_THRESHOLD:
            results["nbns_enumeration"].append({
                "src_ip":           src,
                "unique_names":     len(names),
                "first_timestamp":  enum_first.get(src, ""),
                "last_timestamp":   enum_last.get(src, ""),
                "timestamp_utc":    enum_first.get(src, ""),
            })

    # ── 5. Flood: high packet count per src IP ────────────────────────────
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
        if cnt >= NBNS_FLOOD_THRESHOLD:
            results["nbns_flood"].append({
                "src_ip":          ip,
                "packet_count":    cnt,
                "first_timestamp": pkt_first.get(ip, ""),
                "last_timestamp":  pkt_last.get(ip, ""),
                "timestamp_utc":   pkt_first.get(ip, ""),
            })

    # ── 6. WPAD poisoning: NBNS query/response for WPAD ──────────────────
    wpad_seen: dict[str, str] = {}
    for f in flows:
        if "WPAD" in f["name"].upper():
            key = f["src_ip"]
            if key not in wpad_seen:
                wpad_seen[key] = f["timestamp_utc"]

    for ip, ts in wpad_seen.items():
        role = "responder" if any(
            f["src_ip"] == ip and f["is_response"] == "1" for f in flows
        ) else "querier"
        results["wpad_poisoning"].append({
            "ip":            ip,
            "role":          role,
            "timestamp_utc": ts,
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
        "# NBNS Threat Analysis Report",
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
    ap = argparse.ArgumentParser(description="NBNS threat detector for PCAP files.")
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

    print(f"[*] Analysing NBNS traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] NBNS packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "nbns_threats.json"
    csv_path    = out_dir / "nbns_flows.csv"
    report_path = out_dir / "nbns_threats_report.md"

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
