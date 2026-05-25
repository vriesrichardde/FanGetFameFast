#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_mdns_threats.py — mDNS (Multicast DNS) threat detector.

Extracts mDNS traffic from a PCAP (UDP port 5353) and runs five detection categories:
  - mDNS Amplification / DrDoS     (T1498.002)
  - mDNS Information Leakage       (T1590)
  - mDNS Spoofing                  (T1557)
  - mDNS Outside Local Segment     (T1590)
  - mDNS Flood / DoS               (T1498.001)

Usage:
  python3 fan_mdns_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
                               [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ── Detection categories ─────────────────────────────────────────────────────
CATEGORIES: dict[str, dict] = {
    "mdns_amplification": {
        "label": "mDNS Amplification / DrDoS",
        "severity": "high",
        "mitre": ["T1498.002"],
        "mitre_names": ["Network Denial of Service: Reflection Amplification"],
        "tactic": "Impact",
        "description": (
            "Large mDNS responses (> 512 bytes) were observed, potentially being "
            "used as an amplification vector. mDNS is a legitimate local-link protocol "
            "but its large TXT/SRV records can be abused for distributed reflection "
            "attacks when the multicast group is reachable across segments."
        ),
    },
    "mdns_info_leakage": {
        "label": "mDNS Information Leakage",
        "severity": "medium",
        "mitre": ["T1590"],
        "mitre_names": ["Gather Victim Network Information"],
        "tactic": "Reconnaissance",
        "description": (
            "mDNS announcements or responses contain hostnames, service names, or "
            "TXT record data that reveal internal network topology, device models, "
            "software versions, or user names — information useful to an attacker "
            "for lateral movement planning."
        ),
    },
    "mdns_spoofing": {
        "label": "mDNS Spoofing / Cache Poisoning",
        "severity": "critical",
        "mitre": ["T1557"],
        "mitre_names": ["Adversary-in-the-Middle"],
        "tactic": "Collection / Credential Access",
        "description": (
            "Conflicting mDNS records were observed: two different IP addresses "
            "announcing the same hostname, or a unicast mDNS response sent to a "
            "specific target rather than the multicast group, consistent with "
            "targeted mDNS cache poisoning."
        ),
    },
    "mdns_outside_local": {
        "label": "mDNS Outside Local Network Segment",
        "severity": "medium",
        "mitre": ["T1590"],
        "mitre_names": ["Gather Victim Network Information"],
        "tactic": "Reconnaissance",
        "description": (
            "mDNS traffic (UDP 5353) was observed from or to a unicast source address "
            "that does not match the standard mDNS multicast group (224.0.0.251 or "
            "ff02::fb). This indicates either router misconfiguration forwarding mDNS "
            "across segments or deliberate reconnaissance using mDNS queries."
        ),
    },
    "mdns_flood": {
        "label": "mDNS Flood / DoS",
        "severity": "high",
        "mitre": ["T1498.001"],
        "mitre_names": ["Network Denial of Service: Direct Network Flood"],
        "tactic": "Impact",
        "description": (
            "A single source IP sent an abnormally high number of mDNS queries or "
            "responses, generating excessive multicast traffic on the local segment "
            "and potentially degrading network performance for all connected hosts."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
AMPLIFICATION_SIZE_BYTES = 512   # mDNS response larger than this flagged
MDNS_FLOOD_THRESHOLD     = 200   # mDNS packets from one source to flag
INFO_LEAKAGE_KEYWORDS    = re.compile(
    r"(admin|root|user|pass|login|ssh|rdp|vnc|smb|share|backup|internal|private|secret|"
    r"dev|staging|prod|localhost|\.local)",
    re.IGNORECASE,
)

MDNS_MULTICAST_V4 = "224.0.0.251"
MDNS_MULTICAST_V6 = "ff02::fb"
MDNS_PORT         = "5353"

ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "mdns_threats"


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
        "dns.flags.response",
        "dns.qry.name",
        "dns.resp.name",
        "dns.a",
        "frame.len",
    ]
    rows = _run_tshark(pcap, fields, "mdns")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":       r[0],
            "timestamp_utc":  _ts(r[1]),
            "src_ip":         r[2].strip(),
            "dst_ip":         r[3].strip(),
            "src_port":       r[4].strip(),
            "dst_port":       r[5].strip(),
            "is_response":    r[6].strip() == "1",
            "query_name":     r[7].strip(),
            "resp_name":      r[8].strip(),
            "answer_ip":      r[9].strip(),
            "frame_len":      _int(r[10]),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    responses = [f for f in flows if f["is_response"]]
    queries   = [f for f in flows if not f["is_response"]]

    # ── 1. mDNS Amplification: large response frames ──────────────────────
    for f in responses:
        if f["frame_len"] > AMPLIFICATION_SIZE_BYTES:
            results["mdns_amplification"].append({
                "src_ip":        f["src_ip"],
                "dst_ip":        f["dst_ip"],
                "resp_name":     f["resp_name"] or f["query_name"],
                "answer_ip":     f["answer_ip"],
                "frame_len":     f["frame_len"],
                "timestamp_utc": f["timestamp_utc"],
            })

    # ── 2. mDNS Information Leakage: sensitive keywords in names ──────────
    seen_leaks: set = set()
    for f in flows:
        name = f["query_name"] or f["resp_name"]
        if not name:
            continue
        if INFO_LEAKAGE_KEYWORDS.search(name):
            key = (f["src_ip"], name)
            if key not in seen_leaks:
                seen_leaks.add(key)
                results["mdns_info_leakage"].append({
                    "src_ip":        f["src_ip"],
                    "name":          name,
                    "is_response":   f["is_response"],
                    "answer_ip":     f["answer_ip"],
                    "timestamp_utc": f["timestamp_utc"],
                })

    # ── 3. mDNS Spoofing: same hostname, different answer IPs ─────────────
    name_to_ips: dict[str, dict[str, str]] = defaultdict(dict)  # name -> {ip: ts}
    for f in responses:
        name = f["resp_name"] or f["query_name"]
        ip   = f["answer_ip"]
        if name and ip:
            name_to_ips[name][ip] = f["timestamp_utc"]

    for name, ip_map in name_to_ips.items():
        if len(ip_map) >= 2:
            results["mdns_spoofing"].append({
                "hostname":      name,
                "conflicting_ips": sorted(ip_map.keys()),
                "ip_count":      len(ip_map),
                "timestamp_utc": min(ip_map.values()),
            })

    # Also flag unicast mDNS responses (dst is not multicast)
    for f in responses:
        dst = f["dst_ip"]
        if dst and dst not in (MDNS_MULTICAST_V4, MDNS_MULTICAST_V6):
            if not dst.startswith("224.") and not dst.startswith("ff"):
                results["mdns_spoofing"].append({
                    "hostname":      f["resp_name"] or f["query_name"],
                    "src_ip":        f["src_ip"],
                    "unicast_target": dst,
                    "answer_ip":     f["answer_ip"],
                    "note":          "Unicast mDNS response (possible targeted spoofing)",
                    "timestamp_utc": f["timestamp_utc"],
                })

    # ── 4. mDNS Outside Local Segment: src not 169.254.x.x/10.x/192.168. ─
    # Flag if mDNS traffic came from a globally routable unicast IP
    def _is_link_local_or_rfc1918(ip: str) -> bool:
        if ip.startswith(("169.254.", "10.", "192.168.", "172.")):
            return True
        if ip.startswith("fe80"):  # IPv6 link-local
            return True
        return False

    seen_outside: set = set()
    for f in flows:
        src = f["src_ip"]
        if src and not _is_link_local_or_rfc1918(src) and src != "0.0.0.0":
            key = src
            if key not in seen_outside:
                seen_outside.add(key)
                results["mdns_outside_local"].append({
                    "src_ip":        src,
                    "dst_ip":        f["dst_ip"],
                    "is_response":   f["is_response"],
                    "name":          f["query_name"] or f["resp_name"],
                    "timestamp_utc": f["timestamp_utc"],
                })

    # ── 5. mDNS Flood: high packet rate from single source ────────────────
    src_count: dict[str, int] = defaultdict(int)
    src_first: dict[str, str] = {}
    src_last:  dict[str, str] = {}

    for f in flows:
        src = f["src_ip"]
        if not src:
            continue
        src_count[src] += 1
        if src not in src_first:
            src_first[src] = f["timestamp_utc"]
        src_last[src] = f["timestamp_utc"]

    for src, cnt in src_count.items():
        if cnt >= MDNS_FLOOD_THRESHOLD:
            results["mdns_flood"].append({
                "src_ip":          src,
                "packet_count":    cnt,
                "first_timestamp": src_first.get(src, ""),
                "last_timestamp":  src_last.get(src, ""),
                "timestamp_utc":   src_first.get(src, ""),
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
        "# mDNS Threat Analysis Report",
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
            skip = {"conflicting_ips"}
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
    ap = argparse.ArgumentParser(description="mDNS threat detector for PCAP files.")
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

    print(f"[*] Analysing mDNS traffic in: {pcap}")
    results, flows = analyze(pcap)

    print(f"[*] mDNS packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in results.values())}")

    json_path   = out_dir / "mdns_threats.json"
    csv_path    = out_dir / "mdns_flows.csv"
    report_path = out_dir / "mdns_threats_report.md"

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
