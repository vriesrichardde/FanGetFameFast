#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_llmnr_threats.py — LLMNR (Link-Local Multicast Name Resolution) threat detector.

Extracts LLMNR traffic from a PCAP and runs four detection categories:
  - Spoofing / Poisoning         (T1557.001)
  - Credential Theft             (T1557.001)
  - SMB Relay Attack             (T1557.001)
  - Reconnaissance               (T1046)

Usage:
  python3 fan_llmnr_threats.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
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
    "llmnr_spoofing": {
        "label": "LLMNR Spoofing / Poisoning",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Collection / Credential Access",
        "description": (
            "Multiple distinct unicast IPs responded to the same LLMNR multicast "
            "query, indicating a rogue responder tool (e.g., Responder, Inveigh) "
            "is poisoning LLMNR name resolution."
        ),
    },
    "credential_theft": {
        "label": "LLMNR Credential Theft",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Credential Access",
        "description": (
            "LLMNR spoofing detected where the responding IP subsequently received "
            "SMB or HTTP authentication traffic from the querying host, indicating "
            "Net-NTLMv2 hash capture via LLMNR poisoning."
        ),
    },
    "smb_relay": {
        "label": "SMB Relay via LLMNR",
        "severity": "critical",
        "mitre": ["T1557.001"],
        "mitre_names": ["Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning and SMB Relay"],
        "tactic": "Lateral Movement / Credential Access",
        "description": (
            "LLMNR-based spoofing IP detected acting as both SMB authentication "
            "receiver and SMB connection initiator, consistent with an NTLM "
            "relay attack forwarding captured credentials to a target service."
        ),
    },
    "llmnr_recon": {
        "label": "LLMNR Reconnaissance",
        "severity": "medium",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "Single source IP issued LLMNR queries for an unusually large number "
            "of distinct hostnames, indicating network host discovery or "
            "reconnaissance activity."
        ),
    },
}

# ── Thresholds ────────────────────────────────────────────────────────────────
LLMNR_RECON_THRESHOLD = 20   # Distinct names queried per src to flag as recon

# ── Output paths ──────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "llmnr_threats"


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
        "dns.flags.response",  # 0=query 1=response (LLMNR uses DNS format)
        "dns.qry.name",
        "dns.a",
    ]
    rows = _run_tshark(pcap, fields, "llmnr")

    flows: list[dict] = []
    for r in rows:
        flows.append({
            "frame_no":      r[0],
            "timestamp_utc": _ts(r[1]),
            "src_ip":        r[2].strip(),
            "dst_ip":        r[3].strip(),
            "is_response":   r[4].strip(),  # "0"=query "1"=response
            "queried_name":  r[5].strip(),
            "resolved_ip":   r[6].strip(),
        })

    results: dict[str, list[dict]] = {k: [] for k in CATEGORIES}

    queries   = [f for f in flows if f["is_response"] == "0"]
    responses = [f for f in flows if f["is_response"] == "1"]

    # ── 1. LLMNR Spoofing: multiple unicast responses to same name query ───
    # LLMNR queries go to multicast 224.0.0.252; responses are unicast back.
    name_responders: dict[str, set] = defaultdict(set)
    name_first: dict[str, str] = {}

    for f in responses:
        name = f["queried_name"].lower()
        if not name:
            continue
        name_responders[name].add(f["src_ip"])
        if name not in name_first:
            name_first[name] = f["timestamp_utc"]

    for name, responders in name_responders.items():
        if len(responders) >= 2:
            results["llmnr_spoofing"].append({
                "queried_name":    name,
                "responding_ips":  sorted(responders),
                "responder_count": len(responders),
                "timestamp_utc":   name_first.get(name, ""),
            })

    # ── 2. Credential theft: spoofed IP received SMB/HTTP auth from victim ─
    spoofed_ips: set[str] = set()
    for name, responders in name_responders.items():
        if len(responders) >= 2:
            spoofed_ips.update(responders)

    smb_fields = ["frame.number", "frame.time_epoch", "ip.src", "ip.dst"]
    smb_rows   = _run_tshark(pcap, smb_fields, "smb || smb2 || http")
    smb_dests: set[str] = {r[3].strip() for r in smb_rows if len(r) == 4}

    for ip in spoofed_ips:
        if ip in smb_dests:
            results["credential_theft"].append({
                "spoofing_ip":   ip,
                "threat":        "Authentication traffic to LLMNR-spoofed IP detected",
                "timestamp_utc": "",
            })

    # ── 3. SMB Relay: spoofed IP both receives and initiates SMB ──────────
    smb_sources: set[str] = {r[2].strip() for r in smb_rows if len(r) == 4}
    for ip in spoofed_ips:
        if ip in smb_dests and ip in smb_sources:
            results["smb_relay"].append({
                "relay_ip":      ip,
                "indicator":     "Received auth from victim AND forwarded SMB to target",
                "timestamp_utc": "",
            })

    # ── 4. Reconnaissance: many distinct names queried by one source ───────
    src_names:  dict[str, set] = defaultdict(set)
    recon_first: dict[str, str] = {}
    recon_last:  dict[str, str] = {}

    for f in queries:
        src  = f["src_ip"]
        name = f["queried_name"]
        if not src or not name:
            continue
        src_names[src].add(name)
        if src not in recon_first:
            recon_first[src] = f["timestamp_utc"]
        recon_last[src] = f["timestamp_utc"]

    for src, names in src_names.items():
        if len(names) >= LLMNR_RECON_THRESHOLD:
            results["llmnr_recon"].append({
                "src_ip":           src,
                "unique_names":     len(names),
                "first_timestamp":  recon_first.get(src, ""),
                "last_timestamp":   recon_last.get(src, ""),
                "timestamp_utc":    recon_first.get(src, ""),
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
        "# LLMNR Threat Analysis Report",
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
    ap = argparse.ArgumentParser(description="LLMNR threat detector for PCAP files.")
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

    print(f"[*] Analysing LLMNR traffic in: {pcap}")
    results, flows = analyze(pcap)

    total = sum(len(v) for v in results.values())
    print(f"[*] LLMNR packets parsed: {len(flows)}")
    for cat, items in results.items():
        if items:
            print(f"    [{CATEGORIES[cat]['severity'].upper():8s}] "
                  f"{CATEGORIES[cat]['label']}: {len(items)} finding(s)")
    print(f"[*] Total findings: {total}")

    json_path   = out_dir / "llmnr_threats.json"
    csv_path    = out_dir / "llmnr_flows.csv"
    report_path = out_dir / "llmnr_threats_report.md"

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
