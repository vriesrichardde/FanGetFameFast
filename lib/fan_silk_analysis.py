#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
fan_silk_analysis.py — SiLK flow-level threat analysis.

Converts a PCAP to SiLK binary flow records (via yaf + rwipfix2silk), then
runs seven statistical analyses across all flows simultaneously.  This gives a
macro view that tshark-based per-packet modules cannot efficiently produce on
large captures:

  - Top Talkers             (T1048  — Exfiltration Over Alternative Protocol)
  - Network/Port Scanners   (T1046  — Network Service Discovery)
  - Traffic Timeline Bursts (T1071  — Application Layer Protocol)
  - Long-Lived Connections  (T1571  — Non-Standard Port / T1095)
  - Protocol Distribution   (T1095  — Non-Application Layer Protocol)
  - Service Matrix          (T1046  — Network Service Discovery)
  - Bytes-per-Flow Outliers (T1048  — Exfiltration Over Alternative Protocol)

Requires: silk-tools, yaf
  sudo apt install silk-tools yaf       # Debian/Ubuntu / SIFT workstation

Usage:
  python3 fan_silk_analysis.py /path/to/capture.pcap [--stem NAME] [--case-id ID]
                               [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import shutil
import statistics
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# ── Paths ─────────────────────────────────────────────────────────────────────
ANALYSIS_DIR = Path("./analysis")
OUTPUT_SUBDIR = "silk_analysis"

# ── Detection thresholds ──────────────────────────────────────────────────────
LONG_CONNECTION_SEC   = 3600      # connections open ≥ 1 hour → persistent implant flag
SCANNER_UNIQUE_DESTS  = 20        # unique dest-IPs from one source → scan
SCANNER_UNIQUE_PORTS  = 50        # unique dest-ports to one host from one source → vert scan
EXFIL_BYTES_THRESHOLD = 10_000_000   # 10 MB in a single flow → exfil candidate
UNUSUAL_PROTO_FLOWS   = 10        # protocol in < N flows → rare / suspicious
TOP_N                 = 20        # rows to request from rwstats/rwuniq top queries
TIMELINE_SIGMA        = 3.0       # standard deviations above mean → burst flag

# ── Detection categories ──────────────────────────────────────────────────────
CATEGORIES: dict[str, dict] = {
    "top_talkers": {
        "label": "Top Talkers (Volume)",
        "severity": "medium",
        "mitre": ["T1048"],
        "mitre_names": ["Exfiltration Over Alternative Protocol"],
        "tactic": "Exfiltration",
        "description": (
            "The top source→destination IP pairs ranked by total bytes transferred. "
            "Unusually large volumes from an internal host to an external IP may "
            "indicate data exfiltration or an active C2 download channel."
        ),
    },
    "scanners": {
        "label": "Network/Port Scanners",
        "severity": "high",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "Source IPs that contacted an abnormally high number of unique destination "
            "IPs (horizontal scan) or unique destination ports on one host (vertical "
            "port scan), indicating automated network reconnaissance."
        ),
    },
    "timeline_bursts": {
        "label": "Traffic Timeline Bursts",
        "severity": "medium",
        "mitre": ["T1071"],
        "mitre_names": ["Application Layer Protocol"],
        "tactic": "Command and Control",
        "description": (
            "One-minute traffic bins that exceed the mean by more than "
            f"{int(TIMELINE_SIGMA)}σ. Recurring burst windows indicate beaconing "
            "behaviour; isolated spikes may indicate a DDoS episode or bulk transfer."
        ),
    },
    "long_connections": {
        "label": "Long-Lived Connections",
        "severity": "high",
        "mitre": ["T1571", "T1095"],
        "mitre_names": [
            "Non-Standard Port",
            "Non-Application Layer Protocol",
        ],
        "tactic": "Command and Control",
        "description": (
            f"TCP/UDP sessions with a duration exceeding {LONG_CONNECTION_SEC // 3600} "
            "hour(s). Legitimate interactive sessions rarely stay open this long without "
            "activity; persistent open connections are a characteristic of idle C2 "
            "implants and long-running backdoors."
        ),
    },
    "protocol_distribution": {
        "label": "Unusual Protocol Usage",
        "severity": "low",
        "mitre": ["T1095"],
        "mitre_names": ["Non-Application Layer Protocol"],
        "tactic": "Command and Control",
        "description": (
            f"IP protocols observed fewer than {UNUSUAL_PROTO_FLOWS} times in the "
            "capture. Rare protocols (anything other than TCP/UDP/ICMP in typical "
            "enterprise traffic) may indicate protocol tunnelling or covert channels."
        ),
    },
    "service_matrix": {
        "label": "Service Port Distribution",
        "severity": "info",
        "mitre": ["T1046"],
        "mitre_names": ["Network Service Discovery"],
        "tactic": "Discovery",
        "description": (
            "Destination port distribution across all flows. Ports above 49151 "
            "(ephemeral range) appearing as common server ports, or unexpected "
            "well-known ports, highlight unusual service usage."
        ),
    },
    "bytes_per_flow": {
        "label": "Bytes-per-Flow Outliers",
        "severity": "medium",
        "mitre": ["T1048"],
        "mitre_names": ["Exfiltration Over Alternative Protocol"],
        "tactic": "Exfiltration",
        "description": (
            f"Individual flows that transferred more than "
            f"{EXFIL_BYTES_THRESHOLD // 1_000_000} MB. A single large flow to an "
            "external host may indicate a bulk data exfiltration event."
        ),
    },
}

# ── Protocol number → name lookup (IANA) ─────────────────────────────────────
_PROTO_NAMES: dict[int, str] = {
    1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE",
    50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP",
}


def _proto_name(proto: int | str) -> str:
    try:
        return _PROTO_NAMES.get(int(proto), f"proto-{proto}")
    except (ValueError, TypeError):
        return str(proto)


# ── Availability check ────────────────────────────────────────────────────────

def check_silk_available() -> bool:
    return shutil.which("rwfilter") is not None and shutil.which("yaf") is not None


def _unavailable_payload() -> dict:
    return {
        "status": "unavailable",
        "reason": (
            "SiLK tools or yaf not found on PATH. "
            "Install with: sudo apt install silk-tools yaf"
        ),
        "categories": {},
    }


# ── PCAP → SiLK conversion ────────────────────────────────────────────────────

def pcap_to_silk(pcap: Path, output_dir: Path) -> Path | None:
    """Convert PCAP to SiLK binary flow file (.rw) via yaf → rwipfix2silk."""
    ipfix_path = output_dir / f"{pcap.stem}.ipfix"
    silk_path  = output_dir / f"{pcap.stem}.rw"

    # yaf: packet capture → IPFIX
    yaf_cmd = [
        "yaf",
        "--in", str(pcap),
        "--out", str(ipfix_path),
        "--silk",
        "--applabel",
        "--max-payload", "0",
    ]
    result = subprocess.run(yaf_cmd, capture_output=True, text=True)
    if result.returncode != 0 or not ipfix_path.exists():
        # yaf sometimes exits non-zero on PCAP EOF — treat as warning
        if not ipfix_path.exists():
            print(f"[!] yaf failed to produce IPFIX file: {result.stderr.strip()}")
            return None

    # rwipfix2silk: IPFIX → SiLK binary
    silk_cmd = [
        "rwipfix2silk",
        f"--silk-output={silk_path}",
        str(ipfix_path),
    ]
    result = subprocess.run(silk_cmd, capture_output=True, text=True)
    ipfix_path.unlink(missing_ok=True)   # clean up intermediate IPFIX

    if result.returncode != 0 or not silk_path.exists():
        print(f"[!] rwipfix2silk failed: {result.stderr.strip()}")
        return None

    return silk_path


# ── SiLK query helpers ────────────────────────────────────────────────────────

def _run_rwstats(silk_path: Path, fields: str, values: str, count: int = TOP_N) -> list[dict]:
    cmd = [
        "rwstats",
        f"--fields={fields}",
        f"--values={values}",
        f"--count={count}",
        "--top",
        "--no-titles",
        "--delimited=,",
        str(silk_path),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    field_names = [f.strip() for f in fields.split(",")]
    value_names = [v.strip() for v in values.split(",")]
    col_names   = field_names + value_names
    rows = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < len(col_names):
            continue
        rows.append(dict(zip(col_names, [p.strip() for p in parts])))
    return rows


def _run_rwcount(silk_path: Path, bin_size: int = 60) -> list[dict]:
    cmd = [
        "rwcount",
        f"--bin-size={bin_size}",
        "--no-titles",
        "--delimited=,",
        str(silk_path),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    rows = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < 4:
            continue
        rows.append({
            "bin_start_utc": parts[0].strip(),
            "flows":         parts[1].strip(),
            "packets":       parts[2].strip(),
            "bytes":         parts[3].strip(),
        })
    return rows


def _run_rwfilter_cut(silk_path: Path, duration_min: int) -> list[dict]:
    """Return flows with duration ≥ duration_min seconds."""
    cut_fields = "sIP,dIP,sPort,dPort,protocol,bytes,packets,sTime,dur,flags"
    cmd_filter = [
        "rwfilter",
        f"--duration-min={duration_min}",
        "--pass=stdout",
        str(silk_path),
    ]
    cmd_cut = [
        "rwcut",
        f"--fields={cut_fields}",
        "--no-titles",
        "--delimited=,",
    ]
    p_filter = subprocess.Popen(cmd_filter, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    p_cut    = subprocess.Popen(cmd_cut, stdin=p_filter.stdout,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p_filter.stdout:
        p_filter.stdout.close()
    out, _ = p_cut.communicate()
    p_filter.wait()

    col_names = cut_fields.split(",")
    rows = []
    for line in out.decode(errors="replace").strip().splitlines():
        parts = line.split(",")
        if len(parts) < len(col_names):
            continue
        rows.append(dict(zip(col_names, [p.strip() for p in parts])))
    return rows


def _run_rwuniq(silk_path: Path, fields: str, values: str) -> list[dict]:
    cmd = [
        "rwuniq",
        f"--fields={fields}",
        f"--values={values}",
        "--sort-output",
        "--no-titles",
        "--delimited=,",
        str(silk_path),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    field_names = [f.strip() for f in fields.split(",")]
    value_names = [v.strip() for v in values.split(",")]
    col_names   = field_names + value_names
    rows = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < len(col_names):
            continue
        rows.append(dict(zip(col_names, [p.strip() for p in parts])))
    return rows


def _rwcut_all(silk_path: Path, max_rows: int = 5000) -> list[dict]:
    """Export all flows as text (capped) for the CSV output file."""
    cut_fields = "sIP,dIP,sPort,dPort,protocol,bytes,packets,sTime,dur,flags"
    cmd = [
        "rwcut",
        f"--fields={cut_fields}",
        "--no-titles",
        "--delimited=,",
        "--num-recs", str(max_rows),
        str(silk_path),
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return []
    col_names = cut_fields.split(",")
    rows = []
    for line in r.stdout.strip().splitlines():
        parts = line.split(",")
        if len(parts) < len(col_names):
            continue
        rows.append(dict(zip(col_names, [p.strip() for p in parts])))
    return rows


# ── Analysis functions ────────────────────────────────────────────────────────

def analyze_top_talkers(silk_path: Path) -> list[dict]:
    rows = _run_rwstats(silk_path, fields="sIP,dIP", values="bytes,packets,flows")
    findings = []
    for r in rows:
        try:
            b = int(r.get("bytes", 0))
        except ValueError:
            b = 0
        findings.append({
            "src_ip":      r.get("sIP", ""),
            "dst_ip":      r.get("dIP", ""),
            "bytes":       r.get("bytes", ""),
            "packets":     r.get("packets", ""),
            "flows":       r.get("flows", ""),
            "bytes_mb":    f"{b / 1_048_576:.2f}",
            "severity":    "high" if b >= EXFIL_BYTES_THRESHOLD else "medium",
        })
    return findings


def detect_scanners(silk_path: Path) -> list[dict]:
    findings = []

    # Horizontal scan: one source → many distinct destination IPs
    h_rows = _run_rwstats(silk_path, fields="sIP", values="distinct:dIP,flows")
    for r in h_rows:
        try:
            d = int(r.get("distinct:dIP", 0))
        except ValueError:
            d = 0
        if d >= SCANNER_UNIQUE_DESTS:
            findings.append({
                "src_ip":       r.get("sIP", ""),
                "scan_type":    "horizontal",
                "unique_dests": str(d),
                "flows":        r.get("flows", ""),
                "severity":     "critical" if d >= SCANNER_UNIQUE_DESTS * 5 else "high",
            })

    # Vertical scan: one source → many distinct dest-ports on any single host
    v_rows = _run_rwstats(silk_path, fields="sIP,dIP", values="distinct:dPort,flows")
    for r in v_rows:
        try:
            p = int(r.get("distinct:dPort", 0))
        except ValueError:
            p = 0
        if p >= SCANNER_UNIQUE_PORTS:
            findings.append({
                "src_ip":        r.get("sIP", ""),
                "dst_ip":        r.get("dIP", ""),
                "scan_type":     "vertical",
                "unique_ports":  str(p),
                "flows":         r.get("flows", ""),
                "severity":      "high",
            })

    return findings


def analyze_traffic_timeline(silk_path: Path) -> list[dict]:
    bins = _run_rwcount(silk_path, bin_size=60)
    if not bins:
        return []

    try:
        byte_vals = [int(b["bytes"]) for b in bins if b["bytes"].isdigit()]
    except (KeyError, ValueError):
        return []

    if len(byte_vals) < 3:
        return []

    mean  = statistics.mean(byte_vals)
    stdev = statistics.pstdev(byte_vals)
    threshold = mean + TIMELINE_SIGMA * stdev if stdev > 0 else mean * 2

    findings = []
    for b in bins:
        try:
            bval = int(b["bytes"])
        except (ValueError, KeyError):
            continue
        if bval >= threshold:
            findings.append({
                "bin_start_utc": b.get("bin_start_utc", ""),
                "bytes":         b.get("bytes", ""),
                "packets":       b.get("packets", ""),
                "flows":         b.get("flows", ""),
                "bytes_vs_mean": f"{bval / mean:.1f}x" if mean > 0 else "n/a",
                "severity":      "high" if bval >= threshold * 3 else "medium",
            })
    return findings


def detect_long_connections(silk_path: Path) -> list[dict]:
    rows = _run_rwfilter_cut(silk_path, duration_min=LONG_CONNECTION_SEC)
    findings = []
    for r in rows:
        try:
            dur_sec = int(float(r.get("dur", 0)))
        except (ValueError, TypeError):
            dur_sec = 0
        findings.append({
            "src_ip":     r.get("sIP", ""),
            "dst_ip":     r.get("dIP", ""),
            "src_port":   r.get("sPort", ""),
            "dst_port":   r.get("dPort", ""),
            "protocol":   _proto_name(r.get("protocol", "")),
            "bytes":      r.get("bytes", ""),
            "packets":    r.get("packets", ""),
            "start_utc":  r.get("sTime", ""),
            "duration_h": f"{dur_sec / 3600:.1f}",
            "flags":      r.get("flags", ""),
            "severity":   "critical" if dur_sec >= LONG_CONNECTION_SEC * 12 else "high",
        })
    return findings


def analyze_protocol_distribution(silk_path: Path) -> list[dict]:
    rows = _run_rwuniq(silk_path, fields="protocol", values="flows,bytes,packets")
    findings = []
    for r in rows:
        try:
            f = int(r.get("flows", 0))
        except ValueError:
            f = 0
        proto_num = r.get("protocol", "")
        name = _proto_name(proto_num)
        is_unusual = f < UNUSUAL_PROTO_FLOWS and name not in ("TCP", "UDP", "ICMP", "ICMPv6")
        findings.append({
            "protocol":       name,
            "protocol_num":   proto_num,
            "flows":          r.get("flows", ""),
            "bytes":          r.get("bytes", ""),
            "packets":        r.get("packets", ""),
            "unusual":        "yes" if is_unusual else "no",
            "severity":       "medium" if is_unusual else "info",
        })
    return findings


def analyze_service_matrix(silk_path: Path) -> list[dict]:
    rows = _run_rwuniq(silk_path, fields="dPort,protocol", values="flows,bytes")
    findings = []
    for r in rows:
        try:
            port = int(r.get("dPort", 0))
        except (ValueError, TypeError):
            port = 0
        try:
            flows = int(r.get("flows", 0))
        except ValueError:
            flows = 0
        unusual = port > 49151 and flows > 5
        findings.append({
            "dst_port":  r.get("dPort", ""),
            "protocol":  _proto_name(r.get("protocol", "")),
            "flows":     r.get("flows", ""),
            "bytes":     r.get("bytes", ""),
            "unusual":   "yes" if unusual else "no",
            "severity":  "medium" if unusual else "info",
        })
    # Return top-50 by flow count (already sorted by rwuniq --sort-output by key)
    return sorted(findings, key=lambda x: int(x["flows"]) if x["flows"].isdigit() else 0,
                  reverse=True)[:50]


def analyze_bytes_per_flow(silk_path: Path) -> list[dict]:
    rows = _run_rwstats(silk_path, fields="sIP,dIP,sPort,dPort,protocol",
                        values="bytes,packets", count=TOP_N)
    findings = []
    for r in rows:
        try:
            b = int(r.get("bytes", 0))
        except ValueError:
            b = 0
        if b >= EXFIL_BYTES_THRESHOLD:
            findings.append({
                "src_ip":   r.get("sIP", ""),
                "dst_ip":   r.get("dIP", ""),
                "src_port": r.get("sPort", ""),
                "dst_port": r.get("dPort", ""),
                "protocol": _proto_name(r.get("protocol", "")),
                "bytes":    r.get("bytes", ""),
                "bytes_mb": f"{b / 1_048_576:.2f}",
                "packets":  r.get("packets", ""),
                "severity": "critical" if b >= EXFIL_BYTES_THRESHOLD * 10 else "high",
            })
    return findings


# ── Orchestrator ──────────────────────────────────────────────────────────────

def analyze(pcap: Path, output_dir: Path) -> tuple[dict, list[dict]]:
    """Run all analyses. Returns (results_by_category, all_flows_for_csv)."""
    if not check_silk_available():
        return _unavailable_payload(), []

    output_dir.mkdir(parents=True, exist_ok=True)
    silk_path = pcap_to_silk(pcap, output_dir)
    if silk_path is None:
        return {
            "status": "conversion_failed",
            "reason": "yaf/rwipfix2silk failed to produce a SiLK flow file.",
            "categories": {},
        }, []

    results = {
        "top_talkers":           analyze_top_talkers(silk_path),
        "scanners":              detect_scanners(silk_path),
        "timeline_bursts":       analyze_traffic_timeline(silk_path),
        "long_connections":      detect_long_connections(silk_path),
        "protocol_distribution": analyze_protocol_distribution(silk_path),
        "service_matrix":        analyze_service_matrix(silk_path),
        "bytes_per_flow":        analyze_bytes_per_flow(silk_path),
    }

    flows = _rwcut_all(silk_path)

    # Remove .rw file — it can be very large and is not preserved
    silk_path.unlink(missing_ok=True)

    return results, flows


# ── Output writers ────────────────────────────────────────────────────────────

def write_json(results: dict, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if results.get("status") in ("unavailable", "conversion_failed"):
        path.write_text(json.dumps(results, indent=2), encoding="utf-8")
        return

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
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(flows: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not flows:
        path.write_text("", encoding="utf-8")
        return
    keys = list(flows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=keys, extrasaction="ignore")
        w.writeheader()
        w.writerows(flows)


def write_report(results: dict, path: Path, pcap: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    if results.get("status") in ("unavailable", "conversion_failed"):
        lines = [
            "# SiLK Flow Analysis Report",
            "",
            f"**Source:** `{pcap}`  ",
            f"**Generated:** {datetime.now(tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            "",
            f"> **SiLK analysis not available:** {results.get('reason', '')}",
            "",
            "Install with: `sudo apt install silk-tools yaf`",
        ]
        path.write_text("\n".join(lines), encoding="utf-8")
        return

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    triggered = [CATEGORIES[k]["severity"] for k, v in results.items() if v]
    highest   = min(triggered, key=lambda s: sev_order.get(s, 4)) if triggered else "info"
    total     = sum(len(v) for v in results.values())

    lines: list[str] = [
        "# SiLK Flow Analysis Report",
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
            meta["description"],
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


def _write_vault(results: dict, stem: str, case_id: str | None) -> None:
    if results.get("status") in ("unavailable", "conversion_failed"):
        return
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp, record_ioc  # noqa: F401

        for cat, items in results.items():
            if not items or cat in ("protocol_distribution", "service_matrix"):
                continue
            meta = CATEGORIES[cat]
            sev  = meta["severity"]
            if sev not in ("critical", "high"):
                continue
            for tid in meta["mitre"]:
                record_ttp(
                    tid,
                    meta["mitre_names"][0],
                    f"{len(items)} instance(s) in PCAP stem '{stem}': {meta['description']}",
                    case_id or stem,
                    tactic=meta["tactic"],
                )
            # Record high-severity external IPs as IOCs
            if cat in ("top_talkers", "bytes_per_flow", "scanners"):
                for item in items[:5]:
                    for field in ("dst_ip", "src_ip"):
                        ip = item.get(field, "")
                        if ip and not ip.startswith(("10.", "172.", "192.")):
                            try:
                                record_ioc(
                                    "ip-address", ip,
                                    f"SiLK flow analysis — {meta['label']} ({case_id or stem})",
                                    case_id or stem,
                                    severity=sev,
                                )
                            except Exception:
                                pass
    except Exception:
        pass


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    ap = argparse.ArgumentParser(description="SiLK flow-level threat analysis for PCAP files.")
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

    if not check_silk_available():
        print("[!] SiLK tools (rwfilter, yaf) not found — writing stub output.")
        stub = _unavailable_payload()
        write_json(stub, out_dir / "silk_analysis.json")
        write_report(stub, out_dir / "silk_analysis_report.md", pcap)
        return

    print(f"[*] SiLK flow analysis: {pcap}")
    results, flows = analyze(pcap, out_dir)

    total = sum(len(v) for v in results.items()
                if isinstance(v, list)) if isinstance(results, dict) else 0
    cats  = results if isinstance(results, dict) else {}
    for cat, items in cats.items():
        if not isinstance(items, list) or not items:
            continue
        meta = CATEGORIES.get(cat, {})
        print(f"    [{meta.get('severity', 'info').upper():8s}] "
              f"{meta.get('label', cat)}: {len(items)} finding(s)")
    print(f"[*] Total findings: {sum(len(v) for v in cats.values() if isinstance(v, list))}")

    json_path   = out_dir / "silk_analysis.json"
    csv_path    = out_dir / "silk_flows.csv"
    report_path = out_dir / "silk_analysis_report.md"

    write_json(results, json_path)
    write_csv(flows, csv_path)
    write_report(results, report_path, pcap)

    if not args.no_vault:
        _write_vault(results, stem, args.case_id)

    print(f"[+] JSON:   {json_path}")
    print(f"[+] CSV:    {csv_path}")
    print(f"[+] Report: {report_path}")


if __name__ == "__main__":
    main()
