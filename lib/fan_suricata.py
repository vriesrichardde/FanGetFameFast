# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_suricata.py — Analyze a PCAP with Suricata IDS.

Runs Suricata in offline mode (-r <pcap>) using rules from ./rules/suricata/.
rules/suricata/suricata.rules is a copy of /var/lib/suricata/rules/suricata.rules,
refreshed by ./scripts/update_suricata_rules.sh (runs sudo suricata-update then copies).

Outputs (./analysis/suricata/<stem>/):
  suricata_alerts.json  — alert summary + per-alert records
  suricata_alerts.csv   — flat CSV
  suricata_report.md    — human-readable Markdown report
  eve.json              — raw Suricata EVE JSON (preserved for re-analysis)
  suricata.yaml         — generated offline config (debugging reference)

Install Suricata:
  sudo add-apt-repository ppa:oisf/suricata-stable
  sudo apt-get install suricata

Update rules:
  ./scripts/update_suricata_rules.sh   (runs: sudo suricata-update)
"""
from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT  = Path(__file__).parent.parent
ANALYSIS_DIR  = PROJECT_ROOT / "analysis"
RULES_DIR     = PROJECT_ROOT / "rules" / "suricata"
OUTPUT_SUBDIR = "suricata"

# Suricata severity: 1 = highest (critical), 4 = lowest
_SEV_MAP = {1: "critical", 2: "high", 3: "medium", 4: "low"}

# Map common Suricata alert categories to MITRE ATT&CK technique IDs
_CATEGORY_MITRE: dict[str, str] = {
    "a network trojan was detected":           "T1071",
    "malware command and control activity":    "T1071",
    "command and control":                     "T1071",
    "c2":                                      "T1071",
    "attempted denial of service":             "T1498",
    "denial of service":                       "T1498",
    "web application attack":                  "T1190",
    "attempted administrator privilege gain":  "T1068",
    "attempted user privilege gain":           "T1068",
    "exploit kit activity detected":           "T1189",
    "credential theft":                        "T1003",
    "trojan activity":                         "T1204",
    "policy violation":                        "T1562",
    "network scan":                            "T1046",
    "port scan":                               "T1046",
    "attempted information leak":              "T1590",
    "information leak":                        "T1590",
    "potentially bad traffic":                 "T1071",
    "successful administrator privilege gain": "T1068",
    "successful user privilege gain":          "T1068",
    "ransomware":                              "T1486",
    "lateral movement":                        "T1021",
}


# ── Config generation ─────────────────────────────────────────────────────────

def _suricata_config(rules_dir: Path, log_dir: Path) -> str:
    rule_files = sorted(rules_dir.glob("*.rules")) if rules_dir.exists() else []
    if not rule_files:
        rule_list = "  - local.rules"
    else:
        rule_list = "\n".join(f"  - {p.name}" for p in rule_files)

    classification = Path("/etc/suricata/classification.config")
    reference      = Path("/etc/suricata/reference.config")
    cls_line = f"classification-file: {classification}" if classification.exists() else ""
    ref_line = f"reference-config-file: {reference}"   if reference.exists()       else ""

    return textwrap.dedent(f"""
        %YAML 1.1
        ---
        vars:
          address-groups:
            HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1/32]"
            EXTERNAL_NET: "!$HOME_NET"
            HTTP_SERVERS: "$HOME_NET"
            SMTP_SERVERS: "$HOME_NET"
            SQL_SERVERS:  "$HOME_NET"
            DNS_SERVERS:  "$HOME_NET"
          port-groups:
            HTTP_PORTS:      "80"
            SHELLCODE_PORTS: "!80"
            ORACLE_PORTS:    1521
            SSH_PORTS:       22
            FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
            FTP_PORTS:       21

        default-log-dir: {log_dir}

        outputs:
          - eve-log:
              enabled: yes
              filetype: regular
              filename: eve.json
              types:
                - alert:
                    payload: yes
                    payload-printable: yes
                    metadata: yes
                - http:
                    extended: yes
                - dns
                - tls:
                    extended: yes
                - flow

        app-layer:
          protocols:
            tls:   {{enabled: yes}}
            http:  {{enabled: yes}}
            ftp:   {{enabled: yes}}
            smtp:  {{enabled: yes}}
            dns:   {{enabled: yes}}
            smb:   {{enabled: yes}}
            ssh:   {{enabled: yes}}
            http2: {{enabled: yes}}

        default-rule-path: {rules_dir}

        rule-files:
        {rule_list}

        {cls_line}
        {ref_line}

        logging:
          default-log-level: notice
          outputs:
            - console:
                enabled: no
            - file:
                enabled: yes
                level: notice
                filename: suricata.log
    """).lstrip()


# ── Suricata execution ────────────────────────────────────────────────────────

def run_suricata(pcap: Path, output_dir: Path) -> Path | None:
    """Run Suricata offline. Returns path to eve.json or None."""
    if not shutil.which("suricata"):
        print(
            "[suricata] 'suricata' not found in PATH.\n"
            "[suricata] Install: sudo add-apt-repository ppa:oisf/suricata-stable && sudo apt install suricata\n"
            "[suricata] Update rules: ./scripts/update_suricata_rules.sh",
            file=sys.stderr,
        )
        return None

    if not RULES_DIR.exists():
        RULES_DIR.mkdir(parents=True)

    cfg_path = output_dir / "suricata.yaml"
    cfg_path.write_text(_suricata_config(RULES_DIR, output_dir), encoding="utf-8")

    cmd = [
        "suricata",
        "-r", str(pcap),
        "-l", str(output_dir),
        "-c", str(cfg_path),
        "--runmode", "single",
        "-q",
    ]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        # Exit 239 = "no alerts" on some builds — treat as success
        if result.returncode not in (0, 239):
            print(f"[suricata] Exit code {result.returncode}", file=sys.stderr)
            if result.stderr:
                print(result.stderr[:800], file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[suricata] Timed out after 300 s", file=sys.stderr)
        return None
    except Exception as exc:
        print(f"[suricata] Execution error: {exc}", file=sys.stderr)
        return None

    eve = output_dir / "eve.json"
    return eve if eve.exists() else None


# ── EVE JSON parsing ──────────────────────────────────────────────────────────

def parse_alerts(eve_path: Path) -> list[dict]:
    alerts: list[dict] = []
    try:
        text = eve_path.read_text(encoding="utf-8", errors="replace")
    except Exception as exc:
        print(f"[suricata] Cannot read {eve_path}: {exc}", file=sys.stderr)
        return alerts

    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            evt = json.loads(line)
        except json.JSONDecodeError:
            continue
        if evt.get("event_type") != "alert":
            continue

        alert   = evt.get("alert", {})
        sev_num = int(alert.get("severity", 3))
        sev     = _SEV_MAP.get(sev_num, "medium")

        alerts.append({
            "timestamp_utc":      evt.get("timestamp", ""),
            "src_ip":             evt.get("src_ip", ""),
            "src_port":           str(evt.get("src_port", "")),
            "dest_ip":            evt.get("dest_ip", ""),
            "dest_port":          str(evt.get("dest_port", "")),
            "proto":              evt.get("proto", ""),
            "signature_id":       str(alert.get("signature_id", "")),
            "signature":          alert.get("signature", ""),
            "category":           alert.get("category", ""),
            "severity":           sev,
            "action":             alert.get("action", ""),
            "rev":                str(alert.get("rev", "")),
            "payload_printable":  (evt.get("payload_printable") or "")[:200],
        })

    return alerts


# ── Output writers ────────────────────────────────────────────────────────────

def _write_json(alerts: list[dict], output_dir: Path, stem: str, pcap: Path) -> None:
    critical = sum(1 for a in alerts if a["severity"] == "critical")
    high     = sum(1 for a in alerts if a["severity"] == "high")
    medium   = sum(1 for a in alerts if a["severity"] == "medium")
    low      = sum(1 for a in alerts if a["severity"] == "low")
    doc = {
        "generated_utc":  datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "pcap":           str(pcap),
        "stem":           stem,
        "total_alerts":   len(alerts),
        "critical_count": critical,
        "high_count":     high,
        "medium_count":   medium,
        "low_count":      low,
        "alerts":         alerts,
    }
    (output_dir / "suricata_alerts.json").write_text(
        json.dumps(doc, indent=2), encoding="utf-8"
    )


def _write_csv(alerts: list[dict], output_dir: Path) -> None:
    fields = [
        "timestamp_utc", "src_ip", "src_port", "dest_ip", "dest_port", "proto",
        "signature_id", "signature", "category", "severity", "action", "rev",
        "payload_printable",
    ]
    with (output_dir / "suricata_alerts.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        w.writeheader()
        w.writerows(alerts)


def _write_report(alerts: list[dict], output_dir: Path, stem: str, pcap: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines: list[str] = [
        f"# Suricata IDS Report — {stem}",
        "",
        f"**PCAP:** `{pcap}`  ",
        f"**Generated:** {now}  ",
        f"**Total alerts:** {len(alerts)}  ",
        "",
    ]

    if not alerts:
        lines += ["No Suricata alerts detected in this capture.", "", "---", ""]
        (output_dir / "suricata_report.md").write_text("\n".join(lines), encoding="utf-8")
        return

    sev_counts: dict[str, int] = {}
    for a in alerts:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1

    lines += ["## Summary", ""]
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev in sev_counts:
            lines.append(f"| {sev.upper()} | {sev_counts[sev]} |")
    lines.append("")

    # Top signatures
    sig_counts: dict[str, int] = {}
    sig_to_cat:  dict[str, str] = {}
    sig_to_sev:  dict[str, str] = {}
    for a in alerts:
        sig = a["signature"]
        sig_counts[sig] = sig_counts.get(sig, 0) + 1
        sig_to_cat[sig] = a["category"]
        # Keep highest severity seen for this signature
        cur = sig_to_sev.get(sig, "info")
        cmp_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        if cmp_map.get(a["severity"], 4) < cmp_map.get(cur, 4):
            sig_to_sev[sig] = a["severity"]

    top_sigs = sorted(sig_counts.items(), key=lambda x: -x[1])[:20]
    lines += ["## Top Signatures", ""]
    lines.append("| Count | Severity | Signature | Category |")
    lines.append("|-------|----------|-----------|----------|")
    for sig, cnt in top_sigs:
        sev = sig_to_sev.get(sig, "info").upper()
        cat = sig_to_cat.get(sig, "")
        lines.append(f"| {cnt} | {sev} | {sig} | {cat} |")
    lines.append("")

    # Alert detail — top 50 sorted by severity then timestamp
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    sorted_alerts = sorted(
        alerts,
        key=lambda a: (sev_order.get(a["severity"], 4), a["timestamp_utc"]),
    )
    lines += ["## Alert Details (top 50)", ""]
    lines.append("| Timestamp | Src → Dst | Proto | Severity | Signature |")
    lines.append("|-----------|-----------|-------|----------|-----------|")
    for a in sorted_alerts[:50]:
        ts   = (a["timestamp_utc"] or "")[:19]
        flow = f"{a['src_ip']}:{a['src_port']} → {a['dest_ip']}:{a['dest_port']}"
        lines.append(
            f"| {ts} | {flow} | {a['proto']} | {a['severity'].upper()} | {a['signature']} |"
        )
    lines += ["", "---", ""]

    (output_dir / "suricata_report.md").write_text("\n".join(lines), encoding="utf-8")


def _write_vault(alerts: list[dict], stem: str, case_id: str) -> None:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from knowledge_extractor import record_ioc
    except ImportError:
        return

    seen_ips: set[str] = set()
    for a in alerts:
        if a["severity"] not in ("critical", "high"):
            continue
        for ip in (a.get("src_ip", ""), a.get("dest_ip", "")):
            if ip and ip not in seen_ips:
                seen_ips.add(ip)
                ctx = (
                    f"Suricata alert in {stem}: {a['signature']} "
                    f"(category: {a['category']})"
                )
                try:
                    record_ioc("ip", ip, ctx, case_id, severity=a["severity"])
                except Exception:
                    pass


# ── Public API ────────────────────────────────────────────────────────────────

def analyze(
    pcap: Path,
    stem: str,
    output_dir: Path,
    case_id: str = "",
    no_vault: bool = False,
) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[suricata] Running Suricata on {pcap.name} …")
    eve_path = run_suricata(pcap, output_dir)

    alerts: list[dict] = []
    if eve_path:
        alerts = parse_alerts(eve_path)
        print(f"[suricata] {len(alerts)} alert(s) found")
    else:
        print("[suricata] No EVE output — Suricata unavailable or no alerts", file=sys.stderr)

    _write_json(alerts, output_dir, stem, pcap)
    _write_csv(alerts, output_dir)
    _write_report(alerts, output_dir, stem, pcap)

    if not no_vault and case_id and alerts:
        _write_vault(alerts, stem, case_id)

    print(f"[suricata] Output: {output_dir}")
    return {"total": len(alerts), "alerts": alerts}


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Suricata offline PCAP analyzer")
    p.add_argument("pcap",         help="Path to PCAP file")
    p.add_argument("--stem",       help="Output stem (default: PCAP basename)")
    p.add_argument("--case-id",    default="", metavar="ID")
    p.add_argument("--output-dir", metavar="DIR")
    p.add_argument("--no-vault",   action="store_true")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    pcap = Path(args.pcap).resolve()
    stem = args.stem or pcap.stem
    odir = Path(args.output_dir) if args.output_dir else (ANALYSIS_DIR / OUTPUT_SUBDIR / stem)
    analyze(pcap, stem, odir, case_id=args.case_id, no_vault=args.no_vault)
