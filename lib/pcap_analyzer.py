# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
IR PCAP Analyzer — extracts netflow data, unique IPs, and unique FQDNs from a PCAP file.

Requires: tshark (Wireshark 4.x) on PATH.

Outputs written to ./analysis/pcap/<pcap_stem>/:
  netflow.csv         — per-flow conversation stats (src/dst/port/proto/packets/bytes/times)
  unique_ips.txt      — deduplicated IPv4 and IPv6 addresses, one per line
  unique_fqdns.txt    — deduplicated FQDNs from DNS queries, HTTP Host headers, TLS SNI

CLI:
  python3 lib/pcap_analyzer.py <pcap_file> [--output-dir <dir>] [--case-id <id>]
  python3 lib/pcap_analyzer.py capture.pcap
  python3 lib/pcap_analyzer.py ~/evidence/traffic.pcapng --case-id CASE-2025-001
"""

from __future__ import annotations

import argparse
import csv
import re
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROTO_MAP = {
    "1": "ICMP", "2": "IGMP", "6": "TCP", "17": "UDP",
    "47": "GRE", "50": "ESP", "51": "AH", "58": "ICMPv6",
    "89": "OSPF", "132": "SCTP",
}

# ---------------------------------------------------------------------------
# tshark helpers
# ---------------------------------------------------------------------------

def _tshark(*args: str, pcap: Path) -> tuple[list[str], str]:
    """Run tshark and return (stdout_lines, stderr). Raises on missing binary."""
    cmd = ["tshark", "-r", str(pcap)] + list(args)
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except FileNotFoundError:
        print("[pcap_analyzer] ERROR: tshark not found on PATH.", file=sys.stderr)
        sys.exit(1)
    lines = [l for l in result.stdout.splitlines() if l.strip()]
    return lines, result.stderr


def _fields(pcap: Path, fields: list[str], display_filter: str = "") -> list[list[str]]:
    """
    Run tshark in field-extraction mode.
    Returns a list of rows; each row is a list of field values (tab-separated).
    Empty/missing field values appear as empty strings.
    """
    args = ["-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=\t", "-E", "occurrence=f", "-E", "quote=n"]
    if display_filter:
        args += ["-Y", display_filter]
    lines, stderr = _tshark(*args, pcap=pcap)
    if stderr and "Err" in stderr:
        print(f"[pcap_analyzer] tshark warning: {stderr[:200]}", file=sys.stderr)
    rows = []
    for line in lines:
        parts = line.split("\t")
        # Pad to expected number of columns
        while len(parts) < len(fields):
            parts.append("")
        rows.append(parts)
    return rows


def _utc(epoch_str: str) -> str:
    try:
        return datetime.fromtimestamp(float(epoch_str), tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.%f"
        )[:-3] + "Z"
    except (ValueError, TypeError, OSError):
        return ""


# ---------------------------------------------------------------------------
# Extraction functions
# ---------------------------------------------------------------------------

def extract_netflow(pcap: Path, output_dir: Path) -> tuple[Path, int]:
    """
    Aggregate per-packet data into per-flow conversation records.

    A flow is keyed by (src_ip, dst_ip, src_port, dst_port, protocol).
    Both IPv4 and IPv6 are captured.

    Output: netflow.csv
    """
    # Fetch fields for every IP/IPv6 packet
    rows = _fields(
        pcap,
        fields=[
            "frame.time_epoch",
            "ip.src", "ip.dst", "ip.proto",
            "ipv6.src", "ipv6.dst",
            "tcp.srcport", "tcp.dstport",
            "udp.srcport", "udp.dstport",
            "frame.len",
        ],
        display_filter="ip or ipv6",
    )

    # flow_key -> {packets, bytes, first_ts, last_ts}
    flows: dict[tuple, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "first_ts": None, "last_ts": None})

    for row in rows:
        (ts, ip4_src, ip4_dst, proto_num,
         ip6_src, ip6_dst,
         tcp_sport, tcp_dport,
         udp_sport, udp_dport,
         frame_len) = row[:11]

        src_ip = ip4_src or ip6_src
        dst_ip = ip4_dst or ip6_dst
        if not src_ip or not dst_ip:
            continue

        proto = PROTO_MAP.get(proto_num, f"IP/{proto_num}" if proto_num else "?")
        if proto_num == "6":
            src_port, dst_port = tcp_sport, tcp_dport
        elif proto_num == "17":
            src_port, dst_port = udp_sport, udp_dport
        else:
            src_port, dst_port = "", ""

        try:
            ts_f = float(ts)
            pkt_bytes = int(frame_len) if frame_len else 0
        except (ValueError, TypeError):
            continue

        key = (src_ip, dst_ip, src_port, dst_port, proto)
        f = flows[key]
        f["packets"] += 1
        f["bytes"] += pkt_bytes
        f["first_ts"] = ts_f if f["first_ts"] is None else min(f["first_ts"], ts_f)
        f["last_ts"] = ts_f if f["last_ts"] is None else max(f["last_ts"], ts_f)

    out = output_dir / "netflow.csv"
    with out.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=[
            "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
            "packets", "bytes",
            "first_seen_utc", "last_seen_utc", "duration_sec",
        ])
        w.writeheader()
        for (src_ip, dst_ip, src_port, dst_port, proto), f in sorted(flows.items()):
            dur = round(f["last_ts"] - f["first_ts"], 3) if f["first_ts"] and f["last_ts"] else 0.0
            w.writerow({
                "src_ip": src_ip,
                "src_port": src_port,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "protocol": proto,
                "packets": f["packets"],
                "bytes": f["bytes"],
                "first_seen_utc": _utc(str(f["first_ts"])),
                "last_seen_utc": _utc(str(f["last_ts"])),
                "duration_sec": dur,
            })

    return out, len(flows)


def extract_unique_ips(pcap: Path, output_dir: Path) -> tuple[Path, int]:
    """
    Collect every unique IPv4 and IPv6 address seen as source or destination.

    Output: unique_ips.txt  (one address per line, sorted)
    """
    ip4_rows = _fields(pcap, ["ip.src", "ip.dst"], display_filter="ip")
    ip6_rows = _fields(pcap, ["ipv6.src", "ipv6.dst"], display_filter="ipv6")

    seen: set[str] = set()
    for row in ip4_rows + ip6_rows:
        for val in row:
            val = val.strip()
            if val:
                seen.add(val)

    sorted_ips = sorted(seen, key=lambda a: (
        # Sort: IPv4 first (no colon), then IPv6
        ":" in a,
        # Numeric sort for IPv4
        tuple(int(x) for x in a.split(".")) if "." in a and ":" not in a else (0,),
        a,
    ))

    out = output_dir / "unique_ips.txt"
    out.write_text("\n".join(sorted_ips) + ("\n" if sorted_ips else ""), encoding="utf-8")
    return out, len(sorted_ips)


def extract_unique_fqdns(pcap: Path, output_dir: Path) -> tuple[Path, int]:
    """
    Collect unique FQDNs from three sources:
      1. DNS queries  (dns.qry.name)
      2. HTTP Host headers  (http.host — strips port suffix)
      3. TLS Client Hello SNI  (tls.handshake.extensions_server_name)

    Output: unique_fqdns.txt  (one FQDN per line, sorted, with source annotation)
    """
    sources: dict[str, set[str]] = {"dns": set(), "http": set(), "tls_sni": set()}

    # 1. DNS query names (both queries and responses carry qry.name)
    dns_rows = _fields(pcap, ["dns.qry.name"], display_filter="dns")
    for row in dns_rows:
        val = row[0].strip().rstrip(".")
        if val and not val.startswith(("_", "wpad")):
            sources["dns"].add(val.lower())

    # 2. HTTP Host header
    http_rows = _fields(pcap, ["http.host"], display_filter="http")
    for row in http_rows:
        val = row[0].strip()
        # Strip port (host:port form)
        val = re.sub(r":\d+$", "", val).lower()
        if val and "." in val:
            sources["http"].add(val)

    # 3. TLS SNI (Client Hello extension)
    tls_rows = _fields(
        pcap,
        ["tls.handshake.extensions_server_name"],
        display_filter="tls.handshake.type == 1",
    )
    for row in tls_rows:
        val = row[0].strip().lower()
        if val and "." in val:
            sources["tls_sni"].add(val)

    # Reverse-DNS infrastructure suffixes — never threat indicators
    _ARPA_SUFFIXES = (".in-addr.arpa", ".ip6.arpa")

    # Merge with source tracking, dropping reverse-DNS arpa entries
    fqdn_sources: dict[str, set[str]] = {}
    for src, fqdns in sources.items():
        for fqdn in fqdns:
            if any(fqdn.endswith(s) for s in _ARPA_SUFFIXES):
                continue
            fqdn_sources.setdefault(fqdn, set()).add(src)

    out = output_dir / "unique_fqdns.txt"
    lines = []
    for fqdn in sorted(fqdn_sources):
        src_label = ",".join(sorted(fqdn_sources[fqdn]))
        lines.append(f"{fqdn}\t[{src_label}]")

    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out, len(fqdn_sources)


# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------

def write_report(
    pcap: Path,
    output_dir: Path,
    netflow_count: int,
    ip_count: int,
    fqdn_count: int,
    case_id: str,
) -> Path:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    lines = [
        "# IR PCAP Analysis Report",
        "",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| PCAP file | `{pcap.name}` |",
        f"| Case ID | {case_id or '—'} |",
        f"| Analysed | {now} |",
        f"| Unique flows | {netflow_count:,} |",
        f"| Unique IPs | {ip_count:,} |",
        f"| Unique FQDNs | {fqdn_count:,} |",
        "",
        "## Output Files",
        "",
        f"| File | Contents |",
        f"|------|----------|",
        f"| `netflow.csv` | Per-flow conversation stats (src/dst/port/proto/packets/bytes) |",
        f"| `unique_ips.txt` | All unique IPv4 and IPv6 addresses |",
        f"| `unique_fqdns.txt` | All unique FQDNs with source (dns/http/tls_sni) |",
        "",
        "## Next Steps",
        "",
        "- Run IOC lookups on `unique_ips.txt` via `./scripts/vault_context.sh ioc <ip>` or `./scripts/perplexity_search.sh ioc <ip>`",
        "- Run FQDN lookups on `unique_fqdns.txt` for threat intel",
        "- Import `netflow.csv` into Timeline Explorer or grep for suspicious ports/patterns",
        "- Record confirmed malicious IPs/FQDNs to the vault with `record_ioc()`",
    ]
    out = output_dir / "report.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="IR PCAP Analyzer — netflow, unique IPs, unique FQDNs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/pcap_analyzer.py capture.pcap\n"
            "  python3 lib/pcap_analyzer.py ~/evidence/traffic.pcapng --case-id CASE-2025-001\n"
            "  python3 lib/pcap_analyzer.py capture.pcap --output-dir ./analysis/pcap/custom/\n"
        ),
    )
    p.add_argument("pcap", metavar="<pcap_file>", help="Path to PCAP or PCAPng file")
    p.add_argument(
        "--output-dir", metavar="DIR",
        help="Output directory (default: ./analysis/pcap/<pcap_stem>/)",
    )
    p.add_argument("--case-id", metavar="ID", default="", help="Case identifier for the report")
    return p


def main(pcap_path: Path, output_dir: Path | None = None, case_id: str = "") -> None:
    if not pcap_path.exists():
        print(f"[pcap_analyzer] ERROR: file not found: {pcap_path}", file=sys.stderr)
        sys.exit(1)

    if output_dir is None:
        base = Path(__file__).parent.parent / "analysis" / "pcap"
        output_dir = base / pcap_path.stem

    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"[pcap_analyzer] Input : {pcap_path}")
    print(f"[pcap_analyzer] Output: {output_dir}")
    print()

    print("[pcap_analyzer] Extracting netflow data ...", end=" ", flush=True)
    netflow_path, flow_count = extract_netflow(pcap_path, output_dir)
    print(f"{flow_count:,} flows → {netflow_path.name}")

    print("[pcap_analyzer] Extracting unique IPs   ...", end=" ", flush=True)
    ip_path, ip_count = extract_unique_ips(pcap_path, output_dir)
    print(f"{ip_count:,} addresses → {ip_path.name}")

    print("[pcap_analyzer] Extracting unique FQDNs ...", end=" ", flush=True)
    fqdn_path, fqdn_count = extract_unique_fqdns(pcap_path, output_dir)
    print(f"{fqdn_count:,} FQDNs → {fqdn_path.name}")

    report_path = write_report(pcap_path, output_dir, flow_count, ip_count, fqdn_count, case_id)
    print(f"\n[pcap_analyzer] Report : {report_path}")
    print(f"[pcap_analyzer] Done.")


if __name__ == "__main__":
    args = _build_parser().parse_args()
    out = Path(args.output_dir) if args.output_dir else None
    main(Path(args.pcap), output_dir=out, case_id=args.case_id)
