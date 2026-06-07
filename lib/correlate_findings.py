#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
correlate_findings.py — Cross-module correlation engine for FanGetFameFast.

Reads raw artifact files produced by FAN, FAME, and FAST and surfaces
kill-chain connections that no single module identifies alone:

  FAN  ↔ FAME  — netscan process matched to flagged PCAP connection
  FAME ↔ FAST  — process image found deleted on disk (T1070.004)
  FAN  ↔ FAST  — DNS-queried domain confirmed by carved disk artifact

Run this step BEFORE cleaning up ./analysis/ so raw artifact files are
still available for precise correlation.

Claude: enhance and elaborate when necessary on every finding.

Usage (CLI):
    python3 lib/correlate_findings.py \\
        --case-id CASE-2026-001 \\
        [--hostname SERVER1234] \\
        [--reports-dir ./reports] \\
        [--analysis-dir ./analysis] \\
        [--exports-dir ./exports] \\
        [--output-dir ./reports]

Python API:
    from lib.correlate_findings import correlate
    result = correlate(case_id="CASE-2026-001", hostname="SERVER1234")
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent

try:
    from hallucination_guard import (
        ConfidenceTier,
        tag_finding,
        render_confidence_summary,
        reset_counter as _hg_reset,
    )
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from hallucination_guard import (
        ConfidenceTier,
        tag_finding,
        render_confidence_summary,
        reset_counter as _hg_reset,
    )


# ── Parsers ────────────────────────────────────────────────────────────────────

def _parse_netscan(path: Path) -> list[dict]:
    """Parse Volatility 3 netscan or netstat output into connection records."""
    rows: list[dict] = []
    if not path.exists():
        return rows

    ip_port_re = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):(\d+)")
    state_words = {
        "ESTABLISHED", "CLOSE_WAIT", "TIME_WAIT", "LISTEN",
        "CLOSED", "SYN_SENT", "SYN_RECV", "FIN_WAIT1", "FIN_WAIT2",
    }

    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith(("Volatility", "Offset", "PID", "#", "---")):
            continue
        ips = ip_port_re.findall(line)
        if len(ips) < 2:
            continue

        parts = line.split()
        pid: int | None = None
        process_name = ""
        proto = ""
        state = ""

        for i, p in enumerate(parts):
            if p.upper() in state_words:
                state = p.upper()
                if i + 1 < len(parts):
                    try:
                        pid = int(parts[i + 1])
                    except ValueError:
                        pass
                if i + 2 < len(parts) and pid is not None:
                    process_name = parts[i + 2]
                break

        for p in parts:
            if p.upper().startswith(("TCP", "UDP")):
                proto = p.upper()
                break

        local_ip, local_port   = ips[0]
        remote_ip, remote_port = ips[1]

        if remote_ip in ("0.0.0.0", "127.0.0.1", "::1"):
            continue

        try:
            rows.append({
                "pid":          pid,
                "process_name": process_name,
                "proto":        proto,
                "state":        state,
                "local_ip":     local_ip,
                "local_port":   int(local_port),
                "remote_ip":    remote_ip,
                "remote_port":  int(remote_port),
            })
        except ValueError:
            continue

    return rows


def _parse_pslist(path: Path) -> dict[int, str]:
    """Return pid → process_name mapping from pslist output."""
    mapping: dict[int, str] = {}
    if not path.exists():
        return mapping
    for line in path.read_text(errors="replace").splitlines():
        if not line or line.startswith(("Volatility", "PID", "---", "#")):
            continue
        parts = line.split()
        if len(parts) >= 3:
            try:
                mapping[int(parts[0])] = parts[2]
            except (ValueError, IndexError):
                pass
    return mapping


def _parse_cmdline(path: Path) -> dict[int, str]:
    """Return pid → command_line mapping from cmdline output."""
    mapping: dict[int, str] = {}
    if not path.exists():
        return mapping
    pid_re = re.compile(r"^\s*(\d+)\s+\S+\s+(.+)$")
    for line in path.read_text(errors="replace").splitlines():
        m = pid_re.match(line)
        if m:
            try:
                mapping[int(m.group(1))] = m.group(2).strip()
            except ValueError:
                pass
    return mapping


def _parse_fls(path: Path) -> tuple[list[str], list[str]]:
    """Return (active_paths, deleted_paths) from TSK fls output."""
    active: list[str] = []
    deleted: list[str] = []
    if not path.exists():
        return active, deleted
    for line in path.read_text(errors="replace").splitlines():
        is_deleted = line.startswith("* ")
        m = re.search(r":\s+(.+)$", line)
        if m:
            p = m.group(1).strip()
            (deleted if is_deleted else active).append(p)
    return active, deleted


def _parse_bulk_urls(carved_dir: Path) -> list[dict]:
    """Return URL/domain records from bulk_extractor output directory."""
    results: list[dict] = []
    if not carved_dir.exists():
        return results
    for fname in ("url.txt", "domain.txt"):
        f = carved_dir / fname
        if not f.exists():
            continue
        for line in f.read_text(errors="replace").splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split("\t", 1)
            raw = parts[-1].strip()
            if not raw or " " in raw:
                continue
            domain = re.sub(r"^https?://", "", raw).split("/")[0].split(":")[0].lower()
            if "." in domain:
                results.append({"url": raw, "domain": domain})
    return results


def _load_fan_json(analysis_dir: Path, module: str) -> list[dict]:
    """Load threat records from a FAN module JSON file."""
    candidates: list[Path] = list(analysis_dir.glob(f"fan_{module}/**/{module}_threats.json"))
    candidates += list(analysis_dir.glob(f"{module}_threats.json"))
    for c in candidates:
        try:
            data = json.loads(c.read_text(errors="replace"))
            if isinstance(data, list):
                return data
            if isinstance(data, dict):
                for key in ("threats", "results", "findings"):
                    if isinstance(data.get(key), list):
                        return data[key]
        except (json.JSONDecodeError, OSError):
            pass
    return []


# ── Field extractors ──────────────────────────────────────────────────────────

def _fan_connections(threats: list[dict]) -> list[dict]:
    """Normalise FAN threat records into (dst_ip, dst_port, threat_type, severity)."""
    out: list[dict] = []
    for t in threats:
        dst_ip = (
            t.get("dst_ip") or t.get("server_ip") or
            t.get("remote_ip") or t.get("ip") or ""
        )
        if not dst_ip or dst_ip in ("0.0.0.0", "255.255.255.255"):
            continue
        try:
            dst_port = int(t.get("dst_port") or t.get("port") or 0)
        except (TypeError, ValueError):
            dst_port = 0
        out.append({
            "src_ip":      t.get("src_ip", ""),
            "dst_ip":      dst_ip,
            "dst_port":    dst_port,
            "threat_type": t.get("threat_type") or t.get("type") or "",
            "severity":    t.get("severity", "medium"),
            "timestamp":   t.get("timestamp") or t.get("time") or "",
        })
    return out


def _dns_domains(threats: list[dict]) -> list[dict]:
    """Extract queried domains from DNS threat records."""
    out: list[dict] = []
    for t in threats:
        for field in ("query", "domain", "qname", "name", "hostname"):
            val = t.get(field, "")
            if val and isinstance(val, str) and "." in val:
                out.append({
                    "domain":      val.lower().rstrip("."),
                    "src_ip":      t.get("src_ip", ""),
                    "threat_type": t.get("threat_type") or t.get("type") or "",
                    "severity":    t.get("severity", ""),
                    "timestamp":   t.get("timestamp") or t.get("time") or "",
                })
                break
    return out


# ── Correlation algorithms ────────────────────────────────────────────────────

def _corr_fan_fame(
    netscan: list[dict],
    fan_conns: list[dict],
    pslist: dict[int, str],
    cmdline: dict[int, str],
) -> list[dict]:
    """
    FAN ↔ FAME: match netscan connections to FAN threat detections by IP:port.
    Confirms which process initiated a flagged network connection.
    """
    matches: list[dict] = []
    seen: set[tuple] = set()

    for row in netscan:
        rip, rport = row["remote_ip"], row["remote_port"]
        pid  = row["pid"] or 0
        proc = row["process_name"] or pslist.get(pid, f"PID:{pid}")

        for fc in fan_conns:
            if fc["dst_ip"] == rip and (fc["dst_port"] == 0 or fc["dst_port"] == rport):
                key = (pid, rip, rport)
                if key not in seen:
                    seen.add(key)
                    matches.append({
                        "correlation_type": "fan_fame_process_network",
                        "process_name":     proc,
                        "pid":              pid,
                        "cmdline":          cmdline.get(pid, ""),
                        "proto":            row["proto"],
                        "remote_ip":        rip,
                        "remote_port":      rport,
                        "threat_type":      fc["threat_type"],
                        "severity":         fc["severity"],
                        "timestamp":        fc["timestamp"],
                    })
                break

    return matches


_SUSPICIOUS_PATH_RE = re.compile(
    r"(?i)(\\Temp\\|/tmp/|\\AppData\\|\\Users\\.*\\Desktop\\|"
    r"\\Windows\\(?!System32|SysWOW64|WinSxS)).*\.exe$"
)


def _corr_fame_fast(
    pslist: dict[int, str],
    cmdline: dict[int, str],
    fls_deleted: list[str],
) -> list[dict]:
    """
    FAME ↔ FAST: match process names to deleted disk entries.
    Flags post-execution cleanup (T1070.004) and suspicious deletions.
    """
    matches: list[dict] = []
    proc_lower: dict[str, tuple[int, str]] = {
        name.lower(): (pid, name) for pid, name in pslist.items()
    }

    for del_path in fls_deleted:
        basename = Path(del_path).name.lower()
        if basename.endswith(".exe") and basename in proc_lower:
            pid, name = proc_lower[basename]
            matches.append({
                "correlation_type": "fame_fast_process_disk",
                "process_name":     name,
                "pid":              pid,
                "cmdline":          cmdline.get(pid, ""),
                "disk_path":        del_path,
                "disk_status":      "DELETED",
                "significance": (
                    f"Process `{name}` (PID {pid}) was running in memory but its "
                    "executable was found deleted on disk — indicates post-execution "
                    "cleanup (T1070.004)."
                ),
            })
        elif _SUSPICIOUS_PATH_RE.search(del_path):
            if not any(m["disk_path"] == del_path for m in matches):
                matches.append({
                    "correlation_type": "fame_fast_suspicious_deletion",
                    "process_name":     "",
                    "pid":              None,
                    "cmdline":          "",
                    "disk_path":        del_path,
                    "disk_status":      "DELETED",
                    "significance": (
                        "Executable deleted from a high-risk path — "
                        "cross-reference with FAME process list (T1070.004)."
                    ),
                })

    return matches


def _corr_fan_fast(
    dns_doms: list[dict],
    carved_urls: list[dict],
) -> list[dict]:
    """
    FAN ↔ FAST: match DNS-queried domains to domains carved from disk.
    Confirms active use and disk-side artifact retention.
    """
    matches: list[dict] = []
    carved_index: dict[str, str] = {
        e["domain"]: e["url"] for e in carved_urls if e.get("domain")
    }

    for entry in dns_doms:
        dom = entry["domain"].lower().rstrip(".")
        url = carved_index.get(dom, "")
        if not url:
            for carved_dom, carved_url in carved_index.items():
                if dom.endswith("." + carved_dom) or carved_dom.endswith("." + dom):
                    url = carved_url
                    break
        if url:
            matches.append({
                "correlation_type":  "fan_fast_domain_url",
                "domain":            dom,
                "carved_url":        url,
                "dns_threat_type":   entry["threat_type"],
                "dns_severity":      entry["severity"],
                "dns_src_ip":        entry["src_ip"],
                "dns_timestamp":     entry["timestamp"],
                "significance": (
                    f"Domain `{dom}` queried in DNS (FAN) and found carved from "
                    "disk (FAST) — confirms active use of this endpoint."
                ),
            })

    return matches


# ── Markdown builder ──────────────────────────────────────────────────────────

def _confidence(n: int, both: bool) -> str:
    if not both:
        return "N/A — module missing"
    if n == 0:
        return "None found"
    if n >= 3:
        return "High"
    if n == 2:
        return "Medium"
    return "Low-Medium — verify manually"


def _build_markdown(
    case_id: str,
    hostname: str,
    generated_utc: str,
    modules_found: list[str],
    artifacts: dict[str, bool],
    ff_matches: list[dict],
    mf_matches: list[dict],
    fd_matches: list[dict],
) -> str:
    lines: list[str] = []
    a = lines.append

    a("# Cross-Module Correlation Analysis")
    a("")
    a("| Field | Value |")
    a("|-------|-------|")
    a(f"| Case ID | `{case_id}` |")
    a(f"| Hostname | `{hostname}` |")
    a(f"| Modules | {', '.join(modules_found) or 'None detected'} |")
    a(f"| Generated (UTC) | {generated_utc} |")
    a(f"| Prepared by | Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin |")
    a("")
    a("> **Claude: enhance and elaborate when necessary** — this document surfaces")
    a("> kill-chain connections that no single module identifies alone.")
    a("> Each match is a confirmed pivot point for further investigation.")
    a("")

    a("## Data sources used")
    a("")
    a("| Artifact | Available |")
    a("|----------|-----------|")
    for name, avail in artifacts.items():
        note = "" if avail else " — correlation partially degraded"
        a(f"| `{name}` | {'Yes' if avail else 'No' + note} |")
    a("")

    total = len(ff_matches) + len(mf_matches) + len(fd_matches)
    has_fan  = "FAN"  in modules_found
    has_fame = "FAME" in modules_found
    has_fast = "FAST" in modules_found

    # ── Executive summary ─────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 1. Executive correlation summary")
    a("")
    a("> Audience: CISO, Legal. No technical identifiers.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    if total == 0:
        a("No cross-domain correlations were computed. Either the raw artifact files")
        a("have already been cleaned up (post-investigation) or there is genuinely")
        a("no overlap between network, memory, and storage findings for this case.")
        a("")
        a("Run this step while `./analysis/` still contains raw Volatility and TSK output.")
    else:
        if ff_matches:
            a(f"- {len(ff_matches)} process(es) in memory were confirmed to have initiated "
              "flagged network connections observed in the PCAP, linking specific running "
              "programs to suspicious traffic.")
        proc_m = [m for m in mf_matches if m["correlation_type"] == "fame_fast_process_disk"]
        del_m  = [m for m in mf_matches if m["correlation_type"] == "fame_fast_suspicious_deletion"]
        if proc_m:
            a(f"- {len(proc_m)} process image(s) found running in memory had their "
              "executable deleted from disk, consistent with post-execution cleanup.")
        if del_m:
            a(f"- {len(del_m)} executable(s) were deleted from high-risk disk paths "
              "and require cross-reference with the memory process list.")
        if fd_matches:
            a(f"- {len(fd_matches)} domain(s) or URL(s) appeared in both DNS query traffic "
              "and carved disk artifacts, confirming the machine actively used these endpoints.")
    a("")

    # ── FAN ↔ FAME ────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 2. FAN ↔ FAME — Process-network correlations")
    a("")
    a("> Netscan connections matched to FAN flagged traffic.")
    a("> Confirms which process initiated a detected suspicious connection.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    if ff_matches:
        a("| Process | PID | Remote IP:Port | Protocol | Threat Type | Severity |")
        a("|---------|-----|----------------|----------|-------------|----------|")
        for m in ff_matches:
            a(f"| `{m['process_name']}` | {m['pid']} "
              f"| `{m['remote_ip']}:{m['remote_port']}` "
              f"| {m['proto']} | {m['threat_type']} | {m['severity'].upper()} |")
        a("")
        procs = sorted({m["process_name"] for m in ff_matches if m["process_name"]})
        a(f"Confirmed processes: `{'`, `'.join(procs)}`. Examine command line arguments "
          "and parent-child relationships (pstree) for each to determine origin.")
        cmds = [(m["process_name"], m["pid"], m["cmdline"]) for m in ff_matches if m.get("cmdline")]
        if cmds:
            a("")
            a("**Command lines:**")
            a("")
            for name, pid, cmd in cmds:
                a(f"- PID {pid} `{name}`: `{cmd}`")
    elif has_fan and has_fame:
        a("No IP:port matches between netscan connections and FAN threat detections.")
        a("Possible causes: activity occurred outside the memory capture window, or")
        a("connections were made by processes not captured in netscan output.")
    else:
        missing = [m for m in ("FAN", "FAME") if m not in modules_found]
        a(f"Requires both FAN and FAME. Missing: {', '.join(missing)}.")
    a("")

    # ── FAME ↔ FAST ───────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 3. FAME ↔ FAST — Process-disk correlations")
    a("")
    a("> Running processes matched to deleted file entries on disk.")
    a("> A match indicates post-execution cleanup (T1070.004) or fileless staging.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    if mf_matches:
        a("| Process | PID | Disk Path | Status | Significance |")
        a("|---------|-----|-----------|--------|--------------|")
        for m in mf_matches:
            pid_s  = str(m["pid"]) if m["pid"] is not None else "—"
            proc_s = f"`{m['process_name']}`" if m["process_name"] else "*(unmatched)*"
            sig    = m["significance"]
            if len(sig) > 90:
                sig = sig[:90].rstrip() + "..."
            a(f"| {proc_s} | {pid_s} | `{m['disk_path']}` | **{m['disk_status']}** | {sig} |")
        a("")
        a("MITRE ATT&CK: T1070.004 — Indicator Removal: File Deletion")
        a("")
        a("Verify execution order using USN Journal and Prefetch timestamps. "
          "Check Amcache for SHA1 hashes of the deleted binaries.")
    elif has_fame and has_fast:
        a("No process image paths found deleted on disk. Either the attacker did not")
        a("clean up, or the executables reside in standard system paths.")
    else:
        missing = [m for m in ("FAME", "FAST") if m not in modules_found]
        a(f"Requires both FAME and FAST. Missing: {', '.join(missing)}.")
    a("")

    # ── FAN ↔ FAST ────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 4. FAN ↔ FAST — Domain-URL correlations")
    a("")
    a("> DNS-queried domains matched to domains/URLs carved from disk.")
    a("> Confirms the machine actively used and retained artifacts from these endpoints.")
    a("> Claude: enhance and elaborate when necessary.")
    a("")
    if fd_matches:
        a("| Domain | Carved Artifact | DNS Threat Type | Severity | DNS Source IP |")
        a("|--------|-----------------|-----------------|----------|---------------|")
        for m in fd_matches:
            carved = m["carved_url"]
            if len(carved) > 55:
                carved = carved[:55] + "..."
            a(f"| `{m['domain']}` | `{carved}` | {m['dns_threat_type']} "
              f"| {m['dns_severity'].upper()} | `{m['dns_src_ip']}` |")
        a("")
        a("Extract the full carved artifact and cross-reference with browser history "
          "and Prefetch to determine whether contact was user-initiated or automated.")
    elif has_fan and has_fast:
        a("No domain overlap between DNS queries and carved disk artifacts.")
        a("Possible causes: C2 used direct-IP communication (no DNS), or")
        a("bulk_extractor did not recover URL/domain features.")
    else:
        missing = [m for m in ("FAN", "FAST") if m not in modules_found]
        a(f"Requires both FAN and FAST. Missing: {', '.join(missing)}.")
    a("")

    # ── Confidence table ──────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 5. Confidence assessment")
    a("")
    a("| Correlation | Matches | Confidence | Evidence |")
    a("|-------------|---------|------------|----------|")
    a(f"| FAN ↔ FAME (process-network) | {len(ff_matches)} | "
      f"{_confidence(len(ff_matches), has_fan and has_fame)} | "
      f"{'netscan + FAN threat JSON' if (has_fan and has_fame) else 'N/A'} |")
    a(f"| FAME ↔ FAST (process-disk) | {len(mf_matches)} | "
      f"{_confidence(len(mf_matches), has_fame and has_fast)} | "
      f"{'pslist + fls deleted entries' if (has_fame and has_fast) else 'N/A'} |")
    a(f"| FAN ↔ FAST (domain-URL) | {len(fd_matches)} | "
      f"{_confidence(len(fd_matches), has_fan and has_fast)} | "
      f"{'DNS threats + bulk_extractor' if (has_fan and has_fast) else 'N/A'} |")
    a("")

    # ── Next pivots ───────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 6. Recommended next pivots")
    a("")
    a("> Claude: enhance and elaborate when necessary — prioritise by severity.")
    a("")
    pivots: list[str] = []

    if ff_matches:
        high = [m for m in ff_matches if m["severity"].lower() in ("high", "critical")]
        if high:
            procs = sorted({m["process_name"] for m in high})
            pivots.append(
                f"[HIGH] Dump and analyse memory for `{'`, `'.join(procs)}` via malfind/procdump "
                "— these processes initiated HIGH/CRITICAL-severity flagged connections."
            )
        pivots.append(
            "[MEDIUM] Inspect parent-child tree (pstree) for each matched process — "
            "unexpected lineage (e.g., Word → cmd.exe) confirms injection or macro execution."
        )

    if mf_matches:
        pivots.append(
            "[HIGH] Extract USN Journal and Prefetch timestamps for each deleted executable "
            "to confirm execution preceded deletion, establishing attacker cleanup sequence."
        )
        pivots.append(
            "[MEDIUM] Query Amcache for SHA1 hashes of deleted binaries — "
            "confirms execution even when the file no longer exists on disk."
        )

    if fd_matches:
        high_dns = [m for m in fd_matches if m["dns_severity"].lower() in ("high", "critical")]
        if high_dns:
            doms = sorted({m["domain"] for m in high_dns})
            pivots.append(
                f"[HIGH] Enrich `{'`, `'.join(doms)}` against OpenCTI and Perplexity — "
                "confirmed in both network and disk evidence, warrants immediate CTI lookup."
            )
        pivots.append(
            "[MEDIUM] Extract browser history for matched domains from carved artifacts "
            "to distinguish user-initiated (phishing) from automated (C2 beacon) contact."
        )

    if not pivots:
        a("No high-priority pivots identified — either no correlations found or")
        a("all three modules have not yet been run for this case.")
    else:
        for i, p in enumerate(pivots, 1):
            a(f"{i}. {p}")
    a("")

    a("---")
    a("")
    a("*Correlation analysis complete. All correlations derived from raw artifact files.*")
    a("*Evidence integrity preserved — no evidence directories were modified.*")
    a("")

    # ── Hallucination Guard ───────────────────────────────────────────────────
    hg = _build_correlation_hallucination_guard(
        ff_matches, mf_matches, fd_matches, modules_found,
    )
    if hg:
        a(hg)
        a("")

    return "\n".join(lines)


def _build_correlation_hallucination_guard(
    ff_matches: list[dict],
    mf_matches: list[dict],
    fd_matches: list[dict],
    modules_found: list[str],
) -> str:
    """
    Tag each cross-module correlation match with a ConfidenceTier and
    render the Hallucination Guard section for the correlation report.

    Cross-module matches (2+ modules) → CONFIRMED.
    Single-module claims → INFERRED (one analytical step removed).
    Missing modules → UNVERIFIABLE.
    """
    _hg_reset()
    findings = []
    both_fan_fame  = "FAN" in modules_found and "FAME" in modules_found
    both_fame_fast = "FAME" in modules_found and "FAST" in modules_found
    both_fan_fast  = "FAN" in modules_found and "FAST" in modules_found

    # FAN ↔ FAME matches — process seen in memory AND flagged in PCAP → CONFIRMED
    for m in ff_matches:
        findings.append(tag_finding(
            f"Process `{m.get('process_name', '?')}` (PID {m.get('pid', '?')}) "
            f"→ {m.get('remote_ip', '?')}:{m.get('remote_port', '?')} "
            f"({m.get('threat_type', '?')}, {m.get('severity', '?').upper()})",
            ConfidenceTier.CONFIRMED,
            [],
            ["volatility3/netscan", "fan_protocol_analyzer"],
            ["fame", "fan"],
        ))

    if both_fan_fame and not ff_matches:
        findings.append(tag_finding(
            "FAN ↔ FAME correlation computed — no process-network matches found",
            ConfidenceTier.CONFIRMED,
            [],
            ["volatility3/netscan", "fan_protocol_analyzer"],
            ["fame", "fan"],
        ))
    elif not both_fan_fame:
        findings.append(tag_finding(
            "FAN ↔ FAME correlation unavailable — one or both modules did not run",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["volatility3/netscan", "fan_protocol_analyzer"],
            ["fame", "fan"],
        ))

    # FAME ↔ FAST matches
    for m in mf_matches:
        ctype = m.get("correlation_type", "")
        if "process_disk" in ctype:
            findings.append(tag_finding(
                f"Process `{m.get('process_name', '?')}` running in memory has executable deleted on disk",
                ConfidenceTier.CONFIRMED,
                [],
                ["volatility3/psscan", "tsk/fls"],
                ["fame", "fast"],
            ))
        else:
            findings.append(tag_finding(
                f"Disk path `{m.get('disk_path', '?')}` deleted — correlates with memory process evidence",
                ConfidenceTier.INFERRED,
                [],
                ["tsk/ils", "volatility3/psscan"],
                ["fast", "fame"],
            ))

    if both_fame_fast and not mf_matches:
        findings.append(tag_finding(
            "FAME ↔ FAST correlation computed — no process-disk matches found",
            ConfidenceTier.CONFIRMED,
            [],
            ["volatility3/psscan", "tsk/fls"],
            ["fame", "fast"],
        ))
    elif not both_fame_fast:
        findings.append(tag_finding(
            "FAME ↔ FAST correlation unavailable — one or both modules did not run",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["volatility3/psscan", "tsk/fls"],
            ["fame", "fast"],
        ))

    # FAN ↔ FAST matches
    for m in fd_matches:
        findings.append(tag_finding(
            f"Domain `{m.get('domain', '?')}` appeared in DNS traffic AND carved from disk",
            ConfidenceTier.CONFIRMED,
            [],
            ["fan_dns_threats", "bulk_extractor"],
            ["fan", "fast"],
        ))

    if both_fan_fast and not fd_matches:
        findings.append(tag_finding(
            "FAN ↔ FAST correlation computed — no DNS-to-disk domain matches found",
            ConfidenceTier.CONFIRMED,
            [],
            ["fan_dns_threats", "bulk_extractor"],
            ["fan", "fast"],
        ))
    elif not both_fan_fast:
        findings.append(tag_finding(
            "FAN ↔ FAST correlation unavailable — one or both modules did not run",
            ConfidenceTier.UNVERIFIABLE,
            [],
            ["fan_dns_threats", "bulk_extractor"],
            ["fan", "fast"],
        ))

    return render_confidence_summary(findings, module_label="Cross-module correlation")


# ── Public API ────────────────────────────────────────────────────────────────

def correlate(
    case_id: str,
    hostname: str = "",
    reports_dir: Path | None = None,
    analysis_dir: Path | None = None,
    exports_dir: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Path]:
    """
    Run cross-module correlation for a case and write output files.

    Returns a dict with keys "md" and "json" pointing to the output paths.
    """
    reports_dir  = reports_dir  or (PROJECT_ROOT / "reports")
    analysis_dir = analysis_dir or (PROJECT_ROOT / "analysis")
    exports_dir  = exports_dir  or (PROJECT_ROOT / "exports")
    output_dir   = output_dir   or reports_dir
    output_dir.mkdir(parents=True, exist_ok=True)

    generated_utc = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    stem = case_id.replace(" ", "_")

    memory_dir  = analysis_dir / "memory"
    storage_dir = analysis_dir / "storage"
    carved_dir  = exports_dir  / "carved"

    netscan_path = memory_dir / "netscan.txt"
    if not netscan_path.exists():
        netscan_path = memory_dir / "netstat.txt"
    pslist_path  = memory_dir / "pslist.txt"
    cmdline_path = memory_dir / "cmdline.txt"
    fls_path     = storage_dir / "fls_output.txt"

    artifacts: dict[str, bool] = {
        "analysis/memory/netscan.txt":       netscan_path.exists(),
        "analysis/memory/pslist.txt":        pslist_path.exists(),
        "analysis/memory/cmdline.txt":       cmdline_path.exists(),
        "analysis/storage/fls_output.txt":   fls_path.exists(),
        "exports/carved/url.txt":            (carved_dir / "url.txt").exists(),
        "analysis/fan_dns/dns_threats.json": bool(
            list(analysis_dir.glob("fan_dns*/**/dns_threats.json"))
        ),
    }

    netscan_rows           = _parse_netscan(netscan_path)
    pslist                 = _parse_pslist(pslist_path)
    cmdline_map            = _parse_cmdline(cmdline_path)
    _active, fls_deleted   = _parse_fls(fls_path)
    carved_urls            = _parse_bulk_urls(carved_dir)

    dns_threats  = _load_fan_json(analysis_dir, "dns")
    http_threats = _load_fan_json(analysis_dir, "http")
    tcp_threats  = _load_fan_json(analysis_dir, "tcp")
    udp_threats  = _load_fan_json(analysis_dir, "udp")
    all_fan      = dns_threats + http_threats + tcp_threats + udp_threats

    fan_conns = _fan_connections(all_fan)
    dns_doms  = _dns_domains(dns_threats)

    # Determine which modules have been run (reports OR raw artifacts present)
    modules_found: list[str] = []
    has_fan_report = any(
        (reports_dir / fn).exists()
        for fn in (f"{stem}_incident_report.md", f"{stem}_fan_report.md")
    )
    if has_fan_report or all_fan:
        modules_found.append("FAN")
    if (reports_dir / f"{stem}_fame_report.md").exists() or netscan_rows or pslist:
        modules_found.append("FAME")
    if (reports_dir / f"{stem}_fast_report.md").exists() or fls_deleted or carved_urls:
        modules_found.append("FAST")

    ff_matches = _corr_fan_fame(netscan_rows, fan_conns, pslist, cmdline_map)
    mf_matches = _corr_fame_fast(pslist, cmdline_map, fls_deleted)
    fd_matches = _corr_fan_fast(dns_doms, carved_urls)

    md_text = _build_markdown(
        case_id=case_id,
        hostname=hostname,
        generated_utc=generated_utc,
        modules_found=modules_found,
        artifacts=artifacts,
        ff_matches=ff_matches,
        mf_matches=mf_matches,
        fd_matches=fd_matches,
    )

    md_path   = output_dir / f"{stem}_correlation.md"
    json_path = output_dir / f"{stem}_correlation.json"

    md_path.write_text(md_text)
    print(f"[correlate] Markdown saved: {md_path}")

    json_path.write_text(json.dumps({
        "case_id":                   case_id,
        "hostname":                  hostname,
        "generated_utc":             generated_utc,
        "modules_found":             modules_found,
        "artifacts":                 artifacts,
        "fan_fame_process_network":  ff_matches,
        "fame_fast_process_disk":    mf_matches,
        "fan_fast_domain_url":       fd_matches,
        "total_matches":             len(ff_matches) + len(mf_matches) + len(fd_matches),
    }, indent=2))
    print(f"[correlate] JSON saved: {json_path}")

    return {"md": md_path, "json": json_path}


# ── CLI ───────────────────────────────────────────────────────────────────────

def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="FanGetFameFast — Cross-module correlation engine"
    )
    p.add_argument("--case-id",      required=True, metavar="ID")
    p.add_argument("--hostname",     default="",    metavar="HOST")
    p.add_argument("--reports-dir",  default=None,  metavar="DIR")
    p.add_argument("--analysis-dir", default=None,  metavar="DIR")
    p.add_argument("--exports-dir",  default=None,  metavar="DIR")
    p.add_argument("--output-dir",   default=None,  metavar="DIR")
    return p


if __name__ == "__main__":
    args = _parser().parse_args()
    paths = correlate(
        case_id      = args.case_id,
        hostname     = args.hostname,
        reports_dir  = Path(args.reports_dir)  if args.reports_dir  else None,
        analysis_dir = Path(args.analysis_dir) if args.analysis_dir else None,
        exports_dir  = Path(args.exports_dir)  if args.exports_dir  else None,
        output_dir   = Path(args.output_dir)   if args.output_dir   else None,
    )
    print("[correlate] Done:")
    for fmt, p in paths.items():
        print(f"  {fmt.upper():4s}  {p}")
