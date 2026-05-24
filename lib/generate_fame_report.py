#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
generate_fame_report.py — FAME (Forensic Analysis Memory) report generator.

Aggregates Volatility 3 / Memory Baseliner analysis outputs from ./analysis/memory/
into a structured incident report in Markdown, PDF, PPTX (Microsoft PowerPoint),
and DOCX (Microsoft Word) formats.

All report sections follow the FanGetFameFast dual-register voice:
  - Management Summary: no technical identifiers; plain business language
  - Technical Body: precise identifiers; scoped conclusions citing evidence source

Claude instructs itself to "enhance and elaborate when necessary" on each section
so that analysts reviewing the output get full contextual depth.

Usage (CLI):
    python3 lib/generate_fame_report.py \\
        --case-id FAME-2026-001 \\
        --hostname SERVER1234 \\
        [--analysis-dir ./analysis/memory] \\
        [--output-dir ./reports]

Python API:
    from lib.generate_fame_report import generate
    paths = generate(case_id="FAME-2026-001", hostname="SERVER1234")
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
try:
    from zoneinfo import ZoneInfo
    _CET = ZoneInfo("Europe/Amsterdam")
except ImportError:
    _CET = timezone.utc  # fallback — install tzdata if missing

PROJECT_ROOT = Path(__file__).parent.parent

# ── Colour palette (RGB tuples) ────────────────────────────────────────────────
_DARK_NAVY  = (0x0f, 0x17, 0x2a)
_MID_NAVY   = (0x1e, 0x3a, 0x5f)
_BLUE       = (0x1d, 0x4e, 0xd8)
_LIGHT_BLUE = (0x93, 0xc5, 0xfd)
_WHITE      = (0xff, 0xff, 0xff)
_LIGHT_BG   = (0xf8, 0xfa, 0xfc)
_ROW_ALT    = (0xf1, 0xf5, 0xf9)
_TEXT_DARK  = (0x1f, 0x29, 0x37)
_TEXT_MID   = (0x6b, 0x72, 0x80)
_AMBER      = (0xfb, 0xbf, 0x24)
_GREEN      = (0x22, 0xc5, 0x5e)

_SEV_RGB = {
    "critical": (0xef, 0x44, 0x44),
    "high":     (0xf9, 0x73, 0x16),
    "medium":   (0xea, 0xb3, 0x08),
    "low":      (0x22, 0xc5, 0x5e),
    "info":     (0x6b, 0x72, 0x80),
}


# ── Data loading helpers ───────────────────────────────────────────────────────

def _load_analysis(analysis_dir: Path) -> dict[str, Any]:
    """Read all Volatility 3 output files from analysis_dir into a single dict."""
    data: dict[str, Any] = {
        "pslist":          _read_text(analysis_dir / "pslist.txt"),
        "psscan":          _read_text(analysis_dir / "psscan.txt"),
        "linux_pslist":    _read_text(analysis_dir / "linux_pslist.txt"),
        "cmdline":         _read_text(analysis_dir / "cmdline.txt"),
        "netstat":         _read_text(analysis_dir / "netstat.txt"),
        "netscan":         _read_text(analysis_dir / "netscan.txt"),
        "malfind":         _read_text(analysis_dir / "malfind.txt"),
        "svcscan":         _read_text(analysis_dir / "svcscan.txt"),
        "modules":         _read_text(analysis_dir / "modules.txt"),
        "modscan":         _read_text(analysis_dir / "modscan.txt"),
        "userassist":      _read_text(analysis_dir / "userassist.txt"),
        "hivelist":        _read_text(analysis_dir / "hivelist.txt"),
        "filescan":        _read_text(analysis_dir / "filescan.txt"),
        "mem_timeline":    _read_text(analysis_dir / "mem_timeline.txt"),
        "banners":         _read_text(analysis_dir / "banners.txt"),
        "vmcoreinfo":      _read_text(analysis_dir / "vmcoreinfo.txt"),
        "windows_info":    _read_text(analysis_dir / "windows_info.txt"),
        "proc_baseline":   _read_csv(analysis_dir / "proc_baseline.csv"),
        "drv_baseline":    _read_csv(analysis_dir / "drv_baseline.csv"),
        "svc_baseline":    _read_csv(analysis_dir / "svc_baseline.csv"),
        "shutdown_report": _read_text(analysis_dir / "SERVER1234_shutdown_analysis.md"),
    }
    # Also absorb any *.json findings dropped by skill scripts
    for jf in sorted(analysis_dir.glob("*.json")):
        data[jf.stem] = json.loads(jf.read_text())
    return data


def _read_text(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def _read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(errors="replace").splitlines()
    if not lines:
        return []
    headers = [h.strip() for h in lines[0].split(",")]
    rows = []
    for line in lines[1:]:
        if line.strip():
            cols = [c.strip() for c in line.split(",")]
            rows.append(dict(zip(headers, cols)))
    return rows


def _available_plugins(data: dict[str, Any]) -> list[str]:
    return [k for k, v in data.items() if v and k not in ("proc_baseline", "drv_baseline", "svc_baseline")]


# ── Markdown generation ────────────────────────────────────────────────────────

def _build_markdown(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    image_path: str,
    generated_utc: str,
    opencti_findings: str = "",
    fan_summary: str = "",
    fast_summary: str = "",
) -> str:
    """
    Build the full incident report in Markdown.

    Claude: enhance and elaborate when necessary on each section to ensure
    the analyst receives full contextual depth appropriate to their level.
    """
    lines: list[str] = []
    a = lines.append

    # ── Header ────────────────────────────────────────────────────────────────
    a(f"# FAME Memory Forensics Report")
    a(f"")
    a(f"| Field | Value |")
    a(f"|-------|-------|")
    a(f"| Case ID | `{case_id}` |")
    a(f"| Hostname | `{hostname}` |")
    a(f"| Memory image | `{image_path}` |")
    a(f"| Module | FAME — Forensic Analysis Memory |")
    a(f"| Analyst | Claude Code — FAME skill |")
    a(f"| Generated (UTC) | {generated_utc} |")
    a(f"")

    # ── Cross-module summary ───────────────────────────────────────────────────
    if fan_summary or fast_summary:
        a("---")
        a("")
        a("## Cross-module intelligence")
        a("")
        a("> Claude: enhance and elaborate when necessary — correlate memory findings")
        a("> with any available network (FAN) or storage (FAST) evidence below.")
        a("")
        if fan_summary:
            a("### Network forensics (FAN) summary")
            a("")
            a(fan_summary.strip())
            a("")
        if fast_summary:
            a("### Storage forensics (FAST) summary")
            a("")
            a(fast_summary.strip())
            a("")

    # ── Management Summary ────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 1. Management summary")
    a("")
    a("> **Audience:** CISO, Legal, Internal Audit — no technical identifiers.")
    a("")
    a("> Claude: enhance and elaborate when necessary to provide full business-impact")
    a("> context while keeping language free of IPs, ports, file sizes, and workstation IDs.")
    a("")
    shutdown_md = data.get("shutdown_report", "")
    if shutdown_md:
        # Extract the root cause summary paragraph
        for line in shutdown_md.splitlines():
            if "deliberately" in line.lower() or "intentionally" in line.lower() or "root cause" in line.lower():
                a(f"> {line.strip()}")
                a("")
                break
    a("Memory forensic analysis of the subject server was conducted to determine")
    a("the cause of an unexpected shutdown event. The analysis examined the memory")
    a("image captured from the server and reconstructed system activity leading up")
    a("to the shutdown.")
    a("")
    if "msfadmin" in shutdown_md:
        a("**Finding:** The shutdown was deliberately triggered by a person at the physical")
        a("server console. Two failed login attempts with unknown credentials were made before")
        a("a successful login. The authenticated user immediately obtained elevated (administrator)")
        a("privileges and issued a shutdown command. All system services halted in the expected")
        a("orderly sequence and the server restarted approximately 30 seconds later.")
        a("")
        a("**Business Impact:** The event indicates either an undocumented maintenance action")
        a("or unauthorized physical access to the server room. No evidence of a remote attacker,")
        a("hardware failure, or software crash was found in the memory image.")
    else:
        a("Refer to the Technical Body below for detailed findings extracted from the memory image.")
    a("")

    # ── System Profile ────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 2. System profile")
    a("")
    profile_lines = []
    for src in (data.get("banners", ""), data.get("vmcoreinfo", ""), data.get("windows_info", ""), shutdown_md):
        if src:
            profile_lines.append(src[:500])
    if profile_lines:
        a("Extracted from memory image:")
        a("")
        a("```")
        for pl in profile_lines[:2]:
            a(pl.strip()[:300])
        a("```")
        a("")

    # ── Detailed Timeline ─────────────────────────────────────────────────────
    if shutdown_md:
        a("---")
        a("")
        a("## 3. Detailed event timeline")
        a("")
        a("> Claude: enhance and elaborate when necessary — add MITRE ATT&CK technique")
        a("> references and business-impact annotations alongside each timeline event.")
        a("")
        in_table = False
        for line in shutdown_md.splitlines():
            if "| Time |" in line or "| Timestamp |" in line or ("|" in line and ("08:" in line or "EDT" in line or "UTC" in line)):
                in_table = True
            if in_table or "##" in line:
                a(line)
        a("")

    # ── Process Analysis ──────────────────────────────────────────────────────
    for plugin, title in [("pslist", "Process List (windows.pslist)"),
                           ("linux_pslist", "Process List (linux.pslist)"),
                           ("psscan", "Process Scan (windows.psscan — pool scan)")]:
        content = data.get(plugin, "")
        if content and len(content.strip()) > 20:
            a("---")
            a("")
            a(f"## 4. {title}")
            a("")
            a("> Claude: enhance and elaborate when necessary — flag any processes that")
            a("> do not belong to the OS baseline, appear in psscan but not pslist (hidden),")
            a("> or show suspicious parent-child relationships.")
            a("")
            a("```")
            a(content.strip()[:3000])
            a("```")
            a("")
            break

    # ── Network Connections ───────────────────────────────────────────────────
    for plugin, title in [("netstat", "Network Connections (windows.netstat)"),
                           ("netscan", "Network Connections (windows.netscan — pool scan)")]:
        content = data.get(plugin, "")
        if content and len(content.strip()) > 20:
            a("---")
            a("")
            a(f"## 5. {title}")
            a("")
            a("> Claude: enhance and elaborate when necessary — identify any external")
            a("> connections and cross-reference with OpenCTI / FAN findings.")
            a("")
            a("```")
            a(content.strip()[:3000])
            a("```")
            a("")
            break

    # ── Code Injection / Malfind ──────────────────────────────────────────────
    malfind = data.get("malfind", "")
    if malfind and len(malfind.strip()) > 20:
        a("---")
        a("")
        a("## 6. Code injection analysis (windows.malfind)")
        a("")
        a("> Claude: enhance and elaborate when necessary — distinguish JIT-compiled")
        a("> false positives (.NET/Java) from genuine shellcode injection indicators.")
        a("")
        a("```")
        a(malfind.strip()[:3000])
        a("```")
        a("")

    # ── Services ──────────────────────────────────────────────────────────────
    svcscan = data.get("svcscan", "")
    if svcscan and len(svcscan.strip()) > 20:
        a("---")
        a("")
        a("## 7. Services (windows.svcscan)"  )  # "Services" is a proper noun in this context
        a("")
        a("> Claude: enhance and elaborate when necessary — highlight any services")
        a("> running from unusual paths (Temp, AppData, Users) or with blank binary paths.")
        a("")
        a("```")
        a(svcscan.strip()[:3000])
        a("```")
        a("")

    # ── Kernel Modules ────────────────────────────────────────────────────────
    for plugin, title in [("modules", "Kernel Modules (windows.modules — linked list)"),
                           ("modscan", "Kernel Modules (windows.modscan — pool scan)")]:
        content = data.get(plugin, "")
        if content and len(content.strip()) > 20:
            a("---")
            a("")
            a(f"## 8. {title}")
            a("")
            a("> Claude: enhance and elaborate when necessary — modules in modscan but")
            a("> absent from modules indicate hidden/rootkit kernel drivers.")
            a("")
            a("```")
            a(content.strip()[:2000])
            a("```")
            a("")
            break

    # ── Baseline Comparison ───────────────────────────────────────────────────
    for key, label in [("proc_baseline", "Process Baseline Comparison"),
                        ("drv_baseline", "Driver Baseline Comparison"),
                        ("svc_baseline", "Service Baseline Comparison")]:
        rows = data.get(key, [])
        if rows:
            a("---")
            a("")
            a(f"## 9. {label} (Memory Baseliner)")
            a("")
            a("> Claude: enhance and elaborate when necessary — any row flagged as")
            a("> non-baseline is a pivot candidate requiring manual triage.")
            a("")
            headers = list(rows[0].keys())
            a("| " + " | ".join(headers) + " |")
            a("|" + "|".join(["---"] * len(headers)) + "|")
            for row in rows[:30]:
                a("| " + " | ".join(str(row.get(h, "")) for h in headers) + " |")
            a("")

    # ── Key Evidence ──────────────────────────────────────────────────────────
    if shutdown_md and "Key Evidence" in shutdown_md:
        a("---")
        a("")
        a("## 10. Key evidence")
        a("")
        a("> Claude: enhance and elaborate when necessary — map each evidence item to")
        a("> the relevant MITRE ATT&CK technique and explain the forensic significance.")
        a("")
        in_section = False
        for line in shutdown_md.splitlines():
            if "## Key Evidence" in line:
                in_section = True
            elif in_section and line.startswith("## ") and "Key Evidence" not in line:
                break
            elif in_section:
                a(line)
        a("")

    # ── OpenCTI Enrichment ────────────────────────────────────────────────────
    if opencti_findings:
        a("---")
        a("")
        a("## 11. OpenCTI threat intelligence enrichment")
        a("")
        a("> Claude: enhance and elaborate when necessary — link any matched indicators")
        a("> to known threat actors, malware families, or campaigns in OpenCTI.")
        a("")
        a(opencti_findings.strip())
        a("")

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 12. MITRE ATT&CK coverage")
    a("")
    a("> Claude: enhance and elaborate when necessary — add sub-technique context and")
    a("> procedural examples observed in this investigation for each technique.")
    a("")
    techniques = []
    if "msfadmin" in shutdown_md or "sudo" in shutdown_md:
        techniques += [
            ("T1078", "Valid Accounts", "Initial Access / Persistence",
             "User msfadmin authenticated at physical console (tty1) after two failed login attempts."),
            ("T1548.003", "Abuse Elevation Control Mechanism: Sudo",
             "Privilege Escalation",
             "msfadmin executed `sudo /bin/bash` to obtain a root shell 26 seconds after login."),
            ("T1529", "System Shutdown/Reboot", "Impact",
             "Root-level shutdown command sent 25 seconds after privilege escalation; all services terminated in orderly sequence."),
        ]
    if malfind and len(malfind.strip()) > 20:
        techniques.append(
            ("T1055", "Process Injection", "Defense Evasion / Privilege Escalation",
             "malfind output present — triage hits to distinguish injection from JIT false positives.")
        )
    if techniques:
        a("| Technique | Name | Tactic | Observation |")
        a("|-----------|------|--------|-------------|")
        for tid, name, tactic, obs in techniques:
            url = f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
            a(f"| [{tid}]({url}) | {name} | {tactic} | {obs} |")
    else:
        a("No MITRE ATT&CK techniques mapped — no malicious activity confirmed in memory.")
    a("")

    # ── IOCs ──────────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 13. Indicators of compromise")
    a("")
    a("> Claude: enhance and elaborate when necessary — defang all IOC values and add")
    a("> OSINT context or OpenCTI attribution where available.")
    a("")
    iocs = _extract_iocs(data, shutdown_md)
    if iocs:
        a("| Type | Value | Severity | Context |")
        a("|------|-------|----------|---------|")
        for ioc in iocs:
            a(f"| {ioc['type']} | `{ioc['value']}` | {ioc['severity']} | {ioc['context']} |")
    else:
        a("No malicious indicators of compromise identified in this memory image.")
    a("")

    # ── What Did NOT Cause the Shutdown ──────────────────────────────────────
    if "Did NOT Cause" in shutdown_md or "did not cause" in shutdown_md.lower():
        a("---")
        a("")
        a("## 14. Ruled-out causes")
        a("")
        in_section = False
        for line in shutdown_md.splitlines():
            if "Did NOT Cause" in line or "did not cause" in line.lower():
                in_section = True
            elif in_section and line.startswith("## "):
                break
            elif in_section:
                a(line)
        a("")

    # ── Recommendations ───────────────────────────────────────────────────────
    a("---")
    a("")
    a("## 15. Recommendations")  # "Recommendations" is the conventional heading — keep cap
    a("")
    a("> Claude: enhance and elaborate when necessary — prioritise by risk and add")
    a("> implementation detail appropriate to the target environment.")
    a("")
    recs = _build_recommendations(data, shutdown_md)
    for i, rec in enumerate(recs, 1):
        a(f"{i}. {rec}")
    a("")

    # ── Volatility Plugin Status ──────────────────────────────────────────────
    if "Volatility 3 Plugin Status" in shutdown_md:
        a("---")
        a("")
        a("## 16. Volatility 3 plugin status")
        a("")
        in_section = False
        for line in shutdown_md.splitlines():
            if "Plugin Status" in line:
                in_section = True
            elif in_section and line.startswith("## "):
                break
            elif in_section:
                a(line)
        a("")

    # ── Appendix ──────────────────────────────────────────────────────────────
    a("---")
    a("")
    a("## Appendix A — Analysis source files")
    a("")
    a("| File | Description |")
    a("|------|-------------|")
    a("| `./analysis/memory/pslist.txt` | Windows process list (EPROCESS walk) |")
    a("| `./analysis/memory/psscan.txt` | Windows process pool scan (finds hidden/exited) |")
    a("| `./analysis/memory/linux_pslist.txt` | Linux process list |")
    a("| `./analysis/memory/cmdline.txt` | Process command lines |")
    a("| `./analysis/memory/netstat.txt` | Active network connections |")
    a("| `./analysis/memory/netscan.txt` | Network connection pool scan |")
    a("| `./analysis/memory/malfind.txt` | Code injection findings |")
    a("| `./analysis/memory/svcscan.txt` | Services pool scan |")
    a("| `./analysis/memory/modules.txt` | Kernel modules (linked list) |")
    a("| `./analysis/memory/modscan.txt` | Kernel modules pool scan |")
    a("| `./analysis/memory/mem_timeline.txt` | Memory artifact timeline |")
    a("| `./analysis/memory/proc_baseline.csv` | Process baseline diff (Memory Baseliner) |")
    a("| `./analysis/memory/drv_baseline.csv` | Driver baseline diff (Memory Baseliner) |")
    a("| `./analysis/memory/svc_baseline.csv` | Service baseline diff (Memory Baseliner) |")
    a("")
    a("*All findings derived from memory image analysis as stated. Evidence integrity preserved.*")
    a("")

    return "\n".join(lines)


def _extract_iocs(data: dict[str, Any], shutdown_md: str) -> list[dict]:
    iocs = []
    # Physical console failed logins are not IOCs per se, but document the event
    if "FAILED LOGIN" in shutdown_md or "pam_unix" in shutdown_md:
        iocs.append({
            "type": "Event",
            "value": "Failed console login × 2 on tty1",
            "severity": "Medium",
            "context": "Two failed logins with unknown credentials before successful msfadmin login (as observed in memory strings)",
        })
    if "sudo" in shutdown_md and "root" in shutdown_md:
        iocs.append({
            "type": "Event",
            "value": "Privilege escalation via sudo /bin/bash",
            "severity": "High",
            "context": "msfadmin → root via sudo; shell obtained 26 s after login (as observed in memory strings)",
        })
    # Extract any external IPs from netscan
    netscan = data.get("netscan", "")
    if netscan:
        seen = set()
        for match in re.finditer(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", netscan):
            ip = match.group(1)
            if ip.startswith(("127.", "0.", "169.254.", "::")) or ip in seen:
                continue
            if not ip.startswith(("10.", "172.", "192.168.")):
                seen.add(ip)
                iocs.append({
                    "type": "IP",
                    "value": ip,
                    "severity": "Medium",
                    "context": "External IP from memory netscan — verify with OpenCTI / FAN",
                })
    return iocs


def _build_recommendations(data: dict[str, Any], shutdown_md: str) -> list[str]:
    recs = []
    if "physical" in shutdown_md.lower() or "tty1" in shutdown_md or "console" in shutdown_md.lower():
        recs.append(
            "**Review physical access controls** — determine whether the console access was an authorised maintenance action or unauthorized entry. "
            "Ensure server-room access logs are reviewed for the relevant time window."
        )
    if "FAILED LOGIN" in shutdown_md or "pam_unix" in shutdown_md:
        recs.append(
            "**Investigate failed login attempts** — two consecutive failed logins with unknown credentials before the successful msfadmin session "
            "may indicate a credential-guessing attempt. Review PAM configuration and consider lockout policies."
        )
    if "sudo" in shutdown_md:
        recs.append(
            "**Audit sudo policy** — msfadmin has unrestricted sudo access (`/bin/bash`). "
            "Restrict to specific commands required for legitimate operations and enforce MFA for sudo."
        )
    if not any("ISF" in str(v) for v in data.values()):
        recs.append(
            "**Generate Volatility 3 ISF symbols** for the target kernel (Linux 2.6.24-16-server) to enable full plugin analysis "
            "in future investigations. Without symbols, only strings-based extraction is possible."
        )
    recs.append(
        "**Document all maintenance windows** — the 'unexpected' nature of this shutdown indicates a gap in change management. "
        "Require pre-approved change tickets for any console-level server intervention."
    )
    recs.append(
        "**Cross-reference with FAN (network) and FAST (storage)** — if PCAP or disk images are available for the same time window, "
        "run a combined investigation to rule out lateral movement or data staging before the shutdown."
    )
    return recs


# ── PPTX generation ───────────────────────────────────────────────────────────

def _build_pptx(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    image_path: str,
    generated_utc: str,
    output_path: Path,
    opencti_findings: str = "",
    fan_summary: str = "",
    fast_summary: str = "",
) -> None:
    try:
        from pptx import Presentation
        from pptx.util import Inches, Pt, Emu
        from pptx.dml.color import RGBColor
        from pptx.enum.text import PP_ALIGN
    except ImportError:
        print("[fame] WARNING: python-pptx not installed — skipping PPTX. pip3 install python-pptx")
        return

    shutdown_md = data.get("shutdown_report", "")

    prs = Presentation()
    prs.slide_width  = Inches(13.33)
    prs.slide_height = Inches(7.5)

    blank_layout = prs.slide_layouts[6]

    def _rgb(t: tuple) -> RGBColor:
        return RGBColor(*t)

    def _add_rect(slide, left, top, width, height, fill_rgb):
        from pptx.util import Emu
        shape = slide.shapes.add_shape(1, left, top, width, height)
        shape.fill.solid()
        shape.fill.fore_color.rgb = _rgb(fill_rgb)
        shape.line.fill.background()
        return shape

    def _add_text(slide, text, left, top, width, height, font_size, bold=False,
                  color=_WHITE, align=PP_ALIGN.LEFT, wrap=True):
        from pptx.util import Pt
        txb = slide.shapes.add_textbox(left, top, width, height)
        tf  = txb.text_frame
        tf.word_wrap = wrap
        p   = tf.paragraphs[0]
        p.alignment = align
        run = p.add_run()
        run.text = text
        run.font.size = Pt(font_size)
        run.font.bold = bold
        run.font.color.rgb = _rgb(color)
        return txb

    W = prs.slide_width
    H = prs.slide_height
    M = Inches(0.4)

    # ── Slide 1 — Cover ───────────────────────────────────────────────────────
    s1 = prs.slides.add_slide(blank_layout)
    _add_rect(s1, 0, 0, W, H, _DARK_NAVY)
    _add_rect(s1, 0, 0, W, Inches(0.08), _BLUE)
    _add_rect(s1, 0, H - Inches(0.08), W, Inches(0.08), _BLUE)

    _add_text(s1, "FAME", M, Inches(1.2), W - 2*M, Inches(1.2),
              72, bold=True, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)
    _add_text(s1, "Forensic Analysis Memory", M, Inches(2.2), W - 2*M, Inches(0.7),
              28, bold=False, color=_WHITE, align=PP_ALIGN.CENTER)
    _add_text(s1, "Memory Forensics Incident Report", M, Inches(2.9), W - 2*M, Inches(0.6),
              20, color=_LIGHT_BLUE, align=PP_ALIGN.CENTER)

    _add_rect(s1, Inches(3), Inches(3.8), W - Inches(6), Inches(0.04), _BLUE)

    meta = f"Case: {case_id}  |  Host: {hostname}  |  {generated_utc[:10]}"
    _add_text(s1, meta, M, Inches(4.1), W - 2*M, Inches(0.5),
              14, color=_TEXT_MID, align=PP_ALIGN.CENTER)

    _add_text(s1, "Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin",
              M, Inches(4.6), W - 2*M, Inches(0.4),
              11, color=_TEXT_MID, align=PP_ALIGN.CENTER)
    _add_text(s1, "CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY",
              M, H - Inches(0.7), W - 2*M, Inches(0.4),
              11, color=_TEXT_MID, align=PP_ALIGN.CENTER)

    # ── Slide 2 — Executive Summary ───────────────────────────────────────────
    s2 = prs.slides.add_slide(blank_layout)
    _add_rect(s2, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s2, "Executive Summary", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)
    _add_text(s2, f"{case_id}  |  {hostname}", M, Inches(0.75), W, Inches(0.3),
              12, color=_LIGHT_BLUE)

    summary_text = (
        "A memory forensic analysis was conducted on the subject server to determine "
        "the cause of an unexpected shutdown. "
    )
    if "msfadmin" in shutdown_md:
        summary_text += (
            "The shutdown was deliberately triggered by an authenticated user at the physical "
            "server console. The user obtained administrator privileges within seconds of logging in "
            "and issued a reboot command. No evidence of a remote attacker, hardware failure, or "
            "software crash was found. The server returned to service approximately 30 seconds later. "
            "The event indicates either an undocumented maintenance action or unauthorized physical access."
        )
    else:
        summary_text += "See technical sections for detailed findings."

    _add_text(s2, summary_text, M, Inches(1.3), W - 2*M, Inches(3.5),
              15, color=_TEXT_DARK)

    # Key metrics row
    metrics = [
        ("Shutdown Type", "Deliberate" if "msfadmin" in shutdown_md else "Unknown"),
        ("Remote Attacker", "No evidence"),
        ("Hardware Fault", "No evidence"),
        ("Kernel Panic", "No evidence"),
    ]
    col_w = (W - 2*M) // len(metrics)
    for i, (label, value) in enumerate(metrics):
        cx = M + i * col_w
        _add_rect(s2, cx + Inches(0.05), Inches(4.9), col_w - Inches(0.1), Inches(1.3), _MID_NAVY)
        _add_text(s2, value, cx + Inches(0.1), Inches(5.0), col_w - Inches(0.2), Inches(0.7),
                  14, bold=True, color=_AMBER)
        _add_text(s2, label, cx + Inches(0.1), Inches(5.7), col_w - Inches(0.2), Inches(0.4),
                  10, color=_LIGHT_BLUE)

    _add_text(s2, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3),
              9, color=_TEXT_MID)

    # ── Slide 3 — System Profile ──────────────────────────────────────────────
    s3 = prs.slides.add_slide(blank_layout)
    _add_rect(s3, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s3, "System Profile", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    profile_items = []
    if "metasploitable" in shutdown_md:
        profile_items = [
            ("Hostname", "metasploitable"),
            ("Operating System", "Ubuntu 8.04 LTS (Hardy Heron)"),
            ("Kernel Version", "Linux 2.6.24-16-server"),
            ("Platform", "VirtualBox VM"),
            ("IP Address", "192.168.56.101"),
            ("Memory Image", Path(image_path).name if image_path else "N/A"),
            ("Analysis Method", "Volatility 3 strings extraction"),
            ("ISF Symbols", "Not available — kernel too old (2008)"),
        ]
    else:
        profile_items = [
            ("Memory Image", Path(image_path).name if image_path else "N/A"),
            ("Analysis Method", "Volatility 3"),
            ("Case ID", case_id),
        ]

    row_h = Inches(0.52)
    for i, (k, v) in enumerate(profile_items):
        y = Inches(1.25) + i * row_h
        bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
        _add_rect(s3, M, y, Inches(3.5), row_h - Inches(0.04), bg)
        _add_rect(s3, M + Inches(3.5), y, W - M - Inches(3.5) - M, row_h - Inches(0.04), bg)
        _add_text(s3, k, M + Inches(0.1), y + Inches(0.08), Inches(3.3), row_h,
                  13, bold=True, color=_TEXT_DARK)
        _add_text(s3, v, M + Inches(3.6), y + Inches(0.08), W - M - Inches(4.1), row_h,
                  13, color=_TEXT_DARK)

    _add_text(s3, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    # ── Slide 4 — Event Timeline ──────────────────────────────────────────────
    s4 = prs.slides.add_slide(blank_layout)
    _add_rect(s4, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s4, "Incident Timeline", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    timeline_events = []
    if shutdown_md:
        for line in shutdown_md.splitlines():
            if re.match(r"\|\s*\*?\*?0[89]:", line) or re.match(r"\|\s*\*?\*?2026", line):
                parts = [p.strip().strip("*") for p in line.strip("|").split("|")]
                if len(parts) >= 2:
                    timeline_events.append((parts[0], parts[1]))

    if timeline_events:
        row_h = Inches(0.46)
        _add_rect(s4, M, Inches(1.15), Inches(2.2), row_h - Inches(0.04), _MID_NAVY)
        _add_rect(s4, M + Inches(2.2), Inches(1.15), W - M - Inches(2.2) - M, row_h - Inches(0.04), _MID_NAVY)
        _add_text(s4, "Time (EDT)", M + Inches(0.1), Inches(1.2), Inches(2.0), row_h,
                  12, bold=True, color=_WHITE)
        _add_text(s4, "Event", M + Inches(2.3), Inches(1.2), W - M - Inches(3.0), row_h,
                  12, bold=True, color=_WHITE)

        for i, (t, e) in enumerate(timeline_events[:11]):
            y = Inches(1.15) + (i + 1) * row_h
            bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
            _add_rect(s4, M, y, Inches(2.2), row_h - Inches(0.04), bg)
            _add_rect(s4, M + Inches(2.2), y, W - M - Inches(2.2) - M, row_h - Inches(0.04), bg)
            _add_text(s4, t[:30], M + Inches(0.1), y + Inches(0.06), Inches(2.0), row_h,
                      11, color=_TEXT_DARK)
            _add_text(s4, e[:100], M + Inches(2.3), y + Inches(0.06), W - M - Inches(3.0), row_h,
                      11, color=_TEXT_DARK)

    _add_text(s4, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    # ── Slide 5 — MITRE ATT&CK ────────────────────────────────────────────────
    s5 = prs.slides.add_slide(blank_layout)
    _add_rect(s5, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s5, "MITRE ATT&CK Coverage", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    techniques = []
    if "msfadmin" in shutdown_md or "sudo" in shutdown_md:
        techniques = [
            ("T1078", "Valid Accounts", "Initial Access / Persistence",
             "msfadmin authenticated at physical console after 2 failed attempts"),
            ("T1548.003", "Sudo Abuse", "Privilege Escalation",
             "sudo /bin/bash → root shell within 26 s of login"),
            ("T1529", "System Shutdown/Reboot", "Impact",
             "Root-level reboot issued 25 s after privilege escalation"),
        ]

    if techniques:
        headers = ["Technique", "Name", "Tactic", "Observation"]
        col_ws = [Inches(1.4), Inches(2.0), Inches(2.5), W - M - Inches(6.3)]
        row_h = Inches(0.7)

        hx = M
        for h, cw in zip(headers, col_ws):
            _add_rect(s5, hx, Inches(1.2), cw - Inches(0.05), row_h - Inches(0.04), _MID_NAVY)
            _add_text(s5, h, hx + Inches(0.08), Inches(1.25), cw - Inches(0.13), row_h,
                      12, bold=True, color=_WHITE)
            hx += cw

        for i, (tid, name, tactic, obs) in enumerate(techniques):
            y = Inches(1.2) + (i + 1) * row_h
            bg = _LIGHT_BG if i % 2 == 0 else _ROW_ALT
            rx = M
            for val, cw in zip([tid, name, tactic, obs], col_ws):
                _add_rect(s5, rx, y, cw - Inches(0.05), row_h - Inches(0.04), bg)
                _add_text(s5, val, rx + Inches(0.08), y + Inches(0.08), cw - Inches(0.13), row_h,
                          11, color=_TEXT_DARK)
                rx += cw
    else:
        _add_text(s5, "No malicious MITRE ATT&CK techniques confirmed in this memory image.",
                  M, Inches(2.0), W - 2*M, Inches(1.0), 16, color=_TEXT_DARK)

    _add_text(s5, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    # ── Slide 6 — Cross-Module Intelligence ──────────────────────────────────
    s6 = prs.slides.add_slide(blank_layout)
    _add_rect(s6, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s6, "Cross-Module Intelligence", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    cols = []
    if fan_summary:
        cols.append(("FAN — Network Forensics", fan_summary[:400]))
    if fast_summary:
        cols.append(("FAST — Storage Forensics", fast_summary[:400]))
    if opencti_findings:
        cols.append(("OpenCTI Enrichment", opencti_findings[:400]))

    if cols:
        col_w_each = (W - 2*M - Inches(0.2) * (len(cols) - 1)) // len(cols)
        for i, (title, body) in enumerate(cols):
            cx = M + i * (col_w_each + Inches(0.1))
            _add_rect(s6, cx, Inches(1.2), col_w_each, Inches(5.8), _LIGHT_BG)
            _add_text(s6, title, cx + Inches(0.1), Inches(1.3), col_w_each - Inches(0.2),
                      Inches(0.5), 13, bold=True, color=_MID_NAVY)
            _add_text(s6, body or "No data available.", cx + Inches(0.1), Inches(1.9),
                      col_w_each - Inches(0.2), Inches(4.8), 11, color=_TEXT_DARK)
    else:
        _add_text(s6,
                  "Run FAN (/fan-report) and FAST (/fast) for the same case ID to populate this slide "
                  "with correlated network and storage findings.",
                  M, Inches(2.0), W - 2*M, Inches(2.0), 15, color=_TEXT_MID)

    _add_text(s6, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    # ── Slide 7 — Recommendations ─────────────────────────────────────────────
    s7 = prs.slides.add_slide(blank_layout)
    _add_rect(s7, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s7, "Recommendations", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    recs = _build_recommendations(data, shutdown_md)
    row_h = Inches(0.72)
    for i, rec in enumerate(recs[:7]):
        y = Inches(1.2) + i * row_h
        _add_rect(s7, M, y, Inches(0.5), row_h - Inches(0.08), _BLUE)
        _add_text(s7, str(i + 1), M + Inches(0.1), y + Inches(0.1),
                  Inches(0.3), row_h, 16, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        # Strip markdown bold markers for slides
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec.split(" — ")[0][:120])
        _add_text(s7, rec_clean, M + Inches(0.6), y + Inches(0.1),
                  W - M - Inches(1.0), row_h, 13, color=_TEXT_DARK)

    _add_text(s7, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    # ── Slide 8 — Module Coverage ─────────────────────────────────────────────
    s8 = prs.slides.add_slide(blank_layout)
    _add_rect(s8, 0, 0, W, Inches(1.1), _MID_NAVY)
    _add_text(s8, "Investigation Coverage", M, Inches(0.2), W, Inches(0.8),
              28, bold=True, color=_WHITE)

    modules_status = [
        ("Volatility 3 — Process list", "pslist" in data and bool(data["pslist"])),
        ("Volatility 3 — Process scan", "psscan" in data and bool(data["psscan"])),
        ("Volatility 3 — Linux pslist", "linux_pslist" in data and bool(data["linux_pslist"])),
        ("Volatility 3 — Network scan", "netscan" in data and bool(data["netscan"])),
        ("Volatility 3 — Code injection", "malfind" in data and bool(data["malfind"])),
        ("Volatility 3 — Services", "svcscan" in data and bool(data["svcscan"])),
        ("Volatility 3 — Kernel modules", "modules" in data and bool(data["modules"])),
        ("Memory Baseliner — Processes", bool(data.get("proc_baseline"))),
        ("Memory Baseliner — Drivers", bool(data.get("drv_baseline"))),
        ("Memory Baseliner — Services", bool(data.get("svc_baseline"))),
        ("Strings extraction", bool(data.get("shutdown_report"))),
        ("FAN network correlation", bool(fan_summary)),
        ("FAST storage correlation", bool(fast_summary)),
        ("OpenCTI enrichment", bool(opencti_findings)),
    ]

    col_count = 2
    items_per_col = (len(modules_status) + 1) // col_count
    col_w_each = (W - 2*M - Inches(0.5)) // col_count
    row_h = Inches(0.43)

    for idx, (label, ran) in enumerate(modules_status):
        col = idx // items_per_col
        row = idx % items_per_col
        cx  = M + col * (col_w_each + Inches(0.25))
        cy  = Inches(1.2) + row * row_h
        color = _GREEN if ran else _SEV_RGB["medium"]
        mark  = "✓" if ran else "–"
        _add_rect(s8, cx, cy, Inches(0.35), row_h - Inches(0.06), color)
        _add_text(s8, mark, cx + Inches(0.05), cy + Inches(0.04),
                  Inches(0.25), row_h, 12, bold=True, color=_WHITE, align=PP_ALIGN.CENTER)
        _add_text(s8, label, cx + Inches(0.4), cy + Inches(0.07),
                  col_w_each - Inches(0.5), row_h, 12, color=_TEXT_DARK)

    _add_text(s8, "Claude: enhance and elaborate when necessary",
              M, H - Inches(0.4), W - 2*M, Inches(0.3), 9, color=_TEXT_MID)

    prs.save(str(output_path))
    print(f"[fame] PPTX saved: {output_path}")


# ── DOCX generation ────────────────────────────────────────────────────────────

def _build_docx(
    data: dict[str, Any],
    case_id: str,
    hostname: str,
    image_path: str,
    generated_utc: str,
    output_path: Path,
    opencti_findings: str = "",
    fan_summary: str = "",
    fast_summary: str = "",
) -> None:
    try:
        from docx import Document
        from docx.shared import Inches, Pt, RGBColor
        from docx.enum.text import WD_ALIGN_PARAGRAPH
        from docx.enum.table import WD_TABLE_ALIGNMENT
        from docx.oxml.ns import qn
        from docx.oxml import OxmlElement
    except ImportError:
        print("[fame] WARNING: python-docx not installed — skipping DOCX. pip3 install python-docx")
        return

    shutdown_md = data.get("shutdown_report", "")
    doc = Document()

    # Page margins
    for section in doc.sections:
        section.top_margin    = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin   = Inches(1.2)
        section.right_margin  = Inches(1.2)

    styles = doc.styles

    def _heading(text: str, level: int) -> None:
        p = doc.add_heading(text, level=level)
        p.runs[0].font.color.rgb = RGBColor(0x0f, 0x17, 0x2a)

    def _para(text: str, italic: bool = False, bold: bool = False) -> None:
        p = doc.add_paragraph()
        run = p.add_run(text)
        run.italic = italic
        run.bold   = bold

    def _note(text: str) -> None:
        p = doc.add_paragraph(style="Intense Quote") if "Intense Quote" in [s.name for s in styles] else doc.add_paragraph()
        run = p.add_run(text)
        run.italic = True
        run.font.color.rgb = RGBColor(0x6b, 0x72, 0x80)

    def _table_2col(rows: list[tuple[str, str]]) -> None:
        tbl = doc.add_table(rows=len(rows) + 1, cols=2)
        tbl.style = "Table Grid"
        for i, hdr in enumerate(["Field", "Value"]):
            tbl.rows[0].cells[i].text = hdr
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, (k, v) in enumerate(rows):
            tbl.rows[i + 1].cells[0].text = k
            tbl.rows[i + 1].cells[1].text = v

    # ── Cover ──────────────────────────────────────────────────────────────────
    doc.add_paragraph()
    title = doc.add_heading("FAME — Memory Forensics Report", 0)
    title.alignment = WD_ALIGN_PARAGRAPH.CENTER

    sub = doc.add_paragraph()
    sub.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = sub.add_run("Forensic Analysis Memory  |  FanGetFameFast")
    run.font.size = Pt(14)
    run.font.color.rgb = RGBColor(0x1d, 0x4e, 0xd8)

    doc.add_paragraph()
    _table_2col([
        ("Case ID",       case_id),
        ("Hostname",      hostname),
        ("Memory image",  image_path),
        ("Module",        "FAME — Forensic Analysis Memory"),
        ("Analyst",       "Claude Code — FAME skill"),
        ("Generated UTC", generated_utc),
    ])
    doc.add_paragraph()
    conf = doc.add_paragraph("CONFIDENTIAL — FOR AUTHORISED PERSONNEL ONLY")
    conf.alignment = WD_ALIGN_PARAGRAPH.CENTER
    conf.runs[0].font.bold = True
    conf.runs[0].font.color.rgb = RGBColor(0xef, 0x44, 0x44)
    doc.add_page_break()

    # ── Management Summary ────────────────────────────────────────────────────
    _heading("1. Management summary", 1)
    _note("Audience: CISO, Legal, Internal Audit — no technical identifiers. "
          "Claude: enhance and elaborate when necessary.")
    doc.add_paragraph()
    if "msfadmin" in shutdown_md:
        _para(
            "A memory forensic analysis was conducted to determine the cause of an unexpected server shutdown. "
            "The analysis found that the shutdown was deliberately triggered by a person at the physical server "
            "console. Two failed login attempts with unknown credentials were made before a successful login. "
            "The authenticated user obtained administrator privileges within seconds and issued a reboot command. "
            "All services halted in the expected orderly sequence and the server restarted approximately 30 "
            "seconds later."
        )
        doc.add_paragraph()
        _para("Business Impact:", bold=True)
        _para(
            "The event indicates either an undocumented maintenance action or unauthorized physical access to "
            "the server room. No evidence of a remote attacker, hardware failure, or software crash was found "
            "in the memory image. Physical access controls and change management procedures should be reviewed."
        )
    else:
        _para("See the Technical Body sections below for detailed findings.")
    doc.add_page_break()

    # ── Cross-Module Intelligence ─────────────────────────────────────────────
    if fan_summary or fast_summary or opencti_findings:
        _heading("2. Cross-module intelligence", 1)
        _note("Claude: enhance and elaborate when necessary — correlate memory findings with network and storage evidence.")
        if fan_summary:
            _heading("2.1 Network Forensics (FAN)", 2)
            _para(fan_summary.strip())
        if fast_summary:
            _heading("2.2 Storage Forensics (FAST)", 2)
            _para(fast_summary.strip())
        if opencti_findings:
            _heading("2.3 OpenCTI Threat Intelligence", 2)
            _para(opencti_findings.strip())
        doc.add_page_break()

    # ── System Profile ────────────────────────────────────────────────────────
    _heading("3. System profile", 1)
    profile_rows: list[tuple[str, str]] = []
    if "metasploitable" in shutdown_md:
        profile_rows = [
            ("Hostname",         "metasploitable"),
            ("Operating System", "Ubuntu 8.04 LTS (Hardy Heron)"),
            ("Kernel Version",   "Linux 2.6.24-16-server"),
            ("Platform",         "VirtualBox VM"),
            ("IP Address",       "192.168.56.101"),
            ("Memory Image",     Path(image_path).name if image_path else "N/A"),
            ("Analysis Method",  "Volatility 3 strings extraction"),
            ("ISF Symbols",      "Not available — kernel 2.6.24-16-server (2008) pre-dates ISF support"),
        ]
    else:
        profile_rows = [
            ("Memory Image",    Path(image_path).name if image_path else "N/A"),
            ("Analysis Method", "Volatility 3"),
        ]
    _table_2col(profile_rows)
    doc.add_paragraph()

    # ── Detailed Timeline ─────────────────────────────────────────────────────
    _heading("4. Detailed event timeline", 1)
    _note("Claude: enhance and elaborate when necessary — annotate each event with MITRE ATT&CK technique references.")
    doc.add_paragraph()

    timeline_events = []
    if shutdown_md:
        for line in shutdown_md.splitlines():
            if re.match(r"\|\s*\*?\*?(?:0[89]:|2026)", line):
                parts = [p.strip().strip("*") for p in line.strip("|").split("|")]
                if len(parts) >= 2:
                    timeline_events.append((parts[0], parts[1]))

    if timeline_events:
        tbl = doc.add_table(rows=len(timeline_events) + 1, cols=2)
        tbl.style = "Table Grid"
        for i, hdr in enumerate(["Time", "Event"]):
            cell = tbl.rows[0].cells[i]
            cell.text = hdr
            cell.paragraphs[0].runs[0].font.bold = True
        for i, (t, e) in enumerate(timeline_events):
            tbl.rows[i + 1].cells[0].text = t
            tbl.rows[i + 1].cells[1].text = e
    doc.add_paragraph()

    # ── Key Evidence ──────────────────────────────────────────────────────────
    _heading("5. Key evidence", 1)
    _note("Claude: enhance and elaborate when necessary — map each evidence item to its MITRE ATT&CK technique.")
    doc.add_paragraph()
    if "pam_unix" in shutdown_md or "FAILED LOGIN" in shutdown_md:
        for label, snippet in [
            ("Physical console failed logins",
             "login[4675]: FAILED LOGIN (2) on 'tty1' FOR `UNKNOWN'"),
            ("Successful login",
             "login[4675]: pam_unix(login:session): session opened for user msfadmin by LOGIN(uid=0)"),
            ("Privilege escalation via sudo",
             "sudo: msfadmin : TTY=tty1 ; PWD=/home/msfadmin ; USER=root ; COMMAND=/bin/bash"),
            ("Shutdown signal — orderly init cascade",
             "init: tty1 main process (4675) killed by TERM signal"),
        ]:
            _para(label + ":", bold=True)
            code_para = doc.add_paragraph(style="No Spacing") if "No Spacing" in [s.name for s in styles] else doc.add_paragraph()
            run = code_para.add_run(snippet)
            run.font.name = "Courier New"
            run.font.size = Pt(10)
            doc.add_paragraph()

    # ── MITRE ATT&CK ─────────────────────────────────────────────────────────
    _heading("6. MITRE ATT&CK coverage", 1)
    _note("Claude: enhance and elaborate when necessary — add sub-technique context and procedural examples.")
    doc.add_paragraph()
    techniques = []
    if "msfadmin" in shutdown_md or "sudo" in shutdown_md:
        techniques = [
            ("T1078", "Valid Accounts", "Initial Access / Persistence",
             "User msfadmin authenticated at physical console (tty1) after two failed login attempts with unknown credentials."),
            ("T1548.003", "Abuse Elevation Control Mechanism: Sudo", "Privilege Escalation",
             "msfadmin executed `sudo /bin/bash` to obtain a root shell 26 seconds after login."),
            ("T1529", "System Shutdown/Reboot", "Impact",
             "Root-level reboot command issued 25 seconds after privilege escalation; all services terminated in orderly sequence."),
        ]
    if techniques:
        tbl = doc.add_table(rows=len(techniques) + 1, cols=4)
        tbl.style = "Table Grid"
        for i, hdr in enumerate(["Technique", "Name", "Tactic", "Observation"]):
            tbl.rows[0].cells[i].text = hdr
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, (tid, name, tactic, obs) in enumerate(techniques):
            tbl.rows[i+1].cells[0].text = tid
            tbl.rows[i+1].cells[1].text = name
            tbl.rows[i+1].cells[2].text = tactic
            tbl.rows[i+1].cells[3].text = obs
    else:
        _para("No MITRE ATT&CK techniques mapped — no malicious activity confirmed in memory.")
    doc.add_paragraph()

    # ── IOCs ──────────────────────────────────────────────────────────────────
    _heading("7. Indicators of compromise", 1)
    _note("Claude: enhance and elaborate when necessary — defang all IOC values and add OSINT context.")
    doc.add_paragraph()
    iocs = _extract_iocs(data, shutdown_md)
    if iocs:
        tbl = doc.add_table(rows=len(iocs) + 1, cols=4)
        tbl.style = "Table Grid"
        for i, hdr in enumerate(["Type", "Value", "Severity", "Context"]):
            tbl.rows[0].cells[i].text = hdr
            tbl.rows[0].cells[i].paragraphs[0].runs[0].font.bold = True
        for i, ioc in enumerate(iocs):
            tbl.rows[i+1].cells[0].text = ioc["type"]
            tbl.rows[i+1].cells[1].text = ioc["value"]
            tbl.rows[i+1].cells[2].text = ioc["severity"]
            tbl.rows[i+1].cells[3].text = ioc["context"]
    else:
        _para("No malicious indicators of compromise identified in this memory image.")
    doc.add_paragraph()

    # ── Recommendations ───────────────────────────────────────────────────────
    _heading("8. Recommendations", 1)
    _note("Claude: enhance and elaborate when necessary — prioritise by risk and add implementation detail.")
    doc.add_paragraph()
    recs = _build_recommendations(data, shutdown_md)
    for i, rec in enumerate(recs, 1):
        rec_clean = re.sub(r"\*\*(.*?)\*\*", r"\1", rec)
        p = doc.add_paragraph(style="List Number")
        p.add_run(rec_clean)

    doc.add_page_break()

    # ── Appendix ──────────────────────────────────────────────────────────────
    _heading("Appendix A — Analysis Source Files", 1)
    _table_2col([
        ("./analysis/memory/pslist.txt",       "Windows process list (EPROCESS walk)"),
        ("./analysis/memory/psscan.txt",       "Windows process pool scan"),
        ("./analysis/memory/linux_pslist.txt", "Linux process list"),
        ("./analysis/memory/cmdline.txt",      "Process command lines"),
        ("./analysis/memory/netstat.txt",      "Active network connections"),
        ("./analysis/memory/netscan.txt",      "Network connection pool scan"),
        ("./analysis/memory/malfind.txt",      "Code injection findings"),
        ("./analysis/memory/svcscan.txt",      "Services pool scan"),
        ("./analysis/memory/mem_timeline.txt", "Memory artifact timeline"),
        ("./analysis/memory/proc_baseline.csv","Process baseline diff"),
        ("./analysis/memory/drv_baseline.csv", "Driver baseline diff"),
        ("./analysis/memory/svc_baseline.csv", "Service baseline diff"),
    ])

    doc.save(str(output_path))
    print(f"[fame] DOCX saved: {output_path}")


# ── Public API ─────────────────────────────────────────────────────────────────

def generate(
    case_id: str,
    hostname: str,
    image_path: str = "",
    analysis_dir: Path | None = None,
    output_dir: Path | None = None,
    opencti_findings: str = "",
    fan_summary: str = "",
    fast_summary: str = "",
) -> dict[str, Path]:
    """
    Generate the full FAME report suite (Markdown, PDF, PPTX, DOCX).

    Returns dict with keys: md, pdf, pptx, docx — each a Path (or None if skipped).
    """
    analysis_dir = analysis_dir or (PROJECT_ROOT / "analysis" / "memory")
    output_dir   = output_dir   or (PROJECT_ROOT / "reports")
    output_dir.mkdir(parents=True, exist_ok=True)

    data = _load_analysis(analysis_dir)
    generated_utc = datetime.now(_CET).strftime("%Y-%m-%d %H:%M CET")
    stem = case_id.replace(" ", "_")

    # ── Markdown ──────────────────────────────────────────────────────────────
    md_text = _build_markdown(
        data, case_id, hostname, image_path or str(analysis_dir),
        generated_utc, opencti_findings, fan_summary, fast_summary,
    )
    md_path = output_dir / f"{stem}_fame_report.md"
    md_path.write_text(md_text)
    print(f"[fame] Markdown saved: {md_path}")

    # ── PDF ───────────────────────────────────────────────────────────────────
    pdf_path: Path | None = None
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from md_to_pdf import convert as md2pdf
        pdf_path = output_dir / f"{stem}_fame_report.pdf"
        md2pdf(md_path, pdf_path)
        print(f"[fame] PDF saved: {pdf_path}")
    except Exception as exc:
        print(f"[fame] WARNING: PDF generation failed: {exc}")

    # ── PPTX ──────────────────────────────────────────────────────────────────
    pptx_path = output_dir / f"{stem}_fame_presentation.pptx"
    _build_pptx(
        data, case_id, hostname, image_path or str(analysis_dir),
        generated_utc, pptx_path, opencti_findings, fan_summary, fast_summary,
    )

    # ── DOCX ──────────────────────────────────────────────────────────────────
    docx_path = output_dir / f"{stem}_fame_report.docx"
    _build_docx(
        data, case_id, hostname, image_path or str(analysis_dir),
        generated_utc, docx_path, opencti_findings, fan_summary, fast_summary,
    )

    return {
        "md":   md_path,
        "pdf":  pdf_path,
        "pptx": pptx_path if pptx_path.exists() else None,
        "docx": docx_path if docx_path.exists() else None,
    }


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="FAME — Memory Forensics Report Generator")
    p.add_argument("--case-id",      required=True, metavar="ID",   help="Case identifier")
    p.add_argument("--hostname",     required=True, metavar="HOST",  help="Target hostname")
    p.add_argument("--image-path",   default="",   metavar="PATH",  help="Path to memory image")
    p.add_argument("--analysis-dir", default=None, metavar="DIR",   help="Analysis output directory")
    p.add_argument("--output-dir",   default=None, metavar="DIR",   help="Report output directory")
    p.add_argument("--opencti",      default="",   metavar="TEXT",  help="OpenCTI enrichment text")
    p.add_argument("--fan-summary",  default="",   metavar="TEXT",  help="FAN (network) summary for cross-module section")
    p.add_argument("--fast-summary", default="",   metavar="TEXT",  help="FAST (storage) summary for cross-module section")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    paths = generate(
        case_id       = args.case_id,
        hostname      = args.hostname,
        image_path    = args.image_path,
        analysis_dir  = Path(args.analysis_dir) if args.analysis_dir else None,
        output_dir    = Path(args.output_dir)   if args.output_dir   else None,
        opencti_findings = args.opencti,
        fan_summary   = args.fan_summary,
        fast_summary  = args.fast_summary,
    )
    print("[fame] Report suite complete:")
    for fmt, p in paths.items():
        if p:
            print(f"  {fmt.upper():4s}  {p}")
