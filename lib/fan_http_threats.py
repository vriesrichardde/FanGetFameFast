#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fan_http_threats.py — CTI HTTP(S) Unusual Pattern Analyzer

Detects unusual or malicious HTTP/HTTPS patterns in a PCAP file using tshark
field extraction and Python heuristics. Covers 11 detection categories.

Detection categories:
  - Suspicious User-Agent          (T1071.001)
  - Unusual HTTP Methods           (T1071.001)
  - Scanning / Error Code Flood    (T1595)
  - Suspicious URI Patterns        (T1190)
  - Large HTTP Upload              (T1048.002)
  - Cookie Anomaly                 (T1048)
  - Host Header Anomaly            (T1557)
  - HTTP Beaconing                 (T1071.001)
  - Unusual HTTP Server            (T1071.001)
  - Suspicious Referer             (T1071.001)
  - Deprecated / Weak TLS Version  (T1040)

Usage:
  python3 fan_http_threats.py <pcap_file> [--stem NAME] [--case-id ID]
                               [--output-dir DIR] [--no-vault]
"""

from __future__ import annotations

import argparse
import csv
import json
import math
import re
import statistics
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------
SCANNING_MIN_ERRORS        = 50      # 4xx/5xx from single source to flag scanning
BEACON_MIN_REQUESTS        = 10      # Minimum request count for beaconing analysis
BEACON_MAX_CV              = 0.30    # Max coefficient of variation (stdev/mean)
BEACON_MIN_INTERVAL_SEC    = 5.0     # Ignore sub-5s intervals (retry noise)
LARGE_UPLOAD_MIN_BYTES     = 500_000 # Content-Length / frame threshold for large upload
COOKIE_MIN_LENGTH          = 4096    # Cookie header length to flag
COOKIE_ENTROPY_THRESHOLD   = 4.5     # Shannon entropy on cookie value
URI_MAX_LENGTH             = 2048    # URI length threshold
UA_MAX_LENGTH              = 512     # User-Agent length threshold
REFERER_MAX_LENGTH         = 500     # Referer length threshold
TLS_OLD_VERSIONS           = {0x0200, 0x0300, 0x0301, 0x0302}  # SSL2, SSL3, TLS1.0, TLS1.1

# ---------------------------------------------------------------------------
# Classification constants
# ---------------------------------------------------------------------------

STANDARD_METHODS = frozenset({
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH",
})

# Suspicious method groups
WEBDAV_METHODS = frozenset({
    "PROPFIND", "PROPPATCH", "MKCOL", "COPY", "MOVE",
    "LOCK", "UNLOCK", "SEARCH", "REPORT",
})

# Substring patterns for suspicious user agents (case-insensitive key → description)
SUSPICIOUS_UA_PATTERNS: dict[str, str] = {
    "curl":             "command-line HTTP client",
    "wget":             "command-line HTTP client",
    "python-requests":  "Python HTTP library",
    "python-urllib":    "Python HTTP library",
    "python/":          "Python HTTP library",
    "go-http-client":   "Go HTTP client",
    "libwww-perl":      "Perl HTTP library",
    "lwp-":             "Perl HTTP library",
    "java/":            "Java HTTP client",
    "powershell":       "PowerShell HTTP client",
    "invoke-webrequest": "PowerShell HTTP client",
    "nmap":             "network scanner",
    "nikto":            "web vulnerability scanner",
    "sqlmap":           "SQL injection tool",
    "masscan":          "mass IP scanner",
    "zgrab":            "network scanner",
    "nuclei":           "vulnerability scanner",
    "dirbuster":        "directory brute-forcer",
    "gobuster":         "directory brute-forcer",
    "wfuzz":            "web fuzzer",
    "burpsuite":        "web proxy/scanner",
    "openvas":          "vulnerability scanner",
    "acunetix":         "web vulnerability scanner",
    "metasploit":       "exploit framework",
    "havoc":            "C2 framework",
    "sliver":           "C2 framework",
    "empire":           "C2 framework",
    "cobalt strike":    "C2 framework",
    "meterpreter":      "Metasploit payload",
    "beef":             "browser exploit framework",
    "hydra":            "brute-force tool",
    "medusa":           "brute-force tool",
    "aircrack":         "wireless attack tool",
}

# Path traversal sequences
TRAVERSAL_RE = re.compile(
    r"(\.\./|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f|%252e|\.\.%5c)",
    re.IGNORECASE,
)

# SQL injection heuristics (common keywords in URI context)
SQLI_RE = re.compile(
    r"(union\s+select|'\s*or\s+|'\s*--|\bexec\s*\(|xp_cmdshell|"
    r"waitfor\s+delay|sleep\s*\(|benchmark\s*\(|1=1|or\s+1\s*=\s*1)",
    re.IGNORECASE,
)

# XSS patterns
XSS_RE = re.compile(
    r"(<script|javascript:|vbscript:|onerror\s*=|onload\s*=|"
    r"onmouseover\s*=|alert\s*\(|document\.cookie|eval\s*\()",
    re.IGNORECASE,
)

# Command injection patterns
CMD_RE = re.compile(
    r"(;(cat|ls|id|whoami|uname|pwd|wget|curl)\s|"
    r"\|\s*(id|cat|ls|whoami)|\$\(id\)|`id`|"
    r"/etc/passwd|/etc/shadow|/etc/hosts\b)",
    re.IGNORECASE,
)

# Known admin / sensitive paths
ADMIN_PATH_RE = re.compile(
    r"(/admin|/administrator|/wp-login|/wp-admin|/phpmyadmin|"
    r"/manager/html|/manager/text|/console|/actuator|"
    r"/swagger-ui|/api/v[0-9]/|/xmlrpc\.php|/\.env|/\.git/|"
    r"/web\.config|/config\.php|/\.htaccess|/server-status|"
    r"/\.well-known/|/cgi-bin/)",
    re.IGNORECASE,
)

# Suspicious server header substrings (case-insensitive)
SUSPICIOUS_SERVER_PATTERNS: dict[str, str] = {
    "metasploit":  "Metasploit Framework",
    "empire":      "PowerShell Empire C2",
    "sliver":      "Sliver C2 Framework",
    "havoc":       "Havoc C2 Framework",
    "covenant":    "Covenant C2 Framework",
    "cobalt":      "Cobalt Strike C2",
    "meterpreter": "Meterpreter payload",
    "beef":        "BeEF browser exploit framework",
}

# IP address regex (for Host header anomaly detection)
IP_HOST_RE = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$")

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

TLS_VERSION_NAMES = {
    0x0200: "SSL 2.0",
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}


# ---------------------------------------------------------------------------
# tshark extraction
# ---------------------------------------------------------------------------

def _run_tshark(pcap: Path, display_filter: str, fields: list[str]) -> list[dict]:
    cmd = [
        "tshark", "-r", str(pcap),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "quote=n",
        "-E", "occurrence=f",
    ]
    for f in fields:
        cmd += ["-e", f]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
    except FileNotFoundError:
        print("[ERROR] tshark not found on PATH.", file=sys.stderr)
        sys.exit(1)
    except subprocess.CalledProcessError as e:
        print(f"[WARN] tshark: {e.stderr.strip()[:200]}", file=sys.stderr)
        return []

    rows = []
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        while len(parts) < len(fields):
            parts.append("")
        rows.append(dict(zip(fields, [p.strip() for p in parts])))
    return rows


def extract_http_requests(pcap: Path) -> list[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport",
        "http.request.method", "http.request.uri",
        "http.host", "http.user_agent",
        "http.referer", "http.cookie",
        "http.content_length", "frame.len",
    ]
    rows = _run_tshark(pcap, "http.request", fields)
    records = []
    for r in rows:
        try:
            ts = float(r["frame.time_epoch"]) if r["frame.time_epoch"] else 0.0
        except ValueError:
            ts = 0.0
        cl = r.get("http.content_length", "")
        try:
            content_len = int(cl) if cl else 0
        except ValueError:
            content_len = 0

        records.append({
            "timestamp":    ts,
            "src_ip":       r["ip.src"],
            "dst_ip":       r["ip.dst"],
            "src_port":     r.get("tcp.srcport", ""),
            "dst_port":     r.get("tcp.dstport", ""),
            "direction":    "request",
            "method":       r["http.request.method"].upper(),
            "uri":          r["http.request.uri"],
            "host":         r.get("http.host", ""),
            "user_agent":   r.get("http.user_agent", ""),
            "referer":      r.get("http.referer", ""),
            "cookie":       r.get("http.cookie", ""),
            "content_length": content_len,
            "frame_len":    int(r.get("frame.len", 0) or 0),
            "status_code":  "",
            "server":       "",
        })
    return records


def extract_http_responses(pcap: Path) -> list[dict]:
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tcp.srcport", "tcp.dstport",
        "http.response.code", "http.server",
        "http.content_length", "frame.len",
    ]
    rows = _run_tshark(pcap, "http.response", fields)
    records = []
    for r in rows:
        try:
            ts = float(r["frame.time_epoch"]) if r["frame.time_epoch"] else 0.0
        except ValueError:
            ts = 0.0
        cl = r.get("http.content_length", "")
        try:
            content_len = int(cl) if cl else 0
        except ValueError:
            content_len = 0

        records.append({
            "timestamp":    ts,
            "src_ip":       r["ip.src"],
            "dst_ip":       r["ip.dst"],
            "src_port":     r.get("tcp.srcport", ""),
            "dst_port":     r.get("tcp.dstport", ""),
            "direction":    "response",
            "method":       "",
            "uri":          "",
            "host":         "",
            "user_agent":   "",
            "referer":      "",
            "cookie":       "",
            "content_length": content_len,
            "frame_len":    int(r.get("frame.len", 0) or 0),
            "status_code":  r.get("http.response.code", ""),
            "server":       r.get("http.server", ""),
        })
    return records


def extract_tls_hellos(pcap: Path) -> list[dict]:
    """Extract TLS Client Hello records to detect deprecated TLS versions."""
    fields = [
        "frame.time_epoch", "ip.src", "ip.dst",
        "tls.handshake.version",
        "tls.handshake.extensions_server_name",
    ]
    rows = _run_tshark(pcap, "tls.handshake.type == 1", fields)
    records = []
    for r in rows:
        try:
            ts = float(r["frame.time_epoch"]) if r["frame.time_epoch"] else 0.0
        except ValueError:
            ts = 0.0
        ver_raw = r.get("tls.handshake.version", "")
        try:
            ver = int(ver_raw, 16) if ver_raw.startswith("0x") else int(ver_raw, 0)
        except (ValueError, TypeError):
            ver = 0
        records.append({
            "timestamp": ts,
            "src_ip":    r["ip.src"],
            "dst_ip":    r["ip.dst"],
            "version":   ver,
            "sni":       r.get("tls.handshake.extensions_server_name", ""),
        })
    return records


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts_utc(epoch: float) -> str:
    if not epoch:
        return ""
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    total = len(s)
    return -sum((v / total) * math.log2(v / total) for v in freq.values())


def _uri_path(uri: str) -> str:
    """Return only the path component of a URI (strip query string and fragment)."""
    for ch in ("?", "#"):
        idx = uri.find(ch)
        if idx != -1:
            uri = uri[:idx]
    return uri


def _result(name: str, severity: str, mitre: list[str],
            findings: list, description: str) -> dict:
    return {
        "name":        name,
        "severity":    severity,
        "count":       len(findings),
        "mitre":       mitre,
        "findings":    findings,
        "description": description,
    }


# ---------------------------------------------------------------------------
# Detection functions — requests
# ---------------------------------------------------------------------------

def detect_suspicious_ua(requests: list[dict]) -> dict:
    """
    User-Agent strings matching known offensive tools, C2 frameworks, scanners,
    or automation clients that should not appear in normal browser traffic (T1071.001).
    Also flags empty, missing, or abnormally long UAs.
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        ua = r.get("user_agent", "")
        ua_lower = ua.lower()
        src = r["src_ip"]

        # Empty or missing UA
        if not ua:
            key = ("empty_ua", src)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "indicator":   "Empty/missing User-Agent",
                    "src_ip":      src,
                    "dst_ip":      r["dst_ip"],
                    "host":        r["host"],
                    "uri":         r["uri"][:120],
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })
            continue

        # Abnormally long UA
        if len(ua) > UA_MAX_LENGTH:
            key = ("long_ua", src)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "indicator":   f"Abnormally long User-Agent ({len(ua)} chars)",
                    "src_ip":      src,
                    "dst_ip":      r["dst_ip"],
                    "user_agent":  ua[:200] + "...",
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })
            continue

        # Known suspicious tool / framework
        for pattern, description in SUSPICIOUS_UA_PATTERNS.items():
            if pattern in ua_lower:
                key = (pattern, src)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "indicator":   f"{description} ({pattern})",
                        "src_ip":      src,
                        "dst_ip":      r["dst_ip"],
                        "host":        r["host"],
                        "user_agent":  ua[:200],
                        "timestamp_utc": _ts_utc(r["timestamp"]),
                    })
                break

    sev = "info"
    if findings:
        # C2/exploit framework UAs are critical
        c2_keywords = {"c2 framework", "exploit framework", "metasploit payload",
                       "c2", "Metasploit", "beef"}
        if any(any(kw in f.get("indicator", "").lower() for kw in c2_keywords)
               for f in findings):
            sev = "critical"
        else:
            sev = "high"

    return _result(
        "Suspicious User-Agent",
        sev,
        ["T1071.001", "Application Layer Protocol: Web Protocols"],
        findings,
        f"Unusual or tool-specific User-Agent strings from {len(findings)} source(s). "
        "Includes known scanners, exploit frameworks, C2 beacons, and automation clients "
        "that deviate from expected browser traffic.",
    )


def detect_unusual_methods(requests: list[dict]) -> dict:
    """
    HTTP methods outside the standard set (GET/POST/HEAD/PUT/DELETE/OPTIONS/PATCH).
    Includes WebDAV methods (PROPFIND, MKCOL, etc.) and TRACE/CONNECT abuse (T1071.001).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        method = r.get("method", "")
        if not method or method in STANDARD_METHODS:
            continue

        category = "WebDAV method" if method in WEBDAV_METHODS else "Non-standard method"
        if method == "TRACE":
            category = "TRACE (Cross-Site Tracing)"
        elif method == "CONNECT":
            category = "CONNECT (potential tunnel/proxy abuse)"

        key = (method, r["src_ip"])
        if key not in seen:
            seen.add(key)
            findings.append({
                "method":      method,
                "category":    category,
                "src_ip":      r["src_ip"],
                "dst_ip":      r["dst_ip"],
                "host":        r["host"],
                "uri":         r["uri"][:120],
                "timestamp_utc": _ts_utc(r["timestamp"]),
            })

    sev = "info"
    if findings:
        # TRACE and custom methods are higher risk
        high_risk = {"TRACE", "CONNECT"} | (WEBDAV_METHODS)
        if any(f["method"] in high_risk for f in findings):
            sev = "medium"
        else:
            sev = "low"
        if any(f["method"] == "TRACE" for f in findings):
            sev = "high"

    return _result(
        "Unusual HTTP Methods",
        sev,
        ["T1071.001", "Application Layer Protocol: Web Protocols"],
        findings,
        f"Non-standard HTTP methods from {len(findings)} unique (method, source) pair(s). "
        "TRACE enables Cross-Site Tracing (XST); WebDAV methods may indicate file system "
        "access or exploitation of WebDAV-enabled servers.",
    )


def detect_suspicious_uri(requests: list[dict]) -> dict:
    """
    URI patterns indicative of web exploitation: path traversal, SQL injection,
    XSS, command injection, admin probing, and buffer overflow attempts (T1190).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        uri = r.get("uri", "")
        if not uri:
            continue

        categories = []

        if TRAVERSAL_RE.search(uri):
            categories.append("Path Traversal")
        if SQLI_RE.search(uri):
            categories.append("SQL Injection")
        if XSS_RE.search(uri):
            categories.append("XSS Attempt")
        if CMD_RE.search(uri):
            categories.append("Command Injection")
        if ADMIN_PATH_RE.search(_uri_path(uri)):
            categories.append("Admin/Sensitive Path Probe")
        if len(uri) > URI_MAX_LENGTH:
            categories.append(f"Abnormally Long URI ({len(uri)} chars)")
        if "\x00" in uri or "%00" in uri.lower():
            categories.append("Null Byte Injection")

        if categories:
            key = (r["src_ip"], _uri_path(uri)[:80])
            if key not in seen:
                seen.add(key)
                findings.append({
                    "categories":  categories,
                    "src_ip":      r["src_ip"],
                    "dst_ip":      r["dst_ip"],
                    "host":        r["host"],
                    "method":      r["method"],
                    "uri":         uri[:250],
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    sev = "info"
    if findings:
        exploit_cats = {"SQL Injection", "Command Injection", "XSS Attempt",
                        "Path Traversal", "Null Byte Injection"}
        if any(set(f["categories"]) & exploit_cats for f in findings):
            sev = "critical"
        else:
            sev = "medium"

    return _result(
        "Suspicious URI Patterns",
        sev,
        ["T1190", "Exploit Public-Facing Application"],
        findings,
        f"Malicious URI patterns detected from {len(findings)} unique (source, path) pair(s). "
        "Includes path traversal, injection attacks, admin/config probing, and buffer overflow "
        "attempts in HTTP request URIs.",
    )


def detect_scanning_codes(responses: list[dict]) -> dict:
    """
    High volume of HTTP 4xx/5xx responses to a single client IP — characteristic
    of automated scanning, brute force, or exploitation probing (T1595).
    """
    # For responses: src_ip = server, dst_ip = client
    # We want to count error responses per client (dst_ip)
    client_codes: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in responses:
        code = r.get("status_code", "")
        if not code:
            continue
        try:
            code_int = int(code)
        except ValueError:
            continue
        if code_int >= 400:
            client_codes[r["dst_ip"]][code] += 1

    findings = []
    for client, code_counts in client_codes.items():
        total_errors = sum(code_counts.values())
        if total_errors < SCANNING_MIN_ERRORS:
            continue
        top_codes = sorted(code_counts.items(), key=lambda x: x[1], reverse=True)[:5]
        findings.append({
            "client_ip":    client,
            "total_errors": total_errors,
            "code_breakdown": dict(top_codes),
        })

    findings.sort(key=lambda x: x["total_errors"], reverse=True)
    return _result(
        "HTTP Scanning / Error Code Flood",
        "high" if findings else "info",
        ["T1595", "Active Scanning"],
        findings,
        f"High volumes of HTTP 4xx/5xx error responses to {len(findings)} client IP(s) "
        f"(threshold: ≥{SCANNING_MIN_ERRORS}). Indicates automated web scanning, "
        "directory brute-forcing, or vulnerability probing.",
    )


def detect_large_upload(requests: list[dict]) -> dict:
    """
    Large HTTP POST/PUT requests exceeding threshold — potential data staging
    or exfiltration over HTTP (T1048.002).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        if r["method"] not in ("POST", "PUT", "PATCH"):
            continue
        size = max(r["content_length"], r["frame_len"])
        if size < LARGE_UPLOAD_MIN_BYTES:
            continue
        key = (r["src_ip"], _uri_path(r["uri"])[:60])
        if key not in seen:
            seen.add(key)
            findings.append({
                "src_ip":      r["src_ip"],
                "dst_ip":      r["dst_ip"],
                "host":        r["host"],
                "method":      r["method"],
                "uri":         r["uri"][:120],
                "size_bytes":  size,
                "timestamp_utc": _ts_utc(r["timestamp"]),
            })

    findings.sort(key=lambda x: x["size_bytes"], reverse=True)
    return _result(
        "Large HTTP Upload",
        "high" if findings else "info",
        ["T1048.002", "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"],
        findings,
        f"Large HTTP POST/PUT/PATCH requests (≥{LARGE_UPLOAD_MIN_BYTES:,} B) from "
        f"{len(findings)} unique (source, path) pair(s). May indicate data staging, "
        "file upload to attacker-controlled server, or exfiltration via HTTP.",
    )


def detect_cookie_anomaly(requests: list[dict]) -> dict:
    """
    Cookies with abnormal size or high-entropy values — potential data
    exfiltration or session token hijacking over cookies (T1048).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        cookie = r.get("cookie", "")
        if not cookie:
            continue

        reasons = []
        if len(cookie) >= COOKIE_MIN_LENGTH:
            reasons.append(f"Oversized cookie ({len(cookie)} chars)")

        # Check entropy of cookie values (strip name= prefixes)
        values = [p.split("=", 1)[1] if "=" in p else p
                  for p in cookie.split(";")]
        max_ent = max((_entropy(v.strip()) for v in values if v.strip()), default=0)
        if max_ent >= COOKIE_ENTROPY_THRESHOLD:
            reasons.append(f"High-entropy cookie value (entropy={max_ent:.2f})")

        if reasons:
            key = (r["src_ip"], r["host"])
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":      r["src_ip"],
                    "dst_ip":      r["dst_ip"],
                    "host":        r["host"],
                    "uri":         r["uri"][:120],
                    "reasons":     reasons,
                    "cookie_len":  len(cookie),
                    "max_entropy": round(max_ent, 2),
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    return _result(
        "HTTP Cookie Anomaly",
        "high" if findings else "info",
        ["T1048", "Exfiltration Over Alternative Protocol"],
        findings,
        f"Anomalous HTTP Cookie headers from {len(findings)} (source, host) pair(s). "
        f"Oversized cookies (≥{COOKIE_MIN_LENGTH} chars) or high-entropy values "
        f"(entropy ≥{COOKIE_ENTROPY_THRESHOLD}) may indicate data exfiltration or "
        "encoded payload delivery via cookie headers.",
    )


def detect_host_header_anomaly(requests: list[dict]) -> dict:
    """
    Suspicious Host header values: bare IP addresses (bypasses virtual hosting,
    suggests direct server targeting) or malformed values (T1557).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        host = r.get("host", "")
        if not host:
            continue

        reason = None
        if IP_HOST_RE.match(host):
            reason = f"IP address in Host header: {host}"
        elif not host:
            reason = "Empty Host header"
        elif len(host) > 253:
            reason = f"Abnormally long Host header ({len(host)} chars)"
        elif any(c in host for c in ("<", ">", "'", '"', "\x00", "\n", "\r")):
            reason = "Special characters in Host header (injection attempt)"

        if reason:
            key = (r["src_ip"], host)
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":      r["src_ip"],
                    "dst_ip":      r["dst_ip"],
                    "host_header": host,
                    "uri":         r["uri"][:120],
                    "reason":      reason,
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    sev = "info"
    if findings:
        if any("injection" in f["reason"].lower() for f in findings):
            sev = "high"
        else:
            sev = "medium"

    return _result(
        "Host Header Anomaly",
        sev,
        ["T1557", "Adversary-in-the-Middle"],
        findings,
        f"Unusual HTTP Host header values from {len(findings)} (source, host) pair(s). "
        "Bare IP addresses bypass virtual host routing; special characters indicate "
        "Host header injection attempts targeting SSRF or cache poisoning.",
    )


def detect_http_beaconing(requests: list[dict]) -> dict:
    """
    Regular-interval HTTP requests from the same client to the same path —
    characteristic of malware C2 communication over HTTP (T1071.001).
    """
    # Group by (src_ip, host, uri_path) — strip query params
    groups: dict[tuple, list[float]] = defaultdict(list)
    for r in requests:
        path = _uri_path(r.get("uri", "") or "")
        key = (r["src_ip"], r.get("host", ""), path)
        if r["timestamp"] > 0:
            groups[key].append(r["timestamp"])

    findings = []
    for (src, host, path), timestamps in groups.items():
        if len(timestamps) < BEACON_MIN_REQUESTS:
            continue
        ts_sorted = sorted(timestamps)
        intervals = [ts_sorted[i+1] - ts_sorted[i] for i in range(len(ts_sorted)-1)]
        # Filter out sub-threshold intervals
        intervals = [iv for iv in intervals if iv >= BEACON_MIN_INTERVAL_SEC]
        if len(intervals) < 3:
            continue
        mean_iv = statistics.mean(intervals)
        stdev_iv = statistics.stdev(intervals) if len(intervals) >= 2 else float("inf")
        cv = stdev_iv / mean_iv if mean_iv > 0 else float("inf")
        if cv <= BEACON_MAX_CV:
            findings.append({
                "src_ip":         src,
                "host":           host,
                "uri_path":       path[:120],
                "request_count":  len(timestamps),
                "mean_interval_sec": round(mean_iv, 1),
                "stdev_sec":      round(stdev_iv, 1),
                "cv":             round(cv, 3),
                "first_seen":     _ts_utc(ts_sorted[0]),
                "last_seen":      _ts_utc(ts_sorted[-1]),
            })

    findings.sort(key=lambda x: x["cv"])
    sev = "critical" if findings else "info"
    return _result(
        "HTTP Beaconing",
        sev,
        ["T1071.001", "Application Layer Protocol: Web Protocols"],
        findings,
        f"Regular-interval HTTP requests from {len(findings)} (source, path) pair(s). "
        f"Coefficient of variation ≤ {BEACON_MAX_CV} over ≥ {BEACON_MIN_REQUESTS} "
        "requests indicates machine-driven, clock-like polling consistent with C2 "
        "beaconing behaviour.",
    )


def detect_unusual_server(responses: list[dict]) -> dict:
    """
    HTTP Server response headers matching known C2/exploit framework signatures
    or exposing version information that reveals vulnerable software (T1071.001).
    """
    findings = []
    seen: set[tuple] = set()

    for r in responses:
        server = r.get("server", "")
        if not server:
            continue
        server_lower = server.lower()

        for pattern, framework in SUSPICIOUS_SERVER_PATTERNS.items():
            if pattern in server_lower:
                key = (r["src_ip"], pattern)
                if key not in seen:
                    seen.add(key)
                    findings.append({
                        "src_ip":      r["src_ip"],
                        "dst_ip":      r["dst_ip"],
                        "server_header": server[:200],
                        "matched":     framework,
                        "timestamp_utc": _ts_utc(r["timestamp"]),
                    })
                break

    return _result(
        "Unusual HTTP Server Header",
        "critical" if findings else "info",
        ["T1071.001", "Application Layer Protocol: Web Protocols"],
        findings,
        f"HTTP Server headers matching known C2/exploit framework signatures from "
        f"{len(findings)} server IP(s). Server headers containing Metasploit, Empire, "
        "Sliver, Havoc, or similar names indicate attacker-controlled infrastructure.",
    )


def detect_suspicious_referer(requests: list[dict]) -> dict:
    """
    HTTP Referer headers with injection patterns, abnormal length, or other
    anomalies that may indicate CSRF exploitation or header injection (T1071.001).
    """
    findings = []
    seen: set[tuple] = set()

    for r in requests:
        referer = r.get("referer", "")
        if not referer:
            continue

        reasons = []

        if len(referer) > REFERER_MAX_LENGTH:
            reasons.append(f"Abnormally long Referer ({len(referer)} chars)")
        if SQLI_RE.search(referer):
            reasons.append("SQL injection pattern in Referer")
        if XSS_RE.search(referer):
            reasons.append("XSS pattern in Referer")
        if TRAVERSAL_RE.search(referer):
            reasons.append("Path traversal in Referer")
        if any(c in referer for c in ("\x00", "\r", "\n")):
            reasons.append("Null byte or CRLF injection in Referer")

        if reasons:
            key = (r["src_ip"], referer[:80])
            if key not in seen:
                seen.add(key)
                findings.append({
                    "src_ip":      r["src_ip"],
                    "dst_ip":      r["dst_ip"],
                    "host":        r["host"],
                    "referer":     referer[:250],
                    "reasons":     reasons,
                    "timestamp_utc": _ts_utc(r["timestamp"]),
                })

    sev = "info"
    if findings:
        if any("injection" in r.lower() or "xss" in r.lower() or "traversal" in r.lower()
               for f in findings for r in f["reasons"]):
            sev = "high"
        else:
            sev = "medium"

    return _result(
        "Suspicious HTTP Referer",
        sev,
        ["T1071.001", "Application Layer Protocol: Web Protocols"],
        findings,
        f"Anomalous HTTP Referer headers from {len(findings)} (source, referer) pair(s). "
        "Injection patterns in Referer may indicate attempts to exploit logging "
        "systems, CSRF chains, or log injection attacks.",
    )


# ---------------------------------------------------------------------------
# Detection function — TLS
# ---------------------------------------------------------------------------

def detect_old_tls(tls_records: list[dict]) -> dict:
    """
    TLS Client Hellos advertising deprecated protocol versions (SSL 2.0, SSL 3.0,
    TLS 1.0, TLS 1.1) — vulnerable to known attacks (POODLE, BEAST, DROWN) (T1040).
    """
    findings = []
    seen: set[tuple] = set()

    for r in tls_records:
        ver = r.get("version", 0)
        if ver not in TLS_OLD_VERSIONS or ver == 0:
            continue
        ver_name = TLS_VERSION_NAMES.get(ver, f"0x{ver:04x}")
        key = (r["src_ip"], ver)
        if key not in seen:
            seen.add(key)
            findings.append({
                "src_ip":       r["src_ip"],
                "dst_ip":       r["dst_ip"],
                "tls_version":  ver_name,
                "sni":          r.get("sni", ""),
                "timestamp_utc": _ts_utc(r["timestamp"]),
            })

    sev = "info"
    if findings:
        versions_seen = {f["tls_version"] for f in findings}
        if "SSL 2.0" in versions_seen or "SSL 3.0" in versions_seen:
            sev = "critical"
        elif "TLS 1.0" in versions_seen:
            sev = "high"
        else:
            sev = "medium"

    return _result(
        "Deprecated TLS Version",
        sev,
        ["T1040", "Network Sniffing"],
        findings,
        f"Deprecated TLS/SSL versions in {len(findings)} unique (source, version) pair(s). "
        "SSL 2.0/3.0 are vulnerable to DROWN/POODLE; TLS 1.0 to BEAST/CRIME. "
        "Presence may indicate legacy systems or deliberate downgrade attacks.",
    )


# ---------------------------------------------------------------------------
# Analysis entry point
# ---------------------------------------------------------------------------

_DETECTOR_KEYS_REQUEST = [
    (detect_suspicious_ua,      "suspicious_ua"),
    (detect_unusual_methods,    "unusual_methods"),
    (detect_suspicious_uri,     "suspicious_uri"),
    (detect_large_upload,       "large_upload"),
    (detect_cookie_anomaly,     "cookie_anomaly"),
    (detect_host_header_anomaly, "host_header_anomaly"),
    (detect_http_beaconing,     "http_beaconing"),
    (detect_suspicious_referer, "suspicious_referer"),
]

_DETECTOR_KEYS_RESPONSE = [
    (detect_scanning_codes,   "scanning_codes"),
    (detect_unusual_server,   "unusual_server"),
]

_DETECTOR_KEYS_TLS = [
    (detect_old_tls,  "old_tls"),
]


def analyze(pcap_path: Path) -> tuple[dict, list[dict], list[dict]]:
    print(f"[*] Extracting HTTP requests from {pcap_path} ...", file=sys.stderr)
    requests = extract_http_requests(pcap_path)
    print(f"[*] {len(requests)} HTTP request packets extracted.", file=sys.stderr)

    print(f"[*] Extracting HTTP responses ...", file=sys.stderr)
    responses = extract_http_responses(pcap_path)
    print(f"[*] {len(responses)} HTTP response packets extracted.", file=sys.stderr)

    print(f"[*] Extracting TLS Client Hellos ...", file=sys.stderr)
    tls_records = extract_tls_hellos(pcap_path)
    print(f"[*] {len(tls_records)} TLS Client Hello packets extracted.", file=sys.stderr)

    if not requests and not responses:
        print("[WARN] No HTTP records found — verify PCAP has cleartext HTTP traffic.",
              file=sys.stderr)

    results: dict[str, dict] = {}
    for fn, key in _DETECTOR_KEYS_REQUEST:
        print(f"  [*] {fn.__name__} ...", file=sys.stderr)
        results[key] = fn(requests)
    for fn, key in _DETECTOR_KEYS_RESPONSE:
        print(f"  [*] {fn.__name__} ...", file=sys.stderr)
        results[key] = fn(responses)
    for fn, key in _DETECTOR_KEYS_TLS:
        print(f"  [*] {fn.__name__} ...", file=sys.stderr)
        results[key] = fn(tls_records)

    all_records = requests + responses
    all_records.sort(key=lambda r: r["timestamp"])
    return results, all_records, tls_records


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------

def write_csv(all_records: list[dict], out_path: Path) -> None:
    headers = [
        "timestamp_utc", "src_ip", "dst_ip", "src_port", "dst_port",
        "direction", "method", "uri", "host", "status_code",
        "user_agent", "referer", "server", "content_length", "frame_len",
    ]
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(headers)
        for r in all_records:
            w.writerow([
                _ts_utc(r["timestamp"]),
                r["src_ip"], r["dst_ip"],
                r.get("src_port", ""), r.get("dst_port", ""),
                r["direction"], r.get("method", ""),
                r.get("uri", "")[:300], r.get("host", ""),
                r.get("status_code", ""), r.get("user_agent", "")[:200],
                r.get("referer", "")[:200], r.get("server", ""),
                r.get("content_length", 0), r.get("frame_len", 0),
            ])


def write_json(results: dict, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def write_report(results: dict, out_path: Path,
                 pcap_path: Path, case_id: str = "") -> None:
    now_utc = datetime.now(tz=timezone.utc).isoformat()
    lines = [
        "# HTTP(S) Unusual Patterns Report",
        "",
        f"**PCAP:** `{pcap_path.name}`  ",
        f"**Generated:** {now_utc}  ",
    ]
    if case_id:
        lines.append(f"**Case ID:** {case_id}  ")

    lines += ["", "---", "", "## Severity Summary", "",
              "| Severity | Category | Count |",
              "|----------|----------|-------|"]

    ordered = sorted(results.items(),
                     key=lambda kv: SEVERITY_ORDER.get(kv[1]["severity"], 99))
    for _, r in ordered:
        if r["severity"] == "info":
            continue
        lines.append(f"| {r['severity'].upper()} | {r['name']} | {r['count']} |")

    lines += ["", "---", ""]

    for _, r in ordered:
        if r["severity"] == "info":
            continue
        mitre_str = " / ".join(r["mitre"])
        lines += [
            f"## {r['name']}",
            "",
            f"**Severity:** {r['severity'].upper()}  ",
            f"**MITRE ATT&CK:** {mitre_str}  ",
            f"**Findings:** {r['count']}  ",
            "",
            r["description"],
            "",
            "```json",
        ]
        for finding in r["findings"][:10]:
            lines.append(json.dumps(finding, default=str))
        lines += ["```", ""]

    clean = [r["name"] for r in results.values() if r["severity"] == "info"]
    if clean:
        lines += ["---", "", "## Clean / No Findings", ""]
        for name in clean:
            lines.append(f"- {name}")
        lines.append("")

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text("\n".join(lines), encoding="utf-8")


def _mitre_tactic(mitre_id: str) -> str:
    mapping = {
        "T1071": "command-and-control",
        "T1595": "reconnaissance",
        "T1190": "initial-access",
        "T1048": "exfiltration",
        "T1557": "credential-access",
        "T1040": "credential-access",
    }
    for prefix, tactic in mapping.items():
        if mitre_id.startswith(prefix):
            return tactic
    return "unknown"


def save_to_vault(results: dict, pcap_path: Path, case_id: str = "") -> None:
    try:
        sys.path.insert(0, str(Path(__file__).parent))
        from knowledge_extractor import record_ttp, record_ioc  # type: ignore
    except ImportError:
        print("[WARN] knowledge_extractor not available — skipping vault writes.",
              file=sys.stderr)
        return

    HIGH_SEVS = {"critical", "high"}
    for r in results.values():
        if r["severity"] not in HIGH_SEVS:
            continue
        mitre_id   = r["mitre"][0] if r["mitre"] else ""
        mitre_name = r["mitre"][1] if len(r["mitre"]) > 1 else r["name"]
        evidence   = (f"{r['name']}: {r['count']} finding(s) in {pcap_path.name}. "
                      f"{r['description']}")
        if mitre_id:
            record_ttp(mitre_id, mitre_name, evidence,
                       case_id or "unknown",
                       tactic=_mitre_tactic(mitre_id))

        for finding in r["findings"][:5]:
            ip = (finding.get("src_ip") or finding.get("client_ip"))
            if ip:
                record_ioc(
                    "ip", ip,
                    f"{r['name']} — {r['description'][:100]}",
                    case_id or "unknown",
                    severity=r["severity"],
                    related_ttps=[f"{mitre_id} {mitre_name}"] if mitre_id else [],
                )
            # Record suspicious hosts as domain IOCs
            host = finding.get("host")
            if host and "." in host and not IP_HOST_RE.match(host):
                record_ioc(
                    "domain", host,
                    f"{r['name']} — observed in HTTP traffic",
                    case_id or "unknown",
                    severity=r["severity"],
                )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze a PCAP for unusual HTTP/HTTPS patterns.")
    parser.add_argument("pcap", type=Path, help="Path to PCAP file")
    parser.add_argument("--stem", default="",
                        help="Output directory stem (default: PCAP filename stem)")
    parser.add_argument("--case-id", default="", dest="case_id",
                        help="Case ID stamped in report and vault entries")
    parser.add_argument("--output-dir", type=Path,
                        default=Path("./analysis/http_threats"),
                        dest="output_dir",
                        help="Base output directory (default: ./analysis/http_threats)")
    parser.add_argument("--no-vault", action="store_true", dest="no_vault",
                        help="Skip Obsidian vault writes")
    args = parser.parse_args()

    if not args.pcap.exists():
        print(f"[ERROR] PCAP not found: {args.pcap}", file=sys.stderr)
        sys.exit(1)

    stem    = args.stem or args.pcap.stem
    out_dir = args.output_dir / stem
    out_dir.mkdir(parents=True, exist_ok=True)

    results, all_records, _tls = analyze(args.pcap)

    json_path   = out_dir / "http_threats.json"
    csv_path    = out_dir / "http_flows.csv"
    report_path = out_dir / "http_threats_report.md"

    write_json(results, json_path)
    write_csv(all_records, csv_path)
    write_report(results, report_path, args.pcap, args.case_id)

    if not args.no_vault:
        save_to_vault(results, args.pcap, args.case_id)

    print(f"\n[+] Output directory : {out_dir}", file=sys.stderr)
    print(f"    Report           : {report_path}", file=sys.stderr)
    print(f"    JSON             : {json_path}", file=sys.stderr)
    print(f"    CSV              : {csv_path}", file=sys.stderr)

    print("\n[+] Findings summary:", file=sys.stderr)
    for r in sorted(results.values(),
                    key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)):
        if r["severity"] != "info":
            print(f"    {r['severity'].upper():8s}  {r['name']}: {r['count']}",
                  file=sys.stderr)


if __name__ == "__main__":
    main()
