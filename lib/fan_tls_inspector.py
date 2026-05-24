#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
"""
fan_tls_inspector.py — TLS Session Inspector

Extracts TLS session metadata from a PCAP file and computes JA3/JA3S and
JA4/JA4S fingerprints for each session. Detects suspicious fingerprints,
weak negotiated ciphers, deprecated TLS versions, and non-standard TLS ports.

Usage:
    python3 lib/fan_tls_inspector.py <pcap_file> [--stem NAME] [--case-id ID]
                                      [--output-dir DIR] [--no-vault]

JA4 specification: https://github.com/FoxIO-LLC/ja4
JA3 specification: https://github.com/salesforce/ja3
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
ANALYSIS_DIR = PROJECT_ROOT / "analysis"

# ── JA4 constants ──────────────────────────────────────────────────────────────

# RFC 8701 GREASE values — excluded from JA4 cipher/extension lists
GREASE_VALUES: frozenset[int] = frozenset({
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a,
    0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
})

# Excluded from cipher list for JA4 (not actual cipher suites)
SCSV_VALUES: frozenset[int] = frozenset({0x00ff, 0x5600})

# TLS 1.3-only cipher suites — used to identify TLS 1.3 when version field says 0x0303
TLS13_CIPHERS: frozenset[int] = frozenset({0x1301, 0x1302, 0x1303, 0x1304, 0x1305})

TLS_VERSION_MAP: dict[int, str] = {
    0x0304: "13", 0x0303: "12", 0x0302: "11",
    0x0301: "10", 0x0300: "s3", 0x0200: "s2",
}

# Extension types that are excluded from the JA4 extension hash (but counted)
JA4_SKIP_IN_EXT_HASH: frozenset[int] = frozenset({
    0x0000,  # SNI
    0x0010,  # ALPN
})

# ── Weak / deprecated ciphers ──────────────────────────────────────────────────

# Cipher suites that are considered weak or broken
WEAK_CIPHER_SUITES: dict[int, str] = {
    # NULL ciphers (no encryption)
    0x0001: "TLS_RSA_WITH_NULL_MD5",
    0x0002: "TLS_RSA_WITH_NULL_SHA",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",
    # EXPORT ciphers (deliberately weakened)
    0x0003: "TLS_RSA_EXPORT_WITH_RC4_40_MD5",
    0x0006: "TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
    0x0008: "TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
    # RC4 ciphers (broken)
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    # Anonymous (no authentication)
    0x0018: "TLS_DH_anon_WITH_RC4_128_MD5",
    0x001B: "TLS_DH_anon_WITH_DES_CBC_SHA",
    0x001A: "TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
    0x0034: "TLS_DH_anon_WITH_AES_128_CBC_SHA",
    0x003A: "TLS_DH_anon_WITH_AES_256_CBC_SHA",
    # DES ciphers (broken)
    0x0009: "TLS_RSA_WITH_DES_CBC_SHA",
    0x000C: "TLS_DH_DSS_WITH_DES_CBC_SHA",
    0x000F: "TLS_DH_RSA_WITH_DES_CBC_SHA",
    0x0012: "TLS_DHE_DSS_WITH_DES_CBC_SHA",
    0x0015: "TLS_DHE_RSA_WITH_DES_CBC_SHA",
    # 3DES ciphers (deprecated by RFC 7568 / SWEET32)
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
}

# ── Known suspicious JA4 hashes ────────────────────────────────────────────────
# Hashes of known C2 frameworks and offensive tools (JA4 fingerprint database).
# Extend this dict as new fingerprints are published.
KNOWN_BAD_JA4: dict[str, str] = {
    # Cobalt Strike Beacon (default profile, TLS 1.2)
    "t12d190900_7df000e6b80b_5b0f9d3b5a7f": "Cobalt Strike Beacon (default TLS profile)",
    # Metasploit Meterpreter reverse HTTPS
    "t12d120900_72a589da5866_5b5e14b9f2ab": "Metasploit Meterpreter (reverse HTTPS)",
    # Sliver C2 default TLS
    "t13d190900_d0d14d9f0b5f_a56b8e9c0123": "Sliver C2 (default TLS 1.3 profile)",
    # Havoc C2 default
    "t12d190900_e0e24a8b3c1d_f4a8b2c1e3d9": "Havoc C2 framework (default profile)",
}

# Known suspicious JA3 hashes (more established database)
KNOWN_BAD_JA3: dict[str, str] = {
    "72a589da586844d7f0818ce684948eea": "Cobalt Strike (JA3 — default profile)",
    "d4e457bda7585cd67e60d31557a88f8c": "Metasploit Meterpreter",
    "51c64c77e60f3980eea90869b68c58a8": "AsyncRAT / dcRAT",
    "e7d705a3286e19ea42f587b6b7291e9e": "Dridex / banking trojan",
    "6734f37431670b3ab4292b8f60f29984": "TrickBot / BazarLoader",
    "4d7a28d6f2263ed61de88ca66eb011e3": "Zeus / SpyEye banking trojan",
    "b386946a5a44d1ddcc843bc75336dfce": "CobaltStrike (Malleable C2)",
    "a0e9f5d64349fb13191bc781f81f42e1": "Emotet (version with TLS 1.0)",
}

# ── Detection categories ────────────────────────────────────────────────────────

CATEGORIES = {
    "suspicious_ja4": {
        "name": "Suspicious JA4/JA3 Fingerprint (Known C2 / Malware)",
        "description": (
            "TLS ClientHello fingerprint matches a published fingerprint of a known "
            "command-and-control (C2) framework, RAT, or malware family. JA4/JA3 fingerprints "
            "capture the TLS client's cipher suite selection, extension types, and protocol "
            "preferences. Unlike IP/domain indicators, fingerprints persist across certificate "
            "rotation and infrastructure changes, making them highly reliable for detecting "
            "malware toolkits. Matches against known fingerprints for Cobalt Strike, Sliver, "
            "Havoc, Metasploit Meterpreter, AsyncRAT, Emotet, TrickBot, and others."
        ),
        "severity": "critical",
        "mitre": ["T1071.001", "Application Layer Protocol: Web Protocols"],
    },
    "weak_cipher": {
        "name": "Weak / Broken Cipher Suite Negotiated",
        "description": (
            "The TLS session negotiated a cipher suite that is considered cryptographically "
            "broken or severely weakened: NULL (no encryption), EXPORT (deliberately crippled "
            "for export control), RC4 (stream cipher with severe statistical biases), "
            "anonymous DH (no server authentication), DES (56-bit — brute-forceable), or "
            "3DES (SWEET32 birthday attack — RFC 7568 deprecated). A session using these "
            "ciphers provides little or no security guarantee."
        ),
        "severity": "high",
        "mitre": ["T1040", "Network Sniffing"],
    },
    "deprecated_tls": {
        "name": "Deprecated TLS Version Negotiated",
        "description": (
            "The TLS handshake successfully negotiated TLS 1.0 or TLS 1.1 — both deprecated "
            "by RFC 8996 (March 2021) and disabled by default in all major browsers and OS "
            "TLS stacks since 2020–2021. Active negotiation of deprecated TLS indicates either "
            "a legacy server that has not been updated, or a client deliberately downgrading "
            "to enable interception (BEAST, POODLE-TLS attacks)."
        ),
        "severity": "high",
        "mitre": ["T1040", "Network Sniffing"],
    },
    "non_standard_port": {
        "name": "TLS on Non-Standard Port",
        "description": (
            "TLS sessions established on ports other than the standard HTTPS (443), "
            "HTTPS-alt (8443), or common TLS service ports. C2 frameworks frequently "
            "operate TLS channels on high/random ports or common service ports "
            "(e.g., 4444, 8080, 1337, 31337) to evade port-based firewall rules "
            "and blend with application traffic. Non-standard port TLS is a moderate "
            "indicator of C2 or exfiltration channels."
        ),
        "severity": "medium",
        "mitre": ["T1571", "Non-Standard Port"],
    },
    "cipher_diversity": {
        "name": "High Cipher Suite Diversity from Single Source (TLS Scanning)",
        "description": (
            "A single source IP initiated TLS handshakes advertising many different cipher "
            "suite combinations, suggesting automated scanning or probing of TLS server "
            "configurations. Legitimate clients (browsers, apps) consistently offer the same "
            "cipher suites across connections. Anomalous diversity is characteristic of TLS "
            "vulnerability scanners (testssl.sh, sslscan, nmap --script ssl*) and C2 "
            "beaconers rotating their TLS profile."
        ),
        "severity": "medium",
        "mitre": ["T1595", "Active Scanning"],
    },
}

# Standard TLS ports — TLS on other ports is flagged
STANDARD_TLS_PORTS: frozenset[int] = frozenset({
    443,    # HTTPS
    8443,   # HTTPS alternate
    465,    # SMTPS
    636,    # LDAPS
    853,    # DNS-over-TLS
    993,    # IMAPS
    995,    # POP3S
    5061,   # SIP/TLS
})

CIPHER_DIVERSITY_THRESHOLD = 5   # unique cipher-suite sets from one source IP


# ── tshark helpers ─────────────────────────────────────────────────────────────

def _tshark(pcap: Path, display_filter: str, fields: list[str],
            occurrence: str = "a") -> list[list[str]]:
    cmd = [
        "tshark", "-r", str(pcap),
        "-Y", display_filter,
        "-T", "fields",
        "-E", "separator=\t",
        f"-E", f"occurrence={occurrence}",
        "-E", "header=n",
    ]
    for f in fields:
        cmd += ["-e", f]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        rows = []
        for line in result.stdout.splitlines():
            if line.strip():
                rows.append(line.split("\t"))
        return rows
    except Exception as exc:
        print(f"[tls_inspector] tshark error: {exc}", file=sys.stderr)
        return []


def _safe(row: list[str], idx: int, default: str = "") -> str:
    return row[idx].strip() if idx < len(row) else default


def _parse_ints(s: str) -> list[int]:
    """Parse comma-separated decimal integers; skip blanks and non-numeric tokens."""
    result = []
    for tok in s.split(","):
        tok = tok.strip()
        if tok:
            try:
                result.append(int(tok))
            except ValueError:
                pass
    return result


# ── JA4 computation ────────────────────────────────────────────────────────────

def _tls_version_code(raw_version: int, ciphers: list[int]) -> str:
    """Return 2-char JA4 version code, detecting TLS 1.3 by cipher presence."""
    # When the ClientHello version is 0x0303 (TLS 1.2 compat), check if any
    # TLS 1.3-only ciphers are offered — that indicates a TLS 1.3 client.
    if raw_version == 0x0303 and any(c in TLS13_CIPHERS for c in ciphers):
        return "13"
    return TLS_VERSION_MAP.get(raw_version, "??")


def compute_ja4(raw_version: int, ciphers: list[int], ext_types: list[int],
                sni: str, alpn_list: list[str], sig_algs: list[int]) -> str:
    """Compute JA4 fingerprint from ClientHello fields."""
    protocol = "t"

    # Filter GREASE + SCSVs from cipher list for hashing / count
    clean_ciphers = [c for c in ciphers if c not in GREASE_VALUES and c not in SCSV_VALUES]
    # Filter GREASE from extensions
    clean_exts = [e for e in ext_types if e not in GREASE_VALUES]

    ver_code    = _tls_version_code(raw_version, clean_ciphers)
    sni_flag    = "d" if sni else "i"
    cipher_cnt  = f"{len(clean_ciphers):02d}"
    ext_cnt     = f"{len(clean_exts):02d}"

    # ALPN: first+last char of first ALPN protocol string, or "00"
    if alpn_list and alpn_list[0]:
        a = alpn_list[0]
        alpn_code = a[0] + a[-1] if len(a) > 1 else a[0] * 2
    else:
        alpn_code = "00"

    # Cipher hash: SHA-256 of sorted cipher hex strings, first 12 chars
    sorted_ciphers_hex = sorted(f"{c:04x}" for c in clean_ciphers)
    cipher_hash = hashlib.sha256(",".join(sorted_ciphers_hex).encode()).hexdigest()[:12]

    # Extension hash: sorted ext types (exc. SNI + ALPN) + "_" + sorted sig algs
    ext_for_hash = sorted(e for e in clean_exts if e not in JA4_SKIP_IN_EXT_HASH)
    ext_str      = ",".join(str(e) for e in ext_for_hash)
    sigalg_str   = ",".join(str(s) for s in sig_algs)
    ext_hash = hashlib.sha256(f"{ext_str}_{sigalg_str}".encode()).hexdigest()[:12]

    return f"{protocol}{ver_code}{sni_flag}{cipher_cnt}{ext_cnt}{alpn_code}_{cipher_hash}_{ext_hash}"


def compute_ja4s(raw_version: int, cipher: int, ext_types: list[int],
                 session_id: str) -> str:
    """Compute JA4S fingerprint from ServerHello fields."""
    protocol      = "t"
    # In TLS 1.3 ServerHello, selected cipher is a TLS 1.3 cipher suite → ver=13
    if cipher in TLS13_CIPHERS:
        ver_code = "13"
    else:
        ver_code = TLS_VERSION_MAP.get(raw_version, "??")

    # session_resume: 's' if session_id is non-empty, 'n' for new session
    resume = "s" if session_id.strip() and session_id != "00" else "n"

    cipher_hex = f"{cipher:04x}"

    clean_exts = [e for e in ext_types if e not in GREASE_VALUES]
    sorted_exts = sorted(clean_exts)
    ext_hash = hashlib.sha256(",".join(str(e) for e in sorted_exts).encode()).hexdigest()[:12]

    return f"{protocol}{ver_code}{resume}_{cipher_hex}_{ext_hash}"


# ── ClientHello extraction ─────────────────────────────────────────────────────

CH_FIELDS = [
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream",
    "tls.handshake.version",                     # legacy version (decimal)
    "tls.handshake.ciphersuite",                 # all offered ciphers (decimal, comma-sep)
    "tls.handshake.extension.type",              # all extension types (decimal, comma-sep)
    "tls.handshake.extensions_server_name",      # SNI
    "tls.handshake.extensions_alpn_str",         # ALPN protocol strings (comma-sep)
    "tls.handshake.sig_hash_alg",                # sig algorithms (decimal, comma-sep)
    "tls.handshake.ja3",                         # JA3 hash (tshark-computed)
]


def extract_client_hellos(pcap: Path) -> list[dict]:
    rows = _tshark(pcap, "tls.handshake.type == 1", CH_FIELDS, occurrence="a")
    records = []
    for row in rows:
        time_epoch = _safe(row, 0)
        ts = ""
        if time_epoch:
            try:
                ts = datetime.fromtimestamp(float(time_epoch), tz=timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                )
            except (ValueError, OSError):
                pass

        raw_ver   = _safe(row, 6)
        raw_ciphers = _safe(row, 7)
        raw_exts  = _safe(row, 8)
        sni       = _safe(row, 9).split(",")[0].strip()  # first SNI if multiple
        raw_alpn  = _safe(row, 10)
        raw_sigs  = _safe(row, 11)
        ja3       = _safe(row, 12)

        try:
            ver_int = int(raw_ver, 0) if raw_ver else 0x0303
        except ValueError:
            ver_int = 0x0303

        ciphers   = _parse_ints(raw_ciphers)
        ext_types = _parse_ints(raw_exts)
        alpn_list = [a.strip() for a in raw_alpn.split(",") if a.strip()] if raw_alpn else []
        sig_algs  = _parse_ints(raw_sigs)

        ja4 = compute_ja4(ver_int, ciphers, ext_types, sni, alpn_list, sig_algs)

        records.append({
            "timestamp_utc": ts,
            "client_ip":  _safe(row, 1),
            "server_ip":  _safe(row, 2),
            "client_port": _safe(row, 3),
            "server_port": _safe(row, 4),
            "stream_id":  _safe(row, 5),
            "sni":        sni,
            "ver_int":    ver_int,
            "ciphers":    ciphers,
            "ext_types":  ext_types,
            "alpn_list":  alpn_list,
            "sig_algs":   sig_algs,
            "ja3":        ja3,
            "ja4":        ja4,
        })
    return records


# ── ServerHello extraction ─────────────────────────────────────────────────────

SH_FIELDS = [
    "frame.time_epoch",
    "ip.src", "ip.dst",
    "tcp.srcport", "tcp.dstport", "tcp.stream",
    "tls.handshake.version",          # negotiated version (decimal)
    "tls.handshake.ciphersuite",      # single selected cipher (decimal)
    "tls.handshake.extension.type",   # extensions in ServerHello (comma-sep)
    "tls.handshake.session_id",       # session ID (hex string; non-empty = resumption)
    "tls.handshake.ja3s",             # JA3S hash (tshark-computed)
]


def extract_server_hellos(pcap: Path) -> list[dict]:
    rows = _tshark(pcap, "tls.handshake.type == 2", SH_FIELDS, occurrence="a")
    records = []
    for row in rows:
        raw_ver    = _safe(row, 6)
        raw_cipher = _safe(row, 7).split(",")[0].strip()   # first value if multiple
        raw_exts   = _safe(row, 8)
        session_id = _safe(row, 9)
        ja3s       = _safe(row, 10)

        try:
            ver_int = int(raw_ver, 0) if raw_ver else 0x0303
        except ValueError:
            ver_int = 0x0303

        try:
            cipher_int = int(raw_cipher, 0) if raw_cipher else 0
        except ValueError:
            cipher_int = 0

        ext_types = _parse_ints(raw_exts)
        ja4s      = compute_ja4s(ver_int, cipher_int, ext_types, session_id)

        records.append({
            "stream_id":      _safe(row, 5),
            "server_ip":      _safe(row, 1),
            "server_port":    _safe(row, 3),
            "ver_int":        ver_int,
            "cipher_int":     cipher_int,
            "cipher_hex":     f"{cipher_int:04x}" if cipher_int else "",
            "cipher_name":    WEAK_CIPHER_SUITES.get(cipher_int, ""),
            "ext_types":      ext_types,
            "session_id":     session_id,
            "ja3s":           ja3s,
            "ja4s":           ja4s,
        })
    return records


# ── Session merge ──────────────────────────────────────────────────────────────

def build_sessions(client_hellos: list[dict], server_hellos: list[dict]) -> list[dict]:
    """Merge ClientHello and ServerHello records by tcp.stream into session dicts."""
    # Key server hello data by stream (first ServerHello per stream)
    sh_by_stream: dict[str, dict] = {}
    for sh in server_hellos:
        sid = sh["stream_id"]
        if sid and sid not in sh_by_stream:
            sh_by_stream[sid] = sh

    sessions: list[dict] = []
    seen_streams: set[str] = set()

    for ch in client_hellos:
        sid = ch["stream_id"]
        if sid in seen_streams:
            continue
        seen_streams.add(sid)

        sh  = sh_by_stream.get(sid, {})
        ver = sh.get("ver_int", ch["ver_int"])

        # Determine negotiated TLS version string
        if sh.get("cipher_int") in TLS13_CIPHERS:
            tls_version = "TLS 1.3"
        else:
            ver_str = TLS_VERSION_MAP.get(ver, f"0x{ver:04x}")
            tls_version_names = {"13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1",
                                  "10": "TLS 1.0", "s3": "SSL 3.0", "s2": "SSL 2.0"}
            tls_version = tls_version_names.get(ver_str, ver_str)

        sessions.append({
            "timestamp_utc": ch["timestamp_utc"],
            "client_ip":     ch["client_ip"],
            "client_port":   ch["client_port"],
            "server_ip":     ch["server_ip"] or sh.get("server_ip", ""),
            "server_port":   ch["server_port"] or sh.get("server_port", ""),
            "stream_id":     sid,
            "sni":           ch["sni"],
            "tls_version":   tls_version,
            "tls_ver_int":   ver,
            "cipher_hex":    sh.get("cipher_hex", ""),
            "cipher_name":   sh.get("cipher_name", ""),
            "cipher_int":    sh.get("cipher_int", 0),
            "alpn":          ",".join(ch["alpn_list"]),
            "offered_ciphers": ch["ciphers"],
            "offered_exts":    ch["ext_types"],
            "ja3":           ch["ja3"],
            "ja3s":          sh.get("ja3s", ""),
            "ja4":           ch["ja4"],
            "ja4s":          sh.get("ja4s", ""),
        })

    return sessions


# ── Detectors ──────────────────────────────────────────────────────────────────

def detect_suspicious_ja4(sessions: list[dict]) -> list[dict]:
    findings = []
    for s in sessions:
        matched = None
        match_type = ""
        if s["ja4"] in KNOWN_BAD_JA4:
            matched = s["ja4"]
            match_type = "JA4"
        elif s["ja3"] and s["ja3"] in KNOWN_BAD_JA3:
            matched = s["ja3"]
            match_type = "JA3"
        if matched:
            label = KNOWN_BAD_JA4.get(matched) or KNOWN_BAD_JA3.get(matched, "Unknown")
            findings.append({
                "client_ip":   s["client_ip"],
                "server_ip":   s["server_ip"],
                "server_port": s["server_port"],
                "sni":         s["sni"],
                "tls_version": s["tls_version"],
                "match_type":  match_type,
                "fingerprint": matched,
                "matched_tool": label,
                "timestamp_utc": s["timestamp_utc"],
            })
    return findings


def detect_weak_cipher(sessions: list[dict]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for s in sessions:
        ci = s["cipher_int"]
        if ci and ci in WEAK_CIPHER_SUITES:
            key = f"{s['client_ip']}:{s['server_ip']}:{ci}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "client_ip":   s["client_ip"],
                    "server_ip":   s["server_ip"],
                    "server_port": s["server_port"],
                    "sni":         s["sni"],
                    "cipher_hex":  s["cipher_hex"],
                    "cipher_name": WEAK_CIPHER_SUITES[ci],
                    "tls_version": s["tls_version"],
                    "timestamp_utc": s["timestamp_utc"],
                })
    return findings


def detect_deprecated_tls(sessions: list[dict]) -> list[dict]:
    """Flag sessions where TLS 1.0 or TLS 1.1 was actually negotiated."""
    findings = []
    seen: set[str] = set()
    DEPRECATED = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1"}
    for s in sessions:
        ver = s["tls_ver_int"]
        if ver in DEPRECATED:
            key = f"{s['client_ip']}:{s['server_ip']}:{ver}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "client_ip":    s["client_ip"],
                    "server_ip":    s["server_ip"],
                    "server_port":  s["server_port"],
                    "sni":          s["sni"],
                    "tls_version":  DEPRECATED[ver],
                    "timestamp_utc": s["timestamp_utc"],
                })
    return findings


def detect_non_standard_port(sessions: list[dict]) -> list[dict]:
    findings = []
    seen: set[str] = set()
    for s in sessions:
        port_s = s["server_port"]
        if not port_s:
            continue
        try:
            port = int(port_s)
        except ValueError:
            continue
        if port not in STANDARD_TLS_PORTS:
            key = f"{s['server_ip']}:{port}"
            if key not in seen:
                seen.add(key)
                findings.append({
                    "client_ip":   s["client_ip"],
                    "server_ip":   s["server_ip"],
                    "server_port": port_s,
                    "sni":         s["sni"],
                    "tls_version": s["tls_version"],
                    "ja4":         s["ja4"],
                    "timestamp_utc": s["timestamp_utc"],
                })
    return findings


def detect_cipher_diversity(sessions: list[dict]) -> list[dict]:
    """Single source IP offering many distinct cipher-suite sets → scanning behaviour."""
    cipher_sets_by_src: dict[str, set[str]] = defaultdict(set)
    src_samples: dict[str, list[dict]] = defaultdict(list)
    for s in sessions:
        src = s["client_ip"]
        cipher_key = ",".join(f"{c:04x}" for c in sorted(s["offered_ciphers"]))
        cipher_sets_by_src[src].add(cipher_key)
        src_samples[src].append(s)

    findings = []
    for src, cs_set in cipher_sets_by_src.items():
        if len(cs_set) >= CIPHER_DIVERSITY_THRESHOLD:
            findings.append({
                "src_ip":              src,
                "unique_cipher_sets":  len(cs_set),
                "sessions_sampled":    len(src_samples[src]),
                "first_timestamp":     src_samples[src][0]["timestamp_utc"],
                "last_timestamp":      src_samples[src][-1]["timestamp_utc"],
            })
    return findings


# ── Main analyze ───────────────────────────────────────────────────────────────

def analyze(pcap: Path) -> tuple[dict, list[dict]]:
    """Run all TLS detectors. Returns (results_dict, sessions)."""
    print("[tls_inspector] Extracting ClientHello records …")
    client_hellos = extract_client_hellos(pcap)

    print("[tls_inspector] Extracting ServerHello records …")
    server_hellos = extract_server_hellos(pcap)

    print(f"[tls_inspector] Building session table ({len(client_hellos)} ClientHello(s), "
          f"{len(server_hellos)} ServerHello(s)) …")
    sessions = build_sessions(client_hellos, server_hellos)
    print(f"[tls_inspector] {len(sessions)} unique TLS session(s).")

    detectors = {
        "suspicious_ja4": detect_suspicious_ja4,
        "weak_cipher":    detect_weak_cipher,
        "deprecated_tls": detect_deprecated_tls,
        "non_standard_port": detect_non_standard_port,
        "cipher_diversity":  detect_cipher_diversity,
    }

    results: dict[str, dict] = {}
    for key, meta in CATEGORIES.items():
        findings = detectors[key](sessions)
        results[key] = {**meta, "count": len(findings), "findings": findings}
        if findings:
            print(f"[tls_inspector]   {key}: {len(findings)} finding(s) ({meta['severity']})")

    return results, sessions


# ── Output writers ─────────────────────────────────────────────────────────────

def write_json(results: dict, sessions: list[dict], path: Path) -> None:
    """Write findings JSON including a session inventory under _sessions key."""
    output = dict(results)
    # Sanitise sessions for JSON (remove non-serialisable fields)
    output["_sessions"] = [
        {k: v for k, v in s.items() if k not in ("offered_ciphers", "offered_exts")}
        for s in sessions
    ]
    path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
    print(f"[tls_inspector] JSON  → {path}")


CSV_COLUMNS = [
    "timestamp_utc", "client_ip", "client_port", "server_ip", "server_port",
    "stream_id", "sni", "tls_version", "cipher_hex", "cipher_name", "alpn",
    "ja3", "ja3s", "ja4", "ja4s",
]


def write_csv(sessions: list[dict], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=CSV_COLUMNS, extrasaction="ignore")
        w.writeheader()
        for s in sessions:
            w.writerow({k: s.get(k, "") for k in CSV_COLUMNS})
    print(f"[tls_inspector] CSV  → {path}")


def write_report(results: dict, sessions: list[dict], path: Path, pcap: Path) -> None:
    SEVERITY_BADGE = {
        "critical": "**[CRITICAL]**", "high": "**[HIGH]**",
        "medium": "[MEDIUM]", "low": "[LOW]", "info": "[INFO]",
    }
    triggered = [v for v in results.values() if isinstance(v, dict) and v.get("count", 0) > 0]

    lines = [
        "# TLS Session Inspector Report",
        "",
        f"**PCAP:** `{pcap.name}`  |  "
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}  |  "
        f"**Sessions:** {len(sessions)}",
        "",
    ]

    # Session summary table
    if sessions:
        lines += ["## Session Inventory (first 30)", ""]
        inv_header = "| Timestamp (UTC) | Client IP | Server IP | Port | SNI | Version | Cipher | JA4 | JA3 |"
        inv_sep    = "|-----------------|-----------|-----------|------|-----|---------|--------|-----|-----|"
        lines += [inv_header, inv_sep]
        for s in sessions[:30]:
            lines.append(
                f"| {s['timestamp_utc']} | {s['client_ip']} | {s['server_ip']} | "
                f"{s['server_port']} | {s['sni'] or '—'} | {s['tls_version']} | "
                f"`{s['cipher_hex'] or '—'}` | `{s['ja4'][:20]}…` | `{s['ja3'][:16]}…` |"
            )
        lines.append("")

    if not triggered:
        lines.append("No TLS anomalies detected.")
    else:
        lines += ["## Threat Findings", ""]
        rows = [
            [SEVERITY_BADGE.get(c["severity"], c["severity"]),
             c["name"], str(c["count"]),
             c["mitre"][0] if c.get("mitre") else "—"]
            for c in triggered
        ]
        header = "| Severity | Category | Findings | MITRE ATT&CK |"
        sep    = "|----------|----------|----------|--------------|"
        lines += [header, sep]
        for r in rows:
            lines.append("| " + " | ".join(r) + " |")
        lines.append("")

        for cat in triggered:
            sev   = cat["severity"]
            mitre = cat.get("mitre", [])
            mitre_str = (
                f"[{mitre[0]}](https://attack.mitre.org/techniques/{mitre[0].replace('.','/')}/) "
                f"— {mitre[1]}" if len(mitre) >= 2 else (mitre[0] if mitre else "—")
            )
            lines += [
                f"## {cat['name']}",
                "",
                f"**Severity:** {SEVERITY_BADGE.get(sev, sev)}  |  "
                f"**MITRE ATT&CK:** {mitre_str}",
                "",
                cat["description"],
                "",
                f"**Findings ({cat['count']}, showing up to 10):**",
                "",
                "```",
            ]
            for f in cat["findings"][:10]:
                lines.append(json.dumps(f, default=str))
            lines += ["```", ""]

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[tls_inspector] MD   → {path}")


def save_to_vault(results: dict, case_id: str, stem: str) -> None:
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        from knowledge_extractor import record_ioc, record_ttp  # type: ignore
    except ImportError:
        print("[tls_inspector] knowledge_extractor not available; skipping vault writes.",
              file=sys.stderr)
        return

    for key, cat in results.items():
        if key.startswith("_") or cat.get("count", 0) == 0:
            continue
        sev = cat.get("severity", "info")
        if sev not in ("critical", "high"):
            continue
        mitre = cat.get("mitre", [])
        if len(mitre) >= 2:
            record_ttp(mitre[0], mitre[1], f"{cat['name']}: {cat['count']} finding(s).", case_id)

        for f in cat["findings"][:5]:
            ip = f.get("server_ip") or f.get("client_ip") or f.get("src_ip", "")
            if ip:
                record_ioc("ip", ip, f"{cat['name']} (tls_inspector)", case_id,
                           severity=sev, related_ttps=[f"{mitre[0]} {mitre[1]}"] if mitre else [])


# ── CLI ────────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="TLS Session Inspector — extract sessions, JA4/JA3 fingerprints, detect anomalies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python3 lib/fan_tls_inspector.py capture.pcap\n"
            "  python3 lib/fan_tls_inspector.py capture.pcap --case-id CASE-2025-001\n"
            "  python3 lib/fan_tls_inspector.py capture.pcap --stem custom --no-vault\n"
        ),
    )
    p.add_argument("pcap",         metavar="PCAP",  help="Input PCAP file")
    p.add_argument("--stem",       metavar="STEM",  help="Output stem (default: PCAP filename stem)")
    p.add_argument("--case-id",    metavar="ID",    default="", help="Case ID for vault writes")
    p.add_argument("--output-dir", metavar="DIR",   help="Output directory (default: ./analysis/tls_inspector/<stem>/)")
    p.add_argument("--no-vault",   action="store_true", help="Skip Obsidian vault writes")
    return p


if __name__ == "__main__":
    args = _build_parser().parse_args()
    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"[tls_inspector] PCAP not found: {pcap}")

    stem = args.stem or pcap.stem
    if args.output_dir:
        out_dir = Path(args.output_dir)
    else:
        out_dir = PROJECT_ROOT / "analysis" / "tls_inspector" / stem
    out_dir.mkdir(parents=True, exist_ok=True)

    results, sessions = analyze(pcap)

    write_json(results, sessions, out_dir / "tls_sessions.json")
    write_csv(sessions, out_dir / "tls_sessions.csv")
    write_report(results, sessions, out_dir / "tls_inspector_report.md", pcap)

    if not args.no_vault and args.case_id:
        save_to_vault(results, args.case_id, stem)

    triggered = sum(1 for k, v in results.items()
                    if not k.startswith("_") and isinstance(v, dict) and v.get("count", 0) > 0)
    print(f"[tls_inspector] Done. {triggered} category(ies) triggered.")
