# Skill: FAN TLS Inspector

## Overview

Extracts TLS session metadata from a PCAP file and computes **JA4** and **JA3**
client fingerprints plus **JA4S** and **JA3S** server fingerprints for each
session. Produces a complete session inventory (source/destination IP:port, SNI,
negotiated TLS version, cipher suite, ALPN) and runs five detection categories
against the fingerprints and session attributes.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| Suspicious JA4/JA3 Hash (Known C2/Malware) | T1071.001 — Application Layer Protocol: Web Protocols | Critical |
| Weak / Broken Cipher Suite Negotiated | T1040 — Network Sniffing | High |
| Deprecated TLS Version Negotiated (1.0/1.1) | T1040 — Network Sniffing | High |
| TLS on Non-Standard Port | T1571 — Non-Standard Port | Medium |
| High Cipher Suite Diversity from Single Source | T1595 — Active Scanning | Medium |

| Output | Path |
|--------|------|
| JSON findings + session inventory | `./analysis/tls_inspector/<stem>/tls_sessions.json` |
| Session inventory CSV | `./analysis/tls_inspector/<stem>/tls_sessions.csv` |
| Markdown report | `./analysis/tls_inspector/<stem>/tls_inspector_report.md` |

**Fingerprint coverage:**
- **JA4** — computed from ClientHello cipher suites, extension types, SNI flag,
  ALPN, and signature algorithms per the FoxIO JA4+ specification.
- **JA3** — MD5 of TLS version, ciphers, extensions, elliptic curves, and point
  formats from the ClientHello (tshark-native field `tls.handshake.ja3`).
- **JA4S** — computed from ServerHello negotiated cipher, extension types, and
  session resumption flag per the JA4S specification.
- **JA3S** — MD5 of ServerHello TLS version, selected cipher, and extensions
  (tshark-native field `tls.handshake.ja3s`).

---

## Invocation

```bash
# Analyze a PCAP for TLS session metadata and fingerprints
./scripts/fan_tls_inspector.sh /path/to/capture.pcap

# With case ID (recommended)
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom stem (must match other analysis steps)
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001

# Skip vault writes (offline/air-gapped)
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_tls_inspector import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, sessions = analyze(pcap)
out_dir = Path("./analysis/tls_inspector/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, sessions, out_dir / "tls_sessions.json")
write_csv(sessions, out_dir / "tls_sessions.csv")
write_report(results, sessions, out_dir / "tls_inspector_report.md", pcap)
```

---

## JA4 Computation

JA4 is computed from the TLS ClientHello fields per the
[FoxIO JA4+ specification](https://github.com/FoxIO-LLC/ja4):

```
JA4 = {protocol}{version}{sni_flag}{cipher_count}{ext_count}{alpn}_{cipher_hash}_{ext_hash}
```

| Component | Source | Notes |
|-----------|--------|-------|
| `protocol` | Always `t` | TCP TLS (QUIC/DTLS not yet supported) |
| `version` | `tls.handshake.version` | Detected as TLS 1.3 when any TLS 1.3-only cipher (0x1301–0x1305) is offered |
| `sni_flag` | `tls.handshake.extensions_server_name` | `d` = SNI present, `i` = no SNI |
| `cipher_count` | `tls.handshake.ciphersuite` (all) | Count after removing GREASE + SCSVs, zero-padded to 2 digits |
| `ext_count` | `tls.handshake.extension.type` (all) | Count after removing GREASE, zero-padded to 2 digits |
| `alpn` | `tls.handshake.extensions_alpn_str` | First+last char of first ALPN (`h2`→`h2`, `http/1.1`→`h1`, none→`00`) |
| `cipher_hash` | SHA-256[:12] of sorted cipher hex values (after GREASE+SCSV removal) | |
| `ext_hash` | SHA-256[:12] of sorted ext types (excl. SNI+ALPN) + `_` + sorted sig algs | |

**GREASE values filtered:** 0x0a0a, 0x1a1a, 0x2a2a, … 0xfafa (RFC 8701)
**SCSVs filtered from ciphers:** 0x00ff (renegotiation_info), 0x5600 (fallback)

## JA4S Computation

```
JA4S = {protocol}{version}{session_resume}_{cipher_hex}_{ext_hash}
```

| Component | Source |
|-----------|--------|
| `protocol` | Always `t` |
| `version` | `tls.handshake.version` from ServerHello; `13` if cipher is TLS 1.3-only |
| `session_resume` | `s` if `tls.handshake.session_id` non-empty, `n` otherwise |
| `cipher_hex` | 4-char lowercase hex of selected cipher suite |
| `ext_hash` | SHA-256[:12] of comma-separated sorted ServerHello extension types |

---

## Detection Logic

### Suspicious JA4/JA3 Fingerprint (T1071.001)
Matches computed JA4 and tshark-native JA3 hashes against a curated database of
known C2 frameworks and malware families. Unlike IP/domain IOCs, fingerprints
persist across certificate rotation and IP changes.

**Built-in fingerprint database includes:**
- Cobalt Strike Beacon (default and Malleable C2 profiles)
- Metasploit Meterpreter (reverse HTTPS)
- Sliver C2 framework (default TLS 1.3 profile)
- Havoc C2 framework (default profile)
- AsyncRAT / dcRAT
- Dridex, TrickBot, BazarLoader banking trojans
- Emotet (TLS 1.0 variant)

**Extending the database:** Add entries to `KNOWN_BAD_JA4` and `KNOWN_BAD_JA3`
dicts at the top of `lib/fan_tls_inspector.py`.

**Finding fields:** `client_ip`, `server_ip`, `server_port`, `sni`,
`tls_version`, `match_type`, `fingerprint`, `matched_tool`, `timestamp_utc`

---

### Weak / Broken Cipher Suite Negotiated (T1040)
The ServerHello selected a cryptographically broken cipher suite. The detector
covers NULL, EXPORT, RC4, anonymous DH, DES, and 3DES suites. Only the
**negotiated** cipher (from ServerHello) is checked — not the client's offered
list (use `fan_http_threats.sh` for deprecated TLS versions offered by clients).

**Flagged cipher categories:**
- NULL ciphers (`TLS_RSA_WITH_NULL_*`) — zero encryption
- EXPORT ciphers (`*_EXPORT_*`) — deliberately weakened key lengths
- RC4 stream ciphers — BEAST, RC4 statistical biases
- Anonymous DH (`DH_anon`) — no server authentication
- DES 56-bit — brute-forceable with modern hardware
- 3DES — SWEET32 birthday attack (RFC 7568 deprecated)

**Finding fields:** `client_ip`, `server_ip`, `server_port`, `sni`,
`cipher_hex`, `cipher_name`, `tls_version`, `timestamp_utc`

---

### Deprecated TLS Version Negotiated (T1040)
The TLS handshake completed with TLS 1.0 (0x0301) or TLS 1.1 (0x0302) as the
negotiated version. Both were deprecated by RFC 8996 (March 2021). This
detector checks the ServerHello negotiated version, not the ClientHello offered
versions (the `fan_http_threats` skill covers offered deprecated versions).

**Finding fields:** `client_ip`, `server_ip`, `server_port`, `sni`,
`tls_version`, `timestamp_utc`

---

### TLS on Non-Standard Port (T1571)
TLS sessions on ports outside the standard set. C2 operators frequently run TLS
channels on non-443 ports to evade port-based firewall rules.

**Standard ports (not flagged):** 443, 8443, 465, 636, 853, 993, 995, 5061

**Finding fields:** `client_ip`, `server_ip`, `server_port`, `sni`,
`tls_version`, `ja4`, `timestamp_utc`

---

### High Cipher Suite Diversity from Single Source (T1595)
A single source IP presents 5 or more **distinct cipher-suite combinations**
across its TLS ClientHellos. Legitimate clients (browsers, OS TLS stacks, apps)
send the same cipher list for every connection. Automated TLS scanners
(testssl.sh, sslscan, nmap TLS scripts) and some C2 beaconers rotating their
TLS profile exhibit this pattern.

**Threshold:** `CIPHER_DIVERSITY_THRESHOLD = 5` (configurable at top of module)

**Finding fields:** `src_ip`, `unique_cipher_sets`, `sessions_sampled`,
`first_timestamp`, `last_timestamp`

---

## TLS Session Inventory CSV Columns

| Column | Description |
|--------|-------------|
| `timestamp_utc` | ClientHello frame timestamp (ISO-8601 UTC) |
| `client_ip` | Source (client) IP address |
| `client_port` | Source TCP port |
| `server_ip` | Destination (server) IP address |
| `server_port` | Destination TCP port |
| `stream_id` | tshark TCP stream index (unique per session) |
| `sni` | TLS Server Name Indication from ClientHello |
| `tls_version` | Negotiated TLS version string (e.g., `TLS 1.3`) |
| `cipher_hex` | Negotiated cipher suite as 4-char hex (e.g., `c02c`) |
| `cipher_name` | Cipher name if weak (empty for standard ciphers) |
| `alpn` | ALPN protocol(s) offered by client (comma-separated) |
| `ja3` | JA3 MD5 fingerprint (tshark-computed from ClientHello) |
| `ja3s` | JA3S MD5 fingerprint (tshark-computed from ServerHello) |
| `ja4` | JA4 fingerprint (computed per FoxIO specification) |
| `ja4s` | JA4S fingerprint (computed per FoxIO specification) |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `CIPHER_DIVERSITY_THRESHOLD` | 5 | Unique cipher-set count to flag scanning |
| `STANDARD_TLS_PORTS` | 443, 8443, 465, 636, 853, 993, 995, 5061 | Ports not flagged by non-standard-port detector |

---

## Full IR Workflow

```bash
# Step 1 — Extract netflow, IPs, FQDNs from PCAP
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — ICMP threat detection
./scripts/fan_icmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 3 — DNS threat detection
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 4 — NTP threat detection
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 5 — HTTP(S) unusual pattern detection
./scripts/fan_http_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 6 — TLS certificate inspection
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 7 — TLS session inspection + JA4 fingerprinting
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 8 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 9 — Generate consolidated incident report
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001
```

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| Suspicious JA4/JA3 (known C2/malware) | `IOCs/ja3-<hash>.md` + `TTPs/T1071.001.md` | T1071.001 | Critical |
| Weak / Broken Cipher Suite | `TTPs/T1040.md` + `Concepts/TLS-weak-cipher.md` | T1040 | High |
| Deprecated TLS 1.0/1.1 negotiated | `TTPs/T1040.md` | T1040 | High |
| TLS on Non-Standard Port | `TTPs/T1571.md` + `IOCs/ip-<dst>.md` | T1571 | Medium |
| High Cipher Diversity (scanning) | `TTPs/T1595.md` + `IOCs/ip-<src>.md` | T1595 | Medium |

JA3/JA4 hashes recorded as IOC type `ja3` — use exact hash value as the note name:
```bash
./scripts/vault_context.sh ioc <ja3_hash>
./scripts/vault_context.sh ttp T1071.001
./scripts/vault_context.sh search "<case_id>"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty session inventory | No TLS traffic in PCAP | Verify: `tshark -r capture.pcap -Y "tls.handshake.type == 1"` |
| `ja3` column empty | tshark < 3.0 (no native JA3) | Upgrade tshark or compute JA3 externally |
| JA4 shows `t??…` | TLS version field not parsed | Check `tls.handshake.version` output format in your tshark version |
| Suspicious JA4 not triggering | Local fingerprint DB is small | Extend `KNOWN_BAD_JA4`/`KNOWN_BAD_JA3` in `lib/fan_tls_inspector.py` |
| Sessions missing `ja4s` | No ServerHello captured (half-open connections) | Capture full 3-way handshake; ensure server side traffic is included |
| Non-standard port FP | Internal service uses custom TLS port | Add port to `STANDARD_TLS_PORTS` set in `lib/fan_tls_inspector.py` |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
| Report missing TLS section | TLS inspector not run | Run `fan_tls_inspector.sh <pcap>` first |
