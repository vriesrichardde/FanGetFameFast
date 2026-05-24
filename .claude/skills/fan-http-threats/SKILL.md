# Skill: FAN HTTP(S) Unusual Patterns

## Overview

Detects unusual or malicious HTTP/HTTPS patterns in a PCAP file using tshark
field extraction and Python heuristics. Covers 11 detection categories across
HTTP request analysis, HTTP response analysis, and TLS handshake inspection.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| Suspicious User-Agent | T1071.001 — Web Protocols | Critical/High |
| Unusual HTTP Methods | T1071.001 — Web Protocols | High/Medium |
| HTTP Scanning / Error Code Flood | T1595 — Active Scanning | High |
| Suspicious URI Patterns | T1190 — Exploit Public-Facing Application | Critical |
| Large HTTP Upload | T1048.002 — Exfiltration Over HTTP | High |
| HTTP Cookie Anomaly | T1048 — Exfiltration Over Alt. Protocol | High |
| Host Header Anomaly | T1557 — Adversary-in-the-Middle | High/Medium |
| HTTP Beaconing | T1071.001 — Web Protocols | Critical |
| Unusual HTTP Server Header | T1071.001 — Web Protocols | Critical |
| Suspicious HTTP Referer | T1071.001 — Web Protocols | High/Medium |
| Deprecated / Weak TLS Version | T1040 — Network Sniffing | Critical/High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/http_threats/<stem>/http_threats.json` |
| HTTP flows CSV | `./analysis/http_threats/<stem>/http_flows.csv` |
| Markdown report | `./analysis/http_threats/<stem>/http_threats_report.md` |

**Note:** HTTP content analysis applies only to **cleartext HTTP** (port 80 or any
unencrypted HTTP). HTTPS content is not visible — only TLS handshake metadata
(version, SNI, cipher suite) is analysed for the deprecated-TLS category.

---

## Invocation

```bash
# Analyze a PCAP for HTTP(S) threat patterns
./scripts/fan_http_threats.sh /path/to/capture.pcap

# With case ID (recommended)
./scripts/fan_http_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom stem (must match other analysis steps)
./scripts/fan_http_threats.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001

# Skip vault writes (offline/air-gapped)
./scripts/fan_http_threats.sh /path/to/capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_http_threats import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, all_records, tls_records = analyze(pcap)
out_dir = Path("./analysis/http_threats/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, out_dir / "http_threats.json")
write_csv(all_records, out_dir / "http_flows.csv")
write_report(results, out_dir / "http_threats_report.md", pcap)
```

---

## Detection Logic

### Suspicious User-Agent (T1071.001)
Matches User-Agent headers against a dictionary of known offensive tools,
C2 frameworks, scanners, and automation clients. Also flags empty/missing UAs
and abnormally long UAs (> 512 chars — possible header injection buffer probes).

**Known tool patterns detected (case-insensitive substring match):**
curl, wget, python-requests, python-urllib, go-http-client, libwww-perl,
powershell, invoke-webrequest, nmap, nikto, sqlmap, masscan, zgrab, nuclei,
dirbuster, gobuster, wfuzz, burpsuite, openvas, acunetix, metasploit,
havoc, sliver, empire, cobalt strike, meterpreter, beef, hydra, medusa

**Severity escalation:** C2/exploit framework patterns → CRITICAL; scanner/tool → HIGH

**Finding fields:** `indicator`, `src_ip`, `dst_ip`, `host`, `user_agent`,
`timestamp_utc`

---

### Unusual HTTP Methods (T1071.001)
Flags HTTP methods outside the standard set:
**Standard (allowed):** GET, POST, HEAD, PUT, DELETE, OPTIONS, PATCH

**Flagged groups:**
- **TRACE** → HIGH (enables Cross-Site Tracing / XST attacks)
- **WebDAV** (PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK, SEARCH, REPORT)
  → MEDIUM (file system access, WebDAV exploitation)
- Any other non-standard method → LOW

**Finding fields:** `method`, `category`, `src_ip`, `dst_ip`, `host`, `uri`,
`timestamp_utc`

---

### HTTP Scanning / Error Code Flood (T1595)
High volumes of HTTP 4xx/5xx responses to a single client IP. Responses are
grouped by client (destination of the response), not the server.

**Signal:** Single client IP receiving ≥ 50 error responses (configurable via
`SCANNING_MIN_ERRORS`). Characteristic of directory brute-forcing, vulnerability
scanning, or credential stuffing.

**Finding fields:** `client_ip`, `total_errors`, `code_breakdown`

---

### Suspicious URI Patterns (T1190)
Multi-category URI analysis on every HTTP request URI:

| Sub-category | Pattern Examples |
|---|---|
| Path Traversal | `../`, `..%2F`, `%2e%2e/`, `..%5c` |
| SQL Injection | `UNION SELECT`, `' OR 1=1`, `xp_cmdshell`, `WAITFOR DELAY` |
| XSS Attempt | `<script`, `javascript:`, `onerror=`, `alert(`, `document.cookie` |
| Command Injection | `;cat /etc/passwd`, `|id`, `$(id)`, `` `whoami` `` |
| Admin/Sensitive Path | `/admin`, `/wp-login`, `/phpmyadmin`, `/.env`, `/.git/`, `/actuator` |
| Abnormally Long URI | > 2048 characters |
| Null Byte Injection | `\x00` or `%00` in URI |

**Severity:** Injection attacks → CRITICAL; Admin probing only → MEDIUM

**Finding fields:** `categories`, `src_ip`, `dst_ip`, `host`, `method`, `uri`,
`timestamp_utc`

---

### Large HTTP Upload (T1048.002)
HTTP POST, PUT, or PATCH requests with body size ≥ 500 KB (configurable via
`LARGE_UPLOAD_MIN_BYTES`). Uses `Content-Length` header if present, falls back
to frame length. May indicate data staging to an attacker-controlled server or
exfiltration disguised as a file upload.

**Finding fields:** `src_ip`, `dst_ip`, `host`, `method`, `uri`, `size_bytes`,
`timestamp_utc`

---

### HTTP Cookie Anomaly (T1048)
Flags cookies with:
- **Oversized cookie** ≥ 4096 characters (standard browser limit; exceeding it
  suggests programmatic abuse)
- **High-entropy cookie value** ≥ 4.5 Shannon bits per character (indicates
  base64/hex-encoded data packed into a cookie — common exfil technique)

**Finding fields:** `src_ip`, `dst_ip`, `host`, `uri`, `reasons`, `cookie_len`,
`max_entropy`, `timestamp_utc`

---

### Host Header Anomaly (T1557)
Flags unusual `Host` header values:

| Indicator | Risk |
|---|---|
| Bare IP address in Host (`192.168.1.1`) | MEDIUM — bypasses virtual hosting, direct targeting |
| Special characters (`<`, `'`, `\r`, `\x00`) | HIGH — Host header injection (SSRF, cache poisoning) |
| Abnormally long Host header (> 253 chars) | MEDIUM — potential buffer overflow probe |

**Finding fields:** `src_ip`, `dst_ip`, `host_header`, `uri`, `reason`,
`timestamp_utc`

---

### HTTP Beaconing (T1071.001)
Groups HTTP requests by `(src_ip, host, uri_path)` and tests for regular-interval
polling using the **coefficient of variation** (CV = stdev / mean of inter-request
intervals). A low CV indicates machine-driven, clock-like behaviour.

**Detection criteria:**
- ≥ 10 requests to the same path (configurable via `BEACON_MIN_REQUESTS`)
- Interval ≥ 5 seconds (sub-5s intervals filtered as DNS/TCP retry noise)
- CV ≤ 0.30 (configurable via `BEACON_MAX_CV`)

**Severity:** CRITICAL (regular beaconing is highly indicative of C2)

**Finding fields:** `src_ip`, `host`, `uri_path`, `request_count`,
`mean_interval_sec`, `stdev_sec`, `cv`, `first_seen`, `last_seen`

---

### Unusual HTTP Server Header (T1071.001)
Matches HTTP `Server` response headers against known C2 and exploit framework
signatures (case-insensitive substring match):

**Signatures:** metasploit, empire, sliver, havoc, covenant, cobalt, meterpreter, beef

A server advertising these strings is almost certainly attacker-controlled infrastructure.

**Severity:** CRITICAL

**Finding fields:** `src_ip`, `dst_ip`, `server_header`, `matched`, `timestamp_utc`

---

### Suspicious HTTP Referer (T1071.001)
Flags anomalous `Referer` request headers:
- SQL injection patterns
- XSS patterns
- Path traversal sequences
- Null byte / CRLF injection (`\x00`, `\r`, `\n`)
- Abnormal length (> 500 chars)

Injection in Referer headers targets web application logging systems, log parsers,
and CSRF chain exploitation.

**Finding fields:** `src_ip`, `dst_ip`, `host`, `referer`, `reasons`,
`timestamp_utc`

---

### Deprecated / Weak TLS Version (T1040)
Detects TLS Client Hello messages advertising deprecated protocol versions by
inspecting the `tls.handshake.version` field. Works on both HTTP and non-HTTP TLS.

| Version | Risk | Known Attacks |
|---------|------|---------------|
| SSL 2.0 | CRITICAL | DROWN, export ciphers |
| SSL 3.0 | CRITICAL | POODLE |
| TLS 1.0 | HIGH | BEAST, CRIME, POODLE-TLS |
| TLS 1.1 | MEDIUM | Deprecated (RFC 8996) |

**Finding fields:** `src_ip`, `dst_ip`, `tls_version`, `sni`, `timestamp_utc`

---

## HTTP Flows CSV Columns

| Column | Description |
|--------|-------------|
| `timestamp_utc` | Packet timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source TCP port |
| `dst_port` | Destination TCP port |
| `direction` | `request` or `response` |
| `method` | HTTP method (requests only) |
| `uri` | Full request URI — truncated at 300 chars (requests only) |
| `host` | HTTP Host header (requests only) |
| `status_code` | HTTP response status code (responses only) |
| `user_agent` | User-Agent header — truncated at 200 chars (requests only) |
| `referer` | Referer header — truncated at 200 chars (requests only) |
| `server` | Server header (responses only) |
| `content_length` | Content-Length header value in bytes |
| `frame_len` | Ethernet frame length in bytes |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `SCANNING_MIN_ERRORS` | 50 | 4xx/5xx responses to a single client before flagging |
| `BEACON_MIN_REQUESTS` | 10 | Minimum requests per (src, path) for beaconing test |
| `BEACON_MAX_CV` | 0.30 | Maximum coefficient of variation to flag beaconing |
| `BEACON_MIN_INTERVAL_SEC` | 5.0 | Ignore sub-5s intervals as retry noise |
| `LARGE_UPLOAD_MIN_BYTES` | 500,000 | Upload size threshold (bytes) |
| `COOKIE_MIN_LENGTH` | 4096 | Cookie header length threshold |
| `COOKIE_ENTROPY_THRESHOLD` | 4.5 | Shannon entropy threshold on cookie values |
| `URI_MAX_LENGTH` | 2048 | URI length threshold |
| `UA_MAX_LENGTH` | 512 | User-Agent length threshold |
| `REFERER_MAX_LENGTH` | 500 | Referer header length threshold |

All thresholds are constants at the top of `lib/fan_http_threats.py`.

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

# Step 5 — HTTP(S) threat detection
./scripts/fan_http_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 6 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 7 — Generate consolidated incident report
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001
```

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| Suspicious User-Agent (malware/tool) | `TTPs/T1071.001.md` + `IOCs/url-<defanged>.md` | T1071.001 | Critical/High |
| HTTP Beaconing | `TTPs/T1071.001.md` + `IOCs/ip-<dst>.md` | T1071.001 | Critical |
| Suspicious URI (SQLi, traversal, RCE) | `TTPs/T1190.md` + `IOCs/url-<defanged>.md` | T1190 | Critical |
| Large HTTP Upload (exfil) | `TTPs/T1048.002.md` + `IOCs/ip-<dst>.md` | T1048.002 | High |
| Unusual HTTP Server header | `TTPs/T1071.001.md` + `IOCs/ip-<dst>.md` | T1071.001 | Critical |
| HTTP Scanning / Error Flood | `TTPs/T1595.md` + `IOCs/ip-<src>.md` | T1595 | High |
| Host Header Anomaly (MitM) | `TTPs/T1557.md` | T1557 | High |
| Cookie Anomaly (exfil) | `TTPs/T1048.md` | T1048 | High |
| Suspicious HTTP Referer | `Concepts/HTTP-referer-anomaly.md` | — | Medium |
| Deprecated TLS (1.0/1.1) | `TTPs/T1040.md` | T1040 | Critical/High |
| Unusual HTTP Methods | `Concepts/HTTP-method-anomaly.md` | — | Medium |

Verify:
```bash
./scripts/vault_context.sh ttp T1071.001
./scripts/vault_context.sh ioc <suspicious_dst_ip>
./scripts/vault_context.sh search "<case_id>"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No HTTP records found` | PCAP has no cleartext HTTP | Verify with `tshark -r capture.pcap -Y http.request` |
| All categories show `info` | Only HTTPS traffic present | HTTP(S) analysis still runs TLS version detection |
| Beaconing not detected | Intervals too short or too irregular | Lower `BEACON_MIN_REQUESTS` or raise `BEACON_MAX_CV` |
| Many false-positive UA flags | Legitimate tool traffic | Narrow `SUSPICIOUS_UA_PATTERNS` dict in `lib/fan_http_threats.py` |
| `tls.handshake.version` empty | tshark NTP/TLS field name changed | Verify with `tshark -r capture.pcap -Y "tls.handshake.type==1" -T fields -e tls.handshake.version` |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
