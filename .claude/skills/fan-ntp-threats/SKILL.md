# Skill: FAN NTP Threats

## Overview

Detects NTP-based attack patterns in a PCAP file using tshark field extraction
and Python heuristics. Covers 7 threat categories mapped to MITRE ATT&CK.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| NTP Amplification Attack | T1498.002 — Reflection Amplification | Critical |
| NTP Flood | T1498 — Network Denial of Service | High |
| Kiss-of-Death (KoD) | T1499 — Endpoint DoS | Medium/High |
| NTP Mode 7 / Monlist Abuse | T1590 — Gather Victim Network Information | Medium/High |
| Spoofed NTP Response | T1557 — Adversary-in-the-Middle | Medium/High |
| NTP Time Manipulation | T1070 — Indicator Removal | High |
| NTP Reconnaissance / Scan | T1595 — Active Scanning | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/ntp_threats/<stem>/ntp_threats.json` |
| NTP flows CSV | `./analysis/ntp_threats/<stem>/ntp_flows.csv` |
| Markdown report | `./analysis/ntp_threats/<stem>/ntp_threats_report.md` |

---

## Invocation

```bash
# Analyze a PCAP for NTP threats
./scripts/fan_ntp_threats.sh /path/to/capture.pcap

# With case ID (recommended)
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom stem (must match other analysis steps)
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001

# Skip vault writes (offline/air-gapped)
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_ntp_threats import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, records = analyze(pcap)
out_dir = Path("./analysis/ntp_threats/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, out_dir / "ntp_threats.json")
write_csv(records, out_dir / "ntp_flows.csv")
write_report(results, out_dir / "ntp_threats_report.md", pcap)
```

---

## Detection Logic

### NTP Amplification Attack (T1498.002)
The classic NTP DDoS amplification vector. Attacker sends small NTP requests
with a spoofed source IP (the victim). NTP servers respond with large packets
to the victim — classic monlist responses can be 200–500x the request size.

**Signals detected:**
- NTP server responses (mode 4) with frame length ≥ 200 bytes
- Single destination IP (victim) receiving ≥ 50 such large responses
- Responses originating from ≥ 3 distinct source IPs

**Finding fields:** `victim_ip`, `large_response_count`, `distinct_sources`,
`total_bytes_recv`, `avg_response_bytes`, `sample_sources`

---

### NTP Flood (T1498)
High-volume raw NTP traffic from a single source overwhelming a target.

**Signals detected:**
- ≥ 500 NTP packets from a single source IP, OR
- ≥ 50 NTP packets per second from a single source

**Finding fields:** `src_ip`, `packet_count`, `pps`, `duration_sec`

---

### Kiss-of-Death (KoD) (T1499)
NTP server responses with stratum=0 and a KoD reference ID telling clients to
stop querying. Spoofed KoD packets can be used to deny NTP service to clients.

**KoD codes detected:** DENY, RSTR, RATE, INIT, STEP, MAHV, ACTS, AUTH,
AUTO, BCST, CRYPT, DROP, RSET, XFAC, NKEY, RMOT

**Severity escalation:** If KoD responses originate from > 3 distinct sources →
HIGH (indicates spoofed KoD flood targeting multiple clients).

**Finding fields:** `kod_code`, `count`, `src_ips`, `dst_ips`, `first_seen`

---

### NTP Mode 7 / Monlist Abuse (T1590)
NTP Mode 7 (private) is deprecated since NTPv4. Its presence indicates either
legacy `ntpdc` usage or exploitation of the `monlist` command, which returns
up to 600 recent NTP clients per request — a massive amplification vector.

**Signals detected:**
- Any NTP mode 7 packets from a single source (≥ 5 packets to flag)

**Finding fields:** `src_ip`, `mode7_count`, `dst_ips`, `first_seen`

---

### Spoofed NTP Response (T1557)
NTP server responses that deviate from expected characteristics, indicating
crafted/spoofed packets used for MITM time poisoning.

**Three sub-indicators:**
1. **Non-standard source port**: NTP responses (mode 4) from port ≠ 123
2. **Unsynchronised server**: Stratum 16 (unsync) sending server responses
3. **Multiple stratum-1 conflicts**: > 3 distinct stratum-1 servers claiming
   to be the time source for the same client IP

**Finding fields:** `indicator`, `src_ip`, `src_port`, `dst_ip`, `stratum`
(or `client_ip`, `server_count`, `servers` for the multi-stratum case)

---

### NTP Time Manipulation (T1070)
Rogue or misconfigured NTP servers sending extreme root dispersion or root delay
values. Adversaries manipulate NTP time to shift system clocks, causing log
timestamps to become unreliable and masking intrusion activity.

**Signals detected:**
- `rootdispersion` > 16 seconds from a server (mode 4 or 5)
- `rootdelay` > 16 seconds from a server

Normal root dispersion for a healthy NTP server is < 100 milliseconds.

**Finding fields:** `src_ip`, `stratum`, `rootdispersion`, `rootdelay`,
`flag`, `timestamp_utc`

---

### NTP Reconnaissance / Server Scan (T1595)
A single source querying many distinct NTP servers — used to enumerate NTP
infrastructure or identify servers with monlist enabled for DDoS recruitment.

**Signals detected:**
- Single source IP sending NTP client requests (mode 3) to ≥ 20 distinct servers

**Finding fields:** `src_ip`, `unique_servers`, `duration_sec`,
`rate_servers_per_sec`, `sample_targets`

---

## NTP Flows CSV Columns

| Column | Description |
|--------|-------------|
| `timestamp_utc` | Packet timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source UDP port |
| `dst_port` | Destination UDP port |
| `frame_len` | Ethernet frame length (bytes) |
| `ntp_mode` | NTP mode number (0–7) |
| `ntp_mode_name` | Human-readable mode name |
| `stratum` | NTP stratum (0=KoD/unspec, 1=primary, 2–15=secondary, 16=unsync) |
| `refid` | Reference ID (KoD code for stratum 0; clock type for stratum 1; IP for stratum 2+) |
| `rootdelay` | Root delay in seconds |
| `rootdispersion` | Root dispersion in seconds |
| `ppoll` | Poll interval exponent (interval = 2^ppoll seconds) |
| `is_kod` | 1 if Kiss-of-Death packet |
| `is_mode7` | 1 if NTP Mode 7 (private/deprecated) packet |
| `is_large_response` | 1 if mode 4 response ≥ 200 bytes (amplification candidate) |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `FLOOD_MIN_PACKETS` | 500 | NTP packets from single source to flag flood |
| `FLOOD_PPS_THRESHOLD` | 50 | Packets per second to flag flood |
| `AMPLIFICATION_RESPONSE_MIN_BYTES` | 200 | Frame length for "large" NTP response |
| `AMPLIFICATION_MIN_RESPONSES` | 50 | Large responses to same victim IP |
| `AMPLIFICATION_MIN_SOURCES` | 3 | Distinct sources sending to victim |
| `MODE7_MIN_COUNT` | 5 | Mode 7 packets from single source |
| `RECON_MIN_SERVERS` | 20 | Unique NTP servers queried |
| `TIME_MANIP_ROOTDISP_THRESH` | 16.0 | Root dispersion (seconds) |
| `TIME_MANIP_ROOTDELAY_THRESH` | 16.0 | Root delay (seconds) |

Thresholds are constants at the top of `lib/fan_ntp_threats.py` — adjust for
high-traffic or noisy environments.

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

# Step 5 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 6 — Generate consolidated incident report
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001
```

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| NTP Amplification / DDoS | `TTPs/T1498.002.md` + `IOCs/ip-<reflector>.md` | T1498.002 | High |
| NTP Flood | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Kiss-of-Death (KoD) attack | `TTPs/T1499.md` | T1499 | High |
| Mode 7 / Monlist abuse | `TTPs/T1590.md` | T1590 | Critical |
| Spoofed NTP Response | `TTPs/T1557.md` + `IOCs/ip-<spoof_src>.md` | T1557 | High |
| Time Manipulation | `TTPs/T1562.md` | T1562 | Critical |
| NTP Reconnaissance | `TTPs/T1595.md` + `IOCs/ip-<src>.md` | T1595 | Medium |

Verify:
```bash
./scripts/vault_context.sh ttp T1498.002
./scripts/vault_context.sh ioc <ntp_reflector_ip>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No NTP records found` | PCAP has no UDP/123 traffic | Verify PCAP with `tshark -r capture.pcap -Y ntp` |
| All categories show `info` | Low-volume NTP; thresholds too high | Lower `FLOOD_MIN_PACKETS`/`AMPLIFICATION_MIN_RESPONSES` in `lib/fan_ntp_threats.py` |
| `ntp.flags.mode` field empty | Older tshark version | Upgrade tshark or the dissector falls back gracefully (records will have mode=0) |
| Empty `refid` for KoD | tshark encoding issue | KoD codes may appear as `0x44454e59` (hex) — check raw PCAP in Wireshark |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag; check `lib/knowledge_extractor.py` is present |
