# Skill: FAN ICMP Threats

## Overview

Analyzes a PCAP file for ICMP-based attack patterns using `tshark` for packet
extraction and Python-based heuristics for detection. Covers 10 threat categories
mapped to MITRE ATT&CK. High-severity findings are automatically written to the
Obsidian vault as TTPs and IOCs.

| Output | Contents |
|--------|----------|
| `icmp_threats_report.md` | Human-readable report: severity table, per-category findings, MITRE links |
| `icmp_threats.json` | Full machine-readable findings (all categories) |
| `icmp_flows.csv` | Per-packet ICMP flow log: type, code, ip_len, data_len, TTL, fragment info |

All outputs are written to `./analysis/icmp_threats/<pcap_stem>/`.

> **Note:** This skill covers ICMPv4 only. ICMPv6 uses protocol 58 in IPv6
> and different tshark fields (`icmpv6.type`, `icmpv6.code`) — a separate skill
> would be needed for ICMPv6 analysis.

---

## Invocation

```bash
# Standard run
./scripts/fan_icmp_threats.sh /path/to/capture.pcap

# With case ID (recommended — stamped in report and vault entries)
./scripts/fan_icmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom output stem
./scripts/fan_icmp_threats.sh capture.pcap --stem my-investigation

# Skip vault writes (offline / restricted environment)
./scripts/fan_icmp_threats.sh capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from pathlib import Path
from fan_icmp_threats import extract_icmp_records, detect_icmp_flood, detect_icmp_tunneling

records = extract_icmp_records(Path("capture.pcap"))
print(detect_icmp_flood(records))
print(detect_icmp_tunneling(records))
```

---

## Full IR Workflow

```bash
# Step 1 — Extract netflow, IPs, FQDNs from PCAP
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — ICMP-specific threat detection
./scripts/fan_icmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 3 — DNS-specific threat detection
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 4 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 5 — Review ICMP threat report
cat ./analysis/icmp_threats/capture/icmp_threats_report.md

# Step 6 — Triage specific threat category
python3 -c "
import json
data = json.load(open('./analysis/icmp_threats/capture/icmp_threats.json'))
import pprint; pprint.pprint(data['tunneling'])
"
```

---

## Detection Categories

| Category | MITRE ATT&CK | Severity | What it detects |
|----------|-------------|----------|-----------------|
| ICMP Flood | T1498.001 | High | ≥1000 Echo Requests from single source or ≥100 pps |
| Ping of Death | T1499.002 | High | IP length ≥65000 B or fragment offset > 65000 |
| ICMP Fragmentation Attack | T1498.001 | High/Medium | Many ICMP fragments or multi-fragment reassembly streams |
| ICMP Tunneling | T1572 | Critical | Echo payloads ≥128 bytes (normal ping ≤56 bytes) |
| Smurf Attack / Broadcast Amplification | T1498.001 | High | Echo Requests to broadcast addresses (x.x.x.255 / 255.255.255.255) |
| ICMP Redirect Attack | T1557 | High/Medium | ICMP Type 5 Redirect messages — routing manipulation / MITM |
| ICMP Network Sweep / Scan | T1595.001 | Medium | Single source pings ≥20 unique destination IPs |
| Destination Unreachable Flood | T1498 | High/Medium | ≥200 ICMP Type 3 messages from single source |
| ICMP Reconnaissance Types | T1595 | Medium | Obsolete types: Timestamp (13), Info Request (15), Address Mask (17) |
| ICMP Data Exfiltration | T1048 | Critical | High-entropy (≥3.5 bits) payload data ≥64 bytes in Echo packets |

---

## Detection Thresholds

These are constants in `lib/fan_icmp_threats.py` — adjust to fit your environment:

| Constant | Default | Purpose |
|----------|---------|---------|
| `FLOOD_MIN_PACKETS` | 1000 | Total Echo Requests to flag flood |
| `FLOOD_PPS_THRESHOLD` | 100 | Packets per second triggering flood flag |
| `POD_MIN_IP_LEN` | 65000 B | IP total length indicating oversized ICMP |
| `TUNNEL_MIN_PAYLOAD` | 128 B | ICMP data bytes indicating covert channel |
| `TUNNEL_MIN_PACKETS` | 10 | Minimum oversized Echo packets before flagging |
| `SWEEP_MIN_HOSTS` | 20 | Unique destination IPs to flag as ping sweep |
| `FRAG_MIN_COUNT` | 10 | Total fragmented ICMP packets to flag |
| `FRAG_STREAM_MIN` | 3 | Fragments per reassembly stream to flag |
| `REDIR_MIN_COUNT` | 3 | ICMP Redirect messages from single source |
| `UNREACH_FLOOD_THRESH` | 200 | ICMP Type 3 count per source to flag |
| `EXFIL_PAYLOAD_THRESHOLD` | 64 B | Minimum ICMP data bytes inspected for exfiltration |
| `EXFIL_ENTROPY_THRESHOLD` | 3.5 bits | Shannon entropy threshold on payload hex |
| `EXFIL_MIN_PACKETS` | 5 | High-entropy packets needed before exfil flag |

---

## IR Triage Queries

```bash
STEM="capture"
OUT="./analysis/icmp_threats/$STEM"

# All threat categories with findings
python3 -c "
import json
data = json.load(open('$OUT/icmp_threats.json'))
for k,v in data.items():
    if v['severity'] != 'info':
        print(f\"{v['severity'].upper():8s}  {v['name']}: {v['count']} finding(s)\")
"

# All Echo Requests (potential flood or sweep)
awk -F, '$4 == "8"' $OUT/icmp_flows.csv | wc -l

# Top source IPs by Echo Request count
awk -F, '$4 == "8" && NR>1 {print $2}' $OUT/icmp_flows.csv | sort | uniq -c | sort -rn | head -20

# Fragmented ICMP packets
awk -F, '$11 == "1" && NR>1' $OUT/icmp_flows.csv

# Oversized ICMP (ip_len > 1500 — exceeds standard Ethernet MTU)
awk -F, '$7 > 1500 && NR>1 {print $0}' $OUT/icmp_flows.csv

# Large data payloads (potential tunneling — data > 128 bytes)
awk -F, '$8 > 128 && NR>1 {print $0}' $OUT/icmp_flows.csv | head -20

# ICMP Redirect messages (Type 5)
awk -F, '$4 == "5" && NR>1 {print $0}' $OUT/icmp_flows.csv

# Destination Unreachable messages (Type 3)
awk -F, '$4 == "3" && NR>1 {print $2, $3}' $OUT/icmp_flows.csv | sort | uniq -c | sort -rn | head -20

# Obsolete/recon ICMP types (13, 15, 17)
awk -F, '($4 == "13" || $4 == "15" || $4 == "17") && NR>1 {print $0}' $OUT/icmp_flows.csv

# Traffic from a specific suspect IP
awk -F, '$2 == "192.168.1.100" && NR>1 {print $0}' $OUT/icmp_flows.csv

# Unique destination IPs pinged by a specific source (sweep pivot)
awk -F, '$2 == "10.0.0.5" && $4 == "8" && NR>1 {print $3}' $OUT/icmp_flows.csv | sort -u
```

---

## ICMP Tunneling Detection Logic

Normal `ping` sends 32–56 bytes of padding data in the Echo payload. Tunneling tools
carry full IP packets or encoded data in the payload, producing significantly larger
packets. Two independent signals flag tunneling:

1. **Large payload** — estimated data bytes (`ip_len - 28`) ≥ 128 bytes
2. **Volume** — ≥10 oversized Echo packets from the same source

Known tunneling tools and their typical payload sizes:
| Tool | Typical Payload |
|------|----------------|
| ptunnel | ~1400 bytes (full MTU) |
| icmptunnel | ~1500 bytes |
| PingTunnel | variable, 64–1400 bytes |
| icmpsh | ~128 bytes (shell commands) |

---

## Exfiltration Detection Logic

High-entropy payloads in ICMP Echo indicate encoded or encrypted data being smuggled
out of the network. Shannon entropy is computed on the raw hex string of the payload.

| Signal | Threshold | Indication |
|--------|-----------|------------|
| Payload size | ≥ 64 bytes | Sufficient data to analyze |
| Shannon entropy | ≥ 3.5 bits | Random/encoded distribution |
| Packet count | ≥ 5 packets | Sustained pattern, not single outlier |

Natural-language or pattern data (e.g., standard ping padding `\x08\x09\x0a...`) has
low entropy (~2.5 bits). Base64 / AES-encrypted blobs push entropy toward 4.0+ bits.

---

## Smurf Attack Detection Logic

A Smurf attack sends ICMP Echo Requests with a **spoofed source IP** (the victim) to a
**subnet broadcast address**. Every host on that subnet replies to the spoofed source,
amplifying the attack by a factor equal to the number of hosts.

Detection: any ICMP Echo Request with destination `x.x.x.255` or `255.255.255.255` is
flagged. In modern networks this is near-universally malicious — well-configured routers
drop directed broadcasts. The number of Echo Requests gives the expected amplification
factor (one reply per live host per request).

---

## Vault Integration

High and critical severity findings are automatically written to the vault:

- **TTPs** — one note per triggered MITRE technique (updated if existing)
- **IOCs** — suspicious source IPs from flood, tunneling, exfiltration, redirect, smurf

Use `--no-vault` to suppress vault writes (offline environments or repeated test runs).

```bash
# Manually record a confirmed ICMP tunnel source IP
python3 - <<'EOF'
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc, record_ttp
record_ttp("T1572", "Protocol Tunneling",
           "ICMP tunnel confirmed via ptunnel — 1400-byte payloads in Echo packets.",
           "CASE-2025-001", tactic="command-and-control")
record_ioc("ip", "203.0.113.42", "ICMP tunnel C2 endpoint — 1400-byte Echo payloads.",
           "CASE-2025-001", severity="critical",
           related_ttps=["T1572 Protocol Tunneling", "T1048 Exfiltration Over Alternative Protocol"])
EOF
```

---

## Output Detail

### icmp_threats_report.md

Executive summary table followed by per-category sections with:
- Severity and MITRE ATT&CK link
- Description of what was detected
- Top 10 findings in JSON (one per line for easy grepping)
- List of clean categories at the bottom

### icmp_threats.json

Full structured output. Each key is a detection category:

```json
{
  "tunneling": {
    "name": "ICMP Tunneling",
    "severity": "critical",
    "count": 3,
    "mitre": ["T1572", "Protocol Tunneling"],
    "findings": [ ... ],
    "description": "..."
  },
  ...
}
```

### icmp_flows.csv

One row per ICMP packet.

| Column | Description |
|--------|-------------|
| `timestamp_utc` | Packet timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `icmp_type` | Numeric ICMP type (0=Echo Reply, 8=Echo Request, 5=Redirect, …) |
| `icmp_type_name` | Human-readable type name |
| `icmp_code` | ICMP sub-code |
| `ip_len` | Total IP datagram length (bytes) |
| `data_len_estimated` | Estimated ICMP data payload: `max(data.len, ip_len - 28)` |
| `ttl` | IP TTL value |
| `frame_len` | Total frame size on wire (bytes) |
| `fragmented` | `1` if MF flag set or fragment offset > 0, else `0` |
| `frag_offset` | IP fragment offset (bytes) |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No ICMP records found` | PCAP has no ICMP traffic | Verify with `tshark -r cap.pcap -Y "icmp" -q` |
| Tunneling not detected | Payloads < 128 bytes | Lower `TUNNEL_MIN_PAYLOAD` in `lib/fan_icmp_threats.py` |
| Sweep false negatives | Sweep spans > 1 PCAP | Use merged PCAP or lower `SWEEP_MIN_HOSTS` |
| No flood detected | Capture too short | Capture during active flood, or lower `FLOOD_MIN_PACKETS` |
| Vault writes fail | `pyyaml` not installed | `pip3 install pyyaml` |
| `tshark` permission error | Capture file locked | Copy PCAP to `./exports/` first |
| ICMPv6 not analyzed | Different protocol fields | This skill is ICMPv4 only; use `-Y "icmpv6"` separately |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent and severity meets threshold.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| ICMP flood / DoS | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Ping of Death | `TTPs/T1499.md` + `IOCs/ip-<src>.md` | T1499 | Critical |
| ICMP fragmentation attack | `TTPs/T1499.md` | T1499 | High |
| ICMP tunneling (data exfil) | `TTPs/T1095.md` + `IOCs/ip-<dst>.md` | T1095 | Critical |
| Smurf amplification | `TTPs/T1498.001.md` | T1498.001 | High |
| ICMP redirect injection | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | Critical |
| ICMP sweep / host discovery | `TTPs/T1018.md` + `IOCs/ip-<src>.md` | T1018 | Medium |
| Unreachable flood | `Concepts/ICMP-unreachable-flood.md` | — | Medium |
| Recon via unusual ICMP types | `TTPs/T1595.md` | T1595 | Medium |
| Data exfiltration via large payload | `TTPs/T1048.md` + `IOCs/ip-<dst>.md` | T1048 | High |

Verify:
```bash
./scripts/vault_context.sh ttp T1095
./scripts/vault_context.sh ioc <suspicious_ip>
```

## Output Paths

| File | Path |
|------|------|
| Threat Report | `./analysis/icmp_threats/<stem>/icmp_threats_report.md` |
| JSON Findings | `./analysis/icmp_threats/<stem>/icmp_threats.json` |
| ICMP Flow CSV | `./analysis/icmp_threats/<stem>/icmp_flows.csv` |
| IOC Vault Notes | `./vault/IOCs/ip-<defanged_ip>.md` |
| TTP Vault Notes | `./vault/TTPs/<mitre_id>.md` |
