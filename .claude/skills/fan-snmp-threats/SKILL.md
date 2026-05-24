# Skill: FAN SNMP Threats

## Overview

Extracts all SNMP traffic from a PCAP file and detects six threat categories covering
SNMP-based network attacks. Output is integrated into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| SNMP Default Credentials | T1078 / T1110.001 — Valid Accounts / Brute Force | High |
| SNMP Man-in-the-Middle | T1557 — Adversary-in-the-Middle | Critical |
| SNMP Denial of Service | T1498.001 — Direct Network Flood | High |
| SNMP Reconnaissance & Mapping | T1046 — Network Service Discovery | Medium |
| Malicious Configuration Change (SET) | T1565.001 — Stored Data Manipulation | Critical |
| SNMP Malware / Data Transfer | T1105 — Ingress Tool Transfer | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/snmp_threats/<stem>/snmp_threats.json` |
| Flow inventory CSV | `./analysis/snmp_threats/<stem>/snmp_flows.csv` |
| Markdown report | `./analysis/snmp_threats/<stem>/snmp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_snmp_threats.sh /path/to/capture.pcap
./scripts/fan_snmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_snmp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_snmp_threats import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, flows = analyze(pcap)
out_dir = Path("./analysis/snmp_threats/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, flows, out_dir / "snmp_threats.json")
write_csv(flows, out_dir / "snmp_flows.csv")
write_report(results, out_dir / "snmp_threats_report.md", pcap)
```

---

## Detection Logic

### SNMP Default Credentials (T1078 / T1110.001)
Scans all SNMP packets for well-known community strings: `public`, `private`, or empty
string. These defaults enable unauthenticated read (community: public) or read-write
(community: private) access to managed network devices.

**Finding fields:** `src_ip`, `community`, `timestamp_utc`

---

### SNMP Man-in-the-Middle (T1557)
Builds a set of IPs that received SNMP GetRequests (dst port 161). Flags any SNMP
GetResponse originating from an IP that was never a request destination — indicating
traffic interception, rogue SNMP responder, or relay activity.

**Finding fields:** `unexpected_responder`, `timestamp_utc`

---

### SNMP Denial of Service (T1498.001)
Counts total SNMP packets per source IP. An unusually high count can saturate managed
device CPU (many SNMP agents are single-threaded) and cause agent unavailability.

**Threshold:** `SNMP_FLOOD_THRESHOLD = 200` packets per source IP.

**Finding fields:** `src_ip`, `packet_count`, `first_timestamp`, `last_timestamp`

---

### SNMP Reconnaissance & Mapping (T1046)
Counts distinct destination IPs queried (dst port 161) per source. Tools like snmpwalk,
Net-SNMP, and snmp-check systematically scan subnets to enumerate device types,
configurations, and network topology via MIB-II and enterprise OIDs.

**Threshold:** `SNMP_SCAN_THRESHOLD = 15` unique target IPs per source.

**Finding fields:** `src_ip`, `unique_targets`, `first_timestamp`, `last_timestamp`

---

### Malicious Configuration Change / SNMP SET (T1565.001)
Uses tshark display filter `snmp.setrequest` to extract SetRequest PDUs. SNMP SET
allows modification of device configuration including routing tables, interface state,
SNMP trap destinations, and community strings.

**Finding fields:** `src_ip`, `target_ip`, `timestamp_utc`

---

### SNMP Malware / Data Transfer (T1105)
Flags SNMP frames exceeding the large-frame threshold. Oversized SNMP packets may
indicate firmware upload via TFTP-over-SNMP, OctetString-encoded payloads in SET
operations, or data exfiltration through SNMP GET responses.

**Threshold:** `SNMP_LARGE_THRESHOLD = 1400` bytes per frame.

**Finding fields:** `src_ip`, `dst_ip`, `frame_len`, `timestamp_utc`

---

## SNMP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `frame_len` | Frame length in bytes |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | UDP source port |
| `dst_port` | UDP destination port (161=agent, 162=trap) |
| `snmp_version` | SNMP version (0=v1, 1=v2c, 3=v3) |
| `community` | Community string (v1/v2c only) |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `SNMP_FLOOD_THRESHOLD` | 200 | SNMP packets per src IP to flag as flood |
| `SNMP_SCAN_THRESHOLD` | 15 | Distinct target IPs per src to flag as recon |
| `SNMP_LARGE_THRESHOLD` | 1400 | Frame bytes to flag as large data transfer |

All constants are at the top of `lib/fan_snmp_threats.py`.

---

## Vault Recording

Critical and High severity findings are written automatically when `--no-vault` is
absent and a `--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Default Credentials | `TTPs/T1078.md` | T1078 |
| MitM | `TTPs/T1557.md` | T1557 |
| DoS Flood | `TTPs/T1498.001.md` | T1498.001 |
| Config Manipulation | `TTPs/T1565.001.md` | T1565.001 |
| Malware Transfer | `TTPs/T1105.md` | T1105 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No SNMP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "snmp"` |
| No default cred findings | SNMPv3 (no community strings) or non-default strings | Expected — SNMPv3 uses user-based auth |
| No SET findings | No SNMP write activity | Genuine read-only SNMP traffic |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
