# Skill: FAN LLMNR Threats

## Overview

Extracts all LLMNR (Link-Local Multicast Name Resolution, UDP/TCP 5355) traffic from
a PCAP file and detects four threat categories covering LLMNR poisoning attacks.
Output is integrated into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| LLMNR Spoofing / Poisoning | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| LLMNR Credential Theft | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| SMB Relay via LLMNR | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| LLMNR Reconnaissance | T1046 — Network Service Discovery | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/llmnr_threats/<stem>/llmnr_threats.json` |
| Flow inventory CSV | `./analysis/llmnr_threats/<stem>/llmnr_flows.csv` |
| Markdown report | `./analysis/llmnr_threats/<stem>/llmnr_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_llmnr_threats.sh /path/to/capture.pcap
./scripts/fan_llmnr_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_llmnr_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### LLMNR Spoofing / Poisoning (T1557.001)
LLMNR queries are sent to multicast 224.0.0.252 (port 5355). Responses must be unicast
back to the querier. This detector compiles a queried-name → set of responding IPs map
from all LLMNR responses. If two or more distinct unicast IPs respond to the same name
query, a rogue LLMNR responder is present (e.g., Responder, Inveigh, PowerSploit).

**Finding fields:** `queried_name`, `responding_ips`, `responder_count`, `timestamp_utc`

---

### LLMNR Credential Theft (T1557.001)
Builds the set of spoofing IPs (those that issued LLMNR responses alongside legitimate
responders), then checks whether any victim host sent SMB or HTTP authentication to one
of those IPs after the spoofed response. This is the canonical Net-NTLMv2 hash capture
path used in virtually every internal red-team engagement.

**Finding fields:** `spoofing_ip`, `threat`, `timestamp_utc`

---

### SMB Relay via LLMNR (T1557.001)
Extends credential theft: flags IPs that both received authentication from a poisoned
victim (inbound SMB) and initiated outbound SMB connections, consistent with NTLM relay
tools (Impacket ntlmrelayx, Responder+MultiRelay) relaying captured hashes to targets.

**Finding fields:** `relay_ip`, `indicator`, `timestamp_utc`

---

### LLMNR Reconnaissance (T1046)
Counts distinct hostnames queried per source IP. Automated tools query many hostnames
to discover live hosts and services. High query counts from a single source indicate
host discovery or automated tooling.

**Threshold:** `LLMNR_RECON_THRESHOLD = 20` distinct names per source IP.

**Finding fields:** `src_ip`, `unique_names`, `first_timestamp`, `last_timestamp`

---

## LLMNR Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `is_response` | 0=query, 1=response |
| `queried_name` | Hostname queried (DNS format) |
| `resolved_ip` | IP address in response (if any) |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `LLMNR_RECON_THRESHOLD` | 20 | Distinct names queried per src to flag as recon |

All constants are at the top of `lib/fan_llmnr_threats.py`.

---

## Vault Recording

Critical and High severity findings are written automatically when `--no-vault` is
absent and a `--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| All poisoning / relay categories | `TTPs/T1557.001.md` | T1557.001 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No LLMNR traffic in PCAP | Verify: `tshark -r capture.pcap -Y "llmnr"` |
| No spoofing found | Single legitimate LLMNR responder | Expected in clean environments |
| Missing queried_name | LLMNR multicast with no DNS fields | tshark version may parse differently; check raw with `-x` |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
