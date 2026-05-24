# Skill: FAN NBNS Threats

## Overview

Extracts all NBNS (NetBIOS Name Service, UDP 137) traffic from a PCAP file and detects
six threat categories covering NBT-NS poisoning and abuse attacks. Output is integrated
into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| NBNS Spoofing / Poisoning | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| NBNS Credential Theft | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| SMB Relay via NBNS | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| NBNS Network Enumeration | T1046 — Network Service Discovery | Medium |
| NBNS Denial of Service | T1498.001 — Direct Network Flood | High |
| WPAD Poisoning via NBNS | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/nbns_threats/<stem>/nbns_threats.json` |
| Flow inventory CSV | `./analysis/nbns_threats/<stem>/nbns_flows.csv` |
| Markdown report | `./analysis/nbns_threats/<stem>/nbns_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_nbns_threats.sh /path/to/capture.pcap
./scripts/fan_nbns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_nbns_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### NBNS Spoofing / Poisoning (T1557.001)
Compiles a NetBIOS name → set of responding IPs mapping from all NBNS responses.
If two or more distinct IPs claim the same name, the name is flagged as poisoned.
This detects rogue NBNS responders such as Responder, NBNSpoof, and Metasploit's
`auxiliary/spoof/nbns/nbns_response`.

**Finding fields:** `queried_name`, `responding_ips`, `responder_count`, `timestamp_utc`

---

### NBNS Credential Theft (T1557.001)
Identifies the set of IPs sending spoofed NBNS responses, then correlates with SMB
traffic to detect whether victim hosts authenticated against those IPs. When a host
resolves a name to a spoofed IP and then sends SMB auth, Net-NTLMv2 hashes are exposed.

**Finding fields:** `spoofing_ip`, `threat`, `timestamp_utc`

---

### SMB Relay via NBNS (T1557.001)
Extends credential theft detection: flags IPs that both received SMB authentication
(from poisoned victim) AND initiated outbound SMB connections (to a relay target),
consistent with NTLM relay tools such as Impacket's ntlmrelayx or Responder+MultiRelay.

**Finding fields:** `relay_ip`, `indicator`, `timestamp_utc`

---

### NBNS Network Enumeration (T1046)
Counts distinct NetBIOS names queried per source IP. Host discovery tools query many
names sequentially to map workgroups, server names, and domain controllers.

**Threshold:** `NBNS_ENUM_THRESHOLD = 20` distinct names per source IP.

**Finding fields:** `src_ip`, `unique_names`, `first_timestamp`, `last_timestamp`

---

### NBNS Denial of Service (T1498.001)
Counts total NBNS packets per source IP. High-rate NBNS floods target WINS servers
and can cause broadcast storms on flat Layer 2 networks.

**Threshold:** `NBNS_FLOOD_THRESHOLD = 200` packets per source IP.

**Finding fields:** `src_ip`, `packet_count`, `first_timestamp`, `last_timestamp`

---

### WPAD Poisoning via NBNS (T1557.001)
Flags any NBNS query or response containing the string "WPAD". Attackers respond to
WPAD NBNS queries with their own IP to serve a malicious PAC file, enabling full
HTTP interception including credential capture from corporate proxy-configured clients.

**Finding fields:** `ip`, `role` (querier/responder), `timestamp_utc`

---

## NBNS Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `name` | NetBIOS name queried or registered |
| `is_response` | 0=query, 1=response |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `NBNS_FLOOD_THRESHOLD` | 200 | NBNS packets per src IP to flag as flood |
| `NBNS_ENUM_THRESHOLD` | 20 | Distinct names queried per src to flag as enum |

All constants are at the top of `lib/fan_nbns_threats.py`.

---

## Vault Recording

Critical and High severity findings are written automatically when `--no-vault` is
absent and a `--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| All poisoning / relay categories | `TTPs/T1557.001.md` | T1557.001 |
| DoS flood | `TTPs/T1498.001.md` | T1498.001 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No NBNS traffic in PCAP | Verify: `tshark -r capture.pcap -Y "nbns"` |
| No spoofing found | Only one responder per name | Clean network or attack not in capture window |
| WPAD findings on every capture | Legitimate Windows WPAD probing at boot | Correlate with NBNS response to confirm active poisoning |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
