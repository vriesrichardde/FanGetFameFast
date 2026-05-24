# Skill: FAN NetBIOS Threats

## Overview

Extracts NetBIOS Name Service (NBNS/NBT-NS, UDP 137) and NetBIOS Session Service
(NBSS, TCP 139) / SMB traffic from a PCAP file and detects eight threat categories
covering the full NetBIOS attack surface. Output is integrated into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| NetBIOS Poisoning / Spoofing | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| NTLM Hash Theft | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| NTLM Relay Attacks | T1557.001 — LLMNR/NBT-NS Poisoning and SMB Relay | Critical |
| NetBIOS Enumeration | T1046 — Network Service Discovery | Medium |
| NetBIOS Reconnaissance | T1018 — Remote System Discovery | Medium |
| Null Session Exploitation | T1078.003 — Valid Accounts: Local Accounts | High |
| NetBIOS DDoS Amplification | T1498.001 — Direct Network Flood | High |
| Malware Propagation via SMB | T1021.002 — SMB/Windows Admin Shares | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/netbios_threats/<stem>/netbios_threats.json` |
| Flow inventory CSV | `./analysis/netbios_threats/<stem>/netbios_flows.csv` |
| Markdown report | `./analysis/netbios_threats/<stem>/netbios_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_netbios_threats.sh /path/to/capture.pcap
./scripts/fan_netbios_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_netbios_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### NetBIOS Poisoning / Spoofing (T1557.001)
Compiles a NetBIOS name → set of responding IPs from all NBNS responses. When two or
more distinct IPs claim the same name, the name is flagged. Detects Responder,
NBNSpoof, and Metasploit `auxiliary/spoof/nbns` in classic LAN environments.

**Finding fields:** `queried_name`, `responding_ips`, `responder_count`, `timestamp_utc`

---

### NTLM Hash Theft (T1557.001)
Cross-correlates the set of poisoning IPs against NTLMSSP authentication traffic and
SMB flows. When a victim host sends NTLM challenge/response or SMB Session Setup to a
poisoned IP, Net-NTLMv1/v2 hash capture is flagged.

**Finding fields:** `spoofing_ip`, `threat`, `timestamp_utc`

---

### NTLM Relay Attacks (T1557.001)
Flags IPs that both received SMB authentication from a victim and initiated outbound
SMB connections to a relay target, consistent with Impacket ntlmrelayx or
Responder+MultiRelay relaying captured NTLM credentials.

**Finding fields:** `relay_ip`, `indicator`, `timestamp_utc`

---

### NetBIOS Enumeration (T1046)
Counts distinct NetBIOS names queried per source IP. Tools like nbtscan, nmap -sV,
and enum4linux send systematic name queries to build a picture of network services.

**Threshold:** `NBNS_ENUM_THRESHOLD = 20` distinct names per source IP.

**Finding fields:** `src_ip`, `unique_names`, `first_timestamp`, `last_timestamp`

---

### NetBIOS Reconnaissance (T1018)
Counts broadcast NBNS queries (destination .255 or 255.255.255.255) per source IP.
Broadcast-based name enumeration reveals hostnames, workgroup membership, and MAC
addresses without any authentication, making it a stealthy initial discovery technique.

**Threshold:** `RECON_BROADCAST_THRESH = 50` broadcast queries per source IP.

**Finding fields:** `src_ip`, `broadcast_count`, `first_timestamp`, `last_timestamp`

---

### Null Session Exploitation (T1078.003)
Detects SMB connections to the IPC$ share (a classic null session indicator). Null
sessions allow unauthenticated enumeration of shares, users, groups, password policies,
and domain SIDs via named pipes — exploitable on legacy Windows and misconfigured systems.

**Finding fields:** `src_ip`, `indicator`, `timestamp_utc`

---

### NetBIOS DDoS Amplification (T1498.001)
Counts total NBNS packets per source IP. High-rate floods saturate WINS servers, cause
broadcast storms on flat Layer 2 networks, and can exhaust switch ARP tables.

**Threshold:** `NBNS_FLOOD_THRESHOLD = 200` NBNS packets per source IP.

**Finding fields:** `src_ip`, `packet_count`, `first_timestamp`, `last_timestamp`

---

### Malware Propagation via SMB (T1021.002)
Counts SMB connections to administrative shares (IPC$, ADMIN$, C$, D$, E$) per source
IP. Worms (EternalBlue, WannaCry, NotPetya), ransomware, and lateral movement tools
(Impacket psexec, CrackMapExec) access these shares for remote code execution.

**Threshold:** `SMB_SHARE_THRESHOLD = 10` admin share connections per source IP.

**Finding fields:** `src_ip`, `admin_share_hits`, `first_timestamp`, `timestamp_utc`

---

## NetBIOS Flow CSV Columns

The flow CSV combines NBNS, SMB, and SMB2 traffic.

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `name` | NetBIOS name / SMB share path / SMB2 filename |
| `is_response` | 0=query, 1=response (NBNS only; empty for SMB) |
| `protocol` | NBNS, SMB, or SMB2 |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `NBNS_FLOOD_THRESHOLD` | 200 | NBNS packets per src IP to flag as DDoS |
| `NBNS_ENUM_THRESHOLD` | 20 | Distinct names queried per src to flag as enum |
| `RECON_BROADCAST_THRESH` | 50 | Broadcast NBNS queries per src to flag as recon |
| `SMB_SHARE_THRESHOLD` | 10 | Admin share connections per src to flag as propagation |

All constants are at the top of `lib/fan_netbios_threats.py`.

---

## Vault Recording

Critical and High severity findings are written automatically when `--no-vault` is
absent and a `--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Poisoning / Hash Theft / Relay | `TTPs/T1557.001.md` | T1557.001 |
| Null Session | `TTPs/T1078.003.md` | T1078.003 |
| DDoS | `TTPs/T1498.001.md` | T1498.001 |
| Malware Propagation | `TTPs/T1021.002.md` | T1021.002 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No NBNS or SMB traffic | Verify: `tshark -r capture.pcap -Y "nbns"` |
| No poisoning found | Single responder per name | Clean capture or attack outside window |
| Null session FP | SCCM/WMI legitimate IPC$ access | Correlate with auth events; filter known admin IPs |
| SMB propagation FP | Domain software deployment | Check SMB source against known SCCM/WSUS servers |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
