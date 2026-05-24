# Skill: FAN SSDP Threats

## Overview

Extracts all SSDP/UPnP traffic (UDP 1900) from a PCAP file and detects four threat
categories covering SSDP amplification and UPnP abuse. Output is integrated into the
PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| SSDP Amplification / Reflection DDoS | T1498.002 — Reflection Amplification | High |
| Unauthorized Device Exposure | T1590 — Gather Victim Network Information | High |
| SSDP Local Network Manipulation | T1557 — Adversary-in-the-Middle | High |
| Vulnerable UPnP Implementation | T1203 — Exploitation for Client Execution | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/ssdp_threats/<stem>/ssdp_threats.json` |
| Flow inventory CSV | `./analysis/ssdp_threats/<stem>/ssdp_flows.csv` |
| Markdown report | `./analysis/ssdp_threats/<stem>/ssdp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_ssdp_threats.sh /path/to/capture.pcap
./scripts/fan_ssdp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_ssdp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### SSDP Amplification / Reflection DDoS (T1498.002)
SSDP M-SEARCH requests sent to the multicast address 239.255.255.250 can elicit large
NOTIFY responses from all UPnP-enabled devices. This detector flags:
1. M-SEARCH from non-RFC1918 (external) source IPs — indicates spoofed source for reflection.
2. M-SEARCH flood: high count (≥ `SSDP_FLOOD_THRESHOLD`) from any single source IP.

**Finding fields:** `src_ip`, `msearch_count`, `source_type`, `first_timestamp`, `last_timestamp`

---

### Unauthorized Device Exposure (T1590)
Scans SSDP NOTIFY packets for `LOCATION` headers referencing non-RFC1918 (external)
URLs. Legitimate UPnP devices should only advertise internal locations. External
LOCATION values indicate either misconfiguration exposing device profiles to the
internet, or a rogue NOTIFY crafted to redirect UPnP clients to attacker infrastructure.

**Finding fields:** `src_ip`, `external_location`, `usn`, `timestamp_utc`

---

### SSDP Local Network Manipulation (T1557)
Detects two sub-patterns:
1. SUBSCRIBE/UNSUBSCRIBE messages from unexpected hosts — UPnP event subscription
   hijacking enabling silent interception of device state change notifications.
2. Duplicate NOTIFY messages claiming the same USN (Unique Service Name) from multiple
   IPs — device impersonation where an attacker mimics a legitimate UPnP device to
   intercept or redirect traffic.

**Finding fields:** `src_ip`/`usn`, `method`/`duplicate_ips`, `indicator`, `timestamp_utc`

---

### Vulnerable UPnP Implementation (T1203)
Checks Server, USN, and Location fields in SSDP NOTIFY/M-SEARCH packets against known
vulnerable implementation signatures: Portable UPnP SDK (CVE-2012-5958), MiniUPnP,
outdated Linux kernel UPnP stacks, and DLNA middleware with known CVEs.

**Vulnerable signatures:** `portable sdk`, `miniupnp`, `upnp/1.0`, `linux/2.4`, `linux/2.6`, `dlna`, `redsonic`, `airties`

**Finding fields:** `src_ip`, `signature`, `server`, `usn`, `timestamp_utc`

---

## SSDP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `method` | SSDP method: M-SEARCH, NOTIFY, SUBSCRIBE, UNSUBSCRIBE |
| `st` | Search Target (M-SEARCH) |
| `nt` | Notification Type (NOTIFY) |
| `location` | Device description URL (NOTIFY) |
| `usn` | Unique Service Name |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `SSDP_FLOOD_THRESHOLD` | 100 | M-SEARCH packets per src IP to flag as amplification setup |

All constants are at the top of `lib/fan_ssdp_threats.py`.

---

## Vault Recording

High severity findings are written automatically when `--no-vault` is absent and a
`--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Amplification DDoS | `TTPs/T1498.002.md` | T1498.002 |
| Device Exposure / Network Manipulation | `TTPs/T1590.md` / `TTPs/T1557.md` | T1590 / T1557 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No SSDP/UPnP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "ssdp"` |
| Many external-source amplification findings | NAT causing observed packets to appear external | Check if capture point is behind NAT |
| Vulnerable UPnP false positives | Old server strings in legitimate firmware | Verify CVE applicability for specific device/version |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
