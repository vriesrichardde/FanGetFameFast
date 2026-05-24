# Skill: FAN ARP Threats

## Overview

Extracts all ARP traffic from a PCAP file and detects five threat categories covering
ARP-based network attacks. Output is integrated into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| ARP Cache Poisoning / Spoofing | T1557.002 — ARP Cache Poisoning | Critical |
| Gratuitous ARP Anomaly | T1557.002 — ARP Cache Poisoning | High |
| ARP Flood / DoS | T1498.001 — Direct Network Flood | High |
| ARP Reconnaissance Scan | T1018 — Remote System Discovery | Medium |
| ARP Proxy / Relay Anomaly | T1557 — Adversary-in-the-Middle | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/arp_threats/<stem>/arp_threats.json` |
| Flow inventory CSV | `./analysis/arp_threats/<stem>/arp_flows.csv` |
| Markdown report | `./analysis/arp_threats/<stem>/arp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_arp_threats.sh /path/to/capture.pcap
./scripts/fan_arp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_arp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_arp_threats import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, flows = analyze(pcap)
out_dir = Path("./analysis/arp_threats/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, flows, out_dir / "arp_threats.json")
write_csv(flows, out_dir / "arp_flows.csv")
write_report(results, out_dir / "arp_threats_report.md", pcap)
```

---

## Detection Logic

### ARP Cache Poisoning / Spoofing (T1557.002)
Compiles an IP → MAC mapping from all observed ARP replies. If two or more distinct
MAC addresses claim the same IP address, the IP is flagged as poisoned. This detects
classic ARP spoofing (e.g., arpspoof, Ettercap, Bettercap) where an attacker
broadcasts fake ARP replies to redirect traffic through their machine.

**Finding fields:** `target_ip`, `claiming_macs`, `mac_count`, `timestamp_utc`

---

### Gratuitous ARP Anomaly (T1557.002)
Flags ARP reply packets where `sender_ip == target_ip` (gratuitous ARP). A high
volume of gratuitous ARPs from a single MAC indicates automated cache poisoning.
Legitimate gratuitous ARPs occur during host boot or IP conflict detection, but
tool-generated floods are anomalous.

**Threshold:** `GRAT_ARP_THRESHOLD = 10` gratuitous replies per source MAC.

**Finding fields:** `src_mac`, `grat_arp_count`, `first_timestamp`, `last_timestamp`

---

### ARP Flood / DoS (T1498.001)
Counts ARP request packets per source MAC address. An unusually high count saturates
the local network broadcast domain and can overwhelm switch ARP table capacity,
causing the switch to enter failopen (hub) mode — exposing all traffic to sniffing.

**Threshold:** `ARP_FLOOD_THRESHOLD = 200` requests per source MAC.

**Finding fields:** `src_mac`, `request_count`, `first_timestamp`, `last_timestamp`

---

### ARP Reconnaissance Scan (T1018)
Counts unique target IPs per source MAC in ARP requests. Host discovery tools (nmap
`-sn`, arp-scan) send one ARP request per target IP sequentially. A MAC probing many
distinct IPs is performing network enumeration.

**Threshold:** `ARP_SCAN_THRESHOLD = 20` unique target IPs per source MAC.

**Finding fields:** `src_mac`, `unique_targets`, `first_timestamp`, `last_timestamp`

---

### ARP Proxy / Relay Anomaly (T1557)
Checks whether the Ethernet source MAC (`eth.src`) in an ARP reply differs from the
ARP sender hardware address field (`arp.src.hw_mac`). A mismatch indicates a proxy
ARP device or an attacker deliberately forging the hardware address in the ARP payload
to redirect traffic while appearing as a legitimate relay.

**Finding fields:** `eth_src_mac`, `arp_sender_mac`, `sender_ip`, `timestamp_utc`

---

## ARP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `opcode` | ARP opcode: 1=request, 2=reply |
| `sender_mac` | ARP sender hardware (MAC) address |
| `sender_ip` | ARP sender protocol (IP) address |
| `target_mac` | ARP target hardware (MAC) address |
| `target_ip` | ARP target protocol (IP) address |
| `eth_src` | Ethernet frame source MAC |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `ARP_FLOOD_THRESHOLD` | 200 | ARP requests per MAC to flag as flood |
| `ARP_SCAN_THRESHOLD` | 20 | Unique target IPs per MAC to flag as scan |
| `GRAT_ARP_THRESHOLD` | 10 | Gratuitous ARP replies per MAC to flag |

All constants are at the top of `lib/fan_arp_threats.py`.

---

## Vault Recording

The lib writes to the vault automatically when `--no-vault` is absent and a `--case-id` is provided. The following is written:

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| ARP Cache Poisoning / Gratuitous ARP | `TTPs/T1557.002.md` | T1557.002 |
| ARP Proxy / Relay Anomaly | `TTPs/T1557.md` | T1557 |
| ARP Flood / DoS | `TTPs/T1498.001.md` | T1498.001 |
| ARP Reconnaissance Scan | `TTPs/T1018.md` | T1018 |
| Spoofing source MAC (if identifiable) | `IOCs/<mac>.md` | — |

Severity threshold for vault writes: **Critical and High** findings only. Informational findings are not written.

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ttp, record_ioc

# Written automatically by lib/fan_arp_threats.py — verify with:
# ./scripts/vault_context.sh ttp T1557.002
# ./scripts/vault_context.sh search "<case_id>"
```

**Manual supplement** — if the attacking MAC is identified and correlates to a known host:
```python
record_ioc("mac", "<attacker_mac>", "ARP spoofing source confirmed in PCAP.", case_id, severity="high",
           related_ttps=["T1557.002 ARP Cache Poisoning"])
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No ARP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "arp"` |
| No poisoning findings | Only one MAC per IP | Genuine network — no spoofing detected |
| Proxy anomaly false positives | Legitimate router proxy ARP | Check if router is performing proxy ARP; add its MAC to allowlist in code |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
