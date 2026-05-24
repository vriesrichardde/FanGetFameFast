# Skill: FAN mDNS Threats

## Overview

Extracts mDNS (Multicast DNS, UDP port 5353) traffic from a PCAP file and detects
five threat categories covering amplification, information disclosure, spoofing,
unsafe network exposure, and flooding.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| mDNS Amplification / DrDoS | T1498.002 — Reflection Amplification | High |
| mDNS Information Leakage | T1590 — Gather Victim Network Information | Medium |
| mDNS Spoofing / Cache Poisoning | T1557 — Adversary-in-the-Middle | Critical |
| mDNS Outside Local Network Segment | T1590 — Gather Victim Network Information | Medium |
| mDNS Flood / DoS | T1498.001 — Direct Network Flood | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/mdns_threats/<stem>/mdns_threats.json` |
| Flow inventory CSV | `./analysis/mdns_threats/<stem>/mdns_flows.csv` |
| Markdown report | `./analysis/mdns_threats/<stem>/mdns_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_mdns_threats.sh /path/to/capture.pcap
./scripts/fan_mdns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_mdns_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### mDNS Amplification / DrDoS (T1498.002)
Flags mDNS response frames exceeding 512 bytes. mDNS is designed for link-local use
and responses can include large TXT and SRV records. When attackers can reach the
multicast group (e.g., via misconfigured routers), they trigger large responses
directed at spoofed victim IPs — a distributed reflective DoS pattern.

**Threshold:** `AMPLIFICATION_SIZE_BYTES = 512`

**Finding fields:** `src_ip`, `dst_ip`, `resp_name`, `answer_ip`, `frame_len`

---

### mDNS Information Leakage (T1590)
Scans query and response name fields for sensitive keywords: admin, root, user,
login, ssh, rdp, vnc, smb, share, backup, internal, private, secret, dev, staging,
prod. mDNS announces services with descriptive names that reveal internal topology,
device models, and software versions to any host on the local segment.

**Finding fields:** `src_ip`, `name`, `is_response`, `answer_ip`, `timestamp_utc`

---

### mDNS Spoofing / Cache Poisoning (T1557)
Two sub-detections:
1. **Conflicting records** — the same hostname resolves to two or more different IP
   addresses in mDNS responses, indicating that a second host is injecting fake
   answers to poison mDNS caches.
2. **Unicast mDNS responses** — a response sent directly to a specific IP (not the
   multicast group 224.0.0.251 / ff02::fb). Targeted unicast responses are used by
   attackers to poison only the victim's cache without alerting other hosts.

**Finding fields:** `hostname`, `conflicting_ips` / `unicast_target`, `src_ip`

---

### mDNS Outside Local Network Segment (T1590)
Flags mDNS traffic (UDP 5353) originating from globally routable unicast addresses
(i.e., not 169.254.x.x, 10.x.x.x, 192.168.x.x, 172.16-31.x.x, or IPv6 link-local).
mDNS is intentionally link-local; traffic from routable IPs indicates either router
misconfiguration forwarding mDNS across segments or deliberate reconnaissance.

**Finding fields:** `src_ip`, `dst_ip`, `is_response`, `name`, `timestamp_utc`

---

### mDNS Flood / DoS (T1498.001)
Counts all mDNS packets (queries + responses) per source IP. An automated flood of
mDNS traffic generates broadcast storms on the local segment, consuming bandwidth
for all connected hosts and potentially overwhelming embedded devices (printers, IoT).

**Threshold:** `MDNS_FLOOD_THRESHOLD = 200` packets per source IP.

**Finding fields:** `src_ip`, `packet_count`, `first_timestamp`, `last_timestamp`

---

## mDNS Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source UDP port |
| `dst_port` | Destination UDP port (5353) |
| `is_response` | True if DNS flags indicate response |
| `query_name` | Queried name from question section |
| `resp_name` | Name from answer section |
| `answer_ip` | A/AAAA record IP from answer section |
| `frame_len` | Frame size in bytes |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `AMPLIFICATION_SIZE_BYTES` | 512 | Response frame size to flag |
| `MDNS_FLOOD_THRESHOLD` | 200 | Packets per source IP to flag as flood |
| `INFO_LEAKAGE_KEYWORDS` | regex | Sensitive terms to match in name fields |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| mDNS Amplification / DDoS | `TTPs/T1498.002.md` + `IOCs/ip-<src>.md` | T1498.002 | High |
| Information Leakage | `Concepts/mDNS-info-leakage.md` | T1590 | Medium |
| mDNS Spoofing / Cache Poisoning | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | Critical |
| mDNS Outside Local Segment | `TTPs/T1571.md` + `IOCs/ip-<src>.md` | T1571 | High |
| mDNS Flood | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |

Verify:
```bash
./scripts/vault_context.sh ttp T1557
./scripts/vault_context.sh ioc <suspicious_src_ip>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No mDNS traffic in PCAP | Verify: `tshark -r capture.pcap -Y "mdns"` |
| Information leakage FPs | `.local` domains are always matched | Review findings — `.local` is expected in mDNS |
| Spoofing FPs | Device with multiple interfaces | Check if src_ip has multiple valid A records |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
