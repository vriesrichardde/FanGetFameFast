# Skill: FAN UDP Threats

## Overview

Extracts UDP traffic from a PCAP file and detects five threat categories covering
flooding, reflection amplification, port scanning, fragmentation attacks, and
IP spoofing indicators.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| UDP Flood | T1498.001 — Direct Network Flood | Critical |
| UDP Reflection / Amplification Attack | T1498.002 — Reflection Amplification | Critical |
| UDP Port Scan | T1046 — Network Service Discovery | Medium |
| UDP Fragmentation Attack | T1499 — Endpoint Denial of Service | High |
| IP Spoofing Indicator (UDP) | T1001 — Data Obfuscation | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/udp_threats/<stem>/udp_threats.json` |
| Flow inventory CSV | `./analysis/udp_threats/<stem>/udp_flows.csv` |
| Markdown report | `./analysis/udp_threats/<stem>/udp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_udp_threats.sh /path/to/capture.pcap
./scripts/fan_udp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_udp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### UDP Flood (T1498.001)
Counts UDP datagrams per (src_ip, dst_ip, dst_port) tuple. A single source sending
a high volume of datagrams to one destination saturates bandwidth or exhausts the
target's receive buffer.

**Threshold:** `UDP_FLOOD_THRESHOLD = 1000` datagrams per flow tuple.

**Finding fields:** `src_ip`, `dst_ip`, `dst_port`, `packet_count`, `total_bytes`

---

### UDP Reflection / Amplification (T1498.002)
Compares request bytes (to amplification port) vs response bytes (from amplification
port) per reflector IP. A high ratio indicates the reflector is sending much more
data than it received — the defining characteristic of an amplification attack.

**Monitored amplification ports:** DNS (53), NTP (123), SSDP (1900), Memcached (11211),
LDAP (389), mDNS (5353), Chargen (19), QOTD (17), NetBIOS-NS (137).

**Thresholds:** `AMPLIFICATION_RATIO = 10` (10× or more); `AMPLIFICATION_MIN_RESPONSES = 20`.

**Finding fields:** `reflector_ip`, `reflector_port`, `victim_ip`, `response_packets`,
`response_bytes`, `request_bytes`, `amplification_ratio`

---

### UDP Port Scan (T1046)
Tracks unique destination ports probed per source IP. UDP port scanners (nmap `-sU`)
send a UDP datagram to each port; closed ports return ICMP Port Unreachable.

**Threshold:** `UDP_SCAN_THRESHOLD = 30` unique destination ports per source IP.

**Finding fields:** `src_ip`, `unique_dst_ports`, `first_timestamp`, `last_timestamp`

---

### UDP Fragmentation Attack (T1499)
Detects packets with the IP More Fragments (MF) flag set or a non-zero fragment
offset. Crafted IP fragmentation can crash or stall stateful inspection devices
by generating incomplete reassembly queues, and can bypass some IDS/IPS signatures
that inspect only the first fragment.

**Threshold:** `FRAGMENT_THRESHOLD = 50` fragmented packets per source IP.

**Finding fields:** `src_ip`, `fragment_count`, `first_timestamp`, `last_timestamp`

---

### IP Spoofing Indicator (T1001)
Flags UDP packets with anomalously low TTL values (≤5). Legitimate internet traffic
has TTLs of 64, 128, or 255 that decrement en route. A TTL of ≤5 on received traffic
strongly suggests the packet was injected with a crafted low TTL, which is a common
characteristic of spoofed-source DoS traffic.

**Threshold:** `SPOOFING_TTL_MAX = 5`

**Finding fields:** `src_ip`, `min_ttl`, `packet_count`, `timestamp_utc`

---

## UDP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source UDP port |
| `dst_port` | Destination UDP port |
| `frame_len` | Frame size in bytes |
| `ttl` | IP time-to-live |
| `more_frags` | IP more-fragments flag (1=fragmented) |
| `frag_offset` | IP fragment offset |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `UDP_FLOOD_THRESHOLD` | 1000 | Datagrams per src→dst:port to flag |
| `UDP_SCAN_THRESHOLD` | 30 | Unique dst ports per source IP |
| `AMPLIFICATION_RATIO` | 10 | Response/request byte ratio |
| `AMPLIFICATION_MIN_RESPONSES` | 20 | Minimum response packets before check |
| `FRAGMENT_THRESHOLD` | 50 | Fragmented packets per source IP |
| `SPOOFING_TTL_MAX` | 5 | TTL value to flag as spoofing indicator |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| UDP Flood | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Reflection / Amplification | `TTPs/T1498.002.md` + `IOCs/ip-<reflector>.md` | T1498.002 | High |
| UDP Port Scan | `TTPs/T1046.md` + `IOCs/ip-<src>.md` | T1046 | Medium |
| UDP Fragmentation Attack | `TTPs/T1499.md` | T1499 | High |
| IP Spoofing Indicator | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | High |

Verify:
```bash
./scripts/vault_context.sh ttp T1498.002
./scripts/vault_context.sh ioc <reflector_ip>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No UDP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "udp"` |
| Amplification FPs on CDN | CDN sends large UDP responses legitimately | Raise `AMPLIFICATION_RATIO` threshold |
| Fragment FPs | Legitimate jumbo frame fragmentation | Adjust `FRAGMENT_THRESHOLD` upward |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
