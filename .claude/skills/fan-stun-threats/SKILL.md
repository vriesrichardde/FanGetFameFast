# Skill: FAN STUN Threats

## Overview

Extracts all STUN (Session Traversal Utilities for NAT, UDP/TCP 3478) traffic from a
PCAP file and detects four threat categories covering STUN abuse and exploitation.
Output is integrated into the PCAP incident report.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| STUN Reflected / Amplification DDoS | T1498.002 — Reflection Amplification | High |
| STUN Information Leakage | T1590.005 — Network Topology | Medium |
| STUN Firewall Traversal / Misconfig | T1599 — Network Boundary Bridging | Medium |
| STUN Service Abuse | T1071 — Application Layer Protocol | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/stun_threats/<stem>/stun_threats.json` |
| Flow inventory CSV | `./analysis/stun_threats/<stem>/stun_flows.csv` |
| Markdown report | `./analysis/stun_threats/<stem>/stun_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_stun_threats.sh /path/to/capture.pcap
./scripts/fan_stun_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_stun_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### STUN Reflected / Amplification DDoS (T1498.002)
Builds a set of source IPs that sent STUN Binding Requests (type `0x0001`). Flags any
Binding Response (type `0x0101`) with frame length ≥ `STUN_LARGE_RESP` (200 bytes) that
is directed at an IP which sent no corresponding request. This pattern indicates STUN
reflection: spoofed-source requests trigger responses directed at a victim IP.

**Finding fields:** `reflector_ip`, `victim_ip`, `response_bytes`, `timestamp_utc`

---

### STUN Information Leakage (T1590.005)
Extracts XOR-MAPPED-ADDRESS and MAPPED-ADDRESS attributes from STUN Binding Responses.
If the mapped IP is in RFC 1918 private address space (10.x, 172.16-31.x, 192.168.x),
the response exposes internal network topology to external parties observing the
exchange — particularly relevant in WebRTC/ICE traffic captured on egress.

**Finding fields:** `responder_ip`, `querier_ip`, `mapped_ip`, `note`, `timestamp_utc`

---

### STUN Firewall Traversal / Misconfiguration (T1599)
Flags STUN traffic observed on ports other than the standard STUN/TURN ports (3478,
5349, 19302). Non-standard STUN ports may indicate deliberate firewall bypass via
port-hopping, misconfigured TURN relay servers permitting arbitrary traversal, or
C2 channels tunnelled through STUN hole-punching on permitted ports.

**Finding fields:** `src_ip`, `dst_ip`, `port`, `timestamp_utc`

---

### STUN Service Abuse (T1071)
Counts STUN Binding Requests per source IP. High request rates from a single source
indicate automated NAT mapping discovery, ICE candidate flooding, or resource
exhaustion of STUN servers. Attackers also use STUN to maintain persistent UDP
hole-punched channels to C2 infrastructure.

**Threshold:** `STUN_ABUSE_THRESHOLD = 100` requests per source IP.

**Finding fields:** `src_ip`, `request_count`, `first_timestamp`, `last_timestamp`

---

## STUN Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `frame_len` | Frame length in bytes |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `stun_type` | STUN message type (hex: 0x0001=Binding Req, 0x0101=Binding Resp) |
| `stun_length` | STUN payload length |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `STUN_ABUSE_THRESHOLD` | 100 | STUN requests per src IP to flag as abuse |
| `STUN_LARGE_RESP` | 200 | Minimum response bytes to flag in amplification check |
| `STANDARD_STUN_PORTS` | {3478, 5349, 19302} | Ports exempt from firewall traversal flag |

All constants are at the top of `lib/fan_stun_threats.py`.

---

## Vault Recording

High severity findings are written automatically when `--no-vault` is absent and a
`--case-id` is provided.

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Amplification DDoS | `TTPs/T1498.002.md` | T1498.002 |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No STUN traffic in PCAP | Verify: `tshark -r capture.pcap -Y "stun"` |
| Many firewall traversal findings | Standard WebRTC on non-3478 ports | Expand `STANDARD_STUN_PORTS` set |
| XOR-MAPPED-ADDRESS not extracted | tshark field name varies by version | Check with `tshark -G fields \| grep stun` |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
