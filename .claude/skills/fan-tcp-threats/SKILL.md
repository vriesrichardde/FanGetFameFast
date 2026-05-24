# Skill: FAN TCP Threats

## Overview

Extracts TCP traffic from a PCAP file and detects six threat categories covering
flooding, scanning, session-level attacks, and stealth probing techniques.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| SYN Flood | T1498.001 — Direct Network Flood | Critical |
| TCP Port Scan | T1046 — Network Service Discovery | Medium |
| RST Flood / Connection Reset DoS | T1499.002 — Service Exhaustion Flood | High |
| TCP Stealth Scan (FIN / NULL / Xmas) | T1046 — Network Service Discovery | Medium |
| TCP Session Hijacking Indicators | T1563 — Remote Service Session Hijacking | Critical |
| Half-Open Connection Flood | T1499.002 — Service Exhaustion Flood | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/tcp_threats/<stem>/tcp_threats.json` |
| Flow inventory CSV | `./analysis/tcp_threats/<stem>/tcp_flows.csv` |
| Markdown report | `./analysis/tcp_threats/<stem>/tcp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_tcp_threats.sh /path/to/capture.pcap
./scripts/fan_tcp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_tcp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_tcp_threats import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, flows = analyze(pcap)
out_dir = Path("./analysis/tcp_threats/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, flows, out_dir / "tcp_threats.json")
write_csv(flows, out_dir / "tcp_flows.csv")
write_report(results, out_dir / "tcp_threats_report.md", pcap)
```

---

## Detection Logic

### SYN Flood (T1498.001)
Counts TCP SYN-only packets (SYN=1, ACK=0) per source IP. A high count with no
corresponding SYN-ACK or ACK completions indicates a SYN flood attack that exhausts
the target's connection table (TCB). Tools: hping3, scapy, botnets.

**Threshold:** `SYN_FLOOD_THRESHOLD = 500` SYN packets per source IP.

**Finding fields:** `src_ip`, `syn_count`, `unique_dst_ips`, `first_timestamp`, `last_timestamp`

---

### TCP Port Scan (T1046)
Tracks SYN packets sent by a single source IP to distinct destination port numbers on
the same target host. Automated scanners (nmap, masscan) probe hundreds or thousands
of ports in rapid succession.

**Threshold:** `PORT_SCAN_THRESHOLD = 30` unique destination ports per (src_ip, dst_ip) pair.

**Finding fields:** `src_ip`, `dst_ip`, `unique_ports`, `first_timestamp`, `last_timestamp`

---

### RST Flood / Connection Reset DoS (T1499.002)
Counts TCP RST packets per source IP. A large volume of RST packets disrupts
established connections between other hosts (TCP Reset Attack), commonly used to
terminate sessions between a target and its peers.

**Threshold:** `RST_FLOOD_THRESHOLD = 200` RST packets per source IP.

**Finding fields:** `src_ip`, `rst_count`, `first_timestamp`, `last_timestamp`

---

### TCP Stealth Scan — FIN / NULL / Xmas (T1046)
Detects three flag-anomaly scan types:
- **FIN scan** — FIN=1, SYN=0, ACK=0 (bypasses stateless ACL that only blocks SYN)
- **NULL scan** — all flags cleared (flags == 0x00)
- **Xmas scan** — FIN=1, PSH=1, URG=1 (Christmas tree lighting)

On closed ports, RFC 793 mandates RST responses; on open ports, silence. Scanners
use this asymmetry to infer port state without completing a handshake.

**Threshold:** `STEALTH_SCAN_THRESHOLD = 10` stealth probes per source IP.

**Finding fields:** `src_ip`, `fin_count`, `null_count`, `xmas_count`, `total_probes`

---

### TCP Session Hijacking Indicators (T1563)
Detects RST injection into established streams: after a three-way handshake between
two hosts (recorded by stream ID), a third IP sends a RST on the same TCP stream.
This is characteristic of session reset injection attacks (Juggernaut, Hunt, etc.)

**Finding fields:** `stream_id`, `injecting_ip`, `established_parties`, `dst_ip`, `dst_port`

---

### Half-Open Connection Flood (T1499.002)
Measures the ratio of SYN packets sent by a source IP to SYN-ACK responses received
back. When ≥90% of SYNs receive no SYN-ACK, the connections remain half-open,
exhausting the server's backlog queue (SYN_RCVD state).

**Thresholds:** `HALF_OPEN_SYN_THRESHOLD = 200` SYNs minimum; ≥90% unanswered.

**Finding fields:** `src_ip`, `syn_count`, `syn_ack_received`, `half_open_ratio`

---

## TCP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source TCP port |
| `dst_port` | Destination TCP port |
| `flags_raw` | TCP flags as hex string (e.g., `0x002`) |
| `stream_id` | tshark TCP stream index |
| `flag_syn` | True if SYN flag set |
| `flag_ack` | True if ACK flag set |
| `flag_rst` | True if RST flag set |
| `flag_fin` | True if FIN flag set |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `SYN_FLOOD_THRESHOLD` | 500 | SYN-only packets per src IP |
| `PORT_SCAN_THRESHOLD` | 30 | Unique dst ports per src→dst pair |
| `RST_FLOOD_THRESHOLD` | 200 | RST packets per src IP |
| `STEALTH_SCAN_THRESHOLD` | 10 | FIN/NULL/Xmas probes per src IP |
| `HALF_OPEN_SYN_THRESHOLD` | 200 | Minimum SYNs to evaluate half-open ratio |

All constants are at the top of `lib/fan_tcp_threats.py`.

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| SYN Flood | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Port Scan | `TTPs/T1046.md` + `IOCs/ip-<src>.md` | T1046 | Medium |
| RST Flood | `TTPs/T1499.md` + `IOCs/ip-<src>.md` | T1499 | High |
| Stealth Scan (FIN/NULL/Xmas) | `TTPs/T1046.md` + `IOCs/ip-<src>.md` | T1046 | High |
| Session Hijacking | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | Critical |
| Half-Open Flood | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |

Verify:
```bash
./scripts/vault_context.sh ttp T1046
./scripts/vault_context.sh ioc <scanning_src_ip>
./scripts/vault_context.sh search "<case_id>"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No TCP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "tcp"` |
| No session hijacking findings | All RSTs are from legitimate endpoints | Expected — both parties of a stream are tracked |
| SYN flood FP on load balancer | High-traffic load balancer sends many SYNs | Raise `SYN_FLOOD_THRESHOLD` or filter the LB IP |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
