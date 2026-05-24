# Skill: FAN QUIC Threats

## Overview

Extracts QUIC protocol traffic from a PCAP file and detects five threat categories
covering amplification, replay attacks, version forgery, handshake exhaustion, and
C2 channel indicators.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| QUIC Amplification / DDoS | T1498.002 — Reflection Amplification | Critical |
| 0-RTT Replay Attack | T1550 — Use Alternate Authentication Material | High |
| Version Forgery / Negotiation Anomaly | T1562 — Impair Defenses | Medium |
| Pre-Handshake Exhaustion | T1499.002 — Service Exhaustion Flood | High |
| QUIC on Non-Standard Port | T1571 — Non-Standard Port | Medium |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/quic_threats/<stem>/quic_threats.json` |
| Flow inventory CSV | `./analysis/quic_threats/<stem>/quic_flows.csv` |
| Markdown report | `./analysis/quic_threats/<stem>/quic_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_quic_threats.sh /path/to/capture.pcap
./scripts/fan_quic_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_quic_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### QUIC Amplification / DDoS (T1498.002)
Compares QUIC response bytes (from standard ports 443/8443) to request bytes
(to the same ports). The QUIC Initial packet requires address validation via tokens,
but incomplete or misconfigured validation can allow amplification at the handshake
stage. Large Retry or Version Negotiation responses relative to the triggering
Initial are flagged.

**Thresholds:** `AMPLIFICATION_RATIO = 5`; `AMPLIFICATION_MIN_PKTS = 10`

**Finding fields:** `server_ip`, `server_port`, `victim_ip`, `response_packets`,
`response_bytes`, `request_bytes`, `amplification_ratio`

---

### 0-RTT Replay Attack (T1550)
Detects multiple QUIC long-header packets with type 0x01 (0-RTT data) from the same
source IP to the same destination. QUIC 0-RTT Early Data reuses keying material from
a previous session and does not provide forward secrecy. Replayed 0-RTT packets can
be accepted by the server if anti-replay measures are absent or incomplete.

**Threshold:** `ZERO_RTT_REPEAT_THRESHOLD = 3` repeated 0-RTT packets per src→dst pair.

**Finding fields:** `src_ip`, `dst_ip`, `dst_port`, `zero_rtt_count`, `timestamp_utc`

---

### Version Forgery / Negotiation Anomaly (T1562)
Flags QUIC long-header packets with version numbers not in the known-good set
(QUIC v1 RFC 9000, QUIC v2 RFC 9369, draft-29, and common GREASE values). Attackers
forge version fields to trigger Version Negotiation responses (leaking the server's
supported versions), probe for version-specific parsing vulnerabilities, or confuse
QUIC-aware security appliances.

**Known versions:** `0x00000001` (v1), `0x00000002` (v2), `0x6b3343cf` (draft-29),
and several draft and GREASE values.

**Finding fields:** `src_ip`, `dst_ip`, `dst_port`, `version_hex`, `pkt_type`

---

### Pre-Handshake Exhaustion (T1499.002)
Tracks source IPs sending a high volume of QUIC Initial packets (long header type 0)
without any corresponding Handshake or 1-RTT packets completing the connection. Each
Initial packet causes the server to allocate cryptographic state (generate keys,
decrypt CRYPTO frames), making incomplete-handshake flooding a resource exhaustion
attack.

**Threshold:** `HANDSHAKE_EXHAUSTION_THRESHOLD = 100` Initial packets per source IP
with no Handshake packet observed from that source.

**Finding fields:** `src_ip`, `initial_count`, `handshake_seen`, `first_timestamp`

---

### QUIC on Non-Standard Port (T1571)
QUIC sessions on ports other than 443 or 8443 are flagged. While QUIC/HTTP3 is
typically served on UDP 443, C2 frameworks and tunnelling tools may encapsulate QUIC
channels on arbitrary UDP ports to evade port-based firewall rules and protocol
inspection.

**Standard ports (not flagged):** 443, 8443

**Finding fields:** `src_ip`, `dst_ip`, `src_port`, `dst_port`, `version_hex`

---

## QUIC Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source UDP port |
| `dst_port` | Destination UDP port |
| `version_raw` | QUIC version field (hex string) |
| `version_int` | QUIC version as integer |
| `pkt_type_raw` | Long-header packet type (0=Initial, 1=0-RTT, 2=Handshake, 3=Retry) |
| `header_form` | Header form: 1=long header, 0=short header |
| `frame_len` | Frame size in bytes |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `AMPLIFICATION_RATIO` | 5 | Response/request byte ratio |
| `AMPLIFICATION_MIN_PKTS` | 10 | Minimum response packets before check |
| `HANDSHAKE_EXHAUSTION_THRESHOLD` | 100 | Initial packets from one source without completion |
| `ZERO_RTT_REPEAT_THRESHOLD` | 3 | 0-RTT packets per pair to flag as replay |
| `STANDARD_QUIC_PORTS` | {443, 8443} | Ports not flagged by non-standard-port detector |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| QUIC Amplification / DDoS | `TTPs/T1498.002.md` + `IOCs/ip-<src>.md` | T1498.002 | High |
| 0-RTT Replay Attack | `TTPs/T1499.md` + `IOCs/ip-<src>.md` | T1499 | Critical |
| Version Forgery | `TTPs/T1562.md` + `IOCs/ip-<src>.md` | T1562 | High |
| Pre-Handshake Exhaustion | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Non-Standard Port | `TTPs/T1571.md` + `IOCs/ip-<dst>.md` | T1571 | Medium |

Verify:
```bash
./scripts/vault_context.sh ttp T1498.002
./scripts/vault_context.sh ioc <suspicious_ip>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No QUIC traffic or tshark < 3.3 | Verify: `tshark -r capture.pcap -Y "quic"` |
| `version_raw` empty | tshark can't dissect encrypted QUIC | Ensure QUIC dissector is enabled; try `tshark --disable-protocol ssl` |
| Non-standard port FPs | Internal service uses custom QUIC port | Add port to `STANDARD_QUIC_PORTS` in `lib/fan_quic_threats.py` |
| 0-RTT FPs | CDN with aggressive session resumption | Raise `ZERO_RTT_REPEAT_THRESHOLD` |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
