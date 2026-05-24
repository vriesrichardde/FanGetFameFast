# Skill: FAN DHCP Threats

## Overview

Extracts DHCP traffic from a PCAP file and detects six threat categories covering
address pool exhaustion, rogue servers, spoofing, flooding, relay abuse, and
option injection. Compatible with both `dhcp` (tshark ≥ 3.0) and `bootp` (legacy)
dissector field names — the module tries `dhcp` first and falls back to `bootp`.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| DHCP Starvation Attack | T1499 — Endpoint Denial of Service | Critical |
| Rogue DHCP Server | T1557 — Adversary-in-the-Middle | Critical |
| DHCP Spoofing | T1557 — Adversary-in-the-Middle | Critical |
| DHCP Release / Decline Flood | T1499 — Endpoint Denial of Service | High |
| Unauthorized DHCP Relay | T1557 — Adversary-in-the-Middle | High |
| DHCP Message Injection / Option Manipulation | T1565.001 — Stored Data Manipulation | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/dhcp_threats/<stem>/dhcp_threats.json` |
| Flow inventory CSV | `./analysis/dhcp_threats/<stem>/dhcp_flows.csv` |
| Markdown report | `./analysis/dhcp_threats/<stem>/dhcp_threats_report.md` |

---

## Invocation

```bash
./scripts/fan_dhcp_threats.sh /path/to/capture.pcap
./scripts/fan_dhcp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_dhcp_threats.sh /path/to/capture.pcap --stem capture --no-vault
```

---

## Detection Logic

### DHCP Starvation Attack (T1499)
Counts distinct client MAC addresses sending DHCP DISCOVER messages. Tools like
`yersinia` or `dhcpstarv` generate fake DISCOVERs from randomised MACs, exhausting
the server's available IP lease pool and denying service to legitimate clients.

**Threshold:** `STARVATION_MAC_THRESHOLD = 50` unique client MACs sending DISCOVER.

**Finding fields:** `unique_client_macs`, `total_discovers`, `first_timestamp`, `last_timestamp`

---

### Rogue DHCP Server (T1557)
Collects all source IP addresses that send DHCP OFFER or ACK messages. A legitimate
network typically has exactly one authorised DHCP server. Two or more distinct server
IPs indicate a rogue DHCP server — possibly configured to hand out attacker-controlled
gateway and DNS addresses.

**Threshold:** `ROGUE_SERVER_THRESHOLD = 2` distinct server IPs sending OFFER/ACK.

**Finding fields:** `server_ip_count`, `server_ips`, `timestamp_utc`

---

### DHCP Spoofing (T1557)
Checks whether the IP source address of OFFER/ACK messages matches the server
identifier (option 54). When a rogue server crafts responses, it may set option 54
to the legitimate server's IP while sending from a different source, making the
response appear authoritative.

**Finding fields:** `src_ip`, `server_id_opt`, `dst_ip`, `msg_type`, `timestamp_utc`

---

### DHCP Release / Decline Flood (T1499)
Counts DHCP RELEASE and DECLINE messages per client MAC or source IP. A flood of
release messages forces clients off the network and spams the DHCP server's audit
log, disrupting normal operations.

**Threshold:** `RELEASE_FLOOD_THRESHOLD = 100` RELEASE/DECLINE messages per source.

**Finding fields:** `src_identifier`, `message_count`, `first_timestamp`, `last_timestamp`

---

### Unauthorized DHCP Relay (T1557)
Flags DHCP messages containing a non-zero GIADDR (relay agent IP address) field
originating from a source IP that has not been identified as a legitimate DHCP server.
An attacker can inject relay information to intercept or redirect DHCP traffic across
network segments.

**Finding fields:** `src_ip`, `relay_ip`, `msg_type`, `client_mac`, `timestamp_utc`

---

### DHCP Message Injection / Option Manipulation (T1565.001)
Flags DHCP messages containing vendor-specific information (option 43) or relay agent
information (option 82). Attackers can inject these options to deliver malicious
configuration, redirect DNS to attacker-controlled resolvers, or override default
gateway settings.

**Finding fields:** `src_ip`, `client_mac`, `msg_type`, `vendor_class`, `relay_flags`

---

## DHCP Flow CSV Columns

| Column | Description |
|--------|-------------|
| `frame_no` | tshark frame number |
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | Sender IP address |
| `dst_ip` | Destination IP address |
| `client_mac` | Client hardware (MAC) address |
| `msg_type` | DHCP message type (1=DISC, 2=OFFER, 3=REQ, 4=DECL, 5=ACK, 6=NAK, 7=REL, 8=INFORM) |
| `your_ip` | Offered IP address (yiaddr) |
| `server_id` | Server identifier option (option 54) |
| `relay_ip` | Relay agent IP (GIADDR) |
| `vendor_class` | Vendor class identifier (option 60) |
| `relay_flags` | Relay agent information flags (option 82) |
| `frame_len` | Frame size in bytes |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `STARVATION_MAC_THRESHOLD` | 50 | Unique client MACs sending DISCOVER |
| `ROGUE_SERVER_THRESHOLD` | 2 | Distinct IPs sending OFFER/ACK |
| `RELEASE_FLOOD_THRESHOLD` | 100 | RELEASE/DECLINE messages per source |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| DHCP Starvation | `TTPs/T1498.001.md` + `IOCs/ip-<src>.md` | T1498.001 | High |
| Rogue DHCP Server | `TTPs/T1557.md` + `IOCs/ip-<rogue_server>.md` | T1557 | Critical |
| DHCP Spoofing | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | Critical |
| RELEASE/DECLINE Flood | `TTPs/T1499.md` + `IOCs/ip-<src>.md` | T1499 | High |
| DHCP Relay Anomaly | `Concepts/DHCP-relay-anomaly.md` | T1557 | Medium |
| DHCP Message Injection | `TTPs/T1557.md` + `IOCs/ip-<src>.md` | T1557 | Critical |

Verify:
```bash
./scripts/vault_context.sh ttp T1557
./scripts/vault_context.sh ioc <rogue_server_ip>
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Empty flow inventory | No DHCP traffic in PCAP | Verify: `tshark -r capture.pcap -Y "dhcp or bootp"` |
| All fields empty | tshark using bootp vs dhcp naming | Module auto-falls back; check tshark version |
| Rogue server FP | Network has multiple authorised DHCP servers | Raise `ROGUE_SERVER_THRESHOLD` to match the count |
| Relay FPs | Legitimate multi-subnet relay agents | Expected in multi-VLAN environments |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
