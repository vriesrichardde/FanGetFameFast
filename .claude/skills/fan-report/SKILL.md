# Skill: FAN Report

## Overview

Aggregates the outputs of all PCAP analysis modules into a single structured
incident report in both Markdown and PDF format. All input sources are optional —
the report renders cleanly with whatever analyses have been run.

| Input Module | Source Directory | What it contributes |
|---|---|---|
| `fan_pcap_analyzer` | `./analysis/pcap/<stem>/` | Flow statistics, unique IPs/FQDNs, top talkers |
| `fan_ip_lookup` | `./analysis/fan_ip/<stem>/` | CTI reputation for IPs and domains |
| `fan_dns_threats` | `./analysis/dns_threats/<stem>/` | DNS threat findings + flow data for timeline |
| `fan_icmp_threats` | `./analysis/icmp_threats/<stem>/` | ICMP threat findings + flow data for timeline |
| `fan_ntp_threats` | `./analysis/ntp_threats/<stem>/` | NTP threat findings + flow data for timeline |
| `fan_http_threats` | `./analysis/http_threats/<stem>/` | HTTP(S) threat findings + flow data for timeline |
| `fan_cert_inspector` | `./analysis/cert_inspector/<stem>/` | X.509 certificate findings + inventory for timeline |
| `fan_tls_inspector` | `./analysis/tls_inspector/<stem>/` | TLS session inventory + JA4/JA3 fingerprints for timeline |
| `fan_arp_threats` | `./analysis/arp_threats/<stem>/` | ARP threat findings + flow data for timeline |
| `fan_tcp_threats` | `./analysis/tcp_threats/<stem>/` | TCP threat findings + flow data for timeline |
| `fan_udp_threats` | `./analysis/udp_threats/<stem>/` | UDP threat findings + flow data for timeline |
| `fan_dhcp_threats` | `./analysis/dhcp_threats/<stem>/` | DHCP threat findings + flow data for timeline |
| `fan_mdns_threats` | `./analysis/mdns_threats/<stem>/` | mDNS threat findings + flow data for timeline |
| `fan_quic_threats` | `./analysis/quic_threats/<stem>/` | QUIC threat findings + flow data for timeline |
| `fan_snmp_threats` | `./analysis/snmp_threats/<stem>/` | SNMP threat findings (default creds, MitM, flood, recon, SET, large data) |
| `fan_nbns_threats` | `./analysis/nbns_threats/<stem>/` | NBNS threat findings (spoofing, cred theft, SMB relay, WPAD, enum, DoS) |
| `fan_llmnr_threats` | `./analysis/llmnr_threats/<stem>/` | LLMNR threat findings (spoofing, cred theft, SMB relay, recon) |
| `fan_stun_threats` | `./analysis/stun_threats/<stem>/` | STUN threat findings (amplification, info leakage, FW traversal, abuse) |
| `fan_ssdp_threats` | `./analysis/ssdp_threats/<stem>/` | SSDP threat findings (amplification, device exposure, manipulation, UPnP) |
| `fan_netbios_threats` | `./analysis/netbios_threats/<stem>/` | NetBIOS threat findings (poisoning, NTLM hash/relay, null session, SMB) |
| `fan_file_hashes` | `./analysis/file_hashes/<stem>/` | Extracted file inventory, MD5/SHA256 hashes, OSINT verdicts |
| `fan_suricata` | `./analysis/suricata/<stem>/` | Suricata IDS EVE JSON alerts |
| `fan_yara_pcap` | `./analysis/yara_pcap/<stem>/` | YARA rule matches against PCAP + extracted files |

| Output | Path |
|--------|------|
| Markdown report | `./reports/<stem>_incident_report.md` |
| PDF report | `./reports/<stem>_incident_report.pdf` |

---

## Invocation

```bash
# Standard run — uses all available analysis outputs
./scripts/generate_pcap_report.sh --stem capture

# With case ID (recommended — stamped in report header)
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001

# Custom output directory
./scripts/generate_pcap_report.sh --stem capture --output-dir ./reports/case1/
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from generate_pcap_report import generate_report
from pathlib import Path

md_path, pdf_path = generate_report(
    stem="capture",
    case_id="CASE-2025-001",
    output_dir=Path("./reports/")
)
```

---

## Full IR Workflow

```bash
# Step 1 — Extract netflow, IPs, FQDNs from PCAP
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — ICMP threat detection
./scripts/fan_icmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 3 — DNS threat detection
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 4 — NTP threat detection
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 5 — HTTP(S) unusual pattern detection
./scripts/fan_http_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 6 — TLS certificate inspection
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 7 — TLS session inspection + JA4 fingerprinting
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 8 — ARP threat detection
./scripts/fan_arp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 9 — TCP threat detection
./scripts/fan_tcp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 10 — UDP threat detection
./scripts/fan_udp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 11 — DHCP threat detection
./scripts/fan_dhcp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 12 — mDNS threat detection
./scripts/fan_mdns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 13 — QUIC threat detection (note: full orchestrator handles all steps automatically)
./scripts/fan_quic_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 14 — SNMP threat detection
./scripts/fan_snmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 15 — NBNS threat detection
./scripts/fan_nbns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 16 — LLMNR threat detection
./scripts/fan_llmnr_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 17 — STUN threat detection
./scripts/fan_stun_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 18 — SSDP threat detection
./scripts/fan_ssdp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 19 — NetBIOS threat detection
./scripts/fan_netbios_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 20 — CTI enrichment (FQDN/IP OSINT)
python3 lib/fan_ip_lookup.py <fqdn_file> <ip_file> --case-id CASE-2025-001

# Step 21 — Generate consolidated incident report
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001

# Step 22 — Review report
cat ./reports/capture_incident_report.md
```

The `--stem` value must match the PCAP filename stem used in the earlier analysis
steps (e.g., if you analysed `capture.pcap`, stem is `capture`).

---

## Report Structure

| Section | Audience | Contents |
|---------|----------|---------|
| **1. Management Summary** | Non-technical | Overall severity, key findings in plain language, top 5 immediate actions |
| **2.1 ICMP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.2 DNS Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.3 NTP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.4 HTTP(S) Unusual Patterns** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.5 TLS Certificate Inspector** | Technical | Self-signed, expired, short-lived, SNI-mismatch findings; cert inventory |
| **2.6 TLS Session Inspector** | Technical | Session inventory with JA4/JA3/JA4S/JA3S fingerprints, threat findings |
| **2.7 ARP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.8 TCP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.9 UDP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.10 DHCP Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.11 mDNS Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.12 QUIC Threat Analysis** | Technical | Per-category severity, MITRE ATT&CK links, top 10 findings per category |
| **2.13 SNMP Threat Analysis** | Technical | Default creds, MitM, flood, recon, SET operations, large data transfers |
| **2.14 NBNS Threat Analysis** | Technical | Spoofing/poisoning, credential theft, SMB relay, WPAD, enum, DoS |
| **2.15 LLMNR Threat Analysis** | Technical | Spoofing/poisoning, credential theft, SMB relay, reconnaissance |
| **2.16 STUN Threat Analysis** | Technical | Amplification DDoS, info leakage (XOR-MAPPED-ADDRESS), FW traversal, abuse |
| **2.17 SSDP Threat Analysis** | Technical | Amplification, device exposure, network manipulation, vulnerable UPnP |
| **2.18 NetBIOS Threat Analysis** | Technical | Poisoning, NTLM hash theft, relay, enumeration, null session, malware propagation |
| **2.19 File Hash Analysis** | Technical | Extracted file inventory (HTTP/SMB/TFTP/IMF/DICOM), MD5/SHA256, OSINT verdicts |
| **2.20 Suricata IDS Alerts** | Technical | EVE JSON alerts with severity breakdown, top signatures, critical/high detail |
| **2.21 YARA Rule Matches** | Technical | YARA match results: rule name, matched target, severity, MITRE ATT&CK |
| **2.22 Network Flow Summary** | Technical | Protocol distribution, top talkers (src/dst), total traffic stats |
| **2.23 CTI Enrichment** | Technical | Malicious/suspicious IPs and domains from OSINT, OSINT summaries |
| **3. Threat Timeline** | Technical | Chronological table of up to 150 significant events from all flows |
| **4. Indicators of Compromise** | Technical | Deduplicated IOC table: type, value, severity, category |
| **5. MITRE ATT&CK Coverage** | Technical | Techniques observed, linked to attack.mitre.org |
| **6. Recommendations** | Mixed | Specific actionable steps based on what was found |
| **Appendix A** | Technical | Paths to all source analysis files |

---

## Threat Timeline Logic

The timeline samples significant events directly from the flow CSVs
(`icmp_flows.csv`, `dns_flows.csv`) and annotates them using the detector findings
from the JSON outputs. It does **not** include every packet — it selects events
that correspond to detected threat patterns:

**ICMP timeline events selected:**
- Echo Requests from flood-flagged source IPs
- Oversized Echo payloads (≥128 bytes) from tunneling-flagged sources
- Echo payloads from exfiltration-flagged sources
- Packets with IP length ≥65000 (Ping of Death)
- Fragmented ICMP packets
- Echo Requests to broadcast addresses (Smurf)
- ICMP Type 5 Redirect messages
- Packets from ping-sweep sources
- Obsolete ICMP types (13, 14, 15, 16, 17, 18)
- Destination Unreachable (Type 3) packets

**DNS timeline events selected:**
- Queries matching tunneling-flagged domains
- Queries matching beaconing-flagged domains
- Queries matching DGA-flagged domains
- NXDOMAIN responses
- AXFR/IXFR zone transfer attempts
- DNS ANY queries
- Large DNS responses (>512 bytes)

**HTTP(S) timeline events selected:**
- Regular-interval requests from beaconing-flagged (source, host, path) tuples
- Requests from exploit/injection-flagged source IPs (suspicious URI)
- Requests from suspicious-UA-flagged source IPs
- Unusual HTTP methods (TRACE, PROPFIND, MKCOL, SEARCH, LOCK, UNLOCK)
- Large uploads (POST/PUT ≥ 500 KB) from flagged sources
- Error responses (4xx/5xx) to scanning-flagged client IPs
- Responses with C2-framework Server header signatures

**NTP timeline events selected:**
- Large NTP responses (≥200 bytes) to amplification victim IPs
- NTP flood packets from flagged source IPs
- Kiss-of-Death (KoD) packets (stratum 0 with KoD refid)
- NTP Mode 7 (private/deprecated) packets
- NTP responses from time-manipulation-flagged sources
- NTP server responses from non-standard source port (not 123)
- Stratum 16 (unsynchronised) server responses
- NTP client probes from reconnaissance-flagged sources

**Certificate timeline events selected:**
- Sessions where server presents a self-signed certificate (from flagged server IPs)
- Sessions with certificate CN/SNI mismatch (possible MITM — from flagged server IPs)
- Sessions with expired certificate (from flagged server IPs)
- Sessions with very short-lived certificate (< 30 days validity)

**TLS timeline events selected:**
- Sessions from client IPs matching known C2 JA4/JA3 fingerprints
- Sessions with weak cipher suite negotiated (from flagged IP pairs)
- TLS sessions on non-standard ports (from flagged server IPs)
- Sessions where TLS 1.0 or TLS 1.1 was negotiated

**ARP timeline events selected:**
- ARP replies from cache-poisoning-flagged source MACs
- Gratuitous ARP announcements from flagged IPs
- ARP requests from flood-flagged source IPs
- ARP requests from scan-flagged source IPs (volume-based)

**TCP timeline events selected:**
- SYN packets from SYN-flood-flagged source IPs
- Port scan probes from scan-flagged source IPs
- RST packets from RST-flood-flagged sources
- Stealth scan packets (FIN-only, NULL, Xmas) from flagged sources
- RST packets from session-hijacking-flagged third-party IPs

**UDP timeline events selected:**
- UDP datagrams from UDP-flood-flagged (src, dst, port) tuples
- Large UDP responses from amplification-flagged reflector IPs
- UDP probes from port-scan-flagged source IPs
- Fragmented UDP packets from fragmentation-flagged sources
- Low-TTL UDP packets from spoofing-flagged sources

**DHCP timeline events selected:**
- DHCP DISCOVER from starvation-attack MAC addresses
- DHCP OFFER/ACK from rogue server IPs
- DHCP OFFER/ACK where src_ip ≠ server-id option (spoofing)
- DHCP RELEASE/DECLINE from flood-flagged sources
- DHCP messages with non-zero GIADDR from unauthorized relay IPs

**mDNS timeline events selected:**
- Large mDNS responses (≥512 bytes) from amplification-flagged sources
- mDNS queries/responses matching sensitive keyword patterns
- Conflicting mDNS records (same hostname, different IPs) from spoofing sources
- mDNS unicast responses to non-multicast targets
- mDNS traffic from globally-routable (non-link-local) source IPs

**QUIC timeline events selected:**
- QUIC responses from amplification-flagged server IPs
- QUIC 0-RTT packets from replay-flagged source IPs
- QUIC long-header packets with unknown version numbers
- QUIC Initial packets from handshake-exhaustion-flagged source IPs
- QUIC sessions on non-standard ports from flagged source IPs

Timeline is capped at **150 events**. When truncating, critical and high severity
events are preserved over medium/low.

---

## PDF Generation

PDF output requires either `pandoc` or the Python `weasyprint` package.
The module tries both automatically in order.

**Recommended (Python-only, no system packages needed):**
```bash
pip3 install markdown weasyprint
```

**Alternative (system package, requires LaTeX for PDF):**
```bash
sudo apt install pandoc texlive-latex-base texlive-fonts-recommended
# OR — for weasyprint engine without LaTeX:
sudo apt install pandoc
pip3 install weasyprint
```

If neither tool is available the Markdown report is still written successfully;
only the PDF conversion step is skipped with a warning message.

---

## IOC Extraction Logic

IOCs are automatically extracted from triggered detection categories:

| Source | What is extracted |
|--------|------------------|
| ICMP flood/tunneling/exfil/redirect/sweep | Source IP of flagged flows |
| ICMP smurf | Broadcast destination IPs |
| DNS DGA/beaconing/tunneling/typosquatting | Flagged domain names |
| CTI enrichment | Any IP or FQDN with reputation `malicious` or `suspicious` |

All IOCs are deduplicated across sources. The same IP flagged by both an ICMP
flood detector and CTI enrichment appears once at the highest severity.

---

## Recommendations Logic

Recommendations are generated dynamically based on which categories triggered:

| Finding | Recommendation generated |
|---------|--------------------------|
| Malicious IPs (CTI) | Block immediately + quarantine communicating hosts |
| ICMP exfiltration | Block large outbound ICMP; investigate source hosts for malware |
| ICMP tunneling | Rate-limit/block oversized ICMP; deploy DPI for tunnel tools |
| ICMP flood | Rate-limit at border; contact ISP for upstream nullrouting |
| Smurf | Disable directed broadcast forwarding; block at edge |
| ICMP redirect | Disable redirect processing (`net.ipv4.conf.all.accept_redirects = 0`) |
| DNS tunneling/exfil | Block long-label DNS queries; deploy DNS security layer |
| DNS DGA | Investigate hosts; deploy DNS RPZ sinkholing |
| DNS beaconing | Isolate beaconing hosts; full memory+disk forensics |
| DNS amplification | Block ANY queries; configure resolver rate limits |
| HTTP beaconing | Isolate beaconing hosts; full memory+disk forensics for C2 implants |
| Suspicious URI | Review web logs; WAF-protect injection/traversal endpoints |
| Suspicious UA | Block offensive tool UAs at proxy; investigate source hosts |
| Unusual HTTP server | Block C2-framework server IPs immediately |
| Large HTTP upload | Inspect POST/PUT payloads for exfiltrated data |
| HTTP scanning | WAF rate-limit scanning clients; review for successful exploitation |
| Deprecated TLS | Enforce TLS 1.2+ minimum on all servers and clients |
| Cookie anomaly | Inspect oversized/high-entropy cookies for exfil payloads |
| Host header injection | WAF-block malformed Host headers; validate in application |
| NTP amplification | Rate-limit inbound NTP responses; disable monlist on NTP servers |
| NTP Mode 7 abuse | Disable mode 7 (`restrict default noquery nomodify`); block at perimeter |
| NTP Kiss-of-Death | Verify NTP server list; investigate spoofed KoD sources |
| NTP spoofed response | Block non-port-123 NTP responses; deploy NTPsec/NTS |
| NTP time manipulation | Audit NTP servers; check system logs for timestamp anomalies |
| NTP flood | Rate-limit NTP at perimeter; contact ISP for upstream nullrouting |
| NTP recon | Alert on hosts scanning NTP infrastructure |
| Certificate CN/SNI mismatch | Investigate path for MITM proxies; audit SSL inspection appliances |
| Self-signed certificate | Block TLS to self-signed certs on external services; check for C2 |
| Expired certificate | Audit neglected servers; update cert management processes |
| Weak certificate signature | Replace MD5/SHA-1 certs; enforce SHA-256 minimum in CA policy |
| Short-validity certificate | Cross-reference JA4 + IP intel for C2 framework indicators |
| Suspicious JA4/JA3 | Block immediately; isolate communicating hosts; full forensic analysis |
| Weak TLS cipher | Disable NULL/EXPORT/RC4/anon/DES/3DES; enforce AES-GCM/ChaCha20 |
| Deprecated TLS negotiated | Disable TLS 1.0/1.1 on servers; enforce TLS 1.2 minimum |
| TLS non-standard port | Review for C2 channels; block unexpected TLS ports at perimeter |
| TLS cipher diversity | Investigate source for TLS scanning or C2 fingerprint rotation |
| ARP cache poisoning | Deploy Dynamic ARP Inspection (DAI) on managed switches; monitor ARP table for IP conflicts |
| Gratuitous ARP flood | Enable DAI rate-limiting; investigate source for MITM tools (arpspoof, bettercap) |
| ARP scan | Alert on ARP volume spikes; isolate scanning host for further investigation |
| ARP flood | Rate-limit ARP at switch level; consider static ARP entries for critical infrastructure |
| SYN flood | Enable SYN cookies on servers; deploy rate-limiting at firewall/load balancer |
| TCP port scan | Alert and block scanning source; review firewall rules for unnecessary open ports |
| RST flood | Rate-limit RST packets at perimeter; investigate source for injection tools |
| Stealth scan | Deploy IDS rules for FIN/NULL/Xmas probes; block scanning source |
| Session hijacking | Enforce encrypted sessions (TLS); deploy TCP sequence number randomization |
| TCP half-open flood | Configure server SYN backlog and timeout values; enable SYN cookies |
| UDP flood | Rate-limit UDP at perimeter; contact ISP for upstream nullrouting of attack source |
| UDP amplification | Block spoofed-source UDP responses; contact reflector ISPs; deploy BCP38 |
| UDP port scan | Block scanning source; audit UDP services exposed to network |
| UDP fragmentation | Drop malformed fragments at firewall; tune reassembly timeouts on stateful devices |
| UDP spoofing indicator | Validate that upstream providers implement BCP38/uRPF; investigate low-TTL sources |
| DHCP starvation | Deploy DHCP snooping on access switches; limit DHCP per-port lease rate |
| Rogue DHCP server | Enable DHCP snooping; configure trusted DHCP server ports only; investigate rogue source |
| DHCP spoofing | Deploy DHCP snooping + IP Source Guard; compare option-54 vs src_ip on all OFFER/ACK |
| DHCP release flood | Enable DHCP snooping rate-limiting; isolate flooding source |
| DHCP relay anomaly | Audit GIADDR sources; restrict relay agent permissions at DHCP server |
| DHCP message injection | Block unknown vendor-class identifiers; audit option-82 relay sources |
| mDNS amplification | Block mDNS forwarding at routers; firewall UDP 5353 to link-local only |
| mDNS information leakage | Audit service naming conventions; suppress sensitive hostnames from mDNS announcements |
| mDNS spoofing | Deploy mDNS-aware IDS rules; monitor ARP/mDNS consistency for MITM indicators |
| mDNS outside segment | Block UDP 5353 at segment boundaries; investigate source for reconnaissance activity |
| mDNS flood | Rate-limit mDNS at switch/AP level; investigate source for broadcast storm tools |
| QUIC amplification | Validate QUIC token enforcement on servers; rate-limit Initial packets per IP |
| QUIC 0-RTT replay | Disable 0-RTT on servers or enforce server-side anti-replay checks |
| QUIC version forgery | Log/block unknown QUIC versions at perimeter; investigate source for version probing |
| QUIC handshake exhaustion | Rate-limit QUIC Initial packets per source IP at load balancer/firewall |
| QUIC non-standard port | Block unexpected QUIC/UDP ports; inspect for C2 channels encapsulating QUIC |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No analysis sources found` | Stem doesn't match analysis directories | Check `./analysis/*/` subdirectory names match `--stem` |
| PDF not generated | Neither pandoc nor weasyprint installed | `pip3 install markdown weasyprint` |
| `ImportError: No module named 'markdown'` | Missing Python package | `pip3 install markdown weasyprint` |
| Empty timeline | Flow CSVs contain no notable events | Run `cti_icmp_threats.sh`, `cti_dns_threats.sh`, and `cti_ntp_threats.sh` first |
| Report missing CTI section | CTI enrichment not run | Run `cti_ip_lookup.sh --stem <stem>` first |
| Report missing NTP section | NTP analysis not run | Run `cti_ntp_threats.sh <pcap> --stem <stem>` first |
| Report missing HTTP section | HTTP analysis not run | Run `cti_http_threats.sh <pcap> --stem <stem>` first |
| Report missing certificate section | Cert inspector not run | Run `cti_cert_inspector.sh <pcap> --stem <stem>` first |
| Report missing TLS section | TLS inspector not run | Run `cti_tls_inspector.sh <pcap> --stem <stem>` first |
| Report missing ARP section | ARP analysis not run | Run `cti_arp_threats.sh <pcap> --stem <stem>` first |
| Report missing TCP section | TCP analysis not run | Run `cti_tcp_threats.sh <pcap> --stem <stem>` first |
| Report missing UDP section | UDP analysis not run | Run `cti_udp_threats.sh <pcap> --stem <stem>` first |
| Report missing DHCP section | DHCP analysis not run | Run `cti_dhcp_threats.sh <pcap> --stem <stem>` first |
| Report missing mDNS section | mDNS analysis not run | Run `cti_mdns_threats.sh <pcap> --stem <stem>` first |
| Report missing QUIC section | QUIC analysis not run | Run `cti_quic_threats.sh <pcap> --stem <stem>` first |
| weasyprint font warnings | Missing system fonts | `sudo apt install fonts-dejavu` |

---

## Vault Recording

The report generator is the final step in the PCAP analysis pipeline. It closes the
investigation case in the vault and records a consolidated summary of all findings.

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import close_case, record_risk

# On report generation completion — close the case with findings summary:
close_case(
    case_id=case_id,
    findings=(
        f"PCAP incident report generated (v{report_version}). "
        f"Suricata alerts: {suricata_count}. YARA matches: {yara_count}. "
        f"Critical IOCs: {critical_ioc_count}. "
        f"Report: {report_path}"
    ),
)

# If the overall investigation found Critical severity threats, record the risk:
if max_severity in ("Critical", "High"):
    record_risk(
        asset=f"Network capture — {pcap_stem}",
        risk_description=(
            f"PCAP investigation found {critical_ioc_count} critical IOCs, "
            f"{suricata_count} IDS alerts, {yara_count} YARA matches. "
            f"Full report: {report_path}."
        ),
        severity=max_severity.lower(),
        case_id=case_id,
    )
```

The individual analysis skills (cti-dns-threats, cti-suricata, etc.) write TTPs and IOCs
during their own execution — this step only adds the case closure and risk summary.

Verify:
```bash
./scripts/vault_context.sh cases          # case should appear as closed
./scripts/vault_context.sh risks          # risk entry should appear if Critical/High
```

## Output Paths

| File | Path |
|------|------|
| Markdown Report | `./reports/<stem>_incident_report.md` |
| PDF Report | `./reports/<stem>_incident_report.pdf` |
