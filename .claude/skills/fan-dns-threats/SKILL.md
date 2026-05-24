# Skill: FAN DNS Threats

## Overview

Analyzes a PCAP file for DNS-based attack patterns using `tshark` for packet
extraction and Python-based heuristics for detection. Covers 11 threat categories
mapped to MITRE ATT&CK. High-severity findings are automatically written to the
Obsidian vault as TTPs and IOCs.

| Output | Contents |
|--------|----------|
| `dns_threats_report.md` | Human-readable report: severity table, per-category findings, MITRE links |
| `dns_threats.json` | Full machine-readable findings (all categories) |
| `dns_flows.csv` | Per-packet DNS flow log: direction, FQDN, qtype, rcode, TTL, A records |

All outputs are written to `./analysis/dns_threats/<pcap_stem>/`.

---

## Invocation

```bash
# Standard run
./scripts/fan_dns_threats.sh /path/to/capture.pcap

# With case ID (recommended — stamped in report and vault entries)
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom output stem
./scripts/fan_dns_threats.sh capture.pcap --stem my-investigation

# Skip vault writes (offline / restricted environment)
./scripts/fan_dns_threats.sh capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from pathlib import Path
from fan_dns_threats import extract_dns_records, detect_dga, detect_beaconing

records = extract_dns_records(Path("capture.pcap"))
print(detect_dga(records))
print(detect_beaconing(records))
```

---

## Full IR Workflow

```bash
# Step 1 — Extract netflow, IPs, FQDNs from PCAP
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — DNS-specific threat detection
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 3 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 4 — Review DNS threat report
cat ./analysis/dns_threats/capture/dns_threats_report.md

# Step 5 — Triage specific threat category
python3 -c "
import json
data = json.load(open('./analysis/dns_threats/capture/dns_threats.json'))
import pprint; pprint.pprint(data['dga'])
"
```

---

## Detection Categories

| Category | MITRE ATT&CK | Severity | What it detects |
|----------|-------------|----------|-----------------|
| DNS Amplification / Reflection | T1498.002 | High | Response/query byte ratio ≥5× or ANY queries |
| NXDomain Flooding | T1498 | High | ≥20 NXDOMAIN responses from single source IP |
| Domain Generation Algorithm | T1568.002 | High/Medium | High-entropy, long, consonant-heavy domain names |
| C&C DNS Beaconing | T1071.004 | High | Regular-interval queries (CV ≤ 0.30, ≥5 queries) |
| DNS Data Exfiltration / Tunneling | T1048.001 / T1572 | Critical/High | Long labels (>40 chars), encoded subdomains, many unique subdomains |
| Excessive DNS Query Rate | T1498 | Medium | ≥200 queries total from single source IP |
| Fast Flux DNS | T1568.001 | High/Medium | ≥3 unique IPs per domain or TTL ≤300s |
| Unauthorized DNS Servers | T1584.002 | Medium | Public DNS servers not in known-good list |
| Unusual DNS Record Types | T1071.004 | Critical/Medium | AXFR/IXFR (zone transfer), ANY, bulk TXT |
| Typosquatting / Impersonation | T1583.001 | Medium | Edit distance ≤2 from well-known domains |
| DNS Response Spoofing | T1557 | High | Same domain returns different IPs from different servers |

---

## Detection Thresholds

These are constants in `lib/fan_dns_threats.py` — adjust to fit your environment:

| Constant | Default | Purpose |
|----------|---------|---------|
| `DGA_ENTROPY_THRESHOLD` | 3.5 bits | Shannon entropy above which SLD is flagged |
| `DGA_MIN_SLD_LENGTH` | 10 chars | Minimum SLD length for DGA analysis |
| `DGA_CONSONANT_RATIO` | 0.65 | Consonant fraction indicating random generation |
| `BEACON_MIN_QUERIES` | 5 | Minimum queries before timing analysis runs |
| `BEACON_MAX_CV` | 0.30 | Coefficient of variation threshold (low = regular) |
| `EXFIL_LABEL_LEN` | 40 chars | Single subdomain label length trigger |
| `EXFIL_TOTAL_LEN` | 100 chars | Total FQDN length trigger |
| `EXFIL_UNIQUE_SUBS` | 15 | Unique subdomains per apex = likely tunnel |
| `NXDOMAIN_FLOOD_THRESH` | 20 | NXDOMAIN count per source IP |
| `EXCESSIVE_QUERY_THRESH` | 200 | Total query count per source IP |
| `AMPLIFICATION_FACTOR` | 5.0× | Response / query byte ratio |
| `FAST_FLUX_MAX_TTL` | 300 s | TTL below which A records are suspicious |
| `FAST_FLUX_MIN_IPS` | 3 | Unique IPs per domain triggering fast flux flag |

---

## IR Triage Queries

```bash
STEM="capture"
OUT="./analysis/dns_threats/$STEM"

# All threat categories with findings
python3 -c "
import json
data = json.load(open('$OUT/dns_threats.json'))
for k,v in data.items():
    if v['severity'] != 'info':
        print(f\"{v['severity'].upper():8s}  {v['name']}: {v['count']} finding(s)\")
"

# All NXDOMAIN responses
awk -F, '$6 == "NXDOMAIN"' $OUT/dns_flows.csv | head -30

# All TXT queries (tunneling vector)
awk -F, '$9 == "TXT" && $5 == "query"' $OUT/dns_flows.csv

# ALL AXFR/IXFR (zone transfer attempts)
awk -F, '$9 ~ /AXFR|IXFR/' $OUT/dns_flows.csv

# Any queries (amplification)
awk -F, '$9 == "ANY"' $OUT/dns_flows.csv

# Large frames (> 512 bytes — potential amplification responses)
awk -F, '$13 > 512 && $5 == "response"' $OUT/dns_flows.csv | head -20

# DNS flows to unexpected servers (not 8.8.8.8, 1.1.1.1, etc.)
awk -F, '$4 != "8.8.8.8" && $4 != "1.1.1.1" && $4 != "9.9.9.9" && $5 == "query"' \
  $OUT/dns_flows.csv | head -20

# Unique queried domains sorted by frequency
awk -F, 'NR>1 && $5=="query" {print $7}' $OUT/dns_flows.csv | sort | uniq -c | sort -rn | head -30

# All FQDN queries from a specific source IP
awk -F, '$2 == "192.168.1.100" && $5 == "query" {print $7}' $OUT/dns_flows.csv
```

---

## DGA Detection Logic

Shannon entropy is computed on the second-level domain (SLD — the label immediately
left of the TLD). High entropy indicates characters are distributed randomly rather
than following natural-language patterns.

A domain is scored and flagged if it accumulates **≥3 points**:

| Signal | Points | Example |
|--------|--------|---------|
| Entropy ≥ 3.5 bits | +2 | `xvzqmplf` |
| Consonant ratio ≥ 0.65 | +1 | `krstmpln` |
| SLD length ≥ 16 chars | +1 | `qpwxzmkrtbvclndf` |
| >25% digits, ≥4 digits | +1 | `a3b9d2f7c1` |

Known CDN patterns (akamai, cloudfront, fastly, etc.) and well-known domain apexes
are excluded before scoring to reduce false positives.

---

## Beaconing Detection Logic

Queries are grouped by **(source IP, apex domain)**. Timing analysis runs if the
group has ≥5 queries with inter-query intervals ≥5 seconds (to exclude DNS retransmits).

**Coefficient of Variation (CV) = std_dev / mean**

- CV ≤ 0.30: highly regular → likely C2 beacon (flag)
- CV 0.31–1.0: irregular → likely human or retry traffic
- CV > 1.0: random bursts → not beaconing

---

## DNS Exfiltration / Tunneling Detection Logic

Three independent signals, any of which independently flags a domain:

1. **Long labels** — a single subdomain label > 40 chars encodes substantial data
2. **Encoded patterns** — base64 regex (`[A-Za-z0-9+/]{30,}=*`) or hex (`[0-9a-fA-F]{30,}`) in the subdomain
3. **Unique subdomain count** — ≥15 unique subdomains per apex domain suggests a sustained tunnel

TXT queries are additionally flagged in bulk (>5 TXT queries) as they are commonly
abused by DNS tunneling tools (dnscat2, iodine, dns2tcp).

---

## Vault Integration

High and critical severity findings are automatically written to the vault:

- **TTPs** — one note per triggered MITRE technique (updated if existing)
- **IOCs** — suspicious domains from DGA, beaconing, exfiltration, fast flux, typosquatting

Use `--no-vault` to suppress vault writes (offline environments or when running repeated tests).

```bash
# Manually record a confirmed DNS tunnel domain
python3 - <<'EOF'
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc, record_ttp
record_ttp("T1572", "Protocol Tunneling",
           "DNS tunneling tool (iodine) confirmed via label length and base64 subdomain analysis.",
           "CASE-2025-001", tactic="command-and-control")
record_ioc("domain", "tunnel.evil.com", "DNS exfiltration tunnel — 47-char encoded labels.",
           "CASE-2025-001", severity="critical",
           related_ttps=["T1572 Protocol Tunneling", "T1048.001 DNS Exfiltration"])
EOF
```

---

## Output Detail

### dns_threats_report.md

Executive summary table followed by per-category sections with:
- Severity and MITRE ATT&CK link
- Description of what was detected
- Top 10 findings in JSON (one per line for easy grepping)
- List of clean categories at the bottom

### dns_threats.json

Full structured output. Each key is a detection category:

```json
{
  "dga": {
    "name": "Domain Generation Algorithm (DGA)",
    "severity": "high",
    "count": 12,
    "mitre": ["T1568.002", "Dynamic Resolution: Domain Generation Algorithms"],
    "findings": [ ... ],
    "description": "..."
  },
  ...
}
```

### dns_flows.csv

One row per DNS packet.

| Column | Description |
|--------|-------------|
| `timestamp_utc` | Packet timestamp (ISO-8601 UTC) |
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `dns_server` | IP of the DNS server (dst for queries, src for responses) |
| `direction` | `query` or `response` |
| `rcode` | Response code: `NOERROR`, `NXDOMAIN`, `SERVFAIL`, … |
| `fqdn` | Queried domain name |
| `qtype_code` | Numeric record type (1=A, 28=AAAA, 16=TXT, 255=ANY, …) |
| `qtype_name` | Record type name |
| `a_records` | Comma-separated A record IPs in responses |
| `ttl_sec` | TTL from response (blank for queries) |
| `answer_count` | Number of answers in response |
| `frame_len_bytes` | Total frame size on wire |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No DNS records found` | PCAP has no UDP/TCP port 53 traffic | Verify with `tshark -r cap.pcap -Y "dns" -q` |
| All DGA scores low | Domains are CDN/cloud infrastructure | Expected — CDN patterns are excluded |
| No beaconing detected | Capture too short for ≥5 interval samples | Capture longer sessions or lower `BEACON_MIN_QUERIES` |
| Many false positives in typosquatting | Internal domains similar to well-known ones | Add your domain to `WELL_KNOWN_DOMAINS` in `lib/fan_dns_threats.py` |
| Vault writes fail | `pyyaml` not installed | `pip3 install pyyaml` |
| `tshark` permission error | Capture file locked | Copy PCAP to `./exports/` first |

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent and severity meets threshold.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| DGA domain detected | `IOCs/domain-<defanged>.md` + `TTPs/T1568.md` | T1568 | High |
| Beaconing domain | `IOCs/domain-<defanged>.md` + `TTPs/T1071.004.md` | T1071.004 | Critical/High |
| DNS exfiltration | `TTPs/T1048.003.md` | T1048.003 | Critical |
| Fast flux detected | `IOCs/domain-<defanged>.md` + `TTPs/T1568.001.md` | T1568.001 | High |
| DNS amplification | `TTPs/T1498.002.md` | T1498.002 | High |
| NXDomain flood | `TTPs/T1498.001.md` | T1498.001 | High |
| Typosquatting domain | `IOCs/domain-<defanged>.md` | — | Medium |
| DNS spoofing/hijack | `TTPs/T1557.md` + `IOCs/ip-<defanged>.md` | T1557 | Critical |
| Zone transfer attempt | `TTPs/T1590.md` | T1590 | Medium |
| Unauthorised resolver | `IOCs/ip-<defanged>.md` | — | High |
| Unusual query types | `Concepts/DNS-<query_type>-anomaly.md` | — | Medium |

Only Critical and High severity findings are written by default. Verify:
```bash
./scripts/vault_context.sh ttp T1568
./scripts/vault_context.sh ioc <suspicious_domain>
./scripts/vault_context.sh search "<case_id>"
```

## Output Paths

| File | Path |
|------|------|
| Threat Report | `./analysis/dns_threats/<stem>/dns_threats_report.md` |
| JSON Findings | `./analysis/dns_threats/<stem>/dns_threats.json` |
| DNS Flow CSV | `./analysis/dns_threats/<stem>/dns_flows.csv` |
| IOC Vault Notes | `./vault/IOCs/<type>-<defanged_value>.md` |
| TTP Vault Notes | `./vault/TTPs/<mitre_id>.md` |
