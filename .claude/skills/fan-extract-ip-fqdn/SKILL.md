# Skill: FAN Extract IP+FQDN

## Overview

Use this skill to analyse a PCAP or PCAPng file during an incident response.
Given a file path, the analyzer extracts three artefact sets using `tshark`:

| Output | Contents |
|--------|----------|
| `netflow.csv` | Per-flow conversation stats: src/dst IP, ports, protocol, packets, bytes, first/last seen UTC, duration |
| `unique_ips.txt` | Every unique IPv4 and IPv6 address seen as source or destination |
| `unique_fqdns.txt` | Every unique FQDN resolved from DNS queries, HTTP Host headers, and TLS SNI — with source annotation |

All outputs are written to `./analysis/pcap/<pcap_stem>/` and are safe to open
directly in a spreadsheet or Timeline Explorer without further processing.

---

## Invocation

### Standard run

```bash
./scripts/pcap_analyze.sh <pcap_file>
```

### With a case ID (recommended — stamped in the report)

```bash
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001
```

### Custom output directory

```bash
./scripts/pcap_analyze.sh capture.pcap --output-dir ./analysis/pcap/custom/
```

### Python directly (for use inside scripts)

```python
import sys; sys.path.insert(0, "./lib")
from pathlib import Path
from pcap_analyzer import main, extract_netflow, extract_unique_ips, extract_unique_fqdns

# Full pipeline
main(Path("capture.pcap"), case_id="CASE-2025-001")

# Individual extractors
out_dir = Path("./analysis/pcap/capture/")
out_dir.mkdir(parents=True, exist_ok=True)
netflow_path, flow_count   = extract_netflow(Path("capture.pcap"), out_dir)
ip_path,      ip_count     = extract_unique_ips(Path("capture.pcap"), out_dir)
fqdn_path,    fqdn_count   = extract_unique_fqdns(Path("capture.pcap"), out_dir)
```

---

## Output Detail

### netflow.csv

One row per unique unidirectional flow. Columns:

| Column | Description |
|--------|-------------|
| `src_ip` | Source IP (IPv4 or IPv6) |
| `src_port` | Source port (blank for ICMP, GRE, ESP, etc.) |
| `dst_ip` | Destination IP |
| `dst_port` | Destination port |
| `protocol` | TCP / UDP / ICMP / GRE / ESP / AH / ICMPv6 / … |
| `packets` | Total packets in this flow direction |
| `bytes` | Total bytes (frame length on wire) |
| `first_seen_utc` | First packet timestamp (ISO-8601 UTC) |
| `last_seen_utc` | Last packet timestamp (ISO-8601 UTC) |
| `duration_sec` | Flow duration in seconds |

**IR triage queries against netflow.csv:**

```bash
# Top talkers by bytes (most data transferred)
sort -t, -k7 -rn ./analysis/pcap/<stem>/netflow.csv | head -20

# Flows to unusual ports (not 80/443/53/22)
awk -F, '$5 !~ /^(80|443|53|22|25|587|465|110|995|143|993)$/ && $1 != "src_ip"' \
  ./analysis/pcap/<stem>/netflow.csv

# Long-duration flows (potential beaconing) — over 300 seconds
awk -F, '$10 > 300 && $1 != "src_ip"' ./analysis/pcap/<stem>/netflow.csv

# UDP traffic only
grep ",UDP," ./analysis/pcap/<stem>/netflow.csv

# External flows only (exclude RFC1918 destinations)
grep -v ",\(10\.\|192\.168\.\|172\.\(1[6-9]\|2[0-9]\|3[01]\)\)\." \
  ./analysis/pcap/<stem>/netflow.csv
```

### unique_ips.txt

One IP per line, IPv4 first then IPv6, sorted numerically.

```bash
# Count
wc -l ./analysis/pcap/<stem>/unique_ips.txt

# Check each against the vault
while IFS= read -r ip; do
  ./scripts/vault_context.sh ioc "$ip"
done < ./analysis/pcap/<stem>/unique_ips.txt

# Check unknown IPs against Perplexity
./scripts/perplexity_search.sh ioc 203.0.113.42
```

### unique_fqdns.txt

One FQDN per line with source tag. Format: `fqdn\t[source,source]`

Sources: `dns` | `http` | `tls_sni`

**Automatically excluded:**
- `*.in-addr.arpa` — reverse DNS PTR query names (not threat indicators)
- `*.ip6.arpa` — IPv6 reverse DNS query names (not threat indicators)

```bash
# Count
wc -l ./analysis/pcap/<stem>/unique_fqdns.txt

# FQDNs seen only in TLS (no DNS — potential DGA or encrypted C2)
grep "tls_sni" ./analysis/pcap/<stem>/unique_fqdns.txt | grep -v "dns"

# FQDNs with no legitimate-looking TLD
grep -Ev "\.(com|net|org|io|gov|edu|co\.|uk|de|fr|nl|au|ca|jp)(\t|$)" \
  ./analysis/pcap/<stem>/unique_fqdns.txt

# Lookup unknown domain against Perplexity
./scripts/perplexity_search.sh ioc evil.example.com
```

---

## Full IR Workflow

```bash
# 1. Run analyzer
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# 2. Check IPs against vault
./scripts/vault_context.sh search "$(head -5 ./analysis/pcap/capture/unique_ips.txt | tr '\n' ' ')"

# 3. Pivot unknown IPs and FQDNs through Perplexity
./scripts/perplexity_search.sh ioc <suspicious_ip>
./scripts/perplexity_search.sh ioc <suspicious_fqdn>

# 4. Record confirmed IOCs to vault
python3 - <<'EOF'
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc
record_ioc("ip", "203.0.113.42", "C2 destination confirmed in PCAP.", "CASE-2025-001",
           severity="high", related_ttps=["T1071.001 Web Protocols"])
record_ioc("domain", "evil.example.com", "Resolved in PCAP DNS. No legitimate use.",
           "CASE-2025-001", severity="high")
EOF

# 5. Review report
cat ./analysis/pcap/capture/report.md
```

---

## FQDN Source Interpretation

| Source tag | Meaning | Notes |
|------------|---------|-------|
| `dns` | Seen in a DNS query or response | Most reliable — explicit name resolution |
| `http` | Seen in an HTTP Host header | Confirms actual HTTP connection to that host |
| `tls_sni` | Seen in a TLS Client Hello SNI extension | Confirms TLS connection; hostname not in DNS = suspicious |

A domain appearing only as `tls_sni` with no `dns` entry may indicate:
- DNS over HTTPS (DoH) bypassing local DNS
- Hardcoded IP with SNI spoofing
- DGA domain that wasn't resolved locally

---

## Supported File Formats

tshark supports any format Wireshark can open:
`pcap`, `pcapng`, `cap`, `dmp`, `etl` (Windows ETL via conversion), `log` (various).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `netflow.csv` is empty | No IP traffic in PCAP | Verify with `tshark -r <pcap> -q -z io,phs` |
| `unique_fqdns.txt` is empty | No DNS/HTTP/TLS traffic | PCAP may be raw TCP only |
| `tshark` permission error on interface PCAP | Capture file locked | Copy to `./exports/` first |
| IPv6 flows not appearing | PCAP has only IPv4 | Expected — both are captured when present |
| Large PCAP takes >5 min | Normal for GB-scale PCAPs | Use `--output-dir` to resume partial runs |

---

## Vault Recording

The FAN Extract IP+FQDN extracts data rather than classifying threats, so vault recording
is minimal at this stage — the downstream analysis skills write the intelligence.

**However**, if a case ID is provided, open the case in the vault immediately so all
downstream skill results are grouped under a single case record:

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import open_case

# At the start of PCAP analysis when a case ID is assigned:
open_case(
    case_id=case_id,
    summary=f"PCAP analysis: {pcap_filename}. "
            f"Flows: {flow_count}. Unique IPs: {ip_count}. Unique FQDNs: {fqdn_count}.",
    severity="medium",           # update to high/critical after threat assessment
)
```

The case is closed by the analyst or by `/fan-report` after all modules complete.

**After running downstream skills**, if specific IOCs are confirmed, record them:
```python
from knowledge_extractor import record_ioc
record_ioc("ip", "203.0.113.42", "High-volume external destination. 87% of PCAP traffic.", case_id, severity="medium")
```

Verify:
```bash
./scripts/vault_context.sh cases          # case should appear as open
./scripts/vault_context.sh search "<case_id>"
```

## Output Paths

| File | Path |
|------|------|
| Netflow CSV | `./analysis/pcap/<pcap_stem>/netflow.csv` |
| Unique IPs | `./analysis/pcap/<pcap_stem>/unique_ips.txt` |
| Unique FQDNs | `./analysis/pcap/<pcap_stem>/unique_fqdns.txt` |
| Report | `./analysis/pcap/<pcap_stem>/report.md` |
