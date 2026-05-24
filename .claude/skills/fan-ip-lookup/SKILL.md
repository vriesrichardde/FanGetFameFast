# Skill: FAN IP Lookup

## Overview

Correlates the FQDN and IP address lists produced by the FAN Extract IP+FQDN with live DNS
resolution and OSINT enrichment via Perplexity.ai. All results are cached in the Obsidian
vault for 7 days — repeated analysis of the same indicators is fast and API-cost-free within
the cache window.

| Output | Contents |
|--------|----------|
| `correlation.csv` | FQDN → resolved IPs → PCAP match → reputation |
| `ip_enrichment.csv` | IP → reverse DNS → FQDN match → reputation |
| `cti_report.md` | Summary: malicious/suspicious indicators, unmatched IPs |
| `vault/IOCs/<ioc>.md` | IOC note with `## OSINT` section (7-day cache) |

All outputs are written to `./analysis/cti/<pcap_stem>/`.

---

## Invocation

### From PCAP stem (recommended)

```bash
./scripts/fan_ip_lookup.sh --stem <pcap_stem> [--case-id CASE-2025-001]
```

### Explicit file paths

```bash
./scripts/fan_ip_lookup.sh \
  ./analysis/pcap/<stem>/unique_fqdns.txt \
  ./analysis/pcap/<stem>/unique_ips.txt \
  --case-id CASE-2025-001
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from pathlib import Path
from fan_ip_lookup import main

main(
    Path("./analysis/pcap/capture/unique_fqdns.txt"),
    Path("./analysis/pcap/capture/unique_ips.txt"),
    case_id="CASE-2025-001",
)
```

---

## Full IR Workflow

```bash
# Step 1 — PCAP analysis (produces unique_fqdns.txt and unique_ips.txt)
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — CTI enrichment
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 3 — Review the summary report
cat ./analysis/cti/capture/cti_report.md

# Step 4 — Inspect a specific IOC in the vault
cat ./vault/IOCs/domain-evil[.]com.md

# Step 5 — Record confirmed malicious indicators
python3 - <<'EOF'
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc
record_ioc("domain", "evil.com", "Confirmed C2 domain.", "CASE-2025-001",
           severity="high", related_ttps=["T1071.001 Web Protocols"])
EOF
```

---

## Obsidian Vault Caching (7-Day Rule)

Every enriched indicator is stored in `vault/IOCs/` with a `## OSINT` section:

| Cache state | Action |
|-------------|--------|
| Note exists, `date_updated` < 7 days, `## OSINT` present | **Cache hit** — vault data used, Perplexity skipped |
| Note missing, stale (≥ 7 days), or no OSINT section | **Cache miss** — Perplexity queried, result stored in vault |

**Benefit**: investigating the same infrastructure repeatedly (re-infections, multi-stage campaigns) is fast after the first run.

```bash
# Manually check vault for an IOC
./scripts/vault_context.sh ioc 203.0.113.42
./scripts/vault_context.sh ioc evil.com
```

---

## Output Detail

### correlation.csv

One row per FQDN from `unique_fqdns.txt`.

| Column | Description |
|--------|-------------|
| `fqdn` | Domain name |
| `source_tags` | Origin in PCAP: `dns`, `http`, `tls_sni` (comma-separated) |
| `resolved_ips` | Current forward DNS results (comma-separated IPs) |
| `matched_pcap_ips` | IPs present in both DNS resolution and the PCAP IP list |
| `in_pcap` | `yes` = IP match found; `resolved` = resolved but not in PCAP; `no` = unresolvable |
| `reputation` | `malicious` / `suspicious` / `legitimate` / `unknown` |
| `osint_summary` | First 300 chars of Perplexity OSINT answer |

**IR triage queries:**
```bash
# Malicious FQDNs
awk -F, '$6 == "malicious"' ./analysis/cti/<stem>/correlation.csv

# FQDNs that couldn't be resolved (potential DGA or sinkholed)
awk -F, '$5 == "no"' ./analysis/cti/<stem>/correlation.csv

# FQDNs seen only in TLS SNI (no DNS record — suspicious)
grep "tls_sni" ./analysis/cti/<stem>/correlation.csv | grep -v ",dns"
```

### ip_enrichment.csv

One row per IP from `unique_ips.txt`.

| Column | Description |
|--------|-------------|
| `ip` | IP address (IPv4 or IPv6) |
| `is_public` | `yes` / `no` (RFC1918/loopback/link-local = `no`) |
| `reverse_dns` | PTR record, or first matched FQDN if reverse DNS fails |
| `matched_fqdns` | FQDNs (from PCAP) whose forward DNS resolved to this IP |
| `reputation` | `malicious` / `suspicious` / `legitimate` / `unknown` / `private` |
| `osint_summary` | First 300 chars of OSINT (public IPs only) |

**IR triage queries:**
```bash
# Public IPs with no FQDN match (potential direct C2 or lateral movement)
awk -F, '$2 == "yes" && $4 == ""' ./analysis/cti/<stem>/ip_enrichment.csv

# Malicious IPs
awk -F, '$5 == "malicious"' ./analysis/cti/<stem>/ip_enrichment.csv

# All public IPs for bulk threat intel review
awk -F, '$2 == "yes"' ./analysis/cti/<stem>/ip_enrichment.csv
```

---

## Reputation Heuristics

Reputation is inferred automatically from the Perplexity OSINT answer:

| Reputation | Rule |
|------------|------|
| `malicious` | ≥2 malicious keywords, OR 1 malicious keyword with 0 legitimate keywords |
| `suspicious` | Exactly 1 malicious keyword |
| `legitimate` | ≥1 legitimate keyword, 0 malicious keywords |
| `unknown` | No matching keywords, or no OSINT available |
| `private` | RFC1918/loopback/link-local IP — no OSINT performed |

Malicious keywords include: `malicious`, `c2`, `botnet`, `ransomware`, `phishing`, `trojan`,
`backdoor`, `stealer`, `cobalt strike`, `blacklist`, `exploit`, `dropper`.

Legitimate keywords include: `legitimate`, `benign`, `cloudflare`, `akamai`, `fastly`,
`microsoft`, `amazon aws`, `google cloud`, `cdn provider`, `no known malicious`.

**Always manually verify.** Heuristics are a triage aid — not a definitive verdict.

---

## Vault IOC Note Structure

After enrichment, each IOC note contains:

```markdown
---
ioc_type: domain
value: evil[.]com
severity: medium
reputation: malicious
resolved_ips: [203.0.113.42]
case_refs: [CASE-2025-001]
date_updated: 2025-05-05T12:00:00Z
---

## Context
Observed in PCAP. Sources: dns,tls_sni. Resolved: 203.0.113.42. Matched PCAP IPs: 203.0.113.42.

## Observations
### 2025-05-05T12:00:00Z — CASE-2025-001
...

## OSINT
*2025-05-05T12:00:00Z via Perplexity.ai (sonar-pro)*

Known C2 domain associated with Lumma Stealer campaigns observed in 2025...

**Sources:**
- https://...
```

The `## OSINT` section is replaced on cache miss; the surrounding note content is preserved.

---

## DNS Resolution Notes

- **Forward DNS** (`FQDN → IPs`): uses `socket.getaddrinfo()` — system DNS resolver
- **Reverse DNS** (`IP → hostname`): uses `socket.gethostbyaddr()` — PTR record lookup
- Resolution reflects **current** DNS state, which may differ from the time of the PCAP capture
- A FQDN that resolves to an IP not in the PCAP (`in_pcap=resolved`) may indicate DNS rotation
  or infrastructure reuse across campaigns

---

## Dependencies

| Dependency | Required | Notes |
|------------|---------|-------|
| `PERPLEXITY_API_KEY` | For live OSINT | Falls back to vault cache only if unset |
| `lib/pcap_analyzer.py` | Provides input files | Run first |
| `lib/knowledge_extractor.py` | Vault IOC writes | Part of this project |
| `lib/perplexity_client.py` | OSINT queries | Part of this project |

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No OSINT in output | `PERPLEXITY_API_KEY` not set | `export PERPLEXITY_API_KEY='pplx-...'` in `~/.bashrc` |
| All reputations `unknown` | API returning errors or key quota exceeded | Check key; fall back to manual Perplexity |
| `correlation.csv` empty | `unique_fqdns.txt` is empty | Check PCAP for DNS/HTTP/TLS traffic |
| All IPs show `private` | Internal-only capture | Expected — no OSINT on RFC1918 IPs |
| `resolved_ips` empty for many FQDNs | DGA domains, sinkholed, or DNS filtered | Expected — flag these for manual review |

---

## Vault Recording

Written automatically by the lib. The 7-day cache means each unique IOC is only queried
once per week — subsequent runs read from the vault note directly.

| Condition | Vault Note | Severity Written |
|-----------|------------|-----------------|
| OSINT verdict = malicious | `IOCs/ip-<defanged_ip>.md` or `IOCs/domain-<defanged>.md` | Critical |
| OSINT verdict = suspicious | `IOCs/ip-<defanged_ip>.md` or `IOCs/domain-<defanged>.md` | High |
| OSINT verdict = unknown (no hit) | `IOCs/ip-<defanged_ip>.md` (cache stub) | Info — prevents re-query for 7 days |
| All external IPs | Cache stub written even if clean | Always (7-day cache) |

**Manual supplement** — after analyst review, upgrade severity or add context:
```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc

# Promote a previously 'unknown' IP to confirmed malicious after analyst confirms:
record_ioc("ip", "203.0.113.42", "Confirmed C2 server. High-volume beacon traffic in PCAP.",
           case_id, severity="critical", related_ttps=["T1071.001 Web Protocols"])
```

Verify:
```bash
./scripts/vault_context.sh ioc <suspicious_ip>
./scripts/vault_context.sh ioc <suspicious_domain>
./scripts/vault_context.sh search "<case_id>"
```

## Output Paths

| File | Path |
|------|------|
| Correlation CSV | `./analysis/cti/<pcap_stem>/correlation.csv` |
| IP Enrichment CSV | `./analysis/cti/<pcap_stem>/ip_enrichment.csv` |
| CTI Report | `./analysis/cti/<pcap_stem>/cti_report.md` |
| IOC Vault Notes | `./vault/IOCs/<type>-<defanged_value>.md` |
