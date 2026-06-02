# Skill: CTI-OpenCTI-lookup ((FAN))

## Overview

After FAN Extract IP+FQDN has run, look up every extracted IP and FQDN in OpenCTI. Report which indicators are known threats, with their confidence score, TLP classification, and associated context (malware family, threat actor, campaign). Write a structured results file to the case folder.

---

## Invocation

```
/fan-opencti-lookup --case-id <CASE_ID>
/fan-opencti-lookup --ips ./analysis/pcap/<stem>/unique_ips.txt --fqdns ./analysis/pcap/<stem>/unique_fqdns.txt --case-id <CASE_ID>
```

| Argument | Required | Description |
|----------|----------|-------------|
| `--case-id` | Yes | FAN case ID — results uploaded to `~/cases/<case_id>/opencti_lookup.md` on the investigations vault |
| `--ips` | No | Path to `unique_ips.txt`; auto-discovered from case folder if omitted |
| `--fqdns` | No | Path to `unique_fqdns.txt`; auto-discovered from case folder if omitted |

---

## Input Discovery

If `--ips` and `--fqdns` are not provided, locate the files automatically:

```python
from pathlib import Path

case_dir = Path("./analysis")  # WIP dir during active investigation
pcap_analysis = list(case_dir.glob("analysis/pcap/*/unique_ips.txt"))
if not pcap_analysis:
    # Fallback: check project-level analysis dir
    pcap_analysis = list(Path("./analysis/pcap").glob("*/unique_ips.txt"))

if not pcap_analysis:
    raise FileNotFoundError(
        f"No unique_ips.txt found for case {case_id}. "
        "Run /fan-extract-ip-fqdn first."
    )

ips_file   = pcap_analysis[0]
fqdns_file = ips_file.parent / "unique_fqdns.txt"
```

---

## Procedure

### Step 1 — Load IPs and FQDNs

```python
ips   = [l.strip() for l in ips_file.read_text().splitlines() if l.strip()]
fqdns = [l.split("\t")[0].strip() for l in fqdns_file.read_text().splitlines() if l.strip()]
```

Filter out RFC-1918 and loopback IPs — these are never in OpenCTI:

```python
import ipaddress

def is_private(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

public_ips   = [ip for ip in ips   if not is_private(ip)]
public_fqdns = [f  for f  in fqdns if f]  # FQDNs are already external
```

### Step 2 — Query OpenCTI for each IP

Use `opencti_search_ioc` for each public IP. Batch if the list is large (>50 IPs — process in groups of 20 with a brief pause to avoid rate-limiting).

```python
ip_results = {}
for ip in public_ips:
    hits = opencti_search_ioc(value=ip, limit=5)
    if hits:
        ip_results[ip] = hits
```

### Step 3 — Query OpenCTI for each FQDN

```python
fqdn_results = {}
for fqdn in public_fqdns:
    hits = opencti_search_ioc(value=fqdn, limit=5)
    if hits:
        fqdn_results[fqdn] = hits
```

### Step 4 — Classify results

For each hit, extract:

| Field | Source |
|-------|--------|
| Indicator value | `hit["value"]` |
| Confidence | `hit["confidence"]` (0–100) |
| TLP | `hit["tlp"]` |
| Malware families | `hit.get("malware", [])` |
| Threat actors | `hit.get("threat_actor", [])` |
| Campaigns | `hit.get("campaign", [])` |
| Valid from | `hit.get("valid_from")` |
| Score | `hit.get("x_opencti_score", 0)` |

Classify each hit:
- **CONFIRMED_MALICIOUS**: score ≥ 75 or explicitly tagged malicious
- **SUSPICIOUS**: score 40–74 or associated with a threat actor/campaign
- **INFORMATIONAL**: score < 40, no malicious associations

### Step 5 — Write results file

Write results via `investigations_write_file` MCP tool to `<case_id>/opencti_lookup.md`:

```markdown
---
case_id: <case_id>
lookup_utc: <ISO timestamp>
ips_checked: N
fqdns_checked: N
confirmed_malicious: N
suspicious: N
---

# OpenCTI Lookup — <case_id>

## Summary

| Category | Count |
|----------|-------|
| IPs checked | N |
| FQDNs checked | N |
| Confirmed malicious | N |
| Suspicious | N |
| Informational hits | N |
| Not found in OpenCTI | N |

## Confirmed Malicious

### IPs

| IP | Confidence | TLP | Malware | Actor | Score |
|----|-----------|-----|---------|-------|-------|
| 203.0.113.42 | 90 | TLP:WHITE | Cobalt Strike | APT29 | 85 |

### FQDNs

| FQDN | Confidence | TLP | Malware | Actor | Score |
|------|-----------|-----|---------|-------|-------|
| evil.example.com | 85 | TLP:WHITE | IcedID | TA505 | 80 |

## Suspicious

### IPs

(same table format)

### FQDNs

(same table format)

## Informational

Brief list — not a full table.

## Not Found in OpenCTI

IPs and FQDNs that returned no results — candidates for enrichment via Perplexity or CTI agent.

| Indicator | Type | Recommended Action |
|-----------|------|-------------------|
| 198.51.100.7 | IP | Run /fan-ip-lookup or /cti-osint |
| unknown.example.net | FQDN | Run /cti-osint if suspicious behaviour observed |
```

### Step 6 — Update vault for confirmed malicious indicators

For each CONFIRMED_MALICIOUS indicator not already in the vault:

```python
from knowledge_extractor import record_ioc

record_ioc(
    ioc_type="ip",        # or "domain"
    value=ip,             # defanged before writing to vault
    context=f"OpenCTI confirmed malicious. Score: {score}. Malware: {malware}.",
    case_id=case_id,
    severity="high" if score >= 75 else "medium",
)
```

Defang before writing to vault:
```python
def defang(value: str) -> str:
    return (value
        .replace(".", "[.]")
        .replace("http://", "hxxp://")
        .replace("https://", "hxxps://"))
```

### Step 7 — Output summary

```
[fan-opencti-lookup] CASE-2025-001 — Checked 47 IPs, 23 FQDNs.
  Confirmed malicious: 3 (2 IPs, 1 FQDN)
  Suspicious: 5 (3 IPs, 2 FQDNs)
  Not in OpenCTI: 38 IPs, 20 FQDNs
  Results: uploaded to investigations vault — ~/cases/CASE-2025-001/opencti_lookup.md
```

---

## Integration in FAN Pipeline

`/fan-opencti-lookup` runs after `/fan-extract-ip-fqdn` and before `/fan-ip-lookup`:

```
/fan-extract-ip-fqdn      — extract IPs and FQDNs from PCAP
/fan-opencti-lookup       — check all against OpenCTI (structured threat intel)
/fan-ip-lookup            — OSINT enrichment via Perplexity for unknowns
```

For indicators not found in OpenCTI, pass them to `/fan-ip-lookup` for Perplexity-based enrichment.

---

## Privacy Rules

- Never query OpenCTI with RFC-1918 addresses, loopback addresses, or link-local addresses
- Never query with internal hostnames (`.local`, `.internal`, `.corp` TLDs)
- Results are written only to the case folder — not to shared reports unless `/fan-report` is run
- TLP:RED or TLP:AMBER results from OpenCTI are flagged clearly in output; do not include in shared outputs
