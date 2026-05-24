# Skill: Perplexity.ai Cybersecurity Research

## Overview

Use this skill when the Obsidian vault returns no answer and you encounter something
you cannot confidently explain from existing knowledge. Perplexity.ai provides real-time
web search with citations — it bridges the gap between the vault (accumulated case
knowledge) and live threat intelligence.

> **Decision rule:**
> 1. Query the vault first (`obsidian-query` skill).
> 2. If the vault has no prior knowledge AND the unknown element is required to
>    progress the investigation → invoke Perplexity.
> 3. After receiving confirmed results → save to vault (`obsidian-record` skill).

---

## Trigger Conditions

Invoke Perplexity automatically when you encounter **any** of the following during
an investigation or analysis task:

| Trigger | Example |
|---------|---------|
| Unknown malware family or tool name | `svchost32.exe` found in memory — is it legitimate? |
| Unrecognised process, DLL, or file | Registry value points to `C:\Users\...\AppData\update.exe` |
| Unknown threat actor name or alias | Attribution references `UNC3890` |
| CVE referenced without details | Exploit attempts against `CVE-2024-XXXX` in logs |
| Unrecognised MITRE technique behaviour | New sub-technique variant not in vault |
| Suspicious domain or IP with no vault hit | `203.0.113.42` — no prior case context |
| Unknown C2 protocol pattern | Unusual beacon structure observed in PCAP |
| Ambiguous tool (dual-use?) | `certutil.exe -urlcache` — need attacker usage context |
| Technique seen but not understood | e.g. "what does PrintNightmare look like in memory?" |
| General gap: "I'm not sure what this is" | Any artifact that requires external research |

---

## Prerequisites — API Key Setup

The Perplexity API requires a key. **Check if it is set before running any query:**

```bash
echo "${PERPLEXITY_API_KEY:-NOT SET}"
```

If not set, add to `~/.bashrc` and reload:

```bash
echo 'export PERPLEXITY_API_KEY="pplx-YOUR_KEY_HERE"' >> ~/.bashrc
source ~/.bashrc
```

Get a key at: https://www.perplexity.ai/settings/api  
Models available: `sonar` (fast) | `sonar-pro` (default, best quality) |
`sonar-reasoning` | `sonar-reasoning-pro` (deep analysis)

---

## Command Reference

All commands are run from the project root. Use `scripts/perplexity_search.sh` for
shell invocations or `python3 lib/perplexity_client.py` directly.

### IOC Reputation Lookup

```bash
# IP address
./scripts/perplexity_search.sh ioc 203.0.113.42

# Domain
./scripts/perplexity_search.sh ioc evil.example.com

# File hash (MD5/SHA1/SHA256)
./scripts/perplexity_search.sh ioc d41d8cd98f00b204e9800998ecf8427e

# URL
./scripts/perplexity_search.sh ioc "hxxps://malicious.example.com/payload"
```

Returns: known malicious activity, associated malware/actors, blocklist presence,
first/last seen dates.

### Malware Family Profile

```bash
./scripts/perplexity_search.sh malware "Cobalt Strike"
./scripts/perplexity_search.sh malware "SUNBURST"
./scripts/perplexity_search.sh malware "Emotet"
./scripts/perplexity_search.sh malware "LockBit 3.0"
```

Returns: malware type, capabilities, delivery, persistence, C2 protocols, MITRE ATT&CK
IDs, known IOCs, associated threat actors, first observed.

### MITRE ATT&CK Technique Details

```bash
./scripts/perplexity_search.sh ttp T1059.001
./scripts/perplexity_search.sh ttp T1071.001
./scripts/perplexity_search.sh ttp T1003
./scripts/perplexity_search.sh ttp T1548.002
```

Returns: technique implementation details, real-world threat actor usage, detection
opportunities, log sources, mitigations.

### CVE Details

```bash
./scripts/perplexity_search.sh cve CVE-2024-1234
./scripts/perplexity_search.sh cve CVE-2021-44228     # Log4Shell
./scripts/perplexity_search.sh cve CVE-2021-34527     # PrintNightmare
```

Returns: affected products, CVSS score, exploit availability, in-the-wild exploitation,
patches and workarounds.

### Threat Actor Profile

```bash
./scripts/perplexity_search.sh actor APT29
./scripts/perplexity_search.sh actor "Lazarus Group"
./scripts/perplexity_search.sh actor UNC3890
./scripts/perplexity_search.sh actor "Midnight Blizzard"
```

Returns: aliases, origin/attribution, motivation, targets, MITRE ATT&CK techniques,
malware families, known infrastructure patterns, recent campaigns.

### Unknown Tool / Utility

```bash
./scripts/perplexity_search.sh tool mimikatz
./scripts/perplexity_search.sh tool "Sysinternals PsExec"
./scripts/perplexity_search.sh tool "certutil -urlcache"
./scripts/perplexity_search.sh tool "svchost32.exe"
./scripts/perplexity_search.sh tool "update.exe in AppData"
```

Returns: whether the tool is legitimate / dual-use / malicious, attacker usage
patterns, MITRE ATT&CK IDs, detection signatures.

### General Free-Form Research

```bash
./scripts/perplexity_search.sh search "PrintNightmare memory artefacts volatility"
./scripts/perplexity_search.sh search "HTTPS beacon jitter detection PCAP"
./scripts/perplexity_search.sh search "LSASS dump detection evasion techniques 2024"
./scripts/perplexity_search.sh search "NTLM relay attack detection event logs"
```

---

## Python Interface (for inline use in scripts)

```python
import sys; sys.path.insert(0, "./lib")
from perplexity_client import (
    lookup_ioc, lookup_malware, lookup_ttp,
    lookup_cve, lookup_actor, lookup_tool, search,
    format_result, save_to_vault,
)

# Example: unknown process name found during memory analysis
result = lookup_tool("svchost32.exe")
print(format_result(result))

# Example: research a CVE referenced in exploit traffic
result = lookup_cve("CVE-2021-34527")
print(format_result(result))

# Example: general gap fill
result = search("how does Cobalt Strike beacon avoid EDR memory scanning?")
print(format_result(result))
```

---

## Save Results to Vault

After confirming Perplexity results are reliable, persist them as vault knowledge:

```bash
# Auto-save to Concepts/ in the vault
./scripts/perplexity_search.sh malware "Cobalt Strike" --save-vault
./scripts/perplexity_search.sh actor APT29 --save-vault
./scripts/perplexity_search.sh ttp T1071.001 --save-vault
```

Or use the Python `save_to_vault()` function, then call the `obsidian-record` skill
to add richer cross-links (related TTPs, case refs, etc.).

**Always verify** Perplexity output against at least one cited source before recording
findings as vault facts, especially for IOC attribution.

---

## Model Selection Guide

| Model | Use when |
|-------|----------|
| `sonar` | Fast lookup needed; single fact (e.g. CVE CVSS score) |
| `sonar-pro` | Default — comprehensive threat profiles, most queries |
| `sonar-reasoning` | Complex technical questions (exploit mechanics, detection logic) |
| `sonar-reasoning-pro` | Deep analysis with chain-of-thought (slow; use for critical unknowns) |

```bash
# Override model
./scripts/perplexity_search.sh actor APT29 --model sonar-reasoning-pro
```

---

## Standard Research Workflow

```bash
# 1. Confirm vault has no answer
./scripts/vault_context.sh search "<unknown term>"

# 2. If no vault hit — query Perplexity
./scripts/perplexity_search.sh <type> "<value>"

# 3. Review output and citations

# 4. Save to vault (use obsidian-record skill for structured entry)
./scripts/perplexity_search.sh <type> "<value>" --save-vault
# OR record manually with the appropriate record_* function
```

---

## Vault Recording

**Mandatory:** Every Perplexity lookup that returns usable intelligence must be written to the
vault. This is the primary mechanism for converting live web intelligence into permanent
institutional memory. A lookup with no vault write is wasted — the same query will be run
again in the future.

Use `--save-vault` for quick automated recording, or call the appropriate `record_*` function
for structured entries with full metadata:

| Lookup Type | Vault Function | Note Created |
|------------|---------------|-------------|
| `ioc <ip\|domain\|hash>` | `record_ioc()` | `IOCs/<type>-<defanged>.md` |
| `malware <name>` | `record_malware()` | `Malware/<name>.md` |
| `ttp <T-ID>` | `record_ttp()` | `TTPs/<T-ID>.md` |
| `actor <name>` | `record_threat_actor()` | `ThreatActors/<name>.md` |
| `cve <CVE-ID>` | `record_concept()` | `Concepts/CVE-<ID>.md` |
| `tool <name>` | `record_concept()` | `Concepts/Tool-<name>.md` |
| `search <any>` | `record_concept()` | `Concepts/<topic>.md` |

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc, record_malware, record_ttp, record_threat_actor, record_concept

# After reviewing and validating Perplexity output:

# IOC lookup:
record_ioc("ip", "203.0.113.42", "Perplexity: C2 server associated with LockBit 3.0 group. "
           "Multiple vendor reports. Confidence: High.", case_id, severity="critical",
           related_ttps=["T1071.001 Web Protocols"])

# Malware lookup:
record_malware("LockBit 3.0",
               "Perplexity: RAAS platform. AES-256 file encryption. Uses PrintNightmare for initial access.",
               case_id)

# CVE lookup:
record_concept("CVE-2024-3400",
               "Perplexity: PAN-OS RCE via GlobalProtect. CVSS 10.0. PoC public. Patch: PAN-OS 11.1.2-h3.",
               related_ttps=["T1190"])

# Unknown concept:
record_concept("Living Off Trusted Sites (LOTS)",
               "Perplexity: Attackers abuse legitimate cloud services (GitHub, Discord, Dropbox) "
               "for C2 and payload hosting to evade domain-based filtering.",
               related_ttps=["T1102", "T1105"])
```

**Threshold:** Record if the Perplexity response cites at least one named source and contains
specific, verifiable claims. Do not record vague responses — note them as `Confidence: Low` if
borderline.

Verify:
```bash
./scripts/vault_context.sh search "<looked_up_term>"
```

---

## Reliability Notes

- Always check the cited sources — Perplexity may hallucinate details on obscure topics
- For IOC attribution: treat Perplexity as a starting point; verify via VirusTotal,
  Shodan, or vendor threat feeds before treating as confirmed malicious
- CVE CVSS scores and patch availability change over time — verify against NVD directly
  for critical findings
- Threat actor attribution in Perplexity output reflects public reporting which may
  be contested or vendor-specific
- Results are internet-sourced and may include information the user should keep
  confidential — do not include live case details (hostnames, usernames, IP addresses
  from active investigations) in Perplexity queries
