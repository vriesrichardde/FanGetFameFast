# Skill: Obsidian Vault Recording (Post-Investigation Knowledge Capture)

## Overview

Use this skill to write confirmed forensic findings into the Obsidian vault
(`./vault/`) after an investigation or at any point a fact is established.
Most `record_*` calls are **idempotent**: `record_ioc`, `record_ttp`, and
`record_threat_actor` append a new timestamped observation block on each call
rather than replacing existing content. `record_risk`, `record_malware`, and
`record_concept` replace the note body on each call.

> **Rule:** Only record confirmed, tool-verified findings. Never write speculation,
> raw evidence paths, or content from `/cases/`, `/mnt/`, or `/media/` into the vault.
> All IOC values must be defanged before storage (the library handles this automatically).

---

## Automatic vault write from a report (primary use)

**Normal use: fully automatic.** `fame_analyze.sh`, `fast_analyze.sh`, and
`analyze_pcap.sh` all call `lib/vault_writer.py` at the end of their pipelines.
Vault entries are parsed directly from the finalised report Markdown — the
analyst's reviewed output — so only confirmed findings are recorded.

Run this manually when:
- You edited the report Markdown after the pipeline finished and want the vault
  to reflect the updated findings.
- A pipeline ran with `--no-vault` and you want to record findings now.
- You want to add a finding that isn't captured in the report tables (threat
  actor attribution, a new concept, a manual risk note).

```bash
# Re-run vault write after editing a FAME report
python3 lib/vault_writer.py --module fame --case-id FAME-2026-001

# Explicit paths (when the case ID doesn't match the default filename pattern)
python3 lib/vault_writer.py --module fame \
    --report ./reports/FAME-2026-001_fame_report.md \
    --notes  ./reports/FAME-2026-001_research_notes.md

# FAST and FAN work identically
python3 lib/vault_writer.py --module fast --case-id FAST-2026-001
python3 lib/vault_writer.py --module fan  --case-id FAN-2026-001
```

**What `vault_writer.py` records automatically:**

| Source in report | Vault record |
|---|---|
| Header table (`Case ID`, `Hostname`) | `open_case()` → `vault/Cases/<case_id>.md` |
| §Management Summary body text | Case summary text |
| MITRE ATT&CK coverage table — confirmed rows | `record_ttp()` → `vault/TTPs/<ID> <Name>.md` |
| Indicators of Compromise table — non-Informational rows | `record_ioc()` → `vault/IOCs/<type>-<value>.md` |
| Recommendations / numbered list | `record_risk()` → `vault/Risks/<case_id>-<hostname>.md` |
| Research notes Investigation Summary | `close_case()` closing text |

**What is skipped automatically:**
- MITRE rows marked "Not confirmed" in the observation
- IOC rows with Severity = Informational
- IOC rows of type Event or Condition (analytical observations, not indicators)

---

## Python API

All recording is done through `lib/knowledge_extractor.py`.

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import (
    open_case, close_case,
    record_ioc, record_ttp, record_threat_actor,
    record_malware, record_risk, record_concept,
)
```

---

## Case Lifecycle

### Open a Case

Call this at the start of every investigation. Creates `vault/Cases/<case_id>.md`.

```python
open_case(
    case_id="CASE-2025-042",          # unique identifier — use a consistent scheme
    summary="Suspected C2 beacon originating from workstation WS-FINANCE-03.",
    severity="high",                   # critical | high | medium | low
)
```

### Close a Case

Call when the investigation is concluded. Updates status to `closed` and appends findings.

```python
close_case(
    case_id="CASE-2025-042",
    findings="Confirmed Cobalt Strike beacon. Host isolated. IOC shared with IR team.",
)
```

---

## Recording Findings

### IOC

Call for every confirmed indicator: IP, domain, URL, file hash, email, filename, registry key.
The library automatically defangs IPs, domains, and URLs.

```python
record_ioc(
    ioc_type="ip",                        # ip | domain | url | hash | email | filename | registry_key
    value="203.0.113.42",                 # raw value — defanged automatically if ioc_type is ip/domain/url
    context="C2 destination observed in PCAP; HTTPS POST every 60s.",
    case_id="CASE-2025-042",
    severity="high",                      # optional; default "medium"
    related_ttps=["T1071.001 Web Protocols"],   # optional list of TTP note titles
    related_actors=["Cobalt Strike Operator"],   # optional list of actor note titles
)

# Hash example (not defanged)
record_ioc(
    ioc_type="hash",
    value="d41d8cd98f00b204e9800998ecf8427e",
    context="MD5 of dropped payload found at C:\\Users\\victim\\AppData\\Roaming\\svchost32.exe",
    case_id="CASE-2025-042",
    severity="critical",
    related_ttps=["T1036 Masquerading"],
)
```

**ioc_type values:**
| Value | Use for |
|-------|---------|
| `ip` | IPv4 / IPv6 addresses |
| `domain` | Domain and FQDN |
| `url` | Full URLs |
| `hash` | MD5, SHA1, SHA256 — prefix with algorithm if known |
| `email` | Email addresses |
| `filename` | Suspicious filenames or file paths (defanged as plain text) |
| `registry_key` | Windows registry key paths |
| `mutex` | Named mutex values |
| `useragent` | Suspicious HTTP User-Agent strings |

---

### TTP

Call for each observed MITRE ATT&CK technique. Creates `vault/TTPs/<MITRE_ID> <Name>.md`.

```python
record_ttp(
    mitre_id="T1071.001",
    technique_name="Web Protocols",
    evidence_summary="HTTPS POST to 203[.]0[.]113[.]42:443 at 60s intervals; consistent beacon jitter of ±5s observed in PCAP.",
    case_id="CASE-2025-042",
    tactic="command-and-control",         # MITRE tactic name
    severity="high",
    related_actors=["APT29"],             # optional
    related_malware=["Cobalt Strike"],    # optional
    related_iocs=["ip-203[.]0[.]113[.]42"],  # optional — use the note title (defanged)
)
```

**Common tactic values:** `initial-access`, `execution`, `persistence`, `privilege-escalation`,
`defense-evasion`, `credential-access`, `discovery`, `lateral-movement`,
`collection`, `command-and-control`, `exfiltration`, `impact`

---

### Threat Actor

Call when an actor is attributed or suspected. Creates `vault/ThreatActors/<Name>.md`.

```python
record_threat_actor(
    name="APT29",
    aliases=["Cozy Bear", "Midnight Blizzard", "YTTRIUM"],
    motivation="espionage",
    observed_ttps=["T1071.001 Web Protocols", "T1003 OS Credential Dumping"],
    known_malware=["Cobalt Strike", "SUNBURST"],
    case_id="CASE-2025-042",
    notes="Attribution based on beacon timing profile and known infrastructure overlap with prior campaigns.",
)
```

---

### Malware

Call when a malware family is confirmed. Creates `vault/Malware/<Family>.md`.

```python
record_malware(
    family="Cobalt Strike",
    malware_type="C2 framework",          # RAT | dropper | loader | ransomware | wiper | C2 framework | ...
    description="Commercial adversary simulation framework widely misused by threat actors.",
    case_id="CASE-2025-042",
    related_actors=["APT29"],
    related_ttps=["T1071.001 Web Protocols", "T1055 Process Injection"],
    known_hashes=["d41d8cd98f00b204e9800998ecf8427e"],
)
```

---

### Risk

Call to record a risk finding tied to a case and asset. Creates `vault/Risks/<case_id>-<asset>.md`.

```python
record_risk(
    asset="WS-FINANCE-03",
    risk_description="Host has active C2 channel and unpatched RCE (CVE-2024-XXXX). Potential pivot point to finance network segment.",
    case_id="CASE-2025-042",
    severity="critical",
    likelihood="high",
    related_ttps=["T1071.001 Web Protocols", "T1210 Exploitation of Remote Services"],
    mitigations="Isolate host immediately. Patch CVE-2024-XXXX. Review lateral movement to adjacent hosts.",
)
```

**severity / likelihood values:** `critical` | `high` | `medium` | `low`

---

### Concept

Call to capture a cybersecurity concept or technique explanation for future reference.
Creates `vault/Concepts/<Name>.md`. Use for building up general knowledge, not tied to a case.

```python
record_concept(
    name="Beacon Jitter",
    definition="A randomisation factor applied to C2 callback intervals to evade network-based detections that look for perfectly regular connection patterns.",
    related_ttps=["T1071.001 Web Protocols"],
    related_concepts=["Living off the Land", "C2 over DNS"],
    examples="Cobalt Strike beacons default to 0% jitter (regular). Operators commonly set 20–50% jitter to evade detection.",
)
```

---

## Typical Post-Investigation Workflow

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import (
    open_case, close_case,
    record_ioc, record_ttp, record_threat_actor, record_risk,
)

# 1. Open the case (if not already open)
open_case("CASE-2025-042", "Suspected C2 beacon on WS-FINANCE-03.", severity="high")

# 2. Record the TTP first (other records link to it by note title)
record_ttp("T1071.001", "Web Protocols",
           "HTTPS POST every 60s ±5s jitter to external IP. Confirmed via PCAP and memory analysis.",
           "CASE-2025-042", tactic="command-and-control", severity="high")

# 3. Record IOCs (link back to the TTP note title)
record_ioc("ip", "203.0.113.42",
           "C2 destination. Resolves to ASN 64496 (test range — replace with real).",
           "CASE-2025-042", severity="high",
           related_ttps=["T1071.001 Web Protocols"])

record_ioc("hash", "d41d8cd98f00b204e9800998ecf8427e",
           "MD5 of Cobalt Strike beacon DLL found in memory via malfind.",
           "CASE-2025-042", severity="critical",
           related_ttps=["T1071.001 Web Protocols"])

# 4. Record risk
record_risk("WS-FINANCE-03",
            "Active C2 channel confirmed. Host likely fully compromised.",
            "CASE-2025-042", severity="critical", likelihood="high",
            related_ttps=["T1071.001 Web Protocols"])

# 5. Close the case
close_case("CASE-2025-042",
           "Cobalt Strike C2 confirmed. Host isolated. IOCs shared. "
           "Recommend full EDR sweep of finance segment.")
```

---

## Checking what was written

```bash
# Open cases
python3 lib/vault_query.py --cases

# Specific TTP across all cases
python3 lib/vault_query.py --ttp T1014

# IOC lookup
python3 lib/vault_query.py --ioc 104.201.158.26

# Top risks
python3 lib/vault_query.py --risks

# Full-text search
python3 lib/vault_query.py --search DKOM

# Dashboard (auto-maintained index)
cat vault/Dashboard.md
```

---

## Defanging Reference

The library defangs automatically for `ioc_type` values of `ip`, `domain`, `url`, and `email`.
For manual references in body text, follow these conventions:

| Original | Defanged form |
|----------|--------------|
| `192.168.1.1` | `192[.]168[.]1[.]1` |
| `evil.example.com` | `evil[.]example[.]com` |
| `https://evil.example.com/payload` | `hxxps://evil[.]example[.]com/payload` |
| `attacker@evil.com` | `attacker[@]evil[.]com` |

---

## Dashboard Auto-Update

Every `record_*` call and `open_case`/`close_case` automatically refreshes
`vault/Dashboard.md` with:
- **Active Cases** — open cases with severity and observed TTPs
- **Recent IOCs** — last 10 IOC notes with type and severity
- **Active Risks** — all open risks sorted by severity
- **TTPs Observed** — last 10 TTP notes
- **Threat Actors** — all actor notes

The Dashboard sections are bounded by `<!-- AUTO:SECTION -->` markers and are safe to
read at any time for a current snapshot of vault state.

---

## Notes

- `record_ioc`, `record_ttp`, and `record_threat_actor` are idempotent — re-running
  appends a new timestamped observation block. `record_risk`, `record_malware`, and
  `record_concept` replace the existing note body on each call.
- Severity is propagated at the **maximum** level: a second recording at `high`
  promotes a `medium` note; a `low` recording does not demote a `high` note.
- Note titles become Obsidian wikilink targets — keep them stable; avoid renaming after creation.
- The vault is plain Markdown and version-controllable alongside the scripts.
