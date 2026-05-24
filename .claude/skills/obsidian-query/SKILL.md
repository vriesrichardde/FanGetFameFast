# Skill: Obsidian Vault Query (Pre-Investigation Context)

## Overview

Use this skill at the **start of every investigation** to surface institutional memory before
running any forensic tools. The vault (`./vault/`) is a persistent Obsidian knowledge graph
that accumulates TTPs, IOCs, threat actors, malware, risks, and cases across investigations.
Querying it first prevents duplicating work, surfaces prior context, and links new findings
to the existing threat picture.

> **Rule:** Always query the vault before examining a new IOC, TTP, or host.
> If the vault is empty or returns no hits, proceed — the absence is itself informative.

---

## Shell Interface

All queries are run from the project root via `scripts/vault_context.sh` or
`python3 lib/vault_query.py` directly.

### Keyword / Full-Vault Search

```bash
# Broad search — use at case start to find any prior vault knowledge
./scripts/vault_context.sh search <keyword>
./scripts/vault_context.sh search "powershell encoded"
./scripts/vault_context.sh search "lateral movement"
./scripts/vault_context.sh search "LSASS"

# Equivalent direct call
python3 lib/vault_query.py --search <keyword>
```

Output: list of matching notes with their folder, severity, and matching snippets.

### IOC Lookup

```bash
# Before triaging any IP, domain, hash, or filename — check the vault first
./scripts/vault_context.sh ioc <value>
./scripts/vault_context.sh ioc "192.168.1.42"
./scripts/vault_context.sh ioc "evil.example.com"
./scripts/vault_context.sh ioc "d41d8cd98f00b204e9800998ecf8427e"

# Equivalent
python3 lib/vault_query.py --ioc <value>
```

Output: matching IOC notes with type, severity, related TTPs, disposition, and case refs.
Vault values are defanged — search with the raw value and the bridge handles the match.

### TTP Lookup

```bash
# Before attributing any observed behavior, check what prior cases recorded for this TTP
./scripts/vault_context.sh ttp T1059
./scripts/vault_context.sh ttp T1071.001
./scripts/vault_context.sh ttp T1003

# Equivalent
python3 lib/vault_query.py --ttp <MITRE_ID>
```

Output: TTP note details including tactic, severity, linked cases, related actors, related malware,
and any cross-references in other vault notes.

### Case Status

```bash
# List all open cases — run at session start
./scripts/vault_context.sh cases
python3 lib/vault_query.py --cases
```

Output: case ID, severity, observed TTPs, suspected actors for each open case.

### Risk Prioritisation

```bash
# Top 10 open risks sorted by severity
./scripts/vault_context.sh risks
./scripts/vault_context.sh risks 20     # top 20

python3 lib/vault_query.py --risks
python3 lib/vault_query.py --risks 20
```

Output: ranked list of open risks with asset, case reference, and severity.

### Backlink Graph

```bash
# Find all notes that wikilink to a given title (simulates Obsidian backlinks)
./scripts/vault_context.sh backlinks "T1059 Command and Scripting Interpreter"
./scripts/vault_context.sh backlinks "APT29"

python3 lib/vault_query.py --backlinks "<Note Title>"
```

Output: list of all vault notes that contain `[[Note Title]]`.

---

## Python Interface (for scripted workflows)

```python
import sys; sys.path.insert(0, "./lib")
from vault_query import (
    search_context,
    get_context_for_ioc,
    get_context_for_ttp,
    get_active_cases,
    get_top_risks,
    get_related_notes,
)

# Use returned strings directly as context in prompts or printed reports
print(get_context_for_ioc("203.0.113.42"))
print(get_context_for_ttp("T1071"))
print(get_active_cases())
print(get_top_risks(10))
print(get_related_notes("Cobalt Strike"))
```

All functions return structured plain-text suitable for direct inclusion in investigation notes
or Claude context windows.

---

## Standard Pre-Investigation Checklist

Run these in order at the start of every case:

```bash
# 1. Check for any open cases — orient yourself
./scripts/vault_context.sh cases

# 2. Search by suspect hostname / username / tool name
./scripts/vault_context.sh search "<hostname or actor keyword>"

# 3. Look up any known IOCs from the initial triage report
./scripts/vault_context.sh ioc "<ip-or-hash>"

# 4. Check TTPs suspected from initial triage
./scripts/vault_context.sh ttp <MITRE_ID>

# 5. Review top open risks for context
./scripts/vault_context.sh risks
```

---

## Reading the Output

| Field | Meaning |
|-------|---------|
| `severity` | critical / high / medium / low — propagated from the original recording |
| `case_refs` | List of case IDs that contributed to this note |
| `related_ttps` | Wikilinked TTP notes — follow with `--ttp` |
| `related_actors` | Wikilinked threat actor notes |
| `disposition` | IOC-specific: unknown / malicious / benign / investigating |
| `status` | Case-specific: open / closed |

---

## Vault Layout Reference

| Folder | Contents |
|--------|----------|
| `vault/TTPs/` | One note per MITRE ATT&CK (sub)technique — titled `<ID> <Name>` |
| `vault/IOCs/` | One note per indicator — titled `<type>-<defanged-value>` |
| `vault/ThreatActors/` | Threat group profiles |
| `vault/Malware/` | Malware family profiles |
| `vault/Concepts/` | Cybersecurity concept explanations |
| `vault/Risks/` | Risk assessments — titled `<case_id>-<asset>` |
| `vault/Cases/` | Post-investigation summaries |
| `vault/Dashboard.md` | Auto-maintained index of all recent activity |

---

## Notes

- Vault values are defanged (`192[.]168[.]1[.]1`, `evil[.]com`, `hxxps://`) — pass raw values
  to query functions; the search normalises the comparison automatically
- An empty vault result is valid — note it and proceed; record your findings afterward via
  the `obsidian-record` skill so future investigations benefit
- The vault is plain Markdown — you can `grep` or `Read` any note directly if needed
- Open `./vault/` in the Obsidian desktop app for graph view and visual navigation
