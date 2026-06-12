# Skill: correlate — Cross-module correlation

## Overview

**correlate** is the cross-module correlation step of FanGetFameFast. It reads raw
artifact files produced by FAN, FAME, and FAST and surfaces kill-chain connections
that no single module identifies alone:

| Correlation | What it finds |
|-------------|---------------|
| FAN ↔ FAME | Specific processes (netscan) matched to flagged PCAP connections — links a running program to suspicious traffic |
| FAME ↔ FAST | Process images running in memory found deleted on disk — indicates post-execution cleanup (T1070.004) |
| FAN ↔ FAST | Domains queried in DNS (PCAP) confirmed by carved disk artifacts — proves active use of the endpoint |

**When to run:** After all available modules have completed their analysis steps but
**before** the `./analysis/` directory is cleaned up. The raw Volatility and TSK
artifact files are required for precise correlation. If the analysis directory has
already been cleared, the step still runs but marks each correlation as degraded and
notes which module reports were found.

**Output:**

| File | Path | Purpose |
|------|------|---------|
| Correlation report | `./reports/<case_id>_correlation.md` | Narrative analysis with match tables |
| Correlation data | `./reports/<case_id>_correlation.json` | Machine-readable records for downstream tools |

---

## Invocation

### CLI (recommended — run from project root)

```bash
python3 lib/correlate_findings.py \
    --case-id <case_id> \
    --hostname <hostname>
```

### With explicit paths (non-default directories)

```bash
python3 lib/correlate_findings.py \
    --case-id CASE-2026-001 \
    --hostname SERVER1234 \
    --reports-dir ./reports \
    --analysis-dir ./analysis \
    --exports-dir ./exports \
    --output-dir ./reports
```

### Python API

```python
import sys; sys.path.insert(0, "./lib")
from correlate_findings import correlate

result = correlate(case_id="CASE-2026-001", hostname="SERVER1234")
# result: {"md": Path, "json": Path}
```

---

## Research notes step

After running the correlation and reading the output, log it immediately:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Cross-module Correlation (FAN / FAME / FAST)" \
  --action "python3 lib/correlate_findings.py --case-id <case_id> → ./reports/<case_id>_correlation.md" \
  --why "Correlates netscan connections to PCAP threats (FAN↔FAME), process images to deleted disk entries (FAME↔FAST), and DNS domains to carved URLs (FAN↔FAST) — surfaces kill-chain connections that no single module identifies alone" \
  --outcome "<N FAN↔FAME matches, M FAME↔FAST matches, K FAN↔FAST matches — key finding, e.g.: svchost.exe (PID 1234) confirmed initiating C2 beacon on TCP 4444>"
```

Use `--raw` only when specific high-severity matches were found:

```bash
  --raw "FAN↔FAME: svchost.exe (PID 1234) → 203.0.113.1:4444 [HIGH - tcp_c2_beacon]"
```

---

## Artifact file requirements

The correlation engine reads the following raw artifact files. Run the correlation
step before `./analysis/` is cleaned up (i.e., before the investigation upload).

| Artifact | Used for | Produced by |
|----------|----------|-------------|
| `./analysis/memory/netscan.txt` | FAN↔FAME: process-to-connection mapping | Volatility 3 `windows.netscan` |
| `./analysis/memory/netstat.txt` | FAN↔FAME: fallback when netscan absent | Volatility 3 `windows.netstat` |
| `./analysis/memory/pslist.txt` | FAN↔FAME + FAME↔FAST: process names | Volatility 3 `windows.pslist` |
| `./analysis/memory/cmdline.txt` | Enriches process matches with arguments | Volatility 3 `windows.cmdline` |
| `./analysis/storage/fls_output.txt` | FAME↔FAST: deleted file entries | TSK `fls -r -p` |
| `./exports/carved/url.txt` | FAN↔FAST: carved URLs from disk | `bulk_extractor` |
| `./exports/carved/domain.txt` | FAN↔FAST: carved domains from disk | `bulk_extractor` |
| `./analysis/fan_dns*/**/dns_threats.json` | FAN↔FAME + FAN↔FAST: DNS threats | FAN dns module |
| `./analysis/fan_tcp*/**/tcp_threats.json` | FAN↔FAME: TCP connection threats | FAN tcp module |
| `./analysis/fan_http*/**/http_threats.json` | FAN↔FAME: HTTP connection threats | FAN http module |
| `./analysis/fan_udp*/**/udp_threats.json` | FAN↔FAME: UDP connection threats | FAN udp module |

If a file is absent, that correlation type degrades gracefully and is marked in the
output as "partially degraded."

---

## Where correlate fits in the investigation workflow

### After FAME analysis

Run correlate as the penultimate step — after all Volatility plugins, Memory Baseliner,
and YARA scanning, but before generating the formal report:

```
pslist → psscan → cmdline → netstat/netscan → malfind → svcscan → modules →
filescan → hivelist → Memory Baseliner → YARA → [correlate] → generate_fame_report.py
```

### After FAST analysis

Run correlate after bulk_extractor has completed, before generating the formal report:

```
ewfinfo → mmls → fls → mactime → artifact extraction → bulk_extractor →
[correlate] → generate_fast_report.py
```

### Feeding correlate's output into the campaign report

`correlate_findings.py`'s output (`<case_id>_correlation.md`/`.json`) is a
**best-effort research aid**, not the campaign report itself. The per-case
campaign report (`<case_id>_campaign_report.*`) must be hand-authored
following `docs/campaign_report_template.md`: read this file as one input
when drafting Section 3 (Cross-Domain Correlation), but ground that section in
the modules' research notes regardless. **Zero matches reported here does not
mean no correlation exists** — `correlate_findings.py` only checks a fixed set
of artifact paths and comparison types; real pivots visible in the research
notes (e.g., matching timestamps, file paths referenced across modules) must
still be written up even if this tool found nothing.

Once the campaign report MD is hand-authored, render it:

```python
import sys; sys.path.insert(0, "./lib")
from render_campaign_report import render

paths = render(md_path="./reports/<case_id>/<case_id>_campaign_report.md",
                case_id="<case_id>", hostname="<hostname>")
```

`lib/generate_combined_report.py`'s `generate()` is deprecated for this
workflow — it remains only as an automated fallback for `--md-only`/headless
batch runs or very-low-evidence cases.

---

## Interpreting the output

### Section 2 — FAN ↔ FAME (Process-network)

Each table row is a **confirmed link** between a running process and a flagged network
connection. Key questions:

- Is the process name expected to make external connections?
  (`svchost.exe` → non-Microsoft IP is suspicious; `chrome.exe` is not)
- Does the command line contain encoded or obfuscated arguments?
- Is the parent process appropriate?
  (Word spawning powershell confirms macro execution or code injection)

### Section 3 — FAME ↔ FAST (Process-disk)

Each row identifies a process whose executable was deleted from disk while still
running in memory, or a deleted executable in a high-risk path. Key questions:

- Was the deletion timed to coincide with other attacker activity?
  (Cross-reference USN Journal timestamps)
- Is the executable a known-good binary name in an unexpected path?
  (`svchost.exe` in `C:\Temp\` is a masquerading indicator — T1036)
- Does Amcache have the binary's SHA1 hash for a reputation lookup?

### Section 4 — FAN ↔ FAST (Domain-URL)

Each row shows a domain confirmed in both network traffic and disk artifacts. Key
questions:

- Is the carved artifact a downloaded payload, a configuration file, or a browser
  cache entry?
- Does the domain match known threat intelligence (OpenCTI / Perplexity lookup)?
- Was the contact automated (C2 beacon) or user-triggered (phishing click)?

### Section 5 — Confidence assessment

| Confidence | Meaning |
|------------|---------|
| High | 3+ independent matches — strong signal, prioritise immediately |
| Medium | 2 matches — corroborating evidence, verify before escalating |
| Low-Medium | 1 match — single linkage, manual verification required |
| None found | No overlap detected — does not mean the machine is clean |
| N/A — module missing | Both modules required for this correlation type |

---

## Claude: enhance and elaborate when necessary

Each correlation finding carries the instruction **"Claude: enhance and elaborate
when necessary."** When reviewing the correlation output, Claude must:

1. **Contextualise** — explain why each match is forensically significant beyond
   just noting the IP and port number.
2. **MITRE-map** — assign the most specific applicable ATT&CK (sub)technique.
3. **Pivot** — suggest the next concrete investigation action for each finding.
4. **Dual register** — restate the executive findings in CISO language (no IPs,
   PIDs, or file paths) in the combined report management summary.
