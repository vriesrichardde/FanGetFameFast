# Skill: FAME — Forensic analysis memory

## Overview

**FAME** is the memory forensics module of Fan Get Fame Fast. It orchestrates
Volatility 3 and Memory Baseliner analysis against a memory image, generates a
full report suite (Markdown, PDF, Microsoft PowerPoint, Microsoft Word), and
uploads all artifacts to the investigations vault via the MCP server.

If network forensics (FAN) or storage forensics (FAST) reports already exist for
the same case ID, FAME automatically produces a combined unified report that
correlates findings across all three investigation domains.

**Claude instructs itself to** ***enhance and elaborate when necessary*** **on every
report section** to ensure the analyst receives full analytical depth beyond the
raw tool output.

| Output | Format | Path | Batch (`--md-only`) |
|--------|--------|------|---------------------|
| Technical report | Markdown | `./reports/<case_id>/FAME/<hostname>/<case_id>_fame_report.md` | Always |
| Investigative log | Markdown | `./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md` | Always |
| Technical report | PDF | `./reports/<case_id>/documents/<case_id>_fame_report.pdf` | Standalone only |
| Management briefing | Microsoft PowerPoint (.pptx) | `./reports/<case_id>/documents/<case_id>_fame_presentation.pptx` | Standalone only |
| Full report | Microsoft Word (.docx) | `./reports/<case_id>/documents/<case_id>_fame_report.docx` | Standalone only |
| Campaign report | Markdown/PDF/PPTX/DOCX | `./reports/<case_id>/<case_id>_campaign_report.*` (MD) + `documents/` (PDF/PPTX/DOCX) | Standalone only |

The unified cross-case report (`CAMPAIGN_<batch_id>_report.*`) is generated once at the
end of a batch by `/investigate-all` — not per individual FAME case.

---

## Research Notes

Every FAME investigation produces a **research notes file** (`./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md`)
alongside the formal report. The notes are a timestamped, step-by-step investigative log that lets
any analyst follow the complete workflow, rationale, and findings from start to finish.

> **MANDATORY RULE: Do NOT proceed to the next analysis step until the current step has been
> documented in the research notes via `python3 lib/research_notes.py step ...`. Running a plugin
> and immediately launching the next one without logging is not permitted. Read the output,
> interpret it, call `step`, then advance.**

> **MANDATORY DEVIATION LOGGING: Any time the analysis deviates from the standard workflow —
> a step is skipped, a fallback is used, a plugin returns unexpected results, or an analytical
> decision is made that differs from the normal path — this MUST be logged as its own `step`
> call with `--title "Deviation: <what changed>"`. Examples that require a deviation step:**
>
> - `windows.pslist` returned 0 processes → `step --title "Deviation: DKOM — switching to psscan-only workflow"`
> - ISF symbols unavailable → `step --title "Deviation: No ISF — falling back to strings extraction"`
> - `malfind` skipping dump because all hits are JIT false positives → `step --title "Deviation: malfind dump skipped — all hits confirmed JIT FPs"`
> - Memory Baseliner not installed → `step --title "Deviation: Memory Baseliner absent — step skipped"`
> - A plugin crashes or hangs → `step --title "Deviation: <plugin> failed — reason and workaround"`
>
> The deviation log ensures any analyst reading the notes understands WHY the investigation
> took a different path and can reproduce or challenge that decision.

**Three calls to make during every investigation:**

### 1 — At investigation start (before running any plugins)

```bash
python3 lib/research_notes.py init \
  --case-id <case_id> \
  --module fame \
  --evidence /path/to/image.mem \
  --hostname <hostname>
```

### 2 — After reading and interpreting each plugin / tool output

Call `step` once per analysis action, immediately after Claude has read and understood the output:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Process List (windows.pslist)" \
  --action "vol -f image.mem windows.pslist → <case_id>_evidence/memory/pslist.txt" \
  --why "<case-specific reason — see guidance below>" \
  --outcome "87 processes found. lsass.exe running from C:\\Temp\\ — anomalous path, flagged for follow-up [source: <case_id>_evidence/memory/pslist.txt]" \
  --dismissed "<what you inspected and decided was not significant — see guidance below>" \
  [--raw "first 10 lines of pslist output if significant"]
```

**`--why` — write the case-specific reason, not a generic tool description.** Explain the hypothesis you are testing or the question you are answering *at this moment in this investigation*. Do not restate what the tool does.
> ✗ Generic (do not write): `"pslist walks the EPROCESS doubly-linked list — mandatory first step for Windows triage"`
> ✓ Case-specific (write this): `"psscan found 3 processes absent from pslist — running pslist to quantify the delta and confirm DKOM is active on this image"`

**`--dismissed` (optional but expected for every step):** Note what you observed in the output and decided was not suspicious, and your reason. Omit only when the output is completely empty.
> Examples:
> - `"All svchost.exe instances running from C:\\Windows\\System32 — paths match expected baseline; no injection indicators"`
> - `"No ESTABLISHED connections to external IP space — all connections are RFC 1918 internal"`
> - `"malfind returned 4 hits; all 4 are clr.dll-backed JIT regions — confirmed .NET false positives, not shellcode"`

**Traceability convention:** always reference the **preserved evidence path** (`<case_id>_evidence/memory/<plugin>.txt`) in both `--action` and at the end of `--outcome` as `[source: <case_id>_evidence/memory/<plugin>.txt]`. This survives the `./analysis/` cleanup and unambiguously links each research-notes step to the artifact that produced it.

**Steps that each require a `step` call (in order):**

| Step | Title | Why — write the case-specific reason: what hypothesis are you testing at this point? |
|------|-------|------------------------|
| Image type detection | `Image Type Detection` | State why OS detection matters for the specific image presented (e.g., "extension is .mem but file header must be confirmed before selecting Windows vs Linux plugin chain") |
| psscan | `Hidden Process Scan (windows.psscan)` | State what you expect to find relative to earlier observations |
| pslist | `Active Process List (windows.pslist)` | State how this compares to psscan and what discrepancy you are looking for |
| pstree | `Process Tree (windows.pstree)` | State which suspicious processes from pslist/psscan you are tracing through parent-child relationships |
| cmdline | `Command Line Arguments (windows.cmdline)` | State which processes you are investigating for suspicious arguments |
| netstat / netscan | `Network Connections (windows.netstat + netscan)` | State what network behaviour you hypothesise based on what you have already found |
| malfind | `Code Injection Detection (windows.malfind)` | State which processes are injection candidates based on the process list |
| svcscan | `Service Scan (windows.svcscan)` | State what persistence or elevation you are looking for given current findings |
| modules / modscan | `Loaded Kernel Modules (windows.modules + modscan)` | State whether you suspect a rootkit or driver-level activity and why |
| filescan | `File Handles (windows.filescan)` | State which open file paths you expect to find or are looking for |
| hivelist / userassist | `Registry Artifacts (windows.hivelist + userassist)` | State what registry persistence or execution history you are looking for |
| Memory Baseliner | `Baseline Comparison (Memory Baseliner)` | State what process/driver anomalies you expect relative to a clean baseline |
| YARA scan | `YARA Rule Scan` | State which malware families or shellcode patterns are candidates given current findings |
| OpenCTI enrichment | `Threat Intelligence Enrichment (OpenCTI)` | State which extracted IPs/hashes you are enriching and what attribution you are testing |
| Cross-module correlation | `Cross-module Correlation (FAN / FAME / FAST)` | State what specific cross-module connection you are looking for (e.g., "netscan found IP 1.2.3.4 — checking whether FAN flagged the same flow") |

For **Linux images** using the strings-based fallback, use these titles instead:
`Strings Extraction`, `Syslog Pattern Hunt`, `Network IOC String Hunt`, `Banner Detection (banners.Banners)`.

**Use `--raw` only when the output contains significant findings** (suspicious process paths,
external IP connections, injected memory regions, YARA matches, baseline deviations).
For clean / expected output, omit `--raw` and summarise in `--outcome`.

### 2c — Mid-investigation reflection (mandatory — do not skip)

After reading and logging the **Network Connections (netscan)** step, stop and review all research notes steps recorded so far (RN-001 through the current step). Ask: does any earlier finding need reinterpreting in light of the network connections just observed?

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Mid-investigation review — post-netscan" \
  --reinterpret "<state which earlier steps, if any, should be re-read differently in light of the netscan findings — or write: 'No reinterpretations; earlier findings stand'>" \
  --open-leads "<list specific unresolved questions: processes to dump, IPs to enrich, files to check — or write: 'No open leads identified yet'>"
```

This uses the `reflect` subcommand, not `step`. It does not increment the RN counter.

### 2b — When you discover a confirmed attacker action in the evidence

Whenever Volatility output, YARA scans, baseline deviations, or cross-module correlation
reveals an action **performed by the attacker** — and that action has a **confirmed
timestamp from the evidence** — log it immediately using the `event` subcommand:

```bash
python3 lib/research_notes.py event \
  --case-id <case_id> \
  --timestamp "YYYY-MM-DD HH:MM:SS UTC" \
  --description "Malicious process spawned: explorer.exe → cmd.exe → powershell.exe" \
  --severity critical \
  --module FAME \
  --source "PID 4928 (explorer.exe) → PID 5012 (cmd.exe) → PID 5044 (powershell.exe)" \
  --detail "windows.pstree shows anomalous parent-child chain; malfind confirms injected shellcode in PID 5044"
```

**Rules:**
- **Only call `event` if there is a confirmed timestamp** from an artifact (process creation
  time, log entry, network packet timestamp). Do not estimate or infer timestamps.
- If a significant finding has **no confirmed timestamp**, log it as a `step` instead and
  do NOT call `event`. It will appear in the *Unconfirmed Findings* section of the report.
- `--severity critical` — direct evidence of compromise, active malware execution, credential theft
- `--severity high` — suspicious process chains, anomalous external connections, persistence
- `--severity medium` — anomalies that may be benign but require follow-up
- `--source` must name the specific evidence artifact (PIDs, IPs, file paths, hashes)

### 3 — Pre-finalize open leads review (mandatory)

Before calling `finalize`, read the complete research notes file from top to bottom:

```bash
cat ./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md
```

For every finding marked `[ASSUMPTION]`, every event without a confirmed timestamp, and every
`--dismissed` observation, ask: does the complete picture explain this, or does it remain open?
Then write the second reflect entry:

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Pre-finalize complete case review" \
  --reinterpret "<final pass: state any step that needs reinterpretation given the full picture — or: 'All steps consistent with final conclusion'>" \
  --open-leads "<what this investigation cannot resolve alone — specify what evidence (FAST disk image, FAN PCAP, sandbox detonation) would change or confirm the conclusion>"
```

Then call finalize:

```bash
python3 lib/research_notes.py finalize \
  --case-id <case_id> \
  --summary "One-paragraph summary: key findings, main pivot point, MITRE techniques confirmed, and conclusion."
```

Then include the notes file in the upload call.

**If `--md-only` was set (batch run via `/investigate-all`) — only MD and notes were generated:**
```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md    ./reports/<case_id>/FAME/<hostname>/<case_id>_fame_report.md \
  --notes ./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md \
  --interactive
```

**If `--md-only` was NOT set (standalone run) — all formats were generated:**
```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md    ./reports/<case_id>/FAME/<hostname>/<case_id>_fame_report.md \
  --pdf   ./reports/<case_id>/documents/<case_id>_fame_report.pdf \
  --pptx  ./reports/<case_id>/documents/<case_id>_fame_presentation.pptx \
  --docx  ./reports/<case_id>/documents/<case_id>_fame_report.docx \
  --notes ./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md \
  --interactive
```

`--interactive` prompts for SSH host, identity file, and remote root (all pre-filled with defaults from environment variables), then asks for confirmation before transferring. Press Enter to accept each default; answer **n** at the confirmation prompt to skip the upload and keep reports in `./reports/` only.

To skip upload entirely without any prompts (offline / no VM):

```bash
python3 lib/investigations_upload.py ... --no-upload
```

---

## Narrative file (required before report generation)

After all Volatility / Memory Baseliner steps are complete and **before** calling
`python3 lib/generate_fame_report.py`, Claude must write the narrative file:

```
./reports/<case_id>/FAME/<hostname>/<case_id>_narrative.md
```

This file feeds the Incident Timeline section, the enhanced technical chapters,
and all eight slides of the board PPTX deck (Executive Summary, Business Impact,
Incident Timeline, Root Cause & Risk, Response & Containment, Recommendations,
Lessons Learned). Without it those slides show generic placeholder text — write
every section yourself, in your own words, based on what you actually found. Do not
rely on `lib/narrative_generator.py`'s keyword-matching heuristics to fill these in;
that generator is a headless fallback for batch/no-Claude runs only and produces
noticeably weaker, often generic content.

### Schema (copy exactly, fill every section)

```markdown
<!-- narrative:<case_id> generated:<UTC timestamp> model:claude-sonnet-4-6 -->

## attack_timeline

On [exact timestamp UTC], [machine/hostname] [what happened — initial access, lateral
movement, execution, exfiltration, etc.]. This is [confirmed / assumed] based on
[finding description] ([RN-NNN]).

[Continue chronologically for each significant event. One paragraph per event.
Use "confirmed" when backed by a specific artifact; "assumed" when inferred.
No raw IPs or ports in this section — describe behaviour.]

## section_processes

[Interpret the process list. Which processes are suspicious, why, and what forensic
significance they carry. Reference process names and PIDs. Explain parent-child
anomalies. State what an analyst should look at first and why.]

## section_network

[Interpret the network connections. Which connections are suspicious, what protocol,
what likely purpose (C2, lateral movement, exfiltration). Cross-reference with FAN
findings if available.]

## section_malware

[Interpret malfind / YARA results. Distinguish JIT false positives from genuine
shellcode injection. Name malware families if identifiable. State confidence level.]

## pptx_executive_summary

[3–5 bullet points. CISO language. No IPs, ports, workstation IDs.
Example: "• A server was accessed by an unauthorised individual using valid credentials.
• The access resulted in deliberate shutdown of the system.
• No evidence of remote attacker or data exfiltration was found in the memory image."]

## pptx_risk

[Business risks: data exposure, regulatory, operational, reputational.
No technical identifiers. Example: "Unauthorised physical access to server room
exposes the organisation to undocumented maintenance actions that could recur."]

## pptx_impact

[What was affected: systems, users, services, data. Business language.
Example: "The server was unavailable for approximately 30 seconds. No user data
was accessed or exfiltrated based on current evidence."]

## pptx_mitigations

[What has already been done and what is in progress. Examples:
"• Memory image acquired and analysed within 2 hours of the incident.
• Physical access logs being reviewed.
• Security camera footage requested from facilities management."]

## pptx_recommendations

[Concrete follow-up actions with suggested owner labels. Examples:
"• Review server room physical access policy — CISO / Facilities
• Enable console login alerting — IT Operations
• Confirm whether maintenance was authorised — Line Manager"]

## pptx_timeline

[4-6 bullets: the board-level timeline. Same chronology as attack_timeline, but
plain language, no IPs/ports/PIDs/workstation IDs/RN-NNN citations — "On [date]
at [time], ..." Each bullet should be readable on its own as a slide line.]

## pptx_root_cause

[1-2 sentences: how did this happen, in plain language — e.g. phishing, an
exposed/weak service, compromised credentials, an unpatched vulnerability,
physical access, misconfiguration. Be specific to what you actually found in
this memory image; do not use a generic placeholder if the evidence supports a
real conclusion.]

## pptx_lessons_learned

[3-5 bullets: what worked well in this investigation/response, and what gaps
or improvements this incident points to. Plain language, board-appropriate.]
```

### Rules
- Write **all** sections even if evidence is thin — note the gap explicitly.
- Keep management sections (`pptx_*`) free of IPs, ports, PID numbers, hash values,
  file paths, hostnames/workstation IDs, and RN-/EVT- citation references — write
  them as you would for a board/CISO audience, not a technical one.
- Use RN-NNN references in `attack_timeline` to link back to research notes.
- If a section genuinely has no content (e.g., no malfind hits), write one sentence
  explaining that and why (e.g., "No code injection was detected — malfind returned
  zero regions with executable VAD flags outside mapped images.").

---

## Invocation

```bash
# Standard run (interactive — prompts for case ID)
./scripts/fame_analyze.sh /path/to/image.mem

# Non-interactive
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001

# With explicit hostname (used in reports)
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234

# Batch mode — Markdown + research notes only (skip PDF, PPTX, DOCX)
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --md-only

# Skip upload (offline environment)
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --no-upload
```

### Python API

```python
import sys; sys.path.insert(0, "./lib")
from generate_fame_report import generate

paths = generate(
    case_id       = "FAME-2026-001",
    hostname      = "SERVER1234",
    image_path    = "/path/to/SERVER1234.memory",
    opencti_findings = opencti_text,  # from /fan-opencti-lookup
    fan_summary   = fan_summary_text,  # from existing FAN report
    fast_summary  = fast_summary_text, # from existing FAST report
    md_only       = False,             # set True in batch runs to skip PDF/PPTX/DOCX
)
# paths: {"md": Path, "pdf": Path, "pptx": Path, "docx": Path}
```

---

## Six-step analysis workflow

The `fame_analyze.sh` script follows the six-step memory forensics methodology:

### Step 1 — Identify rogue processes

```bash
# Pool scan finds hidden and exited processes
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.psscan > ./analysis/memory/psscan.txt
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.pslist > ./analysis/memory/pslist.txt

# Find processes in psscan but NOT pslist (hidden)
diff <(awk '{print $3}' ./analysis/memory/psscan.txt | sort) \
     <(awk '{print $2}' ./analysis/memory/pslist.txt | sort)

# Linux images
sudo /opt/volatility3-2.20.0/vol.py -f <image> linux.pslist > ./analysis/memory/linux_pslist.txt
```

### Step 2 — Analyze parent-child relationships

```bash
sudo /opt/volatility3-2.20.0/vol.py -f <image> -r pretty windows.pstree \
  | cut -d '|' -f 1-11 > ./analysis/memory/pstree.txt
```

### Step 3 — Examine command lines and environment

```bash
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.cmdline > ./analysis/memory/cmdline.txt
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.envars  > ./analysis/memory/envars.txt
```

### Step 4 — Review network connections

```bash
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.netstat > ./analysis/memory/netstat.txt
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.netscan > ./analysis/memory/netscan.txt

# Extract unique external IPs for IOC pivot
grep -v "^Offset\|127.0.0.1\|0.0.0.0" ./analysis/memory/netscan.txt | \
  awk '{print $5}' | sort -u
```

### Step 5 — Look for code injection

```bash
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.malfind \
  > ./analysis/memory/malfind.txt
sudo /opt/volatility3-2.20.0/vol.py -f <image> windows.malfind \
  --dump --output-dir ./exports/malfind/
```

### Step 6 — Baseline comparison

```bash
# Requires a baseline.json from a known-good image
python3 /opt/memory-baseliner/baseline.py -proc -i <image> \
  --loadbaseline --jsonbaseline ./baselines/baseline.json \
  -o ./analysis/memory/proc_baseline.csv
```

---

## Linux image workflow (strings-based when ISF symbols unavailable)

Volatility 3 requires ISF symbol files for the target kernel. For old kernels
(pre-2012) or kernels without debug symbols, fall back to strings extraction:

```bash
# Extract all printable strings
strings -a -n 8 <image.mem> > ./analysis/memory/strings_all.txt
strings -a -el -n 8 <image.mem> > ./analysis/memory/strings_unicode.txt

# Hunt for syslog/auth patterns (shutdown analysis)
grep -E "(pam_unix|sudo:|login\[|FAILED|TERM signal|shutdown|reboot|PostgreSQL)" \
  ./analysis/memory/strings_all.txt \
  > ./analysis/memory/syslog_patterns.txt

# Hunt for network IOC patterns
grep -Ei "(https?://|ftp://|\\\\\\\\|cmd\.exe|powershell|certutil)" \
  ./analysis/memory/strings_all.txt \
  > ./analysis/memory/ioc_strings.txt

# Try Volatility 3 banners plugin (works without full ISF)
sudo /opt/volatility3-2.20.0/vol.py -f <image.mem> banners.Banners \
  > ./analysis/memory/banners.txt
```

---

## OpenCTI enrichment

After Volatility analysis, enrich extracted IPs and process IOCs against OpenCTI:

```bash
# Run the OpenCTI lookup skill against extracted IPs
/fan-opencti-lookup --case-id <case_id>

# Or directly via the MCP tool:
# Tool: opencti_search_ioc
# value: <defanged IP from netscan>
# pattern_type: stix
```

Upload confirmed malicious indicators from memory analysis to OpenCTI:

```python
import sys; sys.path.insert(0, "./lib")
# The generate_fame_report.py module calls knowledge_extractor internally.
# To manually push an IOC to OpenCTI after FAME:
from knowledge_extractor import record_ioc, record_ttp

record_ioc("ip", "1[.]2[.]3[.]4", "C2 server seen in memory netscan",
           case_id="FAME-2026-001", severity="critical",
           related_ttps=["T1071 Application Layer Protocol"])

record_ttp("T1548.003", "Sudo Abuse", "msfadmin → root via sudo /bin/bash",
           case_id="FAME-2026-001", tactic="privilege-escalation")
```

---

## Cross-module correlation

Run the correlation engine **before** cleaning up `./analysis/` — it reads raw
Volatility output files directly. Call it after all plugin steps are complete:

```bash
python3 lib/correlate_findings.py \
    --case-id <case_id> \
    --hostname <hostname>
```

Then log the step in research notes:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Cross-module Correlation (FAN / FAME / FAST)" \
  --action "python3 lib/correlate_findings.py --case-id <case_id> → ./reports/<case_id>_correlation.md" \
  --why "Correlates netscan connections to PCAP threats (FAN↔FAME), process images to deleted disk entries (FAME↔FAST), and DNS queries to carved URLs (FAN↔FAST) — surfaces kill-chain connections that no single module identifies alone" \
  --outcome "<N FAN↔FAME matches, M FAME↔FAST matches, K FAN↔FAST matches — key finding>"
```

| Correlation | What it computes |
|-------------|-----------------|
| FAN ↔ FAME | Netscan connections matched to FAN flagged flows — links a specific process to suspicious network traffic |
| FAME ↔ FAST | Process image names matched to deleted fls entries — confirms post-execution cleanup (T1070.004) |
| FAN ↔ FAST | DNS-queried domains matched to bulk_extractor carved URLs — confirms active endpoint use |

`correlate_findings.py`'s output (`<case_id>_correlation.md`/`.json`) is a
**best-effort research aid**, not the campaign report itself: read it as one
input when drafting Section 3 of the campaign report, but ground that section
in the research notes regardless — zero matches reported by the tool does not
mean no correlation exists.

---

## Campaign Report (hand-authored)

If FAN, FAST, or another FAME run already exists for this case ID, the
per-case campaign report (`<case_id>_campaign_report.*`) must be hand-authored,
not auto-generated:

1. Read this module's research notes end-to-end, plus the research notes of
   every other module that has completed for this case ID.
2. Hand-author `./reports/<case_id>/<case_id>_campaign_report.md` following
   `docs/campaign_report_template.md` — Incident Timeline merged across
   modules, Cross-Domain Correlation pivots citing RN-/EVT- IDs from at least
   two modules (or stating explicitly that none exist), unified MITRE/IOC
   tables, and a hand-curated Hallucination Guard FND-list with an overall
   confidence percentage. `lib/correlate_findings.py`'s output and
   `lib/generate_combined_report.py`'s `_merge_*`/`_extract_*` helpers may be
   used as research aids when pre-populating tables.
3. Render it to PDF/PPTX/DOCX:
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

## Report voice

Every FAME report follows the FanGetFameFast dual-register voice:

### Management summary
- No IPs, ports, file sizes, or workstation IDs
- Business-level language: what happened, when, what the business impact was
- Example: *"A person at the physical server console obtained administrator access
  and shut the server down. No evidence of a remote attacker was found."*

### Technical body
- Precise identifiers: hostname, IP, port, process name, PID, command line
- Scoped conclusions citing evidence source
- Example: *"User `msfadmin` (PID 4675) authenticated at tty1 (08:06:07 EDT) and
  executed `sudo /bin/bash` to obtain a root shell (08:06:33 EDT). The root shell
  issued a reboot 25 seconds later, as observed in the memory image strings."*

**Claude: enhance and elaborate when necessary** — each report section carries this
instruction explicitly. Claude must add MITRE ATT&CK context, forensic significance
explanations, cross-domain pivot suggestions, and business-impact annotations beyond
what the raw tool output alone provides.

---

## Output paths

| Output | Path |
|--------|------|
| Volatility text output | `./analysis/memory/` |
| Linux pslist, banners | `./analysis/memory/linux_pslist.txt`, `banners.txt` |
| Strings extraction | `./analysis/memory/strings_all.txt`, `strings_unicode.txt` |
| Malfind dumps | `./exports/malfind/` |
| Process memory dumps | `./exports/memdump/` |
| Baseline comparison CSVs | `./analysis/memory/proc_baseline.csv` etc. |
| Markdown report | `./reports/<case_id>_fame_report.md` |
| PDF report | `./reports/<case_id>_fame_report.pdf` |
| PowerPoint (PPTX) | `./reports/<case_id>_fame_presentation.pptx` |
| Word document (DOCX) | `./reports/<case_id>_fame_report.docx` |
| Combined report | `./reports/<case_id>_combined_report.md` etc. |

---

## Vault integration

FAME writes confirmed findings to the Obsidian vault automatically:

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Privilege escalation via sudo | `TTPs/T1548.003.md` | T1548.003 |
| Valid account console login | `TTPs/T1078.md` | T1078 |
| System shutdown/reboot | `TTPs/T1529.md` | T1529 |
| Code injection (malfind hit) | `TTPs/T1055.md` | T1055 |
| Malicious external IP (netscan) | `IOCs/ip-<defanged>.md` | — |

Use `--no-vault` to suppress vault writes (offline environments).

```bash
# Verify vault entries after FAME run
./scripts/vault_context.sh ttp T1548
./scripts/vault_context.sh cases
```

---

## Deep-dive methodology (manual Volatility 3 + strings analysis)

After all standard Volatility plugins have run, perform a manual deep-dive before writing the
narrative. This surfaces attacker detail that automated plugin output does not directly expose.
All deep-dive steps are logged as `step` calls (RN-NNN) with `--title "Deep Dive N: <title>"`.

### Deep Dive 1 — Process relationship mapping

```bash
# Full process tree with PIDs, PPIDs, start/exit times
vol -f "$IMAGE" windows.pstree 2>/dev/null

# Cross-reference pslist vs psscan to detect DKOM-hidden processes
vol -f "$IMAGE" windows.pslist 2>/dev/null | awk '{print $2}' | sort > /tmp/pslist_pids.txt
vol -f "$IMAGE" windows.psscan 2>/dev/null | awk '{print $2}' | sort > /tmp/psscan_pids.txt
comm -13 /tmp/pslist_pids.txt /tmp/psscan_pids.txt   # in psscan only = DKOM-hidden
```

Any process present in `psscan` but absent from `pslist` is DKOM-hidden (T1014). For each
hidden process, run `cmdline` against its offset, note the full image path, and check
`netscan` for associated network connections.

### Deep Dive 2 — Network connection and process correlation

```bash
# Windows XP/2003: netscan (pool-based, catches closed connections)
vol -f "$IMAGE" windows.netscan 2>/dev/null

# Windows Vista+: netstat (live connection table — may miss recently closed)
vol -f "$IMAGE" windows.netstat 2>/dev/null

# Cross-reference PIDs from netscan against pslist/psscan
```

For each external IP in netscan output: cross-reference with FAN module findings when a PCAP is
available for the same case. A netscan PID connecting to an IP seen in the PCAP is a direct
cross-module corroboration. Document as `[PIVOT: FAN ↔ FAME — PID <N> → <IP> confirmed in both]`.

### Deep Dive 3 — Injected code and unsigned modules (malfind + modules)

```bash
# Regions with RWX permissions and no backing file (injection indicators)
vol -f "$IMAGE" windows.malfind 2>/dev/null

# Loaded kernel modules — look for unsigned or mismatched names
vol -f "$IMAGE" windows.modules 2>/dev/null

# Drivers not in module list (DKOM-hidden kernel drivers)
vol -f "$IMAGE" windows.driverscan 2>/dev/null
```

For each `malfind` hit: check whether the process is known benign (JIT compilers — clr.dll,
jvm.dll — produce false positives). For genuine hits: note the VAD protection flags (PAGE_EXECUTE_READWRITE
is strongest indicator), start/end address, and any embedded PE header in the hex dump.

### Deep Dive 4 — Service and persistence analysis

```bash
# All services (name, binary path, start type)
vol -f "$IMAGE" windows.svcscan 2>/dev/null | grep -v "^Offset\|^---"

# Handles for a suspicious PID (files, registry keys, mutexes it has open)
vol -f "$IMAGE" windows.handles --pid <PID> 2>/dev/null

# Open file handles per process (identify locking of exfil staging files)
vol -f "$IMAGE" windows.filescan 2>/dev/null | grep -i "\.exe\|\.dll\|Temp\|AppData"
```

Services with binary paths outside `C:\Windows\System32\` or `C:\Program Files\` are suspicious.
Services with `StartType=AUTO_START` and a deleted-on-disk binary (cross-reference with FAST fls)
indicate persistence that survives reboot.

### Deep Dive 5 — String extraction and keyword grep

Use when Volatility plugins are unavailable (no ISF symbols, Linux image without profile):

```bash
# Full strings extraction (both endiannesses)
strings -a -td "$IMAGE" > /tmp/strings_le.txt
strings -a -td -el "$IMAGE" >> /tmp/strings_le.txt

# Pattern grep: credentials, shell history, syslog lines
grep -iE "password|passwd|login|sudo|su -|root:" /tmp/strings_le.txt | head -40
grep -iE "^[A-Za-z]{3}\s+[0-9]+ [0-9:]{8} .*(sshd|login|sudo|pam)" /tmp/strings_le.txt | head -40

# IPv4 addresses carved from strings
grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}" /tmp/strings_le.txt | sort | uniq -c | sort -rn | head -30

# URLs
grep -oE "https?://[^[:space:]\"'<>]+" /tmp/strings_le.txt | sort -u | head -40

# Timestamps in ISO format or syslog format (for timeline reconstruction)
grep -oE "[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}" /tmp/strings_le.txt | sort -u
```

Log each grep as its own step, noting what was found and what was deliberately dismissed
(e.g., "grep for 'password' returned 842 hits — all in configuration file plaintext already
in FAST artifact set; no credential reuse or password spray patterns identified").

### Deep Dive 6 — Memory baseline comparison

When a `baselines/baseline.json` is present, Memory Baseliner runs automatically. Interpret the diff:

```bash
# New processes (not in baseline)
python3 /opt/memory-baseliner/baseline.py diff baselines/baseline.json ./analysis/memory/baseliner_current.json \
  --type proc 2>/dev/null

# New drivers (not in baseline)
python3 /opt/memory-baseliner/baseline.py diff baselines/baseline.json ./analysis/memory/baseliner_current.json \
  --type driver 2>/dev/null
```

Any process or driver in the current image but absent from the clean baseline is either:
- A newly installed application (expected) — verify against event log install timestamps
- Malware / attacker tool — if no corresponding install event exists, treat as HIGH finding

### Deep Dive 7 — Cross-module pivot triggers (mandatory review)

After completing all Volatility steps, explicitly check:

| If FAME found... | Pivot to... |
|-----------------|-------------|
| External IP in `netscan` | FAN — does the PCAP show traffic to this IP? If yes: confirmed C2 channel |
| Deleted executable path in `filescan` | FAST — does `fls` show the file deleted? Does MFT entry still exist? |
| Injected code in browser process (`iexplore`, `chrome`, `firefox`) | FAN — look for beaconing or data exfil in the PCAP matching the injection window |
| Service with no on-disk binary | FAST — check pagefile.sys strings, prefetch, and USN journal for the binary name |
| Suspicious kernel driver | FAST — check driver signing via Amcache; search for installer in prefetch |

Document each pivot check as a research notes step, even if the result is negative.
Negative cross-module results are evidence of scope containment and must be cited.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `vol: command not found` | `/home/vscode/.local/bin` not in PATH | Prepend `export PATH="$HOME/.local/bin:$PATH"` to every Bash command, or invoke via full path `/home/vscode/.local/bin/vol` |
| `windows.pslist` empty output | Image is a Linux dump | Use `linux.pslist` plugin instead |
| `windows.pslist` empty AND image is confirmed Windows | DKOM (T1014) — EPROCESS doubly-linked list unlinked by rootkit or kernel driver | Use `psscan` (pool scan) as the authoritative process list for the entire investigation; `netscan`, `modscan`, and `psxview` still work; `pslist`, `pstree`, `cmdline`, `svcscan`, `filescan`, and `malfind` will all return empty |
| `windows.vadyarascan` not found / shows generic `vol` help | `yara-python` Python package not installed — plugin loads silently only when the binding is present | `pip install yara-python` (or rebuild the devcontainer — it is now in `requirements.txt`); fallback: run the standalone `yara` CLI directly against the image file |
| Re-running the generator after manual Markdown edits | Expected — generator always rebuilds MD from raw analysis files | No action needed: if `<case_id>_fame_report.md` already exists the new auto-generated content is written to `<case_id>_fame_report_generated.md` instead, preserving the primary file. Review the draft and promote manually if desired. |
| ISF symbol error / hanging | No symbol file for this kernel | Use `--offline` flag; fall back to strings extraction |
| `malfind` filled with JIT hits | .NET or Java process | Triage hits manually; ignore regions backed by clr.dll or jvm.dll |
| Upload SSH error | ubuntudesktop unreachable | Check `ping ubuntudesktop`; use `--no-upload` to skip |
| Memory Baseliner flags everything | Wrong baseline JSON | Verify baseline was taken from a matching OS/patch level |

---

## Case study: SERVER1234 unexpected shutdown (2026-05-18)

This case was analyzed using the FAME strings-extraction fallback workflow
because ISF symbols were not available for Linux kernel 2.6.24-16-server
(Ubuntu 8.04 LTS, 2008).

**Root cause identified from memory strings:**
- Two failed console logins (unknown credentials) at 08:05:12–08:05:25 EDT
- Successful login as `msfadmin` at 08:06:07 EDT (tty1)
- `sudo /bin/bash` → root at 08:06:33 EDT (T1548.003)
- Shutdown initiated at 08:06:58 EDT (T1529)
- All services terminated in orderly sequence; server back online at 08:07:39 EDT

**MITRE ATT&CK techniques mapped:** T1078, T1548.003, T1529

**Evidence source:** Memory image strings extraction
(`./analysis/memory/syslog_patterns.txt`)

**Conclusion:** Deliberate operator action — either undocumented maintenance or
unauthorized physical access. No remote attacker, hardware fault, or kernel panic.

Report generated by: `./lib/generate_fame_report.py`
