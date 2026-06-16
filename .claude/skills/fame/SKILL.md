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

See `docs/investigation_discipline.md` for the research-notes cadence, the
narrative file contract (shared `pptx_*` schema), cross-module correlation,
campaign-report authoring, and the `lib/report_completeness.py` completeness
gate — all shared with FAN and FAST. This file covers only FAME-specific
content: the Volatility plugin step table, FAME's narrative `section_*` keys,
and the deep-dive methodology below.

---

## Research Notes

Every FAME investigation produces a **research notes file** (`./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md`)
alongside the formal report. Follow `docs/investigation_discipline.md` §1 for
the full research-notes cadence (mandatory rule, deviation logging, the
`init`/`step`/`reflect`/`event`/`finalize` calls, traceability convention,
and the distinction between auto-logged "Evidence preserved" steps and
Claude-authored interpretation). FAME-specific deviation examples:

- `windows.pslist` returned 0 processes → `step --title "Deviation: DKOM — switching to psscan-only workflow"`
- ISF symbols unavailable → `step --title "Deviation: No ISF — falling back to strings extraction"`
- `malfind` skipping dump because all hits are JIT false positives → `step --title "Deviation: malfind dump skipped — all hits confirmed JIT FPs"`
- Memory Baseliner not installed → `step --title "Deviation: Memory Baseliner absent — step skipped"`
- A plugin crashes or hangs → `step --title "Deviation: <plugin> failed — reason and workaround"`

`init` is called with `--module fame --evidence /path/to/image.mem --hostname <hostname>`.

**`--why` — write the case-specific reason, not a generic tool description.** Explain the hypothesis you are testing or the question you are answering *at this moment in this investigation*. Do not restate what the tool does.
> ✗ Generic (do not write): `"pslist walks the EPROCESS doubly-linked list — mandatory first step for Windows triage"`
> ✓ Case-specific (write this): `"psscan found 3 processes absent from pslist — running pslist to quantify the delta and confirm DKOM is active on this image"`

**`--dismissed` (optional but expected for every step):** Note what you observed in the output and decided was not suspicious, and your reason. Omit only when the output is completely empty.
> Examples:
> - `"All svchost.exe instances running from C:\\Windows\\System32 — paths match expected baseline; no injection indicators"`
> - `"No ESTABLISHED connections to external IP space — all connections are RFC 1918 internal"`
> - `"malfind returned 4 hits; all 4 are clr.dll-backed JIT regions — confirmed .NET false positives, not shellcode"`

Evidence paths use `<case_id>_evidence/memory/<plugin>.txt`.

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

Follow `docs/investigation_discipline.md` §1d (the `event` subcommand,
severity levels, and the confirmed-timestamp rule). Example for FAME:

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

### 3 — Pre-finalize open leads review (mandatory)

Follow `docs/investigation_discipline.md` §1e: read
`./reports/<case_id>/FAME/<hostname>/<case_id>_research_notes.md` end to end,
write the pre-finalize `reflect` entry, then call `finalize` with a real
investigation summary. Then include the notes file in the upload call.

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

For the shared `pptx_*` schema and authoring rules, see
`docs/investigation_discipline.md` §2. FAME's own narrative sections are:

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

... followed by the eight shared pptx_* sections (docs/investigation_discipline.md §2)
```

Example wording for FAME's `pptx_executive_summary`: *"• A server was accessed by
an unauthorised individual using valid credentials. • The access resulted in
deliberate shutdown of the system. • No evidence of remote attacker or data
exfiltration was found in the memory image."*

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

## Cross-module correlation & Campaign Report

Follow `docs/investigation_discipline.md` §3 (cross-module correlation via
`lib/correlate_findings.py`) and §4 (hand-authored campaign report +
completeness check via `lib/report_completeness.py --campaign-check`). Run
the correlation engine **before** cleaning up `./analysis/` — it reads raw
Volatility output files directly.

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
| Upload skipped: "vault not configured" | `INVESTIGATIONS_SSH_HOST`/`INVESTIGATIONS_ROOT` unset | Run `./scripts/configure_vault.sh user@host /remote/root` (see `templates/set_env_template.sh`); reports stay in `./reports/` until then |
| Upload SSH error | Configured vault host unreachable | Check connectivity to `$INVESTIGATIONS_SSH_HOST`; use `--no-upload` to skip |
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
