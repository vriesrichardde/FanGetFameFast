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

| Output | Format | Path |
|--------|--------|------|
| Technical report | Markdown | `./reports/<case_id>_fame_report.md` |
| Technical report | PDF | `./reports/<case_id>_fame_report.pdf` |
| Management briefing | Microsoft PowerPoint (.pptx) | `./reports/<case_id>_fame_presentation.pptx` |
| Full report | Microsoft Word (.docx) | `./reports/<case_id>_fame_report.docx` |
| Combined (all modules) | Markdown + PDF + PPTX + DOCX | `./reports/<case_id>_combined_*` |

---

## Research Notes

Every FAME investigation produces a **research notes file** (`./reports/<case_id>_research_notes.md`)
alongside the formal report. The notes are a timestamped, step-by-step investigative log that lets
any analyst follow the complete workflow, rationale, and findings from start to finish.

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
  --action "vol -f image.mem windows.pslist → ./analysis/memory/pslist.txt" \
  --why "pslist walks the EPROCESS doubly-linked list to enumerate active processes — mandatory first step for Windows triage" \
  --outcome "87 processes found. lsass.exe running from C:\\Temp\\ — anomalous path, flagged for follow-up" \
  [--raw "first 10 lines of pslist output if significant"]
```

**Steps that each require a `step` call (in order):**

| Step | Title | Why (use this verbatim) |
|------|-------|-------------------------|
| Image type detection | `Image Type Detection` | Must determine OS type before selecting Volatility plugin chain |
| psscan | `Hidden Process Scan (windows.psscan)` | Pool scan finds hidden and already-exited processes not visible in pslist |
| pslist | `Active Process List (windows.pslist)` | Walks EPROCESS doubly-linked list — baseline view of running processes; compare with psscan for hidden entries |
| pstree | `Process Tree (windows.pstree)` | Reveals parent-child relationships — unexpected parents (e.g. Word spawning cmd.exe) indicate injection or macro execution |
| cmdline | `Command Line Arguments (windows.cmdline)` | Shows exact arguments passed to each process — reveals obfuscated commands, encoded payloads, or unusual flags |
| netstat / netscan | `Network Connections (windows.netstat + netscan)` | Lists active and recently closed TCP/UDP connections — pivots to C2 IPs and lateral movement targets |
| malfind | `Code Injection Detection (windows.malfind)` | Identifies memory regions with executable code and no backing file — primary indicator of process injection (T1055) |
| svcscan | `Service Scan (windows.svcscan)` | Enumerates services including those not in the registry — finds persistence via malicious service installation |
| modules / modscan | `Loaded Kernel Modules (windows.modules + modscan)` | Lists loaded drivers; modscan catches unlinked/hidden drivers — reveals rootkit activity |
| filescan | `File Handles (windows.filescan)` | Scans pool for FILE_OBJECT structures — finds file handles for deleted or hidden files |
| hivelist / userassist | `Registry Artifacts (windows.hivelist + userassist)` | Hive locations confirm registry integrity; UserAssist reveals recently executed programs (T1112) |
| Memory Baseliner | `Baseline Comparison (Memory Baseliner)` | Compares running processes/drivers/services against a known-good baseline — anomalies indicate compromise |
| YARA scan | `YARA Rule Scan` | Applies signature rules to memory — direct detection of known malware families and shellcode patterns |
| OpenCTI enrichment | `Threat Intelligence Enrichment (OpenCTI)` | Correlates extracted IOCs (IPs, hashes) against known threat actors and campaigns |
| Cross-module check | `Cross-module Correlation (FAN / FAST)` | Checks whether FAN or FAST reports exist for this case — surfaces kill-chain connections across network, memory, and disk |

For **Linux images** using the strings-based fallback, use these titles instead:
`Strings Extraction`, `Syslog Pattern Hunt`, `Network IOC String Hunt`, `Banner Detection (banners.Banners)`.

**Use `--raw` only when the output contains significant findings** (suspicious process paths,
external IP connections, injected memory regions, YARA matches, baseline deviations).
For clean / expected output, omit `--raw` and summarise in `--outcome`.

### 3 — Before upload (after formal report is generated)

```bash
python3 lib/research_notes.py finalize \
  --case-id <case_id> \
  --summary "One-paragraph summary: key findings, main pivot point, MITRE techniques confirmed, and conclusion."
```

Then include the notes file in the upload call:

```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md ./reports/<case_id>_fame_report.md \
  --pdf ./reports/<case_id>_fame_report.pdf \
  --pptx ./reports/<case_id>_fame_presentation.pptx \
  --docx ./reports/<case_id>_fame_report.docx \
  --notes ./reports/<case_id>_research_notes.md
```

---

## Invocation

```bash
# Standard run (interactive — prompts for case ID)
./scripts/fame_analyze.sh /path/to/image.mem

# Non-interactive
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001

# With explicit hostname (used in reports)
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234

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

FAME automatically detects and incorporates FAN and FAST reports when they exist
for the same case ID. The combined report surfaces:

| Correlation | What it means |
|-------------|---------------|
| FAN ↔ FAME | Process in memory (`netscan`) matched to PCAP flow — links process to network traffic |
| FAME ↔ FAST | Process image path in memory found deleted on disk — persistence or clean-up indicator |
| FAN + FAME + FAST | Full kill chain: network delivery → memory execution → disk persistence |

To manually trigger a combined report after all modules have run:

```python
import sys; sys.path.insert(0, "./lib")
from generate_combined_report import generate

paths = generate(case_id="CASE-2026-001", hostname="SERVER1234")
```

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

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `windows.pslist` empty output | Image is a Linux dump | Use `linux.pslist` plugin instead |
| ISF symbol error / hanging | No symbol file for this kernel | Use `--offline` flag; fall back to strings extraction |
| `malfind` filled with JIT hits | .NET or Java process | Triage hits manually; ignore regions backed by clr.dll or jvm.dll |
| pptx or docx not generated | Missing python package | `pip3 install python-pptx python-docx` |
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
