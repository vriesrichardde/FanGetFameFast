# Skill: FAST — Forensic analysis storage

## Overview

**FAST** is the storage forensics module of Fan Get Fame Fast. It orchestrates
The Sleuth Kit (TSK), EWF tools, bulk_extractor, and PhotoRec against a disk
image, generates a full report suite (Markdown, PDF, Microsoft PowerPoint,
Microsoft Word), and uploads all artifacts to the investigations vault via the
MCP server.

If network forensics (FAN) or memory forensics (FAME) reports already exist for
the same case ID, FAST automatically produces a combined unified report that
correlates findings across all three investigation domains.

**Claude instructs itself to** ***enhance and elaborate when necessary*** **on every
report section** to ensure the analyst receives full analytical depth beyond the
raw tool output.

| Output | Format | Path | Batch (`--md-only`) |
|--------|--------|------|---------------------|
| Technical report | Markdown | `./reports/<case_id>/FAST/<hostname>/<case_id>_fast_report.md` | Always |
| Investigative log | Markdown | `./reports/<case_id>/FAST/<hostname>/<case_id>_research_notes.md` | Always |
| Technical report | PDF | `./reports/<case_id>/documents/<case_id>_fast_report.pdf` | Standalone only |
| Management briefing | Microsoft PowerPoint (.pptx) | `./reports/<case_id>/documents/<case_id>_fast_presentation.pptx` | Standalone only |
| Full report | Microsoft Word (.docx) | `./reports/<case_id>/documents/<case_id>_fast_report.docx` | Standalone only |
| Campaign report | Markdown/PDF/PPTX/DOCX | `./reports/<case_id>/<case_id>_campaign_report.*` (MD) + `documents/` (PDF/PPTX/DOCX) | Standalone only |

The unified cross-case report (`CAMPAIGN_<batch_id>_report.*`) is generated once at the
end of a batch by `/investigate-all` — not per individual FAST case.

See `docs/investigation_discipline.md` for the research-notes cadence, the
narrative file contract (shared `pptx_*` schema), cross-module correlation,
campaign-report authoring, and the `lib/report_completeness.py` completeness
gate — all shared with FAN and FAME. This file covers only FAST-specific
content: the TSK/EWF/bulk_extractor step table, FAST's narrative `section_*`
keys, and the deep-dive methodology below.

---

## Research Notes

Every FAST investigation produces a **research notes file** (`./reports/<case_id>/FAST/<hostname>/<case_id>_research_notes.md`)
alongside the formal report. Follow `docs/investigation_discipline.md` §1 for
the full research-notes cadence (mandatory rule, deviation logging, the
`init`/`step`/`reflect`/`event`/`finalize` calls, traceability convention,
and the distinction between auto-logged "Evidence preserved" steps and
Claude-authored interpretation). FAST-specific deviation examples:

- `ewfmount` fails → `step --title "Deviation: ewfmount failed — using qemu-nbd instead"`
- Filesystem mount fails (dirty NTFS) → `step --title "Deviation: dirty filesystem — added norecovery flag"`
- `fls` returns no deleted entries → `step --title "Deviation: no deleted entries — filesystem may have been wiped; proceeding with blkls + photorec"`
- Artifact not present (Prefetch, SRUM, etc.) → `step --title "Deviation: Prefetch absent — possible T1070.004 or non-Windows image"`
- A tool crashes or times out → `step --title "Deviation: <tool> failed — reason and workaround"`

`init` is called with `--module fast --evidence /path/to/image.E01 --hostname <hostname>`.

**`--why` — write the case-specific reason, not a generic tool description.** Explain the hypothesis you are testing or the question you are answering *at this moment in this investigation*. Do not restate what the tool does.
> ✗ Generic (do not write): `"Hash verification confirms evidence integrity — required before any findings can be cited in legal proceedings"`
> ✓ Case-specific (write this): `"Verifying hash before analysis — reported incident window is 08:00–09:00 UTC; if hashes mismatch, the image may have been altered after acquisition and all findings would be inadmissible"`

**`--dismissed` (optional but expected for every step):** Note what you observed in the output and decided was not suspicious, and your reason. Omit only when the output is completely empty.
> Examples:
> - `"fls returned 14 000 entries; no deleted entries in system32 or program files — attacker cleanup, if any, was confined to temp directories"`
> - `"mactime shows no file activity outside 08:00–09:00 UTC window — no evidence of persistence installed outside the incident timeframe"`
> - `"browser history present but all domains are legitimate corporate sites; no C2 or phishing domains identified"`

Evidence paths use `<case_id>_evidence/storage/<tool>.txt`.

**Steps that each require a `step` call (in order):**

| Step | Title | Why — write the case-specific reason: what hypothesis are you testing at this point? |
|------|-------|------------------------|
| Image verification | `Image Verification (ewfinfo + ewfverify)` | State why integrity matters here — e.g., whether this image was acquired during or after the incident, and whether chain-of-custody is contested |
| Image mount | `Image Mount (ewfmount / qemu-nbd)` | State which mount approach you chose and why (e.g., "ewfmount — E01 format confirmed by ewfinfo") |
| Partition inspection | `Partition Table (mmls)` | State what OS/partition layout you expect and what you are checking for |
| Filesystem mount | `Filesystem Mount (read-only)` | State whether you added norecovery and why (e.g., "dirty NTFS journal from unclean shutdown") |
| File listing | `File Listing (fls)` | State what you are looking for in the file listing given the known incident context |
| Bodyfile generation | `Bodyfile (fls -m)` | State the time window you will focus on in the mactime output |
| Timeline | `Filesystem Timeline (mactime)` | State the specific incident window you are constraining to and what events you expect to find |
| Filesystem stats | `Filesystem Metadata (fsstat)` | State what you are checking — e.g., last mount time relative to incident, volume label for hostname confirmation |
| Inode listing | `Inode Listing (ils)` | State whether you expect orphaned inodes (e.g., if fls already showed deleted entries) |
| Event logs | `Event Log Extraction (EVTX)` | State which log channels matter for this incident (Security for auth events, System for shutdown, Application for specific software) |
| Registry hives | `Registry Extraction (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)` | State which persistence keys or user accounts you are looking for given the incident |
| Prefetch | `Prefetch Extraction` | State which executables you expect to find (or suspect were deleted) and are looking for in prefetch |
| MFT | `MFT Extraction (icat inode 0)` | State what MFT analysis you plan — timeline reconstruction, deleted entry recovery, or ADS detection |
| USN Journal | `USN Journal Extraction (icat inode 11)` | State what change events you expect in the incident window |
| SRUM | `SRUM Extraction (SRUDB.dat)` | State which processes or network events you are looking to confirm via SRUM |
| Browser history | `Browser History Extraction` | State whether you suspect web-delivered malware, C2 communication, or data exfiltration via browser |
| Mail & messaging | `Mail & Messaging Client Artifacts` | State which mail/IM clients were found in fls output and what communications or account credentials you are looking for |
| IRC clients | `IRC Client Artifacts` | State which IRC client was found (mIRC, HexChat, irssi) and what channels, aliases, or operational communications you are looking for |
| Office & documents | `Office Software & Document Artifacts` | State whether Office is installed, what documents exist in user profile, and whether document metadata or macros could reveal attacker identity or targets |
| Scheduled tasks | `Scheduled Task Extraction` | State whether you expect persistence via scheduled tasks based on findings so far |
| Recycle Bin | `Recycle Bin Extraction + Metadata Parse` | State whether file deletion was suspected from fls output and what files you expect to find; include results from recyclebin_parsed.json |
| Amcache | `Amcache Extraction` | State which binaries you want to confirm execution of (especially those already found deleted in fls) |
| File carving | `File Carving (bulk_extractor)` | State what artifact types you expect to recover and why (emails, URLs, credentials) |
| OpenCTI enrichment | `Threat Intelligence Enrichment (OpenCTI)` | State which carved URLs, hashes, or domains you are enriching and what attribution you are testing |
| Cross-module correlation | `Cross-module Correlation (FAN / FAME / FAST)` | State what specific cross-module connection you are looking for (e.g., "FAME netscan found PID 1234 connecting to 1.2.3.4 — checking FAST fls for the executable on disk") |

**Use `--raw` only when the output contains significant findings** (deleted executables, suspicious
registry keys, carved C2 URLs, EVTX gaps, unusual scheduled tasks). For clean / expected output,
omit `--raw` and summarise in `--outcome`.

### 2c — Mid-investigation reflection (mandatory — do not skip)

After reading and logging the **USN Journal Extraction** step (all artifact extractions complete,
bulk_extractor not yet run), stop and review all research notes steps recorded so far (RN-001
through the current step). Ask: does any earlier finding need reinterpreting in light of the
complete artifact picture you now have?

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Mid-investigation review — post-artifact-extraction" \
  --reinterpret "<state which earlier steps, if any, should be re-read differently in light of all extracted artifacts — or write: 'No reinterpretations; earlier findings stand'>" \
  --open-leads "<list specific unresolved questions: files to carve, registry keys to check, EVTX events to look for — or write: 'No open leads identified yet'>"
```

This uses the `reflect` subcommand, not `step`. It does not increment the RN counter.

### 2b — When you discover a confirmed attacker action in the evidence

Follow `docs/investigation_discipline.md` §1d (the `event` subcommand,
severity levels, and the confirmed-timestamp rule). Example for FAST:

```bash
python3 lib/research_notes.py event \
  --case-id <case_id> \
  --timestamp "YYYY-MM-DD HH:MM:SS UTC" \
  --description "Malicious executable deleted to cover tracks" \
  --severity high \
  --module FAST \
  --source "/Windows/Temp/dropper.exe (inode 45678, MFT entry 12345)" \
  --detail "Deletion timestamp 08:07:02 UTC from mactime — precedes orderly shutdown; SHA256 matches known RAT dropper"
```

### 3 — Pre-finalize open leads review (mandatory)

Follow `docs/investigation_discipline.md` §1e: read
`./reports/<case_id>/FAST/<hostname>/<case_id>_research_notes.md` end to end,
write the pre-finalize `reflect` entry, then call `finalize` with a real
investigation summary. Then include the notes file in the upload call.

**If `--md-only` was set (batch run via `/investigate-all`) — only MD and notes were generated:**
```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md    ./reports/<case_id>/FAST/<hostname>/<case_id>_fast_report.md \
  --notes ./reports/<case_id>/FAST/<hostname>/<case_id>_research_notes.md
```

**If `--md-only` was NOT set (standalone run) — all formats were generated:**
```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md    ./reports/<case_id>/FAST/<hostname>/<case_id>_fast_report.md \
  --pdf   ./reports/<case_id>/documents/<case_id>_fast_report.pdf \
  --pptx  ./reports/<case_id>/documents/<case_id>_fast_presentation.pptx \
  --docx  ./reports/<case_id>/documents/<case_id>_fast_report.docx \
  --notes ./reports/<case_id>/FAST/<hostname>/<case_id>_research_notes.md
```

---

## Narrative file (required before report generation)

After all TSK / EWF / bulk_extractor steps are complete and **before** calling
`python3 lib/generate_fast_report.py`, Claude must write the narrative file:

```
./reports/<case_id>/FAST/<hostname>/<case_id>_narrative.md
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
`docs/investigation_discipline.md` §2. FAST's own narrative sections are:

```markdown
<!-- narrative:<case_id> generated:<UTC timestamp> model:claude-sonnet-4-6 -->

## attack_timeline

On [exact timestamp UTC], [machine/hostname] [what happened — file deletion,
persistence installation, data staging, etc.]. This is [confirmed / assumed] based on
[finding description] ([RN-NNN]).

[Continue chronologically for each significant event. One paragraph per event.
Use "confirmed" when backed by a specific artifact; "assumed" when inferred.]

## section_filesystem

[Interpret the filesystem timeline and fls output. What file activity stands out?
Which files were created, deleted, or modified at suspicious times? What does this
reveal about attacker behaviour? What should an analyst look at first?]

## section_network

[Interpret any carved URLs, domains, or IPs from bulk_extractor. Cross-reference
with FAN findings if available. Note any exfiltration indicators.]

... followed by the eight shared pptx_* sections (docs/investigation_discipline.md §2)
```

Example wording for FAST's `pptx_executive_summary`: *"• Evidence of file
deletion was found on the server disk image. • The deletion timestamps
coincide with the reported incident window. • No evidence of data
exfiltration to external locations was found."*

---

## Invocation

```bash
# Standard run (interactive — prompts for case ID)
./scripts/fast_analyze.sh /path/to/image.E01

# Non-interactive
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001

# With explicit hostname
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234

# Batch mode — Markdown + research notes only (skip PDF, PPTX, DOCX)
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --md-only

# Skip filesystem mount (if mount fails or raw TSK access preferred)
./scripts/fast_analyze.sh /path/to/image.vmdk --case-id FAST-2026-001 --no-mount

# Skip upload (offline environment)
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --no-upload
```

### Python API

```python
import sys; sys.path.insert(0, "./lib")
from generate_fast_report import generate

paths = generate(
    case_id      = "FAST-2026-001",
    hostname     = "SERVER1234",
    disk_image   = "/path/to/SERVER1234.vmdk",
    opencti_findings = opencti_text,
    fan_summary  = fan_summary_text,
    fame_summary = fame_summary_text,
    md_only      = False,             # set True in batch runs to skip PDF/PPTX/DOCX
)
# paths: {"md": Path, "pdf": Path, "pptx": Path, "docx": Path}
```

---

## Full analysis workflow

### 1. Verify the image

```bash
# E01 format — metadata and hash
ewfinfo /path/to/image.E01 > ./analysis/storage/ewfinfo.txt
ewfverify /path/to/image.E01 > ./analysis/storage/ewfverify.txt

# Raw/VMDK format — image stats
img_stat /path/to/image.vmdk > ./analysis/storage/img_stat.txt
```

**Evidence integrity rule:** ewfverify must complete without errors before any
findings are cited in legal or regulatory proceedings.

### 2. Mount E01 image read-only

```bash
sudo mkdir -p /mnt/ewf /mnt/windows_mount

# Mount E01 (multi-segment: point to first segment only)
sudo ewfmount /path/to/image.E01 /mnt/ewf/
# Expected: /mnt/ewf/ewf1

# Check sector size
img_stat /mnt/ewf/ewf1
```

### 3. Inspect partition table

```bash
sudo mmls /mnt/ewf/ewf1 > ./analysis/storage/mmls.txt
# Note the Start sector for the target NTFS/ext partition
```

### 4. Mount filesystem read-only

```bash
# Offset = Start_sector × sector_size
OFFSET=$(( 2048 * 512 ))   # adjust from mmls output
sudo mount -o ro,loop,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount

# If dirty/hibernated:
sudo mount -o ro,loop,norecovery,offset=${OFFSET} /mnt/ewf/ewf1 /mnt/windows_mount
```

### 5. File system navigation and listing

```bash
# Full recursive listing (incl. deleted — marked with *)
sudo fls -r -p /mnt/ewf/ewf1 > ./analysis/storage/fls_output.txt

# Bodyfile (MAC times — for timeline)
sudo fls -r -m / /mnt/ewf/ewf1 > ./analysis/storage/bodyfile.txt

# Show only deleted entries
grep "^\* " ./analysis/storage/fls_output.txt

# Filesystem metadata
sudo fsstat /mnt/ewf/ewf1 > ./analysis/storage/fsstat.txt
```

### 6. Generate filesystem timeline

```bash
# Timeline (UTC, tab-separated)
mactime -b ./analysis/storage/bodyfile.txt -z UTC \
  > ./exports/fs_timeline.txt

# CSV (for Timeline Explorer)
mactime -b ./analysis/storage/bodyfile.txt -z UTC -d \
  > ./exports/fs_timeline.csv

# ISO 8601 timestamps
mactime -b ./analysis/storage/bodyfile.txt -z UTC -y \
  > ./exports/fs_timeline_iso.txt
```

### 7. Extract key artifacts

```bash
# Windows Event logs
sudo find /mnt/windows_mount/Windows/System32/winevt/Logs/ -name "*.evtx" \
  -exec cp {} ./exports/evtx/ \;

# Registry hives
for hive in SYSTEM SOFTWARE SECURITY SAM; do
  sudo cp /mnt/windows_mount/Windows/System32/config/$hive ./exports/registry/
done
sudo find /mnt/windows_mount/Users/ -name "NTUSER.DAT" \
  -exec cp --parents {} ./exports/registry/ \;

# Prefetch
sudo cp -r /mnt/windows_mount/Windows/Prefetch/ ./exports/prefetch/

# MFT (inode 0) and UsnJrnl (inode 11)
sudo icat /mnt/ewf/ewf1 0  > ./exports/mft/\$MFT
sudo icat /mnt/ewf/ewf1 11-128-4 > ./exports/mft/\$J 2>/dev/null || \
sudo icat /mnt/ewf/ewf1 11 > ./exports/mft/\$J

# SRUM database
sudo cp /mnt/windows_mount/Windows/System32/sru/SRUDB.dat ./exports/srum/

# Amcache
sudo cp /mnt/windows_mount/Windows/AppCompat/Programs/Amcache.hve ./exports/registry/
```

### 8. File carving

```bash
# bulk_extractor (emails, URLs, domains, credit cards, BTC addresses)
sudo bulk_extractor -o ./exports/carved/ -j 4 /mnt/ewf/ewf1

# Targeted feature types only (faster)
sudo bulk_extractor -o ./exports/carved/ -e email -e url -e domain /mnt/ewf/ewf1

# PhotoRec (signature-based file recovery — interactive)
sudo photorec /mnt/ewf/ewf1
```

### 9. Unmount

```bash
# Always unmount in reverse order
sudo umount /mnt/windows_mount
sudo umount /mnt/ewf
```

---

## OpenCTI enrichment

After TSK analysis, enrich extracted artifacts against OpenCTI:

```bash
# Run the OpenCTI lookup skill against case IOCs
/fan-opencti-lookup --case-id <case_id>

# Manually search a suspicious URL found in bulk_extractor carved output
# Tool: opencti_search_ioc
# value: hxxps://evil[.]example[.]com/payload
# pattern_type: stix
```

Upload confirmed indicators to OpenCTI:

```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ioc, record_ttp

# A malicious URL carved from unallocated space
record_ioc("url", "hxxps://c2[.]attacker[.]com/rat", "Carved from unallocated disk space",
           case_id="FAST-2026-001", severity="critical")

# File deletion used to cover tracks
record_ttp("T1070.004", "Indicator Removal: File Deletion",
           "Deleted executable found in fls output — attacker cleaned up after execution.",
           case_id="FAST-2026-001", tactic="defense-evasion")
```

---

## Cross-module auto-trigger (FAN and FAME)

When FAST discovers evidence files that belong to another module's domain,
**do not silently note them** — automatically trigger the relevant module.

### Trigger FAN when a network capture file is found on disk

Detection: during `File Listing (fls)` or `File Carving`, check for:

```bash
grep -i "\.pcap\|\.pcapng\|\.cap\b\|\.dmp\b\|\.dump\b\|\.snoop\|\.etl\b\|\.netmon\|Network Monitor\|WireShark\|Ethereal\|interception\|capture" \
  ./analysis/storage/fls_output.txt
```

Also check user profile `My Documents/`, Desktop, and any tool directories (Wireshark,
Ethereal, Network Monitor, Cain) for saved capture files.

**When found:**
1. Extract the file with `icat` to `exports/pcaps/<filename>` immediately.
2. Run `file <extracted>` to confirm it is a valid pcap/pcapng.
3. Log the discovery as a research notes step with inode, size, and path.
4. **Invoke `/fan <path-to-pcap> --case-id <current-case-id>`** to run the full FAN
   pipeline on the capture. FAN will generate its own report and upload it; when it
   completes, the combined report generator will merge the findings.

> **Rationale:** A packet capture saved on an attacker's disk is direct evidence of
> interception activity. The FAN pipeline extracts protocol threats, HTTP sessions,
> DNS queries, TLS certificates, and file hashes that a FAST analyst cannot recover
> from a binary blob alone. This case (FAST-2026-NIST-HACK) found `Documents and
> Settings/Mr. Evil/interception` (inode 12264) — a 173 KB Ethereal PCAP containing
> the stolen Hotmail session. FAN would have surfaced this automatically.

### Trigger FAME when a memory image or hibernation file is found on disk

Detection: during `File Listing (fls)`:

```bash
grep -i "\.mem\b\|\.vmem\b\|\.dmp\b\|hiberfil\.sys\|pagefile\.sys\|\.raw\b\|\.lime\b\|memdump\|memory\.img\|crash.*\.dmp\|minidump\|\.vmss\b\|\.vmsn\b" \
  ./analysis/storage/fls_output.txt
```

**When found:**
1. Check size: `istat` to confirm the file has actual content (not Actual Size: 0).
2. For `hiberfil.sys` — this is the Windows hibernation file; it contains a compressed
   snapshot of physical memory at the time of hibernation. Extract with `icat`.
3. For `.dmp` files — check whether they are full kernel dumps, minidumps, or user-mode
   crash dumps. Full kernel dumps and live capture `.mem`/`.raw`/`.vmem` files are
   suitable for Volatility 3.
4. Log the discovery as a research notes step.
5. **Invoke `/fame` and provide the extracted image path** to run the full FAME pipeline.
   FAME will produce its own report; when complete, the combined report generator merges.

> **Note on `pagefile.sys`:** always extract and run `strings` on the pagefile — it contains
> memory pages swapped out during the session and can reveal process command lines,
> network connections, and credentials that were active in RAM but are not recoverable
> from the NTFS filesystem. This does not require FAME; extract with `icat` and scan:
> ```bash
> strings -n 12 exports/pagefile.sys | grep -iE "password|token|cookie|auth|cmd|powershell|bash|nc\b|netcat|meterpreter" | head -50
> ```

---

## Cross-module correlation & Campaign Report

Follow `docs/investigation_discipline.md` §3 (cross-module correlation via
`lib/correlate_findings.py`) and §4 (hand-authored campaign report +
completeness check via `lib/report_completeness.py --campaign-check`). Run
the correlation engine **after** bulk_extractor has completed but **before**
cleaning up `./analysis/` — it reads raw TSK and bulk_extractor output files
directly.

---

## Report voice

Every FAST report follows the FanGetFameFast dual-register voice:

### Management summary
- No technical identifiers — no inode numbers, sector offsets, file paths
- Business-level language: what was found, when, and what the business impact was
- Example: *"Analysis of the server disk image found evidence that files were
  deleted after the shutdown event. Administrator-level activity was recorded
  in the file system timeline immediately before the deletion."*

### Technical body
- Precise identifiers: file paths, inode numbers, MAC times, hash values
- Scoped conclusions citing evidence source
- Example: *"Deleted file entry `* r/r 45678 (/Windows/Temp/dropper.exe)` identified
  in fls output. Deletion timestamp 08:07:02 EDT precedes the orderly shutdown
  sequence (as observed in disk timeline `./exports/fs_timeline.csv`).
  SHA256: `deadbeef...`.*"

**Claude: enhance and elaborate when necessary** — each report section carries this
instruction explicitly. Claude must add MITRE ATT&CK context, forensic significance,
cross-domain pivot suggestions, and recommended next analytical steps.

---

## Deep-Dive Pivot Instructions

When any of the following artifacts are encountered, Claude **must** execute the
corresponding follow-up steps **before** advancing to the next module. Log each
follow-up as its own `step` call with a descriptive title such as
`"Deep-dive: Browser history SQL query"`.

### Deep-dive pivot table

| Artifact | Mandatory Follow-Up Steps |
|----------|--------------------------|
| **Network capture file found** (`.pcap`, `.pcapng`, `.cap`, Wireshark/Ethereal saves, Cain captures, Network Monitor `.etl`) | Extract with `icat`, verify with `file`, then **invoke `/fan <path> --case-id <id>`** — see Cross-module auto-trigger section. |
| **Memory image or hibernation file found** (`hiberfil.sys`, `.mem`, `.vmem`, `.raw`, `.dmp`, `.lime`, `.vmss`) | Extract with `icat`, check size, then **invoke `/fame`** — see Cross-module auto-trigger section. Extract and string-grep `pagefile.sys` regardless. |
| **Prefetch file(s)** | Run `python3 -m prefetch_parser -d ./exports/prefetch/` or `PECmd.exe -d ./exports/prefetch/ --csv ./exports/` → extract first/last run time, run count, loaded DLLs. Flag apps run once or within the incident window. |
| **Browser History SQLite DB** | Run `sqlite3 ./exports/browser/**/History "SELECT url, title, visit_count, datetime(last_visit_time/1000000-11644473600,'unixepoch') as lv FROM urls ORDER BY last_visit_time DESC LIMIT 100;"` — surface domains, download URLs, and keyword matches to case IOCs. |
| **Mail client present** (Outlook Express `.dbx`, Outlook `.pst`/`.ost`, Thunderbird profile, Windows Mail, Lotus Notes `.nsf`) | Execute the Mail & Messaging Artifacts Workflow (below). |
| **Instant messaging / collaboration client present** (Skype `main.db`, Teams SQLite, Slack LevelDB, Discord, Signal, Telegram Desktop, MSN Messenger `.dat`) | Execute the Mail & Messaging Artifacts Workflow (below). |
| **IRC client present** (mIRC `mirc.ini`+`logs/`, HexChat `hexchat/logs/`, irssi `logs/`, XChat, Bersirc, Pirch, KVIrc) | Execute the IRC Client Artifacts Workflow (below). |
| **Office software present** (Microsoft Office, OpenOffice, LibreOffice, WPS Office, WordPerfect) **OR** user document files found (`.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`, `.odt`, `.ods`, `.odp`, `.rtf`, `.wpd`) | Execute the Office & Document Artifacts Workflow (below). |
| **Installed application (dual-use, RAT, C2 tool)** | Execute the Application Deep-Dive Workflow (below). |
| **EVTX files** | Run `chainsaw hunt ./exports/evtx/ --sigma rules/` or `python3 -m evtx` for: logon (4624/4625), service install (7045), process creation (4688), PowerShell script block (4103/4104), account creation (4720), scheduled task (4698). |
| **SAM / user accounts** | For every username found, run the User Correlation Workflow (below). |
| **Recycle Bin entries** | Recover `$R` content for executables and scripts. Map SID to username via SAM. Record `deleted_filepath` IOC for each entry via `--record-ioc`. |
| **PowerShell history commands** | Scan for: Base64 blobs (`-EncodedCommand`), download cradles (`IEX`, `Invoke-WebRequest`, `curl`, `wget`), credential access (`mimikatz`, `sekurlsa`, `lsass`), lateral movement (`Enter-PSSession`, `Invoke-Command`). Flag suspicious commands as events. |
| **Scheduled Tasks XML** | Parse trigger (schedule), action (binary path), and principal (account) for each task. Flag tasks pointing to `Temp`, `AppData`, `ProgramData`, or encoded command-line strings. |
| **SRUM database** | Run `srum-dump ./exports/srum/SRUDB.dat` or `python3 -m srudb_parser` → extract per-app network bytes sent/received + timestamps. Identify apps with anomalous outbound data volumes in the incident window. |
| **Amcache.hve** | Run `RegRipper` with `amcache` plugin or `RECmd.exe -f ./exports/registry/Amcache.hve` → correlates executable hash, first-seen timestamp, and path. Use to confirm execution of tools that were subsequently deleted. |

---

## Mail & Messaging Artifacts Workflow

When any mail client, newsgroup reader, instant messaging client, or collaboration
tool is found in `fls_output.txt` — or when the registry reveals a configured mail
account — execute the following steps **in full** before advancing. Log each step.

> **Detection first:** always search `fls_output.txt` before deciding which clients
> to extract. Do NOT assume only one client is present.

```bash
# Detect mail/messaging artifacts in fls output
grep -i "\.dbx\|\.pst\|\.ost\|\.wab\|\.eml\|mbox\|\.nsf" \
  ./analysis/storage/fls_output.txt
grep -i "Outlook Express\|Thunderbird\|profiles\|\.thunderbird\|Skype\|Teams\|Slack\|Discord\|Signal\|Telegram\|HexChat\|mIRC\|main\.db\|msnmsgr\|messenger" \
  ./analysis/storage/fls_output.txt
```

### Step 1 — Check the registry for configured accounts

Before extracting any mailbox files, read `NTUSER.DAT` for configured mail/news accounts.
This reveals account usernames, server addresses, and display names even when mailboxes are empty.

```python
# python-registry query — Internet Account Manager
import sys; sys.path.insert(0, "./lib")
from Registry import Registry
reg = Registry.Registry("exports/registry/NTUSER.DAT")
# Walk: Software\Microsoft\Internet Account Manager\Accounts
```

Key registry paths:

| Path | What it reveals |
|------|----------------|
| `NTUSER.DAT\Software\Microsoft\Internet Account Manager\Accounts\*` | OE/Windows Mail accounts: POP3/IMAP/SMTP server, username, display name, NNTP server |
| `NTUSER.DAT\Software\Microsoft\Office\*\Outlook\Profiles` | Outlook profile names |
| `NTUSER.DAT\Software\Skype\ProtectedStorage` | Skype account name |
| `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\UnreadMail` | Accounts with unread mail at last logon |
| `SOFTWARE\Microsoft\Windows Messaging Subsystem\Profiles` | MAPI profiles (Outlook) |

**Always record discovered account usernames and email addresses as IOCs.**

NNTP server subdomains often reveal geographic location (e.g., `news.dallas.sbcglobal.net`
→ Dallas TX). Record this as a `location_hint` note in the research step outcome.

### Step 2 — Extract mailbox files

```bash
mkdir -p exports/mail

# Outlook Express (Windows XP/2000/ME): .dbx files under
#   Documents and Settings\<user>\Local Settings\Application Data\
#   Identities\{GUID}\Microsoft\Outlook Express\
# Use icat for raw image access (no mount needed):
#   icat -o <offset> <image> <inode> > exports/mail/<name>.dbx
# Use file(1) to confirm each: "MS Outlook Express DBX file, N items"
# Note: $STANDARD_INFORMATION "Actual Size: 0" is a known artefact on some
# XP images — always check the $DATA attribute init_size via istat.

# Windows Address Book (.wab)
# Located at: AppData\Microsoft\Address Book\<user>.wab
# Contains contacts in a Jet/MAPI binary format. Extract with icat.
# Readable strings are sparse — use strings -e l (UTF-16LE) first,
# then fall back to a raw bytes scan. An empty WAB (no contacts) is normal.

# Microsoft Outlook (.pst / .ost)
# Located at: Documents and Settings\<user>\Local Settings\Application Data\
#   Microsoft\Outlook\*.pst  (personal store)
# Or: AppData\Local\Microsoft\Outlook\*.ost  (offline store, Vista+)
# Extract with icat. Parse with:
#   python3 -c "import pypff; pff=pypff.file(); pff.open('exports/mail/outlook.pst'); ..."
# Or use libpff-tools: pffexport exports/mail/outlook.pst

# Thunderbird
# Profile at: AppData\Roaming\Thunderbird\Profiles\<profile>\
# Contains: Inbox (mbox), Sent, Drafts, key4.db (passwords), logins.json
# Extract the whole profile folder. Parse mbox files with:
#   python3 -c "import mailbox; mb=mailbox.mbox('exports/mail/Inbox'); ..."

# Skype
# main.db at: AppData\Roaming\Skype\<username>\main.db  (SQLite)
# Query: SELECT chatname, author, body_xml, timestamp FROM Messages ORDER BY timestamp
# Also check: AppData\Local\Packages\Microsoft.SkypeApp_*\LocalCache\Roaming\Skype (Win10+)

# Microsoft Teams
# SQLite DBs at: AppData\Roaming\Microsoft\Teams\databases\
# LevelDB at:    AppData\Roaming\Microsoft\Teams\Local Storage\leveldb\
# Query with sqlite3 or parse leveldb with python-leveldb

# Slack
# LevelDB at: AppData\Roaming\Slack\Local Storage\leveldb\
# SQLite at:  AppData\Roaming\Slack\databases\

# Discord
# LevelDB at: AppData\Roaming\discord\Local Storage\leveldb\

# mIRC / HexChat logs
# mIRC:    Documents and Settings\<user>\Application Data\mIRC\logs\
# HexChat: AppData\Roaming\HexChat\logs\
# Plain text — grep directly
```

### Step 3 — Examine mailbox content

For each extracted mailbox file:

1. **Run `file` to confirm format and item count** — OE .dbx reports item count directly.
2. **Extract email headers** — search for From/To/Subject/Date:
   ```bash
   strings -n 8 exports/mail/<file>.dbx | \
     grep -E "^(From:|To:|Cc:|Subject:|Date:|Newsgroups:|X-Mailer:|Reply-To:|Return-Path:)"
   ```
3. **Extract message bodies** — search for IOC-relevant content:
   ```bash
   strings -n 8 exports/mail/<file>.dbx | grep -Ei "@|password|credential|login|token|cookie|auth"
   ```
4. **Check for newsgroup subscriptions** — OE creates one .dbx per subscribed newsgroup.
   Newsgroup names are themselves IOCs (e.g., `alt.2600.*` indicates hacker interest profile).
   Extract and check item counts for each; only examine those with content (item count > 0).
5. **Search for attacker-authored posts** — grep all newsgroup .dbx files for the
   attacker's confirmed email addresses. Messages FROM the attacker reveal aliases,
   intent, and targeting language.

### Step 4 — IM / chat client analysis

For SQLite-based clients (Skype, Teams, Slack, Discord):
```bash
# Skype
sqlite3 exports/mail/main.db \
  "SELECT datetime(timestamp,'unixepoch'), author, chatname, body_xml \
   FROM Messages ORDER BY timestamp DESC LIMIT 100;"

# Confirm contact list
sqlite3 exports/mail/main.db \
  "SELECT skypename, fullname, emails, lastonline_timestamp FROM Contacts;"
```

For log-based clients (mIRC, HexChat): `grep -i "incident_keywords" exports/mail/irc_logs/`

### Step 5 — Record findings

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Mail & Messaging Client Artifacts" \
  --action "icat extraction of <client> mailboxes + registry Internet Account Manager" \
  --why "<case-specific reason>" \
  --outcome "<accounts found, email addresses, mailbox item counts, notable messages>"
```

Record every email address, NNTP server, IM username, and server address as IOCs:
```bash
python3 lib/fast_machine_details.py --record-ioc email "<addr>" "RN-<step>" CONFIRMED
python3 lib/fast_machine_details.py --record-ioc domain "<nntp-server>" "RN-<step>" CONFIRMED
```

### Deviation cases

| Condition | What to do |
|-----------|-----------|
| No mail client found in fls output | Log as `Deviation: No mail client artifacts found — only web-based email indicated` and proceed |
| .dbx Actual Size = 0 but $DATA init_size > 0 | This is a known Windows XP artefact — extract with icat anyway and verify with `file` |
| .pst file > 500 MB | Extract with icat in background; parse only headers and subject lines first |
| Newsgroup .dbx files > 20 | Check item counts via `file` first; skip zero-item files |
| WAB is binary-only (< 1% ASCII) | Note it as empty/no-contacts; do not spend time parsing the Jet schema |

---

## User Correlation Workflow

Whenever a username, SID, or account name is discovered anywhere in the investigation,
execute the following steps **in full** before proceeding. Log each step separately.

1. **Record in research notes:** `python3 lib/research_notes.py step --title "User identified: <username>" ...`
2. **SAM correlation:** Look up the username in the SAM hive output (Section 3.2) — confirm full name, account flags, last logon, password last set.
3. **EVTX logon events:** Search extracted EVTX for Event ID 4624 (successful logon) and 4625 (failed logon) with this username → extract workstation name, logon type (2=interactive, 3=network, 10=remote interactive), and source IP.
4. **Browser profile:** Check `./exports/browser/` for a folder named after this username — if present, query the History DB for this user's browsing activity.
5. **Recycle Bin SID mapping:** Cross-reference Recycle Bin SIDs (Section 6b) with the SAM RID → SID mapping to attribute deleted files to this account.
6. **Email address search:** Search `./exports/carved/email.txt` (bulk_extractor output) for email patterns matching the username (e.g., `jdoe@*.`).
7. **Full-disk string search (mandatory):**
   ```bash
   # Search live mounted filesystem for any reference to the username
   grep -ril "<username>" "$FS_MOUNT" 2>/dev/null | head -50
   # Search raw image unallocated space for username strings
   strings -el "$DISK_IMAGE" | grep -i "<username>" | head -50
   ```
   For each hit outside expected profile paths (`Users/<username>/`, `SAM`, `EVTX`),
   investigate the containing file: what application wrote it? What does the file reveal?
8. **Consolidated identity profile:** Record in research notes:
   ```
   Username: <uname>  Full name: <fname>  SID: <sid>
   Last logon: <ts>  Logon count: <n>  Password last set: <ts>
   Email: <if found>  Browser profile: <yes/no>
   Recycle Bin activity: <yes/no>
   Extra disk hits: [<path1>, <path2>, ...]
   ```
9. **Record IOC:** `python3 lib/fast_machine_details.py --record-ioc username "<username>" "RN-<step>" CONFIRMED`

---

## IRC Client Artifacts Workflow

IRC clients store identity, server preferences, channel memberships, and plaintext chat logs.
Execute when any IRC binary or log directory is present in `fls_output.txt`.

### Detection

```bash
grep -i "mirc\|hexchat\|xchat\|irssi\|pirch\|kvirc\|bersirc\|chatzilla\|/logs/.*\.log" \
  ./analysis/storage/fls_output.txt
```

### Step 1 — Extract identity from config file

| Client | Config file | Key fields |
|--------|------------|-----------|
| mIRC | `Program Files/mIRC/mirc.ini` | `[mirc]` section: `user`, `email`, `nick`, `anick`; `[ident]` section: `userid`, `system`; `[mirc]` section: `host` (default server); `[fileserver]` section: `homedir` |
| HexChat | `AppData\Roaming\HexChat\hexchat.conf` | `irc_nick1`, `irc_nick2`, `irc_real_name`, `irc_user_name` |
| irssi | `AppData\Roaming\.irssi\config` | `nick`, `real_name`, `user_name` |

**Record all aliases (nick, alternate nick, ident userid) as IOCs** — they are operational identities that may appear in external logs, IRC archives, or court records.

**DCC file server**: if `[fileserver] homedir=` is set in mirc.ini, the client was configured to serve files to other IRC users from that directory. Check whether the configured directory contains case-relevant files.

### Step 2 — Extract and read all channel logs

```bash
mkdir -p exports/irc

# mIRC logs are in Program Files/mIRC/logs/ — one file per channel
# File naming: #channelname.NetworkName.log  (channel)
#              nickname.NetworkName.log       (private message)
# Extract with icat using inodes from fls output:
# icat -o <offset> <image> <inode> > "exports/irc/<filename>"
```

For each log file, look for:
1. **Messages FROM the attacker** (using their confirmed nicks) — reveals intent, targeting language, accomplices
2. **Private messages** (files without `#` prefix = DMs) — highest intelligence value
3. **Channel topics** — shell-trading channels (`#ushells`, `#LuxShell`, etc.) confirm acquisition of remote access
4. **Repeated test strings across channels** — a pattern like posting the same string to multiple channels within minutes indicates automated channel scanning for open shells or DCC servers
5. **URLs and server addresses** shared in channel

### Step 3 — Extract server list and channel list

```bash
# mIRC servers.ini — lists all configured IRC networks and servers
# mIRC channels/channels.txt — saved channel listing (may be a downloaded Usenet-style full list)
# Check for custom-added servers beyond defaults
```

### Step 4 — Check for saved passwords and automation scripts

```bash
# mIRC remote.ini — scripting/event handlers (may contain automated commands)
# mIRC popups.ini — right-click menu (custom commands reveal operational workflow)
# mIRC aliases.ini — shortcut commands
# HexChat: servlist.conf stores server passwords
```

### Deviation cases

| Condition | What to do |
|-----------|-----------|
| No IRC client in fls output | Log as `Deviation: No IRC client artifacts found` and proceed |
| Log files present but all empty/tiny | Note sessions were brief or logging was disabled; check `[log]` section in mirc.ini for `logmode` setting |
| channels.txt is very large (>100KB) | It is a downloaded full server channel listing, not personal favorites; skip content analysis, note its presence |

---

## Office & Document Artifacts Workflow

Execute when Office software is installed **or** when user document files (`.doc`, `.xls`, `.ppt`, `.odt`, `.rtf`, etc.) are found in user profile directories.

### Step 1 — Confirm what is (and is not) installed

```bash
# Check SOFTWARE registry Uninstall keys
# If no Office found, note explicitly: "No Microsoft Office, OpenOffice, or LibreOffice installed"
# This is a significant finding on a workstation — it confirms the machine was a dedicated
# attack platform rather than a general-purpose work computer.
```

### Step 2 — Find all user-created documents

```bash
# Scan fls output for document extensions in user directories
grep -i "\.doc\b\|\.docx\|\.xls\b\|\.xlsx\|\.ppt\b\|\.pptx\|\.odt\|\.ods\|\.odp\|\.rtf\b\|\.wpd\|\.wps" \
  ./analysis/storage/fls_output.txt | \
  grep -i "Documents and Settings\|Users\|Desktop\|My Documents\|Downloads"
```

**Distinguish user-created files from bundled documentation:**
- Files under `Program Files/<appname>/` are almost always app documentation — note them but do not prioritise
- Files under `Documents and Settings/<user>/` or `Users/<user>/` are user-created — prioritise
- Template files under `*/Templates/*.doc|xls|ppt` are Windows OEM defaults — dismiss

### Step 3 — Extract and analyse user documents

For each user-created document found:

```bash
# Extract with icat, then inspect:
icat -o <offset> <image> <inode> > exports/docs/<filename>

# Check metadata (author, company, last modified by, revision history):
python3 -c "
import zipfile, json
# For .docx/.xlsx/.pptx (OOXML):
with zipfile.ZipFile('exports/docs/file.docx') as z:
    props = z.read('docProps/core.xml').decode()
    print(props)
"
# For legacy .doc/.xls/.ppt (OLE/CFB format):
strings -n 8 exports/docs/file.doc | grep -iE "author|company|created|modified|revision|subject|title|lastauthor"

# Check for embedded macros (legacy formats):
file exports/docs/file.doc   # should say "Microsoft Word" or "Composite Document File"
strings -n 8 exports/docs/file.doc | grep -i "macro\|vba\|auto_open\|auto_close\|shell\|cmd\|wscript"
```

**Metadata in Office documents can reveal:**
- Author's real name or username (may differ from the OS account)
- Company name (employer or target organization)
- Last saved by (confirms who last edited — useful for documents copied from a target)
- Creation date vs. last modified date (gap may indicate stolen documents)
- Revision count (high count on a new file may indicate copied content)

### Step 4 — Check Office application data for recent files lists

```bash
# NTUSER.DAT: recent file lists per Office application
# HKCU\Software\Microsoft\Office\<version>\<app>\File MRU
# HKCU\Software\Microsoft\Office\<version>\<app>\Place MRU
# HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
# These reveal documents opened even if the documents were deleted
```

### Step 5 — Record findings

```bash
python3 lib/research_notes.py step \
  --title "Office Software & Document Artifacts" \
  --action "SOFTWARE registry check; fls grep for doc/xls/ppt/odt; icat extraction and metadata analysis" \
  --why "<case-specific: e.g., looking for stolen documents, attacker-authored plans, or evidence of data staging>" \
  --outcome "<Office installed/not installed; N user documents found; metadata summary>"
```

If Office is **not** installed: note this explicitly — the absence of productivity software on a workstation is a significant finding that helps characterise the machine's intended role.

---

## Application Deep-Dive Workflow

When an installed application, executed binary, or service is flagged as interesting
(dual-use tool, remote access utility, credential manager, P2P client, VPN client,
anonymiser, packet sniffer, mail client, IM client):

### Step 1 — Locate the binary (do NOT assume standard paths)

Work through these sources in order — stop when the path is confirmed:

1. **Prefetch:** check the prefetch file for this executable — the embedded path shows the actual launch location.
2. **EVTX 4688:** check process creation event log — the `CommandLine` field shows the full path used at runtime.
3. **Registry `InstallLocation`:** check `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\<app>\InstallLocation` — may be empty or stale.
4. **Full filesystem search (last resort):**
   ```bash
   find "$FS_MOUNT" -iname "<appname>*.exe" 2>/dev/null
   find "$FS_MOUNT" -iname "<appname>*.dll" 2>/dev/null
   ```
   Also search common non-standard locations: `$FS_MOUNT/Users/*/AppData/Roaming/`, `$FS_MOUNT/ProgramData/`, `$FS_MOUNT/Windows/Temp/`, `$FS_MOUNT/Temp/`.

### Step 2 — Find configuration and log data (do NOT assume AppData)

Once the binary path is known:
1. Scan the directory containing the binary and all subdirectories for: `.ini`, `.cfg`, `.json`, `.xml`, `.db`, `.log`, `.conf`, `.dat`.
2. Run a full-disk string search for the app name:
   ```bash
   grep -ril "<appname>" "$FS_MOUNT" 2>/dev/null | grep -v "^$FS_MOUNT/Windows/WinSxS"
   ```
   This catches references in other apps' config files, log files, registry transaction logs, and temp files.
3. Check `AppData\Roaming\<AppName>\` and `AppData\Local\<AppName>\` as **secondary** locations only — many apps store data elsewhere.
4. Check `ProgramData\<AppName>\` for system-wide configuration and logs.

### Step 3 — Evidence gathering

- **Execution:** confirm via Prefetch (run count, first/last timestamp) and SRUM (network bytes attributed to this executable).
- **Network:** SRUM gives per-app bytes sent/received + timestamps. Cross-reference with FAN PCAP if available.
- **Download:** search browser history for the installer download URL.
- **Configuration:** read any config files found — document server addresses, credentials, proxy settings.

### Step 4 — Record findings

```bash
python3 lib/research_notes.py step \
  --title "Application deep-dive: <AppName>" \
  --action "Binary at <path>; config at <path>; SRUM: <N> bytes sent" \
  --why "<case-specific reason: why this app is suspicious>" \
  --outcome "<what was found — configuration, logs, network activity, IOCs>"
```

Record any server addresses, C2 URLs, or credential material found as IOCs:
```bash
python3 lib/fast_machine_details.py \
  --record-ioc url "<server-url>" "RN-<step>" CONFIRMED
```

Tag with the appropriate MITRE ATT&CK technique (e.g., T1219 Remote Access Software,
T1552 Unsecured Credentials, T1048 Exfiltration Over Alternative Protocol).

---

## IOC Recording

Whenever Claude surfaces a new finding (IP address, username, file path, URL, hash,
application name), it **must** call the IOC recorder before advancing to the next step:

```bash
python3 lib/fast_machine_details.py \
  --record-ioc <category> "<value>" "<step-label>" <confidence>
```

| Category | Examples |
|----------|---------|
| `ip` | `192.168.1.5`, `10.0.0.1` |
| `mac` | `00:11:22:33:44:55` |
| `domain` | `evil.example.com` |
| `url` | `https://c2.attacker.com/payload` |
| `username` | `jdoe`, `Administrator` |
| `fullname` | `John Doe` |
| `email` | `jdoe@company.com` |
| `filepath` | `C:\Users\jdoe\AppData\Temp\payload.exe` |
| `deleted_filepath` | `C:\Windows\Temp\dropper.exe` (from Recycle Bin) |
| `hash` | `deadbeef...` (SHA-256 of artifact) |
| `suspicious_app` | `AnyDesk`, `PuTTY`, `nmap` |
| `registry_key` | `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\malware` |
| `scheduled_task` | `\Microsoft\Windows\fakeupdate` |

Step label format: `"RN-<step-number>"` when tied to a research note step,
or `"machine_details-<source>"` for items from the automated registry extraction.

---

## MITRE ATT&CK techniques detected by FAST

| Technique | Name | What triggers it |
|-----------|------|-----------------|
| T1070.004 | File Deletion | Deleted entries in fls output |
| T1070.001 | Clear Windows Event Logs | Gaps in EVTX file timestamps or cleared log entries |
| T1564.003 | NTFS File Attributes | ADS streams or hidden attribute artifacts |
| T1048 | Exfiltration Over Alternative Protocol | URLs/domains in bulk_extractor carved output |
| T1547.001 | Registry Run Keys / Startup Folder | Persistence keys found in registry artifacts |
| T1053.005 | Scheduled Task/Job | Suspicious XML in extracted scheduled tasks |
| T1112 | Modify Registry | Non-baseline registry modifications |
| T1055 | Process Injection | Executable code in MFT slack space or ADS |

---

## Output paths

| Output | Path |
|--------|------|
| ewfinfo / ewfverify | `./analysis/storage/ewfinfo.txt`, `ewfverify.txt` |
| Partition table (mmls) | `./analysis/storage/mmls.txt` |
| Filesystem metadata (fsstat) | `./analysis/storage/fsstat.txt` |
| FLS output (incl. deleted) | `./analysis/storage/fls_output.txt` |
| Bodyfile | `./analysis/storage/bodyfile.txt` |
| Filesystem timeline | `./exports/fs_timeline.txt` / `.csv` |
| MFT + UsnJrnl | `./exports/mft/$MFT`, `./exports/mft/$J` |
| Event logs | `./exports/evtx/` |
| Registry hives | `./exports/registry/` |
| Prefetch | `./exports/prefetch/` |
| SRUM | `./exports/srum/` |
| Carved artifacts | `./exports/carved/` |
| Mail & messaging artifacts | `./exports/mail/` |
| Machine details JSON | `./exports/machine_details/machine_details.json` |
| Recycle Bin parsed JSON | `./exports/recyclebin/recyclebin_parsed.json` |
| IOC reference JSON | `./exports/machine_details/iocs.json` |
| PowerShell history | `./exports/machine_details/ps_history.txt` |
| Markdown report | `./reports/<case_id>_fast_report.md` |
| PDF report | `./reports/<case_id>_fast_report.pdf` |
| PowerPoint (PPTX) | `./reports/<case_id>_fast_presentation.pptx` |
| Word document (DOCX) | `./reports/<case_id>_fast_report.docx` |
| Combined report | `./reports/<case_id>_combined_report.md` etc. |

---

## Vault integration

FAST writes confirmed findings to the Obsidian vault automatically:

| Finding | Vault Note | MITRE ID |
|---------|------------|----------|
| Deleted executable in user path | `TTPs/T1070.004.md` + `IOCs/<hash>.md` | T1070.004 |
| Cleared event log | `TTPs/T1070.001.md` | T1070.001 |
| Registry persistence key | `TTPs/T1547.001.md` | T1547.001 |
| Suspicious URL (carved) | `IOCs/url-<defanged>.md` | — |
| Scheduled task (malicious XML) | `TTPs/T1053.005.md` | T1053.005 |

```bash
# Verify vault entries
./scripts/vault_context.sh ttp T1070
./scripts/vault_context.sh cases
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| ewfmount fails | Missing libewf | `sudo apt install libewf-dev ewf-tools` |
| mount fails (dirty) | NTFS journal dirty | Add `norecovery` to mount options |
| Wrong file listing | Wrong byte offset | Re-check `img_stat` sector size; recalculate offset |
| fls shows no deleted files | Filesystem was wiped | Run `blkls -u` for carving; use `photorec` |
| mactime empty | bodyfile is empty | Verify `fls -r -m /` wrote content |
| pptx or docx not generated | Missing Python package | `pip3 install python-pptx python-docx` |
| Upload skipped: "vault not configured" | `INVESTIGATIONS_SSH_HOST`/`INVESTIGATIONS_ROOT` unset | Run `./scripts/configure_vault.sh user@host /remote/root` (see `templates/set_env_template.sh`); reports stay in `./reports/` until then |
| Upload SSH error | Configured vault host unreachable | Check connectivity to `$INVESTIGATIONS_SSH_HOST`; use `--no-upload` |
| bulk_extractor slow | Large image | Limit to targeted features: `-e url -e domain -e email` |

---

## Evidence integrity constraints

- **Never write to `/mnt/`, `/media/`, or any `evidence/` directory.**
- All mounts are read-only (`ro,loop` or `ro,loop,norecovery`).
- Analysis WIP goes to `./analysis/storage/` only.
- Extracted artifacts go to `./exports/`.
- The `./analysis/` folder must be empty after a completed investigation
  (artifacts move to the investigations vault via upload).
- Report timestamps use the timezone of the incident's geographical location.
  If unknown, use UTC and state it explicitly in the report.
