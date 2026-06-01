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
| Technical report | Markdown | `./reports/<case_id>_fast_report.md` | Always |
| Investigative log | Markdown | `./reports/<case_id>_research_notes.md` | Always |
| Technical report | PDF | `./reports/<case_id>_fast_report.pdf` | Standalone only |
| Management briefing | Microsoft PowerPoint (.pptx) | `./reports/<case_id>_fast_presentation.pptx` | Standalone only |
| Full report | Microsoft Word (.docx) | `./reports/<case_id>_fast_report.docx` | Standalone only |

The unified cross-case report (`CAMPAIGN_<batch_id>_report.*`) is generated once at the
end of a batch by `/investigate-all` — not per individual FAST case.

---

## Research Notes

Every FAST investigation produces a **research notes file** (`./reports/<case_id>_research_notes.md`)
alongside the formal report. The notes are a timestamped, step-by-step investigative log that lets

> **MANDATORY RULE: Do NOT proceed to the next analysis step until the current step has been
> documented in the research notes via `python3 lib/research_notes.py step ...`. Running a tool
> and immediately launching the next one without logging is not permitted. Read the output,
> interpret it, call `step`, then advance.**

> **MANDATORY DEVIATION LOGGING: Any time the analysis deviates from the standard workflow —
> a step is skipped, a fallback is used, a tool returns unexpected results, or an analytical
> decision is made that differs from the normal path — this MUST be logged as its own `step`
> call with `--title "Deviation: <what changed>"`. Examples that require a deviation step:**
>
> - `ewfmount` fails → `step --title "Deviation: ewfmount failed — using qemu-nbd instead"`
> - Filesystem mount fails (dirty NTFS) → `step --title "Deviation: dirty filesystem — added norecovery flag"`
> - `fls` returns no deleted entries → `step --title "Deviation: no deleted entries — filesystem may have been wiped; proceeding with blkls + photorec"`
> - Artifact not present (Prefetch, SRUM, etc.) → `step --title "Deviation: Prefetch absent — possible T1070.004 or non-Windows image"`
> - A tool crashes or times out → `step --title "Deviation: <tool> failed — reason and workaround"`
>
> The deviation log ensures any analyst reading the notes understands WHY the investigation
> took a different path and can reproduce or challenge that decision.
any analyst follow the complete workflow, rationale, and findings from start to finish.

**Three calls to make during every investigation:**

### 1 — At investigation start (before running any tools)

```bash
python3 lib/research_notes.py init \
  --case-id <case_id> \
  --module fast \
  --evidence /path/to/image.E01 \
  --hostname <hostname>
```

### 2 — After reading and interpreting each tool output

Call `step` once per analysis action, immediately after Claude has read and understood the output:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Image Verification (ewfverify)" \
  --action "ewfverify /path/to/image.E01 → <case_id>_evidence/storage/ewfverify.txt" \
  --why "<case-specific reason — see guidance below>" \
  --outcome "MD5 and SHA1 hashes verified successfully. No corruption detected. [source: <case_id>_evidence/storage/ewfverify.txt]" \
  --dismissed "<what you inspected and decided was not significant — see guidance below>" \
  [--raw "verification output if it shows errors or unexpected checksums"]
```

**`--why` — write the case-specific reason, not a generic tool description.** Explain the hypothesis you are testing or the question you are answering *at this moment in this investigation*. Do not restate what the tool does.
> ✗ Generic (do not write): `"Hash verification confirms evidence integrity — required before any findings can be cited in legal proceedings"`
> ✓ Case-specific (write this): `"Verifying hash before analysis — reported incident window is 08:00–09:00 UTC; if hashes mismatch, the image may have been altered after acquisition and all findings would be inadmissible"`

**`--dismissed` (optional but expected for every step):** Note what you observed in the output and decided was not suspicious, and your reason. Omit only when the output is completely empty.
> Examples:
> - `"fls returned 14 000 entries; no deleted entries in system32 or program files — attacker cleanup, if any, was confined to temp directories"`
> - `"mactime shows no file activity outside 08:00–09:00 UTC window — no evidence of persistence installed outside the incident timeframe"`
> - `"browser history present but all domains are legitimate corporate sites; no C2 or phishing domains identified"`

**Traceability convention:** always reference the **preserved evidence path** (`<case_id>_evidence/storage/<tool>.txt`) in both `--action` and at the end of `--outcome` as `[source: <case_id>_evidence/storage/<tool>.txt]`. This survives the `./analysis/` cleanup and unambiguously links each research-notes step to the artifact that produced it.

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
| Scheduled tasks | `Scheduled Task Extraction` | State whether you expect persistence via scheduled tasks based on findings so far |
| Recycle Bin | `Recycle Bin Extraction` | State whether file deletion was suspected from fls output and what files you expect to find |
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

Whenever TSK tools, MFT analysis, EVTX parsing, prefetch records, or bulk_extractor output
reveals an action **performed by the attacker** — and that action has a **confirmed
timestamp from the evidence** — log it immediately using the `event` subcommand:

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

**Rules:**
- **Only call `event` if there is a confirmed timestamp** from an artifact (MAC time,
  event log timestamp, prefetch execution time, USN journal entry). Do not estimate.
- If a significant finding has **no confirmed timestamp**, log it as a `step` instead and
  do NOT call `event`. It will appear in the *Unconfirmed Findings* section of the report.
- `--severity critical` — direct evidence of compromise, active malware, ransomware execution
- `--severity high` — deleted executables, privilege escalation artefacts, persistence keys
- `--severity medium` — anomalies that may be benign but require follow-up
- `--source` must name the specific artifact (inode, MFT entry, registry path, file path)

### 3 — Pre-finalize open leads review (mandatory)

Before calling `finalize`, read the complete research notes file from top to bottom:

```bash
cat ./reports/<case_id>_research_notes.md
```

For every finding marked `[ASSUMPTION]`, every event without a confirmed timestamp, and every
`--dismissed` observation, ask: does the complete picture explain this, or does it remain open?
Then write the second reflect entry:

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Pre-finalize complete case review" \
  --reinterpret "<final pass: state any step that needs reinterpretation given the full picture — or: 'All steps consistent with final conclusion'>" \
  --open-leads "<what this investigation cannot resolve alone — specify what evidence (FAME memory image, FAN PCAP, sandbox detonation) would change or confirm the conclusion>"
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
  --md    ./reports/<case_id>_fast_report.md \
  --notes ./reports/<case_id>_research_notes.md
```

**If `--md-only` was NOT set (standalone run) — all formats were generated:**
```bash
python3 lib/investigations_upload.py \
  --case-id <case_id> \
  --md    ./reports/<case_id>_fast_report.md \
  --pdf   ./reports/<case_id>_fast_report.pdf \
  --pptx  ./reports/<case_id>_fast_presentation.pptx \
  --docx  ./reports/<case_id>_fast_report.docx \
  --notes ./reports/<case_id>_research_notes.md
```

---

## Narrative file (required before report generation)

After all TSK / EWF / bulk_extractor steps are complete and **before** calling
`python3 lib/generate_fast_report.py`, Claude must write the narrative file:

```
./reports/<case_id>_narrative.md
```

This file feeds the Incident Timeline section, the enhanced technical chapters,
and all five board-deck slides in the PPTX.

### Schema (copy exactly, fill every section)

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

## pptx_executive_summary

[3–5 bullet points. CISO language. No file paths, inode numbers, or hash values.
Example: "• Evidence of file deletion was found on the server disk image.
• The deletion timestamps coincide with the reported incident window.
• No evidence of data exfiltration to external locations was found."]

## pptx_risk

[Business risks: data integrity, regulatory, operational, reputational.
No technical identifiers.]

## pptx_impact

[What was affected: systems, users, services, data. Business language.]

## pptx_mitigations

[What has already been done and what is in progress.]

## pptx_recommendations

[Concrete follow-up actions with suggested owner labels (CISO / IT / Legal).]
```

### Rules
- Write **all** sections even if evidence is thin.
- Keep management sections (`pptx_*`) free of file paths, inode numbers, sector offsets, or hash values.
- Use RN-NNN references in `attack_timeline` to link back to research notes.

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

## Cross-module correlation

Run the correlation engine **after** bulk_extractor has completed but **before**
cleaning up `./analysis/` — it reads raw TSK and bulk_extractor output files directly:

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

After running correlate, trigger the combined report to embed the findings:

```python
import sys; sys.path.insert(0, "./lib")
from generate_combined_report import generate

paths = generate(case_id="CASE-2026-001", hostname="SERVER1234")
```

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
| Upload SSH error | ubuntudesktop unreachable | Check connectivity; use `--no-upload` |
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
