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

| Output | Format | Path |
|--------|--------|------|
| Technical report | Markdown | `./reports/<case_id>_fast_report.md` |
| Technical report | PDF | `./reports/<case_id>_fast_report.pdf` |
| Management briefing | Microsoft PowerPoint (.pptx) | `./reports/<case_id>_fast_presentation.pptx` |
| Full report | Microsoft Word (.docx) | `./reports/<case_id>_fast_report.docx` |
| Combined (all modules) | Markdown + PDF + PPTX + DOCX | `./reports/<case_id>_combined_*` |

---

## Research Notes

Every FAST investigation produces a **research notes file** (`./reports/<case_id>_research_notes.md`)
alongside the formal report. The notes are a timestamped, step-by-step investigative log that lets

> **MANDATORY RULE: Do NOT proceed to the next analysis step until the current step has been
> documented in the research notes via `python3 lib/research_notes.py step ...`. Running a tool
> and immediately launching the next one without logging is not permitted. Read the output,
> interpret it, call `step`, then advance.**
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
  --action "ewfverify /path/to/image.E01 → ./analysis/storage/ewfverify.txt" \
  --why "Hash verification confirms evidence integrity — required before any findings can be cited in legal proceedings" \
  --outcome "MD5 and SHA1 hashes verified successfully. No corruption detected." \
  [--raw "verification output if it shows errors or unexpected checksums"]
```

**Steps that each require a `step` call (in order):**

| Step | Title | Why (use this verbatim) |
|------|-------|-------------------------|
| Image verification | `Image Verification (ewfinfo + ewfverify)` | Hash verification confirms evidence integrity — required before findings can be cited in legal or regulatory proceedings |
| Image mount | `Image Mount (ewfmount / qemu-nbd)` | Read-only mount makes the image accessible for TSK tools without risk of modification |
| Partition inspection | `Partition Table (mmls)` | Identifies partition boundaries and start sectors needed to calculate filesystem byte offset |
| Filesystem mount | `Filesystem Mount (read-only)` | Provides direct file system access for artifact extraction; norecovery flag preserves forensic state |
| File listing | `File Listing (fls)` | Recursive listing including deleted entries (marked `*`) — foundation for all subsequent artifact identification |
| Bodyfile generation | `Bodyfile (fls -m)` | MAC-time bodyfile is the input for mactime timeline generation — captures every file system timestamp |
| Timeline | `Filesystem Timeline (mactime)` | Chronological view of all file system activity — primary tool for event sequencing and anomaly detection |
| Filesystem stats | `Filesystem Metadata (fsstat)` | Captures volume label, creation date, cluster size, and last mount time — contextualises the file system state |
| Inode listing | `Inode Listing (ils)` | Lists all inodes including orphaned (unlinked) ones — finds files that have been deleted but whose data blocks remain |
| Event logs | `Event Log Extraction (EVTX)` | Windows event logs contain authentication, process creation, and service events — primary source for Windows activity reconstruction |
| Registry hives | `Registry Extraction (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)` | Registry hives contain persistence keys, user activity, network configuration, and installed software history |
| Prefetch | `Prefetch Extraction` | Prefetch files record executable run counts and timestamps — confirms program execution even after deletion (T1070.004) |
| MFT | `MFT Extraction (icat inode 0)` | The Master File Table records every file's metadata — complete even for deleted entries; analysed by tools like MFTECmd |
| USN Journal | `USN Journal Extraction (icat inode 11)` | Change journal records file create/delete/rename/modify events — fills gaps in the filesystem timeline |
| SRUM | `SRUM Extraction (SRUDB.dat)` | System Resource Usage Monitor records per-application network and CPU usage — confirms process execution with timestamps |
| Browser history | `Browser History Extraction` | Chrome / Edge history files reveal web activity, downloads, and search queries relevant to initial access or exfiltration |
| Scheduled tasks | `Scheduled Task Extraction` | Scheduled task XML files reveal persistence mechanisms and their trigger conditions (T1053.005) |
| Recycle Bin | `Recycle Bin Extraction` | Deleted file metadata in `$Recycle.Bin` records original path and deletion time — evidence of file removal (T1070.004) |
| Amcache | `Amcache Extraction` | Amcache.hve records SHA1 hashes and first-execution times for every binary run — confirms execution of files that no longer exist on disk |
| File carving | `File Carving (bulk_extractor)` | Signature-based carving of unallocated space recovers deleted files, emails, URLs, and credentials not visible in the active file system |
| OpenCTI enrichment | `Threat Intelligence Enrichment (OpenCTI)` | Correlates carved URLs, file hashes, and domains against known threat actors and malware campaigns |
| Cross-module check | `Cross-module Correlation (FAN / FAME)` | Checks whether FAN or FAME reports exist for this case — surfaces kill-chain connections across network, memory, and disk |

**Use `--raw` only when the output contains significant findings** (deleted executables, suspicious
registry keys, carved C2 URLs, EVTX gaps, unusual scheduled tasks). For clean / expected output,
omit `--raw` and summarise in `--outcome`.

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
  --md ./reports/<case_id>_fast_report.md \
  --pdf ./reports/<case_id>_fast_report.pdf \
  --pptx ./reports/<case_id>_fast_presentation.pptx \
  --docx ./reports/<case_id>_fast_report.docx \
  --notes ./reports/<case_id>_research_notes.md
```

---

## Invocation

```bash
# Standard run (interactive — prompts for case ID)
./scripts/fast_analyze.sh /path/to/image.E01

# Non-interactive
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001

# With explicit hostname
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234

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

FAST automatically detects and incorporates FAN and FAME reports when they exist
for the same case ID. The combined report surfaces:

| Correlation | What it means |
|-------------|---------------|
| FAST ↔ FAME | Process image path in memory found deleted on disk — persistence or clean-up indicator |
| FAST ↔ FAN | URLs carved from disk match DNS queries in PCAP — confirms C2 contact method |
| FAN + FAME + FAST | Full kill chain: network delivery → memory execution → disk persistence |

To manually trigger a combined report after all modules have run:

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
