# Skill: investigate-all — Batch evidence analysis (in-session)

## Overview

**investigate-all** runs FAME (memory) and FAST (disk) forensics against every
evidence file in a directory, invoking the `/fame` and `/fast` skills directly
in the current session — no child `claude` processes, no background agents.

Because everything runs in-session:
- Permission prompts appear once per tool category; the analyst can "allow always
  for this session" and the rest of the batch runs unattended.
- Research notes, reports, and vault writes happen in real time and are visible
  in the active window.
- The analyst can interrupt, redirect, or add context at any point.

### Invocation

```
/investigate-all [evidence_dir]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `evidence_dir` | `/home/vscode/evidence` | Root of the evidence tree |

---

## Step 1 — Enumerate evidence files

Run this command to build the complete file list:

```bash
find "<evidence_dir>" -type f | sort
```

Categorise every file by extension:

| Extension | Module | Notes |
|-----------|--------|-------|
| `.7z` `.zip` | FAME | Archive — skill extracts internally to `/tmp/` |
| `.mem` `.img` `.raw` `.lime` `.vmem` `.dmp` | FAME | Direct image |
| `.E01` `.ewf` `.vmdk` `.vdi` `.qcow2` `.vhd` `.vhdx` | FAST | Disk image |
| `.pcap` `.pcapng` `.cap` | FAN | Use `/fan-*` skills (not covered here) |

**Deduplication rule:** If both an archive (`.7z`/`.zip`) and a pre-extracted
image with the same stem exist in the evidence tree (e.g.
`base-wkstn-06-memory.7z` and `base-wkstn-06-memory/base-wkstn-06-memory.img`),
**use the archive and skip the pre-extracted file** — they are the same content.
Record the skip decision in a note before continuing.

---

## Step 2 — Build the case table and prompt for batch ID

For each evidence file, derive:

| Field | Derivation rule |
|-------|-----------------|
| **Case ID** | `FAME-YYYY-<STEM>` or `FAST-YYYY-<STEM>` where `<STEM>` is the filename without extension, uppercased, hyphens preserved. Use the current year for `YYYY`. |
| **Hostname** | Strip common suffixes from the stem: `-memory`, `-mem`, `-cdrive`, `-c-drive`, `-snapshot<N>`. The remainder is the hostname. Examples: `base-admin-memory` → `base-admin`; `base-dc-cdrive` → `base-dc`; `base-file-snapshot5` → `base-file`. |
| **Module** | `FAME` or `FAST` per the extension table above. |

Also propose a **Batch ID** for the unified report. Derive it from the evidence directory name or the common hostname prefix, uppercased. Example: evidence in `shieldbase/` → `SHIELDBASE-2026`. If no clear prefix exists, use `BATCH-YYYY-MM-DD` with today's date.

Present the full case table and proposed Batch ID to the analyst before running any analysis. Example:

```
# Case table — 29 cases   |   Batch ID: SHIELDBASE-2026

| # | File | Module | Case ID | Hostname |
|---|------|--------|---------|----------|
| 1 | memory/base-admin-memory.7z | FAME | FAME-2026-BASE-ADMIN-MEMORY | base-admin |
...
```

Ask the analyst to confirm or adjust case IDs / hostnames / Batch ID before proceeding.
A single "looks good" or "go ahead" is sufficient to proceed.

Once the analyst confirms, **immediately create the campaign folder** that will hold all
outputs for this batch:

```bash
mkdir -p ./reports/<BATCH_ID>
```

Announce:
> Campaign folder created: `./reports/<BATCH_ID>/`. All reports for this batch will be
> moved here after each case completes.

If `./reports/<BATCH_ID>/` already exists (e.g. resuming an interrupted batch), warn
the analyst and ask whether to continue into it or choose a different Batch ID before
proceeding.

---

## Step 3 — Run cases sequentially

Invoke cases one at a time. For each case:

### FAME case

```
/fame <absolute_path_to_file> --case-id <CASE_ID> --hostname <hostname> --md-only
```

Wait for the `/fame` skill to complete fully (research notes finalized, report
generated, upload done) before starting the next case.

### FAST case

```
/fast <absolute_path_to_file> --case-id <CASE_ID> --hostname <hostname> --md-only
```

Wait for the `/fast` skill to complete fully before starting the next case.

**Order:** Run all FAME cases first (sorted alphabetically by filename), then
all FAST cases. This order is recommended but not required — adjust if the
analyst specifies otherwise.

**After each case:** announce completion with a one-line summary:
> Case N/29 FAME-2026-BASE-DC complete — [one-sentence finding]

Then move all files produced by that case from `./reports/` root into the campaign folder:

```bash
# Move per-case report files (adjust <CASE_ID> to the actual case ID)
mv ./reports/<CASE_ID>_* ./reports/<BATCH_ID>/ 2>/dev/null

# Move the evidence subdirectory if it exists
[ -d "./reports/<CASE_ID>_evidence" ] && \
    mv ./reports/<CASE_ID>_evidence ./reports/<BATCH_ID>/
```

Then immediately start the next case without waiting for analyst input.

---

## Step 4 — Post-batch verification

After all cases have completed:

1. List all case folders in the investigations vault:
   Use MCP tool `investigations_list_cases` (or `investigations_list_directory`)

2. Verify `./analysis/` is empty:
   ```bash
   ls ./analysis/
   ```
   The FAME and FAST pipelines clean up WIP after each case. Any leftover files
   indicate a failed or interrupted case.

3. List generated reports:
   ```bash
   ls -lh ./reports/<BATCH_ID>/ | grep -E "(fame_report\.md|fast_report\.md|research_notes)"
   ```
   Individual case reports are MD + research notes only (`--md-only` was set for each batch case).

4. Report a final summary table:

```
# Batch complete — <N> cases

| Case ID | Module | Status | Key finding |
|---------|--------|--------|-------------|
| FAME-2026-BASE-ADMIN | FAME | done | ... |
...

Failed cases: <list any that errored>
```

---

## Step 4b — Batch synthesis (mandatory before unified report)

After all cases are verified, read the finalize summary from every research notes file:

```bash
grep -A 5 "## Investigation Summary" ./reports/<BATCH_ID>/*_research_notes.md
```

Then write a batch synthesis file that answers five questions across the whole case set:

```bash
# Create the file inside the campaign folder
cat > ./reports/<BATCH_ID>/<BATCH_ID>_batch_synthesis.md << 'EOF'
# Batch synthesis — <BATCH_ID>

## Common IOCs
<!-- Which IPs, domains, hashes, or file paths appeared in more than one case? -->

## Common TTPs
<!-- Which MITRE ATT&CK techniques appeared across multiple hosts? -->

## Outlier
<!-- Which case behaved most differently from the others, and why is that significant? -->

## Highest-severity open leads
<!-- From all per-case reflect entries (RF-NNN), which unresolved leads most affect the overall campaign conclusion? -->

## Revised campaign conclusion
<!-- Given all cases together, what can be concluded? Cite the evidence base.
     Example: "All 8 hosts share the same C2 infrastructure (1.2.3.4:443); lateral movement confirmed via netscan on 6 of 8 images." -->
EOF
```

Fill every section before proceeding. If a section has no content, write one sentence explaining why (e.g., "No common IOCs found — each host connected to distinct infrastructure").

This file is embedded as Section 2 of the campaign report by `generate_campaign_report.py` when present.
Pass `--synthesis ./reports/<BATCH_ID>/<BATCH_ID>_batch_synthesis.md` to the campaign
report generator in Step 5b so it picks up the file from the campaign folder.

---

## Step 5 — Generate the unified investigation report (automatic)

Immediately after completing Step 4b, without waiting for analyst input:

**5a — Generate narrative files for every case in the batch:**

```bash
# Replace <CASE_ID_1> … with the full list from Step 2
for case_id in <CASE_ID_1> <CASE_ID_2> …; do
    python3 lib/narrative_generator.py \
        --case-id     "$case_id" \
        --reports-dir ./reports/<BATCH_ID>
done
```

> Note: this is the cross-*case* batch report (`CAMPAIGN_<BATCH_ID>_*`,
> generated by `lib/generate_campaign_report.py`), distinct from each
> individual case's hand-authored `<case_id>_campaign_report.*` (per
> `docs/campaign_report_template.md` + `lib/render_campaign_report.py`),
> which should already exist for each case in the batch.

**5b — Generate the campaign report:**

```bash
python3 lib/generate_campaign_report.py \
    --campaign-id  <BATCH_ID> \
    --title        "<descriptive title agreed with analyst in Step 2>" \
    --reports-dir  ./reports/<BATCH_ID> \
    --output-dir   ./reports/<BATCH_ID>
```

This produces (all inside `./reports/<BATCH_ID>/`):

| File | Format | Audience |
|------|--------|----------|
| `CAMPAIGN_<BATCH_ID>_report.md` | Markdown | Analyst / archival |
| `CAMPAIGN_<BATCH_ID>_report.pdf` | PDF | Legal / Law Enforcement / Audit |
| `CAMPAIGN_<BATCH_ID>_board_deck.pptx` | PowerPoint | CISO / Executive |
| `CAMPAIGN_<BATCH_ID>_timeline.png` | Image | Embedded in PPTX |

The report includes a **Top 3 Immediate Actions** table (§1b) with what / why / who / when / how columns derived automatically from the highest-severity findings.

**5c — Upload the unified report to the investigations vault:**

```bash
python3 lib/investigations_upload.py \
    --case-id <BATCH_ID> \
    --md   ./reports/<BATCH_ID>/CAMPAIGN_<BATCH_ID>_report.md \
    --pdf  ./reports/<BATCH_ID>/CAMPAIGN_<BATCH_ID>_report.pdf \
    --pptx ./reports/<BATCH_ID>/CAMPAIGN_<BATCH_ID>_board_deck.pptx \
    --interactive
```

Announce completion:
> Unified report generated — CAMPAIGN_<BATCH_ID>_report covering <N> hosts. [One-sentence overall finding.]

---

## Constraints

- **Never write to `/mnt/`, `/media/`, or any `evidence/` directory.**
- **Do not spawn child `claude` processes** — all analysis runs in the current
  session via `/fame` and `/fast` skill invocations.
- **Do not run cases in parallel** — competing writes to `./analysis/` will
  corrupt WIP output.
- Evidence archives (`.7z`, `.zip`) are never deleted — the `/fame` skill
  deletes only the extracted copy in `/tmp/`.
- All other constraints from the FAME and FAST skills apply within each case.

---

## Handling errors

If a case fails (skill returns an error, Volatility crashes, mount fails):

1. Log the failure: note the case ID and error message.
2. Continue to the next case — do not abort the entire batch.
3. Retry failed cases at the end after all others have run.
4. If retries also fail, report the failure in the final summary with the error
   message and recommended manual follow-up steps.
