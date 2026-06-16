---
description: Autonomously process the evidence vault one top-level folder at a time, smallest first, treating each folder as a single case. Each run reschedules itself for the next night before doing any long-running work, so a multi-night/multi-session investigation (e.g. srl-2018, 29 evidence files) resumes automatically. Built for unattended scheduled runs (cron / CronCreate).
---

# Nightly folder investigation

You are running **unattended** (a scheduled overnight run, fired by `CronCreate`
in this container, or by a `cron` job calling `claude -p` on a SIFT workstation —
see [docs/DEPLOYMENT_GUIDE.md §11](../../docs/DEPLOYMENT_GUIDE.md#11-first-investigation)
for both setups). Work autonomously and never block on a question — if something
is ambiguous, make the safest reasonable choice and flag it in the morning
summary instead of stopping.

`scripts/batch_agentic.sh` already does the routing, dedup, per-case agentic
FAME/FAST/FAN analysis, batch report, and campaign report — **one case per
top-level evidence folder** (see "Required code change" history: `case_id ==
batch_id`, hostnames within the case are each evidence file's stem). Your job
is to drive it one folder per night, track progress in
`batch_work/nightly_queue.json`, and reschedule yourself.

## Configuration
- **Evidence root:** `/home/vscode/evidence` (override if invoked with an
  argument).
- **Queue state file:** `batch_work/nightly_queue.json` (gitignored, under
  `batch_work/`).
- **Evidence detection:** same extension list as `batch_agentic.sh` Phase 2 —
  `mem/img/raw/lime/vmem/dmp/mans/001/E01/ewf/vmdk/vdi/qcow2/vhd/vhdx/pcap/pcapng/cap`,
  plus archive (`.7z`/`.zip`) contents already extracted by Phase 1. Note `.001`
  is FAME (lone segment) or FAST (split image, if a `.002` sibling exists), and
  `.mans` is triaged via `lib/redline_triage.py` — both routed automatically by
  `batch_agentic.sh`.
- **Skip rule:** only top-level **directories** of `/home/vscode/evidence` are
  queued. Loose files at the root (e.g. `.zip` duplicates of a directory) are
  never enumerated — this is what "skip the two zip files" means in practice.

## Procedure

### 1. Reschedule first, before any long-running work

Use `CronCreate` with `recurring: false` to schedule **tomorrow, same time**
with the exact same prompt that invoked this skill ("Run the
nightly-folder-investigation skill"). This is the safety net: if this session
gets killed mid-`batch_agentic.sh`, tomorrow's run still fires and resumes via
`batch_agentic.sh`'s own `processed_stems.txt` dedup. One-shot jobs
auto-delete on fire, so there's never more than one pending job — no
`CronList`/`CronDelete` bookkeeping needed each night.

### 2. Load or create the queue

Read `batch_work/nightly_queue.json`. If it doesn't exist, create it:

```json
{
  "queue": ["Nitroba", "NIST Data Leakage", "NIST Hacking Case",
            "win7-64-nfury-10.3.58.6", "win7-32-nromanoff-10.3.58.5", "srl-2018"],
  "case_ids": {"Nitroba": "NITROBA", "NIST Data Leakage": "NISTLEAK",
                 "NIST Hacking Case": "NISTHACK",
                 "win7-64-nfury-10.3.58.6": "WIN764NFURY",
                 "win7-32-nromanoff-10.3.58.5": "WIN732NROM",
                 "srl-2018": "SRL2018"},
  "current_index": 0
}
```

This is the smallest-first order derived from `du -sh /home/vscode/evidence/*/`.
If re-bootstrapping later (file missing again, e.g. after the queue was fully
drained and reset), re-derive the order the same way: `du -sh` ascending over
top-level directories not yet represented in `case_ids`.

If `current_index >= len(queue)`: re-scan `/home/vscode/evidence` for top-level
directories not already present in `queue` (handles new evidence dropped in
after the backlog is cleared — "new windows"). For each new folder, derive a
short `case_id` (uppercase, alphanumeric, satisfying `validate_case_id`'s
`[A-Za-z0-9._-]{1,64}`), append to `queue` and `case_ids` sorted by `du -sh`
ascending, and continue with the first new one. If no new folders are found,
this is a no-op night — the step-1 reschedule already covers tomorrow; report
"queue empty, no new evidence" and stop.

### 3. Run the current folder's batch — repeat while folders complete

Loop over steps 3a–3c. The loop continues to the next folder **only if** the
current folder fully completes within this run; it stops (ending the run for
tonight) as soon as a folder doesn't finish or the queue is exhausted. This
lets small folders (e.g. `Nitroba`, one `.pcap`) cascade through several in a
single session, while a folder that doesn't fit (e.g. `srl-2018`, 29 evidence
files) naturally stops the loop and waits for tomorrow's reschedule.

**3a. Run the batch for the current folder:**

```bash
folder="$(python3 -c "import json; d=json.load(open('batch_work/nightly_queue.json')); print(d['queue'][d['current_index']])")"
batch_id="$(python3 -c "import json; d=json.load(open('batch_work/nightly_queue.json')); print(d['case_ids'][d['queue'][d['current_index']]])")"
./scripts/batch_agentic.sh "/home/vscode/evidence/$folder" --batch-id "$batch_id"
```

Same agentic pipeline as before (archives extracted, FAME/FAST via
`claude -p "/fame ..."` / `/fast`, FAN via `analyze_pcap.sh`, manifest +
batch/campaign report under `./reports/$batch_id/`).

**3b. Check whether the folder is fully done.** Compare the set of evidence
files `batch_agentic.sh` would detect in `<folder>` (extension list above,
plus already-extracted archive contents) against
`batch_work/<batch_id>/processed_stems.txt`. If every evidence file's
`MODULE:stem.ext` key is present, the folder is complete.

**3c. Advance or stop:**
- **Complete:** increment `current_index` in `batch_work/nightly_queue.json`
  and save it. If `current_index >= len(queue)`, re-run the "new windows"
  re-scan from step 2. If a next folder exists, go back to 3a for it.
- **Not complete** (ran out of time/session, or genuine failures left in
  `processed_stems.txt` gaps): leave `current_index` unchanged and stop the
  loop — tomorrow's run resumes the same folder (re-running `batch_agentic.sh`
  on it skips everything already in `processed_stems.txt` and continues with
  what's left). Step 1 already guarantees tomorrow's continuation.
- **Queue empty after re-scan:** stop the loop — "queue empty, no new
  evidence" for tonight.

### 4. Follow-up remediation pass

`batch_agentic.sh` runs each host's `/fame` or `/fast` as a separate
`claude -p` subprocess with no memory of this session. After report
generation, `lib/report_completeness.py` checks two things and — if either
fails — writes
`reports/<batch_id>/<MODULE>/<hostname>/<batch_id>_INVESTIGATION_INCOMPLETE.json`
and records `MODULE:hostname` in `batch_work/<batch_id>/needs_followup.txt`:

1. **Narrative gaps** — `<batch_id>_narrative.md` is missing or missing
   required sections (`attack_timeline`, module-specific `section_*`, all
   `pptx_*`). Phase 4 of `batch_agentic.sh` already ran the headless
   `lib/narrative_generator.py` fallback against each flagged host, which may
   have closed this gap on its own.
2. **Reasoning gaps** — the research notes show no `Reflect RF-` entries, the
   `<!-- summary-placeholder -->` was never finalized, or every step is an
   auto-logged `Evidence preserved: ...` chain-of-custody entry with no
   Claude-authored interpretation. **The headless fallback cannot fix this —
   only this session can.**

For each `MODULE:hostname` still listed in
`batch_work/<batch_id>/needs_followup.txt` (re-read the marker JSON to confirm
it's still present — Phase 4's fallback may have already cleared the narrative
portion):

1. Read the preserved evidence under
   `reports/<batch_id>/<MODULE>/<hostname>/<batch_id>_evidence/` — the same
   plugin/tool outputs the per-host `claude -p` run already hashed.
2. Add the missing Claude-authored interpretation steps to
   `<batch_id>_research_notes.md` via `lib/research_notes.py step` (one per
   plugin/tool output, following the module's normal step cadence — see
   `docs/investigation_discipline.md`), then a `reflect` entry, then
   `finalize` to replace `<!-- summary-placeholder -->` with a real
   investigation summary.
3. Hand-write `<batch_id>_narrative.md` per the module's schema in
   `docs/investigation_discipline.md` (overwrite any Phase-4 fallback content
   with real, host-specific findings).
4. Re-run `lib/generate_fame_report.py` / `lib/generate_fast_report.py` for
   this host (same `--case-dir`/`--docs-dir` the per-host run used) so the
   report picks up the new narrative and research notes, and confirm
   `<batch_id>_INVESTIGATION_INCOMPLETE.json` is gone.

If time runs out mid-folder, leave the remaining entries in
`needs_followup.txt` — they are picked up again the next time this folder's
batch completes (the file is read fresh each run; already-resolved hosts no
longer have a marker so they're skipped).

After working through `needs_followup.txt`, check whether any case now has
`>=2` modules with reports but no `<batch_id>_campaign_report.md`
(`python3 lib/report_completeness.py --campaign-check --case-id <batch_id>`).
If flagged, hand-author the campaign report per
`docs/campaign_report_template.md` and render it via
`lib/render_campaign_report.py`.

### 5. Verify and spot-check

- Verify `./analysis/` is empty. Leftover WIP means a case inside the batch
  failed partway through — note it for human review, do not delete it
  yourself.
- Spot-check one or two newly-generated reports under
  `./reports/<batch_id>/` for obviously broken output (empty report, missing
  sections, or an `⚠️ INVESTIGATION INCOMPLETE` banner) before declaring a
  case successful in the summary. After step 4, spot-checked reports should
  show no `INCOMPLETE` banners.

### 6. Morning summary

End with a concise summary for the morning analyst:
- **Folder/queue position:** e.g. "folder 2/6 (NIST Data Leakage) — N hostnames
  processed tonight, M still pending" or "folder 2/6 complete, advanced to
  folder 3/6 (NIST Hacking Case)".
- **New cases/hostnames processed:** module, one-line key finding, report
  locations under `./reports/<batch_id>/`.
- **Skipped (already processed):** count only.
- **Failed:** hostnames/files, error from `manifest.json`/`errors.log`, and
  what to check first.
- **Campaign report:** location of the regenerated `<batch_id>` campaign
  report, if regenerated.
- Anything unusual found in `./analysis/` that needs human attention.
- **Tomorrow's job:** confirm the one-shot reschedule from step 1 is in place.

## Constraints
- Never weaken `lib/path_guard.py` / `validate_case_id` / write-policy checks.
- Never delete, move, or modify files under the evidence root.
- Per-case failures are handled by `batch_agentic.sh` itself (logged to
  `manifest.json`/`errors.log`, batch continues). Don't re-run failed cases
  yourself — the next scheduled run will retry them since they were never
  added to `processed_stems.txt`.

## Known limitations
- `CronCreate`'s persistence across container restarts/session-exit is
  uncertain (the tool has reported "session-only... dies when Claude exits"
  even with `durable: true`). If the devcontainer/session is restarted, the
  pending one-shot job may be lost and the chain stalls until someone manually
  re-fires `/nightly-folder-investigation` once. The SIFT workstation `cron` +
  `claude -p` path documented in
  [docs/DEPLOYMENT_GUIDE.md §11](../../docs/DEPLOYMENT_GUIDE.md#11-first-investigation)
  doesn't have this problem and is the recommended path for unattended
  production use.
