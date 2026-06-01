# Skill: archive-reports — Campaign report archiver

## Overview

**archive-reports** moves a completed campaign folder from `./reports/<CAMPAIGN_ID>/`
to `./archive/<CAMPAIGN_ID>/`, preserving all reports and evidence files for future
reference without cluttering the active working area.

It also handles the **one-time migration** of legacy flat files (reports written
directly to `./reports/` root before campaign subfolders were introduced).

### Invocation

```
/archive-reports [CAMPAIGN_ID]
```

| Argument | Default | Description |
|----------|---------|-------------|
| `CAMPAIGN_ID` | (interactive) | Campaign folder to archive. If omitted, lists available campaigns and prompts for selection. |

---

## Step 1 — Scan `./reports/`

```bash
# List campaign subfolders
find ./reports -mindepth 1 -maxdepth 1 -type d | sort

# List loose files at root level (legacy flat layout)
find ./reports -mindepth 1 -maxdepth 1 -type f | sort
```

Classify findings:

| Finding | Action |
|---------|--------|
| No subfolders, no files | Announce "`./reports/` is empty — nothing to archive." and stop. |
| Subfolders present | List them as archivable campaigns. |
| Loose files at root (no subfolder) | Trigger **migration mode** (Step 1b) to consolidate them first. |
| Both subfolders and loose files | List subfolders for archiving; also offer to consolidate the loose files. |

---

## Step 1b — Migration mode (loose files only)

If `./reports/` contains files directly at root level (no campaign subfolder), the
files predate the campaign-folder layout. Consolidate them before archiving:

1. **Detect the batch prefix** — inspect filenames for a common uppercase segment.
   Examples:
   - `FAME-2026-BASE-FILE_fame_report.md`, `CAMPAIGN_SHIELDBASE-2026_report.pdf`
     → common prefix `SHIELDBASE-2026`
   - `FAME-2026-BASE-WKSTN-05_*`, `FAST-2026-BASE-WKSTN-05_*`
     → common prefix derived from campaign name in `CAMPAIGN_*` files, else `BATCH-<DATE>`

2. **Propose consolidation target:** `./reports/<detected_prefix>/`

3. **Ask analyst to confirm** the folder name (or supply a custom name).

4. **Consolidate:**
   ```bash
   mkdir -p ./reports/<CAMPAIGN_ID>
   mv ./reports/FAME-* ./reports/<CAMPAIGN_ID>/ 2>/dev/null
   mv ./reports/FAST-* ./reports/<CAMPAIGN_ID>/ 2>/dev/null
   mv ./reports/CAMPAIGN_* ./reports/<CAMPAIGN_ID>/ 2>/dev/null
   # Move any remaining loose files
   find ./reports -mindepth 1 -maxdepth 1 -type f -exec mv {} ./reports/<CAMPAIGN_ID>/ \;
   ```

5. Verify `./reports/` root is now clean (only the new subfolder present), then
   continue to Step 2 with `<CAMPAIGN_ID>` as the archive target.

---

## Step 2 — Identify target campaign

If a `CAMPAIGN_ID` argument was provided, use it directly and skip to Step 3.

Otherwise, display all campaign folders found:

```
Available campaigns in ./reports/:

  1. SHIELDBASE-2026   (N files, ~X MB)
  2. TESTRUN-2026      (N files, ~X MB)

Which campaign should be archived? (enter number or name, or "all" to archive all)
```

Get file counts and sizes with:
```bash
for d in ./reports/*/; do
    count=$(find "$d" | wc -l)
    size=$(du -sh "$d" | cut -f1)
    echo "${d##./reports/}  ($count items, $size)"
done
```

Wait for analyst to select a campaign before proceeding.

---

## Step 3 — Confirm archive action

Display a summary and ask for explicit confirmation:

```
Archive target:  ./reports/<CAMPAIGN_ID>/
Destination:     ./archive/<CAMPAIGN_ID>/
Contents:        N files, ~X MB

This will MOVE (not copy) all files. The campaign will no longer appear in
./reports/ and will only be accessible under ./archive/.

Proceed? (yes / no)
```

If the analyst says no, stop immediately without making any changes.

---

## Step 4 — Move to archive

```bash
# Create archive root if it does not exist
mkdir -p ./archive

# Safety check — refuse to overwrite an existing archive
if [ -d "./archive/<CAMPAIGN_ID>" ]; then
    echo "ERROR: ./archive/<CAMPAIGN_ID>/ already exists. Aborting to avoid overwrite."
    exit 1
fi

# Move
mv ./reports/<CAMPAIGN_ID> ./archive/<CAMPAIGN_ID>
```

---

## Step 5 — Verify and announce

```bash
# Confirm destination exists
ls -lh ./archive/<CAMPAIGN_ID>/ | head -20

# Confirm source is gone
ls ./reports/ | grep "<CAMPAIGN_ID>"   # should return nothing
```

Announce:
> **`<CAMPAIGN_ID>` archived** → `./archive/<CAMPAIGN_ID>/` (N files, ~X MB).
> `./reports/<CAMPAIGN_ID>/` has been removed. `./reports/` is ready for the next investigation.

---

## Constraints

- **Move only, never delete.** Files are never removed — only relocated.
- **Never overwrite an existing archive folder.** If `./archive/<CAMPAIGN_ID>/` already
  exists, abort with an error message and leave `./reports/` unchanged.
- **Never touch `/mnt/`, `/media/`, or any `evidence/` directory.**
- **Never archive the `./archive/` tree itself.**
- `./reports/` root may contain other campaign subfolders that are not being archived —
  leave them untouched.
