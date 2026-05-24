# Skill: Remove Case

## Overview

Permanently removes an investigation case from the FanGetFameFast platform:
- Deletes the case folder from the local investigations vault (`~/cases/<case_id>/`)
- Removes the Obsidian vault note (`vault/Cases/<case_id>.md`)

This operation is irreversible.

---

## Invocation

```bash
# Interactive — lists cases on the remote vault and prompts for selection
./scripts/remove_case.sh

# Direct — specify case ID
./scripts/remove_case.sh FAN-2025-001

# Keep Obsidian vault note (remove remote folder only)
./scripts/remove_case.sh FAN-2025-001 --keep-vault

# Skip confirmation prompt (for scripted use)
./scripts/remove_case.sh FAN-2025-001 --force
```

---

## What Gets Removed

| Item | Location | Condition |
|------|----------|-----------|
| Remote case folder | `~/cases/<case_id>/` on investigations vault host | Always |
| Reports | `~/cases/<case_id>/reports/` | Part of remote case folder |
| Vault case note | `vault/Cases/<case_id>.md` | Unless `--keep-vault` |

---

## Safety

- The interactive form requires the analyst to **retype the case ID** to confirm deletion.
- The `--force` flag skips the confirmation and is intended for scripted cleanup only.
- `--keep-vault` preserves the Obsidian knowledge graph entry (TTPs, IOCs linked from the case note are not removed — only the case summary note itself).
- Vault root is controlled by `INVESTIGATIONS_ROOT` env var (default: `~/cases`).

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Case folder not found | Wrong case ID or already removed | Run `investigations_list_cases` via MCP to see existing cases |
| Case folder not deleted | Wrong case ID or already removed | Run `investigations_list_cases` via MCP to see existing cases |
| Vault note not found | Note was never created or already deleted | Expected — `--no-vault` was used during investigation |
