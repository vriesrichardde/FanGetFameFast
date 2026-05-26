#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
init_vault.py — Bootstrap the Obsidian vault directory structure.

Creates vault/ with all required sub-folders and an empty Dashboard.md
with AUTO section markers.  Safe to re-run: existing notes are never
overwritten.

Usage:
    python3 lib/init_vault.py
    python3 lib/init_vault.py --vault /path/to/custom/vault
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from pathlib import Path

VAULT_ROOT = Path(__file__).parent.parent / "vault"

FOLDERS = [
    "TTPs",
    "IOCs",
    "ThreatActors",
    "Malware",
    "Concepts",
    "Risks",
    "Cases",
    "Templates",
]

_DASHBOARD_TEMPLATE = """\
---
date_created: {now}
date_updated: {now}
tags:
- dashboard
---

# FanGetFameFast — Vault Dashboard

Auto-maintained index. Updated automatically after every investigation.

---

## Active Cases

<!-- AUTO:CASES -->
*No cases recorded yet.*
<!-- /AUTO:CASES -->

---

## Recent IOCs

<!-- AUTO:IOCS -->
*No IOCs recorded yet.*
<!-- /AUTO:IOCS -->

---

## Active Risks

<!-- AUTO:RISKS -->
*No open risks.*
<!-- /AUTO:RISKS -->

---

## TTPs Observed

<!-- AUTO:TTPS -->
*No TTPs recorded yet.*
<!-- /AUTO:TTPS -->

---

## Threat Actors

<!-- AUTO:ACTORS -->
*No threat actors recorded yet.*
<!-- /AUTO:ACTORS -->
"""


def init_vault(vault_root: Path = VAULT_ROOT) -> None:
    """Create vault directory structure. Existing notes are never overwritten."""
    vault_root.mkdir(parents=True, exist_ok=True)

    for folder in FOLDERS:
        (vault_root / folder).mkdir(exist_ok=True)

    dashboard = vault_root / "Dashboard.md"
    if not dashboard.exists():
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        dashboard.write_text(_DASHBOARD_TEMPLATE.format(now=now), encoding="utf-8")
        print(f"[vault] Dashboard created: {dashboard}")
    else:
        print(f"[vault] Dashboard already exists: {dashboard}")

    print(f"[vault] Vault ready at {vault_root}")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="Bootstrap the Obsidian vault.")
    p.add_argument("--vault", default=None, metavar="DIR",
                   help="Vault root (default: ./vault/)")
    args = p.parse_args()
    init_vault(Path(args.vault) if args.vault else VAULT_ROOT)
