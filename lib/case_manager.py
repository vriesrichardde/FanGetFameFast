# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
"""
case_manager.py — Investigation case lifecycle management.

Cases are stored under ./cases/<case_id>/ with this structure:
  case.json          — metadata (created, status, pcaps, versions)
  analysis/          — per-module analysis outputs (mirrors ./analysis/ layout)
  reports/           — generated Markdown + PDF reports
  exports/           — miscellaneous exported artefacts
  .version_<stem>    — version counter for each PCAP stem's report

Usage:
  from lib.case_manager import CaseManager, generate_case_id
  cm = CaseManager()
  cd = cm.init_case("CASE-2025-001", "Suspected C2 beacon")
  cm.add_pcap("CASE-2025-001", "~/evidence/capture.pcap")
  v  = cm.next_report_version("CASE-2025-001", "capture")
  zp = cm.archive_case("CASE-2025-001")
  cm.remove_case("CASE-2025-001")
"""
from __future__ import annotations

import json
import shutil
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
CASES_DIR    = PROJECT_ROOT / "cases"


def generate_case_id() -> str:
    return f"CASE-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"


class CaseManager:
    def __init__(self, cases_dir: Path | None = None) -> None:
        self.cases_dir = cases_dir or CASES_DIR
        self.cases_dir.mkdir(parents=True, exist_ok=True)

    # ── Directory helpers ────────────────────────────────────────────────────

    def case_dir(self, case_id: str) -> Path:
        return self.cases_dir / case_id

    def analysis_dir(self, case_id: str, subdir: str = "") -> Path:
        d = self.case_dir(case_id) / "analysis"
        return d / subdir if subdir else d

    def reports_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "reports"

    def exports_dir(self, case_id: str) -> Path:
        return self.case_dir(case_id) / "exports"

    # ── Case creation / metadata ─────────────────────────────────────────────

    def init_case(self, case_id: str, description: str = "") -> Path:
        """Create directory structure. Idempotent — safe to call on existing case."""
        cd = self.case_dir(case_id)
        for sub in ["analysis", "reports", "exports"]:
            (cd / sub).mkdir(parents=True, exist_ok=True)
        meta_path = cd / "case.json"
        if not meta_path.exists():
            now = datetime.now(timezone.utc).isoformat()
            meta_path.write_text(json.dumps({
                "case_id":      case_id,
                "description":  description,
                "created_utc":  now,
                "updated_utc":  now,
                "status":       "open",
                "pcaps":        [],
            }, indent=2, ensure_ascii=False))
        return cd

    def get_meta(self, case_id: str) -> dict:
        mp = self.case_dir(case_id) / "case.json"
        try:
            return json.loads(mp.read_text())
        except Exception:
            return {}

    def update_meta(self, case_id: str, **kwargs) -> None:
        mp = self.case_dir(case_id) / "case.json"
        if not mp.exists():
            return
        meta = json.loads(mp.read_text())
        meta.update(kwargs)
        meta["updated_utc"] = datetime.now(timezone.utc).isoformat()
        mp.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    def add_pcap(self, case_id: str, pcap_path: str) -> None:
        mp = self.case_dir(case_id) / "case.json"
        if not mp.exists():
            return
        meta = json.loads(mp.read_text())
        if pcap_path not in meta.get("pcaps", []):
            meta.setdefault("pcaps", []).append(pcap_path)
        meta["updated_utc"] = datetime.now(timezone.utc).isoformat()
        mp.write_text(json.dumps(meta, indent=2, ensure_ascii=False))

    def list_cases(self) -> list[dict]:
        cases = []
        if not self.cases_dir.exists():
            return cases
        for p in sorted(self.cases_dir.iterdir()):
            if not p.is_dir():
                continue
            mp = p / "case.json"
            if mp.exists():
                try:
                    cases.append(json.loads(mp.read_text()))
                except Exception:
                    cases.append({"case_id": p.name, "description": "",
                                  "created_utc": "", "status": "unknown"})
        return cases

    def case_exists(self, case_id: str) -> bool:
        return (self.case_dir(case_id) / "case.json").exists()

    # ── Report versioning ────────────────────────────────────────────────────

    def _version_file(self, case_id: str, stem: str) -> Path:
        return self.reports_dir(case_id) / f".version_{stem}"

    def get_report_version(self, case_id: str, stem: str) -> int:
        try:
            return int(self._version_file(case_id, stem).read_text().strip())
        except Exception:
            return 0

    def has_archive(self, case_id: str) -> bool:
        return any(self.cases_dir.glob(f"{case_id}_*.zip"))

    def next_report_version(self, case_id: str, stem: str) -> int:
        """Return next version number; increments if an archive already exists."""
        current = self.get_report_version(case_id, stem)
        new_ver = (current + 1) if (current == 0 or self.has_archive(case_id)) else max(current, 1)
        self.reports_dir(case_id).mkdir(parents=True, exist_ok=True)
        self._version_file(case_id, stem).write_text(str(new_ver))
        return new_ver

    # ── Archive ──────────────────────────────────────────────────────────────

    def archive_case(self, case_id: str) -> Path:
        """Zip the entire case directory. Returns path to the ZIP file."""
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        zip_path = self.cases_dir / f"{case_id}_{ts}.zip"
        cd = self.case_dir(case_id)
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for f in sorted(cd.rglob("*")):
                if f.is_file():
                    zf.write(f, f.relative_to(self.cases_dir))
        self.update_meta(case_id,
                         last_archive_utc=datetime.now(timezone.utc).isoformat(),
                         last_archive_zip=str(zip_path))
        return zip_path

    # ── Remove ───────────────────────────────────────────────────────────────

    def remove_case(self, case_id: str, remove_vault: bool = True) -> None:
        """Delete case directory, ZIP archives, and optionally Obsidian notes."""
        cd = self.case_dir(case_id)
        if cd.exists():
            shutil.rmtree(cd)
            print(f"[case_manager] Removed case directory: {cd}")
        for z in self.cases_dir.glob(f"{case_id}_*.zip"):
            z.unlink(missing_ok=True)
            print(f"[case_manager] Removed archive: {z}")
        if remove_vault:
            _remove_vault_case(case_id)


def _remove_vault_case(case_id: str) -> None:
    """Remove the Cases/<case_id>.md vault note for this case."""
    try:
        sys.path.insert(0, str(PROJECT_ROOT / "lib"))
        vault = PROJECT_ROOT / "vault" / "Cases"
        note = vault / f"{case_id}.md"
        if note.exists():
            note.unlink()
            print(f"[case_manager] Removed vault note: {note}")
        else:
            print(f"[case_manager] No vault note found for {case_id}")
    except Exception as e:
        print(f"[case_manager] Vault cleanup skipped: {e}", file=sys.stderr)


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser(description="Case lifecycle management")
    sub = p.add_subparsers(dest="cmd")

    pi = sub.add_parser("init",    help="Initialise a new case")
    pi.add_argument("case_id")
    pi.add_argument("--description", default="")

    pl = sub.add_parser("list",    help="List all cases")
    pa = sub.add_parser("archive", help="Create timestamped ZIP of a case")
    pa.add_argument("case_id")

    pr = sub.add_parser("remove",  help="Delete a case (directory + vault note)")
    pr.add_argument("case_id")
    pr.add_argument("--keep-vault", action="store_true")

    pv = sub.add_parser("version", help="Show or advance the report version")
    pv.add_argument("case_id")
    pv.add_argument("stem")
    pv.add_argument("--advance", action="store_true")

    args = p.parse_args()
    cm = CaseManager()

    if args.cmd == "init":
        cd = cm.init_case(args.case_id, args.description)
        print(f"Case initialised: {cd}")

    elif args.cmd == "list":
        cases = cm.list_cases()
        if not cases:
            print("No cases found.")
        for c in cases:
            print(f"  {c['case_id']:<30} {c.get('status','?'):<8} {c.get('created_utc','')[:10]}  {c.get('description','')[:60]}")

    elif args.cmd == "archive":
        z = cm.archive_case(args.case_id)
        print(f"Archive: {z}")

    elif args.cmd == "remove":
        cm.remove_case(args.case_id, remove_vault=not args.keep_vault)
        print(f"Case {args.case_id} removed.")

    elif args.cmd == "version":
        if args.advance:
            v = cm.next_report_version(args.case_id, args.stem)
            print(f"Report version advanced to: {v}")
        else:
            v = cm.get_report_version(args.case_id, args.stem)
            print(f"Current report version: {v}")
