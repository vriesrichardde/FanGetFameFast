#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
chain_of_custody.py — Court-ready integrity manifest for a case folder.

Maintains a single, durable, append-only manifest at
``reports/<case_id>/documents/<case_id>_chain_of_custody.json`` recording, for
every file under the case directory (and optionally the source evidence
file(s)):

  - size, modification time, MD5, SHA-1, SHA-256
  - when it was first recorded and when it was last verified

Every call to :func:`update_manifest` appends one entry to ``history``
describing what changed since the previous run (added / changed / removed
paths), who triggered it, and why. A hash that changes for a path already in
the manifest is recorded in ``changed`` with both the old and new digest —
this is the tamper/integrity signal a court needs.

Evidence entries are append-only: if a previously recorded evidence file's
hash no longer matches, the original record is preserved and the mismatch is
surfaced in ``history`` as a critical integrity finding.

Python API:
    from lib.chain_of_custody import update_manifest
    update_manifest(case_dir, case_id, evidence_paths=["/home/vscode/evidence/x.pcap"],
                     examiner="J. Everling", trigger="investigation",
                     note="initial FAN run")

CLI:
    python3 lib/chain_of_custody.py update --case-id FAN-2026-001 \\
        --case-dir reports/FAN-2026-001 \\
        --evidence /home/vscode/evidence/capture.pcap \\
        --trigger investigation --note "FAN pipeline run"

Self-test:
    python3 lib/chain_of_custody.py --test
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import path_guard  # noqa: E402  write-path policy enforcement

SCHEMA_VERSION = 1
_MANIFEST_SUFFIX = "_chain_of_custody.json"

# Files never included as artifacts (the manifest itself, OS noise, VCS dirs).
_SKIP_NAMES = {".DS_Store"}
_SKIP_DIR_NAMES = {".git"}


# ── Hashing ──────────────────────────────────────────────────────────────────

def _hash_file(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _mtime_utc(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S UTC"
    )


def _git_commit() -> str:
    try:
        out = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=Path(__file__).resolve().parent.parent,
            capture_output=True, text=True, timeout=5, check=True,
        )
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


# ── Manifest I/O ─────────────────────────────────────────────────────────────

def _manifest_path(case_dir: Path, case_id: str) -> Path:
    return Path(case_dir) / "documents" / f"{case_id}{_MANIFEST_SUFFIX}"


def _load_manifest(path: Path, case_id: str) -> dict:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    return {
        "case_id": case_id,
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "FanGetFameFast", "git_commit": _git_commit()},
        "evidence": [],
        "artifacts": [],
        "history": [],
    }


# ── Core update logic ────────────────────────────────────────────────────────

def _collect_files(case_dir: Path, manifest_path: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    for f in sorted(case_dir.rglob("*")):
        if not f.is_file():
            continue
        if f == manifest_path:
            continue
        if f.name in _SKIP_NAMES:
            continue
        if any(part in _SKIP_DIR_NAMES for part in f.relative_to(case_dir).parts):
            continue
        found[str(f.relative_to(case_dir))] = f
    return found


def _diff_artifacts(manifest: dict, case_dir: Path, manifest_path: Path, now: str) -> dict:
    existing = {a["path"]: a for a in manifest["artifacts"]}
    current = _collect_files(case_dir, manifest_path)

    added: list[str] = []
    changed: list[dict] = []
    removed: list[str] = []
    new_artifacts: list[dict] = []

    for rel, f in current.items():
        digests = _hash_file(f)
        size = f.stat().st_size
        mtime = _mtime_utc(f)
        prev = existing.get(rel)
        if prev is None:
            added.append(rel)
            new_artifacts.append({
                "path": rel,
                "size_bytes": size,
                "mtime_utc": mtime,
                **digests,
                "first_recorded_utc": now,
                "last_verified_utc": now,
            })
        elif prev.get("sha256") != digests["sha256"]:
            changed.append({
                "path": rel,
                "old_sha256": prev.get("sha256"),
                "new_sha256": digests["sha256"],
            })
            new_artifacts.append({
                **prev,
                "size_bytes": size,
                "mtime_utc": mtime,
                **digests,
                "last_verified_utc": now,
            })
        else:
            new_artifacts.append({**prev, "mtime_utc": mtime, "last_verified_utc": now})

    for rel in existing:
        if rel not in current:
            removed.append(rel)

    manifest["artifacts"] = sorted(new_artifacts, key=lambda a: a["path"])
    return {"added": added, "changed": changed, "removed": removed}


def _diff_evidence(manifest: dict, evidence_paths: list[str], now: str) -> tuple[dict, list[str]]:
    existing = {e["path"]: e for e in manifest["evidence"]}
    added: list[str] = []
    integrity_alerts: list[str] = []

    for raw in evidence_paths:
        p = Path(raw)
        if not p.is_file():
            integrity_alerts.append(f"evidence path not found: {raw}")
            continue
        digests = _hash_file(p)
        prev = existing.get(raw)
        if prev is None:
            manifest["evidence"].append({
                "path": raw,
                "size_bytes": p.stat().st_size,
                **digests,
                "first_recorded_utc": now,
                "last_verified_utc": now,
            })
            added.append(raw)
        elif prev.get("sha256") != digests["sha256"]:
            integrity_alerts.append(
                f"EVIDENCE HASH MISMATCH for {raw}: recorded {prev.get('sha256')} "
                f"at {prev.get('first_recorded_utc')}, now {digests['sha256']} — "
                f"original record preserved, do not overwrite"
            )
            # Append-only: preserve the original record, add a new one alongside it.
            manifest["evidence"].append({
                "path": raw,
                "size_bytes": p.stat().st_size,
                **digests,
                "first_recorded_utc": now,
                "last_verified_utc": now,
                "note": "hash differs from earlier record — see history for details",
            })
        else:
            prev["last_verified_utc"] = now

    return {"added": added}, integrity_alerts


def update_manifest(
    case_dir: Path | str,
    case_id: str,
    evidence_paths: list[str] | None = None,
    examiner: str | None = None,
    trigger: str = "investigation",
    note: str | None = None,
) -> Path:
    """Update (or create) the chain-of-custody manifest for *case_id*.

    Returns the path of the manifest file.
    """
    case_dir = Path(case_dir)
    manifest_path = _manifest_path(case_dir, case_id)
    path_guard.guard_output_dir(manifest_path.parent)

    manifest = _load_manifest(manifest_path, case_id)
    manifest["case_id"] = case_id
    manifest["schema_version"] = SCHEMA_VERSION
    manifest.setdefault("tool", {"name": "FanGetFameFast", "git_commit": _git_commit()})

    now = _now_utc()
    artifact_diff = _diff_artifacts(manifest, case_dir, manifest_path, now)

    evidence_diff: dict = {"added": []}
    integrity_alerts: list[str] = []
    if evidence_paths:
        evidence_diff, integrity_alerts = _diff_evidence(manifest, evidence_paths, now)

    examiner_val = examiner or os.environ.get("FGFF_EXAMINER") or "unspecified"

    history_entry = {
        "timestamp_utc": now,
        "trigger": trigger,
        "examiner": examiner_val,
        "note": note or "",
        "added": artifact_diff["added"] + [f"[evidence] {p}" for p in evidence_diff["added"]],
        "changed": artifact_diff["changed"],
        "removed": artifact_diff["removed"],
    }
    if integrity_alerts:
        history_entry["integrity_alerts"] = integrity_alerts

    manifest["history"].append(history_entry)

    path_guard.safe_write_text(
        manifest_path, json.dumps(manifest, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    return manifest_path


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Chain-of-custody integrity manifest for FanGetFameFast cases"
    )
    sub = p.add_subparsers(dest="command", required=True)

    pu = sub.add_parser("update", help="Hash the case tree and update the manifest")
    pu.add_argument("--case-id", required=True, metavar="ID")
    pu.add_argument("--case-dir", required=True, metavar="DIR")
    pu.add_argument("--evidence", action="append", default=[], metavar="PATH",
                     help="Source evidence file to hash (repeatable)")
    pu.add_argument("--examiner", metavar="NAME",
                     help="Examiner name (default: $FGFF_EXAMINER or 'unspecified')")
    pu.add_argument("--trigger", choices=["investigation", "followup", "manual"],
                     default="investigation")
    pu.add_argument("--note", metavar="TEXT", help="Free-text note for this history entry")

    return p


def _cmd_update(args: argparse.Namespace) -> None:
    manifest_path = update_manifest(
        case_dir=args.case_dir,
        case_id=args.case_id,
        evidence_paths=args.evidence,
        examiner=args.examiner,
        trigger=args.trigger,
        note=args.note,
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    last = manifest["history"][-1]
    print(f"[chain_of_custody] Updated: {manifest_path}")
    print(f"[chain_of_custody]   added={len(last['added'])} changed={len(last['changed'])} "
          f"removed={len(last['removed'])}")
    if last.get("integrity_alerts"):
        for alert in last["integrity_alerts"]:
            print(f"[chain_of_custody]   ALERT: {alert}", file=sys.stderr)


# ── Self-test ────────────────────────────────────────────────────────────────

def _run_self_test() -> int:
    import tempfile

    failures = 0

    with tempfile.TemporaryDirectory() as tmp:
        case_dir = Path(tmp) / "CASE-TEST"
        (case_dir / "FAN" / "stem").mkdir(parents=True)
        (case_dir / "documents").mkdir(parents=True)

        f1 = case_dir / "FAN" / "stem" / "report.md"
        f1.write_text("hello")

        # First update: report.md should be added.
        update_manifest(case_dir, "CASE-TEST", trigger="manual", note="round 1")
        manifest_path = _manifest_path(case_dir, "CASE-TEST")
        m1 = json.loads(manifest_path.read_text())
        h1 = m1["history"][-1]
        ok = "FAN/stem/report.md" in h1["added"] and not h1["changed"] and not h1["removed"]
        print(f"[{'PASS' if ok else 'FAIL'}] round 1: report.md added")
        failures += 0 if ok else 1

        # Second update, no changes: nothing added/changed/removed.
        update_manifest(case_dir, "CASE-TEST", trigger="manual", note="round 2 (no-op)")
        m2 = json.loads(manifest_path.read_text())
        h2 = m2["history"][-1]
        ok = not h2["added"] and not h2["changed"] and not h2["removed"]
        print(f"[{'PASS' if ok else 'FAIL'}] round 2: idempotent (no changes)")
        failures += 0 if ok else 1

        # Modify the file: should show up in 'changed' with old/new hashes.
        f1.write_text("hello, world — modified")
        update_manifest(case_dir, "CASE-TEST", trigger="manual", note="round 3 (modified)")
        m3 = json.loads(manifest_path.read_text())
        h3 = m3["history"][-1]
        changed_paths = [c["path"] for c in h3["changed"]]
        ok = changed_paths == ["FAN/stem/report.md"] and \
            h3["changed"][0]["old_sha256"] != h3["changed"][0]["new_sha256"]
        print(f"[{'PASS' if ok else 'FAIL'}] round 3: modification detected with old/new hashes")
        failures += 0 if ok else 1

        # Remove the file: should show up in 'removed'.
        f1.unlink()
        update_manifest(case_dir, "CASE-TEST", trigger="manual", note="round 4 (removed)")
        m4 = json.loads(manifest_path.read_text())
        h4 = m4["history"][-1]
        ok = h4["removed"] == ["FAN/stem/report.md"]
        print(f"[{'PASS' if ok else 'FAIL'}] round 4: removal detected")
        failures += 0 if ok else 1

        # Evidence hashing: add an evidence file, then mutate it -> integrity alert.
        ev = Path(tmp) / "evidence.pcap"
        ev.write_bytes(b"original-bytes")
        update_manifest(case_dir, "CASE-TEST", evidence_paths=[str(ev)],
                        trigger="manual", note="round 5 (evidence)")
        m5 = json.loads(manifest_path.read_text())
        ok = len(m5["evidence"]) == 1 and m5["evidence"][0]["path"] == str(ev)
        print(f"[{'PASS' if ok else 'FAIL'}] round 5: evidence recorded")
        failures += 0 if ok else 1

        ev.write_bytes(b"tampered-bytes")
        update_manifest(case_dir, "CASE-TEST", evidence_paths=[str(ev)],
                        trigger="manual", note="round 6 (evidence tampered)")
        m6 = json.loads(manifest_path.read_text())
        h6 = m6["history"][-1]
        ok = len(m6["evidence"]) == 2 and bool(h6.get("integrity_alerts"))
        print(f"[{'PASS' if ok else 'FAIL'}] round 6: evidence tamper preserved + alerted")
        failures += 0 if ok else 1

    print()
    if failures:
        print(f"chain_of_custody self-test: {failures} FAILURE(S)")
    else:
        print("chain_of_custody self-test: ALL PASS")
    return 1 if failures else 0


if __name__ == "__main__":
    if "--test" in sys.argv:
        raise SystemExit(_run_self_test())

    args = _build_parser().parse_args()
    {"update": _cmd_update}[args.command](args)
