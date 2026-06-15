#!/usr/bin/env python3
"""Generate (or update) the project Software Bill of Materials.

Reads ``requirements.txt`` for the declared dependency set, resolves the
concrete installed version + license from the active environment metadata,
and emits a CycloneDX 1.5 JSON SBOM at ``sbom.json`` plus a human-readable
``sbom.md`` summary.

Usage:
    python3 scripts/generate_sbom.py            # write sbom.json + sbom.md
    python3 scripts/generate_sbom.py --check    # exit 1 if sbom.json is stale

Re-run this whenever ``requirements.txt`` changes or dependencies are upgraded.
"""
from __future__ import annotations

import argparse
import importlib.metadata as md
import json
import re
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIREMENTS = ROOT / "requirements.txt"
SBOM_JSON = ROOT / "sbom.json"
SBOM_MD = ROOT / "sbom.md"

# Curated SPDX license IDs for packages whose metadata is ambiguous, missing,
# or not installed in the current environment. Keys are PyPI names (lowercased).
LICENSE_OVERRIDES = {
    "markdown": "BSD-3-Clause",
    "plotly": "MIT",
    "volatility3": "VSL-1.0",          # Volatility Software License v1.0 (BSD-derived)
    "memprocfs": "AGPL-3.0-or-later",
    "weasyprint": "BSD-3-Clause",
    "cairocffi": "BSD-3-Clause",
    "cairosvg": "LGPL-3.0-or-later",
    "yara-python": "Apache-2.0",
}

_REQ_RE = re.compile(r"^([A-Za-z0-9._-]+)\s*([<>=!~]=?.*)?$")
_PIN_RE = re.compile(r"^==\s*([^,;\s]+)")


def pinned_version(spec: str) -> str:
    """Return the exact version from an ``==`` spec, or '' if not pinned."""
    m = _PIN_RE.match(spec or "")
    return m.group(1) if m else ""


def parse_requirements() -> list[tuple[str, str]]:
    """Return [(name, version_spec), ...] from requirements.txt (comments skipped)."""
    out: list[tuple[str, str]] = []
    for raw in REQUIREMENTS.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        m = _REQ_RE.match(line)
        if not m:
            continue
        out.append((m.group(1), (m.group(2) or "").strip()))
    return out


def resolve_license(name: str) -> str:
    key = name.lower()
    try:
        meta = md.metadata(name)
    except md.PackageNotFoundError:
        return LICENSE_OVERRIDES.get(key, "UNKNOWN")
    # Prefer a curated SPDX id when the package's own metadata is messy.
    if key in LICENSE_OVERRIDES:
        return LICENSE_OVERRIDES[key]
    lic = (meta.get("License") or "").strip()
    if lic and len(lic) <= 40 and "\n" not in lic:
        return lic
    for value in meta.get_all("Classifier") or []:
        if value.startswith("License ::"):
            return value.split("::")[-1].strip()
    return "UNKNOWN"


def resolve_version(name: str) -> tuple[str, bool]:
    """Return (version, installed). Falls back to '' when not installed."""
    try:
        return md.version(name), True
    except md.PackageNotFoundError:
        return "", False


def build_components(reqs: list[tuple[str, str]]) -> list[dict]:
    components = []
    for name, spec in reqs:
        version, installed = resolve_version(name)
        license_id = resolve_license(name)
        # Prefer the concrete installed version; otherwise fall back to the
        # exact ``==`` pin so every component carries a specific version.
        effective = version or pinned_version(spec)
        comp: dict = {
            "type": "library",
            "bom-ref": f"pkg:pypi/{name.lower()}",
            "name": name,
            "version": effective or "unknown",
            "purl": f"pkg:pypi/{name.lower()}@{effective}" if effective else f"pkg:pypi/{name.lower()}",
            "scope": "required",
            "licenses": [{"license": {"id" if license_id != "UNKNOWN" else "name": license_id}}],
            "properties": [
                {"name": "requirement:spec", "value": spec or "(unpinned)"},
                {"name": "resolved:installed", "value": "true" if installed else "false"},
            ],
        }
        components.append(comp)
    return components


def build_sbom(reqs: list[tuple[str, str]]) -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [{"vendor": "FanGetFameFast", "name": "generate_sbom.py", "version": "1.0"}],
            "component": {
                "type": "application",
                "bom-ref": "pkg:github/vriesrichardde/fangetfamefast",
                "name": "FanGetFameFast",
                "description": "FAN/FAME/FAST agentic forensics solution",
                "licenses": [
                    {"license": {"id": "Apache-2.0"}},
                    {"license": {"id": "MIT"}},
                ],
                "externalReferences": [
                    {"type": "vcs", "url": "https://github.com/vriesrichardde/FanGetFameFast"}
                ],
            },
        },
        "components": build_components(reqs),
    }


def render_markdown(sbom: dict) -> str:
    rows = []
    for c in sbom["components"]:
        lic = c["licenses"][0]["license"]
        lic_str = lic.get("id") or lic.get("name")
        props = {p["name"]: p["value"] for p in c["properties"]}
        installed = "yes" if props.get("resolved:installed") == "true" else "no"
        rows.append(f"| {c['name']} | {c['version']} | {props.get('requirement:spec','')} | {lic_str} | {installed} |")
    body = "\n".join(rows)
    meta = sbom["metadata"]
    return (
        f"# FanGetFameFast — Software Bill of Materials\n\n"
        f"- **Format:** CycloneDX {sbom['specVersion']} (`sbom.json`)\n"
        f"- **Serial:** {sbom['serialNumber']}\n"
        f"- **Generated:** {meta['timestamp']}\n"
        f"- **Application license:** Apache-2.0 OR MIT\n"
        f"- **Direct dependencies:** {len(sbom['components'])} (from `requirements.txt`)\n\n"
        f"Regenerate with `python3 scripts/generate_sbom.py`.\n\n"
        f"## Direct Python dependencies\n\n"
        f"| Package | Version | Spec | License | Installed |\n"
        f"|---------|---------|------|---------|-----------|\n"
        f"{body}\n\n"
        f"> Every dependency is pinned to an exact version (`==`) in "
        f"`requirements.txt`. Packages marked *Installed: no* are "
        f"optional/platform-specific (e.g. memprocfs is x86-64 only) and were "
        f"not present in the generating environment; their version is taken "
        f"from the pin.\n\n"
        f"## License notes\n\n"
        f"- **AGPL-3.0** component (`memprocfs`) is copyleft. It is "
        f"invoked as separate tools / optional modules and are not statically linked "
        f"into the dual Apache-2.0/MIT codebase, but redistribution of a combined "
        f"work should account for their terms.\n"
        f"- **LGPL-3.0** (`CairoSVG`) and **VSL-1.0** (`volatility3`) likewise impose "
        f"their own redistribution conditions.\n"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true", help="exit 1 if sbom.json component set is stale")
    args = ap.parse_args()

    reqs = parse_requirements()
    sbom = build_sbom(reqs)

    if args.check:
        if not SBOM_JSON.exists():
            print("sbom.json missing", file=sys.stderr)
            return 1
        old = json.loads(SBOM_JSON.read_text())
        old_set = {(c["name"], c["version"]) for c in old.get("components", [])}
        new_set = {(c["name"], c["version"]) for c in sbom["components"]}
        if old_set != new_set:
            print("sbom.json is stale; run: python3 scripts/generate_sbom.py", file=sys.stderr)
            return 1
        print("sbom.json is up to date")
        return 0

    SBOM_JSON.write_text(json.dumps(sbom, indent=2) + "\n", encoding="utf-8")
    SBOM_MD.write_text(render_markdown(sbom), encoding="utf-8")
    print(f"Wrote {SBOM_JSON.relative_to(ROOT)} ({len(sbom['components'])} components)")
    print(f"Wrote {SBOM_MD.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
