# FanGetFameFast — Software Bill of Materials

- **Format:** CycloneDX 1.5 (`sbom.json`)
- **Serial:** urn:uuid:4c847484-3ede-4ba3-a95f-ab0ebbb94a12
- **Generated:** 2026-06-15T19:31:53Z
- **Application license:** Apache-2.0 OR MIT
- **Direct dependencies:** 11 (from `requirements.txt`)

Regenerate with `python3 scripts/generate_sbom.py`.

## Direct Python dependencies

| Package | Version | Spec | License | Installed |
|---------|---------|------|---------|-----------|
| weasyprint | 68.1 | ==68.1 | BSD-3-Clause | no |
| cairocffi | 1.7.1 | ==1.7.1 | BSD-3-Clause | no |
| CairoSVG | 2.9.0 | ==2.9.0 | LGPL-3.0-or-later | no |
| python-pptx | 1.0.2 | ==1.0.2 | UNKNOWN | no |
| python-docx | 1.2.0 | ==1.2.0 | UNKNOWN | no |
| Markdown | 3.10.2 | ==3.10.2 | BSD-3-Clause | no |
| PyYAML | 6.0.3 | ==6.0.3 | UNKNOWN | no |
| plotly | 5.18.0 | ==5.18.0 | MIT | no |
| volatility3 | 2.0.0 | ==2.0.0 | VSL-1.0 | no |
| yara-python | 4.3.1 | ==4.3.1 | Apache-2.0 | no |
| memprocfs | 5.0.0 | ==5.0.0 | AGPL-3.0-or-later | no |

> Every dependency is pinned to an exact version (`==`) in `requirements.txt`. Packages marked *Installed: no* are optional/platform-specific (e.g. memprocfs is x86-64 only) and were not present in the generating environment; their version is taken from the pin.

## License notes

- **AGPL-3.0** component (`memprocfs`) is copyleft. It is invoked as separate tools / optional modules and are not statically linked into the dual Apache-2.0/MIT codebase, but redistribution of a combined work should account for their terms.
- **LGPL-3.0** (`CairoSVG`) and **VSL-1.0** (`volatility3`) likewise impose their own redistribution conditions.
