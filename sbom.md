# FanGetFameFast — Software Bill of Materials

- **Format:** CycloneDX 1.5 (`sbom.json`)
- **Serial:** urn:uuid:25b8523a-eaac-47c3-924d-8120c774b0a5
- **Generated:** 2026-06-07T07:30:19Z
- **Application license:** Apache-2.0 OR MIT
- **Direct dependencies:** 12 (from `requirements.txt`)

Regenerate with `python3 scripts/generate_sbom.py`.

## Direct Python dependencies

| Package | Version | Spec | License | Installed |
|---------|---------|------|---------|-----------|
| weasyprint | 68.1 | ==68.1 | BSD-3-Clause | yes |
| cairocffi | 1.7.1 | ==1.7.1 | BSD-3-Clause | yes |
| CairoSVG | 2.9.0 | ==2.9.0 | LGPL-3.0-or-later | yes |
| python-pptx | 1.0.2 | ==1.0.2 | MIT | yes |
| python-docx | 1.2.0 | ==1.2.0 | MIT | yes |
| Markdown | 3.10.2 | ==3.10.2 | BSD-3-Clause | yes |
| PyYAML | 6.0.3 | ==6.0.3 | MIT | yes |
| plotly | 5.18.0 | ==5.18.0 | MIT | no |
| volatility3 | 2.0.0 | ==2.0.0 | VSL-1.0 | no |
| yara-python | 4.3.1 | ==4.3.1 | Apache-2.0 | yes |
| sslyze | 5.0.0 | ==5.0.0 | AGPL-3.0-or-later | no |
| memprocfs | 5.0.0 | ==5.0.0 | AGPL-3.0-or-later | no |

> Every dependency is pinned to an exact version (`==`) in `requirements.txt`. Packages marked *Installed: no* are optional/platform-specific (e.g. memprocfs is x86-64 only) and were not present in the generating environment; their version is taken from the pin.

## License notes

- **AGPL-3.0** components (`sslyze`, `memprocfs`) are copyleft. They are invoked as separate tools / optional modules and are not statically linked into the dual Apache-2.0/MIT codebase, but redistribution of a combined work should account for their terms.
- **LGPL-3.0** (`CairoSVG`) and **VSL-1.0** (`volatility3`) likewise impose their own redistribution conditions.
