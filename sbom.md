# FanGetFameFast — Software Bill of Materials

- **Format:** CycloneDX 1.5 (`sbom.json`)
- **Serial:** urn:uuid:429e4762-737f-4ca3-888e-5b7cd78ad32f
- **Generated:** 2026-06-05T08:58:29Z
- **Application license:** Apache-2.0 OR MIT
- **Direct dependencies:** 21 (from `requirements.txt`)

Regenerate with `python3 scripts/generate_sbom.py`.

## Direct Python dependencies

| Package | Version | Spec | License | Installed |
|---------|---------|------|---------|-----------|
| weasyprint | 68.1 | >=60.0 | BSD-3-Clause | yes |
| cairocffi | 1.7.1 | >=1.7.0 | BSD-3-Clause | yes |
| CairoSVG | 2.9.0 | >=2.7.0 | LGPL-3.0-or-later | yes |
| python-pptx | 1.0.2 | >=1.0.0 | MIT | yes |
| python-docx | 1.2.0 | >=1.1.0 | MIT | yes |
| xlsxwriter | 3.2.0 | >=3.2.0 | BSD-2-Clause | yes |
| Markdown | 3.10.2 | >=3.4.0 | BSD-3-Clause | yes |
| requests | 2.34.2 | >=2.31.0 | Apache-2.0 | yes |
| urllib3 | 2.7.0 | >=2.0.0 | MIT | yes |
| PyYAML | 6.0.3 | >=6.0 | MIT | yes |
| numpy | 2.2.6 | >=1.26.0 | BSD-3-Clause | yes |
| scipy | 1.15.3 | >=1.11.0 | BSD-3-Clause | yes |
| networkx | 3.4.2 | >=3.2.0 | BSD-3-Clause | yes |
| plotly | 5.18.0 | >=5.18.0 | MIT | no |
| rapidfuzz | 3.14.5 | >=3.0.0 | MIT | yes |
| datasketch | 1.10.0 | >=1.6.0 | MIT | yes |
| graphifyy | 0.8.25 | >=0.7.0 | MIT | yes |
| volatility3 | 2.0.0 | >=2.0.0 | VSL-1.0 | no |
| yara-python | 4.3.1 | >=4.3.0 | Apache-2.0 | yes |
| sslyze | 5.0.0 | >=5.0.0 | AGPL-3.0-or-later | no |
| memprocfs | 5.0.0 | >=5.0.0 | AGPL-3.0-or-later | no |

> Versions reflect what is resolved in the generating environment. Packages marked *Installed: no* are optional/platform-specific (e.g. memprocfs is x86-64 only) and carry the `requirements.txt` minimum.

## License notes

- **AGPL-3.0** components (`sslyze`, `memprocfs`) are copyleft. They are invoked as separate tools / optional modules and are not statically linked into the dual Apache-2.0/MIT codebase, but redistribution of a combined work should account for their terms.
- **LGPL-3.0** (`CairoSVG`) and **VSL-1.0** (`volatility3`) likewise impose their own redistribution conditions.
