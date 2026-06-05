# Fan Get Fame Fast

**Forensic investigation platform for SANS SIFT analysts**

Fan Get Fame Fast is an agentic forensic investigation platform that combines three modules — **FAN** (network forensics), **FAME** (memory forensics), and **FAST** (storage forensics) — and an AI coordinator that drives cross-module correlation. A suspicious network connection triggers FAN to ask FAME which process owned that socket, and FAST which file on disk launched it. The analyst asks; the platform finds.

**Authors:** Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin  
**Platform:** Ubuntu 24.04 LTS (x86-64)  
**License:** Apache 2.0 or MIT (your choice) — see [LICENSE](LICENSE)

---

## What it does

- **Compresses investigation time** during a live incident so containment decisions can be made while the attack is still in progress.
- **Delivers a draft forensics report** in days, not months.
- **Eliminates paperwork** — reports are auto-generated in Markdown, PDF, PPTX, and DOCX. The analyst spends 100% of their time on analysis.

---

## Modules

| Module | Domain | Entry point |
|--------|--------|-------------|
| FAN | Network forensics (PCAP) | `./scripts/analyze_pcap.sh` |
| FAME | Memory forensics (Volatility 3 / Memory Baseliner) | `./scripts/fame_analyze.sh` |
| FAST | Storage forensics (TSK / EWF tools / bulk_extractor) | `./scripts/fast_analyze.sh` |

All three modules are live. When more than one module has run against the same case ID, a combined unified report is produced automatically.

---

## Quick start

```bash
# Network forensics
./scripts/analyze_pcap.sh /path/to/capture.pcap
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2025-001

# Memory forensics
./scripts/fame_analyze.sh /path/to/image.mem
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234

# Storage forensics (E01, VMDK, raw, or any TSK-compatible format)
./scripts/fast_analyze.sh /path/to/image.E01
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234
```

Without `--case-id` the script prompts interactively.

---

## Installation

### Requirements

- Ubuntu 22.04 or 24.04 LTS (x86-64)
- Python 3.10+
- Claude Code (AI coordinator)
- OpenCTI instance (local or remote) — optional but recommended

See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for full server sizing, service account setup, and security hardening.

### Install steps

```bash
# 1. Clone the repository
git clone <repo-url> ~/FanGetFameFast
cd ~/FanGetFameFast

# 2. Create a virtual environment and install Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 3. Install system forensic tools (Volatility 3, TSK, Suricata, YARA, …)
sudo ./scripts/install_dependencies.sh

# 4. Create the folder structure and configure sudoers for read-only mounts
./scripts/setup_folder_structure.sh
sudo ./scripts/setup_sudoers.sh

# 5. Set API credentials
cp templates/set_env_template.sh ~/.soc_env
# Edit ~/.soc_env and add your keys, then:
echo 'source ~/.soc_env' >> ~/.bashrc
source ~/.soc_env
```

### Alternative: VS Code Dev Container

A ready-to-use [Dev Container](.devcontainer/) builds the full toolchain (tshark,
Volatility 3, The Sleuth Kit, EWF tools, bulk_extractor, YARA, Suricata,
WeasyPrint, and the Claude Code CLI) on Debian Bookworm — amd64 and arm64 both
supported.

```bash
git clone <repo-url> FanGetFameFast
cd FanGetFameFast
code .
# Then: "Reopen in Container" (Dev Containers extension), or `devcontainer up`.
```

**Mounting evidence (optional):** set `FGFF_EVIDENCE_INPUT` on the **host** to a
directory of memory/disk images **before** building the container. It is mounted
read-only at `/home/vscode/evidence` inside the container.

```bash
export FGFF_EVIDENCE_INPUT="/path/to/your/evidence"   # then rebuild the container
```

If the variable is unset the container still builds and starts normally — the
evidence mount simply falls back to a harmless placeholder, so you can explore
the solution and supply evidence paths manually later.

### Required API credentials

| Variable | Purpose |
|----------|---------|
| `PERPLEXITY_API_KEY` | Live threat intel lookups |
| `OPENCTI_URL` | OpenCTI base URL |
| `OPENCTI_API_KEY` | OpenCTI API token |

### Verify the installation

```bash
./scripts/test_solution.sh
./scripts/test_mcp_servers.sh
```

---

## How FAN works

1. Analyst provides a PCAP path.
2. 22 protocol threat-detection modules run (ARP, DHCP, DNS, HTTP/S, ICMP, LLMNR, mDNS, NetBIOS, NBNS, NTP, QUIC, SNMP, SSDP, STUN, TCP, TLS, UDP, YARA sweep, Suricata IDS, certificate inspection, IP reputation, file hash extraction).
3. A versioned incident report (Markdown + PDF) is generated.
4. The report is uploaded to the investigations vault at `/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop.
5. All `./analysis/` working directories are deleted — the folder is left empty after a completed investigation.

## How FAME works

1. Analyst provides a memory image path.
2. Volatility 3 plugins run: `pslist`, `psscan`, `netstat`, `netscan`, `malfind`, `svcscan`, `modules`, `filescan`, `cmdline`. Memory Baseliner runs process/driver/service comparisons. Linux images fall back to strings-based extraction when ISF symbols are unavailable.
3. Reports are generated: Markdown + PDF + PPTX + DOCX.
4. If FAN or FAST reports exist for the same case ID, a combined unified report is generated automatically.
5. All reports are uploaded to the investigations vault.

## How FAST works

1. Analyst provides a disk image path.
2. The image is mounted read-only. TSK tools run (`fls`, `fsstat`, `mmls`, `ils`, `icat`). Artifacts are extracted: EVTX, registry hives, prefetch, MFT, USN journal, SRUM, browser history. `bulk_extractor` carves the image.
3. Reports are generated: Markdown + PDF + PPTX + DOCX.
4. If FAN or FAME reports exist for the same case ID, a combined unified report is generated automatically.
5. All reports are uploaded to the investigations vault.

---

## Report format

Every investigation produces one report in two registers:

**Management summary** — plain language, no IPs or technical identifiers. Written for a CISO, legal team, or law enforcement audience.

**Technical body** — precise identifiers (workstation names, IPs, ports, protocols, payload sizes, malware family names), scoped conclusions that explicitly name the evidence source.

Output formats: Markdown, PDF, PPTX (Microsoft PowerPoint), DOCX (Microsoft Word). When more than one module has run for the same case ID, a combined cross-module report is generated in all four formats plus a timestamped ZIP artifact package.

---

## Obsidian vault (institutional memory)

The vault at `./vault/` is a plain-Markdown knowledge graph. TTPs, IOCs, threat actors, malware profiles, risks, and cybersecurity concepts accumulate here across investigations.

```
vault/
├── TTPs/          — One note per MITRE ATT&CK (sub)technique
├── IOCs/          — One note per indicator (hash, IP, domain, URL, …)
├── ThreatActors/  — Threat group profiles
├── Malware/       — Malware family profiles
├── Concepts/      — Generic cybersecurity concepts
├── Risks/         — Risk assessments per case/asset
├── Cases/         — Post-investigation summaries
├── Templates/     — Note schemas (do not edit manually)
└── Dashboard.md   — Auto-maintained index
```

IOC values stored in the vault are defanged (`192[.]168[.]1[.]1`, `evil[.]com`).

Query the vault before an investigation:

```bash
./scripts/vault_context.sh "Cobalt Strike"
python3 lib/vault_query.py --search powershell
```

---

## MCP servers

Three Model Context Protocol servers expose vault and CTI access to the AI coordinator:

| Server | Access | Root |
|--------|--------|------|
| `evidence` | Read-only (SSH) | `/home/sansforensics/evidence/` on ubuntudesktop |
| `investigations` | Read-write | `/home/sansforensics/cases/` on ubuntudesktop |
| `opencti` | Read-write | Your OpenCTI instance |

---

## Live threat intel (Perplexity)

When the vault has no answer for an unknown artifact, CVE, malware family, threat actor, or tool, the platform queries Perplexity for real-time web-sourced intelligence:

```bash
./scripts/perplexity_search.sh ioc     203.0.113.42
./scripts/perplexity_search.sh malware "Cobalt Strike"
./scripts/perplexity_search.sh ttp     T1071.001
./scripts/perplexity_search.sh cve     CVE-2024-1234
./scripts/perplexity_search.sh actor   APT29
./scripts/perplexity_search.sh tool    mimikatz

# Save result to vault automatically
./scripts/perplexity_search.sh malware "Cobalt Strike" --save-vault
```

Privacy rule: never include live case hostnames, usernames, or internal IPs in Perplexity queries.

---

## Python library

| Module | Purpose |
|--------|---------|
| `lib/obsidian_bridge.py` | Low-level vault I/O: `write_note`, `read_note`, `append_to_note`, `search_vault`, `patch_section` |
| `lib/knowledge_extractor.py` | High-level record functions: `record_ioc`, `record_ttp`, `record_threat_actor`, `record_malware`, `record_risk`, `record_concept`, `open_case`, `close_case` |
| `lib/vault_query.py` | Read-path queries: `get_context_for_ioc`, `get_context_for_ttp`, `get_active_cases`, `get_top_risks`, `search_context` |
| `lib/perplexity_client.py` | Real-time threat intel via Perplexity.ai |
| `lib/md_to_pdf.py` | Markdown → styled PDF (WeasyPrint, cover page, CONFIDENTIAL footer, pagination) |
| `lib/generate_pptx_report.py` | Management PowerPoint (7 slides, CISO language) |
| `lib/generate_fame_report.py` | FAME report generator (MD + PDF + PPTX + DOCX) |
| `lib/generate_fast_report.py` | FAST report generator (MD + PDF + PPTX + DOCX) |
| `lib/generate_combined_report.py` | Unified cross-module report (FAN + FAME + FAST) |
| `lib/case_packager.py` | Bundle all artifacts into a timestamped ZIP and upload to investigations vault |
| `lib/investigations_upload.py` | Copy individual report files to the investigations vault via MCP |
| `lib/fan_*.py` | 22 FAN protocol threat-detection modules |

### Self-tests

```bash
python3 lib/obsidian_bridge.py                  # vault write/read/search round-trip
python3 lib/knowledge_extractor.py --test       # all record types + Dashboard refresh
python3 lib/vault_query.py --search powershell
```

---

## Constraints

- Evidence integrity is paramount. Never write to `/mnt/`, `/media/`, or any `evidence/` directory. This is **enforced in code** by `lib/path_guard.py`: every Python write chokepoint (`obsidian_bridge`, `md_to_pdf`, all `generate_*` report generators, `case_packager`) routes through `assert_writable`/`guard_output_dir`, which hard-fail (`WritePolicyError`) on any write outside the approved output folders (`analysis`, `exports`, `reports`, `archive`, `vault`, `cases`, `demo`, `docs`, plus the OS temp dir). The `investigations` MCP server independently rejects writes under `/mnt`, `/media`, or `EVIDENCE_ROOT`, and the analyze scripts source `scripts/pathguard.sh` to verify evidence mounts are read-only before any analysis runs. Validate the policy with `python3 lib/path_guard.py --test`.
- Analysis working files go to `./analysis/` only. That folder must be empty after a completed investigation.
- Finalized reports are stored in the investigations vault, not in the project directory.
- Report timestamps use the timezone of the incident's geographical location. If unknown, use UTC and state it explicitly.
- Internal processing, vault storage, and log entries use UTC.
- Scoped conclusions must cite their evidence source (e.g., "as observed in the PCAP file", "as found in the memory dump").

---

## Documentation

| Document | Contents |
|----------|---------|
| [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) | Server sizing, service account setup, MCP configuration, security hardening, backup, troubleshooting |
| [docs/USER_GUIDE.md](docs/USER_GUIDE.md) | Investigation workflows, vault usage, report interpretation |
| [docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md) | Module internals, library API, MCP server protocol |
| [DISCLAIMER.md](DISCLAIMER.md) | Authorized-use statement and no-warranty disclaimer |

---

## License

Fan Get Fame Fast is dual-licensed under your choice of the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)) or the **MIT License** ([LICENSE-MIT](LICENSE-MIT)). See [LICENSE](LICENSE) for the dual-license notice.

*Copyright 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin*
