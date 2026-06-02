# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Authors

Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin

## Solution name & philosophy

**FanGetFameFast** = **FAN** (network forensics) + **FAME** (memory forensics) + **FAST** (storage forensics).

The three modules interrogate each other. A suspicious network connection found in a PCAP triggers FAN to ask FAME which process opened that connection, and FAST which application or file on disk initiated it. Claude is the agentic coordinator that orchestrates this back-and-forth conversation between modules.

**What "fast-track" means:**
- During a live incident: compress investigation time so containment decisions can be made while the attack is still happening.
- Post-mortem: deliver a draft forensics report within 1 week (major incidents take longer) instead of months.

**Definition of success:** the analyst spends 100% of their time on analysis. Reports are auto-generated. Zero time on paperwork.

**Target user:** SANS SIFT workstation users, junior to senior. The interface translates their forensic question into an answer — they ask, the solution finds.

**Core problems solved:**
1. Correlation under time pressure — a human cannot quickly cross-reference a network connection, a running process, and a file on disk. The three modules do it automatically.
2. Nitty-gritty detail — small artifacts that get skipped when time is short are caught by automated analysis.

## Environment

Runs on Ubuntu 24.04 LTS (x86-64). See the global `~/.claude/CLAUDE.md` for the full inventory of installed forensic tools, their invocation paths, and shell aliases.

In the devcontainer, evidence files are located at `/home/vscode/evidence`.

## Module status

| Module | Domain | Status |
|--------|--------|--------|
| FAN | Network forensics (PCAP) | Live |
| FAME | Memory forensics (Volatility 3 + optional Memory Baseliner) | Live |
| FAST | Storage forensics (disk images — TSK / EWF tools) | Live |

All three modules are live. FAME and FAST auto-detect sibling module reports for the
same case ID and produce a combined unified report (Markdown + PDF + PPTX + DOCX)
when more than one module has run.

## Agentic coordinator

Claude is the coordinator. It decides which module to invoke, in what order, and when the investigation is complete enough to generate a report.

**When uncertain:** Claude asks the human analyst for input and records the answer in the vault so the same question is not asked again.

**Human-in-the-loop:** The analyst can instruct Claude at any time to update or clarify any section of the report. Claude applies the change and remembers the preference for future investigations.

**Stop condition:** Claude determines the investigation is complete when all available evidence sources have been queried, no new pivots remain, and findings can be stated with a scoped conclusion that cites its evidence source (e.g., "No signs of lateral movement observed in the PCAP file").

## Report structure & voice

Every investigation produces one report with two distinct registers.

### Management summary (CISO language)
- No technical identifiers: no IPs, no ports, no file sizes, no workstation IDs.
- Business causality in plain language: what happened, when, and what the business impact was.
- Example: *"On May 1st, 2025 at 1300 CET the workstation initiated the C2 connection that displayed the ransomware note."*

### Technical body (Analyst language)
- Precise identifiers: workstation name/ID, IP addresses, ports, protocols, payload sizes, malware family names.
- Scoped conclusions that explicitly name the evidence source.
- Example: *"On May 1st, 2025, at 1300 CET the workstation (AB1110) initiated the outbound C2 connection to 1.2.3.4 on TCP 9999 and downloaded the payload (10 MB). At 1305 CET the payload detonated, locked the machine, displayed the ransomware note, and began encrypting files using the PLAY ransomware. No signs of lateral movement to other machines were observed in the PCAP file."*

### Audience
Reports may be consumed by: CISO, Legal, Law Enforcement, IT, Internal Audit. A single report with a management summary followed by a full technical body serves all audiences. Multiple standalone versions per audience may be generated in future iterations.

### Timestamps in reports
Use the timezone of the geographical location where the incident took place. If the incident location timezone is unknown, use UTC and state that explicitly.

## Obsidian vault (long-term memory)

The vault is a plain-Markdown knowledge graph at `./vault/`. It is the project's institutional memory — TTPs, IOCs, threat actors, malware, risks, and cybersecurity concepts are recorded here as investigations run and accumulate over time.

**Vault folder layout:**

| Folder | Contains |
|--------|----------|
| `TTPs/` | One note per MITRE ATT&CK (sub)technique observed |
| `IOCs/` | One note per indicator (hash, IP, domain, URL, …) |
| `ThreatActors/` | Threat group profiles |
| `Malware/` | Malware family profiles |
| `Concepts/` | Generic cybersecurity concepts |
| `Risks/` | Risk assessments per case/asset |
| `Cases/` | Post-investigation summaries (metadata only, never raw evidence) |
| `Templates/` | Note schemas — do not modify manually |
| `Dashboard.md` | Auto-maintained index (recent cases, IOCs, risks, TTPs, actors) |

IOC values stored in the vault are **defanged** (`192[.]168[.]1[.]1`, `evil[.]com`, `hxxps://…`).

**What gets written to the vault:** anything discovered during an investigation — automatically by the solution or manually by the analyst. When the vault has conflicting intel across cases (e.g., the same port used for different purposes in two incidents), both entries are preserved with their case context rather than overwriting.

**Decision order when answering an analyst question:** vault → Perplexity → record confirmed findings back to vault.

## Python library

| Module | Purpose |
|--------|---------|
| `lib/obsidian_bridge.py` | Low-level vault I/O: `write_note`, `read_note`, `append_to_note`, `search_vault`, `patch_section` |
| `lib/knowledge_extractor.py` | High-level record functions: `record_ioc`, `record_ttp`, `record_threat_actor`, `record_malware`, `record_risk`, `record_concept`, `open_case`, `close_case` — each also pushes new intel to OpenCTI |
| `lib/vault_query.py` | Read-path queries: `get_context_for_ioc`, `get_context_for_ttp`, `get_active_cases`, `get_top_risks`, `get_related_notes`, `search_context` |
| `lib/perplexity_client.py` | Real-time threat intel via Perplexity.ai: `lookup_ioc`, `lookup_malware`, `lookup_ttp`, `lookup_cve`, `lookup_actor`, `lookup_tool`, `search` |
| `lib/md_to_pdf.py` | Markdown → styled PDF converter: cover page, running page-header stripe, "Page X of Y" pagination, CONFIDENTIAL footer — wraps WeasyPrint, no pandoc required |
| `lib/generate_pptx_report.py` | Management PowerPoint generator (7 slides, CISO language, python-pptx): cover, executive summary, threat landscape, IDS/YARA alerts, IOCs, recommendations, module coverage |
| `lib/case_packager.py` | Package all artifacts (MD + PDF + PPTX + module JSON/CSV) into a timestamped ZIP and upload via SSH/SCP to the investigations vault |
| `lib/investigations_upload.py` | Copy individual report files into the investigations vault (`/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop) — supports MD, PDF, PPTX, DOCX, ZIP |
| `lib/fan_*.py` | FAN analysis modules (22 protocol detectors + pcap_analyzer, generate_pcap_report) |
| `lib/generate_fame_report.py` | FAME report generator: Markdown + PDF + PPTX (8 slides) + DOCX from `./analysis/memory/` Volatility 3 outputs |
| `lib/generate_fast_report.py` | FAST report generator: Markdown + PDF + PPTX (8 slides) + DOCX from `./analysis/storage/` and `./exports/` TSK outputs |
| `lib/generate_combined_report.py` | Unified cross-module report: merges FAN + FAME + FAST reports into a single Markdown + PDF + PPTX + DOCX; automatically embeds `<case_id>_correlation.md` in Section 2 when present |
| `lib/correlate_findings.py` | Cross-module correlation engine: matches netscan→PCAP (FAN↔FAME), process→deleted-file (FAME↔FAST), DNS→carved-URL (FAN↔FAST); outputs `<case_id>_correlation.md` + `.json` |

## Skills

User-invokable skills (invoke with `/skill-name` inside Claude Code):

| Skill | Invoke | Purpose |
|-------|--------|---------|
| Batch analysis (all evidence) | `/investigate-all [evidence_dir]` | Enumerate all FAME + FAST evidence files and run them sequentially in-session; default dir: `/home/vscode/evidence` |
| Memory Forensics (FAME) | `/fame` | Run Volatility 3 (+ Memory Baseliner when a baseline is supplied); generate MD + PDF + PPTX + DOCX; upload to investigations vault |
| Storage Forensics (FAST) | `/fast` | Run TSK / EWF tools; generate MD + PDF + PPTX + DOCX; upload to investigations vault |
| Cross-module correlation | `/correlate` | Compute actual FAN↔FAME / FAME↔FAST / FAN↔FAST matches from raw artifact files; run before `./analysis/` is cleaned up |
| CTI-OpenCTI-lookup | `/fan-opencti-lookup --case-id <id>` | Check extracted IPs and FQDNs against OpenCTI; write `opencti_lookup.md` to investigations vault |
| Vault query (pre-investigation) | `/obsidian-query` | Query the vault before an investigation for known context |
| Vault recording (post-investigation) | `/obsidian-record` | Record confirmed findings into the vault (also pushes to OpenCTI) |
| Unknown artifact / live threat intel | `/perplexity-lookup` | Live threat intel search for an unknown artifact |
| Markdown to PDF | `/md-to-pdf` | Convert any Markdown file to a styled PDF |
| Remove Case | `/remove-case` | Remove a case directory from the investigations vault |
| Archive reports | `/archive-reports [campaign_id]` | Move a completed campaign folder from `./reports/<id>/` to `./archive/<id>/` (also migrates legacy flat files); interactive if no id given |

FAN analysis skills: `fan-arp-threats`, `fan-cert-inspector`, `fan-dhcp-threats`, `fan-dns-threats`, `fan-extract-ip-fqdn`, `fan-file-hashes`, `fan-http-threats`, `fan-icmp-threats`, `fan-ip-lookup`, `fan-llmnr-threats`, `fan-mdns-threats`, `fan-nbns-threats`, `fan-netbios-threats`, `fan-ntp-threats`, `fan-opencti-lookup`, `fan-quic-threats`, `fan-report`, `fan-snmp-threats`, `fan-ssdp-threats`, `fan-stun-threats`, `fan-suricata`, `fan-tcp-threats`, `fan-tls-inspector`, `fan-udp-threats`, `fan-yara-pcap`.

FAME skill: `fame` — memory forensics pipeline (Volatility 3 + optional Memory Baseliner + report generation + upload).

FAST skill: `fast` — storage forensics pipeline (TSK + EWF tools + artifact extraction + report generation + upload).

## Forensics agent network (FAN)

**FAN** is a manual PCAP investigation pipeline. There is no daemon or auto-processing. The analyst starts every investigation explicitly.

```bash
# Start a PCAP investigation (interactive — prompts for case ID)
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive with explicit case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2025-001
```

**Pipeline:**
1. Analyst drops PCAP into the evidence vault or provides a path directly.
2. `analyze_pcap.sh` runs 22 protocol threat-detection modules. All WIP output goes to `./analysis/`.
3. A versioned incident report (Markdown + PDF) is generated.
4. The report is copied to the investigations vault at `/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop.
5. All `./analysis/` WIP directories for this PCAP are deleted — the analysis folder is left empty.

**Investigations vault** — case folders live at `/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop.

## Forensic analysis memory (FAME)

**FAME** is a manual memory forensics pipeline built on Volatility 3, with optional Memory Baseliner comparison. Baseliner runs only when a clean-system baseline is supplied at `baselines/baseline.json` (and `/opt/memory-baseliner/baseline.py` is installed); otherwise it is skipped and the rest of the pipeline proceeds normally.

```bash
# Start a memory investigation (interactive — prompts for case ID)
./scripts/fame_analyze.sh /path/to/image.mem

# Non-interactive with explicit case ID and hostname
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234
```

**Pipeline:**
1. Analyst provides a memory image path.
2. `fame_analyze.sh` runs Volatility 3 plugins (pslist, psscan, netstat, netscan, malfind, svcscan, modules, filescan, cmdline). If a `baselines/baseline.json` is present, it also runs Memory Baseliner (proc/drv/svc comparison); without one this step is skipped. Linux images fall back to strings-based extraction when ISF symbols are unavailable.
3. Reports are generated: Markdown + PDF + PPTX (Microsoft PowerPoint, 8 slides) + DOCX (Microsoft Word).
4. If FAN or FAST reports exist for the same case ID, a combined unified report is also generated.
5. All reports are uploaded to the investigations vault via MCP (`investigations_write_file`).

**Output voice:** Claude instructs itself to *enhance and elaborate when necessary* on every FAME report section.

## Forensic analysis storage (FAST)

**FAST** is a manual disk-image forensics pipeline built on The Sleuth Kit, EWF tools, and bulk_extractor.

```bash
# Start a storage investigation (interactive — prompts for case ID)
./scripts/fast_analyze.sh /path/to/image.E01

# Non-interactive with explicit case ID and hostname
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234
```

**Pipeline:**
1. Analyst provides a disk image path (E01, VMDK, raw, or any TSK-compatible format).
2. `fast_analyze.sh` mounts the image read-only, runs TSK tools (fls, fsstat, mmls, ils, icat), extracts artifacts (EVTX, registry, prefetch, MFT, USN journal, SRUM, browser history), and runs bulk_extractor for carving.
3. Reports are generated: Markdown + PDF + PPTX (8 slides) + DOCX.
4. If FAN or FAME reports exist for the same case ID, a combined unified report is also generated.
5. All reports are uploaded to the investigations vault via MCP.

**Output voice:** Claude instructs itself to *enhance and elaborate when necessary* on every FAST report section.

MCP servers for vault access:
- `evidence` (read-only, SSH to `sansforensics@ubuntudesktop`, root: `/home/sansforensics/evidence/`): `evidence_list_directory`, `evidence_read_file`, `evidence_get_file_info`, `evidence_find_pcaps`
- `investigations` (read-write): `investigations_list_directory`, `investigations_read_file`, `investigations_write_file`, `investigations_create_directory`, `investigations_delete`, `investigations_get_file_info`, `investigations_list_cases`

The SSH-to-`ubuntudesktop` form above is the canonical (production) registration and is not committed. For local development you can register the same servers as plain local processes (`"command": "python3"`, `args: [".../mcp/evidence_server.py"]`) and point them at a local directory via the `EVIDENCE_ROOT` env var — keep this in your gitignored `.claude/settings.local.json`, not the committed `settings.json`.

## OpenCTI integration (MCP server)

`mcp/opencti_server.py` is a Model Context Protocol server that exposes three tools:

| Tool | Description |
|------|-------------|
| `opencti_search_stix` | Search any STIX entity (malware, threat-actor, campaign, vulnerability, …) |
| `opencti_search_ioc` | Search indicators by value, pattern type (stix/yara/sigma), or keyword |
| `opencti_create_indicator` | Create a new indicator with STIX, YARA, or Sigma pattern |

**Credentials — environment variables (not stored in settings.json):**

```bash
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_API_KEY="your-api-token-here"
```

Set in `~/.soc_env` (copy from `templates/set_env_template.sh`), then add `source ~/.soc_env` to `~/.bashrc`.

Get your API token at **Settings → API access** in the OpenCTI web interface.

## Perplexity.ai (live threat intelligence)

When the vault returns no answer for an unknown artifact, CVE, malware family, threat actor, or tool, query Perplexity for real-time web-sourced intelligence:

```bash
# Requires: export PERPLEXITY_API_KEY="pplx-..." in ~/.soc_env
./scripts/perplexity_search.sh ioc     203.0.113.42
./scripts/perplexity_search.sh malware "Cobalt Strike"
./scripts/perplexity_search.sh ttp     T1071.001
./scripts/perplexity_search.sh cve     CVE-2024-1234
./scripts/perplexity_search.sh actor   APT29
./scripts/perplexity_search.sh tool    mimikatz
./scripts/perplexity_search.sh search  "LSASS dump detection evasion"

# Save result to vault automatically
./scripts/perplexity_search.sh malware "Cobalt Strike" --save-vault
```

**Privacy rule:** never include live case hostnames, usernames, or internal IPs in Perplexity queries.

## Self-tests

```bash
python3 lib/obsidian_bridge.py          # write/read/search round-trip
python3 lib/knowledge_extractor.py --test   # all record types + Dashboard refresh
python3 lib/vault_query.py --search powershell
```

## Constraints

- Evidence integrity is paramount. Never write to `/mnt/`, `/media/`, or any `evidence/` directory.
- Analysis WIP goes to `./analysis/` only. The analysis folder must be empty after a completed investigation.
- Finalized reports are stored in the investigations vault (`/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop).
- Report timestamps use the timezone of the incident's geographical location. If unknown, use UTC and state it explicitly.
- Internal processing, vault storage, and log entries use UTC.
- Scoped conclusions must cite their evidence source (e.g., "as observed in the PCAP file", "as found in the memory dump").
- **Research notes are mandatory and sequential**: do NOT run the next investigation step until the output of the current step has been read, interpreted, and appended to the research notes via `python3 lib/research_notes.py step`. Parallel background tool execution is permitted only when the outputs are logged before launching subsequent steps.

## License

Fan Get Fame Fast is dual-licensed under your choice of the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)) or the **MIT License** ([LICENSE-MIT](LICENSE-MIT)). See [LICENSE](LICENSE) for the dual-license notice and [DISCLAIMER.md](DISCLAIMER.md) for the authorized-use and no-warranty disclaimer.
