# Fan Get Fame Fast

**Forensic investigation platform for SANS SIFT analysts**

**FanGetFameFast** = **FAN** (network forensics) + **FAME** (memory forensics) + **FAST** (storage forensics) — three forensic domains and one AI coordinator working a single incident in one conversation.

The name is also the promise: **fast-track** the investigation. During a live incident the platform compresses analysis time so containment decisions can be made while the attack is still in progress; post-mortem, it delivers a draft forensics report in days instead of months. Claude is the agentic coordinator — it decides which module to run, in what order, and when the evidence has been queried thoroughly enough to draw a scoped, source-cited conclusion. When it is uncertain, it asks the analyst and remembers the answer.

What makes it more than three tools in a folder is that the modules interrogate each other. A suspicious connection in a PCAP triggers FAN to ask FAME which process owned that socket and FAST which file on disk launched it; a correlation engine then matches netscan→PCAP, process→deleted-file, and DNS→carved-URL across modules automatically. Findings accumulate in a plain-Markdown Obsidian vault that serves as institutional memory across cases, and every investigation auto-generates a two-register report (CISO management summary + full technical body) in Markdown, PDF, PPTX, and DOCX — plus a SHA-256-fingerprinted chain-of-evidence transcript of the whole session.

The goal is simple: the analyst spends 100% of their time on analysis. The reports, the correlation, and the paperwork are handled. The analyst asks; the platform finds.

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
- OpenCTI instance (local or remote) — **optional**
- Perplexity.ai API key — **optional**

> **Note on threat intelligence:** OpenCTI and Perplexity are what give the
> solution its real power — OpenCTI contributes structured, accumulated STIX
> threat-intel knowledge, and Perplexity adds live, web-sourced intelligence
> with citations. Together they let the platform enrich indicators, identify
> malware and threat actors, and correlate against known campaigns. Both are
> **optional**: without them the three forensic modules (FAN, FAME, FAST),
> cross-module correlation, the Obsidian vault, and report generation all
> operate exactly as expected — you simply lose the external threat-intel
> enrichment layer.

See [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) for full server sizing, service account setup, and security hardening.

### Install steps

```bash
# 1. Clone the repository
git clone <repo-url> ~/FanGetFameFast
cd ~/FanGetFameFast

# 2. Create a virtual environment and install Python dependencies
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Versions in requirements.txt are pinned (==) to the releases recorded in the
# checked-in CycloneDX SBOM (sbom.json). MemProcFS (FAME) is x86-64-only and may
# fail to build on arm64 — it is optional; the rest of the pipeline runs without it.

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

A ready-to-use [Dev Container](.devcontainer/) builds the full toolchain on
Debian Bookworm — amd64 and arm64 both supported:

- **FAN** — tshark, Suricata (with `suricata-update`), YARA
- **FAME** — Volatility 3, MemProcFS (x86-64 only; skipped automatically on arm64)
- **FAST** — The Sleuth Kit, EWF tools, bulk_extractor, plus the foremost / scalpel / binwalk fallback carvers
- **Reporting & coordination** — WeasyPrint (PDF), python-pptx / python-docx, and the Claude Code CLI

Suricata and bulk_extractor are built from source by [post-create.sh](.devcontainer/post-create.sh)
when no prebuilt package is available, so first build can take several minutes.

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
./scripts/test_solution.sh                  # end-to-end smoke test
./scripts/test_mcp_servers.sh               # evidence / investigations / opencti MCP servers
python3 lib/path_guard.py --test            # write-path allow/deny matrix (evidence stays read-only)
python3 scripts/generate_sbom.py --check    # confirm sbom.json matches requirements.txt
```

---

## How FAN works

You point FAN at a PCAP — either by dropping it into the evidence vault or by passing a path directly — and the script asks for a case ID if you didn't supply one, then opens a running research-notes log that every subsequent step appends to. It starts by extracting the netflow picture (unique IPs, FQDNs, conversations) and then sweeps the capture with its full battery of protocol threat detectors: ARP, DHCP, DNS, HTTP/S, ICMP, LLMNR, mDNS, NBNS, NetBIOS, NTP, QUIC, SNMP, SSDP, STUN, TCP, UDP, and TLS (including certificate inspection and JA4 fingerprinting). On top of the protocol layer it extracts and hashes transferred files, runs a Suricata IDS pass, and sweeps both the raw capture and any carved files with YARA rules. When OpenCTI or Perplexity are configured, the IPs and FQDNs are enriched against external threat intelligence; when they are not, FAN leans on the local vault cache and continues.

From those outputs Claude writes a versioned incident report (Markdown + PDF), generates a CISO-facing management briefing as a PowerPoint deck, and bundles every artifact into a timestamped ZIP. The reports are uploaded to the investigations vault at `/home/sansforensics/cases/<case_id>/reports/` on ubuntudesktop, and the entire Claude Code coordination session is captured as a chain-of-evidence transcript — Markdown, PDF, and the verbatim, SHA-256-fingerprinted `.jsonl` — and uploaded alongside them. Finally the `./analysis/` working directories for that capture are deleted, leaving the analysis folder empty while the finalized reports persist in `./reports/` and in the vault.

## How FAME works

You hand FAME a memory image and a case ID (and optionally a hostname), and it first works out whether the image is Windows or Linux. For Windows images it runs the Volatility 3 plugins that matter for triage — process listings and scans (`pslist`, `psscan`, `pstree`, `cmdline`), the network view (`netstat`, `netscan`), injected-code detection (`malfind`), services and drivers (`svcscan`, `modules`, `modscan`), the file-object scan (`filescan`), and registry artifacts (`userassist`, `hivelist`) plus image metadata. When a clean-system baseline is present at `baselines/baseline.json`, Memory Baseliner adds a process/driver/service comparison, and on x86-64 hosts MemProcFS runs as a second, independent analysis pathway. Linux images run their own Volatility plugins (`pslist`, `pstree`, `netstat`, `malfind`, banners) and fall back to strings extraction and YARA scanning when ISF symbols aren't available, so the pipeline still produces results on images Volatility can't fully parse.

The findings become a full report set — Markdown, PDF, a PowerPoint management deck, and a technical Word document. FAME then looks for sibling FAN or FAST reports under the same case ID; when it finds them it generates a combined, cross-module report and embeds the correlation analysis where available. Everything is uploaded to the investigations vault, and the coordination session is recorded as the same chain-of-evidence transcript (Markdown + PDF + verbatim, SHA-256-fingerprinted `.jsonl`) and uploaded with the reports.

## How FAST works

You give FAST a disk image in any TSK-compatible format — E01, VMDK, raw, and so on. For EnCase/EWF images it first runs `ewfinfo` and `ewfverify` to confirm integrity, then mounts the image **read-only** (via `ewfmount`, falling back to a network block device for other formats) so the evidence is never altered. With the volume mounted it walks the disk with The Sleuth Kit: `mmls` to map partitions, `fsstat` for filesystem detail, `fls` to list files recursively and emit a timeline bodyfile, and `ils`/`icat` to reach inodes and recover content. It then pulls the artifacts that drive most investigations — Windows event logs (EVTX), registry hives, prefetch, the MFT, the USN journal, SRUM, and browser history — and runs `bulk_extractor` (with foremost, scalpel, and binwalk as fallback carvers) to carve deleted and unallocated data.

As with the other modules, the results are written as Markdown, PDF, a PowerPoint deck, and a Word document; if FAN or FAME reports already exist for the case, a combined cross-module report is produced automatically. The reports go to the investigations vault, and the full Claude Code session is preserved as the chain-of-evidence transcript (Markdown + PDF + verbatim, SHA-256-fingerprinted `.jsonl`) and uploaded alongside them.

---

## Report format

Every investigation produces a single report written in two registers, so one document serves every audience from the boardroom to law enforcement.

The **management summary** is plain language for a CISO, legal team, or law-enforcement reader: it carries the business causality — what happened, when, and what the impact was — and deliberately omits technical identifiers like IPs, ports, and file sizes.

The **technical body** is for the analyst: precise identifiers (workstation names, IP addresses, ports, protocols, payload sizes, malware family names) and scoped conclusions that explicitly name the evidence source they rest on — for example, "no signs of lateral movement were observed *in the PCAP file*."

Reports are produced as Markdown, PDF, PPTX (Microsoft PowerPoint), and DOCX (Microsoft Word); FAN additionally bundles its artifacts into a timestamped ZIP. When more than one module has run against the same case ID, a combined cross-module report is generated in all four formats — with the cross-module correlation woven in — so the network, memory, and disk findings read as one narrative rather than three separate documents.

---

## Obsidian vault (institutional memory)

The vault at `./vault/` is the platform's long-term memory: a plain-Markdown knowledge graph where TTPs, IOCs, threat actors, malware profiles, risks, and cybersecurity concepts accumulate across every investigation. Because it is just Markdown, it opens directly in Obsidian (or any editor) as a navigable, cross-linked graph — no database, no server, fully portable, and reviewable by a human at any time.

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

**Why it matters.** The vault is what turns a sequence of one-off investigations into compounding institutional knowledge — the second time an indicator, technique, or malware family appears, the platform already knows what it learned the first time. Concretely, it adds value in four ways:

- **It answers first, so you don't pay for the same lookup twice.** Every investigation consults the vault *before* reaching out to OpenCTI or Perplexity (`vault → Perplexity → record back to vault`). A FAN IP/FQDN lookup that found fresh intel on a prior case reuses the cached note instead of re-querying the network, which keeps investigations fast and works even when external services are offline or unconfigured.
- **It carries context between cases.** Querying the vault before an investigation surfaces what is already known — that a port was used for C2 in a previous incident, that a hash belongs to a known tool, that an actor has a documented playbook — so the analyst starts with history instead of a blank page.
- **It preserves conflicting intel instead of overwriting it.** When two cases disagree (e.g., the same port serving different purposes), both entries are kept with their case context, so the knowledge graph reflects reality rather than the most recent write.
- **It is safe to share and audit.** All IOC values are stored **defanged** (`192[.]168[.]1[.]1`, `evil[.]com`, `hxxps://…`), so the vault can be opened, reviewed, and circulated without risk of accidentally clicking a live malicious indicator. Case notes hold metadata only — never raw evidence.

Query the vault before an investigation:

```bash
./scripts/vault_context.sh "Cobalt Strike"
python3 lib/vault_query.py --search powershell
```

Validate the vault read/write path with the built-in self-tests:

```bash
python3 lib/obsidian_bridge.py             # write/read/search round-trip
python3 lib/knowledge_extractor.py --test  # all record types + Dashboard refresh
```

---

## MCP servers

Model Context Protocol (MCP) servers are how the AI coordinator reaches the outside world under controlled, auditable rules — instead of giving Claude raw shell access to evidence and case storage, each server exposes a small, explicit set of tools with a fixed root directory and a fixed access mode. Three servers are wired in:

| Server | Access | Root |
|--------|--------|------|
| `evidence` | Read-only (SSH) | `/home/sansforensics/evidence/` on ubuntudesktop |
| `investigations` | Read-write | `/home/sansforensics/cases/` on ubuntudesktop |
| `opencti` | Read-write | Your OpenCTI instance |

- **`evidence` — read-only access to the source material.** This server lets the coordinator list, read, and fingerprint evidence files (and find PCAPs) over SSH, but it is **physically incapable of writing** — the connection is read-only by design. This is the first line of defence for evidence integrity: even if the coordinator were instructed to modify a memory image or disk image, this path cannot do it. Tools: `evidence_list_directory`, `evidence_read_file`, `evidence_get_file_info`, `evidence_find_pcaps`.
- **`investigations` — read-write access to the case vault.** This is where finalized reports, transcripts, and artifact bundles are stored, organized per case under `/home/sansforensics/cases/<case_id>/reports/`. It is the *only* write path the coordinator has to durable storage, and it independently enforces the write policy — it rejects any write under `/mnt`, `/media`, or the evidence root, and jails every path inside the case root — so a malformed case ID or a path-traversal attempt cannot escape it. Tools: `investigations_list_directory`, `investigations_read_file`, `investigations_write_file`, `investigations_create_directory`, `investigations_delete`, `investigations_get_file_info`, `investigations_list_cases`.
- **`opencti` — structured threat-intelligence exchange.** This server connects the platform to your OpenCTI instance so the coordinator can both *consume* accumulated STIX intelligence (searching entities and indicators) and *contribute* new indicators discovered during an investigation, closing the loop between what is found on the wire/in memory/on disk and your organization's central CTI knowledge base. Tools: `opencti_search_stix`, `opencti_search_ioc`, `opencti_create_indicator`. This server is optional — see [Live threat intel](#live-threat-intel-perplexity) and the requirements note above.

---

## Live threat intel (Perplexity)

The vault remembers what *this* deployment has already seen, and OpenCTI holds structured intel you've curated — but a live incident routinely turns up something neither knows: a brand-new CVE, a freshly registered domain, a malware family or tool the team hasn't encountered yet. Perplexity fills exactly that gap. It is the platform's **live, web-sourced research layer**: real-time search with citations, so an unknown artifact can be identified during the investigation rather than parked as a TODO for later.

Its value compounds with the rest of the system because it sits in a deliberate pipeline — `vault → Perplexity → record back to vault`. The vault is consulted first; only when it has no answer does Perplexity reach out to the web; and whatever it confirms is written back into the vault as a defanged, cited note. That means **the platform only has to learn each thing once** — the next investigation that meets the same indicator answers instantly from memory, with the citation preserved for the report's chain of evidence. The result is a system that gets smarter over time while still being able to research something it has never seen.

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

## Constraints

These are not style guidelines — they are the rules that make the platform trustworthy in a forensic and legal context. Each one exists for a reason:

- **Evidence is never written to — and that's enforced in code, not by convention.** The platform must never write to `/mnt/`, `/media/`, or any `evidence/` directory, because altering source material would destroy its evidentiary value and break chain of custody. This is guaranteed by `lib/path_guard.py`, the single source of truth for the write policy: every Python write chokepoint (`obsidian_bridge`, `md_to_pdf`, all `generate_*` report generators, `case_packager`) routes through `assert_writable`/`guard_output_dir`, which hard-fail with `WritePolicyError` on any write outside the approved output folders (`analysis`, `exports`, `reports`, `archive`, `vault`, `cases`, `demo`, `docs`, plus the OS temp dir). Two independent layers back this up: the `investigations` MCP server separately rejects writes under `/mnt`, `/media`, or `EVIDENCE_ROOT`, and the shell analyze scripts source `scripts/pathguard.sh` to confirm evidence mounts are read-only *before* any analysis runs. Validate the whole allow/deny matrix with `python3 lib/path_guard.py --test`.
- **Untrusted evidence input is validated before it can reach a dangerous sink.** Evidence is attacker-controlled data, so anything derived from it is treated as hostile until proven safe: a `case_id` is constrained to `[A-Za-z0-9._-]{1,64}` so it cannot traverse out of the case/output root, PDF rendering blocks `file://`/SSRF resource fetches that malicious text in an evidence file might trigger, and the MCP file servers jail every path with `Path.is_relative_to` rather than a string prefix. The full guardrail table is in [docs/DEPLOYMENT_GUIDE.md §13](docs/DEPLOYMENT_GUIDE.md), and a CycloneDX SBOM of the dependency set is checked in at [sbom.json](sbom.json) (regenerate with `python3 scripts/generate_sbom.py`) so the supply chain is auditable.
- **Working files live only in `./analysis/`, and that folder is emptied when an investigation completes.** All intermediate, work-in-progress output is confined to one place so it is easy to reason about and clean up; a completed investigation leaves `./analysis/` empty, which is both a tidiness guarantee and a signal that the pipeline ran to the end and the only surviving outputs are the finalized reports.
- **Finalized reports live in the investigations vault, not in the project directory.** The authoritative copy of every report is stored per case under `/home/sansforensics/cases/<case_id>/reports/` (via the `investigations` MCP server), so deliverables are centralized, durable, and separated from the working code checkout.
- **Report timestamps use the incident's local timezone; when it's unknown, UTC is used and said so explicitly.** A forensic timeline is only meaningful if the reader knows which clock it's on, so reports are anchored to the timezone where the incident actually happened — and never silently default to UTC, which would misrepresent when events occurred.
- **All internal processing, vault storage, and log entries use UTC.** While *reports* speak in incident-local time for the reader, the platform's own bookkeeping is kept in a single, unambiguous reference timezone so records from different cases and machines can be ordered and compared without conversion errors.
- **Every scoped conclusion must name the evidence source it rests on.** Conclusions are written as scoped, sourced statements — e.g. "as observed in the PCAP file" or "as found in the memory dump" — so a reader (or a court) can always see exactly which artifact supports a claim, and an absence of evidence in one source is never overstated as proof across all sources.

---

## Documentation

This README is the overview; the detailed documentation lives in `docs/` and a few top-level files. Reach for the one that matches what you're trying to do:

- **Setting it up or running it in production?** → [docs/DEPLOYMENT_GUIDE.md](docs/DEPLOYMENT_GUIDE.md) — server sizing, service-account setup, MCP server configuration, the full security-hardening / guardrail reference (§13), backup, and troubleshooting.
- **Actually investigating a case?** → [docs/USER_GUIDE.md](docs/USER_GUIDE.md) — day-to-day investigation workflows, how to use the vault before and after a case, and how to read and interpret the generated reports.
- **Extending the platform or integrating with it?** → [docs/TECHNICAL_REFERENCE.md](docs/TECHNICAL_REFERENCE.md) — module internals, the `lib/` Python API (the per-module reference that previously lived in this README), and the MCP server protocol.
- **Want the big picture first?** → [docs/ARCHITECTURE_DIAGRAM.md](docs/ARCHITECTURE_DIAGRAM.md) — how FAN, FAME, FAST, the coordinator, the vault, and the MCP/CTI layers fit together.
- **Need the dependency inventory?** → [sbom.json](sbom.json) (machine-readable CycloneDX) with a human-readable summary in [sbom.md](sbom.md).
- **Before you point it at anything?** → [DISCLAIMER.md](DISCLAIMER.md) — the authorized-use statement and no-warranty disclaimer. Read this first.

> The project-specific guidance for the AI coordinator itself lives in [CLAUDE.md](CLAUDE.md), and its report-writing voice/register rules are in [VOICE.md](VOICE.md) — useful background if you want to understand or tune how Claude drives an investigation.

---

## License

Fan Get Fame Fast is dual-licensed under your choice of the **Apache License, Version 2.0** ([LICENSE-APACHE](LICENSE-APACHE)) or the **MIT License** ([LICENSE-MIT](LICENSE-MIT)). See [LICENSE](LICENSE) for the dual-license notice.

*Copyright 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin*
