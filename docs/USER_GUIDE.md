# FanGetFameFast — User guide

**Version:** 3.2 · May 2026  
**Platform:** Ubuntu 24.04 LTS (x86-64)  
**Classification:** Internal

> **New installation?** See the [Deployment Guide](DEPLOYMENT_GUIDE.md) for step-by-step production setup.  
> **Integrating or extending Fan Get Fame Fast?** See the [Technical Reference](TECHNICAL_REFERENCE.md).

---

## Table of contents

1. [What is Fan Get Fame Fast?](#1-what-is-fan-get-fame-fast)
2. [Quick start](#2-quick-start)
3. [Network traffic forensics (FAN)](#3-network-traffic-forensics-fan)
4. [Memory forensics (FAME)](#4-memory-forensics-fame)
5. [Disk forensics (FAST)](#5-disk-forensics-fast)
6. [Detection modules (FAN)](#6-detection-modules-fan)
7. [IDS and YARA rule management](#7-ids-and-yara-rule-management)
8. [Claude skills](#8-claude-skills)
9. [Obsidian vault — knowledge graph](#9-obsidian-vault--knowledge-graph)
10. [Live threat intelligence (Perplexity.ai)](#10-live-threat-intelligence-perplexityai)
11. [OpenCTI integration](#11-opencti-integration)
12. [MCP servers](#12-mcp-servers)
13. [Reporting](#13-reporting)
14. [Configuration reference](#14-configuration-reference)
15. [Self-tests](#15-self-tests)
16. [Evidence integrity rules](#16-evidence-integrity-rules)
17. [License and disclaimer](#17-license-and-disclaimer)

---

## 1. What is Fan Get Fame Fast?

Every serious incident leaves traces in three places: the network, memory, and disk. A senior analyst can work each one individually. Nobody can correlate all three fast enough to matter during an active incident.

Fan Get Fame Fast solves that. Three forensic modules — **FAN** (network), **FAME** (memory), and **FAST** (storage) — are coordinated by Claude, which decides which module to run, in what order, and when to pivot across disciplines. The analyst asks. The platform finds.

**Three entry points:**

```bash
./scripts/analyze_pcap.sh  /path/to/capture.pcap      # FAN
./scripts/fame_analyze.sh  /path/to/image.mem         # FAME
./scripts/fast_analyze.sh  /path/to/image.E01         # FAST
```

**FAN** runs 22 protocol threat-detection modules, Suricata IDS, YARA, and IOC enrichment, then generates a report. Typical runtime: 8–15 minutes per GB of captured traffic.

**FAME** runs Volatility 3 plugins, Memory Baseliner, AutoTimeliner super-timeline, and EVTXtract event recovery. Output: Markdown + PDF + PPTX + DOCX.

**FAST** runs TSK (fls, fsstat, icat, mactime), bulk_extractor carving, and Autopsy headless ingest, then extracts EVTX, registry hives, prefetch, MFT, SRUM, and browser history. Output: Markdown + PDF + PPTX + DOCX.

When two or more modules have run against the same case ID, the platform produces a combined unified report that correlates findings across all three disciplines.

---

## 2. Quick start

### New machine — one-time setup

```bash
cd /path/to/FanGetFameFast

# 1. Install system and Python dependencies
bash scripts/install_dependencies.sh

# 2. Create folder structure and MCP configuration
bash scripts/setup_folder_structure.sh

# 3. Set API credentials
cp scripts/set_env_template.sh ~/.soc_env
nano ~/.soc_env            # fill in PERPLEXITY_API_KEY, OPENCTI_URL, OPENCTI_API_KEY
echo 'source ~/.soc_env' >> ~/.bashrc
source ~/.soc_env

# 4. Verify
./scripts/test_solution.sh
```

Full details: [Deployment Guide](DEPLOYMENT_GUIDE.md).

### Analyze network traffic

```bash
cd /home/richard/Documents/FanGetFameFast

# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive with explicit case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001
```

The finished report goes to `/home/sansforensics/cases/FAN-2026-001/reports/` on ubuntudesktop. All WIP files under `./analysis/` are deleted once the upload completes.

---

## 3. Network traffic forensics (FAN)

FAN is a manual PCAP investigation pipeline. There is no daemon or auto-trigger. Every investigation starts with an explicit analyst command.

```bash
# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive with case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001

# With case description
./scripts/analyze_pcap.sh /path/to/capture.pcap \
    --case-id FAN-2026-001 \
    --description "Suspected C2 beacon on DESKTOP-42"

# Skip vault writes
./scripts/analyze_pcap.sh /path/to/capture.pcap --no-vault
```

### Pipeline steps

1. All 22 detection modules run, writing WIP output to `./analysis/<module>/<stem>/`
2. An incident report (Markdown + PDF) is generated in `./analysis/_reports/<stem>/`
3. A management PowerPoint briefing (PPTX) is generated in `./analysis/_reports/<stem>/`
4. All artifacts — MD, PDF, PPTX, and all module outputs — are packaged into a single timestamped ZIP: `<case_id>_<YYYYMMDD-HHMMSS>.zip`
5. The ZIP goes to the investigations vault: `/home/sansforensics/cases/<case_id>/` on ubuntudesktop
6. All WIP directories under `./analysis/` are deleted; the analysis folder is left empty

### Output files per investigation

| File | Audience | Contents |
|------|----------|----------|
| `<stem>_incident_report.md` | Analyst | Full technical findings, all protocol sections |
| `<stem>_incident_report.pdf` | Analyst / Legal | Styled PDF of the technical report |
| `<stem>_management_briefing.pptx` | CISO / Management | 7-slide PowerPoint: executive summary, threat landscape, IDS alerts, IOCs, recommendations, module coverage |
| `<case_id>_<timestamp>.zip` | Archive | All of the above + raw module JSON/CSV outputs |

### Analysis folder

`./analysis/` holds temporary outputs while a PCAP is being processed. Do not store anything there that you need to keep. Once the ZIP is packaged and uploaded, the directory is cleared automatically.

---

## 4. Memory forensics (FAME)

FAME is a manual memory forensics pipeline. Every investigation starts explicitly.

```bash
# Interactive — prompts for case ID
./scripts/fame_analyze.sh /path/to/image.mem

# Non-interactive
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234

# Skip vault uploads
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --no-upload
```

### What runs

| Stage | What it does |
|-------|-------------|
| **Volatility 3** | pslist, psscan, pstree, cmdline, netstat, netscan, malfind, svcscan, modules, modscan, filescan, userassist, hivelist, info |
| **Memory timeline** | `vol.py timeliner` builds a bodyfile; `mactime` converts it to a sorted MACB timeline |
| **Memory Baseliner** | Compares processes, drivers, and services against a known-good baseline JSON |
| **AutoTimeliner** | Correlates multiple Volatility plugin outputs into a single super-timeline CSV (optional) |
| **EVTXtract** | Recovers Windows Event Log records from raw memory pages — catches events from fragmented or deleted EVTX files (optional) |
| **Linux strings fallback** | When no ISF symbols are available for a Linux image, extracts ASCII and Unicode strings and greps for auth/syslog patterns |

### Output files

| File | Contents |
|------|---------|
| `<stem>_fame_report.md` | Full technical findings |
| `<stem>_fame_report.pdf` | Styled PDF |
| `<stem>_fame_presentation.pptx` | 8-slide PowerPoint briefing |
| `<stem>_fame_report.docx` | Word document |
| `analysis/memory/autotimeliner/supertimeline.csv` | Super-timeline (if AutoTimeliner ran) |
| `analysis/memory/evtxtract/recovered_events.xml` | Recovered EVTX records (if EVTXtract ran) |
| `<stem>_combined_report.*` | Cross-module report (generated when FAN or FAST report exists for this case ID) |

### Installing optional tools

```bash
# AutoTimeliner
git clone https://github.com/andreafortuna/autotimeliner /opt/autotimeliner
pip3 install -r /opt/autotimeliner/requirements.txt

# EVTXtract
git clone https://github.com/williballenthin/EVTXtract /opt/EVTXtract
pip3 install -r /opt/EVTXtract/requirements.txt
```

When either tool is absent, that step is skipped with a log entry and the pipeline continues.

---

## 5. Disk forensics (FAST)

FAST is a manual disk-image forensics pipeline built on The Sleuth Kit, bulk_extractor, and Autopsy.

```bash
# Interactive — prompts for case ID
./scripts/fast_analyze.sh /path/to/image.E01

# Non-interactive
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234

# Skip filesystem mount (TSK-only mode)
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --no-mount
```

Supported image formats: E01/EWF, VMDK, raw (.dd, .img), and any format TSK recognizes.

### What runs

| Stage | What it does |
|-------|-------------|
| **Image verification** | `ewfinfo` + `ewfverify` for E01; `img_stat` for raw images |
| **Partition map** | `mmls` — identifies all partitions and their start sectors |
| **Filesystem stats** | `fsstat` — filesystem type, cluster size, volume serial number |
| **File listing** | `fls -r -p` — full recursive file/directory listing with metadata |
| **MACB bodyfile** | `fls -m` — generates bodyfile for mactime processing |
| **Filesystem timeline** | `mactime` — converts bodyfile to sorted MACB timeline (TXT + CSV) |
| **Inode listing** | `ils` — lists allocated and orphan inodes |
| **Artifact extraction** | Copies EVTX logs, registry hives, prefetch, SRUM, browser history, Recycle Bin, and scheduled tasks from the mounted filesystem |
| **MFT + USN journal** | `icat` — extracts `$MFT` (inode 0) and `$J` (USN change journal) |
| **File carving** | `bulk_extractor` — carves emails, URLs, credit cards, registry keys from raw image (skipped for images > 20 GB) |
| **Autopsy** | Headless ingest: file-type mismatch, hash lookup, recent activity, EXIF, keyword index (optional) |

### Output files

| File | Contents |
|------|---------|
| `<stem>_fast_report.md` | Full technical findings |
| `<stem>_fast_report.pdf` | Styled PDF |
| `<stem>_fast_presentation.pptx` | 8-slide PowerPoint briefing |
| `<stem>_fast_report.docx` | Word document |
| `exports/fs_timeline.csv` | Full filesystem MACB timeline |
| `exports/autopsy/` | Autopsy case + exported artifacts (if Autopsy ran) |
| `<stem>_combined_report.*` | Cross-module report (generated when FAN or FAME report exists for this case ID) |

### Installing Autopsy

```bash
# From apt (if available)
sudo apt-get install -y autopsy

# Or install the upstream .deb
sudo dpkg -i autopsy-4.x.x-amd64.deb
sudo apt-get install -f
```

When `autopsy` is not on `$PATH`, that step is skipped and a `AUTOPSY_NOT_RUN.txt` marker is written to `./exports/autopsy/`.

---

## 6. Detection modules (FAN)

22 modules run sequentially. Each has a shell wrapper in `scripts/` and a Python library in `lib/`.

| Module | Detection categories |
|--------|---------------------|
| **DNS** | DGA, beaconing, exfiltration, fast flux, amplification, NXDomain flood, typosquatting, spoofing, zone transfer, unauthorized servers, unusual types |
| **HTTP/S** | Suspicious UA, unusual methods, scanning status codes, suspicious URI, large upload, cookie anomaly, host header anomaly, beaconing, unusual server headers, suspicious referer, deprecated TLS |
| **TLS session** | Suspicious JA4/JA3, weak cipher, deprecated TLS, non-standard port, cipher diversity scan |
| **TLS certificate** | Self-signed, expired, not-yet-valid, short/long validity, wildcard, SNI mismatch, weak signature |
| **ARP** | Cache poisoning, gratuitous ARP flood, ARP flood, ARP scan, proxy anomaly |
| **TCP** | SYN flood, port scan, RST flood, stealth scan, session hijacking, half-open flood |
| **UDP** | Flood, reflection/amplification, port scan, fragmentation, IP spoofing |
| **ICMP** | Flood, Ping of Death, fragmentation, tunneling, Smurf, redirect, sweep, unreachable flood, recon, exfiltration |
| **NTP** | Amplification, flood, Kiss-of-Death, monlist abuse, spoofed response, time manipulation, recon |
| **DHCP** | Starvation, rogue server, spoofing, release/decline flood, relay anomaly, message injection |
| **mDNS** | Amplification, information leakage, spoofing/cache poisoning, outside local segment, flood |
| **QUIC** | Amplification/DDoS, 0-RTT replay, version forgery, pre-handshake exhaustion, non-standard port |
| **SNMP** | Default credentials, MitM, DoS flood, reconnaissance, malicious SET, large data transfer |
| **NBNS** | Spoofing/poisoning, credential theft, SMB relay, enumeration, DoS, WPAD poisoning |
| **LLMNR** | Spoofing/poisoning, credential theft, SMB relay, reconnaissance |
| **STUN** | Amplification DDoS, info leakage, firewall traversal, service abuse |
| **SSDP/UPnP** | Amplification DDoS, device exposure, network manipulation, vulnerable UPnP |
| **NetBIOS** | Poisoning, NTLM hash theft, NTLM relay, enumeration, recon, null session, DDoS, malware propagation |
| **File hashes** | Extracts HTTP/SMB/TFTP/IMF/DICOM files; MD5+SHA256; Perplexity OSINT |
| **Suricata IDS** | ET Open rules + local.rules |
| **YARA** | PE, entropy, network, malware rules + community rules |
| **IP/FQDN lookup** | FQDN/IP correlation, DNS resolution, OSINT enrichment |

Run any module standalone:

```bash
./scripts/fan_dns_threats.sh  /path/to/capture.pcap
./scripts/fan_http_threats.sh /path/to/capture.pcap
```

---

## 7. IDS and YARA rule management

### Suricata

```bash
# Update ET Open rules
./scripts/update_suricata_rules.sh

# ET Open only (no extra dependencies)
./scripts/update_suricata_rules.sh --et-only

# Add custom rules
nano rules/suricata/local.rules
```

Install Suricata once:

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update && sudo apt-get install suricata
```

### YARA

```bash
# Run YARA scan standalone
./scripts/fan_yara_pcap.sh /path/to/capture.pcap

# Sweep a disk mount or memory image
./scripts/yara_sweep.sh --target /mnt/windows_mount/ --case-id FAN-2026-001
./scripts/yara_sweep.sh --target /path/to/memory.img --strings --threads 4
```

Drop `.yar` files into `./rules/yara/`. They are compiled and loaded automatically at scan time.

---

## 8. Claude skills

Open Claude Code in the project directory and type the skill name.

| Skill | Command | What it does |
|-------|---------|-------------|
| CTI-OpenCTI-lookup | `/fan-opencti-lookup --case-id <id>` | Checks all IPs and FQDNs extracted from the PCAP against OpenCTI; writes `opencti_lookup.md` |
| FAN IP lookup | `/fan-ip-lookup` | FQDN/IP enrichment + OSINT via Perplexity with 7-day vault cache |
| FAN report | `/fan-report` | Generates MD + PDF incident report from all module outputs |
| FAN extract IP+FQDN | `/fan-extract-ip-fqdn` | Extracts netflow, unique IPs, and FQDNs from a PCAP |
| Perplexity lookup | `/perplexity-lookup` | Live threat intel for an unknown artifact |
| Obsidian query | `/obsidian-query` | Queries the vault before an investigation |
| Obsidian record | `/obsidian-record` | Records findings into the vault and pushes to OpenCTI |
| Markdown to PDF | `/md-to-pdf` | Converts any Markdown file to a styled PDF |
| Remove case | `/remove-case` | Removes a case from the investigations vault |

Individual detection module skills (`/fan-dns-threats`, `/fan-http-threats`, etc.) run one module at a time.

---

## 9. Obsidian vault — knowledge graph

The vault at `./vault/` is the platform's institutional memory: TTPs, IOCs, threat actors, malware families, risks, and case histories accumulate here across investigations.

### Writing

```python
from lib.knowledge_extractor import open_case, record_ioc, record_ttp, close_case

open_case("FAN-2026-001", "Suspected C2 beacon on DESKTOP-42.", severity="high")

record_ioc("ip", "203.0.113.42", "C2 destination in PCAP.", "FAN-2026-001", severity="high")
record_ttp("T1071.001", "Web Protocols", "HTTPS POST every 60s.", "FAN-2026-001")

close_case("FAN-2026-001", "C2 confirmed. Host isolated.")
```

All `record_*` calls are idempotent. Calling again updates the existing note rather than creating a duplicate. Each call also pushes the finding to OpenCTI via `opencti_create_indicator`.

### Querying

```bash
./scripts/vault_context.sh search <keyword>
./scripts/vault_context.sh ioc <ip-or-hash>
./scripts/vault_context.sh ttp T1059
```

IOC values in the vault are defanged: `192[.]168[.]1[.]1`, `evil[.]com`, `hxxps://...`

---

## 10. Live threat intelligence (Perplexity.ai)

When the vault has no answer for an artifact, Perplexity provides real-time web-sourced intelligence.

```bash
./scripts/perplexity_search.sh ioc     203.0.113.42
./scripts/perplexity_search.sh malware "Cobalt Strike"
./scripts/perplexity_search.sh ttp     T1071.001
./scripts/perplexity_search.sh cve     CVE-2024-1234
./scripts/perplexity_search.sh actor   APT29

# Save result to vault
./scripts/perplexity_search.sh malware "Cobalt Strike" --save-vault
```

Decision order: vault first, Perplexity on a cache miss, confirmed findings recorded back to vault.

Privacy rule: never include live case hostnames, usernames, or internal IPs in Perplexity queries.

---

## 11. OpenCTI integration

The `/fan-opencti-lookup` skill checks all IPs and FQDNs extracted by FAN against your OpenCTI instance. Results go to `opencti_lookup.md` in the investigations vault case folder.

Every `record_ioc`, `record_ttp`, and `record_malware` call in `lib/knowledge_extractor.py` pushes the finding to OpenCTI via `opencti_create_indicator`.

Configure credentials in `~/.soc_env`:

```bash
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_API_KEY="your-api-token-here"
```

Get your token at Settings → API access in the OpenCTI web UI.

Score thresholds: CONFIRMED_MALICIOUS (≥ 75), SUSPICIOUS (40–74), INFORMATIONAL (< 40), NOT_FOUND.

---

## 12. MCP servers

| MCP server | Root | Tools |
|------------|------|-------|
| `evidence` | `/home/sansforensics/evidence` on `ubuntudesktop` (SSH, read-only) | `evidence_find_pcaps`, `evidence_read_file`, `evidence_get_file_info`, `evidence_list_directory` |
| `investigations` | `/home/sansforensics/cases` on `ubuntudesktop` (SSH, read-write) | `investigations_list_cases`, `investigations_read_file`, `investigations_write_file`, `investigations_create_directory`, `investigations_delete`, `investigations_get_file_info`, `investigations_list_directory` |
| `opencti` | OpenCTI instance | `opencti_search_ioc`, `opencti_search_stix`, `opencti_create_indicator` |

Registered in `.claude/settings.json` with absolute paths. Re-run `setup_folder_structure.sh` to regenerate this file if you move the project or change the evidence/cases paths.

Credentials (`OPENCTI_URL`, `OPENCTI_API_KEY`) come from environment variables, not from `settings.json`.

`lib/investigations_upload.py` uses the investigations MCP server to store reports after each investigation completes.

Full MCP API reference: [Technical Reference — MCP server API](TECHNICAL_REFERENCE.md#5-mcp-server-api).

---

## 13. Reporting

### Report outputs by module

**FAN** — generated by `analyze_pcap.sh`:

| Format | Filename |
|--------|----------|
| Markdown | `<stem>_incident_report.md` |
| PDF | `<stem>_incident_report.pdf` |
| PowerPoint | `<stem>_management_briefing.pptx` |

**FAME** — generated by `fame_analyze.sh`:

| Format | Filename |
|--------|----------|
| Markdown | `<stem>_fame_report.md` |
| PDF | `<stem>_fame_report.pdf` |
| PowerPoint | `<stem>_fame_presentation.pptx` |
| Word | `<stem>_fame_report.docx` |

**FAST** — generated by `fast_analyze.sh`:

| Format | Filename |
|--------|----------|
| Markdown | `<stem>_fast_report.md` |
| PDF | `<stem>_fast_report.pdf` |
| PowerPoint | `<stem>_fast_presentation.pptx` |
| Word | `<stem>_fast_report.docx` |

**Combined** — generated automatically when two or more module reports exist for the same case ID:

| Format | Filename |
|--------|----------|
| Markdown | `<stem>_combined_report.md` |
| PDF | `<stem>_combined_report.pdf` |
| PowerPoint | `<stem>_combined_presentation.pptx` |
| Word | `<stem>_combined_report.docx` |

All FAN files plus raw module outputs are zipped into `<case_id>_<YYYYMMDD-HHMMSS>.zip` and uploaded to `/home/sansforensics/cases/<case_id>/` on ubuntudesktop.

To generate reports manually:

```bash
# Full incident report (MD + PDF)
./scripts/generate_pcap_report.sh \
    --stem <pcap-stem> \
    --case-id FAN-2026-001 \
    --output-dir ./analysis/_reports/<stem>/

# Management PowerPoint only
python3 lib/generate_pptx_report.py \
    --stem <pcap-stem> \
    --case-id FAN-2026-001 \
    --output-dir ./analysis/_reports/<stem>/

# Package and upload
python3 lib/case_packager.py \
    --case-id FAN-2026-001 \
    --stem <pcap-stem> \
    --reports-dir ./analysis/_reports/<stem>/ \
    --upload
```

### Management PowerPoint slide structure

| Slide | Content |
|-------|---------|
| 1 | Cover — case ID, date, classification |
| 2 | Executive summary — severity, traffic scope, key findings |
| 3 | Threat landscape — triggered threat categories with severity |
| 4 | Security alerts — Suricata IDS and YARA results |
| 5 | Indicators of compromise — defanged IOCs |
| 6 | Recommended actions — up to 8 prioritized action items |
| 7 | Investigation coverage — status of all 23 detection modules |

### Markdown to PDF

```bash
./scripts/md_to_pdf.sh /path/to/report.md /path/to/output.pdf
```

The PDF includes a styled cover page, header stripe, and "Page X of Y" pagination.

---

## 14. Configuration reference

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PERPLEXITY_API_KEY` | Yes | Perplexity.ai API key |
| `OPENCTI_URL` | Yes (for OpenCTI) | OpenCTI instance URL |
| `OPENCTI_API_KEY` | Yes (for OpenCTI) | OpenCTI API token |
| `INVESTIGATIONS_SSH_HOST` | No | SSH target for investigations vault (default: `sansforensics@ubuntudesktop`) |
| `INVESTIGATIONS_ROOT` | No | Remote path for case output (default: `/home/sansforensics/cases`) |

Set in `~/.soc_env` (template: `scripts/set_env_template.sh`), sourced from `~/.bashrc`.

### Key paths

| Path | Purpose |
|------|---------|
| `/home/sansforensics/evidence/` on `ubuntudesktop` | PCAP drop zone (accessed via SSH) |
| `/home/sansforensics/cases/<case_id>/reports/` on `ubuntudesktop` | Uploaded incident reports |
| `./analysis/` | WIP only — emptied after each investigation |
| `./vault/` | Obsidian knowledge graph |
| `./rules/suricata/` | Suricata rule files |
| `./rules/yara/` | YARA rule files |
| `.claude/settings.json` | MCP server configuration, permissions |

---

## 15. Self-tests

```bash
# Vault library round-trips
python3 lib/obsidian_bridge.py
python3 lib/knowledge_extractor.py --test
python3 lib/vault_query.py --search powershell
```

---

## 16. Evidence integrity rules

1. Never write to `/mnt/`, `/media/`, or any `evidence/` directory.
2. Analysis WIP goes to `./analysis/` only. It is deleted automatically after each investigation.
3. Finalized reports go to the investigations vault (`/home/sansforensics/cases/` on ubuntudesktop) via SSH/SCP.
4. All timestamps are UTC internally. Reports use the timezone of the incident location (UTC if unknown).
5. IOC values stored in the vault are defanged. Never store live IPs or domains in plain text.
6. External API calls (Perplexity) receive only defanged, anonymized values. No raw evidence paths, internal hostnames, or personal data.
7. Report versioning is automatic. Do not edit report files manually after upload.

---

## Related documentation

| Document | Purpose |
|----------|---------|
| [Deployment guide](DEPLOYMENT_GUIDE.md) | Production server setup, Autopsy/AutoTimeliner/EVTXtract install, hardening, backup, upgrade |
| [Technical reference](TECHNICAL_REFERENCE.md) | Architecture, FAME/FAST pipelines, library API, MCP API, vault schema |
| [CLAUDE.md](../CLAUDE.md) | Project philosophy, constraints, report voice |

---

## 17. License and disclaimer

Fan Get Fame Fast is dual-licensed under your choice of:

- Apache License, Version 2.0 — [LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0
- MIT License — [LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT

See [LICENSE](../LICENSE) for the dual-license notice.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Run it only against systems, memory images, disk images, and network captures you own or have explicit written authorization to examine. All findings must be reviewed and validated by a qualified human analyst before use in legal proceedings or incident response decisions.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · May 2026 — v3.2*
