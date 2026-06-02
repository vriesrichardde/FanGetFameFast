# FanGetFameFast — User guide

**Version:** 4.0 · June 2026
**Platform:** Ubuntu 24.04 LTS (x86-64)
**Authors:** Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
**Classification:** Internal

> **New installation?** See the [Deployment Guide](DEPLOYMENT_GUIDE.md) for step-by-step production setup.
> **Integrating or extending Fan Get Fame Fast?** See the [Technical Reference](TECHNICAL_REFERENCE.md).
> **Presenting the architecture?** See the [Architecture diagrams](ARCHITECTURE_DIAGRAM.md).

> **New in v4.0:** the trust features are now documented end to end —
> [research notes & the audit trail](#9-research-notes--the-audit-trail),
> [how the platform avoids hallucinations and handles failures](#10-how-the-platform-stays-accurate-trust-features),
> and [batch / campaign analysis](#8-batch-analysis-many-evidence-files-at-once) across many evidence files.

---

## Table of contents

1. [What is Fan Get Fame Fast?](#1-what-is-fan-get-fame-fast)
2. [Quick start](#2-quick-start)
3. [Network traffic forensics (FAN)](#3-network-traffic-forensics-fan)
4. [Memory forensics (FAME)](#4-memory-forensics-fame)
5. [Disk forensics (FAST)](#5-disk-forensics-fast)
6. [Detection modules (FAN)](#6-detection-modules-fan)
7. [IDS and YARA rule management](#7-ids-and-yara-rule-management)
8. [Batch analysis — many evidence files at once](#8-batch-analysis-many-evidence-files-at-once)
9. [Research notes & the audit trail](#9-research-notes--the-audit-trail)
10. [How the platform stays accurate (trust features)](#10-how-the-platform-stays-accurate-trust-features)
11. [Claude skills](#11-claude-skills)
12. [Obsidian vault — knowledge graph](#12-obsidian-vault--knowledge-graph)
13. [Live threat intelligence (Perplexity.ai)](#13-live-threat-intelligence-perplexityai)
14. [OpenCTI integration](#14-opencti-integration)
15. [MCP servers](#15-mcp-servers)
16. [Reporting](#16-reporting)
17. [Configuration reference](#17-configuration-reference)
18. [Self-tests and verification](#18-self-tests-and-verification)
19. [Evidence integrity rules](#19-evidence-integrity-rules)
20. [License and disclaimer](#20-license-and-disclaimer)

---

## 1. What is Fan Get Fame Fast?

Every serious incident leaves traces in three places: the network, memory, and disk. A senior analyst can work each one individually. Nobody can correlate all three fast enough to matter during an active incident.

Fan Get Fame Fast solves that. Three forensic modules (FAN for network, FAME for memory, FAST for storage) are coordinated by Claude, which decides which module to run, in what order, and when to pivot across disciplines. The analyst asks. The platform finds.

**Three entry points:**

```bash
./scripts/analyze_pcap.sh  /path/to/capture.pcap      # FAN — network forensics
./scripts/fame_analyze.sh  /path/to/image.mem         # FAME — memory forensics
./scripts/fast_analyze.sh  /path/to/image.E01         # FAST — disk forensics
```

**FAN** runs 22 protocol threat-detection modules, Suricata IDS, YARA, and IOC enrichment against a PCAP file, then generates a report. Typical runtime: 8–15 minutes per GB of captured traffic.

**FAME** runs Volatility 3 plugins, Memory Baseliner, AutoTimeliner super-timeline, EVTXtract event recovery, and MemProcFS physical memory analysis. Output: Markdown + PDF + PPTX + DOCX.

**FAST** runs TSK (fls, fsstat, icat, mactime), bulk_extractor carving, and Autopsy headless ingest, then extracts EVTX, registry hives, prefetch, MFT, SRUM, and browser history. Output: Markdown + PDF + PPTX + DOCX.

When two or more modules have run against the same case ID, the platform produces a combined unified report that correlates findings across disciplines.

---

## 2. Quick start

### New machine — one-time setup

```bash
cd /path/to/FanGetFameFast

# 1. Install system and Python dependencies
bash scripts/install_dependencies.sh

# 2. Configure passwordless sudo for suricata-update (required for non-interactive pipelines)
sudo bash scripts/setup_sudoers.sh

# 3. Create folder structure and MCP configuration
bash scripts/setup_folder_structure.sh

# 4. Set API credentials
cp templates/set_env_template.sh ~/.soc_env
nano ~/.soc_env            # fill in PERPLEXITY_API_KEY, OPENCTI_URL, OPENCTI_API_KEY
echo 'source ~/.soc_env' >> ~/.bashrc
source ~/.soc_env

# 5. Set up SSH key access to the investigations vault (ubuntudesktop)
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""    # skip if you already have this key
ssh-copy-id -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop

# 6. Verify
./scripts/test_solution.sh
./scripts/test_mcp_servers.sh
```

Full setup details: [Deployment Guide](DEPLOYMENT_GUIDE.md).

### Alternative — VS Code Dev Container

Instead of the one-time setup above, open the repository in the bundled
[Dev Container](../.devcontainer/) (Dev Containers extension → **Reopen in
Container**, or `devcontainer up`). The image builds the full forensic toolchain
— tshark, Volatility 3, The Sleuth Kit, EWF tools, bulk_extractor, YARA,
Suricata, WeasyPrint — plus the Claude Code CLI, on both amd64 and arm64.

To analyze your own evidence inside the container, point `FGFF_EVIDENCE_INPUT` at
a directory of images on the **host** before building it:

```bash
export FGFF_EVIDENCE_INPUT="/path/to/your/evidence"   # then build / rebuild the container
```

That directory is mounted read-only at `/home/vscode/evidence`. If the variable
is unset the container still builds and starts — the mount falls back to a
placeholder, so nothing breaks and you can supply evidence paths by hand. API
credentials are still set via `~/.soc_env` inside the container as in step 4
above.

### Analyze network traffic

```bash
cd /path/to/FanGetFameFast

# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive with explicit case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001
```

The finished report goes to `/home/sansforensics/cases/FAN-2026-001/reports/` on ubuntudesktop. All WIP files under `./analysis/` are deleted once the upload completes.

---

## 3. Network traffic forensics (FAN)

FAN is a manual PCAP investigation pipeline. There is no daemon or auto-trigger. Every investigation starts with an explicit analyst command.

### Starting an investigation

```bash
# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive with case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001

# With case description (stored in vault)
./scripts/analyze_pcap.sh /path/to/capture.pcap \
    --case-id FAN-2026-001 \
    --description "Suspected C2 beacon on DESKTOP-42"

# Skip vault writes (useful for test runs against sanitized PCAPs)
./scripts/analyze_pcap.sh /path/to/capture.pcap --no-vault

# Skip upload to investigations vault (runs analysis locally only)
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001 --no-upload
```

### Pipeline steps

1. All 22 detection modules run sequentially, writing WIP output to `./analysis/<module>/<stem>/`
2. Suricata IDS scans using ET Open rules and any rules in `rules/suricata/local.rules`
3. YARA scans all `.yar` files compiled from `rules/yara/`
4. IP and FQDN extraction runs; each indicator is enriched via vault lookup then Perplexity on a cache miss
5. An incident report (Markdown + PDF) is generated in `./analysis/_reports/<stem>/`
6. A management PowerPoint briefing (PPTX) is generated in `./analysis/_reports/<stem>/`
7. All artifacts (MD, PDF, PPTX, and all module outputs) are packaged into a single timestamped ZIP
8. The ZIP goes to the investigations vault: `/home/sansforensics/cases/<case_id>/` on ubuntudesktop via SSH/SCP
9. Vault recording runs: IOCs, TTPs, and the case summary are written to `./vault/`
10. All WIP directories under `./analysis/` are deleted; the analysis folder is left empty

### Output files per investigation

| File | Audience | Contents |
|------|----------|----------|
| `<stem>_incident_report.md` | Analyst | Full technical findings, all protocol sections |
| `<stem>_incident_report.pdf` | Analyst / Legal | Styled PDF of the technical report |
| `<stem>_management_briefing.pptx` | CISO / Management | 7-slide PowerPoint: executive summary, threat landscape, IDS alerts, IOCs, recommendations, module coverage |
| `<case_id>_<YYYYMMDD-HHMMSS>.zip` | Archive | All of the above + raw module JSON/CSV outputs |

### Analysis folder

`./analysis/` holds temporary outputs while a PCAP is being processed. Do not store anything there that you need to keep. Once the ZIP is packaged and uploaded, the directory is cleared automatically. If an investigation is interrupted, the WIP files remain in `./analysis/` until the next successful run or manual cleanup.

### Extract IP and FQDN only

`pcap_analyze.sh` is a lightweight alternative to the full pipeline. It extracts netflow, unique IPs, and FQDNs from a PCAP without running all 22 detection modules.

```bash
./scripts/pcap_analyze.sh /path/to/capture.pcap [--case-id <id>] [--output-dir <dir>]
```

Output goes to `./analysis/pcap/<pcap_stem>/`: `netflow.csv`, `unique_ips.txt`, `unique_fqdns.txt`, `report.md`. This script is also invoked internally by the `/fan-extract-ip-fqdn` Claude skill.

---

## 4. Memory forensics (FAME)

FAME is a manual memory forensics pipeline built on Volatility 3 and Memory Baseliner. Every investigation starts explicitly.

### Starting an investigation

```bash
# Interactive — prompts for case ID
./scripts/fame_analyze.sh /path/to/image.mem

# Non-interactive
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --hostname SERVER1234

# Skip vault writes
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --no-vault

# Skip upload to investigations vault (analyze locally, do not upload)
./scripts/fame_analyze.sh /path/to/image.mem --case-id FAME-2026-001 --no-upload
```

The `--hostname` argument is used in the report header. If omitted, FAME attempts to derive the hostname from the image filename stem.

### What runs

| Stage | Tool | What it does |
|-------|------|-------------|
| **Volatility 3** | `vol.py` | Runs pslist, psscan, pstree, cmdline, netstat, netscan, malfind, svcscan, modules, modscan, filescan, userassist, hivelist, info against the memory image |
| **YARA memory scan** | `yara` | Scans the memory image against all rules in `rules/yara/` |
| **Memory timeline** | `vol.py timeliner` + `mactime` | Builds a bodyfile and converts it to a sorted MACB timeline |
| **Memory Baseliner** | `baseline.py` | Compares processes, drivers, and services against a known-good baseline JSON; flags deviations |
| **MemProcFS** | `memprocfs` (Python) | Provides physical memory access via LeechCore as a second analysis pathway; for VirtualBox ELF core dumps, extracts the CR3/DTB from the VBCPU PT_NOTE segment (optional) |
| **AutoTimeliner** | `autotimeliner.py` | Correlates multiple Volatility plugin outputs into a single super-timeline CSV (optional) |
| **EVTXtract** | `evtxtract.py` | Recovers Windows Event Log records from raw memory pages — useful when EVTX files are fragmented across pages (optional) |
| **Linux strings fallback** | `strings` + grep | When no ISF symbols are available for a Linux image, extracts ASCII and Unicode strings and greps for auth/syslog patterns |
| **Rekall** | — | Abandoned by Google in 2021 (last release v1.7.2.post1, October 2019). Requires Python ≤ 3.7. Not available. Volatility 3 provides equivalent coverage. |

### Output files

| File | Contents |
|------|---------|
| `<stem>_fame_report.md` | Full technical findings |
| `<stem>_fame_report.pdf` | Styled PDF |
| `<stem>_fame_presentation.pptx` | 8-slide PowerPoint briefing |
| `<stem>_fame_report.docx` | Word document |
| `analysis/memory/memprocfs/` | MemProcFS artifacts: physical banners, attack strings, IOC matches (if MemProcFS ran) |
| `analysis/memory/autotimeliner/supertimeline.csv` | Super-timeline (if AutoTimeliner ran) |
| `analysis/memory/evtxtract/recovered_events.xml` | Recovered EVTX records (if EVTXtract ran) |
| `<stem>_combined_report.*` | Cross-module report (generated when FAN or FAST report exists for this case ID) |

### Installing optional tools

```bash
# MemProcFS — physical memory access via LeechCore
pip3 install memprocfs --break-system-packages

# AutoTimeliner — Volatility-backed MACB super-timeline
git clone https://github.com/andreafortuna/autotimeliner /opt/autotimeliner
pip3 install -r /opt/autotimeliner/requirements.txt
# AutoTimeliner requires Volatility 3 to be importable:
export PYTHONPATH="/opt/volatility3-2.20.0:$PYTHONPATH"   # add to ~/.soc_env

# EVTXtract — EVTX record recovery from raw binary data
git clone https://github.com/williballenthin/EVTXtract /opt/EVTXtract
pip3 install -r /opt/EVTXtract/requirements.txt
```

When any optional tool is absent, that stage is skipped with a log entry and the pipeline continues.

---

## 5. Disk forensics (FAST)

FAST is a manual disk-image forensics pipeline built on The Sleuth Kit, bulk_extractor, and Autopsy.

### Starting an investigation

```bash
# Interactive — prompts for case ID
./scripts/fast_analyze.sh /path/to/image.E01

# Non-interactive
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --hostname SERVER1234

# Skip filesystem mount (TSK-only mode — use when ewfmount or NBD is unavailable)
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --no-mount

# Skip vault writes
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --no-vault

# Skip upload to investigations vault
./scripts/fast_analyze.sh /path/to/image.E01 --case-id FAST-2026-001 --no-upload
```

Supported image formats: E01/EWF, VMDK, raw (.dd, .img), and any format TSK recognizes.

### What runs

| Stage | Tool | What it does |
|-------|------|-------------|
| **Image verification** | `ewfinfo` + `ewfverify` | For E01 images: validates integrity and reports image metadata. For raw images, `img_stat` is used instead |
| **Partition map** | `mmls` | Identifies all partitions and their start sectors |
| **Filesystem stats** | `fsstat` | Reports filesystem type, cluster size, volume serial number, and allocated/unallocated block counts |
| **File listing** | `fls -r -p` | Produces a full recursive file/directory listing with inode, name, type, and timestamps |
| **MACB bodyfile** | `fls -m` | Generates a bodyfile for mactime processing |
| **Filesystem timeline** | `mactime` | Converts the bodyfile to a sorted MACB timeline (modified, accessed, changed, born) as TXT and CSV |
| **Inode listing** | `ils` | Lists allocated and orphan inodes; orphan inodes indicate deleted-but-recoverable files |
| **Artifact extraction** | `cp` from mount | Copies EVTX logs, registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT), prefetch, SRUM database, browser history, Recycle Bin, and scheduled tasks from the mounted filesystem |
| **MFT + USN journal** | `icat` | Extracts `$MFT` (inode 0) and `$J` (USN change journal) directly from the image |
| **File carving** | `bulk_extractor` | Carves emails, URLs, credit card numbers, and registry keys from the raw image. Skipped for images larger than 20 GB |
| **Autopsy** | `autopsy --nogui` | Headless ingest: file-type mismatch detection, hash lookup against NSRL, recent activity, EXIF, keyword index (optional) |

### Output files

| File | Contents |
|------|---------|
| `<stem>_fast_report.md` | Full technical findings |
| `<stem>_fast_report.pdf` | Styled PDF |
| `<stem>_fast_presentation.pptx` | 8-slide PowerPoint briefing |
| `<stem>_fast_report.docx` | Word document |
| `exports/fs_timeline.csv` | Full filesystem MACB timeline |
| `exports/evtx/` | Extracted Windows Event Log files (.evtx) |
| `exports/registry/` | Registry hives: SYSTEM, SOFTWARE, SAM, NTUSER.DAT |
| `exports/prefetch/` | Prefetch files (.pf) |
| `exports/mft/` | `$MFT` and `$J` (USN change journal) |
| `exports/srum/` | SRUM database (SRUDB.dat) |
| `exports/browser/` | Browser history files |
| `exports/carved/` | bulk_extractor carving output |
| `exports/autopsy/` | Autopsy case + exported artifacts (if Autopsy ran) |
| `<stem>_combined_report.*` | Cross-module report (generated when FAN or FAME report exists for this case ID) |

### Installing Autopsy

```bash
# From apt (Ubuntu 22.04/24.04 — may not be current)
sudo apt-get install -y autopsy

# Or install the upstream .deb (recommended — keeps Autopsy current)
# Download the latest .deb from https://www.autopsy.com/download/
sudo dpkg -i autopsy-4.x.x-amd64.deb
sudo apt-get install -f    # resolve any dependency gaps

# Verify
autopsy --version          # must be 4.17 or later for --nogui support
```

When `autopsy` is absent from `$PATH`, `fast_analyze.sh` skips the Autopsy step and writes `AUTOPSY_NOT_RUN.txt` to `./exports/autopsy/`. The rest of the pipeline continues.

---

## 6. Detection modules (FAN)

22 modules run sequentially during a FAN investigation. Each has a shell wrapper in `scripts/` and a Python library in `lib/`. Any module can also run standalone against a PCAP.

| Module | Detection categories |
|--------|---------------------|
| **DNS** | DGA, beaconing, exfiltration, fast flux, amplification, NXDomain flood, typosquatting, spoofing, zone transfer, unauthorized servers, unusual query types |
| **HTTP/S** | Suspicious user-agent, unusual methods, scanning status codes, suspicious URI patterns, large upload, cookie anomaly, host header anomaly, beaconing, unusual server headers, suspicious referer, deprecated TLS |
| **TLS session** | Suspicious JA4/JA3 fingerprints, weak cipher suites, deprecated TLS versions, non-standard port usage, cipher diversity scanning |
| **TLS certificate** | Self-signed, expired, not-yet-valid, short/long validity period, wildcard misuse, SNI mismatch, weak signature algorithm |
| **ARP** | Cache poisoning, gratuitous ARP flood, ARP flood, ARP scan, proxy anomaly |
| **TCP** | SYN flood, port scan, RST flood, stealth scan (FIN/XMAS/NULL), session hijacking indicators, half-open connection flood |
| **UDP** | Flood, reflection/amplification, port scan, IP fragmentation abuse, IP spoofing indicators |
| **ICMP** | Flood, Ping of Death, fragmentation, tunneling, Smurf attack, redirect abuse, sweep, unreachable flood, recon, covert exfiltration |
| **NTP** | Amplification, flood, Kiss-of-Death, monlist abuse, spoofed response, time manipulation, recon |
| **DHCP** | Starvation, rogue server, spoofing, release/decline flood, relay anomaly, message injection |
| **mDNS** | Amplification, information leakage, spoofing/cache poisoning, traffic outside local segment, flood |
| **QUIC** | Amplification/DDoS, 0-RTT replay attacks, version forgery, pre-handshake resource exhaustion, non-standard port |
| **SNMP** | Default community strings, man-in-the-middle, DoS flood, reconnaissance, malicious SET operations, large data transfer |
| **NBNS** | NetBIOS Name Service spoofing/poisoning, credential theft, SMB relay setup, enumeration, DoS, WPAD poisoning |
| **LLMNR** | Link-Local Multicast Name Resolution spoofing/poisoning, credential theft relay, SMB relay, reconnaissance |
| **STUN** | Session Traversal Utilities for NAT — amplification DDoS, information leakage, firewall traversal abuse, service abuse |
| **SSDP/UPnP** | Simple Service Discovery Protocol — amplification DDoS, device exposure, network manipulation, vulnerable UPnP device detection |
| **NetBIOS** | Poisoning, NTLM hash theft, NTLM relay, enumeration, recon, null session, DDoS, malware propagation indicators |
| **File hashes** | Extracts files transferred over HTTP, SMB, TFTP, IMF, and DICOM; computes MD5 + SHA256; enriches hashes via Perplexity OSINT |
| **Suricata IDS** | ET Open ruleset + any rules in `rules/suricata/local.rules` |
| **YARA** | All `.yar` files in `rules/yara/`: PE structure, entropy anomaly, network patterns, malware family signatures, community rules |
| **IP/FQDN lookup** | FQDN/IP correlation, DNS resolution, vault lookup, Perplexity OSINT enrichment |

Run any module standalone:

```bash
./scripts/fan_dns_threats.sh  /path/to/capture.pcap
./scripts/fan_http_threats.sh /path/to/capture.pcap
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --case-id FAN-2026-001
```

All modules write output to `./analysis/<module_name>/<pcap_stem>/` by default.

---

## 7. IDS and YARA rule management

### Suricata

Suricata processes the PCAP using its `pcap-file` mode. It does not require a live interface.

```bash
# Update ET Open rules (requires internet access)
./scripts/update_suricata_rules.sh

# ET Open only (no extra signing/PPA dependencies)
./scripts/update_suricata_rules.sh --et-only

# Add custom detection rules
nano rules/suricata/local.rules
```

Install Suricata once (if not installed by `install_dependencies.sh`):

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update && sudo apt-get install suricata
```

### YARA

```bash
# Run YARA scan standalone against a PCAP
./scripts/fan_yara_pcap.sh /path/to/capture.pcap

# Sweep a disk mount or memory image
./scripts/yara_sweep.sh --target /mnt/windows_mount/ --case-id FAST-2026-001
./scripts/yara_sweep.sh --target /path/to/memory.img --strings --threads 4
```

Drop `.yar` files into `./rules/yara/`. They are compiled and loaded automatically at scan time. The FAME pipeline also scans memory images against all rules in `./rules/yara/` during the memory analysis stage.

---

## 8. Batch analysis — many evidence files at once

When you have a folder full of evidence — several memory images, disk images, and PCAPs from
the same intrusion — you do not run each one by hand. Point the platform at the directory and it
analyzes every file, then writes a single campaign report that ties the cases together.

### In a Claude Code session (recommended)

```
/investigate-all                       # default evidence dir: /home/vscode/evidence
/investigate-all /path/to/evidence     # explicit directory
```

This enumerates every FAME / FAST / FAN evidence file, proposes a Batch ID, runs the cases
sequentially in-session (so you see the reasoning and approve tool use), and finishes with a
**batch synthesis**: common IOCs, common TTPs, the outlier case, the highest-severity leads, and a
revised campaign-level conclusion — followed by the unified report.

### From the shell

```bash
# Fast, non-interactive — direct shell pipelines per file
./scripts/batch_analyze.sh  /path/to/evidence --batch-id BATCH-2026-001

# Agentic — each case runs through Claude (/fame, /fast) so it produces research
# notes, interpreted findings, and a campaign report
./scripts/batch_agentic.sh  /path/to/evidence --batch-id BATCH-2026-001

# Re-render narratives / board decks / PDFs for cases already in ./reports/
./scripts/batch_regenerate.sh --dry-run        # list what would be regenerated
./scripts/batch_regenerate.sh --only-pptx      # board decks only
```

Files are routed by extension (FAME: `.mem .img .raw .lime .vmem .dmp`; FAST: `.E01 .ewf .vmdk
.vdi .qcow2 .vhd .vhdx`; FAN: `.pcap .pcapng .cap`). `.7z`/`.zip` archives are extracted first.
A `manifest.json` records every case's status and any errors; if a case fails, the batch logs it,
continues, and retries failed cases at the end. Already-processed files are skipped, so an
interrupted batch resumes without redoing work.

**Outputs:** per-case reports in `./reports/`, a batch aggregate report, and (agentic path) a
`CAMPAIGN_<id>_report.*` with a swimlane attack timeline. When finished, archive the campaign
folder with `/archive-reports` to keep `./reports/` clear for the next investigation.

### Cross-module correlation

After a multi-module case (e.g. a host with both a memory image and a disk image), run:

```
/correlate
```

This computes the actual links between modules — which **process** (FAME) opened a flagged
**network connection** (FAN), which running process was found **deleted on disk** (FAST), which
**DNS domain** (FAN) was confirmed by a **carved artifact** (FAST) — and writes
`<case_id>_correlation.md`. Run it **before** `./analysis/` is cleaned up, because it needs the raw
artifact files. Each correlated link is rated by how many modules corroborate it (3+ high
confidence, 1 = "verify manually").

---

## 9. Research notes & the audit trail

Every FAME / FAST / FAN investigation produces a **research notes file** next to the report:
`./reports/<case_id>_research_notes.md`. It is a timestamped, numbered, step-by-step log of the
whole investigation — what was run, *why*, what it found, and what was deliberately *not* flagged.
Any analyst (or any hackathon judge) can read it top to bottom and follow exactly how the
conclusion was reached.

This is what makes findings **auditable**: you can trace any line in the report back to the precise
tool execution that produced it.

```
tool run  →  preserved artifact (with SHA-256)  →  research note RN-005
          →  report section (cites RN-005)       →  vault record (source: …, RN-005)
```

### What a step looks like

```
### [2026-06-02 14:32:10 UTC] — Step 5 [RN-005]: Process List (windows.pslist)

| | |
|---|---|
| **Action** | vol -f image.mem windows.pslist → DEMO_evidence/memory/pslist.txt |
| **Why** | Identify running processes and parents for injection/persistence analysis |
| **Outcome** | 87 processes. lsass.exe running from C:\Temp\ — anomalous [source: …/pslist.txt] |
| **Dismissed** | All svchost.exe under System32 — match baseline, not flagged |
```

### The four kinds of entry

| Entry | What it records | Why it matters |
|-------|-----------------|----------------|
| **Step** (`RN-NNN`) | One tool run: action, why, outcome, and what was dismissed | The workflow, one line per action |
| **Event** (`EVT-NNN`) | A confirmed attacker action with a timestamp from the evidence | Builds the attack timeline |
| **Reflect** (`RF-NNN`) | A mid-investigation re-assessment: how new findings change earlier conclusions, and open leads | The agent re-examining its own work |
| **Assumption** | A working hypothesis that is not yet proven | Surfaces unproven premises so they are never mistaken for fact |

You do not normally call these by hand — Claude writes them as it works. The raw tool output for
each step is preserved under `./reports/<case_id>_evidence/` with a SHA-256 hash. The `./reports/`
directory is git-ignored, so notes and evidence are never committed to the repository.

---

## 10. How the platform stays accurate (trust features)

A forensics report is only useful if you can trust it. Fan Get Fame Fast is built so that a claim
is always reported at its true status — **confirmed**, **inferred**, or **unknown** — and a value is
never invented to fill a gap. These behaviours are enforced in code, not just asked for in a prompt.
The architecture is drawn in [Architecture diagrams §3–§7](ARCHITECTURE_DIAGRAM.md#3-trust--reliability-layer);
the technical detail is in [Technical Reference §11](TECHNICAL_REFERENCE.md#11-trust--reliability-subsystem).

### Confirmed vs. inferred

- Findings that are analytical judgements rather than direct evidence are tagged `[ASSUMPTION]`
  and collected into the report's **Confidence & gaps** section.
- An attacker event with no timestamp confirmed in the evidence is marked `(unconfirmed)` and left
  **out of the visual timeline** — a guessed time never appears as a fact.
- Every scoped conclusion names its evidence source: *"as observed in the PCAP file"*,
  *"Volatility 3 malfind identified injected code in PID 1234"*.

### Confidence & gaps section

Every FAME report ends with a **Confidence & gaps** section that states an overall confidence
(HIGH / MEDIUM / LOW) **with the reason** ("YARA scan and Memory Baseliner were both unavailable",
"DKOM is active"), a completeness table of which steps ran versus were skipped, the data gaps, the
recorded assumptions, and recommended follow-up. You can never mistake what was *not* analyzed for a
clean result.

### Degrade, don't guess

If a rootkit is hiding processes (the hidden-process scan finds more than the active list — DKOM),
the platform detects it, marks the active process list **"not authoritative"**, promotes the scans
that the rootkit cannot hide, and lowers the overall confidence — rather than quietly reporting a
process list it knows is incomplete.

### Confirmed findings only reach the knowledge base

IOCs and TTPs are written to the vault **only** from the analyst-reviewed report tables — never
scraped from raw tool output. Anything marked *"not confirmed"* or merely *Informational* is
skipped. A value you did not vet into the final report never becomes an institutional record.

### It handles failures instead of crashing

An optional stage never aborts the pipeline, and every skip or fallback is logged so the gap is
visible. Examples you will see in the logs:

- Linux memory image with no symbols → falls back to strings-based extraction.
- Disk image won't mount → retries, then falls back to TSK-only mode.
- Autopsy not installed → writes `AUTOPSY_NOT_RUN.txt` and continues.
- A tool returns nothing or errors → the step is recorded as a **Deviation** with the reason, and
  the investigation continues on a fallback path.

Every one of these deviations is written into the research notes, so you can see exactly where and
why the investigation changed course.

---

## 11. Claude skills

Open Claude Code in the project directory and type the skill name preceded by `/`.

| Skill | Command | What it does |
|-------|---------|-------------|
| Batch analysis (all evidence) | `/investigate-all [evidence_dir]` | Enumerates every FAME + FAST + FAN file and runs them in-session, then a unified campaign report |
| Cross-module correlation | `/correlate` | Computes FAN↔FAME / FAME↔FAST / FAN↔FAST matches from raw artifacts; writes `<case_id>_correlation.md` |
| Archive reports | `/archive-reports [CAMPAIGN_ID]` | Moves a finished campaign folder from `./reports/` to `./archive/` (move only, never delete) |
| CTI-OpenCTI-lookup | `/fan-opencti-lookup --case-id <id>` | Checks all IPs and FQDNs extracted from the PCAP against OpenCTI; writes `opencti_lookup.md` to the case folder |
| FAN IP lookup | `/fan-ip-lookup` | FQDN/IP enrichment + OSINT via Perplexity; results cached in the vault for 7 days |
| FAN report | `/fan-report` | Generates MD + PDF incident report from all module outputs under `./analysis/` |
| FAN extract IP+FQDN | `/fan-extract-ip-fqdn` | Extracts netflow, unique IPs, and FQDNs from a PCAP (lightweight, no full module pipeline) |
| Memory forensics | `/fame` | Full FAME pipeline: Volatility 3 + Memory Baseliner + research notes + report generation + upload |
| Storage forensics | `/fast` | Full FAST pipeline: TSK + bulk_extractor + Autopsy + research notes + report generation + upload |
| Perplexity lookup | `/perplexity-lookup` | Live threat intel for an unknown artifact (IOC, CVE, malware family, threat actor) |
| Obsidian query | `/obsidian-query` | Queries the vault for known context before starting an investigation |
| Obsidian record | `/obsidian-record` | Records confirmed findings into the vault and pushes them to OpenCTI |
| Markdown to PDF | `/md-to-pdf` | Converts any Markdown file to a styled PDF with cover page and pagination |
| Remove case | `/remove-case` | Removes a case directory from the investigations vault |

Individual detection module skills (`/fan-dns-threats`, `/fan-http-threats`, `/fan-tls-inspector`, etc.) run one module at a time against the current PCAP.

---

## 12. Obsidian vault — knowledge graph

The vault at `./vault/` is the platform's institutional memory. TTPs, IOCs, threat actors, malware families, risks, and case histories accumulate here across investigations. It is a plain-Markdown directory. Every note is a `.md` file readable without any special tooling.

### Vault folder layout

```
vault/
  IOCs/           One note per indicator (IP, domain, hash, URL, email, filename)
  TTPs/           One note per MITRE ATT&CK (sub)technique
  ThreatActors/   Threat group profiles
  Malware/        Malware family profiles
  Concepts/       Generic cybersecurity concepts
  Risks/          Risk assessments per case/asset
  Cases/          Post-investigation summaries
  Templates/      Note schemas — do not modify manually
  Dashboard.md    Auto-maintained index
```

### Writing to the vault

```python
from lib.knowledge_extractor import open_case, record_ioc, record_ttp, close_case

open_case("FAN-2026-001", "Suspected C2 beacon on DESKTOP-42.", severity="high")

record_ioc("ip", "203.0.113.42", "C2 destination in PCAP.", "FAN-2026-001", severity="high")
record_ttp("T1071.001", "Web Protocols", "HTTPS POST every 60s.", "FAN-2026-001")

close_case("FAN-2026-001", "C2 confirmed. Host isolated.")
```

All `record_*` calls are idempotent. Calling the same function again with the same indicator updates the existing note rather than creating a duplicate. Each call also pushes the finding to OpenCTI via `opencti_create_indicator`.

### Querying the vault

```bash
./scripts/vault_context.sh search <keyword>
./scripts/vault_context.sh ioc <ip-or-hash>
./scripts/vault_context.sh ttp T1059
```

IOC values in the vault are defanged: `192[.]168[.]1[.]1`, `evil[.]com`, `hxxps://...`. The `record_ioc` function defangs values automatically before writing. Never store live IPs or domains in plain text in the vault.

---

## 13. Live threat intelligence (Perplexity.ai)

When the vault has no answer for an artifact, Perplexity provides real-time web-sourced intelligence. Decision order: vault first, Perplexity on a cache miss, confirmed findings recorded back to vault.

```bash
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

**Privacy rule:** never include live case hostnames, usernames, or internal IPs in Perplexity queries. Only pass defanged or anonymized values.

Requires `PERPLEXITY_API_KEY` in `~/.soc_env`.

---

## 14. OpenCTI integration

The `/fan-opencti-lookup` skill checks all IPs and FQDNs extracted by FAN against your OpenCTI instance. Results go to `opencti_lookup.md` in the investigations vault case folder.

Every `record_ioc`, `record_ttp`, and `record_malware` call in `lib/knowledge_extractor.py` pushes the finding to OpenCTI via `opencti_create_indicator`.

Configure credentials in `~/.soc_env`:

```bash
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_API_KEY="your-api-token-here"
```

Get your token at **Settings → API access** in the OpenCTI web UI. The API key must belong to a dedicated service account in OpenCTI, not a personal user account.

Score thresholds:

| Score | Label |
|-------|-------|
| ≥ 75 | CONFIRMED_MALICIOUS |
| 40–74 | SUSPICIOUS |
| < 40 | INFORMATIONAL |
| — | NOT_FOUND |

---

## 15. MCP servers

Fan Get Fame Fast uses three Model Context Protocol (MCP) servers. They run as local Python processes started by Claude Code, communicate over stdio using JSON-RPC 2.0, and are registered in `.claude/settings.json`. They are the bridge between Claude and the evidence vault, investigation reports, and OpenCTI.

| MCP server | Root | Access | Tools |
|------------|------|--------|-------|
| `evidence` | `~/evidence` (local) | Read-only | `evidence_find_pcaps`, `evidence_read_file`, `evidence_get_file_info`, `evidence_list_directory` |
| `investigations` | `~/cases` (local) | Read-write | `investigations_list_cases`, `investigations_read_file`, `investigations_write_file`, `investigations_create_directory`, `investigations_delete`, `investigations_get_file_info`, `investigations_list_directory` |
| `opencti` | OpenCTI instance | Read-write | `opencti_search_ioc`, `opencti_search_stix`, `opencti_create_indicator` |

The evidence and investigations roots are set in `.claude/settings.json` via the `env` block. Re-run `setup_folder_structure.sh` to regenerate this file if you move the project or change the evidence/cases paths.

**These are architectural guardrails, not prompt rules.** The `evidence` server is read-only because it has *no write code at all* — a write isn't refused, it's unimplemented. Both file servers confine every request to their root with a `_safe_path()` check that defeats `../` traversal at the server, before any file is touched. Claude cannot talk its way past either boundary. See [Technical Reference §11.3](TECHNICAL_REFERENCE.md#113-architectural-guardrails).

Credentials (`OPENCTI_URL`, `OPENCTI_API_KEY`) come from environment variables sourced via `~/.soc_env`, not from `settings.json`.

### SSH key setup for report upload

`lib/investigations_upload.py` uses SSH/SCP to copy finished reports to the investigations vault on ubuntudesktop. It reads the SSH private key from `~/.ssh/id_ed25519`. The key must be authorized on the remote host before any investigation can complete:

```bash
# Generate a key if you do not have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Authorize it on ubuntudesktop
ssh-copy-id -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop

# Test
ssh -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop "echo OK"
```

Without this, the final upload step fails and the finished report stays in `./analysis/_reports/<stem>/` rather than being moved to the investigations vault.

### Verifying MCP servers

```bash
./scripts/test_mcp_servers.sh
# Or test individual servers
./scripts/test_mcp_servers.sh --evidence-only
./scripts/test_mcp_servers.sh --investigations-only
./scripts/test_mcp_servers.sh --opencti-only
```

Full MCP API reference: [Technical Reference — MCP server API](TECHNICAL_REFERENCE.md#5-mcp-server-api).

---

## 16. Reporting

### Report outputs by module

**FAN** — generated by `analyze_pcap.sh`:

| Format | Filename |
|--------|----------|
| Markdown | `<stem>_incident_report.md` |
| PDF | `<stem>_incident_report.pdf` |
| PowerPoint | `<stem>_management_briefing.pptx` |
| Archive | `<case_id>_<YYYYMMDD-HHMMSS>.zip` (all artifacts) |

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

### Management PowerPoint slide structure

The PPTX briefing targets CISO and management. Technical identifiers (IPs, ports, process names) are replaced with business-language descriptions.

| Slide | Content |
|-------|---------|
| 1 | Cover — case ID, date, classification |
| 2 | Executive summary — severity, traffic/memory/disk scope, key findings |
| 3 | Threat landscape — triggered threat categories with severity levels |
| 4 | Security alerts — Suricata IDS and YARA results in plain language |
| 5 | Indicators of compromise — defanged IOC list |
| 6 | Recommended actions — up to 8 prioritized action items |
| 7 | Investigation coverage — status of all detection modules that ran |

### Report language conventions

Every finding in the technical body names its evidence source explicitly. Examples:

- "As observed in the PCAP file, host 192.168.1.5 initiated an outbound TCP connection to 203.0.113.42 on port 4444 at 13:05 CET."
- "Volatility 3 malfind identified injected code in PID 1234 (explorer.exe)."
- "The filesystem timeline shows file creation at 14:32 CET on 03-May-2026, consistent with staging activity."

The management summary section uses no technical identifiers. Business causality only.

### Generating reports manually

```bash
# Full incident report (MD + PDF)
./scripts/generate_pcap_report.sh \
    --stem <pcap-stem> \
    --case-id FAN-2026-001 \
    --output-dir ./analysis/_reports/<stem>/

# PowerPoint presentation (FAN)
./scripts/generate_pcap_presentation.sh \
    --stem <pcap-stem> \
    --case-id FAN-2026-001 \
    --output-dir ./analysis/_reports/<stem>/

# Package all artifacts into a ZIP
python3 lib/case_packager.py \
    --case-id FAN-2026-001 \
    --stem <pcap-stem> \
    --reports-dir ./analysis/_reports/<stem>/ \
    --upload
```

### Markdown to PDF

```bash
./scripts/md_to_pdf.sh /path/to/report.md /path/to/output.pdf
```

The PDF includes a styled cover page, running header stripe, and "Page X of Y" pagination. Requires WeasyPrint (installed by `install_dependencies.sh`).

---

## 17. Configuration reference

### Environment variables

All variables are set in `~/.soc_env` (template: `templates/set_env_template.sh`) and sourced from `~/.bashrc`.

| Variable | Required | Description |
|----------|----------|-------------|
| `PERPLEXITY_API_KEY` | Yes | Perplexity.ai API key (`pplx-...`) |
| `OPENCTI_URL` | Yes (for OpenCTI) | OpenCTI instance URL, e.g. `http://localhost:8080` |
| `OPENCTI_API_KEY` | Yes (for OpenCTI) | OpenCTI API token from Settings → API access |
| `INVESTIGATIONS_SSH_HOST` | No | SSH target for investigations vault (default: `sansforensics@ubuntudesktop`) |
| `INVESTIGATIONS_ROOT` | No | Remote root path for case output (default: `/home/sansforensics/cases`) |
| `EVIDENCE_ROOT` | No | Override local evidence root (default: `~/evidence`) |
| `PYTHONPATH` | No (for AutoTimeliner) | Must include path to Volatility 3 source, e.g. `/opt/volatility3-2.20.0` |

### Key paths

| Path | Purpose |
|------|---------|
| `~/evidence/` | PCAP and evidence drop zone (evidence MCP server root) |
| `~/cases/<case_id>/reports/` | Uploaded investigation reports (investigations MCP server root) |
| `./analysis/` | WIP only — emptied automatically after each completed investigation |
| `./vault/` | Obsidian knowledge graph (TTPs, IOCs, cases, threat actors) |
| `./rules/suricata/` | Suricata rule files (ET Open + `local.rules`) |
| `./rules/yara/` | YARA rule files (`.yar` files compiled at scan time) |
| `./exports/` | Extracted artifacts per investigation (EVTX, registry, prefetch, MFT, SRUM) |
| `./reports/` | Manual report exports |
| `.claude/settings.json` | MCP server configuration and permission allowlist |
| `~/.soc_env` | API credentials (never commit to version control) |
| `~/.ssh/id_ed25519` | SSH private key used by `investigations_upload.py` for SCP uploads |

---

## 18. Self-tests and verification

### Vault library round-trips

```bash
source .venv/bin/activate
python3 lib/obsidian_bridge.py                     # write/read/search round-trip
python3 lib/knowledge_extractor.py --test          # all record types + Dashboard refresh
python3 lib/vault_query.py --search powershell     # full-text vault search
```

### MCP server verification

```bash
./scripts/test_mcp_servers.sh                      # all three servers
./scripts/test_mcp_servers.sh --evidence-only      # evidence server only
./scripts/test_mcp_servers.sh --opencti-only       # OpenCTI server only
```

### End-to-end pipeline smoke test

```bash
./scripts/test_solution.sh                         # generates a minimal test PCAP, runs full pipeline
./scripts/test_solution.sh /path/to/sample.pcap    # with a real PCAP
```

All checks report `[PASS]` on a healthy installation. The smoke test exits 0 on success.

---

## 19. Evidence integrity rules

1. Never write to `/mnt/`, `/media/`, or any `evidence/` directory. Those paths are read-only by platform policy.
2. Analysis WIP goes to `./analysis/` only. It is deleted automatically after each investigation completes.
3. Finalized reports go to the investigations vault (`~/cases/<case_id>/reports/` via SSH/SCP).
4. All timestamps are UTC internally. Reports use the timezone of the incident location (UTC if unknown, stated explicitly).
5. IOC values stored in the vault are defanged. Never store live IPs or domains in plain text in any vault note.
6. External API calls (Perplexity) receive only defanged, anonymized values. No raw evidence paths, internal hostnames, or personal data.
7. Report versioning is automatic. Do not edit report files manually after upload to the investigations vault.

---

## Related documentation

| Document | Purpose |
|----------|---------|
| [Architecture diagrams](ARCHITECTURE_DIAGRAM.md) | Presentation-ready diagrams: agentic loop, trust layer, audit chain, guardrails, batch scale-out |
| [Deployment guide](DEPLOYMENT_GUIDE.md) | Production server setup, SSH key configuration, sudoers setup, Autopsy/AutoTimeliner/EVTXtract/MemProcFS install, hardening, backup, upgrade |
| [Technical reference](TECHNICAL_REFERENCE.md) | Architecture, all pipeline data flows, full Python library API, MCP API, vault schema, dependency map, trust & reliability subsystem |
| [CLAUDE.md](../CLAUDE.md) | Project philosophy, agentic coordinator behavior, report voice registers, evidence constraints |

---

## 20. License and disclaimer

Fan Get Fame Fast is dual-licensed under your choice of:

- Apache License, Version 2.0 — [LICENSE-APACHE](../LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0
- MIT License — [LICENSE-MIT](../LICENSE-MIT) or http://opensource.org/licenses/MIT

See [LICENSE](../LICENSE) for the dual-license notice.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Run it only against systems, memory images, disk images, and network captures you own or have explicit written authorization to examine. All findings must be reviewed and validated by a qualified human analyst before use in legal proceedings or incident response decisions.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin — June 2026 — v4.0*
