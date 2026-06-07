# FanGetFameFast — Technical reference

**Version:** 2.0 · June 2026
**Platform:** Ubuntu 24.04 LTS (x86-64)
**Authors:** Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
**Classification:** Internal — SOC Operations

> **Presenting this to the hackathon panel?** The diagram companion to this reference is
> [Architecture diagrams (presentation deck)](ARCHITECTURE_DIAGRAM.md) — projector-ready Mermaid
> renderings of the agentic loop, the trust layer, the audit chain, and the guardrails, each
> mapped to a judging criterion.

> **What's new in v2.0:** this release adds the **trust & reliability subsystem** — the
> research-notes audit trail, failure-handling and self-correction across all three pipelines,
> the anti-hallucination controls (confirmed-vs-inferred labelling, confidence-and-gaps scoring),
> and the architectural guardrails. See the new [Section 11](#11-trust--reliability-subsystem).
> Batch/campaign scale-out (`batch_analyze.sh`, `batch_agentic.sh`, the `correlate` and
> `investigate-all` skills) and the library modules behind it are documented throughout.

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [FAN pipeline — data flow](#2-fan-pipeline--data-flow)
3. [FAME pipeline — data flow](#3-fame-pipeline--data-flow)
4. [FAST pipeline — data flow](#4-fast-pipeline--data-flow)
5. [Module inventory](#5-module-inventory)
6. [Python library API](#6-python-library-api)
7. [MCP server API](#7-mcp-server-api)
8. [Obsidian vault schema](#8-obsidian-vault-schema)
9. [Configuration reference](#9-configuration-reference)
10. [Dependency map](#10-dependency-map)
11. [Trust & reliability subsystem](#11-trust--reliability-subsystem)
12. [Batch & campaign orchestration](#12-batch--campaign-orchestration)
13. [License and disclaimer](#13-license-and-disclaimer)

---

## 1. Architecture overview

```
┌──────────────────────────────────────────────────────────────────┐
│                     Claude Code (Coordinator)                    │
│   Routes evidence · Pivots across modules · Generates reports    │
└───────────────────┬──────────────────────────────────────────────┘
                    │ orchestrates
        ┌───────────┼───────────────┐
        │           │               │
   ┌────▼────┐ ┌────▼────┐   ┌──────▼──────┐
   │  FAN    │ │  FAME   │   │    FAST     │
   │ Network │ │ Memory  │   │   Storage   │
   │forensics│ │forensics│   │  forensics  │
   │  LIVE   │ │  LIVE   │   │    LIVE     │
   └────┬────┘ └─────────┘   └─────────────┘
        │
        │ reads / writes
        ▼
┌───────────────────────────────────────────────────────┐
│                   Knowledge layer                     │
│                                                       │
│  Obsidian vault (./vault/)   ◄──► OpenCTI (GraphQL)   │
│  TTPs · IOCs · ThreatActors       mcp/opencti_server  │
│  Malware · Cases · Risks                              │
└───────────────────────────────────────────────────────┘
        │
        │ lookups (cache miss)
        ▼
┌───────────────────┐
│  Perplexity.ai    │
│  Live threat intel│
└───────────────────┘
```

All three modules are live. FAME and FAST auto-detect sibling module reports for the same case ID and produce a combined unified report when more than one module has run.

### Design decisions

**No daemon.** Every investigation starts with an explicit analyst command. There is no file watcher or auto-trigger. Automated evidence processing without analyst approval is a liability in a forensic context — chain of custody requires that every action be deliberate and auditable.

**WIP isolation.** All temporary analysis output lands in `./analysis/` and is deleted when the investigation completes. The investigations vault (`~/cases/`) is the only persistent store for finished work. If the analysis directory is not empty when a pipeline starts, that is a sign the previous run was interrupted — investigate before proceeding.

**Vault-first lookups.** Before any external API call, the vault is queried. A Perplexity request fires only on a cache miss. This keeps sensitive case context off external infrastructure and speeds up repeated lookups on the same indicators across cases.

**Idempotent recording.** `record_*` functions in `knowledge_extractor.py` update existing notes rather than creating duplicates. Multiple module passes against the same indicator converge on a single vault note. The `case_refs` list in each note accumulates all cases where that indicator has appeared.

**SSH/SCP for report upload.** `lib/investigations_upload.py` uses the key at `~/.ssh/id_ed25519`. The path is hardcoded in the library. If the deployment uses a different key path, edit `_SSH_OPTS` in `investigations_upload.py` before running investigations.

**Agentic coordination, not a fixed script.** Claude is the coordinator, not a hard-coded runbook. It reads each tool's output, decides the next pivot from what it found, and stops when no pivots remain. The investigation is a *reason → act → read → log → verify → (self-correct)* loop, drawn in full in [Architecture diagrams §2](ARCHITECTURE_DIAGRAM.md#2-the-agentic-investigation-loop). The loop is held honest by the trust subsystem in [Section 11](#11-trust--reliability-subsystem): the agent may not advance to the next step until the current one is logged, and every deviation from the standard path is itself a logged step.

**Trust is a subsystem, not a prompt.** The properties the platform is judged on — failure handling, self-correction, distinguishing confirmed findings from inferences, catching hallucinations, and tracing every finding to the tool that produced it — are enforced in code (`lib/research_notes.py`, `lib/vault_writer.py`, the confidence/gaps logic in the report generators, and the `_safe_path()` jail in the MCP servers), not asserted in natural language. [Section 11](#11-trust--reliability-subsystem) documents each mechanism and its enforcement point.

---

## 2. FAN pipeline — data flow

```
Analyst
  │
  └── analyze_pcap.sh /path/to/capture.pcap [--case-id FAN-2026-001]
        │
        ├── [1] Input validation
        │     PCAP file exists · not in /mnt|/media|evidence/
        │     File extension: .pcap or .pcapng
        │
        ├── [2] Case initialization
        │     Assign case ID (prompt or --case-id flag)
        │     lib/knowledge_extractor.py: open_case()
        │     Vault: Cases/<case_id>.md created
        │
        ├── [3] 22 detection modules (sequential)
        │     Each module: scripts/fan_<name>.sh → lib/fan_<name>.py
        │     All modules share a single PcapAnalyzer instance via lib/pcap_analyzer.py
        │     Output: ./analysis/<module>/<pcap-stem>/{*.json,*.csv,*_report.md}
        │
        ├── [4] Suricata IDS scan
        │     suricata -r <pcap> -c suricata.yaml -l ./analysis/suricata/<pcap-stem>/
        │     Rules: rules/suricata/et-open.rules + rules/suricata/local.rules
        │     Output: ./analysis/suricata/<pcap-stem>/eve.json, fast.log
        │
        ├── [5] YARA scan
        │     yara (compiled from rules/yara/*.yar) against PCAP payload bytes
        │     Output: ./analysis/yara_pcap/<pcap-stem>/yara_matches.json
        │
        ├── [6] IP + FQDN extraction and enrichment
        │     lib/fan_ip_lookup.py: vault lookup → Perplexity (on cache miss)
        │     Output: ./analysis/cti/<pcap-stem>/enrichment.json
        │
        ├── [7] Report generation
        │     lib/generate_pcap_report.py → MD + PDF (via lib/md_to_pdf.py)
        │     lib/generate_presentation.py → PPTX (7 slides)
        │     Output: ./analysis/_reports/<pcap-stem>/
        │
        ├── [8] Artifact bundling
        │     lib/case_packager.py: zip MD + PDF + PPTX + all module outputs
        │     ZIP name: <case_id>_<YYYYMMDD-HHMMSS>.zip
        │     Output: ./analysis/_reports/<pcap-stem>/
        │
        ├── [9] Upload to investigations vault
        │     lib/investigations_upload.py
        │     SSH key: ~/.ssh/id_ed25519
        │     SSH host: $INVESTIGATIONS_SSH_HOST (default: sansforensics@ubuntudesktop)
        │     Destination: $INVESTIGATIONS_ROOT/<case_id>/reports/
        │
        ├── [10] Vault recording
        │     lib/knowledge_extractor.py: record_ioc, record_ttp, close_case
        │     Also pushes to OpenCTI via mcp/opencti_server.py
        │
        ├── [11] Session transcript (chain of evidence)
        │     lib/chat_recorder.py → verbatim MD + PDF + raw .jsonl (SHA-256)
        │     Output: ./reports/<case_id>_chat_transcript.{md,pdf,jsonl}
        │     Uploaded to the investigations vault alongside the report
        │
        └── [12] WIP cleanup
              rm -rf ./analysis/<module>/<pcap-stem>/  (all 22 modules)
              rm -rf ./analysis/suricata/<pcap-stem>/
              rm -rf ./analysis/yara_pcap/<pcap-stem>/
              rm -rf ./analysis/cti/<pcap-stem>/
              rm -rf ./analysis/_reports/<pcap-stem>/
              ./analysis/ is empty on completion
```

### Analysis directory structure (during a FAN investigation)

```
analysis/
  dns_threats/<pcap-stem>/
    dns_flows.csv
    dns_threats.json
    dns_threats_report.md
  http_threats/<pcap-stem>/
    http_flows.csv
    http_threats.json
    http_threats_report.md
  <module>/<pcap-stem>/
    <module>_flows.csv
    <module>_threats.json
    <module>_threats_report.md
  suricata/<pcap-stem>/
    eve.json
    fast.log
  yara_pcap/<pcap-stem>/
    yara_matches.json
  cti/<pcap-stem>/
    enrichment.json
  _reports/<pcap-stem>/
    <stem>_incident_report.md
    <stem>_incident_report.pdf
    <stem>_management_briefing.pptx
    <case_id>_<timestamp>.zip
```

Everything under `analysis/` is deleted when step [11] completes.

---

## 3. FAME pipeline — data flow

```
Analyst
  │
  └── fame_analyze.sh /path/to/image.mem [--case-id FAME-2026-001] [--hostname SERVER1234]
        │
        ├── [1] Input validation
        │     Image file exists · not in /mnt|/media|evidence/
        │     Case ID assigned; hostname derived from image filename if not provided
        │
        ├── [2] OS type detection
        │     vol.py info: detect Windows vs Linux image
        │     Selects appropriate plugin set
        │
        ├── [3] Volatility 3 plugins
        │     pslist, psscan, pstree, cmdline, netstat, netscan, malfind,
        │     svcscan, modules, modscan, filescan, userassist, hivelist, info
        │     Output: ./analysis/memory/<plugin>.json
        │
        ├── [4] YARA memory scan
        │     yara (compiled from rules/yara/*.yar) against raw memory image
        │     Output: ./analysis/memory/yara_memory_matches.json
        │
        ├── [5] Memory timeline
        │     vol.py timeliner --create-bodyfile → mem_bodyfile.txt
        │     mactime -b mem_bodyfile.txt → mem_timeline.txt (sorted MACB)
        │     Output: ./analysis/memory/mem_bodyfile.txt, mem_timeline.txt
        │
        ├── [6] Memory Baseliner
        │     baseline.py: compares pslist/modules/svcscan output against
        │     baselines/baseline.json (known-good reference)
        │     Output: ./analysis/memory/proc_baseline.csv
        │                               drv_baseline.csv
        │                               svc_baseline.csv
        │
        ├── [7] MemProcFS (optional — if memprocfs package is installed)
        │     For VirtualBox ELF core dumps: lib/fame_memprocfs.py extracts
        │     CR3/DTB from VBCPU PT_NOTE segment → initializes MemProcFS →
        │     extracts physical banners, attack strings, IOC matches
        │     Output: ./analysis/memory/memprocfs/
        │               artifacts.json, physical_banners.txt, attack_artifacts.txt
        │
        ├── [8] AutoTimeliner (optional — if installed at /opt/autotimeliner/)
        │     Correlates Volatility plugin outputs into a single MACB bodyfile
        │     Output: ./analysis/memory/autotimeliner/supertimeline.csv
        │
        ├── [9] EVTXtract (optional — if installed at /opt/EVTXtract/)
        │     Scans raw memory pages for EVTX record magic bytes
        │     Validates checksums; recovers intact Event records
        │     Output: ./analysis/memory/evtxtract/recovered_events.xml
        │                                          events_summary.txt
        │                                          evtxtract.log
        │
        ├── [10] Linux strings fallback (if no ISF symbols available)
        │     strings -n 8 image → strings_all.txt
        │     strings -el image → strings_unicode.txt
        │     grep for auth/syslog patterns → syslog_patterns.txt
        │     Output: ./analysis/memory/strings/
        │
        ├── [11] Rekall status documentation
        │     Rekall was abandoned (2021). Status recorded in analysis output.
        │     Volatility 3 provides equivalent and extended coverage.
        │
        ├── [12] Report generation
        │     lib/generate_fame_report.py → MD + PDF + PPTX + DOCX
        │     If FAN or FAST reports exist for same case ID:
        │       lib/generate_combined_report.py → combined MD + PDF + PPTX + DOCX
        │     Output: ./analysis/memory/reports/
        │
        ├── [13] Upload to investigations vault
        │     lib/investigations_upload.py (SSH/SCP to ubuntudesktop)
        │
        ├── [14] Vault recording
        │     lib/knowledge_extractor.py: record_ioc, record_ttp, close_case
        │
        └── [15] Session transcript (chain of evidence)
              lib/chat_recorder.py → verbatim MD + PDF + raw .jsonl (SHA-256)
              Output: ./reports/<case_id>_chat_transcript.{md,pdf,jsonl}
              Uploaded to the investigations vault alongside the reports
```

---

## 4. FAST pipeline — data flow

```
Analyst
  │
  └── fast_analyze.sh /path/to/image.E01 [--case-id FAST-2026-001] [--hostname SERVER1234]
        │
        ├── [1] Input validation
        │     Image file exists · not in /mnt|/media|evidence/
        │     Case ID assigned
        │
        ├── [2] Image verification
        │     E01/EWF: ewfinfo (metadata) + ewfverify (MD5/SHA1 integrity check)
        │     Raw:     img_stat
        │     Output: ./analysis/storage/ewfinfo.txt, ewfverify.txt, img_stat.txt
        │
        ├── [3] Partition map
        │     mmls: identifies all partitions and their start sectors
        │     Output: ./analysis/storage/mmls.txt
        │
        ├── [4] Filesystem stats
        │     fsstat: filesystem type, cluster size, volume serial, block counts
        │     Output: ./analysis/storage/fsstat.txt
        │
        ├── [5] File listing
        │     fls -r -p: recursive file/directory listing with inode and timestamps
        │     Output: ./analysis/storage/fls_output.txt
        │
        ├── [6] MACB bodyfile + timeline
        │     fls -m: generates bodyfile
        │     mactime -b bodyfile → fs_timeline.txt + fs_timeline.csv
        │     Output: ./analysis/storage/bodyfile.txt
        │             ./exports/fs_timeline.txt, fs_timeline.csv
        │
        ├── [7] Inode listing
        │     ils: allocated inodes
        │     ils -o: orphan inodes (deleted-but-recoverable files)
        │     Output: ./analysis/storage/ils_output.txt, ils_orphan.txt
        │
        ├── [8] Artifact extraction (requires --mount or filesystem access)
        │     Copies from mounted image to ./exports/:
        │       evtx/        Windows Event Log files (.evtx)
        │       registry/    Registry hives: SYSTEM, SOFTWARE, SAM, NTUSER.DAT
        │       prefetch/    Prefetch files (.pf)
        │       srum/        SRUM database (SRUDB.dat)
        │       browser/     Browser history files
        │       recyclebin/  Recycle Bin entries
        │       tasks/       Scheduled tasks (XML)
        │
        ├── [9] MFT + USN journal extraction
        │     icat image.E01 0 > exports/mft/$MFT
        │     icat image.E01 <J_inode> > exports/mft/$J
        │
        ├── [10] File carving (skipped for images > 20 GB)
        │     bulk_extractor -o exports/carved/ image.E01
        │     Carves: emails, URLs, credit card numbers, registry keys
        │
        ├── [11] Autopsy headless ingest (optional)
        │     autopsy --nogui --createCase --addDataSource image.E01
        │     Ingest modules: FileExtMismatch, HashLookup, RecentActivity,
        │                     TimeLine, ExifParser, KeywordSearch
        │     Output: ./exports/autopsy/case/, autopsy.log
        │     If autopsy not found: AUTOPSY_NOT_RUN.txt written to ./exports/autopsy/
        │
        ├── [12] Report generation
        │     lib/generate_fast_report.py → MD + PDF + PPTX + DOCX
        │     If FAN or FAME reports exist for same case ID:
        │       lib/generate_combined_report.py → combined MD + PDF + PPTX + DOCX
        │     Output: ./analysis/storage/reports/
        │
        ├── [13] Upload to investigations vault
        │     lib/investigations_upload.py (SSH/SCP to ubuntudesktop)
        │
        ├── [14] Vault recording
        │     lib/knowledge_extractor.py: record_ioc, record_ttp, close_case
        │
        └── [15] Session transcript (chain of evidence)
              lib/chat_recorder.py → verbatim MD + PDF + raw .jsonl (SHA-256)
              Output: ./reports/<case_id>_chat_transcript.{md,pdf,jsonl}
              Uploaded to the investigations vault alongside the reports
```

---

## 5. Module inventory

### Detection modules (FAN)

Each module follows the same pattern:

- Shell wrapper: `scripts/fan_<name>.sh <pcap> [--case-id <id>]`
- Python library: `lib/fan_<name>.py`
- Entry point: `analyse(pcap_path, output_dir, case_id=None)`
- Outputs: `<name>_flows.csv`, `<name>_threats.json`, `<name>_threats_report.md`

All modules share a `PcapAnalyzer` instance from `lib/pcap_analyzer.py`. The PCAP is parsed once with tshark at the start; all modules work from the resulting DataFrames.

| Module | Script | Library | Detection categories |
|--------|--------|---------|---------------------|
| ARP threats | `fan_arp_threats.sh` | `fan_arp_threats.py` | Cache poisoning, gratuitous ARP flood, ARP scan, proxy anomaly |
| Certificate inspector | `fan_cert_inspector.sh` | `fan_cert_inspector.py` | Self-signed, expired, short/long validity, wildcard, SNI mismatch, weak sig |
| DHCP threats | `fan_dhcp_threats.sh` | `fan_dhcp_threats.py` | Starvation, rogue server, spoofing, relay anomaly, message injection |
| DNS threats | `fan_dns_threats.sh` | `fan_dns_threats.py` | DGA, beaconing, exfiltration, fast flux, amplification, NXDomain flood, typosquatting, zone transfer |
| File hashes | `fan_file_hashes.sh` | `fan_file_hashes.py` | Extracts HTTP/SMB/TFTP/IMF/DICOM files; MD5+SHA256; Perplexity OSINT |
| HTTP/S threats | `fan_http_threats.sh` | `fan_http_threats.py` | Suspicious UA, unusual methods, scanning status codes, large upload, cookie/host anomaly, beaconing |
| ICMP threats | `fan_icmp_threats.sh` | `fan_icmp_threats.py` | Flood, Ping of Death, fragmentation, tunneling, Smurf, redirect, sweep, recon, exfiltration |
| IP/FQDN lookup | `fan_ip_lookup.sh` | `fan_ip_lookup.py` | FQDN/IP correlation, DNS resolution, vault lookup, Perplexity OSINT enrichment |
| LLMNR threats | `fan_llmnr_threats.sh` | `fan_llmnr_threats.py` | Spoofing/poisoning, credential theft, SMB relay, reconnaissance |
| mDNS threats | `fan_mdns_threats.sh` | `fan_mdns_threats.py` | Amplification, information leakage, spoofing/cache poisoning, outside local segment |
| NBNS threats | `fan_nbns_threats.sh` | `fan_nbns_threats.py` | Spoofing/poisoning, credential theft, SMB relay, enumeration, WPAD poisoning |
| NetBIOS threats | `fan_netbios_threats.sh` | `fan_netbios_threats.py` | Poisoning, NTLM hash theft/relay, enumeration, null session, DDoS, malware propagation |
| NTP threats | `fan_ntp_threats.sh` | `fan_ntp_threats.py` | Amplification, flood, Kiss-of-Death, monlist abuse, time manipulation, recon |
| QUIC threats | `fan_quic_threats.sh` | `fan_quic_threats.py` | Amplification/DDoS, 0-RTT replay, version forgery, pre-handshake exhaustion |
| SNMP threats | `fan_snmp_threats.sh` | `fan_snmp_threats.py` | Default community strings, MitM, DoS flood, reconnaissance, malicious SET, large data transfer |
| SSDP/UPnP threats | `fan_ssdp_threats.sh` | `fan_ssdp_threats.py` | Amplification DDoS, device exposure, network manipulation, vulnerable UPnP |
| STUN threats | `fan_stun_threats.sh` | `fan_stun_threats.py` | Amplification DDoS, info leakage, firewall traversal, service abuse |
| Suricata IDS | `fan_suricata.sh` | `fan_suricata.py` | ET Open rules + `rules/suricata/local.rules` |
| TCP threats | `fan_tcp_threats.sh` | `fan_tcp_threats.py` | SYN flood, port scan, RST flood, stealth scan, session hijacking, half-open flood |
| TLS inspector | `fan_tls_inspector.sh` | `fan_tls_inspector.py` | Suspicious JA4/JA3, weak cipher, deprecated TLS, non-standard port, cipher diversity scan |
| UDP threats | `fan_udp_threats.sh` | `fan_udp_threats.py` | Flood, reflection/amplification, port scan, fragmentation, IP spoofing |
| YARA PCAP scan | `fan_yara_pcap.sh` | `fan_yara_pcap.py` | All `.yar` rules from `rules/yara/`: PE structure, entropy anomaly, network patterns, malware families |

### FAME pipeline — tools and outputs

Entry point: `scripts/fame_analyze.sh`

| Stage | Tool | Output path |
|-------|------|-------------|
| Volatility 3 | `vol.py` | `analysis/memory/<plugin>.json` (one file per plugin) |
| YARA memory scan | `yara` | `analysis/memory/yara_memory_matches.json` |
| Memory timeline | `vol.py timeliner` + `mactime` | `analysis/memory/mem_bodyfile.txt`, `mem_timeline.txt` |
| Memory Baseliner | `baseline.py` | `analysis/memory/proc_baseline.csv`, `drv_baseline.csv`, `svc_baseline.csv` |
| MemProcFS | `lib/fame_memprocfs.py` | `analysis/memory/memprocfs/` (optional) |
| AutoTimeliner | `/opt/autotimeliner/autotimeliner.py` | `analysis/memory/autotimeliner/supertimeline.csv` (optional) |
| EVTXtract | `/opt/EVTXtract/evtxtract.py` | `analysis/memory/evtxtract/recovered_events.xml` (optional) |
| Linux strings fallback | `strings` + grep | `analysis/memory/strings/` (when no ISF symbols) |

**MemProcFS** (`lib/fame_memprocfs.py`) provides a second physical memory analysis pathway via LeechCore. For VirtualBox ELF core dumps, it extracts the CR3 (Directory Table Base) from the VBCPU PT_NOTE segment by scanning for page-aligned physical addresses in the expected range. With the CR3, MemProcFS can initialize a full memory process model even without OS symbols. Install: `pip3 install memprocfs --break-system-packages`.

**AutoTimeliner** lives at `/opt/autotimeliner/autotimeliner.py`. It correlates Volatility plugin outputs (timeliner, pslist, pstree, netstat, filescan) into a single MACB super-timeline in bodyfile format. Requires Volatility 3 importable via `$PYTHONPATH`. When absent, skipped.

**EVTXtract** lives at `/opt/EVTXtract/evtxtract.py`. It scans raw binary data for EVTX record magic bytes (`ElfChnk` signature) and validates record checksums, producing an XML document with all recovered `<Event>` elements. Most useful when `filescan` finds `.evtx` file paths but the records are fragmented across memory pages. When absent, skipped.

**Rekall** was abandoned by Google in 2021. Last release: v1.7.2.post1 (October 2019). It requires Python ≤ 3.7 and has C-extension dependencies (acora, aff4-snappy, pyblake2, fastchunking) that do not build against Python 3.8+. Installation was attempted on Python 3.12.3 and failed at the wheel-build stage for all four C extensions. The FAME pipeline documents this status in the analysis output and continues. Volatility 3 provides equivalent and extended coverage.

### FAST pipeline — tools and outputs

Entry point: `scripts/fast_analyze.sh`

| Stage | Tool | Output path |
|-------|------|-------------|
| Image verification | `ewfinfo` / `ewfverify` / `img_stat` | `analysis/storage/ewfinfo.txt`, `ewfverify.txt`, `img_stat.txt` |
| Partition map | `mmls` | `analysis/storage/mmls.txt` |
| Filesystem stats | `fsstat` | `analysis/storage/fsstat.txt` |
| File listing | `fls -r` | `analysis/storage/fls_output.txt` |
| MACB bodyfile | `fls -m` | `analysis/storage/bodyfile.txt` |
| Filesystem timeline | `mactime` | `exports/fs_timeline.txt`, `fs_timeline.csv` |
| Inode listing | `ils` | `analysis/storage/ils_output.txt`, `ils_orphan.txt` |
| Artifact extraction | `cp` from mount | `exports/evtx/`, `registry/`, `prefetch/`, `srum/`, `browser/`, `recyclebin/` |
| MFT + USN journal | `icat` | `exports/mft/$MFT`, `exports/mft/$J` |
| File carving | `bulk_extractor` | `exports/carved/` (images up to 20 GB only) |
| Autopsy | `autopsy --nogui` | `exports/autopsy/case/` + exported CSVs (optional) |

Autopsy runs in headless (`--nogui`) mode with these ingest modules enabled:

| Module | What it finds |
|--------|--------------|
| `FileExtMismatchDetectorModuleFactory` | Files whose content type does not match their extension (e.g. an executable disguised as a PDF) |
| `HashLookupModuleFactory` | Files present in the NSRL known-good set, or matching any configured hash sets |
| `RecentActivityExtracterModuleFactory` | Browser history, recently opened files, shell items, USB device history |
| `TimeLineModuleFactory` | Visual timeline of filesystem events (mirrors the mactime output) |
| `ExifParserModuleFactory` | EXIF metadata from images (camera model, GPS, timestamps) |
| `KeywordSearchModuleFactory` | Full-text content index for keyword hit searches |

Autopsy is located via `$PATH`, `/opt/autopsy/bin/autopsy`, or `/usr/share/autopsy/bin/autopsy`. When absent, the step is skipped and `AUTOPSY_NOT_RUN.txt` is written to `./exports/autopsy/`.

### Utility scripts

| Script | Purpose |
|--------|---------|
| `analyze_pcap.sh` | Orchestrates the full 22-module FAN pipeline (input: PCAP file) |
| `pcap_analyze.sh` | Lightweight IP/FQDN extractor (input: PCAP file; outputs netflow + IP/FQDN lists only, no full module pipeline) |
| `fame_analyze.sh` | Orchestrates the FAME pipeline (Volatility + MemProcFS + AutoTimeliner + EVTXtract) |
| `fast_analyze.sh` | Orchestrates the FAST pipeline (TSK + bulk_extractor + Autopsy) |
| `batch_analyze.sh` | Walks an evidence directory, routes each file to FAME/FAST/FAN (direct shell pipelines), writes a batch manifest + aggregate report. See [Section 12](#12-batch--campaign-orchestration) |
| `batch_agentic.sh` | Same routing, but each FAME/FAST/FAN case runs through the Claude **agentic** path (`claude -p "/fame …"`) so research notes and interpreted findings are produced; adds a campaign-report phase. Filename prompt-injection guard at the input. See [Section 12](#12-batch--campaign-orchestration) |
| `batch_regenerate.sh` | Regenerates new-format narratives / board decks / PDFs for all cases already in `./reports/` (`--dry-run`, `--only-pptx`, `--case-id`); optionally re-runs the campaign report |
| `generate_pcap_report.sh` | Assembles FAN module outputs into Markdown + PDF incident report |
| `generate_pcap_presentation.sh` | Generates FAN management PowerPoint briefing (wraps `lib/generate_presentation.py`) |
| `bundle_artifacts.sh` | Zips all investigation artifacts for a completed case (reports + per-module outputs) |
| `update_suricata_rules.sh` | Downloads and updates ET Open Suricata rules |
| `yara_sweep.sh` | Standalone YARA sweep against disk mounts or memory images |
| `perplexity_search.sh` | CLI wrapper for Perplexity threat intelligence lookups |
| `vault_context.sh` | CLI wrapper for Obsidian vault queries |
| `md_to_pdf.sh` | Converts a Markdown file to a styled PDF (wraps `lib/md_to_pdf.py`) |
| `remove_case.sh` | Removes a case directory from the investigations vault |
| `setup_sudoers.sh` | Writes a sudoers drop-in granting NOPASSWD for `suricata-update` (run once after install) |
| `test_solution.sh` | End-to-end FAN pipeline smoke test |
| `test_mcp_servers.sh` | Verifies all three MCP servers respond to JSON-RPC initialize requests |
| `install_dependencies.sh` | System and Python dependency installer |
| `setup_folder_structure.sh` | Creates all required directories and generates `.claude/settings.json` |
| `templates/set_env_template.sh` | Template for `~/.soc_env` (API credentials and devcontainer mounts) |

---

## 6. Python library API

All library modules live in `lib/`. The virtual environment must be active:

```bash
source .venv/bin/activate
```

---

### `lib/path_guard.py` — write-path policy (single source of truth)

Enforces the rule *output is written only to approved folders; evidence, `/mnt`, `/media` and
everything else are read-only.* Every file-writing chokepoint in the library routes through it, and
a write outside policy raises `WritePolicyError` (a `PermissionError`) — nothing is written.

```python
from lib.path_guard import (
    assert_writable,    # assert_writable(path) → resolved Path; raises WritePolicyError if blocked
    guard_output_dir,   # guard_output_dir(path) → resolved Path; assert + mkdir(parents, exist_ok)
    is_writable,        # is_writable(path) → bool
    safe_write_text,    # safe_write_text(path, text, **kw) → Path  (policy-checked Path.write_text)
    safe_write_bytes,   # safe_write_bytes(path, data) → Path
    safe_open,          # safe_open(path, mode, **kw) → IO  (asserts only for write/append modes)
    WritePolicyError,
)
```

Policy: a path is writable **iff** it resolves inside an approved root **and not** inside a read-only
root (read-only roots win). Matching is by resolved path prefix — never substring — so
`reports/<case>_evidence` stays writable while a real evidence root does not.

- **Approved roots** (under the project root): `analysis`, `exports`, `reports`, `archive`, `vault`,
  `cases`, `demo`, `docs`, plus the OS temp dir. Extend with `FGFF_APPROVED_ROOTS` (a `:`-separated
  list of absolute paths).
- **Read-only roots**: `/mnt`, `/media`, and any evidence root (`EVIDENCE_ROOT`, the
  devcontainer/production defaults, `<project>/evidence` if present, and `FGFF_READONLY_ROOTS`).

Wired into: `obsidian_bridge` (all vault writes), `md_to_pdf.convert` (all PDFs), every `generate_*`
report generator (output-dir resolution), `chat_recorder` (transcript MD/PDF/JSONL), and
`case_packager` (staging dir + ZIP). The `investigations`
MCP server enforces the same read-only roots independently; the analyze shell scripts use the parallel
`scripts/pathguard.sh`.

Self-test: `python3 lib/path_guard.py --test`

---

### `lib/obsidian_bridge.py` — vault I/O

Low-level read/write operations on `./vault/`. All paths are relative to `./vault/`.

```python
from lib.obsidian_bridge import (
    write_note,       # write_note(path, content) → None
                      # Creates or overwrites the note at vault/path
    read_note,        # read_note(path) → str | None
                      # Returns note content, or None if the note does not exist
    append_to_note,   # append_to_note(path, content) → None
                      # Appends content to an existing note (creates if absent)
    search_vault,     # search_vault(query, max_results=10) → list[dict]
                      # Full-text search across all vault notes
    patch_section,    # patch_section(path, section_header, new_content) → None
                      # Replaces the body of a named section (## Header) in a note
)
```

`path` examples: `"IOCs/192.168.1.1.md"`, `"TTPs/T1071.001.md"`, `"Cases/FAN-2026-001.md"`

Self-test: `python3 lib/obsidian_bridge.py`

---

### `lib/knowledge_extractor.py` — high-level recording

Wraps `obsidian_bridge` with typed record functions. Each call also pushes to OpenCTI via `mcp/opencti_server.py`.

```python
from lib.knowledge_extractor import (
    open_case,           # open_case(case_id, description, severity="medium") → None
                         # Creates Cases/<case_id>.md with status: open
    close_case,          # close_case(case_id, summary) → None
                         # Updates Cases/<case_id>.md with status: closed and summary
    record_ioc,          # record_ioc(ioc_type, value, context, case_id, severity="medium") → None
                         # Creates or updates IOCs/<defanged_value>.md
                         # Defangs value before writing; pushes to OpenCTI
    record_ttp,          # record_ttp(mitre_id, name, context, case_id) → None
                         # Creates or updates TTPs/<mitre_id>.md
    record_threat_actor, # record_threat_actor(name, context, case_id) → None
                         # Creates or updates ThreatActors/<name>.md
    record_malware,      # record_malware(family, context, case_id) → None
                         # Creates or updates Malware/<family>.md
    record_risk,         # record_risk(asset, description, case_id, severity="medium") → None
                         # Creates or updates Risks/<case_id>_<asset>.md
    record_concept,      # record_concept(name, definition, case_id=None) → None
                         # Creates or updates Concepts/<name>.md
)
```

`ioc_type` values: `"ip"`, `"domain"`, `"url"`, `"hash_md5"`, `"hash_sha256"`, `"email"`, `"filename"`

`severity` values: `"low"`, `"medium"`, `"high"`, `"critical"`

All `record_*` functions are idempotent. If a note already exists, they update the `case_refs` list and the context field without overwriting other fields.

Self-test: `python3 lib/knowledge_extractor.py --test`

---

### `lib/vault_query.py` — read-path queries

```python
from lib.vault_query import (
    get_context_for_ioc,    # get_context_for_ioc(value) → dict | None
                             # Looks up a defanged IOC value; returns the note as a dict
    get_context_for_ttp,    # get_context_for_ttp(mitre_id) → dict | None
                             # Looks up a MITRE ATT&CK ID (e.g. "T1071.001")
    get_active_cases,       # get_active_cases() → list[dict]
                             # Returns all cases with status: open
    get_top_risks,          # get_top_risks(limit=5) → list[dict]
                             # Returns top-severity risk notes, sorted by severity
    get_related_notes,      # get_related_notes(note_path) → list[str]
                             # Returns vault paths of notes that link to note_path
    search_context,         # search_context(query) → list[dict]
                             # Full-text search; returns matching notes as dicts
)
```

Self-test: `python3 lib/vault_query.py --search powershell`

---

### `lib/perplexity_client.py` — live threat intelligence

```python
from lib.perplexity_client import (
    lookup_ioc,     # lookup_ioc(value) → dict
                    # Searches Perplexity for threat intelligence on an indicator
    lookup_malware, # lookup_malware(family) → dict
    lookup_ttp,     # lookup_ttp(mitre_id) → dict
    lookup_cve,     # lookup_cve(cve_id) → dict
    lookup_actor,   # lookup_actor(name) → dict
    lookup_tool,    # lookup_tool(name) → dict
    search,         # search(query) → dict
                    # Free-text search
)
```

Requires `PERPLEXITY_API_KEY` in environment. Never pass raw IPs, hostnames, or usernames from live cases — use defanged values only.

---

### `lib/md_to_pdf.py` — PDF generation

Converts Markdown to a styled PDF using WeasyPrint. The PDF includes a styled cover page, running header stripe, and "Page X of Y" pagination. Requires WeasyPrint system libraries (Cairo, Pango, fonts-liberation).

```python
from lib.md_to_pdf import convert

convert(
    md_path="/path/to/report.md",
    pdf_path="/path/to/output.pdf",
    title="Incident report — FAN-2026-001",   # cover page title (optional)
    classification="CONFIDENTIAL",             # footer text (optional)
)
```

---

### `lib/chat_recorder.py` — session transcript (chain of evidence)

Records the Claude Code coordination session that drove the investigation as a
chain-of-evidence document set. It is the analytical counterpart to the
incident report: where the report states the findings, the transcript shows how
they were reached (questions asked, pivots taken, tools invoked, and their
outputs). Runs automatically at the end of every FAN/FAME/FAST pipeline; also
invokable via `/record-chat`.

The active session transcript is auto-detected from
`~/.claude/projects/<encoded-project-dir>/` (resolution order: `--transcript` →
`CLAUDE_TRANSCRIPT_PATH` → `CLAUDE_SESSION_ID` → most-recently-modified
`.jsonl`). The rendering is **complete and verbatim — tool outputs are never
truncated**. The raw `.jsonl` is preserved verbatim and its SHA-256 is recorded
in the MD/PDF, so the rendering always ties back to the original bytes.

```python
from lib.chat_recorder import record_chat

paths = record_chat(
    case_id="FAME-2026-001",
    output_dir="./reports",   # default; path_guard-enforced
    md_only=False,            # set True to skip the PDF
    upload=False,             # True → SSH/SCP to the investigations vault
)
# paths: {"md": Path, "pdf": Path, "jsonl": Path}
```

Outputs: `./reports/<case_id>_chat_transcript.{md,pdf,jsonl}`. The step never
fails an investigation — the analyze scripts treat any recording or upload error
as a warning and continue.

---

### `lib/investigations_upload.py` — report filing via SSH/SCP

Uploads finished report files to the investigations vault on ubuntudesktop. Reads SSH configuration from environment variables; uses the private key at `~/.ssh/id_ed25519` (path hardcoded in `_SSH_OPTS`).

```python
from lib.investigations_upload import upload

upload(
    case_id="FAN-2026-001",
    md_path=Path("/path/to/report.md"),
    pdf_path=Path("/path/to/report.pdf"),     # optional
    pptx_path=Path("/path/to/briefing.pptx"), # optional
    docx_path=Path("/path/to/report.docx"),   # optional
    zip_path=Path("/path/to/artifacts.zip"),  # optional
)
# Copies files to $INVESTIGATIONS_ROOT/<case_id>/reports/ on ubuntudesktop
```

Environment variables:
- `INVESTIGATIONS_SSH_HOST`: SSH target (default: `sansforensics@ubuntudesktop`)
- `INVESTIGATIONS_ROOT`: remote root path (default: `/home/sansforensics/cases`)

`_SSH_OPTS` in `investigations_upload.py` references `~richard/.ssh/id_ed25519` and `~richard/.ssh/known_hosts` by name. On deployments running as a different user, edit those two lines in the library before running any investigation.

---

### `lib/pcap_analyzer.py` — core PCAP interface

The central PCAP parser. All 22 FAN detection modules instantiate one `PcapAnalyzer` and work from its DataFrames rather than re-parsing the PCAP independently. This is why tshark runs once per investigation, not 22 times.

```python
from lib.pcap_analyzer import PcapAnalyzer

pa = PcapAnalyzer(pcap_path="/path/to/capture.pcap")
pa.load()                    # parse with tshark; build internal DataFrames
flows = pa.get_flows()       # → pd.DataFrame (src_ip, dst_ip, protocol, bytes, packets, …)
dns   = pa.get_dns_records() # → pd.DataFrame (query, response, qtype, rcode, …)
http  = pa.get_http_flows()  # → pd.DataFrame (method, uri, status, ua, host, …)
tls   = pa.get_tls_flows()   # → pd.DataFrame (sni, ja3, ja4, version, cipher, …)
```

---

### `lib/case_manager.py` — case lifecycle management

Manages the local case directory structure under `./cases/<case_id>/`. Tracks case metadata (creation time, status, PCAPsanalyzed, report versions) in `case.json`. Used by pipeline scripts to initialize and archive cases locally, separate from the remote investigations vault.

```python
from lib.case_manager import CaseManager, generate_case_id

cm = CaseManager()                                   # uses default ./cases/ directory
cd = cm.init_case("CASE-2025-001", "Suspected C2")   # creates ./cases/CASE-2025-001/
cm.add_pcap("CASE-2025-001", "~/evidence/capture.pcap")
v  = cm.next_report_version("CASE-2025-001", "capture")  # → int, auto-incremented
zp = cm.archive_case("CASE-2025-001")                # creates timestamped ZIP in ./cases/
cm.remove_case("CASE-2025-001")                      # deletes the case directory

# Auto-generate a case ID from the current UTC timestamp
case_id = generate_case_id()   # → "CASE-20260501-142235"
```

Case directory structure created by `init_case`:

```
./cases/<case_id>/
  case.json           metadata (created, status, pcaps, versions)
  analysis/           per-module analysis outputs
  reports/            generated Markdown + PDF reports
  exports/            miscellaneous exported artifacts
```

---

### `lib/fame_memprocfs.py` — MemProcFS integration

Handles MemProcFS initialization and physical memory artifact extraction for the FAME pipeline. Also documents the Rekall abandonment status.

```python
from lib.fame_memprocfs import run_memprocfs, REKALL_STATUS

results = run_memprocfs(
    image_path="/path/to/image.memory",
    outdir=Path("analysis/memory/memprocfs")
)
# results is a dict with keys:
#   dtb                 CR3 / Directory Table Base value (int or None)
#   bits                address width: 32 or 64
#   physical_banners    list of banner strings found in physical memory
#   attack_artifacts    list of suspicious strings/patterns found
#   memprocfs_version   MemProcFS version string (if initialized)
#   error               error message (str or None)

# REKALL_STATUS contains the documented abandonment record:
print(REKALL_STATUS["status"])   # → "ABANDONED"
print(REKALL_STATUS["successor"]) # → "Volatility 3 — provides equivalent and extended coverage"
```

`run_memprocfs` never raises on failure — it returns a result dict with `error` set. The FAME pipeline checks `error` and logs it before continuing.

**DTB extraction for VirtualBox ELF core dumps:** `extract_vbox_dtb()` parses the ELF PT_NOTE segment, locates the VBCPU note (type 2817) containing the CPUMCTX CPU state, and scans for page-aligned physical addresses in the typical CR3 range (0x1000–0xFFFFFFF0). The extracted CR3 is passed to MemProcFS as the `--dtb` argument.

---

### `lib/generate_presentation.py` — FAN PowerPoint generator

Produces the 7-slide management PowerPoint briefing for FAN investigations. Reuses `load_all_data()` and `_overall_severity()` from `generate_pcap_report.py` — there is no duplication of data-loading logic between the report and the presentation.

```python
from lib.generate_presentation import build_presentation

pptx_path = build_presentation(
    stem="capture",
    case_id="FAN-2026-001",
    output_dir=Path("./analysis/_reports/capture/"),
    base_dir=Path("./analysis/"),
    report_version=1,
)
```

Also accessible via shell wrapper: `scripts/generate_pcap_presentation.sh --stem <stem> --case-id <id>`.

---

### `lib/generate_fame_report.py` — FAME report generator

Assembles FAME analysis outputs from `./analysis/memory/` into Markdown + PDF + PPTX (8 slides) + DOCX.

---

### `lib/generate_fast_report.py` — FAST report generator

Assembles FAST analysis outputs from `./analysis/storage/` and `./exports/` into Markdown + PDF + PPTX (8 slides) + DOCX.

---

### `lib/generate_combined_report.py` — cross-module unified report

Merges FAN + FAME + FAST reports for the same case ID into a single Markdown + PDF + PPTX + DOCX. Triggered automatically when `fame_analyze.sh` or `fast_analyze.sh` detects that reports from other modules exist for the same case ID.

---

### `lib/generate_pptx_report.py` — management PowerPoint generator

Lower-level PowerPoint generation used by `generate_fame_report.py` and `generate_fast_report.py`. Produces the 8-slide CISO briefing (cover, executive summary, threat landscape, IDS/YARA alerts, IOCs, recommendations, artifact timeline, module coverage). Separate from `generate_presentation.py`, which is used by the FAN pipeline and shares data-loading logic with `generate_pcap_report.py`.

---

### `lib/generate_technical_reference_doc.py` — Word document generator

Generates a Microsoft Word `.docx` version of the technical operations manual. Output is written to court-submission standard: every claim scoped to its evidence source, every tool cited with its version path and invocation.

```bash
python3 lib/generate_technical_reference_doc.py \
    --output docs/FanGetFameFast_Technical_Operations_Manual.docx \
    --author "Richard de Vries" \
    --classification "CONFIDENTIAL"
```

---

### `lib/case_packager.py` — artifact ZIP and upload

Packages all artifacts for a completed FAN investigation into a timestamped ZIP and uploads to the investigations vault.

```python
from lib.case_packager import package, upload_zip

zip_path = package(
    case_id="FAN-2026-001",
    stem="capture",
    reports_dir=Path("./analysis/_reports/capture/"),
    analysis_dir=Path("./analysis/"),   # optional; includes all per-module outputs for stem
    output_dir=Path("./analysis/_reports/capture/"),
)
# ZIP name: FAN-2026-001_20260501-142235.zip

upload_zip(case_id="FAN-2026-001", zip_path=zip_path)
# Uploads via SSH/SCP to $INVESTIGATIONS_ROOT/FAN-2026-001/
```

Also accessible via shell wrapper: `scripts/bundle_artifacts.sh --stem <stem> --case-id <id> --reports-dir <path> --base-dir <path> --output-dir <path>`

---

### `lib/research_notes.py` — investigative audit trail (trust subsystem)

The audit-trail engine. Claude calls it via Bash at every step of every FAME / FAST / FAN investigation to produce a timestamped, numbered, step-by-step log at `./reports/<case_id>_research_notes.md`. This is the artifact that makes any finding traceable back to the exact tool execution that produced it. See [Section 11.1](#111-audit-trail--researchnotespy) for the full role.

Six subcommands (CLI; all take `--case-id`):

```bash
# Create the notes file with a case header (once, before any plugin runs)
python3 lib/research_notes.py init   --case-id <id> --module fame|fast|fan \
    [--evidence <path>] [--hostname <name>]

# Append one timestamped step after reading a tool's output (RN-NNN)
python3 lib/research_notes.py step   --case-id <id> \
    --title "Process List (windows.pslist)" \
    --action "vol -f image.mem windows.pslist → <id>_evidence/memory/pslist.txt" \
    --why "Forensic rationale for this step" \
    --outcome "Findings … [source: <id>_evidence/memory/pslist.txt]" \
    [--dismissed "What was inspected and judged not significant, and why"] \
    [--assumption]            # prefixes the outcome with [ASSUMPTION] for the report generator
    [--raw "key excerpt"] [--raw-file <path>]   # --raw-file wins; avoids shell arg-size limits

# Log a confirmed attacker action observed in the evidence (EVT-NNN)
python3 lib/research_notes.py event  --case-id <id> \
    --description "What the attacker did" --severity critical|high|medium|low|info \
    --module FAN|FAME|FAST [--timestamp "YYYY-MM-DD HH:MM:SS UTC"] \
    [--source "IP/PID/path"] [--detail "context"] [--no-timestamp]

# Log a structured mid-investigation reflection (RF-NNN)
python3 lib/research_notes.py reflect --case-id <id> --trigger "post-netscan review" \
    [--reinterpret "how new findings change earlier steps"] [--open-leads "what needs follow-up"]

# Record a standalone analytical assumption
python3 lib/research_notes.py assumption --case-id <id> --text "The assumption statement"

# Replace the summary placeholder with a closing paragraph (once, before upload)
python3 lib/research_notes.py finalize --case-id <id> --summary "Closing summary"
```

Importable parsing API, used by the narrative, timeline, campaign, and vault writers:

```python
from lib.research_notes import parse_steps, parse_events, parse_reflections

parse_steps(case_id)        # → list[{id, step_num, timestamp, title, action, why, outcome, dismissed}]
parse_events(case_id)       # → list[{id, event_num, timestamp, severity, module, description, source_detail}]
parse_reflections(case_id)  # → list[{id, reflect_num, timestamp, trigger, reinterpret, open_leads}]
```

Step IDs are `RN-001`, `RN-002`, …; events `EVT-NNN`; reflections `RF-NNN` — each auto-incremented and stable for cross-referencing from report sections and vault records. Raw artifacts are preserved individually under `./reports/<case_id>_evidence/` with SHA-256 hashes. `./reports/` is in `.gitignore`; notes are never committed.

---

### `lib/vault_writer.py` — report → vault (confirmed-findings-only)

Parses a finished module report's Markdown tables and writes the **analyst-reviewed** findings to the Obsidian vault via `knowledge_extractor`. The report Markdown — not raw tool output — is the authoritative source, so only findings that survived analyst review are recorded. This is the anti-fabrication boundary described in [Section 11.2](#112-anti-hallucination--ir-accuracy).

```bash
python3 lib/vault_writer.py --module fame|fast|fan \
    [--case-id <id> | --report <path>] [--reports-dir ./reports]
```

Main functions: `write_fame_to_vault()`, `write_fast_to_vault()`, `write_fan_to_vault()`. Helpers parse the management summary, the MITRE ATT&CK table (→ `record_ttp`), the IOC table (→ `record_ioc`), and recommendations (→ `record_risk`). Rows marked *"not confirmed"* or `Informational` are skipped. Every vault entry is written with a source attribution (`source: FAME report`, `… RN-NNN`). `_refang()` reverses defanging so `knowledge_extractor` can re-defang consistently before storage. On first use it calls `init_vault()` to bootstrap the folder tree.

---

### `lib/narrative_generator.py` — report → narrative sections

Derives the narrative prose sections (`attack_timeline`, `section_processes`, `section_network`, `section_malware`, the `pptx_*` blocks) from the existing module report plus the research notes. Pure text extraction and reformatting — no API calls. Output: `./reports/<case_id>_narrative.md`, consumed by the report and board-deck generators.

```bash
python3 lib/narrative_generator.py --case-id <id> [--reports-dir ./reports]
```

---

### `lib/correlate_findings.py` — cross-module correlation engine

Computes the actual FAN↔FAME, FAME↔FAST, and FAN↔FAST matches from the raw artifact files (netscan / pslist / cmdline for FAME; `fls_output` and carved URLs/domains for FAST; the per-protocol threat JSON for FAN). Must run **after** the modules complete but **before** `./analysis/` is cleaned up. Assigns confidence by the number of independent corroborating matches (3+ High, 2 Medium, 1 "verify manually").

```bash
python3 lib/correlate_findings.py --case-id <id> [--hostname <host>] \
    [--reports-dir ./reports] [--analysis-dir ./analysis]
# or:  from lib.correlate_findings import correlate; correlate(case_id="...", hostname="...")
```

Output: `./reports/<case_id>_correlation.md` (narrative) + `<case_id>_correlation.json` (machine-readable). `generate_combined_report.py` embeds the `.md` in Section 2 automatically when present. Exposed to Claude via the `/correlate` skill.

---

### `lib/generate_timeline.py` — swimlane attack/defender timelines

Renders vertical swimlane timelines (paginated PNG + interactive HTML) from the research-notes events and steps: an attacker view (timestamped `EVT-NNN`), a defender view (analyst `RN-NNN`), and a combined key-events view. Severity drives colour and font size; events without a confirmed timestamp are excluded from the visual timeline (they still appear in the untimed-findings section). PNGs paginate at 12 events per page so text never overlaps. Invoked by the narrative and campaign generators. PNG output requires `matplotlib` (optional); interactive HTML requires `plotly` (in `requirements.txt`); both degrade gracefully to a placeholder when absent.

---

### `lib/generate_batch_report.py` — batch aggregate report

Aggregates the per-case reports produced by `batch_analyze.sh` / `batch_agentic.sh` into a single batch investigation report (MD + PDF + PPTX + DOCX), surfacing cross-host patterns.

```bash
python3 lib/generate_batch_report.py --batch-id BATCH-20260528 \
    --manifest ./batch_work/BATCH-*/manifest.json \
    [--reports-dir ./reports] [--output-dir ./reports] [--no-upload]
# or:  from lib.generate_batch_report import generate; generate(batch_id="...", manifest_path=Path("..."))
```

Reads the batch `manifest.json` (per-case status + errors) and discovers each case's report. Output: `./reports/BATCH_<id>_batch_report.*`.

---

### `lib/generate_campaign_report.py` — unified campaign report

Reads every `<case_id>_narrative.md` + `<case_id>_research_notes.md` in a batch folder and produces a unified cross-case campaign report (`CAMPAIGN_<id>_report.md` + `.pdf` + `_board_deck.pptx` + `_timeline.png`). Detects per-case severity by keyword scan (rootkit, mimikatz, ransomware, C2, …). Generated at the end of an agentic batch and by the `investigate-all` skill.

```bash
python3 lib/generate_campaign_report.py --campaign-id SHIELDBASE-2026 \
    [--title "Operation ShieldBase"] [--reports-dir ./reports] [--output-dir ./reports]
```

---

### `lib/init_vault.py` — vault bootstrap

Creates the `vault/` folder tree (`TTPs/`, `IOCs/`, `ThreatActors/`, `Malware/`, `Concepts/`, `Risks/`, `Cases/`, `Templates/`) and `Dashboard.md` with its AUTO section markers. Idempotent — existing notes are never overwritten. Called automatically the first time `vault_writer` runs.

```bash
python3 lib/init_vault.py [--vault /path/to/vault]    # default: ./vault/
```

---

## 7. MCP server API

All servers implement JSON-RPC 2.0 over stdio (MCP protocol v2024-11-05). They are registered in `.claude/settings.json` and started automatically by Claude Code when it opens the project. Each server runs as a subprocess; failures are isolated and do not affect the other servers.

### `mcp/evidence_server.py` — read-only evidence access

Root: `$EVIDENCE_ROOT` (default: `~/evidence`)

All paths are validated to stay within `EVIDENCE_ROOT` by `_safe_path()` (`evidence_server.py:119`), which resolves the request to an absolute path and rejects it with `ValueError` if it does not start with the resolved root — defeating `../` traversal. Write operations are not "denied" but **unimplemented**: the server defines only the four read-only tools below, with no write handlers at all. This is an *architectural* guardrail, not a prompt instruction — see [Section 11.3](#113-architectural-guardrails).

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `evidence_list_directory` | `path: str` | `list[FileInfo]` | Lists files and directories under the given path |
| `evidence_read_file` | `path: str` | `str` (base64 for binary) | Reads a file; binary files are base64-encoded |
| `evidence_get_file_info` | `path: str` | `FileInfo` | Returns metadata: name, size, mtime, type |
| `evidence_find_pcaps` | *(none)* | `list[str]` | Returns paths to all `.pcap` and `.pcapng` files under `EVIDENCE_ROOT` |

`FileInfo` fields: `name`, `path`, `size` (bytes), `modified` (ISO 8601), `type` (`file` or `directory`)

---

### `mcp/investigations_server.py` — read-write investigations vault

Root: `$INVESTIGATIONS_ROOT` (default: `~/cases`)

Read **and** write, but every operation — read, write, mkdir, delete — first passes through the same `_safe_path()` jail (`investigations_server.py:145`); a path that escapes the root raises `ValueError` before any filesystem call. Writes are therefore confined to the case vault by construction.

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `investigations_list_directory` | `path: str` | `list[FileInfo]` | Lists contents of a case directory |
| `investigations_read_file` | `path: str` | `str` | Reads a report or artifact file |
| `investigations_write_file` | `path: str`, `content: str` | `WriteResult` | Writes a file; creates parent directories as needed |
| `investigations_create_directory` | `path: str` | `CreateResult` | Creates a directory and all parents |
| `investigations_delete` | `path: str` | `DeleteResult` | Deletes a file or directory (recursive for directories) |
| `investigations_get_file_info` | `path: str` | `FileInfo` | Returns file metadata |
| `investigations_list_cases` | *(none)* | `list[CaseSummary]` | Lists all case directories with summary metadata |

`investigations_list_cases` returns all direct subdirectories of `INVESTIGATIONS_ROOT`. Each `CaseSummary` includes: `id`, `created` (ISO 8601), `modified` (ISO 8601), `report_count` (number of files in `reports/` subdirectory).

`WriteResult` fields: `path`, `bytes_written`
`DeleteResult` fields: `path`, `deleted` (bool)

---

### `mcp/opencti_server.py` — OpenCTI CTI integration

Credentials: `OPENCTI_URL` and `OPENCTI_API_KEY` from shell environment.

| Tool | Parameters | Returns | Description |
|------|-----------|---------|-------------|
| `opencti_search_stix` | `query: str`, `entity_type: str?`, `limit: int?` | `list[StixEntity]` | Searches any STIX entity type (malware, threat-actor, campaign, vulnerability, …) |
| `opencti_search_ioc` | `value: str`, `pattern_type: str?`, `limit: int?` | `list[IndicatorResult]` | Searches indicators by value, pattern type, or keyword |
| `opencti_create_indicator` | `name: str`, `pattern: str`, `pattern_type: str`, `description: str?`, `score: int?` | `CreateResult` | Creates a new indicator in OpenCTI |

`pattern_type` values: `"stix"` (e.g. `[ipv4-addr:value = '1.2.3.4']`), `"yara"`, `"sigma"`

`score` range 0–100 maps to:

| Score | Label |
|-------|-------|
| ≥ 75 | CONFIRMED_MALICIOUS |
| 40–74 | SUSPICIOUS |
| < 40 | INFORMATIONAL |

---

## 8. Obsidian vault schema

The vault at `./vault/` is a plain-Markdown knowledge graph. Every note is a `.md` file with YAML frontmatter. Note filenames are the human-readable identifiers — no separate ID system.

### Folder layout

```
vault/
  IOCs/           One note per indicator: 192[.]0[.]2[.]1.md, evil[.]com.md
  TTPs/           One note per MITRE ATT&CK (sub)technique: T1071.001.md
  ThreatActors/   Threat group profiles: APT29.md
  Malware/        Malware family profiles: Cobalt_Strike.md
  Concepts/       Generic cybersecurity concepts
  Risks/          Risk assessments per case/asset
  Cases/          Post-investigation summaries: FAN-2026-001.md
  Templates/      Note schemas — do not modify manually
  Dashboard.md    Auto-maintained index (recent cases, active IOCs, top risks)
```

### Frontmatter conventions

Every note has YAML frontmatter. The `record_*` functions in `knowledge_extractor.py` manage these fields automatically.

**IOC note** (`IOCs/<defanged-value>.md`):

```yaml
---
ioc_type: ip | domain | url | hash_md5 | hash_sha256 | email | filename
value: 192[.]0[.]2[.]1
severity: low | medium | high | critical
disposition: unknown | benign | suspicious | malicious
case_refs:
  - FAN-2026-001
first_seen: 2026-05-01T13:05:00Z
last_seen: 2026-05-01T13:05:00Z
---
```

**TTP note** (`TTPs/T1071.001.md`):

```yaml
---
mitre_id: T1071.001
technique_name: Application Layer Protocol - Web Protocols
tactic: command-and-control
severity: medium | high | critical
case_refs:
  - FAN-2026-001
first_seen: 2026-05-01T13:05:00Z
---
```

**Case note** (`Cases/FAN-2026-001.md`):

```yaml
---
case_id: FAN-2026-001
status: open | closed
severity: low | medium | high | critical
ttps_observed:
  - T1071.001
  - T1059.001
iocs_found:
  - 192[.]0[.]2[.]1
opened: 2026-05-01T12:00:00Z
closed: 2026-05-01T16:00:00Z   # absent if status is open
---
```

### IOC defanging rules

`record_ioc` applies these transformations before writing. The defanging is irreversible — do not store the live value anywhere else in the vault.

| Type | Input | Stored as |
|------|-------|-----------|
| IPv4 | `192.0.2.1` | `192[.]0[.]2[.]1` |
| Domain | `evil.com` | `evil[.]com` |
| URL | `https://evil.com/path` | `hxxps://evil[.]com/path` |
| Hash (MD5/SHA256) | `deadbeef...` | stored as-is (hashes are not network indicators) |
| Email | `attacker@evil.com` | `attacker[@]evil[.]com` |

---

## 9. Configuration reference

### Environment variables

All variables are set in `~/.soc_env` (template: `templates/set_env_template.sh`) and sourced from `~/.bashrc`.

| Variable | Required | Description |
|----------|----------|-------------|
| `PERPLEXITY_API_KEY` | Yes | Perplexity.ai API key — starts with `pplx-` |
| `OPENCTI_URL` | OpenCTI | OpenCTI instance base URL, e.g. `http://localhost:8080` |
| `OPENCTI_API_KEY` | OpenCTI | OpenCTI API token — from Settings → API access |
| `INVESTIGATIONS_SSH_HOST` | No | SSH target (default: `sansforensics@ubuntudesktop`) |
| `INVESTIGATIONS_ROOT` | No | Remote path for case output (default: `/home/sansforensics/cases`) |
| `EVIDENCE_ROOT` | No | Override local evidence root (default: `~/evidence`) |
| `PYTHONPATH` | AutoTimeliner | Must include Volatility 3 source path for AutoTimeliner to work |

### `.claude/settings.json` — MCP and permissions

Generated by `setup_folder_structure.sh`. Paths must be absolute.

```json
{
  "autoMemoryEnabled": true,
  "permissions": {
    "allow": [
      "Bash(./scripts/perplexity_search.sh*)",
      "Bash(./scripts/vault_context.sh*)",
      "Write(vault/**)",
      "Edit(vault/**)",
      "Bash(python3*knowledge_extractor*)"
    ]
  },
  "mcpServers": {
    "evidence": {
      "command": "python3",
      "args": ["/absolute/path/mcp/evidence_server.py"],
      "env": { "EVIDENCE_ROOT": "/home/analyst/evidence" }
    },
    "investigations": {
      "command": "python3",
      "args": ["/absolute/path/mcp/investigations_server.py"],
      "env": { "INVESTIGATIONS_ROOT": "/home/analyst/cases" }
    },
    "opencti": {
      "command": "python3",
      "args": ["/absolute/path/mcp/opencti_server.py"]
    }
  }
}
```

OpenCTI credentials are not stored here. They come from the shell environment.

### Key paths

| Path | Purpose | Writable by analyst? |
|------|---------|----------------------|
| `./analysis/` | WIP during investigation — auto-deleted on completion | No (WIP only) |
| `./vault/` | Obsidian knowledge graph | Via `record_*` functions only |
| `./rules/suricata/` | Suricata rule files | Yes — add `.rules` files; `local.rules` is for custom rules |
| `./rules/yara/` | YARA rule files | Yes — drop `.yar` files here; compiled at scan time |
| `./exports/` | Artifact extraction output for FAST investigations | Via pipeline scripts |
| `./reports/` | Manual report exports | Yes |
| `~/evidence/` | PCAP and evidence drop zone | No — read-only by tools |
| `~/cases/` | Finalized investigation reports | Via MCP server and SSH/SCP only |
| `~/.soc_env` | API credentials | Yes — never commit to version control |
| `~/.ssh/id_ed25519` | SSH key for SCP uploads | Set by analyst during setup |

---

## 10. Dependency map

```
analyze_pcap.sh  (FAN)
  ├── fan_*.sh (×22)
  │     └── lib/fan_*.py
  │           └── lib/pcap_analyzer.py     (tshark — PCAP parsing)
  ├── lib/fan_ip_lookup.py
  │     ├── lib/vault_query.py
  │     │     └── lib/obsidian_bridge.py   (./vault/ read/write)
  │     └── lib/perplexity_client.py       (PERPLEXITY_API_KEY)
  ├── lib/generate_pcap_report.py
  │     ├── lib/md_to_pdf.py               (WeasyPrint / Cairo / Pango)
  │     └── lib/generate_pptx_report.py    (python-pptx)
  ├── lib/generate_presentation.py         (python-pptx — FAN 7-slide PPTX)
  ├── lib/case_packager.py                 (ZIP + SSH/SCP upload)
  │     └── lib/investigations_upload.py   (~/.ssh/id_ed25519)
  └── lib/knowledge_extractor.py
        ├── lib/obsidian_bridge.py
        └── mcp/opencti_server.py          (OPENCTI_URL, OPENCTI_API_KEY)

fame_analyze.sh  (FAME)
  ├── vol.py (Volatility 3)                (MEMORY_IMAGE — all plugins)
  ├── yara                                 (rules/yara/*.yar)
  ├── mactime                              (bodyfile → MACB timeline)
  ├── baseline.py (Memory Baseliner)       (baselines/baseline.json)
  ├── lib/fame_memprocfs.py                (memprocfs Python package — optional)
  ├── /opt/autotimeliner/autotimeliner.py  (PYTHONPATH → vol3 — optional)
  ├── /opt/EVTXtract/evtxtract.py          (optional)
  ├── lib/generate_fame_report.py
  │     ├── lib/md_to_pdf.py
  │     ├── lib/generate_pptx_report.py
  │     └── lib/generate_combined_report.py  (if FAN/FAST reports found)
  └── lib/investigations_upload.py

fast_analyze.sh  (FAST)
  ├── ewfmount / ewfinfo / ewfverify        (E01/EWF image handling)
  ├── mmls / fsstat / fls / ils / icat      (The Sleuth Kit — filesystem analysis)
  ├── mactime                               (bodyfile → MACB timeline)
  ├── bulk_extractor                        (file carving, images up to 20 GB)
  ├── autopsy --nogui                       (headless ingest — optional)
  ├── lib/generate_fast_report.py
  │     ├── lib/md_to_pdf.py
  │     ├── lib/generate_pptx_report.py
  │     └── lib/generate_combined_report.py  (if FAN/FAME reports found)
  └── lib/investigations_upload.py
```

### System binary dependencies

| Binary | Package | Used by |
|--------|---------|---------|
| `tshark` | `tshark` (apt) | `pcap_analyzer.py` — all FAN protocol parsing |
| `suricata` | PPA: oisf/suricata-stable | `fan_suricata.py` |
| `yara` | `yara` (apt) or compiled | `fan_yara_pcap.py`, `yara_sweep.sh`, `fame_analyze.sh` |
| `dotnet` | Microsoft APT | EZ Tools (FAST module prerequisite) |
| `ewfmount` / `ewfinfo` / `ewfverify` | `ewf-tools` / `libewf-dev` | `fast_analyze.sh` — E01/EWF image handling |
| `fls` / `fsstat` / `mmls` / `ils` / `icat` | `sleuthkit` | `fast_analyze.sh` — filesystem analysis |
| `mactime` | `sleuthkit` | `fast_analyze.sh`, `fame_analyze.sh` — bodyfile to timeline |
| `bulk_extractor` | `bulk-extractor` (apt) | `fast_analyze.sh` — file carving |
| `autopsy` | manual install | `fast_analyze.sh` — headless ingest (optional; requires 4.17+) |
| `vol.py` (Volatility 3) | pip or git clone | `fame_analyze.sh` — memory analysis |
| `autotimeliner.py` | git clone `/opt/autotimeliner/` | `fame_analyze.sh` — super-timeline (optional) |
| `evtxtract.py` | git clone `/opt/EVTXtract/` | `fame_analyze.sh` — EVTX recovery (optional) |
| `python3` | system | all Python modules |
| `ssh` / `scp` | openssh-client | `investigations_upload.py` — report upload |

### Python package purposes

| Package | Purpose |
|---------|---------|
| `weasyprint` + `cairocffi` | PDF generation (requires Cairo + Pango system libraries) |
| `python-pptx` | PowerPoint output (PPTX) |
| `python-docx` | Word document output (DOCX) |
| `Markdown` | Markdown to HTML (pre-PDF step) |
| `PyYAML` | YAML frontmatter parsing, configuration files |
| `plotly` | Interactive HTML timeline visualisation |
| `volatility3` + `yara-python` | Memory forensics (FAME) and YARA scanning |
| `sslyze` | TLS / certificate inspection (FAN) |
| `memprocfs` | MemProcFS physical memory access via LeechCore (FAME optional stage) |

---

## 11. Trust & reliability subsystem

This is the subsystem the *FIND EVIL!* judging criteria target directly: autonomous execution
quality (failure handling + self-correction), IR accuracy (confirmed vs. inferred, hallucinations
flagged), constraint implementation (architectural guardrails), and audit-trail quality. Every
mechanism below is enforced in code; none of it is prompt-only. The companion diagrams are
[Architecture §3–§7](ARCHITECTURE_DIAGRAM.md#3-trust--reliability-layer).

### 11.1 Audit trail — `research_notes.py`

The audit trail makes any finding traceable to the tool execution that produced it. Its API is in
[Section 6](#libresearchnotespy--investigative-audit-trail-trust-subsystem); here is how it is wired
into the investigation.

**Enforcement.** The FAME / FAST / FAN skills carry a **MANDATORY RULE**: *"Do NOT proceed to the
next analysis step until the current step has been documented via `research_notes.py step`."*
Running a plugin and immediately launching the next without logging is not permitted. The agent
reads the output, interprets it, calls `step`, and only then advances. Because the step counter is
derived from the file (`_step_count()`), the numbering is gap-free and tamper-evident.

**Four record types, each timestamped (UTC) and ID-stamped:**

| Type | ID | Captures | Used for |
|------|----|----------|----------|
| Step | `RN-NNN` | action · why · outcome · optional `dismissed` · optional raw excerpt | The investigative workflow, one entry per tool run |
| Event | `EVT-NNN` | timestamped attacker action · severity · observing module · source artifact | The attack timeline |
| Reflect | `RF-NNN` | trigger · re-interpretations of earlier steps · open leads | Mid-investigation re-assessment (self-correction of conclusions) |
| Assumption | — | a standalone working hypothesis | Surfacing unproven premises |

**The traceability chain** (diagram: [Architecture §4](ARCHITECTURE_DIAGRAM.md#4-audit-trail-traceability-chain)):

```
tool execution → preserved artifact (<case>_evidence/…  + SHA-256)
              → research note RN-NNN  ("[source: <artifact>]" in the outcome)
              → report section (cites RN-NNN)
              → vault record (record_ttp(... "source: FAME report, RN-NNN"))
```

A reviewer can pick any vault IOC/TTP, read its `source: … RN-NNN` attribution, open the matching
research note, follow the `[source: …]` tag to the preserved artifact, and re-run the command in the
`Action` field. The chain is bidirectional and complete. Raw artifacts are preserved per-step under
`./reports/<case_id>_evidence/` with SHA-256 hashes; `./reports/` is git-ignored so notes and
evidence are never committed.

### 11.2 Anti-hallucination & IR accuracy

The platform's stance: a claim is reported at its true epistemic status — confirmed, inferred, or
unknown — and a value is never invented to fill a gap.

| Control | Mechanism | Enforcement point |
|---------|-----------|-------------------|
| **Confirmed vs. inferred** | `--assumption` prefixes the outcome with `[ASSUMPTION]`; the report generator collects these into the §17 *Assumptions* list | `research_notes.py:294`, `generate_fame_report.py` §17 builder |
| **Unconfirmed timestamps** | `event --no-timestamp` marks the finding `— (unconfirmed)` and **excludes it from the visual timeline** while keeping it in the untimed-findings section | `research_notes.py:379–402`, `parse_events()` |
| **False-positive discipline** | `step --dismissed` records what was inspected and deliberately *not* flagged, and why (e.g. "malfind hits are clr.dll JIT regions — confirmed .NET FPs") | `research_notes.py:295` |
| **Confidence scoring** | `_score_overall_confidence()` returns `(HIGH\|MEDIUM\|LOW, reasoning)`; the reasoning names the specific gap (YARA unavailable, baseline missing, DKOM active) | `generate_fame_report.py:310` |
| **Completeness & gaps** | `_build_confidence_gaps_section()` emits a §17 *Confidence & gaps* section: a completeness table (which steps ran vs. were skipped), data gaps, assumptions, the reflection log, and recommended follow-up | `generate_fame_report.py:382` |
| **Degrade, don't guess (DKOM)** | When `psscan` returns more processes than `pslist`, a rootkit is hiding processes; `_is_dkom_active()` flags it, marks `pslist` *not authoritative*, elevates `psscan`/`netscan`/`modscan`, and drops overall confidence to MEDIUM | `generate_fame_report.py:186, 195` |
| **Confirmed-only vault writes** | `vault_writer` records findings **only** from the analyst-reviewed report tables — never from raw tool output. Rows marked *"not confirmed"* or `Informational` are skipped | `vault_writer.py` `_parse_ioc_table()` |
| **Corroboration confidence** | `correlate_findings._confidence()` rates a cross-module finding by independent matches: 3+ High, 2 Medium, 1 "verify manually" | `correlate_findings.py` |
| **Vault → Perplexity → record-back** | The vault is queried before any external lookup; Perplexity fires only on a cache miss; only confirmed results are written back — preventing a web guess from becoming canonical | `CLAUDE.md` decision order; `fan_ip_lookup.py` |

### 11.3 Architectural guardrails

Security boundaries are enforced at the server and kernel level, where the agent cannot talk its way
past them — not in the prompt. Diagram: [Architecture §5](ARCHITECTURE_DIAGRAM.md#5-architectural-guardrails).

| Guardrail | What it stops | Enforcement point |
|-----------|---------------|-------------------|
| **MCP path jail** | Path traversal out of the evidence/cases root, including sibling-prefix escape (`evidence_exfil`) | `_safe_path()` resolves to absolute + `Path.is_relative_to(ROOT)` containment check (not a string prefix); `evidence_server.py:119`, `investigations_server.py:145` |
| **Read-only evidence server** | Any modification of evidence via MCP | `evidence_server.py` defines **no write handlers** — a write is unimplemented, not merely refused |
| **Library write-path policy** | Any library code (a buggy `--output-dir`, a refactor) writing a report/note into evidence, `/mnt`, `/media`, or outside the approved output folders | `lib/path_guard.py` — `assert_writable`/`guard_output_dir` hard-fail with `WritePolicyError`; wired into `obsidian_bridge`, `md_to_pdf`, every `generate_*` report generator, and `case_packager`. The `investigations` MCP server independently rejects writes under `/mnt`, `/media`, or `EVIDENCE_ROOT` (`investigations_server.py:_assert_writable`). Validate with `python3 lib/path_guard.py --test` |
| **Case ID validation** | An analyst/manifest `case_id` traversing out of the output/cases root (e.g. `../../tmp/x`) into `mkdir`/`rsync`/`zip`/`rmtree` | `validate_case_id()` in `lib/case_manager.py` (gates `case_dir`/`archive_case`/`remove_case`) and `fgff_validate_case_id` in `scripts/pathguard.sh` (called by all three analyze scripts) restrict it to `[A-Za-z0-9._-]{1,64}` |
| **Kernel read-only mount** | Pipeline bugs altering the original disk image | `mount -o ro,loop,norecovery` in `fast_analyze.sh`; mount verified read-only by `fgff_assert_ro_mount` (`scripts/pathguard.sh`) before analysis; Volatility 3 / YARA open the memory image read-only |
| **Prompt-injection path whitelist** | Adversarial evidence filenames — or crafted sub-directory names inside extracted archives — injecting instructions into `claude -p` | `batch_agentic.sh:186` — basename must match `[[:alnum:][:space:]._-]` **and** the full path must match `[[:alnum:][:space:]./_-]`; otherwise skipped and logged to the manifest |
| **Report renderer resource isolation** | Malicious evidence text in a report causing the PDF renderer to read local files (`file://`) or make outbound requests (SSRF) | `md_to_pdf.safe_url_fetcher` restricts WeasyPrint to inline `data:` URIs + an allowlist of web-font hosts; used by `md_to_pdf` and the `generate_pcap_report` PDF fallback |
| **SSH host-key verification** | A MITM substituting a host key on report/evidence uploads to the investigations vault | `StrictHostKeyChecking=accept-new` (trust-on-first-use, reject-on-change) in `lib/investigations_upload.py` and `lib/case_packager.py` |
| **IOC defanging** | Live indicators leaking to the vault or to Perplexity | defang before any vault write / external call; `fan_ip_lookup.py`, `vault_writer._refang()` round-trip |
| **No-daemon / explicit start** | Un-auditable automated evidence processing | every investigation begins with a deliberate analyst command — chain-of-custody requires it |

**Bypass-testing note for the panel:** the evidence server's read-only property is structural (no
write code path exists), and traversal is blocked by *path-relative containment* (`Path.is_relative_to`
on the `.resolve()`-canonicalized path) rather than a string-prefix comparison, so `../`, symlinks,
absolute-path arguments, and sibling directories that merely share the root as a name prefix all land
inside the jail or are rejected.

### 11.4 Failure handling & self-correction

The governing principle: **an optional stage never aborts the pipeline, and every skip or fallback
is logged so the gap is visible rather than hidden.** Diagram:
[Architecture §7](ARCHITECTURE_DIAGRAM.md#7-failure-handling--self-correction-map).

**Shell-level.** Orchestrators run `set -euo pipefail` for fail-fast on *critical* steps; *optional*
steps use `|| true` plus a logged warning. `analyze_pcap.sh`'s `run_step` wrapper aggregates
per-step pass/fail without halting and prints a summary.

**Python-level.** Integrations return structured error objects instead of raising, so the
coordinator observes the failure and continues: `fame_memprocfs.run_memprocfs()` returns a dict with
`error` set (never raises); `perplexity_client` returns `{... "error": "HTTP 401: …"}`;
`investigations_upload` catches `CalledProcessError` and prints a remediation tip.

**Self-correcting fallback chains:**

| Pipeline | Trigger | Fallback |
|----------|---------|----------|
| FAME | No ISF symbols for a Linux image | strings-based extraction (`strings` + grep for auth/syslog) |
| FAME | `pslist` empty / DKOM | switch to `psscan`-authoritative workflow, logged as a *Deviation* step |
| FAME | MemProcFS init fails | record error, continue with Volatility pathway |
| FAST | Filesystem mount fails | retry `norecovery` → fall back to TSK-only mode (`SKIP_MOUNT`) |
| FAST | `fls` fails | retry with explicit `-o <offset>` |
| FAST | Autopsy absent | write `AUTOPSY_NOT_RUN.txt`, continue |
| FAST | Image > 20 GB | skip `bulk_extractor`, note it |
| FAN | Suricata rule update fails | continue with existing rules |
| Shared | Vault miss | Perplexity lookup, then record back |
| Shared | Upload fails | reports retained in `./reports/`/`./analysis/`, re-runnable manually |
| Batch | A case fails | log to manifest, continue, retry failed cases at the end |

**Mandatory deviation logging.** Whenever the analysis leaves the standard path — a step skipped, a
fallback used, a plugin returning unexpected results — the skills require it to be recorded as its
own `step --title "Deviation: <what changed>"`. The deviation log is what lets a reviewer see *where*
and *why* the agent self-corrected, and challenge or reproduce that decision.

**Interrupted-run recovery.** `fast_analyze.sh` writes a `.fast_session.json` and, on an evidence
switch, uploads the previous case's artifacts before cleaning up. Batch runs record processed stems
and skip already-completed evidence, so an interrupted batch resumes without redoing work. A
non-empty `./analysis/` at pipeline start is itself a signal that the previous run was interrupted.

---

## 12. Batch & campaign orchestration

Scale-out for "how much case data can the agent handle". Diagram:
[Architecture §9](ARCHITECTURE_DIAGRAM.md#9-batch--campaign-scale-out).

| Script | Path taken per case | Produces |
|--------|---------------------|----------|
| `batch_analyze.sh` | Direct shell pipelines (`fame_analyze.sh` / `fast_analyze.sh`) — fast, non-agentic | Per-case reports + `manifest.json` + aggregate batch report |
| `batch_agentic.sh` | Claude agentic skills (`claude -p "/fame …"`) — produces research notes + interpreted findings + MITRE context, then a campaign report | Per-case reports + research notes + `CAMPAIGN_*` report |
| `batch_regenerate.sh` | Re-renders narratives / board decks / PDFs for cases already in `./reports/` | Regenerated artifacts (no re-analysis) |

```bash
./scripts/batch_analyze.sh  [evidence_dir] [--batch-id BATCH-2026-001] [--no-vault] [--no-upload]
./scripts/batch_agentic.sh  [evidence_dir] [--batch-id BATCH-2026-001] [--no-vault] [--no-upload]
./scripts/batch_regenerate.sh [--dry-run] [--only-pptx] [--case-id CASE-ID]
```

**Routing.** Files are routed by extension — FAME: `.mem .img .raw .lime .vmem .dmp`; FAST:
`.E01 .ewf .vmdk .vdi .qcow2 .vhd .vhdx`; FAN: `.pcap .pcapng .cap`. `.7z`/`.zip` archives are
extracted first. When both an archive and a pre-extracted image share a stem, the archive wins and
the duplicate is skipped. Default evidence directory: `/home/vscode/evidence`.

**Manifest.** `batch_work/<BATCH_ID>/manifest.json` records one entry per file
(`case_id, source_file, extracted_as, module, hostname, status`) plus an `errors` list, and is the
input to `generate_batch_report.py`.

**Skills.** `/investigate-all [evidence_dir]` runs the same batch in-session via `/fame` and `/fast`,
with a post-batch synthesis step (common IOCs/TTPs, outlier case, highest-severity leads, revised
campaign conclusion) before the unified report. `/correlate` runs `correlate_findings.py`.
`/archive-reports` moves a finished campaign folder from `./reports/` to `./archive/` (move only,
never delete; never overwrites an existing archive).

---

## 13. License and disclaimer

Fan Get Fame Fast is released under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full terms.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Integrators and contributors accept the terms of the Apache 2.0 License, including the disclaimer of warranty and limitation of liability in Sections 7 and 8.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman — June 2026 — v2.0*
