# FanGetFameFast — Technical reference

**Version:** 1.1 · May 2026  
**Platform:** Ubuntu 24.04 LTS (x86-64)  
**Classification:** Internal — SOC Operations

---

## Table of contents

1. [Architecture overview](#1-architecture-overview)
2. [FAN pipeline — data flow](#2-fan-pipeline--data-flow)
3. [Module inventory](#3-module-inventory)
4. [Python library API](#4-python-library-api)
5. [MCP server API](#5-mcp-server-api)
6. [Obsidian vault schema](#6-obsidian-vault-schema)
7. [Configuration reference](#7-configuration-reference)
8. [Dependency map](#8-dependency-map)
9. [License and disclaimer](#9-license-and-disclaimer)

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
│  TTPs · IOCs · ThreatActors       opencti_server.py   │
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

**No daemon.** Every investigation starts with an explicit analyst command. There is no file watcher or auto-trigger. Automated evidence processing without analyst approval is a liability in a forensic context.

**WIP isolation.** All temporary analysis output lands in `./analysis/` and is deleted when the investigation completes. The investigations vault (`~/cases/`) is the only persistent store for finished work.

**Vault-first lookups.** Before any external API call, the vault is queried. A Perplexity request fires only on a cache miss. This keeps sensitive case context off external infrastructure and speeds up repeated lookups on the same indicators.

**Idempotent recording.** `record_*` functions in `knowledge_extractor.py` update existing notes rather than creating duplicates. Multiple module passes against the same indicator converge on a single vault note.

---

## 2. FAN pipeline — data flow

```
Analyst
  │
  └── analyze_pcap.sh /path/to/capture.pcap [--case-id FAN-2026-001]
        │
        ├── [1] Input validation
        │     PCAP file exists · not in /mnt|/media|evidence/
        │
        ├── [2] Case initialisation
        │     Assign case ID · record in vault via open_case()
        │
        ├── [3] 22 detection modules (sequential)
        │     Each module: scripts/fan_<name>.sh → lib/fan_<name>.py
        │     Output: ./analysis/<module>/<pcap-stem>/{*.json,*.csv,*_report.md}
        │
        ├── [4] Suricata IDS scan
        │     rules/suricata/et-open.rules + rules/suricata/local.rules
        │     Output: ./analysis/suricata/<pcap-stem>/
        │
        ├── [5] YARA scan
        │     rules/yara/*.yar
        │     Output: ./analysis/yara_pcap/<pcap-stem>/
        │
        ├── [6] IP + FQDN extraction and enrichment
        │     Vault lookup → Perplexity (on cache miss)
        │     Output: ./analysis/cti/<pcap-stem>/
        │
        ├── [7] Report generation
        │     generate_pcap_report.sh → lib/generate_pcap_report.py
        │     Markdown + PDF via lib/md_to_pdf.py (WeasyPrint)
        │     Output: ./analysis/_reports/<pcap-stem>/
        │
        ├── [8] Upload to investigations vault
        │     lib/investigations_upload.py
        │     Destination: ~/cases/<case_id>/reports/<stem>_v<n>.{md,pdf}
        │
        ├── [9] Vault recording
        │     lib/knowledge_extractor.py: record_ioc, record_ttp, close_case
        │     Also pushes to OpenCTI via mcp/opencti_server.py
        │
        └── [10] WIP cleanup
              rm -rf ./analysis/<module>/<pcap-stem>/  (all modules)
              ./analysis/ is empty on completion
```

### Analysis directory structure (during investigation)

```
analysis/
  dns_threats/<pcap-stem>/
    dns_flows.csv
    dns_threats.json
    dns_threats_report.md
  http_threats/<pcap-stem>/
    ...
  <module>/<pcap-stem>/
    ...
  _reports/<pcap-stem>/
    <stem>_incident_report.md
    <stem>_incident_report.pdf
```

Everything under `analysis/` is deleted when step [10] completes.

---

## 3. Module inventory

### Detection modules (FAN)

Each module follows the same pattern:

- Shell wrapper: `scripts/fan_<name>.sh <pcap> [--case-id <id>]`
- Python library: `lib/fan_<name>.py`
- Entry point: `analyse(pcap_path, output_dir, case_id=None)`
- Outputs: `<name>_flows.csv`, `<name>_threats.json`, `<name>_threats_report.md`

| Module | Script | Library | Detection categories |
|--------|--------|---------|---------------------|
| ARP threats | `fan_arp_threats.sh` | `fan_arp_threats.py` | Cache poisoning, gratuitous ARP flood, ARP scan, proxy anomaly |
| Certificate inspector | `fan_cert_inspector.sh` | `fan_cert_inspector.py` | Self-signed, expired, short/long validity, wildcard, SNI mismatch, weak sig |
| DHCP threats | `fan_dhcp_threats.sh` | `fan_dhcp_threats.py` | Starvation, rogue server, spoofing, relay anomaly, message injection |
| DNS threats | `fan_dns_threats.sh` | `fan_dns_threats.py` | DGA, beaconing, exfiltration, fast flux, amplification, NXDomain flood, typosquatting, zone transfer |
| File hashes | `fan_file_hashes.sh` | `fan_file_hashes.py` | Extracts HTTP/SMB/TFTP/IMF/DICOM files; MD5+SHA256; Perplexity OSINT |
| HTTP/S threats | `fan_http_threats.sh` | `fan_http_threats.py` | Suspicious UA, unusual methods, scanning status codes, large upload, cookie/host anomaly, beaconing |
| ICMP threats | `fan_icmp_threats.sh` | `fan_icmp_threats.py` | Flood, Ping of Death, fragmentation, tunneling, Smurf, redirect, sweep, recon, exfiltration |
| IP/FQDN lookup | `fan_ip_lookup.sh` | `fan_ip_lookup.py` | FQDN/IP correlation, DNS resolution, OSINT enrichment |
| LLMNR threats | `fan_llmnr_threats.sh` | `fan_llmnr_threats.py` | Spoofing/poisoning, credential theft, SMB relay, reconnaissance |
| mDNS threats | `fan_mdns_threats.sh` | `fan_mdns_threats.py` | Amplification, information leakage, spoofing/cache poisoning, outside local segment |
| NBNS threats | `fan_nbns_threats.sh` | `fan_nbns_threats.py` | Spoofing/poisoning, credential theft, SMB relay, enumeration, WPAD poisoning |
| NetBIOS threats | `fan_netbios_threats.sh` | `fan_netbios_threats.py` | Poisoning, NTLM hash theft/relay, enumeration, null session, DDoS, malware propagation |
| NTP threats | `fan_ntp_threats.sh` | `fan_ntp_threats.py` | Amplification, flood, Kiss-of-Death, monlist abuse, time manipulation, recon |
| QUIC threats | `fan_quic_threats.sh` | `fan_quic_threats.py` | Amplification/DDoS, 0-RTT replay, version forgery, pre-handshake exhaustion |
| SNMP threats | `fan_snmp_threats.sh` | `fan_snmp_threats.py` | Default credentials, MitM, DoS flood, reconnaissance, malicious SET, large data transfer |
| SSDP/UPnP threats | `fan_ssdp_threats.sh` | `fan_ssdp_threats.py` | Amplification DDoS, device exposure, network manipulation, vulnerable UPnP |
| STUN threats | `fan_stun_threats.sh` | `fan_stun_threats.py` | Amplification DDoS, info leakage, firewall traversal, service abuse |
| Suricata IDS | `fan_suricata.sh` | `fan_suricata.py` | ET Open rules + local.rules |
| TCP threats | `fan_tcp_threats.sh` | `fan_tcp_threats.py` | SYN flood, port scan, RST flood, stealth scan, session hijacking, half-open flood |
| TLS inspector | `fan_tls_inspector.sh` | `fan_tls_inspector.py` | Suspicious JA4/JA3, weak cipher, deprecated TLS, non-standard port, cipher diversity scan |
| UDP threats | `fan_udp_threats.sh` | `fan_udp_threats.py` | Flood, reflection/amplification, port scan, fragmentation, IP spoofing |
| YARA PCAP scan | `fan_yara_pcap.sh` | `fan_yara_pcap.py` | PE, entropy, network, malware rules + community rules |

### FAME pipeline — memory forensics

Entry point: `scripts/fame_analyze.sh`

| Stage | Tool | Output |
|-------|------|--------|
| Volatility 3 plugins | `vol.py` | pslist, psscan, pstree, cmdline, netstat, netscan, malfind, svcscan, modules, filescan, userassist, hivelist, info |
| Memory timeline | `vol.py timeliner` + `mactime` | `mem_bodyfile.txt` → `mem_timeline.txt` |
| Memory Baseliner | `baseline.py` | `proc_baseline.csv`, `drv_baseline.csv`, `svc_baseline.csv` |
| AutoTimeliner (optional) | `autotimeliner.py` | `autotimeliner/supertimeline.csv` |
| EVTXtract (optional) | `evtxtract.py` | `evtxtract/recovered_events.xml`, `evtxtract/events_summary.txt` |
| Linux strings fallback | `strings` + grep | `strings_all.txt`, `strings_unicode.txt`, `syslog_patterns.txt` |

AutoTimeliner lives at `/opt/autotimeliner/autotimeliner.py`. It correlates Volatility plugin outputs (timeliner, pslist, pstree, netstat, filescan) into a single MACB super-timeline in bodyfile format. When absent, the step is skipped.

EVTXtract lives at `/opt/EVTXtract/evtxtract.py`. It scans raw binary data for EVTX record magic bytes and validates record checksums, producing an XML document with all recovered `<Event>` elements. It is particularly useful when `filescan` finds `.evtx` files but the records are fragmented across memory pages. When absent, the step is skipped.

---

### FAST pipeline — storage forensics

Entry point: `scripts/fast_analyze.sh`

| Stage | Tool | Output |
|-------|------|--------|
| Image verification | `ewfinfo` / `ewfverify` / `img_stat` | `ewfinfo.txt`, `ewfverify.txt`, `img_stat.txt` |
| Partition map | `mmls` | `mmls.txt` |
| Filesystem stats | `fsstat` | `fsstat.txt` |
| File listing | `fls -r` | `fls_output.txt` |
| MACB bodyfile | `fls -m` | `bodyfile.txt` |
| Filesystem timeline | `mactime` | `fs_timeline.txt`, `fs_timeline.csv` |
| Inode listing | `ils` | `ils_output.txt`, `ils_orphan.txt` |
| Artifact extraction | `cp` from mount | evtx/, registry/, prefetch/, srum/, browser/, recyclebin/ |
| MFT + USN journal | `icat` | `mft/$MFT`, `mft/$J` |
| File carving | `bulk_extractor` | `carved/` (images up to 20 GB only) |
| Autopsy (optional) | `autopsy --nogui` | `autopsy/case/` + exported CSVs |

Autopsy runs in headless (`--nogui`) mode with these ingest modules enabled:

- `FileExtMismatchDetectorModuleFactory` — detects files with mismatched extension and content type
- `HashLookupModuleFactory` — compares file hashes against NSRL and any configured hash sets
- `RecentActivityExtracterModuleFactory` — extracts browser history, recently opened files, shell items, USB device history
- `TimeLineModuleFactory` — builds a visual timeline of filesystem events
- `ExifParserModuleFactory` — extracts EXIF metadata from images
- `KeywordSearchModuleFactory` — indexes file content for keyword hits

Autopsy is located via `$PATH`, `/opt/autopsy/bin/autopsy`, or `/usr/share/autopsy/bin/autopsy`. When absent, the step is skipped and `AUTOPSY_NOT_RUN.txt` is written to `./exports/autopsy/`.

---

### Utility scripts

| Script | Purpose |
|--------|---------|
| `analyze_pcap.sh` | Orchestrates the full 22-module FAN pipeline |
| `fame_analyze.sh` | Orchestrates the FAME pipeline (Volatility, AutoTimeliner, EVTXtract) |
| `fast_analyze.sh` | Orchestrates the FAST pipeline (TSK, Autopsy, bulk_extractor) |
| `generate_pcap_report.sh` | Assembles module outputs into Markdown + PDF report |
| `update_suricata_rules.sh` | Downloads/updates ET Open rules |
| `yara_sweep.sh` | Standalone YARA sweep against disk mounts or memory images |
| `perplexity_search.sh` | CLI wrapper for Perplexity lookups |
| `vault_context.sh` | CLI wrapper for vault queries |
| `md_to_pdf.sh` | Converts a Markdown file to a styled PDF |
| `remove_case.sh` | Removes a case directory from the investigations vault |
| `test_solution.sh` | End-to-end smoke test |
| `install_dependencies.sh` | System dependency installer |
| `setup_folder_structure.sh` | Creates all required directories and seeds the vault |
| `set_env_template.sh` | Template for `~/.soc_env` |

---

## 4. Python library API

All library modules live in `lib/`. Activate the virtual environment before importing:

```bash
source .venv/bin/activate
```

### `lib/obsidian_bridge.py` — vault I/O

Low-level read/write operations on `./vault/`.

```python
from lib.obsidian_bridge import (
    write_note,       # write_note(path, content) → None
    read_note,        # read_note(path) → str | None
    append_to_note,   # append_to_note(path, content) → None
    search_vault,     # search_vault(query, max_results=10) → list[dict]
    patch_section,    # patch_section(path, section_header, new_content) → None
)
```

`path` values are relative to `./vault/` (e.g. `"IOCs/192.168.1.1.md"`).
`search_vault` performs full-text search across all vault notes.

Self-test: `python3 lib/obsidian_bridge.py`

---

### `lib/knowledge_extractor.py` — high-level recording

Wraps `obsidian_bridge` with typed record functions. Each call also pushes to OpenCTI.

```python
from lib.knowledge_extractor import (
    open_case,           # open_case(case_id, description, severity="medium") → None
    close_case,          # close_case(case_id, summary) → None
    record_ioc,          # record_ioc(ioc_type, value, context, case_id, severity="medium") → None
    record_ttp,          # record_ttp(mitre_id, name, context, case_id) → None
    record_threat_actor, # record_threat_actor(name, context, case_id) → None
    record_malware,      # record_malware(family, context, case_id) → None
    record_risk,         # record_risk(asset, description, case_id, severity="medium") → None
    record_concept,      # record_concept(name, definition, case_id=None) → None
)
```

`ioc_type` values: `"ip"`, `"domain"`, `"url"`, `"hash_md5"`, `"hash_sha256"`, `"email"`, `"filename"`

`record_ioc` defangs all values before writing to the vault.

Self-test: `python3 lib/knowledge_extractor.py --test`

---

### `lib/vault_query.py` — read-path queries

```python
from lib.vault_query import (
    get_context_for_ioc,    # get_context_for_ioc(value) → dict | None
    get_context_for_ttp,    # get_context_for_ttp(mitre_id) → dict | None
    get_active_cases,       # get_active_cases() → list[dict]
    get_top_risks,          # get_top_risks(limit=5) → list[dict]
    get_related_notes,      # get_related_notes(note_path) → list[str]
    search_context,         # search_context(query) → list[dict]
)
```

Self-test: `python3 lib/vault_query.py --search powershell`

---

### `lib/perplexity_client.py` — live threat intelligence

```python
from lib.perplexity_client import (
    lookup_ioc,     # lookup_ioc(value) → dict
    lookup_malware, # lookup_malware(family) → dict
    lookup_ttp,     # lookup_ttp(mitre_id) → dict
    lookup_cve,     # lookup_cve(cve_id) → dict
    lookup_actor,   # lookup_actor(name) → dict
    lookup_tool,    # lookup_tool(name) → dict
    search,         # search(query) → dict
)
```

Requires `PERPLEXITY_API_KEY` in environment. Never pass raw IPs, hostnames, or usernames from live cases.

---

### `lib/md_to_pdf.py` — PDF generation

```python
from lib.md_to_pdf import convert

convert(
    md_path="/path/to/report.md",
    pdf_path="/path/to/output.pdf",
    title="Incident report — FAN-2026-001",   # optional: cover page title
    classification="CONFIDENTIAL",             # optional: footer text
)
```

Requires WeasyPrint system libraries (Cairo, Pango, fonts-liberation). The PDF includes a styled cover page, running header stripe, and "Page X of Y" pagination.

---

### `lib/investigations_upload.py` — report filing

```python
from lib.investigations_upload import upload_report

upload_report(
    report_md="/path/to/report.md",
    report_pdf="/path/to/report.pdf",
    case_id="FAN-2026-001",
)
# Copies both files to ~/cases/FAN-2026-001/reports/<stem>_v<n>.{md,pdf}
# Auto-increments version number if a report for this stem already exists.
```

---

### `lib/pcap_analyzer.py` — core PCAP interface

```python
from lib.pcap_analyzer import PcapAnalyzer

pa = PcapAnalyzer(pcap_path="/path/to/capture.pcap")
pa.load()                    # parse with tshark, build internal DataFrames
flows = pa.get_flows()       # → pd.DataFrame (src_ip, dst_ip, protocol, …)
dns   = pa.get_dns_records() # → pd.DataFrame
http  = pa.get_http_flows()  # → pd.DataFrame
```

All 22 detection modules instantiate `PcapAnalyzer` and work from its DataFrames rather than re-parsing the PCAP file independently.

---

## 5. MCP server API

All servers implement JSON-RPC 2.0 over stdio (MCP protocol v2024-11-05). They are registered in `.claude/settings.json` and started automatically by Claude Code.

### `mcp/evidence_server.py` — read-only evidence access

Root: `$EVIDENCE_ROOT` (default: `~/evidence`)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `evidence_list_directory` | `path: str` | `list[FileInfo]` |
| `evidence_read_file` | `path: str` | `str` (base64 for binary) |
| `evidence_get_file_info` | `path: str` | `FileInfo` |
| `evidence_find_pcaps` | *(none)* | `list[str]` — paths to all `.pcap/.pcapng` files |

All paths are validated to stay within `EVIDENCE_ROOT`. Write operations are rejected at the server level.

---

### `mcp/investigations_server.py` — read-write investigations vault

Root: `$INVESTIGATIONS_ROOT` (default: `~/cases`)

| Tool | Parameters | Returns |
|------|-----------|---------|
| `investigations_list_directory` | `path: str` | `list[FileInfo]` |
| `investigations_read_file` | `path: str` | `str` |
| `investigations_write_file` | `path: str`, `content: str` | `WriteResult` |
| `investigations_create_directory` | `path: str` | `CreateResult` |
| `investigations_delete` | `path: str` | `DeleteResult` |
| `investigations_get_file_info` | `path: str` | `FileInfo` |
| `investigations_list_cases` | *(none)* | `list[CaseSummary]` |

`investigations_list_cases` returns all direct subdirectories of `INVESTIGATIONS_ROOT` as case summaries (id, creation time, last modified, report count).

---

### `mcp/opencti_server.py` — OpenCTI CTI integration

Credentials: `OPENCTI_URL`, `OPENCTI_API_KEY` from environment.

| Tool | Parameters | Returns |
|------|-----------|---------|
| `opencti_search_stix` | `query: str`, `entity_type: str?`, `limit: int?` | `list[StixEntity]` |
| `opencti_search_ioc` | `value: str`, `pattern_type: str?`, `limit: int?` | `list[IndicatorResult]` |
| `opencti_create_indicator` | `name: str`, `pattern: str`, `pattern_type: str`, `description: str?`, `score: int?` | `CreateResult` |

`pattern_type` values: `"stix"`, `"yara"`, `"sigma"`  
Score range: 0–100. Maps to: `< 40` → INFORMATIONAL, `40–74` → SUSPICIOUS, `≥ 75` → CONFIRMED_MALICIOUS.

---

## 6. Obsidian vault schema

The vault at `./vault/` is a plain-Markdown knowledge graph. Note filenames are the human-readable identifiers.

### Folder layout

```
vault/
  IOCs/           One note per indicator (IP, domain, hash, …)
  TTPs/           One note per MITRE ATT&CK (sub)technique
  ThreatActors/   Threat group profiles
  Malware/        Malware family profiles
  Concepts/       Generic cybersecurity concepts
  Risks/          Risk assessments per case/asset
  Cases/          Post-investigation summaries
  Templates/      Note schemas — do not modify manually
  Dashboard.md    Auto-maintained index
```

### Frontmatter conventions

Every note has YAML frontmatter. Key fields by type:

**IOC note** (`IOCs/<defanged-value>.md`):
```yaml
ioc_type: ip | domain | url | hash_md5 | hash_sha256 | email | filename
value: 192[.]0[.]2[.]1
severity: low | medium | high | critical
disposition: unknown | benign | suspicious | malicious
case_refs: [FAN-2026-001]
```

**TTP note** (`TTPs/T1071.001.md`):
```yaml
mitre_id: T1071.001
technique_name: Application Layer Protocol - Web Protocols
tactic: command-and-control
severity: medium | high | critical
case_refs: [FAN-2026-001]
```

**Case note** (`Cases/FAN-2026-001.md`):
```yaml
case_id: FAN-2026-001
status: open | closed
severity: low | medium | high | critical
ttps_observed: [T1071.001, T1059.001]
iocs_found: [192[.]0[.]2[.]1]
```

### IOC defanging rules

| Type | Example input | Stored as |
|------|--------------|-----------|
| IPv4 | `192.0.2.1` | `192[.]0[.]2[.]1` |
| Domain | `evil.com` | `evil[.]com` |
| URL | `https://evil.com/path` | `hxxps://evil[.]com/path` |
| Hash | `deadbeef...` | stored as-is (not a network indicator) |

---

## 7. Configuration reference

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PERPLEXITY_API_KEY` | Yes | Perplexity.ai API key — `pplx-...` |
| `OPENCTI_URL` | OpenCTI | OpenCTI instance base URL |
| `OPENCTI_API_KEY` | OpenCTI | OpenCTI API token |
| `SENTINEL_TENANT_ID` | Sentinel | Azure tenant GUID |
| `SENTINEL_CLIENT_ID` | Sentinel | App registration client GUID |
| `SENTINEL_CLIENT_SECRET` | Sentinel | App registration secret |
| `SENTINEL_SUBSCRIPTION_ID` | Sentinel | Azure subscription GUID |
| `SENTINEL_RESOURCE_GROUP` | Sentinel | Resource group name |
| `SENTINEL_WORKSPACE_NAME` | Sentinel | Log Analytics workspace name |
| `SENTINEL_WORKSPACE_ID` | Sentinel | Log Analytics workspace GUID |
| `INVESTIGATIONS_ROOT` | No | Override default `~/cases` |
| `EVIDENCE_ROOT` | No | Override default `~/evidence` |

Set in `~/.soc_env`, sourced from `~/.bashrc`. Template: `scripts/set_env_template.sh`.

---

### `.claude/settings.json` — MCP and permissions

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

`setup_folder_structure.sh` generates this file with the correct absolute paths.

---

### Key paths

| Path | Purpose | Writable by analyst? |
|------|---------|----------------------|
| `./analysis/` | WIP during investigation — auto-deleted | No (WIP only) |
| `./vault/` | Obsidian knowledge graph | Via `record_*` functions only |
| `./rules/suricata/` | Suricata rule files | Yes — add `.rules` files |
| `./rules/yara/` | YARA rule files | Yes — add `.yar` files |
| `./reports/` | Manual report exports | Yes |
| `~/evidence/` | PCAP drop zone | No — read-only by tools |
| `~/cases/` | Finalized investigation reports | Via MCP server only |
| `~/.soc_env` | API credentials | Yes — never commit |

---

## 8. Dependency map

```
analyze_pcap.sh  (FAN)
  ├── fan_*.sh (×22)
  │     └── lib/fan_*.py
  │           └── lib/pcap_analyzer.py     (tshark)
  ├── lib/fan_ip_lookup.py
  │     ├── lib/vault_query.py
  │     │     └── lib/obsidian_bridge.py
  │     └── lib/perplexity_client.py       (PERPLEXITY_API_KEY)
  ├── lib/generate_pcap_report.py
  │     ├── lib/md_to_pdf.py               (WeasyPrint / Cairo)
  │     └── lib/generate_pptx_report.py    (python-pptx)
  ├── lib/investigations_upload.py
  │     └── mcp/investigations_server.py
  └── lib/knowledge_extractor.py
        ├── lib/obsidian_bridge.py
        └── mcp/opencti_server.py          (OPENCTI_URL, OPENCTI_API_KEY)

fame_analyze.sh  (FAME)
  ├── vol.py (Volatility 3)                (MEMORY_IMAGE)
  ├── baseline.py (Memory Baseliner)       (baselines/baseline.json)
  ├── autotimeliner.py (AutoTimeliner)     (optional — /opt/autotimeliner/)
  ├── evtxtract.py (EVTXtract)             (optional — /opt/EVTXtract/)
  ├── lib/generate_fame_report.py
  │     ├── lib/md_to_pdf.py
  │     ├── lib/generate_pptx_report.py
  │     └── lib/generate_combined_report.py (if FAN/FAST reports found)
  └── lib/investigations_upload.py

fast_analyze.sh  (FAST)
  ├── ewfmount / ewfinfo / ewfverify        (E01/EWF images)
  ├── mmls / fsstat / fls / ils / icat      (The Sleuth Kit)
  ├── mactime                               (bodyfile → timeline)
  ├── bulk_extractor                        (carving, images up to 20 GB)
  ├── autopsy --nogui                       (optional — headless ingest)
  ├── lib/generate_fast_report.py
  │     ├── lib/md_to_pdf.py
  │     ├── lib/generate_pptx_report.py
  │     └── lib/generate_combined_report.py (if FAN/FAME reports found)
  └── lib/investigations_upload.py
```

### System binary dependencies

| Binary | Package | Used by |
|--------|---------|---------|
| `tshark` | `tshark` (apt) | `pcap_analyzer.py` — all protocol parsing |
| `suricata` | PPA: oisf/suricata-stable | `fan_suricata.py` |
| `yara` | `yara` (apt) or compiled | `fan_yara_pcap.py`, `yara_sweep.sh` |
| `dotnet` | Microsoft APT | EZ Tools (FAST prereq) |
| `ewfmount` / `ewfinfo` / `ewfverify` | `libewf-dev` / `ewf-tools` | `fast_analyze.sh` — E01 image handling |
| `fls` / `fsstat` / `mmls` / `ils` / `icat` | `sleuthkit` | `fast_analyze.sh` — filesystem analysis |
| `mactime` | `sleuthkit` | `fast_analyze.sh` — bodyfile to timeline |
| `bulk_extractor` | `bulk-extractor` (apt) | `fast_analyze.sh` — file carving |
| `autopsy` | manual install | `fast_analyze.sh` — headless ingest (optional) |
| `autotimeliner.py` | git clone | `fame_analyze.sh` — super-timeline (optional) |
| `evtxtract.py` | git clone | `fame_analyze.sh` — EVTX recovery (optional) |
| `python3` | system | all Python modules |

### Python package purposes

| Package | Purpose |
|---------|---------|
| `weasyprint` + `cairocffi` | PDF generation |
| `python-pptx` | PowerPoint output |
| `python-docx` | Word document output (FAME / FAST / combined reports) |
| `xlsxwriter` | Excel output |
| `Markdown` | Markdown to HTML (pre-PDF) |
| `PyYAML` | Frontmatter parsing, config |
| `requests` | Perplexity API, OpenCTI HTTP |
| `numpy` + `scipy` | Statistical anomaly detection in modules |
| `networkx` | Connection graph analysis |
| `rapidfuzz` | Vault deduplication, fuzzy IOC matching |
| `datasketch` | MinHash similarity for large IOC sets |
| `graphifyy` | Network topology visualization |

---

## 9. License and disclaimer

Fan Get Fame Fast is released under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full terms.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Integrators and contributors accept the terms of the Apache 2.0 License, including the disclaimer of warranty and limitation of liability in Sections 7 and 8.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · May 2026 — v1.1*
