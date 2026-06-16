# FanGetFameFast — Integration Benefits for SIFT Protocol

## 1. What is protocol-sift?

[protocol-sift](https://github.com/teamdfir/protocol-sift) is Rob Lee's SIFT Workstation + Claude Code configuration. Despite the name it is not a network-protocol-analysis project; it is a set of five analyst-invoked cheatsheet skills that give Claude contextual awareness of the tools already installed on a SANS SIFT workstation:

| protocol-sift skill | Tool-chain covered |
|--------------------|--------------------|
| `memory-analysis`  | Volatility 3 plugin reference |
| `sleuthkit`        | TSK / EWF / mactime / bulk_extractor |
| `windows-artifacts`| EZ Tools, ASEP (Autoruns), Windows Event Log parsing |
| `plaso-timeline`   | log2timeline / psort super-timeline |
| `yara-hunting`     | YARA rules + Velociraptor VQL |

Protocol-sift is best described as an intelligent cheat-sheet layer: it teaches Claude what tools exist and how to invoke them. The analyst still runs those tools, reads the output, and authors the report manually.

---

## 2. What FanGetFameFast adds

FanGetFameFast is an **agentic orchestration layer** built on top of the same SIFT tool-chain. It does not replace protocol-sift's knowledge — it amplifies it by having Claude actually drive the investigation end-to-end:

- Claude invokes the tools (it does not describe how to invoke them).
- Claude reads every output, interprets it, and decides what to do next.
- Claude cross-correlates findings across network, memory, and storage evidence automatically.
- Claude writes the forensic report in two registers (management summary + technical body) as a by-product of the investigation, not as a separate task.

The analyst's role shifts from **tool operator + report author** to **analyst + reviewer**: they supply the evidence, answer clarifying questions when Claude is uncertain, and review the drafted report — they do not author it from scratch.

---

## 3. Coverage comparison

| protocol-sift skill | FanGetFameFast equivalent | What FanGetFameFast adds |
|--------------------|--------------------------|--------------------------|
| `memory-analysis` | `/fame` — Volatility 3 pipeline (pslist, psscan, pstree, cmdline, netstat/netscan, malfind, modules, svcscan, filescan) + optional Memory Baseliner | Agentic step-by-step execution; mandatory research-notes cadence; DKOM/injection analysis; Linux strings fallback; cross-module trigger to FAN/FAST when network/disk artifacts are found in memory |
| `sleuthkit` | `/fast` — TSK + EWF + bulk_extractor + PhotoRec pipeline (9 analysis steps) | Automated artifact extraction (EVTX, registry, prefetch, MFT, USN Journal, SRUM, browser history, mail, IRC, Office metadata); auto-trigger to FAN when a PCAP is found on disk; auto-trigger to FAME when a memory image is found |
| `windows-artifacts` | `/fast` deep-dive pivot table + EZ Tools integration | EZ Tools invoked as `.dll` via `dotnet /opt/zimmermantools/<Tool>.dll` (Linux-correct syntax); PECmd, AppCompatCacheParser, AmcacheParser, MFTECmd, RECmd, SBECmd, JLECmd, LECmd, WxTCmd, SrumECmd, SQLECmd, RBCmd, EvtxECmd wired into the deep-dive workflow |
| `plaso-timeline` | `/fast` Step 6 filesystem bodyfile (mactime) | Mactime-based filesystem timeline is available today; Plaso super-timeline (log2timeline → psort) is planned as an opt-in `--plaso` step feeding Step 6's bodyfile + EVTX exports + registry exports into a unified cross-artifact timeline |
| `yara-hunting` | `/fan-yara-pcap` — YARA scanning across raw PCAP binary, extracted files, memory images | Four built-in rule categories (network_threats, common_malware, pe_analysis, entropy_detection); pre-compiled rule cache (yarac); community rules (Neo23x0/signature-base); PE module, math.entropy, hash module; parallel threading; Velociraptor VQL is documented as an optional live-IR reference (not wired into automated pipelines — same as protocol-sift) |

---

## 4. Key differentiators

Capabilities that FanGetFameFast provides and protocol-sift does not:

1. **Agentic coordination** — Claude runs the tools, reads every output, and pivots to the next step without analyst direction. Each finding informs the next query.

2. **Cross-module correlation (FAN ↔ FAME ↔ FAST)** — Suspicious network connections are automatically correlated with memory process lists (netscan→PCAP) and disk artifacts (process→deleted file, DNS→carved domain). The correlation engine runs automatically and feeds the narrative.

3. **Dual-register report generation** — Every investigation produces a management summary (CISO language, no technical identifiers) and a technical body (precise IPs, ports, timestamps, evidence citations) in a single document, rendered as Markdown, PDF, PowerPoint, and Word.

4. **Court-ready chain-of-custody manifest** — `lib/chain_of_custody.py` produces a `<case_id>_chain_of_custody.json` with MD5/SHA-1/SHA-256 hashes of every artifact under `reports/<case_id>/`, append-only history entries, and tamper signals (old + new hash on any change). Updated automatically at the end of every pipeline.

5. **Institutional memory (Obsidian vault)** — TTPs, IOCs, threat actors, malware families, risks, and case summaries accumulate across investigations. Subsequent cases query the vault first (`/obsidian-query`) before calling live threat intelligence, so the same IOC is never looked up twice.

6. **Live CTI enrichment at investigation time** — Unknown artifacts that the vault cannot answer are forwarded to Perplexity.ai (`/perplexity-lookup`) for real-time web-sourced intelligence, then recorded back to the vault. OpenCTI integration (`/fan-opencti-lookup`) checks extracted IPs and FQDNs against a local or remote OpenCTI instance.

7. **Automated campaign report** — When two or more modules (FAN + FAME, FAME + FAST, or all three) run against evidence from the same case, the campaign report synthesises cross-module findings into a single board-deck presentation (PDF + PPTX + DOCX) — one document that covers the full incident.

8. **Investigations vault upload** — Finished reports are packaged (ZIP with SHA-256 manifest) and uploaded via SCP to a configured remote vault host (`INVESTIGATIONS_ROOT` on a SIFT box or case-management server). If no vault is configured, reports remain local under `./reports/<case_id>/`.

---

## 5. Known gaps relative to protocol-sift

FanGetFameFast has evaluated protocol-sift's content and identified the following areas where protocol-sift currently goes further:

- **EZ Tools syntax** — Some FAST skill documentation still references Windows `.exe` invocations; the correct SIFT-Linux form is `dotnet /opt/zimmermantools/<Tool>.dll`. Alignment is a known pending item.
- **Consolidated Windows Event ID reference table** — Protocol-sift ships a comprehensive quick-reference covering Logon/Auth (4624/4625), Process Execution (4688), PowerShell (4103/4104/400/600), RDP (1149/4778/4779), Services (7034–7045), Scheduled Tasks (106/129/200/201), and WMI persistence (5857–5861). FanGetFameFast covers these IDs within EVTX parsing steps but lacks a standalone reference table.
- **ASEP (Autoruns) analysis workflow** — Protocol-sift documents an autorunsc collection command, ASEP category table, and CLI triage one-liners. FanGetFameFast extracts Autoruns-equivalent data via registry hives and prefetch but does not ship an ASEP-specific reference section.
- **Velociraptor VQL reference** — Protocol-sift includes a Velociraptor concept primer and VQL query examples for live-IR engagements. FanGetFameFast does not include a Velociraptor skill (Velociraptor is a live-endpoint agent, outside the scope of post-mortem evidence analysis that FAN/FAME/FAST cover).
- **Plaso super-timeline as a first-class step** — mactime provides a filesystem-only timeline today; a full Plaso super-timeline step (log2timeline → pinfo.py verification → psort.py) is planned but not yet implemented.

These gaps do not affect the core three-module investigation pipeline and are tracked as future enhancements.

---

## 6. Recommended adoption path

For SIFT Workstation analysts who are already using protocol-sift:

1. **Install FanGetFameFast** on your SIFT workstation — see [docs/DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) for requirements and setup steps (the tool-chain is already present on SIFT; the main additions are the Python libraries and MCP server configuration).
2. **Use `/fan`, `/fame`, `/fast` as your primary investigation entry points.** Claude will run the tools, read the outputs, and draft the report. Protocol-sift's cheatsheet content is incorporated into the FAST and FAME skill context so the same procedural knowledge is available.
3. **Keep protocol-sift as an offline reference** if desired — particularly for the EZ Tools syntax table and the Event ID quick-reference until those are integrated into FanGetFameFast.
4. **Point the investigations vault** at your existing SIFT case-management directory using `./scripts/configure_vault.sh user@host /path/to/cases` — finished reports will land there automatically after each investigation.

The net result: analysts spend their time on analysis and containment decisions, not on running tools in sequence or authoring reports from scratch.
