# FanGetFameFast — Production deployment guide

**Version:** 2.0 · June 2026
**Platform:** Ubuntu 24.04 LTS (x86-64)
**Authors:** Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
**Classification:** Internal — SOC Operations

> **New in v2.0:** an [Architectural guardrails](#13-architectural-guardrails-deployers-view) section
> documenting the security boundaries as a deployer control, optional batch/timeline dependencies in
> [Section 4](#4-install-system-dependencies), and an audit-trail/output verification note in
> [Section 10](#10-verify-the-installation). The companion diagrams are in
> [Architecture diagrams](ARCHITECTURE_DIAGRAM.md).

---

## Table of contents

1. [Server requirements](#1-server-requirements)
2. [Service account setup](#2-service-account-setup)
3. [Install the codebase](#3-install-the-codebase)
4. [Install system dependencies](#4-install-system-dependencies)
5. [Configure passwordless sudo](#5-configure-passwordless-sudo)
6. [Create the folder structure](#6-create-the-folder-structure)
7. [Configure API credentials](#7-configure-api-credentials)
8. [Configure MCP servers](#8-configure-mcp-servers)
9. [Set up SSH key access to the investigations vault](#9-set-up-ssh-key-access-to-the-investigations-vault)
10. [Verify the installation](#10-verify-the-installation)
11. [First investigation](#11-first-investigation)
12. [Security hardening](#12-security-hardening)
13. [Architectural guardrails (deployer's view)](#13-architectural-guardrails-deployers-view)
14. [Backup and recovery](#14-backup-and-recovery)
15. [Upgrading](#15-upgrading)
16. [Troubleshooting](#16-troubleshooting)
17. [License and disclaimer](#17-license-and-disclaimer)

---

## 1. Server requirements

### Minimum (single analyst, PCAPs up to 500 MB)

| Resource | Minimum |
|----------|---------|
| CPU | 4 cores |
| RAM | 8 GB |
| Disk | 100 GB SSD |
| OS | Ubuntu 22.04 or 24.04 LTS (x86-64) |
| Network | Internet access (Perplexity API, Suricata rule updates) |

### Recommended (team of 3–5 analysts, PCAPs up to 5 GB)

| Resource | Recommended |
|----------|-------------|
| CPU | 8 cores |
| RAM | 32 GB |
| Disk | 500 GB SSD + 2 TB HDD (evidence storage) |
| OS | Ubuntu 24.04 LTS (x86-64) |

Memory-intensive stages: Volatility 3 malfind requires approximately 2× the memory image size in available RAM. A 4 GB memory image needs at least 8 GB free. Autopsy headless ingest requires at least 2 GB heap (`-Xmx2g`).

### Required external access

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| `api.perplexity.ai` | HTTPS/443 | Live threat intelligence lookups |
| `rules.emergingthreats.net` | HTTPS/443 | Suricata ET Open rule updates |
| `packages.microsoft.com` | HTTPS/443 | .NET Runtime (required by EZ Tools) |
| `ppa.launchpad.net` | HTTPS/443 | Suricata PPA |
| `pypi.org` | HTTPS/443 | Python package installation |
| Your OpenCTI instance | HTTP/HTTPS | CTI lookups (local or remote) |

---

## 2. Service account setup

Run as a dedicated service account, not as root. The account needs to be in the `wireshark` group so that tshark can read network interfaces and PCAP files without root privileges.

```bash
# Create the service account
sudo useradd --create-home --shell /bin/bash soc-analyst

# Add to the wireshark group (if the group already exists)
sudo usermod -aG wireshark soc-analyst

# If the wireshark group does not exist yet, install_dependencies.sh creates it.
# Re-run the usermod command after running install_dependencies.sh.

# Switch to the service account for all remaining steps
sudo su - soc-analyst
```

A logout/login (or `newgrp wireshark`) is required for group membership changes to take effect. tshark silently fails to read PCAPs until this is done.

---

## 3. Install the codebase

```bash
# Choose your installation directory
INSTALL_DIR="$HOME/Documents/FanGetFameFast"

# Clone from the repository
git clone <repo-url> "$INSTALL_DIR"

# Or copy from a portable archive
tar -xzf FanGetFameFast.tar.gz -C "$HOME/Documents/"

cd "$INSTALL_DIR"
```

The project must live in a user-writable directory. `/opt/` works if the directory is owned by the service account. `/root/` does not work with the wireshark group restriction.

---

## 4. Install system dependencies

```bash
cd "$INSTALL_DIR"

# Full install (recommended)
bash scripts/install_dependencies.sh

# Skip optional components
bash scripts/install_dependencies.sh --skip-suricata   # no IDS
bash scripts/install_dependencies.sh --skip-yara        # no YARA
bash scripts/install_dependencies.sh --skip-dotnet      # no EZ Tools (.NET runtime)
```

All steps check existing state before acting, so the script is safe to re-run.

### What gets installed

| Component | Source | Notes |
|-----------|--------|-------|
| tshark / wireshark-common | apt | PCAP parsing; all 22 FAN detection modules depend on it |
| Suricata | PPA: oisf/suricata-stable | IDS engine for FAN Suricata module |
| YARA 4.5+ | apt or compiled from source | Signature scanning for FAN YARA module and FAME memory scans |
| .NET Runtime 6/8 | Microsoft APT repository | EZ Tools (FAST module prerequisite) |
| Python 3.10+ venv | system Python | Isolated package environment at `.venv/` |
| Python packages | pip from `requirements.txt` | All analysis and report generation libraries |
| Claude Code CLI | npm / Anthropic installer | Agentic coordinator |
| Suricata ET Open rules | download | Initial ruleset for FAN investigations |
| Font packages | apt | Required for PDF report rendering (WeasyPrint / Cairo) |
| sleuthkit | apt | TSK tools (fls, fsstat, mmls, ils, icat, mactime) — FAST module |
| ewf-tools / libewf-dev | apt | E01/EWF image handling — FAST module |
| bulk-extractor | apt | File carving from disk images — FAST module |
| Volatility 3 | pip or git clone | Memory analysis framework — FAME module |
| Memory Baseliner | git clone | Process/driver/service baseline comparison — FAME module |

### Optional — Autopsy (FAST module)

Autopsy runs in headless (`--nogui`) mode during FAST investigations. It adds file-type mismatch detection, hash lookup against NSRL, recent activity parsing, EXIF extraction, and keyword indexing on top of the TSK layer.

```bash
# Ubuntu 24.04 — install from apt if available
sudo apt-get install -y autopsy

# Or install the upstream .deb (recommended — keeps Autopsy current)
# 1. Download the latest release from https://www.autopsy.com/download/
sudo dpkg -i autopsy-4.x.x-amd64.deb
sudo apt-get install -f    # resolve any missing dependencies

# Verify — must be 4.17 or later for --nogui support
autopsy --version
```

When `autopsy` is absent from `$PATH`, `fast_analyze.sh` skips the Autopsy step and writes `AUTOPSY_NOT_RUN.txt` to `./exports/autopsy/`. The rest of the FAST pipeline runs normally.

### Optional — MemProcFS (FAME module)

MemProcFS provides physical memory access via the LeechCore driver as an independent second analysis pathway alongside Volatility 3. It is particularly useful for VirtualBox ELF core dumps: it extracts the CR3 (Directory Table Base) from the VBCPU PT_NOTE segment and uses it to initialize physical memory analysis.

```bash
pip3 install memprocfs --break-system-packages
```

When the `memprocfs` Python package is not importable, `fame_analyze.sh` skips the MemProcFS stage and continues.

### Optional — AutoTimeliner (FAME module)

AutoTimeliner builds a Volatility-backed MACB super-timeline from a memory image. It correlates output from the timeliner, pslist, pstree, netstat, and filescan plugins into a single bodyfile.

```bash
git clone https://github.com/andreafortuna/autotimeliner /opt/autotimeliner
pip3 install -r /opt/autotimeliner/requirements.txt
```

AutoTimeliner requires Volatility 3 to be importable as a Python module. Add the following to `~/.soc_env`:

```bash
export PYTHONPATH="/opt/volatility3-2.20.0:$PYTHONPATH"
```

When absent, `fame_analyze.sh` skips the super-timeline step and continues.

### Optional — EVTXtract (FAME module)

EVTXtract recovers intact Windows Event Log records from raw binary data by scanning for EVTX record magic bytes and validating checksums. It works on memory images where `filescan` locates `.evtx` files but the records are fragmented across memory pages.

```bash
git clone https://github.com/williballenthin/EVTXtract /opt/EVTXtract
pip3 install -r /opt/EVTXtract/requirements.txt
```

When absent, `fame_analyze.sh` skips the event recovery step and continues.

### Optional — timeline rendering (batch / campaign reports)

The swimlane attack-timeline images in campaign reports (`lib/generate_timeline.py`,
`lib/generate_campaign_report.py`) use two optional plotting libraries:

```bash
source .venv/bin/activate
pip install plotly       # interactive HTML timeline — already in requirements.txt
pip install matplotlib   # static PNG timeline — optional, not in requirements.txt
```

`plotly` ships in `requirements.txt`. `matplotlib` is **not** required: when it is absent the PNG
timeline is skipped with a logged warning and the rest of the campaign report is produced normally.
Install it only if you want the static PNG embedded in PDFs and board decks. This is the same
graceful-degradation pattern used throughout the platform — a missing optional component never
aborts a run.

### Post-install — apply group membership

The wireshark group change does not take effect in the current shell:

```bash
newgrp wireshark    # applies in current shell without logging out
# Or log out and back in
```

---

## 5. Configure passwordless sudo

`analyze_pcap.sh` calls `suricata-update` at the start of every FAN investigation. It runs without a TTY (no terminal prompt available), so sudo must not ask for a password. `setup_sudoers.sh` writes a validated sudoers drop-in that grants the current user passwordless access to the exact binaries that need it — no broader privileges are granted.

```bash
cd "$INSTALL_DIR"
sudo bash scripts/setup_sudoers.sh
```

The script writes to `/etc/sudoers.d/fangetfamefast`. It resolves the binary paths at install time and validates the resulting sudoers file with `visudo -c` before writing. If validation fails, nothing is written.

To verify it worked:

```bash
sudo -n suricata-update --no-reload 2>&1 | head -5
# Should not prompt for a password
```

---

## 6. Create the folder structure

```bash
cd "$INSTALL_DIR"

# Default layout (~/evidence and ~/cases)
bash scripts/setup_folder_structure.sh

# Custom paths (e.g. a separate HDD for evidence storage)
bash scripts/setup_folder_structure.sh \
    --evidence-dir /mnt/evidence \
    --cases-dir /mnt/cases
```

The script creates:

```
~/evidence/                         PCAP drop zone (evidence MCP server root)
~/cases/                            Investigation reports (investigations MCP server root)
$INSTALL_DIR/
  analysis/                         WIP only; cleared after each investigation
    memory/                         FAME: Volatility 3 outputs, Memory Baseliner
      memprocfs/                    FAME: MemProcFS artifacts (if installed)
      autotimeliner/                FAME: AutoTimeliner super-timeline (if installed)
      evtxtract/                    FAME: recovered EVTX records (if installed)
    storage/                        FAST: TSK outputs, mmls, fsstat, bodyfile
  exports/
    evtx/                           FAST: extracted Windows Event Log files
    registry/                       FAST: registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
    prefetch/                       FAST: prefetch files
    mft/                            FAST: $MFT and $J (USN change journal)
    srum/                           FAST: SRUM database
    browser/                        FAST: browser history files
    carved/                         FAST: bulk_extractor carving output
    autopsy/                        FAST: Autopsy case and exported artifacts
  reports/                          Manual report exports
  rules/suricata/                   Suricata rule files (ET Open + local.rules)
  rules/yara/                       YARA rule files (.yar)
  vault/                            Obsidian knowledge graph
    Templates/                      Note schemas — do not modify manually
    Dashboard.md                    Auto-maintained case/IOC/TTP index
  playbooks/                        Response playbooks
  .claude/settings.json             MCP server configuration (auto-generated)
```

The generated `settings.json` contains absolute paths. No manual editing is needed unless you change the paths after setup.

---

## 7. Configure API credentials

```bash
# Copy the template
cp templates/set_env_template.sh ~/.soc_env

# Fill in the values
nano ~/.soc_env
```

Minimum required:

```bash
export PERPLEXITY_API_KEY="pplx-..."
```

For OpenCTI integration (optional but recommended):

```bash
export OPENCTI_URL="http://your-opencti-host:8080"
export OPENCTI_API_KEY="your-api-token"   # from Settings → API access in OpenCTI
```

For AutoTimeliner (if installed):

```bash
export PYTHONPATH="/opt/volatility3-2.20.0:$PYTHONPATH"
```

Load in the current shell and persist across sessions:

```bash
source ~/.soc_env
echo 'source ~/.soc_env' >> ~/.bashrc
```

Set restrictive permissions on the credentials file immediately. The install script does not touch it:

```bash
chmod 600 ~/.soc_env
```

---

## 8. Configure MCP servers

`setup_folder_structure.sh` writes `.claude/settings.json` automatically. Verify the generated file:

```bash
cat .claude/settings.json
```

Expected structure:

```json
{
  "autoMemoryEnabled": true,
  "mcpServers": {
    "evidence": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp/evidence_server.py"],
      "env": { "EVIDENCE_ROOT": "/home/soc-analyst/evidence" }
    },
    "investigations": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp/investigations_server.py"],
      "env": { "INVESTIGATIONS_ROOT": "/home/soc-analyst/cases" }
    },
    "opencti": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp/opencti_server.py"]
    }
  }
}
```

The MCP servers read their root paths from the `env` block at startup. Paths must be absolute — tilde expansion does not work in JSON. OpenCTI credentials (`OPENCTI_URL`, `OPENCTI_API_KEY`) are not stored here; they come from the shell environment sourced via `~/.soc_env`.

If you move the project directory, re-run `setup_folder_structure.sh` to regenerate `settings.json` with the new paths.

---

## 9. Set up SSH key access to the investigations vault

`lib/investigations_upload.py` uses SSH/SCP to copy finished reports to the investigations vault on ubuntudesktop. It uses the private key at `~/.ssh/id_ed25519`. This key must exist and be authorized on the remote host before investigations can complete.

```bash
# Generate the key if you do not already have one
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ""

# Authorize it on ubuntudesktop
ssh-copy-id -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop

# Test passwordless access
ssh -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop "echo SSH OK"
# Should print "SSH OK" without a password prompt
```

If `~/.ssh/known_hosts` does not yet have an entry for ubuntudesktop, add it:

```bash
ssh-keyscan -H ubuntudesktop >> ~/.ssh/known_hosts
```

Without this setup, the final upload step of every investigation fails. The finished report stays in `./analysis/_reports/<stem>/` and `./analysis/` is not cleared.

### Session transcript recording (chain of evidence)

At the end of every pipeline, the shared helper `scripts/record_session.sh`
(`fgff_record_session`) calls `lib/chat_recorder.py` to record the full Claude
Code coordination session as `./reports/<case_id>_chat_transcript.{md,pdf,jsonl}`.
It reads the active session from the Claude Code transcript directory
(`~/.claude/projects/<encoded-project-dir>/`), which is derived automatically
from `CLAUDE_PROJECT_DIR` or the working directory — no configuration is needed,
and it adapts to whichever user the solution runs as. The rendering is verbatim
— tool outputs are never truncated — and the raw `.jsonl` is preserved with its
SHA-256 recorded in the document.

### Artifact bundling and upload (chain of evidence)

Immediately after the transcript, the shared helper
`scripts/package_artifacts.sh` (`fgff_package_artifacts`) calls
`lib/case_packager.py --all` to bundle the case's **complete** artifact set —
reports of every type, the transcript, exhibit images, evidence ZIPs — into
`./exports/<case_id>_<YYYYMMDD-HHMMSS>.zip` with a `MANIFEST.sha256` integrity
manifest, and uploads it to the investigations vault
(`$INVESTIGATIONS_ROOT/<case_id>/`). Because it runs after the recorder, the
transcript is inside the bundle. Both helpers are best-effort: any recording,
packaging, or upload failure is logged as a warning and never aborts the
investigation. Upload is skipped when the pipeline is run with `--no-upload`
(FAME/FAST/batch).

---

## 10. Verify the installation

```bash
cd "$INSTALL_DIR"
source .venv/bin/activate

# Vault library round-trips
python3 lib/obsidian_bridge.py
python3 lib/knowledge_extractor.py --test
python3 lib/vault_query.py --search powershell

# MCP server verification (tests each server with a JSON-RPC initialize request)
./scripts/test_mcp_servers.sh

# End-to-end pipeline smoke test (generates a minimal test PCAP, runs full FAN pipeline)
./scripts/test_solution.sh

# With a real PCAP
./scripts/test_solution.sh /path/to/sample.pcap
```

All checks should report `[PASS]`. The smoke test exits 0 on success.

Expected output tail:

```
══ Summary ══
  PASSED: 22
  FAILED:  0
  SKIPPED: 0

End-to-end pipeline: PASS
```

If any check reports `[FAIL]`, see [Section 16 — Troubleshooting](#16-troubleshooting).

### Verify the audit trail and report outputs

After the first real (or test) investigation, confirm the trust artifacts were produced — these are
what make the platform's findings auditable:

```bash
ls reports/                                   # expect <case_id>_research_notes.md + <case_id>_*_report.{md,pdf,pptx,docx}
ls reports/<case_id>_evidence/                # preserved raw artifacts (with SHA-256) per step
grep -c '^### \[' reports/<case_id>_research_notes.md   # number of logged steps/events — should be > 0
grep -n 'Confidence & gaps' reports/<case_id>_fame_report.md   # the confidence/gaps section is present
```

`reports/` and its `<case_id>_evidence/` subfolders are intentionally **git-ignored** — research
notes and raw evidence excerpts are never committed to the repository. Back them up via the
investigations vault (Section 14), not via git.

---

## 11. First investigation

```bash
cd "$INSTALL_DIR"

# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001
```

The report lands in `~/cases/FAN-2026-001/reports/` on ubuntudesktop once the investigation completes. All WIP files in `./analysis/` are deleted automatically.

---

## 12. Security hardening

### File permissions

```bash
# Restrict credentials file
chmod 600 ~/.soc_env

# Restrict SSH private key (required by ssh; it refuses to use world-readable keys)
chmod 600 ~/.ssh/id_ed25519

# Restrict case and evidence directories
chmod 750 ~/evidence ~/cases

# Project directory: writable by service account only
chmod 750 "$INSTALL_DIR"
```

### Network isolation

- Allow only outbound HTTPS to the services listed in [Section 1](#1-server-requirements).
- Do not expose the evidence and investigations directories over a network share without authentication.
- If OpenCTI runs on the same host, bind it to `127.0.0.1` only (`--port 8080 --host 127.0.0.1` in the OpenCTI configuration).

### Credentials hygiene

- Never commit `~/.soc_env` to version control. Add it to `.gitignore` explicitly.
- Rotate API keys quarterly or when a team member leaves.
- The `OPENCTI_API_KEY` must belong to a dedicated service account in OpenCTI, not a personal user account. Personal accounts can be disabled; a service account persists independently.

### Sudoers scope

`setup_sudoers.sh` grants NOPASSWD access only to the specific binaries that require it (currently `suricata-update`). It does not grant unrestricted sudo. Review `/etc/sudoers.d/fangetfamefast` after install to confirm the scope.

### Suricata rule updates

Emerging Threats rules change frequently. Automate weekly updates via cron:

```bash
# Add to crontab (weekly, Sunday 02:00)
(crontab -l 2>/dev/null; echo "0 2 * * 0 $INSTALL_DIR/scripts/update_suricata_rules.sh --et-only >> /var/log/suricata_update.log 2>&1") | crontab -
```

### Dependency inventory (SBOM)

A CycloneDX 1.5 Software Bill of Materials for the Python dependency set is checked in at
[`sbom.json`](../sbom.json), with a human-readable summary in [`sbom.md`](../sbom.md). Regenerate it
after any change to `requirements.txt` or a dependency upgrade:

```bash
python3 scripts/generate_sbom.py            # rewrite sbom.json + sbom.md
python3 scripts/generate_sbom.py --check    # CI gate: non-zero exit if stale
```

The generator resolves each declared dependency to the concrete installed version and SPDX license.
Note the copyleft components flagged in `sbom.md` — `sslyze` and `memprocfs` (AGPL-3.0), `CairoSVG`
(LGPL-3.0), and `volatility3` (VSL) — when redistributing a combined work; they are invoked as
separate tools / optional modules, not statically linked into the Apache-2.0/MIT core.

---

## 13. Architectural guardrails (deployer's view)

The platform's security boundaries are enforced in code, at the server and kernel level — not in the
agent's prompt. As a deployer you do not configure these; they are structural. This section
documents where they live so you can audit them and explain them to a security reviewer. The full
technical treatment is [Technical Reference §11.3](TECHNICAL_REFERENCE.md#113-architectural-guardrails);
the diagram is [Architecture §5](ARCHITECTURE_DIAGRAM.md#5-architectural-guardrails).

| Guardrail | What it enforces | Where | How to verify |
|-----------|------------------|-------|---------------|
| **Evidence MCP server is read-only** | Claude cannot modify evidence through MCP | `mcp/evidence_server.py` defines only read tools — no write handler exists | `grep -i "write\|delete\|mkdir" mcp/evidence_server.py` returns no tool handlers |
| **MCP path jail** | No access outside the evidence / cases root, including `../` traversal and sibling-prefix escape (e.g. `evidence_exfil`) | `_safe_path()` in both file servers resolves to an absolute path and tests containment with `Path.is_relative_to(root)` (not a string prefix) | `grep -n "is_relative_to" mcp/evidence_server.py mcp/investigations_server.py` |
| **Read-only evidence mounts** | The original disk/memory image is never altered, even by a pipeline bug | `mount -o ro,loop,norecovery` in `fast_analyze.sh`, verified by `fgff_assert_ro_mount` (`scripts/pathguard.sh`) before analysis runs; Volatility 3 / YARA open images read-only | inspect the `mount` invocation in `scripts/fast_analyze.sh`; `bash -c 'source scripts/pathguard.sh; fgff_assert_ro_mount /'` aborts (rw) |
| **Library write-path policy** | No library code can write a report or note into evidence, `/mnt`, `/media`, or outside the approved output folders — even via a buggy `--output-dir` | `lib/path_guard.py` hard-fails (`WritePolicyError`); wired into `obsidian_bridge`, `md_to_pdf`, every `generate_*` generator, `chat_recorder`, `case_packager`; `investigations_server._assert_writable` rejects the same roots over MCP | `python3 lib/path_guard.py --test` |
| **Case ID validation** | An analyst- or manifest-supplied `case_id` cannot traverse out of the output/cases root (e.g. `../../tmp/x`) into `mkdir`/`rsync`/`zip`/`rmtree` | restricted to `[A-Za-z0-9._-]{1,64}`: `validate_case_id()` in `lib/case_manager.py` (gates `case_dir`/`archive`/`remove`), `fgff_validate_case_id` in `scripts/pathguard.sh` (called by all three analyze scripts) | `python3 -c "import sys;sys.path.insert(0,'lib');from case_manager import validate_case_id as v;v('../../etc')"` raises `ValueError` |
| **Prompt-injection path whitelist** | A hostile evidence filename — *or a crafted sub-directory name inside an extracted archive* — cannot inject instructions into the agentic prompt | `batch_agentic.sh` skips any basename outside `[[:alnum:][:space:]._-]` **and** any full path containing characters outside `[[:alnum:][:space:]./_-]`, logging both | `grep -n "unsafe characters\|unsafe characters in path" scripts/batch_agentic.sh` |
| **Report renderer resource isolation** | Attacker-influenced evidence text in a report cannot cause the PDF renderer to read local files (`file://`) or make outbound requests (SSRF) | `md_to_pdf.safe_url_fetcher` restricts WeasyPrint to inline `data:` URIs and an allowlist of web-font hosts; used by `md_to_pdf` and the `generate_pcap_report` fallback | `grep -n "safe_url_fetcher" lib/md_to_pdf.py lib/generate_pcap_report.py` |
| **SSH host-key verification** | Report/evidence uploads to the investigations vault reject a *changed* host key (MITM), rather than blindly trusting any key | `StrictHostKeyChecking=accept-new` in `lib/investigations_upload.py` and `lib/case_packager.py` (trust-on-first-use, reject-on-change) | `grep -n "StrictHostKeyChecking" lib/investigations_upload.py lib/case_packager.py` |
| **IOC defanging** | Live indicators never leak to the vault or to Perplexity | values are defanged before any vault write or external call | inspect `record_ioc` / `_refang` in `lib/vault_writer.py` |
| **No daemon / explicit start** | No un-audited automated evidence processing — chain of custody requires every action be deliberate | there is no file watcher; every investigation starts with an analyst command | — |

These boundaries hold regardless of what the agent is asked to do. A path-traversal request raises
`ValueError` at the server; an evidence write has no code path to execute; the kernel enforces the
read-only mount; a library write outside the approved folders raises `WritePolicyError` before any
bytes are written. When briefing a security reviewer, this table is the answer to *"are the guardrails
architectural or prompt-based?"* — they are architectural.

---

## 14. Backup and recovery

### What to back up

| Path | Frequency | Notes |
|------|-----------|-------|
| `~/cases/` | Daily | Investigation reports — primary deliverable |
| `$INSTALL_DIR/vault/` | Daily | Obsidian knowledge graph — accumulated TTPs, IOCs, threat actors |
| `$INSTALL_DIR/rules/suricata/local.rules` | On change | Custom detection rules (ET Open rules are re-downloadable) |
| `$INSTALL_DIR/rules/yara/` | On change | Custom YARA rules |
| `~/.soc_env` | On change | Encrypted backup only — contains API keys and credentials |

### What not to back up

- `$INSTALL_DIR/analysis/` — always empty after a completed investigation
- `$INSTALL_DIR/.venv/` — reproducible from `requirements.txt`
- Downloaded ET Open rules — re-downloadable at any time

### Minimal backup script

```bash
#!/usr/bin/env bash
BACKUP_ROOT="/mnt/backup/$(date +%Y-%m-%d)"
INSTALL_DIR="$HOME/Documents/FanGetFameFast"

mkdir -p "$BACKUP_ROOT"
rsync -a --exclude='.venv' --exclude='analysis' "$INSTALL_DIR/" "$BACKUP_ROOT/project/"
rsync -a "$HOME/cases/"    "$BACKUP_ROOT/cases/"
```

### Recovery

```bash
# Restore project files
rsync -a /mnt/backup/2026-05-01/project/ "$INSTALL_DIR/"

# Restore cases
rsync -a /mnt/backup/2026-05-01/cases/ ~/cases/

# Rebuild virtual environment
cd "$INSTALL_DIR"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 15. Upgrading

```bash
cd "$INSTALL_DIR"

# Pull latest code
git pull

# Re-run dependency installer (all steps are idempotent)
bash scripts/install_dependencies.sh

# Update Python packages
source .venv/bin/activate
pip install --upgrade -r requirements.txt
deactivate

# Update Suricata rules
./scripts/update_suricata_rules.sh --et-only

# Run smoke test to confirm nothing broke
./scripts/test_solution.sh
```

Vault template changes in a new release are additive. The setup script adds new templates without overwriting existing notes. New investigation records remain compatible with old vault notes.

---

## 16. Troubleshooting

### tshark fails with permission denied

Symptom: `Running as user "root" and group "root"` or silent empty output.

The current user is not in the `wireshark` group, or the group change has not taken effect in the current shell.

```bash
sudo usermod -aG wireshark "$(whoami)"
newgrp wireshark   # or log out and back in
```

### PDF generation fails (WeasyPrint)

Symptom: `OSError: no library called "cairo" was found`

```bash
sudo apt-get install -y libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    fonts-liberation fonts-dejavu-core
```

### Suricata reports "No rule files found"

```bash
./scripts/update_suricata_rules.sh --et-only
```

If that fails with a network error, download the ruleset manually:

```bash
curl -Lo /tmp/et-open.rules.tar.gz \
    https://rules.emergingthreats.net/open/suricata-6.0/emerging.rules.tar.gz
tar -xzf /tmp/et-open.rules.tar.gz -C rules/suricata/
```

### suricata-update prompts for a password during the pipeline

`setup_sudoers.sh` has not been run, or the binary path it captured no longer matches the installed binary.

```bash
sudo bash scripts/setup_sudoers.sh
sudo -n suricata-update --no-reload   # should succeed without a prompt
```

### Perplexity API returns 401

`PERPLEXITY_API_KEY` is not set or is incorrect.

```bash
echo $PERPLEXITY_API_KEY   # must not be empty
source ~/.soc_env
```

### OpenCTI MCP server fails to start

`OPENCTI_URL` and `OPENCTI_API_KEY` must be exported before launching Claude Code:

```bash
source ~/.soc_env
claude
```

Verify OpenCTI connectivity independently:

```bash
curl -s -H "Authorization: Bearer $OPENCTI_API_KEY" \
    "$OPENCTI_URL/graphql" -d '{"query":"{me{name}}"}' | jq .
```

### Report upload fails (SSH/SCP error)

The SSH key at `~/.ssh/id_ed25519` is not authorized on ubuntudesktop, or the `known_hosts` file does not have an entry for ubuntudesktop.

```bash
ssh-keyscan -H ubuntudesktop >> ~/.ssh/known_hosts
ssh-copy-id -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop
ssh -i ~/.ssh/id_ed25519 sansforensics@ubuntudesktop "echo OK"
```

If the investigation was interrupted after analysis but before upload, the report files are still in `./analysis/_reports/<stem>/`. Re-run the upload manually:

```bash
python3 lib/investigations_upload.py \
    --case-id FAN-2026-001 \
    --md  ./analysis/_reports/<stem>/<stem>_incident_report.md \
    --pdf ./analysis/_reports/<stem>/<stem>_incident_report.pdf
```

### MCP absolute paths break after moving the project

Re-run the folder structure setup script. It regenerates `settings.json` with the new paths:

```bash
bash scripts/setup_folder_structure.sh
```

### Autopsy headless run fails silently

Check `./exports/autopsy/autopsy.log`. Common causes:

- Java not installed: `sudo apt-get install -y default-jre`
- Autopsy < 4.17 does not support `--nogui`. Upgrade to a current release.
- Insufficient heap: Autopsy needs at least 2 GB. Edit the Autopsy launcher script and add `-Xmx2g` to the JVM arguments.

If headless mode is unavailable, run Autopsy manually, save the case to `./exports/autopsy/case/`, and the FAST report generator picks up the exported CSVs.

### AutoTimeliner fails with "No module named 'volatility3'"

AutoTimeliner requires Volatility 3 to be importable as a Python module:

```bash
export PYTHONPATH="/opt/volatility3-2.20.0:$PYTHONPATH"
```

Add that line to `~/.soc_env` so it persists across sessions.

### EVTXtract produces an empty XML file

The memory image may contain no intact EVTX log records. This is expected for heavily fragmented images or Linux memory dumps. Check the EVTXtract log:

```bash
cat ./analysis/memory/evtxtract/evtxtract.log
```

### MemProcFS fails to initialize

MemProcFS requires the LeechCore driver to be loadable. On headless servers without `/dev/mem` access, it may fail to initialize. Check:

```bash
python3 -c "import memprocfs; print('OK')"
```

If the import succeeds but initialization fails, the error details appear in `./analysis/memory/memprocfs/memprocfs_error.json`. When MemProcFS cannot initialize, `fame_memprocfs.py` records the failure and returns without raising an exception; the FAME pipeline continues.

---

## 17. License and disclaimer

Fan Get Fame Fast is released under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full terms.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Use at your own risk. Deploy only in environments you own or have explicit written authorization to administer.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman — June 2026 — v2.0*
