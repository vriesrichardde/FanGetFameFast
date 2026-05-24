# FanGetFameFast — Production deployment guide

**Version:** 1.1 · May 2026  
**Platform:** Ubuntu 24.04 LTS (x86-64)  
**Classification:** Internal — SOC Operations

---

## Table of contents

1. [Server requirements](#1-server-requirements)
2. [Service account setup](#2-service-account-setup)
3. [Install the codebase](#3-install-the-codebase)
4. [Install system dependencies](#4-install-system-dependencies)
5. [Create the folder structure](#5-create-the-folder-structure)
6. [Configure API credentials](#6-configure-api-credentials)
7. [Configure MCP servers](#7-configure-mcp-servers)
8. [Verify the installation](#8-verify-the-installation)
9. [First investigation](#9-first-investigation)
10. [Security hardening](#10-security-hardening)
11. [Backup and recovery](#11-backup-and-recovery)
12. [Upgrading](#12-upgrading)
13. [Troubleshooting](#13-troubleshooting)
14. [License and disclaimer](#14-license-and-disclaimer)

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

### Required external access

| Destination | Protocol | Purpose |
|-------------|----------|---------|
| `api.perplexity.ai` | HTTPS/443 | Live threat intel |
| `rules.emergingthreats.net` | HTTPS/443 | Suricata ET Open rules |
| `packages.microsoft.com` | HTTPS/443 | .NET runtime |
| `ppa.launchpad.net` | HTTPS/443 | Suricata PPA |
| `pypi.org` | HTTPS/443 | Python packages |
| Your OpenCTI instance | HTTP/HTTPS | CTI lookups (local or remote) |

---

## 2. Service account setup

Run as a dedicated service account, not as root.

```bash
# Create the service account
sudo useradd --create-home --shell /bin/bash --groups wireshark soc-analyst

# If the wireshark group does not exist yet, the install script creates it.
# Re-run the usermod command after running install_dependencies.sh in that case.

# Switch to the service account for all remaining steps
sudo su - soc-analyst
```

If you are deploying on an existing account, the installer adds it to the `wireshark` group. A logout/login is required for that group change to take effect.

---

## 3. Install the codebase

```bash
# Choose your installation directory
INSTALL_DIR="$HOME/Documents/FanGetFameFast"

# Clone or copy the repository
git clone <repo-url> "$INSTALL_DIR"
# Or copy from a portable archive:
# tar -xzf FanGetFameFast.tar.gz -C "$HOME/Documents/"

cd "$INSTALL_DIR"
```

The project must live in a user-writable directory. `/opt/` works if ownership is set correctly.

---

## 4. Install system dependencies

```bash
cd "$INSTALL_DIR"

# Full install (recommended)
bash scripts/install_dependencies.sh

# Skip optional components
bash scripts/install_dependencies.sh --skip-suricata   # no IDS
bash scripts/install_dependencies.sh --skip-yara        # no YARA
bash scripts/install_dependencies.sh --skip-dotnet      # no EZ Tools
```

All steps check existing state before acting, so the script is safe to re-run.

### What gets installed

| Component | Source | Notes |
|-----------|--------|-------|
| tshark / wireshark-common | apt | PCAP parsing |
| Suricata | PPA: oisf/suricata-stable | IDS engine |
| YARA 4.5+ | apt or compiled from source | Signature scanning |
| .NET Runtime 6/8 | Microsoft APT | EZ Tools (FAST module prereq) |
| Python 3.10+ venv | system | Isolated package environment |
| Python packages | pip / requirements.txt | See `requirements.txt` |
| Claude Code CLI | npm | Agentic coordinator UI |
| Suricata ET Open rules | download | Initial ruleset |
| Font packages | apt | PDF report rendering |
| Autopsy | manual / apt | Disk forensics GUI + headless ingest (FAST module) |
| AutoTimeliner | git clone | Memory super-timeline builder (FAME module) |
| EVTXtract | git clone | EVTX recovery from raw binary / memory (FAME module) |

### Optional — Autopsy (FAST module)

Autopsy adds file-type mismatch detection, hash lookup, recent activity parsing, EXIF extraction, and a keyword index on top of the TSK layer.

```bash
# Ubuntu 24.04 — install from apt (if available in your repo)
sudo apt-get install -y autopsy

# Or install the upstream .deb (recommended — keeps autopsy current)
# 1. Download the latest .deb from https://www.autopsy.com/download/
# 2. Install
sudo dpkg -i autopsy-4.x.x-amd64.deb
sudo apt-get install -f    # fix any dependency gaps

# Verify
autopsy --version
```

When `autopsy` is absent from `$PATH`, `fast_analyze.sh` skips the Autopsy step and writes `AUTOPSY_NOT_RUN.txt` to `./exports/autopsy/`. The rest of the FAST pipeline runs normally.

### Optional — AutoTimeliner (FAME module)

AutoTimeliner builds a Volatility-backed MACB super-timeline from a memory image, correlating output from timeliner, pslist, pstree, netstat, and filescan into a single bodyfile.

```bash
git clone https://github.com/andreafortuna/autotimeliner /opt/autotimeliner
pip3 install -r /opt/autotimeliner/requirements.txt
```

When absent, `fame_analyze.sh` skips the super-timeline step and continues.

### Optional — EVTXtract (FAME module)

EVTXtract recovers intact Windows Event Log records from raw binary data by scanning for EVTX record magic bytes and validating checksums. It works on memory images where `filescan` locates `.evtx` files but the records are fragmented across pages.

```bash
git clone https://github.com/williballenthin/EVTXtract /opt/EVTXtract
pip3 install -r /opt/EVTXtract/requirements.txt
```

When absent, `fame_analyze.sh` skips event recovery and continues.

### Post-install — apply group membership

```bash
# Without rebooting
newgrp wireshark
# Or log out and back in
```

---

## 5. Create the folder structure

```bash
cd "$INSTALL_DIR"

# Default layout (~/evidence and ~/cases)
bash scripts/setup_folder_structure.sh

# Custom paths (e.g. separate HDD for evidence)
bash scripts/setup_folder_structure.sh \
    --evidence-dir /mnt/evidence \
    --cases-dir /mnt/cases
```

The script creates:

```
~/evidence/                   # PCAP drop zone (evidence MCP server root)
~/cases/                      # Investigation reports (investigations MCP server root)
$INSTALL_DIR/
  analysis/                   # WIP only; cleared after each investigation
    memory/                   # FAME: Volatility 3 outputs, AutoTimeliner, EVTXtract
    storage/                  # FAST: TSK outputs, mmls, fsstat, bodyfile
  reports/                    # Manual report exports
  rules/suricata/             # Suricata rule files
  rules/yara/                 # YARA rule files
  vault/                      # Obsidian knowledge graph
  vault/Templates/            # Note schemas
  vault/Dashboard.md          # Auto-maintained index
  playbooks/                  # Response playbooks
  exports/                    # Data exports per investigation
    evtx/                     # Extracted Windows Event Logs
    registry/                 # Registry hives (SYSTEM, SOFTWARE, SAM, NTUSER.DAT)
    prefetch/                 # Prefetch files
    mft/                      # $MFT and $J (USN journal)
    srum/                     # SRUM database
    browser/                  # Browser history
    carved/                   # bulk_extractor carving output
    autopsy/                  # Autopsy case and exported artifacts (FAST)
  .claude/settings.json       # MCP server configuration (auto-generated)
```

The generated `settings.json` contains absolute paths pointing to the exact directories chosen. No manual editing is needed unless you change the paths after setup.

---

## 6. Configure API credentials

```bash
# Copy the template
cp scripts/set_env_template.sh ~/.soc_env

# Edit with real values
nano ~/.soc_env
```

Minimum required:

```bash
export PERPLEXITY_API_KEY="pplx-..."
```

For OpenCTI integration (optional but recommended):

```bash
export OPENCTI_URL="http://your-opencti-host:8080"
export OPENCTI_API_KEY="your-api-token"
```

For Microsoft Sentinel integration (optional):

```bash
export SENTINEL_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_CLIENT_SECRET="your-client-secret"
export SENTINEL_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_RESOURCE_GROUP="rg-sentinel"
export SENTINEL_WORKSPACE_NAME="law-sentinel"
export SENTINEL_WORKSPACE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```

Load in the current shell and persist:

```bash
source ~/.soc_env
echo 'source ~/.soc_env' >> ~/.bashrc
```

`~/.soc_env` must be `chmod 600`. The install script does not touch it:

```bash
chmod 600 ~/.soc_env
```

---

## 7. Configure MCP servers

`setup_folder_structure.sh` writes `.claude/settings.json` with the correct absolute paths. Verify it looks right:

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

The MCP servers read their root paths from the `env` block. OpenCTI credentials (`OPENCTI_URL`, `OPENCTI_API_KEY`) come from the shell environment sourced via `~/.soc_env`.

---

## 8. Verify the installation

```bash
cd "$INSTALL_DIR"
source .venv/bin/activate

# Vault library round-trips
python3 lib/obsidian_bridge.py
python3 lib/knowledge_extractor.py --test
python3 lib/vault_query.py --search powershell

# End-to-end pipeline smoke test (generates a minimal test PCAP)
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

---

## 9. First investigation

```bash
cd "$INSTALL_DIR"

# Interactive — prompts for case ID
./scripts/analyze_pcap.sh /path/to/capture.pcap

# Non-interactive
./scripts/analyze_pcap.sh /path/to/capture.pcap --case-id FAN-2026-001
```

The report lands in `~/cases/FAN-2026-001/reports/` once the investigation completes. All WIP files in `./analysis/` are deleted automatically.

---

## 10. Security hardening

### File permissions

```bash
# Restrict credentials file
chmod 600 ~/.soc_env

# Restrict case and evidence directories
chmod 750 ~/evidence ~/cases

# Project directory: writable by service account only
chmod 750 "$INSTALL_DIR"
```

### Network isolation

- Allow only outbound HTTPS to the services listed in [Section 1](#1-server-requirements).
- Do not expose the evidence and investigations directories over a network share without authentication.
- If OpenCTI runs on the same host, bind it to `127.0.0.1` only.

### Credentials hygiene

- Never commit `~/.soc_env` to version control.
- Rotate API keys quarterly or when a team member leaves.
- The `OPENCTI_API_KEY` should belong to a dedicated service account in OpenCTI, not a personal user account.

### Suricata rule updates

Emerging Threats rules change frequently. Automate weekly updates:

```bash
# Add to crontab (weekly, Sunday 02:00)
echo "0 2 * * 0 $INSTALL_DIR/scripts/update_suricata_rules.sh --et-only >> /var/log/suricata_update.log 2>&1" \
    | crontab -
```

---

## 11. Backup and recovery

### What to back up

| Path | Frequency | Notes |
|------|-----------|-------|
| `~/cases/` | Daily | Investigation reports — primary deliverable |
| `$INSTALL_DIR/vault/` | Daily | Obsidian knowledge graph — accumulated TTPs, IOCs, threat actors |
| `$INSTALL_DIR/rules/suricata/local.rules` | On change | Custom detection rules |
| `$INSTALL_DIR/rules/yara/` | On change | YARA rules |
| `~/.soc_env` | On change | Encrypted backup only (contains secrets) |

### What not to back up

- `$INSTALL_DIR/analysis/` — always empty after a completed investigation
- `$INSTALL_DIR/.venv/` — reproducible from `requirements.txt`
- Downloaded ET Open rules — re-downloadable

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
# Restore project
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

## 12. Upgrading

```bash
cd "$INSTALL_DIR"

# Pull latest code
git pull

# Re-run dependency installer (idempotent)
bash scripts/install_dependencies.sh

# Update Python packages
source .venv/bin/activate
pip install --upgrade -r requirements.txt
deactivate

# Update Suricata rules
./scripts/update_suricata_rules.sh --et-only

# Run smoke test to confirm
./scripts/test_solution.sh
```

Vault template changes in a new release are additive. The setup script adds new templates without overwriting existing notes.

---

## 13. Troubleshooting

### tshark fails with permission denied

```
Running as user "root" and group "root"
```

The current user is not in the `wireshark` group, or the group change has not taken effect.

```bash
sudo usermod -aG wireshark "$(whoami)"
newgrp wireshark   # or log out and back in
```

### PDF generation fails (WeasyPrint)

```
OSError: no library called "cairo" was found
```

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

Verify connectivity:

```bash
curl -s -H "Authorization: Bearer $OPENCTI_API_KEY" \
    "$OPENCTI_URL/graphql" -d '{"query":"{me{name}}"}' | jq .
```

### MCP absolute paths break after moving the project

Re-run the folder structure setup script. It regenerates `settings.json` with the new paths:

```bash
bash scripts/setup_folder_structure.sh
```

### Autopsy headless run fails silently

Check `./exports/autopsy/autopsy.log`. Common causes:

- Java not installed: `sudo apt-get install -y default-jre`
- Autopsy < 4.17 does not support `--nogui`. Upgrade to a current version.
- Insufficient memory: Autopsy needs at least 2 GB heap. Add `-Xmx2g` to the Autopsy launcher script.

If headless mode is unavailable, run Autopsy manually, save the case to `./exports/autopsy/case/`, and the report generator picks up the exported CSVs.

### AutoTimeliner fails with "No module named 'volatility3'"

AutoTimeliner requires Volatility 3 to be importable as a Python module:

```bash
export PYTHONPATH="/opt/volatility3-2.20.0:$PYTHONPATH"
```

Add that line to `~/.soc_env`.

### EVTXtract produces an empty XML file

The memory image may contain no intact EVTX log records. This is expected for heavily fragmented images or Linux memory dumps. Check the log:

```bash
cat ./analysis/memory/evtxtract/evtxtract.log
```

---

## 14. License and disclaimer

Fan Get Fame Fast is released under the Apache License, Version 2.0. See [LICENSE](../LICENSE) for the full terms.

This software is provided on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND. Use at your own risk. Deploy only in environments you own or have explicit written authorization to administer.

See [DISCLAIMER.md](../DISCLAIMER.md) for the full disclaimer.

---

*Richard de Vries · May 2026*
