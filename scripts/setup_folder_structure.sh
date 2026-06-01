#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# =============================================================================
# setup_folder_structure.sh — FanGetFameFast folder structure initialiser
#
# Creates all required directories, seeds the Obsidian vault with templates
# and a starter Dashboard, writes stub rule files, and sets permissions.
# Safe to re-run: never overwrites existing content.
#
# Usage:
#   bash scripts/setup_folder_structure.sh
#   bash scripts/setup_folder_structure.sh --cases-root /opt/soc/cases
#   bash scripts/setup_folder_structure.sh --skip-vault
#   bash scripts/setup_folder_structure.sh --help
# =============================================================================

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# ── Colour helpers ────────────────────────────────────────────────────────────
C_CYAN='\033[0;36m'; C_GREEN='\033[0;32m'; C_YELLOW='\033[1;33m'
C_BOLD='\033[1m'; C_RESET='\033[0m'
TICK="${C_GREEN}✓${C_RESET}"; SKIP="${C_YELLOW}–${C_RESET}"
section() { echo ""; echo -e "${C_BOLD}${C_CYAN}══════  $*  ══════${C_RESET}"; }
made()    { echo -e "  ${TICK} created  $*"; }
exists()  { echo -e "  ${SKIP} exists   $*"; }
ok()      { echo -e "  ${TICK} $*"; }

# ── Argument defaults ─────────────────────────────────────────────────────────
# Default layout mirrors the MCP server defaults:
#   ~/evidence  — PCAP drop zone (evidence MCP server)
#   ~/cases     — investigation reports (investigations MCP server)
HOME_DIR="${HOME:-$(eval echo ~"$(whoami)")}"
EVIDENCE_DIR="${HOME_DIR}/evidence"
CASES_DIR="${HOME_DIR}/cases"
SKIP_VAULT=0

for arg in "$@"; do
    case "$arg" in
        --evidence-dir=*) EVIDENCE_DIR="${arg#*=}" ;;
        --cases-dir=*)    CASES_DIR="${arg#*=}" ;;
        --skip-vault)     SKIP_VAULT=1 ;;
        --help|-h)
            echo "Usage: $0 [--evidence-dir PATH] [--cases-dir PATH] [--skip-vault]"
            echo "  --evidence-dir PATH  PCAP drop zone (default: ~/evidence)"
            echo "  --cases-dir PATH     Investigation reports root (default: ~/cases)"
            echo "  --skip-vault         Skip Obsidian vault initialisation"
            exit 0 ;;
    esac
done

# ── Helper: create directory if missing ──────────────────────────────────────
mkd() {
    local dir="$1"
    if [[ -d "$dir" ]]; then
        exists "$dir"
    else
        mkdir -p "$dir"
        made "$dir"
    fi
}

# ── Helper: write file only if missing ───────────────────────────────────────
mkf() {
    local path="$1"; shift
    if [[ -f "$path" ]]; then
        exists "$path"
    else
        cat > "$path"
        made "$path"
    fi
}

# ── 1. Evidence and investigations directories ────────────────────────────────
section "Case evidence and investigations directories"

echo "  Evidence drop zone:     ${EVIDENCE_DIR}"
echo "  Investigations vault:   ${CASES_DIR}"

for target_dir in "$EVIDENCE_DIR" "$CASES_DIR"; do
    parent="$(dirname "$target_dir")"
    if [[ ! -w "$parent" ]]; then
        echo "  Requesting sudo to create ${target_dir} …"
        sudo mkdir -p "$target_dir"
        sudo chown "$(id -un)":"$(id -gn)" "$target_dir"
        made "$target_dir"
    else
        mkd "$target_dir"
    fi
done

# Sentinel file to flag a directory as readable by the evidence MCP server
mkf "${EVIDENCE_DIR}/.gitkeep" <<'EOF'
EOF

# ── 2. Project-local case directory (manual / local analysis) ─────────────────
section "Project case directories"

mkd "${PROJECT_ROOT}/cases"

# ── 3. Analysis output directories ───────────────────────────────────────────
section "Analysis output directories"

ANALYSIS_MODULES=(
    pcap
    dns_threats
    http_threats
    tls_inspector
    cert_inspector
    arp_threats
    tcp_threats
    udp_threats
    icmp_threats
    ntp_threats
    dhcp_threats
    mdns_threats
    quic_threats
    file_hashes
    suricata
    yara_pcap
    cti
)

for mod in "${ANALYSIS_MODULES[@]}"; do
    mkd "${PROJECT_ROOT}/analysis/${mod}"
done

# ── 4. Reports directories ────────────────────────────────────────────────────
section "Reports directories"

mkd "${PROJECT_ROOT}/reports"
mkd "${PROJECT_ROOT}/reports/soc"
mkd "${PROJECT_ROOT}/reports/soc/handover"
mkd "${PROJECT_ROOT}/reports/soc/weekly"
mkd "${PROJECT_ROOT}/reports/soc/monthly"
mkd "${PROJECT_ROOT}/reports/cti"

# ── 5. Rules directories ──────────────────────────────────────────────────────
section "IDS and YARA rules directories"

mkd "${PROJECT_ROOT}/rules"
mkd "${PROJECT_ROOT}/rules/suricata"
mkd "${PROJECT_ROOT}/rules/yara"

# Stub local Suricata rules file
mkf "${PROJECT_ROOT}/rules/suricata/local.rules" <<'SURICATA_EOF'
# local.rules — Site-specific Suricata detection rules
#
# Add your custom rules here. This file is never overwritten by update scripts.
#
# Example:
# alert dns any any -> any any (msg:"SOC - Suspicious DGA domain"; dns.query; content:".tk"; classtype:trojan-activity; sid:9000001; rev:1;)
# alert http any any -> any any (msg:"SOC - C2 beacon user-agent"; http.user_agent; content:"libcurl"; classtype:trojan-activity; sid:9000002; rev:1;)
SURICATA_EOF

# ── 6. Playbooks directory ────────────────────────────────────────────────────
section "Playbooks directory"

mkd "${PROJECT_ROOT}/playbooks"

# ── 7. Exports directory ──────────────────────────────────────────────────────
section "Exports directory"

mkd "${PROJECT_ROOT}/exports"

# ── 8. Obsidian vault ────────────────────────────────────────────────────────
section "Obsidian vault"

if [[ $SKIP_VAULT -eq 1 ]]; then
    echo -e "  ${C_YELLOW}[!]${C_RESET} Skipping vault initialisation (--skip-vault)"
else
    VAULT="${PROJECT_ROOT}/vault"

    mkd "${VAULT}"
    mkd "${VAULT}/IOCs"
    mkd "${VAULT}/TTPs"
    mkd "${VAULT}/ThreatActors"
    mkd "${VAULT}/Malware"
    mkd "${VAULT}/Concepts"
    mkd "${VAULT}/Risks"
    mkd "${VAULT}/Cases"
    mkd "${VAULT}/Templates"

    # ── Vault templates ────────────────────────────────────────────────────
    section "Vault templates"

    mkf "${VAULT}/Templates/IOC.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
ioc_type:
value:
severity: medium
tags: [ioc]
case_refs: []
related_ttps: []
related_actors: []
related_malware: []
disposition: unknown
---
## Context

## Observations

## Disposition
EOF

    mkf "${VAULT}/Templates/TTP.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
mitre_id:
technique_name:
tactic:
severity: medium
tags: [ttp]
case_refs: []
related_actors: []
related_malware: []
related_iocs: []
---
## Summary

## Observed Evidence

## Mitigations

## References
EOF

    mkf "${VAULT}/Templates/ThreatActor.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
aliases: []
motivation:
origin:
tags: [threat-actor]
case_refs: []
observed_ttps: []
known_malware: []
known_iocs: []
---
## Profile

## Observed TTPs

## Known Infrastructure

## Campaign History
EOF

    mkf "${VAULT}/Templates/Malware.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
family:
type:
tags: [malware]
case_refs: []
related_actors: []
related_ttps: []
known_hashes: []
---
## Description

## Behavior

## Indicators

## Capabilities
EOF

    mkf "${VAULT}/Templates/Risk.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
case_ref:
asset:
severity: medium
likelihood: medium
status: open
tags: [risk]
related_ttps: []
---
## Risk Description

## Impact

## Likelihood Rationale

## Recommended Mitigations

## Accepted / Resolved
EOF

    mkf "${VAULT}/Templates/Concept.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
tags: [concept]
related_ttps: []
related_concepts: []
---
## Definition

## How It Works

## Defensive Relevance

## Examples Observed
EOF

    mkf "${VAULT}/Templates/Case.md" <<'EOF'
---
date_created: {{date}}
date_updated: {{date}}
case_id:
status: open
severity:
tags: [case]
ttps_observed: []
iocs_found: []
actors_suspected: []
---
## Summary

## Timeline

## Findings

## Artifacts Examined
*Note: artifact paths are omitted — see case directory for raw evidence*

## Recommendations
EOF

    # ── Dashboard ──────────────────────────────────────────────────────────
    section "Vault Dashboard"

    mkf "${VAULT}/Dashboard.md" <<EOF
---
date_updated: '$(date -u +%Y-%m-%dT%H:%M:%SZ)'
tags:
- dashboard
---

# SOC Knowledge Dashboard

This note is maintained automatically by \`lib/knowledge_extractor.py\`. Do not edit by hand.

---

## Active Cases

<!-- AUTO:CASES -->
*(no cases yet)*
<!-- /AUTO:CASES -->

---

## Recent IOCs

<!-- AUTO:IOCS -->
*(no IOCs yet)*
<!-- /AUTO:IOCS -->

---

## Recent TTPs

<!-- AUTO:TTPS -->
*(no TTPs yet)*
<!-- /AUTO:TTPS -->

---

## Threat Actors

<!-- AUTO:ACTORS -->
*(no actors yet)*
<!-- /AUTO:ACTORS -->

---

## Open Risks

<!-- AUTO:RISKS -->
*(no risks yet)*
<!-- /AUTO:RISKS -->
EOF

fi  # end SKIP_VAULT

# ── 10. .claude settings scaffold ────────────────────────────────────────────
section ".claude configuration"

mkd "${PROJECT_ROOT}/.claude"

cat > "${PROJECT_ROOT}/.claude/settings.json" <<EOF
{
  "autoMemoryEnabled": true,
  "mcpServers": {
    "evidence": {
      "command": "python3",
      "args": ["${PROJECT_ROOT}/mcp/evidence_server.py"],
      "env": {
        "EVIDENCE_ROOT": "${EVIDENCE_DIR}"
      }
    },
    "investigations": {
      "command": "python3",
      "args": ["${PROJECT_ROOT}/mcp/investigations_server.py"],
      "env": {
        "INVESTIGATIONS_ROOT": "${CASES_DIR}"
      }
    },
    "opencti": {
      "command": "python3",
      "args": ["${PROJECT_ROOT}/mcp/opencti_server.py"]
    }
  }
}
EOF
made "${PROJECT_ROOT}/.claude/settings.json"

# ── 11. Permissions ───────────────────────────────────────────────────────────
section "Permissions"

# All scripts must be executable
find "${PROJECT_ROOT}/scripts" -name "*.sh" -o -name "*.py" | \
    xargs chmod +x 2>/dev/null || true

# Case directories — accessible by service account only
chmod 700 "${PROJECT_ROOT}/cases" 2>/dev/null || true
chmod 750 "$EVIDENCE_DIR" 2>/dev/null || true
chmod 750 "$CASES_DIR" 2>/dev/null || true

ok "Permissions set"

# ── 12. Summary ───────────────────────────────────────────────────────────────
section "Structure summary"

echo ""
echo -e "${C_BOLD}Project root:${C_RESET}         ${PROJECT_ROOT}"
echo -e "${C_BOLD}Evidence drop zone:${C_RESET}   ${EVIDENCE_DIR}"
echo -e "${C_BOLD}Investigations vault:${C_RESET} ${CASES_DIR}"
echo -e "${C_BOLD}Local cases:${C_RESET}          ${PROJECT_ROOT}/cases"
echo -e "${C_BOLD}Obsidian vault:${C_RESET}       ${PROJECT_ROOT}/vault"
echo -e "${C_BOLD}Suricata rules:${C_RESET}       ${PROJECT_ROOT}/rules/suricata"
echo -e "${C_BOLD}YARA rules:${C_RESET}           ${PROJECT_ROOT}/rules/yara"
echo -e "${C_BOLD}Reports:${C_RESET}              ${PROJECT_ROOT}/reports"
echo -e "${C_BOLD}Playbooks:${C_RESET}            ${PROJECT_ROOT}/playbooks"
echo -e "${C_BOLD}MCP config:${C_RESET}           ${PROJECT_ROOT}/.claude/settings.json"
echo ""
echo -e "${C_GREEN}${C_BOLD}Folder structure ready.${C_RESET}"
echo ""
echo "Next:"
echo "  1. Edit .claude/settings.json — fill in Sentinel and OpenCTI credentials"
echo "  2. Set PERPLEXITY_API_KEY in ~/.bashrc"
echo "  3. Run: ./scripts/update_suricata_rules.sh"
echo "  4. Run: ./scripts/test_solution.sh"
