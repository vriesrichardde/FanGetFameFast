#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# perplexity_search.sh — real-time cybersecurity research via Perplexity.ai
#
# Usage:
#   perplexity_search.sh ioc     <value>          # IP, domain, hash, URL
#   perplexity_search.sh malware <family>          # malware family profile
#   perplexity_search.sh ttp     <MITRE_ID>        # ATT&CK technique details
#   perplexity_search.sh cve     <CVE-ID>          # vulnerability details
#   perplexity_search.sh actor   <name>            # threat actor profile
#   perplexity_search.sh tool    <name>            # unknown tool/utility
#   perplexity_search.sh search  <free query>      # general research
#
# Options:
#   --save-vault     Also save result as a Concept note in the Obsidian vault
#   --no-citations   Suppress source URLs in output
#   --model <name>   Override model (sonar | sonar-pro | sonar-reasoning | sonar-reasoning-pro)
#
# Requires: PERPLEXITY_API_KEY environment variable

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
CLIENT="$PROJECT_ROOT/lib/perplexity_client.py"

if [[ -z "${PERPLEXITY_API_KEY:-}" ]]; then
    echo "[perplexity] ERROR: PERPLEXITY_API_KEY is not set." >&2
    echo "  Add to ~/.bashrc:  export PERPLEXITY_API_KEY='pplx-...'" >&2
    echo "  Then reload:       source ~/.bashrc" >&2
    exit 1
fi

if [[ $# -eq 0 ]]; then
    python3 "$CLIENT" --help
    exit 0
fi

exec python3 "$CLIENT" "$@"
