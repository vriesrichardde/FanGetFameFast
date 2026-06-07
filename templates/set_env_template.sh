#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
# set_env_template.sh — Environment variable template for SOC tooling
#
# USAGE:
#   cp templates/set_env_template.sh ~/.soc_env
#   Fill in real values in ~/.soc_env
#   Add to ~/.bashrc:  source ~/.soc_env
#
# This file contains only placeholder values — never commit real credentials.

# ── OpenCTI MCP ──────────────────────────────────────────────────────────────
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_API_KEY="your-opencti-api-key"

# ── Perplexity (live threat intel) ───────────────────────────────────────────
export PERPLEXITY_API_KEY="pplx-..."

# ── Devcontainer evidence mount (optional) ────────────────────────────────────
# Local directory containing memory images (.mem, .raw, .vmem) and disk images
# (.E01, .vmdk, .dd). Mounted read-only at /home/vscode/evidence inside the
# container. Set this before building/rebuilding the devcontainer to expose your
# evidence. If left unset, the container still builds and the mount falls back to
# a harmless placeholder (see .devcontainer/devcontainer.json).
export FGFF_EVIDENCE_INPUT="/path/to/your/evidence"
