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
# container. Unlike the variables above, EVIDENCE_PATH must be set on the
# HOST shell that launches VS Code (not just inside the container's ~/.soc_env),
# before "Reopen in Container". Use the helper, which also persists it to
# ~/.bashrc on the host:
#   ./scripts/ensure_evidence_path.sh /path/to/your/evidence
# If left unset, EVIDENCE_PATH falls back to /tmp and the container still
# builds with a harmless placeholder mount (see .devcontainer/devcontainer.json).

# ── Investigations vault (report upload destination) ──────────────────────────
# Where finalized reports are uploaded via SSH/SCP at the end of every
# FAN/FAME/FAST investigation (lib/investigations_upload.py, case_packager.py,
# scripts/remove_case.sh). If INVESTIGATIONS_SSH_HOST is left unset/commented
# out, the vault is treated as "not configured": reports stay local in
# ./reports/<case_id>/ and upload steps print setup guidance instead of failing.
#
# Preferred setup: run
#   ./scripts/configure_vault.sh user@host /remote/root [ssh_key_path]
# which writes these three lines into this file for you (idempotent).
#
# Example values for a SANS SIFT-style remote host:
#   INVESTIGATIONS_SSH_HOST="sansforensics@ubuntudesktop"
#   INVESTIGATIONS_ROOT="/home/sansforensics/cases"
# export INVESTIGATIONS_SSH_HOST="user@host"
# export INVESTIGATIONS_ROOT="/home/your-user/cases"
# export INVESTIGATIONS_SSH_KEY="$HOME/.ssh/id_ed25519"

# ── Evidence MCP server (optional, remote-only) ────────────────────────────────
# SSH target + root directory the `evidence` MCP server reads from when
# registered as a remote SSH process (see mcp/evidence_server.py). Not needed
# for the local devcontainer mount above. EVIDENCE_SSH_HOST defaults to
# INVESTIGATIONS_SSH_HOST if unset (both servers usually live on the same host).
# export EVIDENCE_SSH_HOST="user@host"
# export EVIDENCE_ROOT="/home/your-user/evidence"
