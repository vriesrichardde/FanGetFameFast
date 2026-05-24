#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Martinsen-Janssen · Suzanne Maquelin
# set_env_template.sh — Environment variable template for SOC tooling
#
# USAGE:
#   cp scripts/set_env_template.sh ~/.soc_env
#   Fill in real values in ~/.soc_env
#   Add to ~/.bashrc:  source ~/.soc_env
#
# This file contains only placeholder values — never commit real credentials.

# ── Microsoft Sentinel MCP ───────────────────────────────────────────────────
export SENTINEL_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_CLIENT_SECRET="your-client-secret"
export SENTINEL_SUBSCRIPTION_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
export SENTINEL_RESOURCE_GROUP="rg-sentinel"
export SENTINEL_WORKSPACE_NAME="law-sentinel"
export SENTINEL_WORKSPACE_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# ── OpenCTI MCP ──────────────────────────────────────────────────────────────
export OPENCTI_URL="http://localhost:8080"
export OPENCTI_API_KEY="your-opencti-api-key"

# ── Teams Webhook (SOC Virtual Analyst + SOC Reporting) ──────────────────────
export TEAMS_WEBHOOK_URL="https://your-org.webhook.office.com/webhookb2/..."

# ── Perplexity (live threat intel) ───────────────────────────────────────────
export PERPLEXITY_API_KEY="pplx-..."
