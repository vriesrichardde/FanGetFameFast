#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin
# test_mcp_servers.sh — Verify all three MCP servers are reachable and respond.
#
# Sends a JSON-RPC 2.0 'initialize' request to each server and checks that a
# valid result is returned. A timeout of 10 seconds is applied per server.
#
# Usage:
#   ./scripts/test_mcp_servers.sh
#   ./scripts/test_mcp_servers.sh --evidence-only
#   ./scripts/test_mcp_servers.sh --investigations-only
#   ./scripts/test_mcp_servers.sh --opencti-only

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

C_GREEN='\033[0;32m'; C_RED='\033[0;31m'; C_YELLOW='\033[1;33m'
C_CYAN='\033[0;36m'; C_BOLD='\033[1m'; C_RESET='\033[0m'
ok()     { echo -e "${C_GREEN}[PASS]${C_RESET} $*"; PASSED=$((PASSED+1)); }
fail()   { echo -e "${C_RED}[FAIL]${C_RESET} $*"; FAILED=$((FAILED+1)); }
warn()   { echo -e "${C_YELLOW}[ -- ]${C_RESET} $*"; }
info()   { echo -e "${C_CYAN}[INFO]${C_RESET} $*"; }
header() { echo ""; echo -e "${C_BOLD}${C_CYAN}══ $* ══${C_RESET}"; }

PASSED=0; FAILED=0
TEST_EVIDENCE=1; TEST_INVESTIGATIONS=1; TEST_OPENCTI=1

while [[ $# -gt 0 ]]; do
    case "$1" in
        --evidence-only)      TEST_INVESTIGATIONS=0; TEST_OPENCTI=0; shift ;;
        --investigations-only) TEST_EVIDENCE=0;      TEST_OPENCTI=0; shift ;;
        --opencti-only)       TEST_EVIDENCE=0;       TEST_INVESTIGATIONS=0; shift ;;
        *) shift ;;
    esac
done

# MCP JSON-RPC initialize payload (newline-terminated as required by MCP stdio)
INIT_REQ='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"mcp-test","version":"1.0"}}}'

# ── Helper: send initialize, check response contains "result" ─────────────────
# Usage: mcp_ping <label> <timeout_sec> <cmd> [args...]
mcp_ping() {
    local label="$1"; local timeout_sec="$2"; shift 2
    local response
    if response=$(echo "$INIT_REQ" | timeout "$timeout_sec" "$@" 2>/dev/null); then
        if echo "$response" | grep -q '"result"'; then
            local server_name
            server_name=$(echo "$response" | python3 -c \
                "import sys,json; d=json.loads(sys.stdin.read().strip().splitlines()[0]); print(d.get('result',{}).get('serverInfo',{}).get('name','?'))" \
                2>/dev/null || echo "?")
            ok "$label (server: $server_name)"
        else
            fail "$label — response received but no 'result' field: ${response:0:120}"
        fi
    else
        local exit_code=$?
        if [[ $exit_code -eq 124 ]]; then
            fail "$label — timed out after ${timeout_sec}s"
        else
            fail "$label — command failed (exit $exit_code)"
        fi
    fi
}

# ── 1. Evidence MCP server (SSH → ubuntudesktop) ─────────────────────────────
if [[ $TEST_EVIDENCE -eq 1 ]]; then
    header "Evidence MCP Server (sansforensics@ubuntudesktop)"

    info "Checking SSH connectivity to ubuntudesktop ..."
    if timeout 5 ssh -o BatchMode=yes -o ConnectTimeout=4 sansforensics@ubuntudesktop true 2>/dev/null; then
        ok "SSH: sansforensics@ubuntudesktop reachable"

        info "Checking evidence_server.py exists on remote ..."
        if ssh sansforensics@ubuntudesktop "test -f /home/sansforensics/evidence/evidence_server.py" 2>/dev/null; then
            ok "Remote file: /home/sansforensics/evidence/evidence_server.py"
        else
            fail "Remote file not found: /home/sansforensics/evidence/evidence_server.py"
            warn "Deploy with: scp $PROJECT_ROOT/mcp/evidence_server.py sansforensics@ubuntudesktop:/home/sansforensics/evidence/"
        fi

        info "Sending MCP initialize to evidence server ..."
        mcp_ping "Evidence MCP initialize" 10 \
            ssh sansforensics@ubuntudesktop \
            "EVIDENCE_ROOT=/home/sansforensics/evidence python3 /home/sansforensics/evidence/evidence_server.py"
    else
        fail "SSH: cannot reach sansforensics@ubuntudesktop (timeout or key error)"
    fi
fi

# ── 2. Investigations MCP server (SSH → ubuntudesktop) ───────────────────────
if [[ $TEST_INVESTIGATIONS -eq 1 ]]; then
    header "Investigations MCP Server (sansforensics@ubuntudesktop)"

    info "Checking SSH connectivity to ubuntudesktop ..."
    if timeout 5 ssh -o BatchMode=yes -o ConnectTimeout=4 sansforensics@ubuntudesktop true 2>/dev/null; then
        ok "SSH: sansforensics@ubuntudesktop reachable"

        info "Checking investigations_server.py exists on remote ..."
        if ssh sansforensics@ubuntudesktop "test -f /home/sansforensics/cases/investigations_server.py" 2>/dev/null; then
            ok "Remote file: /home/sansforensics/cases/investigations_server.py"
        else
            fail "Remote file not found: /home/sansforensics/cases/investigations_server.py"
            warn "Deploy with: scp $PROJECT_ROOT/mcp/investigations_server.py sansforensics@ubuntudesktop:/home/sansforensics/cases/"
        fi

        info "Sending MCP initialize to investigations server ..."
        mcp_ping "Investigations MCP initialize" 10 \
            ssh sansforensics@ubuntudesktop \
            "INVESTIGATIONS_ROOT=/home/sansforensics/cases python3 /home/sansforensics/cases/investigations_server.py"
    else
        fail "SSH: cannot reach sansforensics@ubuntudesktop (timeout or key error)"
    fi
fi

# ── 3. OpenCTI MCP server (local) ────────────────────────────────────────────
if [[ $TEST_OPENCTI -eq 1 ]]; then
    header "OpenCTI MCP Server (local)"

    SERVER="$PROJECT_ROOT/mcp/opencti_server.py"

    if [[ -f "$SERVER" ]]; then
        ok "Server file: $SERVER"
    else
        fail "Server file not found: $SERVER"
    fi

    if [[ -z "${OPENCTI_URL:-}" ]]; then
        warn "OPENCTI_URL not set — server will start but tool calls will fail"
        warn "Set credentials in ~/.soc_env and run: source ~/.soc_env"
    else
        info "OpenCTI URL: $OPENCTI_URL"
    fi

    info "Sending MCP initialize to OpenCTI server ..."
    mcp_ping "OpenCTI MCP initialize" 10 \
        python3 "$SERVER"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${C_BOLD}════════════════════════════════════════${C_RESET}"
echo -e "${C_BOLD}  MCP Server Test Results${C_RESET}"
echo -e "${C_BOLD}════════════════════════════════════════${C_RESET}"
echo -e "  ${C_GREEN}Passed : $PASSED${C_RESET}"
[[ $FAILED -gt 0 ]] && echo -e "  ${C_RED}Failed : $FAILED${C_RESET}" || echo -e "  Failed : 0"
echo ""

[[ $FAILED -eq 0 ]]
