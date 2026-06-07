#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
opencti_server.py — MCP server for OpenCTI integration.

Implements the Model Context Protocol (MCP) v2024-11-05 over stdio JSON-RPC 2.0.
Exposes three tools to Claude Code for querying and updating an OpenCTI instance.

Tools:
  opencti_search_stix        Search any STIX entity type (malware, threat-actor, campaign, etc.)
  opencti_search_ioc         Search indicators by value, pattern type, or keyword
  opencti_create_indicator   Create a new indicator with STIX, YARA, or Sigma pattern

Configuration (set in .claude/settings.json mcpServers block):
  OPENCTI_URL     — OpenCTI base URL, e.g. http://localhost:4000
  OPENCTI_API_KEY — OpenCTI API token (Settings → API access in the UI)

Registration (project-level, add to .claude/settings.json):

  {
    "mcpServers": {
        "opencti": {
        "command": "python3",
        "args": ["/home/richard/Documents/FanGetFameFast/mcp/opencti_server.py"]
        }
    }
  }

Or user-level (~/.claude/settings.json) with absolute path:
  "args": ["/home/richard/Documents/FanGetFameFast/mcp/opencti_server.py"]

Usage (standalone test):
  OPENCTI_URL=http://localhost:4000 OPENCTI_API_KEY=token python3 mcp/opencti_server.py
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

OPENCTI_URL     = os.environ.get("OPENCTI_URL", "").rstrip("/")
OPENCTI_API_KEY = os.environ.get("OPENCTI_API_KEY", "")


# ── GraphQL client ─────────────────────────────────────────────────────────────

def _graphql(query: str, variables: dict[str, Any] | None = None) -> dict:
    if not OPENCTI_URL:
        raise RuntimeError(
            "OPENCTI_URL is not set. "
            "Add it to the env block in .claude/settings.json mcpServers.opencti."
        )
    if not OPENCTI_API_KEY:
        raise RuntimeError(
            "OPENCTI_API_KEY is not set. "
            "Generate a token at Settings → API access in your OpenCTI instance."
        )

    payload = json.dumps({"query": query, "variables": variables or {}}).encode()
    req = urllib.request.Request(
        f"{OPENCTI_URL}/graphql",
        data=payload,
        headers={
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {OPENCTI_API_KEY}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")[:300]
        raise RuntimeError(f"HTTP {exc.code} from OpenCTI: {body}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Cannot reach OpenCTI at {OPENCTI_URL}: {exc.reason}") from exc


# ── Tool implementations ───────────────────────────────────────────────────────

def _search_stix(search: str, types: list[str] | None = None, limit: int = 20) -> str:
    query = """
    query SearchSTIX($search: String, $types: [String], $first: Int) {
      stixObjectOrStixRelationships(
        search: $search
        types: $types
        first: $first
        orderBy: created_at
        orderMode: desc
      ) {
        edges {
          node {
            id
            entity_type
            ... on StixDomainObject {
              name
              description
              created
              modified
            }
            ... on Indicator {
              name
              pattern
              pattern_type
              indicator_types
              description
              valid_from
              x_opencti_score
            }
            ... on StixCoreRelationship {
              relationship_type
              description
              created
            }
            ... on Malware {
              name
              description
              malware_types
              is_family
            }
            ... on ThreatActor {
              name
              description
              threat_actor_types
              aliases
            }
            ... on AttackPattern {
              name
              description
              x_mitre_id
            }
          }
        }
      }
    }
    """
    variables: dict[str, Any] = {"search": search, "first": min(limit, 50)}
    if types:
        variables["types"] = types

    result = _graphql(query, variables)
    if "errors" in result:
        return f"GraphQL error: {result['errors'][0].get('message', 'unknown')}"

    edges = (
        result.get("data", {})
        .get("stixObjectOrStixRelationships", {})
        .get("edges", [])
    )
    if not edges:
        scope = f" (types: {', '.join(types)})" if types else ""
        return f"No STIX entities found for '{search}'{scope}."

    lines = [f"Found {len(edges)} STIX entity/entities for '{search}':\n"]
    for edge in edges:
        node = edge["node"]
        etype = node.get("entity_type", "unknown")
        name  = (
            node.get("name")
            or node.get("relationship_type")
            or node.get("id", "—")
        )
        lines.append(f"[{etype}] {name}")

        # Type-specific extras
        if node.get("x_mitre_id"):
            lines.append(f"  MITRE: {node['x_mitre_id']}")
        if node.get("pattern"):
            lines.append(f"  Pattern ({node.get('pattern_type','?')}): {node['pattern'][:120]}")
        if node.get("aliases"):
            lines.append(f"  Aliases: {', '.join(node['aliases'][:5])}")
        if node.get("x_opencti_score") is not None:
            lines.append(f"  Score: {node['x_opencti_score']}")
        desc = (node.get("description") or "").strip()
        if desc:
            lines.append(f"  {desc[:200]}")
        lines.append("")

    return "\n".join(lines).rstrip()


def _search_ioc(
    value: str = "",
    pattern_type: str = "",
    keyword: str = "",
    limit: int = 20,
) -> str:
    search = value or keyword
    query = """
    query SearchIndicators(
      $search: String
      $filters: FilterGroup
      $first: Int
    ) {
      indicators(
        search: $search
        filters: $filters
        first: $first
        orderBy: created
        orderMode: desc
      ) {
        edges {
          node {
            id
            name
            pattern
            pattern_type
            indicator_types
            valid_from
            valid_until
            description
            created
            confidence
            x_opencti_score
            x_opencti_main_observable_type
          }
        }
      }
    }
    """
    variables: dict[str, Any] = {"first": min(limit, 50)}
    if search:
        variables["search"] = search
    if pattern_type:
        variables["filters"] = {
            "mode": "and",
            "filters": [{"key": "pattern_type", "values": [pattern_type]}],
            "filterGroups": [],
        }

    result = _graphql(query, variables)
    if "errors" in result:
        return f"GraphQL error: {result['errors'][0].get('message', 'unknown')}"

    edges = result.get("data", {}).get("indicators", {}).get("edges", [])
    if not edges:
        desc = value or keyword or "(no filter)"
        return f"No indicators found matching: {desc}"

    lines = [f"Found {len(edges)} indicator(s):\n"]
    for edge in edges:
        node = edge["node"]
        ioc_types = ", ".join(node.get("indicator_types") or []) or "—"
        score     = node.get("x_opencti_score", "—")
        created   = (node.get("created") or "")[:10]
        valid_to  = (node.get("valid_until") or "")[:10]

        lines.append(f"• {node['name']}")
        lines.append(
            f"  Type: {ioc_types}  |  Pattern: {node.get('pattern_type','?')}  "
            f"|  Score: {score}  |  Created: {created}"
        )
        pattern = (node.get("pattern") or "")
        if pattern:
            lines.append(f"  Pattern: {pattern[:160]}")
        if valid_to:
            lines.append(f"  Valid until: {valid_to}")
        desc = (node.get("description") or "").strip()
        if desc:
            lines.append(f"  Note: {desc[:200]}")
        lines.append("")

    return "\n".join(lines).rstrip()


def _create_indicator(
    name: str,
    pattern: str,
    pattern_type: str,
    description: str = "",
    indicator_types: list[str] | None = None,
    valid_from: str = "",
    confidence: int = 50,
) -> str:
    if not valid_from:
        valid_from = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    mutation = """
    mutation CreateIndicator($input: IndicatorAddInput!) {
      indicatorAdd(input: $input) {
        id
        name
        pattern
        pattern_type
        indicator_types
        valid_from
        created
        x_opencti_score
      }
    }
    """
    input_data: dict[str, Any] = {
        "name":         name,
        "pattern":      pattern,
        "pattern_type": pattern_type,
        "valid_from":   valid_from,
        "confidence":   max(0, min(100, confidence)),
    }
    if description:
        input_data["description"] = description
    if indicator_types:
        input_data["indicator_types"] = indicator_types

    result = _graphql(mutation, {"input": input_data})
    if "errors" in result:
        return f"Error creating indicator: {result['errors'][0].get('message', 'unknown')}"

    ind = result.get("data", {}).get("indicatorAdd") or {}
    if not ind:
        return "Indicator submitted but OpenCTI returned no data."

    ioc_types = ", ".join(ind.get("indicator_types") or []) or "—"
    return (
        f"Indicator created successfully:\n"
        f"  ID:           {ind.get('id','')}\n"
        f"  Name:         {ind.get('name','')}\n"
        f"  Pattern type: {ind.get('pattern_type','')}\n"
        f"  Pattern:      {ind.get('pattern','')[:120]}\n"
        f"  Types:        {ioc_types}\n"
        f"  Valid from:   {ind.get('valid_from','')[:10]}\n"
        f"  Score:        {ind.get('x_opencti_score','—')}"
    )


# ── MCP protocol ───────────────────────────────────────────────────────────────

_TOOLS = [
    {
        "name": "opencti_search_stix",
        "description": (
            "Search any STIX entity type in OpenCTI (Malware, Threat-Actor, Campaign, "
            "Indicator, Vulnerability, Attack-Pattern, Tool, Infrastructure, etc.). "
            "Returns names, descriptions, patterns, MITRE IDs, and aliases."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "search": {
                    "type": "string",
                    "description": "Search term, IOC value, actor name, CVE, malware family, etc.",
                },
                "types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "STIX entity types to restrict the search. Examples: "
                        "['Malware'], ['Threat-Actor'], ['Indicator','Malware']. "
                        "Omit to search all types."
                    ),
                },
                "limit": {
                    "type": "integer",
                    "default": 20,
                    "description": "Maximum number of results (1–50, default 20).",
                },
            },
            "required": ["search"],
        },
    },
    {
        "name": "opencti_search_ioc",
        "description": (
            "Search indicators/IOCs in OpenCTI by value, pattern type, or keyword. "
            "Supports IPs, domains, hashes, URLs, STIX patterns, YARA rules, and Sigma rules."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "value": {
                    "type": "string",
                    "description": "Exact or partial IOC value: IP address, domain, hash, URL.",
                },
                "pattern_type": {
                    "type": "string",
                    "description": (
                        "Filter by pattern language: stix, yara, sigma, snort, suricata. "
                        "Leave blank to search all types."
                    ),
                },
                "keyword": {
                    "type": "string",
                    "description": "Full-text keyword search across all indicator fields.",
                },
                "limit": {
                    "type": "integer",
                    "default": 20,
                    "description": "Maximum number of results (default 20).",
                },
            },
        },
    },
    {
        "name": "opencti_create_indicator",
        "description": (
            "Create a new indicator in OpenCTI with a STIX expression, YARA rule, "
            "or Sigma rule. The indicator is immediately available for correlation."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Short descriptive name for the indicator.",
                },
                "pattern": {
                    "type": "string",
                    "description": (
                        "Detection pattern. STIX example: "
                        "[ipv4-addr:value = '1.2.3.4']. "
                        "Pass full YARA rule text or Sigma YAML as appropriate."
                    ),
                },
                "pattern_type": {
                    "type": "string",
                    "description": "Pattern language: stix | yara | sigma | snort | suricata",
                },
                "description": {
                    "type": "string",
                    "description": "Optional free-text description or investigation context.",
                },
                "indicator_types": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": (
                        "STIX indicator type labels, e.g. "
                        "['malicious-activity'], ['compromised','anonymization']."
                    ),
                },
                "valid_from": {
                    "type": "string",
                    "description": "ISO-8601 UTC start date (defaults to now).",
                },
                "confidence": {
                    "type": "integer",
                    "description": "Analyst confidence 0–100 (default 50).",
                    "default": 50,
                },
            },
            "required": ["name", "pattern", "pattern_type"],
        },
    },
]


def _handle_call(tool_name: str, arguments: dict) -> tuple[str, bool]:
    """Returns (text, is_error)."""
    try:
        if tool_name == "opencti_search_stix":
            text = _search_stix(
                search=arguments["search"],
                types=arguments.get("types"),
                limit=int(arguments.get("limit", 20)),
            )
        elif tool_name == "opencti_search_ioc":
            text = _search_ioc(
                value=arguments.get("value", ""),
                pattern_type=arguments.get("pattern_type", ""),
                keyword=arguments.get("keyword", ""),
                limit=int(arguments.get("limit", 20)),
            )
        elif tool_name == "opencti_create_indicator":
            text = _create_indicator(
                name=arguments["name"],
                pattern=arguments["pattern"],
                pattern_type=arguments["pattern_type"],
                description=arguments.get("description", ""),
                indicator_types=arguments.get("indicator_types"),
                valid_from=arguments.get("valid_from", ""),
                confidence=int(arguments.get("confidence", 50)),
            )
        else:
            return f"Unknown tool: {tool_name}", True

        is_error = text.lower().startswith("error") or text.lower().startswith("graphql error")
        return text, is_error

    except KeyError as exc:
        return f"Error: Missing required argument {exc}", True
    except RuntimeError as exc:
        return f"Error: {exc}", True
    except Exception as exc:
        return f"Error: Unexpected — {exc}", True


def _send(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()


def main() -> None:
    for raw in sys.stdin:
        raw = raw.strip()
        if not raw:
            continue
        try:
            msg = json.loads(raw)
        except json.JSONDecodeError:
            continue

        method = msg.get("method", "")
        req_id = msg.get("id")

        # Notifications have no id — no response
        if req_id is None:
            continue

        if method == "initialize":
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {
                        "name":    "opencti",
                        "version": "1.0.0",
                    },
                },
            })

        elif method == "tools/list":
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": _TOOLS},
            })

        elif method == "tools/call":
            params    = msg.get("params", {})
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})
            text, is_error = _handle_call(tool_name, arguments)
            resp: dict[str, Any] = {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{"type": "text", "text": text}],
                },
            }
            if is_error:
                resp["result"]["isError"] = True
            _send(resp)

        else:
            _send({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"Method not found: {method}"},
            })


if __name__ == "__main__":
    main()
