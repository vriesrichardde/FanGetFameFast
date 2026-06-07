# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
opencti_client.py — Lightweight OpenCTI GraphQL client for the vault record path.

`knowledge_extractor.py` constructs one `OpenCTIClient` at import time and calls
`create_indicator(...)` whenever a new IOC, TTP, or malware family is recorded in
the vault. This makes the "record → push to OpenCTI" behaviour documented in
CLAUDE.md actually happen.

The MCP server (`mcp/opencti_server.py`) exposes the same OpenCTI instance to
Claude interactively; this module is the programmatic counterpart used by the
library. Both speak GraphQL over the same `OPENCTI_URL` / `OPENCTI_API_KEY`.

Configuration (environment variables, set in ~/.soc_env):
  OPENCTI_URL     — OpenCTI base URL, e.g. http://localhost:8080
  OPENCTI_API_KEY — OpenCTI API token (Settings → API access in the UI)

Construction fails fast (raises RuntimeError) when either variable is missing.
`knowledge_extractor` catches that and disables pushing, so an unconfigured
environment silently skips OpenCTI rather than erroring on every vault write.

Only the Python standard library is used — no new dependency.

Self-test (requires a reachable OpenCTI):
  OPENCTI_URL=... OPENCTI_API_KEY=... python3 lib/opencti_client.py --test
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any


class OpenCTIClient:
    """Minimal GraphQL client: create indicators and resolve labels."""

    def __init__(
        self,
        url: str | None = None,
        api_key: str | None = None,
        timeout: int = 30,
    ) -> None:
        self.url = (url or os.environ.get("OPENCTI_URL", "")).rstrip("/")
        self.api_key = api_key or os.environ.get("OPENCTI_API_KEY", "")
        self.timeout = timeout
        if not self.url:
            raise RuntimeError(
                "OPENCTI_URL is not set — add it to ~/.soc_env "
                "(see templates/set_env_template.sh)."
            )
        if not self.api_key:
            raise RuntimeError(
                "OPENCTI_API_KEY is not set — generate a token at "
                "Settings → API access in OpenCTI and add it to ~/.soc_env."
            )

    # ── transport ───────────────────────────────────────────────────────────

    def _graphql(self, query: str, variables: dict[str, Any] | None = None) -> dict:
        payload = json.dumps({"query": query, "variables": variables or {}}).encode()
        req = urllib.request.Request(
            f"{self.url}/graphql",
            data=payload,
            headers={
                "Content-Type":  "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:300]
            raise RuntimeError(f"HTTP {exc.code} from OpenCTI: {body}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Cannot reach OpenCTI at {self.url}: {exc.reason}"
            ) from exc

    # ── labels ──────────────────────────────────────────────────────────────

    def _resolve_label_ids(self, labels: list[str]) -> list[str]:
        """Map label names to OpenCTI label IDs, creating any that don't exist.

        Best-effort: a label that cannot be found or created is skipped rather
        than aborting the indicator creation it was meant to annotate.
        """
        find = """
        query LabelByValue($search: String) {
          labels(search: $search, first: 10) {
            edges { node { id value } }
          }
        }
        """
        create = """
        mutation AddLabel($input: LabelAddInput!) {
          labelAdd(input: $input) { id value }
        }
        """
        ids: list[str] = []
        for name in labels:
            try:
                found = self._graphql(find, {"search": name})
                label_id = None
                for edge in (
                    found.get("data", {}).get("labels", {}).get("edges", [])
                ):
                    node = edge.get("node", {})
                    if (node.get("value") or "").lower() == name.lower():
                        label_id = node.get("id")
                        break
                if label_id is None:
                    made = self._graphql(
                        create, {"input": {"value": name, "color": "#7f8c8d"}}
                    )
                    label_id = (
                        made.get("data", {}).get("labelAdd", {}).get("id")
                    )
                if label_id:
                    ids.append(label_id)
            except RuntimeError:
                continue  # label is decorative; never block the indicator
        return ids

    # ── indicators ────────────────────────────────────────────────────────────

    def create_indicator(
        self,
        name: str,
        pattern: str,
        pattern_type: str,
        description: str = "",
        labels: list[str] | None = None,
        indicator_types: list[str] | None = None,
        valid_from: str = "",
        confidence: int = 50,
    ) -> dict:
        """Create an indicator in OpenCTI and return the created node.

        Mirrors the mutation used by ``mcp/opencti_server._create_indicator`` so
        both code paths behave identically. ``labels`` are resolved to OpenCTI
        label IDs (created on demand); failure to resolve a label degrades to
        creating the indicator without it. Raises RuntimeError on a hard failure
        (unreachable instance, GraphQL error) — callers treat pushes as
        best-effort and catch this.
        """
        if not valid_from:
            valid_from = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000Z"
            )

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
        if labels:
            label_ids = self._resolve_label_ids(labels)
            if label_ids:
                input_data["objectLabel"] = label_ids

        mutation = """
        mutation CreateIndicator($input: IndicatorAddInput!) {
          indicatorAdd(input: $input) {
            id
            name
            pattern_type
            valid_from
            created
          }
        }
        """
        result = self._graphql(mutation, {"input": input_data})
        if "errors" in result:
            msg = result["errors"][0].get("message", "unknown")
            raise RuntimeError(f"OpenCTI indicatorAdd failed: {msg}")
        ind = result.get("data", {}).get("indicatorAdd")
        if not ind:
            raise RuntimeError("OpenCTI returned no data for indicatorAdd.")
        return ind


def _self_test() -> int:
    """Create a throwaway indicator to prove connectivity. Needs a live instance."""
    try:
        client = OpenCTIClient()
    except RuntimeError as exc:
        print(f"[opencti_client] not configured: {exc}")
        return 1
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        ind = client.create_indicator(
            name=f"opencti_client-selftest-{stamp}",
            pattern="[ipv4-addr:value = '203.0.113.255']",
            pattern_type="stix",
            description="Connectivity self-test from opencti_client.py — safe to delete.",
            labels=["fan-extraction", "selftest"],
        )
    except RuntimeError as exc:
        print(f"[opencti_client] push failed: {exc}")
        return 1
    print(f"[opencti_client] OK — created indicator {ind.get('id')}")
    return 0


if __name__ == "__main__":
    if "--test" in sys.argv:
        raise SystemExit(_self_test())
    print(__doc__)
