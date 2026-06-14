# Skill: accuracy-report — Reproduce `/accuracy`

## Overview

The `accuracy/` folder is FanGetFameFast's self-assessment deliverable for the
"CHECK 8: ACCURACY REPORT / IR ACCURACY" rubric. It contains:

| File | What it is | How it's produced |
|------|-----------|-------------------|
| `accuracy.md` | The main report: evidence-integrity architecture, dataset provenance, per-case self-assessment (false positives, missed artifacts, hallucinations), 3 traced claims, cross-cutting limitations, automated-audit summary, overall summary table | **Hand-authored** by Claude, grounded in each in-scope case's Hallucination Guard tables and research notes |
| `verify_claims.py` | Automated claim-traceability auditor | Static script — re-run, don't rewrite, unless its behaviour needs to change |
| `claim_traceability_audit.md` | Output of `verify_claims.py`: every cited (`RN-`/`EVT-`/`RF-`/`FND-`) line in each in-scope case's report, with UNVERIFIED/VERIFIED token checks | **Regenerated** by running `verify_claims.py` |
| `dataset_documentation.md` | Plain-text "what was tested, source of data, what was found" per dataset, for upload to a plain-text field | **Hand-derived** from `accuracy.md` |

This skill describes how to reproduce/refresh all four when the case set in
`reports/`/`archive/` changes (a new investigation completes) or when an existing
case's reports are updated.

**Invocation:** `/accuracy-report`

---

## Step 1 — Regenerate the automated audit

```bash
python3 accuracy/verify_claims.py
```

This discovers in-scope cases (see Step 2), finds each case's campaign report (or
per-module incident/fast/fame report if no campaign report exists), checks every
"hard" token (timestamp, byte count, IPv4/IPv4:port, MAC address, hex hash, date,
frame/tcp.stream number, MITRE technique ID) on every cited line against that case's
`*_research_notes.md` / `*_narrative.md` / `*_correlation.md` files, and writes
`accuracy/claim_traceability_audit.md`. It prints the number of cases it found —
sanity-check that against the scope table from Step 2.

`verify_claims.py` scans both `reports/` (active cases) and `archive/` (cases moved
there by `/archive-reports`), so this works whether the case is still active or has
already been archived.

---

## Step 2 — Reconcile the scope table

`accuracy/verify_claims.py` restricts itself to case IDs listed in `accuracy.md`'s
scope table (the `| \`CASE-ID\` | ... |` rows near the top of the file) — this is
what keeps old/duplicate archived runs out of the audit.

- **New completed case?** Add a row: case ID, module(s) + whether it's a campaign
  report, dataset name, and the **public source URL** for the dataset (e.g. NIST
  CFReDS, Digital Corpora). If the dataset isn't public, write `internal` instead of
  a URL.
- **Case retired from scope?** Remove its row. (Its files stay in `archive/`; they
  just won't be audited.)
- Re-run Step 1 after editing the scope table — the case count printed should match
  the number of rows.

---

## Step 3 — Update the per-case self-assessment (Section 3)

For each case in the scope table, add or refresh a `### 3.N <CASE_ID>` subsection.
Read these sources for each case (do not invent numbers — every figure must come
from one of these):

- The campaign/incident report's **Hallucination Guard / Confidence Assessment**
  table — gives the CONFIRMED/INFERRED/ASSUMED/UNVERIFIABLE counts and percentage.
- That case's `*_research_notes.md` — source of every `RN-NNN`/`EVT-NNN` citation,
  and the place to find **false positives** (automated detector calls that were
  manually reassessed and downgraded) and **near-miss self-corrections** (e.g.
  timezone re-orderings caught before the report was written).
- The report's `FND-NNN` findings — source of **missed/unresolved artifacts**
  (gaps explicitly tagged ASSUMED/UNVERIFIABLE rather than silently omitted) and any
  **hallucinations caught** (claims removed or downgraded because they didn't trace
  to a tool execution).

Each subsection should cover, in this order: confidence summary, false positives
caught, missed/unresolved artifacts, and hallucinations caught (or "none identified
— closest analogue is X").

---

## Step 4 — Refresh the three traced claims (Section 4)

Pick (or re-verify) three claims, one per case where possible, each tracing:

> **Claim** (as written in the campaign/incident report, with its `FND-`/citation)
> → **Log entry** (the exact research-notes line, with file path and `RN-`/`EVT-`
> ID, quoted) → **Verdict**: Supported / Unsupported / Could-not-locate.

A claim is **Supported** only if the cited research-notes line independently
contains the same hard facts (timestamps, identifiers, sizes) as the report claim —
spot-check with `grep` against the research notes file before marking Supported.

---

## Step 5 — Refresh the automated-audit summary (Section 6) and overall summary (Section 7)

- Re-read the freshly generated `accuracy/claim_traceability_audit.md` and update the
  flag count and per-case cited/checked/verified/flagged numbers in Section 6.
- For every `### UNVERIFIED` block, classify it (don't leave it unexplained):
  timezone-converted column, analytical/derived value (e.g. MITRE technique ID added
  during synthesis), report-generation metadata, or — if none of those — a genuine
  candidate hallucination that needs to be traced back into Section 3.
- Update the Section 7 summary table (one row per in-scope case: findings,
  confirmed %, FPs caught, missed-artifact gaps, hallucinations caught) from the
  refreshed Section 3/6 numbers.

---

## Step 6 — Regenerate `dataset_documentation.md`

This file is a plain-text-friendly derivative of `accuracy.md`, structured per
dataset rather than per architecture-section, for pasting into a plain-text
submission field. For each row in the scope table, write:

- **Case ID**, **modules tested**, **source of data** (the URL from the scope table)
- **What the agent found** — 4-6 bullets pulled from that case's Section 3
  subsection: headline finding(s) with their cross-evidence corroboration,
  false positives caught, gaps disclosed, and any self-corrections.

Keep the closing "Notes on provenance and reproducibility" paragraph (build-vs-score
disclosure + pointer to `verify_claims.py`) — update it only if the provenance
caveat changes (e.g. a new case uses a non-public/internal dataset).

---

## Done condition

- `python3 accuracy/verify_claims.py` runs clean and reports the same case count as
  rows in `accuracy.md`'s scope table.
- Every case in scope has a `### 3.N` subsection in `accuracy.md` with confidence
  numbers traceable to that case's Hallucination Guard table.
- `dataset_documentation.md` has one section per scope-table row, each with a
  working source URL (or `internal`).
- No number in any of the four files was invented — everything traces to a
  Hallucination Guard table, a research-notes line, or a `claim_traceability_audit.md`
  count.
