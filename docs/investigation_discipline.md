# Investigation discipline (shared across FAN / FAME / FAST)

This document is the single source of truth for the parts of the investigation
workflow that are identical across all three modules: the research-notes
cadence, the narrative file contract (including the shared `pptx_*` board
schema), cross-module correlation, the hand-authored campaign report, and the
code-level completeness gate.

Each module's `SKILL.md` (`.claude/skills/fame/SKILL.md`,
`.claude/skills/fast/SKILL.md`, `.claude/skills/fan/SKILL.md`) keeps only what
is genuinely module-specific: its tool/plugin step table, its module-specific
narrative section names (`section_*`), its deep-dive methodology, and its
output paths / vault upload commands. When a module's SKILL.md says "see
`docs/investigation_discipline.md`", the text below applies verbatim with
`<module>` replaced by FAN/FAME/FAST and `<tool/plugin>` replaced by that
module's relevant command.

---

## 1. Research notes

Every investigation produces a **research notes file**
(`./reports/<case_id>/<MODULE>/<hostname-or-stem>/<case_id>_research_notes.md`)
alongside the formal report. The notes are a timestamped, step-by-step
investigative log that lets any analyst follow the complete workflow,
rationale, and findings from start to finish.

> **MANDATORY RULE: Do NOT proceed to the next analysis step until the
> current step has been documented in the research notes via
> `python3 lib/research_notes.py step ...`. Running a tool/plugin and
> immediately launching the next one without logging is not permitted. Read
> the output, interpret it, call `step`, then advance.**

> **MANDATORY DEVIATION LOGGING: Any time the analysis deviates from the
> standard workflow — a step is skipped, a fallback is used, a tool returns
> unexpected results, or an analytical decision is made that differs from the
> normal path — this MUST be logged as its own `step` call with
> `--title "Deviation: <what changed>"`.** The deviation log ensures any
> analyst reading the notes understands WHY the investigation took a
> different path and can reproduce or challenge that decision. See each
> module's SKILL.md for module-specific deviation examples.

### 1a — At investigation start (before running any tools)

```bash
python3 lib/research_notes.py init \
  --case-id <case_id> \
  --module <fame|fast|fan> \
  --evidence /path/to/evidence \
  --hostname <hostname-or-stem>
```

### 1b — After reading and interpreting each tool/plugin output

Call `step` once per analysis action, immediately after Claude has read and
understood the output:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "<Step title>" \
  --action "<tool invocation> → <case_id>_evidence/<...>.txt" \
  --why "<case-specific reason — see guidance below>" \
  --outcome "<finding> [source: <case_id>_evidence/<...>.txt]" \
  --dismissed "<what you inspected and decided was not significant — see guidance below>" \
  [--raw "excerpt if the output contains significant findings"] \
  [--confidence direct|inferred|assumed] \
  [--source-tool "<tool that produced this output, e.g. volatility3/psscan>"] \
  [--source-data "<path to the evidence/analysis file this step is based on>"]
```

**`--confidence`, `--source-tool`, `--source-data` (optional):**
`--confidence` overrides the confidence tier shown in the report (default:
auto-detected from `--assumption`). `--source-tool` and `--source-data` record
which tool produced the output and where its raw data lives — this provenance
is what `finalize-evidence` (§1e) later uses to rewrite `Source data` rows to
zip-relative paths after the `./analysis/` cleanup.

**`--why` — write the case-specific reason, not a generic tool description.**
Explain the hypothesis you are testing or the question you are answering *at
this moment in this investigation*. Do not restate what the tool does.

**`--dismissed` (optional but expected for every step):** Note what you
observed in the output and decided was not suspicious, and your reason. Omit
only when the output is completely empty.

**Traceability convention:** always reference the **preserved evidence path**
(`<case_id>_evidence/<...>/<tool>.txt`) in both `--action` and at the end of
`--outcome` as `[source: <case_id>_evidence/<...>/<tool>.txt]`. This survives
the `./analysis/` cleanup and unambiguously links each research-notes step to
the artifact that produced it.

**Use `--raw` only when the output contains significant findings.** For
clean/expected output, omit `--raw` and summarise in `--outcome`.

> **Auto-logged "Evidence preserved" steps are not investigation steps.**
> The analyze scripts (`fame_analyze.sh`, `fast_analyze.sh`,
> `analyze_pcap.sh`) automatically call `research_notes.py step` with
> `--title "Evidence preserved: <file>"` as each raw tool output is copied
> into `<case_id>_evidence/`. These are mechanical chain-of-custody entries —
> they record *that* an artifact exists, not that anyone looked at it. A
> research notes file containing **only** these auto-logged entries (no
> Claude-authored `step` calls with case-specific `--why`/`--outcome`, no
> `reflect` entries, no finalized summary) is evidence that the investigation
> never progressed past mechanical evidence collection. The completeness gate
> (§5 below) detects exactly this pattern and flags it as a reasoning gap.

### 1c — Mid-investigation reflection (mandatory — do not skip)

At the point specified in the module's SKILL.md (typically after the
network-connection step), stop and review all research notes steps recorded
so far (RN-001 through the current step). Ask: does any earlier finding need
reinterpreting in light of what you now know?

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Mid-investigation review — post-<step>" \
  --reinterpret "<state which earlier steps, if any, should be re-read differently — or write: 'No reinterpretations; earlier findings stand'>" \
  --open-leads "<list specific unresolved questions — or write: 'No open leads identified yet'>"
```

This uses the `reflect` subcommand, not `step`. It does not increment the RN
counter.

### 1d — When you discover a confirmed attacker action in the evidence

Whenever a tool/plugin output, YARA scan, baseline deviation, or cross-module
correlation reveals an action **performed by the attacker** — and that action
has a **confirmed timestamp from the evidence** — log it immediately using the
`event` subcommand:

```bash
python3 lib/research_notes.py event \
  --case-id <case_id> \
  --timestamp "YYYY-MM-DD HH:MM:SS UTC" \
  --description "<what the attacker did>" \
  --severity <critical|high|medium> \
  --module <FAME|FAST|FAN> \
  --source "<specific evidence artifact: PID, inode, MFT entry, IP:port, registry path, file path>" \
  --detail "<which artifact(s) confirm the timestamp and what they show>"
```

**Rules:**
- **Only call `event` if there is a confirmed timestamp** from an artifact
  (process creation time, MAC time, event log timestamp, prefetch execution
  time, packet timestamp, USN journal entry). Do not estimate or infer
  timestamps.
- If a significant finding has **no confirmed timestamp**, log it as a `step`
  instead and do NOT call `event`. It will appear in the *Unconfirmed
  Findings* section of the report.
- `--severity critical` — direct evidence of compromise, active malware
  execution, credential theft, ransomware detonation.
- `--severity high` — suspicious process chains, deleted executables,
  anomalous external connections, persistence mechanisms.
- `--severity medium` — anomalies that may be benign but require follow-up.

### 1e — Pre-finalize open leads review (mandatory)

Before calling `finalize`, read the complete research notes file from top to
bottom:

```bash
cat ./reports/<case_id>/<MODULE>/<hostname-or-stem>/<case_id>_research_notes.md
```

For every finding marked `[ASSUMPTION]`, every event without a confirmed
timestamp, and every `--dismissed` observation, ask: does the complete
picture explain this, or does it remain open? Then write the second reflect
entry:

```bash
python3 lib/research_notes.py reflect \
  --case-id <case_id> \
  --trigger "Pre-finalize complete case review" \
  --reinterpret "<final pass: state any step that needs reinterpretation given the full picture — or: 'All steps consistent with final conclusion'>" \
  --open-leads "<what this investigation cannot resolve alone — specify what evidence from the OTHER two modules would change or confirm the conclusion>"
```

Then call finalize — this replaces the `<!-- summary-placeholder -->` left by
`init` with a real investigation summary:

```bash
python3 lib/research_notes.py finalize \
  --case-id <case_id> \
  --summary "One-paragraph summary: key findings, main pivot point, MITRE techniques confirmed, and conclusion."
```

Then include the notes file in the upload call — see each module's SKILL.md
for the exact `investigations_upload.py` invocation (paths differ per
module).

### 1f — Post-report follow-up questions

Once a case's reports have been generated, any further analyst question that
references that case — even much later in the same session or in a new
session — must be logged via the `followup` subcommand:

```bash
python3 lib/research_notes.py followup \
  --case-id <case_id> \
  --case-dir reports/<case_id>/<MODULE>/<hostname-or-stem> \
  --question "<the analyst's follow-up question>" \
  --answer-summary "<summary of the action taken / answer given>" \
  [--output-file <path> ...]
```

`--output-file` is repeatable — pass one for each new or changed file produced
while answering the question (an additional analysis export, an exhibit, a
written answer saved to disk). If any such file was produced, immediately run:

```bash
python3 lib/chain_of_custody.py update \
  --case-id <case_id> \
  --case-dir reports/<case_id> \
  --trigger followup \
  --note "<question>"
```

so the chain-of-custody manifest covers it. See CLAUDE.md's "Follow-up
questions (post-report)" and "Chain of custody" sections.

---

## 2. Narrative file (required before report generation)

After all tool/plugin steps are complete and **before** calling
`python3 lib/generate_<fame|fast>_report.py` (or, for FAN,
`python3 lib/generate_pcap_report.py`), Claude must write the narrative file:

```
./reports/<case_id>/<MODULE>/<hostname-or-stem>/<case_id>_narrative.md
```

This file feeds the Incident Timeline section, the enhanced technical
chapters, and all eight slides of the board PPTX deck (Executive Summary,
Business Impact, Incident Timeline, Root Cause & Risk, Response &
Containment, Recommendations, Lessons Learned). Without it those slides show
generic placeholder text — write every section yourself, in your own words,
based on what you actually found. Do not rely on `lib/narrative_generator.py`'s
keyword-matching heuristics to fill these in; that generator is a headless
fallback for batch/no-Claude runs only and produces noticeably weaker, often
generic content.

### Shared schema fragment — `pptx_*` (identical across all three modules)

Every narrative file, regardless of module, must include these eight
sections. Each module's SKILL.md additionally defines `attack_timeline` and
its own `section_*` keys (see that file for the module-specific schema).

```markdown
## pptx_executive_summary

[3–5 bullet points. CISO language. No technical identifiers (IPs, ports,
PIDs, file paths, inode numbers, hash values, hostnames/workstation IDs).
Example: "• A server was accessed by an unauthorised individual using valid
credentials.
• The access resulted in deliberate shutdown of the system.
• No evidence of remote attacker or data exfiltration was found."]

## pptx_risk

[Business risks: data exposure, regulatory, operational, reputational.
No technical identifiers.]

## pptx_impact

[What was affected: systems, users, services, data. Business language.]

## pptx_mitigations

[What has already been done and what is in progress.]

## pptx_recommendations

[Concrete follow-up actions with suggested owner labels (CISO / IT / Legal).]

## pptx_timeline

[4-6 bullets: the board-level timeline. Same chronology as attack_timeline,
but plain language, no technical identifiers or RN-/EVT- citations — "On
[date] at [time], ..." Each bullet should be readable on its own as a slide
line.]

## pptx_root_cause

[1-2 sentences: how did this happen, in plain language — e.g. phishing, an
exposed/weak service, compromised credentials, an unpatched vulnerability,
physical access, misconfiguration. Be specific to what you actually found in
this evidence; do not use a generic placeholder if the evidence supports a
real conclusion.]

## pptx_lessons_learned

[3-5 bullets: what worked well in this investigation/response, and what gaps
or improvements this incident points to. Plain language, board-appropriate.]
```

### Rules
- Write **all** sections even if evidence is thin — note the gap explicitly
  (e.g., "No code injection was detected — malfind returned zero regions with
  executable VAD flags outside mapped images.").
- Keep management sections (`pptx_*`) free of IPs, ports, PIDs, inode
  numbers, sector offsets, hash values, file paths, hostnames/workstation
  IDs, and RN-/EVT- citation references — write them as you would for a
  board/CISO audience, not a technical one.
- Use RN-NNN references in `attack_timeline` (and module-specific
  `section_*` sections) to link back to research notes.

---

## 3. Cross-module correlation

Run the correlation engine **before** cleaning up `./analysis/` — it reads
raw module output files directly. Call it after all tool/plugin steps are
complete:

```bash
python3 lib/correlate_findings.py \
    --case-id <case_id> \
    --hostname <hostname-or-stem> \
    --output-dir reports/<case_id>
```

> Always pass `--output-dir reports/<case_id>` — without it, the correlation
> output is written outside the case folder.

Then log the step in research notes:

```bash
python3 lib/research_notes.py step \
  --case-id <case_id> \
  --title "Cross-module Correlation (FAN / FAME / FAST)" \
  --action "python3 lib/correlate_findings.py --case-id <case_id> --output-dir reports/<case_id> → <case_id>_correlation.md" \
  --why "Correlates netscan connections to PCAP threats (FAN↔FAME), process images to deleted disk entries (FAME↔FAST), and DNS queries to carved URLs (FAN↔FAST) — surfaces kill-chain connections that no single module identifies alone" \
  --outcome "<N FAN↔FAME matches, M FAME↔FAST matches, K FAN↔FAST matches — key finding>"
```

| Correlation | What it computes |
|-------------|-----------------|
| FAN ↔ FAME | Netscan connections matched to FAN flagged flows — links a specific process to suspicious network traffic |
| FAME ↔ FAST | Process image names matched to deleted fls entries — confirms post-execution cleanup (T1070.004) |
| FAN ↔ FAST | DNS-queried domains matched to bulk_extractor carved URLs — confirms active endpoint use |

`correlate_findings.py`'s output (`<case_id>_correlation.md`/`.json`) is a
**best-effort research aid**, not the campaign report itself: read it as one
input when drafting the Cross-Domain Correlation section of the campaign
report, but ground that section in the research notes regardless — zero
matches reported by the tool does not mean no correlation exists.

---

## 4. Campaign Report (hand-authored)

After this module's report has been generated, the per-case campaign report
(`<case_id>_campaign_report.*`) must always be hand-authored, not
auto-generated — for every case, including single-module cases:

1. Read this module's research notes end-to-end, plus the research notes of
   every other module that has completed for this case ID (if any).
2. Hand-author `./reports/<case_id>/<case_id>_campaign_report.md` following
   `docs/campaign_report_template.md`. For a single-module case, the Incident
   Timeline and findings tables cover this module alone, and the
   Cross-Domain Correlation section states explicitly that no other module
   has run for this case ID. For a multi-module case: Incident Timeline
   merged across modules, Cross-Domain Correlation pivots citing RN-/EVT- IDs
   from at least two modules (or stating explicitly that none exist), unified
   MITRE/IOC tables, and a hand-curated Hallucination Guard FND-list with an
   overall confidence percentage. `lib/correlate_findings.py`'s output and
   `lib/generate_combined_report.py`'s `_merge_*`/`_extract_*` helpers may be
   used as research aids when pre-populating tables.
3. Render it to PDF/PPTX/DOCX:
   ```python
   import sys; sys.path.insert(0, "./lib")
   from render_campaign_report import render

   paths = render(md_path="./reports/<case_id>/<case_id>_campaign_report.md",
                   case_id="<case_id>", hostname="<hostname>")
   ```

`lib/generate_combined_report.py`'s `generate()` is deprecated for this
workflow — it remains only as an automated fallback for `--md-only`/headless
batch runs or very-low-evidence cases.

After generating this module's report, also check whether any module now has
a generated report for this case ID but no campaign report exists:

```bash
python3 lib/report_completeness.py --campaign-check \
    --case-id <case_id> --reports-dir ./reports
```

If it reports a missing campaign report, hand-author it per the procedure
above before considering the investigation complete.

---

## 5. Completeness gate

`lib/report_completeness.py` is a code-level gate that runs automatically
inside every `generate_fame_report.py` / `generate_fast_report.py` /
`generate_pcap_report.py` call (and is re-checked by `fame_analyze.sh` /
`fast_analyze.sh` / `analyze_pcap.sh` after report generation). It performs
two checks:

1. **`check_narrative`** — does `<case_id>_narrative.md` exist and contain
   `attack_timeline`, this module's `section_*` keys, and all eight shared
   `pptx_*` keys (§2), each with non-empty content?
2. **`check_research_notes`** — do the research notes show evidence of an
   actual investigation, not just mechanical evidence collection? This fails
   if any of:
   - `<!-- summary-placeholder -->` is still present (`finalize` was never
     run — §1e never happened);
   - there are zero `Reflect RF-` entries (§1c/§1e never ran);
   - **every** `step` entry's title matches `^Evidence preserved: ` — i.e.
     the only research-notes activity is the analyze script's own
     chain-of-custody logging, with no Claude-authored interpretation (§1b).

If either check fails, the generated report gets a prominent
`> ⚠️ **INVESTIGATION INCOMPLETE**` banner near the top (after the header
table), listing exactly what's missing, and
`reports/<case_id>/<MODULE>/<hostname-or-stem>/<case_id>_INVESTIGATION_INCOMPLETE.json`
is written with the same detail. The analyze scripts print a matching
`[INCOMPLETE]`/`[OK]` status line to stderr.

**What to do if you see `[INCOMPLETE]` or the banner:**
- If `missing_narrative_sections` is non-empty: write/complete
  `<case_id>_narrative.md` per §2 and this module's schema, then re-run the
  report generator.
- If `missing_reasoning` is non-empty: re-read the preserved evidence under
  `<case_id>_evidence/`, add Claude-authored `step` interpretations (§1b),
  run the mid- and pre-finalize `reflect` entries (§1c/§1e), and call
  `finalize` (§1e) with a real summary — then re-run the report generator.

The marker file is **self-clearing**: re-running the report generator after
both gaps are fixed removes
`<case_id>_INVESTIGATION_INCOMPLETE.json` automatically. Running the check
repeatedly (e.g. via `--check`) is always safe and idempotent.
