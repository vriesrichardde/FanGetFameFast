# <Case Title> — Campaign Forensics Report

> **Claude:** This report is **hand-authored, not auto-generated**. Before
> drafting Sections 2 and 3, read every module's `*_research_notes.md` and
> `*_narrative.md` (and `*_correlation.md` if present) end-to-end. Do not
> concatenate per-module summaries — synthesize across modules. Remove every
> `> Claude:` directive block (including this one) from the final report;
> they must never appear in the rendered output.

| Field | Value |
|-------|-------|
| Case ID | `<CASE-ID>` |
| Subject | `<Subject name/alias — primary asset, e.g. "Greg Schardt (alias: Mr. Evil) — Dell Latitude CPi, Windows XP">` |
| Modules run | `<FAN (Network Forensics) · FAME (Memory Forensics) · FAST (Storage Forensics) — list only modules that ran>` |
| Evidence | `<image/pcap/memory filenames>` |
| Incident date | `<YYYY-MM-DD (incident-location timezone)>` |
| Image acquisition | `<date and examiner, if applicable>` |
| Generated (UTC) | `<YYYY-MM-DD HH:MM>` |
| Prepared by | Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman |
| Severity | `<Critical/High/Medium/Low — short qualifier, e.g. "Historical exposure">` |
| Case status | `<e.g. "Reconstructed", "Active", "Contained">` |

---

## 1. Management Summary

> **Claude:** CISO/Legal register. No IPs, ports, file sizes, hostnames, or
> other technical identifiers. Plain-language narrative of what happened,
> when, and the business/legal impact. Synthesize across all modules that
> ran — this is one story, not N module summaries glued together.
>
> The `Board KPIs` table and `Executive Summary`/`Key Findings` subsections
> below drive the cover/KPI-strip/exec-panel slides of the board PPTX (see
> "Board bullet grammar" below) — fill them in alongside the narrative.

`<2-3 paragraph narrative>`

**Business and legal impact:**
- `<bullet>`
- `<bullet>`

#### Board KPIs

| Label | Value | Detail |
|-------|-------|--------|
| `<KPI 1 label, e.g. Incident Date>` | `<value>` | `<short detail>` |
| `<KPI 2 label, e.g. Vector>` | `<value>` | `<short detail>` |
| `<KPI 3 label, e.g. Exposure>` | `<value>` | `<short detail>` |
| `<KPI 4 label, e.g. Classification>` | `<value>` | `<short detail>` |

##### Executive Summary

> **Claude:** 2-3 headline-first bullets — `**Headline**` followed by a
> 1-2 sentence body. These become the numbered exec panels on the board deck.

- **`<Headline>`** — `<Body sentence(s).>`

##### Key Findings

> **Claude:** 4 short eyebrow/headline/body cards, e.g. LEGAL, ATTRIBUTION,
> EXFILTRATION, ACCOUNT IMPACT (pick categories that fit this case).

- **`<EYEBROW>` — `<Headline>`:** `<Body sentence(s).>`

---

## Board Briefing

> **Claude:** This section drives the board PPTX deck (rendered via
> `lib/render_campaign_report.py` -> `lib/board_deck.py`) — every subsection
> below must use CISO/board language: **no IPs, ports, file paths,
> hostnames/workstation IDs, or RN-/EVT- citation references.** Synthesize
> across all modules that ran into one coherent narrative, not N module
> summaries glued together. Keep each subsection short and
> presentation-ready (bullets, 1-2 sentences each).
>
> Each `###` subsection below pairs board-language prose bullets with a
> `#####` structured sub-section that drives the board deck's card/KPI/
> timeline/priority layouts — see "Board bullet grammar" at the end of this
> file. If the structured sub-section is omitted or doesn't match the
> grammar, the deck falls back to plain bullets for that section.

### Business Impact

> **Claude:** 3-6 bullets on operational, financial, legal, or reputational
> impact in plain language.

- `<bullet>`

##### Impact Assessment

> **Claude:** Ideally 5 eyebrow/headline/body cards (3+2 grid), e.g. PRIVACY,
> SCOPE, EXPOSURE, LEGAL, ATTRIBUTION. 1-5 cards render in this layout (fewer
> than 5 leaves empty grid space; more than 5 are dropped) — the structured
> layout is used as long as at least one card matches the bullet grammar.

- **`<EYEBROW>` — `<Headline>`:** `<Body sentence(s).>`

### Board Timeline

> **Claude:** 4-6 bullets giving high-level milestones in plain language
> ("On <date> at <time>, ..."). No technical identifiers.

- `<bullet>`

##### Incident Timeline

> **Claude:** Ideally 5 time/headline/body steps (5-column timeline). Times
> in the incident-location timezone, `HH:MM` format. 1-5 steps render in
> this layout (more than 5 are dropped).

- **`<HH:MM>` — `<Headline>`** — `<Body sentence(s).>`

### Root Cause & Risk

> **Claude:** 1-2 sentence plain-language root-cause statement, followed by
> 3-5 bullets on key risks if unaddressed.

`<root cause statement>`

- `<risk bullet>`

##### Root Cause Analysis

> **Claude:** One headline/body card — the primary-cause banner.

- **`<Headline root cause statement>`:** `<Body sentence(s).>`

##### Contributing Factors

> **Claude:** Ideally 3 short eyebrow/headline chips, e.g. HUMAN, NETWORK,
> CONTROLS. 1-3 chips render in this layout (more than 3 are dropped).

- **`<EYEBROW>`:** `<Headline>`

##### Residual Risks

> **Claude:** Ideally 4 eyebrow/headline/body cards, labeled R1-R4. 1-4 cards
> render in this layout; the structured layout is used as long as at least
> one card matches the bullet grammar.

- **`<R1>` — `<Headline>`:** `<Body sentence(s).>`

### Response & Containment

> **Claude:** 3-6 bullets on actions taken to contain and respond to the
> incident, in plain language.

- `<bullet>`

##### Response Actions

> **Claude:** Ideally 4 eyebrow/headline/body cards, eyebrows prefixed
> `✓ ` (e.g. `✓ ANALYSIS`, `✓ RECOVERY`, `✓ SPREAD`, `✓ CUSTODY`). 1-4 cards
> render in this layout; the structured layout is used as long as at least
> one card matches the bullet grammar.

- **`✓ EYEBROW` — `<Headline>`:** `<Body sentence(s).>`

### Recommendations

> **Claude:** 3-7 bullets, board-level framing of the recommendations from
> Section `<N+1>` (no technical jargon).

- `<bullet>`

##### Priority Actions

> **Claude:** Up to 5 priority rows, each tagged `[P0]`/`[P1]`/`[P2]`
> (P0 = highest priority).

- **[P0] `<Headline>`** — `<Body sentence(s).>`

### Lessons Learned

> **Claude:** 3-5 bullets — what worked well and what should improve, in
> plain language.

- `<bullet>`

##### Key Insights

> **Claude:** Ideally 4 eyebrow/headline/body cards, e.g. INSIGHT, GAP,
> PRIORITY, CONTROL. 1-4 cards render in this layout; the structured layout
> is used as long as at least one card matches the bullet grammar.

- **`<EYEBROW>` — `<Headline>`:** `<Body sentence(s).>`

---

## 2. Incident Timeline

> **Claude:** Build ONE merged chronological table by walking every module's
> research-notes `event`/step log and merging by timestamp. State the
> incident-location timezone in the intro line and show UTC in brackets per
> CLAUDE.md's timezone rule (use UTC only, explicitly stated, if the location
> is unknown).

`<one sentence stating the chosen timezone and why>`

| Time (`<TZ>`) | UTC | Module | Event |
|------------|-----|--------|-------|
| `<...>` | `<...>` | `<FAN/FAME/FAST>` | `<event description, cite RN-/EVT- IDs>` |

---

## 3. Cross-Domain Correlation (`<Module A> ↔ <Module B>`)

> **Claude:** Numbered named pivots (3.1, 3.2, ...). Each pivot must cite
> specific RN-/EVT- IDs from at least two modules where corroboration
> genuinely exists. Use `correlate_findings.py`'s output (if run) as one
> research input only — **zero matches from that tool does NOT mean no
> correlation exists**; ground this section in the research notes. If a
> pivot genuinely cannot be corroborated by a second module, say so
> explicitly and record it as an open lead in Section 9 / Appendix instead
> of fabricating a pivot.
>
> **Single-module cases:** if no other FAN/FAME/FAST module has run for this
> case ID, state that explicitly (e.g. "Only the FAN module has run for this
> case ID; no cross-domain correlation is possible at this time.") and omit
> the numbered pivot subsections rather than fabricating one.

### 3.1 `<Named pivot point>`

- **`<Module A>`:** `<finding, citing RN-/EVT- ID>`
- **`<Module B>`:** `<finding, citing RN-/EVT- ID>`
- **Significance:** `<why this matters — what one source alone could not show>`

### 3.2 `<Named pivot point>`

- **`<Module A>`:** `<...>`
- **`<Module B>`:** `<...>`
- **Significance:** `<...>`

---

## 4. Unified MITRE ATT&CK Coverage

> **Claude:** Merge the MITRE tables from each module report, deduplicating
> techniques and combining "Confirmed by" / "Evidence" columns where the
> same technique is independently observed by multiple modules.

| Technique | Name | Tactic | Confirmed by | Evidence |
|-----------|------|--------|-------------|----------|
| `<[T####](https://attack.mitre.org/techniques/T####/)>` | `<name>` | `<tactic>` | `<Module(s)>` | `<evidence, cite RN-/EVT- IDs>` |

---

## 5. Indicators of Compromise

> **Claude:** All values defanged (`192[.]168[.]1[.]1`, `evil[.]com`).
> Confidence levels: **CONFIRMED** = directly evidenced in tool output;
> **INFERRED** = one reasoning step from confirmed evidence. Group into
> categories relevant to this case (Network, Identity/Account, Malicious
> Tools, etc.) — one table per category, each as its own `###` subsection.

### `<Category, e.g. Network Indicators>`

| Value | Confidence | Source |
|-------|------------|--------|
| `<defanged value>` | `<CONFIRMED/INFERRED>` | `<module RN-NNN>` |

---

## 6. `<MODULE>` — `<Domain>` Forensics Summary

> **Claude:** One `##` section per module that ran (e.g. "6. FAN — Network
> Forensics Summary", "7. FAST — Storage Forensics Summary", "8. FAME —
> Memory Forensics Summary"). Technical register: precise identifiers, scoped
> conclusions citing the evidence source.

`<narrative summary of this module's findings>`

---

## `<N+1>`. Unified Recommendations

> **Claude:** Merge and deduplicate recommendations from each module report.
> Group by owner.

### Legal / Investigative

1. `<...>`

### Technical (further analysis)

`<...>`

### Network / Preventive

`<...>`

---

## `<N+2>`. Confidence Assessment (Hallucination Guard)

> **Claude:** Hand-curate this — do NOT copy a module's per-report
> Hallucination Guard verbatim. Enumerate the actual substantive findings of
> THIS campaign (typically 12-20), each tagged with a tier and the module(s)
> that confirm it. Compute the overall confidence percentage from this table.

| Tier | Count |
|------|-------|
| 🟢 CONFIRMED — direct tool output, two-source corroboration | `<n>` |
| 🟡 INFERRED — single source, one reasoning step | `<n>` |
| 🟠 ASSUMED — no direct evidence | `<n>` |
| 🔴 UNVERIFIABLE — module not run | `<n>` |

**Overall campaign confidence: `<NN>`% confirmed** (`<x>` of `<y>` substantive
findings backed by direct artifact evidence from at least one module; `<z>`
of those confirmed by two independent modules.)

| ID | Tier | Modules | Finding |
|----|------|---------|---------|
| FND-001 | 🟢 CONFIRMED (`<modules>`) | `<modules>` | `<finding>` |

---

## Appendix — Evidence Sources

> **Claude:** Link to each module's research notes, technical report, the
> session transcript, and the artifact ZIP. Use relative links from this
> file's location.

| Artifact | Location | Description |
|----------|----------|-------------|
| `<...>` | `<relative path>` | `<description>` |

*All findings cited to their source module and research note step. Evidence
integrity preserved — no evidence directories were written to during
analysis.*

---

## Board bullet grammar (reference — remove from final report)

> **Claude:** This section documents the bullet patterns `lib/board_deck.py`
> parses for the `#####` sub-sections under `## 1. Management Summary` and
> `## Board Briefing`. Remove this section from the final report along with
> the other `> Claude:` directives — it is authoring guidance only.

| Pattern | Example | Renders as |
|---------|---------|------------|
| `- **EYEBROW — Headline:** Body.` | `- **LEGAL — Unlawful interception risk:** Private webmail correspondence...` | Eyebrow/headline/body card |
| `- **HH:MM — Headline** — Body.` | `- **10:08 — Login & tool download** — The workstation user logged in...` | Timeline step column |
| `- **[P0] Headline** — Body.` | `- **[P0] Enforce TLS-only webmail** — Require encrypted connections...` | Priority row (P0/P1/P2) |
| `- **Headline** — Body.` | `- **Interception Confirmed** — A workstation on the local network used...` | Numbered exec panel / primary-cause banner |
| `- **EYEBROW:** Headline` | `- **HUMAN:** Network-monitoring tools were downloaded...` | Contributing-factor chip |

If a `#####` sub-section is missing, or its bullets don't match the expected
pattern for that layout, `board_deck.py` falls back to plain bullets for that
section — so an incomplete or freeform sub-section never breaks the deck, it
just loses the structured layout for that slide. Card/chip/step counts are
flexible (see "Ideally N" notes above): as long as at least one bullet
matches the grammar, the structured layout is used, with unused grid slots
left empty and any cards beyond the layout's capacity dropped.
