# Skill: FAN — Forensic Analysis Network (Agentic Coordinator)

## Overview

**FAN** is the agentic PCAP investigation skill. It runs all 22 analysis modules
sequentially, with Claude reading and interpreting each module's output before
proceeding to the next. This gives Claude the role of agentic coordinator — it
can surface HIGH/CRITICAL findings in real time, make intelligent pivot decisions
(e.g., a suspicious IP found in DNS gets added to the CTI lookup queue), and
produce a scoped conclusion rather than a blind batch dump.

### When to use this skill vs. `analyze_pcap.sh`

| Mode | Use when |
|------|----------|
| `/fan` (this skill) | Interactive investigation — you want Claude to interpret findings, flag anomalies in real time, and make pivot decisions between modules |
| `./scripts/analyze_pcap.sh` | Headless / CI use — fully automated, no analyst in the loop, Claude never sees intermediate findings |

### Invocation

```
/fan /path/to/capture.pcap [--case-id FAN-YYYY-XXX]
```

If `--case-id` is omitted, derive it as `FAN-<YYYY>-<STEM>` where `<STEM>` is
the PCAP filename without extension, uppercased, with hyphens preserved and
spaces replaced by hyphens. Use the current year for `<YYYY>`.

---

## Execution protocol

> **Sequential rule (CLAUDE.md constraint):** Do NOT start the next module until
> the output of the current module has been read, interpreted, and appended to
> research notes via `python3 lib/research_notes.py step`. This rule is
> mandatory and supersedes convenience.

After each module:
1. Read `<output_dir>/<protocol>_threats.json` (or equivalent output file).
2. Read `<output_dir>/<protocol>_threats_report.md` (if present).
3. Call `python3 lib/research_notes.py step` to append your interpretation.
4. If any finding is severity **HIGH** or **CRITICAL**: surface it immediately
   to the analyst with the finding text and MITRE technique(s) before continuing.
5. Record any new IPs or FQDNs from HIGH/CRITICAL findings for the CTI
   enrichment queue (Step 22 — `fan_ip_lookup`).
6. Note any cross-module pivot (e.g., "IP seen in DNS beaconing should be
   checked in Suricata alerts") in the research notes as `[PIVOT: ...]`.

**Analytical judgements with no direct tool backing** must be prefixed with
`[ASSUMPTION]` in research notes. The hallucination guard maps this tag
to `ConfidenceTier.ASSUMED`, keeping the IR confidence score honest.

---

## Step-by-step execution

Derive `<STEM>` from the PCAP filename once and reuse it for every step.

```bash
PCAP="/path/to/capture.pcap"
STEM="capture"           # filename without extension
CASE_ID="FAN-2026-XXX"   # --case-id argument or derived value
```

### Step 0 — Initialise research notes

Run **before** any analysis module:

```bash
python3 lib/research_notes.py init \
  --case-id  "$CASE_ID" \
  --module   fan \
  --evidence "$PCAP"
```

This creates `./reports/<case_id>/FAN/<pcap_stem>/<case_id>_research_notes.md` in
the per-module investigation directory. All subsequent `step` calls write to
this file automatically.

---

### Step 1 — PCAP netflow extraction

```bash
./scripts/pcap_analyze.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/pcap/<STEM>/`

Read: `pcap_summary.json` (or equivalent). Note: unique IP count, protocol
distribution, top talkers. These establish the scope of the investigation.

---

### Step 2 — ICMP threat detection

```bash
./scripts/fan_icmp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/icmp_threats/<STEM>/icmp_threats.json` +
`icmp_threats_report.md` + `icmp_flows.csv`

---

### Step 3 — DNS threat detection

```bash
./scripts/fan_dns_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/dns_threats/<STEM>/dns_threats.json` +
`dns_threats_report.md` + `dns_flows.csv`

Pivot trigger: any DGA domain, beaconing domain, or DNS tunnel apex → add to
CTI enrichment queue for Step 22.

---

### Step 4 — NTP threat detection

```bash
./scripts/fan_ntp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/ntp_threats/<STEM>/ntp_threats.json` +
`ntp_threats_report.md` + `ntp_flows.csv`

---

### Step 5 — HTTP(S) unusual pattern detection

```bash
./scripts/fan_http_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/http_threats/<STEM>/http_threats.json` +
`http_threats_report.md` + `http_flows.csv`

Pivot trigger: any beaconing (source, host, path) tuple or suspicious User-Agent
→ add destination host to CTI enrichment queue.

---

### Step 6 — TLS certificate inspection

```bash
./scripts/fan_cert_inspector.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/cert_inspector/<STEM>/cert_inspector.json` +
`cert_inspector_report.md` + `cert_inventory.csv`

---

### Step 7 — TLS session inspection (JA4 / JA3 fingerprinting)

```bash
./scripts/fan_tls_inspector.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/tls_inspector/<STEM>/tls_inspector.json` +
`tls_inspector_report.md` + `tls_sessions.csv`

Pivot trigger: any known C2 JA4/JA3 fingerprint match → HIGH priority finding,
surface immediately and add server IP to CTI queue.

---

### Step 8 — ARP threat detection

```bash
./scripts/fan_arp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/arp_threats/<STEM>/arp_threats.json` +
`arp_threats_report.md` + `arp_flows.csv`

---

### Step 9 — TCP threat detection

```bash
./scripts/fan_tcp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/tcp_threats/<STEM>/tcp_threats.json` +
`tcp_threats_report.md` + `tcp_flows.csv`

---

### Step 10 — UDP threat detection

```bash
./scripts/fan_udp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/udp_threats/<STEM>/udp_threats.json` +
`udp_threats_report.md` + `udp_flows.csv`

---

### Step 11 — DHCP threat detection

```bash
./scripts/fan_dhcp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/dhcp_threats/<STEM>/dhcp_threats.json` +
`dhcp_threats_report.md` + `dhcp_flows.csv`

---

### Step 12 — mDNS threat detection

```bash
./scripts/fan_mdns_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/mdns_threats/<STEM>/mdns_threats.json` +
`mdns_threats_report.md` + `mdns_flows.csv`

---

### Step 13 — QUIC threat detection

```bash
./scripts/fan_quic_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/quic_threats/<STEM>/quic_threats.json` +
`quic_threats_report.md` + `quic_flows.csv`

---

### Step 14 — SNMP threat detection

```bash
./scripts/fan_snmp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/snmp_threats/<STEM>/snmp_threats.json` +
`snmp_threats_report.md` + `snmp_flows.csv`

---

### Step 15 — NBNS threat detection

```bash
./scripts/fan_nbns_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/nbns_threats/<STEM>/nbns_threats.json` +
`nbns_threats_report.md` + `nbns_flows.csv`

---

### Step 16 — LLMNR threat detection

```bash
./scripts/fan_llmnr_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/llmnr_threats/<STEM>/llmnr_threats.json` +
`llmnr_threats_report.md` + `llmnr_flows.csv`

---

### Step 17 — STUN threat detection

```bash
./scripts/fan_stun_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/stun_threats/<STEM>/stun_threats.json` +
`stun_threats_report.md` + `stun_flows.csv`

---

### Step 18 — SSDP threat detection

```bash
./scripts/fan_ssdp_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/ssdp_threats/<STEM>/ssdp_threats.json` +
`ssdp_threats_report.md` + `ssdp_flows.csv`

---

### Step 19 — NetBIOS threat detection

```bash
./scripts/fan_netbios_threats.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/netbios_threats/<STEM>/netbios_threats.json` +
`netbios_threats_report.md` + `netbios_flows.csv`

---

### Step 20 — File hash extraction + OSINT

```bash
./scripts/fan_file_hashes.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/file_hashes/<STEM>/file_hashes.json` + `file_hashes_report.md` +
`file_hashes.csv`

Read the JSON; note extracted file count, protocol breakdown (HTTP/SMB/TFTP/IMF/DICOM),
and any malicious/suspicious OSINT verdicts. A non-zero OSINT hit count is an immediate
HIGH finding — surface to the analyst before continuing.

---

### Step 21 — Suricata IDS

```bash
./scripts/fan_suricata.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/suricata/<STEM>/suricata_alerts.json` +
`suricata_report.md`

Pivot trigger: any Suricata alert matching a rule from Steps 3–19 (e.g., a DNS
alert that corroborates a beaconing finding) → annotate the earlier research
note step with `[CORROBORATED BY SURICATA: <rule_name>]`.

---

### Step 22 — YARA rule matching

```bash
./scripts/fan_yara_pcap.sh "$PCAP" --case-id "$CASE_ID"
```

Output: `./analysis/yara_pcap/<STEM>/yara_matches.json` +
`yara_report.md`

---

### Step 23 — CTI enrichment (IP / FQDN reputation)

Run after all protocol detectors, file hashes, Suricata, and YARA. By this point the CTI
enrichment queue should include any IPs and FQDNs flagged as HIGH/CRITICAL in
previous steps.

The input files come from the pcap_analyze output directory (Step 1):

```bash
FQDN_FILE="./analysis/pcap/$STEM/unique_fqdns.txt"
IP_FILE="./analysis/pcap/$STEM/unique_ips.txt"

python3 lib/fan_ip_lookup.py "$FQDN_FILE" "$IP_FILE" --case-id "$CASE_ID"
```

Output: `./analysis/fan_ip/<STEM>/ip_lookup_results.json`

Read the results and cross-reference against findings from previous steps. Any
IP or FQDN rated **malicious** or **suspicious** by OSINT that also appeared in
a protocol detector finding should be noted as a corroborating data point.

---

## Narrative file (required before Step 24)

After completing all analysis steps and **before** calling `generate_pcap_report.sh`,
write the narrative file. This feeds the **Incident Timeline** section of the report and
all eight slides of the board PPTX deck (Executive Summary, Business Impact, Incident
Timeline, Root Cause & Risk, Response & Containment, Recommendations, Lessons Learned).
Without it those slides show generic placeholder text — write every section yourself,
in your own words, based on what you actually found. Do not rely on
`lib/narrative_generator.py`'s keyword-matching heuristics to fill these in; that
generator is a headless fallback for batch/no-Claude runs only and produces noticeably
weaker, often generic content.

Write this file as `./reports/<CASE_ID>/FAN/<STEM>/<CASE_ID>_narrative.md`:

```markdown
<!-- narrative:<CASE_ID> generated:<UTC timestamp> model:claude-sonnet-4-6 -->

## attack_timeline

On [exact timestamp UTC], [source IP / host] [what happened — e.g. C2 beaconing,
data exfiltration, DoS, lateral movement indicator, suspicious scanning].
This is [confirmed / assumed] based on [detector finding and research note RN-NNN].

[Continue chronologically — one paragraph per significant event covering the full
capture window. No raw IPs or port numbers — describe behaviour in business terms.
Use "confirmed" when backed by direct detector output; "assumed" when inferred from
cross-module correlation.]

## pptx_executive_summary

[3–5 bullet points. CISO language. No IPs, ports, or protocol names.
Example: "• Outbound communications consistent with command-and-control activity
were observed throughout the capture window."]

## pptx_risk

[Business risks — data exposure, regulatory, operational. No technical identifiers.]

## pptx_impact

[What was affected: services, users, data — in plain language.]

## pptx_mitigations

[Containment or monitoring actions taken or in progress.]

## pptx_recommendations

[Concrete follow-up actions with suggested owner labels.]

## pptx_timeline

[4-6 bullets: the board-level timeline. Same chronology as attack_timeline, but
plain language, no IPs/ports/protocol names/RN-NNN citations — "On [date] at
[time], ..." Each bullet should be readable on its own as a slide line.]

## pptx_root_cause

[1-2 sentences: how did this happen, in plain language — e.g. phishing, an
exposed/weak service, compromised credentials, an unpatched vulnerability,
physical access, misconfiguration. Be specific to what you actually found in
this capture; do not use a generic placeholder if the evidence supports a
real conclusion.]

## pptx_lessons_learned

[3-5 bullets: what worked well in this investigation/response, and what gaps
or improvements this incident points to. Plain language, board-appropriate.]
```

**Rules:**
- Write all sections even if evidence is thin — note the gap explicitly.
- `attack_timeline` must span the entire capture window chronologically.
- Use RN-NNN references to link each event to the research notes step.
- `pptx_*` sections must be free of IPs, ports, protocol names, file paths,
  hostnames/workstation IDs, and RN-/EVT- citation references — write them as
  you would for a board/CISO audience, not a technical one.

---

### Step 24 — Generate consolidated incident report

```bash
./scripts/generate_pcap_report.sh --stem "$STEM" --case-id "$CASE_ID" \
  --case-dir "./reports/$CASE_ID/FAN/$STEM" \
  --docs-dir "./reports/$CASE_ID/documents"
```

This step:
- Reads `./reports/<CASE_ID>/FAN/<STEM>/<CASE_ID>_narrative.md` and injects the `attack_timeline`
  section into the **Incident Timeline** of the report.
- Aggregates all module outputs into a single Markdown + PDF + PPTX + DOCX report.
- Runs the **hallucination guard** automatically (`_build_fan_hallucination_guard_section`
  in `lib/generate_pcap_report.py:3375`) — tagging every key conclusion with a
  `ConfidenceTier` (CONFIRMED / INFERRED / ASSUMED / UNVERIFIABLE).
- Generates the threat timeline, IOC table, MITRE ATT&CK coverage, and
  recommendations sections.

Output (hierarchical layout):
- `./reports/<CASE_ID>/FAN/<STEM>/<STEM>_incident_report.md`
- `./reports/<CASE_ID>/documents/<STEM>_incident_report.pdf`
- `./reports/<CASE_ID>/documents/<STEM>_fan_presentation.pptx`
- `./reports/<CASE_ID>/documents/<STEM>_fan_report.docx`

---

### Step 25 — Generate timeline visualisation

```bash
python3 lib/generate_timeline.py "$CASE_ID" "./reports/$CASE_ID" "./reports/$CASE_ID"
```

Produces swimlane PNG images and an interactive HTML timeline from the research notes:
- `./reports/<CASE_ID>/<CASE_ID>_timeline.html`
- `./reports/<CASE_ID>/<CASE_ID>_timeline_attacker_p1.png`
- `./reports/<CASE_ID>/<CASE_ID>_timeline_defender_p1.png`
- `./reports/<CASE_ID>/<CASE_ID>_timeline_combined_p1.png`

---

### Upload all artifacts to the investigations vault via MCP

```
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<STEM>_incident_report.md
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/documents/<STEM>_incident_report.pdf
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/documents/<STEM>_fan_presentation.pptx
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/documents/<STEM>_fan_report.docx
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_narrative.md
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_research_notes.md
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_timeline.html
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_timeline_attacker_p1.png
investigations_write_file: /home/sansforensics/cases/<CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_timeline_combined_p1.png
```

---

## Cross-module research notes separation

When FAN is triggered by a FAST investigation (i.e., a PCAP file was found on a suspect disk
and forwarded for analysis), create a **separate research notes file** under the FAN case ID —
do NOT append FAN steps to the FAST research notes file.

**Pattern:**
1. Create `FAN-<YEAR>-<INHERITED_ID>_research_notes.md` via
   `python3 lib/research_notes.py init --case-id FAN-... --module fan --evidence <pcap_path>`.
2. Edit the header of the new file to include `**Parent case:**` and `**Triggered by:**` lines
   citing the FAST case ID and the RN step that identified the PCAP.
3. Add a `## Cross-module Reference` section to the **FAST** research notes pointing at the
   FAN notes file, the FAN report, and the combined report:
   ```markdown
   ## Cross-module Reference
   A network capture file (`<path on disk>`, inode <N>) was found during FAST analysis (<RN-NNN>).
   **FAN investigation notes:** `FAN-<id>_research_notes.md`
   **FAN incident report:** `<stem>_incident_report.md`
   **Campaign report:** `<fast_case_id>_campaign_report.md`
   ```

This keeps each module's investigative log self-contained while preserving bidirectional
cross-references for any analyst reading either file.

---

## Campaign Report (hand-authored)

If FAME, FAST, or another FAN run already exists for this case ID, the
per-case campaign report (`<case_id>_campaign_report.*`) must be hand-authored,
not auto-generated:

1. Read this module's research notes end-to-end, plus the research notes of
   every other module that has completed for this case ID.
2. Hand-author `./reports/<case_id>/<case_id>_campaign_report.md` following
   `docs/campaign_report_template.md` — Incident Timeline merged across
   modules, Cross-Domain Correlation pivots citing RN-/EVT- IDs from at least
   two modules (or stating explicitly that none exist), unified MITRE/IOC
   tables, and a hand-curated Hallucination Guard FND-list with an overall
   confidence percentage. `lib/correlate_findings.py`'s output (a best-effort
   research aid) and `lib/generate_combined_report.py`'s
   `_merge_*`/`_extract_*` helpers may be used as research aids when
   pre-populating tables.
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

---

## Deep-dive methodology (manual tshark analysis)

After all 22 automated modules have run, perform a manual deep-dive before writing the
narrative. This catches protocol-level detail that the automated detectors do not expose.
All deep-dive steps are logged as `step` calls (RN-NNN) under distinct titles.

Log each step as:
```bash
python3 lib/research_notes.py step \
  --case-id "$CASE_ID" \
  --title "Deep Dive N: <title>" \
  --action "<tshark or tool command>" \
  --why "<case-specific question being answered>" \
  --outcome "<findings — cite specific values, not generic summaries>"
```

### Deep Dive 1 — Network baseline

```bash
# Capture summary (duration, packet count, byte count, bits/s)
capinfos "$PCAP"

# Protocol hierarchy (packet distribution by protocol)
tshark -r "$PCAP" -q -z io,phs
```

Record: total packets, duration, data volume, dominant protocol share. This establishes
scope and flags captures that are unexpectedly thin (possibly clipped) or dominated by
a single protocol (single-session captures, beaconing, exfiltration).

### Deep Dive 2 — Device and identity fingerprinting

```bash
# All Ethernet conversations (MAC + IP mapping)
tshark -r "$PCAP" -q -z conv,eth

# All IP conversations
tshark -r "$PCAP" -q -z conv,ip

# NBNS verbose (hostname announcements, browser elections)
tshark -r "$PCAP" -V -Y "nbns" 2>/dev/null | grep -E "Name:|Type:|Address:|Data:"
```

Identify OUI for every MAC address (lookup at https://www.wireshark.org/tools/oui-lookup.html
or `tshark -r "$PCAP" -T fields -e eth.src_resolved`). OUI reveals vendor → device class.
NBNS announcements reveal Windows NetBIOS hostnames of machines on the segment.

### Deep Dive 3 — Session cookie and credential extraction

For HTTPS-absent HTTP sessions carrying authentication tokens:

```bash
# Extract full Cookie headers with frame context
tshark -r "$PCAP" -Y "http.cookie" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e http.request.uri -e http.cookie 2>/dev/null

# Extract Set-Cookie responses
tshark -r "$PCAP" -Y "http.set_cookie" -T fields \
  -e frame.number -e ip.src -e http.set_cookie 2>/dev/null
```

For Microsoft Passport sessions specifically, parse:
- `MSPAuth` / `MSPProf` — active session token (replayable, compute Shannon entropy)
- `MSPPre` — pre-fill field → **victim's email address**
- `MSPRequ` → `lt=<unix_epoch>` — **victim's login timestamp**

`lt=` decoding: `python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(1093620869))"`

### Deep Dive 4 — URL timestamp and session parameter decoding

```bash
# All HTTP request URIs + timestamps + query strings
tshark -r "$PCAP" -Y "http.request" -T fields \
  -e frame.time_utc -e ip.src -e http.host \
  -e http.request.uri -e http.request.method 2>/dev/null
```

Decode protocol-specific timestamps found in query parameters:
- **Unix epoch** (`lt=`, `t=`): `python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(<value>))"`
- **.NET DateTime ticks** (`time=`): `python3 -c "import datetime; print(datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=<ticks>//10))"`

Note PocketPC-specific endpoints (e.g., `composeppc.aspx`, `folder.aspx`) as evidence of
victim device class.

### Deep Dive 5 — TCP stream reconstruction (response bodies + POST bodies)

```bash
# List all HTTP objects (carved files from HTTP payloads)
tshark -r "$PCAP" --export-objects http,/tmp/http_exports/ 2>/dev/null
ls /tmp/http_exports/ | head -20

# Follow a specific TCP stream (replace N with stream index)
tshark -r "$PCAP" -q -z follow,tcp,ascii,N 2>/dev/null | head -200

# Find TCP streams containing POST bodies
tshark -r "$PCAP" -Y "http.request.method == POST" -T fields \
  -e tcp.stream -e http.request.uri -e http.file_data 2>/dev/null
```

Use `--export-objects http` to carve all HTTP response bodies to disk. Follow the stream
index for any POST request to recover the submitted form body. For Hotmail/webmail sessions
this includes the full email body (`Body=`, `Subject=`, `To=`).

### Deep Dive 6 — UPnP/SSDP gateway profiling

```bash
# All SSDP frames verbose
tshark -r "$PCAP" -V -Y "ssdp" 2>/dev/null | \
  grep -E "NOTIFY|ST:|USN:|LOCATION:|SERVER:|Cache-Control:|NT:"
```

UPnP NOTIFY broadcasts from the router/gateway expose:
- **Server** field: OS and UPnP stack version (e.g., `NT/5.0 UPnP/1.0`)
- **USN** (Unique Service Name): UUID derived from MAC → confirms gateway MAC
- **LOCATION**: URL to the description XML (`descrip.xml`) — readable at investigation time
- **Cache-Control: max-age=N**: TTL=N as a non-spoofed SSDP multicast is not IP spoofing

> False-positive note: automated UDP detectors may flag SSDP multicast
> (192.168.x.x:1900 → 239.255.255.250) as "UDP Reflection/Amplification" (no request
> visible in the capture window) and TTL=4 as "IP Spoofing." Both are expected RFC 2608
> behaviour. Document as false positives in the research notes.

### Deep Dive 7 — TCP expert analysis

```bash
# Expert info (RSTs, retransmissions, duplicate ACKs, out-of-order)
tshark -r "$PCAP" -q -z expert 2>/dev/null | head -40

# HTTP server headers (compare across IPs for version consistency)
tshark -r "$PCAP" -Y "http.server" -T fields \
  -e ip.src -e http.server 2>/dev/null | sort -u
```

TCP RSTs at session close are normal on Windows CE/PocketPC (no FIN/ACK handshake).
Duplicate ACKs on 802.11 segments reflect 802.11b reordering — not an attack indicator.
Mismatched HTTP server headers across IPs from the same domain indicate CDN sharding —
document the header values as device/infrastructure fingerprints.

---

## Stop condition

The investigation is complete when:
- All 22 modules have run and their outputs have been read and appended to
  research notes.
- No new pivots remain (all pivot-flagged IPs/FQDNs have been checked in
  Step 22).
- The consolidated report has been generated and uploaded to the investigations
  vault.
- A scoped conclusion can be stated that cites its evidence source (e.g.,
  "No signs of lateral movement observed in the PCAP file").

---

## Hallucination guard — analyst responsibilities

The guard fires automatically during report generation. To keep the IR
confidence score accurate:

| Situation | What to write in research notes |
|-----------|----------------------------------|
| Finding backed by direct tool output (JSON finding, Suricata alert, YARA match) | Plain statement — guard assigns `CONFIRMED` |
| Finding derived from one analytical step (e.g., parent-child deduction, protocol correlation) | Note the inference chain — guard assigns `INFERRED` |
| Analytical judgement with no direct tool backing | Prefix with `[ASSUMPTION]` — guard assigns `ASSUMED` |
| Evidence unavailable (plugin skipped, no traffic of this type) | Note absence — guard assigns `UNVERIFIABLE` |

---

## Constraints (inherited from CLAUDE.md)

- **Never write to** `/mnt/`, `/media/`, or any `evidence/` directory.
- Analysis WIP goes to `./analysis/` only.
- Scoped conclusions must cite their evidence source.
- Timestamps in reports use the timezone of the incident's geographical location.
  If unknown, use UTC and state it explicitly.
- Internal processing, vault storage, and log entries use UTC.
