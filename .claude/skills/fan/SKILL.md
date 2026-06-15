# Skill: FAN — Forensic Analysis Network (Agentic Coordinator)

## Overview

**FAN** is the agentic PCAP investigation skill. Claude acts as the investigator,
not as a runner of a fixed checklist. The 22 protocol/IDS/YARA detectors are a
**toolbox and a completeness floor** — cheap, deterministic, signature-based
coverage that anchors the Hallucination Guard's `CONFIRMED` tier. They are
**not** the boundary of the investigation.

The actual discovery work is driven by an iterative loop:

1. **Triage** — generate statistics on protocols, flows, and conversations to
   understand the shape of the capture.
2. **Sweep the baseline** — run the toolbox of automated detectors to get a
   fast, deterministic floor of known-pattern findings.
3. **Hypothesize & investigate** — based on (1) and (2), decide what is worth
   digging into. Any technique is in scope: a protocol module, manual `tshark`
   reconstruction, a content/PII sweep, a conversation-volume drill-down —
   chosen because it answers a real question raised by the triage or baseline
   sweep, not because it's "next on the list."
4. **Interpret** — read the raw output, understand what it actually means in
   context, not just whether a detector fired.
5. **Reflect & pivot** — ask "what does this open up? what's still
   unexplained? what would a human analyst chase next?" Loop back to step 3
   for any new lead. Stop only when no new pivots remain.

A fixed sequential pass through 22 signature-based detectors will, by
construction, never surface anything outside the detector authors' anticipated
threat patterns (e.g. a benign-reputation site used to send an
identity-spoofed harassment email). The reflect-and-pivot loop is what catches
those — it is the primary engine of the investigation, with the toolbox as its
fuel.

### When to use this skill vs. `analyze_pcap.sh`

| Mode | Use when |
|------|----------|
| `/fan` (this skill) | Interactive investigation — Claude runs the triage→sweep→hypothesize→interpret→reflect loop, surfaces findings in real time, and follows leads wherever they go |
| `./scripts/analyze_pcap.sh` | Headless / CI use — fully automated baseline-sweep-only run, no analyst in the loop, no reflect/pivot loop |

### Invocation

```
/fan /path/to/capture.pcap [--case-id FAN-YYYY-XXX] [--no-vault] [--no-upload]
```

If `--case-id` is omitted, derive it as `FAN-<YYYY>-<STEM>` where `<STEM>` is
the PCAP filename without extension, uppercased, with hyphens preserved and
spaces replaced by hyphens. Use the current year for `<YYYY>`.

`--no-vault` and `--no-upload` mirror the identically-named flags on
`fame_analyze.sh`/`fast_analyze.sh`/`analyze_pcap.sh`:

| Flag | Effect |
|------|--------|
| `--no-vault` | Skip the "Vault findings write" step (`lib/vault_writer.py --module fan`) at the end of the investigation — no TTPs/IOCs/risks are written to the Obsidian vault for this case. |
| `--no-upload` | Skip the "Upload all artifacts to the investigations vault via MCP" step — reports stay local under `./reports/<CASE_ID>/` only. |

---

## Research notes — logging rule (CLAUDE.md constraint)

See `docs/investigation_discipline.md` §1 for the shared `init`/`step`/
`reflect`/`event`/`finalize` cadence (FAN's `init` call is in Step 0 below;
`--module fan`). The logging rule below is FAN's phase-loop-specific framing
of that same discipline.

> Do NOT run the next investigation action until the output of the current
> action has been read, interpreted, and appended to research notes via
> `python3 lib/research_notes.py step`. This rule is mandatory and supersedes
> convenience. It applies equally to baseline-sweep modules and to
> hypothesis-driven/manual techniques — the loop is sequential in its
> *logging*, even though it is not sequential in *what it chooses to do next*.

For every action:
1. Read the raw output (JSON, report.md, tshark output, etc.) in full.
2. Call `python3 lib/research_notes.py step` with a title, the action taken,
   the question it was meant to answer (`--why`), the outcome, and
   `--source-data` pointing at the raw output this step is based on (see
   "Preserve raw analysis artifacts" below for the path convention).
3. If any finding is severity **HIGH** or **CRITICAL**, or is itself a major
   new lead (like RN-029 in a past case): surface it immediately to the
   analyst before continuing.
4. Record any new IPs/FQDNs/identifiers worth checking against CTI/OSINT.
5. Note any pivot opened up by this result as `[PIVOT: ...]` — this is the
   input to step 5 of the loop (Reflect & pivot). A pivot is not optional
   color; it is a candidate for the next iteration of step 3.
6. **If this step establishes a confirmed action by the traffic's subject
   (attacker, victim, or other monitored host) with a direct timestamp from
   the evidence** — e.g. a session-cookie replay, a malicious upload/download,
   a C2 check-in, a form submission — **also log it via
   `python3 lib/research_notes.py event ...`** per
   `docs/investigation_discipline.md` §1d, in addition to the `step` entry.
   This is what populates the attacker-perspective timeline
   (`lib/generate_timeline.py`); a `step`-only entry will not appear there.

**Analytical judgements with no direct tool backing** must be prefixed with
`[ASSUMPTION]` in research notes. The hallucination guard maps this tag to
`ConfidenceTier.ASSUMED`, keeping the IR confidence score honest.

---

## The investigation loop

### Step 0 — Initialise research notes

Run **before** anything else:

```bash
PCAP="/path/to/capture.pcap"
STEM="capture"           # filename without extension
CASE_ID="FAN-2026-XXX"   # --case-id argument or derived value

python3 lib/research_notes.py init \
  --case-id  "$CASE_ID" \
  --module   fan \
  --evidence "$PCAP"
```

This creates `./reports/<case_id>/FAN/<pcap_stem>/<case_id>_research_notes.md`.
All subsequent `step` calls write to this file via `--case-dir
"./reports/$CASE_ID/FAN/$STEM"`.

### Phase 1 — Triage & baseline statistics

Before running any detector, get the shape of the capture. This is cheap and
frames everything that follows.

```bash
# Capture summary (duration, packet count, byte count, bits/s)
capinfos "$PCAP"

# Protocol hierarchy (packet/byte distribution by protocol)
tshark -r "$PCAP" -q -z io,phs

# Ethernet conversations (MAC + IP mapping, OUI vendor → device class)
tshark -r "$PCAP" -q -z conv,eth

# IP conversations (top talkers, byte volumes — who dominates the capture?)
tshark -r "$PCAP" -q -z conv,ip
```

Log one research-notes step covering: total packets/duration/volume, dominant
protocol(s) and their share, number of distinct hosts and which ones dominate
traffic volume, and any device/vendor identification from MAC OUIs. This step
is the foundation for Phase 3's hypotheses — e.g. "host X is 80% of traffic
and almost all of it is one protocol" is itself a hypothesis worth chasing,
independent of whether any detector fires on it.

Flag immediately, as observations to revisit in Phase 3/5:
- A capture unexpectedly thin or short (possibly clipped).
- One protocol or one host/pair dominating the byte count.
- Any host/device class that seems out of place for the environment.

### Phase 2 — Baseline sweep (toolbox)

Run the full toolbox of automated detectors (catalog below) to establish the
deterministic floor: known-bad signatures, IDS/YARA matches, file-hash OSINT,
MITRE-mapped protocol anomalies. Each module's output must be read and logged
per the rule above before moving on, but the *order* may be adapted to the
Phase 1 findings (e.g. if Phase 1 shows the capture is almost entirely DNS,
run the DNS detector first).

Run **all** modules in the catalog — this is the completeness floor the
Hallucination Guard relies on. Do not skip modules because Phase 1 looked
"boring" for that protocol; absence of expected traffic is itself a finding
(`UNVERIFIABLE`/"no activity of this type observed").

For any finding severity **HIGH** or **CRITICAL**, or any non-zero malicious
OSINT verdict (file hashes, CTI): surface immediately with the finding text
and MITRE technique(s).

**Mandatory content/identity sweep trigger.** If Phase 1's protocol hierarchy
shows *any* payload-bearing application protocol — HTTP, FTP, SMTP/POP3/IMAP,
Telnet, IRC, IM protocols (MSN/YMSG/XMPP/AIM), SMB/CIFS, or any other protocol
whose stream can be reconstructed as human-readable content via `tshark -z
follow,tcp,ascii,N` or `--export-objects` — run the Content/Identity pattern
sweep (Toolbox B, below) across the entire capture as part of this baseline,
not as an opportunistic Phase 3 technique gated on a detector firing or a
pivot. Log it as its own step even if it returns nothing
(`UNVERIFIABLE`/"no identity strings or notable content observed").
Rationale: the 22 detectors are reputation/signature-based and structurally
cannot flag a normal-looking session on a benign-reputation host or protocol
that carries abusive, coercive, or incriminating *content* (e.g. an
anonymous-harassment webmail POST to a clean-reputation site, or extortion
language inside an otherwise-ordinary IM session) — the only way to catch
this class of finding — including malicious-insider, extortion, and
harassment scenarios — is to read the content itself, unconditionally,
whenever a content-bearing protocol is present.

### Phase 3 — Hypothesize & investigate

This is where the investigation actually happens. Using everything from
Phases 1–2 (and, on later iterations, Phase 5's pivots), decide what questions
remain unanswered and pick whatever technique answers them — not limited to
running the "next" module.

Ask, for every host/flow/finding that stands out:
- *What is this, concretely?* (not just "detector X fired" — read the actual
  packets/bytes)
- *Who is involved* (identity: cookies, usernames, emails, device IDs,
  certificates)?
- *What did they do* — and could that action have a real-world consequence
  (a message sent, a file transferred, a credential exposed, an account
  accessed)?
- *Is there a benign-looking channel carrying something not benign?* —
  reputation-based detectors will not catch this; only reading content does.

Toolbox B (manual `tshark` techniques, below) is the primary instrument here:
session/cookie/credential extraction, TCP stream reconstruction, content/PII
sweeps, timestamp decoding, device fingerprinting. Use whichever techniques
the questions above demand — there is no fixed order and no fixed count.

Log each investigative action as its own research-notes step (title it
descriptively, e.g. "Investigate: dominant HTTP host from Phase 1" rather than
"Deep Dive N" — the numbering is no longer meaningful since order is
hypothesis-driven).

### Phase 4 — Interpret

For each result from Phase 3, write down in research notes what it actually
*means* for the case — not a restatement of the raw output. Distinguish:
- What is directly observed (cite the evidence source).
- What is inferred from combining multiple observations (`INFERRED`).
- What is a judgement call with no direct backing (`[ASSUMPTION]`).

If the result raises the severity or framing of an earlier finding (e.g. a
host previously assessed as a benign secondary user turns out to be the
source of the case's primary actionable finding), say so explicitly and note
that earlier conclusions may need revision.

### Phase 5 — Reflect & pivot

After interpreting, explicitly ask:
- What loose ends remain from Phase 1 (unexplained traffic dominance, odd
  devices, thin coverage)?
- What `[PIVOT: ...]` items have accumulated and not yet been chased?
- Does this finding change how an earlier host/flow/finding should be read,
  opening a new question about it?
- Would a human analyst, reading this finding, immediately want to know
  something else?
- **For every host/flow already characterized as benign or ordinary**
  (streaming, browsing, chat, routine background traffic): has its *content* —
  not just its destinations or protocol mix — actually been read via the
  Content/Identity sweep? A "benign" label based on protocol/destination alone
  is not the same as having read what was said or sent. A host running
  webmail, IM, file transfer, or any user-content-bearing protocol is an
  automatic candidate for this sweep regardless of how unremarkable its
  traffic otherwise looks.
- **Does any finding reference content that was not fully resolved to its
  original, readable form?** A finding is incomplete — not concluded — if it
  identifies a specific object, request, message, file, or session
  (e.g. a viewed thread, an attachment, a compressed/encoded payload, a
  fragment split across streams) but stops at metadata because the payload
  was compressed, encoded, binary, truncated, or otherwise not directly
  legible with the technique first tried. Any such lead is a mandatory pivot:
  apply whatever technique recovers the underlying data (decompression,
  re-assembly across streams/fragments, decoding, carving, following a
  reference/URL/ID to the object it points at, correlating with another
  module's output) and re-read the result before writing "bits and pieces,"
  "unrecoverable," "not further examined," or any similarly scoped-down
  conclusion. Recovered context can itself surface new findings (credentials,
  additional identities, further pivots) — treat it as a first-class
  investigative step, not cleanup.
- **Has every host attributed as the actor behind a significant finding**
  (sender/recipient of a harassing or threatening message, party to a
  session-hijack, source of exfiltration or policy-violating traffic, etc.)
  been run through the Actor Profiling pivot (Toolbox B)? Attribution to an
  IP/MAC address alone is a starting point, not an endpoint — a finding that
  names a responsible host but stops there, without attempting
  attribution-layer disambiguation, device fingerprinting, logged-in-identity
  extraction, and an intent/premeditation timeline around the event window, is
  incomplete. This pivot is mandatory, not opportunistic — run it
  automatically the moment a host is attributed to a significant finding,
  without waiting to be asked.
- **Does an identity attributed to a host actually reach the attribution
  layer the finding needs?** If a host/network/device was profiled once (e.g.
  earlier in the investigation) and a later finding on the "same" host reuses
  that profile's identity, re-check step 0 of Actor Profiling: a single WAN IP
  can hide multiple MACs/devices (NAT, shared connection, DHCP reassignment); a
  single device can run multiple browsers/app instances, each with its own
  User-Agent and persistent identifier cookies (e.g. Google `PREF=ID=...`);
  and a single browser session can authenticate as different accounts at
  different times, or have its cookies replayed by a different session
  entirely. An identity is only corroboration for a *specific* finding if the
  finding's own traffic carries evidence reaching that identity's layer —
  otherwise it is a separate, unconfirmed lead and the finding's actual actor
  may still be unidentified.

If yes to any of the above: return to Phase 3 with that question. If no new
pivots remain and every flagged item from Phases 1–2 has been either explained
or explicitly marked `UNVERIFIABLE`/false-positive with reasoning: proceed to
narrative + report generation.

This loop (3→4→5→3...) is the core of the investigation. The number of
iterations is whatever the evidence demands — a thin, uneventful capture may
need one pass; a rich capture may need many.

---

## Toolbox A — Automated protocol / IDS / YARA detectors

Run all of these during Phase 2. Each writes JSON + Markdown + CSV under
`./analysis/<module>/<STEM>/`. `--case-id "$CASE_ID"` is passed to every
script.

| # | Module | Script | Notes / pivot triggers |
|---|--------|--------|-------------------------|
| 1 | PCAP netflow/baseline | `./scripts/pcap_analyze.sh "$PCAP"` | Produces `unique_ips.txt` / `unique_fqdns.txt` for module 23 (CTI). Run first. |
| 2 | ICMP threats | `./scripts/fan_icmp_threats.sh "$PCAP"` | |
| 3 | DNS threats | `./scripts/fan_dns_threats.sh "$PCAP"` | Any DGA domain, beaconing domain, or DNS-tunnel apex → CTI queue |
| 4 | NTP threats | `./scripts/fan_ntp_threats.sh "$PCAP"` | |
| 5 | HTTP(S) threats | `./scripts/fan_http_threats.sh "$PCAP"` | Beaconing (source, host, path) tuple or suspicious User-Agent → CTI queue |
| 6 | TLS certificate inspection | `./scripts/fan_cert_inspector.sh "$PCAP"` | |
| 7 | TLS session inspection (JA3/JA4) | `./scripts/fan_tls_inspector.sh "$PCAP"` | Known C2 JA3/JA4 match → HIGH, surface immediately, server IP → CTI queue |
| 8 | ARP threats | `./scripts/fan_arp_threats.sh "$PCAP"` | |
| 9 | TCP threats | `./scripts/fan_tcp_threats.sh "$PCAP"` | |
| 10 | UDP threats | `./scripts/fan_udp_threats.sh "$PCAP"` | |
| 11 | DHCP threats | `./scripts/fan_dhcp_threats.sh "$PCAP"` | |
| 12 | mDNS threats | `./scripts/fan_mdns_threats.sh "$PCAP"` | |
| 13 | QUIC threats | `./scripts/fan_quic_threats.sh "$PCAP"` | |
| 14 | SNMP threats | `./scripts/fan_snmp_threats.sh "$PCAP"` | |
| 15 | NBNS threats | `./scripts/fan_nbns_threats.sh "$PCAP"` | |
| 16 | LLMNR threats | `./scripts/fan_llmnr_threats.sh "$PCAP"` | |
| 17 | STUN threats | `./scripts/fan_stun_threats.sh "$PCAP"` | |
| 18 | SSDP threats | `./scripts/fan_ssdp_threats.sh "$PCAP"` | See false-positive note in Toolbox B (UPnP/SSDP) |
| 19 | NetBIOS threats | `./scripts/fan_netbios_threats.sh "$PCAP"` | |
| 20 | File hashes + OSINT | `./scripts/fan_file_hashes.sh "$PCAP"` | Non-zero malicious/suspicious OSINT verdict → HIGH, surface immediately |
| 21 | Suricata IDS | `./scripts/fan_suricata.sh "$PCAP"` | Any alert corroborating an earlier finding → annotate that step `[CORROBORATED BY SURICATA: <rule_name>]` |
| 22 | YARA rule matching | `./scripts/fan_yara_pcap.sh "$PCAP"` | |
| 23 | CTI enrichment (IP/FQDN reputation) | `python3 lib/fan_ip_lookup.py ./analysis/pcap/$STEM/unique_fqdns.txt ./analysis/pcap/$STEM/unique_ips.txt --case-id "$CASE_ID"` | Run after the CTI queue (from modules 3, 5, 7, plus any Phase 3 pivots) is populated. Cross-reference malicious/suspicious verdicts against earlier findings as corroboration. |

A finding from this toolbox that doesn't immediately resolve (e.g. "TCP RSTs
at session close" or "duplicate ACKs") is exactly the kind of item that should
feed Phase 3/5 — don't dismiss it inline without checking whether Toolbox B
explains it (see Toolbox B notes on TCP expert analysis below).

---

## Toolbox B — Manual investigation techniques

Draw on these during Phase 3 as the questions demand. They are not a fixed
sequence and not gated on the baseline sweep finishing for every module —
if Phase 1 already raises a question Toolbox B can answer, use it immediately.

### Device & identity fingerprinting

```bash
tshark -r "$PCAP" -q -z conv,eth
tshark -r "$PCAP" -q -z conv,ip
tshark -r "$PCAP" -V -Y "nbns" 2>/dev/null | grep -E "Name:|Type:|Address:|Data:"
tshark -r "$PCAP" -T fields -e eth.src_resolved
```

OUI reveals vendor → device class. NBNS announcements reveal Windows NetBIOS
hostnames on the segment.

### Actor profiling (mandatory pivot for any host attributed to a finding)

The moment any host is named as the responsible party for a significant
finding — sender/recipient of a harassing or threatening message, the device
behind a session-hijack or cookie-replay, the source of exfiltration or a
policy violation, etc. — run this profile automatically, without waiting for
the analyst to ask "who is this?" or "what else can we find on them?". An
IP/MAC attribution is the start of attribution, not the end of it.

**0. Attribution-layer disambiguation** — is "this host" actually one actor?

Every attribution is anchored at some *layer*, and a match at one layer does
not prove a match at a finer one:

| Layer | Identifier(s) | A match here means... | ...but does NOT prove |
|-------|---------------|------------------------|------------------------|
| Network | WAN/source IP, subnet | traffic crossed this address | one device — the address may be a NAT gateway, shared connection, or DHCP-reassigned over time |
| Device | MAC, TCP/IP stack & OS fingerprint (TTL, window size, OUI) | traffic came from this physical/virtual NIC | one user or one running session — a device can run multiple browsers/VMs/users |
| Application session | User-Agent, persistent client cookies (e.g. Google `PREF=ID=...`), IM/app session/login IDs | traffic came from this specific browser/app instance | one identity for all time — the same session can log in as different accounts sequentially, or one account's cookies can be replayed by a different session (cookie hijack) |
| Account / identity | logged-in username, email, display name, account ID | this account was authenticated in this session | this is the *person* — accounts can be shared, spoofed, or fake/sockpuppet |

Before reusing any identity discovered elsewhere in the case (an IM login, a
webmail account, a device fingerprint) to explain a *new* finding, identify
which layer the new finding is anchored at, and check whether the earlier
identity's evidence reaches that same layer — don't silently promote a
coarser-layer match into a finer-layer claim. Concretely:

```bash
# Multiple MACs behind one IP (NAT/shared gateway, or a reassigned DHCP lease over time)
tshark -r "$PCAP" -Y "ip.src==<HOST>" -T fields -e frame.time -e eth.src 2>/dev/null | sort -u

# Multiple distinct User-Agents / OS fingerprints from one IP, with active time ranges
tshark -r "$PCAP" -Y "http.request && ip.src==<HOST>" -T fields -e frame.time -e http.user_agent 2>/dev/null | sort -u

# Persistent per-browser/app identifier cookies (e.g. Google PREF=ID=..., other long-lived
# tracking/session cookies), with timestamps — a change in this value mid-capture is a
# different browser instance even if the UA string is identical
tshark -r "$PCAP" -Y "http.cookie && ip.src==<HOST>" -T fields -e frame.time -e tcp.stream -e http.cookie 2>/dev/null \
  | grep -Eo 'PREF=ID=[a-f0-9]+|[A-Za-z_]+=[A-Za-z0-9._-]{16,}' | sort -u
```

If any of these show **more than one distinct value for the same coarser
identifier** (two MACs on one IP, two UA/cookie fingerprints on one MAC, two
account identities in one browser session), treat each as a *candidate
separate actor* — e.g. one machine running two browsers (native OS + VM), a
NAT gateway/shared connection serving multiple devices, or a session-cookie
replay (one browser, two accounts: the legitimate user and an attacker).
Then verify which fingerprint the finding's own traffic carries at the layer
that matters for that finding, and only attribute identities whose evidence
**reaches that layer**. An identity recovered at a coarser layer than the
finding requires is a separate, unconfirmed lead — log it as its own actor
profile and an open `[PIVOT: relationship between <actor A> and <actor B>
sharing <network/device> <HOST> — same operator, different individuals, or a
hijacked session?]`, not as corroboration of the first.

**1. Device/application fingerprint** — what is this host, concretely?

```bash
tshark -r "$PCAP" -Y "http.request && ip.src==<HOST>" -T fields -e http.user_agent 2>/dev/null | sort -u
```

User-Agent strings reveal OS, browser(s), and any client applications (IM
clients, update agents, RSS readers, etc.) — distinct applications with
distinct UAs sharing one host is itself informative (e.g. a single
multi-protocol chat client explaining several IM-protocol findings at once).

**2. Logged-in identity extraction** — does this host carry session state for
any service that ties it to a real name, email address, or account ID?

```bash
# Cookies set for / sent by the host across all observed services
tshark -r "$PCAP" -Y "(http.cookie || http.set_cookie) && ip.addr==<HOST>" -T fields \
  -e frame.time -e ip.dst -e http.host -e http.cookie -e http.set_cookie 2>/dev/null \
  | grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|c_user=[0-9]+|email=[^&;]+'
```

For any service session found (webmail, social network, forum, etc.), apply
the general "resolve referenced content" rule above: if the relevant response
is gzip/compressed, export and decompress it (`--export-objects http`), then
grep the decompressed page for the account's display name / real name (e.g.
`"<UID>", "<Display Name>",` patterns in social-network JS, `Welcome,
<name>`, profile links). A session cookie carrying an email address or account
ID is a direct identity lead and must be followed to the page content it
unlocks, not left as a bare cookie value.

**3. Intent / premeditation timeline** — what did this host do in the minutes
before and after the event?

```bash
# Full search-query / navigation history for the host around the event window
tshark -r "$PCAP" -Y "http.request && ip.src==<HOST> && http.host contains \"google\"" \
  -T fields -e frame.time -e http.request.uri 2>/dev/null | grep -i "q="
```

Read the sequence of searches/page visits immediately before and after the
event. A search for the method ("how to <do the thing>") or an explicit
statement of motive/target shortly before the event converts an isolated
technical finding into evidence of a deliberate, planned act — and a search
immediately after can reveal follow-on intent. Report this timeline alongside
the finding it corroborates.

**Output of this pivot**: a short profile — which attribution layer/fingerprint
performed the finding (step 0), that fingerprint's OS/browser/apps, any
real-name/email/account identity recovered *for that same fingerprint*, and
an intent timeline — attached to the finding that named the host. Treat gaps
in any of the four as open `[PIVOT: ...]` items, not as "not applicable," and
treat identities tied to a *different* fingerprint sharing the same coarser
layer (network, device) as separate, unconfirmed leads rather than folding
them into this profile.

### Session cookie and credential extraction

For HTTP sessions carrying authentication tokens in cleartext:

```bash
tshark -r "$PCAP" -Y "http.cookie" -T fields \
  -e frame.number -e ip.src -e ip.dst \
  -e http.request.uri -e http.cookie 2>/dev/null

tshark -r "$PCAP" -Y "http.set_cookie" -T fields \
  -e frame.number -e ip.src -e http.set_cookie 2>/dev/null
```

For Microsoft Passport sessions specifically, parse:
- `MSPAuth` / `MSPProf` — active session token (replayable, compute Shannon entropy)
- `MSPPre` — pre-fill field → **victim's email address**
- `MSPRequ` → `lt=<unix_epoch>` — **victim's login timestamp**

`lt=` decoding: `python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(1093620869))"`

### URL timestamp and session parameter decoding

```bash
tshark -r "$PCAP" -Y "http.request" -T fields \
  -e frame.time_utc -e ip.src -e http.host \
  -e http.request.uri -e http.request.method 2>/dev/null
```

Decode protocol-specific timestamps found in query parameters:
- **Unix epoch** (`lt=`, `t=`): `python3 -c "import datetime; print(datetime.datetime.utcfromtimestamp(<value>))"`
- **.NET DateTime ticks** (`time=`): `python3 -c "import datetime; print(datetime.datetime(1, 1, 1) + datetime.timedelta(microseconds=<ticks>//10))"`

Note PocketPC-specific endpoints (e.g., `composeppc.aspx`, `folder.aspx`) as
evidence of victim device class.

### TCP stream reconstruction (response bodies + POST bodies)

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

Use `--export-objects http` to carve all HTTP response bodies to disk. Follow
the stream index for any POST request to recover the submitted form body. For
webmail/web-form sessions this includes the full submitted content
(`Body=`, `Subject=`, `To=`, `email=`, etc.).

**General rule — resolve referenced content to its readable form (mandatory):**
whenever a finding identifies a *specific* object, request, message, or
session (e.g. a viewed thread, an attachment, a downloaded file, a fragment
referenced by ID/URL) but the payload as first retrieved is not directly
legible — compressed, encoded, binary, truncated, or split across
streams/fragments — that illegibility is not the conclusion. Apply whatever
recovery technique fits (decompression, re-assembly, decoding, carving,
following the reference to the object it names, cross-module correlation),
then run the content/identity pattern sweep (below) against the recovered
data. Do not write "bits and pieces," "unrecoverable," or "not further
examined" for content that names a specific object until that recovery step
has been tried and read.

**Worked example — gzip-compressed webmail/AJAX responses:** many webmail and
AJAX endpoints (Gmail, Outlook Web Access, etc.) serve `Content-Encoding: gzip`
JSON/JS responses. `follow,tcp,ascii` does **not** decompress these — it dumps
raw gzip bytes that look like binary garbage and will be (wrongly) read as
"nothing recoverable." `--export-objects http` *does* auto-decompress on
export. Whenever a session-hijack, cookie-replay, or webmail-access finding
identifies specific request URIs (e.g. Gmail `view=cv&th=<thread_id>`), run
`--export-objects http` and locate the exported file matching that URI/query
string — it will be the actual decompressed JS/JSON response body. Recovered
viewed-thread content can itself contain new correlative findings (e.g.
plaintext credentials shared by email, secondary account identities,
additional named individuals) — apply the general rule above to those too.

### Content / identity pattern sweep

Reputation- and signature-based detectors will not flag a normal-looking
session on a benign-reputation host or protocol. This sweep catches *what was
said/sent*, independent of *where it went or which protocol carried it*. Run
this whenever the investigation involves webmail, web forms, chat, file
transfer, or any user-content-bearing protocol — and as a standing check even
when nothing else points to it, since this is precisely the class of finding
(including malicious-insider, extortion, and harassment scenarios) that the
rest of the toolbox is structurally blind to.

```bash
# Email addresses anywhere in decoded HTTP request/response content
tshark -r "$PCAP" -Y "http" -T fields -e frame.number -e ip.src -e ip.dst \
  -e http.host -e http.request.uri -e http.file_data 2>/dev/null \
  | grep -Eo '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'

# Same, restricted to POST form submissions (most likely to carry composed content)
tshark -r "$PCAP" -Y "http.request.method == POST" -T fields \
  -e frame.number -e tcp.stream -e http.host -e http.request.uri -e http.file_data 2>/dev/null

# Full-capture string search across ALL protocols/streams (not just HTTP) —
# covers FTP, SMTP/POP3/IMAP, Telnet, IRC, IM (MSN/YMSG/XMPP/AIM), SMB, etc.
tshark -r "$PCAP" -Y "frame contains \"@\"" -T fields -e frame.number -e ip.src -e ip.dst -e tcp.stream 2>/dev/null

# For each content-bearing TCP stream found above, reconstruct and scan it:
tshark -r "$PCAP" -q -z follow,tcp,ascii,N 2>/dev/null \
  | grep -Eio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|bitcoin|wallet|wire transfer|iban|account number|ransom|extort|blackmail|pay(ment)?|deadline|or else|don'"'"'t tell|expose|leak|delete this|password|credentials'

# Same sweep against exported (auto-decompressed) HTTP objects — required for
# any gzip/AJAX webmail response identified above:
grep -Erio '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}|password|credential' /tmp/http_exports/ 2>/dev/null
```

Treat every distinct email address, username, identity string, payment
reference, or coercive/urgency phrase found this way as a candidate
IOC/identity and a candidate pivot: who sent it, who received it, was it
spoofed, was delivery confirmed (check the response in the same stream), and
does the language itself indicate a threat, demand, or insider disclosure
independent of where the traffic was destined?

### UPnP/SSDP gateway profiling

```bash
tshark -r "$PCAP" -V -Y "ssdp" 2>/dev/null | \
  grep -E "NOTIFY|ST:|USN:|LOCATION:|SERVER:|Cache-Control:|NT:"
```

UPnP NOTIFY broadcasts from the router/gateway expose:
- **Server** field: OS and UPnP stack version (e.g., `NT/5.0 UPnP/1.0`)
- **USN** (Unique Service Name): UUID derived from MAC → confirms gateway MAC
- **LOCATION**: URL to the description XML (`descrip.xml`) — readable at investigation time
- **Cache-Control: max-age=N**: TTL=N as a non-spoofed SSDP multicast is not IP spoofing

> False-positive note: automated UDP detectors may flag SSDP multicast
> (192.168.x.x:1900 → 239.255.255.250) as "UDP Reflection/Amplification" (no
> request visible in the capture window) and TTL=4 as "IP Spoofing." Both are
> expected RFC 2608 behaviour. Document as false positives in the research
> notes rather than as findings.

### TCP expert analysis

```bash
# Expert info (RSTs, retransmissions, duplicate ACKs, out-of-order)
tshark -r "$PCAP" -q -z expert 2>/dev/null | head -40

# HTTP server headers (compare across IPs for version consistency)
tshark -r "$PCAP" -Y "http.server" -T fields \
  -e ip.src -e http.server 2>/dev/null | sort -u
```

TCP RSTs at session close are normal on Windows CE/PocketPC (no FIN/ACK
handshake). Duplicate ACKs on 802.11 segments reflect 802.11b reordering — not
an attack indicator. Mismatched HTTP server headers across IPs from the same
domain indicate CDN sharding — document the header values as
device/infrastructure fingerprints.

---

## Narrative file (required before report generation)

After the investigation loop has converged (Phase 5 found no new pivots), and
**before** calling `generate_pcap_report.sh`, write the narrative file. This
feeds the **Incident Timeline** section of the report and all eight slides of
the board PPTX deck (Executive Summary, Business Impact, Incident Timeline,
Root Cause & Risk, Response & Containment, Recommendations, Lessons Learned).
Without it those slides show generic placeholder text — write every section
yourself, in your own words, based on what you actually found. Do not rely on
`lib/narrative_generator.py`'s keyword-matching heuristics to fill these in;
that generator is a headless fallback for batch/no-Claude runs only and
produces noticeably weaker, often generic content.

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

... followed by the eight shared pptx_* sections (docs/investigation_discipline.md §2)
```

For the shared `pptx_*` schema and authoring rules, see
`docs/investigation_discipline.md` §2. Example wording for FAN's
`pptx_executive_summary`: *"• Outbound communications consistent with
command-and-control activity were observed throughout the capture window."*

**Rules (FAN-specific, in addition to docs/investigation_discipline.md §2):**
- `attack_timeline` must span the entire capture window chronologically.
- Use RN-NNN references to link each event to the research notes step.

---

## Generate consolidated incident report

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

> **Note:** this regenerator reads from `./analysis/`. If `./analysis/` has
> already been cleaned up for this case (as required post-investigation), a
> regeneration run will produce a severely degraded report (no IOCs, no MITRE,
> empty Hallucination Guard). If the investigation loop continues *after* a
> report has already been generated and `./analysis/` cleaned (e.g. a
> follow-up analyst question opens a new pivot), do not re-run this script —
> hand-edit the existing Markdown report and regenerate the PDF directly via
> `lib.md_to_pdf.convert()`, which does not depend on `./analysis/`.

### Annotate false-positive Toolbox A findings before finalizing

`generate_pcap_report.sh` writes the raw severity/category counts from every
Toolbox A detector verbatim into Section 2 and the Management Summary "Key
findings" — including categories that Phase 4 interpretation determined are
false positives (e.g. a large-ping MTU test scored as "ICMP Data
Exfiltration", CDN responses scored as "DNS Amplification" or "Fast Flux
DNS"). Left as-is, a report can present a wall of CRITICAL/HIGH bullets for
things that turned out to be benign — alarming to a reader and a drag on the
report's signal-to-noise ratio. Before finalizing, hand-edit the generated MD:

- **Management Summary "Key findings"**: keep only findings that survived
  Phase 4 interpretation as real (CONFIRMED/INFERRED, or ASSUMED findings
  still under active suspicion). Move every category that Phase 4 closed out
  as a false positive into a single explanatory note (e.g. "*Note on
  automated detector output:* the following categories were raised by
  Toolbox A and assessed as false positives — see Section 2.x — and require
  no action"), citing the RN-NNN step(s) that did the verification.
- **Section 2.x detail entries**: for each false-positive category, add a
  `> **Disposition: FALSE POSITIVE (RN-NNN).** <one-line reason>` callout
  directly under the category heading. Keep the raw detector output below it
  — do not delete it, since it is part of the evidence trail — but the
  disposition must be visible at the point of the finding, not only in the
  research notes or narrative.
- **Open pivots that were never resolved** (Phase 5 ended before a `[PIVOT:
  ...]` was chased to a conclusion) are NOT false positives — do not label
  them as such. Annotate them as `> **Disposition: OPEN PIVOT, not confirmed
  (RN-NNN).** <best current hypothesis, [ASSUMPTION]-tagged if applicable>`
  and keep them out of the false-positive summary note.
- **Recommended immediate actions**: remove mitigation bullets that only
  apply to the false-positive categories (e.g. "block ICMP payloads >64B",
  "implement DNS RPZ for DGA domains") — they create work against a
  non-issue. Replace with the recommendations tied to the real findings.

After hand-editing, regenerate the PDF via `lib.md_to_pdf.convert()` (same
pattern as the `./analysis/`-cleaned-up note above).

## Preserve raw analysis artifacts (evidence ZIP)

**Before** the chain-of-custody update and the `./analysis/` cleanup step,
preserve every module's raw output so each research-notes step's
`--source-data` citation remains independently verifiable after cleanup:

```bash
source ./scripts/package_evidence.sh
EVIDENCE_ZIP="$(fgff_package_evidence "$CASE_ID" "./reports/$CASE_ID/FAN/$STEM" "./analysis" "analysis")"

python3 lib/research_notes.py finalize-evidence \
  --case-id     "$CASE_ID" \
  --evidence-dir "./reports/$CASE_ID/FAN/$STEM/${CASE_ID}_evidence/analysis" \
  --src-prefix  "./analysis" \
  --zip-prefix  "${CASE_ID}_evidence/analysis" \
  --case-dir    "./reports/$CASE_ID/FAN/$STEM"
```

`fgff_package_evidence` is the same shared rsync+zip helper that
`analyze_pcap.sh` (and the FAME/FAST entry scripts) run inline as part of
their own evidence-preservation step — `/fan` runs each module independently
rather than through `analyze_pcap.sh`, so it must call this helper explicitly
here — in this order, before chain-of-custody and `./analysis/` cleanup — or
the raw outputs cited by `--source-data` are lost when `./analysis/` is
wiped. The helper never fails the investigation: on any error it logs a
warning to stderr and returns 0 with `$EVIDENCE_ZIP` empty.

`research_notes.py finalize-evidence` then, for every `--source-data` row
recorded under `./analysis/...` during the investigation: computes its
SHA-256 from the copy now inside `$EVIDENCE_ZIP`, appends a per-file
"Evidence preserved: <file>" step (mirroring the FAME/FAST chain-of-custody
pattern — action/why/outcome/SHA-256), and rewrites that `Source data` row
from its live `./analysis/...` path to the zip-relative path
`${CASE_ID}_evidence/analysis/...`. This matters because the auditor receives
`$EVIDENCE_ZIP`, not the `./analysis/` working directory — every `Source
data` citation in the final research notes must resolve to a path *inside the
archive the auditor actually gets*.

After this step, run `python3 lib/chain_of_custody.py update --case-id
"$CASE_ID" --case-dir "./reports/$CASE_ID" --trigger investigation` so
`$EVIDENCE_ZIP`'s hash is captured in the manifest, and include it in the MCP
upload alongside the report/PPTX/DOCX (see below).

### `--source-data` convention

While the investigation is running, every `python3 lib/research_notes.py
step` call should set `--source-data` to the raw-output location for that
step, using the **live `./analysis/...` path at the time the step is
logged**:

- **Toolbox A (module scripts)**: `--source-data "./analysis/<module>/<STEM>/<output_file>"`
  (e.g. `./analysis/http_threats/nitroba/http_threats.json`).
- **Toolbox B (manual `tshark`/CLI techniques)**: redirect the command's
  output to a file under `./analysis/manual/<STEM>/RN-NNN_<slug>.txt` and pass
  that path, so it is swept up by the evidence-preservation step above. If a
  step draws directly on the evidence file with no separate output worth
  saving (e.g. a quick `tshark -Y ... | head`), `--source-data` may instead
  point at the evidence file path (the one passed to `research_notes.py init
  --evidence`) — this is left untouched by `finalize-evidence` since it
  doesn't start with `./analysis/`.

**After** `finalize-evidence` runs (above), every `./analysis/<path>`
recorded this way has been rewritten in the research notes to
`${CASE_ID}_evidence/analysis/<path>` — the path an auditor extracting
`$EVIDENCE_ZIP` will actually find the cited file at, with a logged SHA-256
to verify it against. Do not hand-edit `Source data` rows after this step
runs.

### Record findings to the vault (skip if `--no-vault`)

Mirrors `analyze_pcap.sh`'s "Vault findings write" step. Unless `--no-vault`
was passed, parse the finalised incident report and write confirmed TTPs,
IOCs, and risks to the Obsidian vault:

```bash
python3 lib/vault_writer.py \
  --module fan \
  --report "./reports/$CASE_ID/FAN/$STEM/${STEM}_incident_report.md" \
  --case-id "$CASE_ID" \
  --reports-dir ./reports
```

If `--no-vault` was passed, skip this step entirely (do not run
`vault_writer.py`, and do not invoke `/obsidian-record` for this case).

### Upload all artifacts to the investigations vault via MCP (skip if `--no-upload`)

If `--no-upload` was passed, skip this step entirely — leave all reports under
`./reports/<CASE_ID>/` only. If the investigations vault is not configured
(`INVESTIGATIONS_SSH_HOST`/`INVESTIGATIONS_ROOT` unset — see CLAUDE.md
"Investigations vault configuration"), ask the analyst once for the destination,
run `./scripts/configure_vault.sh`, then proceed. Otherwise (paths below are
relative to `$INVESTIGATIONS_ROOT`, the investigations MCP server's root —
e.g. `/home/sansforensics/cases` is one example root, not a fixed one):

```
investigations_write_file: <CASE_ID>/reports/FAN/<STEM>/<STEM>_incident_report.md
investigations_write_file: <CASE_ID>/reports/documents/<STEM>_incident_report.pdf
investigations_write_file: <CASE_ID>/reports/documents/<STEM>_fan_presentation.pptx
investigations_write_file: <CASE_ID>/reports/documents/<STEM>_fan_report.docx
investigations_write_file: <CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_narrative.md
investigations_write_file: <CASE_ID>/reports/FAN/<STEM>/<CASE_ID>_research_notes.md
investigations_write_file: <CASE_ID>/reports/documents/<CASE_ID>_evidence.zip
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

## Cross-module correlation, Campaign Report & completeness gate

Follow `docs/investigation_discipline.md` §3 (cross-module correlation via
`lib/correlate_findings.py`), §4 (always hand-author the per-case campaign
report after this module's report is generated — single-module cases get a
campaign report covering this module alone in board-deck format; if FAME,
FAST, or another FAN run already exists for this case ID, it becomes a
unified cross-module report; use `lib/report_completeness.py
--campaign-check` to confirm it was created), and §5 (the
`generate_pcap_report.py` completeness gate — narrative + research-notes
reasoning checks, the `⚠️ INVESTIGATION INCOMPLETE` banner, and
`<case_id>_INVESTIGATION_INCOMPLETE.json`). If the generated report shows that
banner, address it per §5 before considering this investigation complete.

---

## Stop condition

The investigation is complete when:
- Phase 1 statistics and Phase 2's full toolbox sweep have run and their
  outputs have been read and appended to research notes.
- The Phase 3↔4↔5 loop has converged: every item flagged in Phases 1–2, and
  every `[PIVOT: ...]` raised during Phase 3/4, has been either chased to a
  conclusion or explicitly documented as a false positive / out of scope with
  reasoning.
- The consolidated report has been generated and uploaded to the investigations
  vault.
- A scoped conclusion can be stated that cites its evidence source (e.g.,
  "No signs of lateral movement observed in the PCAP file").

A follow-up analyst question after the report has been generated is itself a
new entry into Phase 3 (a hypothesis worth investigating) — re-run the loop
for that question specifically, and update the report/narrative/timeline if it
produces a new finding (see the note on hand-editing reports above).

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
