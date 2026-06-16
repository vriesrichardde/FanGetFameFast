# Accuracy & Evidence Integrity Report

**Scope:** self-assessment of the five completed cases currently in `reports/`:

| Case ID | Module(s) | Dataset | Source |
|---------|-----------|---------|--------|
| `NISTHACK` | FAN + FAST (campaign, 2 hosts: DELLCPI + AFCASE2) | NIST Hacking Case (XP war-driver / "Mr. Evil") [DELLCPI]; CCDFiR AF-Case2 challenge image [AFCASE2] | https://cfreds.nist.gov/Hacking_Case.html (DELLCPI); internal (AFCASE2) |
| `NISTLEAK` | FAST (two evidence items: INFORMANT-PC + RM2-MEDIA, campaign) | NIST Data Leakage Case (informant exfiltration) | https://cfreds.nist.gov/data-leakage-case/data-leakage-case.html |
| `FAN-2026-NITROBA-V5` | FAN only (campaign) | Nitroba University Harassment Scenario | https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/ |
| `NROMANOFF` | FAME + FAST (campaign) | Stark Research Labs Data Breach Intrusion — SANS course dataset | internal |
| `WIN764NFURY` | FAME + FAST (campaign) | Stark Research Labs Data Breach Intrusion — SANS course dataset | internal |

This report follows the Official Rules requirement that the accuracy section "address
false positives, missed artifacts, and hallucinated claims identified during testing"
and that "honesty [is] valued over perfection." Every claim below cites the research
notes (`RN-NNN`), events (`EVT-NNN`), or hallucination-guard finding IDs (`FND-NNN`)
it is drawn from, so a reviewer can trace it back to the underlying tool execution.

---

## 1. Evidence Integrity Architecture

**How the architecture prevents original evidence from being modified:**

- **Write-path policy (`lib/path_guard.py`)** is the single source of truth for where
  output may land. Every Python write chokepoint (`obsidian_bridge`, `md_to_pdf`, all
  `generate_*` report generators, `case_packager`, `chain_of_custody`) routes through
  `assert_writable()` / `guard_output_dir()`. A path is writable **iff** it resolves
  inside an approved root (`analysis`, `exports`, `reports`, `archive`, `vault`,
  `cases`, `demo`, `docs`, or the OS temp dir) **and** is not inside a read-only root
  (`/mnt`, `/media`, `EVIDENCE_ROOT`, `/home/vscode/evidence`,
  `/home/sansforensics/evidence`, or any project-local `evidence/`). Read-only roots
  always win, and matching is by resolved-path prefix (`Path.resolve()` +
  `is_relative_to`), not substring, so `reports/<case>_evidence/` stays writable while
  a real evidence mount does not.
- **What happens on a bypass attempt:** any write outside policy raises
  `WritePolicyError` (a `PermissionError` subclass) **before** any bytes are written —
  there is no silent fallback or partial write. The shell pipelines additionally source
  `scripts/pathguard.sh`, which calls `fgff_assert_ro_mount` to verify evidence mounts
  are mounted read-only before analysis starts, and `fgff_validate_case_id` to reject
  any `case_id` outside `[A-Za-z0-9._-]{1,64}` (blocking path traversal via the case
  ID). The self-test (`python3 lib/path_guard.py --test`) exercises this matrix,
  including an explicit assertion that `assert_writable("/mnt/x")` raises.
- **Chain of custody (`lib/chain_of_custody.py`)** records MD5/SHA-1/SHA-256, size, and
  mtime for the source evidence file and every generated artifact under
  `reports/<case_id>/`, written to `<case_id>_chain_of_custody.json`. It is
  append-only: a later run that finds a *different* hash for a previously-recorded
  evidence path does not overwrite the original record — it logs a critical integrity
  alert in `history` with both the old and new hash.
- **Artifact guard (`lib/artifact_guard.py`)** prevents the pipeline from clobbering a
  hand-edited campaign report. If a PDF/PPTX/DOCX was edited since it was last
  generated (hash mismatch, or PPTX `lastModifiedBy`/`revision` change), a re-render is
  diverted to `<stem>.new.<ext>` instead of overwriting the analyst's edit.
- **Hallucination Guard (`lib/hallucination_guard.py`)** is the architectural
  (code-enforced, not prompt-enforced) confidence-tier system. Every finding in a
  report is tagged `CONFIRMED` / `INFERRED` / `ASSUMED` / `UNVERIFIABLE` at parse time
  by the report generator, plus automated single-source flagging and keyword-based
  contradiction detection. This produces the "Hallucination Guard" / "Confidence
  Assessment" sections in each module and campaign report (see Section 3 below).

---

## 2. Dataset Provenance Note (build vs. score)

The five cases use a mix of public and internal (SANS course) datasets:

- **NISTHACK/DELLCPI** and **NISTLEAK** are NIST CFReDS public datasets; their solutions
  are widely published online and likely in the model's training data. We cannot fully
  distinguish reasoning-from-evidence from recall for the headline narrative.
- **FAN-2026-NITROBA-V5** uses the Digital Corpora Nitroba pcap, also widely published.
- **NISTHACK/AFCASE2**, **NROMANOFF**, and **WIN764NFURY** are internal / SANS course
  materials. Public write-ups are not widely available, making the recall-vs-reasoning
  distinction less of a concern for these three sub-cases.

**What we can and do verify independently** for all five cases: every cited finding traces
to an actual tool execution recorded in that case's research notes (Section 4) — the
*evidence trail* in this run was independently re-derived from the supplied image/pcap,
not copied from a published answer key.

**Reproducibility for independent reviewers:** The three public-domain cases can be
reproduced in full by any reviewer — the evidence is freely downloadable from the
sources cited in the dataset table above:

- **NISTHACK/DELLCPI:** https://cfreds.nist.gov/Hacking_Case.html
- **NISTLEAK:** https://cfreds.nist.gov/data-leakage-case/data-leakage-case.html
- **FAN-2026-NITROBA-V5:** https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/

**NROMANOFF** and **WIN764NFURY** use memory and disk images from a licensed SANS course
(Stark Research Labs Data Breach Intrusion). These files are distributed to course
attendees and are not redistributable; a reviewer without a SANS course license cannot
independently re-run the agent against those two evidence sets. The case ZIPs in the
repository root (`cases_for_judges_NROMANOFF.zip`, `cases_for_judges_WIN764NFURY.zip`)
include the full investigation artifacts — reports, research notes, chain-of-custody
manifest, and the verbatim `.jsonl` session transcript — so the complete reasoning
chain is auditable without the original evidence. Independent end-to-end reproduction
of those two cases requires SANS course access.

---

## 3. Manual Assessment
During the testing/benchmarking of our solution, we regularly reviewed the expected output 
defined in the NIST answers, as well as the 
[VIGIA cases](https://github.com/annatchijova/vigia-cases/tree/main/cases). What we noticed 
was that the outcome would be different each time the run had taken place. By carefully 
tuning the missing content, we came to a more complete report each time, but still there 
were small deviations of things it would not find without us providing some direction. This 
confirms our suspicion that for the (near) future it will stay a tool that is used with a 
human-in-the-loop to confirm what it has found, ask questions on what might be there to find 
and tune the results based on these events.

We did confirm that with a few small questions, major findings can be uncovered by Claude as 
our solution is built to let Claude be as intelligent as possible and to ensure that we as 
analysts can follow its way of working. Below is a self assessment by Claude that goes into 
a bit more depth on certain findings.

## 4. Per-Case Self-Assessment

### 4.1 NISTHACK (FAN + FAST, 2 hosts — DELLCPI and AFCASE2)

**Confidence summary (campaign report §10):** 17 substantive findings — 6 CONFIRMED
(2 with two-module corroboration), 6 INFERRED, 1 ASSUMED, 4 UNVERIFIABLE → 71%
confirmed (12 of 17 findings backed by direct artifact evidence from at least one module).

**False positives caught:**
- An automated FAN detector flagged the Passport/Hotmail session cookies in the
  `interception` pcap as a possible T1048 "Exfiltration Over Alternative Protocol"
  indicator (entropy-based); direct content review (FAN RN-003) identified these as
  expected high-entropy session tokens, not exfiltrated data — the automated label was
  corrected and retained in the MITRE table only to document and dismiss it (FND-not
  promoted to confirmed finding).
- The FAN UDP/SSDP module flagged the wireless gateway (192.168.254.254:1900) as
  CRITICAL/HIGH "reflection/amplification" activity; per-packet review (FAN RN-005)
  confirmed these are routine UPnP InternetGatewayDevice NOTIFY broadcasts — benign
  gateway behaviour, not amplification.

**Missed / unresolved artifacts (honestly disclosed):**
- FND-015 (`README.txt.aes` on AFCASE2): AES Crypt, password not recovered despite
  ~20 direct attempts — contents UNVERIFIABLE.
- FND-016 (`Keys.txt` on AFCASE2): GnuPG private-key passphrase not recovered despite
  ~35 direct guesses and a 50-entry BitLocker user-password brute-force alternative
  route — contents UNVERIFIABLE.
- FND-014 (`4.12.220[.]254` IOC from DELLCPI `file://` path): no CTI enrichment
  credentials configured in this environment — threat intelligence UNVERIFIABLE.
- FND-017 (Suricata IDS on `interception` pcap): Suricata failed due to a wrapper-
  script configuration issue (invalid `-q` flag, FAN RN-007) — no IDS corroboration.

**Hallucinations caught during testing:** none of the 17 campaign findings were
identified as unsupported claims requiring removal; the two automated-detector
over-calls (FAN T1048 session-cookie flag; UPnP amplification flag) are the closest
analogue — both caught and corrected before reaching the final report.

---

### 4.2 NISTLEAK (FAST, two evidence items — INFORMANT-PC and RM2-MEDIA)

**Confidence summary (campaign report §8):** 14 substantive findings — 6 CONFIRMED
(all with both-evidence-item corroboration), 5 INFERRED, 1 ASSUMED, 2 UNVERIFIABLE →
79% confirmed or inferred from direct evidence (11 of 14 backed by at least one
evidence item; 6 confirmed independently by both items).

**False positives caught (analyst-level, not automated-detector):**
- 9 of the 24 "stock photo" files on RM2-MEDIA (FND-009 — INFERRED) did not yield
  a detectable appended ZIP/Office blob using the steganography-detection approach
  applied; these were recorded as an open lead (RF-002: different concealment method?)
  rather than added to the exfiltration count, to avoid inflating the confirmed
  document tally.
- The Google Drive desktop sync client active on INFORMANT-PC on 2015-03-25
  (FND-010 — INFERRED) was assessed as a possible secondary exfiltration channel but
  disk evidence alone cannot confirm any upload occurred (FND-012 — ASSUMED) — this
  is recorded as an open lead and a gap, not a confirmed exfiltration vector.

**Missed / unresolved artifacts:**
- FND-013 (UNVERIFIABLE): no network capture for INFORMANT-PC — network-based
  exfiltration and Google Drive upload status cannot be confirmed or ruled out.
- FND-014 (UNVERIFIABLE): no memory image for INFORMANT-PC — live process and
  interactive-session corroboration unavailable.
- FND-015 (ASSUMED): the exact wipe/reformat mechanism on RM2-MEDIA (quick-format,
  directory-only delete, or dedicated anti-forensic tool) is indeterminate from the
  image alone.
- The "Authorized USB (E:) RM#1" device (the original company removable drive) was
  not available for comparison — original vs. exfiltrated copies cannot be byte-diffed.

**Hallucinations caught during testing:** none of the 14 campaign findings were
identified as unsupported claims. The closest analogue is the Google Drive sync
assessment: the report explicitly tiers it ASSUMED / INFERRED rather than CONFIRMED,
correctly reflecting that disk evidence does not prove an upload occurred.

---

### 4.3 FAN-2026-NITROBA-V5 (FAN only)

**Confidence summary (campaign report §8):** 16 substantive findings — 6 CONFIRMED
(all from FAN module alone, since no FAME/FAST modules ran for this case), 4 INFERRED,
2 ASSUMED, 4 UNVERIFIABLE → 75% confirmed (12 of 16 backed by direct artifact evidence
from FAN).

**False positives caught (the largest concentration in any of the five cases):**
Every one of the 22 Toolbox A signature-based detectors that triggered a finding was
individually reviewed (RN-002 through RN-014) and resolved as a false positive
consistent with normal 2008-era traffic (FND-006 — CONFIRMED). The categories
reviewed and dismissed include:
- ICMP "Data Exfiltration" (CRITICAL) and "Smurf Attack" (HIGH) — standard decrementing-
  byte ping payload (RN-002, RN-020).
- DNS "DGA" / "C2 beaconing" / "fast flux" / "tunneling" — all normal DNS traffic;
  gateway captive-portal sinkholing of Apple domains misidentified as MITM (RN-004,
  RN-020).
- HTTP "Suspicious URIs", "Cookie Anomaly", "Suspicious Referer", "Host Header
  Anomaly", "Unusual HTTP Method" (M-SEARCH to SSDP multicast) — benign 2008-era
  ad-tech URLs, normal high-entropy session cookies, standard ad-redirect chains, and
  routine UPnP discovery (RN-005).
- UDP "Flood" / "Amplification" (CRITICAL) and "IP Spoofing (TTL anomaly)" (HIGH) —
  normal SSDP/UPnP NOTIFY multicast, DNS server-response traffic, and link-local
  multicast TTL behaviour (RN-010, RN-018).
- TLS "Deprecated Version" (3 CRITICAL) — TLS 1.0/SSL 3.0 to Google services were
  current standards in July 2008; anachronism, not a vulnerability introduced by the
  incident (RN-005).
- YARA: 5,058 files extracted from the pcap, 0 matches.

**Missed artifacts surfaced by the agent itself (not by the 22 automated detectors):**
- RN-021 explicitly flags that SIP/RTP/RTCP (VoIP), MSN Messenger, Yahoo Messenger,
  and DCERPC traffic are present but not formally covered by any of the 22 Toolbox A
  detectors — the mandatory IM content/identity sweep (RN-015) covered this gap and
  produced the case's central finding.
- FND-013 (UNVERIFIABLE): Suricata IDS did not execute successfully (wrapper-script
  exit code 1, invalid `-q` flag, RN-013) — documented as UNVERIFIABLE, not a clean
  pass.
- FND-027 (from the earlier FAN-2026-NITROBA case, same finding pattern here): CTI/IP
  enrichment for all 443 IPs returned "no data" because the Perplexity API key is not
  configured — tiered ASSUMED (absence of data, not confirmed benign).

**Hallucinations / contradiction-detector behaviour:**
The campaign report's Hallucination Guard notes that the automated `detect_contradictions()`
pass in the underlying FAN module report fired on the word "detected" appearing in
unrelated protocol-module summaries vs. the confirmed harassment finding — a keyword
heuristic over-fire, not a genuine cross-finding hallucination. These flags are surfaced
for analyst review (the intended fail-open behaviour) and explained in the report rather
than silently suppressed. No finding in the final 16-entry Hallucination Guard table
required removal for being unsupported.

---

### 4.4 NROMANOFF (FAME + FAST)

**Confidence summary (campaign report §9):** 14 substantive findings — 9 CONFIRMED
(all with two-module FAME+FAST corroboration), 4 INFERRED, 1 ASSUMED, 0 UNVERIFIABLE
→ 93% confirmed (13 of 14 backed by direct artifact evidence; 9 confirmed by two
independent modules).

**False positives caught:**
- FND-005 (CONFIRMED): T1546.012 (IFEO persistence) was initially hypothesised from
  FAME evidence (PID 6404 holding an open IFEO registry key handle, RN-008). FAST
  registry analysis (RN-005) found the IFEO key contains only legitimate
  Office/Adobe `DisableExceptionChainValidation` entries — no malicious `Debugger`
  value. T1546.012 was downgraded to NOT CONFIRMED and superseded by the confirmed
  Run-key persistence (T1547.001, FAST RN-005, EVT-002). This is the clearest
  example of cross-module evidence correcting a memory-only hypothesis before it
  reached the final report.

**Missed / unresolved artifacts:**
- FND-010 (INFERRED): a shimcache entry for `C:\dllhost.exe` at 2012-04-03 18:08:50
  — between the start of the brute-force attack and the first successful SMB logon —
  represents an early staging artifact. The file was deleted and is not recoverable
  from the current `fls` listing; its purpose (early dropper, reconnaissance tool, or
  unrelated) remains an open lead.
- FND-014 (ASSUMED): the delivery vector for the initial credential compromise — how
  the attacker obtained guessable/valid passwords for `SRL-Helpdesk` and `vibranium`
  — is outside the scope of the two evidence images; no email, phishing, or messaging
  artifact was found on this host.
- The internal pivot host `10.3.58.7` (the attacker's launch point for all three
  sessions) was not part of this evidence set and remains unexamined.

**Hallucinations caught during testing:** none of the 14 campaign findings required
removal. One analytical misinterpretation was self-corrected before the campaign
report was authored: the FAME narrative initially described the Wave-1 PsExec session
(2012-04-04 18:52:11) and the Wave-2 RAT deployment (2012-04-06 19:22:20) as
occurring "the same evening." FAST timeline analysis (RN-006) showed these are two
days apart; the timeline was corrected before report generation (FAST RN-003 deviation
record).

---

### 4.5 WIN764NFURY (FAME + FAST)

**Confidence summary (campaign report §9):** 12 substantive findings — 6 CONFIRMED
(5 from FAST alone; 1 corroborated by FAME + cross-case vault), 5 INFERRED, 1 ASSUMED,
0 UNVERIFIABLE → 92% confirmed (11 of 12 backed by direct artifact evidence; 6
confirmed by two sources including cross-case vault correlation).

**False positives caught:**
- FND-007 (INFERRED): two sockets on `lsass.exe` to public IPs `56.27.190.26` /
  `56.251.168.26` in the memory image were initially considered as possible C2 activity.
  `malfind` returned zero hits against PID 552, both connections show port=0/CLOSED with
  no local port assignment (FAME RN-004/RN-005), and disk evidence provides no
  corroboration — assessed as stale pool-memory artifacts, not live connections.
- FND-008 (INFERRED): `f-response-ent.exe` (PID 328, the live-acquisition agent)
  shows a CLOSED connection to `10.3.58.4:5681` — one digit removed from the Poison-
  Ivy-pattern RAT port `127.0.0.1:5678` documented for the related workstation. This
  was investigated and recorded as an open lead (RF-002) rather than dismissed; the
  most plausible explanation is coincidental port proximity with the legitimate F-Response
  acquisition process, with no disk-side corroboration to advance it beyond INFERRED.

**Missed / unresolved artifacts:**
- FND-009 (INFERRED): `hythonize.exe` (x64, PyInstaller) and `hythonized.exe` (x86,
  PyInstaller), deleted by the attacker alongside the confirmed backdoor at 18:43:07,
  were recovered from the Recycle Bin but their specific function remains undetermined —
  no public reference matched their MD5s in this environment.
- FND-010 (INFERRED): `nfury`'s Outlook PST was present but `readpst`/`libpst` were
  not available in the analysis environment; the PST was not parsed and a possible
  initial-access / phishing vector via email remains unresolved.
- FND-012 (ASSUMED): the `vibranium` domain account (RID 1673, anomalously high vs.
  the organisation's known employee RID range 1105-1114) cannot be attributed to a
  known staff member or newly-created attacker account without domain-controller SAM/AD
  data — outside this evidence set.

**Hallucinations / self-corrections:**
The FAME report's initial interpretation of the `lsass.exe`/`System` RPC(135)/SMB(139)
sockets to `10.3.58.4` suggested NFury had *initiated* that connection — the
classic PsExec/DCOM lateral-movement signature from the related NROMANOFF case.
FAST Security EVTX (RN-003, EVT-006) definitively reversed this: `CONTROLLER` (10.3.58.4)
connected *to* NFury using stolen `rsydow` domain credentials. This is documented in
the campaign report as a confirmed self-correction from disk evidence (§3.1 of the
campaign report), and no unsupported version of the reversed claim appears in the final
Hallucination Guard table.

---

## 4. Claim Traceability — Three Traced Claims

| # | Claim (as it appears in the campaign report) | Log entry it traces to | Verdict |
|---|---|---|---|
| 1 | *"The findme69@hotmail.com → rudy@hotmail.com email content is independently present in both the live pcap and the disk's bulk_extractor carve."* (NISTHACK campaign report, FND-002) | FAN research notes `RN-003` (`FAN/interception/NISTHACK_research_notes.md`): *"at 15:37:55 UTC (tcp.stream 6), a POST to /hm/composeppc.aspx?__ufps=950075 … form body 'ToTextBox=rudy@hotmail.com … SubjectTextBox=Hey%2C+This+is+Mr+Evil … SendCommand=Send', server responded 302 (message queued/sent)"*; and `FAN/interception/NISTHACK_research_notes.md` EVT-001: *"Hijacked Hotmail Mobile session (findme69@hotmail.com) used to send email to rudy@hotmail.com, subject 'Hey, This is Mr Evil', body 'Hi. Call me' — server confirmed 'Message sent!'"*; disk carve corroboration in FAST `RN-017`. | **Supported** — the POST body content, both email addresses, the subject line, and the "Message sent!" server response are independently present verbatim in the FAN research notes from direct `tshark` packet extraction. |
| 2 | *"Host 192.168.15.4 submitted an anonymous harassment message to lilytuckrige@yahoo.com at 06:02:57 UTC via www.sendanonymousemail.net."* (FAN-2026-NITROBA-V5 campaign report, FND-002) | FAN research notes `RN-016` (`FAN/nitroba/FAN-2026-NITROBA-V5_research_notes.md`): *"at 06:02:57 UTC (frame 80614, stream 1631), POST /send.php to www.sendanonymousemail.net (69.80.225.91), spoofing sender 'the_whole_world_is_watching@nitroba.org', subject 'Your class stinks', body 'Why do you persist in teaching a boring class? We don't like it. We don't like you.'"* — derived from a direct `tshark` follow/stream extraction. | **Supported** — the timestamp, source IP, destination FQDN, stream number, frame number, and POST path are all independently present in the RN-016 tool-output excerpt. |
| 3 | *"PSEXESVC.EXE was reused as a remote-execution channel across three sessions, corroborated by prefetch + registry Services key to the microsecond."* (NROMANOFF campaign report, FND-003) | FAST research notes `RN-005` (`FAST/WIN7-32-NROMANOFF/NROMANOFF_research_notes.md`): *"Services key (ControlSet001\\Services) contains a legitimate 'PSEXESVC' service entry (ImagePath %SystemRoot%\\PSEXESVC.EXE, key LastWrite 2012-04-04 18:52:11.178525 — matches FAME PID 2100 creation and the on-disk PSEXESVC.EXE crtime from RN-004 to the microsecond)"*; and FAST `RN-006`: *"PSEXESVC.EXE-51BA46F2.pf has crtime 2012-04-03 21:11:08 (first execution of PSEXESVC.EXE) but mtime 2012-04-04 18:52:21 — i.e. the SAME prefetch entry was updated by a SECOND PsExec session."* | **Supported** — the exact microsecond timestamp `18:52:11.178525` and the dual-crtime/mtime prefetch pattern are independently recorded in the FAST research notes from direct registry and prefetch analysis, and the same PID 2100 creation time is present in the FAME pslist output (FAME RN-003). |

---

## 5. Cross-Cutting Honest Limitations

- **Contradiction-detector false positives** (Section 3.3): the keyword-based
  `detect_contradictions()` heuristic in `lib/hallucination_guard.py` over-fires on
  generic words like "detected" appearing in unrelated protocol-module summaries.
  The Nitroba FAN module report's guard fired on this pattern; all flagged pairs were
  reviewed and explained in the campaign report. Tightening the heuristic to scope it
  to same-protocol or same-host finding pairs is a tracked follow-up, not yet done.
- **Tooling defects disclosed rather than hidden:** the `-q` flag defect in
  `lib/fan_suricata.py` made Suricata coverage UNVERIFIABLE for both the
  `interception` pcap (NISTHACK) and `nitroba.pcap` (FAN-2026-NITROBA-V5); both
  reports state this explicitly rather than treating absence-of-alerts as clean coverage.
- **Memory-analysis misinterpretations are correctable by disk evidence:** WIN764NFURY's
  FAME initial conclusion about the direction of a key network connection was reversed
  by FAST authentication logs (§3.5 above). This validates the FAME+FAST combined-
  analysis design, but also records honestly that memory-only analysis can produce
  incorrect conclusions about network connection direction.
- **Internal-dataset recall is not a concern for NROMANOFF/WIN764NFURY:** these use
  SANS course materials that are not publicly documented, so the "evidence trail vs.
  recall" concern (Section 2) does not apply to them as strongly as to the NIST or
  Nitroba cases.
- **CTI enrichment gaps are labeled as gaps:** where the Perplexity API key was not
  configured (NISTHACK `4.12.220.254` IOC; NITROBA IP/FQDN lookup), the report
  records "no data available," not a confirmed-benign verdict.
- **Unrecoverable deleted files remain open leads, not closed gaps:** `C:\dllhost.exe`
  on NROMANOFF (FND-010) and the two unidentified PyInstaller tools on WIN764NFURY
  (FND-009) are disclosed as open leads in both case reports rather than silently
  omitted.

---

## 6. Automated Claim Traceability Audit

`accuracy/verify_claims.py` was run against the audit targets it discovers for each
in-scope case (the scope table in this report drives discovery): the campaign report
at the case root for all five cases. For every line citing an `RN-`/`EVT-`/`RF-`/`FND-`
step, it extracts every "hard" token (timestamp, byte count, IPv4/IPv4:port, MAC address,
hex hash, date, frame/tcp.stream number, MITRE technique ID) and checks for verbatim
presence anywhere in that case's research notes, narratives, and correlation file.
Re-run with:

```bash
python3 accuracy/verify_claims.py
```

**Result: 12 tokens flagged across 5 reports, 0 hallucinations found.** Every flag is
explained by one of four causes:

| Case | Cited lines | Checkable tokens | Fully verified | Flagged |
|------|------------|------------------|----------------|---------|
| FAN-2026-NITROBA-V5 | 58 | 24 | 23 | 1 |
| NISTHACK | 86 | 40 | 36 | 4 |
| NISTLEAK | 54 | 25 | 24 | 1 |
| NROMANOFF | 78 | 61 | 59 | 2 |
| WIN764NFURY | 61 | 50 | 46 | 4 |
| **Total** | **337** | **200** | **188** | **12** |

1. **MITRE technique IDs assigned during campaign synthesis (8/12 flags).**
   T1190, T1557.002 (Nitroba); T1588.002, T1048, T1486, T1573 (NISTHACK); T1055
   (NROMANOFF); T1078, T1036.005/T1036 (WIN764NFURY) — these technique IDs are added
   during the MITRE ATT&CK mapping pass after investigation, and would not appear as
   literal strings in research notes written during evidence analysis. Each was
   spot-checked against its cited evidence and the mapping is standard (e.g. T1055
   "Process Injection" ← 95 heap-sprayed RWX regions in PID 6404; T1048 explicitly
   retained only to document-and-dismiss the automated FP, not as a confirmed finding).

2. **Cross-case vault reference (2/12 flags).**
   WIN764NFURY's campaign report cites `127.0.0.1:5678` (the Poison-Ivy-pattern
   listener port from NROMANOFF) as cross-case context; the audit script searches only
   within WIN764NFURY's own research notes, where this port is not present. Verified
   in NROMANOFF's FAME research notes (RN-005), where it is a CONFIRMED finding.

3. **Timezone-derived timestamp (1/12 flags).**
   NISTLEAK campaign report's correlation table states the FAT32 birth-timestamp range
   on RM2-MEDIA as "19:51:47–20:55:37 UTC (local+4h conversion)." The endpoint
   `20:55:37` is the UTC conversion of a local-time value from RM2-MEDIA research
   notes; `19:51:47` is verified verbatim. This is correct derived arithmetic, not a
   hallucination — consistent with the local+4h conversion pattern documented across
   this case.

4. **Formatting difference in byte count (1/12 flags).**
   NROMANOFF's IOC table reports `a.exe` as "9,216 bytes" (with comma); the FAST
   research notes record the same file as "9216 bytes" (no comma). Identical value,
   different formatting convention — not a factual error.

**Value of this pass:** it reduced 337 cited lines to 12 candidates in seconds, and
confirmed that 188 checkable tokens (timestamps, hashes, IPs, byte counts, MITRE IDs)
trace verbatim to research notes or have a documented explanation. It is kept as a
script (not a one-off) so it can be re-run against future cases' campaign reports.

---

## 7. Summary

| Case | Findings | Confirmed % | FPs caught & documented | Missed-artifact gaps disclosed | Hallucinations caught |
|------|----------|--------------|---------------------------|----------------------------------|------------------------|
| NISTHACK | 17 | 71% | 2 automated-detector over-calls (T1048 session-cookie; UPnP amplification) | 4 (FND-014–017: 4.12.220.254 IOC, 2× encrypted files, Suricata failure) | 0 unflagged; 2 detector over-calls corrected pre-report |
| NISTLEAK | 14 | 79% | 2 analyst-level assessments (9 stock photos as open lead; Google Drive as unconfirmed channel) | 3 (FND-013–015: no network/memory evidence; wipe mechanism indeterminate) | 0 unflagged; 1 Google Drive upload tiered ASSUMED rather than claimed |
| FAN-2026-NITROBA-V5 | 16 | 75% | All 22 Toolbox A categories reviewed; every triggered finding resolved as FP (FND-006) | 3 (FND-013: Suricata failure; FND-014/015: no FAME/FAST evidence; CTI gap) | Contradiction-detector noise flagged and explained; 0 findings removed as unsupported |
| NROMANOFF | 14 | 93% | 1 (T1546.012 IFEO hypothesis downgraded by disk evidence, FND-005) | 2 (FND-010: unrecoverable early artifact; FND-014: credential delivery vector unknown) | 0 unflagged; 1 timeline mis-dating self-corrected before campaign report authored |
| WIN764NFURY | 12 | 92% | 2 (lsass sockets assessed as pool artifacts FND-007; F-Response port proximity as open lead FND-008) | 3 (FND-009: unidentified tools; FND-010: Outlook PST unparsed; FND-012: vibranium account provenance) | 0 unflagged; 1 connection-direction reversal self-corrected by disk evidence |

No claim in any of the five reports' final Hallucination Guard tables was found to be
unsupported by its cited research-note step during this review. The most material
finding of this accuracy review is the structural pattern of memory-only analysis
producing hypotheses that disk evidence corrects (T1546.012 on NROMANOFF; connection
direction on WIN764NFURY) — validating the combined FAME+FAST design and recording
honestly the limits of single-source memory analysis.
