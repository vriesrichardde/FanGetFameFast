# Dataset Documentation

This document records what FanGetFameFast was tested against, where each dataset
comes from, and what the agent found for each one. It is derived from
`accuracy/accuracy.md` (the full accuracy & evidence integrity self-assessment) —
see that file for citations, confidence-tier breakdowns, and the automated
claim-traceability audit.

Reproducibility: every case below was run end-to-end through the documented
pipeline (FAN and/or FAME and/or FAST, see `CLAUDE.md`) against the source image or
capture listed, with no hand-edited evidence. Each case's research notes (`RN-NNN`),
timeline events (`EVT-NNN`), and Hallucination Guard findings (`FND-NNN`) are stored
under `reports/<case_id>/` (or `archive/<case_id>/` once a case is closed) and can be
re-checked with `python3 accuracy/verify_claims.py`.

---

## 1. NIST Hacking Case + AF-Case2 ("Mr. Evil" XP war-driver)

- **Case ID:** `NISTHACK`
- **Modules tested:** FAN (network/PCAP) + FAST (disk image, two host images —
  DELLCPI and AFCASE2), combined into a campaign report
- **Source of data:** NIST CFReDS — https://cfreds.nist.gov/Hacking_Case.html
  (publicly distributed forensic image + packet capture); AF-Case2 from CCDFiR
  challenge image (`internal` — not publicly distributed)

**What the agent found:**

- 17 substantive findings: 6 CONFIRMED (2 with two-module FAN+FAST corroboration),
  6 INFERRED, 1 ASSUMED, 4 UNVERIFIABLE — 71% confirmed (12 of 17 backed by direct
  artifact evidence from at least one module).
- Reconstructed the attack: installation of Ethereal/WinPcap and Cain & Abel on
  DELLCPI, followed by creation of the `interception` packet-capture file independently
  corroborated across FAST (file size 173,372 bytes, prefetch timestamp 15:41:00 UTC)
  and FAN (decoded Hotmail session hijack at 15:37:55 UTC, email to
  `rudy@hotmail.com` confirmed by both live pcap and bulk_extractor disk carve).
- Caught and corrected two automated FAN detector false positives before they reached
  the report: a CRITICAL "UDP amplification / IP spoofing" flag reassessed as
  routine UPnP/SSDP gateway NOTIFY traffic, and a T1048 "exfiltration" label on
  Passport/Hotmail session cookies that was reassessed as session-token exposure
  (not active exfiltration) — the T1048 entry is retained in the MITRE table only
  to document-and-dismiss it.
- Disclosed four open gaps honestly: Suricata IDS coverage for the `interception`
  pcap is UNVERIFIABLE (wrapper-script `-q` flag defect, FAN RN-007); two encrypted
  files on AFCASE2 (`README.txt.aes`, `Keys.txt`) remain UNVERIFIABLE after ~55
  combined passphrase/key-recovery attempts; CTI enrichment for IP `4.12.220.254`
  is UNVERIFIABLE (Perplexity API key not configured).
- Identified an unresolved subnet discrepancy between FAST (`192.168.1.111`) and FAN
  (`192.168.254.0/24`) that is preserved as a recorded contradiction rather than
  silently reconciled — the two subnets are from different collection points (disk
  NIC config vs. captured traffic), but the reason for the mismatch was not
  definitively established.

---

## 2. NIST Data Leakage Case (informant exfiltration via USB)

- **Case ID:** `NISTLEAK`
- **Modules tested:** FAST (two disk images: INFORMANT-PC and RM2-MEDIA), combined
  into a campaign report
- **Source of data:** NIST CFReDS —
  https://cfreds.nist.gov/data-leakage-case/data-leakage-case.html (publicly
  distributed pair of forensic disk images)

**What the agent found:**

- 14 substantive findings: 6 CONFIRMED (all with both-evidence-item corroboration),
  5 INFERRED, 1 ASSUMED, 2 UNVERIFIABLE — 79% confirmed or inferred from direct
  evidence (11 of 14 backed by at least one evidence item; 6 confirmed independently
  by both items).
- Cross-image pivot: USB device serial `4C530012550531106501` recovered from
  RM2-MEDIA `fsstat`/USB metadata was matched against a USBSTOR registry entry on
  INFORMANT-PC, directly linking the removable media to the suspect workstation with
  two-item corroboration.
- Self-corrected a timeline near-miss mid-investigation: FAT32 timestamps on RM2-MEDIA
  were initially read as UTC, placing one file access *after* the directory wipe.
  A later step identified the effective timezone as EDT (UTC-4), reversed the
  ordering to *~22 minutes before* the wipe, and updated the timeline before report
  generation — the corrected ordering reached the final report, not the initial read.
- Disclosed four gaps honestly: no network capture (network-based exfiltration
  UNVERIFIABLE), no memory image (live-process activity UNVERIFIABLE), exact wipe
  mechanism indeterminate from the image (ASSUMED), and the "Authorized USB RM#1"
  original company drive was not in evidence (byte-comparison impossible).
- Assessed 9 of the 24 "stock photo" files on RM2-MEDIA as open leads (not added to
  the confirmed exfiltration count) because no appended ZIP/Office blob was detected
  for them under the steganography-detection method applied — recorded as RF-002
  rather than inflating the confirmed document tally.

---

## 3. Nitroba University Harassment Scenario

- **Case ID:** `FAN-2026-NITROBA-V5`
- **Modules tested:** FAN only (single-module incident report)
- **Source of data:** Digital Corpora —
  https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/
  (publicly distributed packet capture)

**What the agent found:**

- 16 substantive findings: 6 CONFIRMED, 4 INFERRED, 2 ASSUMED, 4 UNVERIFIABLE — 75%
  confirmed (12 of 16 backed by direct FAN artifact evidence).
- Confirmed the core scenario: traced a harassing email sent via
  `sendanonymousemail.net` (POST `/send.php`, 06:02:57 UTC, frame 80614, tcp.stream
  1631) back to a specific Gmail identity (`jcoachj@gmail.com`) through a
  dual-browser-session / shared-MAC-address correlation — found by three additional
  deep-dive pivots beyond the standard 22-module pass, not flagged by any automated
  detector (the destination domain is a legitimate ad-supported service, not a
  known-bad indicator).
- Largest false-positive concentration across all five cases: every one of the 22
  automated Toolbox A detector alerts was individually reviewed and dismissed as
  a false positive consistent with normal 2008-era traffic — categories included
  ICMP "data exfiltration," DNS "DGA/C2/fast-flux/tunneling," HTTP "suspicious
  URI/cookie anomaly," UDP "flood/amplification/IP spoofing," and TLS "deprecated
  version" (TLS 1.0/SSL 3.0 were current standards in July 2008).
- Surfaced a coverage gap itself: SIP/RTP/RTCP (VoIP), MSN Messenger, Yahoo
  Messenger, and BitTorrent DHT traffic are present in the capture but not covered
  by any of the 22 Toolbox A detectors — the mandatory IM sweep (RN-015) covered
  this gap and produced the case's central finding.
- Suricata IDS did not execute successfully (wrapper-script exit code 1, `-q` flag
  defect, RN-013) — documented as UNVERIFIABLE rather than a clean IDS pass. CTI
  enrichment for all 443 IPs returned "no data" (Perplexity API key not configured)
  — recorded as no data, not confirmed benign.

---

## 4. Stark Research Labs Intrusion — NRomanoff workstation

- **Case ID:** `NROMANOFF`
- **Modules tested:** FAME (memory image) + FAST (disk image), combined into a
  campaign report
- **Source of data:** `internal` — SANS course material (Stark Research Labs Data
  Breach Intrusion dataset; not publicly distributed)

**What the agent found:**

- 14 substantive findings: 9 CONFIRMED (all with two-module FAME+FAST corroboration),
  4 INFERRED, 1 ASSUMED, 0 UNVERIFIABLE — 93% confirmed (13 of 14 backed by direct
  artifact evidence; 9 confirmed by both modules independently).
- Confirmed three-wave PsExec-based intrusion from `10.3.58.7`: remote execution via
  PSEXESVC (corroborated by FAST prefetch `PSEXESVC.EXE-51BA46F2.pf` crtime/mtime
  and registry Services key LastWrite `2012-04-04 18:52:11.178525` matching FAME PID
  2100 creation to the microsecond), dropper `a.exe` (9,216 bytes, SHA-1 confirmed in
  both FAST `fls` and FAME `filescan`), and a Poison-Ivy-pattern RAT listener on
  `127.0.0.1:5678` (FAME RN-005, svchost.exe, 95 heap-sprayed RWX regions via PID
  6404 malfind).
- Caught and corrected a cross-module false positive before the report: FAME evidence
  (PID 6404 holding an open IFEO registry key handle) initially suggested T1546.012
  Image File Execution Options persistence. FAST registry analysis found the IFEO key
  contains only legitimate Office/Adobe `DisableExceptionChainValidation` entries —
  T1546.012 was downgraded to NOT CONFIRMED before report generation, superseded by
  the confirmed Run-key persistence (T1547.001, FAST RN-005).
- Disclosed three gaps honestly: `C:\dllhost.exe` (shimcache entry, 2012-04-03
  18:08:50 — between initial attack and first successful SMB logon) was deleted and
  is unrecoverable; the initial credential-compromise vector is outside this evidence
  set; and the pivot host `10.3.58.7` was not part of the images.
- Self-corrected a timeline description mid-investigation: FAME narrative initially
  described the Wave-1 PsExec session (2012-04-04) and Wave-2 RAT deployment
  (2012-04-06) as occurring "the same evening" — FAST timeline analysis (RN-006)
  showed they are two days apart; corrected before campaign report authoring.

---

## 5. Stark Research Labs Intrusion — NFury workstation

- **Case ID:** `WIN764NFURY`
- **Modules tested:** FAME (memory image) + FAST (disk image), combined into a
  campaign report
- **Source of data:** `internal` — SANS course material (Stark Research Labs Data
  Breach Intrusion dataset; not publicly distributed)

**What the agent found:**

- 12 substantive findings: 6 CONFIRMED (5 from FAST alone; 1 corroborated by FAME +
  cross-case vault), 5 INFERRED, 1 ASSUMED, 0 UNVERIFIABLE — 92% confirmed (11 of 12
  backed by direct artifact evidence; 6 confirmed by two independent sources including
  cross-case vault correlation with NROMANOFF).
- Reversed a key memory-analysis interpretation using disk evidence: FAME initially
  suggested NFury *initiated* RPC/SMB connections to `10.3.58.4` (CONTROLLER) — a
  pattern consistent with the PsExec lateral-movement seen in NROMANOFF. FAST
  Security EVTX (RN-003, EVT-006) definitively reversed this: CONTROLLER connected
  *to* NFury using stolen `rsydow` domain credentials. The corrected interpretation
  reached the final report; the reversed claim does not appear in the Hallucination
  Guard table.
- Confirmed backdoor deployment and attacker cleanup: three PyInstaller-packaged
  executables deleted from disk at 18:43:07 UTC, recovered from the Recycle Bin —
  `backdoor.exe` (MD5 traced to NROMANOFF's dropper by cross-case vault match),
  `hythonize.exe`, and `hythonized.exe`. The latter two remain INFERRED as staging
  tools with undetermined specific function (no public MD5 match in this environment).
- Caught two false positives: two CLOSED `lsass.exe` sockets to public IPs were
  assessed as stale pool-memory artifacts (malfind zero hits, port=0, no FAST
  corroboration); a `f-response-ent.exe` connection on port `5681` (one digit from
  the NROMANOFF RAT port `5678`) was recorded as an open lead rather than a confirmed
  IOC, most plausibly coincidental port proximity with the legitimate F-Response
  acquisition agent.
- Disclosed three open gaps: `hythonize.exe`/`hythonized.exe` function undetermined;
  `nfury`'s Outlook PST not parsed (`readpst`/`libpst` unavailable in this
  environment), leaving a possible phishing/initial-access vector unresolved; and the
  `vibranium` domain account (anomalously high RID 1673) cannot be attributed without
  domain-controller SAM/AD data.

---

## Notes on provenance and reproducibility

Cases 1–3 use public, well-documented forensic challenges; published write-ups for
each exist online and may be part of the model's training data (see `accuracy.md` §2,
"build vs. score"). Cases 4–5 use SANS course material that is not publicly documented,
so the "evidence trail vs. recall" concern is lower for those cases. What this project
independently verifies across all five cases is that **every cited finding traces to an
actual tool execution recorded in that case's research notes** for this run — i.e. the
evidence trail was re-derived from the supplied image/capture, not copied from a
published answer key. An automated audit (`accuracy/verify_claims.py`) checks every
"hard" token (timestamps, byte counts, IP addresses, hashes, MAC addresses, frame/stream
numbers, MITRE technique IDs) cited in each case's campaign report against that case's
research notes, narrative, and correlation files; results are in
`accuracy/claim_traceability_audit.md`. The audit found 12 flagged tokens across 337
cited lines (200 checkable): 8 MITRE technique IDs assigned during synthesis, 2
cross-case vault references, 1 timezone-derived timestamp, and 1 byte-count comma
formatting difference — no genuine hallucinations.
