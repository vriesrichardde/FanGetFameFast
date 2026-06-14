# Dataset Documentation

This document records what FanGetFameFast was tested against, where each dataset
comes from, and what the agent found for each one. It is derived from
`accuracy/accuracy.md` (the full accuracy & evidence integrity self-assessment) —
see that file for citations, confidence-tier breakdowns, and the automated
claim-traceability audit.

Reproducibility: every case below was run end-to-end through the documented
pipeline (FAN and/or FAST, see `CLAUDE.md`) against the public source image/capture
listed, with no hand-edited evidence. Each case's research notes (`RN-NNN`),
timeline events (`EVT-NNN`), and Hallucination Guard findings (`FND-NNN`) are stored
under `reports/<case_id>/` (or `archive/<case_id>/` once a case is closed) and can be
re-checked with `python3 accuracy/verify_claims.py`.

---

## 1. NIST Hacking Case ("Mr. Evil" XP war-driver)

- **Case ID:** `NIST-HACK-2026-V2`
- **Modules tested:** FAN (network/PCAP) + FAST (disk image), combined into a
  campaign report
- **Source of data:** NIST CFReDS — https://cfreds.nist.gov/Hacking_Case.html
  (publicly distributed forensic image + packet capture)

**What the agent found:**

- 18 substantive findings in the campaign report: 10 CONFIRMED (2 with two-source
  corroboration), 4 INFERRED, 2 ASSUMED, 2 UNVERIFIABLE — 78% confirmed.
- Reconstructed the attack timeline: installation of Ethereal/WinPcap and Cain &
  Abel on the suspect ("Mr. Evil") desktop, followed minutes later by creation of an
  `interception` packet-capture file on disk — independently corroborated across the
  FAST (disk) and FAN (PCAP) evidence by matching file size (173,372 bytes) and
  timestamp (15:41:00 UTC).
- Identified ARP-poisoning/MITM as the most likely interception vector, but
  explicitly tagged this **ASSUMED** rather than CONFIRMED because ARP poisoning
  itself is not directly observed in the recovered PCAP extract — only the toolkit
  and the resulting capture file are.
- Caught and corrected two automated-detector **false positives** before they
  reached the report: a CRITICAL "UDP amplification / IP spoofing" alert that was
  reassessed as normal SSDP/UPnP gateway traffic, and a "T1048 exfiltration"
  classification of HTTP cookies that was reassessed as cleartext session-token
  exposure (not active exfiltration).
- Disclosed four open gaps rather than papering over them: Suricata coverage for the
  `interception` PCAP is marked UNVERIFIABLE (known `-q` flag defect), an unresolved
  IP-addressing discrepancy between FAST (`192.168.1.111`) and FAN
  (`192.168.254.0/24`) subnets is left open as a recorded contradiction, and two sets
  of unidentified executables (`30.EXE`/`A32-19.EXE`/`GLJ15.TMP`) are flagged as
  unconfirmed cracks/keygens with no surviving files to verify against.

---

## 2. NIST Data Leakage Case (informant exfiltration)

- **Case ID:** `NIST-DATALEAKAGE-2015`
- **Modules tested:** FAST (two disk images: `pc` and `removable-media-2`),
  combined into a campaign report
- **Source of data:** NIST CFReDS —
  https://cfreds.nist.gov/data-leakage-case/data-leakage-case.html (publicly
  distributed pair of forensic disk images)

**What the agent found:**

- 16 substantive findings in the campaign report: 6 CONFIRMED (all with two-image
  corroboration), 7 INFERRED, 2 ASSUMED, 1 UNVERIFIABLE — 81% confirmed-or-inferred
  from direct evidence.
- Cross-image pivot: USB device serial `4C530012550531106501` recovered from the
  `removable-media-2` image's `fsstat`/USB metadata was matched against a USBSTOR
  registry entry on the `pc` image, directly linking the removable media to
  INFORMANT-PC.
- Caught two automated false positives: 14 IE11 "Burn"-folder Recycle Bin entries
  and ~20 copied stock-photo files were both assessed as incidental/unrelated to the
  leak rather than folded into the exfiltration narrative.
- Disclosed three gaps: no network capture or memory image exists for this case, so
  network-based exfiltration and live-process activity are explicitly stated as
  **cannot be confirmed or ruled out** (UNVERIFIABLE); a Google Drive/iCloud research
  step is recorded as an ASSUMED additional channel with **no transfer evidence
  found**; and the exact media-wipe mechanism is recorded as indeterminate from the
  image alone.
- Self-corrected a near-miss during the investigation itself: removable-media FAT32
  timestamps were initially read as UTC, provisionally placing a file access *after*
  the directory wipe. A later step identified the effective timezone as EDT
  (UTC-4), applied the correction, and found the access actually occurred ~22
  minutes *before* the wipe — the reverse of the initial read. The corrected
  ordering is what reached the final report.

---

## 3. Nitroba University Harassment Scenario

- **Case ID:** `FAN-2026-NITROBA`
- **Modules tested:** FAN only (single-module incident report)
- **Source of data:** Digital Corpora —
  https://digitalcorpora.org/corpora/scenarios/nitroba-university-harassment-scenario/
  (publicly distributed packet capture)

**What the agent found:**

- 29 findings in the incident report's Hallucination Guard: 20 CONFIRMED (69%), 2
  INFERRED (7%), 7 ASSUMED (24%), 0 UNVERIFIABLE.
- Confirmed the core scenario: traced a harassing email sent via
  `sendanonymousemail.net` (POST `/send.php` at 06:02:57 UTC, frame 80614,
  tcp.stream 1631) back to a specific Gmail identity (`jcoachj@gmail.com`) via a
  dual-browser-session / shared-MAC-address correlation — found through three
  additional deep-dive pivots beyond the standard 22-module pass, and not flagged by
  any automated detector because the destination domain is a legitimate ad-supported
  service rather than a known-bad indicator.
- The largest false-positive concentration of the three cases: seven separate
  automated-detector over-calls (ICMP "data exfiltration"/"Smurf", 10 "suspicious
  URI" SQLi/path-traversal heuristics, 93 HTTP "cookie anomaly" alerts, "suspicious
  referer"/"host header anomaly", UDP "flood"/"amplification"/"IP spoofing", and
  "deprecated TLS version") were each manually re-investigated and downgraded to
  FALSE POSITIVE — e.g. the "deprecated TLS" alert was TLS1.0/SSL3.0, which were the
  *current* standards at the capture date (July 2008), not a vulnerability.
- Surfaced a coverage gap itself: SIP/RTP/RTCP (VoIP), IPsec ESP/ISAKMP (VPN), MSN
  Messenger, Yahoo Messenger, and BitTorrent DHT traffic were noted as present in the
  capture but not covered by any of the 22 protocol detectors — recorded as a new
  pivot rather than left unexamined.
- The automated contradiction-detector flagged 24 pairs of findings as
  contradictory; on review, all 24 were a heuristic false positive (the keyword
  "detected" matching across unrelated protocol findings), not genuine
  hallucinations — recorded as a known limitation of `detect_contradictions()`
  rather than suppressed.
- CTI/IP-lookup enrichment returned "0 malicious / 0 suspicious" for all 443 IPs /
  485 FQDNs, but this is recorded as **no data** (Perplexity API key not configured
  in this environment), not as a confirmed-benign verdict.

---

## Notes on provenance and reproducibility

All three datasets above are public, well-documented forensic challenges; published
write-ups for each exist online and may be part of the model's training data (see
`accuracy.md` §2, "build vs. score"). What this project independently verifies is
that **every cited finding traces to an actual tool execution recorded in that case's
research notes** for this run — i.e. the evidence trail was re-derived from the
supplied image/capture, not copied from a published answer key. An automated audit
(`accuracy/verify_claims.py`) checks every "hard" token (timestamps, byte counts, IP
addresses, hashes, MAC addresses, frame/stream numbers, MITRE technique IDs) cited in
each case's report against that case's research notes, narrative, and correlation
files; results are in `accuracy/claim_traceability_audit.md`.
