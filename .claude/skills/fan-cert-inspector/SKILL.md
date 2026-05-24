# Skill: FAN HTTPS Certificate Inspector

## Overview

Extracts and analyses X.509 certificates observed in a PCAP file. For each
TLS `Certificate` handshake message, the skill records the leaf certificate's
subject, issuer, validity window, Subject Alternative Names (SANs), and
signature algorithm. Eight detection categories flag anomalous or suspicious
certificate properties that are characteristic of attacker-deployed
infrastructure.

| Category | MITRE ATT&CK | Default Severity |
|----------|-------------|-----------------|
| Self-Signed Certificate | T1587.003 — Develop Capabilities: Digital Certificates | Critical |
| Expired Certificate | T1040 — Network Sniffing | High |
| Not Yet Valid Certificate | T1040 — Network Sniffing | Medium |
| Very Short Certificate Validity (< 30 days) | T1587.003 — Develop Capabilities: Digital Certificates | High |
| Excessive Certificate Validity (> 398 days) | T1040 — Network Sniffing | Low |
| Wildcard Certificate | T1587.003 — Develop Capabilities: Digital Certificates | Info |
| Certificate CN / SNI Mismatch | T1557 — Adversary-in-the-Middle | Critical |
| Weak Certificate Signature Algorithm | T1040 — Network Sniffing | High |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/cert_inspector/<stem>/certs.json` |
| Certificate inventory CSV | `./analysis/cert_inspector/<stem>/certs.csv` |
| Markdown report | `./analysis/cert_inspector/<stem>/cert_inspector_report.md` |

**Note:** Analysis is limited to the metadata visible in TLS handshake messages
(Certificate, ClientHello). Certificate *content* is not decrypted — private key
material is never visible. Only certificates presented during the captured
handshakes are analysed; certificates from resumed TLS sessions (no Certificate
message) will not appear.

---

## Invocation

```bash
# Analyze a PCAP for certificate anomalies
./scripts/fan_cert_inspector.sh /path/to/capture.pcap

# With case ID (recommended)
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Custom stem (must match other analysis steps)
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --stem capture --case-id CASE-2025-001

# Skip vault writes (offline/air-gapped)
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --no-vault
```

### Python directly

```python
import sys; sys.path.insert(0, "./lib")
from fan_cert_inspector import analyze, write_json, write_csv, write_report
from pathlib import Path

pcap = Path("/path/to/capture.pcap")
results, records = analyze(pcap)
out_dir = Path("./analysis/cert_inspector/capture")
out_dir.mkdir(parents=True, exist_ok=True)
write_json(results, out_dir / "certs.json")
write_csv(records,  out_dir / "certs.csv")
write_report(results, out_dir / "cert_inspector_report.md", pcap)
```

---

## Detection Logic

### Self-Signed Certificate (T1587.003)
Detected by comparing the first two `x509sat.commonName` values from the
certificate chain. tshark emits CNs in chain order: first CN = leaf subject,
second CN = leaf issuer. When both are equal the certificate is its own issuer
(self-signed). A single-cert chain (only one CN value) is also flagged.

**C2 relevance:** Cobalt Strike, Sliver, Havoc, and most other C2 frameworks
generate self-signed certificates by default. Replacing the default cert with a
CA-issued one is a common OPSEC step that this detector exposes when omitted.

**Finding fields:** `src_ip`, `dst_ip`, `dst_port`, `sni`, `subject_cn`,
`issuer_cn`, `valid_from`, `valid_to`, `timestamp_utc`

---

### Expired Certificate (T1040)
Certificate `notAfter` timestamp is in the past relative to analysis time.
Expired certificates are common on neglected infrastructure and on attacker
servers that were deployed, used, and left running beyond the cert lifetime.

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `expired_at`,
`days_expired`, `timestamp_utc`

---

### Not Yet Valid Certificate (T1040)
Certificate `notBefore` timestamp is in the future. Indicates clock skew,
pre-staged attacker infrastructure, or certificates issued for future deployment.

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `valid_from`,
`days_until_valid`, `timestamp_utc`

---

### Very Short Certificate Validity (T1587.003)
Certificates valid for **fewer than 30 days**. C2 toolkits (default Cobalt
Strike profiles, Havoc team servers) often auto-generate certificates with very
short validity windows to frustrate cert-based threat intel lookups. Legitimate
short-lived certs (Let's Encrypt = 90 days) are not flagged by this threshold.

**Threshold:** `SHORT_VALIDITY_DAYS = 30` (configurable at top of module)

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `valid_days`,
`valid_from`, `valid_to`, `timestamp_utc`

---

### Excessive Certificate Validity (T1040)
Certificates valid for **more than 398 days** (> ~13 months). Since 2020,
Chrome, Safari, and the CA/B Forum cap public DV/OV certificates at 398 days.
Certificates exceeding this were issued before the policy or by private/internal
CAs — the latter may include attacker-controlled certificate authorities.

**Threshold:** `LONG_VALIDITY_DAYS = 398` (configurable at top of module)

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `valid_days`,
`valid_from`, `valid_to`, `timestamp_utc`

---

### Wildcard Certificate (T1587.003)
Subject CN or SAN contains a wildcard label (`*.example.com`). Wildcard certs
are legitimate but are used by C2 operators to cover rotating subdomain C2
endpoints (e.g., `a1b2c3.evil.com`, `x9y8z7.evil.com`) with a single
`*.evil.com` certificate, avoiding the need for per-subdomain cert generation.

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `wildcards`,
`timestamp_utc`

---

### Certificate CN / SNI Mismatch (T1557)
The TLS Server Name Indication (SNI) sent by the client does not match any name
in the certificate's CN or SAN list (including wildcard expansion). A mismatch
indicates:
- TLS MITM proxy presenting its own certificate
- SSL inspection appliance with misconfiguration
- Attacker-controlled interception infrastructure
- CDN or load balancer presenting a wrong certificate (misconfiguration)

SNI is extracted from the ClientHello on the same TCP stream (matched by
`tcp.stream`). Wildcard expansion is applied during matching.

**Finding fields:** `src_ip`, `dst_ip`, `sni`, `subject_cn`, `san_dns`,
`timestamp_utc`

---

### Weak Certificate Signature Algorithm (T1040)
Flags certificates or handshakes referencing deprecated cryptographic algorithms
in the `x509af.algorithm.id` field:

| Algorithm | Status |
|-----------|--------|
| md5WithRSAEncryption | Broken — collision attacks allow forgery |
| sha1WithRSAEncryption | Broken — SHAttered collision (2017) |
| id-dsa-with-sha1 | Deprecated |
| ecdsa-with-SHA1 | Deprecated |

**Finding fields:** `src_ip`, `dst_ip`, `subject_cn`, `sig_alg`,
`matched_pattern`, `timestamp_utc`

---

## Certificate Inventory CSV Columns

| Column | Description |
|--------|-------------|
| `timestamp_utc` | Frame timestamp (ISO-8601 UTC) |
| `src_ip` | TLS client IP address |
| `dst_ip` | TLS server IP address (cert presenter) |
| `src_port` | Client TCP port |
| `dst_port` | Server TCP port |
| `stream_id` | tshark TCP stream index |
| `sni` | SNI from ClientHello on same stream |
| `subject_cn` | Leaf certificate subject Common Name |
| `subject_org` | Leaf certificate subject Organization |
| `san_dns` | SANs (pipe-separated DNS names) |
| `not_before` | Certificate notBefore (raw tshark string) |
| `not_after` | Certificate notAfter (raw tshark string) |
| `valid_days` | Validity duration in days |
| `sig_alg` | Signature algorithm OID or name |

---

## Detection Thresholds

| Threshold | Default | Meaning |
|-----------|---------|---------|
| `SHORT_VALIDITY_DAYS` | 30 | Certs valid < 30 days flagged as short |
| `LONG_VALIDITY_DAYS` | 398 | Certs valid > 398 days flagged as excessive |

Both constants are at the top of `lib/fan_cert_inspector.py`.

---

## Full IR Workflow

```bash
# Step 1 — Extract netflow, IPs, FQDNs from PCAP
./scripts/pcap_analyze.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 2 — ICMP threat detection
./scripts/fan_icmp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 3 — DNS threat detection
./scripts/fan_dns_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 4 — NTP threat detection
./scripts/fan_ntp_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 5 — HTTP(S) unusual pattern detection
./scripts/fan_http_threats.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 6 — TLS certificate inspection
./scripts/fan_cert_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 7 — TLS session inspection + JA4 fingerprinting
./scripts/fan_tls_inspector.sh /path/to/capture.pcap --case-id CASE-2025-001

# Step 8 — CTI enrichment (FQDN/IP OSINT)
./scripts/fan_ip_lookup.sh --stem capture --case-id CASE-2025-001

# Step 9 — Generate consolidated incident report
./scripts/generate_pcap_report.sh --stem capture --case-id CASE-2025-001
```

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent.

| Finding Category | Vault Note | MITRE ID | Severity Threshold |
|-----------------|------------|----------|--------------------|
| Self-Signed Certificate | `TTPs/T1587.003.md` + `IOCs/domain-<cn>.md` | T1587.003 | Critical |
| Certificate CN / SNI Mismatch (MitM) | `TTPs/T1557.md` + `IOCs/domain-<cn>.md` | T1557 | Critical |
| Expired Certificate | `TTPs/T1040.md` + `IOCs/domain-<cn>.md` | T1040 | High |
| Very Short Certificate Validity (< 30 days) | `TTPs/T1587.003.md` + `IOCs/domain-<cn>.md` | T1587.003 | High |
| Weak Signature Algorithm | `TTPs/T1040.md` | T1040 | High |
| Not Yet Valid Certificate | `Concepts/Cert-not-yet-valid-<cn>.md` | T1040 | Medium |
| Excessive Validity (> 398 days) | `Concepts/Cert-excessive-validity-<cn>.md` | — | Low |
| Wildcard Certificate | `Concepts/Cert-wildcard-<cn>.md` | T1587.003 | Info |

Certificate domain names are recorded **defanged** in vault note filenames: `evil[.]com`.

Verify:
```bash
./scripts/vault_context.sh ttp T1587.003
./scripts/vault_context.sh ioc <suspicious_domain>
./scripts/vault_context.sh search "<case_id>"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `No certificate message(s)` | PCAP has no TLS Certificate handshakes | Verify: `tshark -r capture.pcap -Y "tls.handshake.type == 11"` |
| `valid_days` column empty | tshark validity field name differs | Check: `tshark -r capture.pcap -Y "tls.handshake.type == 11" -T fields -e tls.handshake.cert.validity_not_before` |
| Self-signed not detected | CN contains comma (parsing ambiguity) | Inspect raw: `tshark -r capture.pcap -Y "tls.handshake.type==11" -T fields -E occurrence=a -e x509sat.commonName` |
| SNI mismatch not detected | Resumed TLS sessions (no ClientHello in capture) | No fix — resumed sessions have no Certificate or SNI message |
| `sig_alg` empty | tshark field `x509af.algorithm.id` unavailable | Weak-signature category will produce no findings; other categories unaffected |
| vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
| Report missing cert section | Cert inspector not run | Run `fan_cert_inspector.sh <pcap>` first |
