# Skill: FAN File Hashes

## Overview

Extracts files embedded in a PCAP capture using tshark's `--export-objects`
mechanism, computes MD5 and SHA256 for each file, performs OSINT lookups via
Perplexity, and records confirmed malicious/suspicious files as IOC hash entries
in the Obsidian vault.

| Supported Protocol | tshark mechanism |
|--------------------|-----------------|
| HTTP | `--export-objects http` |
| SMB / SMB2 | `--export-objects smb` |
| Internet Message Format | `--export-objects imf` |
| TFTP | `--export-objects tftp` |
| DICOM | `--export-objects dicom` |

| Output | Path |
|--------|------|
| JSON findings | `./analysis/file_hashes/<stem>/file_hashes.json` |
| CSV inventory | `./analysis/file_hashes/<stem>/file_hashes.csv` |
| Markdown report | `./analysis/file_hashes/<stem>/file_hashes_report.md` |
| Extracted files | `./analysis/file_hashes/<stem>/files/<protocol>/` |

---

## Invocation

```bash
./scripts/fan_file_hashes.sh /path/to/capture.pcap
./scripts/fan_file_hashes.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_file_hashes.sh /path/to/capture.pcap --output-dir /custom/path --no-vault
./scripts/fan_file_hashes.sh /path/to/capture.pcap --no-osint   # skip Perplexity lookups
```

---

## Detection Logic

### File Extraction
tshark's `--export-objects <proto>,<dir>` reassembles application-layer objects
from captured protocol streams and writes them to disk. Each extracted file is
then hashed independently.

### Severity Assignment

| Condition | Severity |
|-----------|----------|
| OSINT verdict = malicious | Critical |
| OSINT verdict = suspicious | High |
| Executable extension (`.exe`, `.dll`, `.ps1`, `.bat`, `.sh`, `.elf`, …) | High |
| Other file types | Info |

### OSINT Enrichment
Each SHA256 hash is queried against Perplexity.ai. The free-text response is
scanned for keywords to assign `malicious`, `suspicious`, or `clean` verdicts:

- **Malicious keywords**: malware, trojan, ransomware, backdoor, rat, c2, command-and-control
- **Suspicious keywords**: potentially, pua, adware, unwanted, suspicious

Requires `PERPLEXITY_API_KEY` in the environment. OSINT is silently skipped
if the key is absent or the `perplexity_client` module is unavailable.

### Vault Recording
Files with `malicious` or `suspicious` OSINT verdicts are recorded in the
Obsidian vault as SHA256 hash IOC notes via `knowledge_extractor.record_ioc()`.
Each note includes the filename, size, protocol, and OSINT summary.

---

## JSON Output Structure

```json
{
  "generated_utc": "2025-05-06T12:00:00Z",
  "files_found": 3,
  "malicious_count": 1,
  "suspicious_count": 0,
  "files": [
    {
      "protocol":      "http",
      "filename":      "update.exe",
      "path":          "./analysis/file_hashes/capture/files/http/update.exe",
      "size_bytes":    45312,
      "md5":           "d41d8cd98f00b204e9800998ecf8427e",
      "sha256":        "e3b0c44298fc1c149afbf4c8996fb924...",
      "osint_verdict": "malicious",
      "osint_summary": "Known trojan dropper distributed via malspam ...",
      "timestamp_utc": "2025-05-06T12:00:01Z"
    }
  ]
}
```

---

## CSV Columns

| Column | Description |
|--------|-------------|
| `protocol` | Extraction protocol (http, smb, imf, tftp, dicom) |
| `filename` | Reconstructed filename from tshark |
| `size_bytes` | File size in bytes |
| `md5` | MD5 hex digest |
| `sha256` | SHA256 hex digest |
| `osint_verdict` | malicious / suspicious / clean / unknown |
| `osint_summary` | First 500 characters of OSINT result |
| `timestamp_utc` | Time of extraction |

---

## Integration with Report

Findings appear in **Section 2.13 File Hash Analysis** of the consolidated
incident report. Malicious and suspicious file hashes are automatically added
to the IOC table (Section 4) and trigger MITRE ATT&CK T1105 (Ingress Tool
Transfer) in Section 5.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| No files extracted | No HTTP/SMB/TFTP transfers in PCAP | Verify: `tshark -r capture.pcap -Y "http.response or smb"` |
| OSINT skipped | No `PERPLEXITY_API_KEY` | `export PERPLEXITY_API_KEY=pplx-...` in `~/.bashrc` |
| tshark export fails | tshark < 1.12 or unsupported protocol | Use `--no-osint` and hash manually |
| Vault writes fail | `knowledge_extractor` import error | Add `--no-vault` flag |
| Empty JSON but files extracted | Hash computation error | Check file permissions in output directory |
