# Skill: FAN YARA Rules (PCAP)

## Overview

Scans a PCAP file, extracted files, directories, and memory images using YARA rules
stored in `./rules/yara/`. YARA is run against:

1. **The raw PCAP binary** — detects patterns anywhere in packet payloads
2. **Extracted application-layer files** — files previously extracted by `fan-file-hashes`
   (`./analysis/file_hashes/<stem>/files/`)
3. **Extra targets** — additional files, directories (recursive), or memory images
   passed via `--extra-targets`

| Output | Path |
|--------|------|
| Match summary JSON | `./analysis/yara_pcap/<stem>/yara_matches.json` |
| Match CSV | `./analysis/yara_pcap/<stem>/yara_matches.csv` |
| Markdown report | `./analysis/yara_pcap/<stem>/yara_report.md` |
| String offsets | `./analysis/yara_pcap/<stem>/yara_strings.txt` (when `--strings`) |
| Compiled rules | `./analysis/yara_pcap/<stem>/compiled.rules` (when yarac available) |

---

## Invocation

```bash
# Scan PCAP only
./scripts/fan_yara_pcap.sh /path/to/capture.pcap

# With case ID and vault recording
./scripts/fan_yara_pcap.sh /path/to/capture.pcap --case-id CASE-2025-001

# Scan PCAP + mounted filesystem (recursive) + memory image
./scripts/fan_yara_pcap.sh /path/to/capture.pcap \
    --extra-targets /mnt/windows_mount/ /cases/mem/memory.img

# Performance tuning — 4 threads, fast mode, 60 s per-target timeout
./scripts/fan_yara_pcap.sh /path/to/capture.pcap --threads 4 --fast --timeout 60

# Capture matching string offsets
./scripts/fan_yara_pcap.sh /path/to/capture.pcap --strings

# Include community rules directory
./scripts/fan_yara_pcap.sh /path/to/capture.pcap \
    --community-rules /opt/signature-base/yara/

# Run false-positive test against /usr/bin before scanning evidence
./scripts/fan_yara_pcap.sh /path/to/capture.pcap --fp-test
```

Run `fan-file-hashes` first to enable deeper scanning of extracted files:
```bash
./scripts/fan_file_hashes.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_yara_pcap.sh   /path/to/capture.pcap --case-id CASE-2025-001
```

For standalone disk/memory sweeps (no PCAP needed), use `yara_sweep.sh`:
```bash
./scripts/yara_sweep.sh --target /mnt/windows_mount/ --case-id CASE-2025-001
./scripts/yara_sweep.sh --target /path/to/memory.img --strings
./scripts/yara_sweep.sh --target /mnt/evidence/ --fp-test --threads 4
```

---

## Python API

```python
from lib.fan_yara_pcap import analyze
from pathlib import Path

result = analyze(
    pcap=Path("/path/to/capture.pcap"),
    stem="capture",
    output_dir=Path("analysis/yara_pcap/capture"),
    case_id="CASE-2025-001",
    no_vault=False,
    extra_targets=[Path("/mnt/windows_mount/"), Path("/cases/mem/memory.img")],
    community_rules=Path("/opt/signature-base/yara/"),
    threads=4,
    fast=False,
    strings=True,
    timeout=120,
    fp_test=False,
)
print(result["total"], "matches")
```

---

## Rule Management

All `.yar` files in `./rules/yara/` are loaded automatically.

| File | Contents |
|------|----------|
| `rules/yara/network_threats.yar` | HTTP download cradles, Cobalt Strike C2 profile, PE download via HTTP, SMB lateral movement, path traversal, DNS exfil labels, offensive UA strings |
| `rules/yara/common_malware.yar` | Meterpreter stages, Empire stager, Mimikatz strings, LSASS dump transfer, PHP/ASP webshells, ransomware strings, Sliver C2, Nmap signatures |
| `rules/yara/pe_analysis.yar` | PE module rules: high-entropy sections, injection APIs (VirtualAllocEx+WriteProcessMemory+CreateRemoteThread), process-hollowing (NtUnmapViewOfSection), reflective DLL loader, MZ-in-stream, LSASS dump imports, epoch timestamp wipe, PE imphash IOCs |
| `rules/yara/entropy_detection.yar` | Entropy/hash module rules: overall high-entropy, small high-entropy files, packed PE heuristic, known-bad MD5/SHA256, encrypted-content heuristic, base64 density, NOP sled, polyglot file (PDF+PE) |

### Adding custom rules

```yara
import "pe"
import "math"

rule My_Custom_Rule {
    meta:
        severity    = "high"
        description = "Detects X"
        category    = "c2"
        mitre_att   = "T1071.001"
    strings:
        $s1 = "evil-pattern" nocase
    condition:
        $s1
}
```

### Community rulesets

```bash
sudo git clone https://github.com/Neo23x0/signature-base /opt/signature-base
./scripts/fan_yara_pcap.sh capture.pcap --community-rules /opt/signature-base/yara/

sudo git clone https://github.com/Yara-Rules/rules /opt/yara-rules
./scripts/fan_yara_pcap.sh capture.pcap --community-rules /opt/yara-rules/malware/
```

---

## Detection Logic

**YARA binary:** `/usr/local/bin/yara` v4.1.0 (pre-installed on Ubuntu 24.04 LTS)

**yarac compilation:** All `.yar` files are pre-compiled into a single binary `.rules`
file when `yarac` is available. Subsequent targets in the same run use the compiled
file — significantly faster for large directories or memory images.

**Severity** is read from the rule's `severity` metadata field; defaults to **medium**.

**Vault recording:** Critical and high matches with a `mitre_att` field write a TTP
note to the Obsidian vault via `knowledge_extractor.record_ttp()`.

**PE module rules** (`pe_analysis.yar`) use `import "pe"` — built into YARA v4.1.

**Entropy/hash rules** (`entropy_detection.yar`) use `import "math"` and `import "hash"`.

### CLI flags applied

| Flag | Effect |
|------|--------|
| `-p N` | Parallel threads (default: 2) |
| `-f` | Fast mode — first match per rule |
| `-s` | Print matching strings with byte offsets |
| `-r` | Recursive directory scan (auto-applied for directory targets) |
| `--timeout N` | Per-target timeout in seconds |
| `-C compiled.rules` | Use pre-compiled rules (auto-used when yarac available) |

---

## False-Positive Testing

```bash
./scripts/fan_yara_pcap.sh capture.pcap --fp-test
```

Scans `/usr/bin` and `/usr/lib` before evidence. Hits written to
`./analysis/yara_pcap/<stem>/fp_test.txt`. Manual test:

```bash
yara -r ./rules/yara/pe_analysis.yar /usr/bin/
yara -r ./rules/yara/common_malware.yar /usr/lib/
```

---

## Standalone Sweep (`yara_sweep.sh`)

```bash
./scripts/yara_sweep.sh --target /mnt/windows_mount/
./scripts/yara_sweep.sh --target memory.raw --strings
./scripts/yara_sweep.sh --target /mnt/evidence/ --compiled ./analysis/yara_pcap/capture/compiled.rules
```

Output: `./analysis/yara_sweep/<prefix>/` containing `yara_hits.txt`, `yara_strings.txt`, `summary.txt`.

---

## JSON Output Structure

```json
{
  "generated_utc":  "2025-05-06T12:00:00Z",
  "pcap":           "/path/to/capture.pcap",
  "stem":           "capture",
  "total_matches":  3,
  "critical_count": 1,
  "high_count":     2,
  "medium_count":   0,
  "low_count":      0,
  "matches": [
    {
      "rule":          "CobaltStrike_Beacon_x64_Stub",
      "target":        "/path/to/capture.pcap",
      "target_name":   "capture.pcap",
      "rule_file":     "",
      "severity":      "critical",
      "description":   "Cobalt Strike x64 beacon stage shellcode stub",
      "category":      "c2",
      "mitre_att":     "T1071.001",
      "timestamp_utc": "2025-05-06T12:00:01Z"
    }
  ]
}
```

---

## Integration with Report

Findings appear in **Section 2.15 YARA Rule Matches** of the consolidated
incident report. MITRE ATT&CK IDs from rule metadata populate Section 5.
Critical/High matches generate recommendations in Section 6.

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent and a match is found.

| Match Type | Vault Note | Severity Threshold |
|-----------|------------|-------------------|
| Malware family rule (rule name contains known malware) | `Malware/<name>.md` + `IOCs/hash-<sha256>.md` | Critical/High |
| ATT&CK-tagged rule (`tag = "T1234"` in rule meta) | `TTPs/<T-ID>.md` | All severities |
| High-severity match (meta: `severity = "critical"/"high"`) | `IOCs/hash-<matched_file_sha256>.md` | Critical/High |
| Any rule match | `Concepts/YARA-match-<rule_name>.md` | All severities |

**Rule metadata conventions** (add to your `.yar` rule `meta:` blocks):
```yara
meta:
    author      = "SOC"
    severity    = "high"          // critical / high / medium / low
    mitre_id    = "T1059.001"    // primary technique
    malware     = "Cobalt Strike" // malware family (drives record_malware)
    description = "Detects CS shellcode in HTTP stream"
```

**Manual supplement** — record confirmed malware after analyst review:
```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_malware, record_ttp, record_ioc

record_malware("Cobalt Strike", "Beacon implant detected via YARA rule cs-beacon-http.", case_id)
record_ttp("T1059.001", "PowerShell", "CS stager executed via PowerShell. YARA match confirmed.", case_id)
record_ioc("hash", matched_sha256, "YARA match: cs-beacon-http rule. File: update.exe.", case_id, severity="critical")
```

Verify:
```bash
./scripts/vault_context.sh search "YARA-match-"
./scripts/vault_context.sh search "<case_id>"
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `YARA not found` | Not at `/usr/local/bin/yara` | `sudo apt install yara` |
| No `.yar` files found | Empty rules dir | Add rules to `./rules/yara/` |
| No extracted files scanned | `fan_file_hashes` not run first | Run `./scripts/fan_file_hashes.sh` before this skill |
| All severities show "medium" | Rules lack `severity` metadata | Add `severity = "high"` in `meta:` block |
| `pe module not available` | Old YARA | `sudo apt install yara` (v4.1+ has PE module) |
| `math module not available` | Old YARA | `sudo apt install yara` |
| yarac not found | Not installed | `sudo apt install yara` (yarac ships with yara) |
| High FP rate | Rules too broad | Run `--fp-test` and tune rule conditions |
| Memory image scan slow | Large file + many rules | Use `--fast`, pre-compiled rules, `--timeout 300` |
