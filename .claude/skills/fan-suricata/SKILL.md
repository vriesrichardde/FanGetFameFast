# Skill: FAN Suricata IDS

## Overview

Runs Suricata in offline PCAP-read mode (`-r`) using rules from `./rules/suricata/`.
`rules/suricata/suricata.rules` is a copy of `/var/lib/suricata/rules/suricata.rules`,
refreshed by running `./scripts/update_suricata_rules.sh` (`sudo suricata-update` + copy).
Parses the resulting EVE JSON alert stream, produces structured findings, and records
high-severity source/destination IPs in the Obsidian vault.

| Output | Path |
|--------|------|
| Alert summary JSON | `./analysis/suricata/<stem>/suricata_alerts.json` |
| Alert CSV | `./analysis/suricata/<stem>/suricata_alerts.csv` |
| Markdown report | `./analysis/suricata/<stem>/suricata_report.md` |
| Raw EVE JSON | `./analysis/suricata/<stem>/eve.json` |
| Generated config | `./analysis/suricata/<stem>/suricata.yaml` |

---

## Invocation

```bash
./scripts/fan_suricata.sh /path/to/capture.pcap
./scripts/fan_suricata.sh /path/to/capture.pcap --case-id CASE-2025-001
./scripts/fan_suricata.sh /path/to/capture.pcap --output-dir /custom/path --no-vault
```

Update rules before analysis:
```bash
./scripts/update_suricata_rules.sh          # runs: sudo suricata-update
./scripts/update_suricata_rules.sh --list   # list available rule sources
```

---

## Python API

```python
from lib.fan_suricata import analyze
from pathlib import Path

result = analyze(
    pcap=Path("/path/to/capture.pcap"),
    stem="capture",
    output_dir=Path("analysis/suricata/capture"),
    case_id="CASE-2025-001",
    no_vault=False,
)
print(result["total"], "alerts")
```

---

## Rule Management

Rules are loaded from `./rules/suricata/`. The directory contains two files:

| File | Description |
|------|-------------|
| `rules/suricata/suricata.rules` | Copy of `/var/lib/suricata/rules/suricata.rules` — refresh with `update_suricata_rules.sh` |

### Updating rules

```bash
./scripts/update_suricata_rules.sh          # runs: sudo suricata-update
./scripts/update_suricata_rules.sh --list   # list available rule sources
```

### Installing Suricata

```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt-get update && sudo apt-get install suricata
```

---

## Detection Logic

### Offline mode
```
suricata -r capture.pcap -l <log_dir> -c <config> --runmode single -q
```
Suricata reads the PCAP without touching any live interface. The generated
`suricata.yaml` points `default-rule-path` to `./rules/suricata/` and loads `suricata.rules`.

### Severity mapping

| Suricata severity | Report severity |
|-------------------|-----------------|
| 1 (highest)       | Critical        |
| 2                 | High            |
| 3                 | Medium          |
| 4 (lowest)        | Low             |

### Vault recording
Source and destination IPs from **Critical** and **High** alerts are recorded
as IOC notes in the Obsidian vault via `knowledge_extractor.record_ioc()`.

### MITRE ATT&CK mapping
Alert categories are mapped to techniques automatically:

| Suricata category | MITRE technique |
|-------------------|-----------------|
| A Network Trojan was Detected | T1071 |
| Malware Command and Control | T1071 |
| Web Application Attack | T1190 |
| Attempted Privilege Gain | T1068 |
| Exploit Kit Activity Detected | T1189 |
| Credential Theft | T1003 |
| Network Scan | T1046 |
| Ransomware | T1486 |
| Lateral Movement | T1021 |

---

## JSON Output Structure

```json
{
  "generated_utc":  "2025-05-06T12:00:00Z",
  "pcap":           "/path/to/capture.pcap",
  "stem":           "capture",
  "total_alerts":   42,
  "critical_count": 5,
  "high_count":     12,
  "medium_count":   25,
  "low_count":      0,
  "alerts": [
    {
      "timestamp_utc":     "2025-05-06T11:00:01.000000+0000",
      "src_ip":            "192.168.1.5",
      "src_port":          "54321",
      "dest_ip":           "203.0.113.42",
      "dest_port":         "443",
      "proto":             "TCP",
      "signature_id":      "2027865",
      "signature":         "ET MALWARE Cobalt Strike Beacon Activity",
      "category":          "Malware Command and Control Activity Detected",
      "severity":          "critical",
      "action":            "allowed",
      "rev":               "2",
      "payload_printable": ""
    }
  ]
}
```

---

## Vault Recording

Written automatically by the lib when `--no-vault` is absent and alert severity is Critical or High.

| Written | Condition | Vault Note |
|---------|-----------|------------|
| Source IP of Critical/High alert | severity ≥ High | `IOCs/ip-<defanged_src_ip>.md` |
| Destination IP if external | severity ≥ High | `IOCs/ip-<defanged_dst_ip>.md` |
| ATT&CK technique from rule metadata | If `mitre_attack_id` tag present in rule | `TTPs/<T-ID>.md` |
| Alert signature as Concept | All alerts | `Concepts/Suricata-<sig_name>.md` (Critical/High only) |

**Per-rule MITRE tags:** Rules from ET Open often include `metadata:attack_target <T-ID>` or
`classtype:trojan-activity`. The lib maps Suricata rule class types to ATT&CK techniques where possible.
Verify:
```bash
./scripts/vault_context.sh ioc <alert_src_ip>
./scripts/vault_context.sh ttp T1071
./scripts/vault_context.sh search "Suricata-"
```

**Manual supplement** — after reviewing the alert report, record confirmed TTPs from the alert context:
```python
import sys; sys.path.insert(0, "./lib")
from knowledge_extractor import record_ttp
record_ttp("T1071.001", "Web Protocols", "Suricata ET TROJAN alert on <dst_ip>. Rule: <sig>.",
           case_id, tactic="command-and-control")
```

## Integration with Report

Findings appear in **Section 2.14 Suricata IDS Alerts** of the consolidated
incident report. Alert source/dest IPs are added to the IOC table (Section 4),
MITRE ATT&CK techniques populate Section 5, and recommendations are generated
in Section 6.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `suricata not found` | Not installed | `sudo apt install suricata` (see above) |
| `eve.json` not created | Config error or unsupported PCAP | Check `suricata.log` in output dir |
| 0 alerts on known-malicious PCAP | No/outdated rules | Run `./scripts/update_suricata_rules.sh` |
| `classification.config` warning | Missing system file | `sudo apt install suricata` (installs configs) |
| Permission denied on log dir | Output dir owned by root | Use `--output-dir` pointing to a writable path |
| `suricata.rules` missing | `update_suricata_rules.sh` not yet run | Run `./scripts/update_suricata_rules.sh` |
