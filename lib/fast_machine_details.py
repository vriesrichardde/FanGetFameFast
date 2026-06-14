#!/usr/bin/env python3
# SPDX-License-Identifier: MIT OR Apache-2.0
# SPDX-FileCopyrightText: 2026 Richard de Vries · Jeffrey Everling · Malin Janssen · Suzanne Maquelin · Joost Beekman
"""
fast_machine_details.py — FAST deep-extraction helpers.

Extracts machine identity details from registry hives, parses Recycle Bin $I
metadata files, locates PowerShell history files, and records IOC findings to
a consolidated iocs.json for the IOC Reference report section.

All output is written to:
  exports_dir/machine_details/machine_details.json
  exports_dir/machine_details/ps_history.txt
  exports_dir/machine_details/iocs.json
  exports_dir/recyclebin/recyclebin_parsed.json

CLI usage:
  python3 lib/fast_machine_details.py --exports ./exports [--fs-mount /mnt/windows_mount]
  python3 lib/fast_machine_details.py --record-ioc ip 192.168.1.5 step-06-network-config CONFIRMED
  python3 lib/fast_machine_details.py --test
"""
from __future__ import annotations

import argparse
import json
import struct
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

# Windows FILETIME epoch (100-nanosecond intervals since 1601-01-01 UTC)
_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)

# ── Write-path policy ─────────────────────────────────────────────────────────
try:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import path_guard
    _safe_write = path_guard.safe_write_text
except (ImportError, AttributeError):
    def _safe_write(path: Path, content: str) -> None:
        Path(path).write_text(content, encoding="utf-8")


# ── Utilities ─────────────────────────────────────────────────────────────────

def _humanize_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


def _filetime_to_utc(ft: int) -> str:
    """Convert Windows FILETIME (100-ns intervals since 1601-01-01) to UTC string."""
    if ft <= 0:
        return ""
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=ft // 10)
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError):
        return ""


def _defang(value: str, category: str) -> str:
    """Defang IOC values for safe storage and reporting."""
    if not value:
        return value
    if category in ("ip",):
        return value.replace(".", "[.]")
    if category in ("domain", "url", "fqdn"):
        v = value.replace(".", "[.]")
        return v.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return value


# ── Registry parsing ──────────────────────────────────────────────────────────

def _open_registry(hive_path: Path):
    """Return a python-registry Registry object or None if unavailable."""
    try:
        from Registry import Registry  # python3-registry package
        return Registry.Registry(str(hive_path))
    except ImportError:
        return None
    except Exception:
        return None


def _reg_value(key, name: str, default=None):
    """Safe registry value read."""
    try:
        return key.value(name).value()
    except Exception:
        return default


def _extract_from_software_hive(hive_path: Path) -> dict:
    """Extract machine identity and installed applications from SOFTWARE hive."""
    result: dict = {}
    reg = _open_registry(hive_path)
    if reg is None:
        result["_error"] = "python-registry not available (pip3 install python-registry)"
        return result

    # OS metadata + registered owner
    try:
        cv = reg.open("Microsoft\\Windows NT\\CurrentVersion")
        for field in [
            "RegisteredOwner", "RegisteredOrganization",
            "ProductName", "CurrentVersion", "CurrentBuild",
            "BuildBranch", "UBR", "InstallDate", "DisplayVersion",
        ]:
            val = _reg_value(cv, field)
            if val is not None:
                result[field] = val
    except Exception:
        pass

    # Last logged-on user (Winlogon)
    try:
        wl = reg.open("Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        val = _reg_value(wl, "LastLoggedOnUser")
        if val:
            result["LastLoggedOnUser"] = val
    except Exception:
        pass

    # Installed applications (32-bit and 64-bit uninstall keys)
    apps: list[dict] = []
    for subpath in [
        "Microsoft\\Windows\\CurrentVersion\\Uninstall",
        "WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
    ]:
        try:
            uninstall_key = reg.open(subpath)
            for app_key in uninstall_key.subkeys():
                info: dict = {}
                for field in [
                    "DisplayName", "DisplayVersion", "Publisher",
                    "InstallDate", "InstallLocation", "UninstallString",
                ]:
                    val = _reg_value(app_key, field)
                    if val:
                        info[field] = val
                if info.get("DisplayName"):
                    apps.append(info)
        except Exception:
            pass
    result["InstalledApplications"] = apps

    return result


def _extract_from_system_hive(hive_path: Path) -> dict:
    """Extract hostname, timezone, network interfaces, and adapters from SYSTEM hive."""
    result: dict = {}
    reg = _open_registry(hive_path)
    if reg is None:
        result["_error"] = "python-registry not available"
        return result

    # Determine active control set (Select\Current value)
    control_set = "ControlSet001"
    try:
        cs_val = reg.open("Select").value("Current").value()
        control_set = f"ControlSet{cs_val:03d}"
    except Exception:
        pass
    result["ControlSet"] = control_set

    # Computer name
    try:
        cn_key = reg.open(f"{control_set}\\Control\\ComputerName\\ComputerName")
        result["ComputerName"] = _reg_value(cn_key, "ComputerName") or ""
    except Exception:
        pass

    # Timezone
    try:
        tz_key = reg.open(f"{control_set}\\Control\\TimeZoneInformation")
        for field in ["TimeZoneKeyName", "StandardName", "Bias", "ActiveTimeBias"]:
            val = _reg_value(tz_key, field)
            if val is not None:
                result[f"TimeZone_{field}"] = val
    except Exception:
        pass

    # Network interfaces (TCP/IP static + DHCP config)
    interfaces: list[dict] = []
    try:
        ifaces_root = reg.open(
            f"{control_set}\\Services\\Tcpip\\Parameters\\Interfaces"
        )
        for iface_key in ifaces_root.subkeys():
            iface: dict = {"GUID": iface_key.name()}
            for field in [
                "IPAddress", "SubnetMask", "DefaultGateway",
                "DhcpIPAddress", "DhcpSubnetMask", "DhcpDefaultGateway",
                "NameServer", "DhcpNameServer", "EnableDHCP",
            ]:
                val = _reg_value(iface_key, field)
                if val is None:
                    continue
                # Skip empty/loopback values
                if isinstance(val, list):
                    val = [v for v in val if v and v != "0.0.0.0"]
                    if not val:
                        continue
                elif val in ("", "0.0.0.0"):
                    continue
                iface[field] = val
            # Only include interfaces with IP information
            if any(k in iface for k in ("IPAddress", "DhcpIPAddress")):
                interfaces.append(iface)
    except Exception:
        pass
    result["NetworkInterfaces"] = interfaces

    # Network adapters with MAC addresses
    adapters: list[dict] = []
    try:
        nic_class = reg.open(
            f"{control_set}\\Control\\Class\\{{4D36E972-E325-11CE-BFC1-08002BE10318}}"
        )
        for nic_key in nic_class.subkeys():
            if not nic_key.name().isdigit():
                continue
            adapter: dict = {}
            for field in ["DriverDesc", "NetworkAddress", "NetCfgInstanceId",
                          "DeviceInstanceID"]:
                val = _reg_value(nic_key, field)
                if val:
                    adapter[field] = val
            if adapter.get("DriverDesc") or adapter.get("NetworkAddress"):
                adapters.append(adapter)
    except Exception:
        pass
    result["NetworkAdapters"] = adapters

    return result


def _decode_sam_v_value(v_bytes: bytes) -> dict:
    """
    Decode the SAM V value to extract Username, FullName, and Comment.
    V value layout (offsets relative to a 0xCC-byte fixed header):
      0x00–0x03: reserved
      0x04: username offset (uint32 LE) from end of header, len at 0x08
      0x0C: full name offset (uint32 LE) from end of header, len at 0x10
      0x18: comment offset, len at 0x1C
    All strings are UTF-16 LE.
    """
    result: dict = {}
    try:
        if len(v_bytes) < 0x40:
            return result
        header_end = 0xCC  # standard V header size
        for field_name, off_pos in [("FullName", 0x28), ("Comment", 0x3C)]:
            try:
                offset = struct.unpack_from("<I", v_bytes, off_pos)[0]
                length = struct.unpack_from("<I", v_bytes, off_pos + 4)[0]
                if length == 0:
                    continue
                start = header_end + offset
                end = start + length
                if end > len(v_bytes):
                    continue
                text = v_bytes[start:end].decode("utf-16-le", errors="replace").rstrip("\x00")
                if text:
                    result[field_name] = text
            except Exception:
                pass
    except Exception:
        pass
    return result


def _extract_from_sam_hive(hive_path: Path) -> dict:
    """Extract user account list from SAM hive."""
    result: dict = {}
    reg = _open_registry(hive_path)
    if reg is None:
        result["_error"] = "python-registry not available"
        return result

    users: list[dict] = []
    try:
        names_key = reg.open("SAM\\Domains\\Account\\Users\\Names")
        for user_key in names_key.subkeys():
            username = user_key.name()
            user_info: dict = {"Username": username}

            # The default value's type encodes the RID
            try:
                rid_type = user_key.value("").type()
                rid_str = f"{rid_type:08X}"
                rid_key = reg.open(f"SAM\\Domains\\Account\\Users\\{rid_str}")

                # F value: last logon time and logon count
                try:
                    f_val = rid_key.value("F").value()
                    if len(f_val) >= 26:
                        last_logon_ft = struct.unpack_from("<Q", f_val, 8)[0]
                        logon_count = struct.unpack_from("<H", f_val, 24)[0]
                        pwd_last_set_ft = struct.unpack_from("<Q", f_val, 16)[0]
                        user_info["LastLogon"] = _filetime_to_utc(last_logon_ft)
                        user_info["LogonCount"] = logon_count
                        user_info["PasswordLastSet"] = _filetime_to_utc(pwd_last_set_ft)
                except Exception:
                    pass

                # V value: full name and comment
                try:
                    v_val = rid_key.value("V").value()
                    v_decoded = _decode_sam_v_value(bytes(v_val))
                    user_info.update(v_decoded)
                except Exception:
                    pass

            except Exception:
                pass

            users.append(user_info)

    except Exception as e:
        result["_error"] = str(e)

    result["UserAccounts"] = users
    return result


def _extract_from_ntuser(hive_path: Path, username: str) -> dict:
    """Extract recent activity from an NTUSER.DAT hive."""
    result: dict = {"username": username}
    reg = _open_registry(hive_path)
    if reg is None:
        result["_error"] = "python-registry not available"
        return result

    # Typed paths (Explorer address bar)
    try:
        tp_key = reg.open(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths"
        )
        result["TypedPaths"] = {
            v.name(): v.value() for v in tp_key.values()
            if isinstance(v.value(), str)
        }
    except Exception:
        pass

    # Run MRU (Win+R history)
    try:
        run_key = reg.open(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU"
        )
        result["RunMRU"] = {
            v.name(): v.value()
            for v in run_key.values()
            if v.name() != "MRUList" and isinstance(v.value(), str)
        }
    except Exception:
        pass

    # Recent document extensions (subkey names indicate file types recently opened)
    try:
        rd_key = reg.open(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
        )
        result["RecentDocExtensions"] = [sk.name() for sk in rd_key.subkeys()]
    except Exception:
        pass

    # UserAssist (ROT-13 encoded program execution history)
    try:
        import codecs
        ua_executions: list[str] = []
        ua_base = reg.open(
            "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
        )
        for guid_key in ua_base.subkeys():
            try:
                count_key = guid_key.open("Count")
                for val in count_key.values():
                    decoded = codecs.decode(val.name(), "rot_13")
                    # Skip shell virtual folder GUIDs and noise
                    if decoded and not decoded.startswith("{") and len(decoded) > 4:
                        ua_executions.append(decoded)
            except Exception:
                pass
        if ua_executions:
            result["UserAssistExecutions"] = ua_executions[:100]
    except Exception:
        pass

    # Typed URLs (Internet Explorer / legacy URL bar)
    try:
        tu_key = reg.open(
            "Software\\Microsoft\\Internet Explorer\\TypedURLs"
        )
        result["TypedURLs"] = {
            v.name(): v.value()
            for v in tu_key.values()
            if isinstance(v.value(), str)
        }
    except Exception:
        pass

    return result


# ── Recycle Bin parser ────────────────────────────────────────────────────────

def parse_recyclebin(exports_dir: Path) -> list[dict]:
    """
    Parse Windows Recycle Bin $I metadata files.

    $I file format (Vista+):
      Bytes 0–7:   Version uint64 LE (1 = Vista/7, 2 = Win8+)
      Bytes 8–15:  Original file size uint64 LE
      Bytes 16–23: Deletion timestamp (FILETIME) uint64 LE
      Vista/7 (version 1):
        Bytes 24–543: Original path UTF-16 LE (260 chars, null-padded)
      Win8+ (version 2):
        Bytes 24–27: Character count uint32 LE
        Bytes 28+:   Original path UTF-16 LE
    """
    rb_dir = exports_dir / "recyclebin"
    if not rb_dir.exists():
        return []

    entries: list[dict] = []

    # Recursively find all $I* files (may be in SID subdirectories)
    for i_file in sorted(rb_dir.rglob("$I*")):
        if i_file.is_dir():
            continue
        try:
            data = i_file.read_bytes()
            if len(data) < 24:
                continue

            version = struct.unpack_from("<Q", data, 0)[0]
            file_size = struct.unpack_from("<Q", data, 8)[0]
            deletion_ft = struct.unpack_from("<Q", data, 16)[0]

            # Decode original path
            if version == 2 and len(data) >= 28:
                char_count = struct.unpack_from("<I", data, 24)[0]
                path_bytes = data[28: 28 + char_count * 2]
                original_path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")
            else:
                # Version 1: fixed 260-character (520-byte) UTF-16 LE path
                path_bytes = data[24: 24 + 520]
                original_path = path_bytes.decode("utf-16-le", errors="replace").rstrip("\x00")

            deleted_at = _filetime_to_utc(deletion_ft)

            # Find corresponding $R content file (same suffix as $I)
            suffix = i_file.name[2:]  # strip "$I"
            r_file = i_file.parent / f"$R{suffix}"
            r_present = r_file.exists()
            r_size = r_file.stat().st_size if r_present else 0

            # Extract file extension from original path
            ext = ""
            if original_path and "." in original_path.split("\\")[-1]:
                ext = "." + original_path.rsplit(".", 1)[-1].upper()

            # Extract SID from directory hierarchy (format: S-1-5-...)
            sid = ""
            for part in i_file.parts:
                if part.startswith("S-1-"):
                    sid = part
                    break

            entries.append({
                "i_file": str(i_file.relative_to(rb_dir)),
                "r_file": str(r_file.relative_to(rb_dir)) if r_file.exists() else f"$R{suffix}",
                "original_path": original_path,
                "extension": ext,
                "size_bytes": file_size,
                "size_human": _humanize_bytes(file_size),
                "deleted_at_utc": deleted_at,
                "r_file_present": r_present,
                "r_file_size": r_size,
                "sid": sid,
                "version": version,
            })

        except Exception as exc:
            entries.append({"i_file": i_file.name, "error": str(exc)})

    return entries


# ── PowerShell history finder ─────────────────────────────────────────────────

def find_powershell_history(
    exports_dir: Path,
    fs_mount: Path | None = None,
) -> list[dict]:
    """
    Locate PowerShell ConsoleHost_history.txt for every user.
    Searches the live mounted filesystem first, then falls back to scanning
    the NTUSER.DAT parent directories in exports/registry/ for username discovery.
    """
    results: list[dict] = []
    search_roots: list[Path] = []

    if fs_mount and fs_mount.exists():
        search_roots.append(fs_mount)

    skip_names = {"all users", "default", "default user", "public"}

    for root in search_roots:
        users_dir = root / "Users"
        if not users_dir.exists():
            continue
        for user_dir in users_dir.iterdir():
            if not user_dir.is_dir():
                continue
            if user_dir.name.lower() in skip_names:
                continue
            history_file = (
                user_dir
                / "AppData"
                / "Roaming"
                / "Microsoft"
                / "Windows"
                / "PowerShell"
                / "PSReadLine"
                / "ConsoleHost_history.txt"
            )
            if not history_file.exists():
                continue
            try:
                commands = history_file.read_text(errors="replace").splitlines()
                results.append({
                    "username": user_dir.name,
                    "path": str(history_file),
                    "commands": commands,
                    "command_count": len(commands),
                })
            except Exception as exc:
                results.append({"username": user_dir.name, "error": str(exc)})

    return results


# ── IOC recorder ──────────────────────────────────────────────────────────────

def record_ioc_finding(
    exports_dir: Path,
    category: str,
    value: str,
    source_step: str,
    confidence: str = "CONFIRMED",
) -> None:
    """Append an IOC to machine_details/iocs.json, deduplicating by (category, raw_value)."""
    if not value or not value.strip():
        return

    machine_dir = exports_dir / "machine_details"
    machine_dir.mkdir(parents=True, exist_ok=True)
    iocs_file = machine_dir / "iocs.json"

    existing: list[dict] = []
    if iocs_file.exists():
        try:
            existing = json.loads(iocs_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    # Deduplicate
    for entry in existing:
        if entry.get("category") == category and entry.get("raw_value") == value:
            return

    existing.append({
        "category": category,
        "value": _defang(value, category),
        "raw_value": value,
        "source_step": source_step,
        "confidence": confidence,
        "recorded_at": datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    })

    _safe_write(iocs_file, json.dumps(existing, indent=2, default=str))


# ── Auto-IOC extraction ───────────────────────────────────────────────────────

def _auto_record_iocs(exports_dir: Path, machine_data: dict) -> None:
    """Automatically record IOCs discovered in machine details extraction."""
    system = machine_data.get("system", {})
    software = machine_data.get("software", {})
    sam = machine_data.get("sam", {})

    # IP addresses from network interfaces
    for iface in system.get("NetworkInterfaces", []):
        for field in ("IPAddress", "DhcpIPAddress"):
            val = iface.get(field)
            ips = val if isinstance(val, list) else ([val] if val else [])
            for ip in ips:
                if ip and ip != "0.0.0.0":
                    record_ioc_finding(
                        exports_dir, "ip", ip, "machine_details-network-config"
                    )

    # MAC addresses
    for adapter in system.get("NetworkAdapters", []):
        mac = adapter.get("NetworkAddress")
        if mac:
            record_ioc_finding(
                exports_dir, "mac", mac, "machine_details-network-config"
            )

    # Usernames from SAM
    for user in sam.get("UserAccounts", []):
        username = user.get("Username", "")
        # Skip built-in low-value accounts
        if username and username.lower() not in (
            "guest", "defaultaccount", "wdagsutilityaccount",
        ):
            record_ioc_finding(
                exports_dir, "username", username, "machine_details-sam"
            )
        full_name = user.get("FullName")
        if full_name:
            record_ioc_finding(
                exports_dir, "fullname", full_name, "machine_details-sam"
            )

    # Last logged-on user
    last_user = software.get("LastLoggedOnUser")
    if last_user:
        record_ioc_finding(
            exports_dir, "username", last_user, "machine_details-winlogon"
        )

    # Installed applications — flag dual-use / remote access tools
    _SUSPICIOUS_APPS = {
        "nmap", "wireshark", "netcat", "nc", "putty", "anydesk", "teamviewer",
        "vnc", "radmin", "cobalt", "metasploit", "mimikatz", "psexec",
        "torrent", "tor ", " tor", "proxychains", "ngrok", "frp", "chisel",
    }
    for app in software.get("InstalledApplications", []):
        name = (app.get("DisplayName") or "").lower()
        if any(sus in name for sus in _SUSPICIOUS_APPS):
            record_ioc_finding(
                exports_dir, "suspicious_app",
                app.get("DisplayName", name),
                "machine_details-installed-apps",
                confidence="INFERRED",
            )


# ── Main orchestrator ─────────────────────────────────────────────────────────

def run_all(exports_dir: Path, fs_mount: Path | None = None) -> None:
    """
    Run all extraction functions and write JSON/text output files.
    Called by fast_analyze.sh after registry and recycle bin extraction.
    """
    machine_dir = exports_dir / "machine_details"
    machine_dir.mkdir(parents=True, exist_ok=True)

    machine_data: dict = {
        "software": {},
        "system": {},
        "sam": {},
        "ntuser_dat": [],
        "ps_history": [],
    }

    reg_dir = exports_dir / "registry"

    # SOFTWARE hive
    sw_hive = reg_dir / "SOFTWARE"
    if sw_hive.exists():
        print("[fast_machine_details] Parsing SOFTWARE hive...")
        machine_data["software"] = _extract_from_software_hive(sw_hive)
    else:
        print("[fast_machine_details] SOFTWARE hive not found — skipping.")

    # SYSTEM hive
    sys_hive = reg_dir / "SYSTEM"
    if sys_hive.exists():
        print("[fast_machine_details] Parsing SYSTEM hive...")
        machine_data["system"] = _extract_from_system_hive(sys_hive)
    else:
        print("[fast_machine_details] SYSTEM hive not found — skipping.")

    # SAM hive
    sam_hive = reg_dir / "SAM"
    if sam_hive.exists():
        print("[fast_machine_details] Parsing SAM hive...")
        machine_data["sam"] = _extract_from_sam_hive(sam_hive)
    else:
        print("[fast_machine_details] SAM hive not found — skipping.")

    # NTUSER.DAT files (may be nested via --parents copy)
    for ntuser_path in sorted(reg_dir.rglob("NTUSER.DAT")):
        # Derive username from "Users/<username>/NTUSER.DAT" in the path
        username = "unknown"
        parts = ntuser_path.parts
        for i, part in enumerate(parts):
            if part.lower() == "users" and i + 1 < len(parts):
                username = parts[i + 1]
                break
        print(f"[fast_machine_details] Parsing NTUSER.DAT for user: {username}")
        machine_data["ntuser_dat"].append(_extract_from_ntuser(ntuser_path, username))

    # PowerShell history (from live mount if available)
    print("[fast_machine_details] Searching for PowerShell history...")
    machine_data["ps_history"] = find_powershell_history(exports_dir, fs_mount)

    # Write machine_details.json
    md_json = machine_dir / "machine_details.json"
    _safe_write(md_json, json.dumps(machine_data, indent=2, default=str))
    print(f"[fast_machine_details] Machine details → {md_json}")

    # Write ps_history.txt (human-readable)
    if machine_data["ps_history"]:
        lines: list[str] = []
        for entry in machine_data["ps_history"]:
            lines.append(f"=== {entry.get('username', 'unknown')} ===")
            lines.extend(entry.get("commands", []))
            lines.append("")
        _safe_write(machine_dir / "ps_history.txt", "\n".join(lines))
        print(f"[fast_machine_details] PowerShell history → {machine_dir / 'ps_history.txt'}")

    # Auto-record IOCs
    _auto_record_iocs(exports_dir, machine_data)

    # Recycle Bin parsing
    print("[fast_machine_details] Parsing Recycle Bin $I files...")
    rb_entries = parse_recyclebin(exports_dir)
    if rb_entries:
        rb_json = exports_dir / "recyclebin" / "recyclebin_parsed.json"
        _safe_write(rb_json, json.dumps(rb_entries, indent=2, default=str))
        valid = sum(1 for e in rb_entries if "error" not in e)
        print(
            f"[fast_machine_details] Recycle Bin parsed → {rb_json} "
            f"({valid} valid entries)"
        )
        # Record deleted file paths as IOCs
        for entry in rb_entries:
            if entry.get("original_path") and not entry.get("error"):
                record_ioc_finding(
                    exports_dir,
                    "deleted_filepath",
                    entry["original_path"],
                    "machine_details-recyclebin",
                    confidence="CONFIRMED",
                )
    else:
        print("[fast_machine_details] No Recycle Bin $I files found.")


# ── Self-test ─────────────────────────────────────────────────────────────────

def _run_test() -> None:
    """Minimal self-test: verify utility functions and IOC recording logic."""
    import tempfile

    print("[test] Testing _humanize_bytes...")
    assert _humanize_bytes(0) == "0 B"
    assert _humanize_bytes(1024) == "1 KB"
    assert _humanize_bytes(1024 ** 2) == "1 MB"
    print("[test] OK")

    print("[test] Testing _filetime_to_utc...")
    # Compute expected FILETIME for 2020-01-01 00:00:00 UTC dynamically
    _target = datetime(2020, 1, 1, tzinfo=timezone.utc)
    _ft = int((_target - _FILETIME_EPOCH).total_seconds() * 10_000_000)
    result = _filetime_to_utc(_ft)
    assert "2020-01-01" in result, f"Unexpected: {result}"
    assert _filetime_to_utc(0) == ""
    print("[test] OK")

    print("[test] Testing _defang...")
    assert _defang("192.168.1.1", "ip") == "192[.]168[.]1[.]1"
    assert _defang("evil.com", "domain") == "evil[.]com"
    assert _defang("https://evil.com/x", "url") == "hxxps://evil[.]com/x"
    assert _defang("jdoe", "username") == "jdoe"
    print("[test] OK")

    print("[test] Testing record_ioc_finding...")
    with tempfile.TemporaryDirectory() as tmpdir:
        ed = Path(tmpdir)
        (ed / "machine_details").mkdir()
        record_ioc_finding(ed, "ip", "10.0.0.1", "test-step", "CONFIRMED")
        record_ioc_finding(ed, "ip", "10.0.0.1", "test-step", "CONFIRMED")  # dup
        record_ioc_finding(ed, "username", "jdoe", "test-step2")
        data = json.loads((ed / "machine_details" / "iocs.json").read_text())
        assert len(data) == 2, f"Expected 2 entries, got {len(data)}"
        assert data[0]["value"] == "10[.]0[.]0[.]1"
        assert data[1]["raw_value"] == "jdoe"
    print("[test] OK")

    print("[test] Testing parse_recyclebin (no files)...")
    with tempfile.TemporaryDirectory() as tmpdir:
        ed = Path(tmpdir)
        (ed / "recyclebin").mkdir()
        result = parse_recyclebin(ed)
        assert result == []
    print("[test] OK")

    print("[test] All tests passed.")


# ── CLI entrypoint ────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="FAST machine details extractor and IOC recorder"
    )
    parser.add_argument(
        "--exports", type=Path, default=Path("./exports"),
        help="Path to the exports directory (default: ./exports)",
    )
    parser.add_argument(
        "--fs-mount", type=Path, default=None,
        help="Path to the mounted filesystem (for PowerShell history)",
    )
    parser.add_argument(
        "--record-ioc", nargs=4,
        metavar=("CATEGORY", "VALUE", "SOURCE_STEP", "CONFIDENCE"),
        help="Record a single IOC to iocs.json and exit",
    )
    parser.add_argument("--test", action="store_true", help="Run self-tests")
    args = parser.parse_args()

    if args.test:
        _run_test()
        return

    if args.record_ioc:
        category, value, source_step, confidence = args.record_ioc
        record_ioc_finding(args.exports, category, value, source_step, confidence)
        print(f"[fast_machine_details] IOC recorded: [{category}] {value} ({source_step})")
        return

    run_all(args.exports, args.fs_mount)


if __name__ == "__main__":
    main()
