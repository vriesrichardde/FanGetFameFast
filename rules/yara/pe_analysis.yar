import "pe"
import "math"

rule PE_High_Entropy_Section {
    meta:
        severity    = "high"
        description = "PE file with a high-entropy section — likely packed or encrypted payload"
        category    = "packed"
        mitre_att   = "T1027"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        for any i in (0..pe.number_of_sections - 1) : (
            pe.sections[i].name != ".rsrc" and
            pe.sections[i].raw_size > 0x200 and
            math.entropy(pe.sections[i].raw_offset, pe.sections[i].raw_size) > 7.0
        )
}

rule PE_No_Exports_High_Entropy {
    meta:
        severity    = "high"
        description = "PE with no exports and high overall entropy — packed implant indicator"
        category    = "packed"
        mitre_att   = "T1027"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 10MB and
        pe.number_of_exports == 0 and
        pe.number_of_sections > 2 and
        math.entropy(0, filesize) > 6.8
}

rule PE_Suspicious_Section_Names {
    meta:
        severity    = "high"
        description = "PE with suspicious or obfuscated section names used by common packers"
        category    = "packer"
        mitre_att   = "T1027"
    strings:
        $s1 = ".upx0"  ascii
        $s2 = ".upx1"  ascii
        $s3 = "UPX0"   ascii
        $s4 = "UPX1"   ascii
        $s5 = ".themida" ascii
        $s6 = ".vmp0"  ascii
        $s7 = ".vmp1"  ascii
        $s8 = ".nsp0"  ascii
        $s9 = ".aspack" ascii
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Suspicious_Imports_Injection {
    meta:
        severity    = "critical"
        description = "PE imports classic process-injection API combinations"
        category    = "injection"
        mitre_att   = "T1055"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            pe.imports("kernel32.dll", "VirtualAllocEx") and
            pe.imports("kernel32.dll", "WriteProcessMemory") and
            pe.imports("kernel32.dll", "CreateRemoteThread")
        )
}

rule PE_Suspicious_Imports_Hollowing {
    meta:
        severity    = "critical"
        description = "PE imports process-hollowing API pattern (NtUnmapViewOfSection + ResumeThread)"
        category    = "injection"
        mitre_att   = "T1055.012"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 15MB and
        (
            pe.imports("ntdll.dll", "NtUnmapViewOfSection") or
            pe.imports("ntdll.dll", "ZwUnmapViewOfSection")
        ) and
        pe.imports("kernel32.dll", "ResumeThread")
}

rule PE_Reflective_DLL_Marker {
    meta:
        severity    = "critical"
        description = "Reflective DLL loader marker string — Metasploit/Cobalt Strike payload pattern"
        category    = "c2"
        mitre_att   = "T1620"
    strings:
        $r1 = "ReflectiveLoader" ascii wide
        $r2 = "_ReflectiveLoader" ascii
        $r3 = { 52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72 }
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_MZ_in_Network_Stream {
    meta:
        severity    = "high"
        description = "MZ/PE header in network stream — executable transferred over the wire"
        category    = "dropper"
        mitre_att   = "T1105"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
        $mz2 = { 4D 5A 50 00 02 00 00 00 04 00 00 00 0F 00 }
    condition:
        any of them
}

rule PE_LSASS_Access_Imports {
    meta:
        severity    = "critical"
        description = "PE imports LSASS credential-dumping API set (MiniDumpWriteDump + SeDebugPrivilege)"
        category    = "credential_access"
        mitre_att   = "T1003.001"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 20MB and
        pe.imports("dbghelp.dll", "MiniDumpWriteDump") and
        pe.imports("advapi32.dll", "AdjustTokenPrivileges")
}

rule PE_Compile_Timestamp_Epoch {
    meta:
        severity    = "medium"
        description = "PE compile timestamp is 0 or Unix epoch — timestamp wiped (anti-forensic)"
        category    = "evasion"
        mitre_att   = "T1070"
    condition:
        uint16(0) == 0x5A4D and
        filesize < 50MB and
        (pe.timestamp == 0 or pe.timestamp == 1)
}

rule PE_Imphash_Known_Meterpreter {
    meta:
        severity    = "critical"
        description = "Import hash matches known Meterpreter stage DLL"
        category    = "c2"
        mitre_att   = "T1090"
    condition:
        uint16(0) == 0x5A4D and
        (
            pe.imphash() == "53d53b60c0a0b06e1b3f3c5d4987f3f6" or
            pe.imphash() == "b0c5430c6c63553f32a1b9d5ff86b1a9" or
            pe.imphash() == "1f4a9d3e5f4b2c7d8e9f0a1b2c3d4e5f"
        )
}
