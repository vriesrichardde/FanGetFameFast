import "math"
import "hash"

rule High_Entropy_File_Overall {
    meta:
        severity    = "medium"
        description = "File with very high overall entropy — likely encrypted or compressed payload"
        category    = "evasion"
        mitre_att   = "T1027"
    condition:
        filesize > 1KB and
        filesize < 50MB and
        math.entropy(0, filesize) > 7.5
}

rule High_Entropy_Small_File {
    meta:
        severity    = "high"
        description = "Small file (<100KB) with near-maximum entropy — likely shellcode or key material"
        category    = "evasion"
        mitre_att   = "T1027"
    condition:
        filesize > 512 and
        filesize < 100KB and
        math.entropy(0, filesize) > 7.8
}

rule High_Entropy_With_MZ_Header {
    meta:
        severity    = "high"
        description = "PE/MZ header but body has high entropy — runtime-packed executable"
        category    = "packed"
        mitre_att   = "T1027"
    condition:
        uint16(0) == 0x5A4D and
        filesize > 4KB and
        filesize < 20MB and
        math.entropy(0x3c, filesize - 0x3c) > 7.2
}

rule Known_Bad_MD5 {
    meta:
        severity    = "critical"
        description = "File matches a known-malicious MD5 hash (IOC feed placeholder)"
        category    = "malware"
        mitre_att   = "T1588"
    condition:
        hash.md5(0, filesize) == "d41d8cd98f00b204e9800998ecf8427e"
}

rule Known_Bad_SHA256 {
    meta:
        severity    = "critical"
        description = "File matches a known-malicious SHA256 hash (IOC feed placeholder)"
        category    = "malware"
        mitre_att   = "T1588"
    condition:
        hash.sha256(0, filesize) == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}

rule Encrypted_Content_Heuristic {
    meta:
        severity    = "medium"
        description = "Binary blob with no printable strings and high entropy — encrypted data transfer"
        category    = "exfiltration"
        mitre_att   = "T1048"
    strings:
        $printable = /[ -~]{8,}/
    condition:
        filesize > 2KB and
        filesize < 50MB and
        math.entropy(0, filesize) > 7.0 and
        not $printable
}

rule Base64_High_Density {
    meta:
        severity    = "medium"
        description = "File composed predominantly of base64 characters — obfuscated payload"
        category    = "obfuscation"
        mitre_att   = "T1027"
    strings:
        $b64_block = /[A-Za-z0-9+\/]{200,}={0,2}/
    condition:
        #b64_block > 3
}

rule Shellcode_NOP_Sled {
    meta:
        severity    = "high"
        description = "NOP sled pattern preceding executable code — shellcode delivery indicator"
        category    = "exploit"
        mitre_att   = "T1203"
    strings:
        $nop32  = { 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90
                    90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }
        $nop64  = { 66 90 66 90 66 90 66 90 66 90 66 90 66 90 66 90 }
        $fnop   = { D9 D0 D9 D0 D9 D0 D9 D0 D9 D0 D9 D0 D9 D0 D9 D0 }
    condition:
        any of them
}

rule Polyglot_File_PDF_PE {
    meta:
        severity    = "critical"
        description = "File contains both PDF and MZ/PE headers — polyglot file evasion technique"
        category    = "evasion"
        mitre_att   = "T1027.009"
    strings:
        $pdf = "%PDF-"
        $mz  = { 4D 5A }
    condition:
        $pdf and $mz
}
