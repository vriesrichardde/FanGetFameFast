/*
 * network_threats.yar — YARA rules for network threat detection in PCAP files
 *
 * Rules scan the raw PCAP binary (packet payloads included) and any
 * application-layer files extracted via tshark --export-objects.
 *
 * Severity levels (in rule metadata): critical / high / medium / low
 */

rule HTTP_PowerShell_Download_Cradle
{
    meta:
        severity    = "high"
        description = "PowerShell download cradle observed in HTTP traffic"
        category    = "execution"
        mitre_att   = "T1059.001"
    strings:
        $ps  = "powershell" nocase wide ascii
        $dl1 = "DownloadString" nocase wide ascii
        $dl2 = "DownloadFile" nocase wide ascii
        $dl3 = "WebClient" nocase wide ascii
        $iex = "IEX" wide ascii
        $inv = "Invoke-Expression" nocase wide ascii
    condition:
        ($ps and ($dl1 or $dl2 or $dl3)) or
        ($iex and $dl1) or
        ($inv and ($dl1 or $dl2))
}

rule HTTP_CobaltStrike_Default_Profile
{
    meta:
        severity    = "critical"
        description = "Cobalt Strike default malleable C2 profile indicator"
        category    = "c2"
        mitre_att   = "T1071.001"
    strings:
        $ua1  = "Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36" nocase
        $ua2  = "Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko" nocase
        $uri1 = "/jquery-3.3.1.slim.min.js" nocase
        $uri2 = "/jquery-3.3.2.slim.min.js" nocase
        $uri3 = "/pixel.gif" nocase
        $cs1  = "__cfduid=" nocase
        $cs2  = "cf-ray:" nocase
    condition:
        any of ($ua*) or (2 of ($uri*, $cs*))
}

rule HTTP_Executable_Download_MZ
{
    meta:
        severity    = "high"
        description = "Windows PE executable transferred over HTTP"
        category    = "ingress_transfer"
        mitre_att   = "T1105"
    strings:
        $mz      = { 4D 5A }
        $http_ok = "HTTP/1." nocase
    condition:
        $http_ok and $mz
}

rule SMB_PsExec_Lateral_Movement
{
    meta:
        severity    = "high"
        description = "PsExec or similar tool using SMB admin shares"
        category    = "lateral_movement"
        mitre_att   = "T1021.002"
    strings:
        $psexec1    = "PSEXESVC" nocase wide ascii
        $psexec2    = "psexecsvc" nocase wide ascii
        $admin_share = "\\ADMIN$" wide ascii
        $ipc_share   = "\\IPC$" wide ascii
    condition:
        any of ($psexec*) or (all of ($admin_share, $ipc_share))
}

rule HTTP_Base64_Long_Parameter
{
    meta:
        severity    = "medium"
        description = "Long base64-encoded parameter in HTTP request — potential encoded command or exfiltration"
        category    = "exfiltration"
        mitre_att   = "T1041"
    strings:
        $b64_param = /[?&][A-Za-z0-9_]+=([A-Za-z0-9+\/]{100,}={0,2})/
    condition:
        $b64_param
}

rule ICMP_Tunnel_Tool_Signature
{
    meta:
        severity    = "medium"
        description = "ICMP tunneling tool signature (ptunnel, icmptunnel)"
        category    = "tunneling"
        mitre_att   = "T1095"
    strings:
        $ptun1 = "ptunnel" nocase ascii
        $ptun2 = "icmptunnel" nocase ascii
        $ptun3 = "TUNL" ascii
    condition:
        any of them
}

rule DNS_Long_Label_Exfiltration
{
    meta:
        severity    = "high"
        description = "DNS query with unusually long label — potential DNS exfiltration tunnel"
        category    = "exfiltration"
        mitre_att   = "T1048.003"
    strings:
        // Label ≥ 40 chars before a dot or end — typical of DNS tunnelling
        $long_label = /[A-Za-z0-9+\/\-_]{40,}\.[A-Za-z]{2,}/
    condition:
        $long_label
}

rule HTTP_Suspicious_User_Agent_Tools
{
    meta:
        severity    = "high"
        description = "Known offensive tool User-Agent strings in HTTP traffic"
        category    = "attack_tool"
        mitre_att   = "T1059"
    strings:
        $ua_sqlmap   = "sqlmap" nocase
        $ua_nikto    = "Nikto" nocase
        $ua_nessus   = "Nessus" nocase
        $ua_masscan  = "masscan" nocase
        $ua_gobuster = "gobuster" nocase
        $ua_dirbust  = "DirBuster" nocase
        $ua_havoc    = "HavocC2" nocase
        $ua_sliver   = "sliver" nocase
        $ua_brute    = "BruteSpray" nocase
        $ua_python   = "python-requests" nocase
        $ua_curl_sus = "curl/7.1" nocase
    condition:
        any of ($ua_sqlmap, $ua_nikto, $ua_nessus, $ua_masscan, $ua_gobuster, $ua_dirbust, $ua_havoc, $ua_sliver, $ua_brute)
}

rule HTTP_Path_Traversal_Attempt
{
    meta:
        severity    = "high"
        description = "Path traversal or directory traversal attempt in HTTP URI"
        category    = "exploitation"
        mitre_att   = "T1190"
    strings:
        $tr1 = "../../../" nocase
        $tr2 = "..%2F..%2F" nocase
        $tr3 = "..%5C..%5C" nocase
        $tr4 = "%2e%2e%2f" nocase
        $tr5 = "/etc/passwd" nocase
        $tr6 = "/etc/shadow" nocase
        $tr7 = "boot.ini" nocase
        $tr8 = "win.ini" nocase
    condition:
        any of them
}

rule TLS_Self_Signed_Certificate_Pattern
{
    meta:
        severity    = "medium"
        description = "TLS handshake with self-signed or mismatched certificate indicators"
        category    = "suspicious_tls"
        mitre_att   = "T1573"
    strings:
        // Subject == Issuer in DER-encoded cert (simplified heuristic)
        $self1 = "CN=localhost" nocase
        $self2 = "CN=example.com" nocase
        $self3 = "O=Internet Widgits Pty Ltd" nocase
    condition:
        any of them
}
