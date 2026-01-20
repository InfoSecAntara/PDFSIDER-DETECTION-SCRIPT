# YARA Rules for PDFSIDER Detection
# Save as pdfsider_rules.yar

rule PDFSIDER_Malware {
    meta:
        description = "Detects PDFSIDER APT malware"
        author = "Antara Mane"
        date = "2024-01-20"
        threat_name = "PDFSIDER APT Backdoor"
        reference = "Internal Analysis"
        severity = "HIGH"
    
    strings:
        // File names
        $s1 = "cryptbase.dll" nocase
        $s2 = "pdf24.exe" nocase
        
        // Strings found in malicious DLL
        $s3 = "cmd.exe /C"
        $s4 = "CREATE_NO_WINDOW"
        $s5 = "Botan::Cipher_Mode"
        $s6 = "AES-256-GCM"
        $s7 = "GlobalMemoryStatusEx"
        $s8 = "IsDebuggerPresent"
        
        // Network indicators
        $s9 = "45.76.9.248"
        $s10 = "PORT_53"
        
        // Hash strings
        $h1 = "298cbfc6a5f6fa041581233278af9394"  // cryptbase.dll MD5
        $h2 = "a32dc85eee2e1a579199050cd1941e1d"  // pdf24.exe MD5
        
        // API calls
        $a1 = "CreateProcessA"
        $a2 = "CreateProcessW"
        $a3 = "LoadLibraryA"
        $a4 = "LoadLibraryW"
        $a5 = "GetProcAddress"
        $a6 = "WSAStartup"
        
    condition:
        (uint16(0) == 0x5A4D) and  // PE file
        (
            (3 of ($s*)) or
            (2 of ($h*)) or
            (4 of ($a*)) or
            ($s1 and $s3) or
            ($s1 and $s4) or
            ($s2 and $s9)
        )
}

rule PDFSIDER_DLL_Sideloading {
    meta:
        description = "Detects DLL sideloading behavior similar to PDFSIDER"
        author = "Your Name/Organization"
        severity = "HIGH"
    
    strings:
        $dll_export1 = "DllMain" wide
        $dll_export2 = "DllEntryPoint" wide
        $cmd_string = "cmd.exe" wide
        $process_func = "CreateProcess" wide
        $crypt_func = "CryptEncrypt" wide
        $socket_func = "socket" wide
        
    condition:
        uint16(0) == 0x5A4D and  // PE file
        filesize < 2MB and
        (2 of ($dll_export*)) and
        (2 of ($cmd_string, $process_func, $crypt_func, $socket_func))
}

rule PDFSIDER_AntiDebug {
    meta:
        description = "Detects anti-debugging techniques used by PDFSIDER"
        author = "Your Name/Organization"
        severity = "MEDIUM"
    
    strings:
        $debug_check1 = "IsDebuggerPresent"
        $debug_check2 = "CheckRemoteDebuggerPresent"
        $debug_check3 = "NtQueryInformationProcess"
        $debug_check4 = "OutputDebugStringA"
        $vm_check1 = "VBoxService.exe"
        $vm_check2 = "VMwareService.exe"
        $vm_check3 = "vmtoolsd.exe"
        
    condition:
        uint16(0) == 0x5A4D and
        2 of ($debug_check*) and
        1 of ($vm_check*)
}