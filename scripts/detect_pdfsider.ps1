<#
PDFSIDER Detection Script
Author: Antara Mane
Description: Detects PDFSIDER malware indicators on Windows systems
GitHub: https://github.com/InfoSecAntara/
LinkedIn: https://www.linkedin.com/in/antara-mane-967529126/
#>

# Configuration
$Version = "1.0.0"
$IndicatorsFile = "pdfsider_iocs.json"
$LogFile = "pdfsider_detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$ThreatName = "PDFSIDER APT Backdoor"

# Known IOCs
$KnownIOCs = @{
    Hashes = @{
        MD5 = @(
            "298cbfc6a5f6fa041581233278af9394",  # cryptbase.dll (malicious)
            "a32dc85eee2e1a579199050cd1941e1d"   # PDF24.exe (legitimate but abused)
        )
        SHA256 = @()  # Add SHA256 hashes if available
    }
    Files = @(
        "cryptbase.dll",
        "pdf24.exe",
        "About.dll",
        "Language.dll",
        "Settings.dll",
        "NotifyIcon.dll"
    )
    IPs = @(
        "45.76.9.248"
    )
    RegistryKeys = @(
        "HKCU\Software\PDF24",
        "HKLM\Software\PDF24",
        "HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\PDF24"
    )
}

# ANSI Colors for Output
$ColorRed = "`e[91m"
$ColorGreen = "`e[92m"
$ColorYellow = "`e[93m"
$ColorBlue = "`e[94m"
$ColorReset = "`e[0m"

# Logging Function
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp [$Level] $Message"
    Add-Content -Path $LogFile -Value $LogMessage
    
    switch ($Level) {
        "WARNING" { Write-Host "$ColorYellow[!]$ColorReset $Message" }
        "ALERT" { Write-Host "$ColorRed[!]$ColorReset $Message" }
        "SUCCESS" { Write-Host "$ColorGreen[✓]$ColorReset $Message" }
        default { Write-Host "[*] $Message" }
    }
}

# Banner
function Show-Banner {
    Clear-Host
    Write-Host "$ColorBlue" -NoNewline
    Write-Host "========================================================"
    Write-Host "                PDFSIDER DETECTION TOOL                "
    Write-Host "                Version: $Version                        "
    Write-Host "========================================================"
    Write-Host "$ColorReset"
    Write-Log "PDFSIDER Detection Tool Started" "INFO"
}

# Check Running as Admin
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Hash Calculation
function Get-FileHashMD5 {
    param([string]$FilePath)
    if (Test-Path $FilePath) {
        $hash = Get-FileHash -Path $FilePath -Algorithm MD5
        return $hash.Hash
    }
    return $null
}

# 1. Check for Known File Hashes
function Scan-KnownFiles {
    Write-Log "Starting file hash scan..." "INFO"
    $suspiciousFiles = @()
    
    # Common locations to check
    $scanPaths = @(
        "$env:USERPROFILE\Downloads",
        "$env:USERPROFILE\Desktop",
        "$env:ProgramFiles",
        "$env:ProgramFiles(x86)",
        "$env:TEMP",
        "C:\Windows\Temp",
        "$env:APPDATA",
        "$env:LOCALAPPDATA"
    )
    
    foreach ($path in $scanPaths) {
        if (Test-Path $path) {
            Write-Log "Scanning: $path" "INFO"
            
            # Search for PDF24 related files
            $files = Get-ChildItem -Path $path -Recurse -Include $KnownIOCs.Files -ErrorAction SilentlyContinue
            
            foreach ($file in $files) {
                $fileHash = Get-FileHashMD5 -FilePath $file.FullName
                
                if ($fileHash -in $KnownIOCs.Hashes.MD5) {
                    $suspiciousFiles += [PSCustomObject]@{
                        Path = $file.FullName
                        Name = $file.Name
                        Hash = $fileHash
                        Status = "MALICIOUS"
                    }
                    Write-Log "Found malicious file: $($file.FullName)" "ALERT"
                }
                else {
                    Write-Log "Found PDF24 related file: $($file.FullName)" "WARNING"
                }
            }
        }
    }
    
    return $suspiciousFiles
}

# 2. Check DLL Sideloading Indicators
function Check-DLLSideloading {
    Write-Log "Checking for DLL sideloading indicators..." "INFO"
    $suspiciousDLLs = @()
    
    # Check for cryptbase.dll outside system32
    $cryptbasePaths = Get-ChildItem -Path "C:\" -Recurse -Filter "cryptbase.dll" -ErrorAction SilentlyContinue |
                      Where-Object { $_.DirectoryName -notmatch "system32" -and $_.DirectoryName -notmatch "SysWOW64" }
    
    foreach ($dll in $cryptbasePaths) {
        $suspiciousDLLs += [PSCustomObject]@{
            Path = $dll.FullName
            Location = "Non-system directory"
            Risk = "HIGH"
        }
        Write-Log "Found cryptbase.dll in non-system location: $($dll.FullName)" "ALERT"
    }
    
    return $suspiciousDLLs
}

# 3. Check Network Connections
function Check-NetworkConnections {
    Write-Log "Checking network connections for known C2 IPs..." "INFO"
    $suspiciousConnections = @()
    
    try {
        $connections = Get-NetTCPConnection -ErrorAction SilentlyContinue
        
        foreach ($ip in $KnownIOCs.IPs) {
            $matchingConnections = $connections | Where-Object { $_.RemoteAddress -eq $ip }
            
            foreach ($conn in $matchingConnections) {
                $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
                
                $suspiciousConnections += [PSCustomObject]@{
                    RemoteIP = $ip
                    LocalPort = $conn.LocalPort
                    RemotePort = $conn.RemotePort
                    State = $conn.State
                    Process = $process.Name
                    PID = $conn.OwningProcess
                }
                Write-Log "Found connection to C2 IP $ip from process $($process.Name) (PID: $($conn.OwningProcess))" "ALERT"
            }
        }
    }
    catch {
        Write-Log "Network connection check failed. Run as Administrator." "WARNING"
    }
    
    return $suspiciousConnections
}

# 4. Check Registry Entries
function Check-Registry {
    Write-Log "Checking registry for PDFSIDER artifacts..." "INFO"
    $suspiciousRegistry = @()
    
    foreach ($key in $KnownIOCs.RegistryKeys) {
        if (Test-Path "Registry::$key") {
            $suspiciousRegistry += [PSCustomObject]@{
                RegistryPath = $key
                Status = "Found"
            }
            Write-Log "Found suspicious registry key: $key" "WARNING"
        }
    }
    
    return $suspiciousRegistry
}

# 5. Check Running Processes
function Check-RunningProcesses {
    Write-Log "Analyzing running processes..." "INFO"
    $suspiciousProcesses = @()
    
    # Look for PDF24 processes
    $pdf24Processes = Get-Process | Where-Object { $_.ProcessName -like "*pdf24*" }
    
    foreach ($proc in $pdf24Processes) {
        # Check loaded modules
        try {
            $modules = $proc.Modules | Where-Object { $_.ModuleName -like "*cryptbase*" }
            
            if ($modules) {
                $suspiciousProcesses += [PSCustomObject]@{
                    ProcessName = $proc.ProcessName
                    PID = $proc.Id
                    Path = $proc.Path
                    LoadedDLLs = $modules.ModuleName -join ", "
                }
                Write-Log "Found PDF24 process with suspicious DLLs: $($proc.ProcessName) (PID: $($proc.Id))" "ALERT"
            }
        }
        catch {
            # Process access might be denied
        }
    }
    
    return $suspiciousProcesses
}

# 6. Generate Report
function Generate-Report {
    param(
        $FileFindings,
        $DLLFindings,
        $NetworkFindings,
        $RegistryFindings,
        $ProcessFindings
    )
    
    $report = @"
PDFSIDER DETECTION REPORT
Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
System: $env:COMPUTERNAME
User: $env:USERNAME
================================================

SUMMARY
================================================
Total Findings: $(($FileFindings.Count + $DLLFindings.Count + $NetworkFindings.Count + $RegistryFindings.Count + $ProcessFindings.Count))

FILE SCAN RESULTS:
$(if ($FileFindings.Count -gt 0) { $FileFindings | Format-List | Out-String } else { "No malicious files found." })

DLL SIDELOADING INDICATORS:
$(if ($DLLFindings.Count -gt 0) { $DLLFindings | Format-List | Out-String } else { "No DLL sideloading indicators found." })

NETWORK CONNECTIONS:
$(if ($NetworkFindings.Count -gt 0) { $NetworkFindings | Format-List | Out-String } else { "No connections to known C2 IPs." })

REGISTRY FINDINGS:
$(if ($RegistryFindings.Count -gt 0) { $RegistryFindings | Format-List | Out-String } else { "No suspicious registry entries found." })

RUNNING PROCESSES:
$(if ($ProcessFindings.Count -gt 0) { $ProcessFindings | Format-List | Out-String } else { "No suspicious processes found." })

RECOMMENDED ACTIONS:
1. Quarantine any identified malicious files
2. Terminate suspicious processes
3. Block C2 IPs in firewall: 45.76.9.248
4. Update security software definitions
5. Consider re-imaging infected systems

END OF REPORT
"@
    
    $reportPath = "pdfsider_report_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
    $report | Out-File -FilePath $reportPath -Encoding UTF8
    
    Write-Log "Report saved to: $reportPath" "SUCCESS"
    return $reportPath
}

# Main Execution
function Start-Detection {
    Show-Banner
    
    if (-not (Test-Administrator)) {
        Write-Log "Warning: Running without administrator privileges. Some checks may be limited." "WARNING"
    }
    
    Write-Log "Starting PDFSIDER detection scan..." "INFO"
    
    # Run all detection functions
    $fileFindings = Scan-KnownFiles
    $dllFindings = Check-DLLSideloading
    $networkFindings = Check-NetworkConnections
    $registryFindings = Check-Registry
    $processFindings = Check-RunningProcesses
    
    # Generate report
    $reportPath = Generate-Report -FileFindings $fileFindings -DLLFindings $dllFindings `
                                   -NetworkFindings $networkFindings -RegistryFindings $registryFindings `
                                   -ProcessFindings $processFindings
    
    # Summary
    Write-Host "$ColorGreen" -NoNewline
    Write-Host "========================================================"
    Write-Host "                     SCAN COMPLETE                      "
    Write-Host "========================================================"
    Write-Host "$ColorReset"
    
    $totalFindings = $fileFindings.Count + $dllFindings.Count + $networkFindings.Count + $registryFindings.Count + $processFindings.Count
    
    if ($totalFindings -gt 0) {
        Write-Host "$ColorRed" -NoNewline
        Write-Host "ALERT: Found $totalFindings suspicious indicators!"
        Write-Host "Check the report for details: $reportPath"
        Write-Host "$ColorReset"
    }
    else {
        Write-Host "$ColorGreen" -NoNewline
        Write-Host "No indicators of PDFSIDER found."
        Write-Host "$ColorReset"
    }
    
    Write-Log "Scan completed. Total findings: $totalFindings" "INFO"
}

# Entry Point
Start-Detection