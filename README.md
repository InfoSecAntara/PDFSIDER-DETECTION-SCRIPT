# PDFSIDER-DETECTION-SCRIPT
PDFSIDER is a sophisticated Advanced Persistent Threat (APT) backdoor recently identified in targeted intrusion campaigns. It employs DLL sideloading through legitimate vulnerable software, strong AES-256-GCM encryption for C2 communications, and multiple layers of anti-analysis checks. This article breaks down its infection chain, technical components, and provides actionable detection insights.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

# PDFSIDER Detection Tool

A collection of scripts and rules to detect the PDFSIDER APT malware.

## Overview

PDFSIDER is an Advanced Persistent Threat (APT) backdoor that uses:
- DLL sideloading via legitimate PDF24 software
- AES-256-GCM encrypted C2 communications
- Anti-VM and anti-debugging techniques
- Hidden process execution (CREATE_NO_WINDOW)

This repository provides detection tools for security professionals.

# GitHub Repository Structure
<img width="174" height="124" alt="image" src="https://github.com/user-attachments/assets/51b57ca8-c070-439d-bd50-3dfc6e38bbeb" />

## Tools

### 1. PowerShell Detection Script
```powershell
# Run with administrative privileges
.\scripts\detect_pdfsider.ps1
```

### 2. Python Detection Script
```
pip install -r requirements.txt
python scripts/detect_pdfsider.py
```

### 3. YARA Rules
```
yara scripts/pdfsider_rules.yar /path/to/scan
```

# Features
- File hash matching
- DLL sideloading detection
- Network connection monitoring
- Process analysis
- Registry checks (Windows)
- Comprehensive reporting

# Installation

## Windows

powershell
```
git clone https://github.com/InfoSecAntara/PDFSIDER-DETECTION-SCRIPT.git
cd PDFSIDER-DETECTION-SCRIPT
```

## Linux/Mac
```
git clone https://github.com/InfoSecAntara/PDFSIDER-DETECTION-SCRIPT.git
cd PDFSIDER-DETECTION-SCRIPT
pip3 install -r requirements.txt
```

## Usage
Basic Scan
powershell

### PowerShell
```
.\scripts\detect_pdfsider.ps1
```
### Python
```
python scripts/detect_pdfsider.py
```

### Advanced Options
powershell

Custom IOC file refer below
```
.\scripts\detect_pdfsider.ps1 -IOCFile custom_iocs.json
```

# Indicators of Compromise (IOCs)
<img width="330" height="75" alt="image" src="https://github.com/user-attachments/assets/9fdd9da0-1954-4dbb-a64b-642c701034f1" />

Disclaimer
This tool is for educational and authorized security testing only. Use responsibly.

### **requirements.txt**
psutil>=5.9.0
colorama>=0.4.6
pyyaml>=6.0
requests>=2.28.0

# Detection & Mitigation Recommendations
- Monitor DLL Sideloading: Use EDR or Sysmon (Event ID 7) to watch for non-standard DLLs loaded by legitimate processes.
- Inspect Network Traffic: Look for DNS tunneling to unfamiliar IPs, especially on port 53 with high frequency.
- Memory Analysis: Hunt for injected processes and embedded cryptographic libraries (Botan) in memory.
- Application Whitelisting: Restrict execution of vulnerable but legitimate software like PDF24 in high-risk environments.
- User Training: Educate staff on spear-phishing indicators and safe handling of email attachments.

# Final Thoughts
Staying ahead of threats like PDFSIDER requires a layered defense strategy: robust network monitoring, behavioral detection, and continuous threat intelligence updates.
Have you encountered similar DLL sideloading campaigns? Share your experiences in the comments below.
