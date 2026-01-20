# PDFSIDER-DETECTION-SCRIPT
PDFSIDER is a sophisticated Advanced Persistent Threat (APT) backdoor recently identified in targeted intrusion campaigns. It employs DLL sideloading through legitimate vulnerable software, strong AES-256-GCM encryption for C2 communications, and multiple layers of anti-analysis checks. This article breaks down its infection chain, technical components, and provides actionable detection insights.

# PDFSIDER Detection Tool

A collection of scripts and rules to detect the PDFSIDER APT malware.

## Overview

PDFSIDER is an Advanced Persistent Threat (APT) backdoor that uses:
- DLL sideloading via legitimate PDF24 software
- AES-256-GCM encrypted C2 communications
- Anti-VM and anti-debugging techniques
- Hidden process execution (CREATE_NO_WINDOW)

This repository provides detection tools for security professionals.

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
