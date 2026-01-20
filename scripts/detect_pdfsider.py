#!/usr/bin/env python3
"""
PDFSIDER Detection Script
Author: Antara Mane
Description: Cross-platform detection for PDFSIDER malware indicators
Requirements: python3, hashlib, psutil, socket
"""

import os
import sys
import hashlib
import json
import logging
import platform
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import subprocess
import socket

# Configuration
VERSION = "1.0.0"
THREAT_NAME = "PDFSIDER APT Backdoor"
LOG_FILE = f"pdfsider_detection_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

# Known IOCs
KNOWN_IOCS = {
    "hashes": {
        "md5": [
            "298cbfc6a5f6fa041581233278af9394",  # cryptbase.dll
            "a32dc85eee2e1a579199050cd1941e1d"   # PDF24.exe
        ]
    },
    "files": [
        "cryptbase.dll",
        "pdf24.exe",
        "About.dll",
        "Language.dll",
        "Settings.dll",
        "NotifyIcon.dll"
    ],
    "ips": [
        "45.76.9.248"
    ],
    "registry_keys": [
        r"Software\PDF24",
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall\PDF24"
    ]
}

class Colors:
    """ANSI color codes for terminal output"""
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

class PDFSIDERDetector:
    def __init__(self):
        self.system = platform.system()
        self.findings = {
            "files": [],
            "network": [],
            "processes": [],
            "dll_sideloading": [],
            "summary": {}
        }
        self.setup_logging()
        
    def setup_logging(self):
        """Configure logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def log(self, message: str, level: str = "INFO"):
        """Log message with color coding"""
        color_map = {
            "ALERT": Colors.RED,
            "WARNING": Colors.YELLOW,
            "SUCCESS": Colors.GREEN,
            "INFO": Colors.BLUE
        }
        
        color = color_map.get(level, Colors.RESET)
        prefix = f"{color}[{level[0]}]" if level in color_map else "[*]"
        
        print(f"{prefix} {message}{Colors.RESET}")
        getattr(self.logger, level.lower(), self.logger.info)(message)
        
    def show_banner(self):
        """Display tool banner"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{Colors.BLUE}")
        print("=" * 60)
        print("            PDFSIDER DETECTION TOOL            ")
        print(f"            Version: {VERSION}                ")
        print("=" * 60)
        print(f"{Colors.RESET}")
        self.log("PDFSIDER Detection Tool Started")
        
    def calculate_md5(self, file_path: str) -> Optional[str]:
        """Calculate MD5 hash of a file"""
        try:
            with open(file_path, 'rb') as f:
                file_hash = hashlib.md5()
                chunk = f.read(8192)
                while chunk:
                    file_hash.update(chunk)
                    chunk = f.read(8192)
                return file_hash.hexdigest()
        except Exception as e:
            self.log(f"Error calculating hash for {file_path}: {e}", "WARNING")
            return None
            
    def scan_files(self) -> List[Dict]:
        """Scan for known malicious files"""
        self.log("Starting file scan...")
        suspicious_files = []
        
        # Define scan locations based on OS
        if self.system == "Windows":
            scan_locations = [
                os.path.expanduser("~\\Downloads"),
                os.path.expanduser("~\\Desktop"),
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                os.environ.get("TEMP", "C:\\Windows\\Temp"),
                os.path.expanduser("~\\AppData\\Local"),
                os.path.expanduser("~\\AppData\\Roaming")
            ]
        else:
            scan_locations = [
                os.path.expanduser("~/Downloads"),
                os.path.expanduser("~/Desktop"),
                "/tmp",
                "/var/tmp",
                os.path.expanduser("~/.local")
            ]
            
        for location in scan_locations:
            if os.path.exists(location):
                self.log(f"Scanning: {location}")
                
                for root, dirs, files in os.walk(location):
                    for file in files:
                        if file.lower() in [f.lower() for f in KNOWN_IOCS["files"]]:
                            file_path = os.path.join(root, file)
                            file_hash = self.calculate_md5(file_path)
                            
                            if file_hash in KNOWN_IOCS["hashes"]["md5"]:
                                suspicious_files.append({
                                    "path": file_path,
                                    "name": file,
                                    "hash": file_hash,
                                    "status": "MALICIOUS"
                                })
                                self.log(f"Found malicious file: {file_path}", "ALERT")
                            else:
                                self.log(f"Found PDF24 related file: {file_path}", "WARNING")
                                
        return suspicious_files
        
    def check_dll_sideloading(self) -> List[Dict]:
        """Check for DLL sideloading indicators"""
        self.log("Checking for DLL sideloading...")
        suspicious_dlls = []
        
        if self.system == "Windows":
            # Look for cryptbase.dll outside system directories
            import winreg
            import ctypes
            
            system_dirs = [
                os.environ.get("SystemRoot", "C:\\Windows") + "\\System32",
                os.environ.get("SystemRoot", "C:\\Windows") + "\\SysWOW64"
            ]
            
            # Search in common application directories
            search_dirs = [
                "C:\\Program Files",
                "C:\\Program Files (x86)",
                os.path.expanduser("~\\AppData")
            ]
            
            for search_dir in search_dirs:
                if os.path.exists(search_dir):
                    for root, dirs, files in os.walk(search_dir):
                        for file in files:
                            if file.lower() == "cryptbase.dll":
                                file_path = os.path.join(root, file)
                                if not any(system_dir in root for system_dir in system_dirs):
                                    suspicious_dlls.append({
                                        "path": file_path,
                                        "location": "Non-system directory",
                                        "risk": "HIGH"
                                    })
                                    self.log(f"Found cryptbase.dll in non-system location: {file_path}", "ALERT")
                                    
        return suspicious_dlls
        
    def check_network_connections(self) -> List[Dict]:
        """Check for connections to known C2 IPs"""
        self.log("Checking network connections...")
        suspicious_connections = []
        
        try:
            import psutil
            
            for conn in psutil.net_connections(kind='inet'):
                if conn.raddr:
                    for malicious_ip in KNOWN_IOCS["ips"]:
                        if malicious_ip in conn.raddr.ip:
                            try:
                                proc = psutil.Process(conn.pid)
                                proc_name = proc.name()
                            except:
                                proc_name = "Unknown"
                                
                            suspicious_connections.append({
                                "remote_ip": conn.raddr.ip,
                                "remote_port": conn.raddr.port,
                                "local_port": conn.laddr.port,
                                "pid": conn.pid,
                                "process": proc_name,
                                "status": conn.status
                            })
                            self.log(f"Found connection to C2 IP {conn.raddr.ip} from {proc_name} (PID: {conn.pid})", "ALERT")
                            
        except ImportError:
            self.log("psutil not installed. Install with: pip install psutil", "WARNING")
        except Exception as e:
            self.log(f"Network check failed: {e}", "WARNING")
            
        return suspicious_connections
        
    def check_processes(self) -> List[Dict]:
        """Check for suspicious processes"""
        self.log("Analyzing running processes...")
        suspicious_processes = []
        
        try:
            import psutil
            
            for proc in psutil.process_iter(['pid', 'name', 'exe']):
                try:
                    proc_name = proc.info['name'].lower()
                    
                    # Look for PDF24 processes
                    if 'pdf24' in proc_name or 'pdf24' in proc.info['exe'].lower() if proc.info['exe'] else '':
                        suspicious_processes.append({
                            "name": proc.info['name'],
                            "pid": proc.info['pid'],
                            "path": proc.info['exe'],
                            "status": "SUSPICIOUS"
                        })
                        self.log(f"Found PDF24 process: {proc.info['name']} (PID: {proc.info['pid']})", "WARNING")
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
                    
        except ImportError:
            self.log("psutil not installed", "WARNING")
            
        return suspicious_processes
        
    def generate_report(self) -> str:
        """Generate detection report"""
        report_lines = [
            "=" * 60,
            "PDFSIDER DETECTION REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"System: {platform.node()}",
            f"OS: {platform.system()} {platform.release()}",
            "=" * 60,
            "",
            "SUMMARY",
            "=" * 60,
            f"Total Findings: {len(self.findings['files']) + len(self.findings['dll_sideloading']) + len(self.findings['network']) + len(self.findings['processes'])}",
            "",
            "FILE SCAN RESULTS:",
            "=" * 60,
        ]
        
        if self.findings['files']:
            for file in self.findings['files']:
                report_lines.append(f"• {file['name']} at {file['path']}")
                report_lines.append(f"  Hash: {file['hash']} - Status: {file['status']}")
                report_lines.append("")
        else:
            report_lines.append("No malicious files found.")
            report_lines.append("")
            
        report_lines.append("DLL SIDELOADING INDICATORS:")
        report_lines.append("=" * 60)
        if self.findings['dll_sideloading']:
            for dll in self.findings['dll_sideloading']:
                report_lines.append(f"• {dll['path']}")
                report_lines.append(f"  Location: {dll['location']} - Risk: {dll['risk']}")
                report_lines.append("")
        else:
            report_lines.append("No DLL sideloading indicators found.")
            report_lines.append("")
            
        report_lines.append("NETWORK CONNECTIONS:")
        report_lines.append("=" * 60)
        if self.findings['network']:
            for conn in self.findings['network']:
                report_lines.append(f"• Connection to {conn['remote_ip']}:{conn['remote_port']}")
                report_lines.append(f"  From process: {conn['process']} (PID: {conn['pid']})")
                report_lines.append("")
        else:
            report_lines.append("No connections to known C2 IPs.")
            report_lines.append("")
            
        report_lines.append("RUNNING PROCESSES:")
        report_lines.append("=" * 60)
        if self.findings['processes']:
            for proc in self.findings['processes']:
                report_lines.append(f"• {proc['name']} (PID: {proc['pid']})")
                report_lines.append(f"  Path: {proc['path']}")
                report_lines.append(f"  Status: {proc['status']}")
                report_lines.append("")
        else:
            report_lines.append("No suspicious processes found.")
            report_lines.append("")
            
        report_lines.append("RECOMMENDED ACTIONS:")
        report_lines.append("=" * 60)
        report_lines.append("1. Quarantine any identified malicious files")
        report_lines.append("2. Terminate suspicious processes")
        report_lines.append("3. Block C2 IPs in firewall: 45.76.9.248")
        report_lines.append("4. Update security software definitions")
        report_lines.append("5. Consider re-imaging infected systems")
        report_lines.append("")
        report_lines.append("=" * 60)
        report_lines.append("END OF REPORT")
        
        report_content = "\n".join(report_lines)
        report_filename = f"pdfsider_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(report_content)
            
        self.log(f"Report saved to: {report_filename}", "SUCCESS")
        return report_filename
        
    def run(self):
        """Main execution method"""
        self.show_banner()
        
        if self.system == "Windows":
            self.log(f"Running on Windows {platform.release()}")
        else:
            self.log(f"Running on {self.system}. Some checks may be limited.", "WARNING")
            
        # Run all detection modules
        self.findings['files'] = self.scan_files()
        self.findings['dll_sideloading'] = self.check_dll_sideloading()
        self.findings['network'] = self.check_network_connections()
        self.findings['processes'] = self.check_processes()
        
        # Generate report
        report_path = self.generate_report()
        
        # Display summary
        print(f"\n{Colors.GREEN}{'='*60}")
        print("                     SCAN COMPLETE                      ")
        print(f"{'='*60}{Colors.RESET}\n")
        
        total_findings = (
            len(self.findings['files']) +
            len(self.findings['dll_sideloading']) +
            len(self.findings['network']) +
            len(self.findings['processes'])
        )
        
        if total_findings > 0:
            print(f"{Colors.RED}ALERT: Found {total_findings} suspicious indicators!")
            print(f"Check the report for details: {report_path}{Colors.RESET}")
        else:
            print(f"{Colors.GREEN}No indicators of PDFSIDER found.{Colors.RESET}")
            
        self.log(f"Scan completed. Total findings: {total_findings}")

def main():
    """Entry point"""
    try:
        detector = PDFSIDERDetector()
        detector.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}Scan interrupted by user.{Colors.RESET}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()