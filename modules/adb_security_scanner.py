#!/usr/bin/env python3
"""
ANDROID SECURITY TOOLKIT v2.0 - LEGAL NOTICE
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AUTHORIZED USE ONLY. PROHIBITED: Unauthorized access, spying, data theft.
REQUIRES: Device ownership OR written permission. VIOLATION: 5 years imprisonment.
--consent flag mandatory. All actions logged to loot/audit.log.
BY USING THIS TOOL, YOU ACCEPT FULL LEGAL RESPONSIBILITY.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
"""

import socket
import subprocess
import time
import re
import json
from typing import Dict, List, Optional, Tuple, Any
from pathlib import Path

from core.base_scanner import BaseScanner
from core.adb_manager import ADBManager, ADBDevice


class ADBSecurityScanner(BaseScanner):
    """
    Comprehensive ADB security scanner for Android devices.
    
    Features:
    - Device discovery (USB, TCP/IP, emulators)
    - Unauthorized access testing
    - CVE correlation
    - Root detection
    - ADB configuration analysis
    - Network security assessment
    """
    
    # Android CVE Database (2015-2024)
    ANDROID_CVES = [
        {
            "cve_id": "CVE-2016-5195",
            "title": "Dirty COW",
            "severity": "CRITICAL",
            "cvss_score": 7.8,
            "affected_versions": ["3.4.0", "3.4.1", "3.4.2", "3.4.3", "3.4.4", "3.4.5"],
            "description": "Race condition in Linux kernel memory management",
            "remediation": "Update to latest Android security patch"
        },
        {
            "cve_id": "CVE-2017-13274",
            "title": "Broadcom Wi-Fi Chipset Vulnerability",
            "severity": "HIGH",
            "cvss_score": 8.3,
            "affected_versions": ["7.0", "7.1.1", "7.1.2", "8.0", "8.1"],
            "description": "Remote code execution in Broadcom Wi-Fi chipset",
            "remediation": "Update to latest security patch level"
        },
        {
            "cve_id": "CVE-2020-0041",
            "title": "Kernel Use-After-Free",
            "severity": "CRITICAL", 
            "cvss_score": 8.1,
            "affected_versions": ["8.0", "8.1", "9", "10"],
            "description": "Use-after-free in binder driver",
            "remediation": "Apply Android security patch March 2020 or later"
        },
        {
            "cve_id": "CVE-2021-0316",
            "title": "System UI Privilege Escalation",
            "severity": "HIGH",
            "cvss_score": 7.0,
            "affected_versions": ["8.1", "9", "10", "11"],
            "description": "Privilege escalation in System UI component",
            "remediation": "Update to Android 11 or apply security patch"
        },
        {
            "cve_id": "CVE-2021-0682",
            "title": "MediaCodec Out-of-Bounds Write",
            "severity": "CRITICAL",
            "cvss_score": 9.8,
            "affected_versions": ["8.1", "9", "10", "11"],
            "description": "Out-of-bounds write in MediaCodec",
            "remediation": "Apply Android security patch August 2021 or later"
        },
        {
            "cve_id": "CVE-2022-20465",
            "title": "Lock Screen Bypass",
            "severity": "HIGH",
            "cvss_score": 6.8,
            "affected_versions": ["10", "11", "12", "12L"],
            "description": "Lock screen bypass without user interaction",
            "remediation": "Update to Android 13 or apply security patch"
        },
        {
            "cve_id": "CVE-2023-20963",
            "title": "System Privilege Escalation",
            "severity": "HIGH",
            "cvss_score": 7.8,
            "affected_versions": ["11", "12", "12L", "13"],
            "description": "Privilege escalation in system service",
            "remediation": "Apply Android security patch March 2023 or later"
        },
        {
            "cve_id": "CVE-2023-2136",
            "title": "Skia Remote Code Execution",
            "severity": "CRITICAL",
            "cvss_score": 9.6,
            "affected_versions": ["11", "12", "12L", "13"],
            "description": "Remote code execution in Skia graphics library",
            "remediation": "Apply Android security patch June 2023 or later"
        }
    ]
    
    # Common ADB ports
    ADB_PORTS = list(range(5555, 5586))
    
    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize ADB security scanner.
        
        Args:
            device_id: Optional specific device ID to scan
        """
        super().__init__("ADBSecurityScanner", device_id=device_id)
        self.adb_manager = ADBManager()
        self.discovered_devices: List[ADBDevice] = []
        self.vulnerability_count = 0
    
    def scan(self) -> Dict[str, Any]:
        """
        Perform comprehensive ADB security scan.
        
        Returns:
            Dictionary containing scan results and summary
        """
        self.logger.info("Starting ADB security scan")
        
        try:
            # Phase 1: Device discovery
            self._discover_usb_devices()
            self._scan_tcp_ip()
            
            # Phase 2: Security assessment
            for device in self.discovered_devices:
                self._test_unauthorized_access(device)
                self._check_root(device)
                self._analyze_adb_security(device)
                self._check_network_security(device)
                self._correlate_cves(device)
            
            # Phase 3: Generate summary
            summary = self.get_summary()
            
            self.logger.info(f"Scan complete. Found {len(self.findings)} security issues")
            return summary
            
        except Exception as e:
            self.logger.error(f"Scan failed: {e}")
            self.log_finding(
                "ERROR",
                "Scan Execution Failed",
                f"ADB security scan failed with error: {str(e)}",
                {"error": str(e), "traceback": self._format_traceback()},
                "Check logs and retry scan"
            )
            return self.get_summary()
        
        finally:
            self.cleanup()
    
    def _discover_usb_devices(self) -> List[ADBDevice]:
        """Discover USB-connected Android devices."""
        self.logger.info("Discovering USB devices")
        
        devices = self.adb_manager.discover_devices()
        usb_devices = [d for d in devices if d.device_type == "usb"]
        
        for device in usb_devices:
            self.logger.info(f"Found USB device: {device.device_id} - {device.model or 'Unknown'}")
            
            # Log device discovery
            self.log_finding(
                "INFO",
                f"USB Device Discovered: {device.device_id}",
                f"USB-connected Android device detected: {device.model or 'Unknown model'}",
                {
                    "device_id": device.device_id,
                    "status": device.status,
                    "model": device.model,
                    "product": device.product,
                    "transport_id": device.transport_id
                },
                "Verify this is an authorized device"
            )
        
        self.discovered_devices.extend(usb_devices)
        self.update_metrics({"devices_scanned": len(usb_devices)})
        
        return usb_devices
    
    def _scan_tcp_ip(self) -> List[ADBDevice]:
        """Scan for TCP/IP ADB devices on network."""
        self.logger.info("Scanning for TCP/IP devices")
        
        tcp_devices = []
        
        # Scan common ADB ports on local network
        local_ip = self._get_local_ip()
        if not local_ip:
            self.logger.warning("Could not determine local IP for scanning")
            return tcp_devices
        
        # Scan localhost and local network
        scan_targets = ["127.0.0.1"]
        
        # Add local network range
        if local_ip.startswith("192.168."):
            base_ip = local_ip.rsplit(".", 1)[0]
            scan_targets.extend([f"{base_ip}.{i}" for i in range(1, 255)])
        elif local_ip.startswith("10."):
            base_ip = local_ip.rsplit(".", 1)[0]
            scan_targets.extend([f"{base_ip}.{i}" for i in range(1, 255)])
        
        # Scan each target
        for target_ip in scan_targets:
            for port in self.ADB_PORTS:
                device_info = self._test_adb_port(target_ip, port)
                if device_info:
                    tcp_devices.append(device_info)
                    
                    # Check if unauthorized access is possible
                    if device_info.get("unauthorized", False):
                        self.log_finding(
                            "CRITICAL",
                            f"Unauthorized ADB Access: {target_ip}:{port}",
                            "ADB service allows unauthorized access without authentication",
                            {
                                "ip": target_ip,
                                "port": port,
                                "device_info": device_info
                            },
                            "Disable ADB or enable authentication immediately"
                        )
                    else:
                        self.log_finding(
                            "INFO",
                            f"TCP/IP ADB Device: {target_ip}:{port}",
                            "Network-accessible ADB device discovered",
                            {
                                "ip": target_ip,
                                "port": port,
                                "device_info": device_info
                            },
                            "Ensure device is on trusted network"
                        )
        
        self.discovered_devices.extend(tcp_devices)
        self.logger.info(f"Discovered {len(tcp_devices)} TCP/IP devices")
        
        return tcp_devices
    
    def _get_local_ip(self) -> Optional[str]:
        """Get the local IP address."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return None
    
    def _test_adb_port(self, ip: str, port: int) -> Optional[Dict[str, Any]]:
        """Test if port has ADB service and check security."""
        try:
            # First check if port is open
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result != 0:
                return None
            
            # Try to connect with ADB
            process = subprocess.run(
                ["adb", "connect", f"{ip}:{port}"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            device_info = {
                "ip": ip,
                "port": port,
                "status": "unknown",
                "unauthorized": False,
                "accessible": False
            }
            
            if process.returncode == 0:
                output = process.stdout.lower()
                
                if "connected to" in output:
                    device_info["status"] = "connected"
                    device_info["accessible"] = True
                    
                    # Try to get device info
                    device_result = subprocess.run(
                        ["adb", "-s", f"{ip}:{port}", "shell", "getprop", "ro.product.model"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if device_result.returncode == 0:
                        device_info["model"] = device_result.stdout.strip()
                    
                    # Check if we have shell access
                    shell_result = subprocess.run(
                        ["adb", "-s", f"{ip}:{port}", "shell", "id"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    
                    if shell_result.returncode == 0:
                        device_info["shell_access"] = True
                        device_info["user"] = shell_result.stdout.strip()
                    
                    # Disconnect after testing
                    subprocess.run(["adb", "disconnect", f"{ip}:{port}"], 
                                 capture_output=True, timeout=5)
                
                elif "unauthorized" in output:
                    device_info["status"] = "unauthorized"
                    device_info["unauthorized"] = True
            
            return device_info
            
        except subprocess.TimeoutExpired:
            self.logger.debug(f"Timeout testing {ip}:{port}")
            return None
        except Exception as e:
            self.logger.debug(f"Error testing {ip}:{port}: {e}")
            return None
    
    def _test_unauthorized_access(self, device: ADBDevice) -> bool:
        """Test if device allows unauthorized ADB access."""
        self.logger.info(f"Testing unauthorized access for {device.device_id}")
        
        if device.unauthorized:
            self.log_finding(
                "CRITICAL",
                f"Unauthorized ADB Access: {device.device_id}",
                "Device allows ADB connections without proper authorization",
                {
                    "device_id": device.device_id,
                    "ip": device.ip_address,
                    "port": device.port,
                    "device_type": device.device_type
                },
                "Revoke ADB authorizations and require user approval for new connections"
            )
            return True
        
        # Additional checks for TCP/IP devices
        if device.device_type == "tcp_ip":
            # Check if on public network
            if device.ip_address and not self._is_private_ip(device.ip_address):
                self.log_finding(
                    "HIGH",
                    f"Public Network ADB: {device.device_id}",
                    "ADB service accessible on public network",
                    {
                        "device_id": device.device_id,
                        "public_ip": device.ip_address,
                        "port": device.port
                    },
                    "Block ADB access from public networks"
                )
        
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private."""
        private_ranges = [
            r"^127\.",
            r"^10\.",
            r"^192\.168\.",
            r"^172\.(1[6-9]|2[0-9]|3[01])\.",
        ]
        
        for pattern in private_ranges:
            if re.match(pattern, ip):
                return True
        
        return False
    
    def _check_root(self, device: ADBDevice) -> bool:
        """Check if device has root access enabled."""
        self.logger.info(f"Checking root status for {device.device_id}")
        
        # Skip if device is not accessible
        if device.unauthorized or device.offline:
            return False
        
        try:
            # Test with direct ADB command
            if ":" in device.device_id:
                # TCP/IP device
                cmd = ["adb", "-s", device.device_id, "shell", "su", "-c", "id"]
            else:
                # USB device
                cmd = ["adb", "-s", device.device_id, "shell", "su", "-c", "id"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0 and "uid=0" in result.stdout:
                self.log_finding(
                    "HIGH",
                    f"Root Access Enabled: {device.device_id}",
                    "Device has root access enabled via ADB",
                    {
                        "device_id": device.device_id,
                        "root_method": "su binary",
                        "user_id": result.stdout.strip()
                    },
                    "Disable root access for security unless absolutely necessary"
                )
                return True
            
            # Check for other root indicators
            root_indicators = [
                ("which su", "su binary path"),
                ("ls /system/bin/su", "su in system bin"),
                ("ls /system/xbin/su", "su in system xbin"),
                ("getprop ro.secure", "secure boot property")
            ]
            
            for check_cmd, indicator in root_indicators:
                if ":" in device.device_id:
                    cmd = ["adb", "-s", device.device_id, "shell", check_cmd]
                else:
                    cmd = ["adb", "-s", device.device_id, "shell", check_cmd]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
                
                if "su" in result.stdout or "0" in result.stdout:
                    self.log_finding(
                        "MEDIUM",
                        f"Root Indicators Found: {device.device_id}",
                        f"Potential root access indicators detected: {indicator}",
                        {
                            "device_id": device.device_id,
                            "indicator": indicator,
                            "result": result.stdout.strip()
                        },
                        "Investigate root access and remove if unnecessary"
                    )
            
            return False
            
        except subprocess.TimeoutExpired:
            self.logger.warning(f"Root check timeout for {device.device_id}")
            return False
        except Exception as e:
            self.logger.error(f"Root check error for {device.device_id}: {e}")
            return False
    
    def _analyze_adb_security(self, device: ADBDevice) -> Dict[str, Any]:
        """Analyze ADB security configuration."""
        self.logger.info(f"Analyzing ADB security for {device.device_id}")
        
        security_analysis = {
            "device_id": device.device_id,
            "adb_enabled": True,
            "secure_adb": True,
            "issues": []
        }
        
        # Check if device is in unauthorized state
        if device.unauthorized:
            security_analysis["secure_adb"] = False
            security_analysis["issues"].append("ADB unauthorized - requires user approval")
        
        # Try to get ADB security settings
        try:
            if not device.unauthorized and not device.offline:
                # Check ADB enabled status
                if ":" in device.device_id:
                    cmd_base = ["adb", "-s", device.device_id]
                else:
                    cmd_base = ["adb", "-s", device.device_id]
                
                # Check secure boot setting
                result = subprocess.run(
                    cmd_base + ["shell", "getprop", "ro.secure"],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    secure_boot = result.stdout.strip()
                    if secure_boot == "0":
                        security_analysis["issues"].append("Secure boot disabled")
                        self.log_finding(
                            "HIGH",
                            f"Secure Boot Disabled: {device.device_id}",
                            "Device has secure boot disabled",
                            {
                                "device_id": device.device_id,
                                "ro_secure": secure_boot
                            },
                            "Enable secure boot for enhanced security"
                        )
                
                # Check ADB secure setting
                result = subprocess.run(
                    cmd_base + ["shell", "settings", "get", "global", "adb_enabled"],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    adb_enabled = result.stdout.strip()
                    security_analysis["adb_setting"] = adb_enabled
        
        except Exception as e:
            self.logger.debug(f"ADB security analysis error: {e}")
        
        # Log security analysis results
        if not security_analysis["secure_adb"]:
            self.log_finding(
                "MEDIUM",
                f"ADB Security Issues: {device.device_id}",
                "ADB security configuration has issues",
                security_analysis,
                "Review and secure ADB configuration"
            )
        
        return security_analysis
    
    def _check_network_security(self, device: ADBDevice) -> None:
        """Check network security configuration."""
        self.logger.info(f"Checking network security for {device.device_id}")
        
        # Only relevant for TCP/IP devices
        if device.device_type != "tcp_ip" or not device.ip_address:
            return
        
        # Check if using secure protocols
        if device.port == 5555:
            self.log_finding(
                "MEDIUM",
                f"Default ADB Port: {device.device_id}",
                "Device using default ADB port 5555",
                {
                    "device_id": device.device_id,
                    "port": device.port,
                    "recommendation": "Use non-standard port"
                },
                "Consider using non-standard ADB port for security"
            )
        
        # Check for network exposure
        if not self._is_private_ip(device.ip_address):
            self.log_finding(
                "CRITICAL",
                f"Public ADB Exposure: {device.device_id}",
                "ADB service exposed to public internet",
                {
                    "device_id": device.device_id,
                    "public_ip": device.ip_address,
                    "port": device.port
                },
                "Block public access to ADB service immediately"
            )
    
    def _correlate_cves(self, device: ADBDevice) -> None:
        """Correlate device with known CVEs."""
        self.logger.info(f"Correlating CVEs for {device.device_id}")
        
        # Try to get Android version
        android_version = None
        if not device.unauthorized and not device.offline:
            try:
                if ":" in device.device_id:
                    cmd_base = ["adb", "-s", device.device_id]
                else:
                    cmd_base = ["adb", "-s", device.device_id]
                
                result = subprocess.run(
                    cmd_base + ["shell", "getprop", "ro.build.version.release"],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    android_version = result.stdout.strip()
                    
                    # Check each CVE
                    for cve in self.ANDROID_CVES:
                        if self._is_version_affected(android_version, cve["affected_versions"]):
                            self.log_finding(
                                cve["severity"],
                                f"{cve['cve_id']}: {device.device_id}",
                                f"Device may be vulnerable to {cve['title']}",
                                {
                                    "device_id": device.device_id,
                                    "android_version": android_version,
                                    "cve_id": cve["cve_id"],
                                    "cvss_score": cve["cvss_score"],
                                    "affected_versions": cve["affected_versions"]
                                },
                                cve["remediation"],
                                cvss_score=cve["cvss_score"],
                                cve_id=cve["cve_id"]
                            )
                            
                            self.vulnerability_count += 1
            
            except Exception as e:
                self.logger.debug(f"CVE correlation error: {e}")
    
    def _is_version_affected(self, version: str, affected_versions: List[str]) -> bool:
        """Check if version is in affected versions list."""
        # Simple version comparison - in production, use proper version parsing
        version_clean = version.split(".")[0]  # Get major version
        
        for affected in affected_versions:
            if version_clean == affected.split(".")[0]:
                return True
        
        return False
    
    def _format_traceback(self) -> str:
        """Format exception traceback for logging."""
        import traceback
        return traceback.format_exc()
    
    def get_device_summary(self) -> Dict[str, Any]:
        """Get summary of discovered devices."""
        return {
            "total_devices": len(self.discovered_devices),
            "usb_devices": len([d for d in self.discovered_devices if d.device_type == "usb"]),
            "tcp_devices": len([d for d in self.discovered_devices if d.device_type == "tcp_ip"]),
            "emulators": len([d for d in self.discovered_devices if d.device_type == "emulator"]),
            "unauthorized_devices": len([d for d in self.discovered_devices if d.unauthorized]),
            "offline_devices": len([d for d in self.discovered_devices if d.offline]),
            "vulnerabilities_found": self.vulnerability_count
        }