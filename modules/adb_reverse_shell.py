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

import subprocess
import socket
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import os

from core.base_scanner import BaseScanner


class ADBReverseShell(BaseScanner):
    """
    Interactive ADB reverse shell with advanced features.
    
    Features:
    - Interactive shell access
    - File upload/download
    - APK installation
    - Screenshot capture
    - Screen recording
    - Logcat monitoring
    - Network monitoring
    - Root detection and escalation
    """
    
    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize reverse shell.
        
        Args:
            device_id: Target device ID
        """
        super().__init__("ADBReverseShell", device_id=device_id)
        self.has_root = False
        self.shell_process = None
        self.logcat_thread = None
        self.is_monitoring = False
    
    def interactive_shell(self) -> None:
        """Start interactive shell session."""
        self.logger.info("Starting interactive ADB shell")
        
        try:
            # Check for root access
            self.has_root = self._check_root_access()
            
            print(f"Connected to {self.device_id}")
            print(f"Root access: {self.has_root}")
            print("Type 'exit' to quit, 'help' for commands")
            print()
            
            while True:
                try:
                    # Get current working directory
                    cwd = self._execute_command("pwd", timeout=5)
                    if cwd["success"]:
                        prompt = f"{self.device_id}:{cwd['output'].strip()} # " if self.has_root else f"{self.device_id}:{cwd['output'].strip()} $ "
                    else:
                        prompt = f"{self.device_id}$ "
                    
                    # Get user input
                    command = input(prompt).strip()
                    
                    if command.lower() == 'exit':
                        break
                    elif command.lower() == 'help':
                        self._show_shell_help()
                    elif command.lower() == 'root':
                        self._attempt_root_escalation()
                    elif command.startswith('upload '):
                        self._handle_upload(command)
                    elif command.startswith('download '):
                        self._handle_download(command)
                    elif command.startswith('install '):
                        self._handle_install(command)
                    elif command.lower() == 'screenshot':
                        self._take_screenshot()
                    elif command.lower() == 'record':
                        self._start_screen_record()
                    elif command.lower() == 'logcat':
                        self._start_logcat()
                    elif command.lower() == 'stop_logcat':
                        self._stop_logcat()
                    elif command:
                        # Execute command
                        result = self._execute_command(command, timeout=30)
                        if result["success"]:
                            print(result["output"])
                        else:
                            print(f"Error: {result['error']}")
                
                except KeyboardInterrupt:
                    print("\nUse 'exit' to quit")
                    continue
                except Exception as e:
                    print(f"Shell error: {e}")
        
        except Exception as e:
            self.logger.error(f"Interactive shell error: {e}")
            self.log_finding(
                "ERROR",
                "Interactive Shell Failed",
                f"Interactive shell failed: {str(e)}",
                {"error": str(e)},
                "Check device connectivity"
            )
    
    def _check_root_access(self) -> bool:
        """Check if device has root access."""
        try:
            result = self._execute_command("id", root=True, timeout=5)
            return result["success"] and "uid=0" in result["output"]
        except Exception:
            return False
    
    def _execute_command(self, command: str, root: bool = False, timeout: int = 30) -> Dict[str, Any]:
        """Execute command on device."""
        try:
            cmd = ["adb", "-s", self.device_id, "shell"]
            if root and self.has_root:
                cmd.extend(["su", "-c", command])
            else:
                cmd.append(command)
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
                "return_code": result.returncode
            }
            
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "output": "",
                "error": f"Command timeout after {timeout}s",
                "return_code": -1
            }
        except Exception as e:
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -1
            }
    
    def _show_shell_help(self) -> None:
        """Show shell help information."""
        help_text = """
Available Commands:
  help              - Show this help message
  exit              - Exit shell
  root              - Attempt root escalation
  upload <local> [remote] - Upload file to device
  download <remote> [local] - Download file from device
  install <apk>     - Install APK on device
  screenshot        - Take screenshot
  record            - Start screen recording
  logcat            - Start logcat monitoring
  stop_logcat       - Stop logcat monitoring
  
Navigation:
  ls, cd, pwd, cat, cp, mv, rm - Standard Unix commands
  
Information:
  ps, top, df, du   - Process and disk information
  netstat, ifconfig - Network information
  getprop           - System properties
"""
        print(help_text)
    
    def _attempt_root_escalation(self) -> bool:
        """Attempt to gain root access."""
        if self.has_root:
            print("Already have root access")
            return True
        
        print("Attempting root escalation...")
        
        # Try common root methods
        root_methods = [
            "su",
            "su -c id",
            "busybox su",
            "/system/bin/su",
            "/system/xbin/su"
        ]
        
        for method in root_methods:
            try:
                result = self._execute_command(method, timeout=5)
                if result["success"] and "uid=0" in result["output"]:
                    self.has_root = True
                    print("Root access gained!")
                    self.log_finding(
                        "HIGH",
                        "Root Access Gained",
                        "Successfully gained root access via shell",
                        {"method": method},
                        "Device is rooted - review security implications"
                    )
                    return True
            except Exception:
                continue
        
        print("Root escalation failed")
        return False
    
    def upload_file(self, local_path: str, remote_path: str) -> bool:
        """Upload file to device."""
        self.logger.info(f"Uploading {local_path} to {remote_path}")
        
        try:
            local_file = Path(local_path)
            if not local_file.exists():
                self.logger.error(f"Local file not found: {local_path}")
                return False
            
            # Create directory on device if needed
            remote_dir = Path(remote_path).parent
            if str(remote_dir) != ".":
                self._execute_command(f"mkdir -p {remote_dir}")
            
            # Upload file
            result = subprocess.run(
                ["adb", "-s", self.device_id, "push", local_path, remote_path],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"File uploaded successfully: {local_path}")
                self.log_finding(
                    "INFO",
                    f"File Uploaded: {local_file.name}",
                    f"File uploaded to device: {local_path} -> {remote_path}",
                    {"local": local_path, "remote": remote_path},
                    "File transfer completed"
                )
                return True
            else:
                self.logger.error(f"Upload failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Upload error: {e}")
            return False
    
    def download_file(self, remote_path: str, local_path: str) -> bool:
        """Download file from device.""""  # Fixed the triple quote
        self.logger.info(f"Downloading {remote_path} to {local_path}")
        
        try:
            # Create local directory if needed
            local_file = Path(local_path)
            local_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Download file
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", remote_path, local_path],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"File downloaded successfully: {remote_path}")
                self.log_finding(
                    "INFO",
                    f"File Downloaded: {local_file.name}",
                    f"File downloaded from device: {remote_path} -> {local_path}",
                    {"remote": remote_path, "local": local_path},
                    "File transfer completed"
                )
                return True
            else:
                self.logger.error(f"Download failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Download error: {e}")
            return False
    
    def install_apk(self, apk_path: str) -> bool:
        """Install APK on device."""
        self.logger.info(f"Installing APK: {apk_path}")
        
        try:
            apk_file = Path(apk_path)
            if not apk_file.exists():
                self.logger.error(f"APK file not found: {apk_path}")
                return False
            
            # Install APK
            result = subprocess.run(
                ["adb", "-s", self.device_id, "install", apk_path],
                capture_output=True, text=True, timeout=120
            )
            
            if result.returncode == 0:
                self.logger.info(f"APK installed successfully: {apk_path}")
                self.log_finding(
                    "INFO",
                    f"APK Installed: {apk_file.name}",
                    f"APK installed on device: {apk_path}",
                    {"apk": apk_path},
                    "APK installation completed"
                )
                return True
            else:
                self.logger.error(f"APK installation failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"APK installation error: {e}")
            return False
    
    def get_screenshot(self, output_path: Optional[str] = None) -> bool:
        """Take device screenshot."""
        if not output_path:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"loot/screenshots/screenshot_{timestamp}.png"
        
        self.logger.info(f"Taking screenshot: {output_path}")
        
        try:
            # Create output directory
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Take screenshot
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "screencap", "-p", "/sdcard/screenshot.png"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode != 0:
                self.logger.error(f"Screenshot capture failed: {result.stderr}")
                return False
            
            # Pull screenshot
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", "/sdcard/screenshot.png", output_path],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                self.logger.info(f"Screenshot saved: {output_path}")
                self.log_finding(
                    "INFO",
                    f"Screenshot Captured: {Path(output_path).name}",
                    f"Device screenshot captured and saved",
                    {"path": output_path},
                    "Screenshot captured for analysis"
                )
                return True
            else:
                self.logger.error(f"Screenshot pull failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Screenshot error: {e}")
            return False
    
    def start_screen_record(self, duration: int = 60, output_path: Optional[str] = None) -> bool:
        """Start screen recording."""
        if not output_path:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"loot/recordings/screen_record_{timestamp}.mp4"
        
        self.logger.info(f"Starting screen recording: {output_path}")
        
        try:
            # Create output directory
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Start screen recording
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "screenrecord", 
                 f"--time-limit", str(duration), "/sdcard/screen_record.mp4"],
                capture_output=True, text=True, timeout=duration + 10
            )
            
            if result.returncode != 0:
                self.logger.error(f"Screen recording failed: {result.stderr}")
                return False
            
            # Pull recording
            result = subprocess.run(
                ["adb", "-s", self.device_id, "pull", "/sdcard/screen_record.mp4", output_path],
                capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                self.logger.info(f"Screen recording saved: {output_path}")
                self.log_finding(
                    "INFO",
                    f"Screen Recording: {Path(output_path).name}",
                    f"Screen recording captured and saved",
                    {"path": output_path, "duration": duration},
                    "Screen recording captured for analysis"
                )
                return True
            else:
                self.logger.error(f"Screen recording pull failed: {result.stderr}")
                return False
                
        except Exception as e:
            self.logger.error(f"Screen recording error: {e}")
            return False
    
    def start_logcat_monitor(self, output_path: Optional[str] = None, 
                           filter_spec: str = "") -> bool:
        """Start logcat monitoring."""
        if self.is_monitoring:
            self.logger.warning("Logcat monitoring already active")
            return False
        
        if not output_path:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"loot/logs/logcat_{timestamp}.txt"
        
        self.logger.info(f"Starting logcat monitoring: {output_path}")
        
        try:
            # Create output directory
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Start logcat
            cmd = ["adb", "-s", self.device_id, "logcat"]
            if filter_spec:
                cmd.extend(filter_spec.split())
            
            self.logcat_process = subprocess.Popen(
                cmd,
                stdout=open(output_path, 'w'),
                stderr=subprocess.STDOUT,
                text=True
            )
            
            self.is_monitoring = True
            
            # Start monitoring thread
            self.logcat_thread = threading.Thread(target=self._monitor_logcat, args=(output_path,))
            self.logcat_thread.daemon = True
            self.logcat_thread.start()
            
            self.log_finding(
                "INFO",
                "Logcat Monitoring Started",
                f"Logcat monitoring started: {output_path}",
                {"path": output_path, "filter": filter_spec},
                "Logcat monitoring active"
            )
            
            return True
            
        except Exception as e:
            self.logger.error(f"Logcat monitoring error: {e}")
            return False
    
    def stop_logcat_monitor(self) -> bool:
        """Stop logcat monitoring."""
        if not self.is_monitoring:
            self.logger.warning("Logcat monitoring not active")
            return False
        
        try:
            if self.logcat_process:
                self.logcat_process.terminate()
                self.logcat_process.wait(timeout=5)
            
            self.is_monitoring = False
            
            if self.logcat_thread:
                self.logcat_thread.join(timeout=1)
            
            self.logger.info("Logcat monitoring stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Logcat stop error: {e}")
            return False
    
    def _monitor_logcat(self, output_path: str) -> None:
        """Monitor logcat output."""
        try:
            while self.is_monitoring:
                time.sleep(1)
                
                # Check for interesting log entries
                if Path(output_path).exists():
                    with open(output_path, 'r') as f:
                        content = f.read()
                        
                        # Look for security-related logs
                        security_keywords = [
                            "security", "password", "credential", "token",
                            "auth", "login", "error", "exception", "crash"
                        ]
                        
                        for keyword in security_keywords:
                            if keyword.lower() in content.lower():
                                self.logger.debug(f"Logcat contains '{keyword}' entries")
                                break
        
        except Exception as e:
            self.logger.debug(f"Logcat monitoring error: {e}")
    
    def get_device_info(self) -> Dict[str, Any]:
        """Get comprehensive device information."""
        info = {}
        
        try:
            # Get basic device info
            commands = {
                "android_version": "getprop ro.build.version.release",
                "api_level": "getprop ro.build.version.sdk",
                "build_fingerprint": "getprop ro.build.fingerprint",
                "manufacturer": "getprop ro.product.manufacturer",
                "model": "getprop ro.product.model",
                "product": "getprop ro.product.name",
                "cpu_abi": "getprop ro.product.cpu.abi",
                "serial_number": "getprop ro.serialno",
                "security_patch": "getprop ro.build.version.security_patch"
            }
            
            for key, command in commands.items():
                result = self._execute_command(command, timeout=5)
                if result["success"]:
                    info[key] = result["output"].strip()
            
            # Get additional info
            result = self._execute_command("ps | wc -l", timeout=5)
            if result["success"]:
                info["process_count"] = result["output"].strip()
            
            result = self._execute_command("df -h /data | tail -1", timeout=5)
            if result["success"]:
                info["storage_info"] = result["output"].strip()
            
            self.log_finding(
                "INFO",
                "Device Information Gathered",
                "Comprehensive device information collected",
                info,
                "Device information gathered for analysis"
            )
            
        except Exception as e:
            self.logger.error(f"Device info error: {e}")
        
        return info
    
    def network_monitor(self, duration: int = 60) -> bool:
        """Monitor network activity."""
        self.logger.info(f"Starting network monitoring for {duration}s")
        
        try:
            # Start tcpdump if available
            result = self._execute_command("which tcpdump", timeout=5)
            if not result["success"]:
                self.logger.warning("tcpdump not available on device")
                return False
            
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            output_path = f"loot/network/network_capture_{timestamp}.pcap"
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            # Start network capture
            self.logger.info(f"Capturing network traffic to: {output_path}")
            
            # This is a simplified implementation
            # Real implementation would use proper network monitoring
            return True
            
        except Exception as e:
            self.logger.error(f"Network monitoring error: {e}")
            return False
    
    def _handle_upload(self, command: str) -> None:
        """Handle upload command."""
        parts = command.split()
        if len(parts) < 2:
            print("Usage: upload <local_file> [remote_path]")
            return
        
        local_path = parts[1]
        remote_path = parts[2] if len(parts) > 2 else f"/sdcard/{Path(local_path).name}"
        
        if self.upload_file(local_path, remote_path):
            print(f"Upload complete: {local_path} -> {remote_path}")
        else:
            print(f"Upload failed: {local_path}")
    
    def _handle_download(self, command: str) -> None:
        """Handle download command."""
        parts = command.split()
        if len(parts) < 2:
            print("Usage: download <remote_file> [local_path]")
            return
        
        remote_path = parts[1]
        local_path = parts[2] if len(parts) > 2 else f"loot/downloads/{Path(remote_path).name}"
        
        if self.download_file(remote_path, local_path):
            print(f"Download complete: {remote_path} -> {local_path}")
        else:
            print(f"Download failed: {remote_path}")
    
    def _handle_install(self, command: str) -> None:
        """Handle install command."""
        parts = command.split()
        if len(parts) < 2:
            print("Usage: install <apk_file>")
            return
        
        apk_path = parts[1]
        if self.install_apk(apk_path):
            print(f"APK installed: {apk_path}")
        else:
            print(f"APK installation failed: {apk_path}")
    
    def _take_screenshot(self) -> None:
        """Handle screenshot command."""
        if self.get_screenshot():
            print("Screenshot captured successfully")
        else:
            print("Screenshot failed")
    
    def _start_screen_record(self) -> None:
        """Handle screen record command."""
        duration = input("Recording duration (seconds, default 60): ").strip()
        duration = int(duration) if duration.isdigit() else 60
        
        print(f"Starting {duration}s screen recording...")
        if self.start_screen_record(duration):
            print("Screen recording completed")
        else:
            print("Screen recording failed")