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
import time
import re
import os
import logging
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass
from pathlib import Path
import threading


@dataclass
class ADBDevice:
    """Represents an ADB-connected device."""
    
    device_id: str
    status: str
    device_type: str  # "usb", "emulator", "tcp_ip"
    ip_address: Optional[str] = None
    port: Optional[int] = None
    product: Optional[str] = None
    model: Optional[str] = None
    device: Optional[str] = None
    transport_id: Optional[str] = None
    unauthorized: bool = False
    offline: bool = False


class ADBManager:
    """
    Manages ADB connections and device interactions.
    
    Features:
    - Device discovery (USB, TCP/IP, emulators)
    - Connection management
    - Command execution with error handling
    - Root detection and management
    - Port forwarding
    - Shell interaction
    """
    
    # Common ADB ports for TCP/IP discovery
    COMMON_ADB_PORTS = list(range(5555, 5586))  # 5555-5585
    
    # ADB command timeout (seconds)
    DEFAULT_TIMEOUT = 30
    
    def __init__(self, adb_path: str = "adb", timeout: int = DEFAULT_TIMEOUT):
        """
        Initialize ADB manager.
        
        Args:
            adb_path: Path to adb executable
            timeout: Default command timeout in seconds
        """
        self.adb_path = adb_path
        self.timeout = timeout
        self.logger = logging.getLogger("AST.ADBManager")
        
        # Device cache
        self._devices: Dict[str, ADBDevice] = {}
        self._device_lock = threading.Lock()
        
        # Connection tracking
        self._connections: Dict[str, Any] = {}
        self._command_history: List[Dict[str, Any]] = []
        
        # Performance tracking
        self._execution_times: Dict[str, List[float]] = {}
        
        # Initialize ADB server
        self._init_adb_server()
    
    def _init_adb_server(self) -> bool:
        """Initialize ADB server if not running."""
        try:
            result = self._run_command([self.adb_path, "start-server"], timeout=10)
            if result["success"]:
                self.logger.info("ADB server initialized")
                return True
            else:
                self.logger.error(f"Failed to start ADB server: {result['error']}")
                return False
        except Exception as e:
            self.logger.error(f"ADB server initialization error: {e}")
            return False
    
    def _run_command(
        self, 
        command: List[str], 
        timeout: Optional[int] = None,
        capture_output: bool = True,
        check_adb: bool = True
    ) -> Dict[str, Any]:
        """
        Execute a command with error handling and logging.
        
        Args:
            command: Command list to execute
            timeout: Command timeout (uses default if None)
            capture_output: Whether to capture stdout/stderr
            check_adb: Whether to verify ADB is available first
            
        Returns:
            Dictionary with success, output, error, and timing info
        """
        start_time = time.time()
        timeout = timeout or self.timeout
        
        # Verify ADB is available for ADB commands
        if check_adb and command[0] == self.adb_path:
            if not self._is_adb_available():
                return {
                    "success": False,
                    "output": "",
                    "error": "ADB not available",
                    "return_code": -1,
                    "execution_time": time.time() - start_time
                }
        
        try:
            self.logger.debug(f"Executing: {' '.join(command)}")
            
            result = subprocess.run(
                command,
                capture_output=capture_output,
                text=True,
                timeout=timeout,
                check=False
            )
            
            execution_time = time.time() - start_time
            
            # Track execution time
            cmd_key = " ".join(command[:2])  # Track by command base
            if cmd_key not in self._execution_times:
                self._execution_times[cmd_key] = []
            self._execution_times[cmd_key].append(execution_time)
            
            # Log command to history
            self._command_history.append({
                "command": command,
                "return_code": result.returncode,
                "execution_time": execution_time,
                "timestamp": time.time()
            })
            
            # Keep only last 100 commands in history
            if len(self._command_history) > 100:
                self._command_history = self._command_history[-100:]
            
            success = result.returncode == 0
            
            response = {
                "success": success,
                "output": result.stdout if capture_output else "",
                "error": result.stderr if capture_output else "",
                "return_code": result.returncode,
                "execution_time": execution_time
            }
            
            if not success:
                self.logger.warning(f"Command failed: {' '.join(command)} - {result.stderr}")
            
            return response
            
        except subprocess.TimeoutExpired:
            self.logger.error(f"Command timeout: {' '.join(command)}")
            return {
                "success": False,
                "output": "",
                "error": f"Command timeout after {timeout}s",
                "return_code": -1,
                "execution_time": time.time() - start_time
            }
        except Exception as e:
            self.logger.error(f"Command execution error: {e}")
            return {
                "success": False,
                "output": "",
                "error": str(e),
                "return_code": -1,
                "execution_time": time.time() - start_time
            }
    
    def _is_adb_available(self) -> bool:
        """Check if ADB executable is available."""
        try:
            result = subprocess.run(
                [self.adb_path, "version"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def discover_devices(self) -> List[ADBDevice]:
        """
        Discover all ADB-connected devices including USB, TCP/IP, and emulators.
        
        Returns:
            List of discovered ADBDevice objects
        """
        devices = []
        
        # Get standard ADB devices
        adb_devices = self._get_adb_devices()
        devices.extend(adb_devices)
        
        # Discover TCP/IP devices on network
        tcp_devices = self._discover_tcp_devices()
        devices.extend(tcp_devices)
        
        # Update device cache
        with self._device_lock:
            self._devices = {d.device_id: d for d in devices}
        
        self.logger.info(f"Discovered {len(devices)} devices")
        return devices
    
    def _get_adb_devices(self) -> List[ADBDevice]:
        """Get devices from ADB device list."""
        devices = []
        
        result = self._run_command([self.adb_path, "devices", "-l"])
        if not result["success"]:
            self.logger.error(f"Failed to get device list: {result['error']}")
            return devices
        
        lines = result["output"].strip().split("\n")
        # Skip header line
        for line in lines[1:]:
            if not line.strip():
                continue
                
            parts = line.split()
            if len(parts) < 2:
                continue
                
            device_id = parts[0]
            status = parts[1]
            
            # Parse additional info
            product = None
            model = None
            device = None
            transport_id = None
            
            for part in parts[2:]:
                if part.startswith("product:"):
                    product = part.split(":", 1)[1]
                elif part.startswith("model:"):
                    model = part.split(":", 1)[1]
                elif part.startswith("device:"):
                    device = part.split(":", 1)[1]
                elif part.startswith("transport_id:"):
                    transport_id = part.split(":", 1)[1]
            
            # Determine device type
            device_type = "unknown"
            if "." in device_id and ":" in device_id:
                device_type = "tcp_ip"
            elif device_id.startswith("emulator"):
                device_type = "emulator"
            elif device_id.startswith("127.") or device_id.startswith("10."):
                device_type = "tcp_ip"
            else:
                device_type = "usb"
            
            # Parse IP for TCP/IP devices
            ip_address = None
            port = None
            if device_type == "tcp_ip" and ":" in device_id:
                ip_port = device_id.split(":")
                if len(ip_port) == 2:
                    ip_address = ip_port[0]
                    try:
                        port = int(ip_port[1])
                    except ValueError:
                        pass
            
            # Check authorization status
            unauthorized = status.lower() == "unauthorized"
            offline = status.lower() == "offline"
            
            device_obj = ADBDevice(
                device_id=device_id,
                status=status,
                device_type=device_type,
                ip_address=ip_address,
                port=port,
                product=product,
                model=model,
                device=device,
                transport_id=transport_id,
                unauthorized=unauthorized,
                offline=offline
            )
            
            devices.append(device_obj)
        
        return devices
    
    def _discover_tcp_devices(self) -> List[ADBDevice]:
        """Discover TCP/IP ADB devices on network."""
        devices = []
        
        # Scan common ADB ports on local network
        # This is a simplified scan - in practice, you'd want to be more thorough
        network_devices = self._scan_network_adb()
        
        for device_info in network_devices:
            device_obj = ADBDevice(
                device_id=f"{device_info['ip']}:{device_info['port']}",
                status=device_info.get("status", "unknown"),
                device_type="tcp_ip",
                ip_address=device_info["ip"],
                port=device_info["port"]
            )
            devices.append(device_obj)
        
        return devices
    
    def _scan_network_adb(self) -> List[Dict[str, Any]]:
        """Scan network for ADB services."""
        devices = []
        
        # Get local IP range
        local_ip = self._get_local_ip()
        if not local_ip:
            return devices
        
        # Scan common ports on localhost and common network ranges
        scan_targets = [
            "127.0.0.1",
            local_ip,
        ]
        
        # Add some common private network ranges
        if local_ip.startswith("192.168."):
            base_ip = local_ip.rsplit(".", 1)[0]
            scan_targets.extend([f"{base_ip}.{i}" for i in range(1, 255)])
        
        # Scan each target
        for target_ip in scan_targets:
            for port in self.COMMON_ADB_PORTS:
                if self._is_port_open(target_ip, port):
                    # Try to connect to ADB
                    if self._test_adb_connection(target_ip, port):
                        devices.append({
                            "ip": target_ip,
                            "port": port,
                            "status": "online"
                        })
                        self.logger.info(f"Found ADB device at {target_ip}:{port}")
        
        return devices
    
    def _get_local_ip(self) -> Optional[str]:
        """Get the local IP address."""
        try:
            # Connect to a remote address to determine local IP
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return None
    
    def _is_port_open(self, ip: str, port: int, timeout: int = 1) -> bool:
        """Check if a port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _test_adb_connection(self, ip: str, port: int) -> bool:
        """Test if a port responds to ADB protocol."""
        try:
            # Try to connect with ADB
            result = self._run_command(
                [self.adb_path, "connect", f"{ip}:{port}"],
                timeout=5
            )
            
            if result["success"]:
                # Check if connection was successful
                if "connected to" in result["output"].lower():
                    return True
                elif "already connected" in result["output"].lower():
                    return True
            
            return False
        except Exception:
            return False
    
    def get_device(self, device_id: str) -> Optional[ADBDevice]:
        """Get device by ID."""
        with self._device_lock:
            return self._devices.get(device_id)
    
    def get_devices(self) -> List[ADBDevice]:
        """Get all discovered devices."""
        with self._device_lock:
            return list(self._devices.values())
    
    def execute_adb_command(
        self, 
        command: List[str], 
        device_id: Optional[str] = None,
        timeout: Optional[int] = None,
        root: bool = False
    ) -> Dict[str, Any]:
        """
        Execute ADB command on specified device.
        
        Args:
            command: ADB command to execute (without 'adb')
            device_id: Target device ID (uses first available if None)
            timeout: Command timeout
            root: Execute with root privileges if available
            
        Returns:
            Command execution result
        """
        if device_id:
            # Use specific device
            adb_cmd = [self.adb_path, "-s", device_id]
        else:
            # Use first available device
            devices = self.get_devices()
            if not devices:
                return {
                    "success": False,
                    "output": "",
                    "error": "No devices available",
                    "return_code": -1,
                    "execution_time": 0
                }
            device_id = devices[0].device_id
            adb_cmd = [self.adb_path, "-s", device_id]
        
        # Add root if requested
        if root:
            adb_cmd.extend(["shell", "su", "-c"])
        else:
            adb_cmd.append("shell")
        
        adb_cmd.extend(command)
        
        return self._run_command(adb_cmd, timeout=timeout)
    
    def get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get comprehensive device information."""
        info = {
            "device_id": device_id,
            "timestamp": time.time(),
            "android_version": None,
            "api_level": None,
            "build_fingerprint": None,
            "manufacturer": None,
            "model": None,
            "product": None,
            "cpu_abi": None,
            "is_rooted": False,
            "has_su": False,
            "selinux_status": None,
            "adb_enabled": True,
            "developer_options": False,
            "usb_debugging": True
        }
        
        # Get Android version
        result = self.execute_adb_command(["getprop", "ro.build.version.release"], device_id)
        if result["success"]:
            info["android_version"] = result["output"].strip()
        
        # Get API level
        result = self.execute_adb_command(["getprop", "ro.build.version.sdk"], device_id)
        if result["success"]:
            try:
                info["api_level"] = int(result["output"].strip())
            except ValueError:
                pass
        
        # Get build fingerprint
        result = self.execute_adb_command(["getprop", "ro.build.fingerprint"], device_id)
        if result["success"]:
            info["build_fingerprint"] = result["output"].strip()
        
        # Get manufacturer
        result = self.execute_adb_command(["getprop", "ro.product.manufacturer"], device_id)
        if result["success"]:
            info["manufacturer"] = result["output"].strip()
        
        # Get model
        result = self.execute_adb_command(["getprop", "ro.product.model"], device_id)
        if result["success"]:
            info["model"] = result["output"].strip()
        
        # Get product
        result = self.execute_adb_command(["getprop", "ro.product.name"], device_id)
        if result["success"]:
            info["product"] = result["output"].strip()
        
        # Get CPU ABI
        result = self.execute_adb_command(["getprop", "ro.product.cpu.abi"], device_id)
        if result["success"]:
            info["cpu_abi"] = result["output"].strip()
        
        # Check for root
        info["is_rooted"] = self._check_root_access(device_id)
        info["has_su"] = self._check_su_binary(device_id)
        
        # Get SELinux status
        result = self.execute_adb_command(["getenforce"], device_id)
        if result["success"]:
            info["selinux_status"] = result["output"].strip().lower()
        
        return info
    
    def _check_root_access(self, device_id: str) -> bool:
        """Check if device has root access."""
        result = self.execute_adb_command(["id"], device_id, root=True)
        if result["success"]:
            return "uid=0" in result["output"]
        return False
    
    def _check_su_binary(self, device_id: str) -> bool:
        """Check if su binary exists."""
        result = self.execute_adb_command(["which", "su"], device_id)
        return result["success"] and result["output"].strip()
    
    def connect_tcp_device(self, ip: str, port: int = 5555) -> bool:
        """Connect to ADB device over TCP/IP."""
        result = self._run_command([self.adb_path, "connect", f"{ip}:{port}"])
        
        if result["success"] and "connected to" in result["output"].lower():
            self.logger.info(f"Connected to {ip}:{port}")
            return True
        else:
            self.logger.error(f"Failed to connect to {ip}:{port}: {result['error']}")
            return False
    
    def disconnect_device(self, device_id: str) -> bool:
        """Disconnect from ADB device."""
        if ":" in device_id:
            # TCP/IP device
            result = self._run_command([self.adb_path, "disconnect", device_id])
            return result["success"]
        else:
            self.logger.info(f"Device {device_id} is not a TCP/IP connection")
            return True
    
    def reboot_device(self, device_id: str) -> bool:
        """Reboot the device."""
        result = self.execute_adb_command(["reboot"], device_id)
        return result["success"]
    
    def remount_system(self, device_id: str, read_write: bool = True) -> bool:
        """Remount system partition."""
        rw_flag = "rw" if read_write else "ro"
        result = self.execute_adb_command(["mount", "-o", f"remount,{rw_flag}", "/system"], 
                                         device_id, root=True)
        return result["success"]
    
    def push_file(self, device_id: str, local_path: str, remote_path: str) -> bool:
        """Push file to device."""
        result = self._run_command([
            self.adb_path, "-s", device_id, "push", local_path, remote_path
        ])
        return result["success"]
    
    def pull_file(self, device_id: str, remote_path: str, local_path: str) -> bool:
        """Pull file from device."""
        # Create local directory if needed
        Path(local_path).parent.mkdir(parents=True, exist_ok=True)
        
        result = self._run_command([
            self.adb_path, "-s", device_id, "pull", remote_path, local_path
        ])
        return result["success"]
    
    def install_apk(self, device_id: str, apk_path: str) -> bool:
        """Install APK on device."""
        result = self._run_command([
            self.adb_path, "-s", device_id, "install", apk_path
        ])
        return result["success"]
    
    def uninstall_package(self, device_id: str, package_name: str) -> bool:
        """Uninstall package from device."""
        result = self._run_command([
            self.adb_path, "-s", device_id, "uninstall", package_name
        ])
        return result["success"]
    
    def get_screenshot(self, device_id: str, output_path: str) -> bool:
        """Take device screenshot."""
        # First take screenshot on device
        result = self.execute_adb_command([
            "screencap", "-p", "/sdcard/screenshot.png"
        ], device_id)
        
        if not result["success"]:
            return False
        
        # Pull screenshot
        return self.pull_file(device_id, "/sdcard/screenshot.png", output_path)
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        stats = {
            "total_commands": len(self._command_history),
            "execution_times": {},
            "average_times": {},
            "error_rate": 0.0
        }
        
        # Calculate average execution times
        for cmd, times in self._execution_times.items():
            if times:
                stats["execution_times"][cmd] = times
                stats["average_times"][cmd] = sum(times) / len(times)
        
        # Calculate error rate
        if self._command_history:
            errors = sum(1 for cmd in self._command_history if not cmd["success"])
            stats["error_rate"] = errors / len(self._command_history)
        
        return stats
    
    def cleanup(self) -> None:
        """Clean up resources."""
        self.logger.info("Cleaning up ADB manager")
        
        # Disconnect from TCP/IP devices
        for device in self.get_devices():
            if device.device_type == "tcp_ip":
                self.disconnect_device(device.device_id)
        
        # Stop ADB server
        self._run_command([self.adb_path, "kill-server"])