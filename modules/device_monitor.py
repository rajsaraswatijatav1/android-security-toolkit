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

import time
import threading
import subprocess
from typing import Dict, List, Optional, Any, Callable
from pathlib import Path
import json

from core.base_scanner import BaseScanner


class DeviceMonitor(BaseScanner):
    """
    Real-time Android device monitoring and alerting system.
    
    Monitors:
    - Device connections/disconnections
    - New device detection
    - Suspicious activities
    - Network changes
    - App installations
    - System modifications
    
    Provides:
    - Real-time alerts
    - Webhook notifications
    - Email alerts
    - JSON logging
    """
    
    def __init__(self, device_id: Optional[str] = None, 
                 webhook_url: Optional[str] = None,
                 email_config: Optional[Dict[str, Any]] = None):
        """
        Initialize device monitor.
        
        Args:
            device_id: Device to monitor (None for all devices)
            webhook_url: Webhook URL for alerts
            email_config: Email configuration for alerts
        """
        super().__init__("DeviceMonitor", device_id=device_id)
        
        self.monitoring = False
        self.monitor_thread = None
        self.known_devices = set()
        self.alert_callbacks = []
        
        # Alert configuration
        self.webhook_url = webhook_url
        self.email_config = email_config
        
        # Monitoring intervals (seconds)
        self.device_check_interval = 5
        self.activity_check_interval = 10
        
        # Monitoring state
        self.last_device_check = 0
        self.last_activity_check = 0
        
        # Log file
        self.monitor_log = Path("loot") / "device_monitor.jsonl"
        self.monitor_log.parent.mkdir(exist_ok=True)
        
        # Activity tracking
        self.activity_log = []
        self.max_log_entries = 1000
    
    def start_monitoring(self) -> bool:
        """Start device monitoring."""
        if self.monitoring:
            self.logger.warning("Monitoring already active")
            return False
        
        self.monitoring = True
        self.logger.info("Starting device monitoring")
        
        # Initialize known devices
        self._update_known_devices()
        
        # Start monitoring thread
        self.monitor_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.monitor_thread.start()
        
        self.log_finding(
            "INFO",
            "Device Monitoring Started",
            "Real-time device monitoring activated",
            {
                "device_check_interval": self.device_check_interval,
                "activity_check_interval": self.activity_check_interval,
                "known_devices": len(self.known_devices)
            },
            "Device monitoring active"
        )
        
        return True
    
    def stop_monitoring(self) -> bool:
        """Stop device monitoring."""
        if not self.monitoring:
            self.logger.warning("Monitoring not active")
            return False
        
        self.monitoring = False
        
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        self.logger.info("Device monitoring stopped")
        return True
    
    def _monitoring_loop(self) -> None:
        """Main monitoring loop."""
        while self.monitoring:
            current_time = time.time()
            
            # Check for device changes
            if current_time - self.last_device_check >= self.device_check_interval:
                self._check_device_changes()
                self.last_device_check = current_time
            
            # Check for suspicious activities
            if current_time - self.last_activity_check >= self.activity_check_interval:
                self._check_suspicious_activity()
                self.last_activity_check = current_time
            
            time.sleep(1)
        
        self.logger.info("Monitoring loop ended")
    
    def _update_known_devices(self) -> None:
        """Update list of known devices."""
        try:
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                self.known_devices = set()
                
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('*'):
                        device_id = line.split()[0]
                        self.known_devices.add(device_id)
            
        except Exception as e:
            self.logger.error(f"Device update error: {e}")
    
    def _check_device_changes(self) -> None:
        """Check for device connection/disconnection changes."""
        try:
            current_devices = set()
            
            # Get current devices
            result = subprocess.run(
                ["adb", "devices"],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines[1:]:  # Skip header
                    if line.strip() and not line.startswith('*'):
                        device_id = line.split()[0]
                        current_devices.add(device_id)
            
            # Check for new devices
            new_devices = current_devices - self.known_devices
            for device_id in new_devices:
                self._handle_new_device(device_id)
            
            # Check for disconnected devices
            disconnected_devices = self.known_devices - current_devices
            for device_id in disconnected_devices:
                self._handle_disconnected_device(device_id)
            
            # Update known devices
            self.known_devices = current_devices
            
        except Exception as e:
            self.logger.error(f"Device change check error: {e}")
    
    def _handle_new_device(self, device_id: str) -> None:
        """Handle new device connection."""
        event = {
            "timestamp": time.time(),
            "event_type": "device_connected",
            "device_id": device_id,
            "severity": "INFO"
        }
        
        self._log_activity(event)
        
        # Get device info
        device_info = self._get_device_info(device_id)
        event["device_info"] = device_info
        
        self.log_finding(
            "INFO",
            f"New Device Connected: {device_id}",
            f"New Android device connected: {device_info.get('model', 'Unknown')}",
            event,
            "New device detected - verify authorization"
        )
        
        # Send alert
        self._send_alert(event)
    
    def _handle_disconnected_device(self, device_id: str) -> None:
        """Handle device disconnection."""
        event = {
            "timestamp": time.time(),
            "event_type": "device_disconnected",
            "device_id": device_id,
            "severity": "INFO"
        }
        
        self._log_activity(event)
        
        self.log_finding(
            "INFO",
            f"Device Disconnected: {device_id}",
            f"Android device disconnected",
            event,
            "Device disconnected"
        )
        
        # Send alert
        self._send_alert(event)
    
    def _get_device_info(self, device_id: str) -> Dict[str, Any]:
        """Get device information."""
        info = {}
        
        try:
            # Get basic device properties
            props = [
                ("ro.product.manufacturer", "manufacturer"),
                ("ro.product.model", "model"),
                ("ro.build.version.release", "android_version"),
                ("ro.build.version.security_patch", "security_patch"),
                ("ro.serialno", "serial_number")
            ]
            
            for prop, key in props:
                result = subprocess.run(
                    ["adb", "-s", device_id, "shell", "getprop", prop],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    info[key] = result.stdout.strip()
            
            # Check if device is authorized
            result = subprocess.run(
                ["adb", "-s", device_id, "shell", "echo", "test"],
                capture_output=True, text=True, timeout=5
            )
            
            info["authorized"] = result.returncode == 0
            
        except Exception as e:
            self.logger.debug(f"Device info error for {device_id}: {e}")
        
        return info
    
    def _check_suspicious_activity(self) -> None:
        """Check for suspicious device activity."""
        try:
            # Check for unusual ADB activity
            self._check_adb_activity()
            
            # Check for app installations
            self._check_app_changes()
            
            # Check for system modifications
            self._check_system_changes()
            
        except Exception as e:
            self.logger.error(f"Suspicious activity check error: {e}")
    
    def _check_adb_activity(self) -> None:
        """Check for suspicious ADB activity."""
        try:
            # Check ADB authorization state
            for device_id in self.known_devices:
                result = subprocess.run(
                    ["adb", "-s", device_id, "shell", "getprop", "ro.adb.secure"],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0:
                    secure_adb = result.stdout.strip()
                    if secure_adb == "0":
                        event = {
                            "timestamp": time.time(),
                            "event_type": "insecure_adb",
                            "device_id": device_id,
                            "severity": "HIGH",
                            "details": {"secure_adb": secure_adb}
                        }
                        
                        self._log_activity(event)
                        
                        self.log_finding(
                            "HIGH",
                            f"Insecure ADB: {device_id}",
                            "Device has insecure ADB configuration",
                            event,
                            "Enable ADB security verification"
                        )
                        
                        self._send_alert(event)
            
        except Exception as e:
            self.logger.debug(f"ADB activity check error: {e}")
    
    def _check_app_changes(self) -> None:
        """Check for app installation/removal."""
        try:
            # Get current app list
            for device_id in self.known_devices:
                result = subprocess.run(
                    ["adb", "-s", device_id, "shell", "pm", "list", "packages"],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    current_apps = set()
                    for line in result.stdout.strip().split('\n'):
                        if line.startswith('package:'):
                            current_apps.add(line[8:])  # Remove 'package:' prefix
                    
                    # This is simplified - real implementation would track app changes over time
                    if len(current_apps) > 100:  # Arbitrary threshold
                        event = {
                            "timestamp": time.time(),
                            "event_type": "many_apps_installed",
                            "device_id": device_id,
                            "severity": "MEDIUM",
                            "details": {"app_count": len(current_apps)}
                        }
                        
                        self._log_activity(event)
            
        except Exception as e:
            self.logger.debug(f"App changes check error: {e}")
    
    def _check_system_changes(self) -> None:
        """Check for system modifications."""
        try:
            # Check for rooted devices
            for device_id in self.known_devices:
                result = subprocess.run(
                    ["adb", "-s", device_id, "shell", "which", "su"],
                    capture_output=True, text=True, timeout=5
                )
                
                if result.returncode == 0 and result.stdout.strip():
                    event = {
                        "timestamp": time.time(),
                        "event_type": "root_detected",
                        "device_id": device_id,
                        "severity": "HIGH",
                        "details": {"su_path": result.stdout.strip()}
                    }
                    
                    self._log_activity(event)
                    
                    self.log_finding(
                        "HIGH",
                        f"Root Detected: {device_id}",
                        "Device appears to be rooted",
                        event,
                        "Rooted devices may have security implications"
                    )
                    
                    self._send_alert(event)
            
        except Exception as e:
            self.logger.debug(f"System changes check error: {e}")
    
    def _log_activity(self, event: Dict[str, Any]) -> None:
        """Log monitoring activity."""
        try:
            # Add to activity log
            self.activity_log.append(event)
            
            # Keep only recent entries
            if len(self.activity_log) > self.max_log_entries:
                self.activity_log = self.activity_log[-self.max_log_entries:]
            
            # Write to log file
            with open(self.monitor_log, 'a') as f:
                f.write(json.dumps(event) + '\n')
            
        except Exception as e:
            self.logger.debug(f"Activity logging error: {e}")
    
    def _send_alert(self, event: Dict[str, Any]) -> None:
        """Send alert via configured channels."""
        try:
            # Webhook alert
            if self.webhook_url and event["severity"] in ["HIGH", "CRITICAL"]:
                self._send_webhook_alert(event)
            
            # Email alert
            if self.email_config and event["severity"] in ["HIGH", "CRITICAL"]:
                self._send_email_alert(event)
            
            # Callback alerts
            for callback in self.alert_callbacks:
                try:
                    callback(event)
                except Exception as e:
                    self.logger.debug(f"Alert callback error: {e}")
            
        except Exception as e:
            self.logger.debug(f"Alert sending error: {e}")
    
    def _send_webhook_alert(self, event: Dict[str, Any]) -> None:
        """Send webhook alert."""
        try:
            import requests
            
            payload = {
                "event": event,
                "timestamp": time.time(),
                "source": "android_security_toolkit"
            }
            
            response = requests.post(self.webhook_url, json=payload, timeout=10)
            response.raise_for_status()
            
            self.logger.info(f"Webhook alert sent for {event['event_type']}")
            
        except Exception as e:
            self.logger.debug(f"Webhook alert error: {e}")
    
    def _send_email_alert(self, event: Dict[str, Any]) -> None:
        """Send email alert."""
        try:
            import smtplib
            from email.mime.text import MIMEText
            
            subject = f"Android Security Alert: {event['event_type']}"
            body = json.dumps(event, indent=2)
            
            msg = MIMEText(body)
            msg['Subject'] = subject
            msg['From'] = self.email_config.get('from')
            msg['To'] = self.email_config.get('to')
            
            server = smtplib.SMTP(self.email_config.get('smtp_server', 'localhost'))
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Email alert sent for {event['event_type']}")
            
        except Exception as e:
            self.logger.debug(f"Email alert error: {e}")
    
    def add_alert_callback(self, callback: Callable[[Dict[str, Any]], None]) -> None:
        """Add callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def get_activity_log(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent activity log."""
        return self.activity_log[-limit:]
    
    def get_monitoring_stats(self) -> Dict[str, Any]:
        """Get monitoring statistics."""
        return {
            "monitoring_active": self.monitoring,
            "known_devices": len(self.known_devices),
            "activity_log_entries": len(self.activity_log),
            "alert_callbacks": len(self.alert_callbacks),
            "monitoring_duration": time.time() - self.metrics["start_time"] if self.monitoring else 0
        }