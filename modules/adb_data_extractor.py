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
import sqlite3
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any
import xml.etree.ElementTree as ET

from core.base_scanner import BaseScanner
from core.adb_manager import ADBManager


class ADBDataExtractor(BaseScanner):
    """
    Comprehensive ADB data extraction module for Android devices.
    
    Extracts:
    - SMS messages
    - Contacts
    - Call logs
    - Application data
    - WiFi passwords
    - Browser history
    - System logs
    - File system structure
    
    Supports both root and non-root scenarios.
    """
    
    def __init__(self, device_id: Optional[str] = None, output_dir: str = "loot/extracted_data"):
        """
        Initialize data extractor.
        
        Args:
            device_id: Target device ID
            output_dir: Directory for extracted data
        """
        super().__init__("ADBDataExtractor", device_id=device_id)
        self.adb_manager = ADBManager()
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.has_root = False
        self.extraction_results = {}
    
    def extract_all(self) -> Dict[str, Any]:
        """
        Extract all available data from device.
        
        Returns:
            Dictionary containing extraction results
        """
        self.logger.info(f"Starting data extraction from {self.device_id}")
        
        try:
            # Check root access
            self.has_root = self._check_root_access()
            
            # Extract different data types
            self.extract_sms()
            self.extract_contacts()
            self.extract_call_logs()
            self.extract_wifi_passwords()
            self.extract_browser_history()
            self.extract_app_list()
            self.extract_system_info()
            self.extract_file_structure()
            
            # Generate summary
            summary = self._generate_extraction_summary()
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Data extraction failed: {e}")
            self.log_finding(
                "ERROR",
                "Data Extraction Failed",
                f"Data extraction failed with error: {str(e)}",
                {"error": str(e), "device_id": self.device_id},
                "Check device connectivity and permissions"
            )
            return self.extraction_results
    
    def _check_root_access(self) -> bool:
        """Check if device has root access."""
        try:
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "su", "-c", "id"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0 and "uid=0" in result.stdout
        except Exception:
            return False
    
    def extract_sms(self) -> List[Dict[str, Any]]:
        """Extract SMS messages from device."""
        self.logger.info("Extracting SMS messages")
        
        sms_data = []
        
        try:
            # Try to pull SMS database
            sms_db_path = "/data/data/com.android.providers.telephony/databases/mmssms.db"
            local_db_path = self.output_dir / "sms.db"
            
            if self.has_root:
                # Copy database with root access
                subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "su", "-c", 
                     f"cp {sms_db_path} /sdcard/sms.db"],
                    capture_output=True, timeout=10
                )
                
                subprocess.run(
                    ["adb", "-s", self.device_id, "pull", "/sdcard/sms.db", str(local_db_path)],
                    capture_output=True, timeout=30
                )
            else:
                # Try without root (may not work on newer Android versions)
                subprocess.run(
                    ["adb", "-s", self.device_id, "pull", sms_db_path, str(local_db_path)],
                    capture_output=True, timeout=30
                )
            
            # Parse SMS database
            if local_db_path.exists():
                conn = sqlite3.connect(local_db_path)
                cursor = conn.cursor()
                
                # Query SMS table
                cursor.execute("""
                    SELECT _id, thread_id, address, person, date, 
                           protocol, read, status, type, reply_path_present,
                           subject, body, service_center, locked
                    FROM sms
                    ORDER BY date DESC
                """)
                
                for row in cursor.fetchall():
                    sms_record = {
                        "id": row[0],
                        "thread_id": row[1],
                        "address": row[2],  # Phone number
                        "person": row[3],
                        "date": row[4],
                        "protocol": row[5],
                        "read": row[6],
                        "status": row[7],
                        "type": row[8],  # 1 = received, 2 = sent
                        "reply_path_present": row[9],
                        "subject": row[10],
                        "body": row[11],  # Message content
                        "service_center": row[12],
                        "locked": row[13]
                    }
                    sms_data.append(sms_record)
                
                conn.close()
                
                self.logger.info(f"Extracted {len(sms_data)} SMS messages")
                
                # Save to JSON
                sms_file = self.output_dir / "sms.json"
                with open(sms_file, 'w') as f:
                    json.dump(sms_data, f, indent=2)
                
                self.log_finding(
                    "INFO",
                    f"SMS Extraction Complete: {len(sms_data)} messages",
                    f"Successfully extracted {len(sms_data)} SMS messages",
                    {"count": len(sms_data), "has_root": self.has_root},
                    "SMS data extracted for analysis"
                )
            
        except Exception as e:
            self.logger.error(f"SMS extraction error: {e}")
            self.log_finding(
                "WARNING",
                "SMS Extraction Failed",
                f"Failed to extract SMS messages: {str(e)}",
                {"error": str(e), "has_root": self.has_root},
                "Requires root access or proper permissions"
            )
        
        self.extraction_results["sms"] = sms_data
        return sms_data
    
    def extract_contacts(self) -> List[Dict[str, Any]]:
        """Extract contacts from device."""
        self.logger.info("Extracting contacts")
        
        contacts_data = []
        
        try:
            # Try to pull contacts database
            contacts_db_path = "/data/data/com.android.providers.contacts/databases/contacts2.db"
            local_db_path = self.output_dir / "contacts.db"
            
            if self.has_root:
                # Copy database with root access
                subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "su", "-c",
                     f"cp {contacts_db_path} /sdcard/contacts.db"],
                    capture_output=True, timeout=10
                )
                
                subprocess.run(
                    ["adb", "-s", self.device_id, "pull", "/sdcard/contacts.db", str(local_db_path)],
                    capture_output=True, timeout=30
                )
            else:
                # Try alternative method via content provider
                result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "content", "query",
                     "--uri", "content://contacts/people"],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    # Parse content provider output
                    lines = result.stdout.strip().split('\n')
                    for line in lines:
                        if 'Row:' in line:
                            # Parse contact information
                            contact_info = self._parse_contact_line(line)
                            if contact_info:
                                contacts_data.append(contact_info)
            
            # Parse contacts database if available
            if local_db_path.exists():
                conn = sqlite3.connect(local_db_path)
                cursor = conn.cursor()
                
                # Query contacts
                cursor.execute("""
                    SELECT _id, display_name, sort_key, photo_id,
                           send_to_voicemail, times_contacted, last_time_contacted,
                           starred, in_visible_group, has_phone_number
                    FROM contacts
                    ORDER BY display_name
                """)
                
                for row in cursor.fetchall():
                    contact_record = {
                        "id": row[0],
                        "display_name": row[1],
                        "sort_key": row[2],
                        "photo_id": row[3],
                        "send_to_voicemail": row[4],
                        "times_contacted": row[5],
                        "last_time_contacted": row[6],
                        "starred": row[7],
                        "in_visible_group": row[8],
                        "has_phone_number": row[9]
                    }
                    
                    # Get phone numbers for this contact
                    cursor.execute("""
                        SELECT number, type, label
                        FROM phone_lookup
                        WHERE contact_id = ?
                    """, (row[0],))
                    
                    phone_numbers = []
                    for phone_row in cursor.fetchall():
                        phone_numbers.append({
                            "number": phone_row[0],
                            "type": phone_row[1],
                            "label": phone_row[2]
                        })
                    
                    contact_record["phone_numbers"] = phone_numbers
                    contacts_data.append(contact_record)
                
                conn.close()
                
                self.logger.info(f"Extracted {len(contacts_data)} contacts")
                
                # Save to JSON
                contacts_file = self.output_dir / "contacts.json"
                with open(contacts_file, 'w') as f:
                    json.dump(contacts_data, f, indent=2)
                
                self.log_finding(
                    "INFO",
                    f"Contacts Extraction Complete: {len(contacts_data)} contacts",
                    f"Successfully extracted {len(contacts_data)} contacts",
                    {"count": len(contacts_data), "has_root": self.has_root},
                    "Contact data extracted for analysis"
                )
            
        except Exception as e:
            self.logger.error(f"Contacts extraction error: {e}")
        
        self.extraction_results["contacts"] = contacts_data
        return contacts_data
    
    def extract_call_logs(self) -> List[Dict[str, Any]]:
        """Extract call logs from device."""
        self.logger.info("Extracting call logs")
        
        call_logs = []
        
        try:
            # Try to pull call log database
            calls_db_path = "/data/data/com.android.providers.contacts/databases/contacts2.db"
            local_db_path = self.output_dir / "calls.db"
            
            if self.has_root:
                # Copy database with root access
                subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "su", "-c",
                     f"cp {calls_db_path} /sdcard/calls.db"],
                    capture_output=True, timeout=10
                )
                
                subprocess.run(
                    ["adb", "-s", self.device_id, "pull", "/sdcard/calls.db", str(local_db_path)],
                    capture_output=True, timeout=30
                )
            
            # Parse call log database if available
            if local_db_path.exists():
                conn = sqlite3.connect(local_db_path)
                cursor = conn.cursor()
                
                # Query call logs
                cursor.execute("""
                    SELECT _id, number, date, duration, type, new,
                           name, numbertype, numberlabel
                    FROM calls
                    ORDER BY date DESC
                """)
                
                for row in cursor.fetchall():
                    call_record = {
                        "id": row[0],
                        "number": row[1],
                        "date": row[2],
                        "duration": row[3],  # Duration in seconds
                        "type": row[4],  # 1 = incoming, 2 = outgoing, 3 = missed
                        "new": row[5],
                        "name": row[6],
                        "number_type": row[7],
                        "number_label": row[8]
                    }
                    call_logs.append(call_record)
                
                conn.close()
                
                self.logger.info(f"Extracted {len(call_logs)} call logs")
                
                # Save to JSON
                calls_file = self.output_dir / "call_logs.json"
                with open(calls_file, 'w') as f:
                    json.dump(call_logs, f, indent=2)
                
                self.log_finding(
                    "INFO",
                    f"Call Logs Extraction Complete: {len(call_logs)} calls",
                    f"Successfully extracted {len(call_logs)} call logs",
                    {"count": len(call_logs), "has_root": self.has_root},
                    "Call log data extracted for analysis"
                )
            
        except Exception as e:
            self.logger.error(f"Call logs extraction error: {e}")
        
        self.extraction_results["call_logs"] = call_logs
        return call_logs
    
    def extract_wifi_passwords(self) -> List[Dict[str, Any]]:
        """Extract WiFi passwords from device."""
        self.logger.info("Extracting WiFi passwords")
        
        wifi_networks = []
        
        try:
            # WiFi passwords require root access
            if not self.has_root:
                self.logger.warning("WiFi password extraction requires root access")
                return wifi_networks
            
            # Pull WiFi configuration file
            wifi_config_path = "/data/misc/wifi/wpa_supplicant.conf"
            local_config_path = self.output_dir / "wpa_supplicant.conf"
            
            subprocess.run(
                ["adb", "-s", self.device_id, "shell", "su", "-c",
                 f"cp {wifi_config_path} /sdcard/wifi.conf"],
                capture_output=True, timeout=10
            )
            
            subprocess.run(
                ["adb", "-s", self.device_id, "pull", "/sdcard/wifi.conf", str(local_config_path)],
                capture_output=True, timeout=30
            )
            
            # Parse WiFi configuration
            if local_config_path.exists():
                with open(local_config_path, 'r') as f:
                    content = f.read()
                
                # Extract network configurations
                network_blocks = re.findall(
                    r'network=\{(.*?)\}',
                    content,
                    re.DOTALL
                )
                
                for block in network_blocks:
                    network_info = {}
                    
                    # Extract SSID
                    ssid_match = re.search(r'ssid="([^"]*)"', block)
                    if ssid_match:
                        network_info["ssid"] = ssid_match.group(1)
                    
                    # Extract password
                    psk_match = re.search(r'psk="([^"]*)"', block)
                    if psk_match:
                        network_info["password"] = psk_match.group(1)
                    
                    # Extract key management
                    key_mgmt_match = re.search(r'key_mgmt=([^\s]+)', block)
                    if key_mgmt_match:
                        network_info["key_mgmt"] = key_mgmt_match.group(1)
                    
                    # Extract priority
                    priority_match = re.search(r'priority=(\d+)', block)
                    if priority_match:
                        network_info["priority"] = int(priority_match.group(1))
                    
                    if network_info:
                        wifi_networks.append(network_info)
                
                self.logger.info(f"Extracted {len(wifi_networks)} WiFi networks")
                
                # Save to JSON
                wifi_file = self.output_dir / "wifi_networks.json"
                with open(wifi_file, 'w') as f:
                    json.dump(wifi_networks, f, indent=2)
                
                # Log critical finding for WiFi passwords
                if wifi_networks:
                    self.log_finding(
                        "CRITICAL",
                        f"WiFi Passwords Extracted: {len(wifi_networks)} networks",
                        f"Extracted WiFi passwords for {len(wifi_networks)} networks",
                        {"count": len(wifi_networks), "networks": [net["ssid"] for net in wifi_networks[:5]]},
                        "WiFi passwords extracted - handle with extreme care"
                    )
            
        except Exception as e:
            self.logger.error(f"WiFi passwords extraction error: {e}")
        
        self.extraction_results["wifi_networks"] = wifi_networks
        return wifi_networks
    
    def extract_browser_history(self) -> List[Dict[str, Any]]:
        """Extract browser history from device."""
        self.logger.info("Extracting browser history")
        
        browser_history = []
        
        try:
            # Try different browser databases
            browsers = [
                {
                    "name": "Chrome",
                    "db_path": "/data/data/com.android.chrome/app_chrome/Default/History",
                    "table": "urls"
                },
                {
                    "name": "Firefox",
                    "db_path": "/data/data/org.mozilla.firefox/files/mozilla/default/places.sqlite",
                    "table": "moz_places"
                },
                {
                    "name": "Stock Browser",
                    "db_path": "/data/data/com.android.browser/databases/browser.db",
                    "table": "bookmarks"
                }
            ]
            
            for browser in browsers:
                try:
                    local_db_path = self.output_dir / f"{browser['name'].lower()}_history.db"
                    
                    if self.has_root:
                        # Copy database with root access
                        subprocess.run(
                            ["adb", "-s", self.device_id, "shell", "su", "-c",
                             f"cp {browser['db_path']} /sdcard/{browser['name'].lower()}_history.db"],
                            capture_output=True, timeout=10
                        )
                        
                        subprocess.run(
                            ["adb", "-s", self.device_id, "pull", 
                             f"/sdcard/{browser['name'].lower()}_history.db", str(local_db_path)],
                            capture_output=True, timeout=30
                        )
                    
                    # Parse browser database if available
                    if local_db_path.exists():
                        conn = sqlite3.connect(local_db_path)
                        cursor = conn.cursor()
                        
                        if browser['name'] == "Chrome":
                            cursor.execute("""
                                SELECT url, title, visit_count, typed_count,
                                       last_visit_time, hidden
                                FROM urls
                                ORDER BY last_visit_time DESC
                            """)
                            
                            for row in cursor.fetchall():
                                history_record = {
                                    "browser": browser['name'],
                                    "url": row[0],
                                    "title": row[1],
                                    "visit_count": row[2],
                                    "typed_count": row[3],
                                    "last_visit_time": row[4],
                                    "hidden": row[5]
                                }
                                browser_history.append(history_record)
                        
                        conn.close()
                
                except Exception as e:
                    self.logger.debug(f"{browser['name']} history extraction error: {e}")
                    continue
            
            self.logger.info(f"Extracted {len(browser_history)} browser history entries")
            
            # Save to JSON
            history_file = self.output_dir / "browser_history.json"
            with open(history_file, 'w') as f:
                json.dump(browser_history, f, indent=2)
            
            self.log_finding(
                "INFO",
                f"Browser History Extraction Complete: {len(browser_history)} entries",
                f"Successfully extracted {len(browser_history)} browser history entries",
                {"count": len(browser_history), "has_root": self.has_root},
                "Browser history extracted for analysis"
            )
        
        except Exception as e:
            self.logger.error(f"Browser history extraction error: {e}")
        
        self.extraction_results["browser_history"] = browser_history
        return browser_history
    
    def extract_app_list(self) -> List[Dict[str, Any]]:
        """Extract list of installed applications."""
        self.logger.info("Extracting installed applications")
        
        app_list = []
        
        try:
            # Get list of installed packages
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "pm", "list", "packages", "-f"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines:
                    if line.startswith('package:'):
                        parts = line[8:].split('=')  # Remove 'package:' prefix
                        if len(parts) == 2:
                            apk_path = parts[0]
                            package_name = parts[1]
                            
                            app_info = {
                                "package_name": package_name,
                                "apk_path": apk_path
                            }
                            
                            # Get app details
                            try:
                                app_details = self._get_app_details(package_name)
                                app_info.update(app_details)
                            except Exception:
                                pass
                            
                            app_list.append(app_info)
                
                self.logger.info(f"Extracted {len(app_list)} installed applications")
                
                # Save to JSON
                apps_file = self.output_dir / "installed_apps.json"
                with open(apps_file, 'w') as f:
                    json.dump(app_list, f, indent=2)
                
                self.log_finding(
                    "INFO",
                    f"App List Extraction Complete: {len(app_list)} apps",
                    f"Successfully extracted {len(app_list)} installed applications",
                    {"count": len(app_list)},
                    "Application list extracted for analysis"
                )
        
        except Exception as e:
            self.logger.error(f"App list extraction error: {e}")
        
        self.extraction_results["installed_apps"] = app_list
        return app_list
    
    def _get_app_details(self, package_name: str) -> Dict[str, Any]:
        """Get detailed information about an app."""
        details = {}
        
        try:
            # Get app info
            result = subprocess.run(
                ["adb", "-s", self.device_id, "shell", "dumpsys", "package", package_name],
                capture_output=True, text=True, timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse relevant information
                version_match = re.search(r'versionName=([^\s]+)', output)
                if version_match:
                    details["version_name"] = version_match.group(1)
                
                version_code_match = re.search(r'versionCode=([^\s]+)', output)
                if version_code_match:
                    details["version_code"] = version_code_match.group(1)
                
                # Check if system app
                is_system = "/system/" in output or "/vendor/" in output
                details["is_system_app"] = is_system
                
                # Check if enabled
                is_enabled = "enabled=" in output
                details["is_enabled"] = is_enabled
        
        except Exception:
            pass
        
        return details
    
    def extract_system_info(self) -> Dict[str, Any]:
        """Extract system information from device."""
        self.logger.info("Extracting system information")
        
        system_info = {}
        
        try:
            # Get various system properties
            properties = [
                "ro.build.version.release",      # Android version
                "ro.build.version.sdk",          # API level
                "ro.build.fingerprint",          # Build fingerprint
                "ro.product.manufacturer",       # Manufacturer
                "ro.product.model",              # Model
                "ro.product.brand",              # Brand
                "ro.serialno",                   # Serial number
                "ro.bootloader",                 # Bootloader version
                "ro.kernel.version",             # Kernel version
                "ro.security.patch",             # Security patch level
                "ro.build.id",                   # Build ID
                "ro.build.type",                 # Build type
                "ro.build.tags",                 # Build tags
                "ro.build.user",                 # Build user
                "ro.build.host",                 # Build host
                "ro.debuggable",                 # Debuggable
                "ro.secure",                     # Secure boot
                "persist.sys.usb.config",        # USB configuration
            ]
            
            for prop in properties:
                try:
                    result = subprocess.run(
                        ["adb", "-s", self.device_id, "shell", "getprop", prop],
                        capture_output=True, text=True, timeout=5
                    )
                    
                    if result.returncode == 0:
                        system_info[prop] = result.stdout.strip()
                
                except Exception:
                    continue
            
            # Get additional system information
            try:
                # Get CPU information
                cpu_result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "cat", "/proc/cpuinfo"],
                    capture_output=True, text=True, timeout=10
                )
                
                if cpu_result.returncode == 0:
                    system_info["cpu_info"] = cpu_result.stdout
                
                # Get memory information
                mem_result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "cat", "/proc/meminfo"],
                    capture_output=True, text=True, timeout=10
                )
                
                if mem_result.returncode == 0:
                    system_info["mem_info"] = mem_result.stdout
                
                # Get disk space
                df_result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "df", "-h"],
                    capture_output=True, text=True, timeout=10
                )
                
                if df_result.returncode == 0:
                    system_info["disk_usage"] = df_result.stdout
                
                # Get running processes
                ps_result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "ps"],
                    capture_output=True, text=True, timeout=10
                )
                
                if ps_result.returncode == 0:
                    process_lines = ps_result.stdout.strip().split('\n')
                    system_info["process_count"] = len(process_lines) - 1  # Subtract header
                
                # Get network interfaces
                net_result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "ifconfig"],
                    capture_output=True, text=True, timeout=10
                )
                
                if net_result.returncode == 0:
                    system_info["network_interfaces"] = net_result.stdout
            
            except Exception as e:
                self.logger.debug(f"Additional system info error: {e}")
            
            # Save to JSON
            system_file = self.output_dir / "system_info.json"
            with open(system_file, 'w') as f:
                json.dump(system_info, f, indent=2)
            
            self.log_finding(
                "INFO",
                "System Information Extraction Complete",
                f"Successfully extracted system information",
                {"properties_count": len(system_info)},
                "System information extracted for analysis"
            )
        
        except Exception as e:
            self.logger.error(f"System info extraction error: {e}")
        
        self.extraction_results["system_info"] = system_info
        return system_info
    
    def extract_file_structure(self) -> Dict[str, Any]:
        """Extract device file system structure."""
        self.logger.info("Extracting file system structure")
        
        file_structure = {
            "directories": [],
            "files": [],
            "total_size": 0
        }
        
        try:
            # List common directories
            directories = [
                "/system",
                "/vendor", 
                "/data",
                "/sdcard",
                "/storage"
            ]
            
            for directory in directories:
                try:
                    result = subprocess.run(
                        ["adb", "-s", self.device_id, "shell", "ls", "-la", directory],
                        capture_output=True, text=True, timeout=15
                    )
                    
                    if result.returncode == 0:
                        file_structure["directories"].append({
                            "path": directory,
                            "listing": result.stdout
                        })
                
                except Exception as e:
                    self.logger.debug(f"Directory listing error for {directory}: {e}")
                    continue
            
            # Save to JSON
            structure_file = self.output_dir / "file_structure.json"
            with open(structure_file, 'w') as f:
                json.dump(file_structure, f, indent=2)
            
            self.log_finding(
                "INFO",
                "File Structure Extraction Complete",
                f"Successfully extracted file system structure",
                {"directories": len(file_structure["directories"])},
                "File structure extracted for analysis"
            )
        
        except Exception as e:
            self.logger.error(f"File structure extraction error: {e}")
        
        self.extraction_results["file_structure"] = file_structure
        return file_structure
    
    def _parse_contact_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse contact information from content provider output."""
        try:
            # Simple parsing - could be enhanced
            if 'display_name=' in line:
                parts = line.split(', ')
                contact = {}
                for part in parts:
                    if '=' in part:
                        key, value = part.split('=', 1)
                        contact[key.strip()] = value.strip()
                return contact
        except Exception:
            pass
        return None
    
    def _generate_extraction_summary(self) -> Dict[str, Any]:
        """Generate summary of data extraction."""
        summary = {
            "extraction_timestamp": time.time(),
            "device_id": self.device_id,
            "has_root": self.has_root,
            "output_directory": str(self.output_dir),
            "data_types": {},
            "total_records": 0
        }
        
        total_records = 0
        
        for data_type, data in self.extraction_results.items():
            if isinstance(data, list):
                count = len(data)
                summary["data_types"][data_type] = count
                total_records += count
            elif isinstance(data, dict):
                summary["data_types"][data_type] = len(data)
                total_records += len(data)
        
        summary["total_records"] = total_records
        
        # Save summary
        summary_file = self.output_dir / "extraction_summary.json"
        with open(summary_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        self.logger.info(f"Data extraction complete: {total_records} total records")
        
        return summary
    
    def extract_app_data(self, package_name: str) -> Dict[str, Any]:
        """Extract data for specific application."""
        self.logger.info(f"Extracting data for app: {package_name}")
        
        app_data = {
            "package_name": package_name,
            "files": [],
            "databases": [],
            "shared_preferences": []
        }
        
        try:
            # Get app data directory
            app_data_path = f"/data/data/{package_name}"
            
            if self.has_root:
                # List app files with root access
                result = subprocess.run(
                    ["adb", "-s", self.device_id, "shell", "su", "-c",
                     f"find {app_data_path} -type f"],
                    capture_output=True, text=True, timeout=30
                )
                
                if result.returncode == 0:
                    files = result.stdout.strip().split('\n')
                    
                    for file_path in files:
                        if file_path.strip():
                            app_data["files"].append(file_path.strip())
            
            # Try to pull specific files
            target_files = [
                "databases/",
                "shared_prefs/",
                "files/",
                "cache/"
            ]
            
            for target in target_files:
                try:
                    remote_path = f"{app_data_path}/{target}"
                    local_path = self.output_dir / package_name / target
                    local_path.parent.mkdir(parents=True, exist_ok=True)
                    
                    if self.has_root:
                        # Copy directory with root access
                        subprocess.run(
                            ["adb", "-s", self.device_id, "shell", "su", "-c",
                             f"cp -r {remote_path} /sdcard/{package_name}_{target.rstrip('/')}"],
                            capture_output=True, timeout=30
                        )
                        
                        subprocess.run(
                            ["adb", "-s", self.device_id, "pull",
                             f"/sdcard/{package_name}_{target.rstrip('/')}", str(local_path)],
                            capture_output=True, timeout=60
                        )
                
                except Exception as e:
                    self.logger.debug(f"App data extraction error for {target}: {e}")
                    continue
            
            self.logger.info(f"App data extraction complete for {package_name}")
        
        except Exception as e:
            self.logger.error(f"App data extraction error: {e}")
        
        return app_data