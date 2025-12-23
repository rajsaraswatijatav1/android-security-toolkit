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

import zipfile
import xml.etree.ElementTree as ET
import subprocess
import re
import hashlib
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json

from core.base_scanner import BaseScanner


class APKAnalyzer(BaseScanner):
    """
    Comprehensive APK analysis module for Android security assessment.
    
    Features:
    - Permission analysis
    - Manifest extraction
    - Certificate analysis
    - Hardcoded secret detection
    - Code decompilation (JADX)
    - Debuggable detection
    - Risk scoring (CVSS-style)
    - Malware pattern detection
    """
    
    # Risky permissions with associated scores
    RISKY_PERMISSIONS = {
        "android.permission.READ_CONTACTS": 6,
        "android.permission.WRITE_CONTACTS": 6,
        "android.permission.READ_SMS": 7,
        "android.permission.SEND_SMS": 8,
        "android.permission.RECEIVE_SMS": 7,
        "android.permission.CALL_PHONE": 8,
        "android.permission.RECORD_AUDIO": 7,
        "android.permission.CAMERA": 6,
        "android.permission.ACCESS_FINE_LOCATION": 7,
        "android.permission.ACCESS_COARSE_LOCATION": 5,
        "android.permission.READ_PHONE_STATE": 6,
        "android.permission.PROCESS_OUTGOING_CALLS": 8,
        "android.permission.INSTALL_PACKAGES": 9,
        "android.permission.DELETE_PACKAGES": 9,
        "android.permission.MODIFY_PHONE_STATE": 9,
        "android.permission.DEVICE_ADMIN": 9,
        "android.permission.BIND_DEVICE_ADMIN": 9,
        "android.permission.REQUEST_INSTALL_PACKAGES": 6,
        "android.permission.SYSTEM_ALERT_WINDOW": 7,
        "android.permission.WRITE_SETTINGS": 7,
        "android.permission.BIND_ACCESSIBILITY_SERVICE": 8,
        "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": 7
    }
    
    # Suspicious API calls
    SUSPICIOUS_APIS = [
        "getRuntime().exec",
        "ProcessBuilder",
        "System.loadLibrary",
        "DexClassLoader",
        "getSystemService",
        "getDeviceId",
        "getSubscriberId",
        "sendTextMessage",
        "startActivity",
        "bindService",
        "registerReceiver",
        "getInstalledPackages",
        "getPackageInfo",
        "createPackageContext",
        "openFileOutput",
        "openOrCreateDatabase",
        "getWritableDatabase",
        "getReadableDatabase",
        "query",
        "insert",
        "update",
        "delete",
        "execSQL",
        "rawQuery",
        "getContentResolver",
        "registerContentObserver",
        "getSharedPreferences",
        "edit",
        "putString",
        "putInt",
        "putBoolean",
        "commit",
        "apply"
    ]
    
    # Hardcoded secret patterns
    SECRET_PATTERNS = [
        (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', "EMAIL_ADDRESS"),
        (r'(?i)api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']', "API_KEY"),
        (r'(?i)password["\']?\s*[:=]\s*["\']([^"\']+)["\']', "PASSWORD"),
        (r'(?i)token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']', "TOKEN"),
        (r'(?i)secret["\']?\s*[:=]\s*["\']([^"\']+)["\']', "SECRET"),
        (r'(?i)auth["\']?\s*[:=]\s*["\']([a-zA-Z0-9_-]+)["\']', "AUTH_TOKEN"),
        (r'https?://[^\s"\'<>]+', "URL"),
        (r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}', "IP_ADDRESS"),
        (r'(?i)database[_-]?url["\']?\s*[:=]\s*["\']([^"\']+)["\']', "DATABASE_URL"),
        (r'(?i)jdbc:[^\s"\'<>]+', "JDBC_CONNECTION"),
        (r'-----BEGIN [A-Z ]+-----', "PRIVATE_KEY"),
        (r'[A-Fa-f0-9]{32}', "MD5_HASH"),
        (r'[A-Fa-f0-9]{40}', "SHA1_HASH"),
        (r'[A-Fa-f0-9]{64}', "SHA256_HASH")
    ]
    
    def __init__(self, apk_path: Optional[str] = None):
        """
        Initialize APK analyzer.
        
        Args:
            apk_path: Path to APK file to analyze
        """
        super().__init__("APKAnalyzer")
        self.apk_path = apk_path
        self.analysis_results = {}
        self.risk_score = 0
        self.jadx_available = self._check_jadx_availability()
    
    def analyze(self, apk_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Perform comprehensive APK analysis.
        
        Args:
            apk_path: Path to APK file (uses instance path if None)
            
        Returns:
            Dictionary containing analysis results
        """
        apk_path = apk_path or self.apk_path
        if not apk_path:
            raise ValueError("APK path must be provided")
        
        if not Path(apk_path).exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")
        
        self.logger.info(f"Starting APK analysis: {apk_path}")
        self.apk_path = apk_path
        
        try:
            # Phase 1: Basic APK information
            self._extract_basic_info()
            
            # Phase 2: Manifest analysis
            self._analyze_manifest()
            
            # Phase 3: Certificate analysis
            self._analyze_certificate()
            
            # Phase 4: Permission analysis
            self._analyze_permissions()
            
            # Phase 5: Hardcoded secrets detection
            self._detect_hardcoded_secrets()
            
            # Phase 6: Code analysis (if JADX available)
            if self.jadx_available:
                self._decompile_code()
                self._analyze_decompiled_code()
            
            # Phase 7: Risk assessment
            self._calculate_risk_score()
            
            # Phase 8: Generate report
            self._generate_analysis_report()
            
            return self.analysis_results
            
        except Exception as e:
            self.logger.error(f"APK analysis failed: {e}")
            self.log_finding(
                "ERROR",
                "APK Analysis Failed",
                f"APK analysis failed with error: {str(e)}",
                {"error": str(e), "apk_path": apk_path},
                "Check logs and retry analysis"
            )
            return self.analysis_results
    
    def _check_jadx_availability(self) -> bool:
        """Check if JADX decompiler is available."""
        try:
            result = subprocess.run(
                ["jadx", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _extract_basic_info(self) -> None:
        """Extract basic APK information."""
        self.logger.info("Extracting basic APK information")
        
        # Get file size
        file_size = Path(self.apk_path).stat().st_size
        
        # Calculate file hashes
        md5_hash = self._calculate_hash(self.apk_path, "md5")
        sha1_hash = self._calculate_hash(self.apk_path, "sha1")
        sha256_hash = self._calculate_hash(self.apk_path, "sha256")
        
        # Extract APK contents to temp directory
        temp_dir = Path("loot/apk_analysis") / Path(self.apk_path).stem
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        with zipfile.ZipFile(self.apk_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        
        self.analysis_results["basic_info"] = {
            "file_path": self.apk_path,
            "file_size_bytes": file_size,
            "file_size_mb": round(file_size / (1024 * 1024), 2),
            "md5_hash": md5_hash,
            "sha1_hash": sha1_hash,
            "sha256_hash": sha256_hash,
            "extraction_path": str(temp_dir)
        }
        
        self.log_finding(
            "INFO",
            f"APK Basic Info: {Path(self.apk_path).name}",
            f"APK file analyzed: {file_size / 1024:.1f} KB",
            self.analysis_results["basic_info"],
            "Continue with detailed analysis"
        )
    
    def _calculate_hash(self, file_path: str, algorithm: str) -> str:
        """Calculate file hash."""
        hash_obj = getattr(hashlib, algorithm)()
        
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        
        return hash_obj.hexdigest()
    
    def _analyze_manifest(self) -> None:
        """Analyze AndroidManifest.xml."""
        self.logger.info("Analyzing AndroidManifest.xml")
        
        manifest_path = Path(self.analysis_results["basic_info"]["extraction_path"]) / "AndroidManifest.xml"
        
        if not manifest_path.exists():
            self.logger.warning("AndroidManifest.xml not found")
            return
        
        try:
            # Parse manifest
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            
            # Extract package name
            package_name = root.get('package', 'unknown')
            
            # Extract version info
            version_code = root.get('{http://schemas.android.com/apk/res/android}versionCode', 'unknown')
            version_name = root.get('{http://schemas.android.com/apk/res/android}versionName', 'unknown')
            
            # Extract permissions
            permissions = []
            for perm in root.findall('.//uses-permission'):
                perm_name = perm.get('{http://schemas.android.com/apk/res/android}name')
                if perm_name:
                    permissions.append(perm_name)
            
            # Extract activities
            activities = []
            for activity in root.findall('.//activity'):
                activity_name = activity.get('{http://schemas.android.com/apk/res/android}name')
                if activity_name:
                    activities.append(activity_name)
            
            # Extract services
            services = []
            for service in root.findall('.//service'):
                service_name = service.get('{http://schemas.android.com/apk/res/android}name')
                if service_name:
                    services.append(service_name)
            
            # Extract receivers
            receivers = []
            for receiver in root.findall('.//receiver'):
                receiver_name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                if receiver_name:
                    receivers.append(receiver_name)
            
            # Check for debuggable flag
            debuggable = False
            for app in root.findall('.//application'):
                debug_attr = app.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debug_attr == 'true':
                    debuggable = True
                    break
            
            # Check for allowBackup flag
            allow_backup = True
            for app in root.findall('.//application'):
                backup_attr = app.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if backup_attr == 'false':
                    allow_backup = False
                    break
            
            self.analysis_results["manifest"] = {
                "package_name": package_name,
                "version_code": version_code,
                "version_name": version_name,
                "permissions": permissions,
                "activities": activities,
                "services": services,
                "receivers": receivers,
                "debuggable": debuggable,
                "allow_backup": allow_backup,
                "activity_count": len(activities),
                "service_count": len(services),
                "receiver_count": len(receivers)
            }
            
            # Log findings
            if debuggable:
                self.log_finding(
                    "HIGH",
                    f"Debuggable APK: {package_name}",
                    "APK is compiled with debug mode enabled",
                    {"package": package_name, "debuggable": debuggable},
                    "Disable debug mode in production builds"
                )
            
            if allow_backup:
                self.log_finding(
                    "MEDIUM",
                    f"Backup Enabled: {package_name}",
                    "APK allows data backup via ADB",
                    {"package": package_name, "allow_backup": allow_backup},
                    "Consider disabling backup for sensitive apps"
                )
            
            self.logger.info(f"Manifest analysis complete: {len(permissions)} permissions")
            
        except Exception as e:
            self.logger.error(f"Manifest analysis error: {e}")
    
    def _analyze_certificate(self) -> None:
        """Analyze APK signing certificate."""
        self.logger.info("Analyzing APK certificate")
        
        try:
            # Use keytool to extract certificate info
            result = subprocess.run(
                ["keytool", "-printcert", "-jarfile", self.apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                cert_info = result.stdout
                
                # Extract certificate details
                issuer = self._extract_cert_field(cert_info, "Issuer")
                subject = self._extract_cert_field(cert_info, "Owner")
                serial_number = self._extract_cert_field(cert_info, "Serial number")
                valid_from = self._extract_cert_field(cert_info, "Valid from")
                valid_until = self._extract_cert_field(cert_info, "Valid until")
                
                # Check if self-signed
                is_self_signed = issuer == subject
                
                # Check certificate validity
                is_valid = "Valid" in cert_info
                
                self.analysis_results["certificate"] = {
                    "issuer": issuer,
                    "subject": subject,
                    "serial_number": serial_number,
                    "valid_from": valid_from,
                    "valid_until": valid_until,
                    "is_self_signed": is_self_signed,
                    "is_valid": is_valid,
                    "raw_certificate": cert_info
                }
                
                # Log findings
                if is_self_signed:
                    self.log_finding(
                        "MEDIUM",
                        f"Self-Signed Certificate: {self.analysis_results['manifest']['package_name']}",
                        "APK is signed with self-signed certificate",
                        {"issuer": issuer, "subject": subject},
                        "Use proper certificate from trusted CA"
                    )
                
                if not is_valid:
                    self.log_finding(
                        "HIGH",
                        f"Invalid Certificate: {self.analysis_results['manifest']['package_name']}",
                        "APK certificate is invalid or expired",
                        {"valid_until": valid_until},
                        "Renew certificate and re-sign APK"
                    )
                
                self.logger.info("Certificate analysis complete")
                
        except Exception as e:
            self.logger.error(f"Certificate analysis error: {e}")
    
    def _extract_cert_field(self, cert_info: str, field_name: str) -> str:
        """Extract field from certificate info."""
        pattern = rf"{field_name}: ([^\n]+)"
        match = re.search(pattern, cert_info)
        return match.group(1) if match else "Unknown"
    
    def _analyze_permissions(self) -> None:
        """Analyze APK permissions for security risks."""
        self.logger.info("Analyzing permissions")
        
        if "manifest" not in self.analysis_results:
            return
        
        permissions = self.analysis_results["manifest"]["permissions"]
        permission_analysis = {
            "total_permissions": len(permissions),
            "risky_permissions": [],
            "dangerous_permissions": [],
            "normal_permissions": [],
            "risk_score": 0
        }
        
        for permission in permissions:
            if permission in self.RISKY_PERMISSIONS:
                risk_score = self.RISKY_PERMISSIONS[permission]
                permission_analysis["risky_permissions"].append({
                    "permission": permission,
                    "risk_score": risk_score
                })
                permission_analysis["risk_score"] += risk_score
                
                # Log high-risk permissions
                if risk_score >= 8:
                    self.log_finding(
                        "HIGH",
                        f"High-Risk Permission: {permission}",
                        f"APK requests high-risk permission: {permission}",
                        {"permission": permission, "risk_score": risk_score},
                        "Review if this permission is necessary"
                    )
                
            elif self._is_dangerous_permission(permission):
                permission_analysis["dangerous_permissions"].append(permission)
            else:
                permission_analysis["normal_permissions"].append(permission)
        
        self.analysis_results["permissions"] = permission_analysis
        
        # Log permission summary
        self.log_finding(
            "INFO",
            f"Permission Analysis: {len(permissions)} permissions",
            f"Total permissions: {len(permissions)}, Risk score: {permission_analysis['risk_score']}",
            permission_analysis,
            "Review risky permissions"
        )
        
        self.logger.info(f"Permission analysis complete: Risk score {permission_analysis['risk_score']}")
    
    def _is_dangerous_permission(self, permission: str) -> bool:
        """Check if permission is dangerous."""
        dangerous_prefixes = [
            "android.permission.",
            "com.android.",
            "android.Manifest.permission."
        ]
        
        # Common dangerous permissions not in our specific list
        dangerous_patterns = [
            "LOCATION", "CONTACTS", "SMS", "PHONE", "MICROPHONE", "CAMERA",
            "STORAGE", "CALENDAR", "SENSORS"
        ]
        
        for pattern in dangerous_patterns:
            if pattern in permission.upper():
                return True
        
        return False
    
    def _detect_hardcoded_secrets(self) -> None:
        """Detect hardcoded secrets in APK."""
        self.logger.info("Detecting hardcoded secrets")
        
        secrets_found = []
        extraction_path = Path(self.analysis_results["basic_info"]["extraction_path"])
        
        # Search in various files
        search_files = []
        
        # Add resource files
        res_path = extraction_path / "res"
        if res_path.exists():
            for file_path in res_path.rglob("*.xml"):
                search_files.append(file_path)
            for file_path in res_path.rglob("*.json"):
                search_files.append(file_path)
        
        # Add assets
        assets_path = extraction_path / "assets"
        if assets_path.exists():
            for file_path in assets_path.rglob("*"):
                if file_path.is_file():
                    search_files.append(file_path)
        
        # Search for secrets
        for file_path in search_files:
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    for pattern, secret_type in self.SECRET_PATTERNS:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if len(match) > 3:  # Filter out short matches
                                secret_info = {
                                    "file": str(file_path),
                                    "type": secret_type,
                                    "value": match[:50] + "..." if len(match) > 50 else match,
                                    "full_value": match
                                }
                                secrets_found.append(secret_info)
                                
                                # Log critical secrets
                                if secret_type in ["API_KEY", "PASSWORD", "PRIVATE_KEY"]:
                                    self.log_finding(
                                        "CRITICAL",
                                        f"Hardcoded {secret_type}: {Path(file_path).name}",
                                        f"Found hardcoded {secret_type} in {file_path}",
                                        secret_info,
                                        "Remove hardcoded secrets and use secure storage"
                                    )
            
            except Exception as e:
                self.logger.debug(f"Error reading {file_path}: {e}")
        
        self.analysis_results["secrets"] = {
            "total_secrets": len(secrets_found),
            "secrets": secrets_found
        }
        
        self.logger.info(f"Secret detection complete: {len(secrets_found)} secrets found")
    
    def _decompile_code(self) -> None:
        """Decompile APK using JADX."""
        if not self.jadx_available:
            self.logger.warning("JADX not available, skipping decompilation")
            return
        
        self.logger.info("Decompiling APK with JADX")
        
        # Create output directory
        decompile_path = Path("loot/apk_analysis") / f"{Path(self.apk_path).stem}_decompiled"
        decompile_path.mkdir(parents=True, exist_ok=True)
        
        try:
            # Run JADX
            result = subprocess.run(
                ["jadx", "-d", str(decompile_path), self.apk_path],
                capture_output=True,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                self.analysis_results["decompilation"] = {
                    "success": True,
                    "output_path": str(decompile_path),
                    "java_files": len(list(decompile_path.rglob("*.java"))),
                    "resource_files": len(list(decompile_path.rglob("*.xml")))
                }
                self.logger.info("APK decompilation successful")
            else:
                self.logger.warning(f"JADX decompilation failed: {result.stderr}")
                self.analysis_results["decompilation"] = {
                    "success": False,
                    "error": result.stderr
                }
                
        except subprocess.TimeoutExpired:
            self.logger.warning("JADX decompilation timeout")
            self.analysis_results["decompilation"] = {
                "success": False,
                "error": "Decompilation timeout"
            }
        except Exception as e:
            self.logger.error(f"Decompilation error: {e}")
            self.analysis_results["decompilation"] = {
                "success": False,
                "error": str(e)
            }
    
    def _analyze_decompiled_code(self) -> None:
        """Analyze decompiled Java code."""
        if "decompilation" not in self.analysis_results:
            return
        
        if not self.analysis_results["decompilation"]["success"]:
            return
        
        self.logger.info("Analyzing decompiled code")
        
        decompile_path = Path(self.analysis_results["decompilation"]["output_path"])
        java_files = list(decompile_path.rglob("*.java"))
        
        code_analysis = {
            "total_files": len(java_files),
            "suspicious_apis": [],
            "reflection_usage": 0,
            "native_calls": 0,
            "obfuscation_level": "low"
        }
        
        # Analyze each Java file
        for java_file in java_files[:50]:  # Limit to first 50 files for performance
            try:
                with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                    
                    # Check for suspicious APIs
                    for api in self.SUSPICIOUS_APIS:
                        if api in content:
                            code_analysis["suspicious_apis"].append({
                                "file": str(java_file),
                                "api": api
                            })
                    
                    # Check for reflection
                    if "Class.forName" in content or "getMethod" in content:
                        code_analysis["reflection_usage"] += 1
                    
                    # Check for native calls
                    if "System.loadLibrary" in content or "native" in content:
                        code_analysis["native_calls"] += 1
            
            except Exception as e:
                self.logger.debug(f"Error analyzing {java_file}: {e}")
        
        # Calculate obfuscation level
        if code_analysis["reflection_usage"] > 10 or code_analysis["native_calls"] > 5:
            code_analysis["obfuscation_level"] = "high"
        elif code_analysis["reflection_usage"] > 5 or code_analysis["native_calls"] > 2:
            code_analysis["obfuscation_level"] = "medium"
        
        self.analysis_results["code_analysis"] = code_analysis
        
        # Log findings
        if code_analysis["reflection_usage"] > 10:
            self.log_finding(
                "MEDIUM",
                f"Heavy Reflection Usage: {self.analysis_results['manifest']['package_name']}",
                f"APK uses reflection extensively ({code_analysis['reflection_usage']} instances)",
                code_analysis,
                "Review reflection usage for security implications"
            )
        
        self.logger.info(f"Code analysis complete: {len(code_analysis['suspicious_apis'])} suspicious APIs")
    
    def _calculate_risk_score(self) -> None:
        """Calculate overall risk score."""
        self.logger.info("Calculating risk score")
        
        risk_factors = []
        total_score = 0
        
        # Permission risk
        if "permissions" in self.analysis_results:
            perm_score = self.analysis_results["permissions"]["risk_score"]
            risk_factors.append({
                "factor": "permissions",
                "score": perm_score,
                "weight": 0.3
            })
            total_score += perm_score * 0.3
        
        # Debuggable risk
        if self.analysis_results.get("manifest", {}).get("debuggable", False):
            risk_factors.append({
                "factor": "debuggable",
                "score": 50,
                "weight": 0.2
            })
            total_score += 50 * 0.2
        
        # Secrets risk
        if "secrets" in self.analysis_results:
            secret_count = self.analysis_results["secrets"]["total_secrets"]
            secret_score = min(secret_count * 10, 100)
            risk_factors.append({
                "factor": "secrets",
                "score": secret_score,
                "weight": 0.25
            })
            total_score += secret_score * 0.25
        
        # Certificate risk
        if self.analysis_results.get("certificate", {}).get("is_self_signed", False):
            risk_factors.append({
                "factor": "self_signed_cert",
                "score": 30,
                "weight": 0.1
            })
            total_score += 30 * 0.1
        
        # Obfuscation risk
        obfuscation = self.analysis_results.get("code_analysis", {}).get("obfuscation_level", "low")
        if obfuscation == "high":
            risk_factors.append({
                "factor": "obfuscation",
                "score": 20,
                "weight": 0.15
            })
            total_score += 20 * 0.15
        
        # Calculate final score (0-10 scale)
        self.risk_score = min(total_score / 10, 10)
        
        # Determine risk level
        if self.risk_score >= 8:
            risk_level = "CRITICAL"
        elif self.risk_score >= 6:
            risk_level = "HIGH"
        elif self.risk_score >= 4:
            risk_level = "MEDIUM"
        elif self.risk_score >= 2:
            risk_level = "LOW"
        else:
            risk_level = "INFO"
        
        self.analysis_results["risk_assessment"] = {
            "score": round(self.risk_score, 1),
            "level": risk_level,
            "factors": risk_factors,
            "recommendations": self._generate_recommendations()
        }
        
        # Log risk assessment
        self.log_finding(
            risk_level,
            f"Risk Assessment: {self.analysis_results['manifest']['package_name']}",
            f"APK risk score: {self.risk_score:.1f}/10",
            self.analysis_results["risk_assessment"],
            "Review recommendations and address security issues"
        )
        
        self.logger.info(f"Risk assessment complete: {self.risk_score:.1f}/10")
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        if self.analysis_results.get("manifest", {}).get("debuggable", False):
            recommendations.append("Disable debug mode in production builds")
        
        if self.analysis_results.get("manifest", {}).get("allow_backup", True):
            recommendations.append("Consider disabling backup for sensitive data")
        
        if self.analysis_results.get("permissions", {}).get("risk_score", 0) > 50:
            recommendations.append("Review and minimize requested permissions")
        
        if self.analysis_results.get("secrets", {}).get("total_secrets", 0) > 0:
            recommendations.append("Remove hardcoded secrets and use secure storage")
        
        if self.analysis_results.get("certificate", {}).get("is_self_signed", False):
            recommendations.append("Use proper certificate from trusted CA")
        
        if self.analysis_results.get("code_analysis", {}).get("obfuscation_level") == "high":
            recommendations.append("Review heavy reflection usage for security implications")
        
        return recommendations
    
    def _generate_analysis_report(self) -> None:
        """Generate comprehensive analysis report."""
        self.logger.info("Generating analysis report")
        
        report = {
            "analysis_timestamp": time.time(),
            "apk_path": self.apk_path,
            "basic_info": self.analysis_results.get("basic_info", {}),
            "manifest": self.analysis_results.get("manifest", {}),
            "certificate": self.analysis_results.get("certificate", {}),
            "permissions": self.analysis_results.get("permissions", {}),
            "secrets": self.analysis_results.get("secrets", {}),
            "code_analysis": self.analysis_results.get("code_analysis", {}),
            "risk_assessment": self.analysis_results.get("risk_assessment", {}),
            "summary": {
                "total_findings": len(self.findings),
                "critical_issues": self.metrics["critical_count"],
                "high_issues": self.metrics["high_count"],
                "medium_issues": self.metrics["medium_count"],
                "low_issues": self.metrics["low_count"],
                "info_issues": self.metrics["info_count"],
                "risk_score": self.risk_score
            }
        }
        
        # Save report
        report_file = Path("loot/apk_analysis") / f"{Path(self.apk_path).stem}_analysis.json"
        report_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)
        
        self.analysis_results["report_file"] = str(report_file)
        
        self.logger.info(f"Analysis report saved: {report_file}")
    
    def get_risk_score(self) -> float:
        """Get calculated risk score."""
        return self.risk_score
    
    def get_permissions(self) -> List[str]:
        """Get list of requested permissions."""
        return self.analysis_results.get("manifest", {}).get("permissions", [])
    
    def is_debuggable(self) -> bool:
        """Check if APK is debuggable."""
        return self.analysis_results.get("manifest", {}).get("debuggable", False)