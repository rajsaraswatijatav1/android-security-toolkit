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

import abc
import sqlite3
import threading
import logging
import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path


@dataclass
class Finding:
    """Represents a security finding or vulnerability."""
    
    timestamp: str
    module: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    title: str
    description: str
    evidence: Dict[str, Any]
    remediation: str
    cvss_score: Optional[float] = None
    cve_id: Optional[str] = None
    device_id: Optional[str] = None


class BaseScanner(abc.ABC):
    """
    Abstract base class for all security scanners.
    
    Provides common functionality including:
    - SQLite caching system
    - Thread-safe operations
    - Comprehensive logging
    - Metrics tracking
    - Finding correlation
    """
    
    def __init__(
        self,
        module_name: str,
        cache_db: str = "cache.db",
        audit_log: str = "loot/audit.log",
        device_id: Optional[str] = None
    ):
        """
        Initialize the base scanner.
        
        Args:
            module_name: Name of the scanning module
            cache_db: Path to SQLite cache database
            audit_log: Path to audit log file
            device_id: Target device identifier
        """
        self.module_name = module_name
        self.device_id = device_id
        self.cache_db = cache_db
        self.audit_log = audit_log
        
        # Thread safety
        self.lock = threading.Lock()
        self._cache_conn = None
        
        # Metrics tracking
        self.metrics = {
            "start_time": time.time(),
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "errors_count": 0,
            "warnings_count": 0,
            "devices_scanned": 0,
            "executed_commands": 0,
            "data_processed_mb": 0.0
        }
        
        # Finding storage
        self.findings: List[Finding] = []
        self._setup_logger()
        self._init_cache()
        self._log_execution_start()
    
    def _setup_logger(self) -> None:
        """Set up module-specific logger."""
        self.logger = logging.getLogger(f"AST.{self.module_name}")
        self.logger.setLevel(logging.DEBUG)
        
        # Prevent duplicate handlers
        if not self.logger.handlers:
            # Console handler
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter(
                "[%(asctime)s] %(name)s - %(levelname)s - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
            
            # File handler for detailed logs
            log_file = Path("loot") / f"{self.module_name}.log"
            log_file.parent.mkdir(exist_ok=True)
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(logging.DEBUG)
            file_formatter = logging.Formatter(
                "[%(asctime)s] %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            )
            file_handler.setFormatter(file_formatter)
            self.logger.addHandler(file_handler)
    
    def _init_cache(self) -> None:
        """Initialize SQLite cache database."""
        try:
            cache_path = Path(self.cache_db)
            cache_path.parent.mkdir(exist_ok=True)
            
            with self.lock:
                self._cache_conn = sqlite3.connect(cache_path, isolation_level=None)
                self._cache_conn.execute("""
                    CREATE TABLE IF NOT EXISTS cache (
                        key TEXT PRIMARY KEY,
                        value TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        expires_at REAL
                    )
                """)
                
                # Create findings table
                self._cache_conn.execute("""
                    CREATE TABLE IF NOT EXISTS findings (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        module TEXT NOT NULL,
                        device_id TEXT,
                        severity TEXT NOT NULL,
                        title TEXT NOT NULL,
                        description TEXT NOT NULL,
                        evidence TEXT,
                        remediation TEXT,
                        cvss_score REAL,
                        cve_id TEXT,
                        hash TEXT UNIQUE NOT NULL,
                        created_at REAL NOT NULL
                    )
                """)
                
                # Create metrics table
                self._cache_conn.execute("""
                    CREATE TABLE IF NOT EXISTS metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        module TEXT NOT NULL,
                        timestamp REAL NOT NULL,
                        metric_data TEXT NOT NULL
                    )
                """)
                
                # Create audit log table
                self._cache_conn.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT NOT NULL,
                        module TEXT NOT NULL,
                        action TEXT NOT NULL,
                        device_id TEXT,
                        details TEXT,
                        legal_consent BOOLEAN NOT NULL,
                        user TEXT,
                        ip_address TEXT
                    )
                """)
                
                self._cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_cache_key ON cache(key)")
                self._cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_module ON findings(module)")
                self._cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_device ON findings(device_id)")
                self._cache_conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize cache: {e}")
            self._cache_conn = None
    
    def _log_execution_start(self) -> None:
        """Log the start of execution with legal notice."""
        self.logger.info("=" * 60)
        self.logger.info(f"ANDROID SECURITY TOOLKIT v2.0 - {self.module_name}")
        self.logger.info("LEGAL NOTICE: Authorized use only. Requires device ownership or permission.")
        self.logger.info("All actions are logged for audit purposes.")
        self.logger.info("=" * 60)
        
        # Log to audit
        self._audit_log("EXECUTION_START", {"module": self.module_name})
    
    def _audit_log(self, action: str, details: Dict[str, Any]) -> None:
        """Log action to audit trail."""
        try:
            audit_entry = {
                "timestamp": datetime.now().isoformat(),
                "module": self.module_name,
                "action": action,
                "device_id": self.device_id,
                "details": details,
                "legal_consent": True,  # Must be set by caller
                "user": "toolkit_user",  # Should be actual user
                "ip_address": "127.0.0.1"  # Should be actual IP
            }
            
            # Write to file audit log
            audit_path = Path(self.audit_log)
            audit_path.parent.mkdir(exist_ok=True)
            with open(audit_path, "a") as f:
                f.write(json.dumps(audit_entry) + "\n")
            
            # Write to database
            if self._cache_conn:
                with self.lock:
                    self._cache_conn.execute("""
                        INSERT INTO audit_log 
                        (timestamp, module, action, device_id, details, legal_consent, user, ip_address)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        audit_entry["timestamp"],
                        audit_entry["module"],
                        audit_entry["action"],
                        audit_entry["device_id"],
                        json.dumps(audit_entry["details"]),
                        audit_entry["legal_consent"],
                        audit_entry["user"],
                        audit_entry["ip_address"]
                    ))
                    
        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e}")
    
    def get_from_cache(self, key: str) -> Optional[str]:
        """Retrieve value from cache if not expired."""
        try:
            if not self._cache_conn:
                return None
                
            with self.lock:
                cursor = self._cache_conn.execute(
                    "SELECT value, expires_at FROM cache WHERE key = ?",
                    (key,)
                )
                result = cursor.fetchone()
                
                if result:
                    value, expires_at = result
                    if expires_at and time.time() > expires_at:
                        # Expired, remove from cache
                        self._cache_conn.execute("DELETE FROM cache WHERE key = ?", (key,))
                        return None
                    return value
                    
        except Exception as e:
            self.logger.debug(f"Cache get error: {e}")
            
        return None
    
    def set_cache(self, key: str, value: str, ttl_seconds: Optional[int] = None) -> None:
        """Store value in cache with optional TTL."""
        try:
            if not self._cache_conn:
                return
                
            expires_at = None
            if ttl_seconds:
                expires_at = time.time() + ttl_seconds
                
            with self.lock:
                self._cache_conn.execute("""
                    INSERT OR REPLACE INTO cache (key, value, timestamp, expires_at)
                    VALUES (?, ?, ?, ?)
                """, (key, value, time.time(), expires_at))
                
        except Exception as e:
            self.logger.debug(f"Cache set error: {e}")
    
    def log_finding(
        self,
        severity: str,
        title: str,
        description: str,
        evidence: Dict[str, Any],
        remediation: str,
        cvss_score: Optional[float] = None,
        cve_id: Optional[str] = None
    ) -> None:
        """Log a security finding."""
        try:
            finding = Finding(
                timestamp=datetime.now().isoformat(),
                module=self.module_name,
                severity=severity.upper(),
                title=title,
                description=description,
                evidence=evidence,
                remediation=remediation,
                cvss_score=cvss_score,
                cve_id=cve_id,
                device_id=self.device_id
            )
            
            # Add to memory
            self.findings.append(finding)
            
            # Update metrics
            self.metrics["findings_count"] += 1
            severity_key = f"{severity.lower()}_count"
            if severity_key in self.metrics:
                self.metrics[severity_key] += 1
            
            # Generate hash for deduplication
            finding_hash = hashlib.sha256(
                f"{self.module_name}{title}{description}{self.device_id}".encode()
            ).hexdigest()
            
            # Store in database
            if self._cache_conn:
                with self.lock:
                    try:
                        self._cache_conn.execute("""
                            INSERT OR IGNORE INTO findings 
                            (timestamp, module, device_id, severity, title, description, 
                             evidence, remediation, cvss_score, cve_id, hash, created_at)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """, (
                            finding.timestamp,
                            finding.module,
                            finding.device_id,
                            finding.severity,
                            finding.title,
                            finding.description,
                            json.dumps(finding.evidence),
                            finding.remediation,
                            finding.cvss_score,
                            finding.cve_id,
                            finding_hash,
                            time.time()
                        ))
                    except sqlite3.IntegrityError:
                        # Duplicate finding, skip
                        pass
            
            # Log to console with severity color coding
            severity_colors = {
                "CRITICAL": "🔴",
                "HIGH": "🟠", 
                "MEDIUM": "🟡",
                "LOW": "🔵",
                "INFO": "ℹ️"
            }
            
            color = severity_colors.get(finding.severity, "")
            self.logger.warning(f"{color} [{finding.severity}] {finding.title}")
            
            # Log to audit
            self._audit_log("FINDING_LOGGED", {
                "severity": finding.severity,
                "title": finding.title,
                "cvss_score": cvss_score,
                "cve_id": cve_id
            })
            
        except Exception as e:
            self.logger.error(f"Failed to log finding: {e}")
            self.metrics["errors_count"] += 1
    
    def update_metrics(self, metric_updates: Dict[str, Any]) -> None:
        """Update metrics with new values."""
        with self.lock:
            for key, value in metric_updates.items():
                if key in self.metrics:
                    if isinstance(self.metrics[key], (int, float)):
                        self.metrics[key] += value
                    else:
                        self.metrics[key] = value
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current metrics with calculated values."""
        with self.lock:
            metrics = self.metrics.copy()
            metrics["end_time"] = time.time()
            metrics["duration_seconds"] = metrics["end_time"] - metrics["start_time"]
            metrics["findings_per_minute"] = (
                metrics["findings_count"] / (metrics["duration_seconds"] / 60)
                if metrics["duration_seconds"] > 0 else 0
            )
            return metrics
    
    def get_summary(self) -> Dict[str, Any]:
        """Get execution summary with findings and metrics."""
        return {
            "module": self.module_name,
            "device_id": self.device_id,
            "execution_time": datetime.now().isoformat(),
            "metrics": self.get_metrics(),
            "findings": [asdict(f) for f in self.findings],
            "findings_by_severity": {
                "CRITICAL": self.metrics["critical_count"],
                "HIGH": self.metrics["high_count"],
                "MEDIUM": self.metrics["medium_count"],
                "LOW": self.metrics["low_count"],
                "INFO": self.metrics["info_count"]
            }
        }
    
    def save_metrics(self) -> None:
        """Save metrics to database."""
        try:
            if self._cache_conn:
                with self.lock:
                    self._cache_conn.execute("""
                        INSERT INTO metrics (module, timestamp, metric_data)
                        VALUES (?, ?, ?)
                    """, (
                        self.module_name,
                        time.time(),
                        json.dumps(self.get_metrics())
                    ))
        except Exception as e:
            self.logger.error(f"Failed to save metrics: {e}")
    
    def export_findings(self, format_type: str = "json", output_file: Optional[str] = None) -> str:
        """Export findings to specified format."""
        summary = self.get_summary()
        
        if format_type.lower() == "json":
            output = json.dumps(summary, indent=2, default=str)
        elif format_type.lower() == "csv":
            import csv
            import io
            output_buffer = io.StringIO()
            if self.findings:
                fieldnames = ["timestamp", "module", "severity", "title", "description", 
                            "cvss_score", "cve_id", "device_id", "remediation"]
                writer = csv.DictWriter(output_buffer, fieldnames=fieldnames)
                writer.writeheader()
                for finding in self.findings:
                    row = {
                        "timestamp": finding.timestamp,
                        "module": finding.module,
                        "severity": finding.severity,
                        "title": finding.title,
                        "description": finding.description,
                        "cvss_score": finding.cvss_score,
                        "cve_id": finding.cve_id,
                        "device_id": finding.device_id,
                        "remediation": finding.remediation
                    }
                    writer.writerow(row)
            output = output_buffer.getvalue()
        else:
            raise ValueError(f"Unsupported format: {format_type}")
        
        if output_file:
            Path(output_file).parent.mkdir(exist_ok=True)
            with open(output_file, "w") as f:
                f.write(output)
            self.logger.info(f"Findings exported to {output_file}")
        
        return output
    
    def cleanup(self) -> None:
        """Clean up resources."""
        try:
            self.save_metrics()
            
            if self._cache_conn:
                with self.lock:
                    self._cache_conn.close()
                    self._cache_conn = None
            
            self._audit_log("EXECUTION_COMPLETE", {
                "findings_count": len(self.findings),
                "duration": self.get_metrics()["duration_seconds"]
            })
            
            self.logger.info("=" * 60)
            self.logger.info(f"Scan complete. Total findings: {len(self.findings)}")
            self.logger.info("=" * 60)
            
        except Exception as e:
            self.logger.error(f"Cleanup error: {e}")
    
    @abc.abstractmethod
    def scan(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Main scanning method to be implemented by subclasses.
        
        Returns:
            Dictionary containing scan results and summary
        """
        pass


class ScannerManager:
    """Manages multiple scanner instances and coordinates their execution."""
    
    def __init__(self):
        self.scanners: List[BaseScanner] = []
        self.results: List[Dict[str, Any]] = []
        self.logger = logging.getLogger("AST.ScannerManager")
    
    def add_scanner(self, scanner: BaseScanner) -> None:
        """Add a scanner to the manager."""
        self.scanners.append(scanner)
        self.logger.info(f"Added scanner: {scanner.module_name}")
    
    def run_all(self, parallel: bool = False) -> Dict[str, Any]:
        """Execute all scanners."""
        start_time = time.time()
        
        if parallel:
            # Run scanners in parallel using threads
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = [executor.submit(scanner.scan) for scanner in self.scanners]
                for future in concurrent.futures.as_completed(futures):
                    try:
                        result = future.result()
                        self.results.append(result)
                    except Exception as e:
                        self.logger.error(f"Scanner failed: {e}")
        else:
            # Run sequentially
            for scanner in self.scanners:
                try:
                    result = scanner.scan()
                    self.results.append(result)
                except Exception as e:
                    self.logger.error(f"Scanner {scanner.module_name} failed: {e}")
        
        # Aggregate results
        total_findings = sum(len(r.get("findings", [])) for r in self.results)
        
        return {
            "total_scanners": len(self.scanners),
            "successful_scans": len(self.results),
            "total_findings": total_findings,
            "execution_time": time.time() - start_time,
            "scanner_results": self.results
        }
    
    def cleanup_all(self) -> None:
        """Clean up all scanners."""
        for scanner in self.scanners:
            scanner.cleanup()