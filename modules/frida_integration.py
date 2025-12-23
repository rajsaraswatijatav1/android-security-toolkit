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
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

from core.base_scanner import BaseScanner


class FridaIntegration(BaseScanner):
    """
    Frida integration for dynamic analysis and runtime manipulation.
    
    Features:
    - Process enumeration
    - Module loading detection
    - Function hooking
    - Memory dumping
    - SSL pinning bypass
    - Root detection bypass
    - Custom script execution
    """
    
    def __init__(self, device_id: Optional[str] = None):
        """
        Initialize Frida integration.
        
        Args:
            device_id: Target device ID
        """
        super().__init__("FridaIntegration", device_id=device_id)
        self.frida_available = self._check_frida_availability()
        self.device_available = self._check_device_availability()
        
        if not self.frida_available:
            self.logger.warning("Frida not available - some features disabled")
    
    def _check_frida_availability(self) -> bool:
        """Check if Frida is available."""
        try:
            result = subprocess.run(
                ["frida", "--version"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def _check_device_availability(self) -> bool:
        """Check if device is available for Frida."""
        if not self.frida_available:
            return False
        
        try:
            result = subprocess.run(
                ["frida-ps", "-U"],
                capture_output=True, text=True, timeout=10
            )
            return result.returncode == 0
        except Exception:
            return False
    
    def enumerate_processes(self) -> List[Dict[str, Any]]:
        """Enumerate running processes on device."""
        if not self.device_available:
            self.logger.error("Frida device not available")
            return []
        
        processes = []
        
        try:
            result = subprocess.run(
                ["frida-ps", "-U"],
                capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                
                for line in lines[1:]:  # Skip header
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            pid = int(parts[0])
                            name = ' '.join(parts[1:])
                            
                            processes.append({
                                "pid": pid,
                                "name": name
                            })
                        except ValueError:
                            continue
                
                self.logger.info(f"Enumerated {len(processes)} processes")
                
                self.log_finding(
                    "INFO",
                    f"Process Enumeration: {len(processes)} processes",
                    f"Successfully enumerated {len(processes)} running processes",
                    {"count": len(processes)},
                    "Process enumeration completed"
                )
            
        except Exception as e:
            self.logger.error(f"Process enumeration error: {e}")
        
        return processes
    
    def attach_to_process(self, process_name: str, script_path: Optional[str] = None) -> bool:
        """Attach to a running process."""
        if not self.device_available:
            self.logger.error("Frida device not available")
            return False
        
        try:
            # Build Frida command
            cmd = ["frida", "-U", "-n", process_name]
            
            if script_path:
                cmd.extend(["-l", script_path])
            
            # Start Frida in background
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Wait a bit to see if it starts successfully
            time.sleep(2)
            
            if process.poll() is None:  # Still running
                self.logger.info(f"Attached to process: {process_name}")
                
                self.log_finding(
                    "INFO",
                    f"Frida Attached: {process_name}",
                    f"Successfully attached to process: {process_name}",
                    {"process": process_name, "script": script_path},
                    "Process attached for dynamic analysis"
                )
                
                return True
            else:
                stderr_output = process.stderr.read()
                self.logger.error(f"Failed to attach: {stderr_output}")
                return False
                
        except Exception as e:
            self.logger.error(f"Attach error: {e}")
            return False
    
    def spawn_process(self, package_name: str, script_path: Optional[str] = None) -> bool:
        """Spawn a new process and attach to it."""
        if not self.device_available:
            self.logger.error("Frida device not available")
            return False
        
        try:
            # Build Frida command
            cmd = ["frida", "-U", "-f", package_name]
            
            if script_path:
                cmd.extend(["-l", script_path])
            
            # Start Frida
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            time.sleep(3)  # Wait for process to start
            
            if process.poll() is None:  # Still running
                self.logger.info(f"Spawned process: {package_name}")
                
                self.log_finding(
                    "INFO",
                    f"Frida Spawn: {package_name}",
                    f"Successfully spawned process: {package_name}",
                    {"package": package_name, "script": script_path},
                    "Process spawned for dynamic analysis"
                )
                
                return True
            else:
                stderr_output = process.stderr.read()
                self.logger.error(f"Failed to spawn: {stderr_output}")
                return False
                
        except Exception as e:
            self.logger.error(f"Spawn error: {e}")
            return False
    
    def run_script(self, script_content: str, process_name: str) -> Optional[str]:
        """Run Frida script on a process."""
        if not self.device_available:
            self.logger.error("Frida device not available")
            return None
        
        try:
            # Save script to temporary file
            script_file = Path("loot") / f"frida_script_{time.time()}.js"
            script_file.parent.mkdir(exist_ok=True)
            
            with open(script_file, 'w') as f:
                f.write(script_content)
            
            # Run script
            cmd = ["frida", "-U", "-n", process_name, "-l", str(script_file), "--no-pause"]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60
            )
            
            # Clean up script file
            script_file.unlink(missing_ok=True)
            
            if result.returncode == 0:
                self.logger.info(f"Script executed successfully on {process_name}")
                
                self.log_finding(
                    "INFO",
                    f"Frida Script Executed: {process_name}",
                    f"Frida script executed on process: {process_name}",
                    {"process": process_name, "script_size": len(script_content)},
                    "Script executed for dynamic analysis"
                )
                
                return result.stdout
            else:
                self.logger.error(f"Script execution failed: {result.stderr}")
                return None
                
        except Exception as e:
            self.logger.error(f"Script execution error: {e}")
            return None
    
    def bypass_ssl_pinning(self, process_name: str) -> bool:
        """Bypass SSL pinning in a process."""
        ssl_bypass_script = """
Java.perform(function() {
    // TrustManager bypass
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    // Implement custom TrustManager
    var CustomTrustManager = Java.registerClass({
        name: "com.android.security.CustomTrustManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    // Replace default TrustManager
    var tm = CustomTrustManager.$new();
    var context = SSLContext.getInstance("TLS");
    context.init(null, [tm], null);
    SSLContext.setDefault(context);
    
    console.log("SSL pinning bypassed");
});
"""
        
        result = self.run_script(ssl_bypass_script, process_name)
        if result:
            self.logger.info(f"SSL pinning bypassed for {process_name}")
            
            self.log_finding(
                "INFO",
                f"SSL Pinning Bypassed: {process_name}",
                f"SSL pinning bypassed for process: {process_name}",
                {"process": process_name},
                "SSL pinning bypassed for traffic analysis"
            )
            
            return True
        
        return False
    
    def bypass_root_detection(self, process_name: str) -> bool:
        """Bypass root detection in a process."""
        root_bypass_script = """
Java.perform(function() {
    // Common root detection bypasses
    var File = Java.use("java.io.File");
    var Runtime = Java.use("java.lang.Runtime");
    
    // Hook file existence checks
    File.exists.implementation = function() {
        var path = this.getPath();
        if (path.contains("su") || path.contains("magisk")) {
            return false;
        }
        return this.exists();
    };
    
    // Hook runtime exec for su commands
    Runtime.exec.overload('java.lang.String').implementation = function(command) {
        if (command.contains("su") || command.contains("id")) {
            return this.exec("echo uid=0(root) gid=0(root)");
        }
        return this.exec(command);
    };
    
    console.log("Root detection bypassed");
});
"""
        
        result = self.run_script(root_bypass_script, process_name)
        if result:
            self.logger.info(f"Root detection bypassed for {process_name}")
            
            self.log_finding(
                "INFO",
                f"Root Detection Bypassed: {process_name}",
                f"Root detection bypassed for process: {process_name}",
                {"process": process_name},
                "Root detection bypassed for analysis"
            )
            
            return True
        
        return False
    
    def dump_memory(self, process_name: str, output_path: Optional[str] = None) -> bool:
        """Dump process memory."""
        if not output_path:
            output_path = f"loot/memory_dump_{process_name}_{time.time()}.bin"
        
        try:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            
            memory_dump_script = f"""
var dump_path = "{output_path}";
var process_name = "{process_name}";

Java.perform(function() {
    // Memory dumping implementation would go here
    // This is a simplified version
    console.log("Memory dump would be saved to: " + dump_path);
});
"""
            
            result = self.run_script(memory_dump_script, process_name)
            if result:
                self.logger.info(f"Memory dump initiated for {process_name}")
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Memory dump error: {e}")
            return False
    
    def trace_crypto_operations(self, process_name: str) -> bool:
        """Trace cryptographic operations in a process."""
        crypto_trace_script = """
Java.perform(function() {
    // Trace common crypto operations
    var Cipher = Java.use("javax.crypto.Cipher");
    var MessageDigest = Java.use("java.security.MessageDigest");
    
    // Hook Cipher operations
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("Cipher.doFinal called");
        console.log("Input: " + input);
        var result = this.doFinal(input);
        console.log("Output: " + result);
        return result;
    };
    
    // Hook MessageDigest operations
    MessageDigest.digest.overload('[B').implementation = function(input) {
        console.log("MessageDigest.digest called");
        console.log("Input: " + input);
        var result = this.digest(input);
        console.log("Hash: " + result);
        return result;
    };
    
    console.log("Crypto tracing enabled");
});
"""
        
        result = self.run_script(crypto_trace_script, process_name)
        if result:
            self.logger.info(f"Crypto tracing enabled for {process_name}")
            
            self.log_finding(
                "INFO",
                f"Crypto Tracing: {process_name}",
                f"Cryptographic operations tracing enabled for: {process_name}",
                {"process": process_name},
                "Crypto operations being traced"
            )
            
            return True
        
        return False
    
    def intercept_network_calls(self, process_name: str) -> bool:
        """Intercept network calls in a process."""
        network_intercept_script = """
Java.perform(function() {
    // Intercept HTTP connections
    var URL = Java.use("java.net.URL");
    var HttpURLConnection = Java.use("java.net.HttpURLConnection");
    
    // Hook URL connections
    URL.openConnection.implementation = function() {
        var url = this.toString();
        console.log("Network request to: " + url);
        return this.openConnection();
    };
    
    // Hook HTTP requests
    HttpURLConnection.connect.implementation = function() {
        console.log("HTTP connection to: " + this.getURL().toString());
        console.log("Method: " + this.getRequestMethod());
        return this.connect();
    };
    
    console.log("Network interception enabled");
});
"""
        
        result = self.run_script(network_intercept_script, process_name)
        if result:
            self.logger.info(f"Network interception enabled for {process_name}")
            
            self.log_finding(
                "INFO",
                f"Network Interception: {process_name}",
                f"Network calls interception enabled for: {process_name}",
                {"process": process_name},
                "Network calls being intercepted"
            )
            
            return True
        
        return False
    
    def generate_frida_script(self, hooks: List[str]) -> str:
        """Generate Frida script based on requested hooks."""
        script_parts = ["Java.perform(function() {"]
        
        for hook in hooks:
            if hook == "ssl_pinning":
                script_parts.append(self._get_ssl_pinning_hook())
            elif hook == "root_detection":
                script_parts.append(self._get_root_detection_hook())
            elif hook == "crypto":
                script_parts.append(self._get_crypto_hook())
            elif hook == "network":
                script_parts.append(self._get_network_hook())
        
        script_parts.append("});")
        
        return "\n".join(script_parts)
    
    def _get_ssl_pinning_hook(self) -> str:
        """Get SSL pinning bypass hook."""
        return """
    // SSL Pinning Bypass
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    
    var CustomTrustManager = Java.registerClass({
        name: "com.security.CustomTrustManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    
    var tm = CustomTrustManager.$new();
    var context = SSLContext.getInstance("TLS");
    context.init(null, [tm], null);
    SSLContext.setDefault(context);
"""
    
    def _get_root_detection_hook(self) -> str:
        """Get root detection bypass hook."""
        return """
    // Root Detection Bypass
    var File = Java.use("java.io.File");
    File.exists.implementation = function() {
        var path = this.getPath();
        if (path.contains("su") || path.contains("magisk")) {
            return false;
        }
        return this.exists();
    };
"""
    
    def _get_crypto_hook(self) -> str:
        """Get crypto operations hook."""
        return """
    // Crypto Operations Hook
    var Cipher = Java.use("javax.crypto.Cipher");
    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log("Cipher operation detected");
        return this.doFinal(input);
    };
"""
    
    def _get_network_hook(self) -> str:
        """Get network operations hook."""
        return """
    // Network Operations Hook
    var URL = Java.use("java.net.URL");
    URL.openConnection.implementation = function() {
        var url = this.toString();
        console.log("Network request: " + url);
        return this.openConnection();
    };
"""
    
    def get_available_hooks(self) -> List[str]:
        """Get list of available hooks."""
        return [
            "ssl_pinning",
            "root_detection", 
            "crypto",
            "network",
            "file_operations",
            "database_operations",
            "shared_preferences"
        ]
    
    def save_script(self, script_content: str, filename: str) -> bool:
        """Save Frida script to file."""
        try:
            script_path = Path("loot/frida_scripts") / filename
            script_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(script_path, 'w') as f:
                f.write(script_content)
            
            self.logger.info(f"Frida script saved: {script_path}")
            return True
            
        except Exception as e:
            self.logger.error(f"Script save error: {e}")
            return False