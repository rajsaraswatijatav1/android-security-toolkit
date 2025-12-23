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

import hashlib
import hmac
import binascii
import logging
from typing import Dict, List, Optional, Tuple, Union
from pathlib import Path
import re


class HashUtils:
    """
    Comprehensive hash utility class for Android security operations.
    
    Supports:
    - Android PIN hashing (SHA-1, MD5)
    - Pattern hashing
    - Password hashing
    - Hash identification
    - Hash cracking utilities
    - Android-specific hash formats
    """
    
    # Android PIN/Password hash patterns
    ANDROID_HASH_PATTERNS = {
        r"^[a-f0-9]{40}$": "SHA-1",
        r"^[a-f0-9]{32}$": "MD5", 
        r"^[a-f0-9]{64}$": "SHA-256",
        r"^[a-f0-9]{128}$": "SHA-512",
        r"^[0-9]+:[a-f0-9]+:[a-f0-9]+$": "Android PIN/Pattern (Salted)",
    }
    
    # Hashcat hash modes for Android
    HASHCAT_MODES = {
        "android_pin_sha1": 5800,
        "android_pin_md5": 10,
        "android_pattern": 5800,
        "sha1": 100,
        "md5": 0,
        "sha256": 1400,
        "sha512": 1700,
    }
    
    def __init__(self):
        """Initialize hash utilities."""
        self.logger = logging.getLogger("AST.HashUtils")
    
    def identify_hash(self, hash_string: str) -> List[str]:
        """
        Identify the type of hash based on pattern matching.
        
        Args:
            hash_string: The hash string to identify
            
        Returns:
            List of possible hash types
        """
        possible_types = []
        hash_string = hash_string.lower().strip()
        
        for pattern, hash_type in self.ANDROID_HASH_PATTERNS.items():
            if re.match(pattern, hash_string):
                possible_types.append(hash_type)
        
        # Additional heuristic checks
        if len(hash_string) == 40 and all(c in "0123456789abcdef" for c in hash_string):
            if "SHA-1" not in possible_types:
                possible_types.append("SHA-1")
        
        if len(hash_string) == 32 and all(c in "0123456789abcdef" for c in hash_string):
            if "MD5" not in possible_types:
                possible_types.append("MD5")
        
        return possible_types
    
    def hash_android_pin(self, pin: str, salt: Optional[str] = None, algorithm: str = "sha1") -> str:
        """
        Hash Android PIN using specified algorithm.
        
        Args:
            pin: The PIN to hash (4-8 digits)
            salt: Optional salt for hashing
            algorithm: Hash algorithm (sha1, md5, sha256)
            
        Returns:
            Hashed PIN string
        """
        if not pin.isdigit():
            raise ValueError("PIN must contain only digits")
        
        if not (4 <= len(pin) <= 8):
            raise ValueError("PIN must be 4-8 digits long")
        
        # Android uses specific PIN formatting
        # PIN is converted to bytes as ASCII digits
        pin_bytes = pin.encode('ascii')
        
        if algorithm.lower() == "sha1":
            if salt:
                # Salted SHA-1: salt:hash
                hash_obj = hashlib.sha1()
                hash_obj.update(binascii.unhexlify(salt))
                hash_obj.update(pin_bytes)
                return f"{salt}:{hash_obj.hexdigest()}"
            else:
                return hashlib.sha1(pin_bytes).hexdigest()
        
        elif algorithm.lower() == "md5":
            if salt:
                hash_obj = hashlib.md5()
                hash_obj.update(binascii.unhexlify(salt))
                hash_obj.update(pin_bytes)
                return f"{salt}:{hash_obj.hexdigest()}"
            else:
                return hashlib.md5(pin_bytes).hexdigest()
        
        elif algorithm.lower() == "sha256":
            if salt:
                hash_obj = hashlib.sha256()
                hash_obj.update(binascii.unhexlify(salt))
                hash_obj.update(pin_bytes)
                return f"{salt}:{hash_obj.hexdigest()}"
            else:
                return hashlib.sha256(pin_bytes).hexdigest()
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def hash_android_pattern(self, pattern: str, grid_size: int = 3) -> str:
        """
        Hash Android lock pattern.
        
        Args:
            pattern: Pattern as dot numbers (e.g., "1-2-3-6-9")
            grid_size: Grid size (default 3x3)
            
        Returns:
            SHA-1 hash of the pattern
        """
        # Android pattern hashing uses specific byte encoding
        pattern_bytes = self._pattern_to_bytes(pattern, grid_size)
        return hashlib.sha1(pattern_bytes).hexdigest()
    
    def _pattern_to_bytes(self, pattern: str, grid_size: int) -> bytes:
        """
        Convert pattern string to Android byte format.
        
        Args:
            pattern: Pattern string (e.g., "1-2-3")
            grid_size: Grid size
            
        Returns:
            Byte representation for hashing
        """
        dots = pattern.split("-")
        
        # Android uses specific byte encoding for patterns
        # Each dot is converted to its byte value (1-9 for 3x3 grid)
        pattern_bytes = bytearray()
        
        for dot in dots:
            try:
                dot_num = int(dot)
                if 1 <= dot_num <= (grid_size * grid_size):
                    pattern_bytes.append(dot_num)
                else:
                    raise ValueError(f"Invalid dot number: {dot_num}")
            except ValueError:
                raise ValueError(f"Invalid pattern format: {pattern}")
        
        return bytes(pattern_bytes)
    
    def hash_password(self, password: str, salt: Optional[str] = None, 
                     algorithm: str = "sha256") -> str:
        """
        Hash password using specified algorithm.
        
        Args:
            password: Password to hash
            salt: Optional salt
            algorithm: Hash algorithm
            
        Returns:
            Password hash
        """
        password_bytes = password.encode('utf-8')
        
        if salt:
            salt_bytes = salt.encode('utf-8') if isinstance(salt, str) else salt
        
        if algorithm.lower() == "sha1":
            if salt:
                return hashlib.sha1(salt_bytes + password_bytes).hexdigest()
            else:
                return hashlib.sha1(password_bytes).hexdigest()
        
        elif algorithm.lower() == "sha256":
            if salt:
                return hashlib.sha256(salt_bytes + password_bytes).hexdigest()
            else:
                return hashlib.sha256(password_bytes).hexdigest()
        
        elif algorithm.lower() == "sha512":
            if salt:
                return hashlib.sha512(salt_bytes + password_bytes).hexdigest()
            else:
                return hashlib.sha512(password_bytes).hexdigest()
        
        elif algorithm.lower() == "md5":
            if salt:
                return hashlib.md5(salt_bytes + password_bytes).hexdigest()
            else:
                return hashlib.md5(password_bytes).hexdigest()
        
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")
    
    def generate_pin_hashes(self, pin_length: int = 4, algorithm: str = "sha1",
                           salt: Optional[str] = None) -> Dict[str, str]:
        """
        Generate all possible PIN hashes for specified length.
        
        Args:
            pin_length: Length of PIN (4-8)
            algorithm: Hash algorithm
            salt: Optional salt
            
        Returns:
            Dictionary mapping PINs to their hashes
        """
        if not (4 <= pin_length <= 8):
            raise ValueError("PIN length must be 4-8 digits")
        
        pin_hashes = {}
        
        # Generate all possible PINs
        start = 10 ** (pin_length - 1) if pin_length > 1 else 0
        end = 10 ** pin_length
        
        for pin_int in range(start, end):
            pin = str(pin_int).zfill(pin_length)
            try:
                pin_hash = self.hash_android_pin(pin, salt, algorithm)
                pin_hashes[pin] = pin_hash
            except Exception as e:
                self.logger.warning(f"Failed to hash PIN {pin}: {e}")
        
        self.logger.info(f"Generated {len(pin_hashes)} PIN hashes")
        return pin_hashes
    
    def crack_pin_hash(self, target_hash: str, max_length: int = 8,
                      algorithm: str = "sha1", salt: Optional[str] = None,
                      hash_file: Optional[str] = None) -> Optional[str]:
        """
        Crack Android PIN hash using brute force.
        
        Args:
            target_hash: Hash to crack
            max_length: Maximum PIN length to try
            algorithm: Hash algorithm used
            salt: Salt if used
            hash_file: Optional file to save generated hashes
            
        Returns:
            Cracked PIN or None if not found
        """
        target_hash = target_hash.lower()
        
        # Try each PIN length
        for length in range(4, max_length + 1):
            self.logger.info(f"Trying PIN length {length}")
            
            # Generate hashes for this length
            pin_hashes = self.generate_pin_hashes(length, algorithm, salt)
            
            # Save to file if requested
            if hash_file:
                self._save_hash_file(pin_hashes, hash_file, length)
            
            # Check for match
            for pin, pin_hash in pin_hashes.items():
                if pin_hash.lower() == target_hash:
                    self.logger.info(f"PIN cracked: {pin}")
                    return pin
        
        self.logger.info("PIN not cracked")
        return None
    
    def _save_hash_file(self, pin_hashes: Dict[str, str], 
                       base_filename: str, length: int) -> None:
        """Save hash file for hashcat."""
        filename = f"{base_filename}_{length}digit.txt"
        
        with open(filename, "w") as f:
            for pin, pin_hash in pin_hashes.items():
                f.write(f"{pin_hash}\n")
        
        self.logger.info(f"Saved {len(pin_hashes)} hashes to {filename}")
    
    def verify_hash(self, plaintext: str, target_hash: str, 
                   algorithm: str = "sha1", salt: Optional[str] = None) -> bool:
        """
        Verify if plaintext matches hash.
        
        Args:
            plaintext: Plaintext to check
            target_hash: Hash to compare against
            algorithm: Hash algorithm
            salt: Optional salt
            
        Returns:
            True if match, False otherwise
        """
        try:
            if algorithm.lower() in ["sha1", "md5", "sha256"]:
                computed_hash = self.hash_android_pin(plaintext, salt, algorithm)
            else:
                computed_hash = self.hash_password(plaintext, salt, algorithm)
            
            return computed_hash.lower() == target_hash.lower()
        except Exception as e:
            self.logger.error(f"Hash verification error: {e}")
            return False
    
    def calculate_entropy(self, data: str) -> float:
        """
        Calculate Shannon entropy of a string.
        
        Args:
            data: Input string
            
        Returns:
            Entropy value in bits
        """
        if not data:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for char in data:
            freq[char] = freq.get(char, 0) + 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in freq.values():
            p = count / data_len
            if p > 0:
                entropy -= p * (p.bit_length() - 1)
        
        return entropy
    
    def get_hashcat_command(self, hash_file: str, wordlist: str, 
                           hash_mode: int, attack_mode: str = "0") -> List[str]:
        """
        Generate hashcat command for given parameters.
        
        Args:
            hash_file: Path to hash file
            wordlist: Path to wordlist
            hash_mode: Hashcat hash mode
            attack_mode: Hashcat attack mode
            
        Returns:
            Hashcat command as list
        """
        return [
            "hashcat",
            "-m", str(hash_mode),
            "-a", attack_mode,
            "-o", "cracked.txt",
            hash_file,
            wordlist,
            "--force",
            "--potfile-disable"
        ]
    
    def analyze_hash_strength(self, hash_string: str) -> Dict[str, Any]:
        """
        Analyze hash strength and provide recommendations.
        
        Args:
            hash_string: Hash to analyze
            
        Returns:
            Dictionary with strength analysis
        """
        analysis = {
            "hash": hash_string,
            "length": len(hash_string),
            "possible_types": self.identify_hash(hash_string),
            "entropy": self.calculate_entropy(hash_string),
            "strength": "unknown",
            "recommendations": []
        }
        
        # Determine strength based on hash type and length
        hash_len = len(hash_string)
        
        if hash_len == 32:  # MD5
            analysis["strength"] = "very_weak"
            analysis["recommendations"].append("MD5 is cryptographically broken")
            analysis["recommendations"].append("Use SHA-256 or stronger")
            
        elif hash_len == 40:  # SHA-1
            analysis["strength"] = "weak"
            analysis["recommendations"].append("SHA-1 is deprecated")
            analysis["recommendations"].append("Use SHA-256 or stronger")
            
        elif hash_len == 64:  # SHA-256
            analysis["strength"] = "good"
            analysis["recommendations"].append("SHA-256 is currently secure")
            
        elif hash_len == 128:  # SHA-512
            analysis["strength"] = "strong"
            analysis["recommendations"].append("SHA-512 is secure")
            
        else:
            analysis["strength"] = "unknown"
            analysis["recommendations"].append("Unknown hash format")
        
        # Add entropy-based recommendations
        if analysis["entropy"] < 3.0:
            analysis["recommendations"].append("Low entropy detected - vulnerable to attacks")
        
        return analysis
    
    def hash_file_contents(self, file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """
        Calculate hash of file contents.
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm
            
        Returns:
            File hash or None if error
        """
        try:
            hash_obj = getattr(hashlib, algorithm.lower())()
            
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
            
        except Exception as e:
            self.logger.error(f"File hashing error: {e}")
            return None
    
    def compare_hashes(self, hash1: str, hash2: str) -> bool:
        """
        Compare two hashes for equality (case-insensitive).
        
        Args:
            hash1: First hash
            hash2: Second hash
            
        Returns:
            True if hashes are equal
        """
        return hash1.lower() == hash2.lower()
    
    def generate_random_salt(self, length: int = 16) -> str:
        """
        Generate random salt.
        
        Args:
            length: Salt length in bytes
            
        Returns:
            Hex-encoded salt
        """
        import os
        return os.urandom(length).hex()
    
    def hmac_hash(self, key: str, message: str, algorithm: str = "sha256") -> str:
        """
        Calculate HMAC hash.
        
        Args:
            key: HMAC key
            message: Message to hash
            algorithm: Hash algorithm
            
        Returns:
            HMAC hash
        """
        key_bytes = key.encode('utf-8')
        message_bytes = message.encode('utf-8')
        
        if algorithm.lower() == "sha1":
            return hmac.new(key_bytes, message_bytes, hashlib.sha1).hexdigest()
        elif algorithm.lower() == "sha256":
            return hmac.new(key_bytes, message_bytes, hashlib.sha256).hexdigest()
        elif algorithm.lower() == "sha512":
            return hmac.new(key_bytes, message_bytes, hashlib.sha512).hexdigest()
        elif algorithm.lower() == "md5":
            return hmac.new(key_bytes, message_bytes, hashlib.md5).hexdigest()
        else:
            raise ValueError(f"Unsupported HMAC algorithm: {algorithm}")