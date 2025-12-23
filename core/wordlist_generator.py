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

import itertools
import logging
from typing import List, Dict, Set, Optional, Generator, Tuple
from pathlib import Path
import re


class WordlistGenerator:
    """
    Comprehensive wordlist generator for Android security testing.
    
    Generates:
    - PIN combinations (4-8 digits)
    - Android patterns (3-9 dots, 389,112 combinations)
    - Keyboard walks
    - Common patterns
    - Season/year combinations
    - Custom wordlists
    """
    
    # Android pattern grid (3x3)
    PATTERN_GRID = {
        1: (0, 0), 2: (0, 1), 3: (0, 2),
        4: (1, 0), 5: (1, 1), 6: (1, 2),
        7: (2, 0), 8: (2, 1), 9: (2, 2)
    }
    
    # Pattern constraints - which dots can be reached from each dot
    PATTERN_CONSTRAINTS = {
        1: {3: 2, 7: 4, 9: 5},
        2: {8: 5},
        3: {1: 2, 7: 5, 9: 6},
        4: {6: 5},
        5: {},
        6: {4: 5},
        7: {1: 4, 3: 5, 9: 8},
        8: {2: 5},
        9: {1: 5, 3: 6, 7: 8}
    }
    
    def __init__(self):
        """Initialize wordlist generator."""
        self.logger = logging.getLogger("AST.WordlistGenerator")
    
    def generate_pins(self, min_length: int = 4, max_length: int = 8) -> List[str]:
        """
        Generate all possible PIN combinations.
        
        Args:
            min_length: Minimum PIN length
            max_length: Maximum PIN length
            
        Returns:
            List of all PIN combinations
        """
        pins = []
        
        for length in range(min_length, max_length + 1):
            # Generate all combinations of digits for this length
            for combo in itertools.product('0123456789', repeat=length):
                pins.append(''.join(combo))
        
        self.logger.info(f"Generated {len(pins)} PINs (length {min_length}-{max_length})")
        return pins
    
    def generate_patterns(self, min_dots: int = 3, max_dots: int = 9) -> List[str]:
        """
        Generate all valid Android lock patterns.
        
        Android patterns must:
        - Use at least 3 dots
        - Use at most 9 dots  
        - Cannot skip over dots without including them
        
        Args:
            min_dots: Minimum number of dots
            max_dots: Maximum number of dots
            
        Returns:
            List of all valid patterns (e.g., ["1-2-3", "1-4-7", ...])
        """
        patterns = []
        
        def is_valid_pattern(pattern: List[int]) -> bool:
            """Check if pattern follows Android rules."""
            if len(pattern) < min_dots:
                return False
            
            used = set()
            for i, current_dot in enumerate(pattern):
                if current_dot in used:
                    return False  # Cannot reuse dots
                
                used.add(current_dot)
                
                if i > 0:
                    prev_dot = pattern[i - 1]
                    
                    # Check if we need to include an intermediate dot
                    if prev_dot in self.PATTERN_CONSTRAINTS:
                        required_intermediate = self.PATTERN_CONSTRAINTS[prev_dot].get(current_dot)
                        if required_intermediate and required_intermediate not in used:
                            return False
            
            return True
        
        def generate_patterns_recursive(current_pattern: List[int], remaining_dots: Set[int]):
            """Recursively generate valid patterns."""
            # Add current pattern if valid
            if len(current_pattern) >= min_dots and len(current_pattern) <= max_dots:
                if is_valid_pattern(current_pattern[:]):
                    patterns.append("-".join(map(str, current_pattern)))
            
            # Stop if we've reached max length
            if len(current_pattern) >= max_dots:
                return
            
            # Try each remaining dot
            for dot in remaining_dots:
                new_pattern = current_pattern + [dot]
                
                # Quick validation check
                if len(new_pattern) > 1:
                    prev_dot = new_pattern[-2]
                    
                    # Check if intermediate dot is required
                    if prev_dot in self.PATTERN_CONSTRAINTS:
                        required = self.PATTERN_CONSTRAINTS[prev_dot].get(dot)
                        if required and required not in new_pattern[:-1]:
                            continue
                
                generate_patterns_recursive(
                    new_pattern,
                    remaining_dots - {dot}
                )
        
        # Start generation from each possible starting dot
        for start_dot in range(1, 10):
            generate_patterns_recursive([start_dot], set(range(1, 10)) - {start_dot})
        
        self.logger.info(f"Generated {len(patterns)} valid Android patterns")
        return patterns
    
    def generate_all_patterns(self) -> List[str]:
        """
        Generate all 389,112 possible Android patterns.
        
        Returns:
            Complete list of all Android patterns
        """
        return self.generate_patterns(3, 9)
    
    def generate_keyboard_walks(self) -> List[str]:
        """
        Generate keyboard walk patterns.
        
        Returns:
            List of keyboard walk patterns
        """
        walks = []
        
        # Horizontal walks
        horizontal_patterns = [
            "qwerty", "asdfgh", "zxcvbn",
            "123456", "234567", "345678", "456789",
            "987654", "876543", "765432", "654321"
        ]
        
        # Vertical walks  
        vertical_patterns = [
            "qaz", "wsx", "edc", "rfv", "tgb", "yhn", "ujm",
            "qazwsx", "wsxedc", "edcrfv", "rfvtgb", "tgbyhn", "yhnujm",
            "1qaz", "2wsx", "3edc", "4rfv", "5tgb", "6yhn", "7ujm"
        ]
        
        # Diagonal walks
        diagonal_patterns = [
            "qwe", "asd", "zxc", "wer", "sdf", "xcv",
            "qay", "wax", "esz", "rdx", "tfc", "ygv"
        ]
        
        # Add all patterns
        walks.extend(horizontal_patterns)
        walks.extend(vertical_patterns)
        walks.extend(diagonal_patterns)
        
        # Add numeric variations
        numeric_walks = [
            "147", "258", "369", "741", "852", "963",
            "123", "456", "789", "321", "654", "987",
            "159", "357", "951", "753"
        ]
        walks.extend(numeric_walks)
        
        self.logger.info(f"Generated {len(walks)} keyboard walk patterns")
        return walks
    
    def generate_common_patterns(self) -> List[str]:
        """
        Generate common Android patterns.
        
        Returns:
            List of common patterns
        """
        patterns = []
        
        # L-shaped patterns
        l_patterns = [
            "1-4-7-8-9", "1-2-3-6-9", "3-6-9-8-7", "3-2-1-4-7",
            "7-8-9-6-3", "7-4-1-2-3", "9-8-7-4-1", "9-6-3-2-1"
        ]
        
        # Z-shaped patterns
        z_patterns = [
            "1-2-3-5-7-8-9", "3-2-1-5-7-8-9", "7-8-9-5-3-2-1", "9-8-7-5-1-2-3"
        ]
        
        # S-shaped patterns
        s_patterns = [
            "1-2-3-6-5-4-7-8-9", "3-2-1-4-5-6-9-8-7"
        ]
        
        # Box patterns
        box_patterns = [
            "1-2-3-6-9-8-7-4-1", "2-3-6-9-8-7-4-1-2",  # Outer box
            "1-2-3-5-9-8-7-5-1", "2-3-5-7-8-5-2"  # Inner patterns
        ]
        
        # Cross patterns
        cross_patterns = [
            "2-5-8", "4-5-6", "1-5-9", "3-5-7"
        ]
        
        patterns.extend(l_patterns)
        patterns.extend(z_patterns)
        patterns.extend(s_patterns)
        patterns.extend(box_patterns)
        patterns.extend(cross_patterns)
        
        self.logger.info(f"Generated {len(patterns)} common patterns")
        return patterns
    
    def generate_seasons_years(self, start_year: int = 2000, 
                              end_year: int = 2030) -> List[str]:
        """
        Generate season/year combinations.
        
        Args:
            start_year: Start year
            end_year: End year
            
        Returns:
            List of season/year combinations
        """
        combinations = []
        seasons = ["spring", "summer", "fall", "winter", "autumn"]
        
        # Season + year
        for year in range(start_year, end_year + 1):
            for season in seasons:
                combinations.append(f"{season}{year}")
                combinations.append(f"{season}{str(year)[2:]}")
                combinations.append(f"{year}{season}")
        
        # Month + year
        months = [
            "jan", "feb", "mar", "apr", "may", "jun",
            "jul", "aug", "sep", "oct", "nov", "dec"
        ]
        
        for year in range(start_year, end_year + 1):
            for month in months:
                combinations.append(f"{month}{year}")
                combinations.append(f"{month}{str(year)[2:]}")
        
        self.logger.info(f"Generated {len(combinations)} season/year combinations")
        return combinations
    
    def generate_custom_wordlist(self, base_words: List[str], 
                                transformations: List[str] = None) -> List[str]:
        """
        Generate custom wordlist with transformations.
        
        Args:
            base_words: Base words to transform
            transformations: List of transformation types
            
        Returns:
            Transformed wordlist
        """
        if transformations is None:
            transformations = ["lowercase", "uppercase", "capitalize", "reverse"]
        
        wordlist = set()
        
        for word in base_words:
            # Add original
            wordlist.add(word)
            
            # Apply transformations
            if "lowercase" in transformations:
                wordlist.add(word.lower())
            
            if "uppercase" in transformations:
                wordlist.add(word.upper())
            
            if "capitalize" in transformations:
                wordlist.add(word.capitalize())
            
            if "reverse" in transformations:
                wordlist.add(word[::-1])
            
            if "leet" in transformations:
                wordlist.update(self._apply_leet_speak(word))
            
            if "numbers" in transformations:
                wordlist.update(self._add_numbers(word))
        
        self.logger.info(f"Generated {len(wordlist)} custom words from {len(base_words)} base words")
        return list(wordlist)
    
    def _apply_leet_speak(self, word: str) -> List[str]:
        """Apply leet speak transformations."""
        leet_map = {
            'a': ['4', '@'],
            'e': ['3'],
            'i': ['1', '!'],
            'o': ['0'],
            's': ['5', '$'],
            't': ['7'],
            'l': ['1'],
            'g': ['9'],
            'b': ['8']
        }
        
        variations = [word]
        
        for char, replacements in leet_map.items():
            new_variations = []
            for variation in variations:
                for replacement in replacements:
                    new_variations.append(variation.replace(char, replacement))
                    new_variations.append(variation.replace(char.upper(), replacement))
            variations.extend(new_variations)
        
        return variations
    
    def _add_numbers(self, word: str) -> List[str]:
        """Add common number suffixes."""
        variations = []
        
        # Single digits
        for i in range(10):
            variations.append(f"{word}{i}")
            variations.append(f"{word}0{i}")
        
        # Years
        for year in range(1900, 2030):
            variations.append(f"{word}{year}")
            variations.append(f"{word}{str(year)[2:]}")
        
        # Common patterns
        patterns = ["123", "321", "007", "666", "777", "888", "999"]
        for pattern in patterns:
            variations.append(f"{word}{pattern}")
        
        return variations
    
    def save_wordlist(self, wordlist: List[str], filename: str, 
                     sort: bool = True, unique: bool = True) -> int:
        """
        Save wordlist to file.
        
        Args:
            wordlist: List of words to save
            filename: Output filename
            sort: Whether to sort the wordlist
            unique: Whether to remove duplicates
            
        Returns:
            Number of words saved
        """
        # Process wordlist
        words = wordlist.copy()
        
        if unique:
            words = list(set(words))
        
        if sort:
            words.sort()
        
        # Create directory if needed
        Path(filename).parent.mkdir(parents=True, exist_ok=True)
        
        # Save to file
        with open(filename, 'w') as f:
            for word in words:
                f.write(f"{word}\n")
        
        self.logger.info(f"Saved {len(words)} words to {filename}")
        return len(words)
    
    def load_wordlist(self, filename: str) -> List[str]:
        """
        Load wordlist from file.
        
        Args:
            filename: Wordlist filename
            
        Returns:
            List of words
        """
        words = []
        
        try:
            with open(filename, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word and not word.startswith('#'):
                        words.append(word)
        
        except Exception as e:
            self.logger.error(f"Failed to load wordlist {filename}: {e}")
        
        self.logger.info(f"Loaded {len(words)} words from {filename}")
        return words
    
    def filter_wordlist(self, wordlist: List[str], 
                       min_length: int = None,
                       max_length: int = None,
                       must_contain: List[str] = None,
                       must_not_contain: List[str] = None) -> List[str]:
        """
        Filter wordlist based on criteria.
        
        Args:
            wordlist: Wordlist to filter
            min_length: Minimum word length
            max_length: Maximum word length
            must_contain: List of required substrings
            must_not_contain: List of forbidden substrings
            
        Returns:
            Filtered wordlist
        """
        filtered = []
        
        for word in wordlist:
            # Length filtering
            if min_length and len(word) < min_length:
                continue
            
            if max_length and len(word) > max_length:
                continue
            
            # Required substrings
            if must_contain:
                if not all(substr in word for substr in must_contain):
                    continue
            
            # Forbidden substrings
            if must_not_contain:
                if any(substr in word for substr in must_not_contain):
                    continue
            
            filtered.append(word)
        
        self.logger.info(f"Filtered {len(wordlist)} to {len(filtered)} words")
        return filtered
    
    def combine_wordlists(self, wordlists: List[List[str]], 
                         unique: bool = True) -> List[str]:
        """
        Combine multiple wordlists.
        
        Args:
            wordlists: List of wordlists to combine
            unique: Whether to remove duplicates
            
        Returns:
            Combined wordlist
        """
        combined = []
        
        for wordlist in wordlists:
            combined.extend(wordlist)
        
        if unique:
            combined = list(set(combined))
        
        self.logger.info(f"Combined {len(wordlists)} wordlists into {len(combined)} words")
        return combined