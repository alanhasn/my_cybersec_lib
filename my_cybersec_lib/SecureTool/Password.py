import math
import re
import random
import string
import hashlib
import secrets
from enum import Enum
from typing import Optional, Dict, List

class StrengthLevel(Enum):
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"
    VERY_STRONG = "Very Strong"

class PasswordStrengthChecker:
    def __init__(self, username: str = ""):
        self.special_characters = "!@#$%^&*()-+?_=,<>/"
        self.common_patterns = ["1234", "abcd", "password", "qwerty", "admin", "letmein"]
        self.username = username.lower()

    def check_strength(self, password: str):
        score = 0
        issues = []
        suggestions = []

        # Length check
        if len(password) >= 12:
            score += 1
        else:
            issues.append("Length should be at least 12 characters.")
            suggestions.append("Increase password length to 12 or more.")

        # Digit check
        if any(char.isdigit() for char in password):
            score += 1
        else:
            issues.append("Password should include at least one digit.")
            suggestions.append("Add at least one digit (0-9).")

        # Letter check
        if any(char.isalpha() for char in password):
            score += 1
        else:
            issues.append("Password should include at least one letter.")
            suggestions.append("Include alphabetic characters (a-z, A-Z).")

        # Special character check
        if any(char in self.special_characters for char in password):
            score += 1
        else:
            issues.append("Password should include at least one special character.")
            suggestions.append("Use special characters like @, $, #, etc.")

        # Lowercase letter
        if any(char.islower() for char in password):
            score += 1
        else:
            issues.append("Password should include at least one lowercase letter.")
            suggestions.append("Add lowercase letters (a-z).")

        # Uppercase letter
        if any(char.isupper() for char in password):
            score += 1
        else:
            issues.append("Password should include at least one uppercase letter.")
            suggestions.append("Add uppercase letters (A-Z).")

        # Check common patterns
        if any(pattern in password.lower() for pattern in self.common_patterns):
            issues.append("Password contains a common weak pattern.")
            suggestions.append("Avoid using common patterns like '1234' or 'password'.")
            score -= 1

        # Repeated characters
        if re.search(r"(.)\1{2,}", password):
            issues.append("Password contains repeated characters.")
            suggestions.append("Avoid repeating characters like 'aaa' or '111' too much.")
            score -= 1

        # Check for username
        if self.username and self.username in password.lower():
            issues.append("Password should not contain your username.")
            suggestions.append("Avoid using your username in your password.")
            score -= 1

        # Calculate entropy
        entropy = self._calculate_entropy(password)

        # Determine strength level
        if score >= 6 and entropy >= 80:
            strength = StrengthLevel.VERY_STRONG
        elif score >= 5:
            strength = StrengthLevel.STRONG
        elif score >= 3:
            strength = StrengthLevel.MODERATE
        else:
            strength = StrengthLevel.WEAK

        return {
            "strength": strength.value,
            "score": score,
            "entropy": round(entropy, 2),
            "issues": issues,
            "suggestions": random.sample(suggestions, min(3, len(suggestions))) if suggestions else []
        }

    def _calculate_entropy(self, password: str) -> float:
        """
        Calculate password entropy (measure of randomness).

        Parameters
        ----------
        password : str
            The password to analyze.

        Returns
        -------
        float
            Entropy value in bits.
        """
        if not password:
            return 0.0

        # Determine character set size
        charset_size = 0
        if any(c.islower() for c in password):
            charset_size += 26
        if any(c.isupper() for c in password):
            charset_size += 26
        if any(c.isdigit() for c in password):
            charset_size += 10
        if any(c in self.special_characters for c in password):
            charset_size += len(self.special_characters)

        if charset_size == 0:
            return 0.0

        # Calculate entropy: log2(charset_size^length)
        entropy = len(password) * math.log2(charset_size)
        return entropy

    def generate_password(
        self,
        length: int = 16,
        include_uppercase: bool = True,
        include_lowercase: bool = True,
        include_digits: bool = True,
        include_special: bool = True,
        exclude_similar: bool = True
    ) -> str:
        """
        Generate a secure random password.

        Parameters
        ----------
        length : int, optional
            Length of the password. Defaults to 16.
        include_uppercase : bool, optional
            Include uppercase letters. Defaults to True.
        include_lowercase : bool, optional
            Include lowercase letters. Defaults to True.
        include_digits : bool, optional
            Include digits. Defaults to True.
        include_special : bool, optional
            Include special characters. Defaults to True.
        exclude_similar : bool, optional
            Exclude similar characters (i, l, 1, L, o, 0, O). Defaults to True.

        Returns
        -------
        str
            Generated password.
        """
        if length < 4:
            raise ValueError("Password length must be at least 4 characters")

        charset = ""
        if include_lowercase:
            charset += string.ascii_lowercase
        if include_uppercase:
            charset += string.ascii_uppercase
        if include_digits:
            charset += string.digits
        if include_special:
            charset += self.special_characters

        if not charset:
            raise ValueError("At least one character set must be included")

        if exclude_similar:
            similar_chars = "il1Lo0O"
            charset = "".join(c for c in charset if c not in similar_chars)

        # Ensure at least one character from each selected set
        password_chars = []
        if include_lowercase:
            password_chars.append(secrets.choice(string.ascii_lowercase))
        if include_uppercase:
            password_chars.append(secrets.choice(string.ascii_uppercase))
        if include_digits:
            password_chars.append(secrets.choice(string.digits))
        if include_special:
            password_chars.append(secrets.choice(self.special_characters))

        # Fill the rest randomly
        remaining_length = length - len(password_chars)
        password_chars.extend(secrets.choice(charset) for _ in range(remaining_length))

        # Shuffle to avoid predictable patterns
        random.shuffle(password_chars)

        return "".join(password_chars)

    def hash_password(self, password: str, algorithm: str = "sha256") -> Dict[str, str]:
        """
        Hash a password using the specified algorithm.

        Parameters
        ----------
        password : str
            The password to hash.
        algorithm : str, optional
            Hash algorithm (md5, sha1, sha256, sha512). Defaults to "sha256".

        Returns
        -------
        dict
            Dictionary containing hash algorithm and hash value.
        """
        algorithms = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
            "sha512": hashlib.sha512
        }

        if algorithm.lower() not in algorithms:
            raise ValueError(f"Unsupported algorithm. Choose from: {list(algorithms.keys())}")

        hash_func = algorithms[algorithm.lower()]()
        hash_func.update(password.encode('utf-8'))
        hash_value = hash_func.hexdigest()

        return {
            "algorithm": algorithm.upper(),
            "hash": hash_value
        }

    def verify_password_hash(self, password: str, hash_value: str, algorithm: str = "sha256") -> bool:
        """
        Verify a password against a hash.

        Parameters
        ----------
        password : str
            The password to verify.
        hash_value : str
            The hash to compare against.
        algorithm : str, optional
            Hash algorithm used. Defaults to "sha256".

        Returns
        -------
        bool
            True if password matches hash, False otherwise.
        """
        computed_hash = self.hash_password(password, algorithm)
        return computed_hash["hash"].lower() == hash_value.lower()

    def generate_passphrase(self, word_count: int = 4, separator: str = "-") -> str:
        """
        Generate a memorable passphrase using random words.

        Parameters
        ----------
        word_count : int, optional
            Number of words in the passphrase. Defaults to 4.
        separator : str, optional
            Separator between words. Defaults to "-".

        Returns
        -------
        str
            Generated passphrase.
        """
        # Common word list for passphrase generation
        words = [
            "apple", "banana", "cherry", "dolphin", "elephant", "forest", "guitar",
            "honey", "island", "jungle", "knight", "lighthouse", "mountain", "ocean",
            "penguin", "quasar", "rainbow", "sunset", "tiger", "umbrella", "volcano",
            "waterfall", "xylophone", "yacht", "zebra", "anchor", "bridge", "castle",
            "diamond", "eagle", "falcon", "glacier", "horizon", "iceberg", "jaguar",
            "kangaroo", "leopard", "moonlight", "nebula", "octopus", "panther",
            "quartz", "river", "starfish", "tornado", "unicorn", "vortex", "whale",
            "xenon", "yogurt", "zenith"
        ]

        selected_words = [secrets.choice(words) for _ in range(word_count)]
        return separator.join(selected_words)
