import math
import re
import random
from enum import Enum

class StrengthLevel(Enum):
    WEAK = "Weak"
    MODERATE = "Moderate"
    STRONG = "Strong"

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

        # Determine strength level
        if score >= 5:
            strength = StrengthLevel.STRONG
        elif score >= 3:
            strength = StrengthLevel.MODERATE
        else:
            strength = StrengthLevel.WEAK

        return {
            "strength": strength.value,
            "score": score,
            "issues": issues,
            "suggestions": random.sample(suggestions, min(3, len(suggestions)))
        }
