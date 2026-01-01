r"""
# SecureTool Library

SecureTool is a comprehensive cybersecurity utility library designed to simplify security tasks such as network scanning, web scraping, password strength checking, encryption, and validation. With SecureTool, you get powerful, easy-to-use tools for vulnerability discovery and data extraction.

## Features

### Scanner

- Perform various types of scans on individual IP addresses or entire networks.
- Supports multiple scanning modes including:
  - `regular` — scans ports 1-1024
  - `quick` — scans 100 common ports quickly
  - `deep` — scans 1000 ports with OS and version detection
  - `stealth` — stealth SYN scan to avoid detection
  - `vulnerability` — scan for common vulnerabilities
  - `deep scan plus udp` — scans both TCP and UDP ports
  - `deep_scan_plusAll_TCP_ports` — scans all 65535 TCP ports
- Retrieves information such as open/closed ports, OS detection, and response times.
- Utilizes `nmap` for accurate and efficient scanning.

### Password Strength Checker

- Checks password complexity based on length, digits, letters, special characters, uppercase and lowercase letters.
- Provides clear feedback on missing criteria for improving password strength.
- Classifies passwords into **Strong**, **Moderate**, or **Weak** categories based on comprehensive checks.
- Generate secure random passwords and passphrases.
- Calculate password entropy.
- Hash passwords using various algorithms.

### Web Scraper

- Extract links, forms, and external JavaScript/CSS files from any given webpage.
- Save webpage content as pretty HTML or structured JSON data.
- Search for specific keywords within webpage content and return matching sentences.
- Check security headers (HSTS, CSP, X-Frame-Options, etc.).
- Extract metadata (Open Graph, Twitter Cards).
- Check SSL/TLS certificate information.
- Scan for exposed sensitive data (emails, API keys, etc.).
- Robust error handling for HTTP and parsing issues.

### Encryption

- Encrypt and decrypt data using Fernet symmetric encryption.
- Generate encryption keys.
- Hash data using various algorithms (MD5, SHA1, SHA256, SHA512, BLAKE2b).
- Generate keys from passwords using PBKDF2.

### Validation

- Validate email addresses, URLs, IP addresses, and ports.
- Sanitize user input to prevent injection attacks.
- Validate network ranges (CIDR notation).

## Installation

SecureTool requires Python 3.6+ and `nmap` installed on your system.

Install SecureTool via pip:

```bash
pip install SecureTool
```

Make sure nmap is installed:

**Windows**: Download from [https://nmap.org/download.html](https://nmap.org/download.html)

**Linux/macOS**:

```bash
sudo apt install nmap   # Debian/Ubuntu
brew install nmap       # macOS (Homebrew)
```

## Usage Examples

### Scanner

```python
from SecureTool import Scanner

scanner = Scanner()
result = scanner.regular_scan("192.168.1.1")
print(result)

# Vulnerability scan
vuln_result = scanner.vulnerability_scan("192.168.1.1")
print(vuln_result)
```

### Password Strength Checker

```python
from SecureTool import PasswordStrengthChecker

checker = PasswordStrengthChecker()
result = checker.check_strength("YourPassword123!")
print(result)

# Generate secure password
password = checker.generate_password(length=20)
print(f"Generated password: {password}")
```

### Web Scraper

```python
from SecureTool import Scraper

scraper = Scraper()
links = scraper.extract_links("https://example.com")
print(links)

# Check security headers
headers = scraper.check_security_headers("https://example.com")
print(headers)
```

### Encryption

```python
from SecureTool import Encryption

# Encrypt data
result = Encryption.encrypt_data("Sensitive data")
print(result)

# Decrypt data
decrypted = Encryption.decrypt_data(result["encrypted_data"], result["key"])
print(decrypted)
```

### Validation

```python
from SecureTool import Validation

# Validate email
email_result = Validation.validate_email("user@example.com")
print(email_result)

# Validate URL
url_result = Validation.validate_url("https://example.com")
print(url_result)
```

## Contributing

Contributions are highly welcomed! Feel free to open issues or submit pull requests to enhance SecureTool further.

## License

SecureTool is licensed under the MIT License. See the LICENSE file for details.

## Contact

For questions, support, or feedback:

📧 whoamialan11@gmail.com  
🔗 GitHub Repository

If you want a professional, reliable security toolset — SecureTool is ready to empower your cybersecurity projects. Download and get started today! 🚀
"""

from .Scanning import Scanner
from .Password import PasswordStrengthChecker
from .Scraping import Scraper
from .Encryption import Encryption
from .Validation import Validation

__all__ = [
    "Scanner",
    "PasswordStrengthChecker",
    "Scraper",
    "Encryption",
    "Validation"
]

__version__ = "2.1.0"
