# SecureTool Library

[![PyPI Downloads](https://static.pepy.tech/badge/securetool)](https://pepy.tech/projects/securetool)

SecureTool is a comprehensive cybersecurity utility library designed to simplify security tasks such as network scanning, web scraping, password strength checking, encryption, and validation. With SecureTool, you get powerful, easy-to-use tools for vulnerability discovery and data extraction.

## 🚀 Features

### 🔍 Scanner Module

Perform various types of network scans on individual IP addresses or entire networks.

**Scanning Modes:**

- `regular_scan()` — scans ports 1-1024
- `quick_scan()` — scans 100 common ports quickly
- `deep_scan()` — scans 1000 ports with OS and version detection
- `stealth_scan()` — stealth SYN scan to avoid detection
- `vulnerability_scan()` — scan for common vulnerabilities with recommendations
- `deep_udp_scan()` — scans both TCP and UDP ports
- `full_tcp_scan()` — scans all 65535 TCP ports
- `network_scan()` — scan entire network ranges
- `service_scan()` — detailed service detection on specific ports

**Capabilities:**

- Open/closed port detection
- OS fingerprinting
- Service version detection
- Vulnerability assessment
- Export results to JSON, CSV, or XML

### 🔐 Password Strength Checker

Comprehensive password security analysis and generation.

**Features:**

- Password strength analysis with entropy calculation
- Strength classification: Weak, Moderate, Strong, Very Strong
- Secure password generation with customizable options
- Passphrase generation for memorable passwords
- Password hashing (MD5, SHA1, SHA256, SHA512)
- Password verification against hashes
- Detailed feedback and suggestions

### 🌐 Web Scraper

Security-focused web scraping with vulnerability detection.

**Features:**

- Extract links, forms, JavaScript, CSS, and images
- Security headers analysis (HSTS, CSP, X-Frame-Options, etc.)
- SSL/TLS certificate validation
- Metadata extraction (Open Graph, Twitter Cards)
- Sensitive data scanning (emails, API keys, IPs, JWT tokens)
- Save content as HTML or JSON
- Keyword search in page content
- Configurable user-agent and timeout

### 🔒 Encryption Module

Cryptographic utilities for data protection.

**Features:**

- Fernet symmetric encryption/decryption
- Encryption key generation
- Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, BLAKE2b)
- PBKDF2 key derivation from passwords
- Hash verification

### ✅ Validation Module

Input validation and sanitization utilities.

**Features:**

- Email validation (RFC 5322 compliant)
- URL validation with optional accessibility check
- IP address validation (IPv4/IPv6) with metadata
- Port validation with well-known port detection
- Network range (CIDR) validation
- Input sanitization to prevent injection attacks
- SQL injection, XSS, and command injection detection

## 📦 Installation

SecureTool requires **Python 3.6+** and `nmap` installed on your system.

### Install SecureTool

```bash
pip install SecureTool
```

### Install nmap

**Windows**: Download from [https://nmap.org/download.html](https://nmap.org/download.html)

**Linux/macOS**:

```bash
sudo apt install nmap   # Debian/Ubuntu
brew install nmap       # macOS (Homebrew)
```

### Dependencies

The package automatically installs:

- `python-nmap` - Network scanning
- `requests` - HTTP requests
- `beautifulsoup4` - HTML parsing
- `cryptography` - Encryption/decryption

## 📖 Usage Examples

### Scanner

```python
from SecureTool import Scanner

scanner = Scanner()

# Regular port scan
result = scanner.regular_scan("192.168.1.1")
print(result)

# Quick scan
result = scanner.quick_scan("192.168.1.1")

# Deep scan with OS detection
result = scanner.deep_scan("192.168.1.1")

# Stealth scan (SYN scan)
result = scanner.stealth_scan("192.168.1.1")

# Vulnerability scan
vuln_result = scanner.vulnerability_scan("192.168.1.1")
print(vuln_result)

# Service detection on specific port
service_info = scanner.service_scan("192.168.1.1", 80)
print(service_info)

# Network scan
network_results = scanner.network_scan("192.168.1.0/24")

# Export results
scanner.export(result, "scan_results", format="json")
scanner.export(result, "scan_results", format="csv")
scanner.export(result, "scan_results", format="xml")
```

### Password Strength Checker

```python
from SecureTool import PasswordStrengthChecker

checker = PasswordStrengthChecker(username="john_doe")

# Check password strength
result = checker.check_strength("MyPassword123!")
print(f"Strength: {result['strength']}")
print(f"Score: {result['score']}")
print(f"Entropy: {result['entropy']} bits")
print(f"Issues: {result['issues']}")
print(f"Suggestions: {result['suggestions']}")

# Generate secure password
password = checker.generate_password(
    length=20,
    include_uppercase=True,
    include_lowercase=True,
    include_digits=True,
    include_special=True,
    exclude_similar=True
)
print(f"Generated password: {password}")

# Generate passphrase
passphrase = checker.generate_passphrase(word_count=4, separator="-")
print(f"Generated passphrase: {passphrase}")

# Hash password
hash_result = checker.hash_password("MyPassword123!", algorithm="sha256")
print(f"Hash: {hash_result['hash']}")

# Verify password against hash
is_valid = checker.verify_password_hash(
    "MyPassword123!",
    hash_result['hash'],
    algorithm="sha256"
)
print(f"Password valid: {is_valid}")
```

### Web Scraper

```python
from SecureTool import Scraper

# Initialize scraper with custom settings
scraper = Scraper(user_agent="Custom-Agent/1.0", timeout=15)

# Extract links
links = scraper.extract_links("https://example.com", absolute_urls=True)
print(links)

# Extract forms
forms = scraper.extract_forms("https://example.com")
print(forms)

# Extract JavaScript files
js_files = scraper.extract_js_files("https://example.com")
print(js_files)

# Extract CSS files
css_files = scraper.extract_css_files("https://example.com")
print(css_files)

# Extract images
images = scraper.extract_images("https://example.com")
print(images)

# Check security headers
headers = scraper.check_security_headers("https://example.com")
print(f"Security Score: {headers['security_score']}%")
print(f"Found Headers: {headers['found_headers']}")
print(f"Missing Headers: {headers['missing_headers']}")
print(f"Recommendations: {headers['recommendations']}")

# Extract metadata
metadata = scraper.extract_metadata("https://example.com")
print(metadata)

# Check SSL certificate
ssl_info = scraper.check_ssl_certificate("https://example.com")
print(ssl_info)

# Scan for sensitive data
sensitive_data = scraper.extract_sensitive_data("https://example.com")
print(sensitive_data)

# Search for keywords
matches = scraper.search_in_page("https://example.com", "security")
print(matches)

# Save as HTML
scraper.scrape_and_save("https://example.com", "page.html")

# Save as JSON
scraper.save_as_json("https://example.com", "page_data.json")
```

### Encryption

```python
from SecureTool import Encryption

# Encrypt data
encryption_result = Encryption.encrypt_data("Sensitive information")
print(f"Encrypted: {encryption_result['encrypted_data']}")
print(f"Key: {encryption_result['key']}")

# Decrypt data
decryption_result = Encryption.decrypt_data(
    encryption_result['encrypted_data'],
    encryption_result['key']
)
print(f"Decrypted: {decryption_result['decrypted_data']}")

# Generate encryption key
key = Encryption.generate_key()
print(f"Generated key: {key}")

# Hash data
hash_result = Encryption.hash_data("Data to hash", algorithm="sha256")
print(f"Hash: {hash_result['hash']}")

# Verify hash
is_valid = Encryption.verify_hash("Data to hash", hash_result['hash'], "sha256")
print(f"Hash valid: {is_valid}")

# Generate key from password
key_result = Encryption.generate_key_from_password("MyPassword123!")
print(f"Key: {key_result['key']}")
print(f"Salt: {key_result['salt']}")
```

### Validation

```python
from SecureTool import Validation

# Validate email
email_result = Validation.validate_email("user@example.com")
if email_result['valid']:
    print(f"Valid email: {email_result['email']}")
    print(f"Domain: {email_result['domain']}")
else:
    print(f"Invalid email: {email_result['error']}")

# Validate URL
url_result = Validation.validate_url("https://example.com", check_accessibility=True)
if url_result['valid']:
    print(f"Valid URL: {url_result['url']}")
    print(f"Scheme: {url_result['scheme']}")
    print(f"Accessible: {url_result.get('accessible', False)}")
else:
    print(f"Invalid URL: {url_result['error']}")

# Validate IP address
ip_result = Validation.validate_ip("192.168.1.1")
if ip_result['valid']:
    print(f"Valid IP: {ip_result['ip']}")
    print(f"Version: IPv{ip_result['version']}")
    print(f"Private: {ip_result['is_private']}")
    print(f"Loopback: {ip_result['is_loopback']}")

# Validate port
port_result = Validation.validate_port(443)
if port_result['valid']:
    print(f"Valid port: {port_result['port']}")
    print(f"Service: {port_result['service']}")
    print(f"Well-known: {port_result['is_well_known']}")

# Validate network range
network_result = Validation.validate_network_range("192.168.1.0/24")
if network_result['valid']:
    print(f"Valid network: {network_result['network']}")
    print(f"Netmask: {network_result['netmask']}")
    print(f"Hosts: {network_result['num_hosts']}")

# Sanitize input
input_result = Validation.sanitize_input("user input<script>alert('xss')</script>")
print(f"Sanitized: {input_result['sanitized']}")
print(f"Safe: {input_result['is_safe']}")
print(f"Detected patterns: {input_result['detected_patterns']}")
```

## 📚 API Reference

### Scanner Class

#### Methods

- `regular_scan(ip: str) -> dict` - Regular port scan (ports 1-1024)
- `quick_scan(ip: str) -> dict` - Quick scan of common ports
- `deep_scan(ip: str) -> dict` - Deep scan with OS detection
- `stealth_scan(ip: str) -> dict` - Stealth SYN scan
- `vulnerability_scan(ip: str, ports: List[int] = None) -> dict` - Vulnerability scan
- `deep_udp_scan(ip: str) -> dict` - Deep UDP scan
- `full_tcp_scan(ip: str) -> dict` - Full TCP port scan
- `network_scan(network_range: str) -> list` - Scan network range
- `service_scan(ip: str, port: int) -> dict` - Service detection
- `port_scan(ip: str, port: int, protocol: str = "tcp") -> dict` - Single port scan
- `version_scan(ip: str) -> dict` - Version detection scan
- `get_os_info(ip: str) -> dict` - OS detection
- `export(data: dict, filename: str, format: str = "json") -> str` - Export results

### PasswordStrengthChecker Class

#### Methods

- `check_strength(password: str) -> dict` - Check password strength
- `generate_password(length: int = 16, ...) -> str` - Generate secure password
- `generate_passphrase(word_count: int = 4, separator: str = "-") -> str` - Generate passphrase
- `hash_password(password: str, algorithm: str = "sha256") -> dict` - Hash password
- `verify_password_hash(password: str, hash_value: str, algorithm: str = "sha256") -> bool` - Verify password

### Scraper Class

#### Methods

- `scrape_and_save(website_url: str, file_name: str = "data.html") -> dict` - Save page as HTML
- `extract_links(website_url: str, absolute_urls: bool = True) -> dict` - Extract links
- `extract_forms(website_url: str) -> dict` - Extract forms
- `extract_js_files(website_url: str, absolute_urls: bool = True) -> dict` - Extract JS files
- `extract_css_files(website_url: str, absolute_urls: bool = True) -> dict` - Extract CSS files
- `extract_images(website_url: str, absolute_urls: bool = True) -> dict` - Extract images
- `extract_metadata(website_url: str) -> dict` - Extract metadata
- `check_security_headers(website_url: str) -> dict` - Check security headers
- `check_ssl_certificate(website_url: str) -> dict` - Check SSL certificate
- `extract_sensitive_data(website_url: str) -> dict` - Scan for sensitive data
- `search_in_page(website_url: str, keyword: str) -> dict` - Search keywords
- `save_as_json(website_url: str, file_name: str = "output.json") -> dict` - Save as JSON

### Encryption Class

#### Static Methods

- `encrypt_data(data: str, key: bytes = None) -> dict` - Encrypt data
- `decrypt_data(encrypted_data: str, key: str) -> dict` - Decrypt data
- `generate_key() -> bytes` - Generate encryption key
- `hash_data(data: str, algorithm: str = "sha256") -> dict` - Hash data
- `generate_key_from_password(password: str, salt: bytes = None) -> dict` - Derive key from password
- `verify_hash(data: str, hash_value: str, algorithm: str = "sha256") -> bool` - Verify hash

### Validation Class

#### Static Methods

- `validate_email(email: str) -> dict` - Validate email
- `validate_url(url: str, check_accessibility: bool = False) -> dict` - Validate URL
- `validate_ip(ip: str, check_version: bool = True) -> dict` - Validate IP
- `validate_port(port: int) -> dict` - Validate port
- `validate_network_range(network: str) -> dict` - Validate network range
- `sanitize_input(input_string: str, max_length: int = None) -> dict` - Sanitize input

## 🔒 Security Considerations

- **Network Scanning**: Always ensure you have permission to scan target networks. Unauthorized scanning may be illegal.
- **Password Storage**: Use proper password hashing (bcrypt, Argon2) for production. The provided hash functions are for basic use cases.
- **Encryption**: Fernet encryption is suitable for most use cases, but consider additional security measures for highly sensitive data.
- **Input Validation**: Always validate and sanitize user input before processing.
- **SSL/TLS**: Always verify SSL certificates in production environments.

## 🤝 Contributing

Contributions are highly welcomed! Feel free to open issues or submit pull requests to enhance SecureTool further.

### Development Setup

```bash
# Clone the repository
git clone https://github.com/alanhasn/my_cybersec_lib.git

# Navigate to the directory
cd my_cybersec_lib

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirement.txt
```

## 📝 License

SecureTool is licensed under the MIT License. See the LICENSE file for details.

## 📧 Contact

For questions, support, or feedback:

- 📧 Email: whoamialan11@gmail.com
- 🔗 GitHub: [Repository](https://github.com/alanhasn/my_cybersec_lib)

## 🎯 Version History

- **v2.1.0** - Added encryption, validation modules, enhanced scanning and scraping features
- **v2.0.0** - Initial release with scanning, password checking, and scraping

---

If you want a professional, reliable security toolset — SecureTool is ready to empower your cybersecurity projects. Download and get started today! 🚀
