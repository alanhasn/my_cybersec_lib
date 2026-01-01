# Changelog

All notable changes to SecureTool will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2024

### Added
- **Encryption Module**: New module for encryption/decryption operations
  - Fernet symmetric encryption/decryption
  - Encryption key generation
  - Multiple hash algorithms (MD5, SHA1, SHA256, SHA512, BLAKE2b)
  - PBKDF2 key derivation from passwords
  - Hash verification functionality

- **Validation Module**: New module for input validation
  - Email validation (RFC 5322 compliant)
  - URL validation with optional accessibility check
  - IP address validation (IPv4/IPv6) with metadata
  - Port validation with well-known port detection
  - Network range (CIDR) validation
  - Input sanitization with injection attack detection

- **Enhanced Scanner Module**:
  - Added `stealth_scan()` method for stealth SYN scanning
  - Added `vulnerability_scan()` method with port-specific vulnerability checks
  - Added `service_scan()` method for detailed service detection
  - Added XML export format support
  - Enhanced vulnerability detection with recommendations
  - Improved export functionality with better encoding

- **Enhanced Password Module**:
  - Added `generate_password()` method for secure password generation
  - Added `generate_passphrase()` method for memorable passphrases
  - Added entropy calculation for password strength assessment
  - Added password hashing utilities (MD5, SHA1, SHA256, SHA512)
  - Added password verification against hashes
  - Enhanced strength classification (added "Very Strong" level)

- **Enhanced Scraping Module**:
  - Added `check_security_headers()` method for security header analysis
  - Added `extract_metadata()` method for Open Graph and Twitter Cards
  - Added `check_ssl_certificate()` method for SSL/TLS validation
  - Added `extract_sensitive_data()` method for scanning exposed data
  - Added `extract_images()` method for image URL extraction
  - Added `extract_css_files()` method for CSS file extraction
  - Improved error handling with centralized request method
  - Added configurable user-agent and timeout
  - Enhanced link extraction with metadata (text, title)

### Changed
- Updated package structure to export all modules from `__init__.py`
- Updated `setup.py` with new dependencies (beautifulsoup4, cryptography)
- Improved error handling across all modules
- Enhanced documentation and code comments

### Dependencies
- Added `beautifulsoup4>=4.12.0` for enhanced HTML parsing
- Added `cryptography>=41.0.0` for encryption/decryption functionality

## [2.0.0] - Previous Release

### Added
- Initial release with core functionality
- Scanner module with multiple scan types
- Password strength checker
- Web scraper with basic functionality

### Features
- Network scanning capabilities
- Password strength analysis
- Web content extraction
- Basic error handling

---

[2.1.0]: https://github.com/alanhasn/my_cybersec_lib/releases/tag/v2.1.0
[2.0.0]: https://github.com/alanhasn/my_cybersec_lib/releases/tag/v2.0.0

