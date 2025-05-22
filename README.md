# SecureTool Library
[![PyPI Downloads](https://static.pepy.tech/badge/securetool)](https://pepy.tech/projects/securetool)

SecureTool is a comprehensive cybersecurity utility library designed to simplify security tasks such as network scanning, web scraping, and password strength checking. With SecureTool, you get powerful, easy-to-use tools for vulnerability discovery and data extraction.

## Features

### Scanner

- Perform various types of scans on individual IP addresses or entire networks.
- Supports multiple scanning modes including:
  - `regular` — scans ports 1-1024
  - `quick` — scans 100 common ports quickly
  - `deep` — scans 1000 ports with OS and version detection
  - `deep scan plus udp` — scans both TCP and UDP ports
  - `deep_scan_plusAll_TCP_ports` — scans all 65535 TCP ports
- Retrieves information such as open/closed ports, OS detection, and response times.
- Utilizes `nmap` for accurate and efficient scanning.

### Password Strength Checker

- Checks password complexity based on length, digits, letters, special characters, uppercase and lowercase letters.
- Provides clear feedback on missing criteria for improving password strength.
- Classifies passwords into **Strong**, **Moderate**, or **Weak** categories based on comprehensive checks.

### Web Scraper

- Extract links, forms, and external JavaScript files from any given webpage.
- Save webpage content as pretty HTML or structured JSON data.
- Search for specific keywords within webpage content and return matching sentences.
- Robust error handling for HTTP and parsing issues.

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
from SecureTool.Scanner import Scanner

scanner = Scanner()
result = scanner.RegularScan("192.168.1.1")
print(result)
```

### Password Strength Checker

```python
from SecureTool.PasswordChecker import PasswordStrengthChecker

checker = PasswordStrengthChecker()
strength, feedback = checker.check_strength("YourPassword123!")
print(strength)
print("Suggestions:", feedback)
```

### Web Scraper

```python
from SecureTool.Scraper import Scraper

scraper = Scraper()
links = scraper.extract_links("https://example.com")
print(links)

json_result = scraper.save_as_json("https://example.com", "page_data.json")
print(json_result)
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

```

```
