# Security Library

Security is a simple cybersecurity scanning library that helps users scan individual IPs and networks easily.

## Installation

You can install the Security library directly from PyPI using:

```sh
pip install security
```

## Features

- Perform different types of scans on a single target or an entire network.
- Supports multiple scanning modes: `regular`, `quick`, `deep`, and `UDP scan`.
- Retrieves information such as open/closed ports, OS detection, and response time.
- Uses `nmap` for accurate and efficient scanning.

## Usage

After installing the library, you can import it and start scanning:

```python
from Security.Scanner import Scanner

# Create an instance of the Scanner
scanner = Scanner()

# Perform a regular scan on a specific IP
result = scanner.RegularScan("192.168.1.1", "regular")

# Print scan results
print(result)
```

## Scan Types

| Scan Type                      | Description                                      |
|---------------------------------|--------------------------------------------------|
| `regular`                      | Scans ports 1-1024                               |
| `quick`                        | Scans 100 common ports quickly                   |
| `deep`                         | Scans 1000 ports with OS and version detection   |
| `deep scan plus udp`           | Scans both TCP and UDP ports                     |
| `deep_scan_plusAll_TCP_ports`  | Scans all 65535 TCP ports                        |

## Requirements

This library requires:

- **Python 3.6+**
- **Nmap installed on your system**  

You can install Nmap using:

- **Windows**: Download from [https://nmap.org/download.html](https://nmap.org/download.html)
- **Linux/macOS**: Install via package manager:

  ```sh
  sudo apt install nmap   # Debian/Ubuntu
  brew install nmap       # macOS (Homebrew)
  ```

## License

This project is licensed under the **MIT License** - see the `LICENSE` file for details.

## Contribution

Contributions are welcome! If you find any issues or want to add new features, feel free to open an issue or submit a pull request.

## Contact

For any questions or support, contact:  
📧 **whoamialan11@gmail.com**  
🔗 [GitHub Repository](https://github.com/alanhasn/my_cybersec_lib)
