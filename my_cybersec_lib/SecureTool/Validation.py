"""
Validation utilities for SecureTool.

This module provides URL, email, and input validation functions.
"""

import re
import ipaddress
from typing import Optional, Dict
from urllib.parse import urlparse


class Validation:
    """
    A class for validating various types of input.

    Methods
    -------
    validate_email(email)
        Validate email address format.

    validate_url(url)
        Validate URL format and accessibility.

    validate_ip(ip)
        Validate IP address format.

    validate_port(port)
        Validate port number.

    sanitize_input(input_string)
        Sanitize user input to prevent injection attacks.
    """

    @staticmethod
    def validate_email(email: str) -> Dict:
        """
        Validate email address format.

        Parameters
        ----------
        email : str
            Email address to validate.

        Returns
        -------
        dict
            Dictionary containing validation result and details.
        """
        if not email:
            return {"valid": False, "error": "Email is empty"}

        # RFC 5322 compliant email regex (simplified)
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if re.match(pattern, email):
            # Additional checks
            local_part, domain = email.split('@')
            
            if len(local_part) > 64:
                return {"valid": False, "error": "Local part exceeds 64 characters"}
            
            if len(domain) > 255:
                return {"valid": False, "error": "Domain exceeds 255 characters"}
            
            if '..' in email:
                return {"valid": False, "error": "Email contains consecutive dots"}
            
            return {
                "valid": True,
                "email": email,
                "local_part": local_part,
                "domain": domain
            }
        else:
            return {"valid": False, "error": "Invalid email format"}

    @staticmethod
    def validate_url(url: str, check_accessibility: bool = False) -> Dict:
        """
        Validate URL format and optionally check accessibility.

        Parameters
        ----------
        url : str
            URL to validate.
        check_accessibility : bool, optional
            Whether to check if URL is accessible. Defaults to False.

        Returns
        -------
        dict
            Dictionary containing validation result and details.
        """
        if not url:
            return {"valid": False, "error": "URL is empty"}

        # Add scheme if missing
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        try:
            parsed = urlparse(url)
            
            if not parsed.scheme or not parsed.netloc:
                return {"valid": False, "error": "Invalid URL format"}

            result = {
                "valid": True,
                "url": url,
                "scheme": parsed.scheme,
                "netloc": parsed.netloc,
                "path": parsed.path,
                "query": parsed.query,
                "fragment": parsed.fragment
            }

            if check_accessibility:
                try:
                    import requests
                    response = requests.head(url, timeout=5, allow_redirects=True)
                    result["accessible"] = response.status_code < 400
                    result["status_code"] = response.status_code
                except Exception as e:
                    result["accessible"] = False
                    result["error"] = str(e)

            return result
        except Exception as e:
            return {"valid": False, "error": f"URL validation failed: {str(e)}"}

    @staticmethod
    def validate_ip(ip: str, check_version: bool = True) -> Dict:
        """
        Validate IP address format.

        Parameters
        ----------
        ip : str
            IP address to validate.
        check_version : bool, optional
            Whether to check IP version (IPv4/IPv6). Defaults to True.

        Returns
        -------
        dict
            Dictionary containing validation result and details.
        """
        if not ip:
            return {"valid": False, "error": "IP address is empty"}

        try:
            ip_obj = ipaddress.ip_address(ip)
            result = {
                "valid": True,
                "ip": ip,
                "version": ip_obj.version if check_version else None,
                "is_private": ip_obj.is_private,
                "is_multicast": ip_obj.is_multicast,
                "is_reserved": ip_obj.is_reserved,
                "is_loopback": ip_obj.is_loopback
            }
            return result
        except ValueError as e:
            return {"valid": False, "error": f"Invalid IP address: {str(e)}"}

    @staticmethod
    def validate_port(port: int) -> Dict:
        """
        Validate port number.

        Parameters
        ----------
        port : int
            Port number to validate.

        Returns
        -------
        dict
            Dictionary containing validation result and details.
        """
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return {"valid": False, "error": "Port must be a number"}

        if port < 1 or port > 65535:
            return {"valid": False, "error": "Port must be between 1 and 65535"}

        well_known_ports = {
            20: "FTP Data",
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            143: "IMAP",
            443: "HTTPS",
            3306: "MySQL",
            5432: "PostgreSQL",
            3389: "RDP"
        }

        result = {
            "valid": True,
            "port": port,
            "is_well_known": port in well_known_ports,
            "service": well_known_ports.get(port, "Unknown")
        }

        if port < 1024:
            result["requires_root"] = True
        else:
            result["requires_root"] = False

        return result

    @staticmethod
    def sanitize_input(input_string: str, max_length: Optional[int] = None) -> Dict:
        """
        Sanitize user input to prevent injection attacks.

        Parameters
        ----------
        input_string : str
            Input string to sanitize.
        max_length : int, optional
            Maximum allowed length. If None, no length check is performed.

        Returns
        -------
        dict
            Dictionary containing sanitized input and security flags.
        """
        if not isinstance(input_string, str):
            return {"error": "Input must be a string"}

        # Check length
        if max_length and len(input_string) > max_length:
            return {
                "error": f"Input exceeds maximum length of {max_length}",
                "sanitized": input_string[:max_length]
            }

        # Detect potentially dangerous patterns
        dangerous_patterns = {
            "sql_injection": [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b)",
                r"(--|;|\/\*|\*\/|')"
            ],
            "xss": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*="
            ],
            "command_injection": [
                r"[;&|`$()]",
                r"\b(cat|ls|pwd|whoami|id|uname)\b"
            ]
        }

        detected_patterns = []
        for pattern_type, patterns in dangerous_patterns.items():
            for pattern in patterns:
                if re.search(pattern, input_string, re.IGNORECASE):
                    detected_patterns.append(pattern_type)
                    break

        # Basic sanitization (remove null bytes, control characters)
        sanitized = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', input_string)
        sanitized = sanitized.strip()

        return {
            "sanitized": sanitized,
            "original_length": len(input_string),
            "sanitized_length": len(sanitized),
            "detected_patterns": list(set(detected_patterns)),
            "is_safe": len(detected_patterns) == 0
        }

    @staticmethod
    def validate_network_range(network: str) -> Dict:
        """
        Validate network range (CIDR notation).

        Parameters
        ----------
        network : str
            Network range in CIDR notation (e.g., "192.168.1.0/24").

        Returns
        -------
        dict
            Dictionary containing validation result and network details.
        """
        if not network:
            return {"valid": False, "error": "Network range is empty"}

        try:
            net = ipaddress.ip_network(network, strict=False)
            result = {
                "valid": True,
                "network": str(net),
                "version": net.version,
                "netmask": str(net.netmask),
                "hostmask": str(net.hostmask),
                "num_addresses": net.num_addresses,
                "num_hosts": net.num_addresses - 2 if net.version == 4 else net.num_addresses,
                "is_private": net.is_private,
                "is_multicast": net.is_multicast
            }
            return result
        except ValueError as e:
            return {"valid": False, "error": f"Invalid network range: {str(e)}"}

