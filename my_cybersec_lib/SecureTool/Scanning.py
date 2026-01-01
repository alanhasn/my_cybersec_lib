import platform
import subprocess
import nmap
import ipaddress
import re
import json
import csv
from typing import Dict, List, Optional, Union
from datetime import datetime


class Scanner:
    """
    A comprehensive network scanning class with security-focused features.

    Methods
    -------
    regular_scan(ip)
        Perform a regular port scan (ports 1-1024).

    quick_scan(ip)
        Perform a quick scan of common ports.

    deep_scan(ip)
        Perform a deep scan with OS and version detection.

    stealth_scan(ip)
        Perform a stealth SYN scan to avoid detection.

    vulnerability_scan(ip)
        Scan for common vulnerabilities.

    check_common_vulnerabilities(ip, ports)
        Check for common vulnerabilities on specific ports.
    """

    def __init__(self):
        self.scanner = nmap.PortScanner()
        self.common_vulnerabilities = {
            21: ["FTP", "Check for anonymous login, weak credentials"],
            22: ["SSH", "Check for weak keys, outdated versions"],
            23: ["Telnet", "Insecure protocol, check for authentication"],
            25: ["SMTP", "Check for open relay, misconfiguration"],
            53: ["DNS", "Check for DNS amplification, zone transfer"],
            80: ["HTTP", "Check for outdated servers, misconfigurations"],
            443: ["HTTPS", "Check SSL/TLS configuration, certificate issues"],
            3306: ["MySQL", "Check for weak credentials, exposed databases"],
            5432: ["PostgreSQL", "Check for weak credentials, exposed databases"],
            3389: ["RDP", "Check for weak credentials, brute force protection"],
            5900: ["VNC", "Check for weak credentials, unencrypted access"]
        }

    def _is_valid_ip_or_network(self, ip_input):
        try:
            ipaddress.ip_network(ip_input, strict=False)
            return True
        except ValueError:
            return False

    def _ping_target(self, ip):
        ping_cmd = ["ping", "-n" if platform.system().lower() == "windows" else "-c", "1", ip]
        ping_result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, text=True)

        status = "Host is Offline"
        rtt = "Not Available"
        ttl = "Not Available"

        if ping_result.returncode == 0:
            status = "Host is Online"
            output = ping_result.stdout
            if platform.system().lower() == "windows":
                rtt_match = re.search(r"Maximum = (\d+ms)", output)
                ttl_match = re.search(r"TTL=(\d+)", output)
            else:
                rtt_match = re.search(r"time=(\d+\.?\d*) ms", output)
                ttl_match = re.search(r"ttl=(\d+)", output)
            rtt = rtt_match.group(1) if rtt_match else rtt
            ttl = ttl_match.group(1) if ttl_match else ttl

        return status, rtt, ttl

    def _perform_scan(self, ip_input, scan_type):
        if not self._is_valid_ip_or_network(ip_input):
            return {"error": "Invalid IP address or network range"}

        scan_args = {
            "regular": "-p 1-1024",
            "quick": "-T4 -F",
            "deep": "-T4 -A -v",
            "deep_udp": "-sS -sU -T4 -A -v",
            "full_tcp": "-p 1-65535 -T4 -A -v",
            "network": "-T4 -A -v"
        }

        if scan_type not in scan_args:
            return {"error": "Invalid scan type"}

        try:
            self.scanner.scan(ip_input, arguments=scan_args[scan_type])
        except Exception as e:
            return {"error": "Scanning failed: " + str(e)}

        results = {
            "target": ip_input,
            "scan_type": scan_type,
            "status": "unreachable",
            "hostname": "N/A",
            "open_ports": {},
            "closed_ports": "N/A",
            "ping_status": "Host is Offline",
            "RTT_Maximum": "Not Available",
            "TTL": "Not Available",
            "osmatch": "Not Available",
            "osclass": "Not Available",
            "scan_duration": self.scanner.scanstats()
        }

        if ip_input in self.scanner.all_hosts():
            host_data = self.scanner[ip_input]
            results["status"] = host_data.state()
            results["hostname"] = host_data.hostname() or "N/A"

            if "tcp" in host_data:
                results["open_ports"] = host_data["tcp"]
                total_ports = 1024 if scan_type == "regular" else 65535
                results["closed_ports"] = total_ports - len(results["open_ports"])

            if "osmatch" in host_data and host_data["osmatch"]:
                results["osmatch"] = host_data["osmatch"][0].get("name", "Not Available")
                results["osclass"] = host_data["osmatch"][0].get("osclass", "Not Available")

        # Ping info
        status, rtt, ttl = self._ping_target(ip_input)
        results["ping_status"] = status
        results["RTT_Maximum"] = rtt
        results["TTL"] = ttl

        return results

    def regular_scan(self, ip):
        print("Starting Regular Scan...")
        return self._perform_scan(ip, "regular")

    def quick_scan(self, ip):
        print("Starting Quick Scan...")
        return self._perform_scan(ip, "quick")

    def deep_scan(self, ip):
        print("Starting Deep Scan...")
        return self._perform_scan(ip, "deep")

    def deep_udp_scan(self, ip):
        print("Starting Deep UDP Scan...")
        return self._perform_scan(ip, "deep_udp")

    def full_tcp_scan(self, ip):
        print("Starting Full TCP Scan...")
        return self._perform_scan(ip, "full_tcp")

    def network_scan(self, network_range):
        print("Starting Network Scan...")
        if not self._is_valid_ip_or_network(network_range):
            return {"error": "Invalid network range"}

        results = []
        net = ipaddress.ip_network(network_range, strict=False)
        for ip in net.hosts():
            print("Scanning", ip)
            res = self._perform_scan(str(ip), "network")
            results.append(res)
        return results

    def get_os_info(self, ip):
        print("Starting OS Detection...")
        try:
            self.scanner.scan(ip, arguments="-O")
            if "osmatch" in self.scanner[ip]:
                return self.scanner[ip]["osmatch"]
            return {"error": "No OS info available"}
        except Exception as e:
            return {"error": "OS detection failed: " + str(e)}

    def port_scan(self, ip, port, protocol="tcp"):
        print("Starting Port Scan...")
        try:
            if protocol == "udp":
                self.scanner.scan(ip, arguments=f"-p {port} -sU")
                if port in self.scanner[ip].get("udp", {}):
                    return {"status": f"UDP Port {port} is open"}
                else:
                    return {"status": f"UDP Port {port} is closed"}
            else:
                self.scanner.scan(ip, arguments=f"-p {port} -sS")
                if port in self.scanner[ip].get("tcp", {}):
                    state = self.scanner[ip]["tcp"][port]["state"]
                    return {"status": f"TCP Port {port} is {state}"}
                else:
                    return {"status": f"TCP Port {port} is closed"}
        except Exception as e:
            return {"error": "Port scan failed: " + str(e)}

    def version_scan(self, ip):
        print("Starting Version Scan...")
        try:
            self.scanner.scan(ip, arguments="-sV")
            return self.scanner[ip]
        except Exception as e:
            return {"error": "Version scan failed: " + str(e)}

    def stealth_scan(self, ip):
        """
        Perform a stealth SYN scan to avoid detection.

        Parameters
        ----------
        ip : str
            IP address to scan.

        Returns
        -------
        dict
            Scan results dictionary.
        """
        print("Starting Stealth Scan...")
        if not self._is_valid_ip_or_network(ip):
            return {"error": "Invalid IP address or network range"}

        try:
            # SYN scan (-sS) with timing (-T2 for slower, less detectable)
            self.scanner.scan(ip, arguments="-sS -T2 -p 1-1000")
        except Exception as e:
            return {"error": "Stealth scan failed: " + str(e)}

        results = {
            "target": ip,
            "scan_type": "stealth",
            "status": "unreachable",
            "open_ports": {},
            "scan_duration": self.scanner.scanstats()
        }

        if ip in self.scanner.all_hosts():
            host_data = self.scanner[ip]
            results["status"] = host_data.state()
            if "tcp" in host_data:
                results["open_ports"] = host_data["tcp"]

        return results

    def vulnerability_scan(self, ip, ports: Optional[List[int]] = None):
        """
        Scan for common vulnerabilities on open ports.

        Parameters
        ----------
        ip : str
            IP address to scan.
        ports : list, optional
            Specific ports to check. If None, checks all open ports.

        Returns
        -------
        dict
            Vulnerability scan results.
        """
        print("Starting Vulnerability Scan...")
        if not self._is_valid_ip_or_network(ip):
            return {"error": "Invalid IP address or network range"}

        # First, perform a version scan to get open ports
        try:
            self.scanner.scan(ip, arguments="-sV -T4")
        except Exception as e:
            return {"error": "Vulnerability scan failed: " + str(e)}

        if ip not in self.scanner.all_hosts():
            return {"error": "Host is unreachable"}

        host_data = self.scanner[ip]
        open_ports = host_data.get("tcp", {})

        if ports:
            open_ports = {p: open_ports[p] for p in ports if p in open_ports}

        vulnerabilities = []
        for port, port_info in open_ports.items():
            port_num = int(port)
            service = port_info.get("name", "unknown")
            version = port_info.get("version", "unknown")
            product = port_info.get("product", "unknown")

            vuln_info = {
                "port": port_num,
                "service": service,
                "version": version,
                "product": product,
                "state": port_info.get("state", "unknown"),
                "recommendations": []
            }

            # Check for common vulnerabilities based on port
            if port_num in self.common_vulnerabilities:
                vuln_info["service_type"] = self.common_vulnerabilities[port_num][0]
                vuln_info["recommendations"].append(self.common_vulnerabilities[port_num][1])

            # Check for outdated or vulnerable versions
            if "old" in version.lower() or "deprecated" in version.lower():
                vuln_info["recommendations"].append("Outdated version detected - update recommended")

            # Check for default/weak configurations
            if port_num == 21:  # FTP
                vuln_info["recommendations"].append("Check for anonymous FTP access")
            elif port_num == 3306 or port_num == 5432:  # Database ports
                vuln_info["recommendations"].append("Ensure strong authentication is enabled")
            elif port_num == 80 or port_num == 443:  # Web servers
                vuln_info["recommendations"].append("Check for security headers and SSL/TLS configuration")

            vulnerabilities.append(vuln_info)

        return {
            "target": ip,
            "scan_type": "vulnerability",
            "timestamp": datetime.now().isoformat(),
            "vulnerabilities": vulnerabilities,
            "total_ports_scanned": len(open_ports)
        }

    def check_common_vulnerabilities(self, ip: str, ports: List[int]) -> Dict:
        """
        Check for common vulnerabilities on specific ports.

        Parameters
        ----------
        ip : str
            IP address to check.
        ports : list
            List of port numbers to check.

        Returns
        -------
        dict
            Vulnerability check results.
        """
        return self.vulnerability_scan(ip, ports)

    def service_scan(self, ip: str, port: int) -> Dict:
        """
        Perform detailed service detection on a specific port.

        Parameters
        ----------
        ip : str
            IP address to scan.
        port : int
            Port number to scan.

        Returns
        -------
        dict
            Service information.
        """
        print(f"Starting Service Scan on port {port}...")
        try:
            self.scanner.scan(ip, arguments=f"-p {port} -sV -sC")
        except Exception as e:
            return {"error": f"Service scan failed: {str(e)}"}

        if ip not in self.scanner.all_hosts():
            return {"error": "Host is unreachable"}

        host_data = self.scanner[ip]
        port_info = host_data.get("tcp", {}).get(str(port), {})

        return {
            "target": ip,
            "port": port,
            "state": port_info.get("state", "unknown"),
            "service": port_info.get("name", "unknown"),
            "product": port_info.get("product", "unknown"),
            "version": port_info.get("version", "unknown"),
            "extrainfo": port_info.get("extrainfo", ""),
            "script": port_info.get("script", {})
        }

    def export(self, data, filename="scan_result", format="json"):
        """
        Export scan results to various formats.

        Parameters
        ----------
        data : dict or list
            Scan results to export.
        filename : str, optional
            Output filename (without extension). Defaults to "scan_result".
        format : str, optional
            Export format (json, csv, xml). Defaults to "json".

        Returns
        -------
        str
            Success message with file path.
        """
        if format == "json":
            with open(f"{filename}.json", "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            return f"Results exported to {filename}.json"
        elif format == "csv":
            if isinstance(data, list):
                keys = set()
                for entry in data:
                    if isinstance(entry, dict):
                        keys.update(entry.keys())
                keys = list(keys)
                with open(f"{filename}.csv", "w", newline='', encoding="utf-8") as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for row in data:
                        if isinstance(row, dict):
                            writer.writerow(row)
                return f"Results exported to {filename}.csv"
            else:
                return "CSV export supports only list of results"
        elif format == "xml":
            # Simple XML export
            xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n<scan_results>\n'
            if isinstance(data, dict):
                xml_content += self._dict_to_xml(data, "result")
            elif isinstance(data, list):
                for item in data:
                    xml_content += self._dict_to_xml(item, "result")
            xml_content += "</scan_results>"
            with open(f"{filename}.xml", "w", encoding="utf-8") as f:
                f.write(xml_content)
            return f"Results exported to {filename}.xml"
        else:
            return "Unsupported export format. Use: json, csv, or xml"

    def _dict_to_xml(self, d: Dict, root_name: str = "item") -> str:
        """Convert dictionary to XML string."""
        xml = f"<{root_name}>\n"
        for key, value in d.items():
            if isinstance(value, dict):
                xml += self._dict_to_xml(value, key)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict):
                        xml += self._dict_to_xml(item, key)
                    else:
                        xml += f"<{key}>{item}</{key}>\n"
            else:
                xml += f"<{key}>{value}</{key}>\n"
        xml += f"</{root_name}>\n"
        return xml
