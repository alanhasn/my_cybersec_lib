r"""
Security is a simple cybersecurity scanning library that helps users scan individual IPs and networks easily.
## Features

- Perform different types of scans on a single target or an entire network.
- Supports multiple scanning modes: `regular`, `quick`, `deep`, and `UDP scan`.
- Retrieves information such as open/closed ports, OS detection, and response time.
- Uses `nmap` for accurate and efficient scanning.


After installing the library, you can import it and start scanning:

from Security.Scanner import Scanner

# Create an instance of the Scanner
scanner = Scanner()

# Perform a regular scan on a specific IP
result = scanner.RegularScan("192.168.1.1", "regular")

# Print scan results
print(result)

"""


import platform
import subprocess
import nmap
import ipaddress
import re

class Scanner:
    @staticmethod
    def perform_scan(ip_input, scan_type):
        # Validate the IP address or network range
        try:
            ipaddress.ip_network(ip_input, strict=False)  # individual or network range
        except ValueError:
            return {"error": "Invalid IP address or network range"}

        scanner = nmap.PortScanner()  # create nmap object

        # Define scan types
        scan_args = {
            "regular": "-p 1-1024",
            "quick": "-T4 -F",
            "deep": "-T4 -A -v",
            "deep scan plus udp": "-sS -sU -T4 -A -v",
            "deep_scan_plusAll_TCP_ports": "-p 1-65535 -T4 -A -v",
            "network_scan": "-T4 -A -v"
        }

        # Check if the scan type is valid
        if scan_type not in scan_args:
            return {"error": "Invalid scan type"}

        try:
            scanner.scan(ip_input, arguments=scan_args[scan_type])
        except Exception as e:
            return {"error": f"Scanning failed: {str(e)}"}

        # Initialize results
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
            "scan_duration": scanner.scanstats()
        }

        if ip_input in scanner.all_hosts():
            results["status"] = scanner[ip_input].state()
            results["hostname"] = scanner[ip_input].hostname() or "N/A"

            # Extract open ports
            if "tcp" in scanner[ip_input]:
                results["open_ports"] = scanner[ip_input]["tcp"]
                results["closed_ports"] = (1024 if scan_type == "regular" else 65535) - len(results["open_ports"])

            # Extract OS information
            os_match = scanner[ip_input].get("osmatch", [])
            if os_match:
                results["osmatch"] = os_match[0].get("name", "Not Available")
                results["osclass"] = os_match[0].get("osclass", "Not Available")

        # Execute Ping Command
        ping_cmd = ["ping", "-n" if platform.system().lower() == "windows" else "-c", "1", ip_input]
        ping_result = subprocess.run(ping_cmd, stdout=subprocess.PIPE, text=True)

        if ping_result.returncode == 0:
            output = ping_result.stdout
            results["ping_status"] = "Host is Online"
            rtt_match = re.search(r"Maximum = (\d+ms)", output)
            ttl_match = re.search(r"TTL=(\d+)", output)
            results["RTT_Maximum"] = rtt_match.group(1) if rtt_match else "Not Available"
            results["TTL"] = ttl_match.group(1) if ttl_match else "Not Available"

        return results

    @staticmethod
    def RegularScan(IP):
        print("Your Scan Started Now Please Wait Until The Scan Finish")
        print("==========================================================")
        return Scanner.perform_scan(IP , "regular")
    
    @staticmethod
    def QuickScan(IP):
        print("Your Scan Started Now Please Wait Until The Scan Finish")
        print("==========================================================")
        return Scanner.perform_scan(IP, "quick")
    
    @staticmethod
    def DeepScan(IP):
        print("Your Deep Scan Started Now Please Wait Until The Scan Finish")
        print("==========================================================")
        return Scanner.perform_scan(IP , "deep")
    
    @staticmethod
    def DeepScan_Plus_UDP(IP):
        print("Your UDP Scan Started Please Wait Until The Scan Finish")
        print("==========================================================")
        return Scanner.perform_scan(IP , "deep scan plus udp")
    
    @staticmethod
    def DeepScan_PlusAll_TCP_Ports(IP):
        print("Your TCP Scan Started , Please Wait Until The Scan Finish")
        print("==========================================================")
        return Scanner.perform_scan(IP , "deep_scan_plusAll_TCP_ports")
    
    @staticmethod
    def NetworkScan(network_input):
        # Add logic to scan a network range
        try:
            network = ipaddress.ip_network(network_input)
            all_results = []
            for ip in network.hosts():
                print(f"Scanning {ip}")
                result = Scanner.perform_scan(str(ip), "network_scan")
                all_results.append(result)
            return all_results
        except ValueError:
            return {"error": "Invalid network range"}

    @staticmethod
    def get_OS_info(IP):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(IP, arguments="-O")
            if "osmatch" in scanner[IP]:
                return scanner[IP]["osmatch"]
            else:
                return {"error": "OS information not available"}
        except Exception as e:
            return {"error": f"OS detection failed: {str(e)}"}

    @staticmethod
    def port_scan(IP, port, protocol="tcp"):
        try:
            scanner = nmap.PortScanner()
            
            if protocol == "udp":
                # Perform a UDP scan with the correct arguments
                scanner.scan(IP, arguments=f"-p {port} -sU")
                # Check if the port exists in the 'udp' dictionary
                if port in scanner[IP]['udp']:
                    return {"status": f"UDP Port {port} is open"}
                else:
                    return {"status": f"UDP Port {port} is closed"}
            
            else:  # Default to TCP scan
                # Perform a TCP scan with the correct arguments
                scanner.scan(IP, arguments=f"-p {port} -sS")
                # Check if the port exists in the 'tcp' dictionary
                if port in scanner[IP]['tcp']:
                    port_status = scanner[IP]['tcp'][port]['state']
                    if port_status == "open":
                        return {"status": f"TCP Port {port} is open"}
                    else:
                        return {"status": f"TCP Port {port} is closed"}
                else:
                    return {"status": f"TCP Port {port} is closed"}

        except KeyError:
            return {"error": f"Port {port} scan result not available"}
        except Exception as e:
            return {"error": f"Port scan failed: {str(e)}"}

        
    @staticmethod
    def version_scan(IP):
        try:
            scanner = nmap.PortScanner()
            scanner.scan(IP, arguments="-sV")  # Service version detection
            return scanner[IP]
        except Exception as e:
            return {"error": f"Version scan failed: {str(e)}"}
