import platform
import subprocess
import nmap
import ipaddress
import re
import json
import csv


class Scanner:

    def __init__(self):
        self.scanner = nmap.PortScanner()

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

    def export(self, data, filename="scan_result", format="json"):
        if format == "json":
            with open(f"{filename}.json", "w") as f:
                json.dump(data, f, indent=4)
            return f"Results exported to {filename}.json"
        elif format == "csv":
            if isinstance(data, list):
                keys = set()
                for entry in data:
                    keys.update(entry.keys())
                keys = list(keys)
                with open(f"{filename}.csv", "w", newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=keys)
                    writer.writeheader()
                    for row in data:
                        writer.writerow(row)
                return f"Results exported to {filename}.csv"
            else:
                return "CSV export supports only list of results"
        else:
            return "Unsupported export format"
