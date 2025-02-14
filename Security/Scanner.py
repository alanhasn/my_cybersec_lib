import platform
import subprocess
import nmap
import ipaddress
import re

class Scanner:
    @staticmethod
    def perform_scan(ip_input, scan_type):
        # validate the IP
        try:
            ipaddress.ip_network(ip_input, strict=False)  # indevidual or network range
        except ValueError:
            return {"error": "Invalid IP address or network range"}

        scanner = nmap.PortScanner()  # create nmap object

        # specify the scan types
        scan_args = {
            "regular": "-p 1-1024",
            "quick": "-T4 -F",
            "deep": "-T4 -A -v",
            "deep scan plus udp": "-sS -sU -T4 -A -v",
            "deep_scan_plusAll_TCP_ports": "-p 1-65535 -T4 -A -v"
        }

        # if the scan is not in the scan types dictionary
        if scan_type not in scan_args:
            return {"error": "Invalid scan type"}

        try:
            scanner.scan(ip_input, arguments=scan_args[scan_type]) 
        except Exception as e:
            return {"error": f"Scanning failed: {str(e)}"}

        # all results
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

            # extract the Ports info
            if "tcp" in scanner[ip_input]:
                results["open_ports"] = scanner[ip_input]["tcp"]
                results["closed_ports"] = (1024 if scan_type == "regular" else 65535) - len(results["open_ports"])

            # extract OS info
            os_match = scanner[ip_input].get("osmatch", [])
            if os_match:
                results["osmatch"] = os_match[0].get("name", "Not Available")
                results["osclass"] = os_match[0].get("osclass", "Not Available")

        # Excute Ping Command
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

    def RegularScan(IP):
        return Scanner.perform_scan(IP , "regular")
    
    def QuickScan(IP):
        return Scanner.perform_scan(IP,"quick")
    
    def DeepScan(IP):
        return Scanner.perform_scan(IP , "deep")
    
    def DeepScan_Plus_UDP(IP):
        return Scanner.perform_scan(IP , "deep scan plus udp")
    
    def DeepScan_PlusAll_TCP_Ports(IP):
        return Scanner.perform_scan(IP , "deep_scan_plusAll_TCP_ports")
    







print(Scanner.QuickScan("127.0.0.1"))
print("===============================================================================================================")
print(Scanner.DeepScan("127.0.0.1"))