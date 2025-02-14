from Security.Scanner import Scanner



regular_scan = Scanner.RegularScan("127.0.0.1")
quick_scan = Scanner.QuickScan("127.0.0.1")
deep_scan = Scanner.DeepScan("127.0.0.1")
deepUdp_scan = Scanner.DeepScan_Plus_UDP("127.0.0.1")
deepALL_TCP_scan = Scanner.DeepScan_PlusAll_TCP_Ports("127.0.0.1")
version = Scanner.version_scan("127.0.0.1")
port_scan = Scanner.port_scan("127.0.0.1" , 80)
network = Scanner.NetworkScan("127.0.0.1/24")
os = Scanner.get_OS_info("127.0.0.1")

print(regular_scan)
print(quick_scan)
print(deep_scan)
print(deepUdp_scan)
print(deepALL_TCP_scan)
print(network)
print(version)
print(os)
print(port_scan)