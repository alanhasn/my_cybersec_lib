from SecureTool.Scanner import Scanner


regular_scan = Scanner.RegularScan("127.0.0.1")
print(regular_scan)

quick_scan = Scanner.QuickScan("127.0.0.1")
print(quick_scan)

deep_scan = Scanner.DeepScan("127.0.0.1")
print(deep_scan)

deepUdp_scan = Scanner.DeepScan_Plus_UDP("127.0.0.1")
print(deepUdp_scan)

deepALL_TCP_scan = Scanner.DeepScan_PlusAll_TCP_Ports("127.0.0.1")
print(deepALL_TCP_scan)

network = Scanner.NetworkScan("127.0.0.1/24")
print(network)

version = Scanner.version_scan("127.0.0.1")
print(version)

port_scan = Scanner.port_scan("127.0.0.1" , 80)
print(port_scan)

os = Scanner.get_OS_info("127.0.0.1")
print(os)
