"""
Need to Research Pcap Parsing python modules

1. Scapy (now installed)
2. other options:
    - dpkt
    - pyshark
"""

from scapy.all import rdpcap

packets = rdpcap("./input/net_log_2026-01-20T14_18-17.230613Z.pcap")

for i, pkt in enumerate(packets):
    print(f"\n===== PACKET {i} =====")
    pkt.show2()
