#!/usr/bin/env python3
from scapy.all import Ether, IP, ICMP, sendp

print("[TEST] Sending ICMP Ping from VLAN 10 (h1) to VLAN 20 (h2)...")
print("[EXPECTED] Switch should DROP this packet based on DENY_ALL policy.")

# Craft packet: L2 Header / L3 Header / ICMP Payload
pkt = Ether()/IP(dst="10.0.20.20")/ICMP()

# Send at Layer 2 to bypass Linux routing
sendp(pkt, iface="eth0", verbose=True)
print("[DONE] Check h2 tcpdump - nothing should appear.")