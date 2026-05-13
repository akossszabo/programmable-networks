#!/usr/bin/env python3
from scapy.all import Ether, IP, UDP, DNS, DNSQR, sendp

print("[TEST] Sending DNS Query (UDP 53) from VLAN 10 (h1) to VLAN 20 (h2)...")
print("[EXPECTED] Switch should FORWARD this packet based on ALLOW_L4_PORT policy.")

# Craft packet: L2 / L3 / UDP Port 53 / DNS Query for test.com
pkt = Ether()/IP(dst="10.0.20.20")/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname="test.com"))

sendp(pkt, iface="eth0", verbose=True)
print("[DONE] Check h2 tcpdump - the DNS packet should be captured.")