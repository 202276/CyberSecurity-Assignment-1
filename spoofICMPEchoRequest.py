#!/usr/bin/env python3
from scapy.all import *

# Create IP header with spoofed source IP
ip = IP(src="1.2.3.4", dst="10.9.0.5")

# Create ICMP Echo Request
icmp = ICMP()

# Create the packet
packet = ip / icmp

# Sending the packet
send(packet)


