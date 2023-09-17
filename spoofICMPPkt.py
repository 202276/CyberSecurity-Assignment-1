#!/usr/bin/env python3
from scapy.all import *

# Create an IP packet object.
a = IP()
a.src = '1.2.3.4'  # Spoofed source IP
a.dst = '10.9.0.6'  # Destination IP

# Create an ICMP packet
b = ICMP()

# An ICMP Echo Request packet has type 8
b.type = 8

# Combine the IP and ICMP packets
pkt = a/b

# Send the packet
send(pkt)
ls(pkt)
