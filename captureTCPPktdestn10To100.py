#!/usr/bin/env python3
from scapy.all import *

def handle_packet(packet):
    print(packet.summary())

# Interfaces from where you want to sniff
ifaces = ['enp0s3', 'br-9bff7edb888c', 'lo']

# tcp specifies TCP packets, and dst portrange specifies the destination port range
filter_str = 'tcp and (dst portrange 10-100)'

# Sniff the packets
# prn specifies the function handle_packet to be run on each packet that matches the filter
sniff(iface = ifaces, filter = filter_str, prn = handle_packet)
