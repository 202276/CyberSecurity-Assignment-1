#!/usr/bin/env python3
from scapy.all import *

def handle_packet(packet):
    print(packet.summary())

host1 = '10.9.0.5'
host2 = '10.9.0.6'

# interfaces where to sniff packets
ifaces = ['enp0s3', 'br-9bff7edb888c', 'lo']

filter_str = f"icmp and ((src host {host1} and dst host {host2}) or (src host {host2} and dst host {host1}))"

# Sniff the packets
# prn specifies the function handle_packet to be run on each packet that matches the filter
sniff(iface = ifaces, filter = filter_str, prn=handle_packet)

