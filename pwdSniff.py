#!/usr/bin/env python3
from scapy.all import *
from scapy.layers.inet import TCP, IP

def packet_callback(packet):
    if packet[TCP].payload:
        tcp_payload = str(packet[TCP].payload)
        print(f"TCP payload: {tcp_payload}")

ifaces = ['enp0s3', 'br-9bff7edb888c', 'lo']

# Start the sniffer
sniff(iface = ifaces, filter="tcp port telnet", prn=packet_callback, store=0)


