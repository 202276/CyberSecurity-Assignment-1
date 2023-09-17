#!/usr/bin/env python3
from scapy.all import *

def packet_callback(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
        print(f"Source IP: {source_ip} --> Destination IP: {destination_ip}")

# Start sniffing
sniff(prn=packet_callback)
