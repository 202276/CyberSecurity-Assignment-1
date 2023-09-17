#!/usr/bin/env python3
from scapy.all import *

def spoof_icmp(packet):
   # Only process ICMP echo requests
   if ICMP in packet and packet[ICMP].type == 8:
       print("Received ICMP Echo Request, sending spoofed reply...")

       ip = IP(src=packet[IP].dst, dst=packet[IP].src)
       icmp = ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
       if packet[ICMP].payload:
           data = packet[ICMP].payload
       else:
           data = ""

       spoofedPacket = ip / icmp / data
       send(spoofedPacket, verbose=0)

# Sniff for ICMP packets where the destination IP is 10.9.0.99
sniff(filter="icmp and dst 10.9.0.99",prn=spoof_icmp)
