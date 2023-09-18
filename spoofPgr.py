#!/usr/bin/env python3
from scapy.all import *

print("Sending Spoofed UDP Packet.........")
ip = IP(src="1.2.3.4", dst="10.9.0.5")

udp = UDP(sport=8888, dport=9090)
data = "Hello UDP\n"
pkt = ip/udp/data
pkt.show()

#Send packet
send(pkt,verbose=0)


