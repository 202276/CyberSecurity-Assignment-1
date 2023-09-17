#!/usr/bin/env python3

from scapy.all import *

def pkt_capture(pkt):
	if pkt.haslayer(TCP):
		tcp = pkt[TCP]
		tcp.show()

ifaces = ['enp0s3', 'br-9bff7edb888c', 'lo']
f = 'tcp dst port 23 and (src host 10.9.0.1)'

pkt = sniff(iface = ifaces, filter = f, prn = pkt_capture)
