#!/usr/bin/env python3

from scapy.all import *

def pkt_capture(pkt):
	pkt.show()

ifaces = ['enp0s3', 'lo']
f = 'dst net 128.230.0.0/16'

pkt = sniff(iface = ifaces, filter = f, prn = pkt_capture)
