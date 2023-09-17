#!/usr/bin/env python3
from scapy.all import *

a = IP()
b = ICMP()

a.dst = '142.250.199.174'
i = 1 # TTL counter
flag = True

while flag:
    a.ttl = i

    h = sr1(a/b, timeout=2, verbose=0)

    if h is None: 
        # No response from any intermediary routers
        print("{} Router: hops = {}".format(i, i))
    elif h.type == 0: 
        # Response from the destination
        print("{} Router: {} hops = {}".format(i, h.src, i))
        flag = False
    else: 
        # Response from intermediate node
        print("{} Router: {} hops = {}".format(i, h.src, i))

    i = i + 1
