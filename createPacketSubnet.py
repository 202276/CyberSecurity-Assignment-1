#!/usr/bin/env python3
from scapy.all import *

a = IP()
a.dst = '128.230.0.0/16'
send(a,1)
