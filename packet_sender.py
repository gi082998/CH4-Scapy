#!/usr/bin/python
# Creates and sends a custom packet. Must be run with sudo

from scapy.all import *

# Creates a packet with dst and src IP/Port and flags below
packet = IP(dst="192.168.42.1", src="1.2.3.4")/TCP(dport=80, flags="S")

# send a packet or list of packets without customer ether layer
send(packet)