#!/usr/bin/python
# Packet sniffer in python
# For Linux this sniffer uses raw sockets
# run with sudo
# works on the principle that a raw socket is capable of receiving all (of its type, like AF_INET) incoming
# traffic.
# outputs is a dump of network packets in hex, they can be parsed by using the unpack function

import socket

# create an INET, raw socket
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# receive a packet
while True:
    print s.recvfrom(65565)