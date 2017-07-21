#!/usr/bin/python
# UDP Client
import socket

target_host = "10.55.0.72"
target_port = 80

# create a socket object. SOCK_DGRAM is the socket type
# socket.SOCK_DGRAM = UDP
client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# send some data. call "sendto", pass in data and server IP.
# because UDP is connectionless there is no call to "connect()" like in the TCP client
client.sendto("AAABBBCCC", (target_host, target_port))

# receive some UDP data back. Returns data and details of remote host and port;
data, addr = client.recvfrom(4096)

# Tested it by running a listener with netcat ("nc -lu 80") on another machine then running this
# program from the same workstation
