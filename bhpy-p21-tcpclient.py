#!/usr/bin/python

# Simple TCP Client
# Assumes that connection will always succeed
# and server is always expecting us to send data first.
# Also assumes the server will always send us data back in a timely fashion
import socket

target_host = "www.google.com"
target_port = 80

# create socket object
# AF_INET = IPv4 address or hostname
# SOCK_STREAM=TCP
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# connect the client
client.connect((target_host, target_port))

# send some data
client.send("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n")

# receive some data and print
response = client.recv(4096)

print response
