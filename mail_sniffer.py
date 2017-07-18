#!/usr/bin/python
# Need to run with sudo (ie sudo ./mail_sniffer.py)

from scapy.all import *


# our packet callback which receives each sniffed packet, displays it and dissects some
# of the protocol information.
# in general using show is a great way to debug and make sure you are capturing what you
# want

def packet_callback(packet):
    print packet.show()

# sniff(filter='tcp port 110 or tcp port 25', prn=packet_callback, store=0)

#    print packet[TCP].sport

#    if packet[TCP].payload:
#        mail_packet = str(packet[TCP].payload)

#        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
#                print "[*] Server %s" % packet[IP_PROTOS].dst
#                print "[*] %s " % packet[TCP].payload

# fire up our sniffer to start sniffing on all interfaces with no filter
# Filter only includes traffic destined for the common mail ports
# Store=0 means Scapy isn't keeping the packets in memory. It is good to use this if
# you intend to keep a long term sniffer running so you don't use up RAM

sniff(filter='tcp port 80 or tcp port 25 or tcp port 143', prn=packet_callback, store=0)

# sniff(filter)
#sniff(prn=packet_callback, count=3)
