#!/usr/bin/python
# Need to run with sudo (ie sudo ./mail_sniffer.py)

from scapy.all import *


# our packet callback which receives each sniffed packet, displays it and dissects some
# of the protocol information.
# in general using show is a great way to debug and make sure you are capturing what you
# want

def packet_callback(packet):
    print packet.show()

# fire up our sniffer to start sniffing on all interfaces with no filter
sniff(prn=packet_callback, count=50)
