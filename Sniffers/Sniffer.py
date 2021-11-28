# Sniffer.py

import socket, sys, time, signal
from scapy.all import *

#local address and the ports to detect for
localIPAddr = socket.gethostbyname(socket.gethostname())
tcpPorts = [ x for x in range(0, 65536) ]


#filters the unnecessary packets out
def pkt_filter(pkt):
    if IP in pkt:
        if pkt[IP].src == localIPAddr:
            return False
    if TCP in pkt and pkt[TCP].dport in tcpPorts:
        return True
    else: 
        return False


#parses the packets...
def parsePacket(pkt):

#sniffing stuff
sniffer = sniff(lfilter=pkt_filter, count=0, prn=parsePacket, timeout = 5)