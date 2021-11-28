# PSDetectingSniffer.py

import socket, sys, time, signal
from scapy.all import *

#local address and the ports to detect for
localIPAddr = socket.gethostbyname(socket.gethostname())
tcpPorts = [ x for x in range(0, 65536) ]

#handles Ctrl-C
def signal_handler(signal, frame):
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

#filters the unnecessary packets out
def pkt_filter(pkt):
    if IP in pkt:
        if pkt[IP].src == localIPAddr:
            return False
    if TCP in pkt and pkt[TCP].dport in tcpPorts:
        return True
    else: 
        return False

#list of whos scanning the ports and what ports they're scanning
hackers = dict()

#parses the packets and stores their source addresses and destination ports in hackers
def parsePacket(pkt):
    currentTime = time.time()
    sourceAddr = ""
    if IP in pkt:
        sourceAddr = pkt[IP].src
    if TCP in pkt:
        destPort = pkt[TCP].dport
    if sourceAddr in hackers:
        hackers[sourceAddr].append(destPort)
    else:
        hackers[sourceAddr] = [destPort]

#sniffs all the ports and detects scanners
if(len(sys.argv) == 1):
    while True:
        scanned_by = []
        sniffer = sniff(lfilter=pkt_filter, count=0, prn=parsePacket, timeout = 5)
        for key in hackers.keys():
            being_scanned = False
            l = hackers[key]
            for s in range(len(l)):
                if (s + 15) > len(l):
                    break
                if(all(l[i] < l[i+1] for i in range(s, s + 14))):
                    being_scanned = True
            if(being_scanned):
                scanned_by.append(key)
        for scanner in scanned_by:
            print("Scanner detected. The scanner originated from host "+scanner)
        hackers = dict()
#the usage is incorrect
else:
    print ("Usage: sudo python PSDetectingSniffer.py")
    sys.exit()
