# PortScannerButBetter.py

import socket, sys, time, random, signal

#handles Ctrl-C
def signal_handler(signal, frame):
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

if(len(sys.argv) == 2):
    #target to scan
    target = sys.argv[1]
    
    portlist = [] #list of ports open
    dots = [] #formatting
    openports = 0 #number of open ports
    print ("Scanning "+target)
    print ("----------------------------------------------------")
    
    #shuffles the ports to evade PSDetect
    shuffled = list(range(0, 65536))
    random.shuffle(shuffled)

    #scans all the ports
    start = time.time()
    for x in range (0, 65536):
        port = shuffled[x]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        c = s.connect_ex((target, port))
        if c == 0:
            openports += 1
            portlist.append(port)
    end = time.time()
    
    #does the ! formatting
    for x in range (0, 65536):
        if (x%256 == 0):
            dots.append(".")
        for p in portlist:
            if x == p:
                dots.append("!")

    #prints the . formatting and the output
    s = 0
    e = 16
    for i in [0, 4096, 8192, 12288, 16384, 20480, 24576, 28672, 32768, 36864, 40960, 45056, 49152, 53248, 57344, 61440]:
        for p in portlist:
            if (p < (i+4096)) and (p > i):
                e += 1
        print (str(i), end="    " )

        for dot in range(s,e):
            print(dots[dot], end=" ")
        print ("")
        s = e
        e = (s + 16)

    print ("Scan finished!")   
    print ("----------------------------------------------------")
    print (str(openports) + " ports found")
    print (str(end-start) + " seconds elapsed")
    print (str(65536/(end-start)) + " ports per second")
    print("Open Ports:")
    for p in portlist:
        try:
            print (str(p) + ": " + str(socket.getservbyport(p)))
        except:
            print (str(p) + ": [ unassigned ]") 
    print("Terminating Normally")

#the usage is incorrect
else:
    print ("Usage: python3 PortScannerButBetter.py target")
    sys.exit()