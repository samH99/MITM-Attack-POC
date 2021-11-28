# EncryptedMessenger.py

import socket, sys, select, os
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256

PORT = 9999
RECV_BUFFER = 4096
GENERATOR_G = 2
PRIME = 0x00cc81ea8157352a9e9a318aac4e33ffba80fc8da3373fb44895109e4c3ff6cedcc55c02228fccbd551a504feb4346d2aef47053311ceaba95f6c540b967b9409e9f0502e598cfc71327c5a455e2e807bede1e0b7d23fbea054b951ca964eaecae7ba842ba1fc6818c453bf19eb9c5c86e723e69a210d4b72561cab97b3fb3060b

#pads the message
def pad(msg):
    size = (AES.block_size - len(msg)) % AES.block_size
    if(size == 0):
        size = AES.block_size
    
    padding = (chr(size) *(size))
    return (msg + padding).encode('utf-8')

#unpads the message
def unpad(data):
    return data[:-data[-1]]

#encrypts the message
def encrypt(msg, confkey, authkey):
    msg = pad(msg)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(confkey, AES.MODE_CBC, iv)
    
    ci = cipher.encrypt(msg)
    h = hmac(ci,authkey)
    return (iv + h.digest() + ci)

#decrypts the message
def decrypt(enc,confkey, authkey):
    iv = enc[0:AES.block_size]
    cipher = AES.new(confkey, AES.MODE_CBC, iv)
    
    h = enc[AES.block_size:AES.block_size + 32]
    msg =  (enc[AES.block_size + 32:])
    
    verifyhmac(msg, authkey, h)
    msg =  cipher.decrypt(enc[AES.block_size + 32:])
    return unpad(msg).decode('utf-8')

#hmacs the message
def hmac(encs,authkey):
    h = HMAC.new(authkey, digestmod=SHA256)
    h.update(encs)
    return h

#verifies the hmac
def verifyhmac(msg, authkey, mac):
    h = HMAC.new(authkey, digestmod=SHA256)
    h.update(msg)
    
    if (h.digest() != mac):
        print ("bad HMAC")
        os._exit(1)

#makes the secret and the calculation to send
def secretMaker():
    secret = int.from_bytes(Random.new().read(32), sys.byteorder) #random is from Crypto
    send = pow(GENERATOR_G,secret,PRIME)
    return secret, send

#makes the two keys needed from the secret and the recieved calculation
def keyMaker(s, recieved):
    k = pow(recieved,s,PRIME)
    hashconf = SHA256.new()
    hashconf.update(str(k).encode())
    phasedconf = hashconf.digest()[0:16]
    phasedauth = hashconf.digest()[16:32]
    return phasedconf, phasedauth

#client
if(len(sys.argv) == 3 and sys.argv[1] == "-c"):
    hostname = sys.argv[2]    
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    #connecting to the server
    try:
        server.connect((hostname, PORT))
    except:
        print ('Unable to connect to ' + hostname)
        os._exit(1)
    
    #gets the needed keys
    secret, send = secretMaker()
    server.sendall(str(send).encode())
    recieved = int((server.recv(RECV_BUFFER)).decode())
    phasedconf, phasedauth = keyMaker(secret, recieved)
    
    #reading from and writing to server
    while True:
        #catches KeyboardInterrupts to terminate the program cleanly
        try:
            r, w, e = select.select([sys.stdin, server], [], [])

            for socket in r:
                #incoming message from server
                if socket == server:
                    message = socket.recv(RECV_BUFFER)
                    #if CTRL-D was pressed, the program terminates
                    if (message == "".encode()):
                        os._exit(1)
                    else:
                        mess = decrypt(message, phasedconf, phasedauth)
                        sys.stdout.write(mess)
                #client sending message
                else:
                    message = sys.stdin.readline()
                    #if CTRL-D was pressed, the program terminates
                    if (message == ""):
                        server.sendall("".encode())
                        os._exit(1)
                    else:
                        mess = encrypt(message, phasedconf, phasedauth)
                        server.sendall(mess)
        except KeyboardInterrupt:
            os._exit(1)

#server
elif(len(sys.argv) == 2 and sys.argv[1] == "-s"):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('', PORT))
    #only have one client
    server.listen(1)
    connection, address = server.accept()
    
    #gets the needed keys
    secret, send = secretMaker()
    connection.sendall(str(send).encode())
    try:
        recieved = int((connection.recv(RECV_BUFFER)).decode())
    except:
        print("sussy alert: someone (not client) sent a packet to the port") #detects portscanner
        os._exit(1)

    phasedconf, phasedauth = keyMaker(secret, recieved)
    
    #reading from and writing to client
    while True:
        #catches KeyboardInterrupts to terminate the program cleanly
        try:
            r, w, e = select.select([sys.stdin, connection], [], [])

            for socket in r:
                #incoming message from client
                if socket == connection:
                    message = socket.recv(RECV_BUFFER)
                    #if CTRL-D was pressed, the program terminates 
                    if (message == "".encode()):
                        os._exit(1)
                    else:
                        mess = decrypt(message, phasedconf, phasedauth)
                        sys.stdout.write(mess)
                #server sending message
                else:
                    message = sys.stdin.readline()
                    #if CTRL-D was pressed, the program terminates
                    if (message == ""):
                        connection.sendall("".encode())
                        os._exit(1)
                    else:
                        mess = encrypt(message, phasedconf, phasedauth)
                        connection.sendall(mess)
        except KeyboardInterrupt:
            os._exit(1)

#invalid command line option
else:
    print ("Usage: python3 EncryptedMessenger.py [-s|-c hostname]")
    os._exit(1)