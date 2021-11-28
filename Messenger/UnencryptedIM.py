import socket, sys, select, string
PORT = 9999
RECV_BUFFER = 4096
CONNECTIONS = []

if(len(sys.argv) == 2 and sys.argv[1] == "-s"):
    #The server code

    HOST = '0.0.0.0' 
    PORT = 9999

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    print("Now listening...")
    s.listen(1) #only needs to receive one connection (the client)
    conn, addr = s.accept() #accepts the connection
    print("Connected by: ", addr) #prints the connection
    i = True

    while i is True:
        data = conn.recv(RECV_BUFFER) #receives data
        sys.stdout.write(data.decode('utf-8')) #prints the message from client 

        reply = sys.stdin.readline() #server types a response
        conn.sendall(reply.encode('utf-8')) #server now sends response back to client

elif(len(sys.argv) == 3 and sys.argv[1] == "-c"):

    HOST = sys.argv[2]
    PORT = 9999
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    while True:
        message = sys.stdin.readline()  #client's message to the server
        s.sendall(message.encode('utf-8')) #sends message to the server

        reply = s.recv(RECV_BUFFER) #receives message from server
        sys.stdout.write(reply.decode('utf-8')) #prints the message received 

else:
    print ('usage: UnencryptedIM -s|-c hostname')
    sys.exit()