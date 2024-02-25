import socket 

Websocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

Websocket.bind(('192.168.100.101', 81))

Websocket.listen(5)

while True:
    print('Waiting for connections')
    (reciveSocket, address) = Websocket.accept()
    print('HTTP request recieved:')
    print (reciveSocket.recv(1024))
    reciveSocket.send(bytes('HTTP/1.1 200 OK\r\n\r\n <Html> <body> <h1> Hello from Mike Corona-Gonzalez!</h1> </body> </html> \r\n', 'utf-8'))
    reciveSocket.close()
