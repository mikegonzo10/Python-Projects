#! /usr/bin/python3

import socket

tcp_ip = '127.0.0.1'

tcp_port = 55

buffer_size=100

s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind((tcp_ip,tcp_port))

s.listen(1)

conn,addr= s.accept()

print('Connectionaddress: ', addr)

while 1:
	
	data=conn.recv(buffer_size)
	if not data :break
	print('recived data: ', data)
	conn.send(data)
	
conn.close
