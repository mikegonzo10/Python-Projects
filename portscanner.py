#This is a simple port scanner that evaluates whether a port is open by whether we can create a socket at the port 
import socket
import sys

#We are asking the user to scan what ip address they want to scan.
print('What ip do you want to scan?')
ip = input()

# this is our first function!
def checkports(ip,portlist):
    try: 
        for port in portlist:
            sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result=sock.connect_ex((ip,port))
            if result == 0:
                print('Port {}:\t Open '.format(port))
            else: 
                print('Port {}:\t Close '.format(port))
            
            socket.close

    except socket.error as error:
        print(str(error))
        print('ConnectionError')
        sys.exit()
    
#This calls our function checkports and passes parameters to it with ip and ports 
checkports(ip, [21,22,80,81,8080,443])

    