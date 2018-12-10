import socket
import time
import sys

if __name__ == '__main__':
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    port = 55555

    server.bind(('',port))
    #server.listen(5)
    #c, addr = server.accept()
    while(True):
        m , addr = server.recvfrom(1024)
        m = m.decode()
        print("%s: %s" %(addr,m))
        if m == 'stop':
            break
    print('closing')
    server.close()