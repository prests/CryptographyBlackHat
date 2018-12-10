import socket
import time

if __name__ == "__main__":
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ip = '192.168.1.214'
    port = 55555
    client.connect((ip,port))
    while(True):
        try:
            m = input('>>> ')
            client.sendto(m.encode(),(ip,port))
            print('sent')
        except KeyboardInterrupt:
            break
    print('closing')
    client.close()