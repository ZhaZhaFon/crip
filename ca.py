import os
import time
import socket


LISTEN_PORT = 62652
BUFSIZE = 4096
cur_path = os.getcwd()
cpath = cur_path + '/opt/easy-rsa/'
os.chdir(cpath)

# file_name = 'clinent5'
# if file_name == 'q':
#     pass
# else:
    
#     os.system('./easyrsa import-req client.req %s'%file_name)
#     os.system('./easyrsa sign-req client %s'%file_name)
#     time.sleep(0.1)
    
#     print('Certificate created at: /opt/easy-rsa/pki/issued/%s.crt'%file_name)

def main():
    TCP_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    TCP_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
    TCP_server.bind(('', LISTEN_PORT))
    TCP_server.listen(60)
    while True:
        connect, _ = TCP_server.accept()
        client_ip = connect.recv(BUFSIZE).decode('utf-8')
        connect.sendall('receive client ip'.encode('utf-8'))
        client_req = connect.recv(BUFSIZE)
        with open('client.req', 'wb') as f:
            f.write(client_req)
        os.system('./easyrsa import-req client.req %s'%(client_ip))
        os.system('./easyrsa sign-req client %s'%(client_ip))
        print('Certificate created at: /opt/easy-rsa/pki/issued/%s.crt'%(client_ip))
        file_path = './pki/issued/' + client_ip + '.crt'
        with open(file_path, 'rb') as f:
            crt = f.read(BUFSIZE)
            connect.sendall(crt)
            connect.recv(BUFSIZE)
        with open('pki/ca.crt', 'rb') as f:
            ca_crt = f.read(BUFSIZE)
            connect.sendall(ca_crt)
        connect.close()
        
if __name__ == '__main__':
    main()