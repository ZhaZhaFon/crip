# reference
# https://github.com/saberbin/socket-/blob/master/server_v4_0.py

# Zifeng Zhao, June 17


import socket
import os
import time
import util
import threading
import concurrent.futures

CA_IP = '127.0.0.1'
CA_PORT = 62652
BUFSIZE = 4096  
POLL_BUFSIZE = 1024
STORY_DIRECTORY_PATH = 'server'
LOCAL_IP = '127.0.0.1'
LISTEN_PORT = 63231
POLL_PORT = 63231

# Resource 文件夹保存接收的文件
def creat_folder(path):
    if os.path.exists(path):
        return
    else:
        os.mkdir(path)

class ServerApplication(object):

    client_manager = {}

    def __init__(self, server_port=2200):
        super(ServerApplication, self).__init__()
        self.TCP_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.TCP_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        self.TCP_server.bind(('', server_port))
        self.TCP_server.listen(60)
        self.client_server = None

        
        # self.poll_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # self.poll_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
        # self.poll_server.bind(('', POLL_PORT))
        self.poll_connect = None

        # get host name
        self.host_name = socket.gethostname()
        # get computer ip address
        self.ip_address = LOCAL_IP
        print("本机IP: {}".format(self.ip_address))
        print("本机端口: {}".format(server_port))
        self.pub_key, self.pri_key = util.generate_asymetric_key()
        server_pub_path = 'server_pub_key'
        server_pri_path = 'server_pri_key'
        if os.path.exists(server_pub_path):
            print('read from exist pair')
            with open(server_pub_path, 'rb') as f:
                self.pub_key = f.read(BUFSIZE)
            with open(server_pri_path, 'rb') as f:
                self.pri_key = f.read(BUFSIZE)
        else:
            print('generate new pair')
            self.pub_key, self.pri_key = util.generate_asymetric_key()
            with open(server_pub_path, 'wb') as f:
                f.write(self.pub_key)
            with open(server_pri_path, 'wb') as f:
                f.write(self.pri_key)
        self.wait_send_table = {}
        self.all_recv_fils = []
        self.client_id = 'server'
        self._lock = threading.Lock()
        self.register()

    def register(self):
        print('register begin')
        if os.path.exists(self.client_id + '.crt'):
            print('exist a crt')
            with open(self.client_id + '.crt', 'rb') as f:
                self.crt = f.read(BUFSIZE)
            with open('ca.crt', 'rb') as f:
                self.ca_crt = f.read(BUFSIZE)
        else:
            with open('client.key', 'wb') as f:
                f.write(self.pri_key)
            os.system('openssl req -new -key client.key -out ' + self.client_id + '.req')
            with open(self.client_id + '.req', 'rb') as f:
                req = f.read(BUFSIZE)
            ca_connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ca_connect.connect((CA_IP, int(CA_PORT)))
            ca_connect.sendall(self.client_id.encode('utf-8'))
            ca_connect.recv(BUFSIZE)
            ca_connect.sendall(req)
            self.crt = ca_connect.recv(BUFSIZE) 
            with open(self.client_id + '.crt', 'wb') as f:
                f.write(self.crt)
            ca_connect.sendall('receive crt'.encode('utf-8'))
            self.ca_crt = ca_connect.recv(BUFSIZE)
            with open('ca.crt', 'wb') as f:
                f.write(self.ca_crt)
            ca_connect.close()
            os.system('chmod 600 ca.crt')
            os.system('chmod 600 ' + self.client_id + '.crt')
            print('get crt issued and ca crt')
    
    def run_server(self):
        # with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        #     executor.submit(self.recv_from_client)
        #     executor.submit(self.poll_handle)
        while True:
            self.client_server, self.client_ip_port = self.TCP_server.accept()
            mess = self.client_server.recv(BUFSIZE).decode('utf-8')
            self.client_server.sendall('receive task type'.encode('utf-8'))
            if mess == 'send file':
                self.recv_from_client()
            elif mess == 'poll':
                self.poll_connect = self.client_server
                self.poll_handle()
            else:
                print('receive task type not right')
                self.client_server.close()
        

    def recv_from_client(self):
        recv_client_id = self.client_server.recv(BUFSIZE).decode('utf-8')
        self.client_server.sendall('receive client id'.encode('utf-8'))
        sender_crt = self.client_server.recv(BUFSIZE)
        self.client_server.sendall(self.crt)
        
        with open('client.crt', 'wb') as f:
            f.write(sender_crt)
        os.system('chmod 600 client.crt')
        verify_succ, sender_pub_key = util.verify_digital_signature('client.crt')
        if verify_succ == False:
            print("verify digital signtature error")
            self.client_server.close()
            return
        # with open('../client5/client_pub_key', 'rb') as f:
        #     sender_pub_key = f.read(BUFSIZE)

        print("Ready to recv the file from %s"%(recv_client_id))
        # 接收发送端发送的文件名及文件大小
        file_name = self.client_server.recv(BUFSIZE).decode('utf-8')
        self.client_server.sendall('receive file name'.encode('utf-8'))
        print('recv file name size is %d'%(len(file_name)))
        print('file name is %s'%(file_name))
        creat_folder(STORY_DIRECTORY_PATH)
        file_path = os.path.join(STORY_DIRECTORY_PATH, file_name)
        with open(file_path, "wb") as f1:
            while True:
                # 循环接收文件数据
                ct = self.client_server.recv(BUFSIZE)
                with open('ct.txt',  'wb') as f:
                    f.write(ct)
                if len(ct) == 0 :
                    print("file receive complete")
                    with self._lock:
                        if recv_client_id not in self.wait_send_table:
                            self.wait_send_table[recv_client_id] = self.all_recv_fils
                        if file_name not in self.all_recv_fils:
                            self.all_recv_fils.append(file_name)
                        for client_id in self.wait_send_table :
                            if client_id ==  recv_client_id:
                                continue
                            if file_name not in self.wait_send_table[client_id]:
                                self.wait_send_table[client_id].append(file_name)
                    break
                self.client_server.sendall('receive ct'.encode('utf-8'))
                ck = self.client_server.recv(BUFSIZE)
                with open('ck.txt',  'wb') as f:
                    f.write(ck)
                if len(ck) == 0 :
                    print("file receve fail: since ck is empty")
                    break
                self.client_server.sendall('receive ck'.encode('utf-8'))
                ms = self.client_server.recv(BUFSIZE)
                with open('ms.txt',  'wb') as f:
                    f.write(ck)
                if len(ms) == 0 :
                    print("file receve fail: since ms is empty")
                    break
                self.client_server.sendall('receive ms'.encode('utf-8'))
                with open('rece_pri_key.txt', 'wb') as f:
                    f.write(self.pri_key)
                with open('rece_sender_pub_key.txt', 'wb') as f:
                    f.write(sender_pub_key)
                succ, message = util.decrypte_file(ct, ck, ms, self.pri_key, sender_pub_key)
                if succ:
                    f1.write(message)
                else:
                    print('file receive fail: since message verify fail')
                    break
        self.client_server.close()

    def poll_handle(self):
        client_crt = self.poll_connect.recv(BUFSIZE)
        self.poll_connect.sendall(self.crt)
        with open('client.crt', 'wb') as f:
            f.write(client_crt)
        os.system('chmod 600 client.crt')
        verify_succ, client_pub_key = util.verify_digital_signature('client.crt')
        if verify_succ == False:
            print("verify digital signtature error")
            self.poll_connect.close()
            return
        poll_client_id = self.poll_connect.recv(POLL_BUFSIZE).decode('utf-8')
        print("get a connection from client %s"%(poll_client_id))
        need_to_sned = []
        with self._lock:
            if poll_client_id not in self.wait_send_table :
                self.wait_send_table[poll_client_id] = []
                need_to_sned = self.all_recv_fils
            else:
                need_to_sned = self.wait_send_table[poll_client_id]
                self.wait_send_table[poll_client_id] = []
        for file_name in need_to_sned:
            self.poll_connect.sendall(file_name.encode('utf-8'))
            self.poll_connect.recv(POLL_BUFSIZE)
            file_path = os.path.join(STORY_DIRECTORY_PATH, file_name)
            with open(file_path, 'rb') as f:
                while True:
                    file_content = f.read(POLL_BUFSIZE)
                    if file_content :
                        ct, ck, ms = util.encrypt_file(file_content, client_pub_key, self.pri_key)
                        self.poll_connect.sendall(ct)
                        self.poll_connect.recv(POLL_BUFSIZE)
                        self.poll_connect.sendall(ck)
                        self.poll_connect.recv(POLL_BUFSIZE)
                        self.poll_connect.sendall(ms)
                        self.poll_connect.recv(POLL_BUFSIZE)
                    else:
                        self.poll_connect.sendall('finish sending file'.encode('utf-8'))
                        self.poll_connect.recv(POLL_BUFSIZE)
                        print('finish sending file %s'%(file_name))
                        break
        print('finish poll from cline %s'%(poll_client_id))
        self.poll_connect.close()
                
 
                

if __name__ == "__main__":

    print('')
    print('### 客户端启动 ###')
    print('')
    creat_folder('server')
    os.chdir('server')
    tcp_server = ServerApplication(LISTEN_PORT)
    print('')
    tcp_server.run_server()
