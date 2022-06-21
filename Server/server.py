# reference
# https://github.com/saberbin/socket-/blob/master/server_v4_0.py

# Zifeng Zhao, June 17


import socket
import os
import time
import util
import threading
import concurrent.futures


BUFSIZE = 4096  
POLL_BUFSIZE = 1024
STORY_DIRECTORY_PATH = 'Server'
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
        self.TCP_server.listen(60)
        self.pub_key, self.pri_key = util.generate_asymetric_key()
        self.wait_send_table = {}
        self.all_recv_fils = []
        self._lock = threading.Lock()
    
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
        sender_pub_key = self.client_server.recv(BUFSIZE)
        self.client_server.sendall(self.pub_key)
        print("Ready to recv the file from %s"%(recv_client_id))
        # 接收发送端发送的文件名及文件大小
        file_name = self.client_server.recv(BUFSIZE).decode('utf-8')
        self.client_server.sendall('receive file name'.encode('utf-8'))
        print('recv file name size is %d'%(len(file_name)))
        print('file name is %s'%(file_name))
        creat_folder(STORY_DIRECTORY_PATH)
        file_path = os.path.join(STORY_DIRECTORY_PATH, file_name)
        with open(file_path, "wb") as f:
            while True:
                # 循环接收文件数据
                ct = self.client_server.recv(BUFSIZE)
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
                if len(ck) == 0 :
                    print("file receve fail: since ck is empty")
                    break
                self.client_server.sendall('receive ck'.encode('utf-8'))
                ms = self.client_server.recv(BUFSIZE)
                if len(ms) == 0 :
                    print("file receve fail: since ms is empty")
                    break
                self.client_server.sendall('receive ms'.encode('utf-8'))
                succ, message = util.decrypte_file(ct, ck, ms, self.pri_key, sender_pub_key)
                if succ:
                    f.write(message)
                else:
                    print('file receive fail: since message verify fail')
                    break
        self.client_server.close()

    def poll_handle(self):
        client_pub_key = self.poll_connect.recv(POLL_BUFSIZE)
        self.poll_connect.sendall(self.pub_key)
        verify_succ = util.verify_digital_signature()
        if verify_succ == False:
            print("verify digital signtature error")
            self.client_server.close()
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
    tcp_server = ServerApplication(LISTEN_PORT)
    print('')
    tcp_server.run_server()
