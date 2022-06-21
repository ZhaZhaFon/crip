# reference
# https://github.com/saberbin/socket-/blob/master/client_v3_0.py

# Zifeng Zhao, June 17

from curses.ascii import CR
from http import server
import socket
import time
import os
import threading
import concurrent.futures

import util

CA_IP = '127.0.0.1'
CA_PORT = 62652
SERVER_IP = '127.0.0.1'
BUFSIZE = 1024
POLL_BUFSIZE = 4096
POLL_PORT = 62132

def creat_folder(path):
    if os.path.exists(path):
        return
    else:
        os.mkdir(path)

class ClientApplication(object):

    def __init__(self, server_ip, server_port, client_id):
        super(ClientApplication, self).__init__()
        self.server_ip = server_ip
        self.server_port = server_port
        client_pub_path = 'client_pub_key'
        client_pri_path = 'client_pri_key'
        if os.path.exists(client_pub_path):
            print('read from key pair')
            with open(client_pub_path, 'rb') as f:
                self.public_key = f.read(POLL_BUFSIZE)
            with open(client_pri_path, 'rb') as f:
                self.private_key = f.read(POLL_BUFSIZE)
        else:
            print('generate key pair')
            self.public_key, self.private_key = util.generate_asymetric_key()
            with open(client_pub_path, 'wb') as f:
                f.write(self.public_key)
            with open(client_pri_path, 'wb') as f:
                f.write(self.private_key)
        self.client_id = client_id
        self._lock = threading.Lock()
        self.register()
        print('')
    
    def register(self):
        print('register begin')
        if os.path.exists(self.client_id + '.crt'):
            print('exist a crt')
            with open(self.client_id + '.crt', 'rb') as f:
                self.crt = f.read(POLL_BUFSIZE)
            with open('ca.crt', 'rb') as f:
                self.ca_crt = f.read(POLL_BUFSIZE)
        else:
            with open('client.key', 'wb') as f:
                f.write(self.private_key)
            os.system('openssl req -new -key client.key -out ' + self.client_id + '.req')
            with open(self.client_id + '.req', 'rb') as f:
                req = f.read(POLL_BUFSIZE)
            ca_connect = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ca_connect.connect((CA_IP, int(CA_PORT)))
            ca_connect.sendall(self.client_id.encode('utf-8'))
            ca_connect.recv(POLL_BUFSIZE)
            ca_connect.sendall(req)
            self.crt = ca_connect.recv(POLL_BUFSIZE) 
            with open(self.client_id + '.crt', 'wb') as f:
                f.write(self.crt)
            ca_connect.sendall('receive crt'.encode('utf-8'))
            self.ca_crt = ca_connect.recv(POLL_BUFSIZE)
            with open('ca.crt', 'wb') as f:
                f.write(self.ca_crt)
            ca_connect.close()
            os.system('chmod 600 ca.crt')
            os.system('chmod 600 ' + self.client_id + '.crt')
            print('get crt issued and ca crt')
        
        
    
    # @staticmethod
    # def menu():
    #     print("--------- 文件安全传输系统 v1.0 ---------")
    #     print("------- 客户端 ClientApplication ---------")
    #     print("  1. 发送文件")
    #     print("  2. 接收文件")
    #     print("  3. 退出程序")

    def run_client(self):
        t = threading.Thread(target=self.poll, daemon=True)
        t.start()
        while True:
            # self.menu()
            # option = input("选择功能: ")
            # if option == "1":
            #     self.send_to_server()
            # elif option == "2":
            #     self.recv_from_server()
            # elif option == "3":
            #     print("客户端退出")
            #     self.client_server.close()
            #     return
            # else:
            #     print("客户端退出")
            #     self.client_server.close()
            #     return
            # continue_flag = input("\n是否继续(Y/y)? ")
            # if continue_flag not in "yY":
            #     print("客户端退出")
            #     self.client_server.close()
            #     return

            file_name = input("press file path(q represent quit): ")
            if file_name == 'q':
                break
            with self._lock:
                self.send_to_server(file_name)

    def send_to_server(self, file_name):
        print("begin sending file")
        self.client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_server.connect((self.server_ip, int(self.server_port)))
        self.client_server.sendall('send file'.encode('utf-8'))
        self.client_server.recv(BUFSIZE)
        self.client_server.sendall(self.client_id.encode('utf-8'))
        self.client_server.recv(BUFSIZE)
        self.client_server.sendall(self.crt)
        server_crt = self.client_server.recv(POLL_BUFSIZE)
        with open('server.crt', 'wb') as f:
            f.write(server_crt)
        os.system('chmod 600 server.crt')
        verify_succ, receiver_pub_key = util.verify_digital_signature('server.crt')
        if verify_succ == False:
            print("verify digital signtature error")
            self.client_server.close()
            return
        print("rece pub key size %d"%(len(receiver_pub_key)))
        print("send pub key size %d"%(len(self.public_key)))
        print('send filename size %d'%(len(file_name.encode('utf-8'))))
        self.client_server.sendall(file_name.encode('utf-8'))
        self.client_server.recv(BUFSIZE)
        with open(file_name, 'rb') as f1:
            while True:
                file_content = f1.read(BUFSIZE)
                if file_content :
                    ct, ck, ms = util.encrypt_file(file_content, receiver_pub_key, self.private_key)
                    with open('ct.txt', 'wb') as f:
                        f.write(ct)
                    with open('ck.txt', 'wb') as f:
                        f.write(ck)
                    with open('ms.txt', 'wb') as f:
                        f.write(ms)
                    with open('send_rece_pub_key.txt', 'wb') as f:
                        f.write(receiver_pub_key)
                    with open('send_pri_key.txt', 'wb') as f:
                        f.write(self.private_key)
                    self.client_server.sendall(ct)
                    self.client_server.recv(BUFSIZE)
                    self.client_server.sendall(ck)
                    self.client_server.recv(BUFSIZE)
                    self.client_server.sendall(ms)
                    self.client_server.recv(BUFSIZE)
                else:
                    self.client_server.close()
                    print('finish sending file')
                    break
    
    def poll(self):
        while True:
            time.sleep(5)
            with self._lock:

                print('try to connect server')
                self.poll_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.poll_client.connect((SERVER_IP, int(self.server_port)))
                self.poll_client.sendall('poll'.encode('utf-8'))
                self.poll_client.recv(POLL_BUFSIZE)
                print('connect to server success')
                self.poll_client.sendall(self.crt)
                # server_pub_key = self.poll_client.recv(POLL_BUFSIZE)
                server_crt = self.poll_client.recv(POLL_BUFSIZE)
                with open('server.crt', 'wb') as f:
                    f.write(server_crt)
                os.system('chmod 600 server.crt')
                verify_succ, server_pub_key = util.verify_digital_signature('server.crt')
                if verify_succ == False:
                    print("verify digital signtature error")
                    self.poll_client.close()
                    return
                # verify_succ = util.verify_digital_signature()
                # if verify_succ == False:
                #     print("verify digital signtature error")
                #     self.client_server.close()
                #     return
                self.poll_client.sendall(self.client_id.encode('utf-8'))
                while True:
                    file_name = self.poll_client.recv(POLL_BUFSIZE).decode('utf-8')
                    if len(file_name) == 0:
                        break
                    self.poll_client.sendall('receive file name'.encode('utf-8'))
                    creat_folder(self.client_id)
                    file_path = os.path.join(self.client_id, file_name)
                    with open(file_path, 'wb') as f:
                        while True:
                            ct = self.poll_client.recv(POLL_BUFSIZE)
                            mess = ct.decode('utf-8')
                            self.poll_client.sendall('receive ct'.encode('utf-8'))
                            if 'finish sending file' in mess:
                                break
                            ck = self.poll_client.recv(POLL_BUFSIZE)
                            self.poll_client.sendall('receive ck'.encode('utf-8'))
                            ms = self.poll_client.recv(POLL_BUFSIZE)
                            self.poll_client.sendall('receive ms'.encode('utf-8'))
                            succ, message = util.decrypte_file(ct, ck, ms, self.private_key, server_pub_key)
                            if succ:
                                f.write(message)
                            else:
                                print('file receive fail: since message verify fail')
                                break            
                self.poll_client.close()
        

        # if os.path.exists(file_name) and (not os.path.isdir(file_name)) :

        # # 输入需要发送的文件名，包括文件后缀。仅限二进制文件，包括图片、视频、压缩文件等
        # print("正在连接...")
        # self.client_server.connect((self.server_ip, int(self.server_port)))
        # print("连接成功 !")
        # file_name = input("文件路径: ")
        # server_pub_key = self.client_server.recv(BUFSIZE)
        # self.client_server.sendall(self.public_key)
        # if os.path.exists(file_name) and (not os.path.isdir(file_name)):  # 判断文件是否存在，是否文件夹
        #     # 获取文件的大小
        #     # file_size = os.path.getsize(file_name)
        #     # file_message = file_name + "|" + str(file_size)
        #     # 与服务端建立连接后，先将文件名字与文件的大小发送给服务端
        #     self.client_server.sendall(file_name.encode())
        #     # 对方接收到了file_message的信息后返回一个“RX_HEAD”，接收不成功会返回别的信息
        #     # recv_data = self.client_server.recv(1024)
        #     # 判断对方是否接收信息成功
        #     # if recv_data.decode() == "RX_HEAD":
        #     print("  >> 开始发送...")
        #     start_time = time.time()  # 计算发送文件的开始时间
        #     send_flag = self.send_handle(file_name, server_pub_key)  # 发送文件的请求处理，返回处理结果
        #     end_time = time.time()  # 计算发送文件的结束时间
        #     spend_time = end_time - start_time  # 计算发送文件的耗时
        #     #print("sending file spend {} s".format(spend_time))  # 在控制台输出发送文件的耗时

        #     if send_flag:  # 判断文件是否发送成功
        #         recv_message = self.client_server.recv(1024)
        #         if recv_message.decode() == "RX_COMPLETE":
        #             # 文件发送成功
        #             print("  >> 文件发送成功 !")
        #             self.client_server.close()
        #             return 1
        #         else:
        #             # 对方文件接收不成功
        #             print("server recv file failed.")
        #             self.client_server.close()
        #             return 0
        #     else:
        #         # 文件发送不成功
        #         print("Error,failed to send the file.")
        #         self.client_server.close()
        #         return 0
        #     # else:
        #     #     # 对方没有接收到文件名及文件大小，或者对方断开了连接，取消发送文件，并关闭socket，退出发送服务
        #     #     print("Can't recv the server answer.")
        #     #     print("The client don't send the file data and close the server.")
        #     #     self.client_server.close()
        #     #     return 0
        # try:
        #     self.client_server.close()  # 尝试关闭本方的socket，防止前面没有进行关闭，如果前面已经关闭了，直接退出函数
        # except Exception:
        #     pass

    # def send_handle(self, file_name, server_pub_key):
    #     """
    #     处理传输文件数据，将文件读取并发送到接收端，只允许单次发送
    #     单次发送失败后需要进行重连再重新发送
    #     :param file_name: 要发送的文件名
    #     :return: 发送文件的结果，1为发送成功，0为发送失败
    #     """
    #     if file_name:
    #         # 判断传入的文件信息是否空
    #         # self.client_server.sendall(b"START_TO_TX")
    #         with open(file_name, "rb") as f:
    #             while True:
    #                 # 循环读取文件
    #                 file_content = f.read(BUFSIZE)  # 每次从文件种读取1M数据
    #                 al_read_size += len(file_content)  # 计算总共读取的数据的大小
    #                 if file_content:  # 判断文件是否读取完了
    #                     # print("  >> {}%".format(al_read_size / file_size))  # 输出读取文件的进度
    #                     ct, ck, ms = util.encrypt_file(file_content, server_pub_key, self.private_key)
    #                     self.client_server.sendall(ct)
    #                     self.client_server.sendall(ck)
    #                     self.client_server.sendall(ms)
    #                 else:
    #                     print("send file complete")  # 判断文件读取完了，输出读取的进度
    #                     return 1  # 文件读取发送完了，返回处理情况
    #     else:
    #         print("Can't find the file or the file is empty.")  # 打开文件失败，文件或文件名为空，则退出发送服务
    #         self.client_server.sendall(b'cancel send file.')  # 通知服务端取消文件的发送
    #         return 0  # 文件未发送成功，返回0

def main():
    print('### 客户端启动 ###')
    # server_address = input("  >> 服务器地址: ")
    # server_port = eval(input("  >> 进程端口号: "))
    server_address = '127.0.0.1'
    server_port = int(63231)
    client_id = input("输入客户端名称")
    creat_folder(client_id)
    os.chdir(client_id)
    client = ClientApplication(server_address, server_port, client_id)
    client.run_client()

if __name__ == "__main__":
    print('')
    main()