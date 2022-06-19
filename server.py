# reference
# https://github.com/saberbin/socket-/blob/master/server_v4_0.py

# Zifeng Zhao, June 17

LOCAL_IP = '127.0.0.1'
LISTEN_PORT = 63231

import socket
import os
import time
import util


BUFSIZE = 4096  

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
        self.TCP_server.bind((LOCAL_IP, server_port))
        self.client_server = None

        # get host name
        self.host_name = socket.gethostname()
        # get computer ip address
        self.ip_address = LOCAL_IP
        print("本机IP: {}".format(self.ip_address))
        print("本机端口: {}".format(server_port))
        self.TCP_server.listen(60)
        self.pub_key, self.pri_key = util.generate_asymetric_key()

    # def connect_server(self):
    #     print("等待客户端接入...")
    #     self.client_server, self.client_ip_port = self.TCP_server.accept()
    #     self.__class__.client_manager[self.client_server] = self.client_ip_port
    #     print('连接成功 !')

    # @staticmethod
    # def menu():
    #     print("--------- 文件安全传输系统 v1.0 ---------")
    #     print("------- 服务端 ServerApplication ---------")
    #     print("  1. 发送文件")
    #     print("  2. 接收文件")
    #     print("  3. 退出程序")
    
    def run_server(self):
        while True:
            self.client_server, self.client_ip_port = self.TCP_server.accept()
            self.recv_from_client()
            # self.menu()
            # option = input("选择功能: ")
            # if option == "1":
            #     self.send_to_server()
            # elif option == "2":
            #     self.recv_from_client()
            # elif option == "3":
            #     print("服务端退出")
            #     self.client_server.close()
            #     return
            # else:
            #     print("服务端退出")
            #     self.client_server.close()
            # continue_flag = input("\n是否继续(Y/y)? ")
            # if continue_flag not in "yY":
            #     print("服务端退出")
            #     self.client_server.close()
            #     return

    def recv_from_client(self):
        print('send pub key size is %d'%(len(self.pub_key)))
        sender_pub_key = self.client_server.recv(BUFSIZE)
        self.client_server.sendall(self.pub_key)
        print('recv pub key size is %d'%(len(sender_pub_key)))
        print("Ready to recv the file...")
        # 接收发送端发送的文件名及文件大小
        file_name = self.client_server.recv(BUFSIZE).decode()
        self.client_server.sendall('receive file name'.encode())
        print('recv file name size is %d'%(len(file_name)))
        print('file name is %s'%(file_name))
        creat_folder("Rx")
        file_path = os.path.join("Rx", file_name)
        with open(file_path, "wb") as f:
            while True:
                # 循环接收文件数据
                ct = self.client_server.recv(BUFSIZE)
                if len(ct) == 0 :
                    print("file receive complete")
                    break
                self.client_server.sendall('receive ct'.encode())
                ck = self.client_server.recv(BUFSIZE)
                if len(ck) == 0 :
                    print("file receve fail: since ck is empty")
                    break
                self.client_server.sendall('receive ck'.encode())
                ms = self.client_server.recv(BUFSIZE)
                if len(ms) == 0 :
                    print("file receve fail: since ms is empty")
                    break
                self.client_server.sendall('receive ms'.encode())
                succ, message = util.decrypte_file(ct, ck, ms, self.pri_key, sender_pub_key)
                if succ:
                    f.write(message)
                else:
                    print('file receive fail: since message verify fail')
                    break
        self.client_server.close()
 
        # if file_name :
        #     recv_flag = self.recv_handle(file_path, client_pub_key)  # 启用文件接收服务
        #     # 判断文件的接收结果
        #     if recv_flag:
        #         self.client_server.close()
        #         print("文件接收成功，断开连接")
        #         return
        #     else:
        #         print("文件接收失败，断开连接")
        #         self.client_server.close()
        # else:
        #     # 文件名或文件大小为空，拒绝接收文件，断开连接
        #     print("server get a empty file name")
        #     self.client_server.colse()
        #     return

    # def recv_handle(self, file_path, client_pub_key):
    #     """
    #         接收文件的处理函数，只允许单次接收，一次接收失败后需要重新建立连接后重新发送
    #         :param file_path: 保存文件的路径
    #         :return: 接收文件的结果，1表示接收成功，0表示接收失败
    #         """
    #     print("Start to recv th file...")
    #     with open(file_path, "w") as f:
    #         while True:
    #             # 循环接收文件数据
    #             ct = self.client_server.recv(BUFSIZE).decode()
    #             if len(ct) == 0 :
    #                 print("file receive complete")
    #                 return True
    #             ck = self.client_server.recv(BUFSIZE).decode()
    #             if len(ck) == 0 :
    #                 print("file receve fail: since ck is empty")
    #                 return False
    #             ms = self.client_server.recv(BUFSIZE).decode()
    #             if len(ms) == 0 :
    #                 print("file receve fail: since ms is empty")
    #                 return False
                

if __name__ == "__main__":

    print('')
    print('### 客户端启动 ###')
    # flag = 1
    # while flag:
    #     try:
    #         server_port = int(input("  >> 输入监听端口号: "))
    #         flag = 0
    #     except Exception as e:
    #         print(e)
    #         select = input("请出入正确端口号 是否继续(Y/y)? ")
    #         if select in "yY":
    #             flag = 1
    #         else:
    #             exit()  # exit the program.
    print('')
    tcp_server = ServerApplication(LISTEN_PORT)
    print('')
    # tcp_server.connect_server()
    tcp_server.run_server()

    # tcp_server.system_quit()