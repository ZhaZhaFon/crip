# reference
# https://github.com/saberbin/socket-/blob/master/server_v4_0.py

# Zifeng Zhao, June 17

LOCAL_IP = '219.223.194.127'

import socket
import os
import time

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
        self.TCP_server.bind(("", server_port))
        self.client_server = None
        self.client_ip_port = None

        # get host name
        self.host_name = socket.gethostname()
        # get computer ip address
        self.ip_address = LOCAL_IP
        print("本机IP: {}".format(self.ip_address))
        print("本机端口: {}".format(server_port))
        self.TCP_server.listen(60)

    def connect_server(self):
        print("等待客户端接入...")
        self.client_server, self.client_ip_port = self.TCP_server.accept()
        self.__class__.client_manager[self.client_server] = self.client_ip_port
        print('连接成功 !')

    @staticmethod
    def menu():
        print("--------- 文件安全传输系统 v1.0 ---------")
        print("------- 服务端 ServerApplication ---------")
        print("  1. 发送文件")
        print("  2. 接收文件")
        print("  3. 退出程序")
    
    def run_server(self):
        while True:
            self.menu()
            option = input("选择功能: ")
            if option == "1":
                self.send_to_server()
            elif option == "2":
                self.recv_from_server()
            elif option == "3":
                print("服务端退出")
                self.client_server.close()
                return
            else:
                print("服务端退出")
                self.client_server.close()
            continue_flag = input("\n是否继续(Y/y)? ")
            if continue_flag not in "yY":
                print("服务端退出")
                self.client_server.close()
                return

    def recv_from_server(self):
        print("Ready to recv the file...")
        # 接收发送端发送的文件名及文件大小
        file_name, file_size = self.client_server.recv(1024).decode().split("|")
        file_size = int(file_size)
        creat_folder("Rx")
        file_path = os.path.join("Rx", file_name)
        # 判断文件名及文件大小是否为空
        if file_name and file_size:
            self.client_server.send(b'RX_HEAD')  # 反馈文件发送端，已收到文件名及文件大小
            start_flag = self.client_server.recv(1024).decode()
            if start_flag == "START_TO_TX":
                recv_flag = self.recv_handle(file_path, file_size)  # 启用文件接收服务
                # 判断文件的接收结果
                if recv_flag:
                    self.client_server.close()
                    print("文件接收成功，断开连接")
                    return
                else:
                    print("文件接收失败，断开连接")
                    self.client_server.close()
            else:
                print("对方拒绝发送文件，取消连接")
                self.client_server.close()
                return
        else:
            # 文件名或文件大小为空，拒绝接收文件，断开连接
            self.client_server.send(b'refuse')
            self.client_server.colse()
            return

    def recv_handle(self, file_path, file_size):
        """
            接收文件的处理函数，只允许单次接收，一次接收失败后需要重新建立连接后重新发送
            :param file_path: 保存文件的路径
            :param file_size: 要接收的文件的大小
            :return: 接收文件的结果，1表示接收成功，0表示接收失败
            """
        print("Start to recv th file...")
        recv_size = 0  # 保存接收的文件的大小
        start_time = time.time()  # 保存开始接收文件的时间
        with open(file_path, "w") as f:
            if True:
                # 循环接收文件数据
                file_content = self.client_server.recv(1048576).decode()
                if file_content:  # 判断文件是否接收完了
                    recv_size += len(file_content)  # 累计接收的文件大小
                    f.write(file_content)  # 将接收的数据保存到文件中
            # 如果文件接收完了，则退出循环
            end_time = time.time()  # 保存文件接收结束的时间
            #print("spend time:{}".format(end_time - start_time))
        if recv_size == file_size:  # 判断接收的文件大小与对方发送的文件大小是否一致
            print("文件全部接收完毕，耗时：{}".format(end_time - start_time))
            self.client_server.send(b'RX_COMPLETE')
            return 1
        else:
            print("文件未接收完成，只接收了{}%".format(recv_size / file_size))
            print("Failed to recv the file.")
            self.client_server.send(b'fail')
            return 0

if __name__ == "__main__":

    print('')
    print('### 客户端启动 ###')
    flag = 1
    while flag:
        try:
            server_port = int(input("  >> 输入监听端口号: "))
            flag = 0
        except Exception as e:
            print(e)
            select = input("请出入正确端口号 是否继续(Y/y)? ")
            if select in "yY":
                flag = 1
            else:
                exit()  # exit the program.
    print('')
    tcp_server = ServerApplication(server_port)
    print('')
    tcp_server.connect_server()
    tcp_server.run_server()

    tcp_server.system_quit()