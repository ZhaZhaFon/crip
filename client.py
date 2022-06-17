# reference
# https://github.com/saberbin/socket-/blob/master/client_v3_0.py

# Zifeng Zhao, June 17

from curses.ascii import CR
import socket
import time
import os
import util

class ClientApplication(object):

    def __init__(self, server_ip, server_port):
        super(ClientApplication, self).__init__()
        self.client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_ip = server_ip
        self.server_port = server_port
        self.public_key, self.private_key = util.generate_asymetric_key
        print('')
    
    @staticmethod
    def menu():
        print("--------- 文件安全传输系统 v1.0 ---------")
        print("------- 客户端 ClientApplication ---------")
        print("  1. 发送文件")
        print("  2. 接收文件")
        print("  3. 退出程序")

    def run_client(self):
        while True:
            self.menu()
            option = input("选择功能: ")
            if option == "1":
                self.send_to_server()
            elif option == "2":
                self.recv_from_server()
            elif option == "3":
                print("客户端退出")
                self.client_server.close()
                return
            else:
                print("客户端退出")
                self.client_server.close()
                return
            continue_flag = input("\n是否继续(Y/y)? ")
            if continue_flag not in "yY":
                print("客户端退出")
                self.client_server.close()
                return

    def send_to_server(self):
        # 输入需要发送的文件名，包括文件后缀。仅限二进制文件，包括图片、视频、压缩文件等
        print("正在连接...")
        self.client_server.connect((self.server_ip, int(self.server_port)))
        print("连接成功 !")
        file_name = input("文件路径: ")
        if os.path.exists(file_name) and (not os.path.isdir(file_name)):  # 判断文件是否存在，是否文件夹
            # 获取文件的大小
            file_size = os.path.getsize(file_name)
            file_message = file_name + "|" + str(file_size)
            # 与服务端建立连接后，先将文件名字与文件的大小发送给服务端
            self.client_server.sendall(file_message.encode())
            # 对方接收到了file_message的信息后返回一个“RX_HEAD”，接收不成功会返回别的信息
            recv_data = self.client_server.recv(1024)
            # 判断对方是否接收信息成功
            if recv_data.decode() == "RX_HEAD":
                print("  >> 开始发送...")
                start_time = time.time()  # 计算发送文件的开始时间
                send_flag = self.send_handle(file_name, file_size)  # 发送文件的请求处理，返回处理结果
                end_time = time.time()  # 计算发送文件的结束时间
                spend_time = end_time - start_time  # 计算发送文件的耗时
                #print("sending file spend {} s".format(spend_time))  # 在控制台输出发送文件的耗时

                if send_flag:  # 判断文件是否发送成功
                    recv_message = self.client_server.recv(1024)
                    if recv_message.decode() == "RX_COMPLETE":
                        # 文件发送成功
                        print("  >> 文件发送成功 !")
                        self.client_server.close()
                        return 1
                    else:
                        # 对方文件接收不成功
                        print("server recv file failed.")
                        self.client_server.close()
                        return 0
                else:
                    # 文件发送不成功
                    print("Error,failed to send the file.")
                    self.client_server.close()
                    return 0
            else:
                # 对方没有接收到文件名及文件大小，或者对方断开了连接，取消发送文件，并关闭socket，退出发送服务
                print("Can't recv the server answer.")
                print("The client don't send the file data and close the server.")
                self.client_server.close()
                return 0
        try:
            self.client_server.close()  # 尝试关闭本方的socket，防止前面没有进行关闭，如果前面已经关闭了，直接退出函数
        except Exception:
            pass

    def send_handle(self, file_name, file_size):
        """
        处理传输文件数据，将文件读取并发送到接收端，只允许单次发送
        单次发送失败后需要进行重连再重新发送
        :param file_name: 要发送的文件名
        :param file_size: 要发送的文件的大小
        :return: 发送文件的结果，1为发送成功，0为发送失败
        """
        al_read_size = 0  # 保存已读取的文件大小，显示读取的进度
        if file_name and file_size:
            # 判断传入的文件信息是否空
            self.client_server.sendall(b"START_TO_TX")
            with open(file_name, "rb") as f:
                while True:
                    # 循环读取文件
                    file_content = f.read(1048576)  # 每次从文件种读取1M数据
                    al_read_size += len(file_content)  # 计算总共读取的数据的大小
                    if file_content:  # 判断文件是否读取完了
                        print("  >> {}%".format(al_read_size / file_size))  # 输出读取文件的进度
                        self.client_server.sendall(file_content)  # 将读取的文件发送到服务端
                    else:
                        print("  >> 100%")  # 判断文件读取完了，输出读取的进度
                        return 1  # 文件读取发送完了，返回处理情况
        else:
            print("Can't find the file or the file is empty.")  # 打开文件失败，文件或文件名为空，则退出发送服务
            self.client_server.sendall(b'cancel send file.')  # 通知服务端取消文件的发送
            return 0  # 文件未发送成功，返回0

def main():
    print('### 客户端启动 ###')
    server_address = input("  >> 服务器地址: ")
    server_port = eval(input("  >> 进程端口号: "))
    client = ClientApplication(server_address, server_port)
    client.run_client()

if __name__ == "__main__":
    print('')
    main()