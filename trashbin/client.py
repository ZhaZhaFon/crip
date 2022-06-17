'''
import argparse
parser = argparse.ArgumentParser()
parser.add_argument('--file_path',  required=True, type=str)
parser.add_argument('--ip_address', required=True, type=str)
parser.add_argument('--port',       required=False, default='2200', type=int)

def main(args):

    import socket
    import struct  
    import json   # 转换数据格式(序列化)
    import os

    share_dir =  ''# 这里是服务器储存资源的地址

    phone = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    phone.bind((args.ip_address, args.port))
    phone.listen(5)
    while True:
        conn, client = phone.accept()
        while True:
            try:
                # 收命令
                res = conn.recv(8096)  # b'get a.txt'

                # 解析命令、提取相应的命令参数
                cmds = res.decode('gbk').split()  # ['get','a.txt']  split变列表格式
                filename = cmds[1]

                # 已读的方式打开文件，读取文件内容发送给客户端
                # 第一步：制作固定长度的报头
                header_dic = {
                    'filename': filename,
                    'file_size': os.path.getsize(r'%s/%s' % (share_dir, filename))  # 这里把文件的名字和地址结合在一起得到文件长度
                }      # 字典方便储存数据
                header_json = json.dumps(header_dic)  # 把字典转换成js格式(字符串类型)

                header_bytes = header_json.encode('gbk')  

                # 第二步：先发送报头的长度
                conn.send(struct.pack('i', len(header_bytes)))  

                # 第三步：再发报头
                conn.send(header_bytes)

                # 第四步：发送真实数据
                with open('%s/%s' % (share_dir, filename), 'rb') as f:   
                    for line in f:   # 这样一行一行发比直接发送f.read节省内存空间
                        conn.send(line)
            except ConnectionResetError as err:
                break
        conn.close()

    phone.close()

if __name__ == '__main__':
    args = parser.parse_args()
    main(args)
'''

# -*- coding:UTF-8 -*-
# /usr/bin/python
# Date: 2019/7/26 17:00

import socket
import time
import os


class ClientServer(object):
    def __init__(self, server_ip, server_port):
        super(ClientServer, self).__init__()
        self.client_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("connecting the server...")
        self.client_server.connect((server_ip, int(server_port)))
        print("connecting success!")

    def recv_server(self):
        print("Ready to recv the file...")
        # 接收发送端发送的文件名及文件大小
        file_name, file_size = self.client_server.recv(1024).decode().split("|")
        creat_folder("Resource")
        file_path = os.path.join("Resource", file_name)
        if os.path.exists(file_path):
            file_name, point, end_str = file_path.partition(".")
            file_path = file_name + "_1" + point + end_str
        # 判断文件名及文件大小是否为空
        if file_name and file_size:
            self.client_server.send(b'copy')  # 反馈文件发送端，已收到文件名及文件大小
            start_flag = self.client_server.recv(1024).decode()
            if start_flag == "starting send file":
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
        with open(file_path, "ab") as f:
            while True:
                # 循环接收文件数据
                file_content = self.client_server.recv(1048576)
                if file_content:  # 判断文件是否接收完了
                    recv_size += len(file_content)  # 累计接收的文件大小
                    f.write(file_content)  # 将接收的数据保存到文件中
                else:
                    # 如果文件接收完了，则退出循环
                    end_time = time.time()  # 保存文件接收结束的时间
                    print("spend time:{}".format(end_time - start_time))
                    break

        if recv_size == file_size:  # 判断接收的文件大小与对方发送的文件大小是否一致
            print("文件全部接收完毕，耗时：{}".format(end_time - start_time))
            self.client_server.send(b'ok')
            return 1
        else:
            print("文件未接收完成，只接收了{}%".format(recv_size / file_size))
            print("Failed to recv the file.")
            self.client_server.send(b'fail')
            return 0

    def send_server(self):
        # 输入需要发送的文件名，包括文件后缀。仅限二进制文件，包括图片、视频、压缩文件等
        file_name = input("Please enter the file path or the file name:")
        if os.path.exists(file_name) and (not os.path.isdir(file_name)):  # 判断文件是否存在，是否文件夹
            # 获取文件的大小
            file_size = os.path.getsize(file_name)
            file_message = file_name + "|" + str(file_size)
            # 与服务端建立连接后，先将文件名字与文件的大小发送给服务端
            self.client_server.send(file_message.encode())
            # 对方接收到了file_message的信息后返回一个“copy”，接收不成功会返回别的信息
            recv_data = self.client_server.recv(1024)
            # 判断对方是否接收信息成功
            if recv_data.decode() == "copy":
                print("start to send data...")
                start_time = time.time()  # 计算发送文件的开始时间
                send_flag = self.send_handle(file_name, file_size)  # 发送文件的请求处理，返回处理结果
                end_time = time.time()  # 计算发送文件的结束时间
                spend_time = end_time - start_time  # 计算发送文件的耗时
                print("sending file spend {} s".format(spend_time))  # 在控制台输出发送文件的耗时
                print(send_flag)
                if send_flag:  # 判断文件是否发送成功
                    recv_message = self.client_server.recv(1024)
                    if recv_message == "ok":
                        # 文件发送成功
                        print("send file successful, close the client server.")
                        self.client_server.close()
                        return 1
                    else:
                        # 对方文件接收不成功
                        print("server recv file failed.")
                        self.client_server.close()f
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
            self.client_server.send(b"starting send file")
            with open(file_name, "rb") as f:
                while True:
                    # 循环读取文件
                    file_content = f.read(1048576)  # 每次从文件种读取1M数据
                    al_read_size += len(file_content)  # 计算总共读取的数据的大小
                    if file_content:  # 判断文件是否读取完了
                        print("{}%".format(al_read_size / file_size))  # 输出读取文件的进度
                        self.client_server.send(file_content)  # 将读取的文件发送到服务端
                    else:
                        print("100%")  # 判断文件读取完了，输出读取的进度
                        return 1  # 文件读取发送完了，返回处理情况
        else:
            print("Can't find the file or the file is empty.")  # 打开文件失败，文件或文件名为空，则退出发送服务
            self.client_server.send(b'cancel send file.')  # 通知服务端取消文件的发送
            return 0  # 文件未发送成功，返回0

    @staticmethod
    def menu():
        print("--------- File Transmission Server version 1.1 ---------")
        print("The program is made by TCP agreement.This is the TCP client.")
        print("menu:")
        print("1.send the file to the server.")
        print("2.recv the file from the server.")
        print("3.quit the program.")

    def run_server(self):
        while True:
            self.menu()
            option = input("Please enter your choice:")
            if option == "1":
                self.send_server()
            elif option == "2":
                self.recv_server()
            elif option == "3":
                print("Quit and close the server.")
                self.client_server.close()
                return
            else:
                print("Quit and close the server.")
                self.client_server.close()
            continue_flag = input("Y or y for continue?")
            if continue_flag not in "yY":
                print("Quit and close the server.")
                self.client_server.close()
                return


# Resource 文件夹保存接收的文件
def creat_folder(path):
    if os.path.exists(path):
        return
    else:
        os.mkdir(path)


def main():
    server_address = input("Please enter the server address:")
    server_port = eval(input("Please enter the server port:"))  # 9546
    client = ClientServer(server_address, server_port)
    client.run_server()


if __name__ == "__main__":
    main()