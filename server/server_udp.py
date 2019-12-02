# !/usr/bin/env python
# zhhuang 2019/11/26 验证完成

from scapy.all import *
from sys import argv
import threading
import time
import base64
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
from IPy import IP
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_


#########一些预先定义的参数##########
encoded_message = ""
ip = ""
message_r = ""
packets = 0
recived_p = 0
first = True
lock = threading.Lock()

####################################
#############定义主函数#########################################
def main():
    global destination_ip, source_ip
    source_ip = "2001:da8:270:2021::88"  # 源地址（client的地址)
    destination_ip = "2001:da8:270:2021::9c"  # 目的地址（server的ip地址)
    while True:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind((source_ip, 8087))  # 绑定服务器的ip和端口
        data = s.recv(1024)  # 一次接收1024字节
        print(data.decode())  # decode()解码收到的字节
        if data:
            print("已发送连接成功信息，可以收发消息")
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            s.sendto("Established".encode(), (destination_ip, 8087))
            # 建两个线程，一个用来监听包，一个用来发送包
            process_sniff = threading.Thread(target=message_receive)
            process_sniff.start()
            process_sniff.join()

##############################################################
# def message_send():
#     while True:
#         sent_message = input()
#         if sent_message == "exit":
#             break
#         else:
#             s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
#             s.sendto(sent_message.encode(), (destination_ip, 8081))
#             time.sleep(0.08)


############消息接收模块#############

def message_receive():
    switch = input()
    if switch == 'a':
        func = MyAES_('loihydquweiuytgn')
    elif switch == 'b':
        func = Mybase64_()
    elif switch == 'c':
        func = MyBlowfish_('axzccsd')
    elif switch == 'd':
        func = MyDES_('dsaxzsd')
    elif switch == 'e':
        func = MyDES3_('azxcwasd')
    while True:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind((source_ip, 8087))  # 绑定服务器的ip和端口
        data = (s.recv(1024)).decode('utf-8')  # 一次接收1024字节
        print(data)  # 这里是显示得到的加密的信息！！！！！！！！！！
        real_data = data[3:-3]
        real_data = real_data.encode('utf-8')
        print(func.decode(real_data))  # 这里是得到的真实信息 ！！！！！！！！！！！
        time.sleep(0.1)

if __name__ == "__main__":
    main()


