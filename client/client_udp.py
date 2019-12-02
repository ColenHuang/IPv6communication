# zhhuang 2019/11/26 验证完成

from scapy.all import *
from sys import argv
import base64
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
import threading
import time
import socket
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_

############一些基本的设定#############

lock = threading.Lock()
first = True
message_r = ""
recived_p = 0
encoded_message = ''
packets = 0
###########一些函数模块##################
####主程序####

def main():
    global destination_ip, source_ip
    #source_ip = "2001:250:4402:1112:ce2f:71ff:fe68:fa2e"   #源地址（client的地址)
    source_ip = "2001:250:4402:2001:dacb:8aff:fee3:8512"
    #destination_ip = "2001:250:4402:2001:dacb:8aff:fee3:8512"  #目的地址（server的ip地址)
    destination_ip = "2001:250:4402:2001:4ecc:6aff:fe23:9684"
    #destination_ip="10.69.91.138"
    success = estabilish_conn(source_ip,destination_ip)    #第一步，这个地方要通
    if success:
        print("连接成功，可以收发数据")
        # 建两个线程，一个用来监听包，一个用来发送包
        process_send =  threading.Thread(target= message_send)
        process_send.start()
        process_send.join()
    exit(0)  #无错误退出

#str(base64.b64encode(source_ip.encode('utf-8')),'utf-8'
def estabilish_conn(source_ip,destination_ip):
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.sendto(source_ip.encode(), (destination_ip ,8081))
    return recall(destination_ip)  #这里应该要接收一个返回值

def recall(destination_ip):  #成功建立端口与否
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind((source_ip, 8081))  # 绑定服务器的ip和端口
    data = s.recv(1024)  # 一次接收1024字节
    print(data.decode())  # decode()解码收到的字节
    if data:
        return True
    else:
        return False

#建立连接，返回值为1;接收消息直接打印消息
def check_response(message,id):
    global first, recived_p, message_r, packets
    print(message)
    if message == "":   #搭配recall
        pass
    else:
        decoded_r = (base64.b64decode(message)).decode('utf-8')
        print("message from", id,":",decoded_r)


###############消息发送模块#############################
def message_send():
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
        sent_message = input()
        if sent_message == "exit":
                break
        else:
            sent_message = func.encode(sent_message)
            random_message_be = 'goz'
            random_message_af = 'pjc'
            s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            mes = random_message_be+sent_message.decode('utf-8')+random_message_af
            s.sendto(mes.encode('utf-8'), (destination_ip, 8081))
            time.sleep(0.08)
if __name__ == "__main__":
    main()