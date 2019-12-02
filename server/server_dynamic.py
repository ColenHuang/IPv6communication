#!/usr/bin/env python

from scapy.all import *
from sys import argv
import threading
import time
import base64
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import UDP,TCP
from scapy.layers.inet6 import IPv6
from IPy import IP
from scapy.layers.inet6 import IPv6ExtHdrRouting,IPv6ExtHdrDestOpt,ICMPv6EchoRequest
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_
from encryption_dynamic.Blowfish_ours import MyBlowfish
#########一些预先定义的参数##########
opendns = "2001:da8:270:2021::88"
encoded_message = ""
ip = ""
message_r = ""
packets = 0
recived_p = 0
first = True
lock = threading.Lock()
network_card = "Red Hat VirtIO Ethernet Adapter"


####################################
#############定义主函数#########################################
def main():
    while True:
        DNSPacket = sniff(iface=network_card, filter="src port 53", count=1)  # 从目标网卡监听消息，嗅探一个包
        # print DNSPacket[0].getlayer(DNS).command()
        if (DNSPacket[0].haslayer(DNS)) and (DNSPacket[0].getlayer(DNS).id == 6666):
            command = DNSPacket[0].getlayer(DNS).qd.qname  # 传递过来的是字符串
            command = check_first_packet(command)
            print(command)
            if command:
                global source_ip
                source_ip = command
                DNSpacket = IPv6(dst=source_ip, src=opendns) / UDP(sport=53) / DNS(id=5555, rd=0, z=1, tc=1,
                                                                                   qd=DNSQR(qname=command, qtype="A",
                                                                                            qclass="IN"))
                send(DNSpacket, verbose=0)
                print("已发送连接成功信息，可以收发消息")
                # 建两个线程，一个用来监听包，一个用来发送包
                process_sniff = threading.Thread(target=message_receive)
                process_sniff.start()
                process_sniff.join()


##############################################################
def check_first_packet(message):  # 第一步用于建立连接使用，其他地方暂时没用到(message is str)
    prolog = message[0:3]
    print(message)
    message = message[3:]
    print(message)
    if prolog:
        decoded_message = str(base64.b64decode(message), 'utf-8')
        print(decoded_message)
        return decoded_message
    else:
        return False


def check_response(message, id):  # 后续用于解析数据包使用
    global first, recived_p, message_r, packets
    if message == "":  # 搭配recall
        pass
    else:
        # decoded_r = str(base64.b64decode(message),'utf-8')
        # print("message from client" + ":" + decoded_r)
        pass


############消息接收模块#############
def message_receive():
    dict_blowfish = {1: 'hdhwyqwt', 2: 'loiujhty', 3: 'ksisqhcd', 4: 'njkdnw12', 5: 'fk345kao'}
    num_key = 1
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
        Packet = sniff(iface=network_card, filter=str("src" +"\n" +source_ip),count=1)
        if (Packet[0].haslayer(ICMPv6EchoRequest)):  # 这个与Server端要结合起来看
            response_message = Packet[0].getlayer(ICMPv6EchoRequest).data
            print(response_message.decode('utf-8'))  # 表面上获得的信息！！！！！！！！！！！
            #sec_message = (response_message.decode('utf-8')[:-1]).encode('utf-8')
            if response_message != "":
                # check_response(response_message,DNSPacket[0].getlayer(DNS).id)
                IP_address = Packet[0].getlayer(IPv6ExtHdrRouting).addresses[0]
                print(IP_address)  # 输出一下捕获到的IP！！！！！！！！！！！
                func1 = MyBlowfish(dict_blowfish[num_key])
                real_msg = func1.decode(IP_address)
                print(real_msg)     # 实际的真实信息 ！！！！！！！！！！
                num_key += 1
                if num_key >5 :
                    num_key = 1
                continue

if __name__ == "__main__":
    main()
