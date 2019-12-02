from scapy.all import *
from sys import argv
import base64
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
import threading
import time
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
opendns = "2001:250:4402:2001:dacb:8aff:fee3:8512" #默认网关
network_card = "Realtek PCIe GBE Family Controller #2"
###########一些函数模块##################
####主程序####

def main():
    global destination_ip, source_ip
    source_ip = "2001:250:4402:2001:dacb:8aff:fee3:8512"   #源地址（client的地址)
    #destination_ip = "2001:250:4402:1112:ce2f:71ff:fe68:fa2e"  #目的地址（server的ip地址)
    destination_ip = "2001:250:4402:2001:4ecc:6aff:fe23:9684"
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
    # 通过DNS传输，由dst向src发包，UDP端口号是53，
    DNSpacket = IPv6(dst = destination_ip, src = source_ip) / UDP(sport=53) / DNS(id=6666
                                                                                  , rd=0, z=1, tc=1,qd=DNSQR(qname="A00" + str(base64.b64encode(source_ip.encode('utf-8')),'utf-8'),qtype="A", qclass="IN"))
    # 建立连接是发送一个包，包里包含源地址
    #DNSpacket = IPv6(dst=destination_ip, src=opendns) / UDP(sport=53) / DNS(id=1222, rd=0, z=1, tc=1, qd=DNSQR(qname="123", qtype="A",qclass="IN"))
    send(DNSpacket,count=1,verbose=0)  #发送到服务端，稍后看服务端是否收到
    return recall(network_card)  #这里应该要接收一个返回值

def recall(network_card):  #成功建立端口与否
    while True:
       DNSPacket = sniff(iface=network_card, filter="dst port 53", count=1) #接收从端口53传来的信息，接一个包,iface留空则对所有网卡进行嗅探，否则是嗅探指定的网卡
       if (DNSPacket[0].haslayer(DNS)) and (DNSPacket[0].getlayer(DNS).id == 5555):  #这个与Server端要结合起来看
           response = DNSPacket[0].getlayer(DNS).qd.qname  #消息的传递是放在查询名中
           if response:
                   return True
                   break
       return False

#建立连接，返回值为1;接收消息直接打印消息
def check_response(message,id):
    global first, recived_p, message_r, packets
    if message == "":   #搭配recall
        pass
    else:
        decoded_r = (base64.b64decode(message)).decode('utf-8')
        print("message from server",":",decoded_r)


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
               ##########################
            if sent_message == "exit":
                break

            encoded_message = str(base64.b64encode(sent_message.encode('utf-8')),'utf-8')  #python3里面需要进行转码，python2不需要
            size = 60
            x = 0
            prolog = ""
            encoded_message_size = len(encoded_message)   #编码后的信息长度
            if encoded_message_size > 60:
                prolog = str((encoded_message_size - 60) / 63 + 1) #原则上不要超过60
            else:
                prolog = "1"
            if len(prolog) == 1: prolog = "00" + prolog
            elif len(prolog) == 2: prolog = "0" + prolog
    # print prolog
            if prolog != "":
                #send_message = prolog + e
                # ncoded_message[x:x + size]   #加3位标识符。
                encoded_message = func.encode(sent_message)
                print(encoded_message)
                print(func.decode(encoded_message))
                DNSpacket = IPv6(dst=destination_ip, src = opendns) / UDP(sport=53) / DNS(id=6666, rd=0, z=1, tc=1, qd=DNSQR(qname=encoded_message, qtype="A", qclass="IN"))
                send(DNSpacket, verbose=0)
                time.sleep(0.08)
############消息接收模块#############

# def message_receive():
#     while True:
#        DNSPacket = sniff(iface=network_card, filter="dst port 53", count=1) #接收从端口53传来的信息 ,iface留空则对所有网卡进行嗅探, count留空默认嗅探无限个包
#        if (DNSPacket[0].haslayer(DNS)) and (DNSPacket[0].getlayer(DNS).id == 5555):  #这个与Server端要结合起来看
#            response_message = DNSPacket[0].getlayer(DNS).qd.qname
#            if response_message != "":
#                check_response(response_message[0:-1],DNSPacket[0].getlayer(DNS).id)
#                continue

if __name__ == "__main__":
    main()