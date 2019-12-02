from scapy.all import *
from sys import argv
import base64
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6
import threading
import time
from encryption_dynamic.Blowfish_ours import MyBlowfish
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_

############一些基本的设定#############
source_ip = "2001:250:4402:2001:dacb:8aff:fee3:8512"   #源地址（client的地址）
destination_ip = "2001:250:4402:2001:4ecc:6aff:fe23:9684"  #目的地址(server的地址)
des = "2001:250:4402:2001:"
network_card = "Realtek PCIe GBE Family Controller #2"

#############主程序######################

def identify_address(func,msg):    #返回放到src字段的地址
    sec = func.encrypt(msg)
    sec_send = func.divide(sec)
    new_address = des + sec_send
    return new_address


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
def message_send(number_send=1):
    dict_blowfish = {1: 'hdhwyqwt', 2: 'loiujhty', 3: 'ksisqhcd', 4: 'njkdnw12', 5: 'fk345kao'}   # 通过blowfish 对源地址进行加密
    switch = input()   # 选择干扰信息的加密方式
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
        func1 = MyBlowfish(dict_blowfish[number_send])  #func1 加密秘密信息放到地址里,可以放8个英文字母，64bit
        msg = func.encode(input()) # 输入干扰信息
        real_msg = input() # 输入真实想要传输的信息
        if real_msg == 'exit0':  # 退出程序使用
            break
        new_address = identify_address(func1,real_msg)      #将new_address 放到src字段；通过这个方式，可以使源地址一直在变化，这里可以做一个显示，证明我们的地址是在变化的
        print(new_address)
        print(msg)
        # #print(func1.decode(new_address))
        # if number_send%2 == 0:
        #    func = MyAES(dict_AES[number_AES])  # func2 加密地址，放到扩展报头里
        #    sec = func.source_check(source_ip)
        #    sec_source = func.encode(sec)  # 把源地址加密后,放到扩展报头进行传输
        #    print(sec_source)
        #    print(func.decode((sec_source)))
        #    number_AES += 1
        #    if number_AES > 5: number_AES = 1
        # else:
        #     func = MyDES(dict_DES[number_DES])  # func2 加密地址，放到扩展报头里
        #     sec = func.source_check(source_ip)
        #     sec_source = func.encode(sec)  # 把源地址加密后,放到扩展报头进行传输
        #     print(func.decode((sec_source)))
        #     number_DES += 1
        #     if number_DES > 5: number_DES = 1
        number_send += 1
        if number_send >5:
            number_send = 1
        DNSpacket = IPv6(dst=destination_ip, src=new_address) / UDP(sport=53) / DNS(id=6666, rd=0, z=1, tc=1,qd=DNSQR(qname=msg,qtype="A", qclass="IN"))
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