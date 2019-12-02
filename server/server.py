import socket
from struct import *
import datetime
import pcapy
import sys
import inspect
from encryption.AES import MyAES_
from encryption.base64_ import Mybase64_
from encryption.Blowfish import MyBlowfish_
from encryption.DES import MyDES_
from encryption.DES3 import MyDES3_

# ======
# Global
listen_port = 80
iface = "foo"
rmsg = ''
# ======

multiplier = 16777216
# Clear before/after each use; otherwise the array is repeatedly appended.
msg_array = []

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


# =============
# Main function
# =============


def main(argv):
    # List all devices
    devices = pcapy.findalldevs()  #遍历网卡数目
    dev = "foo" # The device we want to listen on
    # listen_port = listen_port # Port to listen on
    if iface == "foo":
        print("Available devices are :")
        x = 0
        for d in devices:
            print(" ", x , " ", d)
            x += 1

        dev = devices[0]
    else:
        dev = iface

    # Ensure we have a proper device
    try:
        devices.index(dev)
    except ValueError:
        print("ERROR: Invalid listen interface")
        exit(0)

    if listen_port < 0 or listen_port > 65535:
        print("\nERROR: Destination port number is invalid, try a number 0 to 65,535\n")
        # parser.print_help()
        exit(0)

    print("Sniffing device " + dev + " on port " + str(listen_port))

    '''
    Open device
    Arguments here are:
    - device
    - snaplen (maximum number of bytes to capture _per_packet_)
    - promiscious mode (1 for true)
    - timeout (in milliseconds)
    '''
    filt = "tcp and port 80"
    cap = pcapy.open_live(dev, 65536, 1, 0)
    cap.setfilter(filt)
    # while 1:
    #     try:
    #         cap.loop(0, handle_packet)
    #     except:
    #         print('[-] Exception: cap.next caught, moving on..')





    # Start sniffing packets
    while (1):
        # The line below randomly generates an error. Adding try/except to fix
        try:
            (header, packet) = cap.next()
        # print ('%s: captured %d bytes, truncated to %d bytes' %(datetime.datetime.now(), header.getlen(), header.getcaplen()))
            parse_packet(packet, listen_port)
        except IOError as e:
            print("[-] I/O error({0}): {1}".format(e.errno, e.strerror))
        except:
            print('[-] Exception: cap.next caught, moving on..')


# =========
# Functions
# =========

# Convert a string of 6 characters of ethernet address into a dash separated hex string
def eth_addr(a):
    b = "%.2x:%.2x:%.2x:%.2x:%.2x:%.2x" % (a[0], a[1], a[2], a[3], a[4], a[5])
    return b


#
# Function to parse a packet
# TODO: this could be it's own Python module/class/library
def parse_packet(packet, listen_port):
    # print("\npacket:", packet)
    # print("packet[0]:%x" % packet[0])
    # print("packet[1]:%x" % packet[1])
    # Parse ethernet header
    eth_length = 14

    eth_header = packet[:eth_length]
    eth = unpack('!6s6sH', eth_header)  ## TODO: spell this out
    # print("eth:", eth)  # --------
    eth_protocol = socket.ntohs(eth[2])
    # print("eth_protocol:", eth_protocol)  # ------
    # print 'Destination MAC: ' + eth_addr(packet[0:6]) + \
    # ' Source MAC: ' + eth_addr(packet[6:12])

    # Parse IP packets, IP Protocol number = 8
    if eth_protocol == 56710:
        # print("yes")
        ip_header = packet[eth_length:40 + eth_length]
        # print("ip_header:",ip_header)
        # now unpack them :)
        iph = unpack('!BBHHBB16s16s', ip_header)
        # print("iph", iph)
        version_temp = iph[0]
        # print("version_ihl", version_temp)
        version = version_temp >> 4
        # print("version:",version) #ipv6版本号
        payload_l = iph[3] #有效负荷长度
        next_protocol =  iph[4] #上层协议
        hop_limit = iph[5] #跳限制
        src_ip = iph[6] #源IP
        dst_ip = iph[6] #目的IP
        # TCP协议
        if next_protocol == 6:
            t = eth_length + 40 #eth头部长度+IP头部
            tcp_h = packet[t:t+20]
            tcph = unpack('!HHLLBBHHH', tcp_h)
            # print("tcph", tcph)
            # TCP报文首部 20字节
            source_port = tcph[0]
            dest_port = tcph[1]
            sequence = tcph[2]
            acknowledgement = tcph[3]
            doff_reserved = tcph[4]
            window = tcph[6]
            tcph_length = doff_reserved >> 4

            h_size = eth_length + 40+ tcph_length * 4
            data_size = len(packet) - h_size

            # get data from the packet
            data = packet[h_size:]

            if str(dest_port) == str(listen_port):
                rmsg = ''.join(msg_array)
                print('Smuggled: ' + ''.join(msg_array))
                if str(window) == '1337':
                    decipher_iseq(sequence)
                elif str(window) == '7331':
                    print('[*] End Of Message')
                    # print(rmsg)
                    # data = rmsg.decode('utf-8')
                    real_data = rmsg[3:-3]
                    real_data = real_data.encode('utf-8')
                    print(func.decode(real_data))  # 这里是得到的真实信息 ！！！！！！！！！！！
                    # Reset the data array
                    data = []
                else:
                    print('n0ise packet')



# =========================================
# Functions for deciphering covert channels
# =========================================

# Decipher the initial sequence numbers
def decipher_iseq(seq):
    char = 0
    char = int(int(seq) / multiplier)
    # Add seq to the global seq_array.
    msg_array.append(chr(char))
    print('Received: %s' % chr(char))



# =========
# Call main
# =========

if __name__ == "__main__":
    main(sys.argv)
