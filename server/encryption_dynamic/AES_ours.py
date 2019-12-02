import time
import sys
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

class MyAES():      #把源地址加密嵌到扩展报头里面
    def __init__(self, key):   #这里是把key传进来
        # self.key = key.encode('utf-8')
        self.key = key
        if len(self.key) >= 16:
             self.iv = self.key[0:16]
        else:
             self.iv = self.key + ('\0' * (16 - len(self.key)))

    def source_check(self,source):    #把要嵌密的地址恢复到16位（还原为连续的0被省略的部分）
        des = source
        part = des.split(':')[4:8]
        des_join = ''.join(part)  # 把一个字符串的拼接成一串
        length = len(des_join)
        if length < 16:
            add = '0' * (16 - length)
            mid = part.index('')
            part[mid] = add
            new_source= ''.join(part)
        else:
            new_source = des_join
        return new_source

    def add_to_16(slef,text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        return text.encode('utf-8')

    def encode(self,text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('*' * add)
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cryptor.encrypt(text)
        return b2a_hex(ciphertext)

    def decode(self,text):
        mode = AES.MODE_CBC
        cryptos = AES.new(self.key, mode, self.iv)
        plain_text = cryptos.decrypt(a2b_hex(text))
        ad = bytes.decode(plain_text).rstrip('\0')
        ad1 = ad[0:4]
        ad2 = ad[4:8]
        ad3 = ad[8:12]
        ad4 = ad[12:16]
        return (ad1 + ":" + ad2 + ":" + ad3 + ":" + ad4)