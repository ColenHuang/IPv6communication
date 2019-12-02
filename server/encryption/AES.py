import time
import sys
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex

# AES的区块长度固定为128位，密钥长度则可以是128，192或256位；而Rijndael使用的密钥和区块长度可以是32位的整数倍，以128位为下限，256位为上限
# zhhuang 2019/11/25 验证通过
# 若时间充足，考虑做一个自己写秘钥的

class MyAES_():      #把源地址加密嵌到扩展报头里面
    def __init__(self, key):   #这里是把key传进来
        # self.key = key.encode('utf-8')
        self.key = key
        if len(self.key) >= 16:  # 秘钥长度为16
             self.iv = self.key[0:16]
        else:
             self.iv = self.key + ('\0' * (16 - len(self.key)))

    def encode(self,text):
        if len(text.encode('utf-8')) % 16:
            add = 16 - (len(text.encode('utf-8')) % 16)
        else:
            add = 0
        text = text + ('\0' * add)
        text = text.encode('utf-8')
        cryptor = AES.new(self.key, AES.MODE_CBC, self.iv)
        ciphertext = cryptor.encrypt(text)
        return b2a_hex(ciphertext)

    def decode(self,text):
        mode = AES.MODE_CBC
        cryptos = AES.new(self.key, mode, self.iv)
        plain_text = cryptos.decrypt(a2b_hex(text))
        ad = bytes.decode(plain_text).rstrip('\0')
        return ad
