# zhhuang 2019/11/25 验证通过
# DES算法把64位的明文输入块变为64位的密文输出块,它所使用的密钥也是64位
from Crypto.Cipher import DES
from binascii import b2a_hex, a2b_hex


class MyDES_():
    def __init__(self, key):   # 初始化密钥和向量，秘钥是64位
            if len(key)>8:
                key = key[0:8]
            elif len(key) < 8:
                key = key + '0'*(8-len(key))
            self.key = key
            self.iv = self.key

    def encode(self, ecryptText):
        if len(ecryptText.encode('utf-8')) % 8:
            add = 8 - (len(ecryptText.encode('utf-8')) % 8)
        else:
            add = 0
        text = ecryptText + ('\0' * add)
        text = text.encode('utf-8')
        #de_message = ecryptText.encode('utf-8')
        cryptor = DES.new(self.key,DES.MODE_CBC, self.iv)
        code = cryptor.encrypt(text)
        return b2a_hex(code)

    def decode(self, decryptText):
        cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
        decryptText = a2b_hex(decryptText)
        nor_msg = cipher.decrypt(decryptText)
        ad = bytes.decode(nor_msg).rstrip('\0')
        return (ad)



