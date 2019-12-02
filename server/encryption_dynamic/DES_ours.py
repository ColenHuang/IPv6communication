from Crypto.Cipher import DES
from binascii import b2a_hex, a2b_hex


class MyDES():
    def __init__(self, key):   # 初始化密钥和向量
            if len(key)>8:
                key = key[0:8]
            elif len(key) < 8:
                key = key + '0'*(8-len(key))
            self.key = key
            self.iv = self.key

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

    def encode(self, ecryptText):
        de_message = ecryptText.encode('utf-8')
        cryptor = DES.new(self.key,DES.MODE_CBC, self.iv)
        code = cryptor.encrypt(de_message)
        return b2a_hex(code)

    def decode(self, decryptText):
        cipher = DES.new(self.key, DES.MODE_CBC, self.iv)
        decryptText = a2b_hex(decryptText)
        nor_msg = cipher.decrypt(decryptText)
        ad = bytes.decode(nor_msg).rstrip('\0')
        ad1 = ad[0:4]
        ad2 = ad[4:8]
        ad3 = ad[8:12]
        ad4 = ad[12:16]
        return (ad1 + ":" + ad2 + ":" + ad3 + ":" + ad4)

#add = "2001:250:4402:1112:ce2f:71ff:fe68:fa2e"

# func = MyDES('opaihdcg')
# step1 = func.source_check(add)
# step2 = func.encode(step1)
# print(step2)
# step3 = func.decode(step2)
# print(step3)

