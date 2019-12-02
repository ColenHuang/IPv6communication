from Crypto.Cipher import Blowfish
import base64

#对需要嵌密在源地址，接口标识部分的数据进行加密与切分
class MyBlowfish():

    def __init__(self,key):
        #self.key = key.encode('utf-8')
        self.key = key
        if len(self.key)>=8:
            self.iv = self.key[0:8]
        else:
            self.iv = self.key + ('\0' * (8 - len(self.key)))
        self.mode = Blowfish.MODE_CBC

    def encrypt(self,code):  # 加密，后续进行切分
        l = len(code)
        n = 8
        if l % 8 != 0 :
            code = code + '\0' * (8 - (l %8))
        code = code.encode('utf-8')
        cryptor = Blowfish.new(self.key,self.mode,self.iv)
        encode = cryptor.encrypt(code)
        return base64.b16encode(encode)

    def decode(self,message):  #对数据切分合成后进行解密
        message = message.split(":")
        for i in range(4,len(message)):
            if len(message[i]) <4 :
                length = 4-len(message[i])
                message[i] = '0'* length + message[i]
        de_message = (message[4] + message[5] + message[6] + message[7]).encode('utf-8')
        de_message = ((de_message.decode('utf-8')).upper()).encode('utf-8')
        cryptor = Blowfish.new(self.key, self.mode, self.iv)
        code = cryptor.decrypt(base64.b16decode(de_message))
        return (code.decode('utf-8')).rstrip('\0')

    def divide(self,message):   # 切分，方便嵌入   前64位 前缀， 后位本地接口标识（这里用于嵌密）
        message = str(message,'utf-8')
        ad1 = message[0:4]
        ad2 = message[4:8]
        ad3 = message[8:12]
        ad4 = message[12:16]
        return (ad1 + ":" + ad2 + ":" + ad3 + ":" + ad4)

# while True:
#     des = "2001:250:4402:1112:"
#     func = MyBlowfish('hdhwyqwt')
#     sec = func.encrypt(input())
#     sec_send = func.divide(sec)
#     new_address = des + sec_send
#     a = func.decode('2001:250:4402:1112:1147:40F6:85C9:D24A')
#     print(a)
