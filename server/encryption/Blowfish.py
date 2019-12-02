from Crypto.Cipher import Blowfish
import base64
# zhhuang 2019/11/26 验证通过
#对需要嵌密在源地址，接口标识部分的数据进行加密与切分
#加密8位
#来不及自己写秘钥就把秘钥写进去
class MyBlowfish_():
    def __init__(self,key):
        #self.key = key.encode('utf-8')
        self.key = key
        if len(self.key)>=8:
            self.iv = self.key[0:8]
        else:
            self.iv = self.key + ('\0' * (8 - len(self.key)))
        self.mode = Blowfish.MODE_CBC

    def encode(self,code):  # 加密，后续进行切分
        l = len(code)
        n = 8
        if l % 8 != 0 :
            code = code + '\0' * (8 - (l %8))
        code = code.encode('utf-8')
        cryptor = Blowfish.new(self.key,self.mode,self.iv)
        encode = cryptor.encrypt(code)
        return base64.b16encode(encode)

    def decode(self,message):  #对数据切分合成后进行解密
        cryptor = Blowfish.new(self.key, self.mode, self.iv)
        code = cryptor.decrypt(base64.b16decode(message))
        return (code.decode('utf-8')).rstrip('\0')
