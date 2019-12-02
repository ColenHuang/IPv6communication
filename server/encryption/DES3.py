from Crypto.Cipher import DES3
import base64
# zhhuang 2019/11/26 验证通过
# 秘钥可定，或自己输入

BS = DES3.block_size
def pad(s):
    return s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

def unpad(s):
    return s[0:-ord(s[-1])]


class MyDES3_():
    def __init__(self, key):
        self.key = key
        if len(self.key) >= 16:
            tmp = key[0:15]
            self.key = tmp + ' '
        else:
            while len(self.key) < 16:
                self.key += " "
        self.mode = DES3.MODE_ECB


    def encode(self, text):
        text = pad(text)
        cryptor = DES3.new(self.key, self.mode)
        x = len(text) % 8
        if x != 0:
            text = text + '\0' * (8 - x)
        # print(text)
        self.ciphertext = cryptor.encrypt(text)
        return base64.standard_b64encode(self.ciphertext).decode("utf-8")

    def decode(self, text):
        cryptor = DES3.new(self.key, self.mode)
        de_text = base64.standard_b64decode(text)
        plain_text = cryptor.decrypt(de_text)
        st = str(plain_text.decode("utf-8")).rstrip('\0')
        out = unpad(st)
        return out
