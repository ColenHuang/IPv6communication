# zhhuang 2019/11/25 验证通过

import base64

class Mybase64_():      #把源地址加密嵌到扩展报头里面

    def encode(self,text):
        text = text.encode('utf-8')
        enc = base64.b64encode(text)
        return enc


    def decode(self,text):
        dec = (base64.b64decode(text)).decode('utf-8')
        return dec
