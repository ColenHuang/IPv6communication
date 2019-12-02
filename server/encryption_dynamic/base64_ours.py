import base64

class Mybase64():      #把源地址加密嵌到扩展报头里面
    def source_check(self,source):    #把要嵌密的地址恢复到16位（还原的为连续的0被省略的部分）
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

    def encode(self,text):
        text = text.encode('utf-8')
        enc = base64.b64encode(text)
        return enc


    def decode(self,text):
        dec = (base64.b64decode(text)).decode('utf-8')
        ad1 = dec[0:4]
        ad2 = dec[4:8]
        ad3 = dec[8:12]
        ad4 = dec[12:16]
        return (ad1 + ":" + ad2 + ":" + ad3 + ":" + ad4)