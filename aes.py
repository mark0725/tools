#coding: utf8  
import sys  
from Crypto.Cipher import AES  
from binascii import b2a_hex, a2b_hex  
   
class aestool():  
    def __init__(self, key):  
        self.key = key  
        self.mode = AES.MODE_CBC  
       
    #加密函数，如果text不是16的倍数【加密文本text必须为16的倍数！】，那就补足为16的倍数  
    def encrypt(self, text):  
        cryptor = AES.new(self.key, self.mode, self.key)  
        #这里密钥key 长度必须为16（AES-128）、24（AES-192）、或32（AES-256）Bytes 长度.目前AES-128足够用  
        length = 16  
        count = len(text)  
        if(count % length != 0) :  
            add = length - (count % length)  
        else:  
            add = 0  

        text = text + ('\0' * add)  
        self.ciphertext = cryptor.encrypt(text)  
        #因为AES加密时候得到的字符串不一定是ascii字符集的，输出到终端或者保存时候可能存在问题  
        #所以这里统一把加密后的字符串转化为16进制字符串  
        return b2a_hex(self.ciphertext)  
       
    #解密后，去掉补足的空格用strip() 去掉  
    def decrypt(self, text):  
        cryptor = AES.new(self.key, self.mode, self.key)  
        plain_text = cryptor.decrypt(a2b_hex(text))  
        return plain_text.rstrip('\0')  
   
if __name__ == '__main__':  
    pc = aestool('keyskeyskeyskeys')      #初始化密钥  
    e = pc.encrypt("0123456789ABCDEF")  
    d = pc.decrypt(e)                       
    print e, d  

    e = pc.encrypt("00000000000000000000000000")  
    d = pc.decrypt(e)                    
    print e, d  
