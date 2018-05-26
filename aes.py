#coding: utf8  
#example: python aes.py keyskeyskeyskeys 0123456789ABCDEF
import sys  
from Crypto.Cipher import AES  
from binascii import b2a_hex, a2b_hex  
   
class aestool():  
    def __init__(self, key):  
        count = len(key) 
        if(count % 16 != 0) :  
            add = 16 - (count % 16)  
        else:  
            add = 0  

        key = key + ('\0' * add)
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
   
def main(argv):

    if len(argv) < 3 :
        print 'Useage: ', argv[0], ' key data'
        print '  key: length 16 bytes.'
        sys.exit(1)

    if len(argv[1]) > 16 :
        print '  key max length 16 bytes.'
        sys.exit(1)

    pc = aestool(argv[1])      #初始化密钥  
    e = pc.encrypt(argv[2])  
    d = pc.decrypt(e)                       
    print 'plain text:', d
    print 'encrypt text:', e

if __name__ == '__main__':
    main(sys.argv) 
