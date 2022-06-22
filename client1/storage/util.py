from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import AES
from binascii import b2a_hex,a2b_hex
from Crypto.Random import get_random_bytes
from base64 import b64decode, b64encode
import json
import os
import hashlib
import random
import string

def generate_asymetric_key():
    random_generator = Random.new().read
    rsa = RSA.generate(2048,random_generator)
    '''
    generate(bits, randfunc=None, e=65537) 
    参数解释：
    bits：    字节大小，一般为1024的整数倍
    randfunc: 随机函数，默认为Crypto.Random.get_random_bytes
    e=65537： 是公共RSA指数，必须为整数，一般保持默认
    '''

    #随机值生成私钥
    private_key = rsa.exportKey()
    # print("the private key is:")
    # print(private_key.decode('utf-8'))

    # print('###########################')
    #随机值生成公钥
    public_key = rsa.publickey().exportKey()
    # print("the public key is:")
    # print(public_key.decode('utf-8'))
    return public_key, private_key


def encrypt_with_asymetric_key(message, pub_key):
    assert isinstance(message, bytes)
    assert isinstance(pub_key, bytes)
    
    pub_key = RSA.importKey(pub_key)
    cipher = PKCS1_cipher.new(pub_key)
    rsa_text = base64.b64encode(cipher.encrypt(message))
    # print("the encrypt message is:")
    # print(rsa_text.decode("utf-8"))
    return rsa_text
    

def decrypt_with_asymetric_key(rsa_text, pri_key):
    assert isinstance(rsa_text, bytes)
    assert isinstance(pri_key, bytes)
    pri_key = RSA.import_key(pri_key)
    cipher = PKCS1_cipher.new(pri_key)
    message = cipher.decrypt(base64.b64decode(rsa_text),0)
    return  message 


def sign(message, pri_key):
    assert isinstance(message, bytes)
    assert isinstance(pri_key, bytes)
    pri_key = RSA.import_key(pri_key)
    signer = PKCS1_signature.new(pri_key)
    digest = SHA.new()
    digest.update(message)
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    # print("the signature is :")
    # print(signature.decode("utf-8"))
    return signature

def verify_signature(message, pub_key, signature):
    assert isinstance(message, bytes)
    assert isinstance(pub_key, bytes)
    assert isinstance(signature, bytes)
    pub_key = RSA.import_key(pub_key)
    verifier = PKCS1_signature.new(pub_key)
    digest = SHA.new()
    digest.update(message)
    succ = verifier.verify(digest, base64.b64decode(signature))
    return succ

# def encrypt_with_AES(message, key):
#     mode = AES.MODE_OFB
#     cryptor = AES.new(key.encode("utf-8"), mode, b'0000000000000000')
#     """
#     参数解释：
#     key.encode("utf-8"): 为加密和解密时使用的秘钥, 长度有限制. 一般为16,24,32
#     mode=AES.MODE_OFB :  为AES的不同模式
#     b'0000000000000000': 为表示16进制
#     """
#     length = 16
#     count = len(message)
#     if count % length !=0:
#         add = length - (count % length)
#     else:
#         add = 0
#     message = message + ('\0' * add)

#     ciphertext = cryptor.encrypt(message.encode("utf-8"))
#     result = b2a_hex(ciphertext) #对加密结果进行16进制处理
#     print("the encrypt result is :")
#     print(result.decode("utf-8"))
#     return result

# def decrypt_with_AES(AES_text, key):
#     mode = AES.MODE_OFB
#     cryptor = AES.new(key.encode("utf-8"),mode,b'0000000000000000')
#     message = cryptor.decrypt(a2b_hex(AES_text))  #对解密结果进行16进制处理
#     message = message.decode("utf-8").rstrip('\0')
#     print("the decrypt result is :")
#     print(message)
#     return message

class AESCipher(object):

    def __init__(self, key): 
        assert isinstance(key, bytes)
        self.key = key

    def encrypt(self, data):
        assert isinstance(data, bytes)
        cipher = AES.new(self.key, AES.MODE_CFB)
        ct_bytes = cipher.encrypt(data)
        iv = b64encode(cipher.iv).decode('utf-8')
        ct = b64encode(ct_bytes).decode('utf-8')
        result = json.dumps({'iv': iv, 'ciphertext': ct})
        return result.encode('utf-8')

    def decrypt(self, input):
        assert isinstance(input, bytes)
        b64 = json.loads(input.decode('utf-8'))
        iv = b64decode(b64['iv'])
        ct = b64decode(b64['ciphertext'])
        cipher = AES.new(self.key, AES.MODE_CFB, iv=iv)
        dt = cipher.decrypt(ct)
        return dt

def encrypt_file(message, receiver_pub_key, sender_pri_key):
    # random_key = ''.join(random.choices(string.ascii_uppercase + string.digits, k=32)) # type: string
    assert isinstance(message, bytes)
    assert isinstance(receiver_pub_key, bytes)
    assert isinstance(sender_pri_key, bytes)
    random_key = get_random_bytes(16) 
    cipher = AESCipher(random_key)
    ciphertext = cipher.encrypt(message)
    cipherkey = encrypt_with_asymetric_key(random_key, receiver_pub_key)
    message_signature = sign(message, sender_pri_key)
    return ciphertext, cipherkey, message_signature 

def decrypte_file(ct, ck, ms, receiver_pri_key, sender_pub_key):
    assert isinstance(ct, bytes) 
    assert isinstance(ck, bytes) 
    assert isinstance(ms, bytes) 
    assert isinstance(receiver_pri_key, bytes) 
    assert isinstance(sender_pub_key, bytes) 
    symetric_key = decrypt_with_asymetric_key(ck, receiver_pri_key)
    aescipher = AESCipher(symetric_key)
    message = aescipher.decrypt(ct) 
    succ =  verify_signature(message, sender_pub_key, ms)
    if succ == False:
        return False, message
    return True, message

def verify_digital_signature(crt_name):
    rc =  os.system('openssl verify -CAfile ca.crt %s > /dev/null'%crt_name) 
    if rc != 0:
        return False, None

    #证书提取公钥 
    os.system('openssl x509 -in %s -pubkey -out opposit_pub.key > /dev/null'%crt_name) 
    with open('opposit_pub.key','rb') as f:
        pub_key = f.read(450)
    return True, pub_key


    

