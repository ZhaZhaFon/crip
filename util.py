from email import message
from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
import base64
from Crypto.Hash import SHA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_signature
from Crypto.Cipher import AES
from binascii import b2a_hex,a2b_hex

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
    print("the private key is:")
    print(private_key.decode('utf-8'))

    print('###########################')
    #随机值生成公钥
    public_key = rsa.publickey().exportKey()
    print("the public key is:")
    print(public_key.decode('utf-8'))
    return public_key, private_key


def encrypt_with_asymetric_key(message, key):
    cipher = PKCS1_cipher.new(key)
    rsa_text = base64.b64encode(cipher.encrypt(bytes(message.encode("utf-8)"))))
    print("the encrypt message is:")
    print(rsa_text.decode("utf-8"))
    return rsa_text
    

def decrypt_with_asymetric_key(rsa_text, key):
    cipher = PKCS1_cipher.new(key)
    message = cipher.decrypt(base64.b64decode(rsa_text),0)
    print(message.decode("utf-8"))
    return  message 


def generate_signatur(message, key):
    signer = PKCS1_signature.new(key)
    digest = SHA.new()
    digest.update(message.encode("utf-8"))
    sign = signer.sign(digest)
    signature = base64.b64encode(sign)
    print("the signature is :")
    print(signature.decode("utf-8"))
    return signature

def verify_signature(message, key, signature):
    verifier = PKCS1_signature.new(key)
    digest = SHA.new()
    digest.update(message.encode("utf-8"))
    succ = verifier.verify(digest,base64.b64decode(signature))
    return succ

def encrypt_with_AES(message, key):
    mode = AES.MODE_OFB
    cryptor = AES.new(key.encode("utf-8"), mode, b'0000000000000000')
    """
    参数解释：
    key.encode("utf-8"): 为加密和解密时使用的秘钥, 长度有限制. 一般为16,24,32
    mode=AES.MODE_OFB :  为AES的不同模式
    b'0000000000000000': 为表示16进制
    """
    length = 16
    count = len(message)
    if count % length !=0:
        add = length - (count % length)
    else:
        add = 0
    message = message + ('\0' * add)

    ciphertext = cryptor.encrypt(message.encode("utf-8"))
    result = b2a_hex(ciphertext) #对加密结果进行16进制处理
    print("the encrypt result is :")
    print(result.decode("utf-8"))
    return result

def decrypt_with_AES(AES_text, key):
    mode = AES.MODE_OFB
    cryptor = AES.new(key.encode("utf-8"),mode,b'0000000000000000')
    message = cryptor.decrypt(a2b_hex(AES_text))  #对解密结果进行16进制处理
    message = message.decode("utf-8").rstrip('\0')
    print("the decrypt result is :")
    print(message)
    return message

