#!/usr/bin/python3
# -- coding: utf-8 --
from Crypto.PublicKey.RSA import importKey, construct
from Crypto.Cipher import PKCS1_v1_5
from base64 import b64encode

DEF_LEN = 117


def public_key(rsaExponent, rsaModulus = '10001'):
    e = int(rsaExponent, 16)
    n = int(rsaModulus, 16)  # snipped for brevity
    pubkey = construct((n, e)).export_key()
    return pubkey


class RSA_Encrypt:
    def __init__(self, key):
        if isinstance(key, str):
            # 若提供的rsa公钥不为pem格式 则先将hex转化为pem格式
            self.key = public_key(key) if "PUBLIC KEY" not in key else key.encode()
        else:
            print("提供的公钥格式不正确")

    def encrypt(self, data, b64 = False):
        pub_key = importKey(self.key)
        cipher = PKCS1_v1_5.new(pub_key)
        data = data.encode('utf8')
        length = len(data)
        if length < DEF_LEN:
            rsa_text = cipher.encrypt(data)
        else:
            offset = 0
            res = []
            while length - offset > 0:
                if length - offset > DEF_LEN:
                    res.append(cipher.encrypt(data[offset:offset + DEF_LEN]))
                else:
                    res.append(cipher.encrypt(data[offset:]))
                offset += DEF_LEN
            rsa_text = b''.join(res)
        return b64encode(rsa_text).decode() if b64 else rsa_text.hex()
