# -*- coding:utf-8 -*-


import base64
from Crypto.Cipher import AES


class PKCS7Encoder():
    """提供基于PKCS7算法的加解密接口"""

    block_size = 32

    def encode(self, text):
        """ 对需要加密的明文进行填充补位
        @param text: 需要进行填充补位操作的明文
        @return: 补齐明文字符串
        """
        text_length = len(text)
        # 计算需要填充的位数
        amount_to_pad = self.block_size - (text_length % self.block_size)
        if amount_to_pad == 0:
            amount_to_pad = self.block_size
        # 获得补位所用的字符
        pad = chr(amount_to_pad)
        if type(text) == bytes:
            return text + amount_to_pad * amount_to_pad.to_bytes(1, 'big')
        return text + pad * amount_to_pad

    def decode(self, decrypted):
        """删除解密后明文的补位字符
        @param decrypted: 解密后的明文
        @return: 删除补位字符后的明文
        """
        pad = decrypted[-1]
        if pad < 1 or pad > 32:
            pad = 0
        return decrypted[:-pad]


class WXBizMsgCrypt:

    def __init__(self, encoding_aes_key, token, corp_id):
        self.encoding_aes_key = encoding_aes_key
        self.token = token
        self.corp_id = corp_id

    def verification_url(self, echostr):
        print(echostr)
        aes_key = base64.b64decode(self.encoding_aes_key + "=")
        aes_mode = AES.MODE_CBC
        aes = AES.new(aes_key, aes_mode, aes_key[:16])
        aes_decode = aes.decrypt(base64.b64decode(echostr))
        pkcs = PKCS7Encoder()
        plain_text = pkcs.decode(aes_decode)
        msg_len = int.from_bytes(plain_text[16:20], byteorder='big')
        msg = plain_text[20: 20 + msg_len].decode('utf-8')
        receive_id = plain_text[20 + msg_len:].decode('utf-8')

        return msg, receive_id

#
# timestamp = '1552028048'
# nonce = '1551967245'
# echostr = 'z0bTh7cX1yd446kmfxLkEBNZu1jOpZfG5jyps7FlXCyv+tEYLX0DemxC+Yg9CZlQzw3ULlIfC+my9PhgZrz9Tw=='
#
# CorpID = "wwdbdd26e737810033"
# Secret = 'r54UcdZ5Q3pKfgIgS5wsZleI009jHf-rWM03GHh-wj0'
#
# AgentId = '1000004'
# token = 'FneVKEt7QYlC5Q'
# EncodingAESKey = 'cpgba8d4ewimqrrFQTkr6omB2o4oDmlvGDvhMrWV1Ec'
#
# # 签名
# msg_signature = '2d304d4a1cbe8af82b52b7076cc72fec3dd3f457'
# msg_encrypt = base64.b64decode(echostr)
#
# AESKey = base64.b64decode(EncodingAESKey + "=")
# aes_msg = base64.b64decode(msg_encrypt)
# mode = AES.MODE_CBC
# cryptor = AES.new(AESKey, mode, AESKey[:16])
#
# c = cryptor.decrypt(base64.b64decode(echostr))
#
# content = c[16:]  # 去掉前16随机字节
#
# pkcs7 = PKCS7Encoder()
# plain_text = pkcs7.decode(c)
#
# msg_len = int.from_bytes(plain_text[16:20], byteorder='big')
# msg = plain_text[20: 20 + msg_len].decode('utf-8')
# receive_id = plain_text[20 + msg_len:].decode('utf-8')
#
# print(msg)
# print(receive_id)
