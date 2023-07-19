import struct
from enum import Enum


class MessageType(Enum):
    client_hello = 0x80
    server_hello = 0x81
    server_certificate = 0x82
    client_certificate = 0x83
    certificate_verify = 0x84
    client_key_exchange = 0x85
    server_finished = 0x86
    client_finished = 0x87
    error_message = 0x88
    application_data = 0x89


class Message:
    def __init__(self, msg_type, length, body):
        self.msg_type = msg_type
        self.length = length
        self.body = body

    def encode(self):
        encoded_message = struct.pack("!B H", self.msg_type.value, self.length) + self.body
        return encoded_message


class ClientHello:
    def __init__(self, random, cipher_suite):
        self.random = random
        self.cipher_suite = cipher_suite

    def encode(self):
        encoded_random = self.random
        encoded_cipher_suite = struct.pack("B", self.cipher_suite)

        encoded_body = encoded_random + encoded_cipher_suite
        return encoded_body


class ServerHello:
    def __init__(self, random, cipher_suite):
        self.random = random
        self.cipher_suite = cipher_suite

    def encode(self):
        encoded_random = self.random
        encoded_cipher_suite = struct.pack("B", self.cipher_suite)

        encoded_body = encoded_random + encoded_cipher_suite
        return encoded_body


class ServerCertificate:
    def __init__(self, certificate):
        self.certificate = certificate

    def encode(self):
        encoded_certificate = self.certificate.encode()

        encoded_body = encoded_certificate
        return encoded_body


class ClientCertificate:
    def __init__(self, certificate):
        self.certificate = certificate

    def encode(self):
        encoded_certificate = self.certificate.encode()

        encoded_body = encoded_certificate
        return encoded_body


class CertificateVerify:
    def __init__(self, signature):
        self.signature = signature

    def encode(self):
        encoded_body = self.signature
        return encoded_body


class ClientKeyExchange:
    def __init__(self, encrypted_shared_secret):
        self.encrypted_shared_secret = encrypted_shared_secret

    def encode(self):
        # 将 self.encrypted_shared_secret 转换为字节串
        encrypted_shared_secret_bytes = self.encrypted_shared_secret

        # 使用 struct.pack() 将消息字段打包为字节串
        client_key_exchange_message = struct.pack('!H', len(encrypted_shared_secret_bytes)) + encrypted_shared_secret_bytes

        return client_key_exchange_message

    @classmethod
    def decode(cls, data):
        # 使用 struct.unpack() 解包数据
        encrypted_shared_secret_length, = struct.unpack('!H', data[:2])
        encrypted_shared_secret = data[2:2 + encrypted_shared_secret_length]

        # 创建 ClientKeyExchange 对象并返回
        return cls(encrypted_shared_secret)



class ServerFinished:
    def __init__(self, message_mac):
        self.message_mac = message_mac

    def encode(self):
        return self.message_mac


class ClientFinished:
    def __init__(self, message_mac):
        self.message_mac = message_mac

    def encode(self):
        encoded_message_mac = self.message_mac

        encoded_body = encoded_message_mac
        return encoded_body
