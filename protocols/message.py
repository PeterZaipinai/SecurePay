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
        encoded_signature = self.signature.encode()

        encoded_body = encoded_signature
        return encoded_body


class ClientKeyExchange:
    def __init__(self, encrypted_shared_secret):
        self.encrypted_shared_secret = encrypted_shared_secret

    def encode(self):
        encoded_encrypted_shared_secret = self.encrypted_shared_secret.encode()

        encoded_body = encoded_encrypted_shared_secret
        return encoded_body


class ServerFinished:
    def __init__(self, message_mac):
        self.message_mac = message_mac

    def encode(self):
        encoded_message_mac = self.message_mac.encode()

        encoded_body = encoded_message_mac
        return encoded_body


class ClientFinished:
    def __init__(self, message_mac):
        self.message_mac = message_mac

    def encode(self):
        encoded_message_mac = self.message_mac.encode()

        encoded_body = encoded_message_mac
        return encoded_body
