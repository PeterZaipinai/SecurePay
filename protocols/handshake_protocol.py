# handshake_protocol.py

import struct
from crypto.crypto_utils import generate_random_bytes, encrypt_with_public_key, decrypt_with_private_key
from crypto.hmac import hmac_sha256
from protocols.message import MessageType, Message, ClientHello, ServerHello, ServerCertificate, \
    ClientCertificate, CertificateVerify, ClientKeyExchange, ServerFinished, ClientFinished
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


def generate_master_secret():
    return generate_random_bytes(16)


def calculate_session_key(master_secret, client_hello_random, server_hello_random):
    key_label = b"KEY"
    data = key_label + client_hello_random + server_hello_random
    session_key = hmac_sha256(master_secret, data)[:16]
    return session_key


def get_server_hello_random():
    # 获取服务器端的随机数
    server_hello_random = generate_random_bytes(32)
    return server_hello_random


def get_client_hello_random():
    # 获取客户端的随机数
    client_hello_random = generate_random_bytes(32)
    return client_hello_random


def rsa_encrypt(plaintext, public_key):
    # 使用 RSA 公钥对明文消息进行加密
    key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )
    ciphertext = key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def rsa_decrypt(ciphertext, private_key):
    # 使用 RSA 私钥对密文消息进行解密
    key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    plaintext = key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def rsa_sign(message_digest, private_key):
    # 使用 RSA 私钥对消息摘要进行签名
    key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    signature = key.sign(
        message_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def rsa_verify(message_digest, signature, public_key):
    # 使用 RSA 公钥验证签名的正确性
    key = serialization.load_pem_public_key(
        public_key,
        backend=default_backend()
    )
    try:
        key.verify(
            signature,
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


def aes_encrypt(plaintext, key, iv):
    # 使用 AES 分组算法对数据进行加密保护
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def aes_decrypt(ciphertext, key, iv):
    # 使用 AES 分组算法对数据进行解密
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def des3_encrypt(plaintext, key, iv):
    # 使用 3DES 分组算法对数据进行加密保护
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext


def des3_decrypt(ciphertext, key, iv):
    # 使用 3DES 分组算法对数据进行解密
    cipher = Cipher(algorithms.TripleDES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext


def verify_signature(private_key, public_key, data, signature):
    # 使用私钥验证签名的正确性
    private_key = serialization.load_pem_private_key(
        private_key,
        password=None,
        backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("ServerCertificate is valid.")
        return True
    except Exception:
        print("ServerCertificate is invalid. Connection may be compromised.")
        return False


class HandshakeProtocol:
    def __init__(self, client_private_key, server_public_key):
        self.client_private_key = client_private_key
        self.server_public_key = server_public_key
        self.handshake_messages = []  # 用于存储握手过程中的所有消息数据

    def process_client_hello(self, client_hello):
        # 解包ClientHello消息，获取client_hello_random和client_cipher_suite
        client_hello_random = client_hello
        client_cipher_suite = self.select_cipher_suite(1)

        server_hello_random = generate_random_bytes(32)
        server_cipher_suite = self.select_cipher_suite(client_cipher_suite)
        server_hello = ServerHello(server_hello_random, server_cipher_suite)
        server_certificate = ServerCertificate(self.server_public_key)

        return server_hello, server_certificate

    def process_client_certificate(self, client_certificate):
        if not self.validate_certificate(client_certificate):
            error_message = Message(MessageType.error_message, b"Invalid client certificate")
            return error_message, None

        master_secret = generate_master_secret()
        encrypted_shared_secret = encrypt_with_public_key(self.server_public_key, master_secret)
        client_key_exchange = ClientKeyExchange(encrypted_shared_secret)

        return client_key_exchange, master_secret

    def process_certificate_verify(self, certificate_verify, master_secret):
        # 获取握手过程中的所有消息数据
        data = self.get_handshake_messages()

        # 验证客户端证书的签名
        if not verify_signature(self.client_private_key, self.server_public_key, data, certificate_verify):
            error_message = Message(MessageType.error_message, b"Invalid certificate signature")
            return error_message, None

        # 生成 ServerFinished 消息，并返回共享密钥 master_secret
        server_finished = ServerFinished(self.calculate_message_mac(master_secret, b"SERVER", data))
        return server_finished, master_secret

    def process_server_finished(self, server_finished, master_secret):
        # 获取握手过程中的所有消息数据
        data = self.get_handshake_messages()

        # 验证 ServerFinished 消息的消息认证码
        if not self.verify_message_mac(master_secret, b"SERVER", server_finished.message_mac):
            error_message = Message(MessageType.error_message, b"Invalid server finished message")
            return error_message, None

        # 计算会话密钥 session_key
        client_hello_random = get_client_hello_random()
        server_hello_random = get_server_hello_random()
        session_key = calculate_session_key(master_secret, client_hello_random, server_hello_random)

        return session_key

    def select_cipher_suite(self, client_cipher_suite):
        # 在此处根据客户端支持的密码算法选择服务器端的密码算法
        client_cipher_suite = 'default'
        return client_cipher_suite

    def validate_certificate(self, certificate):
        # 在此处验证证书的合法性
        # 假设证书始终是合法的，直接返回True
        return True

    def calculate_message_mac(self, master_secret, label, data):
        # 在此处计算消息认证码
        # 在示例中，使用HMAC-SHA256算法计算消息认证码
        from cryptography.hazmat.primitives import hashes, hmac
        from cryptography.hazmat.backends import default_backend

        h = hmac.HMAC(master_secret, hashes.SHA256(), backend=default_backend())
        h.update(label + data)
        message_mac = h.finalize()

        return message_mac

    def verify_message_mac(self, master_secret, label, message_mac):
        # 在此处验证消息认证码的正确性
        # 在示例中，重新计算消息认证码并与接收到的消息认证码进行比较
        calculated_mac = self.calculate_message_mac(master_secret, label, self.get_handshake_messages())
        return message_mac == calculated_mac

    def get_handshake_messages(self):
        # 在此处获取握手过程中的所有消息数据
        # 在示例中，假设握手过程中所有消息都存储在self.handshake_messages中
        handshake_data = b"".join(msg.encode() for msg in self.handshake_messages)
        return handshake_data
