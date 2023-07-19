# crypto/crypto_utils.py

import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def generate_random_bytes(length):
    return os.urandom(length)


# def encrypt_with_public_key(public_key, plaintext):
#     # 使用 RSA 公钥对明文消息进行加密
#     encrypted = public_key.encrypt(
#         plaintext,
#         padding.OAEP(
#             mgf=padding.MGF1(algorithm=hashes.SHA256()),
#             algorithm=hashes.SHA256(),
#             label=None
#         )
#     )
#     return encrypted

def encrypt_with_public_key(public_key_bytes, plaintext):
    # Deserialize the public key from bytes
    public_key = serialization.load_pem_public_key(
        public_key_bytes,
        backend=default_backend()
    )

    # Use RSA public key to encrypt the plaintext
    encrypted = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def decrypt_with_private_key(private_key_bytes, ciphertext):
    # 从 PEM 格式的密钥文件内容加载私钥
    private_key = serialization.load_pem_private_key(
        private_key_bytes,  # 这里是 PEM 格式的私钥文件内容（字节对象）
        password=None,  # 如果私钥文件有密码，需要提供密码，否则可以设置为 None
        backend=default_backend()
    )

    # 使用 RSA 私钥对密文消息进行解密
    decrypted = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted
