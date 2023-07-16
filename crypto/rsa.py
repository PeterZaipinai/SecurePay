from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding, utils


def rsa_encrypt(plaintext, public_key):
    # 使用 RSA 公钥对明文消息进行加密
    key = serialization.load_pem_public_key(public_key, backend=default_backend())
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
    key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
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
    key = serialization.load_pem_private_key(private_key, password=None, backend=default_backend())
    signature = key.sign(
        message_digest,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        utils.Prehashed(hashes.SHA256())
    )
    return signature


def rsa_verify(message_digest, signature, public_key):
    # 使用 RSA 公钥验证签名的正确性
    key = serialization.load_pem_public_key(public_key, backend=default_backend())
    try:
        key.verify(
            signature,
            message_digest,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception:
        return False
