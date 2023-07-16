# crypto/hmac.py

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()
