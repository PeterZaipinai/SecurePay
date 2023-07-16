import hashlib

from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.backends import default_backend


def hmac_sha256(key, data):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def calculate_master_secret(pre_master_secret, client_hello_random, server_hello_random):
    # Concatenate client_hello_random and server_hello_random
    randoms = client_hello_random + server_hello_random

    # Calculate master_secret using PRF (Pseudorandom function)
    master_secret = hmac_sha256(pre_master_secret, randoms)

    return master_secret
