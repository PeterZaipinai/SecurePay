import os
import pickle
import socket
import struct

import base64
import time

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from crypto.crypto_utils import encrypt_with_public_key, decrypt_with_private_key
from crypto.symmetric_encryption import aes_encrypt, aes_decrypt
from protocols.handshake_protocol import HandshakeProtocol, get_client_hello_random, calculate_session_key, \
    generate_master_secret, rsa_sign
from protocols.message import Message, MessageType, ClientFinished, ServerFinished, ClientCertificate, \
    CertificateVerify, ClientKeyExchange
from protocols.record_protocol import RecordProtocol


def run_client():
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 23333))

    # Load client private key and server public key
    with open('client_private_key.pem', 'rb') as f:
        client_private_key = f.read()
    with open('server_public_key.pem', 'rb') as f:
        server_public_key = f.read()

    # Start handshake protocol
    handshake_protocol = HandshakeProtocol(client_private_key, server_public_key)

    # Step 1: Generate ClientHello.random and select cipherSuite
    client_hello_random = get_client_hello_random()
    cipher_suite = 1  # Replace 1 with the appropriate value for the selected cipher suite
    client_hello = client_hello_random + struct.pack('!B', cipher_suite)
    client_socket.sendall(struct.pack('!H', len(client_hello)) + client_hello)
    print('client_hello_random is ', client_hello_random)

    # Step 2: Receive ServerHello
    server_hello_data = client_socket.recv(1024)
    server_hello_length, = struct.unpack('!H', server_hello_data[:2])
    server_hello = server_hello_data[2:2 + server_hello_length]
    server_hello_random, server_cipher_suite = struct.unpack('!32sB', server_hello)
    print('server_hello_random is ', server_hello_random)

    # Generate and send the IV along with ServerHello
    iv = os.urandom(16)  # Generate a random 16-byte IV
    server_hello_iv_message = iv
    iv_length = len(server_hello_iv_message)
    client_socket.sendall(struct.pack('!H', iv_length) + server_hello_iv_message)

    # Step 3: Receive ServerCertificate
    server_certificate_data = client_socket.recv(1024)
    server_certificate_length, = struct.unpack('!H', server_certificate_data[:2])
    server_certificate = server_certificate_data[2:2 + server_certificate_length]
    # Parse ServerCertificate
    # server_cert = x509.load_pem_x509_certificate(server_certificate, default_backend())
    print('server_certificate is ', server_certificate)

    # Step 4: Send ClientCertificate
    with open('client_certificate.pem', 'rb') as f:
        client_certificate = f.read()

    client_certificate_message = client_certificate
    certificate_length = len(client_certificate_message)
    client_socket.sendall(struct.pack('!H', certificate_length) + client_certificate_message)
    print('client_certificate is ', client_certificate)

    # # Step 5: Send CertificateVerify
    # data = handshake_protocol.get_handshake_messages()
    # signature = rsa_sign(data, client_private_key)
    # signature_length = len(signature)
    # client_socket.sendall(struct.pack('!H', signature_length) + signature)
    # print('certificate_verify is ', signature)

    client_socket.close()
    time.sleep(1)
    # Connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 23333))

    # Step 6: Send ClientKeyExchange
    master_secret = generate_master_secret()
    print('master_secret is ', master_secret)

    cipher = PKCS1_cipher.new(RSA.importKey(server_public_key))
    encrypt_text = cipher.encrypt(master_secret)
    print('encrypt_text is ', encrypt_text)
    share_encrypt_text = pickle.dumps(encrypt_text)
    secret_length = len(share_encrypt_text)
    client_socket.sendall(struct.pack('!H', secret_length) + share_encrypt_text)

    # Step 7: Receive ServerFinished
    server_finished_data = client_socket.recv(1024)
    server_finished_length, = struct.unpack('!H', server_finished_data[:2])
    server_finished = server_finished_data[2:2 + server_finished_length]

    # Verify the MAC of the received ServerFinished message
    received_server_finished = ServerFinished(server_finished)
    received_mac = received_server_finished.message_mac
    print('received_mac is ', received_mac)
    expected_mac = calculate_session_key(master_secret, b"Data for MAC calculation", client_hello_random)
    print('expected_mac is ', expected_mac)

    # Step 8: Send ClientFinished
    client_finished_data = b"Data for ClientFinished"
    message_mac = calculate_session_key(master_secret, client_finished_data, server_hello_random)
    mac_length = len(message_mac)
    client_socket.sendall(struct.pack('!H', mac_length) + message_mac)
    print('client_finished_message is ', message_mac)

    # Step 8: Complete handshake protocol and get session key
    # session_key = handshake_protocol.process_client_certificate(server_certificate)

    # Start record protocol
    record_protocol = RecordProtocol(master_secret)

    # Send encrypted data using RecordProtocol
    plaintext = b"Hello, this is a test message from the client!"
    record_message = aes_encrypt(plaintext, master_secret, iv)
    record_message_length = len(record_message)
    client_socket.sendall(struct.pack('!H', record_message_length) + record_message)

    # Receive encrypted data from server and decrypt using RecordProtocol
    encrypted_data = client_socket.recv(1024)
    record_message_type, record_message_length = struct.unpack('!BB', encrypted_data[:2])
    encrypted_data = encrypted_data[2:2 + record_message_length]
    decrypted_data = aes_decrypt(encrypted_data, master_secret, iv)
    print("Received from server:", decrypted_data.decode())

    client_socket.close()


if __name__ == "__main__":
    run_client()
