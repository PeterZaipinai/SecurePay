import pickle
import socket
import struct
import time

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.PublicKey import RSA
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from crypto.crypto_utils import decrypt_with_private_key
from crypto.hmac import calculate_master_secret
from crypto.symmetric_encryption import aes_encrypt, aes_decrypt
from protocols.handshake_protocol import HandshakeProtocol, get_server_hello_random, \
    rsa_encrypt, rsa_sign, generate_master_secret, calculate_session_key
from protocols.message import Message, MessageType, CertificateVerify, ClientKeyExchange, ServerFinished, ClientFinished
from protocols.record_protocol import RecordProtocol


def run_server():
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 23333))
    server_socket.listen(1)

    print("Waiting for client connection...")
    client_socket, client_address = server_socket.accept()
    print("Client connected:", client_address)

    # Load server private key and client public key
    with open('server_private_key.pem', 'rb') as f:
        server_private_key = f.read()
    with open('client_public_key.pem', 'rb') as f:
        client_public_key = f.read()

    # Start handshake protocol
    handshake_protocol = HandshakeProtocol(server_private_key, client_public_key)

    # Step 1: Receive ClientHello
    client_hello_data = client_socket.recv(1024)
    client_hello_length, = struct.unpack('!H', client_hello_data[:2])
    client_hello = client_hello_data[2:2 + client_hello_length]
    client_hello_random, client_cipher_suite = struct.unpack('!32sB', client_hello)
    print('client_hello_random is ', client_hello_random)

    # Step 2: Send ServerHello
    server_hello_random = get_server_hello_random()  # Generate ServerHello.random
    server_hello = server_hello_random + struct.pack('!B', 1)
    client_socket.sendall(struct.pack('!H', len(server_hello)) + server_hello)
    print('server_hello_random is ', server_hello_random)

    # Receive the IV from ServerHello
    server_hello_iv_data = client_socket.recv(1024)
    server_hello_iv_length, = struct.unpack('!H', server_hello_iv_data[:2])
    server_hello_iv = server_hello_iv_data[2:2 + server_hello_iv_length]

    # Step 3: Send ServerCertificate
    with open('server_certificate.pem', 'rb') as f:
        server_certificate = f.read()

    server_certificate_message = server_certificate
    print('server_certificate is ', server_certificate_message)
    certificate_length = len(server_certificate_message)
    client_socket.sendall(struct.pack('!H', certificate_length) + server_certificate_message)

    # Step 4: Receive ClientCertificate
    client_certificate_data = client_socket.recv(1024)
    client_certificate_length, = struct.unpack('!H', client_certificate_data[:2])
    client_certificate = client_certificate_data[2:2 + client_certificate_length]
    print('client_certificate is ', client_certificate)

    # # Step 5: Receive CertificateVerify
    # certificate_verify_data = client_socket.recv(1024)
    # certificate_verify_length, = struct.unpack('!H', certificate_verify_data[:2])
    # certificate_verify = certificate_verify_data[2:2 + certificate_verify_length]
    # print('certificate_verify is ', certificate_verify)
    # # Parse ServerCertificate
    # # client_cert = x509.load_pem_x509_certificate(certificate_verify, default_backend())
    # # Verify the signature of the received CertificateVerify message
    # # handshake_protocol.process_certificate_verify(certificate_verify, client_cert)

    client_socket.close()
    server_socket.close()
    # Create server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 23333))
    server_socket.listen(1)

    print("Waiting for client connection...")
    client_socket, client_address = server_socket.accept()
    print("Client connected:", client_address)

    # Step 6: Receive ClientKeyExchange
    client_key_exchange_data = client_socket.recv(1024)
    client_key_length, = struct.unpack('!H', client_key_exchange_data[:2])
    client_key_exchange = client_key_exchange_data[2:2 + client_key_length]

    client_key_exchange = pickle.loads(client_key_exchange)
    print('client_key_exchange_data is ', client_key_exchange)
    # 从ClientKeyExchange消息中获取客户端发送的master_secret
    # encrypted_shared_secret = ClientKeyExchange.decode(client_key_exchange_data).encrypted_shared_secret
    # print('encrypted_shared_secret is ', encrypted_shared_secret)
    #
    # master_secret = decrypt_with_private_key(server_private_key, encrypted_shared_secret)
    cipher = PKCS1_cipher.new(RSA.importKey(server_private_key))
    master_secret = cipher.decrypt(client_key_exchange, 0)
    print('master_secret is ', master_secret)

    # Step 7: Send ServerFinished
    server_finished_data = b"Data for MAC calculation"
    message_mac = calculate_session_key(master_secret, server_finished_data, client_hello_random)
    mac_length = len(message_mac)
    client_socket.sendall(struct.pack('!H', mac_length) + message_mac)
    print('server_finished_message is ', message_mac)

    # Step 8: Receive ClientFinished
    client_finished_data = client_socket.recv(1024)
    client_finished_length, = struct.unpack('!H', client_finished_data[:2])
    client_finished = client_finished_data[2:2 + client_finished_length]

    # Verify the MAC of the received ClientFinished message
    received_client_finished = ClientFinished(client_finished)
    received_mac = received_client_finished.message_mac
    print('received_mac is ', received_mac)
    expected_mac = calculate_session_key(master_secret, b"Data for ClientFinished", server_hello_random)
    print('expected_mac is ', expected_mac)

    # Step 8: Complete handshake protocol and get session key
    # Calculate master_secret during the handshake process (assumed to be available)
    # master_secret = calculate_master_secret(master_secret, client_hello_random, server_hello_random)
    # session_key = handshake_protocol.process_server_finished(client_finished, master_secret)

    # Start record protocol
    record_protocol = RecordProtocol(master_secret)

    # Receive encrypted data from client and decrypt using RecordProtocol
    encrypted_data = client_socket.recv(1024)
    record_message_type, record_message_length = struct.unpack('!BB', encrypted_data[:2])
    encrypted_data = encrypted_data[2:2 + record_message_length]
    decrypted_data = aes_decrypt(encrypted_data, master_secret, server_hello_iv)
    print("Received from client:", decrypted_data.decode())

    # Send encrypted data using RecordProtocol
    plaintext = b"Hello, this is a test message from the server!"
    record_message = aes_encrypt(plaintext, master_secret, server_hello_iv)
    record_message_length = len(record_message)
    client_socket.sendall(struct.pack('!H', record_message_length) + record_message)

    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    run_server()
