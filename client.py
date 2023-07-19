import os
import pickle
import socket
import struct

import base64

from Crypto import Random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from crypto.crypto_utils import encrypt_with_public_key, decrypt_with_private_key
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

    # Step 5: Send CertificateVerify
    data = handshake_protocol.get_handshake_messages()
    signature = rsa_sign(data, client_private_key)
    certificate_verify_message = CertificateVerify(signature)
    client_socket.sendall(certificate_verify_message.encode())
    print('certificate_verify is ', signature)

    # Step 6: Send ClientKeyExchange
    master_secret = generate_master_secret()
    print('master_secret is ', master_secret)

    cipher = PKCS1_cipher.new(RSA.importKey(server_public_key))
    encrypt_text = cipher.encrypt(master_secret)
    print('encrypt_text is ', encrypt_text)
    client_socket.sendall(pickle.dumps(encrypt_text))

    with open('server_private_key.pem', 'rb') as f:
        server_private_key = f.read()
    cipher = PKCS1_cipher.new(RSA.importKey(server_private_key))
    back_text = cipher.decrypt(encrypt_text, 0)
    print('back_text is ', back_text)



    # encrypted_shared_secret = encrypt_with_public_key(server_public_key, master_secret)
    # client_key_exchange = ClientKeyExchange(encrypted_shared_secret)
    # client_socket.sendall(client_key_exchange.encode())
    # print('client_key_exchange is ', client_key_exchange.encode())
    #
    # # 从ClientKeyExchange消息中获取客户端发送的master_secret
    # encrypted_shared_secret = ClientKeyExchange.decode(client_key_exchange).encrypted_shared_secret
    # print('encrypted_shared_secret is ', encrypted_shared_secret)
    # with open('server_private_key.pem', 'rb') as f:
    #     server_private_key = f.read()
    # master_secret = decrypt_with_private_key(server_private_key, encrypted_shared_secret)

    # Step 7: Receive ServerFinished
    server_finished_data = client_socket.recv(1024)
    server_finished_length, = struct.unpack('!H', server_finished_data[:2])
    server_finished = server_finished_data[2:2 + server_finished_length]
    print('server_finished is ', server_finished)

    # Verify the MAC of the received ServerFinished message
    received_server_finished = ServerFinished(server_finished)
    received_mac = received_server_finished.message_mac
    expected_mac = calculate_session_key(master_secret, b"Data for MAC calculation", client_hello_random)

    print(received_mac, '\n', expected_mac)

    if received_mac == expected_mac:
        print("ServerFinished message is valid and verified.")
    else:
        print("ServerFinished message is invalid. Connection may be compromised.")

    # Step 8: Send ClientFinished
    client_finished_data = b"Data for ClientFinished"
    message_mac = calculate_session_key(master_secret, client_finished_data, server_hello_random)
    client_finished_message = ClientFinished(message_mac)
    client_socket.sendall(client_finished_message.encode())
    print('client_finished is ', client_finished_message)

    # Step 8: Complete handshake protocol and get session key
    # session_key = handshake_protocol.process_client_certificate(server_certificate)

    # Start record protocol
    record_protocol = RecordProtocol(master_secret)

    # Send encrypted data using RecordProtocol
    plaintext = b"Hello, this is a test message from the client!"
    record_message = record_protocol.encrypt_data(plaintext, iv)
    client_socket.sendall(record_message.encode())

    # Receive encrypted data from server and decrypt using RecordProtocol
    encrypted_data = client_socket.recv(1024)
    record_message_type, record_message_length = struct.unpack('!BB', encrypted_data[:2])
    encrypted_data = encrypted_data[2:2 + record_message_length]
    record_message = Message(MessageType(record_message_type), record_message_length, encrypted_data)
    decrypted_data = record_protocol.decrypt_data(record_message, iv)
    print("Received from server:", decrypted_data.decode())

    client_socket.close()


if __name__ == "__main__":
    run_client()
