import socket
import struct

from protocols.handshake_protocol import HandshakeProtocol, get_client_hello_random
from protocols.message import Message, MessageType
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

    # Step 2: Receive ServerHello
    server_hello_data = client_socket.recv(1024)
    server_hello_length, = struct.unpack('!H', server_hello_data[:2])
    server_hello = server_hello_data[2:2 + server_hello_length]
    server_hello_random, server_cipher_suite = struct.unpack('!32sB', server_hello)

    # Step 3: Receive ServerCertificate
    server_certificate_data = client_socket.recv(1024)
    server_certificate_length, = struct.unpack('!H', server_certificate_data[:2])
    server_certificate = server_certificate_data[2:2 + server_certificate_length]

    # Step 4: Receive CertificateVerify
    certificate_verify_data = client_socket.recv(1024)
    certificate_verify_length, = struct.unpack('!H', certificate_verify_data[:2])
    certificate_verify = certificate_verify_data[2:2 + certificate_verify_length]

    # Step 5: Receive ClientKeyExchange
    client_key_exchange_data = client_socket.recv(1024)
    client_key_exchange_length, = struct.unpack('!H', client_key_exchange_data[:2])
    client_key_exchange = client_key_exchange_data[2:2 + client_key_exchange_length]

    # Step 6: Receive ServerFinished
    server_finished_data = client_socket.recv(1024)
    server_finished_length, = struct.unpack('!H', server_finished_data[:2])
    server_finished = server_finished_data[2:2 + server_finished_length]

    # Step 7: Receive ClientFinished
    client_finished_data = client_socket.recv(1024)
    client_finished_length, = struct.unpack('!H', client_finished_data[:2])
    client_finished = client_finished_data[2:2 + client_finished_length]

    # Step 8: Complete handshake protocol and get session key
    session_key = handshake_protocol.process_client_certificate(server_certificate)

    # Start record protocol
    record_protocol = RecordProtocol(session_key)

    # Send encrypted data using RecordProtocol
    plaintext = b"Hello, this is a test message from the client!"
    record_message = record_protocol.encrypt_data(plaintext)
    client_socket.sendall(record_message.encode())

    # Receive encrypted data from server and decrypt using RecordProtocol
    encrypted_data = client_socket.recv(1024)
    record_message_type, record_message_length = struct.unpack('!BB', encrypted_data[:2])
    encrypted_data = encrypted_data[2:2 + record_message_length]
    record_message = Message(MessageType(record_message_type), record_message_length, encrypted_data)
    decrypted_data = record_protocol.decrypt_data(record_message)
    print("Received from server:", decrypted_data.decode())

    client_socket.close()


if __name__ == "__main__":
    run_client()
