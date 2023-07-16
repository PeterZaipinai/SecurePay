import socket
import struct

from crypto.hmac import calculate_master_secret
from protocols.handshake_protocol import HandshakeProtocol, get_server_hello_random, \
    rsa_encrypt, rsa_sign, generate_master_secret, calculate_session_key
from protocols.message import Message, MessageType, CertificateVerify, ClientKeyExchange, ServerFinished
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

    # Step 2: Send ServerHello
    server_hello_random = get_server_hello_random()  # Generate ServerHello.random
    server_hello = server_hello_random + struct.pack('!B', 1)  # Replace 1 with the appropriate value for the selected cipher suite
    client_socket.sendall(struct.pack('!H', len(server_hello)) + server_hello)

    # Step 3: Send ServerCertificate
    with open('server_certificate.pem', 'rb') as f:
        server_certificate = f.read()

    server_certificate_message = server_certificate
    certificate_length = len(server_certificate_message)
    client_socket.sendall(struct.pack('!H', certificate_length) + server_certificate_message)

    # Step 4: Send CertificateVerify
    certificate_verify_data = b"Data to sign for CertificateVerify"
    signature = rsa_sign(certificate_verify_data, server_private_key)
    certificate_verify_message = CertificateVerify(signature)
    client_socket.sendall(certificate_verify_message.encode())

    # Step 5: Send ClientKeyExchange
    session_key = generate_master_secret()
    encrypted_session_key = rsa_encrypt(session_key, client_public_key)
    client_key_exchange_message = ClientKeyExchange(encrypted_session_key)
    client_socket.sendall(client_key_exchange_message.encode())

    # Step 6: Send ServerFinished
    server_finished_data = b"Data for MAC calculation"
    message_mac = calculate_session_key(session_key, server_finished_data, client_hello_random)
    server_finished_message = ServerFinished(message_mac)
    client_socket.sendall(server_finished_message.encode())

    # Step 7: Receive ClientFinished
    client_finished_data = client_socket.recv(1024)
    client_finished_length, = struct.unpack('!H', client_finished_data[:2])
    client_finished = client_finished_data[2:2 + client_finished_length]

    # Step 8: Complete handshake protocol and get session key
    # Calculate master_secret during the handshake process (assumed to be available)
    master_secret = calculate_master_secret(session_key, client_hello_random, server_hello_random)
    session_key = handshake_protocol.process_server_finished(client_finished, master_secret)

    # Start record protocol
    record_protocol = RecordProtocol(session_key)

    # Receive encrypted data from client and decrypt using RecordProtocol
    encrypted_data = client_socket.recv(1024)
    record_message_type, record_message_length = struct.unpack('!BB', encrypted_data[:2])
    encrypted_data = encrypted_data[2:2 + record_message_length]
    record_message = Message(MessageType(record_message_type), record_message_length, encrypted_data)
    decrypted_data = record_protocol.decrypt_data(record_message)
    print("Received from client:", decrypted_data.decode())

    # Send encrypted data using RecordProtocol
    plaintext = b"Hello, this is a test message from the server!"
    record_message = record_protocol.encrypt_data(plaintext)
    client_socket.sendall(record_message.encode())

    client_socket.close()
    server_socket.close()


if __name__ == "__main__":
    run_server()
