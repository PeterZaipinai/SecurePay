# protocol.py

import struct
from message import MessageType, Message, ClientHello, ServerHello, ServerCertificate, ClientCertificate, \
    CertificateVerify, ClientKeyExchange, ServerFinished, ClientFinished


class Protocol:

    def encode_message(self, message):
        encoder = {
            MessageType.client_hello: self.encode_client_hello,
            MessageType.server_hello: self.encode_server_hello,
            MessageType.server_certificate: self.encode_server_certificate,
            MessageType.client_certificate: self.encode_client_certificate,
            MessageType.certificate_verify: self.encode_certificate_verify,
            MessageType.client_key_exchange: self.encode_client_key_exchange,
            MessageType.server_finished: self.encode_server_finished,
            MessageType.client_finished: self.encode_client_finished,
            MessageType.error_message: self.encode_error_message,
            MessageType.application_data: self.encode_application_data
        }

        if message.msg_type not in encoder:
            raise ValueError("Unknown message type")

        return encoder[message.msg_type](message.body)

    def encode_client_hello(self, client_hello):
        random = client_hello.random
        cipher_suite = client_hello.cipher_suite

        # Encode the ClientHello message
        encoded_random = random
        encoded_cipher_suite = struct.pack("B", cipher_suite)

        # Create the encoded message
        encoded_body = encoded_random + encoded_cipher_suite
        encoded_message = self._create_encoded_message(MessageType.client_hello, encoded_body)

        return encoded_message

    def encode_server_hello(self, server_hello):
        random = server_hello.random
        cipher_suite = server_hello.cipher_suite

        # Encode the ServerHello message
        encoded_random = random
        encoded_cipher_suite = struct.pack("B", cipher_suite)

        # Create the encoded message
        encoded_body = encoded_random + encoded_cipher_suite
        encoded_message = self._create_encoded_message(MessageType.server_hello, encoded_body)

        return encoded_message

    def encode_server_certificate(self, server_certificate):
        certificate = server_certificate.certificate

        # Encode the ServerCertificate message
        encoded_certificate = certificate

        # Create the encoded message
        encoded_body = encoded_certificate
        encoded_message = self._create_encoded_message(MessageType.server_certificate, encoded_body)

        return encoded_message

    def encode_client_certificate(self, client_certificate):
        certificate = client_certificate.certificate

        # Encode the ClientCertificate message
        encoded_certificate = certificate

        # Create the encoded message
        encoded_body = encoded_certificate
        encoded_message = self._create_encoded_message(MessageType.client_certificate, encoded_body)

        return encoded_message

    def encode_certificate_verify(self, certificate_verify):
        signature = certificate_verify.signature

        # Encode the CertificateVerify message
        encoded_signature = signature

        # Create the encoded message
        encoded_body = encoded_signature
        encoded_message = self._create_encoded_message(MessageType.certificate_verify, encoded_body)

        return encoded_message

    def encode_client_key_exchange(self, client_key_exchange):
        encrypted_shared_secret = client_key_exchange.encrypted_shared_secret

        # Encode the ClientKeyExchange message
        encoded_encrypted_shared_secret = encrypted_shared_secret

        # Create the encoded message
        encoded_body = encoded_encrypted_shared_secret
        encoded_message = self._create_encoded_message(MessageType.client_key_exchange, encoded_body)

        return encoded_message

    def encode_server_finished(self, server_finished):
        message_mac = server_finished.message_mac

        # Encode the ServerFinished message
        encoded_message_mac = message_mac

        # Create the encoded message
        encoded_body = encoded_message_mac
        encoded_message = self._create_encoded_message(MessageType.server_finished, encoded_body)

        return encoded_message

    def encode_client_finished(self, client_finished):
        message_mac = client_finished.message_mac

        # Encode the ClientFinished message
        encoded_message_mac = message_mac

        # Create the encoded message
        encoded_body = encoded_message_mac
        encoded_message = self._create_encoded_message(MessageType.client_finished, encoded_body)

        return encoded_message

    def encode_error_message(self, error_message):
        error_code = error_message

        # Encode the ErrorMessage message
        encoded_error_code = struct.pack("B", error_code)

        # Create the encoded message
        encoded_body = encoded_error_code
        encoded_message = self._create_encoded_message(MessageType.error_message, encoded_body)

        return encoded_message

    def encode_application_data(self, application_data):
        encrypted_data = application_data

        # Create the encoded message
        encoded_body = encrypted_data
        encoded_message = self._create_encoded_message(MessageType.application_data, encoded_body)

        return encoded_message

    def _create_encoded_message(self, msg_type, encoded_body):
        # Create the encoded message with message type and body length
        encoded_message = struct.pack("!B H", msg_type, len(encoded_body)) + encoded_body

        return encoded_message
