from crypto.symmetric_encryption import aes_encrypt, aes_decrypt, des3_encrypt, des3_decrypt
from protocols.message import Message, MessageType


class RecordProtocol:
    def __init__(self, session_key):
        self.session_key = session_key

    def encrypt_data(self, data):
        # Add length prefix to data
        length = len(data).to_bytes(2, 'big')
        data_with_length = length + data

        # Encrypt data using session key
        encrypted_data = self.encrypt_with_session_key(data_with_length)

        # Create Record message
        record_message = Message(MessageType.application_data, len(encrypted_data), encrypted_data)

        return record_message

    def decrypt_data(self, record_message):
        # Decrypt data using session key
        decrypted_data = self.decrypt_with_session_key(record_message.body)

        # Remove length prefix from data
        data = decrypted_data[2:]

        return data

    def encrypt_with_session_key(self, data):
        # Select appropriate encryption algorithm based on session key size
        if len(self.session_key) == 16:
            # AES-128 encryption
            encrypted_data = aes_encrypt(data, self.session_key)
        elif len(self.session_key) == 24:
            # TripleDES encryption
            encrypted_data = des3_encrypt(data, self.session_key)

        return encrypted_data

    def decrypt_with_session_key(self, data):
        # Select appropriate decryption algorithm based on session key size
        if len(self.session_key) == 16:
            # AES-128 decryption
            decrypted_data = aes_decrypt(data, self.session_key)
        elif len(self.session_key) == 24:
            # TripleDES decryption
            decrypted_data = des3_decrypt(data, self.session_key)

        return decrypted_data
