# SecurePay
BJTU 2023 Summer Crypto Course.
# SSL Client and Server

This is a simple implementation of a Secure Socket Layer (SSL) client and server written in Python. It provides an example of how SSL handshake and encryption can be implemented between a client and server. The client is designed to connect to the server that supports SSL and perform a secure handshake to establish a secure communication channel.

## Prerequisites

Before running the SSL client and server, make sure you have the following installed:

- Python 3.x

Install the required libraries using `pip`:

```bash
pip install -r requirements.txt
```

## Key Generation

Generate the necessary RSA key pairs for the client and server using `RSA_generator.py`. This will create `client_private_key.pem` and `client_public_key.pem` for the client, and `server_private_key.pem` and `server_public_key.pem` for the server.

```bash
python RSA_generator.py
```

## Usage

1. Start the SSL server:

```bash
python server.py
```

2. Start the SSL client:

```bash
python client.py
```

The client will initiate the handshake with the server and establish a secure communication channel.

## Implementation Details

The SSL client follows these main steps during the handshake:

1. Generate a 32-byte random number (`ClientHello.random`) and select a cipher suite based on supported algorithms. The client sends a `ClientHello` message to start the handshake.

2. Receive `ServerHello` from the server, containing a 32-byte random number (`ServerHello.random`) and the selected cipher suite.

3. Receive `ServerCertificate` from the server and validate it.

4. Send `ClientCertificate`, `CertificateVerify`, and `ClientKeyExchange` messages to the server, which includes encrypting the shared master secret using the server's public key.

5. Receive `ServerFinished` message from the server, verify its authenticity, and send `ClientFinished` back to the server.

6. If the handshake is successful, the client and server compute the session key.

## Contributing

Contributions are welcome! If you find any issues or want to add new features, feel free to create a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Acknowledgments

Special thanks to [OpenSSL](https://www.openssl.org/) for providing the foundation for this implementation.

## Disclaimer

This project is for educational purposes only and not intended for production use. Use it at your own risk.

---

Feel free to modify the content according to your specific project details and add more sections if needed. Make sure to include relevant information about the project, its usage, and any important notes for potential contributors and users.