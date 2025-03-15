# PySecureX

PySecureX is an advanced Python security library that provides a comprehensive suite of tools for encryption, hashing, password management, network security, steganography, post-quantum cryptography, and AI-based threat detection. This library is designed to help developers implement robust security features in their applications with ease.

## Features

- **Encryption and Decryption**: Support for AES, RSA, and hybrid encryption methods.
- **Hashing**: Generate SHA-256, MD5, and HMAC hashes, check file integrity, and securely erase files.
- **Password Management**: Generate strong passwords, check password strength, and perform password hashing using PBKDF2 and Argon2.
- **Network Security**: Check SSL certificates and detect Man-in-the-Middle (MITM) attacks.
- **Steganography**: Hide and extract text and files in images and audio files, apply invisible watermarks, and encrypt and hide data in PDF files.
- **Post-Quantum Cryptography**: Perform Kyber key exchange, use Dilithium and Falcon digital signatures, and hybrid PQC + AES encryption and decryption.
- **AI Threat Detection**: Scan network traffic, files, directories, and logs for anomalies, and train AI models for threat detection.

## Installation

To install PySecureX, clone the repository and install the required dependencies:

```bash
git clone https://github.com/PriyankGaikwad/PySecureX.git
cd PySecureX
pip install -r requirements.txt