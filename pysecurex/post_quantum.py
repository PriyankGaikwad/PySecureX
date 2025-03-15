from pqcrypto.kem.kyber512 import generate_keypair, encapsulate, decapsulate
from pqcrypto.sign.dilithium2 import generate_keypair as dilithium_generate_keypair, sign, verify
from pqcrypto.sign.falcon512 import generate_keypair as falcon_generate_keypair, sign as falcon_sign_func, verify as falcon_verify_func
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def kyber_key_exchange():
    """
    Implements a post-quantum secure key exchange using Kyber.
    
    Returns:
        tuple: (private_key, public_key, shared_secret)
    """
    public_key, private_key = generate_keypair()
    shared_secret, ciphertext = encapsulate(public_key)
    return private_key, public_key, shared_secret, ciphertext

def dilithium_sign(data: bytes, private_key: bytes):
    """
    Sign data using the Dilithium post-quantum digital signature scheme.

    Args:
        data (bytes): Data to sign.
        private_key (bytes): Dilithium private key.

    Returns:
        bytes: Digital signature.
    """
    return sign(data, private_key)

def dilithium_verify(data: bytes, signature: bytes, public_key: bytes):
    """
    Verify a Dilithium digital signature.

    Args:
        data (bytes): Original data.
        signature (bytes): Digital signature.
        public_key (bytes): Dilithium public key.

    Returns:
        bool: True if valid, False otherwise.
    """
    return verify(data, signature, public_key)

def falcon_sign(data: bytes, private_key: bytes):
    """
    Sign data using the Falcon post-quantum digital signature scheme.

    Args:
        data (bytes): Data to sign.
        private_key (bytes): Falcon private key.

    Returns:
        bytes: Digital signature.
    """
    return falcon_sign_func(data, private_key)

def falcon_verify(data: bytes, signature: bytes, public_key: bytes):
    """
    Verify a Falcon digital signature.

    Args:
        data (bytes): Original data.
        signature (bytes): Digital signature.
        public_key (bytes): Falcon public key.

    Returns:
        bool: True if valid, False otherwise.
    """
    return falcon_verify_func(data, signature, public_key)

def hybrid_pqc_aes_encrypt(data: bytes, public_key: bytes):
    """
    Hybrid encryption using AES-GCM + post-quantum Kyber.
    
    Args:
        data (bytes): Data to encrypt.
        public_key (bytes): Kyber public key.
    
    Returns:
        dict: Encrypted data components.
    """
    aes_key, ciphertext = encapsulate(public_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key[:32]), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return {"ciphertext": ciphertext, "iv": iv, "tag": encryptor.tag, "encrypted_data": encrypted_data}

def hybrid_pqc_aes_decrypt(encrypted_payload: dict, private_key: bytes):
    """
    Decrypt hybrid post-quantum AES-GCM encrypted data.
    
    Args:
        encrypted_payload (dict): Encrypted data components.
        private_key (bytes): Kyber private key.
    
    Returns:
        bytes: Decrypted data.
    """
    aes_key = decapsulate(encrypted_payload["ciphertext"], private_key)
    cipher = Cipher(algorithms.AES(aes_key[:32]), modes.GCM(encrypted_payload["iv"], encrypted_payload["tag"]))
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_payload["encrypted_data"]) + decryptor.finalize()
