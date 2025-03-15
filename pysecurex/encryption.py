from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.backends import default_backend
import os

def aes_encrypt(data: bytes, key: bytes):
    """
    Encrypt data using AES (256-bit) encryption with GCM mode.
    
    Args:
        data (bytes): Data to encrypt.
        key (bytes): AES key (32 bytes for AES-256).
        
    Returns:
        tuple: (encrypted_data, iv, tag)
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return encrypted_data, iv, encryptor.tag

def aes_decrypt(encrypted_data: bytes, key: bytes, iv: bytes, tag: bytes):
    """
    Decrypt AES-encrypted data.
    
    Args:
        encrypted_data (bytes): AES encrypted data.
        key (bytes): AES key.
        iv (bytes): Initialization vector.
        tag (bytes): Authentication tag.
        
    Returns:
        bytes: Decrypted data.
    """
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

def generate_rsa_key_pair():
    """
    Generate an RSA public-private key pair.
    
    Returns:
        tuple: (private_key, public_key)
    """
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(data: bytes, public_key):
    """
    Encrypt data using RSA encryption.
    
    Args:
        data (bytes): Data to encrypt.
        public_key: RSA public key object.
        
    Returns:
        bytes: Encrypted data.
    """
    return public_key.encrypt(
        data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def rsa_decrypt(encrypted_data: bytes, private_key):
    """
    Decrypt RSA-encrypted data.
    
    Args:
        encrypted_data (bytes): RSA encrypted data.
        private_key: RSA private key object.
        
    Returns:
        bytes: Decrypted data.
    """
    return private_key.decrypt(
        encrypted_data,
        asym_padding.OAEP(
            mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

def hybrid_encrypt(data: bytes, public_key):
    """
    Encrypt data using hybrid encryption (AES + RSA).
    
    Args:
        data (bytes): Data to encrypt.
        public_key: RSA public key object.
        
    Returns:
        dict: {'encrypted_data': encrypted data, 'encrypted_key': RSA-encrypted AES key, 'iv': IV, 'tag': tag}
    """
    aes_key = os.urandom(32)
    encrypted_data, iv, tag = aes_encrypt(data, aes_key)
    encrypted_key = rsa_encrypt(aes_key, public_key)
    return {'encrypted_data': encrypted_data, 'encrypted_key': encrypted_key, 'iv': iv, 'tag': tag}

def hybrid_decrypt(encrypted_payload: dict, private_key):
    """
    Decrypt hybrid-encrypted data (AES + RSA).
    
    Args:
        encrypted_payload (dict): Dictionary containing 'encrypted_data', 'encrypted_key', 'iv', and 'tag'.
        private_key: RSA private key object.
        
    Returns:
        bytes: Decrypted data.
    """
    aes_key = rsa_decrypt(encrypted_payload['encrypted_key'], private_key)
    return aes_decrypt(encrypted_payload['encrypted_data'], aes_key, encrypted_payload['iv'], encrypted_payload['tag'])

def chacha20_encrypt(data: bytes, key: bytes):
    """
    Encrypts the given data using the ChaCha20-Poly1305 algorithm.

    Args:
        data (bytes): The plaintext data to encrypt.
        key (bytes): A 32-byte encryption key.

    Returns:
        tuple: A tuple containing:
            - encrypted_data (bytes): The encrypted ciphertext.
            - nonce (bytes): A 12-byte randomly generated nonce required for decryption.

    Raises:
        ValueError: If the provided key is not 32 bytes long.
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long for ChaCha20-Poly1305.")

    nonce = os.urandom(12)  # ChaCha20-Poly1305 requires a 12-byte nonce
    cipher = ChaCha20Poly1305(key)
    encrypted_data = cipher.encrypt(nonce, data, None)
    return encrypted_data, nonce

def chacha20_decrypt(encrypted_data: bytes, key: bytes, nonce: bytes):
    """
    Decrypts the given ciphertext using the ChaCha20-Poly1305 algorithm.

    Args:
        encrypted_data (bytes): The ciphertext to decrypt.
        key (bytes): A 32-byte encryption key (must match the encryption key).
        nonce (bytes): The 12-byte nonce used during encryption.

    Returns:
        bytes: The decrypted plaintext data.

    Raises:
        ValueError: If the provided key is not 32 bytes long.
        cryptography.exceptions.InvalidTag: If decryption fails (e.g., wrong key or nonce).
    """
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes long for ChaCha20-Poly1305.")

    cipher = ChaCha20Poly1305(key)
    return cipher.decrypt(nonce, encrypted_data, None)

def blowfish_encrypt(data: bytes, key: bytes):
    """
    Encrypt data using Blowfish with proper padding.
    
    Args:
        data (bytes): Data to encrypt.
        key (bytes): Blowfish key.
        
    Returns:
        tuple: (encrypted_data, iv)
    """
    padder = padding.PKCS7(algorithms.Blowfish.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    iv = os.urandom(8)  # Blowfish uses 8-byte blocks
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, iv

def blowfish_decrypt(encrypted_data: bytes, key: bytes, iv: bytes):
    """
    Decrypt Blowfish-encrypted data.
    
    Args:
        encrypted_data (bytes): Encrypted data.
        key (bytes): Blowfish key.
        iv (bytes): Initialization vector used during encryption.
        
    Returns:
        bytes: Decrypted data.
    """
    cipher = Cipher(algorithms.Blowfish(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.Blowfish.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def des3_encrypt(data: bytes, key: bytes):
    """
    Encrypt data using Triple DES (3DES) with proper padding.
    
    Args:
        data (bytes): Data to encrypt.
        key (bytes): 24-byte Triple DES key.
        
    Returns:
        tuple: (encrypted_data, iv)
    """
    padder = padding.PKCS7(algorithms.TripleDES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    
    iv = os.urandom(8)
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    
    return encrypted_data, iv

def des3_decrypt(encrypted_data: bytes, key: bytes, iv: bytes):
    """
    Decrypt 3DES-encrypted data.
    
    Args:
        encrypted_data (bytes): 3DES encrypted data.
        key (bytes): 24-byte Triple DES key.
        iv (bytes): Initialization vector.
        
    Returns:
        bytes: Decrypted data.
    """
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    
    unpadder = padding.PKCS7(algorithms.TripleDES.block_size).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

