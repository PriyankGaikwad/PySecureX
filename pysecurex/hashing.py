import hashlib
import hmac
import os
import shutil
import argon2
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

def sha256_hash(data: bytes) -> str:
    """
    Compute the SHA-256 hash of input data.
    
    Args:
        data (bytes): The input data to hash.
        
    Returns:
        str: The hexadecimal representation of the SHA-256 hash.
        
    Example:
        >>> sha256_hash(b"hello world")
        'b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9'
    """
    return hashlib.sha256(data).hexdigest()

def md5_hash(data: bytes) -> str:
    """
    Compute the MD5 hash of input data.
    
    Note: MD5 is considered cryptographically broken and should not be used for 
    security-sensitive applications. Use SHA-256 or stronger algorithms instead.
    
    Args:
        data (bytes): The input data to hash.
        
    Returns:
        str: The hexadecimal representation of the MD5 hash.
        
    Example:
        >>> md5_hash(b"hello world")
        '5eb63bbbe01eeed093cb22bb8f5acdc3'
    """
    return hashlib.md5(data).hexdigest()

def hmac_hash(key: bytes, message: bytes) -> str:
    """
    Create an HMAC (Hash-based Message Authentication Code) using SHA-256.
    
    Args:
        key (bytes): The secret key for the HMAC.
        message (bytes): The message to authenticate.
        
    Returns:
        str: The hexadecimal representation of the HMAC.
        
    Example:
        >>> hmac_hash(b"secret_key", b"message to authenticate")
        '4c5a9ec0963e185ecf6147379d03d5f36c0cdb6e92da551afc91df63a73a4723'
    """
    return hmac.new(key, message, hashlib.sha256).hexdigest()

def file_integrity_check(filepath: str) -> str:
    """
    Calculate the SHA-256 hash of a file to verify its integrity.
    
    Args:
        filepath (str): Path to the file to check.
        
    Returns:
        str: The hexadecimal representation of the file's SHA-256 hash.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        
    Example:
        >>> file_integrity_check("/path/to/file.txt")
        'a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e'
    """
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def generate_salted_hash(password: str, salt: bytes = None) -> tuple[bytes, bytes]:
    """
    Generate a salted hash of a password using PBKDF2-HMAC-SHA256.
    
    Args:
        password (str): The password to hash.
        salt (bytes, optional): The salt to use. If None, a random 16-byte salt is generated.
        
    Returns:
        tuple: A tuple containing:
            - bytes: The derived key (hash value).
            - bytes: The salt used in hashing.
            
    Example:
        >>> hash_value, salt = generate_salted_hash("my_secure_password")
        >>> len(hash_value)
        32
        >>> len(salt)
        16
    """
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return dk, salt

def verify_password_hash(password: str, hash_value: bytes, salt: bytes) -> bool:
    """
    Verify a password against a previously generated salted hash.
    
    Args:
        password (str): The password to verify.
        hash_value (bytes): The previously generated hash value.
        salt (bytes): The salt used to generate the original hash.
        
    Returns:
        bool: True if the password matches the hash, False otherwise.
        
    Example:
        >>> hash_value, salt = generate_salted_hash("my_secure_password")
        >>> verify_password_hash("my_secure_password", hash_value, salt)
        True
        >>> verify_password_hash("wrong_password", hash_value, salt)
        False
    """
    return generate_salted_hash(password, salt)[0] == hash_value

def pbkdf2_key_derivation(password: str, salt: bytes, iterations: int = 100000) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2.
    
    Args:
        password (str): The password to derive the key from.
        salt (bytes): The salt to use in key derivation.
        iterations (int, optional): Number of iterations to perform. Default is 100000.
        
    Returns:
        bytes: The derived key (32 bytes).
        
    Example:
        >>> salt = os.urandom(16)
        >>> key = pbkdf2_key_derivation("my_secure_password", salt)
        >>> len(key)
        32
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode())

def argon2_key_derivation(password: str) -> bytes:
    """
    Derive a cryptographic key from a password using Argon2, a modern password-hashing function.
    
    Args:
        password (str): The password to derive the key from.
        
    Returns:
        bytes: The encoded hash string which includes the salt and parameters.
        
    Example:
        >>> hash_value = argon2_key_derivation("my_secure_password")
        >>> hash_value.startswith(b'$argon2id$')
        True
    """
    ph = argon2.PasswordHasher()
    return ph.hash(password).encode()

def hash_large_file(filepath: str, chunk_size: int = 65536) -> str:
    """
    Calculate the SHA-256 hash of a large file by processing it in chunks.
    
    Args:
        filepath (str): Path to the file to hash.
        chunk_size (int, optional): Size of each chunk in bytes. Defaults to 65536 (64KB).
        
    Returns:
        str: The hexadecimal representation of the file's SHA-256 hash.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        
    Example:
        >>> hash_large_file("/path/to/large_file.iso")
        '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824'
    """
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while chunk := f.read(chunk_size):
            hasher.update(chunk)
    return hasher.hexdigest()

def check_file_tampering(filepath: str, signature: bytes, public_key_pem: bytes) -> bool:
    """
    Verify a file's digital signature to check for tampering.
    
    Args:
        filepath (str): Path to the file to verify.
        signature (bytes): The digital signature of the file.
        public_key_pem (bytes): The PEM-encoded public key to use for verification.
        
    Returns:
        bool: True if the signature is valid, False if the file has been tampered with.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        
    Example:
        >>> with open("public_key.pem", "rb") as key_file:
        ...     public_key = key_file.read()
        >>> check_file_tampering("/path/to/file.txt", signature, public_key)
        True
    """
    with open(filepath, 'rb') as f:
        data = f.read()
    public_key = serialization.load_pem_public_key(public_key_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def securely_erase_file(filepath: str, passes: int = 3):
    """
    Securely erase a file by overwriting it multiple times before deletion.
    
    Args:
        filepath (str): Path to the file to erase.
        passes (int, optional): Number of overwrite passes. Defaults to 3.
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        
    Note:
        This function may not be effective on all storage systems, particularly SSDs
        with wear leveling or journaling file systems. For critical security needs,
        specialized tools or full-disk encryption should be used.
        
    Example:
        >>> securely_erase_file("/path/to/sensitive_file.txt")
    """
    if os.path.exists(filepath):
        with open(filepath, 'ba+') as f:
            length = f.tell()
        for _ in range(passes):
            with open(filepath, 'wb') as f:
                f.write(os.urandom(length))
        os.remove(filepath)

def file_metadata_protection(filepath: str):
    """
    Create a backup of a file's metadata (permissions, timestamps) and remove the original file.
    
    This can be used to preserve metadata information while handling sensitive files.
    
    Args:
        filepath (str): Path to the file to protect.
        
    Returns:
        str: Path to the backup file (original path + '.bak').
        
    Raises:
        FileNotFoundError: If the specified file does not exist.
        
    Example:
        >>> file_metadata_protection("/path/to/sensitive_file.txt")
        '/path/to/sensitive_file.txt.bak'
    """
    backup_path = filepath + '.bak'
    shutil.copystat(filepath, backup_path)
    os.remove(filepath)
    return backup_path