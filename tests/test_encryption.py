import unittest
from pysecurex.encryption import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, hybrid_encrypt, hybrid_decrypt
from pysecurex.hashing import sha256_hash
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class TestEncryption(unittest.TestCase):

    def setUp(self):
        self.password = "strongpassword"
        self.data = b"Sensitive data"
        
        # Generate RSA keys for testing
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        self.public_key = self.private_key.public_key()
        
        self.private_key_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        self.public_key_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def test_aes_encryption_decryption(self):
        encrypted_data, iv, tag = aes_encrypt(self.data, self.password.encode())
        decrypted_data = aes_decrypt(encrypted_data, self.password.encode(), iv, tag)
        self.assertEqual(self.data, decrypted_data)

    def test_rsa_encryption_decryption(self):
        encrypted_data = rsa_encrypt(self.data, self.public_key_pem)
        decrypted_data = rsa_decrypt(encrypted_data, self.private_key_pem)
        self.assertEqual(self.data, decrypted_data)

    def test_hybrid_encryption_decryption(self):
        encrypted_data = hybrid_encrypt(self.data, self.public_key_pem)
        decrypted_data = hybrid_decrypt(encrypted_data, self.private_key_pem)
        self.assertEqual(self.data, decrypted_data)

    def test_sha256_hash(self):
        hash1 = sha256_hash("test")
        hash2 = sha256_hash("test")
        self.assertEqual(hash1, hash2)

if __name__ == "__main__":
    unittest.main()