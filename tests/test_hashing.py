import unittest
from pysecurex.hashing import (
    sha256_hash, md5_hash, hmac_hash, file_integrity_check, 
    verify_password_hash, pbkdf2_key_derivation, argon2_key_derivation, 
    hash_large_file, check_file_tampering, securely_erase_file, file_metadata_protection
)
import os

class TestHashing(unittest.TestCase):

    def setUp(self):
        self.data = "Sensitive data"
        self.password = "strongpassword"
        self.filepath = "test_file.txt"
        with open(self.filepath, "w") as f:
            f.write(self.data)

    def tearDown(self):
        if os.path.exists(self.filepath):
            os.remove(self.filepath)

    def test_sha256_hash(self):
        hash1 = sha256_hash(self.data)
        hash2 = sha256_hash(self.data)
        self.assertEqual(hash1, hash2)

    def test_md5_hash(self):
        hash1 = md5_hash(self.data)
        hash2 = md5_hash(self.data)
        self.assertEqual(hash1, hash2)

    def test_hmac_hash(self):
        hmac1 = hmac_hash(self.data, self.password)
        hmac2 = hmac_hash(self.data, self.password)
        self.assertEqual(hmac1, hmac2)

    def test_file_integrity_check(self):
        original_hash = sha256_hash(self.data)
        self.assertTrue(file_integrity_check(self.filepath, original_hash))

    def test_verify_password_hash(self):
        hashed_password = pbkdf2_key_derivation(self.password)
        self.assertTrue(verify_password_hash(self.password, hashed_password))

    def test_pbkdf2_key_derivation(self):
        key1 = pbkdf2_key_derivation(self.password)
        key2 = pbkdf2_key_derivation(self.password)
        self.assertNotEqual(key1, key2)  # PBKDF2 should generate different salts

    def test_argon2_key_derivation(self):
        key1 = argon2_key_derivation(self.password)
        key2 = argon2_key_derivation(self.password)
        self.assertNotEqual(key1, key2)  # Argon2 should generate different salts

    def test_hash_large_file(self):
        large_file_path = "large_test_file.txt"
        with open(large_file_path, "w") as f:
            f.write(self.data * 1000)
        hash1 = hash_large_file(large_file_path)
        hash2 = hash_large_file(large_file_path)
        self.assertEqual(hash1, hash2)
        os.remove(large_file_path)

    def test_check_file_tampering(self):
        original_hash = sha256_hash(self.data)
        self.assertFalse(check_file_tampering(self.filepath, original_hash))

    def test_securely_erase_file(self):
        securely_erase_file(self.filepath)
        self.assertFalse(os.path.exists(self.filepath))

    def test_file_metadata_protection(self):
        metadata_hash = file_metadata_protection(self.filepath)
        self.assertIsNotNone(metadata_hash)

if __name__ == "__main__":
    unittest.main()