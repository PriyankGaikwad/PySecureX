import unittest
from pysecurex.password_tools import generate_strong_password, check_password_strength
from pysecurex.hashing import pbkdf2_key_derivation, verify_password_hash

class TestPasswordTools(unittest.TestCase):

    def setUp(self):
        self.password = "strongpassword"

    def test_generate_strong_password(self):
        password = generate_strong_password()
        self.assertTrue(len(password) >= 12)
        self.assertTrue(any(c.islower() for c in password))
        self.assertTrue(any(c.isupper() for c in password))
        self.assertTrue(any(c.isdigit() for c in password))
        self.assertTrue(any(c in "!@#$%^&*()-_+=" for c in password))

    def test_check_password_strength(self):
        strength = check_password_strength(self.password)
        self.assertTrue(strength['length'])
        self.assertTrue(strength['uppercase'])
        self.assertTrue(strength['lowercase'])
        self.assertTrue(strength['digits'])
        self.assertTrue(strength['special'])

    def test_pbkdf2_key_derivation(self):
        hashed_password = pbkdf2_key_derivation(self.password)
        self.assertTrue(verify_password_hash(self.password, hashed_password))

    def test_verify_password_hash(self):
        hashed_password = pbkdf2_key_derivation(self.password)
        self.assertTrue(verify_password_hash(self.password, hashed_password))
        self.assertFalse(verify_password_hash("wrongpassword", hashed_password))

if __name__ == "__main__":
    unittest.main()