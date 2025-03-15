import os
import json
import hashlib
from cryptography.fernet import Fernet

class SecureFileVault:
    """
    A secure file vault that encrypts and stores files, requiring authentication for access.
    """
    
    def __init__(self, vault_path="vault"):  
        self.vault_path = vault_path
        self.vault_key_file = os.path.join(self.vault_path, "vault.key")
        self.metadata_file = os.path.join(self.vault_path, "metadata.json")
        os.makedirs(self.vault_path, exist_ok=True)
        self.key = self.load_or_generate_key()
    
    def load_or_generate_key(self):
        """Loads the encryption key if it exists, otherwise generates a new one."""
        if os.path.exists(self.vault_key_file):
            with open(self.vault_key_file, "rb") as key_file:
                return key_file.read()
        else:
            key = Fernet.generate_key()
            with open(self.vault_key_file, "wb") as key_file:
                key_file.write(key)
            return key
    
    def encrypt_file(self, file_path):
        """Encrypts a file and stores it securely in the vault."""
        fernet = Fernet(self.key)
        with open(file_path, "rb") as file:
            encrypted_data = fernet.encrypt(file.read())
        encrypted_file_path = os.path.join(self.vault_path, os.path.basename(file_path) + ".enc")
        with open(encrypted_file_path, "wb") as enc_file:
            enc_file.write(encrypted_data)
        self.save_metadata(file_path)
        print(f"File '{file_path}' encrypted and stored successfully.")
    
    def decrypt_file(self, encrypted_filename, output_path):
        """Decrypts an encrypted file and restores it to its original state."""
        fernet = Fernet(self.key)
        encrypted_file_path = os.path.join(self.vault_path, encrypted_filename)
        with open(encrypted_file_path, "rb") as enc_file:
            decrypted_data = fernet.decrypt(enc_file.read())
        with open(output_path, "wb") as file:
            file.write(decrypted_data)
        print(f"File '{encrypted_filename}' decrypted successfully.")
    
    def list_files(self):
        """Lists all encrypted files in the vault."""
        files = [f for f in os.listdir(self.vault_path) if f.endswith(".enc")]
        return files
    
    def save_metadata(self, file_path):
        """Saves metadata of encrypted files."""
        metadata = self.load_metadata()
        filename = os.path.basename(file_path)
        metadata[filename] = {
            "original_size": os.path.getsize(file_path),
            "hash": self.compute_file_hash(file_path)
        }
        with open(self.metadata_file, "w") as meta_file:
            json.dump(metadata, meta_file, indent=4)
    
    def load_metadata(self):
        """Loads the vault metadata."""
        if os.path.exists(self.metadata_file):
            with open(self.metadata_file, "r") as meta_file:
                return json.load(meta_file)
        return {}
    
    def compute_file_hash(self, file_path):
        """Computes a SHA-256 hash of the given file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as file:
            while chunk := file.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()
    
    def verify_integrity(self, filename):
        """Verifies if an encrypted file has been tampered with."""
        metadata = self.load_metadata()
        if filename not in metadata:
            print("No metadata found for this file.")
            return False
        encrypted_file_path = os.path.join(self.vault_path, filename)
        computed_hash = self.compute_file_hash(encrypted_file_path)
        if computed_hash == metadata[filename]["hash"]:
            print("File integrity verified: No tampering detected.")
            return True
        else:
            print("WARNING: File integrity compromised!")
            return False
    
if __name__ == "__main__":
    vault = SecureFileVault()
    
    while True:
        print("\nSecure File Vault")
        print("1. Encrypt and Store File")
        print("2. Decrypt File")
        print("3. List Encrypted Files")
        print("4. Verify File Integrity")
        print("5. Exit")
        
        choice = input("Choose an option: ")
        
        if choice == "1":
            file_path = input("Enter file path to encrypt: ")
            vault.encrypt_file(file_path)
        elif choice == "2":
            encrypted_file = input("Enter encrypted file name: ")
            output_path = input("Enter output path to save decrypted file: ")
            vault.decrypt_file(encrypted_file, output_path)
        elif choice == "3":
            print("Encrypted Files:", vault.list_files())
        elif choice == "4":
            filename = input("Enter encrypted file name to verify: ")
            vault.verify_integrity(filename)
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please try again.")
