import argparse
import os
import json
from pysecurex.encryption import aes_encrypt, aes_decrypt, rsa_encrypt, rsa_decrypt, hybrid_encrypt, hybrid_decrypt
from pysecurex.hashing import (
    sha256_hash, md5_hash, hmac_hash, file_integrity_check, 
    verify_password_hash, pbkdf2_key_derivation, argon2_key_derivation, 
    hash_large_file, check_file_tampering, securely_erase_file, file_metadata_protection
)
from pysecurex.password_tools import generate_strong_password, check_password_strength
from pysecurex.network_security import check_ssl_certificate, detect_mitm_attack
from pysecurex.steganography import (
    hide_text_in_image, extract_text_from_image,
    hide_text_in_audio, extract_text_from_audio,
    hide_file_in_image, extract_file_from_image,
    invisible_watermark, encrypt_and_hide_data_in_pdf
)
from pysecurex.post_quantum import (
    kyber_key_exchange, dilithium_sign, dilithium_verify,
    falcon_sign, falcon_verify, hybrid_pqc_aes_encrypt,
    hybrid_pqc_aes_decrypt
)
from pysecurex.ai_threat_detection import ThreatDetectionSystem
from getpass import getpass

VAULT_PATH = "secure_vault.json"

def initialize_vault():
    """Initialize an empty secure file vault if not already present."""
    if not os.path.exists(VAULT_PATH):
        with open(VAULT_PATH, "w") as vault_file:
            json.dump({}, vault_file)

def encrypt_and_store_file(filepath, password):
    """Encrypt and store a file securely in the vault."""
    if not os.path.exists(filepath):
        print("Error: File not found.")
        return

    with open(filepath, "rb") as f:
        file_data = f.read()

    encrypted_data, iv, tag = aes_encrypt(file_data, password.encode())
    filename_hash = sha256_hash(os.path.basename(filepath))  # Encrypt metadata

    initialize_vault()
    with open(VAULT_PATH, "r+") as vault_file:
        vault = json.load(vault_file)
        vault[filename_hash] = {"data": encrypted_data.hex(), "iv": iv.hex(), "tag": tag.hex()}
        vault_file.seek(0)
        vault_file.truncate()
        json.dump(vault, vault_file)

    print(f"File '{filepath}' encrypted and stored securely.")

def retrieve_and_decrypt_file(filename, password):
    """Retrieve and decrypt a file from the secure vault."""
    filename_hash = sha256_hash(filename)

    initialize_vault()
    with open(VAULT_PATH, "r") as vault_file:
        vault = json.load(vault_file)

    if filename_hash not in vault:
        print("Error: File not found in vault.")
        return

    encrypted_info = vault[filename_hash]
    decrypted_data = aes_decrypt(
        bytes.fromhex(encrypted_info["data"]),
        password.encode(),
        bytes.fromhex(encrypted_info["iv"]),
        bytes.fromhex(encrypted_info["tag"])
    )

    output_filename = f"decrypted_{filename}"
    with open(output_filename, "wb") as f:
        f.write(decrypted_data)

    print(f"File decrypted successfully and saved as '{output_filename}'.")

def delete_secure_file(filename):
    """Securely delete a file from the vault."""
    filename_hash = sha256_hash(filename)

    initialize_vault()
    with open(VAULT_PATH, "r+") as vault_file:
        vault = json.load(vault_file)

        if filename_hash not in vault:
            print("Error: File not found in vault.")
            return

        del vault[filename_hash]
        vault_file.seek(0)
        vault_file.truncate()
        json.dump(vault, vault_file)

    print(f"File '{filename}' securely deleted from vault.")

def main():
    """Main function for command-line usage"""
    parser = argparse.ArgumentParser(description="PySecureX CLI - Secure Encryption, Hashing, Network Security, and AI Threat Detection Tool")
    subparsers = parser.add_subparsers(dest="command", help="Available Commands")

    # Secure File Vault Commands
    vault_parser = subparsers.add_parser("vault", help="Secure File Vault")
    vault_parser.add_argument("--store", help="Encrypt and store a file")
    vault_parser.add_argument("--retrieve", help="Retrieve and decrypt a file")
    vault_parser.add_argument("--delete", help="Securely delete a file")

    # Encryption Commands
    enc_parser = subparsers.add_parser("encrypt", help="Encrypt data")
    enc_parser.add_argument("--data", required=True, help="Data to encrypt")
    enc_parser.add_argument("--method", choices=["aes", "rsa", "hybrid"], required=True, help="Encryption method")
    enc_parser.add_argument("--key", required=True, help="Encryption key (or RSA public key)")

    # Decryption Commands
    dec_parser = subparsers.add_parser("decrypt", help="Decrypt data")
    dec_parser.add_argument("--data", required=True, help="Data to decrypt")
    dec_parser.add_argument("--method", choices=["aes", "rsa", "hybrid"], required=True, help="Decryption method")
    dec_parser.add_argument("--key", required=True, help="Decryption key (or RSA private key)")
    dec_parser.add_argument("--iv", help="Initialization vector (for AES)")
    dec_parser.add_argument("--tag", help="Authentication tag (for AES)")

    # Hashing Commands
    hash_parser = subparsers.add_parser("hash", help="Generate hash")
    hash_subparsers = hash_parser.add_subparsers(dest="hash_command", help="Hashing operations")
    
    # Basic hash commands
    basic_hash_parser = hash_subparsers.add_parser("basic", help="Basic hashing functions")
    basic_hash_parser.add_argument("--data", help="Data to hash")
    basic_hash_parser.add_argument("--file", help="File to hash")
    basic_hash_parser.add_argument("--method", choices=["sha256", "md5"], required=True, help="Hashing method")
    
    # HMAC hash command
    hmac_parser = hash_subparsers.add_parser("hmac", help="HMAC hashing")
    hmac_parser.add_argument("--message", required=True, help="Message to authenticate")
    hmac_parser.add_argument("--key", required=True, help="Secret key for HMAC")
    
    # File integrity commands
    file_integrity_parser = hash_subparsers.add_parser("file-integrity", help="Check file integrity")
    file_integrity_parser.add_argument("--file", required=True, help="File to check")
    
    # Large file hash command
    large_file_parser = hash_subparsers.add_parser("large-file", help="Hash large files")
    large_file_parser.add_argument("--file", required=True, help="Large file to hash")
    large_file_parser.add_argument("--chunk-size", type=int, default=65536, help="Chunk size in bytes")
    
    # Password hashing commands
    password_hash_parser = hash_subparsers.add_parser("password", help="Password hashing functions")
    password_hash_parser.add_argument("--action", choices=["generate", "verify"], required=True, help="Action to perform")
    password_hash_parser.add_argument("--password", required=True, help="Password to hash or verify")
    password_hash_parser.add_argument("--hash", help="Hash value (for verification)")
    password_hash_parser.add_argument("--salt", help="Salt value (for verification)")
    password_hash_parser.add_argument("--method", choices=["pbkdf2", "argon2"], default="pbkdf2", help="Hashing method")
    
    # File tampering check command
    tampering_parser = hash_subparsers.add_parser("check-tampering", help="Check file tampering")
    tampering_parser.add_argument("--file", required=True, help="File to check")
    tampering_parser.add_argument("--signature", required=True, help="Signature file")
    tampering_parser.add_argument("--public-key", required=True, help="Public key file")
    
    # Secure file erasure command
    secure_erase_parser = hash_subparsers.add_parser("secure-erase", help="Securely erase files")
    secure_erase_parser.add_argument("--file", required=True, help="File to securely erase")
    secure_erase_parser.add_argument("--passes", type=int, default=3, help="Number of overwrite passes")
    
    # File metadata protection command
    metadata_parser = hash_subparsers.add_parser("metadata-protection", help="Protect file metadata")
    metadata_parser.add_argument("--file", required=True, help="File to protect")

    # Password Commands
    pass_parser = subparsers.add_parser("password", help="Generate and check password strength")
    pass_parser.add_argument("--generate", action="store_true", help="Generate a strong password")
    pass_parser.add_argument("--check", help="Check password strength")

    # Network Security Commands
    net_parser = subparsers.add_parser("network", help="Network security tools")
    net_parser.add_argument("--ssl", help="Check SSL certificate of a domain")
    net_parser.add_argument("--mitm", help="Detect MITM attacks on network interface")

    # Steganography Commands
    stego_parser = subparsers.add_parser("stego", help="Steganography tools")
    stego_subparsers = stego_parser.add_subparsers(dest="stego_command", help="Steganography operations")
    
    # Image text steganography
    hide_img_text_parser = stego_subparsers.add_parser("hide-text-image", help="Hide text in an image")
    hide_img_text_parser.add_argument("--image", required=True, help="Source image file")
    hide_img_text_parser.add_argument("--message", required=True, help="Text to hide")
    hide_img_text_parser.add_argument("--output", required=True, help="Output image file")
    
    extract_img_text_parser = stego_subparsers.add_parser("extract-text-image", help="Extract hidden text from an image")
    extract_img_text_parser.add_argument("--image", required=True, help="Image file with hidden text")
    
    # Audio text steganography
    hide_audio_text_parser = stego_subparsers.add_parser("hide-text-audio", help="Hide text in an audio file")
    hide_audio_text_parser.add_argument("--audio", required=True, help="Source audio file")
    hide_audio_text_parser.add_argument("--message", required=True, help="Text to hide")
    hide_audio_text_parser.add_argument("--output", required=True, help="Output audio file")
    
    extract_audio_text_parser = stego_subparsers.add_parser("extract-text-audio", help="Extract hidden text from an audio file")
    extract_audio_text_parser.add_argument("--audio", required=True, help="Audio file with hidden text")
    
    # File in image steganography
    hide_file_parser = stego_subparsers.add_parser("hide-file", help="Hide a file inside an image")
    hide_file_parser.add_argument("--image", required=True, help="Source image file")
    hide_file_parser.add_argument("--file", required=True, help="File to hide")
    hide_file_parser.add_argument("--output", required=True, help="Output image file")
    
    extract_file_parser = stego_subparsers.add_parser("extract-file", help="Extract a hidden file from an image")
    extract_file_parser.add_argument("--image", required=True, help="Image file with hidden file")
    extract_file_parser.add_argument("--output", required=True, help="Path to save extracted file")
    
    # Watermark
    watermark_parser = stego_subparsers.add_parser("watermark", help="Apply an invisible watermark to an image")
    watermark_parser.add_argument("--image", required=True, help="Source image file")
    watermark_parser.add_argument("--watermark", required=True, help="Watermark text")
    watermark_parser.add_argument("--output", required=True, help="Output image file")
    
    # PDF steganography
    pdf_parser = stego_subparsers.add_parser("pdf", help="Encrypt and hide data in a PDF file")
    pdf_parser.add_argument("--action", choices=["hide", "extract"], required=True, help="Action to perform")
    pdf_parser.add_argument("--pdf", required=True, help="Source PDF file")
    pdf_parser.add_argument("--data", help="Data to hide (for hide action)")
    pdf_parser.add_argument("--password", help="Password for encryption")
    pdf_parser.add_argument("--output", help="Output PDF file (for hide action)")

    # Post-Quantum Cryptography
    pqc_parser = subparsers.add_parser("pqc", help="Post-Quantum Cryptography")
    pqc_subparsers = pqc_parser.add_subparsers(dest="pqc_command", help="PQC operations")
    
    # Kyber key exchange
    kyber_parser = pqc_subparsers.add_parser("kyber", help="Perform Kyber key exchange")
    
    # Dilithium signatures
    dilithium_parser = pqc_subparsers.add_parser("dilithium", help="Use Dilithium digital signatures")
    dilithium_parser.add_argument("--action", choices=["sign", "verify"], required=True, help="Sign or verify")
    dilithium_parser.add_argument("--data", required=True, help="Data to sign or verify")
    dilithium_parser.add_argument("--signature", help="Signature to verify (only for verify)")
    
    # Falcon signatures
    falcon_parser = pqc_subparsers.add_parser("falcon", help="Use Falcon digital signatures")
    falcon_parser.add_argument("--action", choices=["sign", "verify"], required=True, help="Sign or verify")
    falcon_parser.add_argument("--data", required=True, help="Data to sign or verify")
    falcon_parser.add_argument("--signature", help="Signature to verify (only for verify)")
    
    # Hybrid PQC+AES
    hybrid_parser = pqc_subparsers.add_parser("hybrid", help="Hybrid PQC + AES encryption")
    hybrid_parser.add_argument("--action", choices=["encrypt", "decrypt"], required=True, help="Encrypt or decrypt")
    hybrid_parser.add_argument("--data", required=True, help="Data to encrypt or decrypt")

    # AI Threat Detection Commands
    ai_parser = subparsers.add_parser("ai", help="AI Threat Detection System")
    ai_parser.add_argument("--pcap", help="Path to PCAP file for network traffic analysis")
    ai_parser.add_argument("--file", help="Path to file for malware analysis")
    ai_parser.add_argument("--directory", help="Path to directory for scanning")
    ai_parser.add_argument("--log", help="Path to log file for analysis")
    ai_parser.add_argument("--train", action="store_true", help="Train AI models for threat detection")

    args = parser.parse_args()

    # Handle case when no command is provided
    if not args.command:
        parser.print_help()
        return

    # Vault operations
    if args.command == "vault":
        password = getpass("Enter vault password: ")
        if args.store:
            encrypt_and_store_file(args.store, password)
        elif args.retrieve:
            retrieve_and_decrypt_file(args.retrieve, password)
        elif args.delete:
            delete_secure_file(args.delete)
        else:
            vault_parser.print_help()

    # Encryption operations
    elif args.command == "encrypt":
        if args.method == "aes":
            encrypted, iv, tag = aes_encrypt(args.data.encode(), args.key.encode())
            print(f"Encrypted Data: {encrypted.hex()} | IV: {iv.hex()} | Tag: {tag.hex()}")
        elif args.method == "rsa":
            encrypted = rsa_encrypt(args.data.encode(), args.key)
            print(f"Encrypted Data: {encrypted.hex()}")
        elif args.method == "hybrid":
            encrypted = hybrid_encrypt(args.data.encode(), args.key)
            print(f"Encrypted Data: {encrypted}")

    # Decryption operations
    elif args.command == "decrypt":
        if args.method == "aes":
            if not args.iv or not args.tag:
                print("Error: AES decryption requires --iv and --tag parameters")
                return
            decrypted = aes_decrypt(bytes.fromhex(args.data), args.key.encode(), bytes.fromhex(args.iv), bytes.fromhex(args.tag))
            print(f"Decrypted Data: {decrypted.decode()}")
        elif args.method == "rsa":
            decrypted = rsa_decrypt(bytes.fromhex(args.data), args.key)
            print(f"Decrypted Data: {decrypted.decode()}")
        elif args.method == "hybrid":
            decrypted = hybrid_decrypt(eval(args.data), args.key)
            print(f"Decrypted Data: {decrypted.decode()}")

    elif args.command == "hash":
        if args.hash_command == "basic":
            if args.data:
                if args.method == "sha256":
                    print(f"SHA-256 Hash: {sha256_hash(args.data)}")
                elif args.method == "md5":
                    print(f"MD5 Hash: {md5_hash(args.data)}")
            elif args.file:
                with open(args.file, "rb") as f:
                    file_data = f.read()
                if args.method == "sha256":
                    print(f"SHA-256 File Hash: {sha256_hash(file_data)}")
                elif args.method == "md5":
                    print(f"MD5 File Hash: {md5_hash(file_data)}")

        elif args.hash_command == "hmac":
            hmac_value = hmac_hash(args.message, args.key)
            print(f"HMAC Hash: {hmac_value}")

        elif args.hash_command == "file-integrity":
            integrity_check = file_integrity_check(args.file)
            if integrity_check:
                print(f"File '{args.file}' integrity is INTACT.")
            else:
                print(f"WARNING: File '{args.file}' has been MODIFIED.")

        elif args.hash_command == "large-file":
            large_file_hash = hash_large_file(args.file, args.chunk_size)
            print(f"Large File Hash: {large_file_hash}")

        elif args.hash_command == "password":
            if args.action == "generate":
                if args.method == "pbkdf2":
                    hashed_password, salt = pbkdf2_key_derivation(args.password)
                elif args.method == "argon2":
                    hashed_password, salt = argon2_key_derivation(args.password)
                print(f"Password Hash: {hashed_password}")
                print(f"Salt: {salt}")

            elif args.action == "verify":
                if args.method == "pbkdf2":
                    verified = verify_password_hash(args.password, args.hash, args.salt, method="pbkdf2")
                elif args.method == "argon2":
                    verified = verify_password_hash(args.password, args.hash, args.salt, method="argon2")
                print(f"Password Verification: {'MATCH' if verified else 'MISMATCH'}")

        elif args.hash_command == "check-tampering":
            tampering_status = check_file_tampering(args.file, args.signature, args.public_key)
            if tampering_status:
                print(f"File '{args.file}' is AUTHENTIC and NOT tampered.")
            else:
                print(f"ALERT: File '{args.file}' has been TAMPERED!")

        elif args.hash_command == "secure-erase":
            securely_erase_file(args.file, args.passes)
            print(f"File '{args.file}' securely erased with {args.passes} overwrite passes.")

        elif args.hash_command == "metadata-protection":
            metadata_protection_status = file_metadata_protection(args.file)
            print(f"Metadata Protection Applied: {metadata_protection_status}")

        else:
            print("Invalid hash operation. Use --help for valid options.")

    # Password operations
    elif args.command == "password":
        if args.generate:
            print(f"Generated Password: {generate_strong_password()}")
        elif args.check:
            print(f"Password Strength: {check_password_strength(args.check)}")
        else:
            pass_parser.print_help()

    # Network Security operations
    elif args.command == "network":
        if args.ssl:
            print(f"SSL Check: {check_ssl_certificate(args.ssl)}")
        elif args.mitm:
            print(f"MITM Attack Detection: {detect_mitm_attack(args.mitm)}")
        else:
            net_parser.print_help()

    # Steganography operations
    elif args.command == "stego":
        if not hasattr(args, 'stego_command') or not args.stego_command:
            stego_parser.print_help()
            return
            
        if args.stego_command == "hide-text-image":
            hide_text_in_image(args.image, args.message, args.output)
            print("✅ Text hidden in image successfully.")
            
        elif args.stego_command == "extract-text-image":
            message = extract_text_from_image(args.image)
            print(f"📜 Extracted Text from Image: {message}")
            
        elif args.stego_command == "hide-text-audio":
            hide_text_in_audio(args.audio, args.message, args.output)
            print("✅ Text hidden in audio successfully.")
            
        elif args.stego_command == "extract-text-audio":
            message = extract_text_from_audio(args.audio)
            print(f"🎵 Extracted Text from Audio: {message}")
            
        elif args.stego_command == "hide-file":
            hide_file_in_image(args.image, args.file, args.output)
            print("✅ File hidden in image successfully.")
            
        elif args.stego_command == "extract-file":
            extracted_file = extract_file_from_image(args.image, args.output)
            print(f"📂 Extracted File saved at: {extracted_file}")
            
        elif args.stego_command == "watermark":
            invisible_watermark(args.image, args.watermark, args.output)
            print("✅ Invisible watermark applied.")
            
        elif args.stego_command == "pdf":
            if args.action == "hide":
                if not all([args.data, args.password, args.output]):
                    print("❌ Error: --data, --password, and --output are required for PDF hide operation.")
                    return
                encrypt_and_hide_data_in_pdf(args.pdf, args.data, args.password, args.output)
                print("✅ Data encrypted and hidden in PDF successfully.")
            else:
                print("❌ Error: Invalid PDF action. Use --action {hide}")

    # Post-Quantum Cryptography operations
    elif args.command == "pqc":
        if not hasattr(args, 'pqc_command') or not args.pqc_command:
            pqc_parser.print_help()
            return
            
        if args.pqc_command == "kyber":
            shared_key_alice, shared_key_bob = kyber_key_exchange()
            print("Kyber key exchange completed successfully.")
            print(f"Shared key (Alice): {shared_key_alice.hex()}")
            print(f"Shared key (Bob): {shared_key_bob.hex()}")
            print("Keys match:", shared_key_alice == shared_key_bob)
            
        elif args.pqc_command == "dilithium":
            if args.action == "sign":
                signature = dilithium_sign(args.data.encode())
                print(f"Dilithium Signature: {signature.hex()}")
            elif args.action == "verify":
                if not args.signature:
                    print("Error: --signature is required for verification.")
                    return
                valid = dilithium_verify(args.data.encode(), bytes.fromhex(args.signature))
                print(f"Dilithium Signature Valid: {valid}")
            
        elif args.pqc_command == "falcon":
            if args.action == "sign":
                signature = falcon_sign(args.data.encode())
                print(f"Falcon Signature: {signature.hex()}")
            elif args.action == "verify":
                if not args.signature:
                    print("Error: --signature is required for verification.")
                    return
                valid = falcon_verify(args.data.encode(), bytes.fromhex(args.signature))
                print(f"Falcon Signature Valid: {valid}")
            
        elif args.pqc_command == "hybrid":
            if args.action == "encrypt":
                encrypted_data = hybrid_pqc_aes_encrypt(args.data.encode())
                print(f"Hybrid PQC + AES Encrypted Data: {encrypted_data.hex()}")
            elif args.action == "decrypt":
                decrypted_data = hybrid_pqc_aes_decrypt(bytes.fromhex(args.data))
                print(f"Decrypted Data: {decrypted_data.decode()}")

    # AI Threat Detection operations
    elif args.command == "ai":
        system = ThreatDetectionSystem()
        system.load_models()

        if args.pcap:
            result = system.scan_network(pcap_path=args.pcap)
            print(f"Network Scan Results: {result}")
        elif args.file:
            result = system.scan_file(args.file)
            print(f"File Scan Results: {result}")
        elif args.directory:
            result = system.scan_directory(args.directory)
            print(f"Directory Scan Results: {result}")
        elif args.log:
            result = system.analyze_logs(args.log)
            print(f"Log Analysis Results: {result}")
        elif args.train:
            print("Training AI models...")
            system.train_models()
        else:
            ai_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()