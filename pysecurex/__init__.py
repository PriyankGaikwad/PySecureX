from .encryption import (
    aes_encrypt, aes_decrypt,
    generate_rsa_key_pair, rsa_encrypt, rsa_decrypt,
    hybrid_encrypt, hybrid_decrypt,
    chacha20_encrypt, chacha20_decrypt,
    blowfish_encrypt, blowfish_decrypt,
    des3_encrypt, des3_decrypt
)

from .hashing import (
    sha256_hash, md5_hash,
    hmac_hash, file_integrity_check,
    generate_salted_hash, verify_password_hash,
    pbkdf2_key_derivation, argon2_key_derivation,
    hash_large_file, check_file_tampering,
    securely_erase_file, file_metadata_protection
)

from .password_tools import (
    generate_strong_password, check_password_strength,
    store_password_securely, verify_stored_password,
    setup_two_factor_auth, generate_totp, verify_totp,
    generate_hotp, verify_hotp,
    store_api_key, retrieve_api_key,
    encrypt_password_vault, decrypt_password_vault,
    auto_fill_password
)

from .steganography import (
    hide_text_in_image, extract_text_from_image,
    hide_text_in_audio, extract_text_from_audio,
    hide_file_in_image, extract_file_from_image,
    invisible_watermark, encrypt_and_hide_data_in_pdf
)

from .network_security import (
    check_ssl_certificate, detect_mitm_attack,
    encrypt_message_aes_gcm, encrypt_file_aes,
    validate_ssl_cert, dns_over_https_lookup,
    secure_web_scrape, ip_geolocation,
    scan_open_ports, detect_arp_spoofing,
    tor_request,

)

from .post_quantum import (
    kyber_key_exchange, dilithium_sign, dilithium_verify,
    falcon_sign, falcon_verify, hybrid_pqc_aes_encrypt,
    hybrid_pqc_aes_decrypt,
)

from .utils import (
    process_data_multithreaded, process_data_multiprocessing, process_data,
    secure_password_prompt
)

__all__ = [
    # Encryption functions
    "aes_encrypt", "aes_decrypt",
    "generate_rsa_key_pair", "rsa_encrypt", "rsa_decrypt",
    "hybrid_encrypt", "hybrid_decrypt",
    "chacha20_encrypt", "chacha20_decrypt",
    "blowfish_encrypt", "blowfish_decrypt",
    "des3_encrypt", "des3_decrypt",
    
    # Hashing and security functions
    "sha256_hash", "md5_hash",
    "hmac_hash", "file_integrity_check",
    "generate_salted_hash", "verify_password_hash", 
    "pbkdf2_key_derivation", "argon2_key_derivation",
    "hash_large_file", "check_file_tampering",
    "securely_erase_file", "file_metadata_protection",

    # Password management and authentication
    "generate_strong_password", "check_password_strength",
    "store_password_securely", "verify_stored_password",
    "setup_two_factor_auth", "generate_totp", "verify_totp",
    "generate_hotp", "verify_hotp",
    "store_api_key", "retrieve_api_key",
    "encrypt_password_vault", "decrypt_password_vault",
    "auto_fill_password",

    # Steganography functions
    "hide_text_in_image", "extract_text_from_image",
    "hide_text_in_audio", "extract_text_from_audio",
    "hide_file_in_image", "extract_file_from_image",
    "invisible_watermark", "encrypt_and_hide_data_in_pdf",

    # Network security functions
    "check_ssl_certificate", "detect_mitm_attack",
    "encrypt_message_aes_gcm", "encrypt_file_aes",
    "validate_ssl_cert", "dns_over_https_lookup",
    "secure_web_scrape", "ip_geolocation",
    "scan_open_ports", "detect_arp_spoofing",
    "tor_request",

    # Post-Quantum Cryptography
    "kyber_key_exchange", "dilithium_sign", "dilithium_verify",
    "falcon_sign", "falcon_verify", "hybrid_pqc_aes_encrypt",
    "hybrid_pqc_aes_decrypt", "pqc_digital_certificate",

    # Utility functions
    "process_data_multithreaded", "process_data_multiprocessing", "process_data",
    "secure_password_prompt"
]
