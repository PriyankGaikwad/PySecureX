import secrets
import string
import hmac
import base64
import time
import os
import json
import re
from typing import Dict, Optional, Union
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pyotp
import keyring

def generate_strong_password(
    length: int = 16, 
    use_uppercase: bool = True, 
    use_lowercase: bool = True, 
    use_digits: bool = True, 
    use_special: bool = True
) -> str:
    """
    Generate a cryptographically secure random password with customizable complexity.
    
    Args:
        length (int, optional): Length of the password. Defaults to 16.
        use_uppercase (bool, optional): Include uppercase letters. Defaults to True.
        use_lowercase (bool, optional): Include lowercase letters. Defaults to True.
        use_digits (bool, optional): Include digits. Defaults to True.
        use_special (bool, optional): Include special characters. Defaults to True.
        
    Returns:
        str: A randomly generated password matching the specified criteria.
        
    Raises:
        ValueError: If no character set is selected or length is less than 8.
        
    Example:
        >>> generate_strong_password(length=20, use_special=False)
        'tB7DpL2HrJq9Nz5KxF8X'
    """
    if length < 8:
        raise ValueError("Password length should be at least 8 characters for security")
    
    character_sets = []
    if use_uppercase:
        character_sets.append(string.ascii_uppercase)
    if use_lowercase:
        character_sets.append(string.ascii_lowercase)
    if use_digits:
        character_sets.append(string.digits)
    if use_special:
        character_sets.append("!@#$%^&*()_+-=[]{}|;:,.<>?")
    
    if not character_sets:
        raise ValueError("At least one character set must be selected")
    
    all_chars = ''.join(character_sets)
    
    password = []
    for char_set in character_sets:
        password.append(secrets.choice(char_set))
    
    while len(password) < length:
        password.append(secrets.choice(all_chars))
    
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

def check_password_strength(password: str) -> Dict[str, Union[int, bool, str]]:
    """
    Evaluate the strength of a password based on various criteria.
    
    Args:
        password (str): The password to evaluate.
        
    Returns:
        Dict[str, Union[int, bool, str]]: Dictionary containing:
            - score (int): Strength score from 0-100
            - strength (str): Descriptive strength ('Weak', 'Moderate', 'Strong', 'Very Strong')
            - has_uppercase (bool): Contains uppercase letters
            - has_lowercase (bool): Contains lowercase letters
            - has_digits (bool): Contains digits
            - has_special (bool): Contains special characters
            - length_sufficient (bool): Length >= 12
            - weaknesses (List[str]): List of identified weaknesses
            
    Example:
        >>> check_password_strength("Passw0rd!")
        {
            'score': 65, 
            'strength': 'Moderate', 
            'has_uppercase': True, 
            'has_lowercase': True, 
            'has_digits': True, 
            'has_special': True, 
            'length_sufficient': False, 
            'weaknesses': ['Password is too short (< 12 characters)', 'Contains common password pattern']
        }
    """
    result = {
        'has_uppercase': bool(re.search(r'[A-Z]', password)),
        'has_lowercase': bool(re.search(r'[a-z]', password)),
        'has_digits': bool(re.search(r'[0-9]', password)),
        'has_special': bool(re.search(r'[^A-Za-z0-9]', password)),
        'length_sufficient': len(password) >= 12,
        'weaknesses': []
    }
    
    score = 0
    if result['has_uppercase']:
        score += 10
    if result['has_lowercase']:
        score += 10
    if result['has_digits']:
        score += 10
    if result['has_special']:
        score += 15
    
    length_score = min(30, len(password) * 2)
    score += length_score
    
    if len(password) < 12:
        result['weaknesses'].append("Password is too short (< 12 characters)")
    
    common_patterns = [
        r'123456', r'password', r'qwerty', r'admin', r'welcome',
        r'abc123', r'letmein', r'monkey', r'1234', r'12345',
        r'111111', r'1q2w3e', r'000000', r'iloveyou', r'1234567',
        r'1234567890', r'password1'
    ]
    
    for pattern in common_patterns:
        if re.search(pattern, password.lower()):
            result['weaknesses'].append("Contains common password pattern")
            score -= 30
            break
    
    for seq_type in [string.ascii_lowercase, string.ascii_uppercase, string.digits]:
        for i in range(len(seq_type) - 2):
            if seq_type[i:i+3] in password:
                result['weaknesses'].append("Contains sequential characters")
                score -= 10
                break
    
    keyboard_rows = [
        "qwertyuiop", "asdfghjkl", "zxcvbnm",
        "1234567890"
    ]
    
    for row in keyboard_rows:
        for i in range(len(row) - 2):
            if row[i:i+3].lower() in password.lower():
                result['weaknesses'].append("Contains keyboard pattern")
                score -= 10
                break
    
    if re.search(r'(.)\1{2,}', password):
        result['weaknesses'].append("Contains repeating characters")
        score -= 15
    
    score = max(0, min(100, score))
    result['score'] = score
    
    if score < 50:
        result['strength'] = 'Weak'
    elif score < 75:
        result['strength'] = 'Moderate'
    elif score < 90:
        result['strength'] = 'Strong'
    else:
        result['strength'] = 'Very Strong'
    
    return result

def store_password_securely(username: str, password: str, service_name: str = "default") -> Dict[str, bytes]:
    """
    Store a password securely with salt and PBKDF2 hashing.
    
    Args:
        username (str): Username or identifier for the password.
        password (str): The password to store.
        service_name (str, optional): Service or application identifier. Defaults to "default".
        
    Returns:
        Dict[str, bytes]: Dictionary containing:
            - salt: Random salt used for hashing
            - hash: The hashed password
            - service: Service name
            - username: Username
            
    Example:
        >>> stored = store_password_securely("john_doe", "SecurePass123!")
        >>> isinstance(stored['salt'], bytes) and isinstance(stored['hash'], bytes)
        True
    """
    salt = os.urandom(32)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    password_hash = kdf.derive(password.encode())
    
    return {
        'salt': salt,
        'hash': password_hash,
        'service': service_name.encode(),
        'username': username.encode()
    }

def verify_stored_password(password: str, stored_credentials: Dict[str, bytes]) -> bool:
    """
    Verify a password against stored credentials.
    
    Args:
        password (str): The password to verify.
        stored_credentials (Dict[str, bytes]): The stored credentials from store_password_securely.
        
    Returns:
        bool: True if the password matches, False otherwise.
        
    Example:
        >>> stored = store_password_securely("john_doe", "SecurePass123!")
        >>> verify_stored_password("SecurePass123!", stored)
        True
        >>> verify_stored_password("WrongPassword", stored)
        False
    """
    salt = stored_credentials['salt']
    stored_hash = stored_credentials['hash']
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    try:
        test_hash = kdf.derive(password.encode())
        return hmac.compare_digest(test_hash, stored_hash)
    except Exception:
        return False

def setup_two_factor_auth(username: str, issuer_name: str = "MyApp") -> Dict[str, str]:
    """
    Set up two-factor authentication for a user.
    
    Args:
        username (str): Username or identifier for the user.
        issuer_name (str, optional): Name of the service/application. Defaults to "MyApp".
        
    Returns:
        Dict[str, str]: Dictionary containing:
            - secret: Base32 encoded secret key
            - uri: URI for QR code generation
            - username: Username
            - issuer: Issuer name
            
    Example:
        >>> tfa = setup_two_factor_auth("alice@example.com", "SecureApp")
        >>> len(tfa['secret'])
        32
        >>> tfa['uri'].startswith('otpauth://totp/')
        True
    """
    secret = pyotp.random_base32()
    
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(username, issuer_name=issuer_name)
    
    return {
        'secret': secret,
        'uri': uri,
        'username': username,
        'issuer': issuer_name
    }

def generate_totp(secret: str, interval: int = 30) -> str:
    """
    Generate a Time-Based One-Time Password (TOTP).
    
    Args:
        secret (str): The base32 encoded secret key.
        interval (int, optional): Time interval in seconds. Defaults to 30.
        
    Returns:
        str: Current TOTP code.
        
    Example:
        >>> secret = pyotp.random_base32()
        >>> totp = generate_totp(secret)
        >>> len(totp)
        6
        >>> totp.isdigit()
        True
    """
    totp = pyotp.TOTP(secret, interval=interval)
    return totp.now()

def verify_totp(secret: str, code: str, interval: int = 30, window: int = 1) -> bool:
    """
    Verify a Time-Based One-Time Password (TOTP).
    
    Args:
        secret (str): The base32 encoded secret key.
        code (str): The TOTP code to verify.
        interval (int, optional): Time interval in seconds. Defaults to 30.
        window (int, optional): Number of intervals to check before and after. Defaults to 1.
        
    Returns:
        bool: True if the code is valid, False otherwise.
        
    Example:
        >>> secret = pyotp.random_base32()
        >>> code = generate_totp(secret)
        >>> verify_totp(secret, code)
        True
    """
    totp = pyotp.TOTP(secret, interval=interval)
    return totp.verify(code, valid_window=window)

def generate_hotp(secret: str, counter: int) -> str:
    """
    Generate an HMAC-Based One-Time Password (HOTP).
    
    Args:
        secret (str): The base32 encoded secret key.
        counter (int): Counter value for the HOTP.
        
    Returns:
        str: HOTP code.
        
    Example:
        >>> secret = pyotp.random_base32()
        >>> hotp = generate_hotp(secret, 1)
        >>> len(hotp)
        6
        >>> hotp.isdigit()
        True
    """
    hotp = pyotp.HOTP(secret)
    return hotp.at(counter)

def verify_hotp(secret: str, code: str, counter: int, window: int = 1) -> Optional[int]:
    """
    Verify an HMAC-Based One-Time Password (HOTP).
    
    Args:
        secret (str): The base32 encoded secret key.
        code (str): The HOTP code to verify.
        counter (int): Current counter value.
        window (int, optional): Look-ahead window. Defaults to 1.
        
    Returns:
        Optional[int]: New counter value if valid, None if invalid.
        
    Example:
        >>> secret = pyotp.random_base32()
        >>> code = generate_hotp(secret, 5)
        >>> verify_hotp(secret, code, 5)
        6
    """
    hotp = pyotp.HOTP(secret)
    result = hotp.verify(code, counter, window)
    
    if result is not None:
        return result
    return None

def store_api_key(service_name: str, username: str, api_key: str) -> bool:
    """
    Securely store an API key using the system's keyring.
    
    Args:
        service_name (str): Name of the service the API key belongs to.
        username (str): Username or identifier for the API key.
        api_key (str): The API key to store.
        
    Returns:
        bool: True if stored successfully, False otherwise.
        
    Example:
        >>> store_api_key("GitHub", "dev_account", "ghp_1234567890abcdef")
        True
    """
    try:
        keyring.set_password(service_name, username, api_key)
        return True
    except Exception:
        return False

def retrieve_api_key(service_name: str, username: str) -> Optional[str]:
    """
    Retrieve a stored API key from the system's keyring.
    
    Args:
        service_name (str): Name of the service the API key belongs to.
        username (str): Username or identifier for the API key.
        
    Returns:
        Optional[str]: The API key if found, None otherwise.
        
    Example:
        >>> # Assuming a key was previously stored
        >>> api_key = retrieve_api_key("GitHub", "dev_account")
        >>> isinstance(api_key, str)
        True
    """
    try:
        return keyring.get_password(service_name, username)
    except Exception:
        return None

def encrypt_password_vault(vault_data: Dict[str, Dict], master_password: str) -> Dict[str, Union[bytes, str]]:
    """
    Encrypt a password vault using a master password.
    
    Args:
        vault_data (Dict[str, Dict]): Dictionary of service name to credentials.
        master_password (str): Master password for encrypting the vault.
        
    Returns:
        Dict[str, Union[bytes, str]]: Dictionary containing:
            - salt: Salt used for key derivation
            - encrypted_vault: Encrypted vault data
            
    Example:
        >>> vault = {
        ...     "gmail": {"username": "user@gmail.com", "password": "pass123"},
        ...     "github": {"username": "gituser", "password": "gitpass"}
        ... }
        >>> encrypted = encrypt_password_vault(vault, "MasterPassword123!")
        >>> isinstance(encrypted['salt'], bytes) and isinstance(encrypted['encrypted_vault'], bytes)
        True
    """
    salt = os.urandom(16)
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
    
    cipher = Fernet(key)
    
    serialized_vault = json.dumps(vault_data).encode()
    encrypted_vault = cipher.encrypt(serialized_vault)
    
    return {
        'salt': salt,
        'encrypted_vault': encrypted_vault
    }

def decrypt_password_vault(encrypted_vault: Dict[str, Union[bytes, str]], master_password: str) -> Optional[Dict]:
    """
    Decrypt a password vault using the master password.
    
    Args:
        encrypted_vault (Dict[str, Union[bytes, str]]): Dictionary containing salt and encrypted vault.
        master_password (str): Master password for decrypting the vault.
        
    Returns:
        Optional[Dict]: Decrypted vault data if successful, None otherwise.
        
    Example:
        >>> vault = {
        ...     "gmail": {"username": "user@gmail.com", "password": "pass123"},
        ...     "github": {"username": "gituser", "password": "gitpass"}
        ... }
        >>> encrypted = encrypt_password_vault(vault, "MasterPassword123!")
        >>> decrypted = decrypt_password_vault(encrypted, "MasterPassword123!")
        >>> decrypted == vault
        True
    """
    try:
        salt = encrypted_vault['salt']
        encrypted_data = encrypted_vault['encrypted_vault']
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
        
        cipher = Fernet(key)
        
        decrypted_data = cipher.decrypt(encrypted_data)
        
        return json.loads(decrypted_data.decode())
    except Exception:
        return None

def auto_fill_password(service_name: str, username: str, vault: Dict[str, Dict]) -> Optional[str]:
    """
    Retrieve a password from the vault for auto-filling.
    
    This function securely retrieves passwords for auto-fill functionality.
    In a real implementation, this would interact with browser extensions or system APIs.
    
    Args:
        service_name (str): Name of the service/website.
        username (str): Username to look up.
        vault (Dict[str, Dict]): Decrypted password vault.
        
    Returns:
        Optional[str]: Password if found, None otherwise.
        
    Example:
        >>> vault = {
        ...     "example.com": {"username": "testuser", "password": "SecurePass123!"}
        ... }
        >>> auto_fill_password("example.com", "testuser", vault)
        'SecurePass123!'
        >>> auto_fill_password("nonexistent.com", "testuser", vault) is None
        True
    """
    try:
        if service_name in vault and vault[service_name]["username"] == username:
            return vault[service_name]["password"]
        return None
    except (KeyError, TypeError):
        return None

def generate_password_reset_token(user_id: str, expiry_seconds: int = 3600) -> Dict[str, Union[str, int]]:
    """
    Generate a secure token for password reset functionality.
    
    Args:
        user_id (str): User identifier.
        expiry_seconds (int, optional): Seconds until token expires. Defaults to 3600 (1 hour).
        
    Returns:
        Dict[str, Union[str, int]]: Dictionary containing:
            - token: Secure token string
            - expires_at: Expiry timestamp
            - user_id: User identifier
            
    Example:
        >>> token_info = generate_password_reset_token("user123")
        >>> isinstance(token_info['token'], str) and len(token_info['token']) > 20
        True
        >>> token_info['expires_at'] > time.time()
        True
    """
    token = secrets.token_urlsafe(32)
    
    expires_at = int(time.time() + expiry_seconds)
    
    return {
        'token': token,
        'expires_at': expires_at,
        'user_id': user_id
    }

def verify_password_reset_token(token_info: Dict[str, Union[str, int]], token: str) -> bool:
    """
    Verify a password reset token.
    
    Args:
        token_info (Dict[str, Union[str, int]]): Token information from generate_password_reset_token.
        token (str): Token to verify.
        
    Returns:
        bool: True if token is valid and not expired, False otherwise.
        
    Example:
        >>> token_info = generate_password_reset_token("user123", expiry_seconds=5)
        >>> verify_password_reset_token(token_info, token_info['token'])
        True
        >>> time.sleep(6)  # Wait for token to expire
        >>> verify_password_reset_token(token_info, token_info['token'])
        False
    """
    current_time = time.time()
    
    return (token == token_info['token'] and 
            current_time < token_info['expires_at'])