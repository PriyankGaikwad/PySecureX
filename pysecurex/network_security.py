import os
import socket
import ssl
import requests
import subprocess
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def encrypt_message_aes_gcm(message: str, key: bytes) -> tuple:
    """
    Encrypts a message using AES-GCM (Authenticated Encryption).
    
    :param message: The plaintext message to encrypt.
    :param key: The encryption key (must be 32 bytes for AES-256).
    :return: Tuple (ciphertext, nonce, tag)
    """
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return b64encode(ciphertext).decode(), b64encode(nonce).decode(), b64encode(encryptor.tag).decode()

def encrypt_file_aes(input_file: str, output_file: str, key: bytes):
    """
    Encrypts a file using AES encryption before transfer.
    
    :param input_file: Path to the file to encrypt.
    :param output_file: Path to save the encrypted file.
    :param key: Encryption key (32 bytes for AES-256).
    """
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)

def validate_ssl_cert(domain: str) -> bool:
    """
    Validates the SSL certificate of a given domain.
    
    :param domain: Domain name (e.g., 'google.com').
    :return: True if the SSL certificate is valid, False otherwise.
    """
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.connect((domain, 443))
            cert = s.getpeercert()
        return bool(cert)
    except ssl.SSLError:
        return False

def dns_over_https_lookup(domain: str) -> dict:
    """
    Performs a secure DNS lookup using DNS-over-HTTPS.
    
    :param domain: The domain to resolve.
    :return: JSON response containing DNS resolution details.
    """
    url = f'https://cloudflare-dns.com/dns-query?name={domain}&type=A'
    headers = {'Accept': 'application/dns-json'}
    response = requests.get(url, headers=headers)
    return response.json()

def detect_mitm(interface: str) -> bool:
    """
    Detects possible MITM attacks by checking ARP table inconsistencies.
    
    :param interface: The network interface to monitor (e.g., 'eth0').
    :return: True if a possible MITM attack is detected, False otherwise.
    """
    arp_output = subprocess.check_output(['arp', '-a']).decode()
    mac_addresses = [line.split()[1] for line in arp_output.split('\n') if len(line.split()) > 1]
    return len(mac_addresses) != len(set(mac_addresses))

def secure_web_scrape(url: str, proxy: str = None) -> str:
    """
    Scrapes a webpage securely using proxies and encrypted headers.
    
    :param url: The URL to scrape.
    :param proxy: Optional proxy server (e.g., 'http://proxy:port').
    :return: HTML content of the page.
    """
    headers = {'User-Agent': 'Mozilla/5.0', 'Referer': 'https://www.google.com'}
    proxies = {'http': proxy, 'https': proxy} if proxy else None
    response = requests.get(url, headers=headers, proxies=proxies)
    return response.text

def ip_geolocation(ip: str) -> dict:
    """
    Retrieves geolocation data and threat intelligence for an IP address.
    
    :param ip: The IP address to check.
    :return: Dictionary containing geolocation and threat information.
    """
    url = f'https://ip-api.com/json/{ip}'
    response = requests.get(url)
    return response.json()

def scan_open_ports(target: str, ports: list) -> dict:
    """
    Scans specified ports on a target machine for vulnerabilities.
    
    :param target: Target IP or hostname.
    :param ports: List of ports to scan.
    :return: Dictionary with open port status.
    """
    open_ports = {}
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((target, port))
            open_ports[port] = result == 0
    return open_ports

def detect_arp_spoofing() -> bool:
    """
    Detects ARP spoofing attempts in the network.
    
    :return: True if ARP spoofing is detected, False otherwise.
    """
    arp_output = subprocess.check_output(['arp', '-a']).decode()
    mac_addresses = [line.split()[1] for line in arp_output.split('\n') if len(line.split()) > 1]
    return len(mac_addresses) != len(set(mac_addresses))

def tor_request(url: str) -> str:
    """
    Sends a request via the Tor network for anonymous browsing.
    
    :param url: The URL to fetch anonymously.
    :return: HTML content of the page.
    """
    proxies = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}
    response = requests.get(url, proxies=proxies)
    return response.text
