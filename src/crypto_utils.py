"""
Common cryptographic helpers: AES encrypt/decrypt, RSA key wrap/unwrap.
Uses PyCryptodome.
"""
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import os

KEYS_DIR = os.path.join(os.path.dirname(__file__), '..', 'keys')
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR, exist_ok=True)

def generate_rsa_keypair(bits: int = 2048, priv_path: str = None, pub_path: str = None):
    key = RSA.generate(bits)
    priv = key.export_key()
    pub = key.publickey().export_key()

    if priv_path is None:
        priv_path = os.path.join(KEYS_DIR, 'private.pem')
    if pub_path is None:
        pub_path = os.path.join(KEYS_DIR, 'public.pem')

    with open(priv_path, 'wb') as f:
        f.write(priv)
    with open(pub_path, 'wb') as f:
        f.write(pub)

    return priv_path, pub_path

def load_rsa_public_key(path: str):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def load_rsa_private_key(path: str):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def aes_encrypt_bytes(plaintext: bytes, key: bytes = None):
    """Encrypt bytes with AES-EAX. Returns (aes_key, nonce, tag, ciphertext)."""
    if key is None:
        key = get_random_bytes(32)  # AES-256
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return key, cipher.nonce, tag, ciphertext

def aes_decrypt_bytes(key: bytes, nonce: bytes, tag: bytes, ciphertext: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext

def rsa_encrypt_bytes(data: bytes, public_key: RSA.RsaKey):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)

def rsa_decrypt_bytes(data: bytes, private_key: RSA.RsaKey):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(data)
