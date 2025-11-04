"""Encrypt a file (or message) using AES, then encrypt AES key using RSA public key.
Output format: | len(enc_aes_key:2bytes) | enc_aes_key | nonce(16) | tag(16) | ciphertext |
"""
import struct
import argparse
from crypto_utils import aes_encrypt_bytes, rsa_encrypt_bytes, load_rsa_public_key

def encrypt_file(in_path: str, out_path: str, pubkey_path: str):
    with open(in_path, 'rb') as f:
        plaintext = f.read()

    aes_key, nonce, tag, ciphertext = aes_encrypt_bytes(plaintext)
    pub = load_rsa_public_key(pubkey_path)
    enc_aes_key = rsa_encrypt_bytes(aes_key, pub)

    with open(out_path, 'wb') as f:
        f.write(struct.pack('>H', len(enc_aes_key)))
        f.write(enc_aes_key)
        f.write(nonce)
        f.write(tag)
        f.write(ciphertext)

    print(f'Encrypted {in_path} -> {out_path}')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('infile')
    p.add_argument('outfile')
    p.add_argument('--pub', default='../keys/public.pem', help='Path to RSA public key')
    args = p.parse_args()
    encrypt_file(args.infile, args.outfile, args.pub)
