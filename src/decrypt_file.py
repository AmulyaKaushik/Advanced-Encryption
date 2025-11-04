"""Decrypt file produced by encrypt_file.py"""
import struct
import argparse
from crypto_utils import rsa_decrypt_bytes, load_rsa_private_key, aes_decrypt_bytes

def decrypt_file(in_path: str, out_path: str, privkey_path: str):
    with open(in_path, 'rb') as f:
        size_data = f.read(2)
        if len(size_data) < 2:
            raise ValueError('Invalid file format')
        (enc_key_len,) = struct.unpack('>H', size_data)
        enc_aes_key = f.read(enc_key_len)
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()

    priv = load_rsa_private_key(privkey_path)
    aes_key = rsa_decrypt_bytes(enc_aes_key, priv)
    plaintext = aes_decrypt_bytes(aes_key, nonce, tag, ciphertext)

    with open(out_path, 'wb') as out:
        out.write(plaintext)

    print(f'Decrypted {in_path} -> {out_path}')

if __name__ == '__main__':
    p = argparse.ArgumentParser()
    p.add_argument('infile')
    p.add_argument('outfile')
    p.add_argument('--priv', default='../keys/private.pem', help='Path to RSA private key')
    args = p.parse_args()
    decrypt_file(args.infile, args.outfile, args.priv)
