"""Generate RSA keypair and save to keys/"""
from crypto_utils import generate_rsa_keypair

if __name__ == '__main__':
    priv, pub = generate_rsa_keypair()
    print('Generated RSA keypair:')
    print(' Private key:', priv)
    print(' Public key :', pub)
