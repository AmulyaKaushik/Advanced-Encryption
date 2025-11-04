"""A minimal Streamlit app demonstrating encryption and decryption."""
import streamlit as st
from src.crypto_utils import generate_rsa_keypair, load_rsa_public_key, load_rsa_private_key, aes_encrypt_bytes, rsa_encrypt_bytes, rsa_decrypt_bytes, aes_decrypt_bytes
import base64
import os

KEY_DIR = 'keys'
if not os.path.exists(KEY_DIR):
    os.makedirs(KEY_DIR, exist_ok=True)

st.title('Hybrid AES + RSA Encryption Demo')

st.sidebar.header('Key Management')
if st.sidebar.button('Generate RSA Keypair'):
    priv, pub = generate_rsa_keypair()
    st.sidebar.success(f'Created keys at {priv}, {pub}')

st.header('Encrypt a message')
msg = st.text_area('Plaintext message')
pub_path = st.text_input('Public key path', 'keys/public.pem')
if st.button('Encrypt message'):
    if not msg:
        st.warning('Type a message first')
    else:
        aes_key, nonce, tag, ciphertext = aes_encrypt_bytes(msg.encode())
        try:
            pub = load_rsa_public_key(pub_path)
            enc_key = rsa_encrypt_bytes(aes_key, pub)
            blob = enc_key + nonce + tag + ciphertext
            b64 = base64.b64encode(blob).decode()
            st.success('Encrypted! Copy the Base64 below')
            st.code(b64)
        except Exception as e:
            st.error(f'Error: {e}')

st.header('Decrypt message (paste Base64)')
priv_path = st.text_input('Private key path', 'keys/private.pem')
enc_b64 = st.text_area('Encrypted Base64')
if st.button('Decrypt message'):
    if not enc_b64:
        st.warning('Paste encrypted base64')
    else:
        try:
            blob = base64.b64decode(enc_b64)
            enc_key = blob[:256]
            nonce = blob[256:256+16]
            tag = blob[256+16:256+32]
            ciphertext = blob[256+32:]

            priv = load_rsa_private_key(priv_path)
            aes_key = rsa_decrypt_bytes(enc_key, priv)
            pt = aes_decrypt_bytes(aes_key, nonce, tag, ciphertext)
            st.success('Decrypted message:')
            st.write(pt.decode())
        except Exception as e:
            st.error(f'Error: {e}')
