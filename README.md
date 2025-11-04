# Advanced Encryption using Cryptographic Techniques

This project implements hybrid encryption (AES-256 + RSA-2048) to securely encrypt files and messages.

## Features
- Generate RSA keypair
- Encrypt files/messages with AES-256 (EAX mode)
- Protect AES key using RSA (PKCS1_OAEP)
- Command-line utilities + Streamlit demo GUI

## Setup
1. Create virtualenv and install dependencies:

```bash
python -m venv venv
source venv/bin/activate  # or venv\Scripts\activate on Windows
pip install -r requirements.txt
```

2. Generate keys:

```bash
python src/keygen.py
```

3. Encrypt a file:

```bash
python src/encrypt_file.py secret.txt secret.enc --pub keys/public.pem
```

4. Decrypt a file:

```bash
python src/decrypt_file.py secret.enc secret_out.txt --priv keys/private.pem
```

5. Run the Streamlit demo:

```bash
streamlit run app_streamlit.py
```

## File format
Binary layout written by `encrypt_file.py`:
- 2 bytes big-endian: length of RSA-encrypted AES key (N)
- N bytes: RSA-encrypted AES key
- 16 bytes: AES nonce
- 16 bytes: AES tag
- Rest: ciphertext

## Security notes
- RSA key size default: 2048 bits. For higher security use 3072 or 4096.
- AES in EAX mode provides confidentiality and integrity; do not reuse same AES key/nonce.
- Keep private.pem secret.

## License
MIT
