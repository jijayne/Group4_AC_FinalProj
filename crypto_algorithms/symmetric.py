from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
import base64
import os
from cryptography.fernet import Fernet



# Padding for block size
def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len]) * pad_len

def unpad(data):
    return data[:-data[-1]]

# ===== AES TEXT =====
def aes_encrypt_text(plain_text, key):
    key = key.ljust(16).encode()[:16]  # pad/truncate key to 16 bytes
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plain_text.encode()))
    return base64.b64encode(iv + ct_bytes).decode()

def aes_decrypt_text(cipher_text, key):
    key = key.ljust(16).encode()[:16]
    data = base64.b64decode(cipher_text)
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode()

# ===== AES FILE =====
def aes_encrypt_file(input_path, output_path, key):
    key = key.ljust(16).encode()[:16]
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    with open(input_path, 'rb') as f:
        data = f.read()
    padded_data = pad(data)
    encrypted = cipher.encrypt(padded_data)
    with open(output_path, 'wb') as f:
        f.write(iv + encrypted)

def aes_decrypt_file(input_path, output_path, key):
    key = key.ljust(16).encode()[:16]
    with open(input_path, 'rb') as f:
        data = f.read()
    iv = data[:16]
    ct = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(ct))
    with open(output_path, 'wb') as f:
        f.write(decrypted)

# ===== DES TEXT =====
def des_encrypt_text(plain_text, key):
    key = key.ljust(8).encode()[:8]  # DES needs exactly 8-byte key
    iv = get_random_bytes(8)  # DES uses 8-byte IV
    cipher = DES.new(key, DES.MODE_CBC, iv)
    ct_bytes = cipher.encrypt(pad(plain_text.encode()))
    return base64.b64encode(iv + ct_bytes).decode()

def des_decrypt_text(cipher_text, key):
    key = key.ljust(8).encode()[:8]
    data = base64.b64decode(cipher_text)
    iv = data[:8]
    ct = data[8:]
    cipher = DES.new(key, DES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct))
    return pt.decode()

# ===== FERNET TEXT =====
def generate_fernet_key():
    return Fernet.generate_key().decode()

def fernet_encrypt_text(plain_text, key):
    fernet = Fernet(key.encode())
    return fernet.encrypt(plain_text.encode()).decode()

def fernet_decrypt_text(cipher_text, key):
    fernet = Fernet(key.encode())
    return fernet.decrypt(cipher_text.encode()).decode()