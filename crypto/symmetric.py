from Crypto.Cipher import AES, DES, ChaCha20
from Crypto.Random import get_random_bytes
import base64

def pad(text):
    return text + (16 - len(text) % 16) * ' '

def encrypt_aes(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_ECB)
    padded = pad(text)
    encrypted = cipher.encrypt(padded.encode())
    return f"AES Encrypted: {base64.b64encode(encrypted).decode()}"

def encrypt_des(text):
    key = get_random_bytes(8)
    cipher = DES.new(key, DES.MODE_ECB)
    padded = pad(text)
    encrypted = cipher.encrypt(padded[:8].encode())
    return f"DES Encrypted: {base64.b64encode(encrypted).decode()}"

def encrypt_chacha(text):
    key = get_random_bytes(32)
    cipher = ChaCha20.new(key=key)
    encrypted = cipher.encrypt(text.encode())
    return f"ChaCha20 Encrypted: {base64.b64encode(encrypted).decode()}"
