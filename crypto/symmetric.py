from Crypto.Cipher import AES
import base64

def pad(text):
    # Pad with spaces to make length multiple of 16 bytes
    while len(text) % 16 != 0:
        text += ' '
    return text

def encrypt_aes(text, key):
    key = key.ljust(16)[:16].encode()  # Ensure key is 16 bytes
    cipher = AES.new(key, AES.MODE_ECB)
    padded_text = pad(text).encode()
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

def decrypt_aes(encrypted_b64, key):
    key = key.ljust(16)[:16].encode()
    cipher = AES.new(key, AES.MODE_ECB)
    encrypted = base64.b64decode(encrypted_b64)
    decrypted = cipher.decrypt(encrypted).decode().rstrip()
    return decrypted
