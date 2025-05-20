import rsa
import base64

(pubkey, privkey) = rsa.newkeys(512)

def encrypt_rsa(text):
    encrypted = rsa.encrypt(text.encode(), pubkey)
    return f"RSA Encrypted: {base64.b64encode(encrypted).decode()}"
