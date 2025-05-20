from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from ecies.utils import generate_eth_key
from ecies import encrypt as ecc_encrypt, decrypt as ecc_decrypt
import base64

# RSA key pair
rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()
rsa_cipher_private = PKCS1_OAEP.new(rsa_key)
rsa_cipher_public = PKCS1_OAEP.new(rsa_public_key)

# ECC key pair
eth_key = generate_eth_key()
ecc_private_key = eth_key.to_hex()
ecc_public_key = eth_key.public_key.to_hex()

# RSA Encryption
def rsa_encrypt(text):
    encrypted = rsa_cipher_public.encrypt(text.encode())
    return base64.b64encode(encrypted).decode()

# RSA Decryption
def rsa_decrypt(ciphertext):
    decrypted = rsa_cipher_private.decrypt(base64.b64decode(ciphertext))
    return decrypted.decode()

# ECC Encryption
def ecc_encrypt_text(text):
    encrypted = ecc_encrypt(ecc_public_key, text.encode())
    return base64.b64encode(encrypted).decode()

# ECC Decryption
def ecc_decrypt_text(ciphertext):
    decrypted = ecc_decrypt(ecc_private_key, base64.b64decode(ciphertext))
    return decrypted.decode()
