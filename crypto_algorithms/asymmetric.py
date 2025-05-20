# --- RSA Imports ---
import rsa
import base64

# === RSA Key Generation ===
def generate_keys():
    public_key, private_key = rsa.newkeys(2048)
    return public_key.save_pkcs1().decode(), private_key.save_pkcs1().decode()

def load_public_key(key_str):
    return rsa.PublicKey.load_pkcs1(key_str.encode())

def load_private_key(key_str):
    return rsa.PrivateKey.load_pkcs1(key_str.encode())

def rsa_encrypt_text(text, pub_key_str):
    pub_key = load_public_key(pub_key_str)
    encrypted = rsa.encrypt(text.encode(), pub_key)
    return base64.b64encode(encrypted).decode()

def rsa_decrypt_text(cipher_text, priv_key_str):
    priv_key = load_private_key(priv_key_str)
    decrypted = rsa.decrypt(base64.b64decode(cipher_text), priv_key)
    return decrypted.decode()

def rsa_encrypt_file(input_path, output_path, pub_key_str):
    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted = rsa_encrypt_text(data.decode(), pub_key_str)
    with open(output_path, 'w') as f:
        f.write(encrypted)

def rsa_decrypt_file(input_path, output_path, priv_key_str):
    with open(input_path, 'r') as f:
        encrypted = f.read()
    decrypted = rsa_decrypt_text(encrypted, priv_key_str)
    with open(output_path, 'wb') as f:
        f.write(decrypted.encode())

# --- ECC Imports ---
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# === ECC Key Generation ===
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem

# === ECC Encrypt Text ===
def ecc_encrypt_text(text, public_key_str):
    public_key = serialization.load_pem_public_key(public_key_str.encode())
    ephemeral_key = ec.generate_private_key(ec.SECP384R1())
    shared_key = ephemeral_key.exchange(ec.ECDH(), public_key)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc encryption',
    ).derive(shared_key)

    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(text.encode()) + encryptor.finalize()

    ephemeral_pub = ephemeral_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return base64.b64encode(ephemeral_pub + iv + ciphertext).decode()

# === ECC Decrypt Text ===
def ecc_decrypt_text(ciphertext_b64, private_key_str):
    private_key = serialization.load_pem_private_key(private_key_str.encode(), password=None)
    data = base64.b64decode(ciphertext_b64.encode())

    pem_end = data.find(b"-----END PUBLIC KEY-----") + len(b"-----END PUBLIC KEY-----\n")
    ephemeral_pub = serialization.load_pem_public_key(data[:pem_end])
    iv = data[pem_end:pem_end+16]
    ciphertext = data[pem_end+16:]

    shared_key = private_key.exchange(ec.ECDH(), ephemeral_pub)

    aes_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'ecc encryption',
    ).derive(shared_key)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# === ECC Encrypt File ===
def ecc_encrypt_file(input_path, output_path, public_key_str):
    with open(input_path, 'rb') as f:
        data = f.read()
    encrypted = ecc_encrypt_text(data.decode(), public_key_str)
    with open(output_path, 'w') as f:
        f.write(encrypted)

# === ECC Decrypt File ===
def ecc_decrypt_file(input_path, output_path, private_key_str):
    with open(input_path, 'r') as f:
        encrypted = f.read()
    decrypted = ecc_decrypt_text(encrypted, private_key_str)
    with open(output_path, 'wb') as f:
        f.write(decrypted)
