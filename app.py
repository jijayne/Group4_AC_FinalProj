from flask import Flask, render_template, request
from Crypto.Cipher import AES, DES, Blowfish, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.concatkdf import ConcatKDFHash
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import hashlib
import os

app = Flask(__name__)

# -------- SYMMETRIC HELPERS --------
def get_block_size(algorithm):
    return {'AES': 16, 'DES': 8, 'Blowfish': 8}.get(algorithm, 16)

def generate_key(key, algorithm):
    if algorithm == 'AES':
        return hashlib.sha256(key.encode()).digest()
    elif algorithm == 'DES':
        return hashlib.md5(key.encode()).digest()[:8]
    elif algorithm == 'Blowfish':
        return hashlib.sha256(key.encode()).digest()[:16]
    return None

def encrypt(text, key, algorithm):
    block_size = get_block_size(algorithm)
    key = generate_key(key, algorithm)
    if algorithm == 'AES':
        cipher = AES.new(key, AES.MODE_ECB)
    elif algorithm == 'DES':
        cipher = DES.new(key, DES.MODE_ECB)
    elif algorithm == 'Blowfish':
        cipher = Blowfish.new(key, Blowfish.MODE_ECB)
    else:
        return "Unsupported Algorithm"
    padded_text = pad(text.encode(), block_size)
    encrypted = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted).decode()

def decrypt(text, key, algorithm):
    block_size = get_block_size(algorithm)
    key = generate_key(key, algorithm)
    try:
        if algorithm == 'AES':
            cipher = AES.new(key, AES.MODE_ECB)
        elif algorithm == 'DES':
            cipher = DES.new(key, DES.MODE_ECB)
        elif algorithm == 'Blowfish':
            cipher = Blowfish.new(key, Blowfish.MODE_ECB)
        else:
            return "Unsupported Algorithm"
        decrypted = cipher.decrypt(base64.b64decode(text))
        unpadded = unpad(decrypted, block_size)
        return unpadded.decode()
    except Exception as e:
        return f"Decryption Error: {str(e)}"

# -------- ASYMMETRIC HELPERS --------
# RSA
def rsa_encrypt_decrypt(action, text):
    key = RSA.generate(2048)
    public_key = key.publickey()
    if action == 'encrypt':
        cipher = PKCS1_OAEP.new(public_key)
        encrypted = cipher.encrypt(text.encode())
        return base64.b64encode(encrypted).decode()
    else:
        cipher = PKCS1_OAEP.new(key)
        try:
            decrypted = cipher.decrypt(base64.b64decode(text.encode()))
            return decrypted.decode()
        except:
            return "Invalid RSA decryption input."

# ECC
def ecc_encrypt_decrypt(action, text):
    private_key = ec.generate_private_key(ec.SECP384R1())
    peer_public_key = private_key.public_key()
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    kdf = ConcatKDFHash(algorithm=hashes.SHA256(), length=32, otherinfo=None)
    aes_key = kdf.derive(shared_key)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    cryptor = cipher.encryptor() if action == 'encrypt' else cipher.decryptor()
    try:
        result = cryptor.update(text.encode()) + cryptor.finalize()
        return base64.b64encode(iv + result).decode() if action == 'encrypt' else result.decode(errors='ignore')
    except:
        return "Invalid ECC decryption input."

# -------- ROUTES --------
@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        algorithm = request.form['algorithm']
        action = request.form['action']
        key = request.form['key']
        text = request.form['text']
        if action == 'encrypt':
            result = encrypt(text, key, algorithm)
        elif action == 'decrypt':
            result = decrypt(text, key, algorithm)
    return render_template('index.html', result=result)

@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():
    result = None
    if request.method == 'POST':
        algorithm = request.form['algorithm']
        action = request.form['action']
        text = request.form['text']
        if algorithm == 'RSA':
            result = rsa_encrypt_decrypt(action, text)
        elif algorithm == 'ECC':
            result = ecc_encrypt_decrypt(action, text)
        else:
            result = "Unsupported Asymmetric Algorithm"
    return render_template('asymmetric.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
