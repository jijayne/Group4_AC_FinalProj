from flask import Flask, request, render_template, send_file, flash
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from ecdsa import SigningKey, NIST384p
import io
import base64
import hashlib

app = Flask(__name__)
app.secret_key = 'supersecretkey123'

# === Key Setup ===
AES_KEY = get_random_bytes(16)  # 16 bytes for AES-128

def generate_3des_key():
    while True:
        key = get_random_bytes(24)
        try:
            return DES3.adjust_key_parity(key)
        except ValueError:
            continue

DES3_KEY = generate_3des_key()

# RSA keys
RSA_KEY = RSA.generate(2048)
RSA_PUBLIC_KEY = RSA_KEY.publickey()
RSA_CIPHER_ENCRYPT = PKCS1_OAEP.new(RSA_PUBLIC_KEY)
RSA_CIPHER_DECRYPT = PKCS1_OAEP.new(RSA_KEY)

# ECC keys (ECDSA for demo, used for hybrid encryption)
ECC_PRIVATE_KEY = SigningKey.generate(curve=NIST384p)
ECC_PUBLIC_KEY = ECC_PRIVATE_KEY.verifying_key

# Symmetric AES encryption (used in ECC hybrid)
def aes_encrypt_with_key(data_bytes, key):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    return iv + ciphertext

def aes_decrypt_with_key(data_bytes, key):
    iv = data_bytes[:16]
    ciphertext = data_bytes[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    return plaintext

# === Symmetric functions ===
def aes_encrypt(data_bytes):
    iv = get_random_bytes(16)
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, AES.block_size))
    return iv + ciphertext

def aes_decrypt(data_bytes):
    iv = data_bytes[:16]
    ciphertext = data_bytes[16:]
    cipher = AES.new(AES_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

def des3_encrypt(data_bytes):
    iv = get_random_bytes(8)
    cipher = DES3.new(DES3_KEY, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data_bytes, DES3.block_size))
    return iv + ciphertext

def des3_decrypt(data_bytes):
    iv = data_bytes[:8]
    ciphertext = data_bytes[8:]
    cipher = DES3.new(DES3_KEY, DES3.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), DES3.block_size)

XOR_KEY = 0x5A
def xor_cipher(data_bytes):
    return bytes([b ^ XOR_KEY for b in data_bytes])

# === RSA asymmetric ===
def rsa_encrypt(data_bytes):
    return RSA_CIPHER_ENCRYPT.encrypt(data_bytes)

def rsa_decrypt(data_bytes):
    return RSA_CIPHER_DECRYPT.decrypt(data_bytes)

# === ECC Hybrid Encryption ===
def ecc_encrypt(data_bytes):
    # ECC public key is used to derive a shared AES key
    shared_key = hashlib.sha256(ECC_PUBLIC_KEY.to_string()).digest()[:16]
    return aes_encrypt_with_key(data_bytes, shared_key)

def ecc_decrypt(data_bytes):
    shared_key = hashlib.sha256(ECC_PUBLIC_KEY.to_string()).digest()[:16]
    return aes_decrypt_with_key(data_bytes, shared_key)

# === Hashing functions ===
def hash_md5(data_bytes):
    h = MD5.new()
    h.update(data_bytes)
    return h.hexdigest()

def hash_sha1(data_bytes):
    h = SHA1.new()
    h.update(data_bytes)
    return h.hexdigest()

def hash_sha256(data_bytes):
    h = SHA256.new()
    h.update(data_bytes)
    return h.hexdigest()

def hash_sha512(data_bytes):
    h = SHA512.new()
    h.update(data_bytes)
    return h.hexdigest()

@app.route('/')
def dashboard():
    symmetric_algos = [
        {"name": "AES", "description": "Advanced Encryption Standard with 128/192/256-bit keys."},
        {"name": "DES", "description": "Data Encryption Standard, now largely obsolete but historically important."},
        {"name": "Blowfish", "description": "Fast block cipher with variable-length keys."}
    ]
    asymmetric_algos = [
        {"name": "RSA", "description": "Widely used public-key algorithm for secure data transmission."},
        {"name": "ElGamal", "description": "Based on Diffie-Hellman key exchange, used in digital signatures."}
    ]
    hashing_algos = [
        {"name": "MD5", "description": "Message Digest Algorithm 5, fast but insecure."},
        {"name": "SHA-1", "description": "Secure Hash Algorithm 1, outdated due to collision attacks."},
        {"name": "SHA-256", "description": "Part of SHA-2 family, used widely in blockchain and security."},
        {"name": "SHA-3", "description": "Latest SHA family using sponge construction."}
    ]
    return render_template("dashboard.html",
                           symmetric_algos=symmetric_algos,
                           asymmetric_algos=asymmetric_algos,
                           hashing_algos=hashing_algos)

ALGORITHM_DETAILS = {
    "symmetric": {
        "AES": {
            "history": "Developed by Vincent Rijmen and Joan Daemen in 1998. Selected by NIST as the new standard in 2001.",
            "pseudocode": "KeyExpansion();\nInitialRound();\nFor 9 rounds: SubBytes(), ShiftRows(), MixColumns(), AddRoundKey();\nFinalRound();",
            "process": "AES encrypts blocks of 128 bits using substitution-permutation network and key sizes of 128, 192, or 256 bits.",
            "use_cases": "Used in SSL/TLS, VPNs, disk encryption, and secure file transfers."
        },
        "DES": {
            "history": "Developed by IBM in the 1970s and adopted as a federal standard in 1977.",
            "pseudocode": "InitialPermutation();\n16 Rounds of: Expansion, KeyMixing, S-Box, Permutation;\nFinalPermutation();",
            "process": "DES is a block cipher that encrypts 64-bit blocks using a 56-bit key and 16 rounds of Feistel structure.",
            "use_cases": "Historically used in banking systems; now replaced due to vulnerabilities."
        },
        "Blowfish": {
            "history": "Designed by Bruce Schneier in 1993 as a fast, free alternative to existing encryption algorithms like DES.",
            "pseudocode": "Divide block into L and R;\nFor 16 rounds: L = L XOR P[i]; R = R XOR F(L); Swap L and R;\nUndo last swap; R = R XOR P[17]; L = L XOR P[18]; Combine L and R;",
            "process": "Blowfish is a symmetric block cipher that encrypts 64-bit blocks using a variable-length key (32 to 448 bits) in 16 rounds of Feistel structure. It uses a key-dependent S-box and P-array for encryption.",
            "use_cases": "Used in file encryption, embedded systems, and password hashing (e.g., bcrypt); popular for its speed and flexibility."
        }
    },
    "asymmetric": {
        "RSA": {
            "history": "Introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.",
            "pseudocode": "Generate keys: (n, e, d);\nEncryption: c = m^e mod n;\nDecryption: m = c^d mod n;",
            "process": "RSA uses two large prime numbers to generate public/private key pairs based on modular exponentiation.",
            "use_cases": "Used in secure data transmission, digital signatures, and key exchange."
        },
        "ElGamal": {
            "history": "Introduced by Taher ElGamal in 1985, based on the Diffie-Hellman key exchange; widely used in cryptographic protocols and digital signatures.",
            "pseudocode": "KeyGen: Choose large prime p, generator g, secret x; Compute public key y = g^x mod p;\nEncrypt: Choose random k; Compute c1 = g^k mod p, c2 = m * y^k mod p;\nDecrypt: m = c2 / c1^x mod p;",
            "process": "ElGamal is an asymmetric encryption algorithm based on discrete logarithms. It uses a pair of public and private keys for encryption and decryption, supporting both confidentiality and digital signatures.",
            "use_cases": "Used in secure communication protocols (e.g., PGP, GPG), digital signatures, and hybrid encryption systems."
        }
    },
    "hashing": {
        "SHA-256": {
            "history": "Part of the SHA-2 family designed by the NSA and published in 2001 by NIST.",
            "pseudocode": "Padding -> Parsing -> Initial hash values -> Compression function over message blocks;",
            "process": "SHA-256 processes input in 512-bit blocks to produce a 256-bit fixed hash output.",
            "use_cases": "Widely used in blockchain (e.g., Bitcoin), digital signatures, and file integrity checks."
        }
    }
}

@app.route('/algorithm/<algo_type>/<name>')
def algorithm_info(algo_type, name):
    algo_data = ALGORITHM_DETAILS.get(algo_type, {}).get(name)
    if algo_data:
        return render_template('algorithm_info.html', algo_type=algo_type, name=name, details=algo_data)
    else:
        abort(404, description="Algorithm not found") 

@app.route('/index', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        algorithm = request.form.get('algorithm')
        action = request.form.get('action')
        input_text = request.form.get('input_data', '').strip()
        file = request.files.get('file')

        if file and file.filename != '':
            data_bytes = file.read()
            filename = file.filename
        elif input_text:
            data_bytes = input_text.encode('utf-8')
            filename = None
        else:
            flash('Please enter text or upload a file.')
            return render_template('index.html', result=result)

        try:
            if algorithm == 'aes':
                if action == 'encrypt':
                    encrypted = aes_encrypt(data_bytes)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.aes.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if filename:
                        decrypted = aes_decrypt(data_bytes)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.aes.dec')
                    else:
                        result = aes_decrypt(base64.b64decode(input_text)).decode('utf-8')

            elif algorithm == 'des3':
                if action == 'encrypt':
                    encrypted = des3_encrypt(data_bytes)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.3des.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if filename:
                        decrypted = des3_decrypt(data_bytes)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.3des.dec')
                    else:
                        result = des3_decrypt(base64.b64decode(input_text)).decode('utf-8')

            elif algorithm == 'xor':
                processed = xor_cipher(data_bytes)
                ext = 'xor.enc' if action == 'encrypt' else 'xor.dec'
                if filename:
                    return send_file(io.BytesIO(processed), as_attachment=True, download_name=f'{filename}.{ext}')
                else:
                    result = base64.b64encode(processed).decode('utf-8')

            elif algorithm == 'rsa':
                if action == 'encrypt':
                    encrypted = rsa_encrypt(data_bytes)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.rsa.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if filename:
                        decrypted = rsa_decrypt(data_bytes)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.rsa.dec')
                    else:
                        result = rsa_decrypt(base64.b64decode(input_text)).decode('utf-8')

            elif algorithm == 'ecc':
                if action == 'encrypt':
                    encrypted = ecc_encrypt(data_bytes)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.ecc.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if filename:
                        decrypted = ecc_decrypt(data_bytes)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.ecc.dec')
                    else:
                        result = ecc_decrypt(base64.b64decode(input_text)).decode('utf-8')

            elif algorithm in ('md5', 'sha1', 'sha256', 'sha512'):
                if action == 'decrypt':
                    flash("Hash functions cannot be decrypted.")
                else:
                    if algorithm == 'md5':
                        result = hash_md5(data_bytes)
                    elif algorithm == 'sha1':
                        result = hash_sha1(data_bytes)
                    elif algorithm == 'sha256':
                        result = hash_sha256(data_bytes)
                    elif algorithm == 'sha512':
                        result = hash_sha512(data_bytes)

            else:
                flash('Invalid algorithm selected.')

        except Exception as e:
            flash(f'Error during processing: {str(e)}')

    return render_template('index.html', result=result)


if __name__ == '__main__':
    app.run(debug=True)
