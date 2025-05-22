from flask import Flask, request, render_template, send_file, flash, abort
from Crypto.Cipher import AES, DES3, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA
from Crypto.PublicKey import ECC
from Crypto.Random import get_random_bytes
from Crypto.Hash import MD5, SHA1, SHA256, SHA512
from ecdsa import SigningKey, NIST384p
import io
import base64
import hashlib
from flask import jsonify

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
        {"name": "AES", "description": "A widely-used symmetric cipher that encrypts data in fixed-size blocks (128 bits) using key sizes of 128, 192, or 256 bits. Known for its speed and strong security, AES is the standard for securing sensitive data."},
        {"name": "DES", "description": "An older symmetric block cipher that uses a 56-bit key. Though historically important, DES is now considered insecure for many applications due to its small key size."},
        {"name": "XOR", "description": "An enhancement of DES that applies the algorithm three times with either two or three keys, improving security over standard DES but slower and gradually being phased out in favor of AES."}
    ]
    asymmetric_algos = [
        {"name": "RSA", "description": "A public-key encryption algorithm that uses large integers and prime factorization for secure key exchange and encryption. RSA is commonly used in digital signatures and secure data transmission."},
        {"name": "ECC", "description": "A modern public-key encryption method offering strong security with smaller keys. ECC is efficient and ideal for mobile and embedded systems where processing power and storage are limited."}
    ]
    hashing_algos = [
        {"name": "MD5", "description": "Produces a 128-bit hash. It’s fast but vulnerable to collisions, making it unsuitable for secure cryptographic use. Still used for file checksums where security isn't critical."},
        {"name": "SHA-1", "description": "Outputs a 160-bit hash. Once popular, but now deprecated in favor of more secure versions due to proven collision attacks."},
        {"name": "SHA-256", "description": "Generates a 256-bit hash and is part of the SHA-2 family. It’s widely used in secure applications like blockchain, digital certificates, and data integrity verification."},
        {"name": "SHA-512", "description": "A 512-bit version of SHA-2, offering even stronger collision resistance. Suitable for high-security systems where a longer hash is needed."}
    ]
    return render_template("dashboard.html",
                           symmetric_algos=symmetric_algos,
                           asymmetric_algos=asymmetric_algos,
                           hashing_algos=hashing_algos)

ALGORITHM_DETAILS = {
    "symmetric": {
        "AES": {
            "history": "Adopted by NIST in 2001 as the successor to DES, developed by Belgian cryptographers Vincent Rijmen and Joan Daemen (Rijndael algorithm).",
            "Library Used": "Crypto.Cipher.AES",
            "How It Works": "Operates on 128-bit blocks using key sizes of 128, 192, or 256 bits. Involves substitution-permutation network over multiple rounds.",
            "use_cases":"Used in SSL/TLS, VPNs, disk encryption, and secure file transfers."
        },
        "DES": {
            "history": "Developed by IBM and adopted as a federal standard in 1977. Once a cornerstone of encryption but now considered insecure due to its 56-bit key.",
            "Library Used": "Crypto.Cipher.DES",
            "How It Works": "Encrypts 64-bit blocks using 16 Feistel rounds and a 56-bit key.",
            "use_cases": "Historically used in banking systems; now replaced due to vulnerabilities."
        },
        "XOR": {
            "history": "One of the earliest and simplest encryption methods, dating back to early computer systems. Used primarily for educational purposes or simple obfuscation.",
            "Library Used": " Custom Python implementation",
            "How It Works": "Performs a bitwise XOR between data and a key. Easily reversible but not secure for real-world use.",
            "use_cases": "Used in basic data masking, simple file obfuscation, and as a foundational concept in modern cryptographic algorithms."
        }

    },
    "asymmetric": {
        "RSA": {
            "history": "Introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman.",
            "Library Used": "Crypto.PublicKey.RSA, Crypto.Cipher.PKCS1_OAEP",
            "How It Works": "Based on factoring large primes; generates public and private key pairs. Encrypts with public key, decrypts with private key.",
            "use_cases": "Used in secure data transmission, digital signatures, and key exchange."
        },
        "ECC": {
            "history": "Proposed in the 1980s by Neal Koblitz and Victor Miller as an alternative to RSA with smaller key sizes and equivalent security.",
            "Library Used": "ecdsa",
            "How It Works": "Uses elliptic curves over finite fields to generate keys. Offers strong encryption with efficient computation.",
            "use_cases": "Used in secure communication protocols (e.g., PGP, GPG), digital signatures, and hybrid encryption systems."
        }
    },
    "hashing": {
        "MD5": {
            "history": "Developed by Ronald Rivest in 1991, MD5 was widely used for checksums and data integrity.",
            "Library Used": "Padding -> Initialize state -> Process blocks -> Produce final hash;",
            "How It Works": "MD5 processes input in 512-bit blocks to produce a 128-bit hash output.",
            "use_cases": "Used for checksums, but not recommended for security due to vulnerabilities."
        },
        "SHA-1": {
            "history": "Developed by NSA in 1993, SHA-1 was widely used for digital signatures and certificates.",
            "Library Used": "Padding -> Initialize state -> Process blocks -> Produce final hash;",
            "How It Works": "SHA-1 processes input in 512-bit blocks to produce a 160-bit hash output.",
            "use_cases": "Used in SSL/TLS, digital signatures, and certificates, but deprecated due to vulnerabilities."
        },
        "SHA-512": {
            "history": "Part of the SHA-2 family designed by NSA and published in 2001 by NIST.",
            "Library Used": "Padding -> Parsing -> Initial hash values -> Compression function over message blocks;",
            "How It Works": "SHA-512 processes input in 1024-bit blocks to produce a 512-bit fixed hash output.",
            "use_cases": "Used in secure applications like SSL/TLS, digital signatures, and file integrity checks."
        },
        "SHA-256": {
            "history": "Part of the SHA-2 family designed by the NSA and published in 2001 by NIST.",
            "Library Used": "Padding -> Parsing -> Initial hash values -> Compression function over message blocks;",
            "How It Works": "SHA-256 processes input in 512-bit blocks to produce a 256-bit fixed hash output.",
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

@app.route('/generate_keys', methods=['POST'])
def generate_keys():
    algo = request.json.get('algorithm')
    if algo == 'rsa':
        key = RSA.generate(2048)
        private_key = key.export_key().decode('utf-8')
        public_key = key.publickey().export_key().decode('utf-8')
        return jsonify({'public_key': public_key, 'private_key': private_key})
    elif algo == 'ecc':
        key = ECC.generate(curve='P-256')
        private_key = key.export_key(format='PEM')
        public_key = key.public_key().export_key(format='PEM')
        return jsonify({'public_key': public_key, 'private_key': private_key})
    else:
        return jsonify({'error': 'Invalid algorithm'}), 400

@app.route('/index', methods=['GET', 'POST'])
def index():
    result = None
    if request.method == 'POST':
        algorithm = request.form.get('algorithm')
        action = request.form.get('action')
        input_text = request.form.get('input_data', '').strip()
        file = request.files.get('file')

         # --- Key pair handling for RSA/ECC ---
        public_key = None
        private_key = None

        # Get public key (textarea or file)
        public_key_text = request.form.get('public_key', '').strip()
        public_key_file = request.files.get('public_key_file')
        if public_key_file and public_key_file.filename:
            public_key = public_key_file.read().decode('utf-8')
        elif public_key_text:
            public_key = public_key_text

        # Get private key (textarea or file)
        private_key_text = request.form.get('private_key', '').strip()
        private_key_file = request.files.get('private_key_file')
        if private_key_file and private_key_file.filename:
            private_key = private_key_file.read().decode('utf-8')
        elif private_key_text:
            private_key = private_key_text

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
                    if not public_key:
                        flash('Public key required for RSA encryption.')
                        return render_template('index.html', result=result)
                    rsa_pubkey = RSA.import_key(public_key)
                    cipher = PKCS1_OAEP.new(rsa_pubkey)
                    encrypted = cipher.encrypt(data_bytes)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.rsa.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if not private_key:
                        flash('Private key required for RSA decryption.')
                        return render_template('index.html', result=result)
                    rsa_privkey = RSA.import_key(private_key)
                    cipher = PKCS1_OAEP.new(rsa_privkey)
                    if filename:
                        decrypted = cipher.decrypt(data_bytes)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.rsa.dec')
                    else:
                        decrypted = cipher.decrypt(base64.b64decode(input_text))
                        result = decrypted.decode('utf-8')

            elif algorithm == 'ecc':
                if action == 'encrypt':
                    if not public_key:
                        flash('Public key required for ECC encryption.')
                        return render_template('index.html', result=result)
                    ecc_pubkey = ECC.import_key(public_key)
                    shared_key = hashlib.sha256(ecc_pubkey.export_key(format='DER')).digest()[:16]
                    encrypted = aes_encrypt_with_key(data_bytes, shared_key)
                    if filename:
                        return send_file(io.BytesIO(encrypted), as_attachment=True, download_name=f'{filename}.ecc.enc')
                    else:
                        result = base64.b64encode(encrypted).decode('utf-8')
                elif action == 'decrypt':
                    if not private_key:
                        flash('Private key required for ECC decryption.')
                        return render_template('index.html', result=result)
                    ecc_privkey = ECC.import_key(private_key)
                    shared_key = hashlib.sha256(ecc_privkey.public_key().export_key(format='DER')).digest()[:16]
                    if filename:
                        decrypted = aes_decrypt_with_key(data_bytes, shared_key)
                        return send_file(io.BytesIO(decrypted), as_attachment=True, download_name=f'{filename}.ecc.dec')
                    else:
                        decrypted = aes_decrypt_with_key(base64.b64decode(input_text), shared_key)
                        result = decrypted.decode('utf-8')
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
    app.run()

