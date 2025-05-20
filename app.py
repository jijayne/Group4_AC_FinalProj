from flask import Flask, render_template, request
from crypto_algorithms.hashing import hash_text
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from crypto_algorithms.symmetric import (
    aes_encrypt_text, aes_decrypt_text,
    des_encrypt_text, des_decrypt_text,
    generate_fernet_key, fernet_encrypt_text, fernet_decrypt_text
)
from crypto_algorithms.asymmetric import (
    generate_keys, rsa_encrypt_text, rsa_decrypt_text,
    generate_ecc_keys, ecc_encrypt_text, ecc_decrypt_text
)

app = Flask(__name__)
app.secret_key = 'your_secret_key'

@app.route('/')
def index():
    return render_template('index.html')

# Test AES Text
@app.route('/test_aes')
def test_aes():
    message = "hello world"
    key = "mypassword"
    encrypted = aes_encrypt_text(message, key)
    decrypted = aes_decrypt_text(encrypted, key)
    return f"<h2><u>AES</u></h2><b>Original:</b> {message}<br><b>Encrypted:</b> {encrypted}<br><b>Decrypted:</b> {decrypted}"

# Test DES Text
@app.route('/test_des')
def test_des():
    message = "secret msg"
    key = "key123"
    encrypted = des_encrypt_text(message, key)
    decrypted = des_decrypt_text(encrypted, key)
    return f"<h2><u>DES</u></h2><b>Original:</b> {message}<br><b>Encrypted:</b> {encrypted}<br><b>Decrypted:</b> {decrypted}"

# Test Fernet Text
@app.route('/test_fernet')
def test_fernet():
    message = "fernet test"
    key = generate_fernet_key()
    encrypted = fernet_encrypt_text(message, key)
    decrypted = fernet_decrypt_text(encrypted, key)
    return f"<h2><u>Fernet</u></h2><b>Original:</b> {message}<br><b>Key:</b> {key}<br><b>Encrypted:</b> {encrypted}<br><b>Decrypted:</b> {decrypted}"

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    encrypted = None
    text_to_download = None
    if request.method == 'POST':
        text = request.form['text']
        key = request.form['key']
        algorithm = request.form['algorithm']

        try:
            if algorithm == 'aes':
                encrypted = aes_encrypt_text(text, key)
            elif algorithm == 'des':
                encrypted = des_encrypt_text(text, key)
            elif algorithm == 'fernet':
                if not key.startswith("gAAAA"):
                    key = generate_fernet_key()
                encrypted = fernet_encrypt_text(text, key)
        except Exception as e:
            encrypted = f"Encryption error: {str(e)}"

        text_to_download = encrypted

    return render_template('encrypt.html', encrypted=encrypted, text_to_download=text_to_download)



@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    decrypted = None
    if request.method == 'POST':
        text = request.form['text']
        key = request.form['key']
        algorithm = request.form['algorithm']

        try:
            if algorithm == 'aes':
                decrypted = aes_decrypt_text(text, key)
            elif algorithm == 'des':
                decrypted = des_decrypt_text(text, key)
            elif algorithm == 'fernet':
                decrypted = fernet_decrypt_text(text, key)
        except Exception as e:
            decrypted = f"Decryption error: {str(e)}"

    return render_template('decrypt.html', decrypted=decrypted)


@app.route('/hash', methods=['GET', 'POST'])
def hash_page():
    hashed = None
    if request.method == 'POST':
        text = request.form['text']
        algorithm = request.form['algorithm']
        hashed = hash_text(text, algorithm)

    return render_template('hash.html', hashed=hashed)

# RSA Encryption/Decryption

@app.route('/rsa', methods=['GET', 'POST'])
def rsa_page():
    encrypted = decrypted = public_key = private_key = None
    if request.method == 'POST':
        action = request.form['action']
        message = request.form['text']

        try:
            if action == 'generate':
                public_key, private_key = generate_keys()
            elif action == 'encrypt':
                public_key = request.form['public_key']
                encrypted = rsa_encrypt_text(message, public_key)
            elif action == 'decrypt':
                private_key = request.form['private_key']
                decrypted = rsa_decrypt_text(message, private_key)
        except Exception as e:
            if action == 'encrypt':
                encrypted = f"Encryption error: {str(e)}"
            elif action == 'decrypt':
                decrypted = f"Decryption error: {str(e)}"

    return render_template('rsa.html', encrypted=encrypted, decrypted=decrypted,
                           public_key=public_key, private_key=private_key)


@app.route('/ecc', methods=['GET', 'POST'])
def ecc_page():
    encrypted = decrypted = public_key = private_key = None
    if request.method == 'POST':
        action = request.form['action']
        message = request.form['text']

        if action == 'generate':
            public_key, private_key = generate_ecc_keys()
        elif action == 'encrypt':
            public_key = request.form['public_key']
            try:
                encrypted = ecc_encrypt_text(message, public_key)
            except Exception as e:
                encrypted = f"Encryption error: {str(e)}"
        elif action == 'decrypt':
            private_key = request.form['private_key']
            try:
                decrypted = ecc_decrypt_text(message, private_key)
            except Exception as e:
                decrypted = f"Decryption error: {str(e)}"

    return render_template('ecc.html', encrypted=encrypted, decrypted=decrypted,
                           public_key=public_key, private_key=private_key)


@app.route('/download', methods=['POST'])
def download():
    content = request.form['content']
    filename = request.form.get('filename', 'output.txt')
    
    response = make_response(content) # type: ignore
    response.headers.set('Content-Disposition', f'attachment; filename={filename}')
    response.headers.set('Content-Type', 'text/plain')
    return response


if __name__ == '__main__':
    app.run(debug=True)
