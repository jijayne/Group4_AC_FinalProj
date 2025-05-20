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
    rsa_encrypt_file, rsa_decrypt_file,
    generate_ecc_keys, ecc_encrypt_text, ecc_decrypt_text,
    ecc_encrypt_file, ecc_decrypt_file  # ← when you add these too
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
    download_file_path = None

    if request.method == 'POST':
        data_type = request.form.get('data_type')  # 'text' or 'file'
        algorithm = request.form.get('algorithm')
        key = request.form.get('key')

        try:
            if data_type == 'text':
                text = request.form.get('text_input', '')

                if algorithm == 'aes':
                    encrypted = aes_encrypt_text(text, key)
                elif algorithm == 'des':
                    encrypted = des_encrypt_text(text, key)
                elif algorithm == 'fernet':
                    if not key or not key.startswith("gAAAA"):
                        key = generate_fernet_key()
                    encrypted = fernet_encrypt_text(text, key)
                # Add asymmetric text encryptions if needed here
                else:
                    encrypted = "Unsupported algorithm for text encryption."

                text_to_download = encrypted

            elif data_type == 'file':
                uploaded_file = request.files.get('file_input')
                if not uploaded_file or uploaded_file.filename == '':
                    encrypted = "No file selected."
                else:
                    # Save uploaded file temporarily
                    temp_input = tempfile.NamedTemporaryFile(delete=False)
                    uploaded_file.save(temp_input.name)

                    temp_output = tempfile.NamedTemporaryFile(delete=False)
                    temp_output.close()  # Close so encryption function can open

                    if algorithm == 'aes':
                        aes_encrypt_file(temp_input.name, temp_output.name, key)
                    elif algorithm == 'des':
                        # Implement des_encrypt_file similarly if available
                        pass
                    elif algorithm == 'fernet':
                        # Implement fernet_encrypt_file if you want
                        pass
                    else:
                        encrypted = "Unsupported algorithm for file encryption."

                    if not encrypted:
                        # Set path for sending file
                        download_file_path = temp_output.name

                    # Clean up input file after encrypting
                    os.unlink(temp_input.name)

        except Exception as e:
            encrypted = f"Encryption error: {str(e)}"

        # If file encryption succeeded, send the file
        if download_file_path:
            return send_file(download_file_path, as_attachment=True, download_name='encrypted_file')

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

from flask import (
    Flask, request, render_template, send_file, 
    make_response, abort
)
from io import BytesIO

@app.route('/symmetric', methods=['GET', 'POST'])
def symmetric():
    result = None

    if request.method == 'POST':
        algorithm = request.form['algorithm'].strip().lower()
        action = request.form['action']
        mode = request.form['mode']
        key = request.form['key']

        if mode == 'text':
            text = request.form['text']

            try:
                if action == 'encrypt':
                    if algorithm == 'aes':
                        result = aes_encrypt_text(text, key)
                    elif algorithm == 'des':
                        result = des_encrypt_text(text, key)
                    elif algorithm == 'fernet':
                        if not key or not key.startswith("gAAAA"):
                            key = generate_fernet_key()
                        result = fernet_encrypt_text(text, key)
                    else:
                        result = "Unsupported algorithm."
                elif action == 'decrypt':
                    if algorithm == 'aes':
                        result = aes_decrypt_text(text, key)
                    elif algorithm == 'des':
                        result = des_decrypt_text(text, key)
                    elif algorithm == 'fernet':
                        result = fernet_decrypt_text(text, key)
                    else:
                        result = "Unsupported algorithm."
            except Exception as e:
                result = f"Error: {str(e)}"

            # For text mode, render template with result in textarea
            return render_template('symmetric.html', result=result)

        elif mode == 'file':
            # Get uploaded file
            uploaded_file = request.files.get('file_input')

            if uploaded_file is None or uploaded_file.filename == '':
                error_msg = "No file uploaded."
                return render_template('symmetric.html', result=error_msg)

            file_data = uploaded_file.read()

            try:
                if action == 'encrypt':
                    if algorithm == 'aes':
                        processed_data = aes_encrypt_bytes(file_data, key)
                    elif algorithm == 'des':
                        processed_data = des_encrypt_bytes(file_data, key)
                    elif algorithm == 'fernet':
                        if not key or not key.startswith("gAAAA"):
                            key = generate_fernet_key()
                        processed_data = fernet_encrypt_bytes(file_data, key)
                    else:
                        return render_template('symmetric.html', result="Unsupported algorithm.")
                elif action == 'decrypt':
                    if algorithm == 'aes':
                        processed_data = aes_decrypt_bytes(file_data, key)
                    elif algorithm == 'des':
                        processed_data = des_decrypt_bytes(file_data, key)
                    elif algorithm == 'fernet':
                        processed_data = fernet_decrypt_bytes(file_data, key)
                    else:
                        return render_template('symmetric.html', result="Unsupported algorithm.")
            except Exception as e:
                return render_template('symmetric.html', result=f"Error: {str(e)}")

            # Prepare file response for download
            output_filename = f"{action}_{uploaded_file.filename}"
            return send_file(
                BytesIO(processed_data),
                download_name=output_filename,
                as_attachment=True
            )

    # GET request renders page with no result
    return render_template('symmetric.html', result=None)


@app.route('/asymmetric', methods=['GET', 'POST'])
def asymmetric():
    result = None
    public_key = None
    private_key = None
    algorithm = None
    action = None
    encrypted = None
    decrypted = None

    if request.method == 'POST':
        algorithm = request.form.get('algorithm')
        action = request.form.get('action')
        message = request.form.get('text', '')
        
        if algorithm == 'rsa':
            if action == 'generate':
                public_key, private_key = generate_keys()
            elif action == 'encrypt':
                public_key = request.form.get('public_key')
                try:
                    encrypted = rsa_encrypt_text(message, public_key)
                except Exception as e:
                    encrypted = f"Encryption error: {str(e)}"
            elif action == 'decrypt':
                private_key = request.form.get('private_key')
                try:
                    decrypted = rsa_decrypt_text(message, private_key)
                except Exception as e:
                    decrypted = f"Decryption error: {str(e)}"
        
        elif algorithm == 'ecc':
            if action == 'generate':
                public_key, private_key = generate_ecc_keys()
            elif action == 'encrypt':
                public_key = request.form.get('public_key')
                try:
                    encrypted = ecc_encrypt_text(message, public_key)
                except Exception as e:
                    encrypted = f"Encryption error: {str(e)}"
            elif action == 'decrypt':
                private_key = request.form.get('private_key')
                try:
                    decrypted = ecc_decrypt_text(message, private_key)
                except Exception as e:
                    decrypted = f"Decryption error: {str(e)}"
        else:
            result = "Unsupported algorithm selected."

    return render_template('asymmetric.html',
                           encrypted=encrypted,
                           decrypted=decrypted,
                           public_key=public_key,
                           private_key=private_key,
                           algorithm=algorithm,
                           action=action,
                           result=result)

if __name__ == '__main__':
    app.run(debug=True)
