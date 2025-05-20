from flask import Flask, render_template, request
from Crypto.Cipher import AES, DES, Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib

app = Flask(__name__)

# Helper: Get block size per algorithm
def get_block_size(algorithm):
    return {
        'AES': 16,
        'DES': 8,
        'Blowfish': 8
    }.get(algorithm, 16)

# Helper: Generate key of proper length
def generate_key(key, algorithm):
    if algorithm == 'AES':
        return hashlib.sha256(key.encode()).digest()
    elif algorithm == 'DES':
        return hashlib.md5(key.encode()).digest()[:8]
    elif algorithm == 'Blowfish':
        return hashlib.sha256(key.encode()).digest()[:16]
    return None

# Encryption logic
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

# Decryption logic
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

if __name__ == '__main__':
    app.run(debug=True)
