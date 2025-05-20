from flask import Flask, render_template, request, send_file
from crypto import symmetric, asymmetric, hashing
import os

app = Flask(__name__)
UPLOAD_FOLDER = "sample_files"
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/encrypt_text", methods=["POST"])
def encrypt_text():
    text = request.form["text"]
    method = request.form["method"]

    if method == "AES":
        encrypted = symmetric.encrypt_aes(text)
    elif method == "DES":
        encrypted = symmetric.encrypt_des(text)
    elif method == "ChaCha20":
        encrypted = symmetric.encrypt_chacha(text)
    elif method == "RSA":
        encrypted = asymmetric.encrypt_rsa(text)
    else:
        encrypted = "Unsupported method."

    return render_template("index.html", result=encrypted)


@app.route("/hash_text", methods=["POST"])
def hash_text():
    text = request.form["text"]
    method = request.form["hash_method"]

    hashed = hashing.hash_text(text, method)

    return render_template("index.html", hash_result=hashed)


if __name__ == "__main__":
    app.run(debug=True)
