# 🔐 SecureFlow

**Course:** CSAC 329- Applied Cryptography  
**Date:** May 2025  

## 👥 Group Members

- [Jane Cagorong]
- [Justine Son Camila]
- [Mark Angelo Umacam]

---

## 📘 Introduction

**SecureFlow** is a **Flask-based web application** that demonstrates the use of key cryptographic algorithms for securing information. The platform allows users to perform encryption, decryption, and hashing of text and files using both symmetric and asymmetric techniques, as well as hash functions.  

The frontend is designed using **HTML and CSS** to create a modern, responsive interface, while Flask handles the backend logic and routing. This hands-on project showcases how cryptography is practically implemented in secure systems, making it a valuable learning tool in the field of applied cryptography.

---

## 🎯 Project Objectives

1. To develop a functional web-based interface for demonstrating various cryptographic operations.
2. To implement and visualize symmetric, asymmetric, and hashing cryptographic algorithms using Python.
3. To highlight the practical applications and differences between encryption methods and hashing techniques.
4. To provide a secure and interactive platform for encrypting, decrypting, and hashing text or files.

---

## 🔧 Application Architecture & UI Design

The **SecureFlow** application is built with a **Flask** backend and a frontend styled using **HTML and CSS**, featuring a neon-themed dark mode interface for a modern aesthetic.

### 🧩 Architecture Overview:
- **Frontend (HTML/CSS)**: User interface with input forms, file upload, and algorithm selection.
- **Flask Backend**: Handles routing, algorithm logic, encryption/decryption, and result rendering.
- **Templates**: Uses Jinja2 for dynamic HTML pages.
- **Static Files**: Contains CSS (and optional JavaScript) for styling and interaction.

### 👨‍💻 User Features:
- Encrypt or decrypt text/files using **AES**, **DES**, or **Blowfish**.
- Perform **RSA** or **ElGamal** encryption/decryption with key generation.
- Hash text or files using **MD5**, **SHA-1**, **SHA-256**, or **SHA-3**.
- Receive outputs directly on the interface with download options.

---

## 🔐 Cryptographic Algorithms Implemented

### 🔸 Symmetric Encryption

#### 1. **AES (Advanced Encryption Standard)**
- **Type:** Symmetric
- **History:** Standardized by NIST in 2001, AES replaced DES as the encryption standard.
- **Process:** Uses 128, 192, or 256-bit keys with multiple rounds of substitution, permutation, and mixing.
- **Library Used:** `Crypto.Cipher.AES`
- **Integration:** Users input text/key and select AES; Flask handles encryption/decryption logic and displays the result.

#### 2. **DES (Data Encryption Standard)**
- **Type:** Symmetric
- **History:** Developed in the 1970s by IBM and adopted as a federal standard.
- **Process:** Operates on 64-bit blocks using a 56-bit key over 16 rounds.
- **Library Used:** `Crypto.Cipher.DES`
- **Integration:** Similar to AES, with dedicated routes for handling DES logic.

#### 3. **Blowfish**
- **Type:** Symmetric
- **History:** Developed by Bruce Schneier in 1993 as a free alternative to DES.
- **Process:** A 16-round Feistel cipher that supports variable key lengths up to 448 bits.
- **Library Used:** `Crypto.Cipher.Blowfish`
- **Integration:** Users select Blowfish and provide key/input via web form.

---

### 🔹 Asymmetric Encryption

#### 4. **RSA (Rivest-Shamir-Adleman)**
- **Type:** Asymmetric
- **History:** Developed in 1977; one of the most widely used public-key cryptosystems.
- **Process:** Involves key pair generation, encryption with public key, decryption with private key.
- **Library Used:** `Crypto.PublicKey.RSA`, `Crypto.Cipher.PKCS1_OAEP`
- **Integration:** Key generation and encryption handled by Flask; users can download keys.

#### 5. **ElGamal**
- **Type:** Asymmetric
- **History:** Introduced by Taher ElGamal in 1985 based on Diffie-Hellman key exchange.
- **Process:** Random number-based encryption that produces ciphertext as a tuple.
- **Library Used:** `pycryptodome` or custom modular implementation.
- **Integration:** Handled via Flask forms with random key generation and modular math.

---

### 🔹 Hashing Functions

#### 6. **MD5 (Message Digest 5)**
- **Type:** Hashing
- **History:** Developed by Ronald Rivest in 1992.
- **Process:** Produces a 128-bit hash; considered broken for cryptographic security but still used in checksums.
- **Library Used:** `hashlib.md5()`
- **Integration:** Hash is calculated and displayed directly after user inputs text.

#### 7. **SHA-1 (Secure Hash Algorithm 1)**
- **Type:** Hashing
- **History:** Designed by NSA, widely used before being deprecated due to vulnerabilities.
- **Process:** Produces a 160-bit hash.
- **Library Used:** `hashlib.sha1()`
- **Integration:** Processes input and displays the hash output on the web page.

#### 8. **SHA-256**
- **Type:** Hashing
- **History:** Part of the SHA-2 family; more secure alternative to SHA-1.
- **Process:** Produces a 256-bit hash using bitwise operations and modular math.
- **Library Used:** `hashlib.sha256()`
- **Integration:** Users input data and receive hash output instantly.

#### 9. **SHA-3**
- **Type:** Hashing
- **History:** Announced by NIST in 2015 as the latest standard; uses Keccak algorithm.
- **Process:** Sponge construction producing 224, 256, 384, or 512-bit digests.
- **Library Used:** `hashlib.sha3_256()` (or variants)
- **Integration:** Added as a selectable option in the web UI.

---

## 📦 Libraries and Dependencies

- **Flask** – For backend and routing
- **PyCryptodome** – Symmetric and asymmetric cryptography (`Crypto`)
- **hashlib** – Built-in hashing functions
- **HTML/CSS** – Frontend layout and styling
- **Jinja2** – Template engine used in Flask
- **Werkzeug** – For secure file handling

---

## 🚀 How to Run the Project

1. Clone the repository:
   ```bash
   git clone https://github.com/jijayne/Group4_AC_FinalProj.git
   cd SecureFlow
2. Install required packages:
   pip install -r requirements.txt
3. Run the Flask app:
   python app.py
4. Open your browser and navigate to:
   http://127.0.0.1:5000

## License
This project is for educational purposes under the Applied Cryptography course. Not intended for real-world production use.

## 🙌 Acknowledgments
CSPC College of Computer Studies
Python and Flask communities
PyCryptodome and hashlib maintainers



