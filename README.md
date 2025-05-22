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

# 👨‍💻 User Features:
- Encrypt or decrypt text/files using AES, DES, or XOR.

- Perform RSA or ECC encryption/decryption with key generation.

- Hash text or files using MD5, SHA-1, SHA-256, or SHA-512.

- Receive outputs directly on the interface with download options.

---

## 🔐 Cryptographic Algorithms Implemented

### 💡 Discussions
🔸 Symmetric Encryption
1. AES (Advanced Encryption Standard)
   Type: Symmetric
   
   History: Adopted by NIST in 2001 as the successor to DES, developed by Belgian cryptographers Vincent Rijmen and Joan Daemen (Rijndael algorithm).
   
   How It Works: Operates on 128-bit blocks using key sizes of 128, 192, or 256 bits. Involves substitution-permutation network over multiple rounds.
   
   Library Used: Crypto.Cipher.AES
   
   Integration: Used for both text and file encryption via Flask backend.

2. DES (Data Encryption Standard)

   Type: Symmetric
   
   History: Developed by IBM and adopted as a federal standard in 1977. Once a cornerstone of encryption but now considered insecure due to its 56-bit key.
   
   How It Works: Encrypts 64-bit blocks using 16 Feistel rounds and a 56-bit key.
   
   Library Used: Crypto.Cipher.DES
   
   Integration: Implemented for legacy comparison in encryption options.

4. XOR Cipher
   
   Type: Symmetric
   
   History: One of the earliest and simplest encryption methods, used mainly for educational or obfuscation purposes.
   
   How It Works: Performs a bitwise XOR between data and a key. Easily reversible but not secure for real-world use.
   
   Library Used: Custom Python implementation
   
   Integration: Used for basic text encryption with a provided key.

🔹 Asymmetric Encryption
4. RSA (Rivest–Shamir–Adleman)

   Type: Asymmetric
   
   History: Introduced in 1977 by Ron Rivest, Adi Shamir, and Leonard Adleman at MIT. Still widely used in secure communications.
   
   How It Works: Based on factoring large primes; generates public and private key pairs. Encrypts with public key, decrypts with private key.
   
   Library Used: Crypto.PublicKey.RSA, Crypto.Cipher.PKCS1_OAEP
   
   Integration: Allows users to generate keys and perform RSA encryption/decryption of messages.

5. ECC (Elliptic Curve Cryptography)
   
   Type: Asymmetric
   
   History: Proposed in the 1980s by Neal Koblitz and Victor Miller as an alternative to RSA with smaller key sizes and equivalent security.
   
   How It Works: Uses elliptic curves over finite fields to generate keys. Offers strong encryption with efficient computation.
   
   Library Used: ecdsa
   
   Integration: Users can generate ECC key pairs and encrypt/decrypt text using ECC.

🔹 Hashing Algorithms
6. MD5 (Message Digest Algorithm 5)

   Type: Hashing
   
   History: Developed by Ronald Rivest in 1991. Widely used but now vulnerable to collisions.
   
   How It Works: Produces a 128-bit hash value from input data.
   
   Library Used: hashlib.md5()
   
   Integration: Accepts user input or files and displays the resulting MD5 hash.

7. SHA-1 (Secure Hash Algorithm 1)
   
   Type: Hashing
   
   History: Developed by the NSA and published in 1995 as a federal standard. Broken in recent years due to collision attacks.
   
   How It Works: Produces a 160-bit hash value from input data.
   
   Library Used: hashlib.sha1()
   
   Integration: Available for hashing text and file inputs.

9. SHA-256
    
   Type: Hashing
   
   History: Part of the SHA-2 family introduced by NIST in 2001 to replace SHA-1.
   
   How It Works: Produces a 256-bit hash using logical functions, padding, and round-based processing.
   
   Library Used: hashlib.sha256()
   
   Integration: Used to demonstrate modern, secure hashing.

9. SHA-512
    
   Type: Hashing
   
   History: Also part of the SHA-2 family. Offers higher security with 512-bit output.
   
   How It Works: Similar to SHA-256 but operates on 1024-bit blocks with 80 rounds of processing.
   
   Library Used: hashlib.sha512()
   
   Integration: Demonstrated as a strong cryptographic hash option.
   
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
   ```bash
   pip install -r requirements.txt
3. Run the Flask app:
   ```bash
   python app.py
4. Open your browser and navigate to:
   ```bash
   http://127.0.0.1:5000

## License
This project is for educational purposes under the Applied Cryptography course. Not intended for real-world production use.

## 🙌 Acknowledgments
CSPC College of Computer Studies

Python and Flask communities

PyCryptodome and hashlib maintainers



