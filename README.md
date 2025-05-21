# 🔐 Applied Cryptography Application 
#### 21: May 2025

<br>

## Group Members
##### Cagorong, Jane
##### Camila, Justine Son
##### Umacam, Mark Angelo

<br>

# 📌 Introduction
##### This project presents a simple yet functional cryptography application that demonstrates the application of various cryptographic techniques to secure digital communication and data. Cryptography is essential for protecting the confidentiality, integrity, and authenticity of information in modern computing systems. The application allows users to encrypt, decrypt, and hash both text and files using symmetric, asymmetric, and hashing algorithms through a user-friendly interface.

<br>

# 🎯 Project Objectives
##### 1. To implement three symmetric encryption algorithms and two asymmetric encryption algorithms for text and file-based encryption/decryption.
##### 2. To apply at least four hashing functions that support both text and file inputs.
##### 3. To provide a UI-based tool for users to interact with cryptographic techniques and view their inner workings and results.

<br>

# 🧩 Discussions
#### 🔧 Application Architecture & UI

##### The application is developed using Python and Streamlit as the UI framework. Streamlit enables rapid development of web-based user interfaces with minimal overhead. The system is modularized into algorithm components for symmetric encryption, asymmetric encryption, and hashing. Each cryptographic operation is executed from its respective module and integrated into the Streamlit interface.

<br>

# 🔐 Implemented Cryptographic Algorithms
### 1. AES - Symmetric Algorithm
**Type**: Symmetric (Text & File Encryption/Decryption)
- **Background**: Advanced Encryption Standard (AES) was standardized by NIST in 2001 and is widely used in secure communication.
- **Process**: Encrypts plaintext using a symmetric key and CBC mode with PKCS7 padding. Uses 128-bit block size.
- 
<br>

### 2. RSA - Asymmetric Algorithm
- **Type**: Asymmetric (Text Encryption/Decryption)
- **Background**: RSA (Rivest-Shamir-Adleman) is a public-key cryptographic algorithm introduced in 1977. It relies on the mathematical difficulty of factoring large primes.

<br>

### 3. SHA-256, SHA-1, MD5, BLAKE2b - Hash Functions
- **Background**:
- - **SHA-256**: Secure Hash Algorithm, 256-bit output, part of SHA-2 family.
- - **SHA-1**: 160-bit output, legacy standard.
- - **MD5**: 128-bit hash, now considered insecure for cryptographic use.
- - **BLAKE2b**: Modern, secure and fast hash function alternative.

<br>

### 4. fcsdfcc
