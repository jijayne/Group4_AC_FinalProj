import hashlib

def hash_text(text, method):
    if method == "MD5":
        return hashlib.md5(text.encode()).hexdigest()
    elif method == "SHA1":
        return hashlib.sha1(text.encode()).hexdigest()
    elif method == "SHA256":
        return hashlib.sha256(text.encode()).hexdigest()
    elif method == "SHA512":
        return hashlib.sha512(text.encode()).hexdigest()
    else:
        return "Invalid hash method"
