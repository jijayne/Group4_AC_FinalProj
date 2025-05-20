import hashlib

def hash_text(text, algorithm):
    text_bytes = text.encode()

    if algorithm == 'sha256':
        return hashlib.sha256(text_bytes).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(text_bytes).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(text_bytes).hexdigest()
    elif algorithm == 'blake2b':
        return hashlib.blake2b(text_bytes).hexdigest()
    else:
        return "Unsupported algorithm"

def hash_file(file_path, algorithm):
    with open(file_path, 'rb') as f:
        data = f.read()

    if algorithm == 'sha256':
        return hashlib.sha256(data).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(data).hexdigest()
    elif algorithm == 'md5':
        return hashlib.md5(data).hexdigest()
    elif algorithm == 'blake2b':
        return hashlib.blake2b(data).hexdigest()
    else:
        return "Unsupported algorithm"
