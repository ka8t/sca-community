# VULNERABLE: Weak/obsolete cryptographic algorithms
# Expected: Should trigger "Algorithme cryptographique faible" detection (HIGH severity)

import hashlib

def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()

def hash_token(token):
    return hashlib.sha1(token.encode()).hexdigest()
