# CLEAN: Strong cryptographic algorithms
# Expected: Should NOT trigger "Algorithme cryptographique faible" detection

import hashlib

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def hash_token(token):
    return hashlib.sha512(token.encode()).hexdigest()
