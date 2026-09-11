# Fixture vulnérable : clé privée PEM hardcodée
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWep4PAtGoRBh..."

def sign_token(payload):
    import jwt
    return jwt.encode(payload, PRIVATE_KEY, algorithm="RS256")
