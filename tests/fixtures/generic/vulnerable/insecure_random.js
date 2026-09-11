// VULNERABLE: Insecure random number generator for sensitive operations
// Expected: Should trigger "RNG non sécurisé" detection (MEDIUM severity)

function generateToken() {
    return Math.random().toString(36).substring(2);
}

function generateOTP() {
    return Math.floor(Math.random() * 1000000);
}
