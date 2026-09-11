// CLEAN: Cryptographically secure random generator
// Expected: Should NOT trigger "RNG non sécurisé" detection

function generateToken() {
    return crypto.getRandomValues(new Uint8Array(32)).join('');
}

function generateOTP() {
    const array = new Uint32Array(1);
    crypto.getRandomValues(array);
    return array[0] % 1000000;
}
