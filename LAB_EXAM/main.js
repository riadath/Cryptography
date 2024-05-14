const crypto = require('crypto');

// Generate RSA key pair
function generateKeyPair() {
    return crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: {
            type: 'spki',
            format: 'pem'
        },
        privateKeyEncoding: {
            type: 'pkcs8',
            format: 'pem',
            cipher: 'aes-256-cbc',
            passphrase: 'top-secret'
        }
    });
}

// Hashing Example
function hashData(data) {
    const hash = crypto.createHash('sha256');
    hash.update(data);
    return hash.digest('hex');
}

// Encryption and Decryption
function encryptData(data, password) {
    const key = crypto.scryptSync(password, 'salt', 32); // Generates a key using the password
    const iv = crypto.randomBytes(16); // Generates a random initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') }; // Return IV with the encrypted data
}

function decryptData(encryptedData, password) {
    const key = crypto.scryptSync(password, 'salt', 32); // Reconstruct key using the same password and salt
    const iv = Buffer.from(encryptedData.iv, 'hex'); // Convert hex string back to buffer
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

// Digital Signatures
function createSignature(data, privateKey) {
    const signer = crypto.createSign('RSA-SHA256');
    signer.update(data);
    return signer.sign({ key: privateKey, passphrase: 'top-secret' }, 'hex');
}

function verifySignature(data, signature, publicKey) {
    const verifier = crypto.createVerify('RSA-SHA256');
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'hex');
}

// Generate keys
const { publicKey, privateKey } = generateKeyPair();

// Usage
const data = "passing a different data";
const password = "password123";

const encryptedData = encryptData(data, password);


console.log("Hashed Data:", hashData(data), "\n");

console.log("Encrypted Data:", encryptedData.encrypted, "\n");

console.log("IV for Decryption:", encryptedData.iv, "\n");

console.log("Decrypted Data:", decryptData(encryptedData, password), "\n");

console.log("Signature:", createSignature(data, privateKey), "\n");

console.log("Signature Verified:", verifySignature(data, createSignature(data, privateKey), publicKey), "\n");
