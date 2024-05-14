const crypto = require('crypto');

// Generate RSA key pair
function generateKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
    modulusLength: 2048,
  });
  return { publicKey, privateKey };
}

// Sign a message
function signMessage(message, privateKey) {
  const signer = crypto.createSign('SHA256');
  signer.update(message);
  signer.end();
  const signature = signer.sign(privateKey, 'base64');
  return signature;
}

// Verify a signature
function verifySignature(message, signature, publicKey) {
  const verifier = crypto.createVerify('SHA256');
  verifier.update(message);
  verifier.end();
  return verifier.verify(publicKey, signature, 'base64');
}

// Example usage
const { publicKey, privateKey } = generateKeyPair();

const message = 'This is a message to sign';
const signature = signMessage(message, privateKey);
const isVerified = verifySignature(message, signature, publicKey);

console.log('Public Key:', publicKey.export({ type: 'pkcs1', format: 'pem' }));
console.log('Private Key:', privateKey.export({ type: 'pkcs1', format: 'pem' }));
console.log('Signature:', signature);
console.log('Verification result:', isVerified);
