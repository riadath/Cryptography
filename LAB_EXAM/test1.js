const crypto = require('crypto');

const message = "One message to rule them all"

function generateKeyPair() {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 2048,
    });
    return { publicKey, privateKey };
}


function signMessage(message, privateKey) {
    const signer = crypto.createSign('SHA256')
        .update(message)
        .end()
    const signature = signer.sign(privateKey, 'base64')

    return signature
}

function verifySignature(message, signature, publicKey) {
    const verifier = crypto.createVerify('SHA256')
        .update(message)
        .end()
    return verifier.verify(publicKey, signature, 'base64')
}



const { publicKey, privateKey } = generateKeyPair()

const signature = signMessage(message, privateKey)

const verification_result = verifySignature(message, signature, publicKey)
console.log(verification_result)

