const crypto = require('crypto');

function generateKeyPair(passphrase) {
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
            passphrase: passphrase
        }
    });
}

function encryptData(data, publicKey) {
    const buffer = Buffer.from(data, 'utf8');
    const encrypted = crypto.publicEncrypt(publicKey, buffer);
    return encrypted.toString('base64');
}

function decryptData(data, privateKey, passphrase) {
    const buffer = Buffer.from(data, 'base64');
    const decrypted = crypto.privateDecrypt(
        {
            key: privateKey,
            passphrase: passphrase,
        },
        buffer
    );
    return decrypted.toString('utf8');
}

function createSignature(data, privateKey, passphrase) {
    const signer = crypto.createSign('sha256');
    signer.update(data);
    const signature = signer.sign({ key: privateKey, passphrase: passphrase }, 'hex');
    return signature;
}

function verifySignature(data, signature, publicKey) {
    const verifier = crypto.createVerify('sha256');
    verifier.update(data);
    return verifier.verify(publicKey, signature, 'hex');
}

const rootCA = {
    keys: generateKeyPair('rootCApass'),
    publicKey() {
        return this.keys.publicKey;
    },
    signCertificate(authPublicKey) {
        return createSignature(authPublicKey, this.keys.privateKey, 'rootCApass');
    },
    verifyCertificate(authPublicKey, signature) {
        return verifySignature(authPublicKey, signature, this.keys.publicKey);
    }
};

const certificateAuthority = {
    keys: generateKeyPair('CApass'),
    certificate: null,
    signCertificate(userPublicKey) {
        return createSignature(userPublicKey, this.keys.privateKey, 'CApass');
    },
    verifyCertificate(userPublicKey, signature) {
        return verifySignature(userPublicKey, signature, this.keys.publicKey);
    }
};

const alice = {
    keys: generateKeyPair('alicePass'),
    certificate: null
};

const bob = {
    keys: generateKeyPair('bobPass'),
    certificate: null
};


function main() {

    // 1/1, 1/2
    console.log("\t\t\tRoot Certificate Authority Public Key:\n", rootCA.publicKey(), "\n\n")


    // 1/2, 2/2 : RCA signs the CA
    certificateAuthority.certificate = rootCA.signCertificate(certificateAuthority.keys.publicKey)

    // 2/1, 2/3
    console.log("\t\t\tCertificate Authority Key Pair:\n", certificateAuthority.keys, "\n\n")
    console.log("\t\t\t\tCA Signed Certificate:\n", certificateAuthority.certificate, "\n\n")


    // verify CA certificate
    console.log("___________Vetification Status of CA Certificate: ", rootCA.verifyCertificate(certificateAuthority.keys.publicKey, certificateAuthority.certificate), "\n\n")

    // 3
    alice.certificate = certificateAuthority.signCertificate(alice.keys.publicKey);
    bob.certificate = certificateAuthority.signCertificate(bob.keys.publicKey);

    console.log("\t\t\t\tAlice's Certificate:\n", alice.certificate, "\n\n")
    console.log("\t\t\t\tBobs' Certificate:\n", bob.certificate, "\n\n")




    const messageFromAlice = "Hello Bob!";
    const encryptedMessage = encryptData(messageFromAlice, bob.keys.publicKey);

    console.log("\t\t\tEncrypted Message Sent by Alice->Bob:\n", encryptedMessage, "\n\n\n")

    const decryptedMessage = decryptData(encryptedMessage, bob.keys.privateKey, 'bobPass');

    console.log("Decrypted Message Sent by Bob->Alice:", decryptedMessage, "\n\n\n")


}
// Malory

function symmetricEncrypt(data, secret) {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(secret, 'hex'), iv);
    let encrypted = cipher.update(data, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return { encrypted, iv: iv.toString('hex') };
}

function symmetricDecrypt(encryptedData, secret) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', Buffer.from(secret, 'hex'), Buffer.from(encryptedData.iv, 'hex'));
    let decrypted = decipher.update(encryptedData.encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

function malory_intercept() {
    // Shared secret key (insecurely shared or leaked, which Malory knows)
    const sharedSecret = crypto.randomBytes(32).toString('hex');

    // Alice encrypts a message for Bob using the shared secret
    const messageFromAlice = "Hello Bob!";
    const encryptedMessage = symmetricEncrypt(messageFromAlice, sharedSecret);

    // Malory captures the encrypted message and decrypts it using the shared secret
    const decryptedMessageByMalory = symmetricDecrypt(encryptedMessage, sharedSecret);

    console.log(`Malory intercepts and decrypts the message: ${decryptedMessageByMalory}`);


}


main()
malory_intercept()