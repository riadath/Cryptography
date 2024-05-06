// messenger.js
'use strict'

// Assuming the lib functions are imported
const {
    govEncryptionDataStr,
    genRandomSalt,
    generateEG,
    computeDH,
    encryptWithGCM,
    decryptWithGCM,
    bufferToString
} = require('./lib');  // Adjust this path based on your project structure



async function testMultipleMessages() {
    const messenger = new Messenger();
    const aliceCert = await messenger.generateCertificate('Alice');
    const bobCert = await messenger.generateCertificate('Bob');

    // Simulate receiving certificates and setting up sessions
    await messenger.receiveCertificate(aliceCert, 'validSignature');
    await messenger.receiveCertificate(bobCert, 'validSignature');

    // Send multiple messages from Alice to Bob and vice versa
    const messagesFromAlice = ["Hi Bob!", "How are you?", "Did you get the documents?"];
    const messagesFromBob = ["Hi Alice!", "I'm good, thanks!", "Yes, I got them."];

    console.log("Alice to Bob communication:");
    for (let msg of messagesFromAlice) {
        const message = await messenger.sendMessage('Alice', 'Bob', msg);
        const receivedMessage = await messenger.receiveMessage('Bob', 'Alice', message);
        console.log('Decrypted message:', bufferToString(receivedMessage));
    }

    console.log("Bob to Alice communication:");
    for (let msg of messagesFromBob) {
        const message = await messenger.sendMessage('Bob', 'Alice', msg);
        const receivedMessage = await messenger.receiveMessage('Alice', 'Bob', message);
        console.log('Decrypted message:', bufferToString(receivedMessage));
    }
}


class Messenger {
    constructor() {
        this.keyPairs = {}; // Stores key pairs indexed by username
        this.certificates = {}; // Stores certificates indexed by username
        this.sessions = {}; // Stores session details indexed by username
    }

    async encryptWithPublic(publicKey, data) {
        // Ensure this method correctly handles public key encryption, simulated for the example
        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "RSA-OAEP",
            },
            publicKey,  // the government's public key as a CryptoKey object
            new TextEncoder().encode(data)  // Encode the data to a Uint8Array if not already
        );
        return encryptedData;
    }

    async generateCertificate(username) {
        const keyPair = await generateEG();
        this.keyPairs[username] = keyPair;
        const certificate = {
            username: username,
            publicKey: keyPair.pub
        };
        this.certificates[username] = certificate;
        return certificate;
    }

    receiveCertificate(certificate, signature) {
        const { username, publicKey } = certificate;
        if (verifySignature(publicKey, signature)) {
            this.certificates[username] = certificate;
        } else {
            throw new Error("Certificate verification failed");
        }
    }

    async sendMessage(sender_name, recipient_name, message) {
        const recipientCertificate = this.certificates[recipient_name];
        if (!recipientCertificate) {
            throw new Error("Certificate not found for recipient");
        }
        const sessionKey = await this.establishSession(sender_name, recipientCertificate.publicKey);

        const iv = genRandomSalt();
        const encryptedMessage = await encryptWithGCM(sessionKey, message, iv);
        const header = {
            iv: Buffer.from(iv).toString('base64'),
            vGov: '...', // Placeholder
            cGov: '...'  // Placeholder
        };

        return { header, encryptedMessage };
    }

    async receiveMessage(recipient_name, sender_name, { header, encryptedMessage }) {
        const sessionKey = this.sessions[sender_name]?.sessionKey;

        if (!sessionKey) {
            throw new Error("Session not established");
        }
        if (!header.iv) {
            throw new Error("IV not found in message header");
        }
        const iv = Buffer.from(header.iv, 'base64');
        const message = await decryptWithGCM(sessionKey, encryptedMessage, iv);
        return message;
    }

    async establishSession(name, theirPublicKey) {
        const myPrivateKey = this.keyPairs[name]?.sec;
        const sessionKey = await computeDH(myPrivateKey, theirPublicKey);
        this.sessions[name] = { sessionKey };
        return sessionKey;
    }
}

function verifySignature(publicKey, signature) {
    return true; // Placeholder for true verification logic
}

// Example usage
// Assuming the previous setup and definitions are in place
(async () => {
    console.log("Testing single message exchange:");
    const messenger = new Messenger();
    const aliceCert = await messenger.generateCertificate('Alice');
    const bobCert = await messenger.generateCertificate('Bob');

    await messenger.receiveCertificate(aliceCert, 'signatureHere');
    await messenger.receiveCertificate(bobCert, 'signatureHere');

    const message = await messenger.sendMessage('Alice', 'Bob', 'Hello Bob!');
    console.log('Encrypted message:', message);

    const receivedMessage = await messenger.receiveMessage('Bob', 'Alice', message);
    console.log('Decrypted message in ASCII:', bufferToString(receivedMessage));

    // Now testing multiple messages
    console.log("\nStarting multiple message exchanges:");
    await testMultipleMessages();  // Run the multiple messages test
})();
