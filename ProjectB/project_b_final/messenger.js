'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  generateEG, // async
  computeDH, // async
  verifyWithECDSA, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr
} = require('./lib')

/** ******* Implementation ********/


async function KDF_RK(root_key, root_input) {
  const [rkBuf, chainKeyBuf] = await HKDF(root_key, root_input, 'ratchet-str')
  return [rkBuf, chainKeyBuf]
}


async function KDF_CK(chain_key) {
  chain_key = await HMACtoHMACKey(chain_key, 'chain-key')
  const message_key = await HMACtoAESKey(chain_key, 'message-key')
  const mk_buffer = await cryptoKeyToJSON(message_key)
  return [chain_key, message_key, mk_buffer]

}




class MessengerClient {
  constructor(certAuthorityPublicKey, govPublicKey) {
    // the certificate authority DSA public key is used to
    // verify the authenticity and integrity of certificates
    // of other users (see handout and receiveCertificate)

    // you can store data as needed in these objects.
    // Feel free to modify their structure as you see fit.
    this.caPublicKey = certAuthorityPublicKey
    this.govPublicKey = govPublicKey
    this.conns = {} // data for each active connection
    this.certs = {} // certificates of other users
    this.EGKeyPair = {} // keypair from generateCertificate
  }

  /**
   * Generate a certificate to be stored with the certificate authority.
   * The certificate must contain the field "username".
   *
   * Arguments:
   *   username: string
   *
   * Return Type: certificate object/dictionary
   */
  async generateCertificate(username) {
    this.EGKeyPair = await generateEG()
    const certificate = {
      username: username,
      publicKey: this.EGKeyPair.pub
    }
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: ArrayBuffer
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    const isValid = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (isValid) {
      this.certs[certificate.username] = certificate
    }
    else {
      throw ('Invalid Certificate')
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, ArrayBuffer]
 */
  async sendMessage(name, plaintext) {
    const receiverPublicKey = this.certs[name].publicKey
    const senderPrivateKey = this.EGKeyPair.sec
    if (!(name in this.conns)) {
      var eg_key = await generateEG()
      var root_key = await computeDH(senderPrivateKey, receiverPublicKey)
      var root_input = await computeDH(eg_key.sec, receiverPublicKey)
      var ck_sender = await KDF_RK(root_key, root_input)
      ck_sender = ck_sender[0]
      /*  
      * 1. Generate a new DHs keypair (eg_key).
      * 2. Compute the root key (root_key) using the sender's private key and the receiver's public key.
      * 3. Compute the chain key for the sender (chain_key_sender) using the root key and the DHs keypair.
      * 4. Store the DHs keypair, the receiver's public key, the root key, and the chain key for the sender in the connection data structure.

      */
      this.conns[name] = {
        DHsend_pair: eg_key, // DHs pair for sending chain
        DHreceive: receiverPublicKey, // reciver public key for receiving chain
        root_key_chain: root_key, // root key chain
        chain_key_sender: ck_sender,
        chain_key_receiver: null
      }
    }

    const current_conn = this.conns[name]


    if (current_conn.chain_key_sender == null) {
      console.log("current_con: ", current_conn)
      var root_key = await computeDH(senderPrivateKey, receiverPublicKey)
      var eg_key = await generateEG()
      var root_input = await computeDH(eg_key.sec, receiverPublicKey)
      var ck_sender = await KDF_RK(root_key, root_input)
      ck_sender = ck_sender[1]
      current_conn.DHsend_pair = eg_key
      current_conn.chain_key_sender = ck_sender
    }



    const [chain_key, message_key, mk_buffer] = await KDF_CK(current_conn.chain_key_sender)
    current_conn.chain_key_sender = chain_key
    const IV = genRandomSalt()
    const gov_IV = genRandomSalt()
    const gov_DH = await generateEG()
    const gov_shared_key = await computeDH(gov_DH.sec, this.govPublicKey)
    const gov_aes_key = await HMACtoAESKey(gov_shared_key, govEncryptionDataStr)
    const cipherkey = await encryptWithGCM(gov_aes_key, mk_buffer, gov_IV)

    const header = {
      publicKey: current_conn.DHsend_pair.pub,
      receiverIV: IV,
      ivGov: gov_IV,
      vGov: gov_DH.pub,
      cGov: cipherkey
    }

    const ciphertext = await encryptWithGCM(message_key, plaintext, IV, JSON.stringify(header))

    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, ArrayBuffer]
 *
 * Return Type: string
 */
  async receiveMessage(name, [header, ciphertext]) {
    throw ('not implemented!')
    return plaintext
  }
};

module.exports = {
  MessengerClient
}
