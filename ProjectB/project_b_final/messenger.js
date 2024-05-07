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

    this.sendCount = {}
    this.receiveCount = {}

    this.messageQueue = {}

    this.previousMessageType = null

    this.previousN = 0

  }

  // Helper functions  

  async KDF_RK(root_key, root_input) {
    const [rkBuf, chainKeyBuf] = await HKDF(root_key, root_input, 'ratchet-str')
    return [rkBuf, chainKeyBuf]
  }


  async KDF_CK(chain_key) {
    chain_key = await HMACtoHMACKey(chain_key, 'chain-key')
    const message_key = await HMACtoAESKey(chain_key, 'message-key')
    const mk_buffer = await HMACtoAESKey(chain_key, 'message-key', true)
    return [chain_key, message_key, mk_buffer]

  }

  async performDHRatchetSender(private_key, public_key) {
    var eg_key = await generateEG()
    var root_key = await computeDH(private_key, public_key)
    var root_input = await computeDH(eg_key.sec, public_key)
    var ck = await this.KDF_RK(root_key, root_input)
    ck = ck[1]

    return [eg_key, root_key, ck]
  }

  async performDHRatchetReceiver(private_key, public_key, hd_pub_key) {
    var root_key = await computeDH(private_key, public_key)
    var root_input = await computeDH(private_key, hd_pub_key)
    var ck = await this.KDF_RK(root_key, root_input)
    ck = ck[1]

    return [root_key, ck]
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
      var [eg_key, root_key, ck_sender] = await this.performDHRatchetSender(senderPrivateKey, receiverPublicKey)

      this.sendCount[name] = 0

      this.conns[name] = {
        DHsend_pair: eg_key, // DHs pair for sending chain
        DHreceive: receiverPublicKey, // reciver public key for receiving chain
        root_key_chain: root_key, // root key chain
        chain_key_sender: ck_sender,
        chain_key_receiver: null
      }
    }

    const current_conn = this.conns[name]


    var alreadyDHRatchetPerformed = false
    if (current_conn.chain_key_sender == null) {
      alreadyDHRatchetPerformed = true
      var [eg_key, root_key, ck_sender] = await this.performDHRatchetSender(senderPrivateKey, receiverPublicKey)
      current_conn.DHsend_pair = eg_key
      current_conn.chain_key_sender = ck_sender

      this.sendCount[name] = 0

    }

    if (this.previousMessageType == 'recieve' && !alreadyDHRatchetPerformed) {
      // perform a DH ratchet step
      var [eg_key, root_key, ck_sender] = await this.performDHRatchetSender(senderPrivateKey, receiverPublicKey)

      current_conn.chain_key_sender = ck_sender
      current_conn.root_key_chain = root_key

      this.previousN = this.receiveCount[name] - this.previousN
    }

    const [chain_key, message_key, mk_buffer] = await this.KDF_CK(current_conn.chain_key_sender)

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
      cGov: cipherkey,
      sendCount: this.sendCount[name],
      pn: this.previousN
    }



    const ciphertext = await encryptWithGCM(message_key, plaintext, IV, JSON.stringify(header))

    this.sendCount[name] = this.sendCount[name] ? this.sendCount[name] + 1 : 1;


    this.previousMessageType = 'send'

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

    const senderPublicKey = this.certs[name].publicKey
    const receiverPrivateKey = this.EGKeyPair.sec

    if (!(name in this.conns)) {
      var [root_key, ck_receiver] = await this.performDHRatchetReceiver(receiverPrivateKey, senderPublicKey, header.publicKey)

      this.receiveCount[name] = 0

      this.conns[name] = {
        DHsend_pair: this.EGKeyPair, // DHs pair for sending chain
        DHreceive: header.publicKey, // reciver public key for receiving chain
        root_key_chain: root_key, // root key chain
        chain_key_sender: null,
        chain_key_receiver: ck_receiver
      }
    }

    const current_conn = this.conns[name]

    var alreadyDHRatchetPerformed = false
    if (current_conn.chain_key_receiver == null) {
      alreadyDHRatchetPerformed = true
      var [root_key, ck_receiver] = await this.performDHRatchetReceiver(receiverPrivateKey, senderPublicKey, header.publicKey)

      current_conn.chain_key_receiver = ck_receiver
      current_conn.DHreceive = header.publicKey

      this.receiveCount[name] = 0
    }

    var dhRatchetTriggered = false
    if (this.previousMessageType == 'Send' && !alreadyDHRatchetPerformed) {
      dhRatchetTriggered = true
      // perform a DH ratchet step
      var [root_key, ck_receiver] = await this.performDHRatchetReceiver(receiverPrivateKey, senderPublicKey, header.publicKey)

      current_conn.chain_key_receiver = ck_receiver
      current_conn.root_key_chain = root_key
    }


    // Extra Credit stuff

    if (header.sendCount != this.receiveCount[name]) {
      if (dhRatchetTriggered) {
        var prevMissed = this.previousN - this.receiveCount[name]
        var currentMissed = header.sendCount 
        for (var i = 0; i < prevMissed; i++) {
          const [chain_key, message_key, mk_buffer] = await this.KDF_CK(current_conn.chain_key_receiver)

          if (name in this.messageQueue) {
            this.messageQueue[name][this.receiveCount[name]] = message_key
          } else {
            this.messageQueue[name] = {}
            this.messageQueue[name][this.receiveCount[name]] = message_key
          }
          current_conn.chain_key_receiver = chain_key
          this.receiveCount[name] += 1
        }

        for (var i = 0; i < currentMissed; i++) {
          const [chain_key, message_key, mk_buffer] = await this.KDF_CK(current_conn.chain_key_receiver)

          if (name in this.messageQueue) {
            this.messageQueue[name][this.receiveCount[name]] = message_key
          } else {
            this.messageQueue[name] = {}
            this.messageQueue[name][this.receiveCount[name]] = message_key
          }
          current_conn.chain_key_receiver = chain_key
          this.receiveCount[name] += 1
        }
      }

      var missed = header.sendCount - this.receiveCount[name]
      for (var i = 0; i < missed; i++) {
        const [chain_key, message_key, mk_buffer] = await this.KDF_CK(current_conn.chain_key_receiver)

        if (name in this.messageQueue) {
          this.messageQueue[name][this.receiveCount[name]] = message_key
        } else {
          this.messageQueue[name] = {}
          this.messageQueue[name][this.receiveCount[name]] = message_key
        }
        current_conn.chain_key_receiver = chain_key
        this.receiveCount[name] += 1
      }
    }


    if (header.sendCount < this.receiveCount[name]) {

      // take message key from message queue
      const message_key = this.messageQueue[name][header.sendCount]

      const plaintext = bufferToString(await decryptWithGCM(message_key, ciphertext, header.receiverIV, JSON.stringify(header)))

      this.previousMessageType = 'receive'
      return plaintext

    }






    const [chain_key, message_key, mk_buffer] = await this.KDF_CK(current_conn.chain_key_receiver)
    current_conn.chain_key_receiver = chain_key



    const plaintext = bufferToString(await decryptWithGCM(message_key, ciphertext, header.receiverIV, JSON.stringify(header)))


    this.receiveCount[name] = this.receiveCount[name] ? this.receiveCount[name] + 1 : 1;

    this.previousMessageType = 'receive'

    return plaintext
  }
};

module.exports = {
  MessengerClient
}
