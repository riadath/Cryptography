'use strict'

/** ******* Imports ********/

const {
  /* The following functions are all of the cryptographic
  primatives that you should need for this assignment.
  See lib.js for details on usage. */
  bufferToString,
  genRandomSalt,
  computeDH, // async
  HMACtoAESKey, // async
  HMACtoHMACKey, // async
  HKDF, // async
  encryptWithGCM, // async
  decryptWithGCM,
  cryptoKeyToJSON, // async
  govEncryptionDataStr,
  verifyWithECDSA, // async
  generateEG // async
} = require('./lib')

/** ********* Implementation ********/
class Certificate {
  constructor(key, username) {
    this.key = key // this is the EG public key
    this.username = username
  }
}

class Connection {
  constructor(DHs, DHr, RK, CKs, CKr) {
    this.DHs = DHs // diffie hellman key pair for sending chain
    this.DHr = DHr // diffie hellman public key for receiving chain
    this.RK = RK // root chain key
    this.CKs = CKs // sending chain key
    this.CKr = CKr // receiving chain key
  }
}

async function KDF_RK(RK, root_input) {
  const info_str = 'ratchet-str'
  return await HKDF(RK, root_input, info_str)
}

async function KDF_CK(ck) {
  ck = await HMACtoHMACKey(ck, 'chainKey')
  const mk = await HMACtoAESKey(ck, 'messageKey')
  const mk_buf = await HMACtoAESKey(ck, 'messageKey', true)
  return [ck, mk, mk_buf]
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
    const certificate = new Certificate(this.EGKeyPair.pub, username)
    return certificate
  }

  /**
 * Receive and store another user's certificate.
 *
 * Arguments:
 *   certificate: certificate object/dictionary
 *   signature: string
 *
 * Return Type: void
 */
  async receiveCertificate(certificate, signature) {
    // The signature will be on the output of stringifying the certificate
    // rather than on the certificate directly.
    const certString = JSON.stringify(certificate)
    // verify sign
    const isSignTrue = await verifyWithECDSA(this.caPublicKey, certString, signature)
    if (!isSignTrue) {
      throw ('potential tampering!')
    } else { // store certificate
      this.certs[certificate.username] = certificate
    }
  }

  /**
 * Generate the message to be sent to another user.
 *
 * Arguments:
 *   name: string
 *   plaintext: string
 *
 * Return Type: Tuple of [dictionary, string]
 */
  async sendMessage(name, plaintext) {
    const receiverPublicKey = this.certs[name].key
    const myPrivateKey = this.EGKeyPair.sec
    let RK, CKs, CKr, root_input

    if (!(name in this.conns)) {
      // session setup
      RK = await computeDH(myPrivateKey, receiverPublicKey)

      var EG_key = await generateEG()
      root_input = await computeDH(EG_key.sec, receiverPublicKey)

      var KDF_RK_out = await KDF_RK(RK, root_input)
      RK = KDF_RK_out[0]
      CKs = KDF_RK_out[1]

      CKr = null
      this.conns[name] = new Connection(EG_key, receiverPublicKey, RK, CKs, CKr)
    }

    const curr_conn = this.conns[name]
    if (curr_conn.CKs == null) {
      RK = await computeDH(myPrivateKey, receiverPublicKey)

      var EG_key = await generateEG()
      root_input = await computeDH(EG_key.sec, receiverPublicKey)

      KDF_RK_out = await KDF_RK(RK, root_input)
      RK = KDF_RK_out[0]
      CKs = KDF_RK_out[1]

      curr_conn.DHs = EG_key;
      curr_conn.CKs = CKs;
    }

    const [ck, mk, mk_buf] = await KDF_CK(curr_conn.CKs)
    curr_conn.CKs = ck

    const iv = genRandomSalt()
    const gov_iv = genRandomSalt()
    const gov_dh = await generateEG()
    const gov_shared_key = await computeDH(gov_dh.sec, this.govPublicKey)
    const gov_aes_key = await HMACtoAESKey(gov_shared_key, govEncryptionDataStr)
    const cipherkey = await encryptWithGCM(gov_aes_key, mk_buf, gov_iv) // using mk_buff

    const header = {
      pu: curr_conn.DHs.pub,
      receiverIV: iv,
      ivGov: gov_iv,
      vGov: gov_dh.pub,
      cGov: cipherkey
    }

    const ciphertext = await encryptWithGCM(mk, plaintext, iv, JSON.stringify(header))
    return [header, ciphertext]
  }

  /**
 * Decrypt a message received from another user.
 *
 * Arguments:
 *   name: string
 *   [header, ciphertext]: Tuple of [dictionary, string]
 *
 * Return Type: string
 */
  async receiveMessage(name, [header, ciphertext]) {
    const receiverPublicKey = this.certs[name].key
    const myPrivateKey = this.EGKeyPair.sec
    let RK, CKs, CKr, root_input
    if (!(name in this.conns)) {
      // session setup
      RK = await computeDH(myPrivateKey, receiverPublicKey)

      root_input = await computeDH(myPrivateKey, header.pu)

      var KDF_RK_out = await KDF_RK(RK, root_input)
      RK = KDF_RK_out[0]
      CKr = KDF_RK_out[1]

      CKs = null
      this.conns[name] = new Connection(this.EGKeyPair, header.pu, RK, CKs, CKr)
    }

    const curr_conn = this.conns[name]
    if (curr_conn.CKr == null) {
      RK = await computeDH(myPrivateKey, receiverPublicKey)

      root_input = await computeDH(myPrivateKey, header.pu)

      KDF_RK_out = await KDF_RK(RK, root_input)
      RK = KDF_RK_out[0]
      CKr = KDF_RK_out[1]

      curr_conn.CKr = CKr
      curr_conn.DHr = header.pu
    }

    if (header.pu !== curr_conn.DHr) { //performs dh ratchet
      curr_conn.DHs = generateEG()
      curr_conn.DHr = header.pu
      const [rkr, ckr] = await KDF_RK(curr_conn.RK, await computeDH(curr_conn.DHs.sec, curr_conn.DHr));
      curr_conn.CKr = ckr;
      curr_conn.DHs = await generateEG();
      const [rks, cks] = await KDF_RK(curr_conn.RK, await computeDH(curr_conn.DHs.sec, curr_conn.DHr));
      curr_conn.CKs = cks;

    }

    const [ck, mk, mk_buf] = await KDF_CK(curr_conn.CKr)
    curr_conn.CKr = ck

    try {
      const plaintext = bufferToString(await decryptWithGCM(mk, ciphertext, header.receiverIV, JSON.stringify(header)))
      return plaintext
    } catch (err) {
      //console.error('Decryption Error:', err);
      throw new Error("the adversary has tampered with your ciphertext");
    }
  }
};

module.exports = {
  MessengerClient
}
