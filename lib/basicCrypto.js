const CryptoJS = require('crypto-js');

const keySize = 128;
const ivSize = 128;
const iterations = 100;

export function encrypt (msg, key) {

  // convert to word array so AES treats this as a key and not a passphrase
  const bytesKey = CryptoJS.enc.Hex.parse(key);

  const iv = CryptoJS.lib.WordArray.random(128/8);

  // The default output format is CryptoJS.format.OpenSSL,
  // but this only transports the salt.
  const encrypted = CryptoJS.AES.encrypt(msg, bytesKey, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC,

  });

  console.log('encrypted.iv: ', encrypted.iv.toString());
  console.log('encrypted.key: ', encrypted.key.toString());

  // append iv - 32 bytes in hex
  let cipherText = '';

  cipherText += iv.toString() + encrypted.toString();

  return cipherText;
}

export function decrypt (txMessage, key) {

  const ivStart = 0,
        msgStart = 32;

  // convert to word array so aes treats this as a key and not a passphrase
  const bytesKey = CryptoJS.enc.Hex.parse(key);

  const iv = CryptoJS.enc.Hex.parse(txMessage.substr(ivStart, msgStart))
  const encrypted = txMessage.substring(msgStart);

  const decrypted = CryptoJS.AES.decrypt(encrypted, bytesKey, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
  })

  return decrypted.toString(CryptoJS.enc.Utf8);
}
