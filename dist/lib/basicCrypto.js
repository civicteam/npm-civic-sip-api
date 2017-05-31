'use strict';

Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.encrypt = encrypt;
exports.decrypt = decrypt;
var CryptoJS = require('crypto-js');

var keySize = 128;
var ivSize = 128;
var iterations = 100;

function encrypt(msg, key) {

  // convert to word array so AES treats this as a key and not a passphrase
  var bytesKey = CryptoJS.enc.Hex.parse(key);

  var iv = CryptoJS.lib.WordArray.random(128 / 8);

  // The default output format is CryptoJS.format.OpenSSL,
  // but this only transports the salt.
  var encrypted = CryptoJS.AES.encrypt(msg, bytesKey, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC

  });

  console.log('encrypted.iv: ', encrypted.iv.toString());
  console.log('encrypted.key: ', encrypted.key.toString());

  // append iv - 32 bytes in hex
  var cipherText = '';

  cipherText += iv.toString() + encrypted.toString();

  return cipherText;
}

function decrypt(txMessage, key) {

  var ivStart = 0,
      msgStart = 32;

  // convert to word array so aes treats this as a key and not a passphrase
  var bytesKey = CryptoJS.enc.Hex.parse(key);

  var iv = CryptoJS.enc.Hex.parse(txMessage.substr(ivStart, msgStart));
  var encrypted = txMessage.substring(msgStart);

  var decrypted = CryptoJS.AES.decrypt(encrypted, bytesKey, {
    iv: iv,
    padding: CryptoJS.pad.Pkcs7,
    mode: CryptoJS.mode.CBC
  });

  return decrypted.toString(CryptoJS.enc.Utf8);
}
