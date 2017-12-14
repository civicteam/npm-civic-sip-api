/**
 * Using secp256r1 ECC curve for key pair generation for use in
 * ECDSA signing. This has wider support in the JWT Token libraries
 * across other languages like python, ruby and php, than the bitcoin curve
 * secp256k1 that was originally used.
 */


const rs = require('jsrsasign');
const uuidV4 = require('uuid/v4');
const timestamp = require('unix-timestamp');
const CryptoJS = require('crypto-js');
const stringify = require('json-stable-stringify');
const merge = require('lodash.merge');

const ALGO = 'ES256';
const CURVE = 'secp256r1';

exports.createToken = (issuer, audience, subject, expiresIn, payload, prvKeyHex) => {
  const now = timestamp.now();
  const until = timestamp.add(now, expiresIn);

  const content = {
    jti: uuidV4(),
    iat: now,
    exp: until,
    iss: issuer,
    aud: audience,
    sub: subject,
    data: payload,
  };

  const header = { alg: ALGO, typ: 'JWT' };
  const sHeader = JSON.stringify(header);
  const sContent = JSON.stringify(content);

  // create ECDSA key object with Hex input
  const prvKey = new rs.KJUR.crypto.ECDSA({ curve: CURVE });
  prvKey.setPrivateKeyHex(prvKeyHex);
  prvKey.isPrivate = true;
  prvKey.isPublic = false;

  // sometimes for some reason the errors below occur randomly, so try a few times before giving up
  // unknown ECDSA sig r length error
  // unknown ECDSA sig s length error
  let token;
  for (let i = 0; i < 5; i++) {
    try {
      token = rs.jws.JWS.sign(null, sHeader, sContent, prvKey);
      break;
    } catch (error) {
      if (i === 4) {
        throw new Error(error);
      }
    }
  }
  return token;
};

exports.verify = (token, pubhex, acceptable) => {
  // verify JWT
  const options = merge(acceptable || {}, { alg: [ALGO] });
  const pubKey = new rs.KJUR.crypto.ECDSA({ curve: CURVE });
  pubKey.setPublicKeyHex(pubhex);
  pubKey.isPrivate = false;
  pubKey.isPublic = true;

  return rs.jws.JWS.verifyJWT(token, pubKey, options);
};

exports.decode = token => rs.jws.JWS.parse(token);

exports.createCivicExt = (body, clientAccessSecret) => {
  const bodyStr = stringify(body);
  const hmacBuffer = CryptoJS.HmacSHA256(bodyStr, clientAccessSecret);
  return CryptoJS.enc.Base64.stringify(hmacBuffer);
};
