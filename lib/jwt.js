"use strict";

const jwtjs = require('jwt-js');
const uuidV4 = require('uuid/v4');
const timestamp = require('unix-timestamp');
const sjcl = require('sjcl');
const stringify = require('json-stable-stringify');

const ALGO = 'ES256k';

exports.createToken = function(issuer, audience, subject, expiresIn, payload, sechex) {

  const now = timestamp.now();
  const until = timestamp.add(now, expiresIn);

  const content = {
    jti: uuidV4(),
    iat: now,
    exp: until,
    iss: issuer,
    aud: audience,
    sub: subject,
    data: payload
  }

  const signer = new jwtjs.TokenSigner(ALGO, sechex);

  return signer.sign(content);

}

exports.verify = function(token, pubhex) {
  const verifier = new jwtjs.TokenVerifier(ALGO, pubhex);
  return verifier.verify(token);
}

exports.decode = function(token) {
  return jwtjs.decodeToken(token);
}

exports.createCivicExt = function(body, clientAccessSecret) {

  const bodyStr = stringify(body);
  const hmac = new sjcl.misc.hmac(clientAccessSecret, sjcl.hash.sha256);
  return sjcl.codec.base64.fromBits(hmac.encrypt(bodyStr));

}