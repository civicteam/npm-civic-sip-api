/**
 * Using secp256r1 ECC curve for key pair generation for use in
 * ECDSA signing. This has wider support in the JWT Token libraries
 * across other languages like python, ruby and php, than the bitcoin curve
 * secp256k1 that was originally used.
 */

"use strict";

var rs = require('jsrsasign');
var uuidV4 = require('uuid/v4');
var timestamp = require('unix-timestamp');
var sjcl = require('sjcl');
var stringify = require('json-stable-stringify');

var ALGO = 'ES256';
var CURVE = "secp256r1";

exports.createToken = function (issuer, audience, subject, expiresIn, payload, prvKeyHex) {

  var now = timestamp.now();
  var until = timestamp.add(now, expiresIn);

  var content = {
    jti: uuidV4(),
    iat: now,
    exp: until,
    iss: issuer,
    aud: audience,
    sub: subject,
    data: payload
  };

  var header = { alg: ALGO, typ: "JWT" },
      sHeader = JSON.stringify(header),
      sContent = JSON.stringify(content);

  // create ECDSA key object with Hex input
  var prvKey = new rs.KJUR.crypto.ECDSA({ curve: CURVE });
  prvKey.setPrivateKeyHex(prvKeyHex);
  prvKey.isPrivate = true;
  prvKey.isPublic = false;

  var token = rs.jws.JWS.sign(null, sHeader, sContent, prvKey);

  return token;
};

exports.verify = function (token, pubhex) {
  // verify JWT
  var pubKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
  pubKey.setPublicKeyHex(pubhex);
  pubKey.isPrivate = false;
  pubKey.isPublic = true;

  return rs.jws.JWS.verifyJWT(token, pubKey, { alg: [ALGO] });
};

exports.decode = function (token) {
  return rs.jws.JWS.parse(token);
};

exports.createCivicExt = function (body, clientAccessSecret) {

  var bodyStr = stringify(body);
  var hmac = new sjcl.misc.hmac(clientAccessSecret, sjcl.hash.sha256);
  return sjcl.codec.base64.fromBits(hmac.encrypt(bodyStr));
};
