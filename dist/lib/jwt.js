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
var CryptoJS = require('crypto-js');
var stringify = require('json-stable-stringify');
var merge = require('lodash.merge');

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

exports.verify = function (token, pubhex, acceptable) {
  // verify JWT
  var options = merge(acceptable || {}, { alg: [ALGO] });
  var pubKey = new rs.KJUR.crypto.ECDSA({ curve: CURVE });
  pubKey.setPublicKeyHex(pubhex);
  pubKey.isPrivate = false;
  pubKey.isPublic = true;

  return rs.jws.JWS.verifyJWT(token, pubKey, options);
};

exports.decode = function (token) {
  return rs.jws.JWS.parse(token);
};

exports.createCivicExt = function (body, clientAccessSecret) {

  var bodyStr = stringify(body);
  var hmacBuffer = CryptoJS.HmacSHA256(bodyStr, clientAccessSecret);
  return CryptoJS.enc.Base64.stringify(hmacBuffer);
};
