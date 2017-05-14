"use strict";

var jwtjs = require('jwt-js');
var uuidV4 = require('uuid/v4');
var timestamp = require('unix-timestamp');
var sjcl = require('sjcl');
var stringify = require('json-stable-stringify');

var ALGO = 'ES256k';

exports.createToken = function (issuer, audience, subject, expiresIn, payload, sechex) {

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

  var signer = new jwtjs.TokenSigner(ALGO, sechex);

  return signer.sign(content);
};

exports.verify = function (token, pubhex) {
  var verifier = new jwtjs.TokenVerifier(ALGO, pubhex);
  return verifier.verify(token);
};

exports.decode = function (token) {
  return jwtjs.decodeToken(token);
};

exports.createCivicExt = function (body, clientAccessSecret) {

  var bodyStr = stringify(body);
  var hmac = new sjcl.misc.hmac(clientAccessSecret, sjcl.hash.sha256);
  return sjcl.codec.base64.fromBits(hmac.encrypt(bodyStr));
};
//# sourceMappingURL=jwt.js.map
