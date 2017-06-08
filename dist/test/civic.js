'use strict';

require('babel-polyfill');
require('babel-core/register');

var needle = require('needle');
var unixTimestamp = require('unix-timestamp');
var rs = require('jsrsasign');
var rsu = require("jsrsasign-util"); // for file I/O
var CryptoJS = require('crypto-js');
var stringify = require('json-stable-stringify');

var civicSip = require('../index');
var jwt = require('../lib/jwt');
var basicCrypto = require('../lib/basicCrypto');

var assert = require('chai').assert;

// secp256r1 ECC curve for key pair:
var HEX_PRVKEY_NIST = 'a3ed0dd27cbfa62e13e340fb3dbb86895b99d5fd330a80e799baffcb1d29c17a';
var HEX_PUBKEY_NIST = '04a77e5c9c01df457ba941e28e187d3f53962f9038b5e481036cd9e7e9d1b1047c223c5b3db30fb12ff9f26eb229bb422eecf1a5df676d91099e081e4ec88ec339';
var SECRET = '879946CE682C0B584B3ACDBC7C169473';
var ALGO = 'ES256',
    curve = "secp256r1";

function generateToken(prvKeyObj, expStr) {
  var now = unixTimestamp.now();
  var until = unixTimestamp.add(now, expStr || '3m');

  var payload = {
    jti: '45a59d10-6e93-47f6-9185-adacfe28907a',
    iat: 1494204971.361,
    exp: until,
    iss: 'civic-sip-hosted-service',
    aud: 'https://api.civic.com/sip/', // valid endpoints for this token
    sub: 'civic-sip-hosted-service',
    data: {
      codeToken: '7cf8cfde-d7a2-4daa-8d44-c8e27320f688'
    }
  };

  var header = { alg: ALGO, typ: "JWT" },
      sHeader = JSON.stringify(header),
      sPayload = JSON.stringify(payload);

  return rs.jws.JWS.sign(null, sHeader, sPayload, prvKeyObj);
}

describe('jsRsaSign JWTToken module', function () {
  this.timeout(10000);
  var tokenES256 = void 0;

  var authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';
  var authCode_ES256 = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWE1OWQxMC02ZTkzLTQ3ZjYtOTE4NS1hZGFjZmUyODkwN2EiLCJpYXQiOjE0OTQyMDQ5NzEuMzYxLCJleHAiOjE0OTUyMTEwMTgsImlzcyI6ImNpdmljLXNpcC1ob3N0ZWQtc2VydmljZSIsImF1ZCI6Ii9kZXYvc2NvcGVSZXF1ZXN0L2F1dGhDb2RlIiwic3ViIjoiY2l2aWMtc2lwLWhvc3RlZC1zZXJ2aWNlIiwiZGF0YSI6eyJjb2RlVG9rZW4iOiI4MWYyNTY0Yy1lN2MwLTQ4NjktYmU0OS1hODhmNTczODUzNGYifX0.U-_xgL9348VhcfGvRqdmIdkBlrYNCs9FUsDmb977mnXuIuVzQkQin8uz1f_BM8JW_1SuxeGBSKIXf4BhmpHo9g';

  it('should generate ES256 NIST keypair in PEM HEX and JWK formats', function (done) {
    var doneFn = done;

    // generate keypair and save to file in PEM format.

    var keyPair = rs.KEYUTIL.generateKeypair("EC", "secp256r1");
    var prvPEM = rs.KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV");
    var pubPEM = rs.KEYUTIL.getPEM(keyPair.pubKeyObj, "PKCS8PUB");

    var prvJWK = rs.KEYUTIL.getJWKFromKey(keyPair.prvKeyObj);
    var pubJWK = rs.KEYUTIL.getJWKFromKey(keyPair.pubKeyObj);

    rsu.saveFile("test/keys/prv.pem", prvPEM);
    rsu.saveFile("test/keys/pub.pem", pubPEM);

    rsu.saveFile("test/keys/prv.hex", keyPair.prvKeyObj.prvKeyHex);
    rsu.saveFile("test/keys/pub.hex", keyPair.pubKeyObj.pubKeyHex);

    rsu.saveFile("test/keys/prv.jwk", JSON.stringify(prvJWK));
    rsu.saveFile("test/keys/pub.jwk", JSON.stringify(pubJWK));

    // var ec = new rs.KJUR.crypto.ECDSA({curve: curve});
    // var keypairHex = ec.generateKeyPairHex();

    doneFn();
  });

  it('should generate Civic ES256 NIST public key in PEM HEX and JWK formats', function (done) {
    var doneFn = done;

    var pubKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    pubKey.setPublicKeyHex('049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1');
    pubKey.isPrivate = false;
    pubKey.isPublic = true;

    // save to file in PEM, HEX and JWK formats.
    var pubPEM = rs.KEYUTIL.getPEM(pubKey, "PKCS8PUB");

    var pubJWK = rs.KEYUTIL.getJWKFromKey(pubKey);

    rsu.saveFile("test/keys/civic_pub.pem", pubPEM);

    rsu.saveFile("test/keys/civic_pub.hex", pubKey.pubKeyHex);

    rsu.saveFile("test/keys/civic_pub.jwk", JSON.stringify(pubJWK));

    doneFn();
  });

  it('should generate a long-lived token', function (done) {
    var doneFn = done;

    var prvKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    prvKey.setPrivateKeyHex(HEX_PRVKEY_NIST);
    prvKey.isPrivate = true;
    prvKey.isPublic = false;

    var result = generateToken(prvKey, '30d');

    console.log('JWT long lived token: ', result);
    doneFn();
  });

  it('should compare javascript and php hmac sha256 results', function (done) {
    var doneFn = done;
    var phpHash = 'MsZHYCq0xMdUPpxQriXlZ8M1ThUysRZJzjCObiVo0gU=';
    var msg = 'Message';
    var key = 'secret';
    var bkey = sjcl.codec.utf8String.toBits(key);
    var strMsg = stringify(msg);
    var hmac = new sjcl.misc.hmac(bkey, sjcl.hash.sha256);
    var jsHash = sjcl.codec.base64.fromBits(hmac.encrypt(strMsg));

    var nsHmac = new sjcl.misc.hmac(key, sjcl.hash.sha256);
    var nsJsHash = sjcl.codec.base64.fromBits(nsHmac.encrypt(msg));

    // crypto-js version
    var hmacBuffer = CryptoJS.HmacSHA256(msg, key);
    var hmacInBase64 = CryptoJS.enc.Base64.stringify(hmacBuffer);

    // const jsHash = jwt.createCivicExt(msg, key);
    console.log('PHP   Hash: ', phpHash);
    console.log('JS    Hash: ', jsHash);
    console.log('JSns  Hash: ', nsJsHash);
    assert(jsHash === phpHash, 'PHP and Javascript hashes are not equal.');

    doneFn();
  });

  it('should sign+verify token using JWK format', function (done) {
    var doneFn = done;

    // generate keypair and save to file in JWK format.
    var keyPair = rs.KEYUTIL.generateKeypair("EC", "secp256r1");
    var prvJWK = rs.KEYUTIL.getJWKFromKey(keyPair.prvKeyObj);
    var pubJWK = rs.KEYUTIL.getJWKFromKey(keyPair.pubKeyObj);

    // save JW keys to file
    rsu.saveFile("test/keys/prvJWK_Key_verify_test.bin", JSON.stringify(prvJWK));
    rsu.saveFile("test/keys/pubJWK_Key_verify_test.bin", JSON.stringify(pubJWK));

    // read in prv key and sign token
    var prv_JWK = rsu.readFile("test/keys/prvJWK_Key_verify_test.bin");
    var prvKey = JSON.parse(prv_JWK);
    var token = generateToken(prvKey);

    // read in public key in JWK format and verify token
    var pub_JWK = rsu.readFile("test/keys/pubJWK_Key_verify_test.bin");
    var pub_json = JSON.parse(pub_JWK);
    var pubKey = rs.KEYUTIL.getKey(pub_json);
    // verify JWT
    var isValid = rs.jws.JWS.verifyJWT(token, pubKey, { alg: [ALGO] });
    console.log('Verified? : ', isValid);

    doneFn();
  });

  /**
   * 1. load public key HEX_PUBKEY_NIST into ECDSA object from hex string.
   * 2. retrieve PEM format of key.
   * 3. verify JWT Token signed with HEX_PRVKEY_NIST.
   */
  it('should verify a JWT token using ES256 key in PEM format', function (done) {

    var doneFn = done;

    var pubKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    pubKey.setPublicKeyHex(HEX_PUBKEY_NIST);
    pubKey.isPrivate = false;
    pubKey.isPublic = true;

    var pubPEM = rs.KEYUTIL.getPEM(pubKey, "PKCS8PUB");
    console.log('PEM public key: ', pubPEM);
    // verify JWT
    var isValid = rs.jws.JWS.verifyJWT(authCode_ES256, pubPEM, { alg: [ALGO] });
    console.log('Verified? : ', isValid);

    doneFn();
  });

  it('should verify a JWT token using ES256 key in JWK format', function (done) {
    var jwtToken_with_encrypted_data = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI2ZGIwODNmZC03NDNkLTQ0NzgtYTZhMy05N2Q2OGYwZDBhNWUiLCJpYXQiOjE0OTYyMzg1MDYuNTQsImV4cCI6MTQ5NjI0MDMwNi41NCwiaXNzIjoiY2l2aWMtc2lwLWhvc3RlZC1zZXJ2aWNlIiwiYXVkIjoiaHR0cHM6Ly9hcGkuY2l2aWMuY29tL3NpcC8iLCJzdWIiOiJIazJ4NU9GZVoiLCJkYXRhIjoiMzNmOTE0NzZjNzk4YTZhZjM0ZmZhMmU2YzQ1ZGJkYjhDaGd3SC9EMFVZWnNZc3FkT011cjlLakwxQktZbk83SGkzYkZvdFk1cjI0Y2M1YUJZZjR2bDBMbWl5R21OM3ErbUVuSTJHYjRyRkdWMldVMXhwNDM1QUlDQ2h6VlJBa2J2T25sSFBZbUlwRG1XdG9oek9vc2xqRWNrRENXZE9TbUgrTHorVTFsMkdmWjJQN1N4eWRWUFErUjBMM3Fmb1pFNm1LRlFGdzFGNGlyUHRUeVhmTXJ4SjNPaHFIMzZBTlhKcG9sdzNHcmR1VkZBZ1BnWW5zMHVEQ3hIaDBRaTJPVlFVTmpaZW5lem5ITFhBOXBRL0t6MkgzWU15WllHeXhYIn0.lbEVq81mvRZLBmW3kOE-nFPDlBgYk008J6O4RY2ld2fADrIFz7y1aBYuPHxt1nEE2D1etoH1INMffEL1rkqKVw";
    var doneFn = done;

    var pubKeyFromHex = new rs.KJUR.crypto.ECDSA({ curve: curve });
    pubKeyFromHex.setPublicKeyHex(HEX_PUBKEY_NIST);
    pubKeyFromHex.isPrivate = false;
    pubKeyFromHex.isPublic = true;

    // read in public key in JWK format and verify token
    var pub_JWK = rsu.readFile("test/keys/civic_pub.jwk");
    var pub_json = JSON.parse(pub_JWK);
    var pubKey = rs.KEYUTIL.getKey(pub_json);
    // verify JWT
    var isValid = rs.jws.JWS.verifyJWT(jwtToken_with_encrypted_data, pubKey, { gracePeriod: 24 * 60 * 60, alg: [ALGO] });
    console.log('Verified? : ', isValid);
    isValid = rs.jws.JWS.verify(jwtToken_with_encrypted_data, pubKey);

    // isValid = rs.jws.JWS.verify(jwtToken_with_encrypted_data, {hex: '6f62ad...'}, ['HS256']);

    doneFn();
  });

  it('should verify a partner authorization header for auth code exchange api call.', function (done) {
    var partner_pub_key = '040e5407b993d672da6727577fc7005119cbecd340366e1f452df67ac536822894fb00414ff77c75e61b9519e61397d1f4c692da449c72cee3a69b33d04858902f';
    var authHeader = 'Civic eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6Il9vLTN3eHoifQ.eyJhdWQiOiJodHRwczpcL1wvYXBpLmNpdmljLmNvbVwvc2lwXC8iLCJpc3MiOiJIazJ4NU9GZVoiLCJpYXQiOjE0OTU0ODM4ODUsImV4cCI6MTQ5NTQ4Mzk1NSwiZGF0YSI6eyJtZXRob2QiOiJQT1NUIiwicGF0aCI6InNjb3BlUmVxdWVzdFwvYXV0aENvZGUifSwic3ViIjoiSGsyeDVPRmVaIn0.PfCHiOruQZHoZnJLqCPBNA5U6UGDWi7OLCzzm1tIwmlE0mvds_frnzqePmZ32I-DxjraylOqZWFiG6YuxQY6UQ./lOwdOrqRrlnWMtl123IH4sN4mzJOE+/TvzS3RZH5jM=';
    var body = "{\"authToken\":\"eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWE1OWQxMC02ZTkzLTQ3ZjYtOTE4NS1hZGFjZmUyODkwN2EiLCJpYXQiOjE0OTQyMDQ5NzEuMzYxLCJleHAiOjE0OTgwNzQ0NzgsImlzcyI6ImNpdmljLXNpcC1ob3N0ZWQtc2VydmljZSIsImF1ZCI6Imh0dHBzOi8vYXBpLmNpdmljLmNvbS9zaXAvIiwic3ViIjoiY2l2aWMtc2lwLWhvc3RlZC1zZXJ2aWNlIiwiZGF0YSI6eyJjb2RlVG9rZW4iOiI3Y2Y4Y2ZkZS1kN2EyLTRkYWEtOGQ0NC1jOGUyNzMyMGY2ODgifX0.QgvcBTtWkybRlbh85V5opwy7cgORRhjHKXXsrlT3BAnU-u-JzWDbMC_z9CHwQeZc1AcmVYTyUKbbO8LPh-2zEA\"}";
    var secret = 'E72E1D26CA40995F622E1BF4F6552B22';

    var bodyObj = JSON.parse(body);

    // start processing the header
    var tokenType = authHeader.split(" ")[0];
    assert(tokenType === 'Civic', 'Incorrect tokenType.');
    var token = authHeader.split(" ")[1];
    var parts = token.split('.');
    assert(parts.length === 4, 'Authorization header should consist of a JWT token plus the Civic Extension.');
    var jwtToken = token.substring(0, token.lastIndexOf('.'));
    var decodedToken = rs.jws.JWS.parse(jwtToken);

    var tokenDetails = decodedToken.payloadObj;
    var appId = tokenDetails.iss;
    assert(appId === tokenDetails.sub, 'iss and sub must be set to the appId for self-signed tokens.');

    var principalId = 'client|' + tokenDetails.sub;
    var expire = tokenDetails.exp;
    var allowedMethod = tokenDetails.data.method;
    var allowedPath = tokenDetails.data.path;
    assert(allowedMethod === 'POST', 'POST must be specified.');
    assert(allowedPath === 'scopeRequest/authCode', 'incorrect path.');

    // partner public key
    var pubKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    pubKey.setPublicKeyHex(partner_pub_key);
    pubKey.isPrivate = false;
    pubKey.isPublic = true;

    // verify JWT
    var acceptable = {
      alg: [ALGO],
      // iss: ['http://foo.com'],
      // sub: ['mailto:john@foo.com', 'mailto:alice@foo.com'],
      // verifyAt: KJUR.jws.IntDate.get('20150520235959Z'),
      aud: ['https://api.civic.com/sip/'], // aud: 'http://foo.com' is fine too.
      gracePeriod: 20 * 60 * 60 // accept 10 hour slow or fast
    };

    var isValid = rs.jws.JWS.verifyJWT(jwtToken, pubKey, acceptable);
    assert(isValid, 'Invalid JWT token as part of the Authorization Header.');

    // validate the Civic Ext portion
    var civicExt = token.substring(token.lastIndexOf('.') + 1);
    var recalcExt = jwt.createCivicExt(bodyObj, secret);

    var bodyStr = stringify(bodyObj);
    var hmac = new sjcl.misc.hmac(secret, sjcl.hash.sha256);
    var tokenOnly = sjcl.codec.base64.fromBits(hmac.encrypt(stringify(bodyObj.authToken)));

    // assert(wholeBody === recalcExt, '')
    console.log('tokenOnly: ', tokenOnly);
    console.log('civic Ext from AuthHeader: ', civicExt);
    console.log('Recalced Civic Ext: ', recalcExt);

    // assert(civicExt === recalcExt, 'Civic Extension mismatch.');

    // verify the JWT Token (authToken) in the body
    isValid = jwt.verify(bodyObj.authToken, HEX_PUBKEY_NIST, { gracePeriod: 0 });
    assert(isValid, 'Civic authToken failed verification');

    done();
  });

  it('should generate JWT token using ES256 Algorithm', function (done) {
    var doneFn = done;

    var payload = {
      jti: '45a59d10-6e93-47f6-9185-adacfe28907a',
      iat: 1494204971.361,
      exp: rs.jws.IntDate.get('now + 1day'), // 3 minute lifespan
      iss: 'civic-sip-hosted-service',
      aud: '/dev/scopeRequest/authCode', // valid endpoints for this token
      sub: 'civic-sip-hosted-service',
      data: {
        codeToken: '81f2564c-e7c0-4869-be49-a88f5738534f'
      }
    };

    var header = { alg: ALGO, typ: "JWT" },
        sHeader = JSON.stringify(header),
        sPayload = JSON.stringify(payload);

    var prvKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    prvKey.setPrivateKeyHex(HEX_PRVKEY_NIST);
    prvKey.isPrivate = true;
    prvKey.isPublic = false;

    var pubKey = new rs.KJUR.crypto.ECDSA({ curve: curve });
    pubKey.setPublicKeyHex(HEX_PUBKEY_NIST);
    pubKey.isPrivate = false;
    pubKey.isPublic = true;

    var tokenES256 = rs.jws.JWS.sign(null, sHeader, sPayload, prvKey);
    console.log('tokenES256 = ', tokenES256);

    // verify JWT
    var isValid = rs.jws.JWS.verifyJWT(tokenES256, pubKey, { alg: [ALGO] });
    console.log('Verified? : ', isValid);

    var decoded = rs.jws.JWS.parse(tokenES256);
    console.log('decoded: ', decoded);

    isValid = rs.KJUR.jws.JWS.verify(tokenES256, pubKey);
    console.log('isValid: ', isValid);

    doneFn();
  });
});

describe('Civic SIP Server', function () {
  this.timeout(10000);

  var API = 'https://ph4x580815.execute-api.us-east-1.amazonaws.com/',
      STAGE = 'dev',
      authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';

  var civicClient = civicSip.newClient({
    appId: 'aaa123',
    prvKey: HEX_PRVKEY_NIST,
    appSecret: SECRET,
    api: API,
    env: STAGE
  });

  it('should call Civic with an invalid token and receive an error code.', function (done) {
    var doneFn = done;

    var BAD_AUTH_HEADER = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVY';
    var body = { authToken: authCode };
    var contentLength = Buffer.byteLength(JSON.stringify(body));
    var options = {
      headers: {
        'Content-Length': contentLength,
        'Accept': '*/*',
        'Authorization': BAD_AUTH_HEADER
      }
    };

    var url = API + STAGE + '/scopeRequest/authCode';

    url = 'https://api.civic.com/sip/prod/scopeRequest/authCode';

    needle.post(url, body, options, function (err, resp) {
      if (err) {
        console.log('Error: ', JSON.stringify(err, null, 2));
        doneFn(err);
      } else {
        console.log('statusCode: ', resp.statusCode);
        console.log('statusMessage: ', resp.statusMessage);
        doneFn();
      }
    });
  });

  it('should exchange authCode for user data.', function (done) {
    var doneFn = done;

    civicClient.exchangeCode(authCode).then(function (data) {
      console.log(data);
      doneFn();
    }).catch(function (error) {
      doneFn(error);
    });
  });

  /*
  it.only('should exchange authCode for user data in async fashion.', async function(done) {
    const doneFn = done;
     try {
      const data = await civicClient.exchangeCode(authCode);
      console.log('response.data: ', JSON.stringify(data, null, 2));
      doneFn();
    } catch(error) {
      console.error(error.message);
    }
   });
  */
});

describe('Encryption and decryption', function () {
  var userData = '[{ "label": "contact.personal.email", "value": "test@tester.com", "isValid": true, "isOwner": true }, { "label": "contact.personal.phoneNumber", "value": "+1 5553590384", "isValid": true, "isOwner": true }]';

  it('should encrypt and decrypt a response using partner secret and AES.', function (done) {
    var doneFn = done,
        txt = '[{"label": "contact.personal.email","value": "test@tester.com","isValid": true,"isOwner": true}]';

    var ct = CryptoJS.AES.encrypt(txt, 'secret key 123');
    var dbytes = CryptoJS.AES.decrypt(ct.toString(), 'secret key 123');
    var dt = dbytes.toString(CryptoJS.enc.Utf8);
    assert(dt === txt, 'The decryption has not succeeded.');
    doneFn();
  });

  it('should create and verify JWT token with encrypted data and decrypt.', function (done) {

    var doneFn = done;
    var cipherText = basicCrypto.encrypt(userData, SECRET);

    var token = jwt.createToken('civic-sip-hosted-service', 'https://api.civic.com/sip/', 'aaa123', '20m', cipherText, HEX_PRVKEY_NIST);

    var isValid = jwt.verify(token, HEX_PUBKEY_NIST, { gracePeriod: 30 });
    assert(isValid, 'JWT Token containing encrypted data could not be verified.');

    // decrypt the data
    var decodedToken = jwt.decode(token);
    var clearData = basicCrypto.decrypt(decodedToken.payloadObj.data, SECRET);
    // const decryptedText = clearData.toString(CryptoJS.enc.Utf8);
    assert(clearData === userData, 'Decrypted Token data does match original input.');
    doneFn();
  });

  it('should verify JWT token with encrypted data and decrypt.', function (done) {

    var doneFn = done;
    var payloadDataOrig = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI3MDcwM2ZiZS0yYTdlLTQ4ZjktYjA5Ny0xMDhjZDgyMThhNjYiLCJpYXQiOjE0OTYxODY1NzUuNjM4LCJleHAiOjE0OTYxODgzNzUuNjM4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6IkhrMng1T0ZlWiIsImRhdGEiOiIzNzQyYTNhYWEzNzgyZDdmOWU1NTRlZjVkMWI5OWFmN1UyRnNkR1ZrWDErOHBMYXF2alcxbkcyTkpqSUp5Y053ekNMNG5KcDF3MGFyQ09lcjVKUE1FOFRJTmgxaEsvTkhoTmtzU0ZJN0FuVGo3eGYraENvS09YTHd6N1IyemZaV1BUUGZUNk9POFBSMlB5SHFzWXdpeXY0ekVZa2ZUcmJXUWJWK0xiNW0veHVEb2pJN3htRk1oOVdTMWNIaWl5aVN3eTJxRXgvUjFOVGlvSzNQTVZqT0p0cHIzVGVCYWJ1ODREV0p4SUJNVTFaa3lBTUVybDVxdGxjSVVEVDFIWkNET1BJQStaWDlWM0VkbXBBaVBwZzVRTHhsK1ZaTCs2aC9tY3VBQ05yV3RBdVB5MkZjVVVZVllRPT0ifQ.dTwUE1hSqUh0yOBv1CQ-tBytmiaRZq-4j8iomq9z5UqwBEA3oIXS3EZaTKZXlhZWpuPTb-Mmqs7UYV5b7t94qQ';
    var payloadData2 = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkMzdmM2UyZS1jYTQ4LTQwMGYtYWY3Zi05YzcxZGNjNjFmNTQiLCJpYXQiOjE0OTYyMTI2MTMuNTQ1LCJleHAiOjE0OTYyMTQ0MTMuNTQ1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6IkhrMng1T0ZlWiIsImRhdGEiOiJiNDRhNTBlZmJkMTk1NGZiNThlZDViMWM1NTBmMGY0NUFtdXQvOUpBemMrRW1pMHpHVmMrVGhtZkkwKzFtSEhQd3RPTkpQNDIvUXV2ZUpWbyt2Y1J6cVpVZnIvNUdOUFUySzlRTDRndXpjT0dKV3BTUnprN08vUys0NE9vdFdlMEdISXBaTjBnU0pROVAzVVpzb2VTM1Iyd2QwVXFhTmtnMWxic09NZFQ2aktvZzVKR0hmSkxabjkxVjhjSURyNGw0RTc2SWVwQ1VmUjRVaVc4Y0Z4RGZSai8vanBkOW1wK0lQcGFjQi9CcU5LTGRoTXRETUpJMk1MN0FQNVRxWW03TndHM2hOWit5dlhINzJjYlFHWXhiYmloVVZHTXVoUjQifQ.-ch3X5l9Yf7LDpx94fapSObuedfRHKiXqyKOSm-ev1uXTMyqes30OofQ8xz8NYJxxZGwm30PPlPoAvtV73bO6w';
    var payloadData = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiJkMzdmM2UyZS1jYTQ4LTQwMGYtYWY3Zi05YzcxZGNjNjFmNTQiLCJpYXQiOjE0OTYyMTI2MTMuNTQ1LCJleHAiOjE0OTYyMTQ0MTMuNTQ1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6IkhrMng1T0ZlWiIsImRhdGEiOiJiNDRhNTBlZmJkMTk1NGZiNThlZDViMWM1NTBmMGY0NUFtdXQvOUpBemMrRW1pMHpHVmMrVGhtZkkwKzFtSEhQd3RPTkpQNDIvUXV2ZUpWbyt2Y1J6cVpVZnIvNUdOUFUySzlRTDRndXpjT0dKV3BTUnprN08vUys0NE9vdFdlMEdISXBaTjBnU0pROVAzVVpzb2VTM1Iyd2QwVXFhTmtnMWxic09NZFQ2aktvZzVKR0hmSkxabjkxVjhjSURyNGw0RTc2SWVwQ1VmUjRVaVc4Y0Z4RGZSai8vanBkOW1wK0lQcGFjQi9CcU5LTGRoTXRETUpJMk1MN0FQNVRxWW03TndHM2hOWit5dlhINzJjYlFHWXhiYmloVVZHTXVoUjQifQ.7LqXPbUwyscpjYqnevAchatXRcDtiiaymtM54ztMgOU';

    var cipherText = basicCrypto.encrypt(userData, SECRET);

    var acceptable = { gracePeriod: 24 * 60 * 60 };
    var isValid = jwt.verify(payloadData, HEX_PUBKEY_NIST, acceptable);
    // assert(isValid, 'JWT Token containing encrypted data could not be verified.');

    // decrypt the data
    var decodedToken = jwt.decode(payloadData);
    var clearData = basicCrypto.decrypt(decodedToken.payloadObj.data, 'D37E1D26FA40995F622E1BF4F6552B12');
    // assert(clearData === userData, 'Decrypted Token data does match original input.');
    doneFn();
  });

  it('test', function (done) {

    var doneFn = done;
    var cipherText = basicCrypto.encrypt("test message to get encrypted", SECRET);

    var token = jwt.createToken('civic-sip-hosted-service', 'https://api.civic.com/sip/', 'aaa123', '20m', cipherText, HEX_PRVKEY_NIST);

    var isValid = jwt.verify(token, HEX_PUBKEY_NIST, { gracePeriod: 30 });
    assert(isValid, 'JWT Token containing encrypted data could not be verified.');

    // decrypt the data
    var decodedToken = jwt.decode(token);
    var clearData = basicCrypto.decrypt(decodedToken.payloadObj.data, SECRET);
    doneFn();
  });
});
