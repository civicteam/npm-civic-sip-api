'use strict';

require("babel-polyfill");
require("babel-core/register");
var jwtjs = require('jwt-js');

var rs = require('jsrsasign');
var rsu = require("jsrsasign-util"); // for file I/O

var civicSip = require('../index');
var assert = require('chai').assert;

// secp256r1 ECC curve for key pair:
var HEX_PRVKEY_NIST = 'a3ed0dd27cbfa62e13e340fb3dbb86895b99d5fd330a80e799baffcb1d29c17a';
var HEX_PUBKEY_NIST = '04a77e5c9c01df457ba941e28e187d3f53962f9038b5e481036cd9e7e9d1b1047c223c5b3db30fb12ff9f26eb229bb422eecf1a5df676d91099e081e4ec88ec339';
var SECRET = '879946CE682C0B584B3ACDBC7C169473';
var ALGO = 'ES256',
    curve = "secp256r1";

function generateToken(prvKeyObj) {
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

  return rs.jws.JWS.sign(null, sHeader, sPayload, prvKeyObj);
}

describe('jsRsaSign JWTToken module', function () {
  this.timeout(10000);
  var tokenES256 = void 0;

  var authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';
  var authCode_ES256 = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0NWE1OWQxMC02ZTkzLTQ3ZjYtOTE4NS1hZGFjZmUyODkwN2EiLCJpYXQiOjE0OTQyMDQ5NzEuMzYxLCJleHAiOjE0OTUyMTEwMTgsImlzcyI6ImNpdmljLXNpcC1ob3N0ZWQtc2VydmljZSIsImF1ZCI6Ii9kZXYvc2NvcGVSZXF1ZXN0L2F1dGhDb2RlIiwic3ViIjoiY2l2aWMtc2lwLWhvc3RlZC1zZXJ2aWNlIiwiZGF0YSI6eyJjb2RlVG9rZW4iOiI4MWYyNTY0Yy1lN2MwLTQ4NjktYmU0OS1hODhmNTczODUzNGYifX0.U-_xgL9348VhcfGvRqdmIdkBlrYNCs9FUsDmb977mnXuIuVzQkQin8uz1f_BM8JW_1SuxeGBSKIXf4BhmpHo9g';

  it.only('should generate ES256 NIST keypair in PEM format', function (done) {
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

  it('should generate JWT token using ES256 Algorithm', function (done) {
    var doneFn = done,
        ALGO = 'ES256';

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

describe('exchangeCode', function () {
  this.timeout(10000);

  var authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';
  var civicClient = civicSip.newClient({
    appId: 'aaa123', // insert appId
    appSecret: SECRET,
    prvKey: HEX_PRVKEY_NIST,
    env: 'dev'
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
  it('should exchange authCode for user data in async fashion.', async function(done) {
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
