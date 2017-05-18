'use strict';

require("babel-polyfill");
require("babel-core/register");
const jwtjs = require('jwt-js');

const rs = require('jsrsasign');
var rsu = require("jsrsasign-util"); // for file I/O

const civicSip = require('../index');
const assert = require('chai').assert;

// secp256k1 ECC curve generated keys
const SECRET = '7cf5ac70fc9eb1671c85547ef594599ce8214e0c6563e12f24cbd338b8e649c4';
const HEX_PUBKEY = '04ac75e5f6d7b161b8337e13d467f0b7a1692931b7e6dd64dd63686d203455a603a23708044ae5edab04f98601a08478cf603c699a75ee9f34e974b166df9fae34';

// secp256r1 ECC curve for key pair:
const SECRET_NIST = 'a3ed0dd27cbfa62e13e340fb3dbb86895b99d5fd330a80e799baffcb1d29c17a';
const HEX_PUBKEY_NIST = '04a77e5c9c01df457ba941e28e187d3f53962f9038b5e481036cd9e7e9d1b1047c223c5b3db30fb12ff9f26eb229bb422eecf1a5df676d91099e081e4ec88ec339';

  describe('jsRsaSign JWTToken module', function() {
  this.timeout(10000);
  let tokenES256;

  const authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';


  it.only('should generate ES256 NIST keypair in PEM format', function (done) {
    const doneFn = done,
    ALGO = 'ES256';

    const curve = "secp256r1";

    // generate keypair and save to file in PEM format.
    const keyPair = rs.KEYUTIL.generateKeypair("EC", "secp256r1");
    const prvPEM = rs.KEYUTIL.getPEM(keyPair.prvKeyObj, "PKCS8PRV");
    const pubPEM = rs.KEYUTIL.getPEM(keyPair.pubKeyObj, "PKCS8PUB");

    rsu.saveFile("test/keys/prv.key", prvPEM);
    rsu.saveFile("test/keys/pub.key", pubPEM);

    rsu.saveFile("test/keys/prv_hex.key", keyPair.prvKeyObj.prvKeyHex);
    rsu.saveFile("test/keys/pub_hex.key", keyPair.pubKeyObj.pubKeyHex);

    var ec = new rs.KJUR.crypto.ECDSA({curve: curve});
    var keypairHex = ec.generateKeyPairHex();

    doneFn();
  });

  it('should generate JWT token using ES256 Algorithm', function (done) {
    const doneFn = done,
    ALGO = 'ES256';

    const payload = {
      jti: '45a59d10-6e93-47f6-9185-adacfe28907a',
      iat: 1494204971.361,
      exp: rs.jws.IntDate.get('now + 1day'),   // 3 minute lifespan
      iss: 'civic-sip-hosted-service',
      aud: '/dev/scopeRequest/authCode',  // valid endpoints for this token
      sub: 'civic-sip-hosted-service',
      data: {
        codeToken: '81f2564c-e7c0-4869-be49-a88f5738534f',
      }
    }

    let header = {alg: ALGO, typ: "JWT"},
          sHeader = JSON.stringify(header),
          sPayload = JSON.stringify(payload);

    // parse raw HEX key into library representation
    var curve = "secp256r1";
    // var ec = new rs.KJUR.crypto.ECDSA({curve: curve});
    // var keypairHex = ec.generateKeyPairHex();

    var prvKey = new rs.KJUR.crypto.ECDSA({curve: curve});
    prvKey.setPrivateKeyHex(SECRET_NIST);
    prvKey.isPrivate = true;
    prvKey.isPublic = false;

    var pubKey = new rs.KJUR.crypto.ECDSA({curve: curve});
    pubKey.setPublicKeyHex(HEX_PUBKEY_NIST);
    pubKey.isPrivate = false;
    pubKey.isPublic = true;

    const tokenES256 = rs.jws.JWS.sign(null, sHeader, sPayload, prvKey);
    console.log('tokenES256 = ', tokenES256);

    // verify JWT
    let isValid = rs.jws.JWS.verifyJWT(tokenES256, pubKey, { alg: [ALGO] });
    console.log('Verified? : ', isValid);

    let decoded = rs.jws.JWS.parse(tokenES256);
    console.log('decoded: ', decoded);

    isValid = rs.KJUR.jws.JWS.verify(tokenES256, pubKey);
    console.log('isValid: ', isValid);

    doneFn();
  });

})

describe('jwt-js Token module', function() {
  this.timeout(10000);
  let tokenES256;

  const authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';

  it('should generate JWT token using ES256K Algorithm', function (done) {
    const doneFn = done,
      ALGO = 'ES256K';

    const payload = {
      jti: '45a59d10-6e93-47f6-9185-adacfe28907a',
      iat: 1494204971.361,
      exp: 1494205151.361,   // 3 minute lifespan
      iss: 'civic-sip-hosted-service',
      aud: '/dev/scopeRequest/authCode',  // valid endpoints for this token
      sub: 'civic-sip-hosted-service',
      data: {
        codeToken: '81f2564c-e7c0-4869-be49-a88f5738534f',
      }
    }

    const signer = new jwtjs.TokenSigner(ALGO, SECRET);

    tokenES256 = signer.sign(payload);
    console.log('tokenES256 = ', tokenES256);

    const verifier = new jwtjs.TokenVerifier(ALGO, HEX_PUBKEY);
    let result = verifier.verify(tokenES256);
    console.log('Verified? : ', result);
    doneFn();
  });
})

describe('exchangeCode', function() {
  this.timeout(10000);

  const authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';
  const civicClient = civicSip.newClient({
    appId: 'aaa123', // insert appId
    appSecret: SECRET,
    env: 'dev',
  });


  it('should exchange authCode for user data.', function(done) {
    const doneFn = done;

      civicClient.exchangeCode(authCode).then(function(data) {
        console.log(data);
        doneFn();
      })
      .catch(function(error) {
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
})
