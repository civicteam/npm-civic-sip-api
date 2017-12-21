const needle = require('needle');
const civicSip = require('../index');
const { assert } = require('chai');

const HEX_PRVKEY_NIST = 'a3ed0dd27cbfa62e13e340fb3dbb86895b99d5fd330a80e799baffcb1d29c17a';
const SECRET = '879946CE682C0B584B3ACDBC7C169473';

describe('Civic SIP Server', function test() {
  this.timeout(10000);

  const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com/';
  // const API = 'http://localhost:3001/';
  const STAGE = 'dev';
  const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI0ZTdjMGJmYi0wZTUzLTQ4YmYtYTA1ZS1hZjMwZDNlZmVhOGQiLCJpYXQiOjE1MTI2NDM2MjEuOTY4LCJleHAiOjE1MTI2NDU0MjEuOTY4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyM2JiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiMmY0NTlkNzYtNGJiNS00ODk1LTg0OTEtNGE1NzM5OGRjNjhiIn19.KJsj265azQiK7gmbRLZCayZILT0_TDhuLzDsTx50Z8O_N6Ox47ohnaQZKQwIkua9T3bFoHrHMzA9e4tCWr-FDw';

  const civicClient = civicSip.newClient({
    appId: 'aaa1234',
    prvKey: HEX_PRVKEY_NIST,
    appSecret: SECRET,
    api: API,
    env: STAGE,
  });

  it('should call Civic with an invalid token and receive an error code.', (done) => {
    const doneFn = done;

    const BAD_AUTH_HEADER = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVY';
    const body = { authToken: authCode };
    const contentLength = Buffer.byteLength(JSON.stringify(body));
    const options = {
      headers: {
        'Content-Length': contentLength,
        Accept: '*/*',
        Authorization: BAD_AUTH_HEADER,
      },
    };

    const url = `${API}${STAGE}/scopeRequest/authCode`;

    needle.post(url, JSON.stringify(body), options, (err, resp) => {
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

  it('should exchange authCode for user data.', (done) => {
    civicClient.exchangeCode(authCode).then((data) => {
      console.log(data);
      done();
    })
      .catch((error) => {
        done(error);
      });
  });

  it('should exchange authCode for user data.', (done) => {
    civicClient.exchange(authCode).then((data) => {
      console.log(data);
      done();
    })
      .catch((error) => {
        done(error);
      });
  });

  it('should verify user data.', (done) => {
    const data = '{"userId":"ac4d5c681d2bfc957778b84c5e6b81ec0c508490199847319e176efb7e972caa","identity":{"contact":{"personal":{"email":"test@civic.com","phoneNumber":"+55 31992617887"}}},"credentials":[{"attestationName":"attCivicBasic","grantedAttestation":{"request":{"clientId":"bbb123bbb123","url":"http://localhost:3001/dev/scopeRequest/10876c34-cb6e-400b-b9b6-3d613af451e5/callback","label":"attCivicBasic","signature":"3045022100f142144d9847976f831a07763ffcf12e7b40b366584d2b8af9668767bb1509bb0220238a765ac2a694bca806b4969877bab305c421d2ec2f8ddca9c1db87f203761e"},"attestation":{"cosigners":[{"xpub":"xpub661MyMwAqRbcGWqz8mWY7A72pgua8KBiE4Vuj5TmnMcvNpxTzZsCoJqfGrcsz528Z4qyG9rEVmpr1zWxuTmQDyaDY4BUkCX3L6rmvE6Svse"},{"xpub":"xpub661MyMwAqRbcFgT4S5aRfUiR4DAbipHSSYinYUTQqvEC4su2QevBkUcvDQDkzK3uiB3e5bfqYjje4XPdR93nbeZQGg48zph9eMvHizCQE6R"}],"tx":"010000000001013c09c09d0e1c9acec5a2f980d43e055ac7be2072b9e0d81b774d7973d35063400200000023220020b3cbc1ea1d042464311b1e4380c9e931f512b8616061bdcbc82396992f338ba2ffffffff05551500000000000017a91450c1cdfc2cf3cd26d4b93a584a7847cc633a10dc87551500000000000017a914ed954b52cb9811cc5dc6dc2f5e9da459a202e73787551500000000000017a9146662eab8a5438e429dea4e321a238d8f77555f43876ea360000000000017a914ee1f7d332baa07a4311bab20625fd6955a82d20987551500000000000017a914fbf03ba04196dd25fac35ec21c16f9623bcae59b870400483045022100839178fae0498b7104f7284208560688fc8877dc63742f77cd1ca74b435b9ead02201d13c6676c1c5f0dd807de961afba038d92a638a1afb6d8fefd059df4cd89f8701473044022027efdcd05049e4d5e7bdde0a01345f9b57317007d8e9968ebf570cbc8538dc22022049bc36e7471e40e00fe52af0067d8b1a2a34503716b44576715834b5f54764310169522102db7fc7db5dfe71824629ad3b3a994321799ed08506c43a65ecba213392dcb9a0210225bd617137dc72dd43cff4152d160dfe52399d4a852fbba5c6f8d65f9c56c05d2103f97a39989525eb5eedecca2946376c4b7f02365d7759f98e16dd5a239e643d5453ae00000000","type":"permanent","subject":{"label":"attCivicBasic","data":"9d20621129e93177178d3bd87be852fae37276ae15f9625536d2bf17ddd58091","xpub":"xpub661MyMwAqRbcFicU35hHYgpZwQDtGLYucWqAPTLGhya4rAzEBjGgkcJy4Qt5vRpJ8WzKNSPMWX3YPZ7FZEaYnqTwY9jzLjWvbbzEQJerGht","signature":"3045022100c217fcca2dad21e404fe1168ad42876688ab2afa1f700f098e1b3fb4510dcddf022026237e36404e00b93ccbde9b85aec5ce4cabb01670923ce6531cab0bf8a7c8a8"},"authority":{"xpub":"xpub661MyMwAqRbcEcNFQXdFJJHkaCvSsqvh6MT4zwZGG1mJQk9CPMnzV8BkAfUhqbFPeLavqk2dMb4j4ac4cqnfyu8xspwjGe7wTzTKgvReXgf","path":"/0/0/11/1221"},"network":"bitcoin"}},"attestationData":"35c86ff344f3f323a8b26e51e2e5b7d57ee7df99fae1ae08f183fdbb0bcd8de4","verificationLevel":"undefined","issuer":"Civic","claims":[{"identifier":"contact.personal.email","hash":"5b471132950d766c08a8b9e5a4be941196839c46edd6f224e5ebb69357988dd8","salt":"f38c1f86e69476e2361630d2cc43657eab06099d7eb38481bb262eeed2037c98","proof":{"merkleTree":{"nodes":[{"right":"706c6b3eca6e505e2b8203c85d1bb835ac47bb74af2a1ab99e2782f3b22c6d21"},{"left":"4556dcd32da44804136db5d60f33817cb8ead9427e523dc8b90580ad79c9e4d7"},{"right":"6502f68da9bd83661d479a20f7599b4f2c109b81bb707a528437cb39ed039529"},{"right":"5468435a3d57aced4eecf1d672ad20e7ec712ced93b97405f1d57724d3f20058"}]}},"value":"test@civic.com"},{"identifier":"contact.personal.phoneNumber","hash":"706c6b3eca6e505e2b8203c85d1bb835ac47bb74af2a1ab99e2782f3b22c6d21","salt":"d6d159a9b0d197ad0b4b4e7ed167ad4df1e4e184c96115801726e002bc02f37d","proof":{"merkleTree":{"nodes":[{"left":"5b471132950d766c08a8b9e5a4be941196839c46edd6f224e5ebb69357988dd8"},{"left":"4556dcd32da44804136db5d60f33817cb8ead9427e523dc8b90580ad79c9e4d7"},{"right":"6502f68da9bd83661d479a20f7599b4f2c109b81bb707a528437cb39ed039529"},{"right":"5468435a3d57aced4eecf1d672ad20e7ec712ced93b97405f1d57724d3f20058"}]}},"value":"+55 31992617887"}]}]}';

    civicClient.verify(data).then((response) => {
      console.log(response);
      done();
    })
      .catch((error) => {
        done(error);
      });
  });
});

