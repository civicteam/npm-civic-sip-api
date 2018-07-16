const sipClient = require('../index');
const sinon = require('sinon');
const { expect, assert } = require('chai');
const nock = require('nock');
const jwtjs = require('../lib/jwt');

const HEX_PRVKEY_NIST = 'bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721';
const SECRET = '44bbae32d1e02bf481074177002bbdef';
const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com';
const STAGE = 'dev';

function mockAuthCode(authCode, data, encrypted) {
  nock(`${API}:443`, { encodedQueryParams: true })
    .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode })
    .reply(200, {
      data, userId: '0eb98e188597a61ee90969a42555ded28dcdddccc6ffa8d8023d8833b0a10991', encrypted, alg: 'aes',
    }, ['Content-Type',
      'application/json',
      'Content-Length',
      '870',
      'Connection',
      'close',
      'Date',
      'Thu, 01 Mar 2018 19:29:32 GMT',
      'x-amzn-RequestId',
      'dcc548df-1d86-11e8-847d-ef62a0370d67',
      'Access-Control-Allow-Origin',
      '*',
      'X-Amzn-Trace-Id',
      'sampled=0;root=1-5a98549a-d995e5c5731d2e7da3b17924',
      'Access-Control-Allow-Credentials',
      'true',
      'X-Cache',
      'Miss from cloudfront',
      'Via',
      '1.1 f32e4aea3683be99c4324204c29f5852.cloudfront.net (CloudFront)',
      'X-Amz-Cf-Id',
      'ydCSjnp8EPOQ1diNhYs6FfqGn1uRUvPiQoL8S16I_JfWX7s_4qxThQ==']);
}

function mockAuthCodeThrowErrror(authCode) {
  nock(`${API}:443`, { encodedQueryParams: true })
    .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode })
    .replyWithError('There was an error');
}

describe('Index', function indexTest() {
  this.timeout(10000);
  const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw';
  const returnData = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1OTYzNWQ2Yy0zYzUyLTQwMzktOTg2OS05MWQwMjUzN2M2YjIiLCJpYXQiOjE1MTk5MzI1NzIuMTU4LCJleHAiOjE1MTk5MzQzNzIuMTU4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOiI0MDNkNjI0MzY1OTYwMjIyYmQzMWE2MWNhMjQzNWYyY1dOWjhrWkNEUWZWQmtSSVdsbDkzNGhZbDRUTGlrWWVENU52WE0xTUowN2FVQzFtcnFmdVdoWk5qQWVKT1plS0M2emk5Umh3cWR0bkswdWxNRFAwTkRaTHBRa2JqaVdBb1c5RXFYQW41eHNyemZSNUZ0cXZqZ0NORzNvUkp0Y29tRVBvaGVWMDZ3NWZDQ0Z1TjQrbTNiSW5CNldMamNBSmVObUJZT2oyWjFFQVoxcHZ0R2RwSThMWTVYS2VFTHpKM3MzZndidEpXbkorSHFqakxsQjJPM0lmaDBRdVdUMldUNWVrc3RLN1F1bk5MSldiSzJqWkkveGc0RHJFWFl0dnEifQ.YBBljiXaqrbiftAhu6X6csDVbRLcsSNf3xZNRgQzj6Wd7v1Ilja55H_K_gO7zFzj3Qi-bc7-83SI1w6A4Y7MEA';
  const clientConfig = {
    appId: 'HyhaWO1SG',
    prvKey: HEX_PRVKEY_NIST,
    appSecret: SECRET,
    api: API,
    env: STAGE,
  };
  const partialConfig = {
    appId: 'anId',
    appSecret: 'anAppSecret',
    prvKey: 'aPrivateKey'
  };

  describe('newClient', function newClientTest() {
    this.beforeEach(() => {
      sinon.stub(jwtjs, 'verify').returns(true);
  
      mockAuthCode(authCode, returnData, true);
    });
  
    this.afterEach(() => {
      nock.cleanAll();
      jwtjs.verify.restore();
    });

    it('expects an application id', () => {
      try {
        sipClient.newClient();
      } catch (error) {
        expect(error.message).to.equal('Please supply your application ID.');
      }
    });

    it('expects an application secret', () => {
      try {
        sipClient.newClient({ appId: 'something' });
      } catch (error) {
        expect(error.message).to.equal('Please supply your application secret.');
      }
    });

    it('expects an application private key', () => {
      try {
        sipClient.newClient({ appId: 'something', appSecret: 'a secret' });
      } catch (error) {
        expect(error.message).to.equal('Please supply your application private key.');
      }
    });

    it('should allow a minimum config', () => {
      const client = sipClient.newClient(partialConfig);
      expect(client.exchangeCode).to.be.a('function');
    });

    it('should allow a config with optional keys', () => {
      const client = sipClient.newClient(clientConfig);
      expect(client.exchangeCode).to.be.a('function');
    });

    it('should exchange an encrypted code', (done) => {
      const doneFn = done;
      const client = sipClient.newClient(clientConfig);
      client.exchangeCode(authCode).then((data) => {
        // console.log(data);
        assert.equal(data.data[1].label, 'contact.personal.phoneNumber', 'The labels are not equal');
        assert.isTrue(data.data[1].isOwner, 'isOwner not true');
        assert.isTrue(data.data[1].isValid, 'isValid not true');
        doneFn();
      })
        .catch((error) => {
          doneFn(error);
        });
    });

    it('should not exchange data that is not encrypted', (done) => {
      const doneFn = done;
      const client = sipClient.newClient(clientConfig);

      nock.cleanAll();
      mockAuthCode(authCode, returnData, false);

      client.exchangeCode(authCode).then((data) => {
        expect(data.data).to.equal(undefined);
        doneFn();
      })
        .catch((error) => {
          doneFn(error);
        });
    });

    it('should handle errors from the authCode end point', (done) => {
      const doneFn = done;
      const client = sipClient.newClient(clientConfig);
      const errorMessage = 'There was an error';

      nock.cleanAll();
      mockAuthCodeThrowErrror(authCode, errorMessage);

      client.exchangeCode(authCode).then((data) => {
        expect(data.data).to.equal(undefined);
        doneFn();
      })
        .catch((error) => {
          expect(error.message).to.equal(`Error exchanging code for data: ${errorMessage}`);
          doneFn();
        });
    });
  });
});
