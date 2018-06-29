const civicSip = require('../index');
const nock = require('nock');
const sinon = require('sinon');
const jwtjs = require('../lib/jwt');
const { assert } = require('chai');
const zlib = require('zlib');

const sizeof = require('object-sizeof');

const HEX_PRVKEY_NIST = 'bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721';
const SECRET = '44bbae32d1e02bf481074177002bbdef';

describe('index.js', function test() {
  const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com';
  const STAGE = 'dev';
  const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw';
  const returnData = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1OTYzNWQ2Yy0zYzUyLTQwMzktOTg2OS05MWQwMjUzN2M2YjIiLCJpYXQiOjE1MTk5MzI1NzIuMTU4LCJleHAiOjE1MTk5MzQzNzIuMTU4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOiI0MDNkNjI0MzY1OTYwMjIyYmQzMWE2MWNhMjQzNWYyY1dOWjhrWkNEUWZWQmtSSVdsbDkzNGhZbDRUTGlrWWVENU52WE0xTUowN2FVQzFtcnFmdVdoWk5qQWVKT1plS0M2emk5Umh3cWR0bkswdWxNRFAwTkRaTHBRa2JqaVdBb1c5RXFYQW41eHNyemZSNUZ0cXZqZ0NORzNvUkp0Y29tRVBvaGVWMDZ3NWZDQ0Z1TjQrbTNiSW5CNldMamNBSmVObUJZT2oyWjFFQVoxcHZ0R2RwSThMWTVYS2VFTHpKM3MzZndidEpXbkorSHFqakxsQjJPM0lmaDBRdVdUMldUNWVrc3RLN1F1bk5MSldiSzJqWkkveGc0RHJFWFl0dnEifQ.YBBljiXaqrbiftAhu6X6csDVbRLcsSNf3xZNRgQzj6Wd7v1Ilja55H_K_gO7zFzj3Qi-bc7-83SI1w6A4Y7MEA';
  const civicClient = civicSip.newClient({
    appId: 'HyhaWO1SG',
    prvKey: HEX_PRVKEY_NIST,
    appSecret: SECRET,
    api: API,
    env: STAGE,
  });

  describe('verifyAndDecrypt', function testVerifyAndDecrypt() {
    const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw';

    it('should decompress the payload', (done) => {
      const compressed = zlib.gzipSync(returnData);

      const doneFn = done;

      sinon.stub(jwtjs, 'verify').returns(true);

      nock(`${API}:443`, { encodedQueryParams: true })
        .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode })
        .reply(200, {
          data: compressed, userId: '0eb98e188597a61ee90969a42555ded28dcdddccc6ffa8d8023d8833b0a10991', encrypted: true, alg: 'aes',
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

      civicClient.exchangeCode(authCode).then((data) => {
        // console.log(data);
        assert.equal(data.data[1].label, 'contact.personal.phoneNumber', 'The labels are not equal');
        assert.isTrue(data.data[1].isOwner, 'isOwner not true');
        assert.isTrue(data.data[1].isValid, 'isValid not true');
        jwtjs.verify.restore();
        doneFn();
      })
        .catch((error) => {
          jwtjs.verify.restore();
          doneFn(error);
        });
    });
  });
});
