const needle = require('needle');
const civicSip = require('../index');
const nock = require('nock');
const sinon = require('sinon');
const jwtjs = require('../lib/jwt');
const chai = require('chai');
const chaiAsPromised = require('chai-as-promised')

chai.use(chaiAsPromised);

const expect = chai.expect;
const assert = chai.assert;
const should = chai.should();

const HEX_PRVKEY_NIST = 'bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721';
// const HEX_PUBKEY_NIST = '047d9fd38a4d370d6cff16bf12723e343090d475bf36c1d806b625615a7873b0919f131e38418b0cd5b8a3e0a253fe3a958c7840bfc6be657af68062fecd7943d1';
const SECRET = '44bbae32d1e02bf481074177002bbdef';

describe('Civic SIP Server', function test() {
  this.timeout(10000);

  const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com';
  const PAYLOAD_PROCESS_API = 'https://h3qe39xpc2.execute-api.us-east-1.amazonaws.com/dev/payload/process?return=url';
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

    const url = `${API}/${STAGE}/scopeRequest/authCode`;

    nock(`${API}:443`, { encodedQueryParams: true })
      .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode })
      .reply(401, 'Unauthorized', ['Content-Type',
        'application/json',
        'Content-Length',
        '12',
        'Connection',
        'close',
        'Date',
        'Thu, 01 Mar 2018 21:12:30 GMT',
        'x-amzn-RequestId',
        '4061216b-1d95-11e8-907a-a10c87994583',
        'X-Amzn-Trace-Id',
        'sampled=0;root=1-5a986cbe-fb795596a9eadaeb13e9cc63',
        'X-Cache',
        'Error from cloudfront',
        'Via',
        '1.1 69ecfaf49062e67077b5f6c4aaf1881f.cloudfront.net (CloudFront)',
        'X-Amz-Cf-Id',
        'iD-SPGUuIGViCT28gs0j2Nhk3Rz_NkJ7sHGiEov0H2aeBkfdq2kMrg==']);

    needle.post(url, JSON.stringify(body), options, (err, resp) => {
      assert.equal(resp.statusCode, 401, 'Status code is not 401');
      assert.equal(resp.body, 'Unauthorized', 'Body should show unauthorized');
      doneFn();
    });
  });

  it('should exchange authCode for user data.', (done) => {
    const doneFn = done;

    sinon.stub(jwtjs, 'verify').returns(true);

    nock(`${API}:443`, { encodedQueryParams: true })
      .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode, processPayload: true })
      .reply(200, {
        data: returnData, userId: '0eb98e188597a61ee90969a42555ded28dcdddccc6ffa8d8023d8833b0a10991', encrypted: true, alg: 'aes'
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

    civicClient.exchangeCode(authCode)
      .then((data) => {
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

  it('should throw error in processPayload if status is not 200', (done) => {
    const doneFn = done;
    const response = {
      body: 'This body does not matter when testing function throw error',
      statusCode: 400
    }

    expect(() => civicClient.processPayload(response)).to.throw();
    doneFn();
  });

  it('should process payload via payload service', (done) => {
    let payloadData;
    const userId = '0eb98e188597a61ee90969a42555ded28dcdddccc6ffa8d8023d8833b0a10991';
    sinon.stub(jwtjs, 'verify').returns(true);

    needle('POST', PAYLOAD_PROCESS_API, JSON.stringify({ payload: returnData }))
      .then((data) => {
        data.body.payloadUrl.should.exist
        data.statusCode = 200
        data.body.processed = true
        data.body.data = data.body.payloadUrl
        data.userId = userId

        payloadData = data
        const processPayload = civicClient.processPayload(payloadData);
        processPayload.should.be.fulfilled
          .then((d) => {
            expect(d).to.haveOwnProperty('data');
            expect(d).to.haveOwnProperty('userId');
            jwtjs.verify.restore();
          })
          .should.notify(done);
      })
      .catch(error => { throw new Error(error)});
  });

  it('should throw error when attempting to process an empty payload', () => {
    const response = {
      body: {
        processed: true,
        data: ''
      },
      statusCode: 200,
    }

    try {
      const processPayload = civicClient.processPayload(response);
      expect(processPayload).to.be.undefined();
    } catch (error) {
     expect(error.message).to.equal('Invalid response body or body data not found: {"processed":true,"data":""}');
    }
  });
});

