const needle = require('needle');
const civicSip = require('../index');
const { assert } = require('chai');

const nock = require('nock');

const HEX_PRVKEY_NIST = 'bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721';
// const HEX_PUBKEY_NIST = '047d9fd38a4d370d6cff16bf12723e343090d475bf36c1d806b625615a7873b0919f131e38418b0cd5b8a3e0a253fe3a958c7840bfc6be657af68062fecd7943d1';
const SECRET = '44bbae32d1e02bf481074177002bbdef';

describe('Civic SIP Server', function test() {
  this.timeout(10000);

  const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com/';
  const STAGE = 'dev';
  const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw';
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
    const doneFn = done;

    nock('https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com:443', { encodedQueryParams: true })
      .post('/dev/scopeRequest/authCode', { authToken: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw' })
      .reply(200, {
        data: 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1OTYzNWQ2Yy0zYzUyLTQwMzktOTg2OS05MWQwMjUzN2M2YjIiLCJpYXQiOjE1MTk5MzI1NzIuMTU4LCJleHAiOjE1MTk5MzQzNzIuMTU4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOiI0MDNkNjI0MzY1OTYwMjIyYmQzMWE2MWNhMjQzNWYyY1dOWjhrWkNEUWZWQmtSSVdsbDkzNGhZbDRUTGlrWWVENU52WE0xTUowN2FVQzFtcnFmdVdoWk5qQWVKT1plS0M2emk5Umh3cWR0bkswdWxNRFAwTkRaTHBRa2JqaVdBb1c5RXFYQW41eHNyemZSNUZ0cXZqZ0NORzNvUkp0Y29tRVBvaGVWMDZ3NWZDQ0Z1TjQrbTNiSW5CNldMamNBSmVObUJZT2oyWjFFQVoxcHZ0R2RwSThMWTVYS2VFTHpKM3MzZndidEpXbkorSHFqakxsQjJPM0lmaDBRdVdUMldUNWVrc3RLN1F1bk5MSldiSzJqWkkveGc0RHJFWFl0dnEifQ.YBBljiXaqrbiftAhu6X6csDVbRLcsSNf3xZNRgQzj6Wd7v1Ilja55H_K_gO7zFzj3Qi-bc7-83SI1w6A4Y7MEA', userId: '0eb98e188597a61ee90969a42555ded28dcdddccc6ffa8d8023d8833b0a10991', encrypted: true, alg: 'aes',
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
      console.log(data);
      nock.restore();
      doneFn();
    })
      .catch((error) => {
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

