const _ = require('lodash');
const sipClient = require('../index');
const sinon = require('sinon');
const { expect, assert } = require('chai');
const nock = require('nock');
const jwtjs = require('../lib/jwt');
const rewire = require('rewire');
const civicIndex = rewire("../index.js");

const HEX_PRVKEY_NIST = 'bf5efd7bdde29dc28443614bfee78c3d6ee39c71e55a0437eee02bf7e3647721';
const SECRET = '44bbae32d1e02bf481074177002bbdef';
const API = 'https://kw9lj3a57c.execute-api.us-east-1.amazonaws.com';
const STAGE = 'dev';
const bucketResponse = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1OTYzNWQ2Yy0zYzUyLTQwMzktOTg2OS05MWQwMjUz' +
'N2M2YjIiLCJpYXQiOjE1MTk5MzI1NzIuMTU4LCJleHAiOjE1MTk5MzQzNzIuMTU4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhd' +
'WQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOiI0MDNkNjI0MzY1OTYwMjIyYmQzMWE2MWNhMj' +
'QzNWYyY1dOWjhrWkNEUWZWQmtSSVdsbDkzNGhZbDRUTGlrWWVENU52WE0xTUowN2FVQzFtcnFmdVdoWk5qQWVKT1plS0M2emk5Umh3cWR0bkswdWx' +
'NRFAwTkRaTHBRa2JqaVdBb1c5RXFYQW41eHNyemZSNUZ0cXZqZ0NORzNvUkp0Y29tRVBvaGVWMDZ3NWZDQ0Z1TjQrbTNiSW5CNldMamNBSmVObUJZ' +
'T2oyWjFFQVoxcHZ0R2RwSThMWTVYS2VFTHpKM3MzZndidEpXbkorSHFqakxsQjJPM0lmaDBRdVdUMldUNWVrc3RLN1F1bk5MSldiSzJqWkkveGc0R' +
'HJFWFl0dnEifQ.YBBljiXaqrbiftAhu6X6csDVbRLcsSNf3xZNRgQzj6Wd7v1Ilja55H_K_gO7zFzj3Qi-bc7-83SI1w6A4Y7MEA';

function mockProcessPayload() {
  nock('https://dev-civic-payload-service-payload-bucket.s3.amazonaws.com:443', { encodedQueryParams:true })
    .get('/2a340e648a2bdcfc124a56ba009e6a68cc07a794')
    .query({"X-Amz-Algorithm":"AWS4-HMAC-SHA256",
      "X-Amz-Credential":"ASIATUH3F2PWGP7FGHG7%2F20181120%2Fus-east-1%2Fs3%2Faws4_request",
      "X-Amz-Date":"20181120T222054Z",
      "X-Amz-Expires":"60",
      "X-Amz-Security-Token":"FQoGZXIvYXdzEJD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDMDunggJGkxZvdPo7iKBAl9lgn0ac3nIiAvdi5ez0dhDuh81WtCCC3%2Fn1S63TEToMQufNHwwoI94bDgZ6a2JXOekJyePevET8u%2Fp2M3jzEzk%2BAIKvG96KxgIjIntykqGb%2BTAe%2Bu9ZT5FefBmXOfoXuYxkAGXWTtaPGzPkRhX318HIiQ9Y3XWnWJOqyzuCtlDBsbvUU%2F7jy5tp9S3dY%2FmguaO%2BjyvK7mVkstqaErrU2HcuZqkeDfPr3pIES8kK3H54aNWo%2FWqxeyiWqrObYFy62YrOZp8lsV1G%2FlX31HTQ%2BjPHy5maMReIJvznMQcLCN%2Fclze9TBBZpI1xcxV41Yzjc6vtYKiOUWHzNJgpG7zdQH6KKuL0t8F",
      "X-Amz-Signature":"245c8f5824b3a1017686595ee8c1b989f43a22267012931ec4b3a97d1aeabcee",
      "X-Amz-SignedHeaders":"host"})
    .reply(200, bucketResponse, [
      'x-amz-id-2',
      'EBxdrc5mIa0/kIigJKikjiNsb5Ws872mBF2j1ZF2BYmjJmDLbfUXRm+ECD1eGpaJsOvLcY98UNY=',
      'x-amz-request-id',
      '86A2C7DB3845BDB7',
      'Date',
      'Wed, 31 Oct 2018 20:33:34 GMT',
      'Last-Modified',
      'Wed, 31 Oct 2018 20:33:34 GMT',
      'x-amz-expiration',
      'expiry-date="Fri, 02 Nov 2018 00:00:00 GMT", rule-id="NDg4OWRlYWItMmU2NC00Yzc0LTgyYjktMGUyNjk3YjZlOTQ0"',
      'ETag',
      '"8e8a7171740edbc62f3b94149411b61e"',
      'Accept-Ranges',
      'bytes',
      'Content-Type',
      'application/json',
      'Content-Length',
      '754',
      'Server',
      'AmazonS3',
      'Connection',
      'close',
    ]);
}

function mockProcessPayloadError() {
  nock('https://dev-civic-payload-service-payload-bucket.s3.amazonaws.com:443', { encodedQueryParams:true })
    .get('/2a340e648a2bdcfc124a56ba009e6a68cc07a794')
    .query({"X-Amz-Algorithm":"AWS4-HMAC-SHA256",
      "X-Amz-Credential":"ASIATUH3F2PWGP7FGHG7%2F20181120%2Fus-east-1%2Fs3%2Faws4_request",
      "X-Amz-Date":"20181120T222054Z",
      "X-Amz-Expires":"60",
      "X-Amz-Security-Token":"FQoGZXIvYXdzEJD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDMDunggJGkxZvdPo7iKBAl9lgn0ac3nIiAvdi5ez0dhDuh81WtCCC3%2Fn1S63TEToMQufNHwwoI94bDgZ6a2JXOekJyePevET8u%2Fp2M3jzEzk%2BAIKvG96KxgIjIntykqGb%2BTAe%2Bu9ZT5FefBmXOfoXuYxkAGXWTtaPGzPkRhX318HIiQ9Y3XWnWJOqyzuCtlDBsbvUU%2F7jy5tp9S3dY%2FmguaO%2BjyvK7mVkstqaErrU2HcuZqkeDfPr3pIES8kK3H54aNWo%2FWqxeyiWqrObYFy62YrOZp8lsV1G%2FlX31HTQ%2BjPHy5maMReIJvznMQcLCN%2Fclze9TBBZpI1xcxV41Yzjc6vtYKiOUWHzNJgpG7zdQH6KKuL0t8F",
      "X-Amz-Signature":"245c8f5824b3a1017686595ee8c1b989f43a22267012931ec4b3a97d1aeabcee",
      "X-Amz-SignedHeaders":"host"})
    .reply(401, 'Unauthorized', [
      'x-amz-id-2',
      'EBxdrc5mIa0/kIigJKikjiNsb5Ws872mBF2j1ZF2BYmjJmDLbfUXRm+ECD1eGpaJsOvLcY98UNY=',
      'x-amz-request-id',
      '86A2C7DB3845BDB7',
      'Date',
      'Wed, 31 Oct 2018 20:33:34 GMT',
      'Last-Modified',
      'Wed, 31 Oct 2018 20:33:34 GMT',
      'x-amz-expiration',
      'expiry-date="Fri, 02 Nov 2018 00:00:00 GMT", rule-id="NDg4OWRlYWItMmU2NC00Yzc0LTgyYjktMGUyNjk3YjZlOTQ0"',
      'ETag',
      '"8e8a7171740edbc62f3b94149411b61e"',
      'Accept-Ranges',
      'bytes',
      'Content-Type',
      'application/json',
      'Content-Length',
      '754',
      'Server',
      'AmazonS3',
      'Connection',
      'close',
    ]);
}

function mockAuthCode(authCode, data, encrypted) {
  nock(`${API}:443`, { encodedQueryParams: true })
    .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode, allowS3UploadedPayload: true })
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

function mockAuthCodeProcessedPayload(authCode, data) {
  nock(`${API}:443`, { encodedQueryParams: true })
    .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode, allowS3UploadedPayload: true })
    .reply(200, data, [
      'Content-Type',
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
      'ydCSjnp8EPOQ1diNhYs6FfqGn1uRUvPiQoL8S16I_JfWX7s_4qxThQ==',
    ]);
}

function mockAuthCodeThrowErrror(authCode, errorMessage) {
  nock(`${API}:443`, { encodedQueryParams: true })
    .post(`/${STAGE}/scopeRequest/authCode`, { authToken: authCode, allowS3UploadedPayload: true })
    .replyWithError(errorMessage);
}

describe('Index', function indexTest() {
  this.timeout(10000);
  const authCode = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIxNzc1ZDQwMi05ZjNjLTQ0OWUtYWZkYS04ZDk4MmM0OGIxYjIiLCJpYXQiOjE1MTk5MzE3MTcuMDM1LCJleHAiOjE1MTk5MzM1MTcuMDM1LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOnsiY29kZVRva2VuIjoiYTRhYjE1MDEtZTg0Ni00NmUyLWEwZDktMzEyNTAwNmIxNzUzIn19.1d3Q3QeL8SE_wlyxHPi6Pn-buf8XsxRlCkfhULiI5CbDLCgEjLuVMGIFSUXg6_snXOD9p-ImVml-0yF-A2-qaw';
  const returnData = 'eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiI1OTYzNWQ2Yy0zYzUyLTQwMzktOTg2OS05MWQwMjUzN2M2YjIiLCJpYXQiOjE1MTk5MzI1NzIuMTU4LCJleHAiOjE1MTk5MzQzNzIuMTU4LCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6Ikh5aGFXTzFTRyIsImRhdGEiOiI0MDNkNjI0MzY1OTYwMjIyYmQzMWE2MWNhMjQzNWYyY1dOWjhrWkNEUWZWQmtSSVdsbDkzNGhZbDRUTGlrWWVENU52WE0xTUowN2FVQzFtcnFmdVdoWk5qQWVKT1plS0M2emk5Umh3cWR0bkswdWxNRFAwTkRaTHBRa2JqaVdBb1c5RXFYQW41eHNyemZSNUZ0cXZqZ0NORzNvUkp0Y29tRVBvaGVWMDZ3NWZDQ0Z1TjQrbTNiSW5CNldMamNBSmVObUJZT2oyWjFFQVoxcHZ0R2RwSThMWTVYS2VFTHpKM3MzZndidEpXbkorSHFqakxsQjJPM0lmaDBRdVdUMldUNWVrc3RLN1F1bk5MSldiSzJqWkkveGc0RHJFWFl0dnEifQ.YBBljiXaqrbiftAhu6X6csDVbRLcsSNf3xZNRgQzj6Wd7v1Ilja55H_K_gO7zFzj3Qi-bc7-83SI1w6A4Y7MEA';
  const returnProcessedData = {
    payloadUrl: 'https://dev-civic-payload-service-payload-bucket.s3.amazonaws.com/2a340e648a2bdcfc124a56ba009e6a68cc07a794?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIATUH3F2PWGP7FGHG7%2F20181120%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20181120T222054Z&X-Amz-Expires=60&X-Amz-Security-Token=FQoGZXIvYXdzEJD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDMDunggJGkxZvdPo7iKBAl9lgn0ac3nIiAvdi5ez0dhDuh81WtCCC3%2Fn1S63TEToMQufNHwwoI94bDgZ6a2JXOekJyePevET8u%2Fp2M3jzEzk%2BAIKvG96KxgIjIntykqGb%2BTAe%2Bu9ZT5FefBmXOfoXuYxkAGXWTtaPGzPkRhX318HIiQ9Y3XWnWJOqyzuCtlDBsbvUU%2F7jy5tp9S3dY%2FmguaO%2BjyvK7mVkstqaErrU2HcuZqkeDfPr3pIES8kK3H54aNWo%2FWqxeyiWqrObYFy62YrOZp8lsV1G%2FlX31HTQ%2BjPHy5maMReIJvznMQcLCN%2Fclze9TBBZpI1xcxV41Yzjc6vtYKiOUWHzNJgpG7zdQH6KKuL0t8F&X-Amz-Signature=245c8f5824b3a1017686595ee8c1b989f43a22267012931ec4b3a97d1aeabcee&X-Amz-SignedHeaders=host',
    processed: true,
    data: 'https://dev-civic-payload-service-payload-bucket.s3.amazonaws.com/2a340e648a2bdcfc124a56ba009e6a68cc07a794?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIATUH3F2PWGP7FGHG7%2F20181120%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20181120T222054Z&X-Amz-Expires=60&X-Amz-Security-Token=FQoGZXIvYXdzEJD%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaDMDunggJGkxZvdPo7iKBAl9lgn0ac3nIiAvdi5ez0dhDuh81WtCCC3%2Fn1S63TEToMQufNHwwoI94bDgZ6a2JXOekJyePevET8u%2Fp2M3jzEzk%2BAIKvG96KxgIjIntykqGb%2BTAe%2Bu9ZT5FefBmXOfoXuYxkAGXWTtaPGzPkRhX318HIiQ9Y3XWnWJOqyzuCtlDBsbvUU%2F7jy5tp9S3dY%2FmguaO%2BjyvK7mVkstqaErrU2HcuZqkeDfPr3pIES8kK3H54aNWo%2FWqxeyiWqrObYFy62YrOZp8lsV1G%2FlX31HTQ%2BjPHy5maMReIJvznMQcLCN%2Fclze9TBBZpI1xcxV41Yzjc6vtYKiOUWHzNJgpG7zdQH6KKuL0t8F&X-Amz-Signature=245c8f5824b3a1017686595ee8c1b989f43a22267012931ec4b3a97d1aeabcee&X-Amz-SignedHeaders=host',
  };
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
      mockProcessPayload();
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
          expect(error.message).to.equal(`Error exchanging code for data: Error: ${errorMessage}`);
          doneFn();
        });
    });

    it('should exchange a payload using a proxy', (done) => {
      nock.cleanAll();
      mockAuthCodeProcessedPayload(authCode, returnProcessedData);
      mockProcessPayload();
      const doneFn = done;
      const clientConfigCopy = _.cloneDeep(clientConfig);
      clientConfigCopy.proxy = {
        url: 'http://localhost:8080',
      };
      const client = sipClient.newClient(clientConfigCopy);
      client.exchangeCode(authCode).then((data) => {
        expect(data).to.haveOwnProperty('data');
        expect(data).to.haveOwnProperty('userId');
        doneFn();
      })
        .catch((error) => {
          doneFn(error);
        });
    });

    it('should throw an error if the payload is unreachable using a proxy', (done) => {
      nock.cleanAll();
      mockAuthCodeProcessedPayload(authCode, returnProcessedData);
      mockProcessPayloadError();
      const doneFn = done;
      const clientConfigCopy = _.cloneDeep(clientConfig);
      clientConfigCopy.proxy = {
        url: 'http://localhost:8080',
      };
      const client = sipClient.newClient(clientConfigCopy);
      client.exchangeCode(authCode).then((data) => {
        expect(data).to.be(undefined);
        doneFn();
      })
        .catch((error) => {
          expect(error.message).to.equal('Error exchanging code for data: Could not return data from processed payload url: StatusCodeError: 401 - "Unauthorized"');
          doneFn();
        });
    });

    it('should throw an error if verify fails', () => {
      jwtjs.verify.restore();
      sinon.stub(jwtjs, 'verify').returns(false);
      const verifyAndDecrypt = civicIndex.__get__('verifyAndDecrypt');

      try {
        verifyAndDecrypt({}, 'asecret');
      } catch (error) {
        assert.equal(error.message, 'JWT Token containing encrypted data could not be verified');
      }
    });

    it('should process all the payload error types', () => {
      const processError = civicIndex.__get__('processPayloadErrorResponse');

      try {
        processError({ data: 'an error' });
      } catch (error) {
        assert.equal(error.message, 'Error exchanging code for data: an error');
      }

      try {
        processError({ message: 'an error' });
      } catch (error) {
        assert.equal(error.message, 'Error exchanging code for data: an error');
      }

      try {
        processError({ data: { message: 'an error' }});
      } catch (error) {
        assert.equal(error.message, 'Error exchanging code for data: an error');
      }

      try {
        processError('an error');
      } catch (error) {
        assert.equal(error.message, 'Error exchanging code for data: an error');
      }

      try {
        processError(['an error']);
      } catch (error) {
        assert.equal(error.message, 'Error exchanging code for data: [ \'an error\' ]');
      }
    });
  });
});
