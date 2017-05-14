'use strict';

require("babel-polyfill");
require("babel-core/register");

const civicSip = require('../index');
const assert = require('chai').assert;


describe('exchangeCode', function() {
  this.timeout(10000);

  const authCode = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJqdGkiOiI1Y2QxY2RiMS05NWRkLTQ5MWYtODE4Mi1mZTdkNmE1NmEzZjciLCJpYXQiOjE0OTQ3MDU2NzAuNzYzLCJleHAiOjE0OTQ3MDU4NTAuNzYzLCJpc3MiOiJjaXZpYy1zaXAtaG9zdGVkLXNlcnZpY2UiLCJhdWQiOiJodHRwczovL2FwaS5jaXZpYy5jb20vc2lwLyIsInN1YiI6ImJiYjEyMyIsImRhdGEiOnsiY29kZVRva2VuIjoiNWVhNjkwN2EtMTQ0MS00NTIwLWFlYmItYjIwOTQ1NjYwM2I2In19.Ih5n-CuzbwcpfOFVYp13UBCyATFsxt52OUl8cvkEvQgU7dQ_UzISnXV30WdFTooHpW9as8uhMeBG3IXTJzktxQ';
  const civicClient = civicSip.newClient({
    appId: 'aaa123', // insert appId
    appSecret: '7cf5ac70fc9eb1671c85547ef594599ce8214e0c6563e12f24cbd338b8e649c4',
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
