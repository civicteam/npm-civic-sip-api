[![NPM version](http://img.shields.io/npm/v/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)
[![NPM downloads](http://img.shields.io/npm/dm/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)
[![node version](http://img.shields.io/node/v/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)

Node.js wrapper for the Civic hosted SIP API.  For best results, be sure that you're using the latest version.

Please see [docs.civic.com](https://docs.civic.com) for a more details.

### Installation

`civic-sip-api` can be installed from npm:

```shell
npm install civic-sip-api --save
```

### Usage
```javascript
const civicSip = require('civic-sip-api');

const civicClient = civicSip.newClient({
    appId: 'ABC123',
    appSecret: APP_SECRET,
    prvKey: PRV_KEY,
});

civicClient.exchangeCode(jwtToken)
    .then((userData) => {
        // store user data and userId as appropriate
        console.log('userData = ', JSON.stringify(userData, null, 4));
    }).catch((error) => {
        console.log(error);
    });
```
Example of data returned for a `ScopeRequest` of `BASIC_SIGNUP`
```javascript
userData =  {
    "data": [
        {
            "label": "contact.personal.email",
            "value": "user.test@gmail.com",
            "isValid": true,
            "isOwner": true
        },
        {
            "label": "contact.personal.phoneNumber",
            "value": "+1 5556187380",
            "isValid": true,
            "isOwner": true
        }
    ],
    "userId": "c6d5795f8a059ez5ad29a33a60f8b402a172c3e0bbe50fd230ae8e0303609b42"
}
```

---
Copyright &copy; 2017 Civic.com

Released under the MIT License, which can be found in the repository in `LICENSE.txt`.



