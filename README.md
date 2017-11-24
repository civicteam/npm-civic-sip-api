# civic-sip-api

[![NPM version](http://img.shields.io/npm/v/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)
[![NPM downloads](http://img.shields.io/npm/dm/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)
[![node version](http://img.shields.io/npm/v/civic-sip-api.svg?style=flat-square)](https://www.npmjs.com/package/civic-sip-api)

Node.js wrapper for the Civic hosted SIP API.  For best results, be sure that you're using the latest version.

### Installation

civic-sip-api can be installed from npm:

```
$ npm install civic-sip-api --save

```

### Usage
```javascript

import * as civicSip from 'civic-sip-api';

const civicClient = civicSip.newClient({ appId: 'ABC123',
                                         appSecret: APP_SECRET,
                                         prvKey: PRV_KEY,
                                      });

civicClient.exchangeCode(jwtToken)
    .then(function(userData) {
        // store user data and userId as appropriate
        console.log("userData = " + JSON.stringify(userData));

        /*  example for response to a CIVIC_BASIC scope request:
            userData = {
                "data": [
                    {
                        "label": "contact.verificationLevel.CIVIC_0",
                        "value": "contact.verificationLevel.CIVIC_0, true",
                        "isValid": true,
                        "isOwner": true
                    },
                    {
                        "label": "contact.personal.email",
                        "value": "user.test@gmail.com",
                        "isValid": true,
                        "isOwner": true
                    },
                    {
                        "label": "contact.personal.phoneNumber",
                        "value": "+1 555-618-7380",
                        "isValid": true,
                        "isOwner": true
                    }
                ],
                "encrypted": false,
                "userId": "36a59d10-6c53-17f6-9185-gthyte22647a"
            }
        */
    }).catch(function(error) {

    });

```


=======================

Copyright &copy; 2017 Civic.com

Released under the MIT License, which can be found in the repository in `LICENSE.txt`.



