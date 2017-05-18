# civic-sip-api

Node.js wrapper for the Civic hosted SIP API.  For best results, be sure that you're using the latest version.

### Installation

civic-sip-api can be installed from npm:

```
$ npm install civic-sip-api --save

```

### Usage
```javascript

import * as civicSip from 'civic-sip-api';

const civicClient = civicSip.newClient({ appId: 'ABC123', appSecret: APP_SECRET });

civicClient.exchangeCode(jwtToken)
    .then(function(userData) {
        // store user data and userId as appropriate
        console.log("userData = " + EJSON.stringify(userData));

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
                        "value": "+1 415-618-7380",
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



