const util = require('util');
const request = require('request-promise-native');
const basicCrypto = require('./lib/basicCrypto');
const jwtjs = require('./lib/jwt');

const sipClientFactory = {};
const JWT_EXPIRATION = '3m';
const hostedServices = {
  SIPHostedService: {
    base_url: 'https://api.civic.com/sip/',
    hexpub: '049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1',
    tokenType: 'JWT',
  },
};

/**
 * Creates the authorization header as an extended Civic JWT Token.
 * The token format: Civic requestToken.extToken
 * where requestToken certifies the service path, method
 * and audience, and extToken certifies the request body.
 *
 * The token is signed by the application secret.
 *
 * @param targetPath
 * @param targetMethod
 * @param requestBody
 * @returns {string}
 */
const makeAuthorizationHeader = (config, targetPath, targetMethod, requestBody) => {
  const jwtToken = jwtjs.createToken(config.appId, hostedServices.SIPHostedService.base_url, config.appId, JWT_EXPIRATION, {
    method: targetMethod,
    path: targetPath,
  }, config.prvKey);

  const extension = jwtjs.createCivicExt(requestBody, config.appSecret);
  return `Civic ${jwtToken}.${extension}`;
};

/**
 * The user data received from the civic sip server is wrapped in a
 * JWT token and encrypted using aes with the partner secret. This
 * function verifies the token is valid (signed by Civic sip server etc.)
 * and decrypts the user data if required.
 *
 * @param payload contains data field with JWT token signed by sip-hosted-services
 */
const verifyAndDecrypt = (payload, secret) => {
  const token = payload.data;
  const isValid = jwtjs.verify(token, hostedServices.SIPHostedService.hexpub, { gracePeriod: 60 });

  if (!isValid) {
    throw new Error('JWT Token containing encrypted data could not be verified');
  }

  // decrypt the data
  const decodedToken = jwtjs.decode(token);
  let userData;
  let clearText = decodedToken.payloadObj.data;

  if (payload.encrypted) {
    clearText = basicCrypto.decrypt(decodedToken.payloadObj.data, secret);
  }

  try {
    userData = JSON.parse(clearText);
  } catch (e) {
    /* Ignore */
    // console.log(`Error parsing decrypted string to user data: ${e.message}`);
  }

  const decryptedPayload = {
    data: userData,
    userId: payload.userId,
  };

  return decryptedPayload;
};

const processPayloadErrorResponse = (error) => {
  let errorStr;
  if (typeof error === 'string') {
    errorStr = error;
  } else if (error.data && error.data.message) {
    errorStr = error.data.message;
  } else if (error.data) {
    errorStr = error.data;
  } else if (error.message) {
    errorStr = error.message;
  } else {
    errorStr = util.inspect(error);
  }
  throw new Error(`Error exchanging code for data: ${errorStr}`);
};

// todo convert to class
sipClientFactory.newClient = (configIn) => {
  let config = Object.assign({}, configIn);
  if (config === undefined) {
    config = {
      appId: '',
      appSecret: '', // hex format
      prvKey: '', // hex format
      env: 'prod',
      defaultContentType: 'application/json',
      defaultAcceptType: 'application/json',
      includeStageInURL: false,
    };
  }

  if (!config.appId) {
    throw new Error('Please supply your application ID.');
  }

  if (!config.appSecret) {
    throw new Error('Please supply your application secret.');
  }

  if (!config.prvKey) {
    throw new Error('Please supply your application private key.');
  }

  if (!config.env) {
    config.env = 'prod';
  }

  if (config.includeStageInURL === undefined) {
    config.includeStageInURL = true;
  }

  if (config.api) {
    hostedServices.SIPHostedService.base_url = config.api;

    if (!config.api.endsWith('/')) {
      hostedServices.SIPHostedService.base_url += '/';
    }
  }

  // If defaultContentType is not defined then default to application/json
  if (config.defaultContentType === undefined) {
    config.defaultContentType = 'application/json';
  }
  // If defaultAcceptType is not defined then default to application/json
  if (config.defaultAcceptType === undefined) {
    config.defaultAcceptType = 'application/json';
  }

  const processPayload = (response) => {
    if (response.statusCode !== 200) {
      throw new Error(`${response.statusCode} ${response.body}`);
    }

    let body;

    try {
      body = JSON.parse(response.body);
    } catch (error) {
      ({ body } = response);
    }

    if (!body || !body.data) {
      throw new Error(`Invalid response body or body data not found: ${JSON.stringify(body)}`);
    }

    const { processed } = body;

    if (processed) {
      const requestOptions = {
        url: body.data,
        method: 'GET',
        resolveWithFullResponse: true,
      };

      if (config.proxy) {
        requestOptions.proxy = config.proxy.url;
        requestOptions.rejectUnauthorized = 'rejectUnauthorized' in config.proxy ? config.proxy.rejectUnauthorized : true;
      }

      return request(requestOptions)
        .then((data) => {
          const payloadData = data.body;
          body.data = payloadData;
          return verifyAndDecrypt(body, config.appSecret);
        })
        .catch((error) => {
          throw new Error(`Could not return data from processed payload url: ${error}`);
        });
    }

    return verifyAndDecrypt(body, config.appSecret);
  };

  // extract endpoint and path from url
  const invokeUrl = config.includeStageInURL ? hostedServices.SIPHostedService.base_url + config.env : hostedServices.SIPHostedService.base_url;

  /**
   * Exchange authorization code in the form of a JWT Token for the user data
   * requested in the scope request.
   *
   * @param {String} jwtToken - Containing the authorization code
   * @returns {Object} The decrypted user data payload
   *
   */
  const exchangeCode = (jwtToken) => {
    // tell SIP that the client supports S3 payload processing
    const body = { authToken: jwtToken, allowS3UploadedPayload: true };

    const authHeader = makeAuthorizationHeader(config, 'scopeRequest/authCode', 'POST', body);
    const contentLength = Buffer.byteLength(JSON.stringify(body));
    const headers = {
      'Content-Length': contentLength,
      Accept: '*/*',
      Authorization: authHeader,
      'Content-Type': 'application/json',
    };
    const requestOptions = {
      headers,
      body: JSON.stringify(body),
      url: `${invokeUrl}/scopeRequest/authCode`,
      method: 'POST',
      resolveWithFullResponse: true,
    };

    if (config.proxy) {
      requestOptions.proxy = config.proxy.url;
      requestOptions.rejectUnauthorized = 'rejectUnauthorized' in config.proxy ? config.proxy.rejectUnauthorized : true;
    }

    return request(requestOptions)
      .then(processPayload)
      .catch(processPayloadErrorResponse);
  };

  return {
    exchangeCode,
    processPayload,
  };
};

module.exports = sipClientFactory;
