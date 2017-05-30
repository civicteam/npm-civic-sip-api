"use strict";

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

require("babel-polyfill");

var stringify = require('json-stringify');
var uritemplate = require('./lib/url-template/url-template');
var apiGateway = require('./lib/apiGatewayCore/apiGatewayClient');
var CryptoJS = require('crypto-js');
var jwtjs = require('./lib/jwt');

var sipClientFactory = {};

var JWT_EXPIRATION = '3m';

sipClientFactory.newClient = function (config) {
  /**
   * Exchange authorization code in the form of a JWT Token for the user data
   * requested in the scope request.
   *
   * @param jwtToken containing the authorization code
   *
   */

  var exchangeCode = function () {
    var _ref = _asyncToGenerator(regeneratorRuntime.mark(function _callee(jwtToken) {
      var body, authHeader, contentLength, additionalParams, params, scopeRequestAuthCodePostRequest, data, errorObj, response;
      return regeneratorRuntime.wrap(function _callee$(_context) {
        while (1) {
          switch (_context.prev = _context.next) {
            case 0:
              body = { authToken: jwtToken };
              authHeader = makeAuthorizationHeader('scopeRequest/authCode', 'POST', body);
              contentLength = Buffer.byteLength(JSON.stringify(body));
              additionalParams = {
                // If there are any unmodeled query parameters or headers that must be
                //   sent with the request, add them here.
                headers: {
                  'Content-Length': contentLength,
                  'Accept': '*/*',
                  'Authorization': authHeader
                },
                queryParams: {}
              };
              params = {};
              scopeRequestAuthCodePostRequest = {
                verb: 'post'.toUpperCase(),
                path: pathComponent + uritemplate('/scopeRequest/authCode').expand(apiGateway.core.utils.parseParametersToObject(params, [])),
                headers: apiGateway.core.utils.parseParametersToObject(params, []),
                queryParams: apiGateway.core.utils.parseParametersToObject(params, []),
                body: body
              };
              data = void 0, errorObj = void 0;
              _context.prev = 7;
              _context.next = 10;
              return apiGatewayClient.makeRequest(scopeRequestAuthCodePostRequest, authType, additionalParams, config.apiKey);

            case 10:
              response = _context.sent;

              console.log('Civic response: ', JSON.stringify(response, null, 2));

              if (!(response.status != 200)) {
                _context.next = 16;
                break;
              }

              errorObj = new Error('Error exchanging code for data: ', response.status);
              _context.next = 17;
              break;

            case 16:
              return _context.abrupt("return", verifyAndDecrypt(response.data));

            case 17:
              _context.next = 23;
              break;

            case 19:
              _context.prev = 19;
              _context.t0 = _context["catch"](7);

              console.log('Civic ERROR response: ', JSON.stringify(_context.t0, null, 2));
              throw new Error('Error exchanging code for data: ' + _context.t0.message);

            case 23:
              if (!errorObj) {
                _context.next = 25;
                break;
              }

              throw errorObj;

            case 25:
            case "end":
              return _context.stop();
          }
        }
      }, _callee, this, [[7, 19]]);
    }));

    return function exchangeCode(_x) {
      return _ref.apply(this, arguments);
    };
  }();

  var hostedServices = {
    SIPHostedService: {
      base_url: 'https://api.civic.com/sip/',
      hexpub: '049a45998638cfb3c4b211d72030d9ae8329a242db63bfb0076a54e7647370a8ac5708b57af6065805d5a6be72332620932dbb35e8d318fce18e7c980a0eb26aa1',
      tokenType: 'JWT'
    }
  };

  var apigClient = {};
  if (config === undefined) {
    config = {
      appId: '',
      appSecret: '', // hex format
      prvKey: '', // hex format
      env: 'prod',
      defaultContentType: 'application/json',
      defaultAcceptType: 'application/json'
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

  if (config.api) {
    hostedServices.SIPHostedService.base_url = config.api;

    if (!config.api.endsWith('/')) {
      hostedServices.SIPHostedService.base_url += '/';
    }
  }

  //If defaultContentType is not defined then default to application/json
  if (config.defaultContentType === undefined) {
    config.defaultContentType = 'application/json';
  }
  //If defaultAcceptType is not defined then default to application/json
  if (config.defaultAcceptType === undefined) {
    config.defaultAcceptType = 'application/json';
  }

  // extract endpoint and path from url
  var invokeUrl = hostedServices.SIPHostedService.base_url + config.env;
  var endpoint = /(^https?:\/\/[^\/]+)/g.exec(invokeUrl)[1];
  var pathComponent = invokeUrl.substring(endpoint.length);

  var sigV4ClientConfig = {
    accessKey: config.accessKey,
    secretKey: config.secretKey,
    sessionToken: config.sessionToken,
    serviceName: 'execute-api',
    region: config.region,
    endpoint: endpoint,
    defaultContentType: config.defaultContentType,
    defaultAcceptType: config.defaultAcceptType
  };

  var authType = 'NONE';
  if (sigV4ClientConfig.accessKey !== undefined && sigV4ClientConfig.accessKey !== '' && sigV4ClientConfig.secretKey !== undefined && sigV4ClientConfig.secretKey !== '') {
    authType = 'AWS_IAM';
  }

  var simpleHttpClientConfig = {
    endpoint: endpoint,
    defaultContentType: config.defaultContentType,
    defaultAcceptType: config.defaultAcceptType
  };

  var apiGatewayClient = apiGateway.core.apiGatewayClientFactory.newClient(simpleHttpClientConfig, sigV4ClientConfig);

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
  function makeAuthorizationHeader(targetPath, targetMethod, requestBody) {
    var jwtToken = jwtjs.createToken(config.appId, hostedServices['SIPHostedService'].base_url, config.appId, JWT_EXPIRATION, {
      method: targetMethod,
      path: targetPath
    }, config.prvKey);

    var extension = jwtjs.createCivicExt(requestBody, config.appSecret);
    return 'Civic' + ' ' + jwtToken + '.' + extension;
  }

  /**
   * The user data received from the civic sip server is wrapped in a
   * JWT token and encrypted using the partner secret with aes.
   *
   * @param payload contains data field with JWT token signed by sip-hosted-services
   */
  function verifyAndDecrypt(payload) {
    var token = payload.data;
    var isValid = jwtjs.verify(token, hostedServices.SIPHostedService.hexpub, { gracePeriod: 60 });

    if (!isValid) {
      console.log('Civic ERROR response: JWT Token containing encrypted data could not be verified');
      throw new Error('JWT Token containing encrypted data could not be verified');
    }

    // decrypt the data
    var decodedToken = jwtjs.decode(token);
    var userData = void 0,
        clearText = decodedToken.payloadObj.data;

    if (payload.encrypted) {
      var clearData = CryptoJS.AES.decrypt(decodedToken.payloadObj.data, config.appSecret);
      clearText = clearData.toString(CryptoJS.enc.Utf8);
    }

    try {
      userData = JSON.parse(clearText);
    } catch (e) {
      /* Ignore */
      console.log('Error parsing decrypted string to user data: ' + e.message);
    }

    return userData;
  };

  apigClient.exchangeCode = exchangeCode;

  return apigClient;
};

module.exports = sipClientFactory;
