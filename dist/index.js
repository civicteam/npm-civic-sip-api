"use strict";

// require("babel-polyfill");

function _asyncToGenerator(fn) { return function () { var gen = fn.apply(this, arguments); return new Promise(function (resolve, reject) { function step(key, arg) { try { var info = gen[key](arg); var value = info.value; } catch (error) { reject(error); return; } if (info.done) { resolve(value); } else { return Promise.resolve(value).then(function (value) { step("next", value); }, function (err) { step("throw", err); }); } } return step("next"); }); }; }

var stringify = require('json-stringify');
var uritemplate = require('./lib/url-template/url-template');
var apiGateway = require('./lib/apiGatewayCore/apiGatewayClient');
var crypto = require('crypto');
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
      var body, authHeader, contentLength, additionalParams, params, scopeRequestAuthCodePostRequest, response;
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
              _context.prev = 6;
              _context.next = 9;
              return apiGatewayClient.makeRequest(scopeRequestAuthCodePostRequest, authType, additionalParams, config.apiKey);

            case 9:
              response = _context.sent;
              return _context.abrupt('return', response.data);

            case 13:
              _context.prev = 13;
              _context.t0 = _context['catch'](6);
              throw new Error('Error exchanging code for data: ' + _context.t0.message);

            case 16:
            case 'end':
              return _context.stop();
          }
        }
      }, _callee, this, [[6, 13]]);
    }));

    return function exchangeCode(_x) {
      return _ref.apply(this, arguments);
    };
  }();

  var hostedServices = {
    SIPHostedService: {
      base_url: 'https://api.civic.com/sip/',
      hexpub: '044798c7940a6119583da4606e40f68df3ff449b2d583f0148e9ce6e09349a25ab68494e2bd10b8d5887d4fed438e8b03ba46f2a4b02e3841e7cf1ef3a70aeebf7',
      tokenType: 'JWT'
    }
  };

  var apigClient = {};
  if (config === undefined) {
    config = {
      appId: '',
      appSecret: '', // in hex format
      env: '',
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

  // TODO: change default to prod once partner accounts and prod setup is in place.
  if (!config.env) {
    config.env = 'dev';
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
  var invokeUrl = 'https://api.civic.com/sip/' + config.env;
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
    }, config.appSecret);

    var extension = jwtjs.createCivicExt(requestBody, config.appSecret);
    return 'Civic' + ' ' + jwtToken + '.' + extension;
  };

  apigClient.exchangeCode = exchangeCode;

  return apigClient;
};

module.exports = sipClientFactory;
//# sourceMappingURL=index.js.map
