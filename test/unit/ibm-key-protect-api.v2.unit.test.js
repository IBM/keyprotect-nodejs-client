/**
 * (C) Copyright IBM Corp. 2023.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* eslint-disable no-await-in-loop */

const nock = require('nock');

// need to import the whole package to mock getAuthenticatorFromEnvironment
const sdkCorePackage = require('ibm-cloud-sdk-core');

const { NoAuthAuthenticator, unitTestUtils } = sdkCorePackage;
const IbmKeyProtectApiV2 = require('../../dist/ibm-key-protect-api/v2');

const {
  getOptions,
  checkUrlAndMethod,
  checkMediaHeaders,
  expectToBePromise,
  checkUserHeader,
} = unitTestUtils;

const ibmKeyProtectApiServiceOptions = {
  authenticator: new NoAuthAuthenticator(),
  url: 'https://us-south.kms.cloud.ibm.com',
};

const ibmKeyProtectApiService = new IbmKeyProtectApiV2(ibmKeyProtectApiServiceOptions);

let createRequestMock = null;
function mock_createRequest() {
  if (!createRequestMock) {
    createRequestMock = jest.spyOn(ibmKeyProtectApiService, 'createRequest');
    createRequestMock.mockImplementation(() => Promise.resolve());
  }
}
function unmock_createRequest() {
  if (createRequestMock) {
    createRequestMock.mockRestore();
    createRequestMock = null;
  }
}

// dont actually construct an authenticator
const getAuthenticatorMock = jest.spyOn(sdkCorePackage, 'getAuthenticatorFromEnvironment');
getAuthenticatorMock.mockImplementation(() => new NoAuthAuthenticator());

describe('IbmKeyProtectApiV2', () => {
  beforeEach(() => {
    mock_createRequest();
  });

  afterEach(() => {
    if (createRequestMock) {
      createRequestMock.mockClear();
    }
    getAuthenticatorMock.mockClear();
  });

  describe('the newInstance method', () => {
    test('should use defaults when options not provided', () => {
      const testInstance = IbmKeyProtectApiV2.newInstance();

      expect(getAuthenticatorMock).toHaveBeenCalled();
      expect(testInstance.baseOptions.authenticator).toBeInstanceOf(NoAuthAuthenticator);
      expect(testInstance.baseOptions.serviceName).toBe(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME);
      expect(testInstance.baseOptions.serviceUrl).toBe(IbmKeyProtectApiV2.DEFAULT_SERVICE_URL);
      expect(testInstance).toBeInstanceOf(IbmKeyProtectApiV2);
    });

    test('should set serviceName, serviceUrl, and authenticator when provided', () => {
      const options = {
        authenticator: new NoAuthAuthenticator(),
        serviceUrl: 'custom.com',
        serviceName: 'my-service',
      };

      const testInstance = IbmKeyProtectApiV2.newInstance(options);

      expect(getAuthenticatorMock).not.toHaveBeenCalled();
      expect(testInstance.baseOptions.authenticator).toBeInstanceOf(NoAuthAuthenticator);
      expect(testInstance.baseOptions.serviceUrl).toBe('custom.com');
      expect(testInstance.baseOptions.serviceName).toBe('my-service');
      expect(testInstance).toBeInstanceOf(IbmKeyProtectApiV2);
    });
  });

  describe('the constructor', () => {
    test('use user-given service url', () => {
      const options = {
        authenticator: new NoAuthAuthenticator(),
        serviceUrl: 'custom.com',
      };

      const testInstance = new IbmKeyProtectApiV2(options);

      expect(testInstance.baseOptions.serviceUrl).toBe('custom.com');
    });

    test('use default service url', () => {
      const options = {
        authenticator: new NoAuthAuthenticator(),
      };

      const testInstance = new IbmKeyProtectApiV2(options);

      expect(testInstance.baseOptions.serviceUrl).toBe(IbmKeyProtectApiV2.DEFAULT_SERVICE_URL);
    });
  });

  describe('constructServiceUrl', () => {
    describe('positive tests', () => {
      test('should use all default variable values if null is passed', () => {
        const defaultFormattedUrl = 'https://us-south.kms.cloud.ibm.com';
        const formattedUrl = IbmKeyProtectApiV2.constructServiceUrl(null);

        expect(formattedUrl).toStrictEqual(defaultFormattedUrl);
      });
    });

    describe('negative tests', () => {
      test('should fail if an invalid variable name is provided', () => {
        expect(() => {
          const providedUrlVariables = new Map([['invalid_variable_name', 'value']]);
          IbmKeyProtectApiV2.constructServiceUrl(providedUrlVariables);
        }).toThrow();
      });
    });
  });

  describe('createKeyAlias', () => {
    describe('positive tests', () => {
      function __createKeyAliasTest() {
        // Construct the params object for operation createKeyAlias
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const createKeyAliasParams = {
          id,
          alias,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const createKeyAliasResult = ibmKeyProtectApiService.createKeyAlias(createKeyAliasParams);

        // all methods should return a Promise
        expectToBePromise(createKeyAliasResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/aliases/{alias}', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.alias).toEqual(alias);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createKeyAliasTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createKeyAliasTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createKeyAliasTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createKeyAliasParams = {
          id,
          alias,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKeyAlias(createKeyAliasParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyAlias({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyAlias();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('deleteKeyAlias', () => {
    describe('positive tests', () => {
      function __deleteKeyAliasTest() {
        // Construct the params object for operation deleteKeyAlias
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const deleteKeyAliasParams = {
          id,
          alias,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const deleteKeyAliasResult = ibmKeyProtectApiService.deleteKeyAlias(deleteKeyAliasParams);

        // all methods should return a Promise
        expectToBePromise(deleteKeyAliasResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/aliases/{alias}', 'DELETE');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.alias).toEqual(alias);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __deleteKeyAliasTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __deleteKeyAliasTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __deleteKeyAliasTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const deleteKeyAliasParams = {
          id,
          alias,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKeyAlias(deleteKeyAliasParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyAlias({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyAlias();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('cryptoV2GetInstanceEndpoints', () => {
    describe('positive tests', () => {
      function __cryptoV2GetInstanceEndpointsTest() {
        // Construct the params object for operation cryptoV2GetInstanceEndpoints
        const instanceId = 'testString';
        const cryptoV2GetInstanceEndpointsParams = {
          instanceId,
        };

        const cryptoV2GetInstanceEndpointsResult = ibmKeyProtectApiService.cryptoV2GetInstanceEndpoints(cryptoV2GetInstanceEndpointsParams);

        // all methods should return a Promise
        expectToBePromise(cryptoV2GetInstanceEndpointsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/crypto_v2/instances/{instanceId}', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        expect(mockRequestOptions.path.instanceId).toEqual(instanceId);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __cryptoV2GetInstanceEndpointsTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __cryptoV2GetInstanceEndpointsTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __cryptoV2GetInstanceEndpointsTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const instanceId = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const cryptoV2GetInstanceEndpointsParams = {
          instanceId,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.cryptoV2GetInstanceEndpoints(cryptoV2GetInstanceEndpointsParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.cryptoV2GetInstanceEndpoints({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.cryptoV2GetInstanceEndpoints();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getGovernanceConfig', () => {
    describe('positive tests', () => {
      function __getGovernanceConfigTest() {
        // Construct the params object for operation getGovernanceConfig
        const configRequestId = 'testString';
        const accountId = 'testString';
        const resourceKind = 'instance';
        const serviceInstanceCrn = 'testString';
        const resourceGroupId = 'testString';
        const transactionId = 'testString';
        const limit = 200;
        const offset = 0;
        const getGovernanceConfigParams = {
          configRequestId,
          accountId,
          resourceKind,
          serviceInstanceCrn,
          resourceGroupId,
          transactionId,
          limit,
          offset,
        };

        const getGovernanceConfigResult = ibmKeyProtectApiService.getGovernanceConfig(getGovernanceConfigParams);

        // all methods should return a Promise
        expectToBePromise(getGovernanceConfigResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/governance/v1/configs', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        expect(mockRequestOptions.qs.config_request_id).toEqual(configRequestId);
        expect(mockRequestOptions.qs.account_id).toEqual(accountId);
        expect(mockRequestOptions.qs.resource_kind).toEqual(resourceKind);
        expect(mockRequestOptions.qs.service_instance_crn).toEqual(serviceInstanceCrn);
        expect(mockRequestOptions.qs.resource_group_id).toEqual(resourceGroupId);
        expect(mockRequestOptions.qs['Transaction-Id']).toEqual(transactionId);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getGovernanceConfigTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getGovernanceConfigTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getGovernanceConfigTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const configRequestId = 'testString';
        const accountId = 'testString';
        const resourceKind = 'instance';
        const serviceInstanceCrn = 'testString';
        const resourceGroupId = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getGovernanceConfigParams = {
          configRequestId,
          accountId,
          resourceKind,
          serviceInstanceCrn,
          resourceGroupId,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getGovernanceConfig(getGovernanceConfigParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getGovernanceConfig({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getGovernanceConfig();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });

    describe('GetGovernanceConfigPager tests', () => {
      const serviceUrl = ibmKeyProtectApiServiceOptions.url;
      const path = '/governance/v1/configs';
      const mockPagerResponse1 =
        '{"next":{"href":"https://myhost.com/somePath?offset=1"},"total_count":2,"config_state":[{"resource_crn":"resource_crn","resource_group_id":"resource_group_id","additional_target_attributes":{"resource_id":"resource_id","location":"location","instance_id":"instance_id"},"current_config":[{"property":"property","value":"value"}]}],"limit":1}';
      const mockPagerResponse2 =
        '{"total_count":2,"config_state":[{"resource_crn":"resource_crn","resource_group_id":"resource_group_id","additional_target_attributes":{"resource_id":"resource_id","location":"location","instance_id":"instance_id"},"current_config":[{"property":"property","value":"value"}]}],"limit":1}';

      beforeEach(() => {
        unmock_createRequest();
        const scope = nock(serviceUrl)
          .get((uri) => uri.includes(path))
          .reply(200, mockPagerResponse1)
          .get((uri) => uri.includes(path))
          .reply(200, mockPagerResponse2);
      });

      afterEach(() => {
        nock.cleanAll();
        mock_createRequest();
      });

      test('getNext()', async () => {
        const params = {
          configRequestId: 'testString',
          accountId: 'testString',
          resourceKind: 'instance',
          serviceInstanceCrn: 'testString',
          resourceGroupId: 'testString',
          transactionId: 'testString',
          limit: 10,
        };
        const allResults = [];
        const pager = new IbmKeyProtectApiV2.GetGovernanceConfigPager(ibmKeyProtectApiService, params);
        while (pager.hasNext()) {
          const nextPage = await pager.getNext();
          expect(nextPage).not.toBeNull();
          allResults.push(...nextPage);
        }
        expect(allResults).not.toBeNull();
        expect(allResults).toHaveLength(2);
      });

      test('getAll()', async () => {
        const params = {
          configRequestId: 'testString',
          accountId: 'testString',
          resourceKind: 'instance',
          serviceInstanceCrn: 'testString',
          resourceGroupId: 'testString',
          transactionId: 'testString',
          limit: 10,
        };
        const pager = new IbmKeyProtectApiV2.GetGovernanceConfigPager(ibmKeyProtectApiService, params);
        const allResults = await pager.getAll();
        expect(allResults).not.toBeNull();
        expect(allResults).toHaveLength(2);
      });
    });
  });

  describe('postImportToken', () => {
    describe('positive tests', () => {
      function __postImportTokenTest() {
        // Construct the params object for operation postImportToken
        const bluemixInstance = 'testString';
        const expiration = 600;
        const maxAllowedRetrievals = 1;
        const correlationId = 'testString';
        const xKmsKeyRing = 'default';
        const postImportTokenParams = {
          bluemixInstance,
          expiration,
          maxAllowedRetrievals,
          correlationId,
          xKmsKeyRing,
        };

        const postImportTokenResult = ibmKeyProtectApiService.postImportToken(postImportTokenParams);

        // all methods should return a Promise
        expectToBePromise(postImportTokenResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/import_token', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body.expiration).toEqual(expiration);
        expect(mockRequestOptions.body.maxAllowedRetrievals).toEqual(maxAllowedRetrievals);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __postImportTokenTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __postImportTokenTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __postImportTokenTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const postImportTokenParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.postImportToken(postImportTokenParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.postImportToken({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.postImportToken();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getImportToken', () => {
    describe('positive tests', () => {
      function __getImportTokenTest() {
        // Construct the params object for operation getImportToken
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'default';
        const getImportTokenParams = {
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const getImportTokenResult = ibmKeyProtectApiService.getImportToken(getImportTokenParams);

        // all methods should return a Promise
        expectToBePromise(getImportTokenResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/import_token', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getImportTokenTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getImportTokenTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getImportTokenTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getImportTokenParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getImportToken(getImportTokenParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getImportToken({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getImportToken();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('wrapKey', () => {
    describe('positive tests', () => {
      function __wrapKeyTest() {
        // Construct the params object for operation wrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionWrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const wrapKeyParams = {
          id,
          bluemixInstance,
          keyActionWrapBody,
          correlationId,
          xKmsKeyRing,
        };

        const wrapKeyResult = ibmKeyProtectApiService.wrapKey(wrapKeyParams);

        // all methods should return a Promise
        expectToBePromise(wrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/wrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_wrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(keyActionWrapBody);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __wrapKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __wrapKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __wrapKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const wrapKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.wrapKey(wrapKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.wrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.wrapKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('unwrapKey', () => {
    describe('positive tests', () => {
      function __unwrapKeyTest() {
        // Construct the params object for operation unwrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionUnwrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const unwrapKeyParams = {
          id,
          bluemixInstance,
          keyActionUnwrapBody,
          correlationId,
          xKmsKeyRing,
        };

        const unwrapKeyResult = ibmKeyProtectApiService.unwrapKey(unwrapKeyParams);

        // all methods should return a Promise
        expectToBePromise(unwrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/unwrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_unwrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(keyActionUnwrapBody);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __unwrapKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __unwrapKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __unwrapKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionUnwrapBody = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const unwrapKeyParams = {
          id,
          bluemixInstance,
          keyActionUnwrapBody,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.unwrapKey(unwrapKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.unwrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.unwrapKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('rewrapKey', () => {
    describe('positive tests', () => {
      function __rewrapKeyTest() {
        // Construct the params object for operation rewrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRewrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const rewrapKeyParams = {
          id,
          bluemixInstance,
          keyActionRewrapBody,
          correlationId,
          xKmsKeyRing,
        };

        const rewrapKeyResult = ibmKeyProtectApiService.rewrapKey(rewrapKeyParams);

        // all methods should return a Promise
        expectToBePromise(rewrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/rewrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_rewrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(keyActionRewrapBody);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __rewrapKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __rewrapKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __rewrapKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRewrapBody = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const rewrapKeyParams = {
          id,
          bluemixInstance,
          keyActionRewrapBody,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.rewrapKey(rewrapKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.rewrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.rewrapKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('rotateKey', () => {
    describe('positive tests', () => {
      function __rotateKeyTest() {
        // Construct the params object for operation rotateKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRotateBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const rotateKeyParams = {
          id,
          bluemixInstance,
          keyActionRotateBody,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const rotateKeyResult = ibmKeyProtectApiService.rotateKey(rotateKeyParams);

        // all methods should return a Promise
        expectToBePromise(rotateKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/rotate', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = 'application/vnd.ibm.kms.key_action_rotate+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.body).toEqual(keyActionRotateBody);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __rotateKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __rotateKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __rotateKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const rotateKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.rotateKey(rotateKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.rotateKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.rotateKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('setKeyForDeletion', () => {
    describe('positive tests', () => {
      function __setKeyForDeletionTest() {
        // Construct the params object for operation setKeyForDeletion
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const setKeyForDeletionParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const setKeyForDeletionResult = ibmKeyProtectApiService.setKeyForDeletion(setKeyForDeletionParams);

        // all methods should return a Promise
        expectToBePromise(setKeyForDeletionResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/setKeyForDeletion', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __setKeyForDeletionTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __setKeyForDeletionTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __setKeyForDeletionTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const setKeyForDeletionParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.setKeyForDeletion(setKeyForDeletionParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.setKeyForDeletion({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.setKeyForDeletion();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('unsetKeyForDeletion', () => {
    describe('positive tests', () => {
      function __unsetKeyForDeletionTest() {
        // Construct the params object for operation unsetKeyForDeletion
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const unsetKeyForDeletionParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const unsetKeyForDeletionResult = ibmKeyProtectApiService.unsetKeyForDeletion(unsetKeyForDeletionParams);

        // all methods should return a Promise
        expectToBePromise(unsetKeyForDeletionResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/unsetKeyForDeletion', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __unsetKeyForDeletionTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __unsetKeyForDeletionTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __unsetKeyForDeletionTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const unsetKeyForDeletionParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.unsetKeyForDeletion(unsetKeyForDeletionParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.unsetKeyForDeletion({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.unsetKeyForDeletion();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('enableKey', () => {
    describe('positive tests', () => {
      function __enableKeyTest() {
        // Construct the params object for operation enableKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const enableKeyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const enableKeyResult = ibmKeyProtectApiService.enableKey(enableKeyParams);

        // all methods should return a Promise
        expectToBePromise(enableKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/enable', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __enableKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __enableKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __enableKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const enableKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.enableKey(enableKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.enableKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.enableKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('disableKey', () => {
    describe('positive tests', () => {
      function __disableKeyTest() {
        // Construct the params object for operation disableKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const disableKeyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const disableKeyResult = ibmKeyProtectApiService.disableKey(disableKeyParams);

        // all methods should return a Promise
        expectToBePromise(disableKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/disable', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __disableKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __disableKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __disableKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const disableKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.disableKey(disableKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.disableKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.disableKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('syncAssociatedResources', () => {
    describe('positive tests', () => {
      function __syncAssociatedResourcesTest() {
        // Construct the params object for operation syncAssociatedResources
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const syncAssociatedResourcesParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const syncAssociatedResourcesResult = ibmKeyProtectApiService.syncAssociatedResources(syncAssociatedResourcesParams);

        // all methods should return a Promise
        expectToBePromise(syncAssociatedResourcesResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/actions/sync', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __syncAssociatedResourcesTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __syncAssociatedResourcesTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __syncAssociatedResourcesTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const syncAssociatedResourcesParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.syncAssociatedResources(syncAssociatedResourcesParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.syncAssociatedResources({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.syncAssociatedResources();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('eventAcknowledge', () => {
    describe('positive tests', () => {
      function __eventAcknowledgeTest() {
        // Construct the params object for operation eventAcknowledge
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'default';
        const eventAcknowledgeParams = {
          bluemixInstance,
          body,
          correlationId,
          xKmsKeyRing,
        };

        const eventAcknowledgeResult = ibmKeyProtectApiService.eventAcknowledge(eventAcknowledgeParams);

        // all methods should return a Promise
        expectToBePromise(eventAcknowledgeResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/event_ack', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = 'application/vnd.ibm.kms.event_acknowledge+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(body);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __eventAcknowledgeTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __eventAcknowledgeTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __eventAcknowledgeTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const eventAcknowledgeParams = {
          bluemixInstance,
          body,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.eventAcknowledge(eventAcknowledgeParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.eventAcknowledge({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.eventAcknowledge();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('listKeyRings', () => {
    describe('positive tests', () => {
      function __listKeyRingsTest() {
        // Construct the params object for operation listKeyRings
        const bluemixInstance = 'testString';
        const limit = 100;
        const offset = 0;
        const totalCount = true;
        const correlationId = 'testString';
        const listKeyRingsParams = {
          bluemixInstance,
          limit,
          offset,
          totalCount,
          correlationId,
        };

        const listKeyRingsResult = ibmKeyProtectApiService.listKeyRings(listKeyRingsParams);

        // all methods should return a Promise
        expectToBePromise(listKeyRingsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/key_rings', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
        expect(mockRequestOptions.qs.totalCount).toEqual(totalCount);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __listKeyRingsTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __listKeyRingsTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __listKeyRingsTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const listKeyRingsParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.listKeyRings(listKeyRingsParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.listKeyRings({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.listKeyRings();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('createKeyRing', () => {
    describe('positive tests', () => {
      function __createKeyRingTest() {
        // Construct the params object for operation createKeyRing
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const createKeyRingParams = {
          keyRingId,
          bluemixInstance,
          correlationId,
        };

        const createKeyRingResult = ibmKeyProtectApiService.createKeyRing(createKeyRingParams);

        // all methods should return a Promise
        expectToBePromise(createKeyRingResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/key_rings/{key-ring-id}', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(mockRequestOptions.path['key-ring-id']).toEqual(keyRingId);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createKeyRingTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createKeyRingTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createKeyRingTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createKeyRingParams = {
          keyRingId,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKeyRing(createKeyRingParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyRing({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyRing();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('deleteKeyRing', () => {
    describe('positive tests', () => {
      function __deleteKeyRingTest() {
        // Construct the params object for operation deleteKeyRing
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const force = false;
        const deleteKeyRingParams = {
          keyRingId,
          bluemixInstance,
          correlationId,
          force,
        };

        const deleteKeyRingResult = ibmKeyProtectApiService.deleteKeyRing(deleteKeyRingParams);

        // all methods should return a Promise
        expectToBePromise(deleteKeyRingResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/key_rings/{key-ring-id}', 'DELETE');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(mockRequestOptions.qs.force).toEqual(force);
        expect(mockRequestOptions.path['key-ring-id']).toEqual(keyRingId);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __deleteKeyRingTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __deleteKeyRingTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __deleteKeyRingTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const deleteKeyRingParams = {
          keyRingId,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKeyRing(deleteKeyRingParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyRing({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyRing();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getKeyCollectionMetadata', () => {
    describe('positive tests', () => {
      function __getKeyCollectionMetadataTest() {
        // Construct the params object for operation getKeyCollectionMetadata
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const state = [0, 1, 2, 3];
        const extractable = true;
        const filter = 'testString';
        const xKmsKeyRing = 'testString';
        const getKeyCollectionMetadataParams = {
          bluemixInstance,
          correlationId,
          state,
          extractable,
          filter,
          xKmsKeyRing,
        };

        const getKeyCollectionMetadataResult = ibmKeyProtectApiService.getKeyCollectionMetadata(getKeyCollectionMetadataParams);

        // all methods should return a Promise
        expectToBePromise(getKeyCollectionMetadataResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys', 'HEAD');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.state).toEqual(state);
        expect(mockRequestOptions.qs.extractable).toEqual(extractable);
        expect(mockRequestOptions.qs.filter).toEqual(filter);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getKeyCollectionMetadataTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getKeyCollectionMetadataTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getKeyCollectionMetadataTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getKeyCollectionMetadataParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyCollectionMetadata(getKeyCollectionMetadataParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyCollectionMetadata({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyCollectionMetadata();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('createKey', () => {
    describe('positive tests', () => {
      function __createKeyTest() {
        // Construct the params object for operation createKey
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const prefer = 'return=representation';
        const xKmsKeyRing = 'default';
        const createKeyParams = {
          bluemixInstance,
          body,
          correlationId,
          prefer,
          xKmsKeyRing,
        };

        const createKeyResult = ibmKeyProtectApiService.createKey(createKeyParams);

        // all methods should return a Promise
        expectToBePromise(createKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(body);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createKeyParams = {
          bluemixInstance,
          body,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKey(createKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getKeys', () => {
    describe('positive tests', () => {
      function __getKeysTest() {
        // Construct the params object for operation getKeys
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const limit = 200;
        const offset = 0;
        const state = [0, 1, 2, 3];
        const extractable = true;
        const search = 'testString';
        const sort = 'id';
        const filter = 'testString';
        const xKmsKeyRing = 'testString';
        const getKeysParams = {
          bluemixInstance,
          correlationId,
          limit,
          offset,
          state,
          extractable,
          search,
          sort,
          filter,
          xKmsKeyRing,
        };

        const getKeysResult = ibmKeyProtectApiService.getKeys(getKeysParams);

        // all methods should return a Promise
        expectToBePromise(getKeysResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
        expect(mockRequestOptions.qs.state).toEqual(state);
        expect(mockRequestOptions.qs.extractable).toEqual(extractable);
        expect(mockRequestOptions.qs.search).toEqual(search);
        expect(mockRequestOptions.qs.sort).toEqual(sort);
        expect(mockRequestOptions.qs.filter).toEqual(filter);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getKeysTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getKeysTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getKeysTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getKeysParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeys(getKeysParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeys({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeys();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('createKeyWithPoliciesOverrides', () => {
    describe('positive tests', () => {
      function __createKeyWithPoliciesOverridesTest() {
        // Construct the params object for operation createKeyWithPoliciesOverrides
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const prefer = 'return=representation';
        const xKmsKeyRing = 'default';
        const createKeyWithPoliciesOverridesParams = {
          bluemixInstance,
          body,
          correlationId,
          prefer,
          xKmsKeyRing,
        };

        const createKeyWithPoliciesOverridesResult = ibmKeyProtectApiService.createKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesParams);

        // all methods should return a Promise
        expectToBePromise(createKeyWithPoliciesOverridesResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys_with_policy_overrides', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(body);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createKeyWithPoliciesOverridesTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createKeyWithPoliciesOverridesTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createKeyWithPoliciesOverridesTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createKeyWithPoliciesOverridesParams = {
          bluemixInstance,
          body,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKeyWithPoliciesOverrides(createKeyWithPoliciesOverridesParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyWithPoliciesOverrides({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyWithPoliciesOverrides();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getKey', () => {
    describe('positive tests', () => {
      function __getKeyTest() {
        // Construct the params object for operation getKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const getKeyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const getKeyResult = ibmKeyProtectApiService.getKey(getKeyParams);

        // all methods should return a Promise
        expectToBePromise(getKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKey(getKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('actionOnKey', () => {
    describe('positive tests', () => {
      function __actionOnKeyTest() {
        // Construct the params object for operation actionOnKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const action = 'disable';
        const body = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const actionOnKeyParams = {
          id,
          bluemixInstance,
          action,
          body,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const actionOnKeyResult = ibmKeyProtectApiService.actionOnKey(actionOnKeyParams);

        // all methods should return a Promise
        expectToBePromise(actionOnKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.body).toEqual(body);
        expect(mockRequestOptions.qs.action).toEqual(action);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __actionOnKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __actionOnKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __actionOnKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const action = 'disable';
        const body = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const actionOnKeyParams = {
          id,
          bluemixInstance,
          action,
          body,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.actionOnKey(actionOnKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.actionOnKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.actionOnKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('patchKey', () => {
    describe('positive tests', () => {
      function __patchKeyTest() {
        // Construct the params object for operation patchKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyPatchBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const patchKeyParams = {
          id,
          bluemixInstance,
          keyPatchBody,
          correlationId,
          xKmsKeyRing,
        };

        const patchKeyResult = ibmKeyProtectApiService.patchKey(patchKeyParams);

        // all methods should return a Promise
        expectToBePromise(patchKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}', 'PATCH');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(keyPatchBody);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __patchKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __patchKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __patchKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const patchKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.patchKey(patchKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.patchKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.patchKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('deleteKey', () => {
    describe('positive tests', () => {
      function __deleteKeyTest() {
        // Construct the params object for operation deleteKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const force = false;
        const deleteKeyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          prefer,
          force,
        };

        const deleteKeyResult = ibmKeyProtectApiService.deleteKey(deleteKeyParams);

        // all methods should return a Promise
        expectToBePromise(deleteKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}', 'DELETE');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.qs.force).toEqual(force);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __deleteKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __deleteKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __deleteKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const deleteKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKey(deleteKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getKeyMetadata', () => {
    describe('positive tests', () => {
      function __getKeyMetadataTest() {
        // Construct the params object for operation getKeyMetadata
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const getKeyMetadataParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const getKeyMetadataResult = ibmKeyProtectApiService.getKeyMetadata(getKeyMetadataParams);

        // all methods should return a Promise
        expectToBePromise(getKeyMetadataResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/metadata', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getKeyMetadataTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getKeyMetadataTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getKeyMetadataTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getKeyMetadataParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyMetadata(getKeyMetadataParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyMetadata({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyMetadata();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('purgeKey', () => {
    describe('positive tests', () => {
      function __purgeKeyTest() {
        // Construct the params object for operation purgeKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const purgeKeyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const purgeKeyResult = ibmKeyProtectApiService.purgeKey(purgeKeyParams);

        // all methods should return a Promise
        expectToBePromise(purgeKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/purge', 'DELETE');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __purgeKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __purgeKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __purgeKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const purgeKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.purgeKey(purgeKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.purgeKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.purgeKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('restoreKey', () => {
    describe('positive tests', () => {
      function __restoreKeyTest() {
        // Construct the params object for operation restoreKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyRestoreBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const restoreKeyParams = {
          id,
          bluemixInstance,
          keyRestoreBody,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const restoreKeyResult = ibmKeyProtectApiService.restoreKey(restoreKeyParams);

        // all methods should return a Promise
        expectToBePromise(restoreKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/restore', 'POST');
        const expectedAccept = 'application/vnd.ibm.kms.key+json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_restore+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.body).toEqual(keyRestoreBody);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.responseType).toBe('stream');
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __restoreKeyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __restoreKeyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __restoreKeyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const restoreKeyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.restoreKey(restoreKeyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.restoreKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.restoreKey();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getKeyVersions', () => {
    describe('positive tests', () => {
      function __getKeyVersionsTest() {
        // Construct the params object for operation getKeyVersions
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const limit = 200;
        const offset = 0;
        const totalCount = true;
        const allKeyStates = false;
        const getKeyVersionsParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          limit,
          offset,
          totalCount,
          allKeyStates,
        };

        const getKeyVersionsResult = ibmKeyProtectApiService.getKeyVersions(getKeyVersionsParams);

        // all methods should return a Promise
        expectToBePromise(getKeyVersionsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/versions', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
        expect(mockRequestOptions.qs.totalCount).toEqual(totalCount);
        expect(mockRequestOptions.qs.allKeyStates).toEqual(allKeyStates);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getKeyVersionsTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getKeyVersionsTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getKeyVersionsTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getKeyVersionsParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyVersions(getKeyVersionsParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyVersions({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyVersions();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('createMigrationIntent', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.migration_intent_input+json',
        collectionTotal: 1,
      };

      // CreateMigrationIntentObject
      const createMigrationIntentObjectModel = {
        targetCRK: 'crn:v1:bluemix:public:hs-crypto:<region>:<account-ID>:<instance-ID>:key:<key-ID>',
      };

      function __createMigrationIntentTest() {
        // Construct the params object for operation createMigrationIntent
        const id = 'testString';
        const bluemixInstance = 'testString';
        const metadata = collectionMetadataModel;
        const resources = [createMigrationIntentObjectModel];
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const createMigrationIntentParams = {
          id,
          bluemixInstance,
          metadata,
          resources,
          correlationId,
          xKmsKeyRing,
        };

        const createMigrationIntentResult = ibmKeyProtectApiService.createMigrationIntent(createMigrationIntentParams);

        // all methods should return a Promise
        expectToBePromise(createMigrationIntentResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/migrationIntent', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body.metadata).toEqual(metadata);
        expect(mockRequestOptions.body.resources).toEqual(resources);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createMigrationIntentTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createMigrationIntentTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createMigrationIntentTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createMigrationIntentParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createMigrationIntent(createMigrationIntentParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createMigrationIntent({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createMigrationIntent();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getMigrationIntent', () => {
    describe('positive tests', () => {
      function __getMigrationIntentTest() {
        // Construct the params object for operation getMigrationIntent
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const getMigrationIntentParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const getMigrationIntentResult = ibmKeyProtectApiService.getMigrationIntent(getMigrationIntentParams);

        // all methods should return a Promise
        expectToBePromise(getMigrationIntentResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/migrationIntent', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getMigrationIntentTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getMigrationIntentTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getMigrationIntentTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getMigrationIntentParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getMigrationIntent(getMigrationIntentParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getMigrationIntent({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getMigrationIntent();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('deleteMigrationIntent', () => {
    describe('positive tests', () => {
      function __deleteMigrationIntentTest() {
        // Construct the params object for operation deleteMigrationIntent
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const deleteMigrationIntentParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
        };

        const deleteMigrationIntentResult = ibmKeyProtectApiService.deleteMigrationIntent(deleteMigrationIntentParams);

        // all methods should return a Promise
        expectToBePromise(deleteMigrationIntentResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/migrationIntent', 'DELETE');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __deleteMigrationIntentTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __deleteMigrationIntentTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __deleteMigrationIntentTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const deleteMigrationIntentParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteMigrationIntent(deleteMigrationIntentParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteMigrationIntent({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteMigrationIntent();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('putPolicy', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.crn+json',
        collectionTotal: 1,
      };

      // KeyPolicyDualAuthDeleteDualAuthDelete
      const keyPolicyDualAuthDeleteDualAuthDeleteModel = {
        enabled: true,
      };

      // KeyPolicyDualAuthDelete
      const keyPolicyDualAuthDeleteModel = {
        type: 'application/vnd.ibm.kms.policy+json',
        dualAuthDelete: keyPolicyDualAuthDeleteDualAuthDeleteModel,
      };

      // SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete
      const setKeyPoliciesOneOfModel = {
        metadata: collectionMetadataModel,
        resources: [keyPolicyDualAuthDeleteModel],
      };

      function __putPolicyTest() {
        // Construct the params object for operation putPolicy
        const id = 'testString';
        const bluemixInstance = 'testString';
        const setKeyPoliciesOneOf = setKeyPoliciesOneOfModel;
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const policy = 'dualAuthDelete';
        const putPolicyParams = {
          id,
          bluemixInstance,
          setKeyPoliciesOneOf,
          correlationId,
          xKmsKeyRing,
          policy,
        };

        const putPolicyResult = ibmKeyProtectApiService.putPolicy(putPolicyParams);

        // all methods should return a Promise
        expectToBePromise(putPolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/policies', 'PUT');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body).toEqual(setKeyPoliciesOneOf);
        expect(mockRequestOptions.qs.policy).toEqual(policy);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __putPolicyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __putPolicyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __putPolicyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const setKeyPoliciesOneOf = setKeyPoliciesOneOfModel;
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const putPolicyParams = {
          id,
          bluemixInstance,
          setKeyPoliciesOneOf,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.putPolicy(putPolicyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.putPolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.putPolicy();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getPolicy', () => {
    describe('positive tests', () => {
      function __getPolicyTest() {
        // Construct the params object for operation getPolicy
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const policy = 'dualAuthDelete';
        const getPolicyParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          policy,
        };

        const getPolicyResult = ibmKeyProtectApiService.getPolicy(getPolicyParams);

        // all methods should return a Promise
        expectToBePromise(getPolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/policies', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.policy).toEqual(policy);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getPolicyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getPolicyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getPolicyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getPolicyParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getPolicy(getPolicyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getPolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getPolicy();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('putInstancePolicy', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.crn+json',
        collectionTotal: 1,
      };

      // InstancePolicyAllowedNetworkPolicyDataAttributes
      const instancePolicyAllowedNetworkPolicyDataAttributesModel = {
        allowed_network: 'public-and-private',
      };

      // InstancePolicyAllowedNetworkPolicyData
      const instancePolicyAllowedNetworkPolicyDataModel = {
        enabled: true,
        attributes: instancePolicyAllowedNetworkPolicyDataAttributesModel,
      };

      // SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem
      const setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel = {
        policy_type: 'allowedNetwork',
        policy_data: instancePolicyAllowedNetworkPolicyDataModel,
      };

      // SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork
      const setInstancePoliciesOneOfModel = {
        metadata: collectionMetadataModel,
        resources: [setInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItemModel],
      };

      function __putInstancePolicyTest() {
        // Construct the params object for operation putInstancePolicy
        const bluemixInstance = 'testString';
        const setInstancePoliciesOneOf = setInstancePoliciesOneOfModel;
        const correlationId = 'testString';
        const policy = 'allowedNetwork';
        const putInstancePolicyParams = {
          bluemixInstance,
          setInstancePoliciesOneOf,
          correlationId,
          policy,
        };

        const putInstancePolicyResult = ibmKeyProtectApiService.putInstancePolicy(putInstancePolicyParams);

        // all methods should return a Promise
        expectToBePromise(putInstancePolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/instance/policies', 'PUT');
        const expectedAccept = undefined;
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(mockRequestOptions.body).toEqual(setInstancePoliciesOneOf);
        expect(mockRequestOptions.qs.policy).toEqual(policy);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __putInstancePolicyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __putInstancePolicyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __putInstancePolicyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const setInstancePoliciesOneOf = setInstancePoliciesOneOfModel;
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const putInstancePolicyParams = {
          bluemixInstance,
          setInstancePoliciesOneOf,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.putInstancePolicy(putInstancePolicyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.putInstancePolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.putInstancePolicy();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getInstancePolicy', () => {
    describe('positive tests', () => {
      function __getInstancePolicyTest() {
        // Construct the params object for operation getInstancePolicy
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const policy = 'allowedNetwork';
        const getInstancePolicyParams = {
          bluemixInstance,
          correlationId,
          policy,
        };

        const getInstancePolicyResult = ibmKeyProtectApiService.getInstancePolicy(getInstancePolicyParams);

        // all methods should return a Promise
        expectToBePromise(getInstancePolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/instance/policies', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(mockRequestOptions.qs.policy).toEqual(policy);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getInstancePolicyTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getInstancePolicyTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getInstancePolicyTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getInstancePolicyParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getInstancePolicy(getInstancePolicyParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getInstancePolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getInstancePolicy();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getAllowedIpPort', () => {
    describe('positive tests', () => {
      function __getAllowedIpPortTest() {
        // Construct the params object for operation getAllowedIpPort
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const getAllowedIpPortParams = {
          bluemixInstance,
          correlationId,
        };

        const getAllowedIpPortResult = ibmKeyProtectApiService.getAllowedIpPort(getAllowedIpPortParams);

        // all methods should return a Promise
        expectToBePromise(getAllowedIpPortResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/instance/allowed_ip_port', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getAllowedIpPortTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getAllowedIpPortTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getAllowedIpPortTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getAllowedIpPortParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getAllowedIpPort(getAllowedIpPortParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getAllowedIpPort({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getAllowedIpPort();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('createRegistration', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.registration_input+json',
        collectionTotal: 1,
      };

      // CreateRegistrationResourceBody
      const createRegistrationResourceBodyModel = {
        preventKeyDeletion: false,
        description: 'A resource registration on a Key Protect key',
        registrationMetadata: 'testString',
      };

      function __createRegistrationTest() {
        // Construct the params object for operation createRegistration
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const metadata = collectionMetadataModel;
        const resources = [createRegistrationResourceBodyModel];
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const createRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          metadata,
          resources,
          correlationId,
          xKmsKeyRing,
        };

        const createRegistrationResult = ibmKeyProtectApiService.createRegistration(createRegistrationParams);

        // all methods should return a Promise
        expectToBePromise(createRegistrationResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations/{urlEncodedResourceCRN}', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.body.metadata).toEqual(metadata);
        expect(mockRequestOptions.body.resources).toEqual(resources);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.urlEncodedResourceCRN).toEqual(urlEncodedResourceCrn);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __createRegistrationTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __createRegistrationTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __createRegistrationTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const createRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createRegistration(createRegistrationParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createRegistration({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.createRegistration();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('updateRegistration', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.registration_input+json',
        collectionTotal: 1,
      };

      // ModifiableRegistrationResourceBody
      const modifiableRegistrationResourceBodyModel = {
        preventKeyDeletion: false,
        description: 'A resource registration on a Key Protect key',
        registrationMetadata: 'testString',
        keyVersionId: 'testString',
      };

      function __updateRegistrationTest() {
        // Construct the params object for operation updateRegistration
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const metadata = collectionMetadataModel;
        const resources = [modifiableRegistrationResourceBodyModel];
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const ifMatch = 'W/"c8f7e349e5a1f8d7255de81f2508e5914667fg5e4aeb88945002286f753064b7"';
        const updateRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          metadata,
          resources,
          correlationId,
          xKmsKeyRing,
          ifMatch,
        };

        const updateRegistrationResult = ibmKeyProtectApiService.updateRegistration(updateRegistrationParams);

        // all methods should return a Promise
        expectToBePromise(updateRegistrationResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations/{urlEncodedResourceCRN}', 'PATCH');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'If-Match', ifMatch);
        expect(mockRequestOptions.body.metadata).toEqual(metadata);
        expect(mockRequestOptions.body.resources).toEqual(resources);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.urlEncodedResourceCRN).toEqual(urlEncodedResourceCrn);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __updateRegistrationTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __updateRegistrationTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __updateRegistrationTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const updateRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.updateRegistration(updateRegistrationParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.updateRegistration({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.updateRegistration();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('replaceRegistration', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.registration_input+json',
        collectionTotal: 1,
      };

      // ReplaceRegistrationResourceBody
      const replaceRegistrationResourceBodyModel = {
        preventKeyDeletion: false,
        description: 'A resource registration on a Key Protect key',
        registrationMetadata: 'testString',
        keyVersionId: 'fadedbee-0000-0000-0000-1234567890ab',
      };

      function __replaceRegistrationTest() {
        // Construct the params object for operation replaceRegistration
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const metadata = collectionMetadataModel;
        const resources = [replaceRegistrationResourceBodyModel];
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const ifMatch = 'W/"c8f7e349e5a1f8d7255de81f2508e5914667fg5e4aeb88945002286f753064b7"';
        const replaceRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          metadata,
          resources,
          correlationId,
          xKmsKeyRing,
          ifMatch,
        };

        const replaceRegistrationResult = ibmKeyProtectApiService.replaceRegistration(replaceRegistrationParams);

        // all methods should return a Promise
        expectToBePromise(replaceRegistrationResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations/{urlEncodedResourceCRN}', 'PUT');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'If-Match', ifMatch);
        expect(mockRequestOptions.body.metadata).toEqual(metadata);
        expect(mockRequestOptions.body.resources).toEqual(resources);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.urlEncodedResourceCRN).toEqual(urlEncodedResourceCrn);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __replaceRegistrationTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __replaceRegistrationTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __replaceRegistrationTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const replaceRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.replaceRegistration(replaceRegistrationParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.replaceRegistration({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.replaceRegistration();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('deleteRegistration', () => {
    describe('positive tests', () => {
      function __deleteRegistrationTest() {
        // Construct the params object for operation deleteRegistration
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const deleteRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const deleteRegistrationResult = ibmKeyProtectApiService.deleteRegistration(deleteRegistrationParams);

        // all methods should return a Promise
        expectToBePromise(deleteRegistrationResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations/{urlEncodedResourceCRN}', 'DELETE');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.path.id).toEqual(id);
        expect(mockRequestOptions.path.urlEncodedResourceCRN).toEqual(urlEncodedResourceCrn);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __deleteRegistrationTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __deleteRegistrationTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __deleteRegistrationTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const urlEncodedResourceCrn = 'crn%3av1%3abluemix%3apublic%3acloud-object-storage%3aglobal%3aa%2f00000000000000000000000000000000%3afeddecaf-0000-0000-0000-1234567890ab%3a%3abucket';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const deleteRegistrationParams = {
          id,
          urlEncodedResourceCrn,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteRegistration(deleteRegistrationParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteRegistration({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteRegistration();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('actionOnRegistration', () => {
    describe('positive tests', () => {
      // Request models needed by this operation.

      // CollectionMetadata
      const collectionMetadataModel = {
        collectionType: 'application/vnd.ibm.kms.crn+json',
        collectionTotal: 1,
      };

      // CloudResourceName
      const cloudResourceNameModel = {
        resourceCrn: 'crn:v1:bluemix:public:<service-name>:<location>:a/<account-id>:<service-instance>:<resource-type>:<resource>',
      };

      // RegistrationActionOneOfDeactivateRegistration
      const registrationActionOneOfModel = {
        metadata: collectionMetadataModel,
        resources: [cloudResourceNameModel],
      };

      function __actionOnRegistrationTest() {
        // Construct the params object for operation actionOnRegistration
        const id = 'testString';
        const bluemixInstance = 'testString';
        const action = 'deactivate';
        const registrationActionOneOf = registrationActionOneOfModel;
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const actionOnRegistrationParams = {
          id,
          bluemixInstance,
          action,
          registrationActionOneOf,
          correlationId,
          xKmsKeyRing,
          prefer,
        };

        const actionOnRegistrationResult = ibmKeyProtectApiService.actionOnRegistration(actionOnRegistrationParams);

        // all methods should return a Promise
        expectToBePromise(actionOnRegistrationResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(mockRequestOptions.body).toEqual(registrationActionOneOf);
        expect(mockRequestOptions.qs.action).toEqual(action);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __actionOnRegistrationTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __actionOnRegistrationTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __actionOnRegistrationTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const action = 'deactivate';
        const registrationActionOneOf = registrationActionOneOfModel;
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const actionOnRegistrationParams = {
          id,
          bluemixInstance,
          action,
          registrationActionOneOf,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.actionOnRegistration(actionOnRegistrationParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.actionOnRegistration({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.actionOnRegistration();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getRegistrations', () => {
    describe('positive tests', () => {
      function __getRegistrationsTest() {
        // Construct the params object for operation getRegistrations
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const limit = 200;
        const offset = 0;
        const urlEncodedResourceCrnQuery = 'crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*';
        const preventKeyDeletion = true;
        const totalCount = true;
        const getRegistrationsParams = {
          id,
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          limit,
          offset,
          urlEncodedResourceCrnQuery,
          preventKeyDeletion,
          totalCount,
        };

        const getRegistrationsResult = ibmKeyProtectApiService.getRegistrations(getRegistrationsParams);

        // all methods should return a Promise
        expectToBePromise(getRegistrationsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/{id}/registrations', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
        expect(mockRequestOptions.qs.urlEncodedResourceCRNQuery).toEqual(urlEncodedResourceCrnQuery);
        expect(mockRequestOptions.qs.preventKeyDeletion).toEqual(preventKeyDeletion);
        expect(mockRequestOptions.qs.totalCount).toEqual(totalCount);
        expect(mockRequestOptions.path.id).toEqual(id);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getRegistrationsTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getRegistrationsTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getRegistrationsTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getRegistrationsParams = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getRegistrations(getRegistrationsParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrations({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrations();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });

  describe('getRegistrationsAllKeys', () => {
    describe('positive tests', () => {
      function __getRegistrationsAllKeysTest() {
        // Construct the params object for operation getRegistrationsAllKeys
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const urlEncodedResourceCrnQuery = 'crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F00000000000000000000000000000000%3Afeddecaf-0000-0000-0000-1234567890ab%3A*%3A*';
        const limit = 200;
        const offset = 0;
        const preventKeyDeletion = true;
        const totalCount = true;
        const getRegistrationsAllKeysParams = {
          bluemixInstance,
          correlationId,
          xKmsKeyRing,
          urlEncodedResourceCrnQuery,
          limit,
          offset,
          preventKeyDeletion,
          totalCount,
        };

        const getRegistrationsAllKeysResult = ibmKeyProtectApiService.getRegistrationsAllKeys(getRegistrationsAllKeysParams);

        // all methods should return a Promise
        expectToBePromise(getRegistrationsAllKeysResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const mockRequestOptions = getOptions(createRequestMock);

        checkUrlAndMethod(mockRequestOptions, '/api/v2/keys/registrations', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(mockRequestOptions.qs.urlEncodedResourceCRNQuery).toEqual(urlEncodedResourceCrnQuery);
        expect(mockRequestOptions.qs.limit).toEqual(limit);
        expect(mockRequestOptions.qs.offset).toEqual(offset);
        expect(mockRequestOptions.qs.preventKeyDeletion).toEqual(preventKeyDeletion);
        expect(mockRequestOptions.qs.totalCount).toEqual(totalCount);
      }

      test('should pass the right params to createRequest with enable and disable retries', () => {
        // baseline test
        __getRegistrationsAllKeysTest();

        // enable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.enableRetries();
        __getRegistrationsAllKeysTest();

        // disable retries and test again
        createRequestMock.mockClear();
        ibmKeyProtectApiService.disableRetries();
        __getRegistrationsAllKeysTest();
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const getRegistrationsAllKeysParams = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getRegistrationsAllKeys(getRegistrationsAllKeysParams);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrationsAllKeys({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });

      test('should reject promise when required params are not given', async () => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrationsAllKeys();
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
      });
    });
  });
});
