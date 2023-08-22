/**
 * (C) Copyright IBM Corp. 2021.
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
'use strict';

// need to import the whole package to mock getAuthenticatorFromEnvironment
const core = require('ibm-cloud-sdk-core');
const { NoAuthAuthenticator, unitTestUtils } = core;

const IbmKeyProtectApiV2 = require('../../dist/ibm-key-protect-api/v2');

const { getOptions, checkUrlAndMethod, checkMediaHeaders, expectToBePromise, checkUserHeader } =
  unitTestUtils;

const service = {
  authenticator: new NoAuthAuthenticator(),
  url: 'ibm.com/123456',
};

const ibmKeyProtectApiService = new IbmKeyProtectApiV2(service);

// dont actually create a request
const createRequestMock = jest.spyOn(ibmKeyProtectApiService, 'createRequest');
createRequestMock.mockImplementation(() => Promise.resolve());

// dont actually construct an authenticator
const getAuthenticatorMock = jest.spyOn(core, 'getAuthenticatorFromEnvironment');
getAuthenticatorMock.mockImplementation(() => new NoAuthAuthenticator());

afterEach(() => {
  createRequestMock.mockClear();
  getAuthenticatorMock.mockClear();
});

describe('IbmKeyProtectApiV2', () => {
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
  describe('createKeyAlias', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation createKeyAlias
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          alias: alias,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const createKeyAliasResult = ibmKeyProtectApiService.createKeyAlias(params);

        // all methods should return a Promise
        expectToBePromise(createKeyAliasResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/aliases/{alias}', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
        expect(options.path['alias']).toEqual(alias);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          alias,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKeyAlias(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyAlias({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const createKeyAliasPromise = ibmKeyProtectApiService.createKeyAlias();
        expectToBePromise(createKeyAliasPromise);

        createKeyAliasPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('deleteKeyAlias', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation deleteKeyAlias
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          alias: alias,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const deleteKeyAliasResult = ibmKeyProtectApiService.deleteKeyAlias(params);

        // all methods should return a Promise
        expectToBePromise(deleteKeyAliasResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/aliases/{alias}', 'DELETE');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
        expect(options.path['alias']).toEqual(alias);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const alias = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          alias,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKeyAlias(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyAlias({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const deleteKeyAliasPromise = ibmKeyProtectApiService.deleteKeyAlias();
        expectToBePromise(deleteKeyAliasPromise);

        deleteKeyAliasPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('postImportToken', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation postImportToken
        const bluemixInstance = 'testString';
        const expiration = 300;
        const maxAllowedRetrievals = 1;
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          expiration: expiration,
          maxAllowedRetrievals: maxAllowedRetrievals,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const postImportTokenResult = ibmKeyProtectApiService.postImportToken(params);

        // all methods should return a Promise
        expectToBePromise(postImportTokenResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/import_token', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body['expiration']).toEqual(expiration);
        expect(options.body['maxAllowedRetrievals']).toEqual(maxAllowedRetrievals);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.postImportToken(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.postImportToken({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const postImportTokenPromise = ibmKeyProtectApiService.postImportToken();
        expectToBePromise(postImportTokenPromise);

        postImportTokenPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getImportToken', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getImportToken
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const getImportTokenResult = ibmKeyProtectApiService.getImportToken(params);

        // all methods should return a Promise
        expectToBePromise(getImportTokenResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/import_token', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getImportToken(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getImportToken({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getImportTokenPromise = ibmKeyProtectApiService.getImportToken();
        expectToBePromise(getImportTokenPromise);

        getImportTokenPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('wrapKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation wrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionWrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyActionWrapBody: keyActionWrapBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const wrapKeyResult = ibmKeyProtectApiService.wrapKey(params);

        // all methods should return a Promise
        expectToBePromise(wrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/wrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_wrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(keyActionWrapBody);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.wrapKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.wrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const wrapKeyPromise = ibmKeyProtectApiService.wrapKey();
        expectToBePromise(wrapKeyPromise);

        wrapKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('unwrapKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation unwrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionUnwrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyActionUnwrapBody: keyActionUnwrapBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const unwrapKeyResult = ibmKeyProtectApiService.unwrapKey(params);

        // all methods should return a Promise
        expectToBePromise(unwrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/unwrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_unwrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(keyActionUnwrapBody);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionUnwrapBody = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          keyActionUnwrapBody,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.unwrapKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.unwrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const unwrapKeyPromise = ibmKeyProtectApiService.unwrapKey();
        expectToBePromise(unwrapKeyPromise);

        unwrapKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('rewrapKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation rewrapKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRewrapBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyActionRewrapBody: keyActionRewrapBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const rewrapKeyResult = ibmKeyProtectApiService.rewrapKey(params);

        // all methods should return a Promise
        expectToBePromise(rewrapKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/rewrap', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_rewrap+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(keyActionRewrapBody);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRewrapBody = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          keyActionRewrapBody,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.rewrapKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.rewrapKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const rewrapKeyPromise = ibmKeyProtectApiService.rewrapKey();
        expectToBePromise(rewrapKeyPromise);

        rewrapKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('rotateKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation rotateKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyActionRotateBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyActionRotateBody: keyActionRotateBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          prefer: prefer,
        };

        const rotateKeyResult = ibmKeyProtectApiService.rotateKey(params);

        // all methods should return a Promise
        expectToBePromise(rotateKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/rotate', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = 'application/vnd.ibm.kms.key_action_rotate+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(options.body).toEqual(keyActionRotateBody);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.rotateKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.rotateKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const rotateKeyPromise = ibmKeyProtectApiService.rotateKey();
        expectToBePromise(rotateKeyPromise);

        rotateKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('setKeyForDeletion', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation setKeyForDeletion
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const setKeyForDeletionResult = ibmKeyProtectApiService.setKeyForDeletion(params);

        // all methods should return a Promise
        expectToBePromise(setKeyForDeletionResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/setKeyForDeletion', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.setKeyForDeletion(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.setKeyForDeletion({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const setKeyForDeletionPromise = ibmKeyProtectApiService.setKeyForDeletion();
        expectToBePromise(setKeyForDeletionPromise);

        setKeyForDeletionPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('unsetKeyForDeletion', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation unsetKeyForDeletion
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const unsetKeyForDeletionResult = ibmKeyProtectApiService.unsetKeyForDeletion(params);

        // all methods should return a Promise
        expectToBePromise(unsetKeyForDeletionResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/unsetKeyForDeletion', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.unsetKeyForDeletion(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.unsetKeyForDeletion({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const unsetKeyForDeletionPromise = ibmKeyProtectApiService.unsetKeyForDeletion();
        expectToBePromise(unsetKeyForDeletionPromise);

        unsetKeyForDeletionPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('enableKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation enableKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const enableKeyResult = ibmKeyProtectApiService.enableKey(params);

        // all methods should return a Promise
        expectToBePromise(enableKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/enable', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.enableKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.enableKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const enableKeyPromise = ibmKeyProtectApiService.enableKey();
        expectToBePromise(enableKeyPromise);

        enableKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('disableKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation disableKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const disableKeyResult = ibmKeyProtectApiService.disableKey(params);

        // all methods should return a Promise
        expectToBePromise(disableKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/disable', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.disableKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.disableKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const disableKeyPromise = ibmKeyProtectApiService.disableKey();
        expectToBePromise(disableKeyPromise);

        disableKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('syncAssociatedResources', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation syncAssociatedResources
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const syncAssociatedResourcesResult =
          ibmKeyProtectApiService.syncAssociatedResources(params);

        // all methods should return a Promise
        expectToBePromise(syncAssociatedResourcesResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/actions/sync', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.syncAssociatedResources(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.syncAssociatedResources({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const syncAssociatedResourcesPromise = ibmKeyProtectApiService.syncAssociatedResources();
        expectToBePromise(syncAssociatedResourcesPromise);

        syncAssociatedResourcesPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });

  describe('listKeyRings', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation listKeyRings
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
        };

        const listKeyRingsResult = ibmKeyProtectApiService.listKeyRings(params);

        // all methods should return a Promise
        expectToBePromise(listKeyRingsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/key_rings', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.listKeyRings(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.listKeyRings({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const listKeyRingsPromise = ibmKeyProtectApiService.listKeyRings();
        expectToBePromise(listKeyRingsPromise);

        listKeyRingsPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('createKeyRing', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation createKeyRing
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const params = {
          keyRingId: keyRingId,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
        };

        const createKeyRingResult = ibmKeyProtectApiService.createKeyRing(params);

        // all methods should return a Promise
        expectToBePromise(createKeyRingResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/key_rings/{key-ring-id}', 'POST');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(options.path['key-ring-id']).toEqual(keyRingId);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          keyRingId,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKeyRing(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.createKeyRing({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const createKeyRingPromise = ibmKeyProtectApiService.createKeyRing();
        expectToBePromise(createKeyRingPromise);

        createKeyRingPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('deleteKeyRing', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation deleteKeyRing
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const params = {
          keyRingId: keyRingId,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
        };

        const deleteKeyRingResult = ibmKeyProtectApiService.deleteKeyRing(params);

        // all methods should return a Promise
        expectToBePromise(deleteKeyRingResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/key_rings/{key-ring-id}', 'DELETE');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(options.path['key-ring-id']).toEqual(keyRingId);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const keyRingId = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          keyRingId,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKeyRing(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKeyRing({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const deleteKeyRingPromise = ibmKeyProtectApiService.deleteKeyRing();
        expectToBePromise(deleteKeyRingPromise);

        deleteKeyRingPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getKeyCollectionMetadata', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getKeyCollectionMetadata
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const state = [0];
        const extractable = true;
        const xKmsKeyRing = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          state: state,
          extractable: extractable,
          xKmsKeyRing: xKmsKeyRing,
        };

        const getKeyCollectionMetadataResult =
          ibmKeyProtectApiService.getKeyCollectionMetadata(params);

        // all methods should return a Promise
        expectToBePromise(getKeyCollectionMetadataResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys', 'HEAD');
        const expectedAccept = undefined;
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['state']).toEqual(state);
        expect(options.qs['extractable']).toEqual(extractable);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyCollectionMetadata(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyCollectionMetadata({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getKeyCollectionMetadataPromise = ibmKeyProtectApiService.getKeyCollectionMetadata();
        expectToBePromise(getKeyCollectionMetadataPromise);

        getKeyCollectionMetadataPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('createKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation createKey
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const prefer = 'return=representation';
        const xKmsKeyRing = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          body: body,
          correlationId: correlationId,
          prefer: prefer,
          xKmsKeyRing: xKmsKeyRing,
        };

        const createKeyResult = ibmKeyProtectApiService.createKey(params);

        // all methods should return a Promise
        expectToBePromise(createKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys', 'POST');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(body);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const body = Buffer.from('This is a mock file.');
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          body,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.createKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.createKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const createKeyPromise = ibmKeyProtectApiService.createKey();
        expectToBePromise(createKeyPromise);

        createKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getKeys', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getKeys
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const limit = 1;
        const offset = 0;
        const state = [0];
        const extractable = true;
        const xKmsKeyRing = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          limit: limit,
          offset: offset,
          state: state,
          extractable: extractable,
          xKmsKeyRing: xKmsKeyRing,
        };

        const getKeysResult = ibmKeyProtectApiService.getKeys(params);

        // all methods should return a Promise
        expectToBePromise(getKeysResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['limit']).toEqual(limit);
        expect(options.qs['offset']).toEqual(offset);
        expect(options.qs['state']).toEqual(state);
        expect(options.qs['extractable']).toEqual(extractable);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeys(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeys({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getKeysPromise = ibmKeyProtectApiService.getKeys();
        expectToBePromise(getKeysPromise);

        getKeysPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const getKeyResult = ibmKeyProtectApiService.getKey(params);

        // all methods should return a Promise
        expectToBePromise(getKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getKeyPromise = ibmKeyProtectApiService.getKey();
        expectToBePromise(getKeyPromise);

        getKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });

  describe('patchKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation patchKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyPatchBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyPatchBody: keyPatchBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const patchKeyResult = ibmKeyProtectApiService.patchKey(params);

        // all methods should return a Promise
        expectToBePromise(patchKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}', 'PATCH');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/vnd.ibm.kms.key+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(keyPatchBody);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.patchKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.patchKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const patchKeyPromise = ibmKeyProtectApiService.patchKey();
        expectToBePromise(patchKeyPromise);

        patchKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('deleteKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation deleteKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const force = true;
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          prefer: prefer,
          force: force,
        };

        const deleteKeyResult = ibmKeyProtectApiService.deleteKey(params);

        // all methods should return a Promise
        expectToBePromise(deleteKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}', 'DELETE');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(options.qs['force']).toEqual(force);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.deleteKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.deleteKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const deleteKeyPromise = ibmKeyProtectApiService.deleteKey();
        expectToBePromise(deleteKeyPromise);

        deleteKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getKeyMetadata', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getKeyMetadata
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
        };

        const getKeyMetadataResult = ibmKeyProtectApiService.getKeyMetadata(params);

        // all methods should return a Promise
        expectToBePromise(getKeyMetadataResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/metadata', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyMetadata(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyMetadata({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getKeyMetadataPromise = ibmKeyProtectApiService.getKeyMetadata();
        expectToBePromise(getKeyMetadataPromise);

        getKeyMetadataPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('purgeKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation purgeKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          prefer: prefer,
        };

        const purgeKeyResult = ibmKeyProtectApiService.purgeKey(params);

        // all methods should return a Promise
        expectToBePromise(purgeKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/purge', 'DELETE');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.purgeKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.purgeKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const purgeKeyPromise = ibmKeyProtectApiService.purgeKey();
        expectToBePromise(purgeKeyPromise);

        purgeKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('restoreKey', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation restoreKey
        const id = 'testString';
        const bluemixInstance = 'testString';
        const keyRestoreBody = Buffer.from('This is a mock file.');
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const prefer = 'return=representation';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          keyRestoreBody: keyRestoreBody,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          prefer: prefer,
        };

        const restoreKeyResult = ibmKeyProtectApiService.restoreKey(params);

        // all methods should return a Promise
        expectToBePromise(restoreKeyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/restore', 'POST');
        const expectedAccept = 'application/vnd.ibm.kms.key+json';
        const expectedContentType = 'application/vnd.ibm.kms.key_action_restore+json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        checkUserHeader(createRequestMock, 'Prefer', prefer);
        expect(options.body).toEqual(keyRestoreBody);
        expect(options.path['id']).toEqual(id);
        expect(options.responseType).toBe('stream');
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.restoreKey(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.restoreKey({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const restoreKeyPromise = ibmKeyProtectApiService.restoreKey();
        expectToBePromise(restoreKeyPromise);

        restoreKeyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getKeyVersions', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getKeyVersions
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const limit = 1;
        const offset = 0;
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          limit: limit,
          offset: offset,
        };

        const getKeyVersionsResult = ibmKeyProtectApiService.getKeyVersions(params);

        // all methods should return a Promise
        expectToBePromise(getKeyVersionsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/versions', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['limit']).toEqual(limit);
        expect(options.qs['offset']).toEqual(offset);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getKeyVersions(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getKeyVersions({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getKeyVersionsPromise = ibmKeyProtectApiService.getKeyVersions();
        expectToBePromise(getKeyVersionsPromise);

        getKeyVersionsPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
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

      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation putPolicy
        const id = 'testString';
        const bluemixInstance = 'testString';
        const setKeyPoliciesOneOf = setKeyPoliciesOneOfModel;
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const policy = 'dualAuthDelete';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          setKeyPoliciesOneOf: setKeyPoliciesOneOf,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          policy: policy,
        };

        const putPolicyResult = ibmKeyProtectApiService.putPolicy(params);

        // all methods should return a Promise
        expectToBePromise(putPolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/policies', 'PUT');
        const expectedAccept = 'application/json';
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.body).toEqual(setKeyPoliciesOneOf);
        expect(options.qs['policy']).toEqual(policy);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const setKeyPoliciesOneOf = setKeyPoliciesOneOfModel;
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          setKeyPoliciesOneOf,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.putPolicy(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.putPolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const putPolicyPromise = ibmKeyProtectApiService.putPolicy();
        expectToBePromise(putPolicyPromise);

        putPolicyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getPolicy', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getPolicy
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const policy = 'dualAuthDelete';
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          policy: policy,
        };

        const getPolicyResult = ibmKeyProtectApiService.getPolicy(params);

        // all methods should return a Promise
        expectToBePromise(getPolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/policies', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['policy']).toEqual(policy);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getPolicy(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getPolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getPolicyPromise = ibmKeyProtectApiService.getPolicy();
        expectToBePromise(getPolicyPromise);

        getPolicyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
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

      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation putInstancePolicy
        const bluemixInstance = 'testString';
        const setInstancePoliciesOneOf = setInstancePoliciesOneOfModel;
        const correlationId = 'testString';
        const policy = 'allowedNetwork';
        const params = {
          bluemixInstance: bluemixInstance,
          setInstancePoliciesOneOf: setInstancePoliciesOneOf,
          correlationId: correlationId,
          policy: policy,
        };

        const putInstancePolicyResult = ibmKeyProtectApiService.putInstancePolicy(params);

        // all methods should return a Promise
        expectToBePromise(putInstancePolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/instance/policies', 'PUT');
        const expectedAccept = undefined;
        const expectedContentType = 'application/json';
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(options.body).toEqual(setInstancePoliciesOneOf);
        expect(options.qs['policy']).toEqual(policy);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const setInstancePoliciesOneOf = setInstancePoliciesOneOfModel;
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          setInstancePoliciesOneOf,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.putInstancePolicy(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.putInstancePolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const putInstancePolicyPromise = ibmKeyProtectApiService.putInstancePolicy();
        expectToBePromise(putInstancePolicyPromise);

        putInstancePolicyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getInstancePolicy', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getInstancePolicy
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const policy = 'allowedNetwork';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          policy: policy,
        };

        const getInstancePolicyResult = ibmKeyProtectApiService.getInstancePolicy(params);

        // all methods should return a Promise
        expectToBePromise(getInstancePolicyResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/instance/policies', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        expect(options.qs['policy']).toEqual(policy);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getInstancePolicy(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getInstancePolicy({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getInstancePolicyPromise = ibmKeyProtectApiService.getInstancePolicy();
        expectToBePromise(getInstancePolicyPromise);

        getInstancePolicyPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getAllowedIpPort', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getAllowedIpPort
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
        };

        const getAllowedIpPortResult = ibmKeyProtectApiService.getAllowedIpPort(params);

        // all methods should return a Promise
        expectToBePromise(getAllowedIpPortResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/instance/allowed_ip_port', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getAllowedIpPort(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getAllowedIpPort({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getAllowedIpPortPromise = ibmKeyProtectApiService.getAllowedIpPort();
        expectToBePromise(getAllowedIpPortPromise);

        getAllowedIpPortPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });

  describe('getRegistrations', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getRegistrations
        const id = 'testString';
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const limit = 1;
        const offset = 0;
        const urlEncodedResourceCrnQuery =
          'crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F274074dce64e9c423ffc238516c755e1%3A29caf0e7-120f-4da8-9551-3abf57ebcfc7%3A*%3A*';
        const preventKeyDeletion = true;
        const totalCount = true;
        const params = {
          id: id,
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          limit: limit,
          offset: offset,
          urlEncodedResourceCrnQuery: urlEncodedResourceCrnQuery,
          preventKeyDeletion: preventKeyDeletion,
          totalCount: totalCount,
        };

        const getRegistrationsResult = ibmKeyProtectApiService.getRegistrations(params);

        // all methods should return a Promise
        expectToBePromise(getRegistrationsResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/{id}/registrations', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['limit']).toEqual(limit);
        expect(options.qs['offset']).toEqual(offset);
        expect(options.qs['urlEncodedResourceCRNQuery']).toEqual(urlEncodedResourceCrnQuery);
        expect(options.qs['preventKeyDeletion']).toEqual(preventKeyDeletion);
        expect(options.qs['totalCount']).toEqual(totalCount);
        expect(options.path['id']).toEqual(id);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const id = 'testString';
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          id,
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getRegistrations(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrations({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getRegistrationsPromise = ibmKeyProtectApiService.getRegistrations();
        expectToBePromise(getRegistrationsPromise);

        getRegistrationsPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
  describe('getRegistrationsAllKeys', () => {
    describe('positive tests', () => {
      test('should pass the right params to createRequest', () => {
        // Construct the params object for operation getRegistrationsAllKeys
        const bluemixInstance = 'testString';
        const correlationId = 'testString';
        const xKmsKeyRing = 'testString';
        const urlEncodedResourceCrnQuery =
          'crn%3Av1%3Abluemix%3Apublic%3Adatabases-for-postgresql%3Aus-south%3Aa%2F274074dce64e9c423ffc238516c755e1%3A29caf0e7-120f-4da8-9551-3abf57ebcfc7%3A*%3A*';
        const limit = 1;
        const offset = 0;
        const preventKeyDeletion = true;
        const totalCount = true;
        const params = {
          bluemixInstance: bluemixInstance,
          correlationId: correlationId,
          xKmsKeyRing: xKmsKeyRing,
          urlEncodedResourceCrnQuery: urlEncodedResourceCrnQuery,
          limit: limit,
          offset: offset,
          preventKeyDeletion: preventKeyDeletion,
          totalCount: totalCount,
        };

        const getRegistrationsAllKeysResult =
          ibmKeyProtectApiService.getRegistrationsAllKeys(params);

        // all methods should return a Promise
        expectToBePromise(getRegistrationsAllKeysResult);

        // assert that create request was called
        expect(createRequestMock).toHaveBeenCalledTimes(1);

        const options = getOptions(createRequestMock);

        checkUrlAndMethod(options, '/api/v2/keys/registrations', 'GET');
        const expectedAccept = 'application/json';
        const expectedContentType = undefined;
        checkMediaHeaders(createRequestMock, expectedAccept, expectedContentType);
        checkUserHeader(createRequestMock, 'Bluemix-Instance', bluemixInstance);
        checkUserHeader(createRequestMock, 'Correlation-Id', correlationId);
        checkUserHeader(createRequestMock, 'X-Kms-Key-Ring', xKmsKeyRing);
        expect(options.qs['urlEncodedResourceCRNQuery']).toEqual(urlEncodedResourceCrnQuery);
        expect(options.qs['limit']).toEqual(limit);
        expect(options.qs['offset']).toEqual(offset);
        expect(options.qs['preventKeyDeletion']).toEqual(preventKeyDeletion);
        expect(options.qs['totalCount']).toEqual(totalCount);
      });

      test('should prioritize user-given headers', () => {
        // parameters
        const bluemixInstance = 'testString';
        const userAccept = 'fake/accept';
        const userContentType = 'fake/contentType';
        const params = {
          bluemixInstance,
          headers: {
            Accept: userAccept,
            'Content-Type': userContentType,
          },
        };

        ibmKeyProtectApiService.getRegistrationsAllKeys(params);
        checkMediaHeaders(createRequestMock, userAccept, userContentType);
      });
    });

    describe('negative tests', () => {
      test('should enforce required parameters', async (done) => {
        let err;
        try {
          await ibmKeyProtectApiService.getRegistrationsAllKeys({});
        } catch (e) {
          err = e;
        }

        expect(err.message).toMatch(/Missing required parameters/);
        done();
      });

      test('should reject promise when required params are not given', (done) => {
        const getRegistrationsAllKeysPromise = ibmKeyProtectApiService.getRegistrationsAllKeys();
        expectToBePromise(getRegistrationsAllKeysPromise);

        getRegistrationsAllKeysPromise.catch((err) => {
          expect(err.message).toMatch(/Missing required parameters/);
          done();
        });
      });
    });
  });
});
