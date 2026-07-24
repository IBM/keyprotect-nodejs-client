'use strict';

const KeyProtectV2 = require('../../dist/ibm-key-protect-api/v2');
const authHelper = require('../resources/auth-helper.js');
const ResourceControllerV2 = require('@ibm-cloud/platform-services/resource-controller/v2');
const describe = authHelper.describe; // this runs describe.skip if there is no auth.js file

const { IamAuthenticator } = require('../../dist/auth');

// testcase timeout value (60s).
// To avoid jest timeout during tests, there is time delay needed between disabling and enabling a key, and deleting and restoring a key
jest.setTimeout(60000);

describe('key protect v2 integration', () => {
  const options = authHelper.auth.keyProtect;
  let keyId;

  // Helper function to get valid API parameters
  const getValidParams = () => ({
    bluemixInstance: instanceGuid,
    correlationId: options.correlationId,
  });

  // Create an IAM authenticator.
  const authenticator = new IamAuthenticator({
    apikey: options.apiKey,
    url: 'https://iam.cloud.ibm.com/identity/token',
  });

  // Construct the key protect service client.
  const keyProtectClient = new KeyProtectV2({
    authenticator, // required
    serviceUrl: 'https://us-south.kms.cloud.ibm.com',
  });

  // Construct the resource controller service client.
  const resourceControllerClient = {
    authenticator,
    url: 'https://resource-controller.cloud.ibm.com',
  };

  let instanceGuid;

  // Set up - create test instance and key, this also serves as creating key test
  beforeAll(async () => {
    const resourceControllerService = new ResourceControllerV2(resourceControllerClient);
    const instance_params = {
      name: 'testInstance',
      target: 'us-south',
      resourceGroup: options.resourceGroup,
      resourcePlanId: 'eedd3585-90c6-4c8f-be3d-062069e99fc3', // keyprotect tiered-pricing ID
    };

    const instanceResponse = await resourceControllerService.createResourceInstance(instance_params);
    instanceGuid = instanceResponse.result.guid;
    console.log('Created instance with GUID:', instanceGuid);

    // wait 30 seconds for completion of creating instance
    await new Promise((r) => setTimeout(r, 30000));
    
    const keyCreateBody = {
      metadata: {
        collectionType: 'application/vnd.ibm.kms.key+json',
        collectionTotal: 1,
      },
      resources: [
        {
          type: 'application/vnd.ibm.kms.key+json',
          name: 'nodejsKey',
          extractable: false,
        },
      ],
    };
    
    const createParams = {
      bluemixInstance: instanceGuid,
      keyCreateBody: keyCreateBody,
      correlationId: options.correlationId,
    };

    console.log('Creating key with params:', JSON.stringify(createParams, null, 2));
    const response = await keyProtectClient.createKey(createParams);
    console.log('Create key response:', JSON.stringify(response, null, 2));

    // save the created key id to use in later tests
    if (response && response.result && response.result.resources && response.result.resources[0]) {
      keyId = response.result.resources[0].id;
      console.log('Created key with ID:', keyId);
    } else {
      throw new Error('Invalid response structure: ' + JSON.stringify(response));
    }
  });

  // Tear down - delete the test instance and key
  afterAll(async () => {
    const deleteKeyParams = {
      bluemixInstance: instanceGuid,
      id: keyId,
      prefer: 'return=representation',
      correlationId: options.correlationId,
    };
    await keyProtectClient.deleteKey(deleteKeyParams);
    
    const resourceControllerService = new ResourceControllerV2(resourceControllerClient);
    await resourceControllerService.deleteResourceInstance({ id: instanceGuid });
    
    console.log('Cleanup completed successfully');
  });

  describe('import token', () => {
    const maxRetrievals = 30;
    const expiration = 80000; // seconds (must be a number, not string)

    it('createImportToken', async () => {
      const createTokenParams = {
        ...getValidParams(),
        maxAllowedRetrievals: maxRetrievals,
        expiration: expiration,
      };
      const response = await keyProtectClient.postImportToken(createTokenParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.maxAllowedRetrievals).toBeDefined();
      expect(response.result.expirationDate).toBeDefined();
    });

    it('getImportToken', async () => {
      const response = await keyProtectClient.getImportToken(getValidParams());
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.maxAllowedRetrievals).toEqual(maxRetrievals);
      expect(response.result.expirationDate).toBeDefined();
      expect(response.result.payload).toBeDefined();
      expect(response.result.nonce).toBeDefined();
    });
  });

  describe('keys and key actions', () => {
    let importedKeyID;
    let ciphertextResult;
    const samplePlaintext = 'dGhpcyBpcyBhIGJhc2U2NCBzdHJpbmcK';
    const samplePayload = 'ODg4ODg4ODg4ODg4ODg4OA==';
    const samplePayloadForRotation = 'SXQgaXMgYSByZWFsbHkgaW1wb3J0YW50IG1lc3NhZ2U=';

    it('getKeyCollectionMetadata', async () => {
      const response = await keyProtectClient.getKeyCollectionMetadata(getValidParams());
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.headers['key-total']).toBeDefined();
    });

    // import a key too.
    it('importKey', async () => {
      const keyCreateBody = {
        metadata: {
          collectionType: 'application/vnd.ibm.kms.key+json',
          collectionTotal: 1,
        },
        resources: [
          {
            type: 'application/vnd.ibm.kms.key+json',
            name: 'newkey',
            extractable: false,
            payload: samplePayload,
          },
        ],
      };
      const createParams = {
        ...getValidParams(),
        keyCreateBody: keyCreateBody,
      };

      const response = await keyProtectClient.createKey(createParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
      expect(response.result.resources[0].id).toBeDefined();

      // save the imported key id to use in later tests
      importedKeyID = response.result.resources[0].id;
    });

    it('getKeys', async () => {
      const response = await keyProtectClient.getKeys(getValidParams());
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
    });

    it('getKey', async () => {
      const getKeyParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.getKey(getKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].id).toEqual(keyId);
    });

    it('wrapKey', async () => {
      const wrapKeyParams = {
        ...getValidParams(),
        id: keyId,
        keyActionWrapBody: {
          plaintext: samplePlaintext,
        },
      };
      const response = await keyProtectClient.wrapKey(wrapKeyParams);
      ciphertextResult = response.result.ciphertext;
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
    });

    it('unwrapKey', async () => {
      const unwrapKeyParams = {
        ...getValidParams(),
        id: keyId,
        keyActionUnwrapBody: {
          ciphertext: ciphertextResult,
        },
      };
      const response = await keyProtectClient.unwrapKey(unwrapKeyParams);
      const plaintextResult = response.result.plaintext;
      expect(response).toBeDefined();
      expect(plaintextResult).toEqual(samplePlaintext);
      expect(response.status).toEqual(200);
    });

    it('rewrapKey', async () => {
      const rewrapKeyParams = {
        ...getValidParams(),
        id: keyId,
        keyActionRewrapBody: {
          ciphertext: ciphertextResult,
        },
      };
      const response = await keyProtectClient.rewrapKey(rewrapKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
    });

    it('rotateKey', async () => {
      const rotateKeyParams = {
        ...getValidParams(),
        id: keyId,
        keyActionRotateBody: {},
      };
      const response = await keyProtectClient.rotateKey(rotateKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });

    it('rotateImportedKey', async () => {
      const rotateKeyParams = {
        ...getValidParams(),
        id: importedKeyID,
        keyActionRotateBody: {
          payload: samplePayloadForRotation,
        },
      };
      const response = await keyProtectClient.rotateKey(rotateKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });

    it('getKeyVersions', async () => {
      const getKeyVersionsParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.getKeyVersions(getKeyVersionsParams);
      expect(response.result.metadata.collectionTotal).toEqual(2);
      expect(response.result.resources[0].id).not.toEqual(response.result.resources[1].id);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
    });

    // Key policies tests - must run before key is deleted
    it('setRotationPolicyOnKey', async () => {
      const interval = 2;
      const rotationPolicyKeyParams = {
        ...getValidParams(),
        id: keyId,
        policy: 'rotation',
        keyPolicyPutBody: {
          metadata: {
            collectionType: 'application/vnd.ibm.kms.policy+json',
            collectionTotal: 1,
          },
          resources: [
            {
              type: 'application/vnd.ibm.kms.policy+json',
              rotation: {
                interval_month: interval,
              },
            },
          ],
        },
      };

      const response = await keyProtectClient.putPolicy(rotationPolicyKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].rotation.interval_month).toEqual(interval);
    });

    it('setDualauthPolicyOnKey', async () => {
      const dualauthPolicyKeyParams = {
        ...getValidParams(),
        id: keyId,
        policy: 'dualAuthDelete',
        keyPolicyPutBody: {
          metadata: {
            collectionType: 'application/vnd.ibm.kms.policy+json',
            collectionTotal: 1,
          },
          resources: [
            {
              type: 'application/vnd.ibm.kms.policy+json',
              dualAuthDelete: {
                enabled: false,
              },
            },
          ],
        },
      };

      const response = await keyProtectClient.putPolicy(dualauthPolicyKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].dualAuthDelete.enabled).toBeFalsy();
    });

    it('getKeyPolicy', async () => {
      const interval = 2;
      const getKeyPolicyParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.getPolicy(getKeyPolicyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.metadata.collectionTotal).toEqual(2);
      const rsrcs = response.result.resources;

      // order of policies might vary
      if ('rotation' in rsrcs[0]) {
        expect(rsrcs[0].rotation.interval_month).toEqual(interval);
        expect(rsrcs[1].dualAuthDelete.enabled).toBeFalsy();
      } else if ('rotation' in rsrcs[1]) {
        expect(rsrcs[1].rotation.interval_month).toEqual(interval);
        expect(rsrcs[0].dualAuthDelete.enabled).toBeFalsy();
      }
    });

    it('disableKey', async () => {
      const disableKeyParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.disableKey(disableKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });

    it('enableKey', async () => {
      // wait for 30 seconds after the key was disabled
      await new Promise((r) => setTimeout(r, 30000));
      const enableKeyParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.enableKey(enableKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });

    it('deleteImportedKey', async () => {
      const deleteImportedKeyParams = {
        ...getValidParams(),
        id: importedKeyID,
        prefer: 'return=representation',
      };
      const response = await keyProtectClient.deleteKey(deleteImportedKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
      expect(response.result.resources[0].id).toEqual(importedKeyID);
    });

    it('deleteKey', async () => {
      const deleteKeyParams = {
        ...getValidParams(),
        id: keyId,
        prefer: 'return=representation',
      };
      const response = await keyProtectClient.deleteKey(deleteKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
      expect(response.result.resources[0].id).toEqual(keyId);
    });

    // purge key should be done 4 hrs after key deletion, so expect to get error
    it('purgeKey', async () => {
      try {
        const purgeKeyParams = {
          ...getValidParams(),
          id: keyId,
          prefer: 'return=representation',
        };
        await keyProtectClient.purgeKey(purgeKeyParams);
      } catch (err) {
        expect(err.body).toContain('REQ_TOO_EARLY_ERR');
      }
    });

    // syncAssociatedResource key should be done 1 hrs after any key operations, so expect to get error
    it('syncAssociatedResource', async () => {
      try {
        const syncParams = {
          ...getValidParams(),
          id: keyId,
        };
        await keyProtectClient.syncAssociatedResources(syncParams);
      } catch (err) {
        expect(err.body).toContain('REQ_TOO_EARLY_ERR');
      }
    });

    it('restoreKey', async () => {
      // wait for 30 seconds after the key was deleted
      await new Promise((r) => setTimeout(r, 30000));
      const restoreKeyParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.restoreKey(restoreKeyParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
    });
  });

  describe('instance policies', () => {
    it('setDualAuthInstancePolicy', async () => {
      const putInstancePolicyParams = {
        ...getValidParams(),
        instancePolicyPutBody: {
          metadata: {
            collectionType: 'application/vnd.ibm.kms.policy+json',
            collectionTotal: 1,
          },
          resources: [
            {
              policy_type: 'dualAuthDelete',
              policy_data: {
                enabled: false,
              },
            },
          ],
        },
      };
      const response = await keyProtectClient.putInstancePolicy(putInstancePolicyParams);
      expect(response.status).toEqual(204);
    });

    it('setAllowedNetworkInstancePolicy', async () => {
      const putInstancePolicyParams = {
        ...getValidParams(),
        instancePolicyPutBody: {
          metadata: {
            collectionType: 'application/vnd.ibm.kms.policy+json',
            collectionTotal: 1,
          },
          resources: [
            {
              policy_type: 'allowedNetwork',
              policy_data: {
                enabled: true,
                attributes: { 'allowed_network': 'public-and-private' },
              },
            },
          ],
        },
      };
      const response = await keyProtectClient.putInstancePolicy(putInstancePolicyParams);
      expect(response.status).toEqual(204);
    });

    it('getInstancePolicy', async () => {
      const response = await keyProtectClient.getInstancePolicy(getValidParams());
      expect(response.status).toEqual(200);

      const rsrcs = response.result.resources;
      // order of policies might vary
      if ('dualAuthDelete' === rsrcs[0].policy_type) {
        expect(rsrcs[0].policy_type).toEqual('dualAuthDelete');
        expect(rsrcs[0].policy_data.enabled).toBeFalsy();
        expect(rsrcs[1].policy_type).toEqual('allowedNetwork');
        expect(rsrcs[1].policy_data.enabled).not.toBeFalsy();
      } else {
        expect(rsrcs[0].policy_type).toEqual('allowedNetwork');
        expect(rsrcs[0].policy_data.enabled).not.toBeFalsy();
        expect(rsrcs[1].policy_type).toEqual('dualAuthDelete');
        expect(rsrcs[1].policy_data.enabled).toBeFalsy();
      }
    });
  });

  describe('key alias', () => {
    const keyAlias = 'nodejsKeyAlias';
    it('createKeyAlias', async () => {
      const createKeyAliasParams = {
        ...getValidParams(),
        id: keyId,
        alias: keyAlias,
      };
      const response = await keyProtectClient.createKeyAlias(createKeyAliasParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
    });

    it('getKeyByAlias', async () => {
      const getKeyAliasParams = {
        ...getValidParams(),
        id: keyAlias,
      };
      const response = await keyProtectClient.getKey(getKeyAliasParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
    });

    it('deleteKeyAlias', async () => {
      const deleteKeyAliasParams = {
        ...getValidParams(),
        id: keyId,
        alias: keyAlias,
      };
      const response = await keyProtectClient.deleteKeyAlias(deleteKeyAliasParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });
  });

  describe('key ring', () => {
    // create unique key ring id
    const keyRingId = 'testNodeSdkKeyRingId' + Math.random().toString(36).substring(7);
    it('createKeyRing', async () => {
      const createKeyRingParams = {
        ...getValidParams(),
        keyRingId: keyRingId,
      };
      const response = await keyProtectClient.createKeyRing(createKeyRingParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
    });

    it('listKeyRings', async () => {
      const response = await keyProtectClient.listKeyRings(getValidParams());
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);

      const keyRingIdArray = [];
      for (let i = 0; i < response.result.resources.length; i++) {
        keyRingIdArray.push(response.result.resources[i].id);
      }
      expect(keyRingIdArray).toContain(keyRingId);
    });

    it('transferKeyRing', async () => {
      let response;
      const transferKeyringParams = {
        ...getValidParams(),
        id: keyId,
        xKmsKeyRing: 'default',
        keyPatchBody: { 'keyRingID': keyRingId },
      };
      response = await keyProtectClient.patchKey(transferKeyringParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].keyRingID).toEqual(keyRingId);

      // transfer the key back to 'default' key ring so that the test key ring can be deleted
      const transferKeyringParams2 = {
        ...getValidParams(),
        id: keyId,
        xKmsKeyRing: keyRingId,
        keyPatchBody: { 'keyRingID': 'default' },
      };
      response = await keyProtectClient.patchKey(transferKeyringParams2);
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].keyRingID).toEqual('default');
    });

    it('deleteKeyRing', async () => {
      const deleteKeyRingParams = {
        ...getValidParams(),
        keyRingId: keyRingId,
      };
      const response = await keyProtectClient.deleteKeyRing(deleteKeyRingParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
    });
  });

  describe('registration', () => {
    it('getRegistrations', async () => {
      const getRegistrationsParams = {
        ...getValidParams(),
        id: keyId,
      };
      const response = await keyProtectClient.getRegistrations(getRegistrationsParams);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result).toBeDefined();
      expect(response.result.metadata.collectionTotal).toBeGreaterThanOrEqual(0);
    });

    it('getRegistrationsAllKeys', async () => {
      const response = await keyProtectClient.getRegistrationsAllKeys(getValidParams());
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result).toBeDefined();
      expect(response.result.metadata.collectionTotal).toBeGreaterThanOrEqual(0);
    });
  });
  describe('key alias extensions', () => {
    it('checkKeyaliasExtension', async done => {
      let response;
      const samplePlaintext = 'dGhpcyBpcyBhIGJhc2U2NCBzdHJpbmcK';
      try {
        // create a key alias
        const keyAlias = 'nodejsAlias';
        const createKeyAliasParams = Object.assign({}, options);
        createKeyAliasParams.id = keyId;
        createKeyAliasParams.alias = keyAlias;
        response = await keyProtectClient.createKeyAlias(createKeyAliasParams);
        expect(response).toBeDefined();
        expect(response.status).toEqual(201);

        // wrap using key alias
        const wrapKeyParams = Object.assign({}, options);
        wrapKeyParams.id = createKeyAliasParams.alias;
        wrapKeyParams.keyActionWrapBody = {
          plaintext: samplePlaintext,
        };
        response = await keyProtectClient.wrapKey(wrapKeyParams);
        const ciphertextResult = response.result.ciphertext;
        expect(response).toBeDefined();
        expect(response.status).toEqual(200);

        // un-wrap using key alias
        const unwrapKeyParams = Object.assign({}, options);
        unwrapKeyParams.id = createKeyAliasParams.alias;
        unwrapKeyParams.keyActionUnwrapBody = {
          ciphertext: ciphertextResult,
        };
        response = await keyProtectClient.unwrapKey(unwrapKeyParams);
        const plaintextResult = response.result.plaintext;
        expect(response).toBeDefined();
        expect(plaintextResult).toEqual(samplePlaintext);
        expect(response.status).toEqual(200);

        // delete a key using key alias
        const deleteKeyParams = Object.assign({}, options);
        deleteKeyParams.id = createKeyAliasParams.alias;
        deleteKeyParams.prefer = 'return=representation';
        response = await keyProtectClient.deleteKey(deleteKeyParams);
        expect(response).toBeDefined();
        expect(response.status).toEqual(200);
      } catch (err) {
        done(err);
      }
      done();
    });
  });
});
