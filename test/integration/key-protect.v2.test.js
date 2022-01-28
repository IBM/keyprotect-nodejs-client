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
  beforeAll(async done => {
    const resourceControllerService = new ResourceControllerV2(resourceControllerClient);
    const instance_params = {
      name: 'testInstance',
      target: 'us-south',
      resourceGroup: options.resourceGroup,
      resourcePlanId: 'eedd3585-90c6-4c8f-be3d-062069e99fc3', // keyprotect tiered-pricing ID
    };

    resourceControllerService
      .createResourceInstance(instance_params)
      .then(res => {
        instanceGuid = res.result.guid;
      })
      .catch(err => {
        done(err);
      });
    // wait 30 seconds for completion of creating instance
    await new Promise(r => setTimeout(r, 30000));
    options.bluemixInstance = instanceGuid;
    const body = {
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
    const createParams = Object.assign({}, options);
    createParams.body = body;

    let response;
    try {
      response = await keyProtectClient.createKey(createParams);
    } catch (err) {
      done(err);
    }

    // save the created key id to use in later tests
    keyId = response.result.resources[0].id;
    done();
  });

  // Tear down - delete the test instance and key
  afterAll(async done => {
    try {
      const deleteKeyParams = Object.assign({}, options);
      deleteKeyParams.id = keyId;
      deleteKeyParams.prefer = 'return=representation';
      await keyProtectClient.deleteKey(deleteKeyParams);
      await resourceControllerClient.deleteResourceInstance({ id: instanceGuid });
    } catch (err) {
      done(err);
    }

    done();
  });

  describe('import token', () => {
    const maxRetrievals = 30;
    const expiration = '80000';

    it('createImportToken', async done => {
      let response;
      const createTokenParams = Object.assign({}, options);
      createTokenParams.maxAllowedRetrievals = maxRetrievals;
      createTokenParams.expirationDate = expiration;
      try {
        response = await keyProtectClient.postImportToken(createTokenParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.maxAllowedRetrievals).toBeDefined();
      expect(response.result.expirationDate).toBeDefined();
      done();
    });

    it('getImportToken', async done => {
      let response;
      try {
        response = await keyProtectClient.getImportToken(options);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.maxAllowedRetrievals).toEqual(maxRetrievals);
      expect(response.result.expirationDate).toBeDefined();
      expect(response.result.payload).toBeDefined();
      expect(response.result.nonce).toBeDefined();

      done();
    });
  });

  describe('keys and key actions', () => {
    let importedKeyID;
    let ciphertextResult;
    const samplePlaintext = 'dGhpcyBpcyBhIGJhc2U2NCBzdHJpbmcK';
    const samplePayload = 'ODg4ODg4ODg4ODg4ODg4OA==';
    const samplePayloadForRotation = 'SXQgaXMgYSByZWFsbHkgaW1wb3J0YW50IG1lc3NhZ2U=';

    it('getKeyCollectionMetadata', async done => {
      let response;
      try {
        response = await keyProtectClient.getKeyCollectionMetadata(options);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.headers['key-total']).toBeDefined();
      done();
    });

    // import a key too.
    it('importKey', async done => {
      const body = {
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
      const createParams = Object.assign({}, options);
      createParams.body = body;

      let response;
      try {
        response = await keyProtectClient.createKey(createParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
      expect(response.result.resources[0].id).toBeDefined();

      // save the imported key id to use in later tests
      importedKeyID = response.result.resources[0].id;

      done();
    });

    it('getKeys', async done => {
      let response;
      try {
        response = await keyProtectClient.getKeys(options);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
      done();
    });

    it('getKey', async done => {
      let response;
      try {
        const getKeyParams = Object.assign({}, options);
        getKeyParams.id = keyId;
        response = await keyProtectClient.getKey(getKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].id).toEqual(keyId);
      done();
    });

    it('wrapKey', async done => {
      let response;
      try {
        const wrapKeyParams = Object.assign({}, options);
        wrapKeyParams.id = keyId;
        wrapKeyParams.keyActionWrapBody = {
          plaintext: samplePlaintext,
        };
        response = await keyProtectClient.wrapKey(wrapKeyParams);
      } catch (err) {
        done(err);
      }
      ciphertextResult = response.result.ciphertext;
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      done();
    });

    it('unwrapKey', async done => {
      let response;
      try {
        const unwrapKeyParams = Object.assign({}, options);
        unwrapKeyParams.id = keyId;
        unwrapKeyParams.keyActionUnwrapBody = {
          ciphertext: ciphertextResult,
        };
        response = await keyProtectClient.unwrapKey(unwrapKeyParams);
      } catch (err) {
        done(err);
      }
      const plaintextResult = response.result.plaintext;
      expect(response).toBeDefined();
      expect(plaintextResult).toEqual(samplePlaintext);
      expect(response.status).toEqual(200);
      done();
    });

    it('rewrapKey', async done => {
      let response;
      try {
        const rewrapKeyParams = Object.assign({}, options);
        rewrapKeyParams.id = keyId;
        rewrapKeyParams.keyActionRewrapBody = {
          ciphertext: ciphertextResult,
        };

        response = await keyProtectClient.rewrapKey(rewrapKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      done();
    });

    it('rotateKey', async done => {
      let response;
      try {
        const rotateKeyParams = Object.assign({}, options);
        rotateKeyParams.id = keyId;
        rotateKeyParams.keyActionRotateBody = {};
        response = await keyProtectClient.rotateKey(rotateKeyParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });

    it('rotateImportedKey', async done => {
      let response;
      try {
        const rotateKeyParams = Object.assign({}, options);
        rotateKeyParams.id = importedKeyID;
        rotateKeyParams.keyActionRotateBody = {
          payload: samplePayloadForRotation,
        };

        response = await keyProtectClient.rotateKey(rotateKeyParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });

    it('getKeyVersions', async done => {
      let response;
      try {
        const getKeyVersionsParams = Object.assign({}, options);
        getKeyVersionsParams.id = keyId;

        response = await keyProtectClient.getKeyVersions(getKeyVersionsParams);
      } catch (err) {
        done(err);
      }
      expect(response.result.metadata.collectionTotal).toEqual(2);
      expect(response.result.resources[0].id).not.toEqual(response.result.resources[1].id);
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      done();
    });

    it('disableKey', async done => {
      let response;
      try {
        const disableKeyParams = Object.assign({}, options);
        disableKeyParams.id = keyId;
        response = await keyProtectClient.disableKey(disableKeyParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });

    it('enableKey', async done => {
      let response;
      try {
        // wait for 30 seconds after the key was disabled
        await new Promise(r => setTimeout(r, 30000));
        const enableKeyParams = Object.assign({}, options);
        enableKeyParams.id = keyId;
        response = await keyProtectClient.enableKey(enableKeyParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });

    it('deleteImportedKey', async done => {
      let response;
      try {
        const deleteImportedKeyParams = Object.assign({}, options);
        deleteImportedKeyParams.id = importedKeyID;
        deleteImportedKeyParams.prefer = 'return=representation';
        response = await keyProtectClient.deleteKey(deleteImportedKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
      expect(response.result.resources[0].id).toEqual(importedKeyID);
      done();
    });

    it('deleteKey', async done => {
      let response;
      try {
        const deleteKeyParams = Object.assign({}, options);
        deleteKeyParams.id = keyId;
        deleteKeyParams.prefer = 'return=representation';
        response = await keyProtectClient.deleteKey(deleteKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources).toBeDefined();
      expect(response.result.resources[0].id).toEqual(keyId);
      done();
    });

    // purge key should be done 4 hrs after key deletion, so expect to get error
    it('purgeKey', async done => {
      try {
        const purgeKeyParams = Object.assign({}, options);
        purgeKeyParams.id = keyId;
        purgeKeyParams.prefer = 'return=representation';
        await keyProtectClient.purgeKey(purgeKeyParams);
      } catch (err) {
        expect(err.body).toContain('REQ_TOO_EARLY_ERR');
      }
      done();
    });

    // syncAssociatedResource key should be done 1 hrs after any key operations, so expect to get error
    it('syncAssociatedResource', async done => {
      try {
        const syncParams = Object.assign({}, options);
        syncParams.id = keyId;
        await keyProtectClient.syncAssociatedResources(syncParams);
      } catch (err) {
        expect(err.body).toContain('REQ_TOO_EARLY_ERR');
      }
      done();
    });

    it('retoreKey', async done => {
      // wait for 30 seconds after the key was deleted
      await new Promise(r => setTimeout(r, 30000));
      let response;
      try {
        const restoreKeyParams = Object.assign({}, options);
        restoreKeyParams.id = keyId;
        response = await keyProtectClient.restoreKey(restoreKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
      done();
    });
  });

  describe('key policies', () => {
    const interval = 2;
    it('setRotationPolicyOnKey', async done => {
      let response;
      try {
        const rotationPolicyKeyParams = Object.assign({}, options);
        rotationPolicyKeyParams.id = keyId;
        rotationPolicyKeyParams.policy = 'rotation';
        rotationPolicyKeyParams.setKeyPoliciesOneOf = {
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
        };

        response = await keyProtectClient.putPolicy(rotationPolicyKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].rotation.interval_month).toEqual(interval);
      done();
    });

    it('setDualauthPolicyOnKey', async done => {
      let response;
      try {
        const dualauthPolicyKeyParams = Object.assign({}, options);
        dualauthPolicyKeyParams.id = keyId;
        dualauthPolicyKeyParams.policy = 'dualAuthDelete';
        dualauthPolicyKeyParams.setKeyPoliciesOneOf = {
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
        };

        response = await keyProtectClient.putPolicy(dualauthPolicyKeyParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].dualAuthDelete.enabled).toBeFalsy();
      done();
    });

    it('getKeyPolicy', async done => {
      let response;
      try {
        const getKeyPolicyParams = Object.assign({}, options);
        getKeyPolicyParams.id = keyId;
        response = await keyProtectClient.getPolicy(getKeyPolicyParams);
      } catch (err) {
        done(err);
      }
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
      done();
    });
  });

  describe('instance policies', () => {
    it('setDualAuthInstancePolicy', async done => {
      let response;
      try {
        const putInstancePolicyParams = Object.assign({}, options);
        putInstancePolicyParams.setInstancePoliciesOneOf = {
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
        };
        response = await keyProtectClient.putInstancePolicy(putInstancePolicyParams);
      } catch (err) {
        done(err);
      }
      expect(response.status).toEqual(204);
      done();
    });

    it('setAllowedNetworkInstancePolicy', async done => {
      let response;
      try {
        const putInstancePolicyParams = Object.assign({}, options);
        putInstancePolicyParams.setInstancePoliciesOneOf = {
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
        };
        response = await keyProtectClient.putInstancePolicy(putInstancePolicyParams);
      } catch (err) {
        done(err);
      }
      expect(response.status).toEqual(204);
      done();
    });

    it('getInstancePolicy', async done => {
      let response;
      try {
        response = await keyProtectClient.getInstancePolicy(options);
      } catch (err) {
        done(err);
      }
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

      done();
    });
  });

  describe('key alias', () => {
    const keyAlias = 'nodejsKeyAlias';
    it('createKeyAlias', async done => {
      let response;
      try {
        const createKeyAliasParams = Object.assign({}, options);
        createKeyAliasParams.id = keyId;
        createKeyAliasParams.alias = keyAlias;
        response = await keyProtectClient.createKeyAlias(createKeyAliasParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
      done();
    });

    it('getKeyByAlias', async done => {
      let response;
      try {
        const getKeyAliasParams = Object.assign({}, options);
        getKeyAliasParams.id = keyAlias;
        response = await keyProtectClient.getKey(getKeyAliasParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      done();
    });

    it('deleteKeyAlias', async done => {
      let response;
      try {
        const deleteKeyAliasParams = Object.assign({}, options);
        deleteKeyAliasParams.id = keyId;
        deleteKeyAliasParams.alias = keyAlias;
        response = await keyProtectClient.deleteKeyAlias(deleteKeyAliasParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });
  });

  describe('key ring', () => {
    // create unique key ring id
    const keyRingId =
      'testNodeSdkKeyRingId' +
      Math.random()
        .toString(36)
        .substring(7);
    it('createKeyRing', async done => {
      let response;
      try {
        const createKeyRingParams = Object.assign({}, options);
        createKeyRingParams.keyRingId = keyRingId;
        response = await keyProtectClient.createKeyRing(createKeyRingParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(201);
      done();
    });

    it('listKeyRings', async done => {
      let response;
      try {
        response = await keyProtectClient.listKeyRings(options);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);

      const keyRingIdArray = [];
      for (let i = 0; i < response.result.resources.length; i++) {
        keyRingIdArray.push(response.result.resources[i].id);
      }
      expect(keyRingIdArray).toContain(keyRingId);
      done();
    });

    it('transferKeyRing', async done => {
      let response;
      try {
        const transferKeyringParams = Object.assign({}, options);
        transferKeyringParams.id = keyId;
        transferKeyringParams.xKmsKeyRing = 'default';
        const body = { 'keyRingID': keyRingId };
        transferKeyringParams.keyPatchBody = body;
        response = await keyProtectClient.patchKey(transferKeyringParams);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].keyRingID).toEqual(keyRingId);

      // transfer the key back to 'default' key ring so that the test key ring can be deleted
      try {
        const transferKeyringParams = Object.assign({}, options);
        transferKeyringParams.id = keyId;
        transferKeyringParams.xKmsKeyRing = keyRingId;
        const body = { 'keyRingID': 'default' };
        transferKeyringParams.keyPatchBody = body;
        response = await keyProtectClient.patchKey(transferKeyringParams);
      } catch (err) {
        done(err);
      }
      expect(response.status).toEqual(200);
      expect(response.result.resources[0].keyRingID).toEqual('default');
      done();
    });

    it('deleteKeyRing', async done => {
      let response;
      try {
        const deleteKeyRingParams = Object.assign({}, options);
        deleteKeyRingParams.keyRingId = keyRingId;
        response = await keyProtectClient.deleteKeyRing(deleteKeyRingParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(204);
      done();
    });
  });

  describe('registration', () => {
    it('getRegistrations', async done => {
      let response;
      const getRegistrationsParams = Object.assign({}, options);
      getRegistrationsParams.id = keyId;
      try {
        response = await keyProtectClient.getRegistrations(getRegistrationsParams);
      } catch (err) {
        done(err);
      }

      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result).toBeDefined();
      expect(response.result.metadata.collectionTotal).toBeGreaterThanOrEqual(0);

      done();
    });

    it('getRegistrationsAllKeys', async done => {
      let response;
      try {
        response = await keyProtectClient.getRegistrationsAllKeys(options);
      } catch (err) {
        done(err);
      }
      expect(response).toBeDefined();
      expect(response.status).toEqual(200);
      expect(response.result).toBeDefined();
      expect(response.result.metadata.collectionTotal).toBeGreaterThanOrEqual(0);
      done();
    });
  });
});
