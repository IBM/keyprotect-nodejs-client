[![Build Status](https://travis-ci.com/IBM/keyprotect-nodejs-client.svg?branch=master)](https://travis-ci.com/IBM/keyprotect-nodejs-client)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

# IBM Cloud Key Protect Node.js SDK
Node.js client library to interact with various [Key Protect APIs](https://cloud.ibm.com/apidocs/key-protect).

<details>
<summary>Table of Contents</summary>

* [Overview](#overview)
* [Prerequisites](#prerequisites)
* [Authentication](#authentication)
* [Using the SDK](#using-the-sdk)
* [Tests](#tests)
* [Questions](#questions)
* [Issues](#issues)
* [Contributing](#contributing)
* [License](#license)

</details>

## Overview

The IBM Cloud Key Protect Node.js SDK allows developers to programmatically interact with the following
IBM Cloud services:

[Key protect Service](https://cloud.ibm.com/apidocs/key-protect) 

## Prerequisites

- An [IBM Cloud account](https://cloud.ibm.com/registration).
- A [Key Protect service instance](https://cloud.ibm.com/catalog/services/key-protect).
- An [IBM Cloud API key](https://cloud.ibm.com/iam/apikeys) that allows the SDK to access your account.
- Node.js version 12 or above.

  This SDK is tested with Node versions 12 and up. The SDK may work on previous versions, but this is not supported
  officially.

## Installation

```
npm install @ibm-cloud/ibm-key-protect
```

## Authentication

Key Protect uses token-based Identity and Access Management (IAM) authentication. With IAM authentication, you supply an API key that is used to generate an access token. 

Authentication for this SDK is accomplished by
using [IAM authenticators](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md#authentication).

To learn more about IAM authenticators and how to use them in your Node.js application, see
the [IBM Node.js SDK Core documentation](https://github.com/IBM/node-sdk-core/blob/master/Authentication.md).

## Using the SDK

### Basic usage

- All methods return a Promise that either resolves with the response from the service or rejects with an Error. The
  response contains the body, the headers, the status code, and the status text. 
- Use the `serviceUrl` parameter to set the endpoint URL that is specific to your Key Protect service instance. The 
  endpoint can be either public or private, for example:
  
  ```
  serviceUrl: 'https://us-south.kms.cloud.ibm.com'
  ```
  or
  ```
  serviceUrl: 'https://private.us-south.kms.cloud.ibm.com'
  ```

#### Examples

```js
const KeyProtectV2 = require('@ibm-cloud/ibm-key-protect/ibm-key-protect-api/v2');
const { IamAuthenticator } = require('@ibm-cloud/ibm-key-protect/auth');

// env vars, using external configuration in this example
const envConfigs = {
  apiKey: process.env.IBMCLOUD_API_KEY,
  iamAuthUrl: process.env.IAM_AUTH_URL,
  serviceUrl: process.env.KP_SERVICE_URL,
  bluemixInstance: process.env.KP_INSTANCE_ID,
};

async function keyProtectSdkExample() {
  let response;

  // Create an IAM authenticator.
  const authenticator = new IamAuthenticator({
    apikey: envConfigs.apiKey,
    url: envConfigs.iamAuthUrl,
  });

  // Construct the service client.
  const keyProtectClient = new KeyProtectV2({
    authenticator,
    serviceUrl: envConfigs.serviceUrl,
  });

  // Create a key
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
  const createParams = Object.assign({}, envConfigs);
  createParams.body = body;
  response = await keyProtectClient.createKey(createParams);
  const keyId = response.result.resources[0].id;
  console.log('Key created, id is: ' + keyId);

  // Get the key
  const getKeyParams = Object.assign({}, envConfigs);
  getKeyParams.id = keyId;
  response = await keyProtectClient.getKey(getKeyParams);
  console.log('Get key result: ');
  console.log(response.result.resources[0]);

  // Get list of keys associated to the instance
  response = await keyProtectClient.getKeys(envConfigs);
  console.log('Get keys result:');
  for(let resource of response.result.resources){
     console.log(resource);
  }

  // Wrap and unwrap key
  const samplePlaintext = 'dGhpcyBpcyBhIGJhc2U2NCBzdHJpbmcK'; // base64 encoded plaintext

  const wrapKeyParams = Object.assign({}, envConfigs);
  wrapKeyParams.id = keyId;
  wrapKeyParams.keyActionWrapBody = {
    plaintext: samplePlaintext,
  };
  response = await keyProtectClient.wrapKey(wrapKeyParams);
  console.log('Wrap key response status: ' + response.status);
  const ciphertextResult = response.result.ciphertext;

  const unwrapKeyParams = Object.assign({}, envConfigs);
  unwrapKeyParams.id = keyId;
  unwrapKeyParams.keyActionUnwrapBody = {
    ciphertext: ciphertextResult, // from wrap key response
  };
  response = await keyProtectClient.unwrapKey(unwrapKeyParams);
  console.log('Key plain text is: ' + response.result.plaintext);   //should be the same as 'samplePlaintext' above

  // Delete key
  const deleteKeyParams = Object.assign({}, envConfigs);
  deleteKeyParams.id = keyId;
  deleteKeyParams.prefer = 'return=representation';
  response = await keyProtectClient.deleteKey(deleteKeyParams);
  console.log('Delete key response status: ' + response.status);
}

keyProtectSdkExample();
```

For more information and IBM Cloud SDK usage examples for Node.js, see
the [IBM Cloud SDK Common documentation](https://github.com/IBM/ibm-cloud-sdk-common/blob/master/README.md)

## Tests

This project includes unit tests `test/unit` and integration tests `test/integration`.

The integration tests are run against an actual Key Protect instance and require the auth.js file with 
proper configuration values to be added under test/resources, use auth.example.js under the same directory 
as example to create the auth.js file.

To run the tests:

```sh
npm run test
npm run test-unit
npm run test-integration
```

## Questions

If you are having difficulties using this SDK or have a question about the IBM Cloud services,
please ask a question at
[Stack Overflow](http://stackoverflow.com/questions/ask?tags=ibm-cloud).

You can also check out the [Key Protect documentation](https://cloud.ibm.com/docs/key-protect)
and [API reference](https://cloud.ibm.com/apidocs/key-protect) for more information about the service.

## Issues
If you encounter an issue with the SDK, you are welcome to submit
a [bug report](https://github.com/IBM/keyprotect-nodejs-client/issues).
Before that, please search for similar issues. It's possible someone has
already encountered this issue.

## Contributing

For general contribution guidelines, see [CONTRIBUTING](CONTRIBUTING.md).

## License

This SDK project is released under the Apache 2.0 license. The license's full text can be found in [LICENSE](LICENSE).
