/**
 * (C) Copyright IBM Corp. 2024.
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

/**
 * IBM OpenAPI SDK Code Generator Version: 3.86.0-bc6f14b3-20240221-193958
 */

import * as extend from 'extend';
import { IncomingHttpHeaders, OutgoingHttpHeaders } from 'http';
import {
  Authenticator,
  BaseService,
  SDKLogger,
  UserOptions,
  constructServiceUrl,
  getAuthenticatorFromEnvironment,
  getNewLogger,
  validateParams,
} from 'ibm-cloud-sdk-core';
import { getSdkHeaders } from '../lib/common';

/**
 * IBM Key Protect helps you provision encrypted keys for apps across IBM Cloud. As you manage the lifecycle of your
 * keys, you can benefit from knowing that your keys are secured by cloud-based FIPS 140-2 Level 3 hardware security
 * modules (HSMs) that protect against theft of information. You can use the Key Protect API to store, generate, and
 * retrieve your key material. Keys within the service can protect any type of data in your symmetric key-based
 * encryption solution.
 *
 * API Version: 2.0.0
 */

class IbmKeyProtectApiV2 extends BaseService {
  static _logger: SDKLogger = getNewLogger('IbmKeyProtectApiV2');

  static DEFAULT_SERVICE_URL: string = 'https://us-south.kms.cloud.ibm.com';

  static DEFAULT_SERVICE_NAME: string = 'ibm_key_protect_api';

  static PARAMETERIZED_SERVICE_URL: string = 'https://{region}.kms.cloud.ibm.com';

  private static defaultUrlVariables = new Map([
    ['region', 'us-south'],
  ]);

  /**
   * Constructs a service URL by formatting the parameterized service URL.
   *
   * The parameterized service URL is:
   * 'https://{region}.kms.cloud.ibm.com'
   *
   * The default variable values are:
   * - 'region': 'us-south'
   *
   * @param {Map<string, string>} | null providedUrlVariables Map from variable names to desired values.
   *  If a variable is not provided in this map,
   *  the default variable value will be used instead.
   * @returns {string} The formatted URL with all variable placeholders replaced by values.
   */
  static constructServiceUrl(providedUrlVariables: Map<string, string> | null): string {
    return constructServiceUrl(
      IbmKeyProtectApiV2.PARAMETERIZED_SERVICE_URL, 
      IbmKeyProtectApiV2.defaultUrlVariables, 
      providedUrlVariables
    );
  }

  /*************************
   * Factory method
   ************************/

  /**
   * Constructs an instance of IbmKeyProtectApiV2 with passed in options and external configuration.
   *
   * @param {UserOptions} [options] - The parameters to send to the service.
   * @param {string} [options.serviceName] - The name of the service to configure
   * @param {Authenticator} [options.authenticator] - The Authenticator object used to authenticate requests to the service
   * @param {string} [options.serviceUrl] - The base URL for the service
   * @returns {IbmKeyProtectApiV2}
   */

  public static newInstance(options: UserOptions): IbmKeyProtectApiV2 {
    options = options || {};

    if (!options.serviceName) {
      options.serviceName = this.DEFAULT_SERVICE_NAME;
    }
    if (!options.authenticator) {
      options.authenticator = getAuthenticatorFromEnvironment(options.serviceName);
    }
    const service = new IbmKeyProtectApiV2(options);
    service.configureService(options.serviceName);
    if (options.serviceUrl) {
      service.setServiceUrl(options.serviceUrl);
    }
    return service;
  }

  /**
   * Construct a IbmKeyProtectApiV2 object.
   *
   * @param {Object} options - Options for the service.
   * @param {string} [options.serviceUrl] - The base URL for the service
   * @param {OutgoingHttpHeaders} [options.headers] - Default headers that shall be included with every request to the service.
   * @param {Authenticator} options.authenticator - The Authenticator object used to authenticate requests to the service
   * @constructor
   * @returns {IbmKeyProtectApiV2}
   */
  constructor(options: UserOptions) {
    options = options || {};

    super(options);
    if (options.serviceUrl) {
      this.setServiceUrl(options.serviceUrl);
    } else {
      this.setServiceUrl(IbmKeyProtectApiV2.DEFAULT_SERVICE_URL);
    }
  }

  /*************************
   * keys
   ************************/

  /**
   * Retrieve key total.
   *
   * Returns the same HTTP headers as a GET request without returning the entity-body. This operation returns the number
   * of keys in your instance in a header called `Key-Total`.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {number[]} [params.state] - The state of the keys to be retrieved. States must be a list of integers from 0
   * to 5 delimited by commas with no whitespace or trailing commas. Valid states are based on NIST SP 800-57. States
   * are integers and correspond to the Pre-activation = 0, Active = 1, Suspended = 2, Deactivated = 3, and Destroyed =
   * 5 values.
   * **Usage:** If you want to retrieve active and deleted keys, use `../keys?state=1,5`.
   * @param {boolean} [params.extractable] - The type of keys to be retrieved. Filters keys based on the `extractable`
   * property. You can use this query parameter to search for keys whose material can leave the service. If set to
   * `true`, standard keys will be retrieved. If set to `false`, root keys will be retrieved. If omitted, both root and
   * standard keys will be retrieved.
   * **Usage:** If you want to retrieve standard keys, use `../keys?extractable=true`.
   * @param {string} [params.filter] - When provided, returns the list of keys that match the queried properties. Each
   * key property to be filtered on is specified as the property name itself, followed by an “=“ symbol,  and then the
   * value to filter on, followed by a space if there are more properties to filter only. Note: Anything between `<` and
   * `>` in the examples or descriptions represent placeholder to specify the value
   * *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to filter on may contain a value related to
   * the property itself, or an operator followed by a value accepted by the operator - Only one operator and value, or
   * one value is accepted per property at a time
   * *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to three of the same property may be
   * specified at a time. The key properties that can be filtered at this time are:
   * - `creationDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `deletionDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `expirationDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `extractable`
   *   * Boolean true or false without quotes, case-insensitive
   * - `lastRotateDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `lastUpdateDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `state`
   *   * A list of comma-separated integers with no space in between: 0,1,2,3,5 Comparison operations (operators) that
   * can be performed on date values are:
   * - `lte:<value>` Less than or equal to - `lt:<value>` Less than - `gte:<value>` Greater than or equal to -
   * `gt:<value>` Greater than A special keyword for date, `none` (case-insensitive), may be used to retreive keys that
   * do not have that property. This is useful for `lastRotateDate`, where only keys that have never been rotated can be
   *  retreived.
   * *Examples*:
   * - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last rotated on February 15, 2022 -
   * `lastRotateDate=gte:"2022-02-15T00:00:00Z"` Filter keys that were last rotated after or on February 15, 2022 -
   * `lastRotateDate=gte:"2022-02-15T00:00:00Z" lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
   * rotated after or on February 15, 2022 but before (not including) March 15, 2022 -
   * `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5 extractable=false` Filter root keys that were last rotated
   * on February 15, 2022, with any state
   * *Note*: When you filter by `state` or `extractable` in this query parameter, you will not be able to use the
   * deprecated `state` or `extractable` independent query parameter. You will get a 400 response code if you specify a
   * value for one of the two properties in both this filter query parameter and the deprecated independent query of the
   * same name (the same applies vice versa).
   * @param {string} [params.xKmsKeyRing] - The ID of the target key ring. If unspecified, all resources in the instance
   * that the caller has access to will be returned. When the header  is specified, only resources within the specified
   * key ring, that the caller has access to,  will be returned. The key ring ID of keys that are created without an
   * `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public getKeyCollectionMetadata(
    params: IbmKeyProtectApiV2.GetKeyCollectionMetadataParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'state', 'extractable', 'filter', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'state': _params.state,
      'extractable': _params.extractable,
      'filter': _params.filter,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKeyCollectionMetadata');

    const parameters = {
      options: {
        url: '/api/v2/keys',
        method: 'HEAD',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Create a key.
   *
   * Creates a new key with specified key material.
   *
   * Key Protect designates the resource as either a root key or a standard key based on the `extractable` value that
   * you specify. A successful
   * `POST /keys` operation adds the key to the service and returns the details of the request in the response
   * entity-body, if the Prefer header is set to `return=representation`.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} params.keyCreateBody - The base request for creating a new key.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key belongs to. When the header is
   * not specified,  Key Protect will perform a key ring lookup. For a more optimized request,  specify the key ring on
   * every call. The key ring ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.Key>>}
   */
  public createKey(
    params: IbmKeyProtectApiV2.CreateKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.Key>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance', 'keyCreateBody'];
    const _validParams = ['bluemixInstance', 'keyCreateBody', 'correlationId', 'prefer', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyCreateBody;
    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'createKey');

    const parameters = {
      options: {
        url: '/api/v2/keys',
        method: 'POST',
        body,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'Prefer': _params.prefer,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List keys.
   *
   * Retrieves a list of keys that are stored in your Key Protect service instance.
   *
   * **Important:** When a user of Key Protect on Satellite views lists of  keys through the [IBM
   * Console](https://cloud.ibm.com/login),  or programmatically via this API, keys with ["fine grain"
   * permissions](/docs/key-protect?topic=key-protect-grant-access-keys#grant-access-key-level)  won't appear due to the
   * manner in which the service aggregates the  collection. While the user can still use the key resource, only by
   * using  the CLI or API and passing the specific key ID can a user access the  metadata and other details of the key.
   *
   * **Note:** `GET /keys` will not return the key material in the response body. You can retrieve the key material for
   * a standard key with a subsequent `GET /keys/{id}` request.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {number} [params.limit] - The number of keys to retrieve. By default, `GET /keys` returns the first 200
   * keys. To retrieve a different set of keys, use `limit` with `offset` to page through your available resources. The
   * maximum value for `limit` is 5,000.
   * **Usage:** If you have 20 keys in your instance, and you want to retrieve only the first 5 keys, use
   * `../keys?limit=5`.
   * @param {number} [params.offset] - The number of keys to skip. By specifying `offset`, you retrieve a subset of keys
   * that starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
   * **Usage:** If you have 100 keys in your instance, and you want to retrieve keys 26 through 50, use
   * `../keys?offset=25&limit=25`.
   * @param {number[]} [params.state] - The state of the keys to be retrieved. States must be a list of integers from 0
   * to 5 delimited by commas with no whitespace or trailing commas. Valid states are based on NIST SP 800-57. States
   * are integers and correspond to the Pre-activation = 0, Active = 1, Suspended = 2, Deactivated = 3, and Destroyed =
   * 5 values.
   * **Usage:** If you want to retrieve active and deleted keys, use `../keys?state=1,5`.
   * @param {boolean} [params.extractable] - The type of keys to be retrieved. Filters keys based on the `extractable`
   * property. You can use this query parameter to search for keys whose material can leave the service. If set to
   * `true`, standard keys will be retrieved. If set to `false`, root keys will be retrieved. If omitted, both root and
   * standard keys will be retrieved.
   * **Usage:** If you want to retrieve standard keys, use `../keys?extractable=true`.
   * @param {string} [params.search] - When provided, performs a search, possibly limiting the number of keys returned.
   * *Examples*:
   *
   *   - `foobar` - find keys where the name or any of its aliases contain `foobar`, case insentive (i.e. matches
   * `xfoobar`, `Foobar`).
   *   - `fadedbee-0000-0000-0000-1234567890ab` (a valid key id) - find keys where the id the key is
   * `fadedbee-0000-0000-0000-1234567890ab`, or the name or any of its aliases contain
   * `fadedbee-0000-0000-0000-1234567890ab`, case insentive.
   *
   * May prepend with options:
   *
   *   - `not:` = when specified, inverts matching logic (example: `not:foo` will search for keys that have aliases or
   * names that do not contain `foo`)
   *   - `escape:` = everything after this option is take as plaintext (example: `escape:not:` will search for keys that
   * have an alias or name containing the substring `not:`)
   *   - `exact:` = only looks for exact matches
   *
   * May prepend with search scopes:
   *
   *   - `alias:` = search in key aliases for search query
   *   - `name:` = search in key names for search query
   *
   * *Examples*:
   *
   *   - `not:exact:foobar`/`exact:not:foobar` - find keys where the name nor any of its aliases are *not* exactly
   * `foobar` (i.e. matches `xfoobar`, `bar`, `foo`)
   *   - `exact:escape:not:foobar` - find keys where the name or any of its aliases are exactly `not:foobar`
   *   - `not:alias:foobar`/`alias:not:foobar` - find keys where any of its aliases do *not* contain `foobar`
   *   - `name:exact:foobar`/`exact:name:foobar` - find keys where the name is exactly `foobar`
   *
   * *Note*:
   *
   *   By default, if no scopes are provided, search will be performed in both `name` and `alias` scopes.
   *
   *   Search is only possible on a intial searchable space of at most 5000 keys. If the initial seachable space is
   * greater than 5000 keys, the API returns HTTP 400 with the property resouces[0].reasons[0].code equals to
   * 'KEY_SEARCH_TOO_BROAD'.
   *   Use the following filters to reduce the initial searchable space:
   *
   *   - `state` (query parameter)
   *   - `extractable` (query parameter)
   *   - `X-Kms-Key-Ring` (HTTP header)
   *
   *   If the total intial searchable space exceeds the 5000 keys limit and when providing a fully specified key id or
   * when searching within the `alias` scope, a lookup
   *   will  be performed and if a key is found, the key will be returned as the only resource and in the response
   * metadata the property `incompleteSearch` will
   *   be `true`.
   *
   *   When providing a fully specified key id or when searching within the `alias` scope, a key lookup is performed in
   * addition to the search.
   *   This means search will try to lookup a single key that is uniquely identified by the key id or provided alias,
   * this key will be included in the response
   *   as the first resource, before other matches.
   *
   *   Search scopes are disjunctive, behaving in an *OR* manner. When using more than one search scope,
   *   a match in at least one of the scopes will result in the key being returned.
   * @param {string} [params.sort] - When provided, sorts the list of keys returned based on one or more key properties.
   * To sort on a property in descending order, prefix the term with "-". To sort on multiple key properties, use a
   * comma to separate each properties. The first property in the comma-separated list will be evaluated before the
   * next. The key properties that can be sorted at this time are:
   *   - `id`
   *   - `state`
   *   - `extractable`
   *   - `imported`
   *   - `creationDate`
   *   - `lastUpdateDate`
   *   - `lastRotateDate`
   *   - `deletionDate`
   *   - `expirationDate`
   *
   * The list of keys returned is sorted on id by default, if this parameter is not provided.
   * @param {string} [params.filter] - When provided, returns the list of keys that match the queried properties. Each
   * key property to be filtered on is specified as the property name itself, followed by an “=“ symbol,  and then the
   * value to filter on, followed by a space if there are more properties to filter only. Note: Anything between `<` and
   * `>` in the examples or descriptions represent placeholder to specify the value
   * *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to filter on may contain a value related to
   * the property itself, or an operator followed by a value accepted by the operator - Only one operator and value, or
   * one value is accepted per property at a time
   * *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to three of the same property may be
   * specified at a time. The key properties that can be filtered at this time are:
   * - `creationDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `deletionDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `expirationDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `extractable`
   *   * Boolean true or false without quotes, case-insensitive
   * - `lastRotateDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `lastUpdateDate`
   *   * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
   * - `state`
   *   * A list of comma-separated integers with no space in between: 0,1,2,3,5 Comparison operations (operators) that
   * can be performed on date values are:
   * - `lte:<value>` Less than or equal to - `lt:<value>` Less than - `gte:<value>` Greater than or equal to -
   * `gt:<value>` Greater than A special keyword for date, `none` (case-insensitive), may be used to retreive keys that
   * do not have that property. This is useful for `lastRotateDate`, where only keys that have never been rotated can be
   *  retreived.
   * *Examples*:
   * - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last rotated on February 15, 2022 -
   * `lastRotateDate=gte:"2022-02-15T00:00:00Z"` Filter keys that were last rotated after or on February 15, 2022 -
   * `lastRotateDate=gte:"2022-02-15T00:00:00Z" lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
   * rotated after or on February 15, 2022 but before (not including) March 15, 2022 -
   * `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5 extractable=false` Filter root keys that were last rotated
   * on February 15, 2022, with any state
   * *Note*: When you filter by `state` or `extractable` in this query parameter, you will not be able to use the
   * deprecated `state` or `extractable` independent query parameter. You will get a 400 response code if you specify a
   * value for one of the two properties in both this filter query parameter and the deprecated independent query of the
   * same name (the same applies vice versa).
   * @param {string} [params.xKmsKeyRing] - The ID of the target key ring. If unspecified, all resources in the instance
   * that the caller has access to will be returned. When the header  is specified, only resources within the specified
   * key ring, that the caller has access to,  will be returned. The key ring ID of keys that are created without an
   * `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeys>>}
   */
  public getKeys(
    params: IbmKeyProtectApiV2.GetKeysParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeys>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'limit', 'offset', 'state', 'extractable', 'search', 'sort', 'filter', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'state': _params.state,
      'extractable': _params.extractable,
      'search': _params.search,
      'sort': _params.sort,
      'filter': _params.filter,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKeys');

    const parameters = {
      options: {
        url: '/api/v2/keys',
        method: 'GET',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Create a key with policy overrides.
   *
   * Creates a new key with specified key material and key policies. This API overrides the policy configurations set at
   * instance level with policies provided in the payload. Key Protect designates the resource as a root key or a
   * standard key based on the extractable value that you specify. A successful `POST /keys_with_policy_overrides`
   * operation adds the key and key policies to the service and returns the details of the request in the response
   * entity-body, if the Prefer header is set to `return=representation`.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} params.keyWithPolicyOverridesCreateBody - The base request for creating a
   * new key with policies.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key belongs to. When the header is
   * not specified,  Key Protect will perform a key ring lookup. For a more optimized request,  specify the key ring on
   * every call. The key ring ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.Key>>}
   */
  public createKeyWithPoliciesOverrides(
    params: IbmKeyProtectApiV2.CreateKeyWithPoliciesOverridesParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.Key>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance', 'keyWithPolicyOverridesCreateBody'];
    const _validParams = ['bluemixInstance', 'keyWithPolicyOverridesCreateBody', 'correlationId', 'prefer', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyWithPolicyOverridesCreateBody;
    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'createKeyWithPoliciesOverrides');

    const parameters = {
      options: {
        url: '/api/v2/keys_with_policy_overrides',
        method: 'POST',
        body,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'Prefer': _params.prefer,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve a key.
   *
   * Retrieves a key and its details by specifying the ID or alias of the key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKey>>}
   */
  public getKey(
    params: IbmKeyProtectApiV2.GetKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKey>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}',
        method: 'GET',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Invoke an action on a key.
   *
   * **Note:** This API has been **deprecated** and transitioned to individual request paths. Existing actions using
   * this API will continue to be supported, but new actions will no longer be added to it. We recommend, if possible,
   * aligning your request URLs to the new API path. The generic format of actions is now the following:
   * `/api/v2/keys/<key_ID>/actions/<action>` where `key_ID` is the key you want to operate on/with and `action` is the
   * same action that was passed as a query parameter previously.
   *
   * Invokes an action on a specified key. This method supports the following actions:
   *
   * - `disable`: [Disable operations](/docs/key-protect?topic=key-protect-disable-keys) for a key
   * - `enable`: [Enable operations](/docs/key-protect?topic=key-protect-disable-keys#enable-api) for a key
   * - `restore`: [Restore a root key](/docs/key-protect?topic=key-protect-restore-keys)
   * - `rewrap`: Use a root key to [rewrap or reencrypt a data encryption
   * key](/docs/key-protect?topic=key-protect-rewrap-keys)
   * - `rotate`: [Create a new version](/docs/key-protect?topic=key-protect-rotate-keys) of a root key
   * - `setKeyForDeletion`: [Authorize
   * deletion](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#set-key-deletion-api) for a key with a dual
   * authorization policy
   * - `unsetKeyForDeletion`: [Remove an
   * authorization](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#unset-key-deletion-api) for a key with a
   * dual authorization policy
   * - `unwrap`: Use a root key to [unwrap or decrypt a data encryption
   * key](/docs/key-protect?topic=key-protect-unwrap-keys)
   * - `wrap`: Use a root key to [wrap or encrypt a data encryption key](/docs/key-protect?topic=key-protect-wrap-keys)
   *
   * **Note:** If you unwrap a wrapped data encryption key (WDEK) that was not  wrapped by the latest version of the
   * key, the service also returns the a  new WDEK, wrapped with the latest version of the key as the ciphertext field.
   * The recommendation is to store and use that WDEK, although older WDEKs will continue to work.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} params.action - The action to perform on the specified key.
   * @param {NodeJS.ReadableStream | Buffer} params.keyActionBody - The base request for key actions.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.KeyActionOneOfResponse>>}
   * @deprecated this method is deprecated and may be removed in a future release
   */
  public actionOnKey(
    params: IbmKeyProtectApiV2.ActionOnKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.KeyActionOneOfResponse>> {
    IbmKeyProtectApiV2._logger.warn('A deprecated operation has been invoked: actionOnKey');
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance', 'action', 'keyActionBody'];
    const _validParams = ['id', 'bluemixInstance', 'action', 'keyActionBody', 'correlationId', 'xKmsKeyRing', 'prefer', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyActionBody;
    const query = {
      'action': _params.action,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'actionOnKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}',
        method: 'POST',
        body,
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key_action+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
            'Prefer': _params.prefer,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Update (patch) a key.
   *
   * Update attributes of a key. Currently only the following attributes are applicable for update: - keyRingID Note: If
   * provided, the `X-Kms-Key-Ring` header should specify the key's current key ring. To change the key ring of the key,
   * specify the new key ring in the request body.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} [params.keyPatchBody] - The base request for patch key.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.PatchKeyResponseBody>>}
   */
  public patchKey(
    params: IbmKeyProtectApiV2.PatchKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.PatchKeyResponseBody>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'keyPatchBody', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyPatchBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'patchKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}',
        method: 'PATCH',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete a key.
   *
   * Deletes a key by specifying the ID or alias of the key.
   *
   * By default, Key Protect requires a single authorization to delete keys. For added protection, you can
   * [enable a dual authorization policy](#set-key-policies) to safely delete keys from your service instance.
   *
   * **Important:** After a key has been deleted, any data that is encrypted by the key becomes inaccessible, though
   * this can be reversed if the key is  restored within the 30-day time frame. After 30 days, key metadata,
   * registrations, and policies are available for up to 90 days, at which  point the key becomes eligible to be purged.
   * Note that once a key is no  longer restorable and has been purged, its associated data can no longer  be accessed.
   *
   * **Note:** By default, Key Protect blocks the deletion of a key that's protecting a cloud resource, such as a Cloud
   * Object Storage bucket. Use
   * `GET keys/{id}/registrations` to verify if the key has an active registration to a resource. To delete the key and
   * its associated registrations, set the optional `force` parameter to `true`.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {boolean} [params.force] - If set to `true`, Key Protect forces deletion on a key that is protecting a cloud
   * resource, such as a Cloud Object Storage bucket. The action removes any registrations that are associated with the
   * key.
   * **Note:** If a key is protecting a cloud resource that has a retention policy, Key Protect cannot delete the key.
   * Use `GET keys/{id}/registrations` to review registrations between the key and its associated cloud resources. To
   * enable deletion, contact an account owner to remove the retention policy on each resource that is associated with
   * this key.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.DeleteKey>>}
   */
  public deleteKey(
    params: IbmKeyProtectApiV2.DeleteKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.DeleteKey>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'prefer', 'force', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'force': _params.force,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}',
        method: 'DELETE',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
            'Prefer': _params.prefer,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve key metadata.
   *
   * Retrieves the details of a key by specifying the ID of the key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyMetadata>>}
   */
  public getKeyMetadata(
    params: IbmKeyProtectApiV2.GetKeyMetadataParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyMetadata>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKeyMetadata');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/metadata',
        method: 'GET',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Purge a deleted key.
   *
   * Purges all key metadata and registrations associated with the specified key.  This method requires setting the
   * [_KeyPurge_
   * permission](https://cloud.ibm.com/docs/key-protect?topic=key-protect-grant-access-keys#grant-access-keys-specific-functions)
   * that is not enabled by default. Purging a key can only be applied to a key in the **Destroyed** (5) state.  After a
   * key is deleted, there is a wait period of up to four hours before purge key operation is allowed.
   * **Important:** When you purge a key, you permanently shred its contents and associated data. The action cannot be
   * reversed.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.PurgeKey>>}
   */
  public purgeKey(
    params: IbmKeyProtectApiV2.PurgeKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.PurgeKey>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'prefer', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'purgeKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/purge',
        method: 'DELETE',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
            'Prefer': _params.prefer,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Restore a key.
   *
   * [Restore a key](/docs/key-protect?topic=key-protect-restore-keys) that has been deleted.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} params.keyRestoreBody - The base request parameters for restore key action.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<NodeJS.ReadableStream>>}
   */
  public restoreKey(
    params: IbmKeyProtectApiV2.RestoreKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<NodeJS.ReadableStream>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance', 'keyRestoreBody'];
    const _validParams = ['id', 'bluemixInstance', 'keyRestoreBody', 'correlationId', 'xKmsKeyRing', 'prefer', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyRestoreBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'restoreKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/restore',
        method: 'POST',
        body,
        path,
        responseType: 'stream',
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/vnd.ibm.kms.key+json',
            'Content-Type': 'application/vnd.ibm.kms.key_action_restore+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
            'Prefer': _params.prefer,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List key versions.
   *
   * Retrieves all versions of a root key by specifying the ID or alias of the key.
   *
   * When you rotate a root key, you generate a new version of the key. If you're using the root key to protect
   * resources across IBM Cloud, the registered cloud services that you associate with the key use the latest key
   * version to wrap your data.
   * [Learn more](/docs/key-protect?topic=key-protect-key-rotation).
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {number} [params.limit] - The number of key versions to retrieve. By default, `GET /versions` returns the
   * first 200 key versions. To retrieve a different set of key versions, use `limit` with `offset` to page through your
   * available resources. The maximum value for `limit` is 5,000.
   * **Usage:** If you have a key with 20 versions in your instance, and you want to retrieve only the first 5 versions,
   * use `../versions?limit=5`.
   * @param {number} [params.offset] - The number of key versions to skip. By specifying `offset`, you retrieve a subset
   * of key versions that starts with the `offset` value. Use `offset` with `limit` to page through your available
   * resources.
   * **Usage:** If you have a key with 100 versions in your instance, and you want to retrieve versions 26 through 50,
   * use `../versions?offset=25&limit=25`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of key versions that match the request,
   * disregarding limit and offset. The default is set to false.
   * **Usage:** To return the `totalCount` value for use with pagination, use `../versions?totalCount=true`.
   * @param {boolean} [params.allKeyStates] - If set to `true`, returns the key versions of a key in any state.
   * **Usage:** If you have deleted a key and still want to retrieve its key versions use
   * `../versions?allKeyStates=true`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeyVersions>>}
   */
  public getKeyVersions(
    params: IbmKeyProtectApiV2.GetKeyVersionsParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeyVersions>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'limit', 'offset', 'totalCount', 'allKeyStates', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'totalCount': _params.totalCount,
      'allKeyStates': _params.allKeyStates,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKeyVersions');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/versions',
        method: 'GET',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * keyActions
   ************************/

  /**
   * Wrap a key.
   *
   * Use a root key to [wrap or encrypt a data encryption key](/docs/key-protect?topic=key-protect-wrap-keys). When
   * present, the ciphertext contains the DEK wrapped by the latest version of the key (WDEK). It is recommended to
   * store and use this WDEK in future calls to Key Protect.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} [params.keyActionWrapBody] - The base request for wrap key action.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.WrapKeyResponseBody>>}
   */
  public wrapKey(
    params: IbmKeyProtectApiV2.WrapKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.WrapKeyResponseBody>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'keyActionWrapBody', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyActionWrapBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'wrapKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/wrap',
        method: 'POST',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key_action_wrap+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Unwrap a key.
   *
   * Use a root key to
   * [unwrap or decrypt a data encryption key](/docs/key-protect?topic=key-protect-unwrap-keys).
   *
   * **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated root key, the service returns a
   * new ciphertext in the response entity-body. Each ciphertext remains available for `unwrap` actions. If you unwrap a
   * DEK with a previous ciphertext, the service also returns the latest ciphertext and latest key version in the
   * response. Use the latest ciphertext for future unwrap operations.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} params.keyActionUnwrapBody - The base request for unwrap key action.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.UnwrapKeyResponseBody>>}
   */
  public unwrapKey(
    params: IbmKeyProtectApiV2.UnwrapKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.UnwrapKeyResponseBody>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance', 'keyActionUnwrapBody'];
    const _validParams = ['id', 'bluemixInstance', 'keyActionUnwrapBody', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyActionUnwrapBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'unwrapKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/unwrap',
        method: 'POST',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key_action_unwrap+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Rewrap a key.
   *
   * Use a root key to [rewrap or reencrypt a data encryption key](/docs/key-protect?topic=key-protect-rewrap-keys).
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} params.keyActionRewrapBody - The base request for rewrap key action.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RewrapKeyResponseBody>>}
   */
  public rewrapKey(
    params: IbmKeyProtectApiV2.RewrapKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RewrapKeyResponseBody>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance', 'keyActionRewrapBody'];
    const _validParams = ['id', 'bluemixInstance', 'keyActionRewrapBody', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyActionRewrapBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'rewrapKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/rewrap',
        method: 'POST',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/vnd.ibm.kms.key_action_rewrap+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Rotate a key.
   *
   * [Create a new version](/docs/key-protect?topic=key-protect-rotate-keys) of a root key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {NodeJS.ReadableStream | Buffer} [params.keyActionRotateBody] - The base request for rotate key action.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.prefer] - Alters server behavior for POST or DELETE operations. A header with
   * `return=minimal` causes the service to return only the key identifier as metadata. A header containing
   * `return=representation` returns both the key material and metadata in the response entity-body. If the key has been
   * designated as a root key, the system cannot return the key material.
   * **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
   * time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public rotateKey(
    params: IbmKeyProtectApiV2.RotateKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'keyActionRotateBody', 'correlationId', 'xKmsKeyRing', 'prefer', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyActionRotateBody;
    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'rotateKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/rotate',
        method: 'POST',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Content-Type': 'application/vnd.ibm.kms.key_action_rotate+json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
            'Prefer': _params.prefer,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Set a key for deletion.
   *
   * [Authorize deletion](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#set-key-deletion-api) for a key with
   * a dual authorization policy.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public setKeyForDeletion(
    params: IbmKeyProtectApiV2.SetKeyForDeletionParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'setKeyForDeletion');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/setKeyForDeletion',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Unset a key for deletion.
   *
   * [Remove an authorization](/docs/key-protect?topic=key-protect-delete-dual-auth-keys#unset-key-deletion-api) for a
   * key with a dual authorization policy.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public unsetKeyForDeletion(
    params: IbmKeyProtectApiV2.UnsetKeyForDeletionParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'unsetKeyForDeletion');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/unsetKeyForDeletion',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Enable a key.
   *
   * [Enable operations](/docs/key-protect?topic=key-protect-disable-keys#enable-api) for a key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public enableKey(
    params: IbmKeyProtectApiV2.EnableKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'enableKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/enable',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Disable a key.
   *
   * [Disable operations](/docs/key-protect?topic=key-protect-disable-keys) for a key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public disableKey(
    params: IbmKeyProtectApiV2.DisableKeyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'disableKey');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/disable',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Sync associated resources.
   *
   * Initiate a [manual data
   * synchronization](/docs/key-protect?topic=key-protect-sync-associated-resources&interface=api) request to the
   * associated resources of a key. Regular key lifecycle events automatically notify integrated services of any change.
   * However, in the case a service does not respond to a key lifecycle event notification after four hours, the
   * `sync` API may be used to initiate a renotification to the integrated services that manage the associated resources
   * linked to the key.
   *
   * **Note:** The services that manage the associated resources linked to the key are responsible for maintaining
   * current records of the key state and version. Key Protect does not have the ability to force data synchronization
   * for other services, which may take up to four hours to complete. The `sync` API is meant to **initiate** a request
   * for all associated resources to synchronize their key records with the information returned from the Key Protect
   * API.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public syncAssociatedResources(
    params: IbmKeyProtectApiV2.SyncAssociatedResourcesParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'syncAssociatedResources');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/actions/sync',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * policies
   ************************/

  /**
   * Set key policies.
   *
   * Creates or updates one or more policies for the specified key.
   *
   * You can set policies for a key, such as an
   * [automatic rotation policy](/docs/key-protect?topic=key-protect-set-rotation-policy) or a
   * [dual authorization policy](/docs/key-protect?topic=key-protect-set-dual-auth-key-policy) to protect against the
   * accidental deletion of keys. Use
   * `PUT /keys/{id}/policies` to create new policies for a key or update an existing policy.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {SetKeyPoliciesOneOf} params.keyPolicyPutBody - The base request for key policy create or update.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.policy] - The type of policy that is associated with the specified key.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyPoliciesOneOf>>}
   */
  public putPolicy(
    params: IbmKeyProtectApiV2.PutPolicyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyPoliciesOneOf>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance', 'keyPolicyPutBody'];
    const _validParams = ['id', 'bluemixInstance', 'keyPolicyPutBody', 'correlationId', 'xKmsKeyRing', 'policy', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.keyPolicyPutBody;
    const query = {
      'policy': _params.policy,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'putPolicy');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/policies',
        method: 'PUT',
        body,
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List key policies.
   *
   * Retrieves a list of policies that are associated with a specified key.
   *
   * You can set policies for a key, such as an
   * [automatic rotation policy](/docs/key-protect?topic=key-protect-set-rotation-policy) or a
   * [dual authorization policy](/docs/key-protect?topic=key-protect-set-dual-auth-key-policy) to protect against the
   * accidental deletion of keys. Use
   * `GET /keys/{id}/policies` to browse the policies that exist for a specified key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.policy] - The type of policy that is associated with the specified key.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyPoliciesOneOf>>}
   */
  public getPolicy(
    params: IbmKeyProtectApiV2.GetPolicyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetKeyPoliciesOneOf>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'policy', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'policy': _params.policy,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getPolicy');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/policies',
        method: 'GET',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Set instance policies.
   *
   * Creates or updates one or more policies for the specified service instance.
   *
   * **Note:** When you set an instance policy, Key Protect associates the policy information with keys that you add to
   * the instance after the policy is updated. This operation does not affect existing keys in the instance.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {SetInstancePoliciesOneOf} params.instancePolicyPutBody - The base request for the create or update of
   * instance level policies.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.policy] - The type of policy that is associated with the specified instance.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public putInstancePolicy(
    params: IbmKeyProtectApiV2.PutInstancePolicyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance', 'instancePolicyPutBody'];
    const _validParams = ['bluemixInstance', 'instancePolicyPutBody', 'correlationId', 'policy', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = _params.instancePolicyPutBody;
    const query = {
      'policy': _params.policy,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'putInstancePolicy');

    const parameters = {
      options: {
        url: '/api/v2/instance/policies',
        method: 'PUT',
        body,
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Content-Type': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List instance policies.
   *
   * Retrieves a list of policies that are associated with a specified service instance.
   *
   * You can manage advanced preferences for keys in your service instance by creating instance-level policies. Use `GET
   * /instance/policies` to browse the policies that are associated with the specified instance. Currently, dual
   * authorization policies are supported.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.policy] - The type of policy that is associated with the specified instance.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetInstancePoliciesOneOf>>}
   */
  public getInstancePolicy(
    params: IbmKeyProtectApiV2.GetInstancePolicyParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetInstancePoliciesOneOf>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'policy', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'policy': _params.policy,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getInstancePolicy');

    const parameters = {
      options: {
        url: '/api/v2/instance/policies',
        method: 'GET',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve allowed IP port.
   *
   * Retrieves the private endpoint port associated with your service instance's active allowed IP policy. If the
   * instance does not contain an active allowed IP policy, no information will be returned.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.AllowedIPPort>>}
   */
  public getAllowedIpPort(
    params: IbmKeyProtectApiV2.GetAllowedIpPortParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.AllowedIPPort>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getAllowedIpPort');

    const parameters = {
      options: {
        url: '/api/v2/instance/allowed_ip_port',
        method: 'GET',
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * importTokens
   ************************/

  /**
   * Create an import token.
   *
   * Creates an import token that you can use to encrypt and import root keys into the service.
   * [Learn more](/docs/key-protect?topic=key-protect-importing-keys#using-import-tokens).
   *
   * When you call `POST /import_token`, Key Protect creates an RSA key-pair from its HSMs. The service encrypts and
   * stores the private key in the HSM, and returns the corresponding public key when you call
   * `GET /import_token`. You can create only one import token per service instance.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {number} [params.expiration] - The time in seconds from the creation of an import token that determines how
   * long its associated public key remains valid. The minimum value is `300` seconds (5 minutes), and the maximum value
   * is `86400` (24 hours). The default value is `600` (10 minutes).
   * @param {number} [params.maxAllowedRetrievals] - The number of times that an import token can be retrieved within
   * its expiration time before it is no longer accessible.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key belongs to. When the header is
   * not specified,  Key Protect will perform a key ring lookup. For a more optimized request,  specify the key ring on
   * every call. The key ring ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ImportToken>>}
   */
  public postImportToken(
    params: IbmKeyProtectApiV2.PostImportTokenParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ImportToken>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'expiration', 'maxAllowedRetrievals', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = {
      'expiration': _params.expiration,
      'maxAllowedRetrievals': _params.maxAllowedRetrievals,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'postImportToken');

    const parameters = {
      options: {
        url: '/api/v2/import_token',
        method: 'POST',
        body,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve an import token.
   *
   * Retrieves the import token that is associated with your service instance.
   *
   * When you call `GET /import_token`, Key Protect returns the public key that you can use to encrypt and import key
   * material to the service, along with details about the key.
   *
   * **Note:** After you reach the `maxAllowedRetrievals` or `expirationDate` for the import token, the import token and
   * its associated public key can no longer be used for key operations. To create a new import token, use
   * `POST /import_token`.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key belongs to. When the header is
   * not specified,  Key Protect will perform a key ring lookup. For a more optimized request,  specify the key ring on
   * every call. The key ring ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetImportToken>>}
   */
  public getImportToken(
    params: IbmKeyProtectApiV2.GetImportTokenParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.GetImportToken>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getImportToken');

    const parameters = {
      options: {
        url: '/api/v2/import_token',
        method: 'GET',
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * registrations
   ************************/

  /**
   * List registrations for a key.
   *
   * Retrieves a list of registrations that are associated with a specified root key.
   *
   * When you use a root key to protect an IBM Cloud resource, such as a Cloud Object Storage bucket, Key Protect
   * creates a registration between the resource and root key. You can use `GET /keys/{id}/registrations` to understand
   * which cloud resources are protected by the key that you specify.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID that uniquely identifies the key.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {number} [params.limit] - The number of registrations to retrieve. By default returns the first 200
   * registrations. To retrieve a different set of registrations, use `limit` with `offset` to page through your
   * available resources. The maximum value for `limit` is 5,000.
   * **Usage:** If you have 20 registrations that are associated with a key, and you want to retrieve only the first 5
   * registrations, use `../registrations?limit=5`.
   * @param {number} [params.offset] - The number of registrations to skip. By specifying `offset`, you retrieve a
   * subset of registrations that starts with the `offset` value. Use `offset` with `limit` to page through your
   * available resources.
   * **Usage:** If you have 100 registrations that are associated with a key, and you want to retrieve registrations 26
   * through 50, use `../registrations?offset=25&limit=25`.
   * @param {string} [params.urlEncodedResourceCrnQuery] - Filters for resources that are associated with a specified
   * [Cloud Resource Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard characters (`*`). The
   * parameter should contain all CRN segments and must be URL encoded. Supports a prefix search when you specify `*` on
   * the last CRN segment.
   * **Usage:** To list registrations that are associated with all resources in `<service-instance>`, use a URL encoded
   * version of the following string:
   * `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:*:*`. To search for subresources,
   * use the following CRN format:
   * `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:<resource-type>:<resource>/<subresource>`.
   * For more examples, see [CRN query
   * examples](/docs/key-protect?topic=key-protect-view-protected-resources#crn-query-examples).
   * @param {boolean} [params.preventKeyDeletion] - Filters registrations based on the `preventKeyDeletion` property.
   * You can use this query parameter to search for registered cloud resources that are non-erasable due to a retention
   * policy. This policy should only be set if a WORM policy
   * (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works) must be
   * satisfied.  Do not set this policy by default.
   * **Usage:** To search for registered cloud resources that have a retention policy, use
   * `../registrations?preventKeyDeletion=true`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of registrations that match the request,
   * disregarding limit and offset.
   * **Usage:** To return the `totalCount` value for use with pagination, use `../registrations?totalCount=true`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RegistrationWithTotalCount>>}
   */
  public getRegistrations(
    params: IbmKeyProtectApiV2.GetRegistrationsParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RegistrationWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'limit', 'offset', 'urlEncodedResourceCrnQuery', 'preventKeyDeletion', 'totalCount', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'urlEncodedResourceCRNQuery': _params.urlEncodedResourceCrnQuery,
      'preventKeyDeletion': _params.preventKeyDeletion,
      'totalCount': _params.totalCount,
    };

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getRegistrations');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/registrations',
        method: 'GET',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List registrations for any key.
   *
   * Retrieves a list of registrations that match the Cloud Resource Name
   * (CRN) query that you specify.
   *
   * When you use a root key to protect an IBM Cloud resource, such as a Cloud Object Storage bucket, Key Protect
   * creates a registration between the resource and root key. You can use `GET /keys/registrations` to understand which
   * cloud resources are protected by keys in your Key Protect service instance.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the target key ring. If unspecified, all resources in the instance
   * that the caller has access to will be returned. When the header  is specified, only resources within the specified
   * key ring, that the caller has access to,  will be returned. The key ring ID of keys that are created without an
   * `X-Kms-Key-Ring` header is: `default`.
   * @param {string} [params.urlEncodedResourceCrnQuery] - Filters for resources that are associated with a specified
   * [Cloud Resource Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard characters (`*`). The
   * parameter should contain all CRN segments and must be URL encoded. If provided, the parameter should not contain
   * (`*`) in the first eight segments. If this parameter is not provided, registrations for all keys in the requested
   * Key Protect instance are returned.
   * @param {number} [params.limit] - The number of registrations to retrieve. By default returns the first 200
   * registrations. To retrieve a different set of registrations, use `limit` with `offset` to page through your
   * available resources. The maximum value for `limit` is 5,000.
   * **Usage:** If you have 20 registrations that are associated with a key, and you want to retrieve only the first 5
   * registrations, use `../registrations?limit=5`.
   * @param {number} [params.offset] - The number of registrations to skip. By specifying `offset`, you retrieve a
   * subset of registrations that starts with the `offset` value. Use `offset` with `limit` to page through your
   * available resources.
   * **Usage:** If you have 100 registrations that are associated with a key, and you want to retrieve registrations 26
   * through 50, use `../registrations?offset=25&limit=25`.
   * @param {boolean} [params.preventKeyDeletion] - Filters registrations based on the `preventKeyDeletion` property.
   * You can use this query parameter to search for registered cloud resources that are non-erasable due to a retention
   * policy. This policy should only be set if a WORM policy
   * (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works) must be
   * satisfied.  Do not set this policy by default.
   * **Usage:** To search for registered cloud resources that have a retention policy, use
   * `../registrations?preventKeyDeletion=true`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of registrations that match the request,
   * disregarding limit and offset.
   * **Usage:** To return the `totalCount` value for use with pagination, use `../registrations?totalCount=true`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RegistrationWithTotalCount>>}
   */
  public getRegistrationsAllKeys(
    params: IbmKeyProtectApiV2.GetRegistrationsAllKeysParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.RegistrationWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'xKmsKeyRing', 'urlEncodedResourceCrnQuery', 'limit', 'offset', 'preventKeyDeletion', 'totalCount', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'urlEncodedResourceCRNQuery': _params.urlEncodedResourceCrnQuery,
      'limit': _params.limit,
      'offset': _params.offset,
      'preventKeyDeletion': _params.preventKeyDeletion,
      'totalCount': _params.totalCount,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getRegistrationsAllKeys');

    const parameters = {
      options: {
        url: '/api/v2/keys/registrations',
        method: 'GET',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * aliases
   ************************/

  /**
   * Create an alias.
   *
   * Creates a unique alias for the specified key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.alias - A human-readable alias that uniquely identifies a key. Each alias is unique  only
   * within the given instance and is not reserved across the Key Protect service.  Each key can have up to five
   * aliases. There is no limit to the number of aliases  per instance. The length of the alias can be between 2 - 90
   * characters, inclusive.  An alias must be alphanumeric and cannot contain spaces or special characters other  than
   * '-' or '_'. Also, the alias cannot be a version 4 UUID and must not be  a Key Protect reserved name: `allowed_ip`,
   * `key`, `keys`, `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`,
   * `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.KeyAlias>>}
   */
  public createKeyAlias(
    params: IbmKeyProtectApiV2.CreateKeyAliasParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.KeyAlias>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'alias', 'bluemixInstance'];
    const _validParams = ['id', 'alias', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
      'alias': _params.alias,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'createKeyAlias');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/aliases/{alias}',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete an alias.
   *
   * Deletes an alias from the associated key.
   *
   * Delete alias does not delete the key.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The v4 UUID or alias that uniquely identifies the key.
   * @param {string} params.alias - A human-readable alias that uniquely identifies a key. Each alias is unique  only
   * within the given instance and is not reserved across the Key Protect service.  Each key can have up to five
   * aliases. There is no limit to the number of aliases  per instance. The length of the alias can be between 2 - 90
   * characters, inclusive.  An alias must be alphanumeric and cannot contain spaces or special characters other  than
   * '-' or '_'. Also, the alias cannot be a version 4 UUID and must not be  a Key Protect reserved name: `allowed_ip`,
   * `key`, `keys`, `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`,
   * `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {string} [params.xKmsKeyRing] - The ID of the key ring that the specified key is a part of. When the  header
   * is not specified, Key Protect will perform a key ring lookup. For  a more optimized request, specify the key ring
   * on every call. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public deleteKeyAlias(
    params: IbmKeyProtectApiV2.DeleteKeyAliasParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'alias', 'bluemixInstance'];
    const _validParams = ['id', 'alias', 'bluemixInstance', 'correlationId', 'xKmsKeyRing', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
      'alias': _params.alias,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKeyAlias');

    const parameters = {
      options: {
        url: '/api/v2/keys/{id}/aliases/{alias}',
        method: 'DELETE',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
            'X-Kms-Key-Ring': _params.xKmsKeyRing,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * keyRings
   ************************/

  /**
   * List key rings.
   *
   * List all key rings in the instance.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {number} [params.limit] - The number of key rings to retrieve. By default, `GET /key_rings` returns  100 key
   * rings including the default key ring. To retrieve a different set of key rings, use `limit` with `offset` to page
   * through your available resources. The maximum value for `limit` is 5,000.
   * **Usage:** If you have 20 key rings in your instance, and you want to retrieve only the first 5 key rings, use
   * `../key_rings?limit=5`.
   * @param {number} [params.offset] - The number of key rings to skip. By specifying `offset`, you retrieve a subset of
   * key rings that starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
   * **Usage:** If you have 20 key rings in your instance, and you want to retrieve keys 10 through 20, use
   * `../keys?offset=10&limit=10`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of key rings that match the request,
   * disregarding limit and offset. The default is set to false.
   * **Usage:** To return the `totalCount` value for use with pagination, use `../key_rings?totalCount=true`.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeyRingsWithTotalCount>>}
   */
  public listKeyRings(
    params: IbmKeyProtectApiV2.ListKeyRingsParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKeyRingsWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'limit', 'offset', 'totalCount', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'totalCount': _params.totalCount,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'listKeyRings');

    const parameters = {
      options: {
        url: '/api/v2/key_rings',
        method: 'GET',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Create a key ring.
   *
   * Create a key ring in the instance with the specified name. The key ring ID `default` is a reserved key ring ID and
   * cannot be created nor destroyed. The `default` key ring is an initial key ring that is generated with each newly
   * created instance. All keys not associated with an otherwise specified key ring exist within the default key ring.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.keyRingId - The ID that identifies the key ring. Each ID is unique only within the given
   * instance and is not reserved across the Key Protect service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public createKeyRing(
    params: IbmKeyProtectApiV2.CreateKeyRingParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['keyRingId', 'bluemixInstance'];
    const _validParams = ['keyRingId', 'bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'key-ring-id': _params.keyRingId,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'createKeyRing');

    const parameters = {
      options: {
        url: '/api/v2/key_rings/{key-ring-id}',
        method: 'POST',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete key ring.
   *
   * Delete the key ring from the instance. The key ring ID `default` cannot be destroyed.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.keyRingId - The ID that identifies the key ring. Each ID is unique only within the given
   * instance and is not reserved across the Key Protect service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {boolean} [params.force] - Force delete the key ring. All keys in the key ring are required to be deleted
   * (in state `5`) before this action can be performed.  If the key ring to be deleted contains keys, they will be
   * moved to the `default` key ring which requires the `kms.secrets.patch` IAM action.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public deleteKeyRing(
    params: IbmKeyProtectApiV2.DeleteKeyRingParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['keyRingId', 'bluemixInstance'];
    const _validParams = ['keyRingId', 'bluemixInstance', 'correlationId', 'force', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'force': _params.force,
    };

    const path = {
      'key-ring-id': _params.keyRingId,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKeyRing');

    const parameters = {
      options: {
        url: '/api/v2/key_rings/{key-ring-id}',
        method: 'DELETE',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
  /*************************
   * kMIPAdapters
   ************************/

  /**
   * List KMIP Adapters.
   *
   * Retrieves a list of KMIP Adapters.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {number} [params.limit] - The number of KMIP Adapters to retrieve. By default, `GET /kmip_adapters` returns
   * the first 100 KMIP Adapters. To retrieve a different set of KMIP adapters, use `limit` with `offset` to page
   * through your available resources. The maximum value for `limit` is 200.
   * **Usage:** If you have 20 KMIP Adapters, and you want to retrieve only the first 5 adapters, use
   * `../kmip_adapters?limit=5`.
   * @param {number} [params.offset] - The number of KMIP adapters to skip. By specifying `offset`, you retrieve a
   * subset of KMIP adapters that starts with the `offset` value. Use `offset` with `limit` to page through your
   * available resources.
   * **Usage:** If you have 20 KMIP Adapters, and you want to retrieve adapters 11 through 15, use
   * `../kmip_adapters?offset=10&limit=5`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of kmip adapters that match the request,
   * disregarding limit and offset. The default is set to false. **Usage:** To return the `totalCount` value for use
   * with pagination, use `../kmip_adapters?totalCount=true`.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdaptersWithTotalCount>>}
   */
  public getKmipAdapters(
    params: IbmKeyProtectApiV2.GetKmipAdaptersParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdaptersWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance'];
    const _validParams = ['bluemixInstance', 'correlationId', 'limit', 'offset', 'totalCount', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'totalCount': _params.totalCount,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipAdapters');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters',
        method: 'GET',
        qs: query,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Create a KMIP Adapter.
   *
   * Creates a KMIP adapter.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {CollectionMetadata} params.metadata - The metadata that describes the resource array.
   * @param {CreateKMIPAdapterRequestBodyResources[]} params.resources - A collection of resources.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdapters>>}
   */
  public createKmipAdapter(
    params: IbmKeyProtectApiV2.CreateKmipAdapterParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdapters>> {
    const _params = { ...params };
    const _requiredParams = ['bluemixInstance', 'metadata', 'resources'];
    const _validParams = ['bluemixInstance', 'metadata', 'resources', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = {
      'metadata': _params.metadata,
      'resources': _params.resources,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'createKmipAdapter');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters',
        method: 'POST',
        body,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve a KMIP Adapter.
   *
   * Retrieves a KMIP adapter using its id / name.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdapters>>}
   */
  public getKmipAdapter(
    params: IbmKeyProtectApiV2.GetKmipAdapterParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPAdapters>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipAdapter');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{id}',
        method: 'GET',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete a KMIP Adapter.
   *
   * Deletes a KMIP Adapter, including all its client certificates, with the given id / name.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.id - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public deleteKmipAdapter(
    params: IbmKeyProtectApiV2.DeleteKmipAdapterParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['id', 'bluemixInstance'];
    const _validParams = ['id', 'bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKmipAdapter');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{id}',
        method: 'DELETE',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List KMIP objects of a KMIP Adapter.
   *
   * List KMIP objects of a KMIP Adapter.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {number} [params.limit] - The number of kmip objects to retrieve. By default, `GET
   * /kmip_adapters/{id}/kmip_objects` returns the first 100 kmip_objects. To retrieve a different set of kmip objects,
   * use `limit` with `offset` to page through your available resources. The maximum value for `limit` is 5000.
   * **Usage:** If you have 20 kmip objects associated with your KMIP adapter, and you want to retrieve only the first 5
   * kmip objects, use `../kmip_adapters/{id}/kmip_objects?limit=5`.
   * @param {number} [params.offset] - The number of kmip objects to skip. By specifying `offset`, you retrieve a subset
   * of kmip objects that starts with the `offset` value. Use `offset` with `limit` to page through your available
   * resources.
   * **Usage:** If you have 20 kmip objects associated with your KMIP adapter, and you want to retrieve kmip objects 11
   * through 15, use `../kmip_adapters/{id}/kmip_objects?offset=10&limit=5`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of kmip objects that match the request,
   * disregarding limit and offset. The default is set to false. **Usage:** To return the `totalCount` value for use
   * with pagination, use `../kmip_adapters/{id}/kmip_objects?totalCount=true`.
   * @param {number[]} [params.state] - List of states to filter the KMIP objects on. The `default` is set to
   * `[1,2,3,4]`. States are integers and correspond to Pre-Active = 1, Active = 2, Deactivated = 3, Compromised = 4,
   * Destroyed = 5, Destroyed Compromised = 6. **Usage:** To filter on multiples `state` values, use
   * `../kmip_adapters/{id}/kmip_objects?state=2,3`.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPObjectsWithTotalCount>>}
   */
  public getKmipObjects(
    params: IbmKeyProtectApiV2.GetKmipObjectsParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPObjectsWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'bluemixInstance'];
    const _validParams = ['adapterId', 'bluemixInstance', 'limit', 'offset', 'totalCount', 'state', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'totalCount': _params.totalCount,
      'state': _params.state,
    };

    const path = {
      'adapter_id': _params.adapterId,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipObjects');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/kmip_objects',
        method: 'GET',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve a KMIP object from a KMIP Adapter.
   *
   * Retrieves a KMIP object from a KMIP Adapter by its id.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} params.id - The v4 UUID of the kmip object that uniquely identifies it.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPObjectsWithTotalCount>>}
   */
  public getKmipObject(
    params: IbmKeyProtectApiV2.GetKmipObjectParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPObjectsWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'bluemixInstance', 'id'];
    const _validParams = ['adapterId', 'bluemixInstance', 'id', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'adapter_id': _params.adapterId,
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipObject');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/kmip_objects/{id}',
        method: 'GET',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete a KMIP object from a KMIP Adapter.
   *
   * Deletes a KMIP object from a KMIP Adapter given its id. Changes the state of the KMIP object to 5 (Destroyed) and
   * erases its key material.  Any data encrypted by this KMIP object will be crypto erased when the KMIP Object changes
   * it state to 5 (Destroyed).
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} params.id - The name or v4 UUID of the client certificate that uniquely identifies it.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public deleteKmipObject(
    params: IbmKeyProtectApiV2.DeleteKmipObjectParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'bluemixInstance', 'id'];
    const _validParams = ['adapterId', 'bluemixInstance', 'id', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'adapter_id': _params.adapterId,
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKmipObject');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/kmip_objects/{id}',
        method: 'DELETE',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * List client certificates of a KMIP Adapter.
   *
   * List client certificates of a KMIP Adapter.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {number} [params.limit] - The number of client certificates to retrieve. By default, `GET
   * /kmip_adapters/{id}/certificates` returns the first 100 certificates. To retrieve a different set of certificates,
   * use `limit` with `offset` to page through your available resources. The maximum value for `limit` is 200.
   * **Usage:** If you have 20 certificates associated with your KMIP adapter, and you want to retrieve only the first 5
   * certificates, use `../kmip_adapters/{id}/certificates?limit=5`.
   * @param {number} [params.offset] - The number of client certificates to skip. By specifying `offset`, you retrieve a
   * subset of certificates that starts with the `offset` value. Use `offset` with `limit` to page through your
   * available resources.
   * **Usage:** If you have 20 certificates associated with your KMIP adapter, and you want to retrieve certificates 11
   * through 15, use `../kmip_adapters/{id}/certificates?offset=10&limit=5`.
   * @param {boolean} [params.totalCount] - If set to `true`, returns `totalCount` in the response metadata for use with
   * pagination. The `totalCount` value returned specifies the total number of client certificates that match the
   * request, disregarding limit and offset. The default is set to false. **Usage:** To return the `totalCount` value
   * for use with pagination, use `../kmip_adapters/{id}/certificates?totalCount=true`.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPPartialClientCertificatesWithTotalCount>>}
   */
  public getKmipClientCertificates(
    params: IbmKeyProtectApiV2.GetKmipClientCertificatesParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPPartialClientCertificatesWithTotalCount>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'bluemixInstance'];
    const _validParams = ['adapterId', 'bluemixInstance', 'limit', 'offset', 'totalCount', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const query = {
      'limit': _params.limit,
      'offset': _params.offset,
      'totalCount': _params.totalCount,
    };

    const path = {
      'adapter_id': _params.adapterId,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipClientCertificates');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/certificates',
        method: 'GET',
        qs: query,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Add a client certificate to a KMIP Adapter.
   *
   * Add a client certificate to a KMIP Adapter. It might take up to 5 minutes for a KMIP call using the newly add
   * certificate to pass authentication. A maximum of 200 client certificates can be associated with a KMIP Adapter at a
   * time.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {CollectionMetadata} params.metadata - The metadata that describes the resource array.
   * @param {CreateKMIPClientCertificateObject[]} params.resources - A collection of resources.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPClientCertificates>>}
   */
  public addKmipClientCertificate(
    params: IbmKeyProtectApiV2.AddKmipClientCertificateParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPClientCertificates>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'bluemixInstance', 'metadata', 'resources'];
    const _validParams = ['adapterId', 'bluemixInstance', 'metadata', 'resources', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const body = {
      'metadata': _params.metadata,
      'resources': _params.resources,
    };

    const path = {
      'adapter_id': _params.adapterId,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'addKmipClientCertificate');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/certificates',
        method: 'POST',
        body,
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Retrieve a client certificate from a KMIP Adapter.
   *
   * Retrieves a client certificate from a KMIP Adapter using its id / name.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.id - The name or v4 UUID of the client certificate that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPClientCertificates>>}
   */
  public getKmipClientCertificate(
    params: IbmKeyProtectApiV2.GetKmipClientCertificateParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.ListKMIPClientCertificates>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'id', 'bluemixInstance'];
    const _validParams = ['adapterId', 'id', 'bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'adapter_id': _params.adapterId,
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'getKmipClientCertificate');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/certificates/{id}',
        method: 'GET',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Accept': 'application/json',
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }

  /**
   * Delete a client certificate from a KMIP Adapter.
   *
   * Removes a client certificate from a KMIP Adapter given its id / name. It might take up to 5 minutes for a KMIP call
   * using deleted certificate to fail authentication.
   *
   * @param {Object} params - The parameters to send to the service.
   * @param {string} params.adapterId - The name or v4 UUID of the KMIP Adapter that uniquely identifies it.
   * @param {string} params.id - The name or v4 UUID of the client certificate that uniquely identifies it.
   * @param {string} params.bluemixInstance - The IBM Cloud instance ID that identifies your Key Protect service
   * instance.
   * @param {string} [params.correlationId] - The v4 UUID used to correlate and track transactions.
   * @param {OutgoingHttpHeaders} [params.headers] - Custom request headers
   * @returns {Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>>}
   */
  public deleteKmipClientCertificate(
    params: IbmKeyProtectApiV2.DeleteKmipClientCertificateParams
  ): Promise<IbmKeyProtectApiV2.Response<IbmKeyProtectApiV2.EmptyObject>> {
    const _params = { ...params };
    const _requiredParams = ['adapterId', 'id', 'bluemixInstance'];
    const _validParams = ['adapterId', 'id', 'bluemixInstance', 'correlationId', 'headers'];
    const _validationErrors = validateParams(_params, _requiredParams, _validParams);
    if (_validationErrors) {
      return Promise.reject(_validationErrors);
    }

    const path = {
      'adapter_id': _params.adapterId,
      'id': _params.id,
    };

    const sdkHeaders = getSdkHeaders(IbmKeyProtectApiV2.DEFAULT_SERVICE_NAME, 'v2', 'deleteKmipClientCertificate');

    const parameters = {
      options: {
        url: '/api/v2/kmip_adapters/{adapter_id}/certificates/{id}',
        method: 'DELETE',
        path,
      },
      defaultOptions: extend(true, {}, this.baseOptions, {
        headers: extend(
          true,
          sdkHeaders,
          {
            'Bluemix-Instance': _params.bluemixInstance,
            'Correlation-Id': _params.correlationId,
          },
          _params.headers
        ),
      }),
    };

    return this.createRequest(parameters);
  }
}

/*************************
 * interfaces
 ************************/

namespace IbmKeyProtectApiV2 {
  /** An operation response. */
  export interface Response<T = any> {
    result: T;
    status: number;
    statusText: string;
    headers: IncomingHttpHeaders;
  }

  /** The callback for a service request. */
  export type Callback<T> = (error: any, response?: Response<T>) => void;

  /** The body of a service request that returns no response data. */
  export interface EmptyObject {}

  /** A standard JS object, defined to avoid the limitations of `Object` and `object` */
  export interface JsonObject {
    [key: string]: any;
  }

  /*************************
   * request interfaces
   ************************/

  /** Parameters for the `getKeyCollectionMetadata` operation. */
  export interface GetKeyCollectionMetadataParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The state of the keys to be retrieved. States must be a list of integers from 0 to 5 delimited by commas
     *  with no whitespace or trailing commas. Valid states are based on NIST SP 800-57. States are integers and
     *  correspond to the Pre-activation = 0, Active = 1, Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
     *  **Usage:** If you want to retrieve active and deleted keys, use `../keys?state=1,5`.
     */
    state?: number[];
    /** The type of keys to be retrieved. Filters keys based on the `extractable` property. You can use this query
     *  parameter to search for keys whose material can leave the service. If set to `true`, standard keys will be
     *  retrieved. If set to `false`, root keys will be retrieved. If omitted, both root and standard keys will be
     *  retrieved.
     *  **Usage:** If you want to retrieve standard keys, use `../keys?extractable=true`.
     */
    extractable?: boolean;
    /** When provided, returns the list of keys that match the queried properties. Each key property to be filtered
     *  on is specified as the property name itself, followed by an “=“ symbol,  and then the value to filter on,
     *  followed by a space if there are more properties to filter only. Note: Anything between `<` and `>` in the
     *  examples or descriptions represent placeholder to specify the value
     *  *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to filter on may contain a value related
     *  to the property itself, or an operator followed by a value accepted by the operator - Only one operator and
     *  value, or one value is accepted per property at a time
     *  *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to three of the same property may be
     *  specified at a time. The key properties that can be filtered at this time are:
     *  - `creationDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `deletionDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `expirationDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `extractable`
     *    * Boolean true or false without quotes, case-insensitive
     *  - `lastRotateDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `lastUpdateDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `state`
     *    * A list of comma-separated integers with no space in between: 0,1,2,3,5 Comparison operations (operators)
     *  that can be performed on date values are:
     *  - `lte:<value>` Less than or equal to - `lt:<value>` Less than - `gte:<value>` Greater than or equal to -
     *  `gt:<value>` Greater than A special keyword for date, `none` (case-insensitive), may be used to retreive keys
     *  that do not have that property. This is useful for `lastRotateDate`, where only keys that have never been
     *  rotated can be  retreived.
     *  *Examples*:
     *  - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last rotated on February 15, 2022 -
     *  `lastRotateDate=gte:"2022-02-15T00:00:00Z"` Filter keys that were last rotated after or on February 15, 2022 -
     *  `lastRotateDate=gte:"2022-02-15T00:00:00Z" lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
     *  rotated after or on February 15, 2022 but before (not including) March 15, 2022 -
     *  `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5 extractable=false` Filter root keys that were last
     *  rotated on February 15, 2022, with any state
     *  *Note*: When you filter by `state` or `extractable` in this query parameter, you will not be able to use the
     *  deprecated `state` or `extractable` independent query parameter. You will get a 400 response code if you specify
     *  a value for one of the two properties in both this filter query parameter and the deprecated independent query
     *  of the same name (the same applies vice versa).
     */
    filter?: string;
    /** The ID of the target key ring. If unspecified, all resources in the instance that the caller has access to
     *  will be returned. When the header  is specified, only resources within the specified key ring, that the caller
     *  has access to,  will be returned. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header
     *  is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `createKey` operation. */
  export interface CreateKeyParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for creating a new key. */
    keyCreateBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: CreateKeyConstants.Prefer | string;
    /** The ID of the key ring that the specified key belongs to. When the header is not specified,  Key Protect
     *  will perform a key ring lookup. For a more optimized request,  specify the key ring on every call. The key ring
     *  ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `createKey` operation. */
  export namespace CreateKeyConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `getKeys` operation. */
  export interface GetKeysParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The number of keys to retrieve. By default, `GET /keys` returns the first 200 keys. To retrieve a different
     *  set of keys, use `limit` with `offset` to page through your available resources. The maximum value for `limit`
     *  is 5,000.
     *  **Usage:** If you have 20 keys in your instance, and you want to retrieve only the first 5 keys, use
     *  `../keys?limit=5`.
     */
    limit?: number;
    /** The number of keys to skip. By specifying `offset`, you retrieve a subset of keys that starts with the
     *  `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 100 keys in your instance, and you want to retrieve keys 26 through 50, use
     *  `../keys?offset=25&limit=25`.
     */
    offset?: number;
    /** The state of the keys to be retrieved. States must be a list of integers from 0 to 5 delimited by commas
     *  with no whitespace or trailing commas. Valid states are based on NIST SP 800-57. States are integers and
     *  correspond to the Pre-activation = 0, Active = 1, Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
     *  **Usage:** If you want to retrieve active and deleted keys, use `../keys?state=1,5`.
     */
    state?: number[];
    /** The type of keys to be retrieved. Filters keys based on the `extractable` property. You can use this query
     *  parameter to search for keys whose material can leave the service. If set to `true`, standard keys will be
     *  retrieved. If set to `false`, root keys will be retrieved. If omitted, both root and standard keys will be
     *  retrieved.
     *  **Usage:** If you want to retrieve standard keys, use `../keys?extractable=true`.
     */
    extractable?: boolean;
    /** When provided, performs a search, possibly limiting the number of keys returned.
     *  *Examples*:
     *
     *    - `foobar` - find keys where the name or any of its aliases contain `foobar`, case insentive (i.e. matches
     *  `xfoobar`, `Foobar`).
     *    - `fadedbee-0000-0000-0000-1234567890ab` (a valid key id) - find keys where the id the key is
     *  `fadedbee-0000-0000-0000-1234567890ab`, or the name or any of its aliases contain
     *  `fadedbee-0000-0000-0000-1234567890ab`, case insentive.
     *
     *  May prepend with options:
     *
     *    - `not:` = when specified, inverts matching logic (example: `not:foo` will search for keys that have aliases
     *  or names that do not contain `foo`)
     *    - `escape:` = everything after this option is take as plaintext (example: `escape:not:` will search for keys
     *  that have an alias or name containing the substring `not:`)
     *    - `exact:` = only looks for exact matches
     *
     *  May prepend with search scopes:
     *
     *    - `alias:` = search in key aliases for search query
     *    - `name:` = search in key names for search query
     *
     *  *Examples*:
     *
     *    - `not:exact:foobar`/`exact:not:foobar` - find keys where the name nor any of its aliases are *not* exactly
     *  `foobar` (i.e. matches `xfoobar`, `bar`, `foo`)
     *    - `exact:escape:not:foobar` - find keys where the name or any of its aliases are exactly `not:foobar`
     *    - `not:alias:foobar`/`alias:not:foobar` - find keys where any of its aliases do *not* contain `foobar`
     *    - `name:exact:foobar`/`exact:name:foobar` - find keys where the name is exactly `foobar`
     *
     *  *Note*:
     *
     *    By default, if no scopes are provided, search will be performed in both `name` and `alias` scopes.
     *
     *    Search is only possible on a intial searchable space of at most 5000 keys. If the initial seachable space is
     *  greater than 5000 keys, the API returns HTTP 400 with the property resouces[0].reasons[0].code equals to
     *  'KEY_SEARCH_TOO_BROAD'.
     *    Use the following filters to reduce the initial searchable space:
     *
     *    - `state` (query parameter)
     *    - `extractable` (query parameter)
     *    - `X-Kms-Key-Ring` (HTTP header)
     *
     *    If the total intial searchable space exceeds the 5000 keys limit and when providing a fully specified key id
     *  or when searching within the `alias` scope, a lookup
     *    will  be performed and if a key is found, the key will be returned as the only resource and in the response
     *  metadata the property `incompleteSearch` will
     *    be `true`.
     *
     *    When providing a fully specified key id or when searching within the `alias` scope, a key lookup is performed
     *  in addition to the search.
     *    This means search will try to lookup a single key that is uniquely identified by the key id or provided alias,
     *  this key will be included in the response
     *    as the first resource, before other matches.
     *
     *    Search scopes are disjunctive, behaving in an *OR* manner. When using more than one search scope,
     *    a match in at least one of the scopes will result in the key being returned.
     */
    search?: string;
    /** When provided, sorts the list of keys returned based on one or more key properties. To sort on a property in
     *  descending order, prefix the term with "-". To sort on multiple key properties, use a comma to separate each
     *  properties. The first property in the comma-separated list will be evaluated before the next. The key properties
     *  that can be sorted at this time are:
     *    - `id`
     *    - `state`
     *    - `extractable`
     *    - `imported`
     *    - `creationDate`
     *    - `lastUpdateDate`
     *    - `lastRotateDate`
     *    - `deletionDate`
     *    - `expirationDate`
     *
     *  The list of keys returned is sorted on id by default, if this parameter is not provided.
     */
    sort?: GetKeysConstants.Sort | string;
    /** When provided, returns the list of keys that match the queried properties. Each key property to be filtered
     *  on is specified as the property name itself, followed by an “=“ symbol,  and then the value to filter on,
     *  followed by a space if there are more properties to filter only. Note: Anything between `<` and `>` in the
     *  examples or descriptions represent placeholder to specify the value
     *  *Basic format*: <propertyA>=<valueB> <propertyB>=<valueB> - The value to filter on may contain a value related
     *  to the property itself, or an operator followed by a value accepted by the operator - Only one operator and
     *  value, or one value is accepted per property at a time
     *  *Format with operator/value pair*: <propertyA>=<operatorA>:<valueA> Up to three of the same property may be
     *  specified at a time. The key properties that can be filtered at this time are:
     *  - `creationDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `deletionDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `expirationDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `extractable`
     *    * Boolean true or false without quotes, case-insensitive
     *  - `lastRotateDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `lastUpdateDate`
     *    * Date in RFC 3339 format in double-quotes: “YYYY-MM-DDTHH:mm:SSZ”
     *  - `state`
     *    * A list of comma-separated integers with no space in between: 0,1,2,3,5 Comparison operations (operators)
     *  that can be performed on date values are:
     *  - `lte:<value>` Less than or equal to - `lt:<value>` Less than - `gte:<value>` Greater than or equal to -
     *  `gt:<value>` Greater than A special keyword for date, `none` (case-insensitive), may be used to retreive keys
     *  that do not have that property. This is useful for `lastRotateDate`, where only keys that have never been
     *  rotated can be  retreived.
     *  *Examples*:
     *  - `lastRotateDate="2022-02-15T00:00:00Z"` Filter keys that were last rotated on February 15, 2022 -
     *  `lastRotateDate=gte:"2022-02-15T00:00:00Z"` Filter keys that were last rotated after or on February 15, 2022 -
     *  `lastRotateDate=gte:"2022-02-15T00:00:00Z" lastRotateDate=lt:"2022-03-15T00:00:00Z"` Filter keys that were last
     *  rotated after or on February 15, 2022 but before (not including) March 15, 2022 -
     *  `lastRotateDate="2022-02-15T00:00:00Z" state=0,1,2,3,5 extractable=false` Filter root keys that were last
     *  rotated on February 15, 2022, with any state
     *  *Note*: When you filter by `state` or `extractable` in this query parameter, you will not be able to use the
     *  deprecated `state` or `extractable` independent query parameter. You will get a 400 response code if you specify
     *  a value for one of the two properties in both this filter query parameter and the deprecated independent query
     *  of the same name (the same applies vice versa).
     */
    filter?: string;
    /** The ID of the target key ring. If unspecified, all resources in the instance that the caller has access to
     *  will be returned. When the header  is specified, only resources within the specified key ring, that the caller
     *  has access to,  will be returned. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header
     *  is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `getKeys` operation. */
  export namespace GetKeysConstants {
    /** When provided, sorts the list of keys returned based on one or more key properties. To sort on a property in descending order, prefix the term with "-". To sort on multiple key properties, use a comma to separate each properties. The first property in the comma-separated list will be evaluated before the next. The key properties that can be sorted at this time are: - `id` - `state` - `extractable` - `imported` - `creationDate` - `lastUpdateDate` - `lastRotateDate` - `deletionDate` - `expirationDate` The list of keys returned is sorted on id by default, if this parameter is not provided. */
    export enum Sort {
      ID = 'id',
      STATE = 'state',
      EXTRACTABLE = 'extractable',
      IMPORTED = 'imported',
      CREATIONDATE = 'creationDate',
      LASTUPDATEDATE = 'lastUpdateDate',
      LASTROTATEDATE = 'lastRotateDate',
      DELETIONDATE = 'deletionDate',
      EXPIRATIONDATE = 'expirationDate',
    }
  }

  /** Parameters for the `createKeyWithPoliciesOverrides` operation. */
  export interface CreateKeyWithPoliciesOverridesParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for creating a new key with policies. */
    keyWithPolicyOverridesCreateBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: CreateKeyWithPoliciesOverridesConstants.Prefer | string;
    /** The ID of the key ring that the specified key belongs to. When the header is not specified,  Key Protect
     *  will perform a key ring lookup. For a more optimized request,  specify the key ring on every call. The key ring
     *  ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `createKeyWithPoliciesOverrides` operation. */
  export namespace CreateKeyWithPoliciesOverridesConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `getKey` operation. */
  export interface GetKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `actionOnKey` operation. */
  export interface ActionOnKeyParams {
    /** The v4 UUID that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The action to perform on the specified key. */
    action: ActionOnKeyConstants.Action | string;
    /** The base request for key actions. */
    keyActionBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: ActionOnKeyConstants.Prefer | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `actionOnKey` operation. */
  export namespace ActionOnKeyConstants {
    /** The action to perform on the specified key. */
    export enum Action {
      DISABLE = 'disable',
      ENABLE = 'enable',
      RESTORE = 'restore',
      REWRAP = 'rewrap',
      ROTATE = 'rotate',
      SETKEYFORDELETION = 'setKeyForDeletion',
      UNSETKEYFORDELETION = 'unsetKeyForDeletion',
      UNWRAP = 'unwrap',
      WRAP = 'wrap',
    }
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `patchKey` operation. */
  export interface PatchKeyParams {
    /** The v4 UUID that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for patch key. */
    keyPatchBody?: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKey` operation. */
  export interface DeleteKeyParams {
    /** The v4 UUID that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: DeleteKeyConstants.Prefer | string;
    /** If set to `true`, Key Protect forces deletion on a key that is protecting a cloud resource, such as a Cloud
     *  Object Storage bucket. The action removes any registrations that are associated with the key.
     *  **Note:** If a key is protecting a cloud resource that has a retention policy, Key Protect cannot delete the
     *  key. Use `GET keys/{id}/registrations` to review registrations between the key and its associated cloud
     *  resources. To enable deletion, contact an account owner to remove the retention policy on each resource that is
     *  associated with this key.
     */
    force?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `deleteKey` operation. */
  export namespace DeleteKeyConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `getKeyMetadata` operation. */
  export interface GetKeyMetadataParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `purgeKey` operation. */
  export interface PurgeKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: PurgeKeyConstants.Prefer | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `purgeKey` operation. */
  export namespace PurgeKeyConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `restoreKey` operation. */
  export interface RestoreKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request parameters for restore key action. */
    keyRestoreBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: RestoreKeyConstants.Prefer | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `restoreKey` operation. */
  export namespace RestoreKeyConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `getKeyVersions` operation. */
  export interface GetKeyVersionsParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** The number of key versions to retrieve. By default, `GET /versions` returns the first 200 key versions. To
     *  retrieve a different set of key versions, use `limit` with `offset` to page through your available resources.
     *  The maximum value for `limit` is 5,000.
     *  **Usage:** If you have a key with 20 versions in your instance, and you want to retrieve only the first 5
     *  versions, use `../versions?limit=5`.
     */
    limit?: number;
    /** The number of key versions to skip. By specifying `offset`, you retrieve a subset of key versions that
     *  starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have a key with 100 versions in your instance, and you want to retrieve versions 26 through
     *  50, use `../versions?offset=25&limit=25`.
     */
    offset?: number;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of key versions that match the request, disregarding limit and offset.
     *  The default is set to false.
     *  **Usage:** To return the `totalCount` value for use with pagination, use `../versions?totalCount=true`.
     */
    totalCount?: boolean;
    /** If set to `true`, returns the key versions of a key in any state. **Usage:** If you have deleted a key and
     *  still want to retrieve its key versions use `../versions?allKeyStates=true`.
     */
    allKeyStates?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `wrapKey` operation. */
  export interface WrapKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for wrap key action. */
    keyActionWrapBody?: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `unwrapKey` operation. */
  export interface UnwrapKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for unwrap key action. */
    keyActionUnwrapBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `rewrapKey` operation. */
  export interface RewrapKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for rewrap key action. */
    keyActionRewrapBody: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `rotateKey` operation. */
  export interface RotateKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for rotate key action. */
    keyActionRotateBody?: NodeJS.ReadableStream | Buffer;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to
     *  return only the key identifier as metadata. A header containing `return=representation` returns both the key
     *  material and metadata in the response entity-body. If the key has been designated as a root key, the system
     *  cannot return the key material.
     *  **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation
     *  time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request.
     */
    prefer?: RotateKeyConstants.Prefer | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `rotateKey` operation. */
  export namespace RotateKeyConstants {
    /** Alters server behavior for POST or DELETE operations. A header with `return=minimal` causes the service to return only the key identifier as metadata. A header containing `return=representation` returns both the key material and metadata in the response entity-body. If the key has been designated as a root key, the system cannot return the key material. **Note:** During POST operations, Key Protect may not immediately return the key material due to key generation time. To retrieve the key material, you can perform a subsequent `GET /keys/{id}` request. */
    export enum Prefer {
      RETURN_REPRESENTATION = 'return=representation',
      RETURN_MINIMAL = 'return=minimal',
    }
  }

  /** Parameters for the `setKeyForDeletion` operation. */
  export interface SetKeyForDeletionParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `unsetKeyForDeletion` operation. */
  export interface UnsetKeyForDeletionParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `enableKey` operation. */
  export interface EnableKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `disableKey` operation. */
  export interface DisableKeyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `syncAssociatedResources` operation. */
  export interface SyncAssociatedResourcesParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `putPolicy` operation. */
  export interface PutPolicyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for key policy create or update. */
    keyPolicyPutBody: SetKeyPoliciesOneOf;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** The type of policy that is associated with the specified key. */
    policy?: PutPolicyConstants.Policy | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `putPolicy` operation. */
  export namespace PutPolicyConstants {
    /** The type of policy that is associated with the specified key. */
    export enum Policy {
      DUALAUTHDELETE = 'dualAuthDelete',
      ROTATION = 'rotation',
    }
  }

  /** Parameters for the `getPolicy` operation. */
  export interface GetPolicyParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** The type of policy that is associated with the specified key. */
    policy?: GetPolicyConstants.Policy | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `getPolicy` operation. */
  export namespace GetPolicyConstants {
    /** The type of policy that is associated with the specified key. */
    export enum Policy {
      DUALAUTHDELETE = 'dualAuthDelete',
      ROTATION = 'rotation',
    }
  }

  /** Parameters for the `putInstancePolicy` operation. */
  export interface PutInstancePolicyParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The base request for the create or update of instance level policies. */
    instancePolicyPutBody: SetInstancePoliciesOneOf;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The type of policy that is associated with the specified instance. */
    policy?: PutInstancePolicyConstants.Policy | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `putInstancePolicy` operation. */
  export namespace PutInstancePolicyConstants {
    /** The type of policy that is associated with the specified instance. */
    export enum Policy {
      ALLOWEDNETWORK = 'allowedNetwork',
      DUALAUTHDELETE = 'dualAuthDelete',
      ALLOWEDIP = 'allowedIP',
      KEYCREATEIMPORTACCESS = 'keyCreateImportAccess',
      METRICS = 'metrics',
      ROTATION = 'rotation',
    }
  }

  /** Parameters for the `getInstancePolicy` operation. */
  export interface GetInstancePolicyParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The type of policy that is associated with the specified instance. */
    policy?: GetInstancePolicyConstants.Policy | string;
    headers?: OutgoingHttpHeaders;
  }

  /** Constants for the `getInstancePolicy` operation. */
  export namespace GetInstancePolicyConstants {
    /** The type of policy that is associated with the specified instance. */
    export enum Policy {
      ALLOWEDNETWORK = 'allowedNetwork',
      DUALAUTHDELETE = 'dualAuthDelete',
      ALLOWEDIP = 'allowedIP',
      KEYCREATEIMPORTACCESS = 'keyCreateImportAccess',
      METRICS = 'metrics',
      ROTATION = 'rotation',
    }
  }

  /** Parameters for the `getAllowedIpPort` operation. */
  export interface GetAllowedIpPortParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `postImportToken` operation. */
  export interface PostImportTokenParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The time in seconds from the creation of an import token that determines how long its associated public key
     *  remains valid. The minimum value is `300` seconds (5 minutes), and the maximum value is `86400` (24 hours). The
     *  default value is `600` (10 minutes).
     */
    expiration?: number;
    /** The number of times that an import token can be retrieved within its expiration time before it is no longer
     *  accessible.
     */
    maxAllowedRetrievals?: number;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key belongs to. When the header is not specified,  Key Protect
     *  will perform a key ring lookup. For a more optimized request,  specify the key ring on every call. The key ring
     *  ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getImportToken` operation. */
  export interface GetImportTokenParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key belongs to. When the header is not specified,  Key Protect
     *  will perform a key ring lookup. For a more optimized request,  specify the key ring on every call. The key ring
     *  ID of keys that are created without an  `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getRegistrations` operation. */
  export interface GetRegistrationsParams {
    /** The v4 UUID that uniquely identifies the key. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    /** The number of registrations to retrieve. By default returns the first 200 registrations. To retrieve a
     *  different set of registrations, use `limit` with `offset` to page through your available resources. The maximum
     *  value for `limit` is 5,000.
     *  **Usage:** If you have 20 registrations that are associated with a key, and you want to retrieve only the first
     *  5 registrations, use `../registrations?limit=5`.
     */
    limit?: number;
    /** The number of registrations to skip. By specifying `offset`, you retrieve a subset of registrations that
     *  starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 100 registrations that are associated with a key, and you want to retrieve registrations
     *  26 through 50, use `../registrations?offset=25&limit=25`.
     */
    offset?: number;
    /** Filters for resources that are associated with a specified [Cloud Resource
     *  Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard characters (`*`). The parameter
     *  should contain all CRN segments and must be URL encoded. Supports a prefix search when you specify `*` on the
     *  last CRN segment.
     *  **Usage:** To list registrations that are associated with all resources in `<service-instance>`, use a URL
     *  encoded version of the following string:
     *  `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:*:*`. To search for
     *  subresources, use the following CRN format:
     *  `crn:v1:bluemix:public:<service-name>:<location>:a/<account>:<service-instance>:<resource-type>:<resource>/<subresource>`.
     *  For more examples, see [CRN query
     *  examples](/docs/key-protect?topic=key-protect-view-protected-resources#crn-query-examples).
     */
    urlEncodedResourceCrnQuery?: string;
    /** Filters registrations based on the `preventKeyDeletion` property. You can use this query parameter to search
     *  for registered cloud resources that are non-erasable due to a retention policy. This policy should only be set
     *  if a WORM policy
     *  (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works) must be
     *  satisfied.  Do not set this policy by default.
     *  **Usage:** To search for registered cloud resources that have a retention policy, use
     *  `../registrations?preventKeyDeletion=true`.
     */
    preventKeyDeletion?: boolean;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of registrations that match the request, disregarding limit and
     *  offset.
     *  **Usage:** To return the `totalCount` value for use with pagination, use `../registrations?totalCount=true`.
     */
    totalCount?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getRegistrationsAllKeys` operation. */
  export interface GetRegistrationsAllKeysParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the target key ring. If unspecified, all resources in the instance that the caller has access to
     *  will be returned. When the header  is specified, only resources within the specified key ring, that the caller
     *  has access to,  will be returned. The key ring ID of keys that are created without an `X-Kms-Key-Ring` header
     *  is: `default`.
     */
    xKmsKeyRing?: string;
    /** Filters for resources that are associated with a specified [Cloud Resource
     *  Name](/docs/account?topic=account-crn) (CRN) by using URL encoded wildcard characters (`*`). The parameter
     *  should contain all CRN segments and must be URL encoded. If provided, the parameter should not contain (`*`) in
     *  the first eight segments. If this parameter is not provided, registrations for all keys in the requested Key
     *  Protect instance are returned.
     */
    urlEncodedResourceCrnQuery?: string;
    /** The number of registrations to retrieve. By default returns the first 200 registrations. To retrieve a
     *  different set of registrations, use `limit` with `offset` to page through your available resources. The maximum
     *  value for `limit` is 5,000.
     *  **Usage:** If you have 20 registrations that are associated with a key, and you want to retrieve only the first
     *  5 registrations, use `../registrations?limit=5`.
     */
    limit?: number;
    /** The number of registrations to skip. By specifying `offset`, you retrieve a subset of registrations that
     *  starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 100 registrations that are associated with a key, and you want to retrieve registrations
     *  26 through 50, use `../registrations?offset=25&limit=25`.
     */
    offset?: number;
    /** Filters registrations based on the `preventKeyDeletion` property. You can use this query parameter to search
     *  for registered cloud resources that are non-erasable due to a retention policy. This policy should only be set
     *  if a WORM policy
     *  (https://www.ibm.com/docs/en/spectrum-scale/5.0.1?topic=ics-how-write-once-read-many-worm-storage-works) must be
     *  satisfied.  Do not set this policy by default.
     *  **Usage:** To search for registered cloud resources that have a retention policy, use
     *  `../registrations?preventKeyDeletion=true`.
     */
    preventKeyDeletion?: boolean;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of registrations that match the request, disregarding limit and
     *  offset.
     *  **Usage:** To return the `totalCount` value for use with pagination, use `../registrations?totalCount=true`.
     */
    totalCount?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `createKeyAlias` operation. */
  export interface CreateKeyAliasParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** A human-readable alias that uniquely identifies a key. Each alias is unique  only within the given instance
     *  and is not reserved across the Key Protect service.  Each key can have up to five aliases. There is no limit to
     *  the number of aliases  per instance. The length of the alias can be between 2 - 90 characters, inclusive.  An
     *  alias must be alphanumeric and cannot contain spaces or special characters other  than '-' or '_'. Also, the
     *  alias cannot be a version 4 UUID and must not be  a Key Protect reserved name: `allowed_ip`, `key`, `keys`,
     *  `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`,
     *  `rewrap`, `version`, `versions`.
     */
    alias: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKeyAlias` operation. */
  export interface DeleteKeyAliasParams {
    /** The v4 UUID or alias that uniquely identifies the key. */
    id: string;
    /** A human-readable alias that uniquely identifies a key. Each alias is unique  only within the given instance
     *  and is not reserved across the Key Protect service.  Each key can have up to five aliases. There is no limit to
     *  the number of aliases  per instance. The length of the alias can be between 2 - 90 characters, inclusive.  An
     *  alias must be alphanumeric and cannot contain spaces or special characters other  than '-' or '_'. Also, the
     *  alias cannot be a version 4 UUID and must not be  a Key Protect reserved name: `allowed_ip`, `key`, `keys`,
     *  `metadata`, `policy`, `policies`, `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`,
     *  `rewrap`, `version`, `versions`.
     */
    alias: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The ID of the key ring that the specified key is a part of. When the  header is not specified, Key Protect
     *  will perform a key ring lookup. For  a more optimized request, specify the key ring on every call. The key ring
     *  ID of keys that are created without an `X-Kms-Key-Ring` header is: `default`.
     */
    xKmsKeyRing?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `listKeyRings` operation. */
  export interface ListKeyRingsParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The number of key rings to retrieve. By default, `GET /key_rings` returns  100 key rings including the
     *  default key ring. To retrieve a different set of key rings, use `limit` with `offset` to page through your
     *  available resources. The maximum value for `limit` is 5,000.
     *  **Usage:** If you have 20 key rings in your instance, and you want to retrieve only the first 5 key rings, use
     *  `../key_rings?limit=5`.
     */
    limit?: number;
    /** The number of key rings to skip. By specifying `offset`, you retrieve a subset of key rings that starts with
     *  the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 20 key rings in your instance, and you want to retrieve keys 10 through 20, use
     *  `../keys?offset=10&limit=10`.
     */
    offset?: number;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of key rings that match the request, disregarding limit and offset.
     *  The default is set to false.
     *  **Usage:** To return the `totalCount` value for use with pagination, use `../key_rings?totalCount=true`.
     */
    totalCount?: boolean;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `createKeyRing` operation. */
  export interface CreateKeyRingParams {
    /** The ID that identifies the key ring. Each ID is unique only within the given instance and is not reserved
     *  across the Key Protect service.
     */
    keyRingId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKeyRing` operation. */
  export interface DeleteKeyRingParams {
    /** The ID that identifies the key ring. Each ID is unique only within the given instance and is not reserved
     *  across the Key Protect service.
     */
    keyRingId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** Force delete the key ring. All keys in the key ring are required to be deleted (in state `5`) before this
     *  action can be performed.  If the key ring to be deleted contains keys, they will be moved to the `default` key
     *  ring which requires the `kms.secrets.patch` IAM action.
     */
    force?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipAdapters` operation. */
  export interface GetKmipAdaptersParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    /** The number of KMIP Adapters to retrieve. By default, `GET /kmip_adapters` returns the first 100 KMIP
     *  Adapters. To retrieve a different set of KMIP adapters, use `limit` with `offset` to page through your available
     *  resources. The maximum value for `limit` is 200.
     *  **Usage:** If you have 20 KMIP Adapters, and you want to retrieve only the first 5 adapters, use
     *  `../kmip_adapters?limit=5`.
     */
    limit?: number;
    /** The number of KMIP adapters to skip. By specifying `offset`, you retrieve a subset of KMIP adapters that
     *  starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 20 KMIP Adapters, and you want to retrieve adapters 11 through 15, use
     *  `../kmip_adapters?offset=10&limit=5`.
     */
    offset?: number;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of kmip adapters that match the request, disregarding limit and
     *  offset. The default is set to false. **Usage:** To return the `totalCount` value for use with pagination, use
     *  `../kmip_adapters?totalCount=true`.
     */
    totalCount?: boolean;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `createKmipAdapter` operation. */
  export interface CreateKmipAdapterParams {
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: CreateKMIPAdapterRequestBodyResources[];
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipAdapter` operation. */
  export interface GetKmipAdapterParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKmipAdapter` operation. */
  export interface DeleteKmipAdapterParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipObjects` operation. */
  export interface GetKmipObjectsParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The number of kmip objects to retrieve. By default, `GET /kmip_adapters/{id}/kmip_objects` returns the first
     *  100 kmip_objects. To retrieve a different set of kmip objects, use `limit` with `offset` to page through your
     *  available resources. The maximum value for `limit` is 5000.
     *  **Usage:** If you have 20 kmip objects associated with your KMIP adapter, and you want to retrieve only the
     *  first 5 kmip objects, use `../kmip_adapters/{id}/kmip_objects?limit=5`.
     */
    limit?: number;
    /** The number of kmip objects to skip. By specifying `offset`, you retrieve a subset of kmip objects that
     *  starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 20 kmip objects associated with your KMIP adapter, and you want to retrieve kmip objects
     *  11 through 15, use `../kmip_adapters/{id}/kmip_objects?offset=10&limit=5`.
     */
    offset?: number;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of kmip objects that match the request, disregarding limit and offset.
     *  The default is set to false. **Usage:** To return the `totalCount` value for use with pagination, use
     *  `../kmip_adapters/{id}/kmip_objects?totalCount=true`.
     */
    totalCount?: boolean;
    /** List of states to filter the KMIP objects on. The `default` is set to `[1,2,3,4]`. States are integers and
     *  correspond to Pre-Active = 1, Active = 2, Deactivated = 3, Compromised = 4, Destroyed = 5, Destroyed Compromised
     *  = 6. **Usage:** To filter on multiples `state` values, use `../kmip_adapters/{id}/kmip_objects?state=2,3`.
     */
    state?: number[];
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipObject` operation. */
  export interface GetKmipObjectParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID of the kmip object that uniquely identifies it. */
    id: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKmipObject` operation. */
  export interface DeleteKmipObjectParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The name or v4 UUID of the client certificate that uniquely identifies it. */
    id: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipClientCertificates` operation. */
  export interface GetKmipClientCertificatesParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The number of client certificates to retrieve. By default, `GET /kmip_adapters/{id}/certificates` returns
     *  the first 100 certificates. To retrieve a different set of certificates, use `limit` with `offset` to page
     *  through your available resources. The maximum value for `limit` is 200.
     *  **Usage:** If you have 20 certificates associated with your KMIP adapter, and you want to retrieve only the
     *  first 5 certificates, use `../kmip_adapters/{id}/certificates?limit=5`.
     */
    limit?: number;
    /** The number of client certificates to skip. By specifying `offset`, you retrieve a subset of certificates
     *  that starts with the `offset` value. Use `offset` with `limit` to page through your available resources.
     *  **Usage:** If you have 20 certificates associated with your KMIP adapter, and you want to retrieve certificates
     *  11 through 15, use `../kmip_adapters/{id}/certificates?offset=10&limit=5`.
     */
    offset?: number;
    /** If set to `true`, returns `totalCount` in the response metadata for use with pagination. The `totalCount`
     *  value returned specifies the total number of client certificates that match the request, disregarding limit and
     *  offset. The default is set to false. **Usage:** To return the `totalCount` value for use with pagination, use
     *  `../kmip_adapters/{id}/certificates?totalCount=true`.
     */
    totalCount?: boolean;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `addKmipClientCertificate` operation. */
  export interface AddKmipClientCertificateParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: CreateKMIPClientCertificateObject[];
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `getKmipClientCertificate` operation. */
  export interface GetKmipClientCertificateParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The name or v4 UUID of the client certificate that uniquely identifies it. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /** Parameters for the `deleteKmipClientCertificate` operation. */
  export interface DeleteKmipClientCertificateParams {
    /** The name or v4 UUID of the KMIP Adapter that uniquely identifies it. */
    adapterId: string;
    /** The name or v4 UUID of the client certificate that uniquely identifies it. */
    id: string;
    /** The IBM Cloud instance ID that identifies your Key Protect service instance. */
    bluemixInstance: string;
    /** The v4 UUID used to correlate and track transactions. */
    correlationId?: string;
    headers?: OutgoingHttpHeaders;
  }

  /*************************
   * model interfaces
   ************************/

  /** Properties associated with the port associated with an instance with an allowed IP policy. */
  export interface AllowedIPPort {
    /** The metadata that describes the resource array. */
    metadata?: CollectionMetadata;
    /** A collection of resources. */
    resources?: AllowedIPPortResource[];
  }

  /** Metadata of the port associated with an instance with an allowed IP policy. */
  export interface AllowedIPPortResource {
    /** The port required to access an instance with an allowed IP policy via the Key Protect private service
     *  endpoint. Cannot be used with the Key Protect public service endpoint. For more information, see [accessing an
     *  instance via private
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint) for
     *  instructions on how to use the `private_endpoint_port` value.
     */
    private_endpoint_port?: number;
  }

  /** The metadata that describes the resource array. */
  export interface CollectionMetadata {
    /** The type of resources in the resource array. */
    collectionType: CollectionMetadata.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
  }
  export namespace CollectionMetadata {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** The metadata that describes the list keys response. */
  export interface CollectionMetadataListKeys {
    /** The type of resources in the resource array. */
    collectionType: CollectionMetadataListKeys.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
    /** If present, indicates the search did not complete due to the searchable set of keys being too large.  Please
     *  retry your request with additional or more specific filters (i.e. extractable, state, etc.). To determine the
     *  size of the searchable set of keys, please use `HEAD /api/v2/keys` with the desired search filters. For a search
     *  to be performmed, the resulting set contain at most 5000 keys.
     */
    incompleteSearch?: boolean;
    /** Represents the parsed search query used for matching logic. Only returned when a search is requested. */
    searchQuery?: ListKeysMetadataPropertiesSearchQuery;
  }
  export namespace CollectionMetadataListKeys {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** CollectionMetadataOneOf. */
  export interface CollectionMetadataOneOf {
  }

  /** The metadata that describes the resource array. */
  export interface CollectionMetadataWithTotalCount {
    /** The type of resources in the resource array. */
    collectionType: CollectionMetadataWithTotalCount.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
    /** The total number of elements that match the request, disregarding limit and offset. */
    totalCount?: number;
  }
  export namespace CollectionMetadataWithTotalCount {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** CreateKMIPAdapterRequestBodyResources. */
  export interface CreateKMIPAdapterRequestBodyResources {
    /** A human-readable name of the KMIP adapter unique within the kms instance. If one is not specified, one will
     *  be autogenerated of the format `kmip_adapter_<random_string>`. To protect your privacy do not use personal data,
     *  such as your name or location, as a name for your KMIP adapter. The name must be  alphanumeric and cannot
     *  contain spaces or special characters other than `-` or `_`. The name cannot be a UUID.
     */
    name?: string;
    /** The optional description of the KMIP adapter. The maximum length is 240 characters. To protect your privacy,
     *  do not use personal data, such as your name or location, as a description for your KMIP adapter.
     */
    description?: string;
    /** The profile of KMIP adapter to be created. */
    profile: CreateKMIPAdapterRequestBodyResources.Constants.Profile | string;
    /** The data specific to the KMIP Adapter profile. This is a required field for profile `native_1.0`. */
    profile_data?: KMIPProfileDataBody;
  }
  export namespace CreateKMIPAdapterRequestBodyResources {
    export namespace Constants {
      /** The profile of KMIP adapter to be created. */
      export enum Profile {
        NATIVE_1_0 = 'native_1.0',
      }
    }
  }

  /** CreateKMIPClientCertificateObject. */
  export interface CreateKMIPClientCertificateObject {
    /** The client certificate to be associated with the KMIP Adapter. It should explicitly have the BEGIN
     *  CERTIFICATE and END CERTIFICATE tags.
     */
    certificate: string;
    /** A human-readable name that uniquely identifies a certificate within the given adapter. If one is  not
     *  specified, one will be autogenerated of the format `kmip_cert_<random_string>`. To protect your privacy do not
     *  use personal data, such as your name or location, as a name for your client certificate. The name must be
     *  alphanumeric and cannot contain spaces or special characters other than `-` or `_`. The name cannot be a UUID.
     */
    name?: string;
  }

  /** The base schema for deleting keys. */
  export interface DeleteKey {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyWithPayload[];
  }

  /** User defined metadata that is associated with the `dualAuthDelete` instance policy type. */
  export interface DualAuthDeleteProperties {
    /** If set to `true`, Key Protect enables a dual authorization deletion policy for your service instance. By
     *  default, Key Protect requires only one authorization to delete a key. After you enable a dual authorization
     *  policy, any new key that you create or add to the instance will require an authorization from two users to
     *  delete keys.
     *  **Note:** This change does not affect existing keys in your instance.
     */
    enabled: boolean;
  }

  /** Metadata that indicates the status of a dual authorization policy on the key. */
  export interface DualAuthKeyMetadata {
    /** The status of a dual authorization policy on the key. If `true`, dual authorization is required to delete
     *  the key. If `false`, no prior authorization is required to delete the key.
     */
    enabled: boolean;
    /** Indicates if a delete authorization has been issued for a key. If `true`, an authorization to delete this
     *  key has been issued by the first user, and a second user with a Manager access policy can safely delete the key.
     *  If the `enabled` property is `false`, this field is omitted in the response body.
     */
    keySetForDeletion?: boolean;
    /** The date that an authorization for deletion expires for the key. If this date has passed, the authorization
     *  is no longer valid. If the `enabled` or `keySetForDeletion` properties are `false`, this field is omitted in the
     *  response body.
     */
    authExpiration?: string;
  }

  /** The base schema for retrieving an import token. */
  export interface GetImportToken {
    /** The time in seconds from the creation of an import token that determines how long its associated public key
     *  remains valid. The minimum value is `300` seconds (5 minutes), and the maximum value is `86400` (24 hours). The
     *  default value is `600` (10 minutes).
     */
    expiration?: number;
    /** The number of times that an import token can be retrieved within its expiration time before it is no longer
     *  accessible.
     */
    maxAllowedRetrievals?: number;
    /** The date the import token was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The date the import token expires. The date format follows RFC 3339. */
    expirationDate?: string;
    /** The number of retrievals that are available for the import token before it is no longer accessible. */
    remainingRetrievals?: number;
    /** The public encryption key that you can use to encrypt key material before you import it into the service.
     *  This value is a PEM-encoded public key in PKIX format. Because PEM encoding is a binary format, the value is
     *  base64 encoded.
     */
    payload?: string;
    /** The nonce value that is used to verify a key import request. Encrypt and provide the encrypted nonce value
     *  when you use `POST /keys` to securely import a key to the service.
     */
    nonce?: string;
  }

  /** GetInstancePoliciesOneOf. */
  export interface GetInstancePoliciesOneOf {
  }

  /** GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `allowedNetwork` instance policy type. */
    policy_data: GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData;
  }

  /** User defined metadata that is associated with the `allowedNetwork` instance policy type. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Data associated with the policy type `allowed_network`. */
    attributes?: GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes;
  }

  /** Data associated with the policy type `allowed_network`. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes {
    /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private
     *  endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private
     *  endpoint.
     */
    allowed_network: GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes.Constants.AllowedNetwork | string;
  }
  export namespace GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItemPolicyDataAttributes {
    export namespace Constants {
      /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private endpoint. */
      export enum AllowedNetwork {
        PUBLIC_AND_PRIVATE = 'public-and-private',
        PRIVATE_ONLY = 'private-only',
      }
    }
  }

  /** GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `keyCreateImportAccess` instance policy type. */
    policy_data: GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData;
  }

  /** User defined metadata that is associated with the `keyCreateImportAccess` instance policy type. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Data associated with the policy type `keyCreateImportAccess`. */
    attributes?: GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes;
  }

  /** Data associated with the policy type `keyCreateImportAccess`. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItemPolicyDataAttributes {
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create root
     *  keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized users to
     *  create root keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_root_key: boolean;
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create
     *  standard keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized
     *  users to create standard keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_standard_key: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing root keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import root keys
     *  into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_root_key: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing standard keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import standard
     *  keys into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_standard_key: boolean;
    /** If set to `true`, the service prevents you or any authorized users from importing key material into the
     *  specified service instance without using an import token. If set to `false`, Key Protect allows you or any
     *  authorized users to import key material into the instance without the use of an import token.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`false`).
     */
    enforce_token: boolean;
  }

  /** GetInstancePolicyAllowedIPResourcesItem. */
  export interface GetInstancePolicyAllowedIPResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `allowedIP` instance policy type. */
    policy_data: GetInstancePolicyAllowedIPResourcesItemPolicyData;
  }

  /** User defined metadata that is associated with the `allowedIP` instance policy type. */
  export interface GetInstancePolicyAllowedIPResourcesItemPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Data associated with the policy type `allowedIP`. */
    attributes?: GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes;
  }

  /** Data associated with the policy type `allowedIP`. */
  export interface GetInstancePolicyAllowedIPResourcesItemPolicyDataAttributes {
    /** A string array of IPv4 or IPv6 CIDR notated subnets that are authorized to interact with the instance. If
     *  both `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with both the `allowed_network`
     *  allowed network policy attribute and the `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
     *  addresses are accepted for public endpoints. Only the IPv4 private network gateway addresses from the array will
     *  be authorized to access your instance via private endpoint.
     *  **Important:** Once set, accessing your instance may require additional steps. For more information, see
     *  [Accessing an instance via public
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint) and
     *  [Accessing an instance via private
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint) for more
     *  details.
     *  **Note:** An allowed IP policy does not affect requests from other IBM Cloud services.
     */
    allowed_ip: string[];
  }

  /** GetInstancePolicyDualAuthDeleteResourcesItem. */
  export interface GetInstancePolicyDualAuthDeleteResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `dualAuthDelete` instance policy type. */
    policy_data: DualAuthDeleteProperties;
  }

  /** GetInstancePolicyMetricsResourcesItem. */
  export interface GetInstancePolicyMetricsResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `metrics` instance policy type. */
    policy_data: MetricsProperties;
  }

  /** GetInstancePolicyRotationResourcesItem. */
  export interface GetInstancePolicyRotationResourcesItem {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with the `rotation` instance policy type. */
    policy_data: GetInstancePolicyRotationResourcesItemPolicyData;
  }

  /** User defined metadata that is associated with the `rotation` instance policy type. */
  export interface GetInstancePolicyRotationResourcesItemPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Data associated with the policy type `rotation`. */
    attributes?: GetInstancePolicyRotationResourcesItemPolicyDataAttributes;
  }

  /** Data associated with the policy type `rotation`. */
  export interface GetInstancePolicyRotationResourcesItemPolicyDataAttributes {
    /** Specifies the key rotation time interval in approximate months, where a month is equivalent to 30 days. A
     *  minimum of 1 and a maximum of 12 can be set.
     */
    interval_month: number;
  }

  /** The base schema for retrieving keys. */
  export interface GetKey {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyWithPayload[];
  }

  /** The base schema for retrieving key metadata. */
  export interface GetKeyMetadata {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyFullRepresentation[];
  }

  /** GetKeyPoliciesOneOf. */
  export interface GetKeyPoliciesOneOf {
  }

  /** Properties that are associated with key level dual authorization delete policy. */
  export interface GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem {
    /** The v4 UUID used to uniquely identify the policy resource, as specified by RFC 4122. */
    id?: string;
    /** The Cloud Resource Name (CRN) that uniquely identifies your cloud resources. */
    crn?: string;
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdateDate?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
    type: GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem.Constants.Type | string;
    /** Data associated with the dual authorization delete policy. */
    dualAuthDelete: KeyPolicyDualAuthDeleteDualAuthDelete;
  }
  export namespace GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem {
    export namespace Constants {
      /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
      }
    }
  }

  /** Properties that are associated with rotation policy. */
  export interface GetKeyPolicyRotationResourcesItem {
    /** The v4 UUID used to uniquely identify the policy resource, as specified by RFC 4122. */
    id?: string;
    /** The Cloud Resource Name (CRN) that uniquely identifies your cloud resources. */
    crn?: string;
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdateDate?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
    type: GetKeyPolicyRotationResourcesItem.Constants.Type | string;
    /** Data associated with the automatic key rotation policy. */
    rotation: KeyPolicyRotationRotation;
  }
  export namespace GetKeyPolicyRotationResourcesItem {
    export namespace Constants {
      /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
      }
    }
  }

  /** Properties that are associated with rotation policy. */
  export interface GetMultipleKeyPoliciesResource {
    /** Data associated with the dual authorization delete policy. */
    dualAuthDelete?: GetMultipleKeyPoliciesResourceDualAuthDelete;
    /** Data associated with the automatic key rotation policy. */
    rotation?: KeyPolicyRotationNonRequiredRotation;
    /** The v4 UUID used to uniquely identify the policy resource, as specified by RFC 4122. */
    id?: string;
    /** The Cloud Resource Name (CRN) that uniquely identifies your cloud resources. */
    crn?: string;
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdateDate?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
  }

  /** Data associated with the dual authorization delete policy. */
  export interface GetMultipleKeyPoliciesResourceDualAuthDelete {
    /** If set to `true`, Key Protect enables a dual authorization policy on a single key. After you enable the
     *  policy, Key Protect requires an authorization from two users to delete this key. For example, you can authorize
     *  the deletion first by using the [SetKeyForDeletion](#invoke-an-action-on-a-key) action. Then, a different user
     *  provides a second authorization implicitly by calling `DELETE /keys` to delete the key.
     *  **Note:** Once the dual authorization policy is set on the key, it cannot be reverted.
     */
    enabled: boolean;
  }

  /** Properties that are associated with import tokens. */
  export interface ImportToken {
    /** The time in seconds from the creation of an import token that determines how long its associated public key
     *  remains valid. The minimum value is `300` seconds (5 minutes), and the maximum value is `86400` (24 hours). The
     *  default value is `600` (10 minutes).
     */
    expiration?: number;
    /** The number of times that an import token can be retrieved within its expiration time before it is no longer
     *  accessible.
     */
    maxAllowedRetrievals?: number;
    /** The date the import token was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The date the import token expires. The date format follows RFC 3339. */
    expirationDate?: string;
    /** The number of retrievals that are available for the import token before it is no longer accessible. */
    remainingRetrievals?: number;
  }

  /** User defined metadata that is associated with the `allowedIP` instance policy type. */
  export interface InstancePolicyAllowedIPPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes of an `allowedIP` instance policy. Must be provided if the `enabled` field is `true`. Cannot be
     *  provided if the `enabled` field is `false`.
     */
    attributes?: InstancePolicyAllowedIPPolicyDataAttributes;
  }

  /** Attributes of an `allowedIP` instance policy. Must be provided if the `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`. */
  export interface InstancePolicyAllowedIPPolicyDataAttributes {
    /** A string array of IPv4 or IPv6 CIDR notated subnets that are authorized to interact with the instance. If
     *  both `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with both the `allowed_network`
     *  allowed network policy attribute and the `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
     *  addresses are accepted for public endpoints. Only the IPv4 private network gateway addresses from the array will
     *  be authorized to access your instance via private endpoint.
     *  **Important:** Once set, accessing your instance may require additional steps. For more information, see
     *  [Accessing an instance via public
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint) and
     *  [Accessing an instance via private
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint) for more
     *  details.
     *  **Note:** An allowed IP policy does not affect requests from other IBM Cloud services.
     */
    allowed_ip?: string[];
  }

  /** User defined metadata that is associated with the `allowedNetwork` instance policy type. */
  export interface InstancePolicyAllowedNetworkPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes of an `allowedNetwork` instance policy. Must be provided if the `enabled` field is `true`. Cannot
     *  be provided if the `enabled` field is `false`.
     */
    attributes?: InstancePolicyAllowedNetworkPolicyDataAttributes;
  }

  /** Attributes of an `allowedNetwork` instance policy. Must be provided if the `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`. */
  export interface InstancePolicyAllowedNetworkPolicyDataAttributes {
    /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private
     *  endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private
     *  endpoint.
     */
    allowed_network: InstancePolicyAllowedNetworkPolicyDataAttributes.Constants.AllowedNetwork | string;
  }
  export namespace InstancePolicyAllowedNetworkPolicyDataAttributes {
    export namespace Constants {
      /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private endpoint. */
      export enum AllowedNetwork {
        PUBLIC_AND_PRIVATE = 'public-and-private',
        PRIVATE_ONLY = 'private-only',
      }
    }
  }

  /** User defined metadata that is associated with the `keyCreateImportAccess` instance policy type. */
  export interface InstancePolicyKeyCreateImportAccessPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes of a `keyCreateImportAccess` instance policy. Must be provided if the `enabled` field is `true`.
     *  Cannot be provided if the `enabled` field is `false`.
     */
    attributes?: InstancePolicyKeyCreateImportAccessPolicyDataAttributes;
  }

  /** Attributes of a `keyCreateImportAccess` instance policy. Must be provided if the `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`. */
  export interface InstancePolicyKeyCreateImportAccessPolicyDataAttributes {
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create root
     *  keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized users to
     *  create root keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create
     *  standard keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized
     *  users to create standard keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_standard_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing root keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import root keys
     *  into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing standard keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import standard
     *  keys into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_standard_key?: boolean;
    /** If set to `true`, the service prevents you or any authorized users from importing key material into the
     *  specified service instance without using an import token. If set to `false`, Key Protect allows you or any
     *  authorized users to import key material into the instance without the use of an import token.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`false`).
     */
    enforce_token?: boolean;
  }

  /** User defined metadata that is associated with any instance policy. */
  export interface InstancePolicyProperties {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes associated with any instance policy type. */
    attributes?: InstancePolicyPropertiesAttributes;
  }

  /** Attributes associated with any instance policy type. */
  export interface InstancePolicyPropertiesAttributes {
    /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private
     *  endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private
     *  endpoint.
     */
    allowed_network?: InstancePolicyPropertiesAttributes.Constants.AllowedNetwork | string;
    /** A string array of IPv4 or IPv6 CIDR notated subnets that are authorized to interact with the instance. If
     *  both `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with both the `allowed_network`
     *  allowed network policy attribute and the `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
     *  addresses are accepted for public endpoints. Only the IPv4 private network gateway addresses from the array will
     *  be authorized to access your instance via private endpoint.
     *  **Important:** Once set, accessing your instance may require additional steps. For more information, see
     *  [Accessing an instance via public
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint) and
     *  [Accessing an instance via private
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint) for more
     *  details.
     *  **Note:** An allowed IP policy does not affect requests from other IBM Cloud services.
     */
    allowed_ip?: string[];
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create root
     *  keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized users to
     *  create root keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create
     *  standard keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized
     *  users to create standard keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_standard_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing root keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import root keys
     *  into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing standard keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import standard
     *  keys into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_standard_key?: boolean;
    /** If set to `true`, the service prevents you or any authorized users from importing key material into the
     *  specified service instance without using an import token. If set to `false`, Key Protect allows you or any
     *  authorized users to import key material into the instance without the use of an import token.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`false`).
     */
    enforce_token?: boolean;
    /** Specifies the key rotation time interval in approximate months, where a month is equivalent to 30 days. A
     *  minimum of 1 and a maximum of 12 can be set.
     */
    interval_month?: number;
  }
  export namespace InstancePolicyPropertiesAttributes {
    export namespace Constants {
      /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private endpoint. */
      export enum AllowedNetwork {
        PUBLIC_AND_PRIVATE = 'public-and-private',
        PRIVATE_ONLY = 'private-only',
      }
    }
  }

  /** InstancePolicyResource. */
  export interface InstancePolicyResource {
    /** The date the policy was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the policy. */
    createdBy?: string;
    /** The unique identifier for the resource that updated the policy. */
    updatedBy?: string;
    /** Updates when the policy is replaced or modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** The type of policy to be retrieved. */
    policy_type: string;
    /** User defined metadata that is associated with any instance policy. */
    policy_data: InstancePolicyProperties;
  }

  /** User defined metadata that is associated with the `rotation` instance policy type. */
  export interface InstancePolicyRotationPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes of a `rotation` instance policy. Must be provided if the `enabled` field is `true`. Cannot be
     *  provided if the `enabled` field is `false`.
     */
    attributes?: InstancePolicyRotationPolicyDataAttributes;
  }

  /** Attributes of a `rotation` instance policy. Must be provided if the `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`. */
  export interface InstancePolicyRotationPolicyDataAttributes {
    /** Specifies the key rotation time interval in approximate months, where a month is equivalent to 30 days. A
     *  minimum of 1 and a maximum of 12 can be set.
     */
    interval_month?: number;
  }

  /** Properties applicable to all KMIP adapter resources. */
  export interface KMIPAdapter {
    /** The v4 UUID that uniquely identifies this KMIP adapter. */
    id: string;
    /** A human-readable name of the KMIP adapter unique within the kms instance. If one is not specified, one will
     *  be autogenerated of the format `kmip_adapter_<random_string>`. To protect your privacy do not use personal data,
     *  such as your name or location, as a name for your KMIP adapter. The name must be  alphanumeric and cannot
     *  contain spaces or special characters other than `-` or `_`. The name cannot be a UUID.
     */
    name: string;
    /** The date the KMIP adapter was created. The date format follows RFC 3339. */
    created_at: string;
    /** The unique identifier of the user that created the KMIP adapter. */
    created_by: string;
    /** The date the KMIP adapter was last modified, either by creation or by modification  of adapter subresources.
     *  The date format follows RFC 3339.
     */
    updated_at: string;
    /** The unique identifier of the user that updated the KMIP adapter. */
    updated_by: string;
    /** The profile of KMIP adapter. */
    profile: KMIPAdapter.Constants.Profile | string;
    /** The optional description of the KMIP adapter. The maximum length is 240 characters. To protect your privacy,
     *  do not use personal data, such as your name or location, as a description for your KMIP adapter.
     */
    description?: string;
    /** The data specific to the KMIP Adapter profile. This is a required field for profile `native_1.0`. */
    profile_data?: KMIPProfileDataBody;
  }
  export namespace KMIPAdapter {
    export namespace Constants {
      /** The profile of KMIP adapter. */
      export enum Profile {
        NATIVE_1_0 = 'native_1.0',
      }
    }
  }

  /** Properties of a client certificate. */
  export interface KMIPClientCertificate {
    /** A human-readable name that uniquely identifies a certificate within the given adapter. If one is  not
     *  specified, one will be autogenerated of the format `kmip_cert_<random_string>`. To protect your privacy do not
     *  use personal data, such as your name or location, as a name for your client certificate. The name must be
     *  alphanumeric and cannot contain spaces or special characters other than `-` or `_`. The name cannot be a UUID.
     */
    name: string;
    /** The v4 UUID that uniquely identifies this certificate resource. */
    id: string;
    /** The date this certificate resource was created on the KMIP Adapter. The date format follows RFC 3339. */
    created_at: string;
    /** The IAM id that created the certificate resource. */
    created_by: string;
    /** The client certificate to be associated with the KMIP Adapter. It should explicitly have the BEGIN
     *  CERTIFICATE and END CERTIFICATE tags.
     */
    certificate: string;
  }

  /** Partial properties of a client certificate. */
  export interface KMIPClientPartialCertificate {
    /** A human-readable name that uniquely identifies a certificate within the given adapter. If one is  not
     *  specified, one will be autogenerated of the format `kmip_cert_<random_string>`. To protect your privacy do not
     *  use personal data, such as your name or location, as a name for your client certificate. The name must be
     *  alphanumeric and cannot contain spaces or special characters other than `-` or `_`. The name cannot be a UUID.
     */
    name: string;
    /** The v4 UUID that uniquely identifies this certificate resource. */
    id: string;
    /** The date this certificate resource was created on the KMIP Adapter. The date format follows RFC 3339. */
    created_at: string;
    /** The IAM id that created the certificate resource. */
    created_by: string;
  }

  /** Properties applicable to all KMIP object resources. */
  export interface KMIPObject {
    /** The v4 UUID that uniquely identifies this KMIP object. */
    id: string;
    /** The object type of the kmip object according to the KMIP specification. Currently, only kmip_object_type
     *  2(Symmetric Key) is supported. For more info on the KMIP specification and object types, read
     *  https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html#_Toc490660932.
     */
    kmip_object_type: number;
    /** States are integers and correspond to Pre-Active = 1, Active = 2, Deactivated = 3, Compromised = 4,
     *  Destroyed = 5, Destroyed Compromised = 6. For more info on the KMIP specification, read
     *  https://docs.oasis-open.org/kmip/spec/v1.4/os/kmip-spec-v1.4-os.html.
     */
    state?: number;
    /** The date the KMIP object was created. The date format follows RFC 3339. */
    created_at: string;
    /** The v4 UUID that uniquely identifies the certificate used to create this KMIP object. */
    created_by_kmip_client_cert_id: string;
    /** The IAM id that created the certificate resource used to create this KMIP object. */
    created_by?: string;
    /** The date the KMIP object was last modified. The date format follows RFC 3339. */
    updated_at?: string;
    /** The v4 UUID that uniquely identifies the certificate used to update this KMIP object. */
    updated_by_kmip_client_cert_id?: string;
    /** The IAM id that created the certificate resource used to update this KMIP object. */
    updated_by?: string;
    /** The date the KMIP object was destroyed. The date format follows RFC 3339. */
    destroyed_at?: string;
    /** The v4 UUID that uniquely identifies the certificate used to destroy this KMIP object. */
    destroyed_by_kmip_client_cert_id?: string;
    /** The IAM id that created the certificate resource used to destroy this KMIP object. */
    destroyed_by?: string;
  }

  /** The data specific to the KMIP Adapter profile. This is a required field for profile `native_1.0`. */
  export interface KMIPProfileDataBody {
  }

  /** Properties associated with a key response. */
  export interface Key {
    metadata?: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources?: KeyWithPayload[];
  }

  /** KeyActionOneOfResponse. */
  export interface KeyActionOneOfResponse {
  }

  /** Properties associated with a specific key alias. */
  export interface KeyAlias {
    /** The metadata that describes the resource array. */
    metadata?: CollectionMetadata;
    /** A collection of resources. */
    resources?: KeyAliasResource[];
  }

  /** Properties associated with an alias. */
  export interface KeyAliasResource {
    /** The ID that identifies the key that is associated with the alias. */
    keyId?: string;
    /** The unique, human-readable alias assigned to the key. */
    alias?: string;
    /** The unique identifier for the user that created the alias. */
    createdBy?: string;
    /** The date the alias was created. The date format follows RFC 3339. */
    creationDate?: string;
  }

  /** Properties returned only for DELETE. */
  export interface KeyFullRepresentation {
    /** Specifies the MIME type that represents the key resource. Currently, only the default is supported. */
    type?: KeyFullRepresentation.Constants.Type | string;
    /** The v4 UUID used to uniquely identify the resource, as specified by RFC 4122. */
    id?: string;
    /** A human-readable name assigned to your key for convenience. To protect your privacy do not use personal
     *  data, such as your name or location, as the name for your key.
     */
    name?: string;
    /** One or more, up to a total of five, human-readable unique aliases assigned  to your key. To protect your
     *  privacy do not use personal data, such as your name or location, as an alias for your key. Each alias must be
     *  alphanumeric and cannot contain spaces or special characters other than `-` or `_`. The alias cannot be a UUID
     *  and must not be a Key Protect reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`, `policies`,
     *  `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
     */
    aliases?: string[];
    /** A text field used to provide a more detailed description of the key. The maximum length is 240 characters.
     *  To protect your privacy, do not use personal data, such as your name or location, as a description for your key.
     */
    description?: string;
    /** Up to 30 tags can be created. Tags can be between 0-30 characters, including spaces. Special characters not
     *  permitted include angled  brackets, comma, colon, ampersand, and vertical pipe character (|). To protect your
     *  privacy, do not use personal data, such as your name or location, as a tag for your key.
     */
    tags?: string[];
    /** The key state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active
     *  = 1,  Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
     */
    state?: number;
    /** The date the key material expires. The date format follows RFC 3339. You can set an expiration date on any
     *  key on its creation. If you create a key without specifying an expiration date, the key does not expire.
     */
    expirationDate?: string;
    /** A boolean that determines whether the key material can leave the service. If set to `false`, Key Protect
     *  designates the key as a nonextractable root key used for `wrap` and `unwrap` actions. If set to `true`, Key
     *  Protect designates the key as a standard key that you can store in your apps and services. Once set to `false`
     *  it cannot be changed to `true`.
     */
    extractable?: boolean;
    /** The Cloud Resource Name (CRN) that uniquely identifies your cloud resources. */
    crn?: string;
    /** A boolean that shows whether your key was originally imported or generated in Key Protect. The value is set
     *  by Key Protect based on how the key material is initially added to the service. A value of `true` indicates that
     *  you must provide new key material when it's time to rotate the key. A value of `false` indicates that Key
     *  Protect will generate the new key material on a `rotate` operation, as it did in key creation.
     */
    imported?: boolean;
    /** An ID that identifies the key ring. Each ID is unique only within the given instance and is not reserved
     *  across the Key Protect service.
     */
    keyRingID?: string;
    /** The date the key material was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the key. */
    createdBy?: string;
    /** Deprecated: Deprecated. */
    algorithmType?: KeyFullRepresentation.Constants.AlgorithmType | string;
    /** Deprecated. */
    algorithmMetadata?: KeyFullRepresentationAlgorithmMetadata;
    /** Deprecated: Deprecated. */
    algorithmBitSize?: number;
    /** Deprecated: Deprecated. */
    algorithmMode?: KeyFullRepresentation.Constants.AlgorithmMode | string;
    /** A code indicating the reason the key is not in the activation state. */
    nonactiveStateReason?: number;
    /** Updates when any part of the key metadata is modified. The date format follows RFC 3339. */
    lastUpdateDate?: string;
    /** Updates to show when the key was last rotated. The date format follows RFC 3339. */
    lastRotateDate?: string;
    /** Properties associated with a specific key version. */
    keyVersion?: KeyVersion;
    /** Metadata that indicates the status of a dual authorization policy on the key. */
    dualAuthDelete?: DualAuthKeyMetadata;
    /** Metadata that indicates the status of a rotation policy on the key. */
    rotation?: RotationKeyMetadata;
    /** A boolean that determines whether the key has been deleted. */
    deleted?: boolean;
    /** The date the key material was destroyed. The date format follows RFC 3339. */
    deletionDate?: string;
    /** The unique identifier for the resource that deleted the key. */
    deletedBy?: string;
    /** The date the key will no longer have the ability to be restored. */
    restoreExpirationDate?: string;
    /** A boolean that specifies if your key has the ability to be restored. A value of `true` indicates that the
     *  key can be restored. A value of `false` indicates that the key is unable to be restored.
     */
    restoreAllowed?: boolean;
    /** A boolean that specifies if the key can be purged. A value of `true` indicates that the key can be purged. A
     *  value of `false` indicates that the key is within the purge wait period and is not ready to be purged.
     */
    purgeAllowed?: boolean;
    /** The date the key will be ready to be purged. */
    purgeAllowedFrom?: string;
    /** The date the deleted key will be automatically purged from Key Protect system. */
    purgeScheduledOn?: string;
  }
  export namespace KeyFullRepresentation {
    export namespace Constants {
      /** Specifies the MIME type that represents the key resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
      }
      /** Deprecated. */
      export enum AlgorithmType {
        AES = 'AES',
        DEPRECATED = 'Deprecated',
      }
      /** Deprecated. */
      export enum AlgorithmMode {
        CBC_PAD = 'CBC_PAD',
        DEPRECATED = 'Deprecated',
      }
    }
  }

  /** Deprecated. */
  export interface KeyFullRepresentationAlgorithmMetadata {
    /** Deprecated. */
    bitLength?: string;
    /** Deprecated. */
    mode?: KeyFullRepresentationAlgorithmMetadata.Constants.Mode | string;
  }
  export namespace KeyFullRepresentationAlgorithmMetadata {
    export namespace Constants {
      /** Deprecated. */
      export enum Mode {
        CBC_PAD = 'CBC_PAD',
        DEPRECATED = 'Deprecated',
      }
    }
  }

  /** Properties that are associated with key level dual authorization delete policy. */
  export interface KeyPolicyDualAuthDelete {
    /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
    type: KeyPolicyDualAuthDelete.Constants.Type | string;
    /** Data associated with the dual authorization delete policy. */
    dualAuthDelete: KeyPolicyDualAuthDeleteDualAuthDelete;
  }
  export namespace KeyPolicyDualAuthDelete {
    export namespace Constants {
      /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
      }
    }
  }

  /** Data associated with the dual authorization delete policy. */
  export interface KeyPolicyDualAuthDeleteDualAuthDelete {
    /** If set to `true`, Key Protect enables a dual authorization policy on a single key. After you enable the
     *  policy, Key Protect requires an authorization from two users to delete this key. For example, you can authorize
     *  the deletion first by using the [SetKeyForDeletion](#invoke-an-action-on-a-key) action. Then, a different user
     *  provides a second authorization implicitly by calling `DELETE /keys` to delete the key.
     *  **Note:** Once the dual authorization policy is set on the key, it cannot be reverted.
     */
    enabled: boolean;
  }

  /** KeyPolicyRotation. */
  export interface KeyPolicyRotation {
    /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
    type: KeyPolicyRotation.Constants.Type | string;
    /** Data associated with the automatic key rotation policy. */
    rotation: KeyPolicyRotationRotation;
  }
  export namespace KeyPolicyRotation {
    export namespace Constants {
      /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
      }
    }
  }

  /** Data associated with the automatic key rotation policy. */
  export interface KeyPolicyRotationNonRequiredRotation {
    /** If set to `true`, Key Protect enables a rotation policy on a single key. */
    enabled: boolean;
    /** Specifies the key rotation time interval in approximate months standardized to 30 days each.  A minimum of 1
     *  and a maximum of 12 can be set.
     */
    interval_month: number;
  }

  /** Data associated with the automatic key rotation policy. */
  export interface KeyPolicyRotationRotation {
    /** If set to `true`, Key Protect enables a rotation policy on a single key. */
    enabled: boolean;
    /** Specifies the key rotation time interval in approximate months standardized to 30 days each. A minimum of 1
     *  and a maximum of 12 can be set.
     */
    interval_month?: number;
  }

  /** Base properties of an instance key ring. */
  export interface KeyRing {
    /** An ID that identifies the key ring. Each ID is unique only within the given instance and is not reserved
     *  across the Key Protect service.
     */
    id?: string;
    /** The date the key ring was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the user that created the key ring. */
    createdBy?: string;
  }

  /** Properties associated with a specific key version. */
  export interface KeyVersion {
    /** The ID of the key version. */
    id?: string;
    /** The date that the version of the key was created. */
    creationDate?: string;
  }

  /** Properties returned only for DELETE. */
  export interface KeyWithPayload {
    /** Specifies the MIME type that represents the key resource. Currently, only the default is supported. */
    type?: KeyWithPayload.Constants.Type | string;
    /** The v4 UUID used to uniquely identify the resource, as specified by RFC 4122. */
    id?: string;
    /** A human-readable name assigned to your key for convenience. To protect your privacy do not use personal
     *  data, such as your name or location, as the name for your key.
     */
    name?: string;
    /** One or more, up to a total of five, human-readable unique aliases assigned  to your key. To protect your
     *  privacy do not use personal data, such as your name or location, as an alias for your key. Each alias must be
     *  alphanumeric and cannot contain spaces or special characters other than `-` or `_`. The alias cannot be a UUID
     *  and must not be a Key Protect reserved name: `allowed_ip`, `key`, `keys`, `metadata`, `policy`, `policies`,
     *  `registration`, `registrations`, `ring`, `rings`, `rotate`, `wrap`, `unwrap`, `rewrap`, `version`, `versions`.
     */
    aliases?: string[];
    /** A text field used to provide a more detailed description of the key. The maximum length is 240 characters.
     *  To protect your privacy, do not use personal data, such as your name or location, as a description for your key.
     */
    description?: string;
    /** Up to 30 tags can be created. Tags can be between 0-30 characters, including spaces. Special characters not
     *  permitted include angled  brackets, comma, colon, ampersand, and vertical pipe character (|). To protect your
     *  privacy, do not use personal data, such as your name or location, as a tag for your key.
     */
    tags?: string[];
    /** The key state based on NIST SP 800-57. States are integers and correspond to the Pre-activation = 0, Active
     *  = 1,  Suspended = 2, Deactivated = 3, and Destroyed = 5 values.
     */
    state?: number;
    /** The date the key material expires. The date format follows RFC 3339. You can set an expiration date on any
     *  key on its creation. If you create a key without specifying an expiration date, the key does not expire.
     */
    expirationDate?: string;
    /** A boolean that determines whether the key material can leave the service. If set to `false`, Key Protect
     *  designates the key as a nonextractable root key used for `wrap` and `unwrap` actions. If set to `true`, Key
     *  Protect designates the key as a standard key that you can store in your apps and services. Once set to `false`
     *  it cannot be changed to `true`.
     */
    extractable?: boolean;
    /** The Cloud Resource Name (CRN) that uniquely identifies your cloud resources. */
    crn?: string;
    /** A boolean that shows whether your key was originally imported or generated in Key Protect. The value is set
     *  by Key Protect based on how the key material is initially added to the service. A value of `true` indicates that
     *  you must provide new key material when it's time to rotate the key. A value of `false` indicates that Key
     *  Protect will generate the new key material on a `rotate` operation, as it did in key creation.
     */
    imported?: boolean;
    /** An ID that identifies the key ring. Each ID is unique only within the given instance and is not reserved
     *  across the Key Protect service.
     */
    keyRingID?: string;
    /** The date the key material was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that created the key. */
    createdBy?: string;
    /** Deprecated: Deprecated. */
    algorithmType?: KeyWithPayload.Constants.AlgorithmType | string;
    /** Deprecated. */
    algorithmMetadata?: KeyWithPayloadAlgorithmMetadata;
    /** Deprecated: Deprecated. */
    algorithmBitSize?: number;
    /** Deprecated: Deprecated. */
    algorithmMode?: KeyWithPayload.Constants.AlgorithmMode | string;
    /** A code indicating the reason the key is not in the activation state. */
    nonactiveStateReason?: number;
    /** Updates when any part of the key metadata is modified. The date format follows RFC 3339. */
    lastUpdateDate?: string;
    /** Updates to show when the key was last rotated. The date format follows RFC 3339. */
    lastRotateDate?: string;
    /** Properties associated with a specific key version. */
    keyVersion?: KeyVersion;
    /** Metadata that indicates the status of a dual authorization policy on the key. */
    dualAuthDelete?: DualAuthKeyMetadata;
    /** Metadata that indicates the status of a rotation policy on the key. */
    rotation?: RotationKeyMetadata;
    /** A boolean that determines whether the key has been deleted. */
    deleted?: boolean;
    /** The date the key material was destroyed. The date format follows RFC 3339. */
    deletionDate?: string;
    /** The unique identifier for the resource that deleted the key. */
    deletedBy?: string;
    /** The date the key will no longer have the ability to be restored. */
    restoreExpirationDate?: string;
    /** A boolean that specifies if your key has the ability to be restored. A value of `true` indicates that the
     *  key can be restored. A value of `false` indicates that the key is unable to be restored.
     */
    restoreAllowed?: boolean;
    /** A boolean that specifies if the key can be purged. A value of `true` indicates that the key can be purged. A
     *  value of `false` indicates that the key is within the purge wait period and is not ready to be purged.
     */
    purgeAllowed?: boolean;
    /** The date the key will be ready to be purged. */
    purgeAllowedFrom?: string;
    /** The date the deleted key will be automatically purged from Key Protect system. */
    purgeScheduledOn?: string;
    /** The key material that you can export to external apps or services.
     *  **Note:** If the key has been designated as a root key, the system cannot return the key material.
     */
    payload?: string;
  }
  export namespace KeyWithPayload {
    export namespace Constants {
      /** Specifies the MIME type that represents the key resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
      }
      /** Deprecated. */
      export enum AlgorithmType {
        AES = 'AES',
        DEPRECATED = 'Deprecated',
      }
      /** Deprecated. */
      export enum AlgorithmMode {
        CBC_PAD = 'CBC_PAD',
        DEPRECATED = 'Deprecated',
      }
    }
  }

  /** Deprecated. */
  export interface KeyWithPayloadAlgorithmMetadata {
    /** Deprecated. */
    bitLength?: string;
    /** Deprecated. */
    mode?: KeyWithPayloadAlgorithmMetadata.Constants.Mode | string;
  }
  export namespace KeyWithPayloadAlgorithmMetadata {
    export namespace Constants {
      /** Deprecated. */
      export enum Mode {
        CBC_PAD = 'CBC_PAD',
        DEPRECATED = 'Deprecated',
      }
    }
  }

  /** ListCollectionMetadata. */
  export interface ListCollectionMetadata {
  }

  /** The base schema for listing kmip adapter(s). */
  export interface ListKMIPAdapters {
    metadata?: ListCollectionMetadata;
    /** A collection of resources. */
    resources?: KMIPAdapter[];
  }

  /** The base schema for listing kmip adapter with total count. */
  export interface ListKMIPAdaptersWithTotalCount {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadataWithTotalCount;
    /** A collection of resources. */
    resources?: KMIPAdapter[];
  }

  /** The base schema for listing client certificates in a kmip adapter. */
  export interface ListKMIPClientCertificates {
    metadata?: ListCollectionMetadata;
    /** A collection of resources. */
    resources?: KMIPClientCertificate[];
  }

  /** The base schema for listing kmip objects in a kmip adapter with total count. */
  export interface ListKMIPObjectsWithTotalCount {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadataWithTotalCount;
    /** A collection of resources. */
    resources?: KMIPObject[];
  }

  /** The base schema for listing client certificates in a kmip adapter with total count. */
  export interface ListKMIPPartialClientCertificatesWithTotalCount {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadataWithTotalCount;
    /** A collection of resources. */
    resources?: KMIPClientPartialCertificate[];
  }

  /** The base schema for listing key rings. */
  export interface ListKeyRingsWithTotalCount {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadataWithTotalCount;
    /** A collection of resources. */
    resources?: KeyRing[];
  }

  /** Properties associated with a registration response. */
  export interface ListKeyVersions {
    metadata?: ListCollectionMetadata;
    /** An array of resources. */
    resources?: KeyVersion[];
  }

  /** The base schema for listing keys. */
  export interface ListKeys {
    /** The metadata that describes the list keys response. */
    metadata: CollectionMetadataListKeys;
    /** A collection of resources. */
    resources?: KeyFullRepresentation[];
  }

  /** Represents the parsed search query used for matching logic. Only returned when a search is requested. */
  export interface ListKeysMetadataPropertiesSearchQuery {
    /** final string to use for matching logic. */
    query: string;
    /** list of scopes to search in. */
    scopes: ListKeysMetadataPropertiesSearchQuery.Constants.Scopes[] | string[];
    /** invert matching logic. */
    not?: boolean;
    /** only match query strings that are fully identical (case insensitive). */
    exact?: boolean;
  }
  export namespace ListKeysMetadataPropertiesSearchQuery {
    export namespace Constants {
      /** list of scopes to search in. */
      export enum Scopes {
        NAME = 'name',
        ALIAS = 'alias',
      }
    }
  }

  /** User defined metadata that is associated with the `metrics` instance policy type. */
  export interface MetricsProperties {
    /** If set to `true`, Key Protect will send service instance metrics to your [Cloud Monitoring With
     *  Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started) monitoring instance. By
     *  default, sending metrics to your [Cloud Monitoring With
     *  Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started) monitoring instance is
     *  disabled.
     *  **Note:** A metrics policy will add an additional metrics source to your [Cloud Monitoring With
     *  Sysdig](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-getting-started) monitoring instance. For more
     *  information, see [Enabling Platform
     *  Metrics](/docs/Monitoring-with-Sysdig?topic=Monitoring-with-Sysdig-platform_metrics_enabling) for more
     *  information.
     */
    enabled: boolean;
  }

  /** The base schema for patch key response body. */
  export interface PatchKeyResponseBody {
    /** The metadata that describes the resource array. */
    metadata?: CollectionMetadata;
    /** An array of resources. */
    resources?: KeyFullRepresentation[];
  }

  /** The base schema for purged key. */
  export interface PurgeKey {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyFullRepresentation[];
  }

  /** Properties associated with a registration. */
  export interface RegistrationResource {
    /** The ID that identifies the root key that is associated with the specified cloud resource. */
    keyId?: string;
    /** The human-readable reference assigned to the key that is associated with the specified cloud resource. */
    keyName?: string;
    /** The [Cloud Resource Name](/docs/account?topic=account-crn) (CRN) that represents the cloud resource, such as
     *  a Cloud Object Storage bucket, that is associated with the key.
     */
    resourceCrn?: string;
    /** The unique identifier for the resource that created the registration. */
    createdBy?: string;
    /** The date the registration was created. The date format follows RFC 3339. */
    creationDate?: string;
    /** The unique identifier for the resource that updated the registration. */
    updatedBy?: string;
    /** Updates when the registration is modified. The date format follows RFC 3339. */
    lastUpdated?: string;
    /** Description of the purpose of the registration. */
    description?: string;
    /** Additional information about the registration. This field is not exposed to customers and is visible only
     *  with IBM Cloud service to service calls.
     */
    registrationMetadata?: string;
    /** A boolean that determines whether Key Protect must prevent deletion of a root key. */
    preventKeyDeletion?: boolean;
    /** Properties associated with a specific key version. */
    keyVersion?: KeyVersion;
  }

  /** Properties associated with a list registration response which may include total registration count. */
  export interface RegistrationWithTotalCount {
    /** The metadata that describes the resource array. */
    metadata?: CollectionMetadataWithTotalCount;
    /** A collection of resources. */
    resources?: RegistrationResource[];
  }

  /** Properties that are associated with the response body of an rewrap action. */
  export interface RewrapKeyResponseBody {
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
    /** The latest key version that was used to rewrap the DEK. This key version is associated with the `ciphertext`
     *  value that's returned in the response.
     */
    rewrappedKeyVersion?: RewrappedKeyVersionRewrappedKeyVersion;
  }

  /** The latest key version that was used to rewrap the DEK. This key version is associated with the `ciphertext` value that's returned in the response. */
  export interface RewrappedKeyVersionRewrappedKeyVersion {
    /** The ID of the key version. */
    id?: string;
  }

  /** Metadata that indicates the status of a rotation policy on the key. */
  export interface RotationKeyMetadata {
    /** If set to `true`, Key Protect enables a rotation policy on a single key. */
    enabled: boolean;
    /** Specifies the key rotation time interval in approximate months, where a month is equivalent to 30 days. A
     *  minimum of 1 and a maximum of 12 can be set.
     */
    interval_month?: number;
  }

  /** SetInstancePoliciesOneOf. */
  export interface SetInstancePoliciesOneOf {
  }

  /** SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `allowedIP` instance policy type. */
    policy_data: InstancePolicyAllowedIPPolicyData;
  }
  export namespace SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        ALLOWEDIP = 'allowedIP',
      }
    }
  }

  /** SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `allowedNetwork` instance policy type. */
    policy_data: InstancePolicyAllowedNetworkPolicyData;
  }
  export namespace SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        ALLOWEDNETWORK = 'allowedNetwork',
      }
    }
  }

  /** SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `keyCreateImportAccess` instance policy type. */
    policy_data: InstancePolicyKeyCreateImportAccessPolicyData;
  }
  export namespace SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        KEYCREATEIMPORTACCESS = 'keyCreateImportAccess',
      }
    }
  }

  /** SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `metrics` instance policy type. */
    policy_data: MetricsProperties;
  }
  export namespace SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        METRICS = 'metrics',
      }
    }
  }

  /** SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `rotation` instance policy type. */
    policy_data: InstancePolicyRotationPolicyData;
  }
  export namespace SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        ROTATION = 'rotation',
      }
    }
  }

  /** SetInstancePolicyDualAuthDeleteResourcesItem. */
  export interface SetInstancePolicyDualAuthDeleteResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetInstancePolicyDualAuthDeleteResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with the `dualAuthDelete` instance policy type. */
    policy_data: DualAuthDeleteProperties;
  }
  export namespace SetInstancePolicyDualAuthDeleteResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        DUALAUTHDELETE = 'dualAuthDelete',
      }
    }
  }

  /** SetKeyPoliciesOneOf. */
  export interface SetKeyPoliciesOneOf {
  }

  /** SetMultipleInstancePoliciesResourcesItem. */
  export interface SetMultipleInstancePoliciesResourcesItem {
    /** The type of policy to be set. */
    policy_type: SetMultipleInstancePoliciesResourcesItem.Constants.PolicyType | string;
    /** User defined metadata that is associated with any instance policy. */
    policy_data: SetMultipleInstancePoliciesResourcesItemPolicyData;
  }
  export namespace SetMultipleInstancePoliciesResourcesItem {
    export namespace Constants {
      /** The type of policy to be set. */
      export enum PolicyType {
        ALLOWEDNETWORK = 'allowedNetwork',
        DUALAUTHDELETE = 'dualAuthDelete',
        ALLOWEDIP = 'allowedIP',
        KEYCREATEIMPORTACCESS = 'keyCreateImportAccess',
        METRICS = 'metrics',
        ROTATION = 'rotation',
      }
    }
  }

  /** User defined metadata that is associated with any instance policy. */
  export interface SetMultipleInstancePoliciesResourcesItemPolicyData {
    /** If set to `true`, Key Protect enables the specified policy for your service instance. If set to `false`, Key
     *  Protect disables the specified policy for your service instance, and the policy will no longer affect Key
     *  Protect actions.
     *  **Note:** If a policy with attributes is disabled, all attributes are reset and are not retained.
     */
    enabled: boolean;
    /** Attributes associated with any instance policy type. Must be provided if the `enabled` field is `true`.
     *  Cannot be provided if the `enabled` field is `false`. Only attributes corresponding to the `policy_type` can be
     *  provided.
     */
    attributes?: SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes;
  }

  /** Attributes associated with any instance policy type. Must be provided if the `enabled` field is `true`. Cannot be provided if the `enabled` field is `false`. Only attributes corresponding to the `policy_type` can be provided. */
  export interface SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes {
    /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private
     *  endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private
     *  endpoint.
     */
    allowed_network?: SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes.Constants.AllowedNetwork | string;
    /** A string array of IPv4 or IPv6 CIDR notated subnets that are authorized to interact with the instance. If
     *  both `allowedNetwork` and `allowedIP` policies are set, only traffic aligning with both the `allowed_network`
     *  allowed network policy attribute and the `allowed_ip` allowed IP policy attribute will be allowed. IPv4 and iIP6
     *  addresses are accepted for public endpoints. Only the IPv4 private network gateway addresses from the array will
     *  be authorized to access your instance via private endpoint.
     *  **Important:** Once set, accessing your instance may require additional steps. For more information, see
     *  [Accessing an instance via public
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-public-endpoint) and
     *  [Accessing an instance via private
     *  endpoint](/docs/key-protect?topic=key-protect-manage-allowed-ip#access-allowed-ip-private-endpoint) for more
     *  details.
     *  **Note:** An allowed IP policy does not affect requests from other IBM Cloud services.
     */
    allowed_ip?: string[];
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create root
     *  keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized users to
     *  create root keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from using Key Protect to create
     *  standard keys in the specified service instance. If set to `true`, Key Protect allows you or any authorized
     *  users to create standard keys in the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    create_standard_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing root keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import root keys
     *  into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_root_key?: boolean;
    /** If set to `false`, the service prevents you or any authorized users from importing standard keys into the
     *  specified service instance. If set to `true`, Key Protect allows you or any authorized users to import standard
     *  keys into the instance.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`true`).
     */
    import_standard_key?: boolean;
    /** If set to `true`, the service prevents you or any authorized users from importing key material into the
     *  specified service instance without using an import token. If set to `false`, Key Protect allows you or any
     *  authorized users to import key material into the instance without the use of an import token.
     *  **Note:** If omitted, `POST /instance/policies` will set this attribute to the default value (`false`).
     */
    enforce_token?: boolean;
    /** Specifies the key rotation time interval in approximate months, where a month is equivalent to 30 days. A
     *  minimum of 1 and a maximum of 12 can be set.
     */
    interval_month?: number;
  }
  export namespace SetMultipleInstancePoliciesResourcesItemPolicyDataAttributes {
    export namespace Constants {
      /** If set to `public-and-private`, Key Protect allows the instance to be accessible through public and private endpoints. If set to `private-only`, Key Protect restricts the instance to only be accessible through a private endpoint. */
      export enum AllowedNetwork {
        PUBLIC_AND_PRIVATE = 'public-and-private',
        PRIVATE_ONLY = 'private-only',
      }
    }
  }

  /** Properties that are associated with key level dual authorization delete policy. */
  export interface SetMultipleKeyPoliciesResource {
    /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
    type: SetMultipleKeyPoliciesResource.Constants.Type | string;
    /** Data associated with the dual authorization delete policy. */
    dualAuthDelete: KeyPolicyDualAuthDeleteDualAuthDelete;
    /** Data associated with the automatic key rotation policy. */
    rotation: KeyPolicyRotationRotation;
  }
  export namespace SetMultipleKeyPoliciesResource {
    export namespace Constants {
      /** Specifies the MIME type that represents the policy resource. Currently, only the default is supported. */
      export enum Type {
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
      }
    }
  }

  /** Properties that are associated with the response body of an unwrap action. */
  export interface UnwrapKeyResponseBody {
    /** The data encryption key (DEK) used in wrap actions when the query parameter is set to `wrap`. The system
     *  returns a base64 encoded plaintext in the response entity-body when you perform an `unwrap` action on a key. To
     *  wrap an existing DEK, provide a base64 encoded plaintext during a `wrap` action. To generate a new DEK, omit the
     *  `plaintext` property. Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and then
     *  wraps that value.
     *  **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated root key, the service returns
     *  a new ciphertext in the response entity-body. Each ciphertext remains available for `unwrap` actions. If you
     *  unwrap a DEK with a previous ciphertext, the service also returns the latest ciphertext in the response. Use the
     *  latest ciphertext for future unwrap operations.
     */
    plaintext: string;
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext?: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
    /** The latest key version that was used to rewrap the DEK. This key version is associated with the `ciphertext`
     *  value that's returned in the response.
     */
    rewrappedKeyVersion?: RewrappedKeyVersionRewrappedKeyVersion;
  }

  /** Properties that are associated with the response body of a wrap action. */
  export interface WrapKeyResponseBody {
    /** The data encryption key (DEK) used in wrap actions when the query parameter is set to `wrap`. The system
     *  returns a base64 encoded plaintext in the response entity-body when you perform an `unwrap` action on a key. To
     *  wrap an existing DEK, provide a base64 encoded plaintext during a `wrap` action. To generate a new DEK, omit the
     *  `plaintext` property. Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and then
     *  wraps that value.
     *  **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated root key, the service returns
     *  a new ciphertext in the response entity-body. Each ciphertext remains available for `unwrap` actions. If you
     *  unwrap a DEK with a previous ciphertext, the service also returns the latest ciphertext in the response. Use the
     *  latest ciphertext for future unwrap operations.
     */
    plaintext?: string;
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
  }

  /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value that was used in the request. */
  export interface WrappedKeyVersionKeyVersion {
    /** The ID of the key version. */
    id?: string;
  }

  /** The metadata that describes the resource array. */
  export interface CollectionMetadataOneOfCollectionMetadata extends CollectionMetadataOneOf {
    /** The type of resources in the resource array. */
    collectionType: CollectionMetadataOneOfCollectionMetadata.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
  }
  export namespace CollectionMetadataOneOfCollectionMetadata {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** Properties that are associated with retrieving an instance level allowed IP policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyAllowedIP extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePolicyAllowedIPResourcesItem[];
  }

  /** Properties that are associated with retrieving an instance level allowed network policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyAllowedNetwork extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePoliciesOneOfGetInstancePolicyAllowedNetworkResourcesItem[];
  }

  /** Properties that are associated with retrieving an instance level dual authorization delete policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyDualAuthDelete extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePolicyDualAuthDeleteResourcesItem[];
  }

  /** Properties that are associated with retrieving an instance level key create and import access policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccess extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePoliciesOneOfGetInstancePolicyKeyCreateImportAccessResourcesItem[];
  }

  /** Properties that are associated with retrieving an instance level metrics policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyMetrics extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePolicyMetricsResourcesItem[];
  }

  /** Properties that are associated with retrieving an instance level rotation policy. */
  export interface GetInstancePoliciesOneOfGetInstancePolicyRotation extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: GetInstancePolicyRotationResourcesItem[];
  }

  /** Properties that are associated with the instance level policies. */
  export interface GetInstancePoliciesOneOfGetMultipleInstancePolicies extends GetInstancePoliciesOneOf {
    metadata: CollectionMetadataOneOf;
    /** A collection of resources. */
    resources: InstancePolicyResource[];
  }

  /** The base schema for retrieving a dual authorization key policy. */
  export interface GetKeyPoliciesOneOfGetKeyPolicyDualAuthDelete extends GetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: GetKeyPoliciesOneOfGetKeyPolicyDualAuthDeleteResourcesItem[];
  }

  /** The base schema for retrieving a dual authorization key policy. */
  export interface GetKeyPoliciesOneOfGetKeyPolicyRotation extends GetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: GetKeyPolicyRotationResourcesItem[];
  }

  /** The base schema for retrieving all key policies. */
  export interface GetKeyPoliciesOneOfGetMultipleKeyPolicies extends GetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: GetMultipleKeyPoliciesResource[];
  }

  /** Properties that must be specified to profile_data when it is of native_1.0 KMIP adapter resource. */
  export interface KMIPProfileDataBodyKMIPProfileDataNative extends KMIPProfileDataBody {
    /** An ID that identifies the Customer Root Key(CRK) to be used. This CRK must exist in the same kms instance as
     *  the adapter.
     */
    crk_id: string;
  }

  /** Properties that are associated with the response body of an rewrap action. */
  export interface KeyActionOneOfResponseRewrapKeyResponseBody extends KeyActionOneOfResponse {
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
    /** The latest key version that was used to rewrap the DEK. This key version is associated with the `ciphertext`
     *  value that's returned in the response.
     */
    rewrappedKeyVersion?: RewrappedKeyVersionRewrappedKeyVersion;
  }

  /** Properties that are associated with the response body of an unwrap action. */
  export interface KeyActionOneOfResponseUnwrapKeyResponseBody extends KeyActionOneOfResponse {
    /** The data encryption key (DEK) used in wrap actions when the query parameter is set to `wrap`. The system
     *  returns a base64 encoded plaintext in the response entity-body when you perform an `unwrap` action on a key. To
     *  wrap an existing DEK, provide a base64 encoded plaintext during a `wrap` action. To generate a new DEK, omit the
     *  `plaintext` property. Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and then
     *  wraps that value.
     *  **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated root key, the service returns
     *  a new ciphertext in the response entity-body. Each ciphertext remains available for `unwrap` actions. If you
     *  unwrap a DEK with a previous ciphertext, the service also returns the latest ciphertext in the response. Use the
     *  latest ciphertext for future unwrap operations.
     */
    plaintext: string;
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext?: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
    /** The latest key version that was used to rewrap the DEK. This key version is associated with the `ciphertext`
     *  value that's returned in the response.
     */
    rewrappedKeyVersion?: RewrappedKeyVersionRewrappedKeyVersion;
  }

  /** Properties that are associated with the response body of a wrap action. */
  export interface KeyActionOneOfResponseWrapKeyResponseBody extends KeyActionOneOfResponse {
    /** The data encryption key (DEK) used in wrap actions when the query parameter is set to `wrap`. The system
     *  returns a base64 encoded plaintext in the response entity-body when you perform an `unwrap` action on a key. To
     *  wrap an existing DEK, provide a base64 encoded plaintext during a `wrap` action. To generate a new DEK, omit the
     *  `plaintext` property. Key Protect generates a random plaintext (32 bytes) that is rooted in an HSM and then
     *  wraps that value.
     *  **Note:** When you unwrap a wrapped data encryption key (WDEK) by using a rotated root key, the service returns
     *  a new ciphertext in the response entity-body. Each ciphertext remains available for `unwrap` actions. If you
     *  unwrap a DEK with a previous ciphertext, the service also returns the latest ciphertext in the response. Use the
     *  latest ciphertext for future unwrap operations.
     */
    plaintext?: string;
    /** The wrapped data encryption key (WDEK) that you can export to your app or service. The ciphertext contains
     *  the DEK wrapped by the latest version  of the key (WDEK). It is recommended to store and use  this WDEK in
     *  future calls to Key Protect. The value is base64 encoded.
     */
    ciphertext: string;
    /** The key version that was used to wrap the DEK. This key version is associated with the `ciphertext` value
     *  that was used in the request.
     */
    keyVersion?: WrappedKeyVersionKeyVersion;
  }

  /** The metadata that describes the resource array. */
  export interface ListCollectionMetadataCollectionMetadata extends ListCollectionMetadata {
    /** The type of resources in the resource array. */
    collectionType: ListCollectionMetadataCollectionMetadata.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
  }
  export namespace ListCollectionMetadataCollectionMetadata {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** The metadata that describes the resource array. */
  export interface ListCollectionMetadataCollectionMetadataWithTotalCount extends ListCollectionMetadata {
    /** The type of resources in the resource array. */
    collectionType: ListCollectionMetadataCollectionMetadataWithTotalCount.Constants.CollectionType | string;
    /** The number of elements in the resource array. */
    collectionTotal: number;
    /** The total number of elements that match the request, disregarding limit and offset. */
    totalCount?: number;
  }
  export namespace ListCollectionMetadataCollectionMetadataWithTotalCount {
    export namespace Constants {
      /** The type of resources in the resource array. */
      export enum CollectionType {
        APPLICATION_VND_IBM_KMS_ALLOWED_IP_METADATA_JSON = 'application/vnd.ibm.kms.allowed_ip_metadata+json',
        APPLICATION_VND_IBM_KMS_CRN_JSON = 'application/vnd.ibm.kms.crn+json',
        APPLICATION_VND_IBM_KMS_ERROR_JSON = 'application/vnd.ibm.kms.error+json',
        APPLICATION_VND_IBM_KMS_EVENT_ACKNOWLEDGE_JSON = 'application/vnd.ibm.kms.event_acknowledge+json',
        APPLICATION_VND_IBM_KMS_IMPORT_TOKEN_JSON = 'application/vnd.ibm.kms.import_token+json',
        APPLICATION_VND_IBM_KMS_KEY_JSON = 'application/vnd.ibm.kms.key+json',
        APPLICATION_VND_IBM_KMS_KEY_ACTION_JSON = 'application/vnd.ibm.kms.key_action+json',
        APPLICATION_VND_IBM_KMS_ALIAS_JSON = 'application/vnd.ibm.kms.alias+json',
        APPLICATION_VND_IBM_KMS_KEY_RING_JSON = 'application/vnd.ibm.kms.key_ring+json',
        APPLICATION_VND_IBM_KMS_POLICY_JSON = 'application/vnd.ibm.kms.policy+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_INPUT_JSON = 'application/vnd.ibm.kms.registration_input+json',
        APPLICATION_VND_IBM_KMS_REGISTRATION_JSON = 'application/vnd.ibm.kms.registration+json',
        APPLICATION_VND_IBM_KMS_RESOURCE_CRN_JSON = 'application/vnd.ibm.kms.resource_crn+json',
        APPLICATION_VND_IBM_KMS_KMIP_ADAPTER_JSON = 'application/vnd.ibm.kms.kmip_adapter+json',
        APPLICATION_VND_IBM_KMS_KMIP_CLIENT_CERTIFICATE_JSON = 'application/vnd.ibm.kms.kmip_client_certificate+json',
        APPLICATION_VND_IBM_KMS_KMIP_OBJECT_JSON = 'application/vnd.ibm.kms.kmip_object+json',
      }
    }
  }

  /** Properties that are associated with setting an instance level allowed IP policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyAllowedIP extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePoliciesOneOfSetInstancePolicyAllowedIPResourcesItem[];
  }

  /** Properties that are associated with setting an instance level allowed network policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyAllowedNetwork extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePoliciesOneOfSetInstancePolicyAllowedNetworkResourcesItem[];
  }

  /** Properties that are associated with setting a dual authorization delete instance policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyDualAuthDelete extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePolicyDualAuthDeleteResourcesItem[];
  }

  /** Properties that are associated with setting an instance level key create and import access policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccess extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePoliciesOneOfSetInstancePolicyKeyCreateImportAccessResourcesItem[];
  }

  /** Properties that are associated with setting a metrics instance policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyMetrics extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePoliciesOneOfSetInstancePolicyMetricsResourcesItem[];
  }

  /** Properties that are associated with setting an instance level rotation policy. */
  export interface SetInstancePoliciesOneOfSetInstancePolicyRotation extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetInstancePoliciesOneOfSetInstancePolicyRotationResourcesItem[];
  }

  /** Properties that are associated with setting any type of instance level policy. */
  export interface SetInstancePoliciesOneOfSetMultipleInstancePolicies extends SetInstancePoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetMultipleInstancePoliciesResourcesItem[];
  }

  /** Base schema for request of create/update of key level dual authorization delete policy. */
  export interface SetKeyPoliciesOneOfSetKeyPolicyDualAuthDelete extends SetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyPolicyDualAuthDelete[];
  }

  /** Base schema for request of create/update of key level rotation policy. */
  export interface SetKeyPoliciesOneOfSetKeyPolicyRotation extends SetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: KeyPolicyRotation[];
  }

  /** Properties that are associated with key. */
  export interface SetKeyPoliciesOneOfSetMultipleKeyPolicies extends SetKeyPoliciesOneOf {
    /** The metadata that describes the resource array. */
    metadata: CollectionMetadata;
    /** A collection of resources. */
    resources: SetMultipleKeyPoliciesResource[];
  }
}

export = IbmKeyProtectApiV2;
