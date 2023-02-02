/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 *
 * Any modifications Copyright OpenSearch Contributors. See
 * GitHub history for details.
 */
/*
 * Licensed to Elasticsearch B.V. under one or more contributor
 * license agreements. See the NOTICE file distributed with
 * this work for additional information regarding copyright
 * ownership. Elasticsearch B.V. licenses this file to you under
 * the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
import uuid from 'uuid';
import type { opensearchtypes } from '@opensearch-project/opensearch';
import { DecoratedError, SavedObjectsErrorHelpers } from '../errors';
import { decodeRequestVersion, encodeHitVersion, encodeVersion } from '../../../version';
import {
  SavedObjectSanitizedDoc,
  SavedObjectsRawDoc,
  SavedObjectsRawDocSource,
} from '../../../serialization';
import {
  SavedObjectsAddToNamespacesOptions,
  SavedObjectsAddToNamespacesResponse,
  SavedObjectsBulkCreateObject,
  SavedObjectsBulkGetObject,
  SavedObjectsBulkResponse,
  SavedObjectsBulkUpdateObject,
  SavedObjectsBulkUpdateOptions,
  SavedObjectsBulkUpdateResponse,
  SavedObjectsCheckConflictsObject,
  SavedObjectsCheckConflictsResponse,
  SavedObjectsCreateOptions,
  SavedObjectsDeleteFromNamespacesOptions,
  SavedObjectsDeleteFromNamespacesResponse,
  SavedObjectsDeleteOptions,
  SavedObjectsFindResponse,
  SavedObjectsFindResult,
  SavedObjectsUpdateOptions,
  SavedObjectsUpdateResponse,
} from '../../saved_objects_client';
import { SavedObject, SavedObjectsBaseOptions, SavedObjectsFindOptions } from '../../../types';
import {
  SavedObjectsRepository,
  normalizeNamespace,
  getSavedObjectNamespaces,
  DEFAULT_REFRESH_SETTING,
  errorContent,
  getBulkOperationError,
  getExpectedVersionProperties,
  Either,
  isLeft,
  isRight,
  SavedObjectsDeleteByNamespaceOptions,
  isFoundGetResponse,
  unique,
  SavedObjectsIncrementCounterOptions,
  getSavedObjectFromSource,
} from '../repository';
import {
  ALL_NAMESPACES_STRING,
  FIND_DEFAULT_PAGE,
  FIND_DEFAULT_PER_PAGE,
  SavedObjectsUtils,
} from '../utils';
import { DeleteDocumentResponse } from '../../../../opensearch/';
import { getRootPropertiesObjects } from '../../../mappings';
import { getSearchDsl } from '.././search_dsl';
import { validateConvertFilterToKueryNode } from '../filter_utils';
import { includedFields } from '../included_fields';

export class OpensearchSavedObjectsRepository extends SavedObjectsRepository {
  async create<T = unknown>(
    type: string,
    attributes: T,
    options: SavedObjectsCreateOptions = {}
  ): Promise<SavedObject<T>> {
    console.log('I am inside OpensearchSavedObjectsRepository create method');
    console.log('this.index', this._index);
    const {
      id,
      migrationVersion,
      overwrite = false,
      references = [],
      refresh = DEFAULT_REFRESH_SETTING,
      originId,
      initialNamespaces,
      version,
    } = options;
    const namespace = normalizeNamespace(options.namespace);

    if (id && overwrite)
      console.log(`====================Saved Object is being CREATED==============`);
    else console.log(`======================Saved object is being UPDATED================`);

    this.validateSavedObjectBeforeCreate(type, initialNamespaces);

    const time = this._getCurrentTime();
    let savedObjectNamespace;
    let savedObjectNamespaces: string[] | undefined;

    if (this._registry.isSingleNamespace(type) && namespace) {
      savedObjectNamespace = namespace;
    } else if (this._registry.isMultiNamespace(type)) {
      if (id && overwrite) {
        // we will overwrite a multi-namespace saved object if it exists; if that happens, ensure we preserve its included namespaces
        // note: this check throws an error if the object is found but does not exist in this namespace
        const existingNamespaces = await this.preflightGetNamespaces(type, id, namespace);
        savedObjectNamespaces = initialNamespaces || existingNamespaces;
      } else {
        savedObjectNamespaces = initialNamespaces || getSavedObjectNamespaces(namespace);
      }
    }

    const migrated = this._migrator.migrateDocument({
      id,
      type,
      ...(savedObjectNamespace && { namespace: savedObjectNamespace }),
      ...(savedObjectNamespaces && { namespaces: savedObjectNamespaces }),
      originId,
      attributes,
      migrationVersion,
      updated_at: time,
      ...(Array.isArray(references) && { references }),
    });

    const raw = this._serializer.savedObjectToRaw(migrated as SavedObjectSanitizedDoc);

    const requestParams = {
      id: raw._id,
      index: this.getIndexForType(type),
      refresh,
      body: raw._source,
      ...(overwrite && version ? decodeRequestVersion(version) : {}),
    };

    const { body } =
      id && overwrite
        ? await this.client.index(requestParams)
        : await this.client.create(requestParams);

    return this._rawToSavedObject<T>({
      ...raw,
      ...body,
    });
  }

  async bulkCreate<T = unknown>(
    objects: Array<SavedObjectsBulkCreateObject<T>>,
    options: SavedObjectsCreateOptions = {}
  ): Promise<SavedObjectsBulkResponse<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository bulkCreate method`);
    const { overwrite = false, refresh = DEFAULT_REFRESH_SETTING } = options;
    const namespace = normalizeNamespace(options.namespace);
    const time = this._getCurrentTime();

    let bulkGetRequestIndexCounter = 0;
    const expectedResults: Either[] = objects.map((object) => {
      let error: DecoratedError | undefined;
      if (!this._allowedTypes.includes(object.type)) {
        error = SavedObjectsErrorHelpers.createUnsupportedTypeError(object.type);
      } else if (object.initialNamespaces) {
        if (!this._registry.isMultiNamespace(object.type)) {
          error = SavedObjectsErrorHelpers.createBadRequestError(
            '"initialNamespaces" can only be used on multi-namespace types'
          );
        } else if (!object.initialNamespaces.length) {
          error = SavedObjectsErrorHelpers.createBadRequestError(
            '"initialNamespaces" must be a non-empty array of strings'
          );
        }
      }

      if (error) {
        return {
          tag: 'Left' as 'Left',
          error: { id: object.id, type: object.type, error: errorContent(error) },
        };
      }

      const method = object.id && overwrite ? 'index' : 'create';
      const requiresNamespacesCheck = object.id && this._registry.isMultiNamespace(object.type);

      if (object.id == null) object.id = uuid.v1();

      return {
        tag: 'Right' as 'Right',
        value: {
          method,
          object,
          ...(requiresNamespacesCheck && { opensearchRequestIndex: bulkGetRequestIndexCounter++ }),
        },
      };
    });

    const bulkGetDocs = expectedResults
      .filter(isRight)
      .filter(({ value }) => value.opensearchRequestIndex !== undefined)
      .map(({ value: { object: { type, id } } }) => ({
        _id: this._serializer.generateRawId(namespace, type, id),
        _index: this.getIndexForType(type),
        _source: ['type', 'namespaces'],
      }));
    const bulkGetResponse = bulkGetDocs.length
      ? await this.client.mget(
          {
            body: {
              docs: bulkGetDocs,
            },
          },
          { ignore: [404] }
        )
      : undefined;

    let bulkRequestIndexCounter = 0;
    const bulkCreateParams: object[] = [];
    const expectedBulkResults: Either[] = expectedResults.map((expectedBulkGetResult) => {
      if (isLeft(expectedBulkGetResult)) {
        return expectedBulkGetResult;
      }

      let savedObjectNamespace: string | undefined;
      let savedObjectNamespaces: string[] | undefined;
      let versionProperties;
      const {
        opensearchRequestIndex,
        object: { initialNamespaces, version, ...object },
        method,
      } = expectedBulkGetResult.value;
      if (opensearchRequestIndex !== undefined) {
        const indexFound = bulkGetResponse?.statusCode !== 404;
        const actualResult = indexFound
          ? bulkGetResponse?.body.docs[opensearchRequestIndex]
          : undefined;
        const docFound = indexFound && actualResult?.found === true;
        // @ts-expect-error MultiGetHit._source is optional
        if (docFound && !this.rawDocExistsInNamespace(actualResult!, namespace)) {
          const { id, type } = object;
          return {
            tag: 'Left' as 'Left',
            error: {
              id,
              type,
              error: {
                ...errorContent(SavedObjectsErrorHelpers.createConflictError(type, id)),
                metadata: { isNotOverwritable: true },
              },
            },
          };
        }
        savedObjectNamespaces =
          initialNamespaces ||
          // @ts-expect-error MultiGetHit._source is optional
          getSavedObjectNamespaces(namespace, docFound ? actualResult : undefined);
        // @ts-expect-error MultiGetHit._source is optional
        versionProperties = getExpectedVersionProperties(version, actualResult);
      } else {
        if (this._registry.isSingleNamespace(object.type)) {
          savedObjectNamespace = initialNamespaces ? initialNamespaces[0] : namespace;
        } else if (this._registry.isMultiNamespace(object.type)) {
          savedObjectNamespaces = initialNamespaces || getSavedObjectNamespaces(namespace);
        }
        versionProperties = getExpectedVersionProperties(version);
      }

      const expectedResult = {
        opensearchRequestIndex: bulkRequestIndexCounter++,
        requestedId: object.id,
        rawMigratedDoc: this._serializer.savedObjectToRaw(
          this._migrator.migrateDocument({
            id: object.id,
            type: object.type,
            attributes: object.attributes,
            migrationVersion: object.migrationVersion,
            ...(savedObjectNamespace && { namespace: savedObjectNamespace }),
            ...(savedObjectNamespaces && { namespaces: savedObjectNamespaces }),
            updated_at: time,
            references: object.references || [],
            originId: object.originId,
          }) as SavedObjectSanitizedDoc
        ),
      };

      bulkCreateParams.push(
        {
          [method]: {
            _id: expectedResult.rawMigratedDoc._id,
            _index: this.getIndexForType(object.type),
            ...(overwrite && versionProperties),
          },
        },
        expectedResult.rawMigratedDoc._source
      );

      return { tag: 'Right' as 'Right', value: expectedResult };
    });

    const bulkResponse = bulkCreateParams.length
      ? await this.client.bulk({
          refresh,
          body: bulkCreateParams,
        })
      : undefined;

    return {
      saved_objects: expectedBulkResults.map((expectedResult) => {
        if (isLeft(expectedResult)) {
          return expectedResult.error as any;
        }

        const { requestedId, rawMigratedDoc, opensearchRequestIndex } = expectedResult.value;
        const { error, ...rawResponse } = Object.values(
          bulkResponse?.body.items[opensearchRequestIndex] ?? {}
        )[0] as any;

        if (error) {
          return {
            id: requestedId,
            type: rawMigratedDoc._source.type,
            error: getBulkOperationError(error, rawMigratedDoc._source.type, requestedId),
          };
        }

        // When method == 'index' the bulkResponse doesn't include the indexed
        // _source so we return rawMigratedDoc but have to spread the latest
        // _seq_no and _primary_term values from the rawResponse.
        return this._rawToSavedObject({
          ...rawMigratedDoc,
          ...{ _seq_no: rawResponse._seq_no, _primary_term: rawResponse._primary_term },
        });
      }),
    };
  }

  async checkConflicts(
    objects: SavedObjectsCheckConflictsObject[] = [],
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObjectsCheckConflictsResponse> {
    console.log(`I'm inside OpensearchSavedObjectsRepository checkConflicts`);
    if (objects.length === 0) {
      return { errors: [] };
    }

    const namespace = normalizeNamespace(options.namespace);

    let bulkGetRequestIndexCounter = 0;
    const expectedBulkGetResults: Either[] = objects.map((object) => {
      const { type, id } = object;

      if (!this._allowedTypes.includes(type)) {
        return {
          tag: 'Left' as 'Left',
          error: {
            id,
            type,
            error: errorContent(SavedObjectsErrorHelpers.createUnsupportedTypeError(type)),
          },
        };
      }

      return {
        tag: 'Right' as 'Right',
        value: {
          type,
          id,
          opensearchRequestIndex: bulkGetRequestIndexCounter++,
        },
      };
    });

    const bulkGetDocs = expectedBulkGetResults.filter(isRight).map(({ value: { type, id } }) => ({
      _id: this._serializer.generateRawId(namespace, type, id),
      _index: this.getIndexForType(type),
      _source: ['type', 'namespaces'],
    }));
    const bulkGetResponse = bulkGetDocs.length
      ? await this.client.mget(
          {
            body: {
              docs: bulkGetDocs,
            },
          },
          { ignore: [404] }
        )
      : undefined;

    const errors: SavedObjectsCheckConflictsResponse['errors'] = [];
    expectedBulkGetResults.forEach((expectedResult) => {
      if (isLeft(expectedResult)) {
        errors.push(expectedResult.error as any);
        return;
      }

      const { type, id, opensearchRequestIndex } = expectedResult.value;
      const doc = bulkGetResponse?.body.docs[opensearchRequestIndex];
      if (doc?.found) {
        errors.push({
          id,
          type,
          error: {
            ...errorContent(SavedObjectsErrorHelpers.createConflictError(type, id)),
            // @ts-expect-error MultiGetHit._source is optional
            ...(!this.rawDocExistsInNamespace(doc!, namespace) && {
              metadata: { isNotOverwritable: true },
            }),
          },
        });
      }
    });

    return { errors };
  }

  async delete(type: string, id: string, options: SavedObjectsDeleteOptions = {}): Promise<{}> {
    console.log(`I'm inside OpensearchSavedObjectsRepository delete`);
    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    const { refresh = DEFAULT_REFRESH_SETTING, force } = options;
    const namespace = normalizeNamespace(options.namespace);

    const rawId = this._serializer.generateRawId(namespace, type, id);
    let preflightResult: SavedObjectsRawDoc | undefined;

    if (this._registry.isMultiNamespace(type)) {
      preflightResult = await this.preflightCheckIncludesNamespace(type, id, namespace);
      const existingNamespaces = getSavedObjectNamespaces(undefined, preflightResult) ?? [];
      if (
        !force &&
        (existingNamespaces.length > 1 || existingNamespaces.includes(ALL_NAMESPACES_STRING))
      ) {
        throw SavedObjectsErrorHelpers.createBadRequestError(
          'Unable to delete saved object that exists in multiple namespaces, use the `force` option to delete it anyway'
        );
      }
    }

    const { body, statusCode } = await this.client.delete<DeleteDocumentResponse>(
      {
        id: rawId,
        index: this.getIndexForType(type),
        ...getExpectedVersionProperties(undefined, preflightResult),
        refresh,
      },
      { ignore: [404] }
    );

    const deleted = body.result === 'deleted';
    if (deleted) {
      return {};
    }

    const deleteDocNotFound = body.result === 'not_found';
    const deleteIndexNotFound = body.error && body.error.type === 'index_not_found_exception';
    if (deleteDocNotFound || deleteIndexNotFound) {
      // see "404s from missing index" above
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    throw new Error(
      `Unexpected OpenSearch DELETE response: ${JSON.stringify({
        type,
        id,
        response: { body, statusCode },
      })}`
    );
  }

  async deleteByNamespace(
    namespace: string,
    options: SavedObjectsDeleteByNamespaceOptions = {}
  ): Promise<any> {
    console.log(`I'm inside OpensearchSavedObjectsRepository deleteByNamespace`);
    if (!namespace || typeof namespace !== 'string' || namespace === '*') {
      throw new TypeError(`namespace is required, and must be a string that is not equal to '*'`);
    }

    const allTypes = Object.keys(getRootPropertiesObjects(this._mappings));
    const typesToUpdate = allTypes.filter((type) => !this._registry.isNamespaceAgnostic(type));

    const { body } = await this.client.updateByQuery(
      {
        index: this.getIndicesForTypes(typesToUpdate),
        refresh: options.refresh,
        body: {
          script: {
            source: `
              if (!ctx._source.containsKey('namespaces')) {
                ctx.op = "delete";
              } else {
                ctx._source['namespaces'].removeAll(Collections.singleton(params['namespace']));
                if (ctx._source['namespaces'].empty) {
                  ctx.op = "delete";
                }
              }
            `,
            lang: 'painless',
            params: { namespace },
          },
          conflicts: 'proceed',
          ...getSearchDsl(this._mappings, this._registry, {
            namespaces: namespace ? [namespace] : undefined,
            type: typesToUpdate,
          }),
        },
      },
      { ignore: [404] }
    );

    return body;
  }

  async find<T = unknown>(options: SavedObjectsFindOptions): Promise<SavedObjectsFindResponse<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository find`);
    const {
      search,
      defaultSearchOperator = 'OR',
      searchFields,
      rootSearchFields,
      hasReference,
      page = FIND_DEFAULT_PAGE,
      perPage = FIND_DEFAULT_PER_PAGE,
      sortField,
      sortOrder,
      fields,
      namespaces,
      type,
      typeToNamespacesMap,
      filter,
      preference,
    } = options;

    if (!type && !typeToNamespacesMap) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'options.type must be a string or an array of strings'
      );
    } else if (namespaces?.length === 0 && !typeToNamespacesMap) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'options.namespaces cannot be an empty array'
      );
    } else if (type && typeToNamespacesMap) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'options.type must be an empty string when options.typeToNamespacesMap is used'
      );
    } else if ((!namespaces || namespaces?.length) && typeToNamespacesMap) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'options.namespaces must be an empty array when options.typeToNamespacesMap is used'
      );
    }

    const types = type
      ? Array.isArray(type)
        ? type
        : [type]
      : Array.from(typeToNamespacesMap!.keys());
    const allowedTypes = types.filter((t) => this._allowedTypes.includes(t));
    if (allowedTypes.length === 0) {
      return SavedObjectsUtils.createEmptyFindResponse<T>(options);
    }

    if (searchFields && !Array.isArray(searchFields)) {
      throw SavedObjectsErrorHelpers.createBadRequestError('options.searchFields must be an array');
    }

    if (fields && !Array.isArray(fields)) {
      throw SavedObjectsErrorHelpers.createBadRequestError('options.fields must be an array');
    }

    let kueryNode;

    try {
      if (filter) {
        kueryNode = validateConvertFilterToKueryNode(allowedTypes, filter, this._mappings);
      }
    } catch (e) {
      if (e.name === 'DQLSyntaxError') {
        throw SavedObjectsErrorHelpers.createBadRequestError('DQLSyntaxError: ' + e.message);
      } else {
        throw e;
      }
    }

    const opensearchOptions = {
      index: this.getIndicesForTypes(allowedTypes),
      size: perPage,
      from: perPage * (page - 1),
      _source: includedFields(type, fields),
      rest_total_hits_as_int: true,
      preference,
      body: {
        seq_no_primary_term: true,
        ...getSearchDsl(this._mappings, this._registry, {
          search,
          defaultSearchOperator,
          searchFields,
          rootSearchFields,
          type: allowedTypes,
          sortField,
          sortOrder,
          namespaces,
          typeToNamespacesMap,
          hasReference,
          kueryNode,
        }),
      },
    };

    const { body, statusCode } = await this.client.search<SavedObjectsRawDocSource>(
      opensearchOptions,
      {
        ignore: [404],
      }
    );
    if (statusCode === 404) {
      // 404 is only possible here if the index is missing, which
      // we don't want to leak, see "404s from missing index" above
      return {
        page,
        per_page: perPage,
        total: 0,
        saved_objects: [],
      };
    }

    return {
      page,
      per_page: perPage,
      total: body.hits.total,
      saved_objects: body.hits.hits.map(
        (hit: opensearchtypes.SearchHit<SavedObjectsRawDocSource>): SavedObjectsFindResult => ({
          // @ts-expect-error @opensearch-project/opensearch _source is optional
          ...this._rawToSavedObject(hit),
          score: hit._score!,
          // @ts-expect-error @opensearch-project/opensearch _source is optional
          sort: hit.sort,
        })
      ),
    } as SavedObjectsFindResponse<T>;
  }

  async bulkGet<T = unknown>(
    objects: SavedObjectsBulkGetObject[] = [],
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObjectsBulkResponse<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository bulkGet`);
    const namespace = normalizeNamespace(options.namespace);

    if (objects.length === 0) {
      return { saved_objects: [] };
    }

    let bulkGetRequestIndexCounter = 0;
    const expectedBulkGetResults: Either[] = objects.map((object) => {
      const { type, id, fields } = object;

      if (!this._allowedTypes.includes(type)) {
        return {
          tag: 'Left' as 'Left',
          error: {
            id,
            type,
            error: errorContent(SavedObjectsErrorHelpers.createUnsupportedTypeError(type)),
          },
        };
      }

      return {
        tag: 'Right' as 'Right',
        value: {
          type,
          id,
          fields,
          opensearchRequestIndex: bulkGetRequestIndexCounter++,
        },
      };
    });

    const bulkGetDocs = expectedBulkGetResults
      .filter(isRight)
      .map(({ value: { type, id, fields } }) => ({
        _id: this._serializer.generateRawId(namespace, type, id),
        _index: this.getIndexForType(type),
        _source: includedFields(type, fields),
      }));
    const bulkGetResponse = bulkGetDocs.length
      ? await this.client.mget(
          {
            body: {
              docs: bulkGetDocs,
            },
          },
          { ignore: [404] }
        )
      : undefined;

    return {
      saved_objects: expectedBulkGetResults.map((expectedResult) => {
        if (isLeft(expectedResult)) {
          return expectedResult.error as any;
        }

        const { type, id, opensearchRequestIndex } = expectedResult.value;
        const doc = bulkGetResponse?.body.docs[opensearchRequestIndex];

        // @ts-expect-error MultiGetHit._source is optional
        if (!doc?.found || !this.rawDocExistsInNamespace(doc, namespace)) {
          return ({
            id,
            type,
            error: errorContent(SavedObjectsErrorHelpers.createGenericNotFoundError(type, id)),
          } as any) as SavedObject<T>;
        }

        // @ts-expect-error MultiGetHit._source is optional
        return getSavedObjectFromSource(this._registry, type, id, doc);
      }),
    };
  }

  async get<T = unknown>(
    type: string,
    id: string,
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObject<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository get`);

    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    const namespace = normalizeNamespace(options.namespace);

    const { body, statusCode } = await this.client.get<SavedObjectsRawDocSource>(
      {
        id: this._serializer.generateRawId(namespace, type, id),
        index: this.getIndexForType(type),
      },
      { ignore: [404] }
    );

    const indexNotFound = statusCode === 404;
    if (
      !isFoundGetResponse(body) ||
      indexNotFound ||
      !this.rawDocExistsInNamespace(body, namespace)
    ) {
      // see "404s from missing index" above
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    const { originId, updated_at: updatedAt } = body._source;

    let namespaces: string[] = [];
    if (!this._registry.isNamespaceAgnostic(type)) {
      namespaces = body._source.namespaces ?? [
        SavedObjectsUtils.namespaceIdToString(body._source.namespace),
      ];
    }

    return {
      id,
      type,
      namespaces,
      ...(originId && { originId }),
      ...(updatedAt && { updated_at: updatedAt }),
      version: encodeHitVersion(body),
      attributes: body._source[type],
      references: body._source.references || [],
      migrationVersion: body._source.migrationVersion,
    };
  }

  async update<T = unknown>(
    type: string,
    id: string,
    attributes: Partial<T>,
    options: SavedObjectsUpdateOptions = {}
  ): Promise<SavedObjectsUpdateResponse<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository update`);
    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    const { version, references, refresh = DEFAULT_REFRESH_SETTING } = options;
    const namespace = normalizeNamespace(options.namespace);

    let preflightResult: SavedObjectsRawDoc | undefined;
    if (this._registry.isMultiNamespace(type)) {
      preflightResult = await this.preflightCheckIncludesNamespace(type, id, namespace);
    }

    const time = this._getCurrentTime();

    const doc = {
      [type]: attributes,
      updated_at: time,
      ...(Array.isArray(references) && { references }),
    };

    const { body, statusCode } = await this.client.update<SavedObjectsRawDocSource>(
      {
        id: this._serializer.generateRawId(namespace, type, id),
        index: this.getIndexForType(type),
        ...getExpectedVersionProperties(version, preflightResult),
        refresh,

        body: {
          doc,
        },
        _source_includes: ['namespace', 'namespaces', 'originId'],
      },
      { ignore: [404] }
    );

    if (statusCode === 404) {
      // see "404s from missing index" above
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    const { originId } = body.get?._source ?? {};
    let namespaces: string[] = [];
    if (!this._registry.isNamespaceAgnostic(type)) {
      namespaces = body.get?._source.namespaces ?? [
        SavedObjectsUtils.namespaceIdToString(body.get?._source.namespace),
      ];
    }

    return {
      id,
      type,
      updated_at: time,
      version: encodeHitVersion(body),
      namespaces,
      ...(originId && { originId }),
      references,
      attributes,
    };
  }

  async addToNamespaces(
    type: string,
    id: string,
    namespaces: string[],
    options: SavedObjectsAddToNamespacesOptions = {}
  ): Promise<SavedObjectsAddToNamespacesResponse> {
    console.log(`I'm inside OpensearchSavedObjectsRepository addToNamespaces`);
    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    if (!this._registry.isMultiNamespace(type)) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        `${type} doesn't support multiple namespaces`
      );
    }

    if (!namespaces.length) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'namespaces must be a non-empty array of strings'
      );
    }

    const { version, namespace, refresh = DEFAULT_REFRESH_SETTING } = options;
    // we do not need to normalize the namespace to its ID format, since it will be converted to a namespace string before being used

    const rawId = this._serializer.generateRawId(undefined, type, id);
    const preflightResult = await this.preflightCheckIncludesNamespace(type, id, namespace);
    const existingNamespaces = getSavedObjectNamespaces(undefined, preflightResult);
    // there should never be a case where a multi-namespace object does not have any existing namespaces
    // however, it is a possibility if someone manually modifies the document in OpenSearch
    const time = this._getCurrentTime();

    const doc = {
      updated_at: time,
      namespaces: existingNamespaces ? unique(existingNamespaces.concat(namespaces)) : namespaces,
    };

    const { statusCode } = await this.client.update(
      {
        id: rawId,
        index: this.getIndexForType(type),
        ...getExpectedVersionProperties(version, preflightResult),
        refresh,
        body: {
          doc,
        },
      },
      { ignore: [404] }
    );

    if (statusCode === 404) {
      // see "404s from missing index" above
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    return { namespaces: doc.namespaces };
  }

  async deleteFromNamespaces(
    type: string,
    id: string,
    namespaces: string[],
    options: SavedObjectsDeleteFromNamespacesOptions = {}
  ): Promise<SavedObjectsDeleteFromNamespacesResponse> {
    console.log(`I'm inside OpensearchSavedObjectsRepository deleteFromNamespaces`);
    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
    }

    if (!this._registry.isMultiNamespace(type)) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        `${type} doesn't support multiple namespaces`
      );
    }

    if (!namespaces.length) {
      throw SavedObjectsErrorHelpers.createBadRequestError(
        'namespaces must be a non-empty array of strings'
      );
    }

    const { namespace, refresh = DEFAULT_REFRESH_SETTING } = options;
    // we do not need to normalize the namespace to its ID format, since it will be converted to a namespace string before being used

    const rawId = this._serializer.generateRawId(undefined, type, id);
    const preflightResult = await this.preflightCheckIncludesNamespace(type, id, namespace);
    const existingNamespaces = getSavedObjectNamespaces(undefined, preflightResult);
    // if there are somehow no existing namespaces, allow the operation to proceed and delete this saved object
    const remainingNamespaces = existingNamespaces?.filter((x) => !namespaces.includes(x));

    if (remainingNamespaces?.length) {
      // if there is 1 or more namespace remaining, update the saved object
      const time = this._getCurrentTime();

      const doc = {
        updated_at: time,
        namespaces: remainingNamespaces,
      };

      const { statusCode } = await this.client.update(
        {
          id: rawId,
          index: this.getIndexForType(type),
          ...getExpectedVersionProperties(undefined, preflightResult),
          refresh,

          body: {
            doc,
          },
        },
        {
          ignore: [404],
        }
      );

      if (statusCode === 404) {
        // see "404s from missing index" above
        throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
      }
      return { namespaces: doc.namespaces };
    } else {
      // if there are no namespaces remaining, delete the saved object
      const { body, statusCode } = await this.client.delete<DeleteDocumentResponse>(
        {
          id: this._serializer.generateRawId(undefined, type, id),
          refresh,
          ...getExpectedVersionProperties(undefined, preflightResult),
          index: this.getIndexForType(type),
        },
        {
          ignore: [404],
        }
      );

      const deleted = body.result === 'deleted';
      if (deleted) {
        return { namespaces: [] };
      }

      const deleteDocNotFound = body.result === 'not_found';
      const deleteIndexNotFound = body.error && body.error.type === 'index_not_found_exception';
      if (deleteDocNotFound || deleteIndexNotFound) {
        // see "404s from missing index" above
        throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);
      }

      throw new Error(
        `Unexpected OpenSearch DELETE response: ${JSON.stringify({
          type,
          id,
          response: { body, statusCode },
        })}`
      );
    }
  }

  async bulkUpdate<T = unknown>(
    objects: Array<SavedObjectsBulkUpdateObject<T>>,
    options: SavedObjectsBulkUpdateOptions = {}
  ): Promise<SavedObjectsBulkUpdateResponse<T>> {
    console.log(`I'm inside OpensearchSavedObjectsRepository bulkUpdate`);
    const time = this._getCurrentTime();
    const namespace = normalizeNamespace(options.namespace);

    let bulkGetRequestIndexCounter = 0;
    const expectedBulkGetResults: Either[] = objects.map((object) => {
      const { type, id } = object;

      if (!this._allowedTypes.includes(type)) {
        return {
          tag: 'Left' as 'Left',
          error: {
            id,
            type,
            error: errorContent(SavedObjectsErrorHelpers.createGenericNotFoundError(type, id)),
          },
        };
      }

      const { attributes, references, version, namespace: objectNamespace } = object;

      if (objectNamespace === ALL_NAMESPACES_STRING) {
        return {
          tag: 'Left' as 'Left',
          error: {
            id,
            type,
            error: errorContent(
              SavedObjectsErrorHelpers.createBadRequestError('"namespace" cannot be "*"')
            ),
          },
        };
      }
      // `objectNamespace` is a namespace string, while `namespace` is a namespace ID.
      // The object namespace string, if defined, will supersede the operation's namespace ID.

      const documentToSave = {
        [type]: attributes,
        updated_at: time,
        ...(Array.isArray(references) && { references }),
      };

      const requiresNamespacesCheck = this._registry.isMultiNamespace(object.type);

      return {
        tag: 'Right' as 'Right',
        value: {
          type,
          id,
          version,
          documentToSave,
          objectNamespace,
          ...(requiresNamespacesCheck && { opensearchRequestIndex: bulkGetRequestIndexCounter++ }),
        },
      };
    });

    const getNamespaceId = (objectNamespace?: string) =>
      objectNamespace !== undefined
        ? SavedObjectsUtils.namespaceStringToId(objectNamespace)
        : namespace;
    const getNamespaceString = (objectNamespace?: string) =>
      objectNamespace ?? SavedObjectsUtils.namespaceIdToString(namespace);

    const bulkGetDocs = expectedBulkGetResults
      .filter(isRight)
      .filter(({ value }) => value.opensearchRequestIndex !== undefined)
      .map(({ value: { type, id, objectNamespace } }) => ({
        _id: this._serializer.generateRawId(getNamespaceId(objectNamespace), type, id),
        _index: this.getIndexForType(type),
        _source: ['type', 'namespaces'],
      }));
    const bulkGetResponse = bulkGetDocs.length
      ? await this.client.mget(
          {
            body: {
              docs: bulkGetDocs,
            },
          },
          {
            ignore: [404],
          }
        )
      : undefined;

    let bulkUpdateRequestIndexCounter = 0;
    const bulkUpdateParams: object[] = [];
    const expectedBulkUpdateResults: Either[] = expectedBulkGetResults.map(
      (expectedBulkGetResult) => {
        if (isLeft(expectedBulkGetResult)) {
          return expectedBulkGetResult;
        }

        const {
          opensearchRequestIndex,
          id,
          type,
          version,
          documentToSave,
          objectNamespace,
        } = expectedBulkGetResult.value;

        let namespaces;
        let versionProperties;
        if (opensearchRequestIndex !== undefined) {
          const indexFound = bulkGetResponse?.statusCode !== 404;
          const actualResult = indexFound
            ? bulkGetResponse?.body.docs[opensearchRequestIndex]
            : undefined;
          const docFound = indexFound && actualResult?.found === true;
          if (
            !docFound ||
            // @ts-expect-error MultiGetHit is incorrectly missing _id, _source
            !this.rawDocExistsInNamespace(actualResult, getNamespaceId(objectNamespace))
          ) {
            return {
              tag: 'Left' as 'Left',
              error: {
                id,
                type,
                error: errorContent(SavedObjectsErrorHelpers.createGenericNotFoundError(type, id)),
              },
            };
          }
          // @ts-expect-error MultiGetHit is incorrectly missing _id, _source
          namespaces = actualResult!._source.namespaces ?? [
            // @ts-expect-error MultiGetHit is incorrectly missing _id, _source
            SavedObjectsUtils.namespaceIdToString(actualResult!._source.namespace),
          ];
          // @ts-expect-error MultiGetHit is incorrectly missing _id, _source
          versionProperties = getExpectedVersionProperties(version, actualResult);
        } else {
          if (this._registry.isSingleNamespace(type)) {
            // if `objectNamespace` is undefined, fall back to `options.namespace`
            namespaces = [getNamespaceString(objectNamespace)];
          }
          versionProperties = getExpectedVersionProperties(version);
        }

        const expectedResult = {
          type,
          id,
          namespaces,
          opensearchRequestIndex: bulkUpdateRequestIndexCounter++,
          documentToSave: expectedBulkGetResult.value.documentToSave,
        };

        bulkUpdateParams.push(
          {
            update: {
              _id: this._serializer.generateRawId(getNamespaceId(objectNamespace), type, id),
              _index: this.getIndexForType(type),
              ...versionProperties,
            },
          },
          { doc: documentToSave }
        );

        return { tag: 'Right' as 'Right', value: expectedResult };
      }
    );

    const { refresh = DEFAULT_REFRESH_SETTING } = options;
    const bulkUpdateResponse = bulkUpdateParams.length
      ? await this.client.bulk({
          refresh,
          body: bulkUpdateParams,
          _source_includes: ['originId'],
        })
      : undefined;

    return {
      saved_objects: expectedBulkUpdateResults.map((expectedResult) => {
        if (isLeft(expectedResult)) {
          return expectedResult.error as any;
        }

        const {
          type,
          id,
          namespaces,
          documentToSave,
          opensearchRequestIndex,
        } = expectedResult.value;
        const response = bulkUpdateResponse?.body.items[opensearchRequestIndex] ?? {};
        // When a bulk update operation is completed, any fields specified in `_sourceIncludes` will be found in the "get" value of the
        // returned object. We need to retrieve the `originId` if it exists so we can return it to the consumer.
        const { error, _seq_no: seqNo, _primary_term: primaryTerm, get } = Object.values(
          response
        )[0] as any;

        // eslint-disable-next-line @typescript-eslint/naming-convention
        const { [type]: attributes, references, updated_at } = documentToSave;
        if (error) {
          return {
            id,
            type,
            error: getBulkOperationError(error, type, id),
          };
        }

        const { originId } = get._source;
        return {
          id,
          type,
          ...(namespaces && { namespaces }),
          ...(originId && { originId }),
          updated_at,
          version: encodeVersion(seqNo, primaryTerm),
          attributes,
          references,
        };
      }),
    };
  }

  async incrementCounter(
    type: string,
    id: string,
    counterFieldName: string,
    options: SavedObjectsIncrementCounterOptions = {}
  ): Promise<SavedObject> {
    console.log(`I'm inside OpensearchSavedObjectsRepository incrementCounter`);
    if (typeof type !== 'string') {
      throw new Error('"type" argument must be a string');
    }
    if (typeof counterFieldName !== 'string') {
      throw new Error('"counterFieldName" argument must be a string');
    }
    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createUnsupportedTypeError(type);
    }

    const { migrationVersion, refresh = DEFAULT_REFRESH_SETTING } = options;
    const namespace = normalizeNamespace(options.namespace);

    const time = this._getCurrentTime();
    let savedObjectNamespace;
    let savedObjectNamespaces: string[] | undefined;

    if (this._registry.isSingleNamespace(type) && namespace) {
      savedObjectNamespace = namespace;
    } else if (this._registry.isMultiNamespace(type)) {
      savedObjectNamespaces = await this.preflightGetNamespaces(type, id, namespace);
    }

    const migrated = this._migrator.migrateDocument({
      id,
      type,
      ...(savedObjectNamespace && { namespace: savedObjectNamespace }),
      ...(savedObjectNamespaces && { namespaces: savedObjectNamespaces }),
      attributes: { [counterFieldName]: 1 },
      migrationVersion,
      updated_at: time,
    });

    const raw = this._serializer.savedObjectToRaw(migrated as SavedObjectSanitizedDoc);

    const { body } = await this.client.update<SavedObjectsRawDocSource>({
      id: raw._id,
      index: this.getIndexForType(type),
      refresh,
      _source: 'true',
      body: {
        script: {
          source: `
              if (ctx._source[params.type][params.counterFieldName] == null) {
                ctx._source[params.type][params.counterFieldName] = params.count;
              }
              else {
                ctx._source[params.type][params.counterFieldName] += params.count;
              }
              ctx._source.updated_at = params.time;
            `,
          lang: 'painless',
          params: {
            count: 1,
            time,
            type,
            counterFieldName,
          },
        },
        upsert: raw._source,
      },
    });

    const { originId } = body.get?._source ?? {};
    return {
      id,
      type,
      ...(savedObjectNamespaces && { namespaces: savedObjectNamespaces }),
      ...(originId && { originId }),
      updated_at: time,
      references: body.get?._source.references ?? [],
      version: encodeHitVersion(body),
      attributes: body.get?._source[type],
    };
  }
}
