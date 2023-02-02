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

import { opensearchtypes } from '@opensearch-project/opensearch';
import { SavedObjectSanitizedDoc, SavedObjectsRawDocSource } from '../../../serialization';
import { SavedObject, SavedObjectsBaseOptions, SavedObjectsFindOptions } from '../../../types';
import { decodeRequestVersion, encodeHitVersion } from '../../../version';
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
import { SavedObjectsErrorHelpers } from '../errors';
import { validateConvertFilterToKueryNode } from '../filter_utils';
import { includedFields } from '../included_fields';
import {
  DEFAULT_REFRESH_SETTING,
  getSavedObjectNamespaces,
  isFoundGetResponse,
  normalizeNamespace,
  SavedObjectsDeleteByNamespaceOptions,
  SavedObjectsIncrementCounterOptions,
  SavedObjectsRepository,
  SavedObjectsRepositoryOptions,
} from '../repository';
import { getSearchDsl } from '../search_dsl';
import { FIND_DEFAULT_PAGE, FIND_DEFAULT_PER_PAGE, SavedObjectsUtils } from '../utils';

export class PostgresSavedObjectsRepository extends SavedObjectsRepository {
  private readonly postgresClient: any;

  constructor(options: SavedObjectsRepositoryOptions, postgresClient: any) {
    console.log(`I'm inside PostgresSavedObjectsRepository constructor`);
    super(options);
    this.postgresClient = postgresClient;
  }

  async create<T = unknown>(
    type: string,
    attributes: T,
    options: SavedObjectsCreateOptions = {}
  ): Promise<SavedObject<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository create`);
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

    // ToDo: Needs to be removed
    const { body } =
      id && overwrite
        ? await this.client.index(requestParams)
        : await this.client.create(requestParams);

    await this.postgresClient
      .query(
        `INSERT INTO kibana(id, body, type, updated_at) VALUES('${
          requestParams.id
        }', json('${JSON.stringify(requestParams.body)}'), '${type}', '${time}')`
      )
      .then((res: any) => {
        console.log('Saved object inserted in kibana table successfully.');
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    return this._rawToSavedObject<T>({
      ...raw,
      ...body,
    });
  }

  async bulkCreate<T = unknown>(
    objects: Array<SavedObjectsBulkCreateObject<T>>,
    options: SavedObjectsCreateOptions = {}
  ): Promise<SavedObjectsBulkResponse<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository bulkCreate`);
    throw new Error('Method not implemented');
  }

  async checkConflicts(
    objects: SavedObjectsCheckConflictsObject[] = [],
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObjectsCheckConflictsResponse> {
    console.log(`I'm inside PostgresSavedObjectsRepository checkConflicts`);
    throw new Error('Method not implemented');
  }

  async delete(type: string, id: string, options: SavedObjectsDeleteOptions = {}): Promise<{}> {
    console.log(`I'm inside PostgresSavedObjectsRepository delete`);
    throw new Error('Method not implemented');
  }

  async deleteByNamespace(
    namespace: string,
    options: SavedObjectsDeleteByNamespaceOptions = {}
  ): Promise<any> {
    console.log(`I'm inside PostgresSavedObjectsRepository deleteByNamespace`);
    throw new Error('Method not implemented');
  }

  async find<T = unknown>(options: SavedObjectsFindOptions): Promise<SavedObjectsFindResponse<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository find`);
    // ToDo: Refactor to remove repetitive code
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
    // ********** This code copied from Mihir's POC *************************
    // console.trace('Options', JSON.stringify(options, null, 4));
    // console.trace('Allowed', JSON.stringify(allowedTypes, null, 4));
    // console.log('opensearchOptions', JSON.stringify(opensearchOptions, null, 4));
    let sql = `SELECT id,body from kibana where type IN(${allowedTypes
      .map((type) => `'${type}'`)
      .join(',')})`;
    if (search) {
      const buildLikeExpr = searchFields
        ?.map(
          (field) =>
            `json_extract(json_each.value, '$.${field.split('^')[0]}') LIKE '%${search.replace(
              '*',
              ''
            )}%'`
        )
        .join(' OR ');
      // SELECT kibana.id, kibana.body from kibana, json_each(kibana.body) where json_valid(json_each.value) and json_extract(json_each.value, '$.title') like '%mihson%'
      sql = `SELECT kibana.id, kibana.body from kibana, json_each(kibana.body) where kibana.type IN(${allowedTypes
        .map((type) => `'${type}'`)
        .join(',')}) AND json_valid(json_each.value) AND (${buildLikeExpr})`;
    }
    console.log('statement', sql);
    //const results = await this.postgresClient.all(sql);
    await this.postgresClient
      .query(sql)
      .then((res: any) => {
        console.log('results', JSON.stringify(res, null, 4));
      })
      .catch((error: any) => {
        throw new Error(error);
      });
    // *************************************************************************

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
    // throw new Error('Method not implemented');
  }

  async bulkGet<T = unknown>(
    objects: SavedObjectsBulkGetObject[] = [],
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObjectsBulkResponse<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository bulkGet`);
    throw new Error('Method not implemented');
  }

  async get<T = unknown>(
    type: string,
    id: string,
    options: SavedObjectsBaseOptions = {}
  ): Promise<SavedObject<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository get`);

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
    let results;
    const sql = `SELECT id,body FROM kibana WHERE id='${this._serializer.generateRawId(
      namespace,
      type,
      id
    )}'`;
    console.log('SQL statement', sql);
    await this.postgresClient
      .query(sql)
      .then((res: any) => {
        results = res;
        console.log('results', JSON.stringify(results, null, 4));
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    const docNotFound = body.found === false || results === undefined;
    const indexNotFound = statusCode === 404;
    if (docNotFound || indexNotFound || !this.rawDocExistsInNamespace(body, namespace)) {
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
    console.log(`I'm inside PostgresSavedObjectsRepository update`);
    throw new Error('Method not implemented');
  }

  async addToNamespaces(
    type: string,
    id: string,
    namespaces: string[],
    options: SavedObjectsAddToNamespacesOptions = {}
  ): Promise<SavedObjectsAddToNamespacesResponse> {
    console.log(`I'm inside PostgresSavedObjectsRepository addToNamespaces`);
    throw new Error('Method not implemented');
  }

  async deleteFromNamespaces(
    type: string,
    id: string,
    namespaces: string[],
    options: SavedObjectsDeleteFromNamespacesOptions = {}
  ): Promise<SavedObjectsDeleteFromNamespacesResponse> {
    console.log(`I'm inside PostgresSavedObjectsRepository deleteFromNamespaces`);
    throw new Error('Method not implemented');
  }

  async bulkUpdate<T = unknown>(
    objects: Array<SavedObjectsBulkUpdateObject<T>>,
    options: SavedObjectsBulkUpdateOptions = {}
  ): Promise<SavedObjectsBulkUpdateResponse<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository bulkUpdate`);
    throw new Error('Method not implemented');
  }

  async incrementCounter(
    type: string,
    id: string,
    counterFieldName: string,
    options: SavedObjectsIncrementCounterOptions = {}
  ): Promise<SavedObject> {
    console.log(`I'm inside PostgresSavedObjectsRepository incrementCounter`);
    throw new Error('Method not implemented');
  }
}
