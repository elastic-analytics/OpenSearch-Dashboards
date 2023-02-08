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
/* eslint-disable no-console */
import { SavedObject, SavedObjectsBaseOptions, SavedObjectsFindOptions } from '../../../types';
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
import {
  normalizeNamespace,
  SavedObjectsDeleteByNamespaceOptions,
  SavedObjectsIncrementCounterOptions,
  SavedObjectsRepository,
  SavedObjectsRepositoryOptions,
} from '../repository';
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

    const id = options.id;
    const overwrite = options.overwrite;
    // const refresh = options.refresh; // We don't need refresh for SQL operation.
    // ToDo: For now we are just storing version in table. Later we need to decide whether we want to use it for concurrency control or not.
    const version = options.version;

    if (id && overwrite)
      console.log(`====================Saved Object is being CREATED==============`);
    else console.log(`======================Saved object is being UPDATED================`);

    const namespace = normalizeNamespace(options.namespace);
    let existingNamespaces: string[] | undefined;
    if (id && overwrite) {
      existingNamespaces = await this.preflightGetNamespaces(type, id, namespace);
    }

    const raw = this.getSavedObjectRawDoc(type, attributes, options, namespace, existingNamespaces);

    // ToDo: Decide if you want to keep raw._source or raw._source[type] in attributes field.
    await this.postgresClient
      .query(
        `INSERT INTO metadatastore(id, type, version, attributes, reference, migrationversion, namespaces, originid, updated_at) 
        VALUES('${raw._id}', '${type}', '${version}', json('${JSON.stringify(raw._source)}'), 
        ${raw._source.references}, ${raw._source.migrationVersion}, ${raw._source.namespaces},
        '${raw._source.originId}', '${raw._source.updated_at}')`
      )
      .then(() => {
        console.log('Saved object inserted in kibana table successfully.');
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    return this._rawToSavedObject<T>({
      ...raw,
      // ...body, //ToDo: Check what is value of body in case of OpenSearch.
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
    const {
      search,
      searchFields,
      page = FIND_DEFAULT_PAGE,
      perPage = FIND_DEFAULT_PER_PAGE,
      fields,
    } = options;

    this.validateTypeAndNamespace(options);
    const allowedTypes = this.getAllowedTypes(options);
    if (allowedTypes.length === 0) {
      return SavedObjectsUtils.createEmptyFindResponse<T>(options);
    }

    this.validateSearchFields(searchFields);

    this.validateFields(fields);

    let sql = `SELECT "id", "type", "version", "attributes", "reference", 
              "migrationversion", "namespaces", "originid", "updated_at" 
              FROM "metadatastore" where type IN(${allowedTypes
                // eslint-disable-next-line no-shadow
                .map((type) => `'${type}'`)
                .join(',')})`;
    console.log('SQL statement without search expression >>>>>>>', sql);

    let buildLikeExpr: string | undefined = '';
    if (search) {
      console.log(`search value ${search}`);
      buildLikeExpr = searchFields
        ?.map(
          (field) =>
            `attributes->>'$."${field.split('^')[0]}"') LIKE '%${search.replace('*', '')}%'`
        )
        .join(' OR ');
    }
    sql = buildLikeExpr ? `${sql} AND (${buildLikeExpr})` : `${sql}`;
    console.log('statement with search query >>>>>>>>>>', sql);
    let results: any;
    await this.postgresClient
      .query(sql)
      .then((res: any) => {
        results = res.rows;
        console.log('results', JSON.stringify(results, null, 4));
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    // ToDO: Handle 404 case i.e. when the index is missing.
    if (results && results.length) {
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
      total: results.length,
      saved_objects: results.map(
        (hit: any): SavedObjectsFindResult => ({
          ...this._rawToSavedObject({
            _source: JSON.parse(hit.attributes),
            _id: hit.id,
            _seq_no: 1,
            _primary_term: 10,
          }),
          score: (hit as any)._score,
        })
      ),
    } as SavedObjectsFindResponse<T>;
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
    throw new Error('Method not implemented');
    /*
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
    */
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

  private async preflightGetNamespaces(type: string, id: string, namespace?: string) {
    // ToDo: Fetch namespace from database.
    return undefined;
  }
}
