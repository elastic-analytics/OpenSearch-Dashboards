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
import { SavedObjectsErrorHelpers } from '../errors';
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
    const query = `INSERT INTO metadatastore(id, type, version, attributes, reference, migrationversion, namespaces, originid, updated_at) 
    VALUES('${raw._id}', '${type}', '${version ?? ''}', '${JSON.stringify(raw._source)}', 
    '${JSON.stringify(raw._source.references)}', 
    '${JSON.stringify(raw._source.migrationVersion ?? {})}', 
    '${JSON.stringify(raw._source.namespaces ?? [])}',
    '${raw._source.originId ?? ''}', '${raw._source.updated_at}')`;
    console.log(`Insert query = ${query}`);
    // ToDo: Decide if you want to keep raw._source or raw._source[type] in attributes field.
    // Above decision to be made after we decide on search functionality.
    await this.postgresClient
      .query(query)
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
    const namespace = normalizeNamespace(options.namespace);
    // ToDo: Do validation of objects as we do in OpenSearch.
    // For sake of POC, we are just inserting all object in a loop.
    const query = `INSERT INTO metadatastore(id, type, version, attributes, reference, migrationversion, namespaces, originid, updated_at) VALUES `;

    const expectedBulkResult = objects.map((object) => {
      // const refresh = options.refresh; // We don't need refresh for SQL operation.
      // ToDo: For now we are just storing version in table. Later we need to decide whether we want to use it for concurrency control or not.
      const raw = this.getSavedObjectRawDoc(
        object.type,
        object.attributes,
        object as SavedObjectsCreateOptions,
        namespace,
        []
      );

      const insertValuesExpr = `('${raw._id}', '${object.type}',
    '${object.version ?? ''}', '${JSON.stringify(raw._source).replace(/'/g, `''`)}',
    '${JSON.stringify(raw._source.references)}',
    '${JSON.stringify(raw._source.migrationVersion ?? {})}',
    '${JSON.stringify(raw._source.namespaces ?? [])}',
    '${raw._source.originId ?? ''}', '${raw._source.updated_at}')`;
      // ToDo: Decide if you want to keep raw._source or raw._source[type] in attributes field.
      // Refactor code to insert all rows in single transaction.
      this.postgresClient
        .query(`${query} ${insertValuesExpr}`)
        .then(() => {
          console.log('Saved object inserted in kibana table successfully.');
        })
        .catch((error: any) => {
          console.error(`error occurred for this query -> "${query} ${insertValuesExpr}"`);
          throw new Error(error);
        });
      const expectedResult = { rawMigratedDoc: raw };
      return { tag: 'Right' as 'Right', value: expectedResult };
    });

    return {
      saved_objects: expectedBulkResult.map((expectedResult) => {
        // When method == 'index' the bulkResponse doesn't include the indexed
        // _source so we return rawMigratedDoc but have to spread the latest
        // _seq_no and _primary_term values from the rawResponse.
        const { rawMigratedDoc } = expectedResult.value;
        return this._rawToSavedObject({
          ...rawMigratedDoc,
        });
      }),
    };
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
          (field) => `attributes->>'$."${field.split('^')[0]}"' LIKE '%${search.replace('*', '')}%'`
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

    this.validateType(type);

    const namespace = normalizeNamespace(options.namespace);

    // ToDo: Find out - 1. Why we are passing index to get api? 2. What is index for type? 3. whta is the index value in case of opensearch?
    /*
    const { body, statusCode } = await this.client.get<SavedObjectsRawDocSource>(
      {
        id: this._serializer.generateRawId(namespace, type, id),
        index: this.getIndexForType(type),
      },
      { ignore: [404] }
    );
    */
    // ToDo: Include index for type in where clause if needed.
    const query = `SELECT "id", "type", "version", "attributes", "reference", 
    "migrationversion", "namespaces", "originid", "updated_at" 
    FROM "metadatastore" where id='${this._serializer.generateRawId(namespace, type, id)}'`;
    console.log(`SQL statement = ${query}`);

    let results: any;
    await this.postgresClient
      .query(query)
      .then((res: any) => {
        results = res.rows[0];
        console.log('results', JSON.stringify(results, null, 4));
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    // ToDo: Find out - 1. Do we need to handle index not found?
    // 2. Implement rawDocExistsInNamespace for RDS. We need convet attributes column to raw saved object and pass it existing rawDocExistsInNamespace.
    if (!results || results.length === 0)
      throw SavedObjectsErrorHelpers.createGenericNotFoundError(type, id);

    // const temp = results.attributes;

    const originId = results.originid;
    const updatedAt = results.updated_at;
    console.log(`originId = ${originId} and updatedAt = ${updatedAt}`);

    let namespaces: string[] = [];
    if (!this._registry.isNamespaceAgnostic(type)) {
      namespaces = results.namespaces ?? [SavedObjectsUtils.namespaceIdToString(results.namespace)];
    }
    console.log(`namespaces = ${namespaces}`);
    // console.log(`attributes = ${JSON.stringify(results.attributes[type])}`);

    // Todo: Research about version parameter
    return {
      id,
      type,
      namespaces,
      ...(originId && { originId }),
      ...(updatedAt && { updated_at: updatedAt }),
      // version: encodeHitVersion(body),
      attributes: results.attributes[type],
      references: results.references || [],
      migrationVersion: results.migrationVersion,
    };
  }

  async update<T = unknown>(
    type: string,
    id: string,
    attributes: Partial<T>,
    options: SavedObjectsUpdateOptions = {}
  ): Promise<SavedObjectsUpdateResponse<T>> {
    console.log(`I'm inside PostgresSavedObjectsRepository update`);
    // ToDo: Do validation of some fields as we are doing in case of OpenSearch.

    const references = options.references ?? [];
    const namespace = normalizeNamespace(options.namespace);
    const time = this._getCurrentTime();

    const selectQuery = `SELECT "originid", "attributes" , "namespaces" 
    FROM "metadatastore" where id='${this._serializer.generateRawId(namespace, type, id)}'`;
    console.log(`SQL statement = ${selectQuery}`);

    let results: any;
    await this.postgresClient
      .query(selectQuery)
      .then((res: any) => {
        if (res && res.rows.length > 0) {
          results = res.rows[0].attributes;
          console.log('attributes', JSON.stringify(attributes, null, 4));
        }
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    if (results) {
      results[type] = attributes;
      // Update attributes, references, updated_at
      const updateQuery = `UPDATE metadatastore SET 
        attributes='${JSON.stringify(results)}', 
        updated_at='${time}', reference='${JSON.stringify(references)}' 
        WHERE id='${this._serializer.generateRawId(namespace, type, id)}'`;
      console.log(`SQL statement = ${updateQuery}`);
      await this.postgresClient
        .query(updateQuery)
        .then((res: any) => {
          console.log(`update operation is successful.`);
        })
        .catch((error: any) => {
          throw new Error(error);
        });
    }

    const { originId } = results.originId ?? {};
    let namespaces: string[] = [];
    if (!this._registry.isNamespaceAgnostic(type)) {
      namespaces = results.namespaces ?? [];
    }

    return {
      id,
      type,
      updated_at: time,
      // version: encodeHitVersion(body),
      namespaces,
      ...(originId && { originId }),
      references,
      attributes: results,
    };
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
    // ToDo: Do validation of some fields as we are doing in case of OpenSearch.
    const namespace = normalizeNamespace(options.namespace);
    const time = this._getCurrentTime();
    const existingNamespaces = await this.preflightGetNamespaces(type, id, namespace);
    const raw = this.getSavedObjectRawDoc(
      type,
      { [counterFieldName]: 1 },
      options,
      namespace,
      existingNamespaces
    );

    const selectQuery = `SELECT "attributes" FROM "metadatastore" where id='${raw._id}'`;
    console.log(`SQL statement = ${selectQuery}`);

    let attributes: any;
    await this.postgresClient
      .query(selectQuery)
      .then((res: any) => {
        if (res && res.rows.length > 0) {
          attributes = res.rows[0].attributes;
          console.log('attributes', JSON.stringify(attributes, null, 4));
        }
      })
      .catch((error: any) => {
        throw new Error(error);
      });

    if (attributes) {
      if (attributes[type][counterFieldName] == null) {
        attributes[type][counterFieldName] = 1;
      } else {
        attributes[type][counterFieldName] += 1;
      }

      console.log(`Updtaed attributes = ${JSON.stringify(attributes)}`);

      const updateQuery = `UPDATE metadatastore SET attributes=${attributes}, updated_at=${time} WHERE id=${raw._id}`;
      await this.postgresClient
        .query(updateQuery)
        .then((res: any) => {
          raw._source = attributes;
          console.log(`incremented counter successfully`);
        })
        .catch((error: any) => {
          throw new Error(error);
        });
    } else {
      raw._source[type][counterFieldName] = 1;
      console.log(`raw._source.migrationVersion = ${raw._source.migrationVersion} `);
      const insertQuery = `INSERT INTO metadatastore(id, type, attributes, reference, migrationversion, namespaces, originid, updated_at) 
        VALUES('${raw._id}', '${type}', '${JSON.stringify(raw._source)}', 
        '${JSON.stringify(raw._source.references)}', 
        '${JSON.stringify(raw._source.migrationVersion ?? {})}', 
        '${JSON.stringify(raw._source.namespaces ?? [])}',
        '${raw._source.originId ?? ''}', '${raw._source.updated_at}')`;
      console.log(`Insert query = ${insertQuery}`);
      // ToDo: Decide if you want to keep raw._source or raw._source[type] in attributes field.
      await this.postgresClient
        .query(insertQuery)
        .then(() => {
          console.log('Saved object inserted in kibana table successfully.');
        })
        .catch((error: any) => {
          throw new Error(error);
        });
    }

    return this._rawToSavedObject({
      ...raw,
    });
  }

  private async preflightGetNamespaces(type: string, id: string, namespace?: string) {
    // ToDo: Fetch namespace from database.
    return undefined;
  }
}
