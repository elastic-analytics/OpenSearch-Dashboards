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
import { SavedObjectsErrorHelpers } from '../errors';
import { decodeRequestVersion } from '../../../version';
import { SavedObjectSanitizedDoc } from '../../../serialization';
import { SavedObjectsCreateOptions } from '../../saved_objects_client';
import { SavedObject } from '../../../types';
import {
  SavedObjectsRepository,
  normalizeNamespace,
  getSavedObjectNamespaces,
  DEFAULT_REFRESH_SETTING,
} from '../repository';

export class OpensearchSavedObjectsRepository extends SavedObjectsRepository {
  public async create<T = unknown>(
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

    // console.log('Inside create : Persists an object');
    if (initialNamespaces) {
      if (!this._registry.isMultiNamespace(type)) {
        throw SavedObjectsErrorHelpers.createBadRequestError(
          '"options.initialNamespaces" can only be used on multi-namespace types'
        );
      } else if (!initialNamespaces.length) {
        throw SavedObjectsErrorHelpers.createBadRequestError(
          '"options.initialNamespaces" must be a non-empty array of strings'
        );
      }
    }

    if (!this._allowedTypes.includes(type)) {
      throw SavedObjectsErrorHelpers.createUnsupportedTypeError(type);
    }

    const time = this._getCurrentTime();
    // console.log('time', time);
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

    // console.log('coming here atleast');

    // await this.postgresClient
    //   .query(
    //     `INSERT INTO kibana(id, body, type, updated_at) VALUES('${
    //       requestParams.id
    //     }', json('${JSON.stringify(requestParams.body)}'), '${type}', '${time}')`
    //   )
    //   .then((res: any) => {
    //     // console.log('Saved object inserted in kibana table successfully.');
    //   })
    //   .catch((error: any) => {
    //     throw new Error(error);
    //   });

    return this._rawToSavedObject<T>({
      ...raw,
      ...body,
    });
  }
}
