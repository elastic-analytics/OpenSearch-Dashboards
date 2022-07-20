/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

import { Client } from '@opensearch-project/opensearch';
import { Logger } from '../../logging';
import { OpenSearchClient, OpenSearchClientConfig } from '../../opensearch/client';
import { SavedObjectsClientContract } from '../../saved_objects/types';

/**
 * TODO: update doc
 * Represents an OpenSearch cluster API client created by the platform.
 * It allows to call API on behalf of the internal OpenSearch Dashboards user and
 * the actual user that is derived from the request headers (via `asScoped(...)`).
 *
 * @public
 **/
export interface IDdataSourceClient {
  /**
   * TODO: update doc. Creates a {@link IScopedClusterClient | scoped cluster client} bound to given {@link ScopeableRequest | request}
   */
  asDataSource: (dataSourceId: string) => Promise<OpenSearchClient>;
}

/**
 * See {@link IClusterClient}
 *
 * @public
 */
export interface ICustomDataSourceClient extends IDdataSourceClient {
  /**
   * Closes the data source client. After that client cannot be used and one should
   * create a new client instance to be able to interact with OpenSearch API.
   */
  close: () => Promise<void>;
}

export class DataSourceClient implements ICustomDataSourceClient {
  public dataSourceClientsPool: Map<string, Client>;
  private savedObjectClient: SavedObjectsClientContract;
  private isDataSourceFeautureEnabled = true;
  private isClosed = false;

  constructor(
    private readonly config: OpenSearchClientConfig,
    savedObjectClient: SavedObjectsClientContract,
    logger: Logger
  ) {
    // init pool as empty
    this.dataSourceClientsPool = new Map<string, Client>();
    this.savedObjectClient = savedObjectClient;
    // TODO: 1.read config and determine isDataSourceEnabled Flag
    // 2. throw error if isDataSourceEnabled == false, while API is called
  }
  async asDataSource(dataSourceId: string) {
    // 1. fetch meta info of data source using saved_object client
    const dataSource = await this.savedObjectClient.get('data-source', dataSourceId);

    // 2. TODO: parse to DataSource object, need update once dataSource type is in place
    const dataSourceObj = dataSource!.attributes as any;
    const url = dataSourceObj.endpoint.url;
    /**
     * TODO:
     * credential manager will provide "decrypt(authId: string)" to return auth
     * Example code: cosnt {username, password} = credentialManager.decrpt(dataSourceObj.authId)
     */
    const username = dataSourceObj.endpoint.credentials.username;
    const password = dataSourceObj.endpoint.credentials.password;

    // 2. build/find client and return
    let dataSourceClient = this.dataSourceClientsPool.get(dataSourceId);
    if (!dataSourceClient) {
      // TODO: make use of existing default clientConfig to build client
      dataSourceClient = new Client({
        node: url,
        auth: {
          username,
          password,
        },
      });
      // update pool
      this.dataSourceClientsPool.set(dataSourceId, dataSourceClient);
    }
    return dataSourceClient;
  }

  // close anything in pool
  public async close() {
    if (this.isClosed) {
      return;
    }
    this.isClosed = true;
    await Promise.all([
      this.dataSourceClientsPool.forEach((v, k) => {
        v.close();
      }),
    ]);
  }
}
