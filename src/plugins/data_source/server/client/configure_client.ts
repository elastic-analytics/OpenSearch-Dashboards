/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 */

import { Client } from '@opensearch-project/opensearch';
import {
  Logger,
  SavedObject,
  SavedObjectsClientContract,
  SavedObjectsErrorHelpers,
} from '../../../../../src/core/server';
import { DATA_SOURCE_SAVED_OBJECT_TYPE } from '../../common';

import { DataSourceAttributes, UsernamePasswordTypedContent } from '../../common/data_sources';
import { DataSourcePluginConfigType } from '../../config';
import { CryptographyClient } from '../cryptography';
import { parseClientOptions } from './client_config';
import { OpenSearchClientPoolSetup } from './client_pool';

export const configureClient = async (
  dataSourceId: string,
  savedObjects: SavedObjectsClientContract,
  cryptographyClient: CryptographyClient,
  openSearchClientPoolSetup: OpenSearchClientPoolSetup,
  config: DataSourcePluginConfigType,
  logger: Logger
): Promise<Client> => {
  const dataSource = await getDataSource(dataSourceId, savedObjects);
  const rootClient = getRootClient(dataSource.attributes, config, openSearchClientPoolSetup);

  return getQueryClient(rootClient, dataSource, cryptographyClient);
};

export const getDataSource = async (
  dataSourceId: string,
  savedObjects: SavedObjectsClientContract
): Promise<SavedObject<DataSourceAttributes>> => {
  try {
    const dataSource = await savedObjects.get<DataSourceAttributes>(
      DATA_SOURCE_SAVED_OBJECT_TYPE,
      dataSourceId
    );
    return dataSource;
  } catch (error: any) {
    // it will cause 500 error when failed to get saved objects, need to handle such error gracefully
    throw SavedObjectsErrorHelpers.createBadRequestError(error.message);
  }
};

export const getCredential = async (
  dataSource: SavedObject<DataSourceAttributes>,
  cryptographyClient: CryptographyClient
): Promise<UsernamePasswordTypedContent> => {
  try {
    const { username, password } = dataSource.attributes.credentials!.credentialsContent;
    const decodedPassword = await cryptographyClient.decodeAndDecrypt(password);
    const credential = {
      username,
      password: decodedPassword,
    };

    return credential;
  } catch (error: any) {
    // it will cause 500 error when failed to get saved objects, need to handle such error gracefully
    throw SavedObjectsErrorHelpers.createBadRequestError(error.message);
  }
};

/**
 * Create a child client object with given auth info.
 *
 * @param rootClient root client for the connection with given data source endpoint.
 * @param dataSource data source saved object
 * @param savedObjects scoped saved object client
 * @returns child client.
 */
const getQueryClient = async (
  rootClient: Client,
  dataSource: SavedObject<DataSourceAttributes>,
  cryptographyClient: CryptographyClient
): Promise<Client> => {
  if (dataSource.attributes.noAuth) {
    return rootClient.child();
  } else {
    const credential = await getCredential(dataSource, cryptographyClient);

    return getBasicAuthClient(rootClient, credential);
  }
};

/**
 * Gets a root client object of the OpenSearch endpoint.
 * Will attempt to get from cache, if cache miss, create a new one and load into cache.
 *
 * @param dataSourceAttr data source saved objects attributes.
 * @param config data source config
 * @returns OpenSearch client for the given data source endpoint.
 */
const getRootClient = (
  dataSourceAttr: DataSourceAttributes,
  config: DataSourcePluginConfigType,
  { getClientFromPool, addClientToPool }: OpenSearchClientPoolSetup
): Client => {
  const endpoint = dataSourceAttr.endpoint;
  const cachedClient = getClientFromPool(endpoint);
  if (cachedClient) {
    return cachedClient;
  } else {
    const clientOptions = parseClientOptions(config, endpoint);

    const client = new Client(clientOptions);
    addClientToPool(endpoint, client);

    return client;
  }
};

const getBasicAuthClient = (
  rootClient: Client,
  credential: UsernamePasswordTypedContent
): Client => {
  const { username, password } = credential;
  return rootClient.child({
    auth: {
      username,
      password,
    },
    // Child client doesn't allow auth option, adding null auth header to bypass,
    // so logic in child() can rebuild the auth header based on the auth input.
    // See https://github.com/opensearch-project/OpenSearch-Dashboards/issues/2182 for details
    headers: { authorization: null },
  });
};
