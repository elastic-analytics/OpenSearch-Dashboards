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
import { first } from 'rxjs/operators';

import {
  PluginInitializerContext,
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../core/server';

import { CredentialManagementPluginSetup, CredentialManagementPluginStart } from './types';
import { credentialSavedObjectType } from './saved_objects';
import { ConfigSchema } from '../config';
import { CryptographySingleton } from './crypto';
import { CredentialSavedObjectsClientWrapper } from './saved_objects';

export class CredentialManagementPlugin
  implements Plugin<CredentialManagementPluginSetup, CredentialManagementPluginStart> {
  private readonly logger: Logger;
  private initializerContext: PluginInitializerContext<ConfigSchema>;

  private cryptographySingleton?: CryptographySingleton;
  private credentialSavedObjectsClientWrapper: CredentialSavedObjectsClientWrapper;

  constructor(initializerContext: PluginInitializerContext<ConfigSchema>) {
    this.logger = initializerContext.logger.get();
    this.initializerContext = initializerContext;
    this.credentialSavedObjectsClientWrapper = new CredentialSavedObjectsClientWrapper();
  }

  public async setup(core: CoreSetup) {
    this.logger.debug('credential_management: Setup');

    const { opensearchDashboards } = await this.initializerContext.config.legacy.globalConfig$
      .pipe(first())
      .toPromise();

    if (opensearchDashboards.multipleDataSource.enabled) {
      const {
        materialPath,
        keyName,
        keyNamespace,
      } = await this.initializerContext.config.create().pipe(first()).toPromise();

      // Instantiate CryptoCli for encryption / decryption
      this.cryptographySingleton = CryptographySingleton.getInstance(
        materialPath,
        keyName,
        keyNamespace
      );

      // Register credential saved object type
      core.savedObjects.registerType(credentialSavedObjectType);
      // Add credential saved objects client wrapper
      core.savedObjects.addClientWrapper(1, 'credential', this.credentialSavedObjectsClientWrapper.wrapperFactory);
    }
    return {};
  }

  public start(core: CoreStart) {
    this.credentialSavedObjectsClientWrapper.httpStart = core.http;

    return {
      http: core.http,
    };
  }

  public stop() {}
}
