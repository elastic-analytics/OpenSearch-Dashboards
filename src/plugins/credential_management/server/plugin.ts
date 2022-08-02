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
import { registerRoutes } from './routes';
import { credentialSavedObjectType } from './saved_objects';
import { ConfigSchema } from '../config';
import { CryptoCli } from './crypto';

export class CredentialManagementPlugin
  implements Plugin<CredentialManagementPluginSetup, CredentialManagementPluginStart> {
  private readonly logger: Logger;
  private initializerContext: PluginInitializerContext<ConfigSchema>;

  private cryptoCli?: CryptoCli;

  constructor(initializerContext: PluginInitializerContext<ConfigSchema>) {
    this.logger = initializerContext.logger.get();
    this.initializerContext = initializerContext;
  }

  public async setup(core: CoreSetup) {
    this.logger.debug('credential_management: Setup');
    const { enabled, materialPath } = await this.initializerContext.config
      .create()
      .pipe(first())
      .toPromise();

    if (enabled) {
      const router = core.http.createRouter();
      // Register server side APIs
      registerRoutes(router);
      // Register credential saved object type
      core.savedObjects.registerType(credentialSavedObjectType);
      // Instantiate CryptoCli for encryption / decryption
      this.cryptoCli = CryptoCli.getInstance(materialPath);
    }
    return {};
  }

  public start(core: CoreStart) {
    return {};
  }

  public stop() {}
}
