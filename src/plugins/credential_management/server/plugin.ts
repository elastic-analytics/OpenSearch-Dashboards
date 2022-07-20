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

import {
  CoreSetup,
  CoreStart,
  Plugin,
  Logger,
} from '../../../core/server';

import { PluginInitializerContext } from 'src/core/public';

import { CredentialManagementPluginSetup, CredentialManagementPluginStart } from './types';
import { registerRoutes } from './routes';
import { credentialSavedObjectType } from './saved_objects';
import { ConfigSchema } from '../config';
import { CryptoCli } from './crypto';

export class CredentialManagementPlugin
  implements Plugin<CredentialManagementPluginSetup, CredentialManagementPluginStart> {
  private cryptoCli: CryptoCli;

  constructor(initializerContext: PluginInitializerContext<ConfigSchema>) {
    const { materialPath } = initializerContext.config.get<ConfigSchema>();
    this.cryptoCli = CryptoCli.getInstance(materialPath);
  }

  public setup(core: CoreSetup) {
    const router = core.http.createRouter();

    // Register server side APIs
    registerRoutes(router);

    // Register credential saved object type
    core.savedObjects.registerType(credentialSavedObjectType);

    return {};
  }

  public start(core: CoreStart) {
    return {};
  }

  public stop() {}
}
