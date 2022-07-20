// /*
//  * SPDX-License-Identifier: Apache-2.0
//  *
//  * The OpenSearch Contributors require contributions made to
//  * this file be licensed under the Apache-2.0 license or a
//  * compatible open source license.
//  *
//  * Any modifications Copyright OpenSearch Contributors. See
//  * GitHub history for details.
//  */

// import { PluginInitializerContext } from 'opensearch-dashboards/server';
// import { TypeOf } from '@osd/config-schema';
// import { configSchema } from '../../config';

// export class ConfigManager {
//   private opensearchShardTimeout: number = 0;
//   private graphiteAllowedUrls: string[] = [];
//   private graphiteBlockedIPs: string[] = [];

//   constructor(config: PluginInitializerContext['config']) {
//     config.create<TypeOf<typeof configSchema>>().subscribe((configUpdate) => {
//       this.graphiteAllowedUrls = configUpdate.graphiteAllowedUrls || [];
//       this.graphiteBlockedIPs = configUpdate.graphiteBlockedIPs || [];
//     });

//     config.legacy.globalConfig$.subscribe((configUpdate) => {
//       this.opensearchShardTimeout = configUpdate.opensearch.shardTimeout.asMilliseconds();
//     });
//   }

//   getOpenSearchShardTimeout() {
//     return this.opensearchShardTimeout;
//   }

//   getGraphiteAllowedUrls() {
//     return this.graphiteAllowedUrls;
//   }

//   getGraphiteBlockedIPs() {
//     return this.graphiteBlockedIPs;
//   }
// }
