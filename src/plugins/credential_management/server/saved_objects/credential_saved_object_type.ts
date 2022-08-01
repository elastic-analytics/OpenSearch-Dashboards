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

import { SavedObjectsType } from 'opensearch-dashboards/server';

export const credentialSavedObjectType: SavedObjectsType = {
  name: 'credential',
  hidden: false,
  namespaceType: 'single',
  management: {
    defaultSearchField: 'title',
    importableAndExportable: true,
    getTitle(obj) {
      return obj.attributes.title;
    },
    getEditUrl(obj) {
      return `/management/opensearch-dashboards/credentials/${encodeURIComponent(obj.id)}`;
    },
    getInAppUrl(obj) {
      return {
        path: `/management/opensearch-dashboards/credentials/${encodeURIComponent(obj.id)}`,
        uiCapabilitiesPath: 'credential.show',
      };
    },
  },
  mappings: {
    dynamic: false,
    properties: {
      title: { type: 'text' },
      credentialType: { type: 'keyword' },
      credentialMaterials: { type: 'object' },
      description: { type: 'text' },
    },
  },
  migrations: {},
};
