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
  namespaceType: 'agnostic',
  hidden: false,
  management: {
    defaultSearchField: 'credential_name',
    importableAndExportable: true,
    getCredentialName(obj) {
      return obj.attributes.credential_name;
    },
    getCredentialType(obj) {
      return obj.attributes.credential_type;
    },
    getUserName(obj) {
      return obj.attributes.user_name;
    },
    getEditUrl(obj) {
      return `/management/opensearch-dashboards/credentials/${encodeURIComponent(obj.id)}`;
    },
    getInAppUrl(obj) {
      return {
        path: `/app/management/opensearch-dashboards/credentials/${encodeURIComponent(obj.id)}`,
        uiCapabilitiesPath: 'management.opensearchDashboards.credentials',
      };
    },
  },
  mappings: {
    dynamic: false,
    properties: {
      credential_name: {
        type: 'text',
      },
      credential_type: {
        type: 'keyword',
      },
      credential_material: { type: 'object' },
    },
  },
  migrations: {},
};
