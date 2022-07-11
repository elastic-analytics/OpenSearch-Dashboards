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

import { i18n } from '@osd/i18n';

export function getListBreadcrumbs() {
  return [
    {
      text: i18n.translate('credentialManagement.credentials.listBreadcrumb', {
        defaultMessage: 'Credentials',
      }),
      href: `/`,
    },
  ];
}

export function getCreateBreadcrumbs() {
  return [
    ...getListBreadcrumbs(),
    {
      text: i18n.translate('credentialManagement.credentials.createBreadcrumb', {
        defaultMessage: 'Create credentials',
      }),
      href: `/create`,
    },
  ];
}
