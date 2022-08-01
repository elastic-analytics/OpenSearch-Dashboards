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

export interface CredentialsTableItem {
  id: string;
  title: string;
  sort: string;
}

export interface CredentialEditPageItem {
  id: string;
  title: string;
  credentialType: string;
}
