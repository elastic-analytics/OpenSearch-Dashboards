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

import { SavedObjectAttributes } from '../../../../src/core/types';

export type UserNamePasswordType = 'username_password_credential';
export type AWSIAMType = 'aws_iam_credential';

export interface CredentialSavedObjectAttributes extends SavedObjectAttributes {
  title: string;
  credentialType: string;
  credentialMaterials: CredentialMaterials;
  description?: string;
}

export interface CredentialMaterials extends SavedObjectAttributes {
  credentialMaterialsType: UserNamePasswordType | AWSIAMType;
  credentialMaterialsContent?: UserNamePasswordTypedContent | AWSIAMTypedContent;
}

export interface UserNamePasswordTypedContent extends SavedObjectAttributes {
  userName: string;
  password: string;
}

export interface AWSIAMTypedContent extends SavedObjectAttributes {
  accessKeyID: string;
  secretAccessKey: string;
}
