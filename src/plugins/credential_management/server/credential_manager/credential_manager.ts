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
import { CryptographySingleton } from '../crypto';
import {
  CredentialMaterials,
  UserNamePasswordType,
  AWSIAMType,
  UserNamePasswordTypedContent,
  AWSIAMTypedContent,
} from '../../common';

const USERNAME_PASSWORD_TYPE: UserNamePasswordType = 'username_password_credential';
const AWS_IAM_TYPE: AWSIAMType = 'aws_iam_credential';

// TODO: Refactor handler with service lifecycle, add logger, etc
export async function handleEncryption(credentialMaterials: CredentialMaterials) {
  const cryptoCli = CryptographySingleton.getInstance();

  switch (credentialMaterials.credentialMaterialsType) {
    case USERNAME_PASSWORD_TYPE: {
      const { userName, password } = credentialMaterials.credentialMaterialsContent! as UserNamePasswordTypedContent;
      return {
        credentialType: credentialMaterials.credentialMaterialsType,
        credentialMaterialsContent: {
          userName,
          password: await cryptoCli.encrypt(password),
        },
      };
    }
    case AWS_IAM_TYPE: {
      const { accessKeyID, secretAccessKey } = credentialMaterials.credentialMaterialsContent! as AWSIAMTypedContent;
      return {
        credentialType: credentialMaterials.credentialMaterialsType,
        credentialMaterialsContent: {
          accessKeyID,
          secretAccessKey: await cryptoCli.encrypt(secretAccessKey),
        },
      };
    }
  }
}
