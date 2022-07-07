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

// TODO: refactor the credential in heritance:
// Credential -> USERNAMEANDPASSWORDCredential
//            -> AWSIAMCredential
export interface ICredential {
  readonly credential_name: string;
  readonly credential_type: CredentialType;
  readonly credential_material: IBasicAuthCredentialMaterial | IAWSIAMCredentialMaterial;
}

export type CredentialType = USERNAMEANDPASSWORDTYPE | AWSIAMTYPE;
// TODO: Update server side
export type USERNAMEANDPASSWORDTYPE = 'basic_auth';
export type AWSIAMTYPE = 'aws_iam_credential';

export interface IBasicAuthCredentialMaterial {
  readonly user_name: string;
  readonly password: string;
}

export interface IAWSIAMCredentialMaterial {
  readonly encrypted_aws_iam_credential: string;
}
