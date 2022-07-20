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
  RawAesKeyringNode,
  buildClient,
  CommitmentPolicy,
  RawAesWrappingSuiteIdentifier,
} from '@aws-crypto/client-node';

import { randomBytes } from 'crypto';
import { readFileSync, writeFile } from 'fs';

const defaultPath = "src/plugins/credential_management/server/crypto/crypto_material";

export class CryptoCli {
  private static _instance: CryptoCli;

  private readonly _keyring: RawAesKeyringNode;

  private readonly _encrypt;
  private readonly _decrypt;

  private constructor(path: string) {
    const wrappingSuite = RawAesWrappingSuiteIdentifier.AES256_GCM_IV12_TAG16_NO_PADDING;
    // TODO: Move config to opensearch_dashboards.yam and load config during bootstrap
    // TODO: Generate materials by default during bootstrap

    // TODO: Add path validation with default calling generateCryptoMaterials
    const cryptoMaterials = JSON.parse(
      readFileSync(path, 'utf8')
    );

    const input = {
      keyName: cryptoMaterials.keyName,
      keyNamespace: cryptoMaterials.keyNamespace,
      unencryptedMasterKey: new Uint8Array(cryptoMaterials.unencryptedMasterKey.data),
      wrappingSuite,
    };

    this._keyring = new RawAesKeyringNode(input);

    const { encrypt, decrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_REQUIRE_DECRYPT);

    this._encrypt = encrypt;
    this._decrypt = decrypt;
  }

  public async encrypt(plainText: string) {
    const result = await this._encrypt(this._keyring, plainText);
    return result.result.toString('base64');
  }

  public async decrypt(encrypted: Buffer) {
    const result = await this._decrypt(this._keyring, encrypted);
    return result.plaintext.toString();
  }

  // TODO: Append CryptoCli.getInstance into plugin lifecycle
  public static getInstance(path=defaultPath): CryptoCli {
    if (!CryptoCli._instance) {
      CryptoCli._instance = new CryptoCli(path);
    }

    return CryptoCli._instance;
  }
}

const generateCryptoMaterials = function (keyName: string, keyNamespace: string, path=defaultPath) {
  const cryptoMaterials = {
    keyName,
    keyNamespace,
    unencryptedMasterKey: randomBytes(32),
  };

  writeFile(path, JSON.stringify(cryptoMaterials), function (err) {
    if (err) throw err;
  });
  console.log('Crypto materials generated!');
};

export { generateCryptoMaterials };
