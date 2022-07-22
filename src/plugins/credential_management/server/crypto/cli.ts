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

import { randomBytes } from 'crypto';
import { writeFileSync } from 'fs';

const defaultPath = 'data/crypto_material';

const generateCryptoMaterials = function (
  path = defaultPath,
  keyName = 'keyName',
  keyNamespace = 'keyNamespace'
) {
  const cryptoMaterials = {
    keyName,
    keyNamespace,
    unencryptedMasterKey: randomBytes(32),
  };
  const input = JSON.stringify(cryptoMaterials);
  writeFileSync(path, input);
  console.log('Crypto materials generated!');

  return input;
};

export { generateCryptoMaterials };
