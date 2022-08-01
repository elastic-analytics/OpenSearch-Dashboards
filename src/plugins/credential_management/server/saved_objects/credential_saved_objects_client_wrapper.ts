import {
  HttpServiceStart,
  SavedObjectsBulkCreateObject,
  SavedObjectsBulkResponse,
  SavedObjectsBulkUpdateObject,
  SavedObjectsBulkUpdateOptions,
  SavedObjectsBulkUpdateResponse,
  SavedObjectsClientWrapperFactory,
  SavedObjectsCreateOptions,
  SavedObjectsUpdateOptions,
  SavedObjectsUpdateResponse,
} from 'opensearch-dashboards/server';
//   import { SavedObjectsErrorHelpers } from '../../../../src/core/server';
import _ from 'lodash';
import { handleEncryption } from '../credential_manager';

export class CredentialSavedObjectsClientWrapper {
  public httpStart?: HttpServiceStart;

  constructor() {}

  public wrapperFactory: SavedObjectsClientWrapperFactory = (wrapperOptions) => {
    const createWithCredentialMaterialsContentEncryption = async <T = unknown>(
      type: string,
      attributes: T,
      options?: SavedObjectsCreateOptions
    ) => {
      // TODO: Add validation
      const encryptedAttributes = {
        title: attributes.title,
        description: attributes.description,
        credentialType: attributes.credentialType,
        credentialMaterials: await handleEncryption(attributes.credentialMaterials),
      };
      return await wrapperOptions.client.create(type, encryptedAttributes, options);
    };

    const bulkCreateWithCredentialMaterialsContentEncryption = async <T = unknown>(
      objects: Array<SavedObjectsBulkCreateObject<T>>,
      options?: SavedObjectsCreateOptions
    ): Promise<SavedObjectsBulkResponse<T>> => {
      objects = await Promise.all(objects.map(async (object) => {
        return {
          ...object,
          attributes: {
            title: attributes.title,
            description: attributes.description,
            credentialType: attributes.credentialType,
            credentialMaterials: await handleEncryption(
              attributes.credentialMaterials
            ),
          },
        // Unfortunately this throws a typescript error without the casting.  I think it's due to the
        // convoluted way SavedObjects are created.  
        } as unknown as SavedObjectsBulkCreateObject<T> 
      }));
      return await wrapperOptions.client.bulkCreate(objects, options);
    };

    const updateWithCredentialMaterialsContentEncryption = async <T = unknown>(
      type: string,
      id: string,
      attributes: Partial<T>,
      options: SavedObjectsUpdateOptions = {}
    ): Promise<SavedObjectsUpdateResponse<T>> => {
      // TODO: Add validation
      const encryptedAttributes: Partial<T> = {
        title: attributes.title,
        description: attributes.description,
        credentialType: attributes.credentialType,
        credentialMaterials: await handleEncryption(
          attributes.credentialMaterials
        ),
      };
      return await wrapperOptions.client.update(type, id, encryptedAttributes, options);
    };

    const bulkUpdateWithCredentialMaterialsContentEncryption = async <T = unknown>(
      objects: Array<SavedObjectsBulkUpdateObject<T>>,
      options?: SavedObjectsBulkUpdateOptions
    ): Promise<SavedObjectsBulkUpdateResponse<T>> => {
      // TODO: Add validation
      objects = await Promise.all(objects.map(async (object) => {
        return {
          ...object,
          attributes: {
            title: attributes.title,
            description: attributes.description,
            credentialType: attributes.credentialType,
            credentialMaterials: await handleEncryption(
              attributes.credentialMaterials
            ),
          },
        // Unfortunately this throws a typescript error without the casting.  I think it's due to the
        // convoluted way SavedObjects are created.  
        } as unknown as SavedObjectsBulkUpdateObject<T> 
      }));

      return await wrapperOptions.client.bulkUpdate(objects, options);
    };

    return {
      ...wrapperOptions.client,
      create: createWithCredentialMaterialsContentEncryption,
      bulkCreate: bulkCreateWithCredentialMaterialsContentEncryption,
      checkConflicts: wrapperOptions.client.checkConflicts,
      delete: wrapperOptions.client.delete,
      find: wrapperOptions.client.find,
      bulkGet: wrapperOptions.client.bulkGet,
      get: wrapperOptions.client.get,
      update: updateWithCredentialMaterialsContentEncryption,
      bulkUpdate: bulkUpdateWithCredentialMaterialsContentEncryption,
      errors: wrapperOptions.client.errors,
      addToNamespaces: wrapperOptions.client.addToNamespaces,
      deleteFromNamespaces: wrapperOptions.client.deleteFromNamespaces,
    };
  };
}
