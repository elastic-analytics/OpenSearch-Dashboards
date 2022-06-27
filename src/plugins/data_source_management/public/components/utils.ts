import { SavedObjectsClientContract } from 'src/core/public';
import { IDataSource } from '../../common/data_sources/types';
import { DataSourceManagementStart } from '../plugin';

export async function getDataSources(
  savedObjectsClient: SavedObjectsClientContract,
  defaultIndex: string,
  dataSourceManagementStart: DataSourceManagementStart
) {
  return (
    savedObjectsClient
      .find<IDataSource>({
        type: 'sample-data-source', // todo: change to data-source
        fields: ['title', 'type'],
        perPage: 10000,
      })
      .then((response) =>
        response.savedObjects
          .map((source) => {
            const id = source.id;
            const title = source.get('title');

            return {
              id,
              title,
              sort: `${title}`,
            };
          })
          .sort((a, b) => {
            if (a.sort < b.sort) {
              return -1;
            } else if (a.sort > b.sort) {
              return 1;
            } else {
              return 0;
            }
          })
      ) || []
  );
}
