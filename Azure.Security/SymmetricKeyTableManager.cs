namespace Azure.Security
{
    using Data.Tables;
    using Exceptions;
    using Interfaces;
    using System;

    public class SymmetricKeyTableManager : ISymmetricKeyTableManager
    {
        private static string _keyTableName;
        private readonly TableServiceClient _tableClient;

#if NET9_0
        private readonly Cache _cache;
#else
        private static readonly Cache _cache = Cache.Current;
#endif
        
        public SymmetricKeyTableManager(
#if NET9_0
            Cache cache,
#endif
            string tableName, 
            TableServiceClient storageAccount)
        {
#if NET9_0
            _cache = cache;
#endif
            _keyTableName = tableName;
            _tableClient = storageAccount;
        }

        public SymmetricKey GetKey(Guid? userId)
        {
            // Construct a unique key
            var itemKey = $"tablekeymanager/key/{userId?.ToString() ?? "none"}";

            // Try to get the item from the cache
            var cachedKey = _cache.GetItem<SymmetricKey>(itemKey);

            // If the data was found in the cache, return it
            if (cachedKey != null)
            {
                return cachedKey;
            }

            // Create the CloudTable object that represents the "key" table.
            var table = _tableClient.GetTableClient(_keyTableName);
            var tableExists = _tableClient.Exists(_keyTableName);
            
            try
            {
                // Get the data using the partition and row keys (fastest way to query known data)
                var result = table.GetEntityIfExists<SymmetricKey>("SymmetricKey", userId?.ToString("N") ?? Guid.Empty.ToString("N"));

                // If the result returned a 404 and the table doesn't exist
                if (!result.HasValue && !tableExists)
                    throw new Exception("Table not found");

                // If we found the data
                if (result.HasValue)
                    cachedKey = result.Value;
            }
            catch (RequestFailedException dsq)
            {
                throw new AzureCryptoException("Failed to load encryption keys from storage", dsq);
            }
            catch (Exception ex)
            {
                throw new AzureCryptoException("Could not load encryption keys table", ex);
            }
            
            // Add the data to the cache for 3 hours if it was found
            if (cachedKey != null)
                _cache.AddItem(itemKey, cachedKey);

            return cachedKey;
        }

        public void DeleteSymmetricKey(SymmetricKey key)
        {
            var cloudTable = GetTableForOperation();
            
            cloudTable.DeleteEntity(key.PartitionKey, key.RowKey);

            _cache.RemoveItem($"tablekeymanager/key/{key.UserId?.ToString() ?? "none"}");
        }

        public void AddSymmetricKey(SymmetricKey key)
        {
            var cloudTable = GetTableForOperation();
            
            cloudTable.AddEntity(key);
        }

        public TableClient CreateTableIfNotExists()
        {
            var cloudTable = _tableClient.GetTableClient(_keyTableName);
            cloudTable.CreateIfNotExists();

            return cloudTable;
        }

        public void DeleteTableIfExists()
        {
            if (!_tableClient.Exists(_keyTableName))
                return;

            var table = _tableClient.GetTableClient(_keyTableName);
            table.Delete();
        }

        private TableClient GetTableForOperation()
        {
            var cloudTable = _tableClient.GetTableClient(_keyTableName);

            if (cloudTable == null)
            {
                throw new AzureCryptoException($"Table {_keyTableName} does not exist");
            }

            return cloudTable;
        }
    }
}
