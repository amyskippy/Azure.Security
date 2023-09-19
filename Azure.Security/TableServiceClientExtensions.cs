namespace Azure.Security
{
    using Data.Tables;
    using System.Threading.Tasks;

    public static class TableServiceClientExtensions
    {
        public static bool Exists(this TableServiceClient client, string tableName)
        {
            var exists = false;
            foreach (var tbl in client.Query(t => t.Name == tableName))
            {
                exists = true;
            }
            return exists;
        }

        public static async Task<bool> ExistsAsync(this TableServiceClient client, string tableName)
        {
            var exists = false;
            await foreach (var tbl in client.QueryAsync(t => t.Name == tableName))
            {
                exists = true;
            }
            return exists;
        }
    }
}
