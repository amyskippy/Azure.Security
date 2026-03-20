using System.Linq;
using System.Threading.Tasks;
using Azure.Data.Tables;

namespace Azure.Security;

public static class TableServiceClientExtensions
{
    public static bool Exists(this TableServiceClient client, string tableName)
    {
        return client.Query(t => t.Name == tableName).Any();
    }

    public static async Task<bool> ExistsAsync(this TableServiceClient client, string tableName)
    {
        await foreach (var _ in client.QueryAsync(t => t.Name == tableName))
        {
            return true;
        }

        return false;
    }
}