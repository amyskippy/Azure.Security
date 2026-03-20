using System;
using Azure.Data.Tables;

namespace Azure.Security;

public sealed class SymmetricKey : ITableEntity
{
    // Parameterless constructor required by Azure Table Storage
    public SymmetricKey() : this(null){}

    public SymmetricKey(Guid? userId = null)
    {
        PartitionKey = "SymmetricKey";

        RowKey = userId?.ToString("N") ?? Guid.Empty.ToString("N");

        CreateDate = DateTime.UtcNow;

    }

    public byte[]? Key { get; set; }
    public byte[]? Iv { get; set; }

    public DateTime CreateDate { get; set; }

    public Guid? UserId { get; set; }

    public string PartitionKey { get; set; }
    public string RowKey { get; set; }
    public DateTimeOffset? Timestamp { get; set; }
    public ETag ETag { get; set; }
}