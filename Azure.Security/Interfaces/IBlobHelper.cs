using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using Azure.Storage.Blobs;

namespace Azure.Security.Interfaces;

public interface IBlobHelper
{
    bool DeleteBlobContainer(string? toDelete = null);
    Task<bool> DeleteBlobContainerAsync(string? toDelete = null, CancellationToken cancellationToken = default);

    bool Delete(string blobId);
    Task<bool> DeleteAsync(string blobId, CancellationToken cancellationToken = default);

    bool CreateOrUpdate(string blobId, MemoryStream contentStream);

    Task<bool> CreateOrUpdateAsync(string blobId, MemoryStream contentStream, CancellationToken cancellationToken = default);

    bool CreateOrUpdate(string blobId, Stream contentStream);

    Task<bool> CreateOrUpdateAsync(string blobId, Stream contentStream, CancellationToken cancellationToken = default);

    BlobClient CreateOrUpdate(string blobId, Stream contentStream, string contentType);

    Task<BlobClient> CreateOrUpdateAsync(string blobId, Stream contentStream, string contentType, CancellationToken cancellationToken = default);

    Stream Get(string blobId);

    Task<Stream> GetAsync(string blobId, CancellationToken cancellationToken = default);

    IEnumerable<BlobClient> GetBlobItemsByDirectory(string directoryName);

    IAsyncEnumerable<BlobClient> GetBlobItemsByDirectoryAsync(string directoryName, CancellationToken cancellationToken = default);

    bool Exists(string blobId, string? directoryName = null);

    Task<bool> ExistsAsync(string blobId, string? directoryName = null, CancellationToken cancellationToken = default);
}