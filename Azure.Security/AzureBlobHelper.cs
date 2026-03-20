using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using Azure.Security.Exceptions;
using Azure.Security.Interfaces;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;

namespace Azure.Security;

public class AzureBlobHelper : IBlobHelper
{
    private readonly BlobServiceClient _blobServiceClient;
    private readonly BlobContainerClient _blobContainerClient;
    private readonly string _containerName;

    public AzureBlobHelper(string connectionString, string blobContainerName)
    {
        if (NameContainsUpperCaseCharacters(blobContainerName))
        {
            throw new ArgumentException("The blob container name has upper case characters or spaces");
        }

        _containerName = blobContainerName;
        _blobServiceClient = new BlobServiceClient(connectionString);
        _blobContainerClient = _blobServiceClient.GetBlobContainerClient(_containerName);
        _blobContainerClient.CreateIfNotExists();
    }

    public bool DeleteBlobContainer(string? toDelete = null)
    {
        var containerToDelete = !string.IsNullOrEmpty(toDelete) ? toDelete : _containerName;

        var blobContainerClient = _blobServiceClient.GetBlobContainerClient(containerToDelete);

        return blobContainerClient.DeleteIfExists();
    }

    public async Task<bool> DeleteBlobContainerAsync(string? toDelete = null, CancellationToken cancellationToken = default)
    {
        var containerToDelete = !string.IsNullOrEmpty(toDelete) ? toDelete : _containerName;

        var blobContainerClient = _blobServiceClient.GetBlobContainerClient(containerToDelete);

        var result = await blobContainerClient.DeleteIfExistsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        return result.Value;
    }

    public bool Delete(string blobId)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        return blob.DeleteIfExists();
    }

    public async Task<bool> DeleteAsync(string blobId, CancellationToken cancellationToken = default)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        var result = await blob.DeleteIfExistsAsync(cancellationToken: cancellationToken).ConfigureAwait(false);

        return result.Value;
    }

    public bool CreateOrUpdate(string blobId, MemoryStream contentStream)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        var result = blob.Upload(contentStream);

        return result.HasValue;
    }

    public async Task<bool> CreateOrUpdateAsync(string blobId, MemoryStream contentStream, CancellationToken cancellationToken = default)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        var result = await blob.UploadAsync(contentStream, cancellationToken).ConfigureAwait(false);

        return result.HasValue;
    }

    public bool CreateOrUpdate(string blobId, Stream contentStream)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        var result = blob.Upload(contentStream);

        return result.HasValue;
    }

    public async Task<bool> CreateOrUpdateAsync(string blobId, Stream contentStream, CancellationToken cancellationToken = default)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);

        var result = await blob.UploadAsync(contentStream, cancellationToken).ConfigureAwait(false);

        return result.HasValue;
    }

    public BlobClient CreateOrUpdate(string blobId, Stream contentStream, string contentType)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);
        var blobHttpHeader = new BlobHttpHeaders { ContentType = contentType };

        var result = blob.Upload(contentStream, blobHttpHeader);

        return result.HasValue ? blob : throw new AzureCryptoException("Failed to create or update blob");
    }

    public async Task<BlobClient> CreateOrUpdateAsync(string blobId, Stream contentStream, string contentType, CancellationToken cancellationToken = default)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);
        var blobHttpHeader = new BlobHttpHeaders { ContentType = contentType };

        var result = await blob.UploadAsync(contentStream, blobHttpHeader, cancellationToken: cancellationToken).ConfigureAwait(false);

        return result.HasValue ? blob : throw new AzureCryptoException("Failed to create or update blob");
    }

    public Stream Get(string blobId)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);
        var memoryStream = new MemoryStream();
        var response = blob.DownloadStreaming();
        memoryStream.Seek(0, SeekOrigin.Begin);

        return response.Value.Content;
    }

    public async Task<Stream> GetAsync(string blobId, CancellationToken cancellationToken = default)
    {
        var blob = _blobContainerClient.GetBlobClient(blobId);
        var response = await blob.DownloadStreamingAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        return response.Value.Content;
    }

    public IEnumerable<BlobClient> GetBlobItemsByDirectory(string directoryName)
    {
        if (!directoryName.EndsWith('/'))
            directoryName += "/";

        var blobs = _blobContainerClient.GetBlobs(options: new GetBlobsOptions { Prefix = directoryName });
        
        return blobs.Select(blob => _blobContainerClient.GetBlobClient(blob.Name));
    }

    public async IAsyncEnumerable<BlobClient> GetBlobItemsByDirectoryAsync(string directoryName, [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (!directoryName.EndsWith('/'))
            directoryName += "/";

        await foreach (var blob in _blobContainerClient.GetBlobsAsync(options: new GetBlobsOptions { Prefix = directoryName }, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            yield return _blobContainerClient.GetBlobClient(blob.Name);
        }
    }

    public bool Exists(string blobId, string? directoryName = null)
    {
        return _blobContainerClient.GetBlobs(options: new GetBlobsOptions { Prefix = directoryName }).Any(blob => blob.Name.Contains(blobId));
    }

    public async Task<bool> ExistsAsync(string blobId, string? directoryName = null, CancellationToken cancellationToken = default)
    {
        await foreach (var blob in _blobContainerClient.GetBlobsAsync(options: new GetBlobsOptions { Prefix = directoryName }, cancellationToken: cancellationToken).ConfigureAwait(false))
        {
            if (blob.Name.Contains(blobId))
                return true;
        }
        return false;
    }

    private static bool NameContainsUpperCaseCharacters(string stringToValidate)
    {
        return !string.IsNullOrEmpty(stringToValidate) && stringToValidate.Any(char.IsUpper);
    }
}