using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Azure.Data.Tables;
using Azure.Security.Interfaces;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Azure.Security;

public class EncryptionHelper : IEncryptionHelper
{
    public TableServiceClient StorageAccount { get; set; }
    public IRsaHelper RsaHelper { get; set; }
    public ISymmetricKeyTableManager KeyTableManager { get; set; }
    public ISymmetricKeyCache KeyCache { get; set; }
    public ICrypto AzureCrypto { get; set; }

    public EncryptionHelper(
        IOptions<EncryptionSettings> settings,
        IMemoryCache cache,
        string pathToCertificate,
        Guid? userId = null,
        X509KeyStorageFlags keyStorageFlags = X509KeyStorageFlags.UserKeySet)
    {
        var config = settings.Value;

        if (config.CertificateName is null)
            throw new ArgumentNullException(nameof(settings), "The certificate name is required");
        if (config.CertificateTable is null)
            throw new ArgumentNullException(nameof(settings), "The certificate table is required");
        if (config.CertificateValue is null)
            throw new ArgumentNullException(nameof(settings), "The certificate value is required");
        if (config.StorageConnectionString is null)
            throw new ArgumentNullException(nameof(settings), "The storage connection string is required");

        StorageAccount = new TableServiceClient(config.StorageConnectionString);
        KeyTableManager = new SymmetricKeyTableManager(cache, config.CertificateTable, StorageAccount);

        var certificatePath = Path.Combine(pathToCertificate, config.CertificateName);
        RsaHelper = new RsaHelper(certificatePath, config.CertificateValue, keyStorageFlags);

        // Create the master key if it doesn't exist
        CreateNewCryptoKeyIfNotExists(userId);

        KeyCache = new SymmetricKeyCache(RsaHelper, KeyTableManager, userId);
        AzureCrypto = new AzureCrypto(KeyCache);
    }

    public void CreateNewCryptoKeyIfNotExists(Guid? userId = null)
    {
        if (KeyTableManager.KeyExists(userId))
            return;

        var newKey = RsaHelper.CreateNewAesSymmetricKeyset(userId);
        KeyTableManager.AddSymmetricKey(newKey);
    }

    public byte[] EncryptBytes(byte[] bytesToEncrypt, Guid? userId = null, bool createIfNotExists = true)
    {
        // Create the master key if it doesn't exist, if required
        if (createIfNotExists)
            CreateNewCryptoKeyIfNotExists(userId);

        return AzureCrypto.Encrypt(bytesToEncrypt, userId);
    }

    public byte[] DecryptBytes(byte[] bytesToDecrypt, Guid? userId = null)
    {
        return AzureCrypto.Decrypt(bytesToDecrypt, userId);
    }

    public string EncryptAndBase64(string valueToEncrypt, Guid? userId = null, bool createIfNotExists = true)
    {
        // Create the master key if it doesn't exist, if required
        if (createIfNotExists)
            CreateNewCryptoKeyIfNotExists(userId);

        return AzureCrypto.EncryptStringAndBase64(valueToEncrypt, userId);
    }

    public string DecryptFromBase64(string valueToDecrypt, Guid? userId = null)
    {
        return AzureCrypto.DecryptStringFromBase64(valueToDecrypt, userId);
    }
}