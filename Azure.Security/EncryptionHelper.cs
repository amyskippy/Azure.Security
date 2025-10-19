namespace Azure.Security
{
    using Data.Tables;
    using Interfaces;
    using System;
    using System.IO;

#if NET9_0
    using Microsoft.Extensions.Options;
#else
    using System.Configuration;
#endif

    public class EncryptionHelper : IEncryptionHelper
    {
        public TableServiceClient StorageAccount { get; set; } 
        public IRsaHelper RsaHelper { get; set; }
        public ISymmetricKeyTableManager KeyTableManager { get; set; }
        public ISymmetricKeyCache KeyCache { get; set; }
        public ICrypto AzureCrypto{ get; set; }

#if NET9_0
        // --- .NET 9 Constructors ---
        public EncryptionHelper(IOptions<EncryptionSettings> settings, Cache cache, string pathToCertificate)
            : this(settings, cache, pathToCertificate, null)
        {
        }

        public EncryptionHelper(IOptions<EncryptionSettings> settings, Cache cache, string pathToCertificate, Guid? userId)
        {
            var config = settings.Value;

            StorageAccount = new TableServiceClient(config.StorageConnectionString);
            KeyTableManager = new SymmetricKeyTableManager(cache, config.CertificateTable, StorageAccount);

            Initialize(config.CertificateValue, config.CertificateTable, config.CertificateName, pathToCertificate, userId);
        }
#else
    // --- .NET Framework Constructors ---
    public EncryptionHelper(string pathToCertificate) 
        : this(pathToCertificate, null)
    {
    }

    public EncryptionHelper(string pathToCertificate, Guid? userId)
    {
        // Get settings from the legacy ConfigurationManager
        var connectionString = ConfigurationManager.AppSettings["StorageConnectionString"];
        var certificateValue = ConfigurationManager.AppSettings["CertificateValue"];
        var certificateTable = ConfigurationManager.AppSettings["CertificateTable"];
        var certificateName = ConfigurationManager.AppSettings["CertificateName"];
        
        StorageAccount = new TableServiceClient(connectionString);
        KeyTableManager = new SymmetricKeyTableManager(certificateTable, StorageAccount);
        
        Initialize(certificateValue, certificateTable, certificateName, pathToCertificate, userId);
    }
#endif
        
        public void CreateNewCryptoKeyIfNotExists()
        {
            CreateNewCryptoKeyIfNotExists(null);
        }

        public void CreateNewCryptoKeyIfNotExists(Guid? userId)
        {
            var key = KeyTableManager.GetKey(userId);
            if (key != null)
            {
                return;
            }

            var newKey = RsaHelper.CreateNewAesSymmetricKeyset(userId);
            KeyTableManager.AddSymmetricKey(newKey);
        }

        public byte[] EncryptBytes(byte[] bytesToEncrypt)
        {
            return EncryptBytes(bytesToEncrypt, null);
        }

        public byte[] EncryptBytes(byte[] bytesToEncrypt, Guid? userId, bool createIfNotExists = true)
        {
            // Create the master key if it doesn't exist, if required
            if(createIfNotExists)
                CreateNewCryptoKeyIfNotExists(userId);

            return AzureCrypto.Encrypt(bytesToEncrypt, userId);
        }

        public byte[] DecryptBytes(byte[] bytesToDecrypt)
        {
            return DecryptBytes(bytesToDecrypt, null);
        }

        public byte[] DecryptBytes(byte[] bytesToDecrypt, Guid? userId)
        {
            return AzureCrypto.Decrypt(bytesToDecrypt, userId);
        }

        public string EncryptAndBase64(string valueToEncrypt)
        {
            return EncryptAndBase64(valueToEncrypt, null);
        }

        public string EncryptAndBase64(string valueToEncrypt, Guid? userId, bool createIfNotExists = true)
        {
            // Create the master key if it doesn't exist, if required
            if (createIfNotExists)
                CreateNewCryptoKeyIfNotExists(userId);

            return AzureCrypto.EncryptStringAndBase64(valueToEncrypt, userId);
        }

        public string DecryptFromBase64(string valueToDecrypt)
        {
            return DecryptFromBase64(valueToDecrypt, null);
        }

        public string DecryptFromBase64(string valueToDecrypt, Guid? userId)
        {
            return AzureCrypto.DecryptStringFromBase64(valueToDecrypt, userId);
        }

        private void CreateCertificateTableIfNotExists()
        {
            KeyTableManager.CreateTableIfNotExists();
        }

        private void Initialize(string certificateValue, string certificateTable, string certificateName, string pathToCertificate, Guid? userId)
        {
            var certificatePath = Path.Combine(pathToCertificate, certificateName);
            RsaHelper = new RsaHelper(certificatePath, certificateValue);

            // Create the master key if it doesn't exist
            CreateNewCryptoKeyIfNotExists(userId);

            KeyCache = new SymmetricKeyCache(RsaHelper, KeyTableManager, userId);
            AzureCrypto = new AzureCrypto(KeyCache);
        }

    }
}