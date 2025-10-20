namespace Azure.Security.Tests
{
    using Data.Tables;
    using Exceptions;
    using FluentAssertions;
    using Interfaces;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Security;
    using System;
    using System.IO;

#if NET9_0
    using Microsoft.Extensions.Caching.Memory;
#else
    using System.Runtime.Caching;
#endif

    [TestClass]
    [DeploymentItem(@"TestFiles\TestCertificate.pfx")]
    public class AzureCryptoTests
    {
        private const string TableName = "TestTableName";
        private const string TestString = "This is some test value";
        private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
        private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");
        private static IRsaHelper _rsaHelper;
        private static ISymmetricKeyTableManager _tableManager;

#if NET9_0
        private IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());
#endif

        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void TestSetup()
        {

#if NET9_0
            Cache cache = new Cache(_memoryCache);
            _tableManager = new SymmetricKeyTableManager(cache, TableName, _client);
#else
            _tableManager = new SymmetricKeyTableManager(TableName, _client);
#endif

            var deploymentDirectory = TestContext.DeploymentDirectory;
            _rsaHelper = new RsaHelper(Path.Combine(deploymentDirectory, "TestCertificate.pfx"), "test");
            _tableManager.CreateTableIfNotExists();
        }

        [TestCleanup]
        public void TestTearDown()
        {
            _tableManager.DeleteTableIfExists();

#if NET9_0
            _memoryCache.Dispose();
#else
            MemoryCache.Default.Dispose();
#endif
        }

        [TestMethod]
        public void TestAzureTableCryptoInitializesSuccessfully()
        {
            //Create the master key if it doesn't exist
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(null);
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
            var c = new AzureCrypto(keyStore);
            Assert.IsNotNull(c);
        }

        [TestMethod]
        public void TestAzureTableCryptoThrowsTableNotFoundException()
        {
            // Delete table to simulate empty Azure storage
            _tableManager.DeleteTableIfExists();
            
            Action action = () =>
            {
                var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);

                var c = new AzureCrypto(keyStore);

                c.GetEncryptor();
            };
            action.Should().Throw<AzureCryptoException>();
        }

        [TestMethod]
        public void TestAzureTableCryptoThrowsTableNotFoundExceptionWithUserId()
        {
            // Delete table to simulate empty Azure storage
            _tableManager.DeleteTableIfExists();
            
            Action action = () =>
            {
                var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);

                var c = new AzureCrypto(keyStore);

                c.GetEncryptor(TestUserId);
            };
            action.Should().Throw<AzureCryptoException>();
        }

        [TestMethod]
        public void TestAzureTableCryptoHasValidEncryptor()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
            var c = new AzureCrypto(keyStore);
            c.Should().NotBeNull("At this stage the contstructor should have succeeded");

            var encryptor = c.GetEncryptor();
            encryptor.Should().NotBeNull("Because the keystore is initialized and there is a key");
        }

        [TestMethod]
        public void TestAzureTableCryptoHasValidEncryptorWithUserId()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);
            var c = new AzureCrypto(keyStore);
            c.Should().NotBeNull("At this stage the contstructor should have succeeded");

            var encryptor = c.GetEncryptor(TestUserId);
            encryptor.Should().NotBeNull("Because the keystore is initialized and there is a key");
        }

        [TestMethod]
        public void EncryptionShouldWorkAsExpected()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
            var c = new AzureCrypto(keyStore);

            var encryptedString = c.EncryptStringAndBase64(TestString);
            encryptedString.Should().NotBeNullOrEmpty("Because the encryption failed");
            encryptedString.Should().NotMatch(TestString);
        }

        [TestMethod]
        public void EncryptionShouldWorkAsExpectedWithUserId()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);
            var c = new AzureCrypto(keyStore);

            var encryptedString = c.EncryptStringAndBase64(TestString, TestUserId);
            encryptedString.Should().NotBeNullOrEmpty("Because the encryption failed");
            encryptedString.Should().NotMatch(TestString);
        }

        [TestMethod]
        public void DecryptionShouldReturnTheOriginalString()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(null);
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
            var c = new AzureCrypto(keyStore);

            var encryptedString = c.EncryptStringAndBase64(TestString);
            var decryptedString = c.DecryptStringFromBase64(encryptedString);

            decryptedString.Should().BeEquivalentTo(TestString);
        }

        [TestMethod]
        public void DecryptionShouldReturnTheOriginalStringWithUserId()
        {
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
            _tableManager.AddSymmetricKey(newKey);

            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);
            var c = new AzureCrypto(keyStore);

            var encryptedString = c.EncryptStringAndBase64(TestString, TestUserId);
            var decryptedString = c.DecryptStringFromBase64(encryptedString, TestUserId);

            decryptedString.Should().BeEquivalentTo(TestString);
        }
    }
}
