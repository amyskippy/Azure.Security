namespace Azure.Security.Tests
{
    using Data.Tables;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using Security;
    using System;
    using System.IO;

#if NET9_0
    using Microsoft.Extensions.Caching.Memory;
    using Microsoft.Extensions.Options;
#else
    using System.Runtime.Caching;
#endif


    [TestClass]
    [DeploymentItem(@"TestFiles\TestCertificate.pfx")]
    [DeploymentItem(@"TestFiles\TestTextFile.txt")]
    public class EncryptionHelperTests
    {
        public TestContext TestContext { get; set; }
        private static string _testFileDeploymentDirectory;
        private const string TestFileName = "TestTextFile.txt";
        private const string TestString = "This is a rendom test string";
        private const string TableName = "TestTableName";
        private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
        
        private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");

#if NET9_0
        private Cache _cache;
        private readonly IOptions<EncryptionSettings> _encryptionSettings = Options.Create(
            new EncryptionSettings
            {
                CertificateName = "TestCertificate.pfx",
                CertificateTable = "TestTableName",
                StorageConnectionString = "UseDevelopmentStorage=true",
                CertificateValue = "test"
            });
#endif

        [TestInitialize]
        public void TestSetup()
        {
            _testFileDeploymentDirectory = TestContext.DeploymentDirectory;
            
#if NET9_0
            _cache = new Cache(new MemoryCache(new MemoryCacheOptions()));
            var tableManager = new SymmetricKeyTableManager(_cache, TableName, _client);
#else
            var tableManager = new SymmetricKeyTableManager(TableName, _client);
#endif
            tableManager.CreateTableIfNotExists();
        }

        [TestCleanup]
        public void TestTearDown()
        {
            var encryptionHelper = CreateEncryptionHelper();
            encryptionHelper.KeyTableManager.DeleteTableIfExists();

#if NET9_0
#else
            MemoryCache.Default.Dispose();
#endif
        }

        [TestMethod]
        public void TestConstructorSucceeds()
        {
            var encryptionHelper = CreateEncryptionHelper();
            encryptionHelper.Should().NotBeNull("Constructor failed");
        }

        [TestMethod]
        public void TestConstructorSucceedsWithUserId()
        {
            var encryptionHelper = CreateEncryptionHelper(TestUserId);
            encryptionHelper.Should().NotBeNull("Constructor failed");
        }

        [TestMethod]
        public void TestEncryptStringShouldSucceed()
        {
            var encryptionHelper = CreateEncryptionHelper();
            var encryptedString = encryptionHelper.EncryptAndBase64(TestString);

            encryptedString.Should().NotBeNullOrEmpty("Encryptiong failed");
            encryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
        }

        [TestMethod]
        public void TestEncryptStringShouldSucceedWithUserId()
        {
            var encryptionHelper = CreateEncryptionHelper(TestUserId);
            var encryptedString = encryptionHelper.EncryptAndBase64(TestString, TestUserId);

            encryptedString.Should().NotBeNullOrEmpty("Encryptiong failed");
            encryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
        }

        [TestMethod]
        public void TestDecryptStringShouldSucceed()
        {
            var encryptionHelper = CreateEncryptionHelper();
            var encryptedString = encryptionHelper.EncryptAndBase64(TestString);
            var decryptedString = encryptionHelper.DecryptFromBase64(encryptedString);

            decryptedString.Should().NotBeNullOrEmpty("Encryptiong failed");
            decryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
            decryptedString.Should().BeEquivalentTo(TestString);
        }

        [TestMethod]
        public void TestDecryptStringShouldSucceedWithUserId()
        {
            var encryptionHelper = CreateEncryptionHelper(TestUserId);
            var encryptedString = encryptionHelper.EncryptAndBase64(TestString, TestUserId);
            var decryptedString = encryptionHelper.DecryptFromBase64(encryptedString, TestUserId);

            decryptedString.Should().NotBeNullOrEmpty("Encryptiong failed");
            decryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
            decryptedString.Should().BeEquivalentTo(TestString);
        }

        [TestMethod]
        public void TestEncryptBinaryShouldSucceed()
        {
            var encryptionHelper = CreateEncryptionHelper();
            var bytesToEncrypt = File.ReadAllBytes(Path.Combine(_testFileDeploymentDirectory, TestFileName));
            var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt);

            encryptedBytes.Should().NotBeNull("EncryptionFailed");
        }

        [TestMethod]
        public void TestEncryptBinaryShouldSucceedWithUserId()
        {
            var encryptionHelper = CreateEncryptionHelper(TestUserId);
            var bytesToEncrypt = File.ReadAllBytes(Path.Combine(_testFileDeploymentDirectory, TestFileName));
            var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt, TestUserId);

            encryptedBytes.Should().NotBeNull("EncryptionFailed");
        }

        [TestMethod]
        public void TestDecryptBinaryShouldSucceed()
        {
            var pathToTestFile = Path.Combine(_testFileDeploymentDirectory, TestFileName);
            var encryptionHelper = CreateEncryptionHelper();
            var bytesToEncrypt = File.ReadAllBytes(pathToTestFile);
            var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt);

            var decryptedBytes = encryptionHelper.DecryptBytes(encryptedBytes);
            decryptedBytes.Should().NotBeNull("EncryptionFailed");

            var decryptedTestContent = System.Text.Encoding.UTF8.GetString(decryptedBytes);
            var originalContent = File.ReadAllText(pathToTestFile);

            Assert.IsTrue(decryptedTestContent.Equals(originalContent, StringComparison.InvariantCultureIgnoreCase));
        }

        [TestMethod]
        public void TestDecryptBinaryShouldSucceedWithUserId()
        {
            var pathToTestFile = Path.Combine(_testFileDeploymentDirectory, TestFileName);
            var encryptionHelper = CreateEncryptionHelper(TestUserId);
            var bytesToEncrypt = File.ReadAllBytes(pathToTestFile);
            var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt, TestUserId);

            var decryptedBytes = encryptionHelper.DecryptBytes(encryptedBytes, TestUserId);
            decryptedBytes.Should().NotBeNull("EncryptionFailed");

            var decryptedTestContent = System.Text.Encoding.UTF8.GetString(decryptedBytes);
            var originalContent = File.ReadAllText(pathToTestFile);

            Assert.IsTrue(decryptedTestContent.Equals(originalContent, StringComparison.InvariantCultureIgnoreCase));
        }

        private EncryptionHelper CreateEncryptionHelper(Guid? userId = null)
        {
#if NET9_0
            return new EncryptionHelper(_encryptionSettings, _cache, _testFileDeploymentDirectory, userId);
#else
            return new EncryptionHelper(_testFileDeploymentDirectory, userId);
#endif
        }
    }
}
