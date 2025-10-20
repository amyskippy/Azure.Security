

namespace Azure.Security.Tests
{
    using Data.Tables;
    using Exceptions;
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.IO;

#if NET9_0
    using Microsoft.Extensions.Caching.Memory;
#else
    using System.Runtime.Caching;
#endif

    [TestClass]
    [DeploymentItem(@"TestFiles\TestCertificate.pfx")]
    public class SymmetricKeyTableManagerTests
    {
        private const string TableName = "RandomTableName";
        private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
        private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");
        private static RsaHelper _rsaHelper;

#if NET9_0
        private Cache _cache;
#endif

        public TestContext TestContext { get; set; }

        [TestInitialize]
        public void TestSetup()
        {
#if NET9_0
            _cache = new Cache(new MemoryCache(new MemoryCacheOptions()));
#else
#endif
            var deploymentDirectory = TestContext.DeploymentDirectory;
            _rsaHelper = new RsaHelper(Path.Combine(deploymentDirectory, "TestCertificate.pfx"), "test");
        }

        [TestCleanup]
        public void TestTearDown()
        {
            if (_client.Exists(TableName))
                _client.GetTableClient(TableName).Delete();
#if NET9_0
#else
            MemoryCache.Default.Dispose();
#endif
        }

        [TestMethod]
        public void ConstructorShouldInitializeSuccessfully()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.Should().NotBeNull("Initialization failed.");
        }

        [TestMethod]
        public void GetKeyShouldReturnNull()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.CreateTableIfNotExists();
            var key = symmetricTableManager.GetKey(null);

            key.Should().BeNull("The get query did not return null as expected");
        }

        [TestMethod]
        public void GetKeyShouldThrowAnException()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();

            Action action = () => symmetricTableManager.GetKey(null);
            action.Should().Throw<AzureCryptoException>();
        }

        [TestMethod]
        public void GetKeyShouldReturnOneKey()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.CreateTableIfNotExists();
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(null);
            symmetricTableManager.AddSymmetricKey(newKey);

            var key = symmetricTableManager.GetKey(null);

            key.Should().NotBeNull("The get query failed");
        }

        [TestMethod]
        public void GetKeyShouldReturnOneKeyWithUserId()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.CreateTableIfNotExists();
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
            symmetricTableManager.AddSymmetricKey(newKey);

            var key = symmetricTableManager.GetKey(TestUserId);

            key.Should().NotBeNull("The get query failed");
        }

        [TestMethod]
        public void DeleteKeyShouldSucceed()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.CreateTableIfNotExists();
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(null);
            symmetricTableManager.AddSymmetricKey(newKey);

            var key = symmetricTableManager.GetKey(null);
            key.Should().NotBeNull("Insert operation failed");

            symmetricTableManager.DeleteSymmetricKey(newKey);
            key = symmetricTableManager.GetKey(null);
            key.Should().BeNull("Delete operation failed");
        }

        [TestMethod]
        public void DeleteKeyShouldSucceedWithUserId()
        {
            var symmetricTableManager = CreateSymmetricKeyTableManager();
            symmetricTableManager.CreateTableIfNotExists();
            var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
            symmetricTableManager.AddSymmetricKey(newKey);

            var key = symmetricTableManager.GetKey(TestUserId);
            key.Should().NotBeNull("Insert operation failed");

            symmetricTableManager.DeleteSymmetricKey(newKey);
            key = symmetricTableManager.GetKey(TestUserId);
            key.Should().BeNull("Delete operation failed");
        }

        private SymmetricKeyTableManager CreateSymmetricKeyTableManager()
        {
#if NET9_0
            return new SymmetricKeyTableManager(_cache, TableName, _client);
#else
            return new SymmetricKeyTableManager(TableName, _client);
#endif
        }
    }
}
