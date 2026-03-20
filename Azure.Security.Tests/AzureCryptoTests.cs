using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Azure.Data.Tables;
using Azure.Security.Exceptions;
using Azure.Security.Interfaces;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using NUnit.Framework;

namespace Azure.Security.Tests;

[TestFixture]
public class AzureCryptoTests
{
    private static string _testFileDeploymentDirectory = null!;

    private const string TableName = "AzureCryptoTestsTableName";
    private const string TestString = "This is some test value";
    private const string CertificatePassword = "test";
    private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
    private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");
    private static IRsaHelper _rsaHelper = null!;
    private static ISymmetricKeyTableManager _tableManager = null!;
    private IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());

    [OneTimeSetUp]
    public void TestFixtureSetup()
    {
        _tableManager = new SymmetricKeyTableManager(_memoryCache, TableName, _client);
        _testFileDeploymentDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestFiles");
        var certificatePath = Path.Combine(_testFileDeploymentDirectory, "TestCertificate.pfx");
        _rsaHelper = new RsaHelper(certificatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
    }

    [OneTimeTearDown]
    public void TestFixtureTearDown()
    {
        _memoryCache.Dispose();
    }

    [SetUp]
    public void TestSetup()
    {
        _tableManager.CreateTableIfNotExists();
    }

    [TearDown]
    public void TestTearDown()
    {
        _tableManager.DeleteTableIfExists();

        _memoryCache.Remove($"tablekeymanager/key/{TestUserId.ToString()}");
        _memoryCache.Remove($"tablekeymanager/key/none");
    }

    [Test]
    [NonParallelizable]
    public void TestAzureTableCryptoInitializesSuccessfully()
    {
        //Create the master key if it doesn't exist
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
        _tableManager.AddSymmetricKey(newKey);

        var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
        var c = new AzureCrypto(keyStore);
        Assert.IsNotNull(c);
    }

    [Test]
    [NonParallelizable]
    public void TestAzureTableCryptoThrowsTableNotFoundException()
    {
        // Delete table to simulate empty Azure storage
        _tableManager.DeleteTableIfExists();

        var action = () =>
        {
            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
            var c = new AzureCrypto(keyStore);
            c.GetEncryptor();
        };
        action.Should().Throw<AzureCryptoException>();
    }

    [Test]
    [NonParallelizable]
    public void TestAzureTableCryptoThrowsTableNotFoundExceptionWithUserId()
    {
        // Delete table to simulate empty Azure storage
        _tableManager.DeleteTableIfExists();

        var action = () =>
        {
            var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);
            var c = new AzureCrypto(keyStore);
            c.GetEncryptor(TestUserId);
        };
        action.Should().Throw<AzureCryptoException>();
    }

    [Test]
    [NonParallelizable]
    public void TestAzureTableCryptoHasValidEncryptor()
    {
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
        _tableManager.AddSymmetricKey(newKey);

        var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
        var c = new AzureCrypto(keyStore);
        c.Should().NotBeNull("At this stage the constructor should have succeeded");

        var encryptor = c.GetEncryptor();
        encryptor.Should().NotBeNull("Because the keystore is initialized and there is a key");
    }

    [Test]
    [NonParallelizable]
    public void TestAzureTableCryptoHasValidEncryptorWithUserId()
    {
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
        _tableManager.AddSymmetricKey(newKey);

        var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, TestUserId);
        var c = new AzureCrypto(keyStore);
        c.Should().NotBeNull("At this stage the constructor should have succeeded");

        var encryptor = c.GetEncryptor(TestUserId);
        encryptor.Should().NotBeNull("Because the keystore is initialized and there is a key");
    }

    [Test]
    [NonParallelizable]
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

    [Test]
    [NonParallelizable]
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

    [Test]
    [NonParallelizable]
    public void DecryptionShouldReturnTheOriginalString()
    {
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
        _tableManager.AddSymmetricKey(newKey);

        var keyStore = new SymmetricKeyCache(_rsaHelper, _tableManager, null);
        var c = new AzureCrypto(keyStore);

        var encryptedString = c.EncryptStringAndBase64(TestString);
        var decryptedString = c.DecryptStringFromBase64(encryptedString);

        decryptedString.Should().BeEquivalentTo(TestString);
    }

    [Test]
    [NonParallelizable]
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