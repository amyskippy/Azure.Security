using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Azure.Data.Tables;
using Azure.Security.Exceptions;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using NUnit.Framework;

namespace Azure.Security.Tests;

[TestFixture]
public class SymmetricKeyTableManagerTests
{
    private static string _testFileDeploymentDirectory = null!;

    private const string TableName = "RandomTableName";
    private const string CertificatePassword = "test";
    private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
    private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");
    private static RsaHelper _rsaHelper = null!;
    private readonly IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());

    [OneTimeSetUp]
    public void TestSetup()
    {
        _testFileDeploymentDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestFiles");
        var certificatePath = Path.Combine(_testFileDeploymentDirectory, "TestCertificate.pfx");
        _rsaHelper = new RsaHelper(certificatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
    }

    [OneTimeTearDown]
    public void TestFixtureTearDown()
    {
        _memoryCache.Dispose();
    }

    [TearDown]
    public void TestTearDown()
    {
        if (_client.Exists(TableName))
            _client.GetTableClient(TableName).Delete();
    }

    [Test]
    public void ConstructorShouldInitializeSuccessfully()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.Should().NotBeNull("Initialization failed.");
    }

    [Test]
    public void GetKeyShouldThrowAnException()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.CreateTableIfNotExists();

        var action = () => symmetricTableManager.GetKey(null);
        action.Should().Throw<AzureCryptoException>();
    }

    [Test]
    public void GetKeyShouldReturnOneKey()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.CreateTableIfNotExists();
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
        symmetricTableManager.AddSymmetricKey(newKey);

        var key = symmetricTableManager.GetKey(null);

        key.Should().NotBeNull("The get query failed");
    }

    [Test]
    public void GetKeyShouldReturnOneKeyWithUserId()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.CreateTableIfNotExists();
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
        symmetricTableManager.AddSymmetricKey(newKey);

        var key = symmetricTableManager.GetKey(TestUserId);

        key.Should().NotBeNull("The get query failed");
    }

    [Test]
    public void DeleteKeyShouldSucceed()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.CreateTableIfNotExists();
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset();
        symmetricTableManager.AddSymmetricKey(newKey);

        var key = symmetricTableManager.GetKey(null);
        key.Should().NotBeNull("Insert operation failed");

        symmetricTableManager.DeleteSymmetricKey(newKey);
        var action = () => symmetricTableManager.GetKey(null);
        action.Should().Throw<AzureCryptoException>();
    }

    [Test]
    public void DeleteKeyShouldSucceedWithUserId()
    {
        var symmetricTableManager = CreateSymmetricKeyTableManager();
        symmetricTableManager.CreateTableIfNotExists();
        var newKey = _rsaHelper.CreateNewAesSymmetricKeyset(TestUserId);
        symmetricTableManager.AddSymmetricKey(newKey);

        var key = symmetricTableManager.GetKey(TestUserId);
        key.Should().NotBeNull("Insert operation failed");

        symmetricTableManager.DeleteSymmetricKey(newKey);
        var action = () => symmetricTableManager.GetKey(TestUserId);
        action.Should().Throw<AzureCryptoException>();
    }

    private SymmetricKeyTableManager CreateSymmetricKeyTableManager()
    {
        return new SymmetricKeyTableManager(_memoryCache, TableName, _client);
    }
}