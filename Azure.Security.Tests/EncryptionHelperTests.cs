using System;
using System.IO;
using Azure.Data.Tables;
using FluentAssertions;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using NUnit.Framework;

namespace Azure.Security.Tests;

[TestFixture]
public class EncryptionHelperTests
{
    private static string _testFileDeploymentDirectory = null!;
    private const string TestFileName = "TestTextFile.txt";
    private const string TestString = "This is a rendom test string";
    private const string TableName = "TestTableName";
    private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");
    private readonly TableServiceClient _client = new("UseDevelopmentStorage=true");
    private readonly IMemoryCache _memoryCache = new MemoryCache(new MemoryCacheOptions());
    //private SymmetricKeyTableManager _tableManager = null!;

    private readonly IOptions<EncryptionSettings> _encryptionSettings = Options.Create(
        new EncryptionSettings
        {
            CertificateName = "TestCertificate.pfx",
            CertificateTable = "TestTableName",
            StorageConnectionString = "UseDevelopmentStorage=true",
            CertificateValue = "test"
        });

    [OneTimeSetUp]
    public void TestFixtureSetup()
    {
        _testFileDeploymentDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestFiles");

        //_tableManager = new SymmetricKeyTableManager(_memoryCache, TableName, _client);
    }

    [OneTimeTearDown]
    public void TestFixtureTearDown()
    {
        _memoryCache.Dispose();
    }


    [SetUp]
    public void TestSetup()
    {
        //_tableManager.CreateTableIfNotExists();
    }

    [TearDown]
    public void TestTearDown()
    {
        //_tableManager.DeleteTableIfExists();
    }

    [Test]
    public void TestConstructorSucceeds()
    {
        var encryptionHelper = CreateEncryptionHelper();
        encryptionHelper.Should().NotBeNull("Constructor failed");
    }

    [Test]
    public void TestConstructorSucceedsWithUserId()
    {
        var encryptionHelper = CreateEncryptionHelper(TestUserId);
        encryptionHelper.Should().NotBeNull("Constructor failed");
    }

    [Test]
    public void TestEncryptStringShouldSucceed()
    {
        var encryptionHelper = CreateEncryptionHelper();
        var encryptedString = encryptionHelper.EncryptAndBase64(TestString);

        encryptedString.Should().NotBeNullOrEmpty("Encrypting failed");
        encryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
    }

    [Test]
    public void TestEncryptStringShouldSucceedWithUserId()
    {
        var encryptionHelper = CreateEncryptionHelper(TestUserId);
        var encryptedString = encryptionHelper.EncryptAndBase64(TestString, TestUserId);

        encryptedString.Should().NotBeNullOrEmpty("Encrypting failed");
        encryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
    }

    [Test]
    public void TestDecryptStringShouldSucceed()
    {
        var encryptionHelper = CreateEncryptionHelper();
        var encryptedString = encryptionHelper.EncryptAndBase64(TestString);
        var decryptedString = encryptionHelper.DecryptFromBase64(encryptedString);

        decryptedString.Should().NotBeNullOrEmpty("Encrypting failed");
        decryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
        decryptedString.Should().BeEquivalentTo(TestString);
    }

    [Test]
    public void TestDecryptStringShouldSucceedWithUserId()
    {
        var encryptionHelper = CreateEncryptionHelper(TestUserId);
        var encryptedString = encryptionHelper.EncryptAndBase64(TestString, TestUserId);
        var decryptedString = encryptionHelper.DecryptFromBase64(encryptedString, TestUserId);

        decryptedString.Should().NotBeNullOrEmpty("Encrypting failed");
        decryptedString.Length.Should().BeGreaterThan(0, "Encryption failed");
        decryptedString.Should().BeEquivalentTo(TestString);
    }

    [Test]
    public void TestEncryptBinaryShouldSucceed()
    {
        var encryptionHelper = CreateEncryptionHelper();
        var bytesToEncrypt = File.ReadAllBytes(Path.Combine(_testFileDeploymentDirectory, TestFileName));
        var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt);

        encryptedBytes.Should().NotBeNull("EncryptionFailed");
    }

    [Test]
    public void TestEncryptBinaryShouldSucceedWithUserId()
    {
        var encryptionHelper = CreateEncryptionHelper(TestUserId);
        var bytesToEncrypt = File.ReadAllBytes(Path.Combine(_testFileDeploymentDirectory, TestFileName));
        var encryptedBytes = encryptionHelper.EncryptBytes(bytesToEncrypt, TestUserId);

        encryptedBytes.Should().NotBeNull("EncryptionFailed");
    }

    [Test]
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

    [Test]
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
        var tableManager = new SymmetricKeyTableManager(_memoryCache, TableName, _client);
        tableManager.CreateTableIfNotExists();

        return new EncryptionHelper(_encryptionSettings, _memoryCache, _testFileDeploymentDirectory, userId);
    }
}