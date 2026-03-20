using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FluentAssertions;
using NUnit.Framework;

namespace Azure.Security.Tests;

[TestFixture]
public class RsaHelperTests
{
    private static string _testFileDeploymentDirectory = null!;
    private static string _testCerficiatePath = null!;
    private const string TestString = "This is a random string for testing";
    private const string CertificatePassword = "test";
    private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");

    [OneTimeSetUp]
    public void TestSetup()
    {
        _testFileDeploymentDirectory = Path.Combine(TestContext.CurrentContext.TestDirectory, "TestFiles");
        _testCerficiatePath = Path.Combine(_testFileDeploymentDirectory, "TestCertificate.pfx");
    }

    [Test]
    public void RsaHelperEncryptStringShouldSucceed()
    {
        var helper = new RsaHelper(_testCerficiatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        var result = helper.RsaEncryptString(TestString);

        Assert.IsNotNull(result);
        Assert.IsTrue(result.Length > 0);
    }

    [Test]
    public void RsaHelperDecryptedStringShouldMatchOriginalValue()
    {
        var helper = new RsaHelper(_testCerficiatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        var result = helper.RsaEncryptString(TestString);

        var decryptedValue = helper.RsaDecryptToString(result);
        decryptedValue.Should().BeEquivalentTo(TestString, "Because the rsa decryption failed.");
    }

    [Test]
    public void RsaHelperCreateSymmetricKeyShouldSucceed()
    {
        var helper = new RsaHelper(_testCerficiatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        var keySet = helper.CreateNewAesSymmetricKeyset();
        keySet.Should().NotBeNull("Because encryption failed");
    }

    [Test]
    public void RsaHelperCreateSymmetricKeyShouldSucceedWithUserId()
    {
        var helper = new RsaHelper(_testCerficiatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);
        var keySet = helper.CreateNewAesSymmetricKeyset(TestUserId);
        keySet.Should().NotBeNull("Because encryption failed");
    }

    [Test]
    public void RsaHelperBytesShouldSucceed()
    {
        var helper = new RsaHelper(_testCerficiatePath, CertificatePassword, X509KeyStorageFlags.EphemeralKeySet);

        var aes = Aes.Create();
        aes.GenerateIV();
        aes.GenerateKey();

        var originalKey = aes.Key;
        var originalIv = aes.IV;

        var encryptedKeyBytes = helper.RsaEncryptBytes(aes.Key);
        var encryptedIvBytes = helper.RsaEncryptBytes(aes.IV);

        encryptedIvBytes.Should().NotBeNull("IV failed to encrypt");
        encryptedKeyBytes.Should().NotBeNull("Key failed to encrypt");

        var decryptedKeyBytes = helper.RsaDecryptToBytes(encryptedKeyBytes);
        var decryptedIvBytes = helper.RsaDecryptToBytes(encryptedIvBytes);

        originalKey.Should().BeEquivalentTo(decryptedKeyBytes);
        originalIv.Should().BeEquivalentTo(decryptedIvBytes);
    }
}