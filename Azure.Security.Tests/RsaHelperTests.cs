﻿namespace Azure.Security.Tests
{
    using FluentAssertions;
    using Microsoft.VisualStudio.TestTools.UnitTesting;
    using System;
    using System.IO;
    using System.Security.Cryptography;

    [TestClass]
    [DeploymentItem(@"TestFiles\TestCertificate.pfx")]
    public class RsaHelperTests
    {
        private const string TestString = "This is a random string for testing";
        private const string CertificatePassword = "test";
        private static readonly Guid TestUserId = new("e6f41e92-a89f-47ab-b511-224260f3bb55");

        public TestContext TestContext { get; set; }

        [TestMethod]
        public void RsaHelperEncryptStringShouldSucceed()
        {
            var directory = TestContext.DeploymentDirectory;
            var helper = new RsaHelper(Path.Combine(directory, "TestCertificate.pfx"), CertificatePassword);
            var result = helper.RsaEncryptString(TestString);

            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > 0);
        }

        [TestMethod]
        public void RsaHelperDecryptedStringShouldMatchOriginalValue()
        {
            var directory = TestContext.DeploymentDirectory;
            var helper = new RsaHelper(Path.Combine(directory, "TestCertificate.pfx"), CertificatePassword);
            var result = helper.RsaEncryptString(TestString);

            var decryptedValue = helper.RsaDecryptToString(result);
            decryptedValue.Should().BeEquivalentTo(TestString, "Because the rsa decryption failed.");
        }

        [TestMethod]
        public void RsaHelperCreateSymmetricKeyShouldSucceed()
        {
            var directory = TestContext.DeploymentDirectory;
            var helper = new RsaHelper(Path.Combine(directory, "TestCertificate.pfx"), CertificatePassword);
            var keySet = helper.CreateNewAesSymmetricKeyset();
            keySet.Should().NotBeNull("Because encryption failed");
        }

        [TestMethod]
        public void RsaHelperCreateSymmetricKeyShouldSucceedWithUserId()
        {
            var directory = TestContext.DeploymentDirectory;
            var helper = new RsaHelper(Path.Combine(directory, "TestCertificate.pfx"), CertificatePassword);
            var keySet = helper.CreateNewAesSymmetricKeyset(TestUserId);
            keySet.Should().NotBeNull("Because encryption failed");
        }

        [TestMethod]
        public void RsaHelperBytesShouldSucceed()
        {
            var directory = TestContext.DeploymentDirectory;
            var helper = new RsaHelper(Path.Combine(directory, "TestCertificate.pfx"), CertificatePassword);

            var aes = new AesManaged();
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
}
