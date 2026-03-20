using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Azure.Security.Interfaces;

namespace Azure.Security;

public class RsaHelper : IRsaHelper
{
    private static readonly UnicodeEncoding ByteConverter = new UnicodeEncoding();
    private readonly X509Certificate2 _x509;

    public RsaHelper(string certificatePath, string password, X509KeyStorageFlags flag = X509KeyStorageFlags.MachineKeySet)
    {
        _x509 = X509CertificateLoader.LoadPkcs12FromFile(certificatePath, password, flag);
    }

    public byte[] RsaEncryptString(string plainText)
    {
        var dataToEncrypt = ByteConverter.GetBytes(plainText);
        return RsaEncryptBytes(dataToEncrypt);
    }

    public byte[] RsaEncryptBytes(byte[] binaryData)
    {
        using var rsa = _x509.GetRSAPublicKey();
        if (rsa == null)
            throw new InvalidOperationException("Certificate does not contain an RSA public key.");


        return rsa.Encrypt(binaryData, RSAEncryptionPadding.Pkcs1);
    }

    public byte[] RsaDecryptToBytes(byte[] dataToDecrypt)
    {
        using var rsa = _x509.GetRSAPrivateKey();
        if (rsa == null)
            throw new InvalidOperationException("Certificate does not contain an RSA private key.");

        return rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.Pkcs1);
    }

    public string RsaDecryptToString(byte[] dataToDecrypt)
    {
        return ByteConverter.GetString(RsaDecryptToBytes(dataToDecrypt));
    }

    public SymmetricKey CreateNewAesSymmetricKeyset(Guid? userId = null)
    {
        var aes = Aes.Create();
        aes.GenerateIV();
        aes.GenerateKey();

        var symmetricKeySet = new SymmetricKey(userId)
        {
            Iv = RsaEncryptBytes(aes.IV),
            Key = RsaEncryptBytes(aes.Key),
            UserId = userId
        };

        return symmetricKeySet;
    }
}