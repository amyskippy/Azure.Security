using System;

namespace Azure.Security.Interfaces;

public interface IEncryptionHelper
{
    void CreateNewCryptoKeyIfNotExists(Guid? userId = null);

    byte[] EncryptBytes(byte[] bytesToEncrypt, Guid? userId = null, bool createIfNotExists = true);

    byte[] DecryptBytes(byte[] bytesToDecrypt, Guid? userId = null);

    string EncryptAndBase64(string valueToEncrypt, Guid? userId = null, bool createIfNotExists = true);

    string DecryptFromBase64(string valueToDecrypt, Guid? userId = null);
}