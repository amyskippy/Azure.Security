using System;
using System.Security.Cryptography;
using Azure.Security.Exceptions;
using Azure.Security.Interfaces;

namespace Azure.Security;

public class SymmetricKeyCache : ISymmetricKeyCache
{
    private readonly SymmetricAlgorithmItem _keyCache;

    public SymmetricKeyCache(
        IRsaHelper theRsaHelper,
        ISymmetricKeyTableManager keyTableManager,
        Guid? userId)
    {
        var key = keyTableManager.GetKey(userId);

        if (key is not { Iv: not null, Key: not null })
            throw new AzureCryptoException("No keys have been configured.");

        try
        {
            var symmetricCryptoKey = theRsaHelper.RsaDecryptToBytes(key.Key);
            var symmetricCryptoIv = theRsaHelper.RsaDecryptToBytes(key.Iv);

            var aes = Aes.Create();
            aes.IV = symmetricCryptoIv;
            aes.Key = symmetricCryptoKey;

            var algorithm = new SymmetricAlgorithmItem
            {
                Algorithm = aes,
                UserId = key.UserId
            };
            _keyCache = algorithm;
        }
        catch (Exception ex)
        {
            throw new AzureCryptoException("Error initializing crypto key.", ex);
        }
    }

    public ICryptoTransform GetDecryptor(Guid? userId = null)
    {
        return GetAlgorithm(userId).CreateDecryptor();
    }

    public ICryptoTransform GetEncryptor(Guid? userId = null)
    {
        return GetAlgorithm(userId).CreateEncryptor();
    }

    private SymmetricAlgorithm GetAlgorithm(Guid? userId)
    {
        return _keyCache.UserId != userId
            ? throw new AzureCryptoException($"No keys have been configured. KeyCache UserId: {_keyCache.UserId}, userId: {userId}")
            : _keyCache.Algorithm;
    }
}