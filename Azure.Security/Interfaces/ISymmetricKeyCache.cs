using System;
using System.Security.Cryptography;

namespace Azure.Security.Interfaces;

public interface ISymmetricKeyCache
{
    ICryptoTransform GetDecryptor(Guid? userId = null);

    ICryptoTransform GetEncryptor(Guid? userId = null);
}