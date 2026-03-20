using System;
using System.Security.Cryptography;

namespace Azure.Security;

public class SymmetricAlgorithmItem
{
    public required SymmetricAlgorithm Algorithm { get; set; }

    public Guid? UserId { get; set; }
}