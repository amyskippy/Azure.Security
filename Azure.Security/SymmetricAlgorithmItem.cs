using System;
using System.Security.Cryptography;

namespace Azure.Security;

public class SymmetricAlgorithmItem
{
    public SymmetricAlgorithm Algorithm { get; set; } = null!;

    public Guid? UserId { get; set; }
}