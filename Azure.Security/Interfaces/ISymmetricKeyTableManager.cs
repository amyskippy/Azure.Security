namespace Azure.Security.Interfaces;

using System;
using Data.Tables;

public interface ISymmetricKeyTableManager
{
    bool KeyExists(Guid? userId);

    SymmetricKey? GetKey(Guid? userId);

    void DeleteSymmetricKey(SymmetricKey key);

    void AddSymmetricKey(SymmetricKey key);

    TableClient CreateTableIfNotExists();

    void DeleteTableIfExists();
}