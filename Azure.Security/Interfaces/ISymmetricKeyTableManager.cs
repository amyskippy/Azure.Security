namespace Azure.Security.Interfaces
{
    using Data.Tables;
    using System;

    public interface ISymmetricKeyTableManager
    {
        SymmetricKey GetKey(Guid? userId);

        void DeleteSymmetricKey(SymmetricKey key);

        void AddSymmetricKey(SymmetricKey key);

        TableClient CreateTableIfNotExists();

        void DeleteTableIfExists();
    }
}
