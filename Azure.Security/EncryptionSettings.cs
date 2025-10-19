namespace Azure.Security
{
    public class EncryptionSettings
    {
        public string StorageConnectionString { get; set; }
        public string CertificateValue { get; set; }
        public string CertificateTable { get; set; }
        public string CertificateName { get; set; }
    }
}
