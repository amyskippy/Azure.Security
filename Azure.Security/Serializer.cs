namespace Azure.Security
{
    using System;
    using System.IO;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Formatters.Binary;

    public static class Serializer
    {
        [Obsolete("Obsolete")]
        public static MemoryStream SerializeToByteArray(object o)
        {
            var stream = new MemoryStream();
            IFormatter formatter = new BinaryFormatter();
            formatter.Serialize(stream, o);
            stream.Seek(0, SeekOrigin.Begin);
            return stream;
        }

        [Obsolete("Obsolete")]
        public static object DeserializeFromStream(MemoryStream blobMemoryStream)
        {
            IFormatter formatter = new BinaryFormatter();
            blobMemoryStream.Seek(0, SeekOrigin.Begin);
            var o = formatter.Deserialize(blobMemoryStream);
            
            return o;
        }
    }
}
