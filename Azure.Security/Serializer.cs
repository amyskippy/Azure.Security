namespace Azure.Security
{
#if NET9_0
    using System.Text.Json;
    using System.IO;

#else
    using System;
    using System.Runtime.Serialization;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.IO;
#endif

    public static class Serializer
    {
#if NET9_0
        public static MemoryStream SerializeToByteArray(object o)
        {
            // Serialize the object to a byte array.
            // This is more efficient than serializing to a string first.
            byte[] jsonUtf8Bytes = JsonSerializer.SerializeToUtf8Bytes(o);

            // Create a new MemoryStream from the resulting byte array.
            // The stream is already at position 0, so no Seek is needed.
            return new MemoryStream(jsonUtf8Bytes);
        }

        public static T DeserializeFromStream<T>(MemoryStream blobMemoryStream)
        {
            // Ensure the stream is at the beginning.
            blobMemoryStream.Seek(0, SeekOrigin.Begin);

            // Deserialize directly from the stream.
            // This is safe because you must specify the type 'T' you expect.
            T? result = JsonSerializer.Deserialize<T>(blobMemoryStream);

            if (result == null)
            {
                throw new JsonException("Deserialization resulted in a null object.");
            }

            return result;
        }
#else
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
#endif
    }
}