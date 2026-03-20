using System.IO;
using System.Text.Json;

namespace Azure.Security;

public static class Serializer
{
    public static Stream SerializeToByteArray(object o)
    {
        // Serialize the object to a byte array.
        // This is more efficient than serializing to a string first.
        var jsonUtf8Bytes = JsonSerializer.SerializeToUtf8Bytes(o);

        // Create a new MemoryStream from the resulting byte array.
        // The stream is already at position 0, so no Seek is needed.
        return new MemoryStream(jsonUtf8Bytes);
    }

    public static T DeserializeFromStream<T>(Stream blobMemoryStream)
    {
        // Ensure the stream is at the beginning.
        if (blobMemoryStream.CanSeek && blobMemoryStream.Position != 0)
            blobMemoryStream.Seek(0, SeekOrigin.Begin);

        // Deserialize directly from the stream.
        // This is safe because you must specify the type 'T' you expect.
        var result = JsonSerializer.Deserialize<T>(blobMemoryStream);

        if (result == null)
            throw new JsonException("Deserialization resulted in a null object.");

        return result;
    }
}