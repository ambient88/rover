using System.IO.Compression;

namespace SubnetSearch.Classification;

public static class CaidaClassificationLoader
{
    // Loads CAIDA AS classification from a gzipped pipe-delimited text file.
    // File format: <asn>|<source>|<class>  (comment lines start with #)
    // Classification values: Content, Enterprise, Transit/Access
    // Returns an empty dictionary for a missing or malformed file so callers can continue.
    public static async Task<IReadOnlyDictionary<uint, string>> LoadAsync(string gzipFilePath)
    {
        var result = new Dictionary<uint, string>();
        if (!File.Exists(gzipFilePath)) return result;
        try
        {
            await using var fs     = File.OpenRead(gzipFilePath);
            await using var gz     = new GZipStream(fs, CompressionMode.Decompress);
            using var reader = new StreamReader(gz);

            string? line;
            while ((line = await reader.ReadLineAsync()) != null)
            {
                if (line.StartsWith('#') || string.IsNullOrWhiteSpace(line)) continue;
                var parts = line.Split('|');
                if (parts.Length < 3) continue;
                if (!uint.TryParse(parts[0].Trim(), out var asn)) continue;
                var cls = parts[2].Trim(); // CAIDA stores the class in column 2.
                if (!string.IsNullOrEmpty(cls))
                    result[asn] = cls;
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException
                                      or FormatException or UnauthorizedAccessException)
        {
            // Callers treat an empty dictionary as unavailable CAIDA data.
        }
        return result;
    }
}
