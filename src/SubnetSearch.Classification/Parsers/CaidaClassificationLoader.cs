using System.IO.Compression;

namespace SubnetSearch.Classification;

public static class CaidaClassificationLoader
{
    // Loads CAIDA AS classification from a gzipped pipe-delimited text file.
    // File format: <asn>|<source>|<class>  (comment lines start with #)
    // Classification values: Content, Enterprise, Transit/Access
    // Returns empty dict when file is missing or malformed — callers degrade gracefully.
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
                var cls = parts[2].Trim(); // column 2 = class per CAIDA spec (asn|source|class)
                if (!string.IsNullOrEmpty(cls))
                    result[asn] = cls;
            }
        }
        catch (Exception ex) when (ex is IOException or InvalidDataException
                                      or FormatException or UnauthorizedAccessException)
        {
            // Degrade gracefully — callers treat empty dict as "no CAIDA data available"
        }
        return result;
    }
}
