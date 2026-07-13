using System.IO.Compression;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

public class Ip2AsnLoader
{
    private const int CacheMagic = 0x49324153;
    private const int CacheVersion = 1;
    private readonly string? _cacheDirectory;

    public Ip2AsnLoader(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory;
    }

    public Task<Ip2AsnRecord[]> LoadAsync(string gzipFilePath)
        => Task.Run(() => LoadWithCache(gzipFilePath));

    private Ip2AsnRecord[] LoadWithCache(string gzipFilePath)
    {
        var source = new FileInfo(gzipFilePath);
        string cachePath = GetCachePath(source);
        if (TryReadCache(cachePath, source, out var cached))
            return cached;

        var records = LoadSync(gzipFilePath);
        TryWriteCache(cachePath, source, records);
        return records;
    }

    private static Ip2AsnRecord[] LoadSync(string gzipFilePath)
    {
        // GZipStream decompresses synchronously regardless of async wrapper.
        // Reading line-by-line with ReadLineAsync in a tight loop over ~400 K entries
        // creates 400 K Task allocations for no benefit. Offload the entire parse to
        // the thread-pool and use synchronous ReadLine throughout.
        var records = new List<Ip2AsnRecord>(500_000);
        var firstLines = new List<string>(5);

        using var fileStream = File.OpenRead(gzipFilePath);
        using var gzipStream = new GZipStream(fileStream, CompressionMode.Decompress);
        using var reader     = new StreamReader(gzipStream, bufferSize: 65_536);

        string? line;
        while ((line = reader.ReadLine()) != null)
        {
            if (firstLines.Count < 5) firstLines.Add(line);
            if (line.StartsWith('#')) continue;

            var cols = line.Split('\t');
            if (cols.Length < 5) continue;

            try
            {
                uint startIp = IpConverter.IpToUint(cols[0]);
                uint endIp   = IpConverter.IpToUint(cols[1]);

                if (uint.TryParse(cols[2], out uint asn))
                    records.Add(new Ip2AsnRecord
                    {
                        StartIp     = startIp,
                        EndIp       = endIp,
                        Asn         = asn,
                        Country     = cols[3],
                        Description = cols[4],
                    });
            }
            catch { }
        }

        if (records.Count == 0)
            throw new InvalidDataException(
                $"File read but contains no IP2ASN records. " +
                $"Sample lines:\n{string.Join("\n", firstLines)}");

        return records.ToArray();
    }

    private string GetCachePath(FileInfo source)
    {
        string directory = _cacheDirectory ?? DerivedCachePath.ForDataDirectory(
            source.DirectoryName ?? Directory.GetCurrentDirectory(),
            "classification");
        return Path.Combine(directory, "ip2asn-v1.bin");
    }

    private static bool TryReadCache(
        string cachePath,
        FileInfo source,
        out Ip2AsnRecord[] records)
    {
        records = Array.Empty<Ip2AsnRecord>();
        try
        {
            if (!File.Exists(cachePath)) return false;
            using var reader = new BinaryReader(File.OpenRead(cachePath));
            if (reader.ReadInt32() != CacheMagic ||
                reader.ReadInt32() != CacheVersion ||
                reader.ReadInt64() != source.Length ||
                reader.ReadInt64() != source.LastWriteTimeUtc.Ticks)
                return false;

            int count = reader.ReadInt32();
            if (count <= 0 || count > 2_000_000) return false;
            records = new Ip2AsnRecord[count];
            for (int i = 0; i < count; i++)
            {
                records[i] = new Ip2AsnRecord
                {
                    StartIp = reader.ReadUInt32(),
                    EndIp = reader.ReadUInt32(),
                    Asn = reader.ReadUInt32(),
                    Country = reader.ReadString(),
                    Description = reader.ReadString()
                };
            }
            return reader.BaseStream.Position == reader.BaseStream.Length;
        }
        catch
        {
            records = Array.Empty<Ip2AsnRecord>();
            return false;
        }
    }

    private static void TryWriteCache(
        string cachePath,
        FileInfo source,
        Ip2AsnRecord[] records)
    {
        string? tempPath = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
            tempPath = cachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using (var writer = new BinaryWriter(File.Create(tempPath)))
            {
                writer.Write(CacheMagic);
                writer.Write(CacheVersion);
                writer.Write(source.Length);
                writer.Write(source.LastWriteTimeUtc.Ticks);
                writer.Write(records.Length);
                foreach (var record in records)
                {
                    writer.Write(record.StartIp);
                    writer.Write(record.EndIp);
                    writer.Write(record.Asn);
                    writer.Write(record.Country ?? string.Empty);
                    writer.Write(record.Description ?? string.Empty);
                }
            }
            File.Move(tempPath, cachePath, true);
            tempPath = null;
        }
        catch
        {
        }
        finally
        {
            if (tempPath != null)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }
}
