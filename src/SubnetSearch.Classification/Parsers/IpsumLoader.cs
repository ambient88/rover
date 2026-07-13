using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

public class IpsumLoader
{
    private const int CacheMagic = 0x4950534D;
    private const int CacheVersion = 1;
    private readonly string? _cacheDirectory;

    public IpsumLoader(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory;
    }

    public Task<Dictionary<uint, int>> LoadAsync(string filePath)
    {
        if (!File.Exists(filePath))
            return Task.FromResult(new Dictionary<uint, int>());

        return Task.Run(() => Load(filePath));
    }

    private Dictionary<uint, int> Load(string filePath)
    {
        var source = new FileInfo(filePath);
        string directory = _cacheDirectory ?? DerivedCachePath.ForDataDirectory(
            source.DirectoryName ?? Directory.GetCurrentDirectory(),
            "classification");
        string cachePath = Path.Combine(directory, "ipsum-v1.bin");
        if (TryReadCache(cachePath, source, out var cached))
            return cached;

        var scores = new Dictionary<uint, int>();
        foreach (var line in File.ReadLines(filePath))
        {
            if (line.Length == 0 || line[0] == '#') continue;

            var tab = line.IndexOf('\t');
            if (tab < 0) continue;

            string ipPart    = line[..tab];
            string scorePart = line[(tab + 1)..];

            if (IpConverter.TryIpToUint(ipPart, out uint ipInt)
                && int.TryParse(scorePart, out int score))
            {
                scores[ipInt] = score;
            }
        }
        TryWriteCache(cachePath, source, scores);
        return scores;
    }

    private static bool TryReadCache(
        string cachePath,
        FileInfo source,
        out Dictionary<uint, int> scores)
    {
        scores = [];
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
            if (count < 0 || count > 5_000_000) return false;
            scores = new Dictionary<uint, int>(count);
            for (int i = 0; i < count; i++)
                scores[reader.ReadUInt32()] = reader.ReadInt32();
            return reader.BaseStream.Position == reader.BaseStream.Length;
        }
        catch
        {
            scores = [];
            return false;
        }
    }

    private static void TryWriteCache(
        string cachePath,
        FileInfo source,
        Dictionary<uint, int> scores)
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
                writer.Write(scores.Count);
                foreach (var (ip, score) in scores)
                {
                    writer.Write(ip);
                    writer.Write(score);
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
