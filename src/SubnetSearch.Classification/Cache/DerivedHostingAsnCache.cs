using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Models.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

internal static class DerivedHostingAsnCache
{
    private const int Magic = 0x4841534E;
    private const int Version = 1;
    private static readonly string[] InputFiles =
    [
        "ipcat-datacenters.csv",
        "cloud-provider-ip-addresses.json",
        "server-ip-addresses.csv",
        "ip2asn-v4.tsv.gz"
    ];

    private readonly record struct Stamp(bool Exists, long Length, long ModifiedTicks);

    public static HashSet<uint> LoadOrBuild(
        string dataDir,
        IReadOnlyList<HostingIpRange> ranges,
        IIpRangeIndex ipIndex)
    {
        var stamps = InputFiles
            .Select(name => GetStamp(Path.Combine(dataDir, name)))
            .ToArray();
        string cachePath = Path.Combine(
            DerivedCachePath.ForDataDirectory(dataDir, "classification"),
            "hosting-asns-v1.bin");
        if (TryRead(cachePath, stamps, out var cached))
            return cached;

        var result = new HashSet<uint>();
        foreach (var range in ranges)
        {
            var record = ipIndex.Find(range.StartIp);
            if (record.HasValue && record.Value.Asn > 0)
                result.Add(record.Value.Asn);
        }
        TryWrite(cachePath, stamps, result);
        return result;
    }

    private static Stamp GetStamp(string path)
    {
        var file = new FileInfo(path);
        return file.Exists
            ? new Stamp(true, file.Length, file.LastWriteTimeUtc.Ticks)
            : new Stamp(false, 0, 0);
    }

    private static bool TryRead(string path, Stamp[] expected, out HashSet<uint> result)
    {
        result = [];
        try
        {
            if (!File.Exists(path)) return false;
            using var reader = new BinaryReader(File.OpenRead(path));
            if (reader.ReadInt32() != Magic || reader.ReadInt32() != Version)
                return false;
            if (reader.ReadInt32() != expected.Length) return false;
            foreach (var stamp in expected)
            {
                if (reader.ReadBoolean() != stamp.Exists
                    || reader.ReadInt64() != stamp.Length
                    || reader.ReadInt64() != stamp.ModifiedTicks)
                    return false;
            }
            int count = reader.ReadInt32();
            if (count < 0 || count > 2_000_000) return false;
            result = new HashSet<uint>(count);
            for (int i = 0; i < count; i++)
                result.Add(reader.ReadUInt32());
            return reader.BaseStream.Position == reader.BaseStream.Length;
        }
        catch
        {
            result = [];
            return false;
        }
    }

    private static void TryWrite(string path, Stamp[] stamps, HashSet<uint> values)
    {
        string? tempPath = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            tempPath = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using (var writer = new BinaryWriter(File.Create(tempPath)))
            {
                writer.Write(Magic);
                writer.Write(Version);
                writer.Write(stamps.Length);
                foreach (var stamp in stamps)
                {
                    writer.Write(stamp.Exists);
                    writer.Write(stamp.Length);
                    writer.Write(stamp.ModifiedTicks);
                }
                writer.Write(values.Count);
                foreach (uint asn in values)
                    writer.Write(asn);
            }
            File.Move(tempPath, path, true);
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
