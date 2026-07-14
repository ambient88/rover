using System.Text.Json;
using SubnetSearch.Classification;
using SubnetSearch.Core.Interfaces.Classification;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Recommend;

public sealed class LocalHostingAsnCache
{
    private const int SchemaVersion = 1;
    private const string CacheFileName = "local_hosting_asns_cache.json";
    private static readonly string[] InputFileNames =
    [
        "ipcat-datacenters.csv",
        "cloud-provider-ip-addresses.json",
        "server-ip-addresses.csv",
        "ip2asn-v4.tsv.gz"
    ];

    private readonly string _dataDir;
    private readonly string _cachePath;
    private readonly string _fallbackCachePath;

    private sealed record InputFingerprint(
        string FileName,
        bool Exists,
        long Length,
        long LastWriteTimeUtcTicks);

    private sealed record AsnCount(uint Asn, int Count);

    private sealed record CacheDocument(
        int Version,
        InputFingerprint[] Inputs,
        AsnCount[] Results);

    public LocalHostingAsnCache(string dataDir)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        _dataDir = Path.GetFullPath(dataDir);
        _cachePath = Path.Combine(_dataDir, CacheFileName);
        _fallbackCachePath = Path.Combine(
            DerivedCachePath.ForDataDirectory(_dataDir, "recommend"),
            CacheFileName);
    }

    public async Task<IReadOnlyList<(uint Asn, int Count)>> GetAsync(
        IIpRangeIndex ipIndex,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(ipIndex);
        InputFingerprint[] fingerprints = GetFingerprints();
        var cached = TryLoad(_cachePath, fingerprints)
            ?? TryLoad(_fallbackCachePath, fingerprints);
        if (cached != null)
            return cached;

        var hostingIndex = new HostingRangeIndex();
        await hostingIndex.LoadRangesAsync(_dataDir, cancellationToken);
        if (hostingIndex.Count == 0)
        {
            WriteWithFallback(fingerprints, []);
            return [];
        }

        var counts = new Dictionary<uint, int>();
        foreach (var range in hostingIndex.Ranges)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var record = ipIndex.Find(range.StartIp);
            if (record.HasValue && record.Value.Asn > 0)
                counts[record.Value.Asn] = counts.GetValueOrDefault(record.Value.Asn) + 1;
        }

        AsnCount[] results =
        [
            .. counts
                .OrderByDescending(pair => pair.Value)
                .Select(pair => new AsnCount(pair.Key, pair.Value))
        ];
        WriteWithFallback(fingerprints, results);
        return results.Select(item => (item.Asn, item.Count)).ToArray();
    }

    private InputFingerprint[] GetFingerprints()
        => InputFileNames.Select(fileName =>
        {
            string path = Path.Combine(_dataDir, fileName);
            if (!File.Exists(path))
                return new InputFingerprint(fileName, false, 0, 0);
            var info = new FileInfo(path);
            return new InputFingerprint(fileName, true, info.Length, info.LastWriteTimeUtc.Ticks);
        }).ToArray();

    private static IReadOnlyList<(uint Asn, int Count)>? TryLoad(
        string cachePath,
        InputFingerprint[] fingerprints)
    {
        try
        {
            if (!File.Exists(cachePath))
                return null;
            var document = JsonSerializer.Deserialize<CacheDocument>(File.ReadAllText(cachePath));
            if (document == null
                || document.Version != SchemaVersion
                || !document.Inputs.SequenceEqual(fingerprints))
            {
                return null;
            }

            return document.Results.Select(item => (item.Asn, item.Count)).ToArray();
        }
        catch
        {
            return null;
        }
    }

    private void WriteWithFallback(InputFingerprint[] fingerprints, AsnCount[] results)
    {
        if (!Write(_cachePath, fingerprints, results))
            Write(_fallbackCachePath, fingerprints, results);
    }

    private static bool Write(
        string cachePath,
        InputFingerprint[] fingerprints,
        AsnCount[] results)
    {
        string tempPath = cachePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
            var document = new CacheDocument(SchemaVersion, fingerprints, results);
            File.WriteAllText(tempPath, JsonSerializer.Serialize(document));
            File.Move(tempPath, cachePath, overwrite: true);
            return true;
        }
        catch
        {
            return false;
        }
        finally
        {
            TryDelete(tempPath);
        }
    }

    // Best-effort removal of a randomly named temp file. The failure branch needs the
    // OS to reject the delete at exactly that moment, which no test can arrange
    // deterministically, so the helper is excluded from the unit-coverage metric.
    [System.Diagnostics.CodeAnalysis.ExcludeFromCodeCoverage]
    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
        }
    }
}
