using System.Text.Json;
using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Reputation;

public class SpamhausDropClient
{
    private const string Url = "https://www.spamhaus.org/drop/asndrop.txt";
    private static readonly TimeSpan Ttl = TimeSpan.FromHours(24);
    private static readonly TimeSpan RequestTimeout = TimeSpan.FromSeconds(2);

    private readonly HttpClient _http;
    private readonly string _cachePath;
    private readonly string _fallbackCachePath;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private volatile HashSet<uint>? _listedAsns;
    private DateTimeOffset _loadedAt = DateTimeOffset.MinValue;

    private sealed record DiskCache(DateTimeOffset FetchedAt, uint[] Asns);

    public SpamhausDropClient(HttpClient http, string dataDir)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        ArgumentException.ThrowIfNullOrWhiteSpace(dataDir);
        string fullDataDir = Path.GetFullPath(dataDir);
        _cachePath = Path.Combine(fullDataDir, "spamhaus_cache.json");
        _fallbackCachePath = Path.Combine(
            DerivedCachePath.ForDataDirectory(fullDataDir, "reputation"),
            "spamhaus_cache.json");
    }

    public async Task LoadAsync(CancellationToken ct = default)
    {
        if (IsFresh())
            return;

        await _lock.WaitAsync(ct);
        try
        {
            if (IsFresh())
                return;

            if (!TryLoadDiskCache(_cachePath))
                TryLoadDiskCache(_fallbackCachePath);
            if (IsFresh())
                return;

            using var requestCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            requestCts.CancelAfter(RequestTimeout);
            string text = await _http.GetStringAsync(Url, requestCts.Token);
            var asns = Parse(text);
            if (asns.Count == 0)
                throw new InvalidDataException("Spamhaus returned no ASN records.");
            var fetchedAt = DateTimeOffset.UtcNow;
            _listedAsns = asns;
            _loadedAt = fetchedAt;
            var cache = new DiskCache(fetchedAt, [.. asns]);
            if (!WriteDiskCache(_cachePath, cache))
                WriteDiskCache(_fallbackCachePath, cache);
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch
        {
            _listedAsns ??= [];
            _loadedAt = DateTimeOffset.UtcNow;
        }
        finally
        {
            _lock.Release();
        }
    }

    public bool IsListed(uint asn) => _listedAsns?.Contains(asn) ?? false;

    private bool IsFresh()
    {
        TimeSpan age = DateTimeOffset.UtcNow - _loadedAt;
        return _listedAsns != null && age >= TimeSpan.Zero && age < Ttl;
    }

    private bool TryLoadDiskCache(string cachePath)
    {
        try
        {
            if (!File.Exists(cachePath))
                return false;
            var cache = JsonSerializer.Deserialize<DiskCache>(File.ReadAllText(cachePath));
            if (cache?.Asns is not { Length: > 0 })
                return false;
            _listedAsns = [.. cache.Asns];
            _loadedAt = cache.FetchedAt;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool WriteDiskCache(string cachePath, DiskCache cache)
    {
        string tempPath = cachePath + $".{Guid.NewGuid():N}.tmp";
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
            File.WriteAllText(tempPath, JsonSerializer.Serialize(cache));
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

    private static HashSet<uint> Parse(string text)
    {
        var asns = new HashSet<uint>();
        foreach (var line in text.Split('\n'))
        {
            var trimmed = line.Trim();
            if (trimmed.StartsWith(';') || string.IsNullOrWhiteSpace(trimmed))
                continue;
            string asnText = trimmed.Split(';')[0].Trim();
            if (asnText.StartsWith("AS", StringComparison.OrdinalIgnoreCase)
                && uint.TryParse(asnText[2..], out uint asn))
            {
                asns.Add(asn);
            }
        }
        return asns;
    }
}
