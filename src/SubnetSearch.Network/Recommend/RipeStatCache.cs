using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace SubnetSearch.Network.Recommend;

// Disk-backed cache for RIPE Stat API responses.
// Reduces non-determinism between runs: once an ASN's prefixes are fetched,
// subsequent runs return the same data (within the TTL window).
public class RipeStatCache
{
    private readonly string   _path;
    private readonly TimeSpan _ttl;
    private readonly ConcurrentDictionary<string, CacheEntry> _store = new();
    private int _dirty; // 0 = clean, 1 = dirty; accessed via Interlocked

    private record CacheEntry(
        [property: JsonPropertyName("e")] DateTime ExpiresAt,
        [property: JsonPropertyName("d")] string   Data);

    public RipeStatCache(string dataDir, TimeSpan? ttl = null)
    {
        _ttl  = ttl ?? TimeSpan.FromHours(24);
        _path = Path.Combine(dataDir, "ripe_cache.json");
    }

    public static async Task<RipeStatCache> LoadAsync(string dataDir, TimeSpan? ttl = null)
    {
        var cache = new RipeStatCache(dataDir, ttl);
        await cache.TryLoadAsync();
        return cache;
    }

    private async Task TryLoadAsync()
    {
        if (!File.Exists(_path)) return;
        try
        {
            var text   = await File.ReadAllTextAsync(_path);
            var stored = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(text);
            if (stored == null) return;
            var now = DateTime.UtcNow;
            foreach (var (k, v) in stored)
                if (v.ExpiresAt > now)
                    _store.TryAdd(k, v);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException) { }
    }

    public bool TryGet(string key, out string? data)
    {
        if (_store.TryGetValue(key, out var e))
        {
            if (e.ExpiresAt > DateTime.UtcNow)
            {
                data = e.Data;
                return true;
            }
            _store.TryRemove(key, out _);
        }
        data = null;
        return false;
    }

    public void Set(string key, string data)
    {
        _store[key] = new CacheEntry(DateTime.UtcNow.Add(_ttl), data);
        Interlocked.Exchange(ref _dirty, 1);
    }

    public async Task FlushIfDirtyAsync()
    {
        // Read _dirty first without clearing: if the write fails we restore it below.
        if (Interlocked.CompareExchange(ref _dirty, 0, 1) == 0) return;
        try
        {
            var dir = Path.GetDirectoryName(_path);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);

            // Evict all expired entries before persisting.
            var now  = DateTime.UtcNow;
            var dict = _store
                .Where(kv => kv.Value.ExpiresAt > now)
                .ToDictionary(kv => kv.Key, kv => kv.Value);
            await File.WriteAllTextAsync(_path, JsonSerializer.Serialize(dict));
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // Write failed — restore dirty flag so the next call retries.
            Interlocked.Exchange(ref _dirty, 1);
            // Write failures are non-fatal — cache is optional.
            _ = ex;
        }
    }
}
