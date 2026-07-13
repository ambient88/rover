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

    // rpki_ entries now live at most RpkiAuthoritativeTtl (7 days); anything with a far larger
    // remaining TTL is a legacy 10-year record to be dropped on load (F6).
    private const int RpkiLegacyTtlCutoffDays = 30;

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
            await using var stream = new FileStream(
                _path, FileMode.Open, FileAccess.Read, FileShare.Read,
                65_536, FileOptions.Asynchronous | FileOptions.SequentialScan);
            var stored = await JsonSerializer.DeserializeAsync<Dictionary<string, CacheEntry>>(stream);
            if (stored == null) return;
            var now = DateTime.UtcNow;
            // F6: legacy rpki_ entries were persisted with a 10-year TTL. Drop those on load so the
            // reduced authoritative TTL actually takes effect. Fresh entries (short TTL) are kept,
            // so this migrates the stale data without forcing a re-fetch of recent results.
            var legacyRpkiCutoff = now.AddDays(RpkiLegacyTtlCutoffDays);
            foreach (var (k, v) in stored)
            {
                if (v.ExpiresAt <= now) continue;
                if (k.StartsWith("rpki_", StringComparison.Ordinal) && v.ExpiresAt > legacyRpkiCutoff)
                    continue;
                _store.TryAdd(k, v);
            }
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
        => Set(key, data, _ttl);

    // Explicit per-entry TTL overload. The store already keeps an absolute
    // ExpiresAt per entry, so heterogeneous TTLs coexist in one file:
    // RPKI "forever" (large TTL), ping "minutes", prefix/neighbour 24h default.
    public void Set(string key, string data, TimeSpan ttl)
    {
        _store[key] = new CacheEntry(DateTime.UtcNow.Add(ttl), data);
        Interlocked.Exchange(ref _dirty, 1);
    }

    public async Task FlushIfDirtyAsync()
    {
        // Atomically claim the dirty flag (1 → 0); restored below if the write fails.
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
            // WR-09: атомарная запись через временный файл — обрыв процесса (Ctrl+C,
            // kill) посреди записи не должен оставлять усечённый JSON и молча
            // уничтожать весь накопленный кэш при следующей загрузке.
            var tmp = _path + ".tmp";
            await using (var stream = new FileStream(
                tmp, FileMode.Create, FileAccess.Write, FileShare.None,
                65_536, FileOptions.Asynchronous))
            {
                await JsonSerializer.SerializeAsync(stream, dict);
            }
            File.Move(tmp, _path, overwrite: true);
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
