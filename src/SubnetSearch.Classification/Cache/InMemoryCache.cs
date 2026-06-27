using SubnetSearch.Core.Interfaces;
using System.Collections.Concurrent;

namespace SubnetSearch.Classification;

public class InMemoryCache : ICache, IDisposable
{
    // Hard cap prevents OOM when classifying large CIDR ranges (e.g. /8 = 16M IPs).
    // When reached, the oldest 10% of entries are evicted before the new entry is added.
    private const int MaxCacheSize = 100_000;

    private readonly ConcurrentDictionary<string, (DateTime Expires, Lazy<object?> Value)> _cache = new();
    private readonly TimeSpan _defaultTtl;
    private readonly Timer _evictionTimer;

    public InMemoryCache(TimeSpan? ttl = null)
    {
        _defaultTtl = ttl ?? TimeSpan.FromHours(1);
        _evictionTimer = new Timer(_ => Evict(), null, TimeSpan.FromMinutes(5), TimeSpan.FromMinutes(5));
    }

    public T? GetOrAdd<T>(string key, Func<T> factory, TimeSpan? ttl = null) where T : class?
    {
        var now = DateTime.UtcNow;
        var effectiveTtl = ttl ?? _defaultTtl;

        if (_cache.Count >= MaxCacheSize)
            EvictOldest(MaxCacheSize / 10);

        var entry = _cache.AddOrUpdate(
            key,
            _ => (now.Add(effectiveTtl), new Lazy<object?>(() => factory(), LazyThreadSafetyMode.ExecutionAndPublication)),
            (_, existing) => existing.Expires > now
                ? existing
                : (now.Add(effectiveTtl), new Lazy<object?>(() => factory(), LazyThreadSafetyMode.ExecutionAndPublication)));
        return (T?)entry.Value.Value;
    }

    public void Remove(string key) => _cache.TryRemove(key, out _);

    public void Clear() => _cache.Clear();

    public void Dispose() => _evictionTimer.Dispose();

    private void Evict()
    {
        var now = DateTime.UtcNow;
        foreach (var key in _cache.Keys.ToList())
            if (_cache.TryGetValue(key, out var v) && v.Expires <= now)
                _cache.TryRemove(key, out _);
    }

    private void EvictOldest(int count)
    {
        foreach (var key in _cache
            .OrderBy(kv => kv.Value.Expires)
            .Take(count)
            .Select(kv => kv.Key))
        {
            _cache.TryRemove(key, out _);
        }
    }
}
