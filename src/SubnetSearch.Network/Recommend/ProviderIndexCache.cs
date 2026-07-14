using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// Disk-backed cache for RIPE Stat country-ASN lists.
// Each country entry expires independently (TTL = 7 days).
// Stored in the data directory alongside other downloaded databases.
public class ProviderIndexCache(string dataDir)
{
    private static readonly TimeSpan Ttl = TimeSpan.FromDays(7);
    private string CachePath => Path.Combine(dataDir, "provider-index-cache.json");

    private record CacheEntry(
        [property: JsonPropertyName("ts")]   DateTime    UpdatedUtc,
        [property: JsonPropertyName("asns")] List<uint>? Asns); // nullable: STJ may deserialize "asns":null

    // Returns non-expired entries keyed by country code, or null on cache miss / full expiry.
    public async Task<IReadOnlyDictionary<string, IReadOnlyList<uint>>?> LoadAsync(
        CancellationToken ct = default)
    {
        try
        {
            if (!File.Exists(CachePath)) return null;
            var text = await File.ReadAllTextAsync(CachePath, ct);
            var raw  = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(text);
            if (raw == null) return null;

            var result = new Dictionary<string, IReadOnlyList<uint>>();
            foreach (var (cc, entry) in raw)
            {
                if (DateTime.UtcNow - entry.UpdatedUtc <= Ttl && entry.Asns != null)
                    result[cc] = entry.Asns;
            }
            return result.Count > 0 ? result : null;
        }
        catch { return null; }
    }

    // Merges updates into the existing cache file (non-updated countries are preserved).
    public async Task SaveAsync(
        IReadOnlyDictionary<string, IReadOnlyList<uint>> updates,
        CancellationToken ct = default)
    {
        try
        {
            Dictionary<string, CacheEntry>? existing = null;
            if (File.Exists(CachePath))
            {
                try
                {
                    var text = await File.ReadAllTextAsync(CachePath, ct);
                    existing = JsonSerializer.Deserialize<Dictionary<string, CacheEntry>>(text);
                }
                catch { }
            }

            var merged = existing ?? [];
            foreach (var (cc, asns) in updates)
                merged[cc] = new CacheEntry(DateTime.UtcNow, [.. asns]);

            // Write to a temporary file before renaming it to avoid corruption if the process stops.
            var tmp = CachePath + ".tmp";
            await File.WriteAllTextAsync(tmp, JsonSerializer.Serialize(merged), ct);
            File.Move(tmp, CachePath, overwrite: true);
        }
        catch { } // best-effort; next run will just re-fetch
    }
}
