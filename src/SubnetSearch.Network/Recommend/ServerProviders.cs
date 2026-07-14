using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// Loads the curated rentable provider core and an optional local override.
// The vps, dedicated, cloud, and server filters only accept verified core members.
public class ServerProviders
{
    // Each ASN maps to its server types. An empty set removes the entry.
    private readonly Dictionary<uint, HashSet<string>> _core;
    private readonly Dictionary<uint, string> _names;

    private ServerProviders(Dictionary<uint, HashSet<string>> core, Dictionary<uint, string> names)
    {
        _core = core;
        _names = names;
    }

    public static async Task<ServerProviders> LoadAsync(string baseFilePath, string localFilePath)
    {
        var core = new Dictionary<uint, HashSet<string>>();
        var names = new Dictionary<uint, string>();
        MergeFile(core, names, await ReadFileAsync(baseFilePath));
        MergeFile(core, names, await ReadFileAsync(localFilePath)); // local on top of base
        // An empty types set (local with []) removes the entry.
        foreach (var asn in core.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList())
            core.Remove(asn);
        return new ServerProviders(core, names);
    }

    private static void MergeFile(Dictionary<uint, HashSet<string>> core, Dictionary<uint, string> names, ProvidersFile? file)
    {
        if (file?.Providers == null) return;
        foreach (var p in file.Providers)
        {
            // A record fully overrides one with the same name (including an empty types set as a removal marker).
            core[p.Asn] = new HashSet<string>(p.Types ?? [], StringComparer.OrdinalIgnoreCase);
            if (!string.IsNullOrWhiteSpace(p.Name)) names[p.Asn] = p.Name!;
        }
    }

    private static async Task<ProvidersFile?> ReadFileAsync(string path)
    {
        if (!File.Exists(path)) return null;
        try { return JsonSerializer.Deserialize<ProvidersFile>(await File.ReadAllTextAsync(path), _json); }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        { return null; }
    }

    public bool IsInCore(uint asn, string type)
        => _core.TryGetValue(asn, out var types) && types.Contains(type);

    public bool IsInCoreAny(uint asn)
        => _core.TryGetValue(asn, out var types) && types.Count > 0;

    // Final membership in the server filter: the curated core only.
    // Server or a missing filter accepts any core type. Other filters match one type.
    // Case does not matter (typeFilter may arrive raw).
    public bool IsAllowed(uint asn, string? typeFilter)
    {
        var t = Normalize(typeFilter);
        return t is null or "server" ? IsInCoreAny(asn) : IsInCore(asn, t);
    }

    // Core ASNs for a given type (used to form candidates for the global-server search).
    public IEnumerable<uint> CoreAsnsForType(string? typeFilter)
    {
        var t = Normalize(typeFilter);
        return t is null or "server"
            ? _core.Where(kv => kv.Value.Count > 0).Select(kv => kv.Key)
            : _core.Where(kv => kv.Value.Contains(t)).Select(kv => kv.Key);
    }

    // Normalize case and fold the documented hosting alias into server.
    // the core-first / from-intersect-core paths (candidates from CoreAsnsForType) do not come back empty on --type hosting.
    private static string? Normalize(string? typeFilter)
    {
        var t = typeFilter?.ToLowerInvariant();
        return t == "hosting" ? "server" : t;
    }

    // (asn, name) from the core for a given type, used to build named candidates
    // (the core name does not depend on PeeringDB/RIPE resolution).
    public IEnumerable<(uint Asn, string Name)> CoreEntriesForType(string? typeFilter)
        => CoreAsnsForType(typeFilter)
            .Select(a => (a, _names.TryGetValue(a, out var n) ? n : $"AS{a}"));

    private static readonly JsonSerializerOptions _json = new() { PropertyNameCaseInsensitive = true };

    private record ProvidersFile(
        [property: JsonPropertyName("providers")] ProviderEntry[]? Providers);

    private record ProviderEntry(
        [property: JsonPropertyName("asn")]   uint     Asn,
        [property: JsonPropertyName("name")]  string?  Name,
        [property: JsonPropertyName("types")] string[]? Types);
}
