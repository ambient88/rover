using System.Text.Json;
using System.Text.Json.Serialization;
using SubnetSearch.Classification;

// Builds the curated server-providers.json core from local data without network access.
// The base set comes from the bgp.tools vpsh tag after carrier, CDN, and AI filtering.
// Base entries use the vps and dedicated types by default.
// data/server-providers.curated.json supplies manual cloud types, corrections, additions, and removals.
// The generated data/server-providers.json file replaces the previous output.
//
// Usage: dotnet run --project tools/SubnetSearch.SeedServerProviders -- [dataDir]

var dataDir = args.Length > 0 ? args[0] : Path.Combine(Directory.GetCurrentDirectory(), "data");
dataDir = Path.GetFullPath(dataDir);

var vpshNames = await BgpToolsTagLoader.LoadTagWithNamesAsync(
    Path.Combine(dataDir, BgpToolsTagLoader.FileName("vpsh")));
var profiles  = await new AsnMetadataParser().LoadNetworkProfilesAsync(Path.Combine(dataDir, "as.json"));

var excluded = new HashSet<uint>();
foreach (var section in new[] { "nonHosting", "knownCdns", "knownAiProviders" })
    excluded.UnionWith(ReadAsnSection(Path.Combine(dataDir, "asn-exclusions.json"), section));

var overlay = ReadOverlay(Path.Combine(dataDir, "server-providers.curated.json"));

var core = ServerCoreBootstrap.Build(vpshNames, profiles, excluded, overlay);

var outPath = Path.Combine(dataDir, "server-providers.json");
var json = JsonSerializer.Serialize(
    new ProvidersFile(core.Select(e => new ProviderEntry(e.Asn, e.Name, e.Types.ToArray())).ToArray()),
    new JsonSerializerOptions { WriteIndented = true, Encoder = System.Text.Encodings.Web.JavaScriptEncoder.UnsafeRelaxedJsonEscaping });
await File.WriteAllTextAsync(outPath, json + "\n");

int vpshCount = vpshNames.Count;
Console.WriteLine($"vpsh {vpshCount} -> after prune+overlay: {core.Count} entries " +
                  $"(overlay: {overlay.Count(o => o.Types.Count > 0)} replace/add, " +
                  $"{overlay.Count(o => o.Types.Count == 0)} remove)");
Console.WriteLine($"wrote {outPath}");
return;

static IEnumerable<uint> ReadAsnSection(string path, string section)
{
    if (!File.Exists(path)) yield break;
    using var doc = JsonDocument.Parse(File.ReadAllText(path));
    if (doc.RootElement.TryGetProperty(section, out var arr) && arr.ValueKind == JsonValueKind.Array)
        foreach (var e in arr.EnumerateArray())
            if (e.TryGetProperty("asn", out var a) && a.TryGetUInt32(out var asn))
                yield return asn;
}

static IReadOnlyList<CoreEntry> ReadOverlay(string path)
{
    if (!File.Exists(path)) return Array.Empty<CoreEntry>();
    var doc = JsonSerializer.Deserialize<ProvidersFile>(File.ReadAllText(path),
        new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
    if (doc?.Providers == null) return Array.Empty<CoreEntry>();
    return doc.Providers
        .Select(p => new CoreEntry(p.Asn, p.Name ?? "", p.Types ?? Array.Empty<string>()))
        .ToList();
}

record ProvidersFile([property: JsonPropertyName("providers")] ProviderEntry[] Providers);
record ProviderEntry(
    [property: JsonPropertyName("asn")]   uint      Asn,
    [property: JsonPropertyName("name")]  string?   Name,
    [property: JsonPropertyName("types")] string[]? Types);
