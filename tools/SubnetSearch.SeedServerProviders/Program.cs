using System.Text.Json;
using SubnetSearch.Classification;

// Coverage checker for the server-providers allowlist (no hardcoded brand knowledge).
//
// The runtime long-tail gate drops every transit-role ASN that is not listed in the core
// (server-providers.json). A rentable provider with a transit networkRole therefore must be
// listed explicitly, or it silently disappears from the server filters. This tool reports
// transit-role vpsh-tagged ASNs that are NOT yet in the core, sorted by reach ascending
// (smaller networks first - the ones most likely to be a real host worth adding rather than
// a large carrier). The maintainer reviews the output and edits server-providers.json by hand.
//
// Usage: dotnet run --project tools/SubnetSearch.SeedServerProviders -- [dataDir]
//        (dataDir defaults to "./data" relative to the working directory)

var dataDir = args.Length > 0 ? args[0] : Path.Combine(Directory.GetCurrentDirectory(), "data");
dataDir = Path.GetFullPath(dataDir);

var transitRoles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
    { "tier1_transit", "major_transit", "midsize_transit" };

var profiles = await new AsnMetadataParser().LoadNetworkProfilesAsync(Path.Combine(dataDir, "as.json"));
var vpshNames = await BgpToolsTagLoader.LoadTagWithNamesAsync(
    Path.Combine(dataDir, BgpToolsTagLoader.FileName("vpsh")));

var core = ReadCoreAsns(Path.Combine(dataDir, "server-providers.json"));
core.UnionWith(ReadCoreAsns(Path.Combine(dataDir, "server-providers.local.json")));
var nonHosting = ReadNonHosting(Path.Combine(dataDir, "asn-exclusions.json"));

var missing = vpshNames
    .Where(kv => profiles.TryGetValue(kv.Key, out var pr)
                 && pr.NetworkRole != null && transitRoles.Contains(pr.NetworkRole)
                 && !core.Contains(kv.Key)
                 && !nonHosting.Contains(kv.Key))
    .Select(kv => (Asn: kv.Key, Name: kv.Value.Trim().Trim('"').Trim(),
                   Profile: profiles[kv.Key]))
    .OrderBy(x => x.Profile.Reach)
    .ToList();

Console.WriteLine($"transit-role vpsh ASNs not in core: {missing.Count} (sorted by reach asc)");
foreach (var m in missing)
    Console.WriteLine($"  AS{m.Asn,-8} reach={m.Profile.Reach,-7} {m.Profile.NetworkRole,-16} {m.Name}");
return;

static HashSet<uint> ReadCoreAsns(string path)
{
    var set = new HashSet<uint>();
    if (!File.Exists(path)) return set;
    using var doc = JsonDocument.Parse(File.ReadAllText(path));
    if (doc.RootElement.TryGetProperty("providers", out var arr) && arr.ValueKind == JsonValueKind.Array)
        foreach (var e in arr.EnumerateArray())
            if (e.TryGetProperty("asn", out var a) && a.TryGetUInt32(out var asn))
                set.Add(asn);
    return set;
}

static HashSet<uint> ReadNonHosting(string path)
{
    var set = new HashSet<uint>();
    if (!File.Exists(path)) return set;
    using var doc = JsonDocument.Parse(File.ReadAllText(path));
    if (doc.RootElement.TryGetProperty("nonHosting", out var arr) && arr.ValueKind == JsonValueKind.Array)
        foreach (var e in arr.EnumerateArray())
            if (e.TryGetProperty("asn", out var a) && a.TryGetUInt32(out var asn))
                set.Add(asn);
    return set;
}
