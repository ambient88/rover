namespace SubnetSearch.Classification;

// Loads ASN community tags from bgp.tools (https://bgp.tools/kb/api).
// File format: "AS44684,Mythic Beasts Ltd", one line per ASN.
// Files are downloaded by DownloadManager as bgptools-{tag}.csv (TTL 7 days).
public static class BgpToolsTagLoader
{
    // Tags used when determining the ASN type (see AsnTypeResolver).
    public static readonly string[] Tags =
    [
        "vpsh",   // VPS hosting (positive signal)
        "cdn",    // CDN
        "dsl",    // residential ISP
        "mobile", // mobile carriers
        "satnet", // satellite networks
        "gov",    // government
        "uni",    // universities / education
        "perso",  // personal ASNs
        "corp",   // corporate networks
        "biznet", // B2B networks
        "event",  // temporary (conferences)
    ];

    public static string FileName(string tag) => $"bgptools-{tag}.csv";

    // Returns the ASNs for each tag. A missing file produces an empty set.
    // (the resolver falls back to as.json categories).
    public static async Task<IReadOnlyDictionary<string, HashSet<uint>>> LoadAllAsync(string dataDir)
    {
        var loads = Tags
            .Select(tag => LoadTagAsync(Path.Combine(dataDir, FileName(tag))))
            .ToArray();
        var loaded = await Task.WhenAll(loads);
        var result = new Dictionary<string, HashSet<uint>>(Tags.Length);
        for (int i = 0; i < Tags.Length; i++)
            result[Tags[i]] = loaded[i];
        return result;
    }

    public static async Task<HashSet<uint>> LoadTagAsync(string filePath)
    {
        var set = new HashSet<uint>();
        if (!File.Exists(filePath)) return set;
        try
        {
            foreach (var line in await File.ReadAllLinesAsync(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var comma = line.IndexOf(',');
                var token = (comma > 0 ? line[..comma] : line).Trim();
                if (token.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                    token = token[2..];
                if (uint.TryParse(token, out var asn))
                    set.Add(asn);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A corrupt or unreadable file produces an empty set so the resolver can continue.
        }
        return set;
    }

    // Parses ASN names from a tag file such as vpsh.csv for local supplements.
    // candidates are built directly from the bgp.tools name, without a per-ASN PeeringDB lookup.
    // Line format: "AS215439,PLAY2GO LTD", ASN up to the first comma, name is the rest
    // (commas inside the name are kept, for example "AS1,Foo, Inc."). Lines without a comma or
    // with an empty name are skipped; a supplement candidate must have a name.
    // Duplicate ASNs: the first entry wins (TryAdd).
    public static async Task<IReadOnlyDictionary<uint, string>> LoadTagWithNamesAsync(string filePath)
    {
        var map = new Dictionary<uint, string>();
        if (!File.Exists(filePath)) return map;
        try
        {
            foreach (var line in await File.ReadAllLinesAsync(filePath))
            {
                if (string.IsNullOrWhiteSpace(line)) continue;
                var comma = line.IndexOf(',');
                if (comma < 0) continue;

                var token = line[..comma].Trim();
                if (token.StartsWith("AS", StringComparison.OrdinalIgnoreCase))
                    token = token[2..];
                if (!uint.TryParse(token, out var asn)) continue;

                var name = line[(comma + 1)..].Trim();
                if (name.Length == 0) continue;

                map.TryAdd(asn, name);
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
        {
            // A corrupt or unreadable file produces an empty dictionary and skips the supplement.
        }
        return map;
    }
}
