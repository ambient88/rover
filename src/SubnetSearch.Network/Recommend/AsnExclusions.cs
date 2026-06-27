using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// ASN exclusion lists loaded from asn-exclusions.json.
// Falls back to built-in defaults when the file is unavailable (first run, download failure).
public class AsnExclusions
{
    public IReadOnlySet<uint> NonHostingAsns { get; }
    public IReadOnlySet<uint> KnownCdnAsns   { get; }

    private AsnExclusions(HashSet<uint> nonHosting, HashSet<uint> knownCdns)
    {
        NonHostingAsns = nonHosting;
        KnownCdnAsns   = knownCdns;
    }

    // Built-in defaults — active on first run before the file is downloaded.
    public static readonly AsnExclusions Default = new(
        new HashSet<uint> { 714, 2906, 32934, 10310, 6507, 14340, 19679, 62955, 26415, 17685, 203724 },
        new HashSet<uint> { 13335, 20940, 54113, 22822, 60068, 139341, 12041 }
    );

    public static async Task<AsnExclusions> LoadAsync(string filePath)
    {
        if (!File.Exists(filePath)) return Default;
        try
        {
            var text = await File.ReadAllTextAsync(filePath);
            var doc  = JsonSerializer.Deserialize<ExclusionsFile>(text, _json);
            if (doc == null) return Default;

            var nonHosting = new HashSet<uint>(doc.NonHosting?.Select(e => e.Asn) ?? []);
            var knownCdns  = new HashSet<uint>(doc.KnownCdns?.Select(e => e.Asn)  ?? []);

            if (nonHosting.Count == 0 && knownCdns.Count == 0) return Default;
            return new AsnExclusions(nonHosting, knownCdns);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException)
        {
            return Default;
        }
    }

    private static readonly JsonSerializerOptions _json = new() { PropertyNameCaseInsensitive = true };

    private record ExclusionsFile(
        [property: JsonPropertyName("nonHosting")] AsnEntry[]? NonHosting,
        [property: JsonPropertyName("knownCdns")]  AsnEntry[]? KnownCdns);

    private record AsnEntry(
        [property: JsonPropertyName("asn")]    uint    Asn,
        [property: JsonPropertyName("org")]    string? Org    = null,
        [property: JsonPropertyName("reason")] string? Reason = null);
}
