using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// ASN exclusion lists loaded from asn-exclusions.json.
// Falls back to built-in defaults when the file is unavailable (first run, download failure).
public class AsnExclusions
{
    public IReadOnlySet<uint> NonHostingAsns      { get; }
    public IReadOnlySet<uint> KnownCdnAsns        { get; }
    public IReadOnlySet<uint> KnownAiProviderAsns { get; }

    private AsnExclusions(HashSet<uint> nonHosting, HashSet<uint> knownCdns, HashSet<uint> knownAi)
    {
        NonHostingAsns      = nonHosting;
        KnownCdnAsns        = knownCdns;
        KnownAiProviderAsns = knownAi;
    }

    // Built-in defaults — active on first run before the file is downloaded.
    public static readonly AsnExclusions Default = new(
        new HashSet<uint> { 714, 2906, 32934, 10310, 6507, 14340, 19679, 62955, 26415, 17685, 203724, 39832,
                            57976, 6939, 8220, 15830, 35280, 36692, 24429, 49544 },
        new HashSet<uint> { 13335, 20940, 54113, 22822, 60068, 139341, 12041 },
        new HashSet<uint> { 33425, 398090, 26356, 399507, 401405, 46082, 401182, 204415, 214438, 23112, 209045, 50489, 400494, 199524, 202422, 59245, 198020 }
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
            var knownAi    = new HashSet<uint>(doc.KnownAiProviders?.Select(e => e.Asn) ?? []);

            // Fall back only when ALL sections are missing from the file (null, not empty).
            // A valid file with only knownAiProviders populated must NOT fall back to Default.
            if (doc.NonHosting == null && doc.KnownCdns == null && doc.KnownAiProviders == null)
                return Default;
            return new AsnExclusions(nonHosting, knownCdns, knownAi);
        }
        catch (Exception ex) when (ex is IOException or JsonException or UnauthorizedAccessException or InvalidOperationException)
        {
            return Default;
        }
    }

    private static readonly JsonSerializerOptions _json = new() { PropertyNameCaseInsensitive = true };

    private record ExclusionsFile(
        [property: JsonPropertyName("nonHosting")]       AsnEntry[]? NonHosting,
        [property: JsonPropertyName("knownCdns")]        AsnEntry[]? KnownCdns,
        [property: JsonPropertyName("knownAiProviders")] AsnEntry[]? KnownAiProviders);

    private record AsnEntry(
        [property: JsonPropertyName("asn")]    uint    Asn,
        [property: JsonPropertyName("org")]    string? Org    = null,
        [property: JsonPropertyName("reason")] string? Reason = null);
}
