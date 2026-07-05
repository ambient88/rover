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
    // Curated bare-metal / dedicated-only providers (no VPS product): hidden from --type vps,
    // visible under --type dedicated and --type server. Editable without recompilation (TAX-01).
    public IReadOnlySet<uint> DedicatedOnlyAsns   { get; }
    // Curated hyperscaler cloud providers (AWS, Azure, GCP, ...): hidden from --type vps,
    // visible under --type cloud and --type server. Editable without recompilation (D-05).
    public IReadOnlySet<uint> CloudOnlyAsns       { get; }

    private AsnExclusions(HashSet<uint> nonHosting, HashSet<uint> knownCdns, HashSet<uint> knownAi, HashSet<uint> dedicatedOnly, HashSet<uint> cloudOnly)
    {
        NonHostingAsns      = nonHosting;
        KnownCdnAsns        = knownCdns;
        KnownAiProviderAsns = knownAi;
        DedicatedOnlyAsns   = dedicatedOnly;
        CloudOnlyAsns       = cloudOnly;
    }

    // Built-in defaults — active on first run before the file is downloaded.
    public static readonly AsnExclusions Default = new(
        new HashSet<uint> { 714, 2906, 32934, 10310, 6507, 14340, 19679, 62955, 26415, 17685, 203724, 39832,
                            57976, 6939, 8220, 15830, 35280, 36692, 24429, 30103, 9009 },
        new HashSet<uint> { 13335, 20940, 54113, 22822, 60068, 139341, 12041 },
        new HashSet<uint> { 33425, 398090, 26356, 399507, 401405, 46082, 401182, 204415, 214438, 23112, 209045, 50489, 400494, 199524, 202422, 59245, 198020 },
        new HashSet<uint> { 49544 },
        new HashSet<uint> { 16509, 14618, 8075, 15169, 396982, 31898, 36351, 45102, 132203, 45090, 136907, 55990, 37963 }
    );

    public static async Task<AsnExclusions> LoadAsync(string filePath)
    {
        if (!File.Exists(filePath)) return Default;
        try
        {
            var text = await File.ReadAllTextAsync(filePath);
            var doc  = JsonSerializer.Deserialize<ExclusionsFile>(text, _json);
            if (doc == null) return Default;

            var nonHosting    = new HashSet<uint>(doc.NonHosting?.Select(e => e.Asn) ?? []);
            var knownCdns     = new HashSet<uint>(doc.KnownCdns?.Select(e => e.Asn)  ?? []);
            var knownAi       = new HashSet<uint>(doc.KnownAiProviders?.Select(e => e.Asn) ?? []);
            var dedicatedOnly = new HashSet<uint>(doc.DedicatedOnly?.Select(e => e.Asn) ?? []);
            var cloudOnly     = new HashSet<uint>(doc.CloudOnly?.Select(e => e.Asn) ?? []);

            // Fall back only when ALL sections are missing from the file (null, not empty).
            // A valid file with only dedicatedOnly/cloudOnly populated must NOT fall back to Default.
            if (doc.NonHosting == null && doc.KnownCdns == null && doc.KnownAiProviders == null &&
                doc.DedicatedOnly == null && doc.CloudOnly == null)
                return Default;
            return new AsnExclusions(nonHosting, knownCdns, knownAi, dedicatedOnly, cloudOnly);
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
        [property: JsonPropertyName("knownAiProviders")] AsnEntry[]? KnownAiProviders,
        [property: JsonPropertyName("dedicatedOnly")]    AsnEntry[]? DedicatedOnly,
        [property: JsonPropertyName("cloudOnly")]        AsnEntry[]? CloudOnly);

    private record AsnEntry(
        [property: JsonPropertyName("asn")]    uint    Asn,
        [property: JsonPropertyName("org")]    string? Org    = null,
        [property: JsonPropertyName("reason")] string? Reason = null);
}
