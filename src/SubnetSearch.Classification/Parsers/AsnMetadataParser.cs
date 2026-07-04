using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Classification;

public class AsnMetadataParser
{
    /// <summary>
    /// Reads as.json once and returns all three data structures.
    /// </summary>
    public async Task<(HashSet<uint> HostingAsns, Dictionary<uint, string> ByAsn, Dictionary<string, string> ByOrg)> LoadAllAsync(string jsonFilePath)
    {
        var entries = await LoadAllEntriesAsync(jsonFilePath);

        var hostingAsns = new HashSet<uint>();
        var byAsn = new Dictionary<uint, string>();
        var byOrg = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (entry.Metadata?.Category == "hosting")
                hostingAsns.Add(entry.Asn);

            if (!string.IsNullOrWhiteSpace(entry.Website))
            {
                if (!byAsn.ContainsKey(entry.Asn))
                    byAsn[entry.Asn] = entry.Website;

                if (!string.IsNullOrWhiteSpace(entry.Organization) && !byOrg.ContainsKey(entry.Organization))
                    byOrg[entry.Organization] = entry.Website;
            }
        }

        return (hostingAsns, byAsn, byOrg);
    }

    /// <summary>
    /// Возвращает полную карту asn → категория (hosting/isp/business/education_research/
    /// government_admin) из as.json. Записи без категории пропускаются.
    /// Используется AsnTypeResolver'ом как локальная замена ASN-типов ipapi.is.
    /// </summary>
    public async Task<Dictionary<uint, string>> LoadCategoriesAsync(string jsonFilePath)
    {
        var entries = await LoadAllEntriesAsync(jsonFilePath);
        var categories = new Dictionary<uint, string>(entries.Count);
        foreach (var entry in entries)
        {
            var cat = entry.Metadata?.Category;
            if (!string.IsNullOrEmpty(cat))
                categories.TryAdd(entry.Asn, cat);
        }
        return categories;
    }

    private async Task<List<AsMetadataEntry>> LoadAllEntriesAsync(string jsonFilePath)
    {
        if (!File.Exists(jsonFilePath))
            return new List<AsMetadataEntry>();

        var json = await File.ReadAllTextAsync(jsonFilePath);
        return JsonSerializer.Deserialize<List<AsMetadataEntry>>(json) ?? new List<AsMetadataEntry>();
    }

    private record AsMetadataEntry(
        [property: JsonPropertyName("asn")]          uint        Asn,
        [property: JsonPropertyName("website")]      string?     Website,
        [property: JsonPropertyName("organization")] string?     Organization,
        [property: JsonPropertyName("metadata")]     AsMetadata? Metadata
    );

    private record AsMetadata(
        [property: JsonPropertyName("category")] string? Category
    );
}