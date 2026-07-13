using System.Text.Json;
using System.Text.Json.Serialization;

using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Classification;

/// <summary>Профиль сети из as.json для gate long-tail: транзитная роль + охват (reach).</summary>
public readonly record struct AsnNetworkProfile(string? NetworkRole, long Reach);

public class AsnMetadataParser
{
    private const int CacheMagic = 0x41534D44;
    private const int CacheVersion = 1;
    private readonly string? _cacheDirectory;

    public AsnMetadataParser(string? cacheDirectory = null)
    {
        _cacheDirectory = cacheDirectory;
    }

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

    /// <summary>
    /// Карта asn → (networkRole, reach) из as.json — питает локальный gate long-tail
    /// (транзитные роли и большой reach = карьер, не арендуемый провайдер). reach=0 при
    /// отсутствии stats.
    /// </summary>
    public async Task<Dictionary<uint, AsnNetworkProfile>> LoadNetworkProfilesAsync(string jsonFilePath)
    {
        var entries = await LoadAllEntriesAsync(jsonFilePath);
        var map = new Dictionary<uint, AsnNetworkProfile>(entries.Count);
        foreach (var entry in entries)
        {
            var role  = entry.Metadata?.NetworkRole;
            var reach = entry.Stats?.Connectivity?.Reach ?? 0;
            map[entry.Asn] = new AsnNetworkProfile(role, reach);
        }
        return map;
    }

    private Task<List<AsMetadataEntry>> LoadAllEntriesAsync(string jsonFilePath)
    {
        if (!File.Exists(jsonFilePath))
            return Task.FromResult(new List<AsMetadataEntry>());

        return Task.Run(() => LoadEntries(jsonFilePath));
    }

    private List<AsMetadataEntry> LoadEntries(string jsonFilePath)
    {
        var source = new FileInfo(jsonFilePath);
        string cachePath = GetCachePath(source);
        if (TryReadCache(cachePath, source, out var cached))
            return cached;

        using var stream = File.OpenRead(jsonFilePath);
        var entries = JsonSerializer.Deserialize<List<AsMetadataEntry>>(stream) ?? [];
        TryWriteCache(cachePath, source, entries);
        return entries;
    }

    private string GetCachePath(FileInfo source)
    {
        string directory = _cacheDirectory ?? DerivedCachePath.ForDataDirectory(
            source.DirectoryName ?? Directory.GetCurrentDirectory(),
            "classification");
        return Path.Combine(directory, "as-metadata-v1.bin");
    }

    private static bool TryReadCache(
        string cachePath,
        FileInfo source,
        out List<AsMetadataEntry> entries)
    {
        entries = [];
        try
        {
            if (!File.Exists(cachePath)) return false;
            using var reader = new BinaryReader(File.OpenRead(cachePath));
            if (reader.ReadInt32() != CacheMagic ||
                reader.ReadInt32() != CacheVersion ||
                reader.ReadInt64() != source.Length ||
                reader.ReadInt64() != source.LastWriteTimeUtc.Ticks)
                return false;

            int count = reader.ReadInt32();
            if (count < 0 || count > 2_000_000) return false;
            entries = new List<AsMetadataEntry>(count);
            for (int i = 0; i < count; i++)
            {
                uint asn = reader.ReadUInt32();
                string? website = ReadNullableString(reader);
                string? organization = ReadNullableString(reader);
                string? category = ReadNullableString(reader);
                string? networkRole = ReadNullableString(reader);
                long reach = reader.ReadInt64();
                entries.Add(new AsMetadataEntry(
                    asn,
                    website,
                    organization,
                    category == null && networkRole == null
                        ? null
                        : new AsMetadata(category, networkRole),
                    new AsStats(new AsConnectivity(reach))));
            }
            return reader.BaseStream.Position == reader.BaseStream.Length;
        }
        catch
        {
            entries = [];
            return false;
        }
    }

    private static void TryWriteCache(
        string cachePath,
        FileInfo source,
        List<AsMetadataEntry> entries)
    {
        string? tempPath = null;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(cachePath)!);
            tempPath = cachePath + "." + Guid.NewGuid().ToString("N") + ".tmp";
            using (var writer = new BinaryWriter(File.Create(tempPath)))
            {
                writer.Write(CacheMagic);
                writer.Write(CacheVersion);
                writer.Write(source.Length);
                writer.Write(source.LastWriteTimeUtc.Ticks);
                writer.Write(entries.Count);
                foreach (var entry in entries)
                {
                    writer.Write(entry.Asn);
                    WriteNullableString(writer, entry.Website);
                    WriteNullableString(writer, entry.Organization);
                    WriteNullableString(writer, entry.Metadata?.Category);
                    WriteNullableString(writer, entry.Metadata?.NetworkRole);
                    writer.Write(entry.Stats?.Connectivity?.Reach ?? 0);
                }
            }
            File.Move(tempPath, cachePath, true);
            tempPath = null;
        }
        catch
        {
        }
        finally
        {
            if (tempPath != null)
            {
                try { File.Delete(tempPath); } catch { }
            }
        }
    }

    private static string? ReadNullableString(BinaryReader reader) =>
        reader.ReadBoolean() ? reader.ReadString() : null;

    private static void WriteNullableString(BinaryWriter writer, string? value)
    {
        writer.Write(value != null);
        if (value != null) writer.Write(value);
    }

    private record AsMetadataEntry(
        [property: JsonPropertyName("asn")]          uint        Asn,
        [property: JsonPropertyName("website")]      string?     Website,
        [property: JsonPropertyName("organization")] string?     Organization,
        [property: JsonPropertyName("metadata")]     AsMetadata? Metadata,
        [property: JsonPropertyName("stats")]        AsStats?    Stats
    );

    private record AsMetadata(
        [property: JsonPropertyName("category")]    string? Category,
        [property: JsonPropertyName("networkRole")] string? NetworkRole
    );

    private record AsStats(
        [property: JsonPropertyName("connectivity")] AsConnectivity? Connectivity
    );

    private record AsConnectivity(
        [property: JsonPropertyName("reach")] long Reach
    );
}
