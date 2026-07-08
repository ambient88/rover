using System.Text.Json;
using System.Text.Json.Serialization;

namespace SubnetSearch.Network.Recommend;

// Курируемое ядро арендуемых провайдеров (server-providers.json) + локальный override.
// ЕДИНСТВЕННЫЙ источник истины для --type vps/dedicated/cloud/server (pure allowlist,
// спека 2026-07-08, ревизия: авто-гейт по vpsh-тегу убран — показываем только проверенные
// провайдеры, у которых точно можно арендовать сервер; ничего не проходит автоматически).
public class ServerProviders
{
    // asn -> набор типов ("vps"/"dedicated"/"cloud"); пустой набор = запись удалена.
    private readonly Dictionary<uint, HashSet<string>> _core;

    private ServerProviders(Dictionary<uint, HashSet<string>> core) => _core = core;

    public static async Task<ServerProviders> LoadAsync(string baseFilePath, string localFilePath)
    {
        var core = new Dictionary<uint, HashSet<string>>();
        MergeFile(core, await ReadFileAsync(baseFilePath));
        MergeFile(core, await ReadFileAsync(localFilePath)); // local поверх base
        // Пустой types (local с []) удаляет запись.
        foreach (var asn in core.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList())
            core.Remove(asn);
        return new ServerProviders(core);
    }

    private static void MergeFile(Dictionary<uint, HashSet<string>> core, ProvidersFile? file)
    {
        if (file?.Providers == null) return;
        foreach (var p in file.Providers)
            // Запись целиком переопределяет одноимённую (в т.ч. пустым types — маркер удаления).
            core[p.Asn] = new HashSet<string>(p.Types ?? [], StringComparer.OrdinalIgnoreCase);
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

    // Итоговое членство в server-фильтре: только курируемое ядро.
    // typeFilter == "server"/null → любой тип ядра; иначе — совпадение по типу.
    public bool IsAllowed(uint asn, string? typeFilter)
        => typeFilter is null or "server" ? IsInCoreAny(asn) : IsInCore(asn, typeFilter);

    // ASN ядра для заданного типа (для формирования кандидатов global-server поиска).
    public IEnumerable<uint> CoreAsnsForType(string? typeFilter)
        => typeFilter is null or "server"
            ? _core.Where(kv => kv.Value.Count > 0).Select(kv => kv.Key)
            : _core.Where(kv => kv.Value.Contains(typeFilter!)).Select(kv => kv.Key);

    private static readonly JsonSerializerOptions _json = new() { PropertyNameCaseInsensitive = true };

    private record ProvidersFile(
        [property: JsonPropertyName("providers")] ProviderEntry[]? Providers);

    private record ProviderEntry(
        [property: JsonPropertyName("asn")]   uint     Asn,
        [property: JsonPropertyName("name")]  string?  Name,
        [property: JsonPropertyName("types")] string[]? Types);
}
