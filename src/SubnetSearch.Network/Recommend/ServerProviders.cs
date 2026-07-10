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
        MergeFile(core, names, await ReadFileAsync(localFilePath)); // local поверх base
        // Пустой types (local с []) удаляет запись.
        foreach (var asn in core.Where(kv => kv.Value.Count == 0).Select(kv => kv.Key).ToList())
            core.Remove(asn);
        return new ServerProviders(core, names);
    }

    private static void MergeFile(Dictionary<uint, HashSet<string>> core, Dictionary<uint, string> names, ProvidersFile? file)
    {
        if (file?.Providers == null) return;
        foreach (var p in file.Providers)
        {
            // Запись целиком переопределяет одноимённую (в т.ч. пустым types — маркер удаления).
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

    // Итоговое членство в server-фильтре: только курируемое ядро.
    // typeFilter == "server"/null → любой тип ядра; иначе — совпадение по типу.
    // Регистр не важен (typeFilter может прийти сырым).
    public bool IsAllowed(uint asn, string? typeFilter)
    {
        var t = Normalize(typeFilter);
        return t is null or "server" ? IsInCoreAny(asn) : IsInCore(asn, t);
    }

    // ASN ядра для заданного типа (для формирования кандидатов global-server поиска).
    public IEnumerable<uint> CoreAsnsForType(string? typeFilter)
    {
        var t = Normalize(typeFilter);
        return t is null or "server"
            ? _core.Where(kv => kv.Value.Count > 0).Select(kv => kv.Key)
            : _core.Where(kv => kv.Value.Contains(t)).Select(kv => kv.Key);
    }

    // Нижний регистр + сворачивание документированного алиаса hosting → server, чтобы
    // core-first/from∩core пути (берут кандидатов из CoreAsnsForType) не давали пусто на --type hosting.
    private static string? Normalize(string? typeFilter)
    {
        var t = typeFilter?.ToLowerInvariant();
        return t == "hosting" ? "server" : t;
    }

    // (asn, имя) ядра для заданного типа — для построения именованных кандидатов
    // (имя из ядра не зависит от резолва PeeringDB/RIPE).
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
