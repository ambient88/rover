namespace SubnetSearch.Classification;

/// <summary>Запись курируемого ядра: asn → имя + типы ("vps"/"dedicated"/"cloud").</summary>
public readonly record struct CoreEntry(uint Asn, string Name, IReadOnlyList<string> Types);

/// <summary>
/// Генерация ядра server-providers: база из vpsh-тега с прополкой карьеров, поверх — ручной
/// оверлей (replace/remove/add). Разовый bootstrap-фильтр (в рантайме прополки нет).
/// </summary>
public static class ServerCoreBootstrap
{
    public const long ReachLimit = 1000;
    private static readonly HashSet<string> TransitRoles =
        new(StringComparer.OrdinalIgnoreCase) { "tier1_transit", "major_transit", "midsize_transit" };
    private static readonly string[] DefaultTypes = { "vps", "dedicated" };

    /// <summary>Провайдер остаётся в базе, если не исключён и не карьер (по role/reach).</summary>
    public static bool PassesPrune(AsnNetworkProfile? profile, bool excluded)
    {
        if (excluded) return false;
        if (profile is null) return true;                 // нет профиля → benefit of doubt
        var p = profile.Value;
        if (p.NetworkRole != null) return !TransitRoles.Contains(p.NetworkRole);
        return p.Reach < ReachLimit;                      // role=null → бэкап по reach
    }

    public static IReadOnlyList<CoreEntry> Build(
        IReadOnlyDictionary<uint, string> vpshNames,
        IReadOnlyDictionary<uint, AsnNetworkProfile> profiles,
        IReadOnlySet<uint> excluded,
        IReadOnlyList<CoreEntry> overlay)
    {
        var map = new Dictionary<uint, CoreEntry>();

        // База: vpsh ∩ прополка, тип по умолчанию.
        foreach (var (asn, rawName) in vpshNames)
        {
            AsnNetworkProfile? prof = profiles.TryGetValue(asn, out var p) ? p : null;
            if (!PassesPrune(prof, excluded.Contains(asn))) continue;
            map[asn] = new CoreEntry(asn, CleanName(rawName), DefaultTypes);
        }

        // Оверлей поверх базы (минуя прополку).
        foreach (var o in overlay)
        {
            if (o.Types.Count == 0) { map.Remove(o.Asn); continue; }  // удаление
            map[o.Asn] = o;                                           // замена/добавление
        }

        return map.Values.OrderBy(e => e.Asn).ToList();
    }

    private static string CleanName(string name) => name.Trim().Trim('"').Trim();
}
