namespace SubnetSearch.Classification;

/// <summary>A curated core record with an ASN, name, and server types.</summary>
public readonly record struct CoreEntry(uint Asn, string Name, IReadOnlyList<string> Types);

/// <summary>
/// Builds the server-providers core: a base from the vpsh tag with carrier weeding, then a manual
/// overlay (replace/remove/add). A one-time bootstrap filter (no weeding at runtime).
/// </summary>
public static class ServerCoreBootstrap
{
    public const long ReachLimit = 1000;
    private static readonly HashSet<string> TransitRoles =
        new(StringComparer.OrdinalIgnoreCase) { "tier1_transit", "major_transit", "midsize_transit" };
    private static readonly string[] DefaultTypes = { "vps", "dedicated" };

    /// <summary>A provider stays in the base set if it is not excluded and not a carrier (by role/reach).</summary>
    public static bool PassesPrune(AsnNetworkProfile? profile, bool excluded)
    {
        if (excluded) return false;
        if (profile is null) return true;                 // Keep entries without a profile.
        var p = profile.Value;
        if (p.NetworkRole != null) return !TransitRoles.Contains(p.NetworkRole);
        return p.Reach < ReachLimit;                      // Use reach when the role is missing.
    }

    public static IReadOnlyList<CoreEntry> Build(
        IReadOnlyDictionary<uint, string> vpshNames,
        IReadOnlyDictionary<uint, AsnNetworkProfile> profiles,
        IReadOnlySet<uint> excluded,
        IReadOnlyList<CoreEntry> overlay)
    {
        var map = new Dictionary<uint, CoreEntry>();

        // Base set: vpsh intersected with weeding, default type.
        foreach (var (asn, rawName) in vpshNames)
        {
            AsnNetworkProfile? prof = profiles.TryGetValue(asn, out var p) ? p : null;
            if (!PassesPrune(prof, excluded.Contains(asn))) continue;
            map[asn] = new CoreEntry(asn, CleanName(rawName), DefaultTypes);
        }

        // Overlay on top of the base set (bypassing weeding).
        foreach (var o in overlay)
        {
            if (o.Types.Count == 0) { map.Remove(o.Asn); continue; }  // removal
            map[o.Asn] = o;                                           // replace or add
        }

        return map.Values.OrderBy(e => e.Asn).ToList();
    }

    private static string CleanName(string name) => name.Trim().Trim('"').Trim();
}
