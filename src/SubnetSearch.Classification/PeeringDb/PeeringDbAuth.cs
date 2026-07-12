namespace SubnetSearch.Classification;

/// <summary>
/// Single source of truth for PeeringDB Api-Key sanitization. Centralizing this
/// removes the duplicated strip logic (WR-01) that used to live in the resolver,
/// the connectivity probe and — after CR-01 — ProviderFinder, where tightening the
/// filter in one copy would silently drift from the others.
/// </summary>
public static class PeeringDbAuth
{
    /// <summary>
    /// Strips CR/LF and null bytes then trims, guarding against header injection before
    /// the value ever reaches AuthenticationHeaderValue. Returns null when the input is
    /// null, whitespace, or empty AFTER stripping (WR-02) — a "\0"-only key must normalize
    /// to null so it is never attached as an empty "Api-Key" credential.
    /// </summary>
    public static string? Sanitize(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        var stripped = key.Replace("\r", "").Replace("\n", "").Replace("\0", "").Trim();
        return string.IsNullOrEmpty(stripped) ? null : stripped;
    }
}
