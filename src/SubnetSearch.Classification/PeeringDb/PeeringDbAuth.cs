namespace SubnetSearch.Classification;

/// <summary>
/// Sanitizes a PeeringDB API key before it is added to a request header.
/// </summary>
public static class PeeringDbAuth
{
    /// <summary>
    /// Removes control separators that could alter an HTTP header.
    /// </summary>
    public static string? Sanitize(string? key)
    {
        if (string.IsNullOrWhiteSpace(key)) return null;
        var stripped = key.Replace("\r", "").Replace("\n", "").Replace("\0", "").Trim();
        return string.IsNullOrEmpty(stripped) ? null : stripped;
    }
}
