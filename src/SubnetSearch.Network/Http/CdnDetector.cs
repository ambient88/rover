namespace SubnetSearch.Network.Http;

internal static class CdnDetector
{
    private static readonly (string Header, string? Contains, string Provider)[] Rules =
    [
        ("CF-Ray",        null,          "Cloudflare"),
        ("Server",        "cloudflare",  "Cloudflare"),
        ("X-Amz-Cf-Id",  null,          "CloudFront"),
        ("X-Served-By",  "cache-",      "Fastly"),
        ("Via",           "varnish",     "Varnish"),
        ("X-Varnish",    null,           "Varnish"),
        ("Server",        "AkamaiGHost", "Akamai"),
        ("X-Sucuri-ID",  null,           "Sucuri WAF"),
        ("Server",        "ddos-guard",  "DDoS-Guard"),
        ("X-DDoS-Guard", null,           "DDoS-Guard"),
    ];

    public static string? Detect(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        var flat = headers.ToDictionary(
            h => h.Key,
            h => string.Join(", ", h.Value),
            StringComparer.OrdinalIgnoreCase);

        foreach (var (header, contains, provider) in Rules)
        {
            if (!flat.TryGetValue(header, out var value)) continue;
            if (contains is null || value.Contains(contains, StringComparison.OrdinalIgnoreCase))
                return provider;
        }
        return null;
    }

    public static string? ExtractServer(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        foreach (var h in headers)
            if (h.Key.Equals("Server", StringComparison.OrdinalIgnoreCase))
                return string.Join(", ", h.Value);
        return null;
    }

    public static string? ExtractXPoweredBy(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        foreach (var h in headers)
            if (h.Key.Equals("X-Powered-By", StringComparison.OrdinalIgnoreCase))
                return string.Join(", ", h.Value);
        return null;
    }
}
