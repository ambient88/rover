using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Http;

public static class CloudflareProductDetector
{
    // Known Cloudflare IP ranges and their associated products.
    // Ranges marked "Ambiguous" require HTTP probing to distinguish WARP from Tunnel.
    private static readonly (uint Start, uint End, string Product)[] IpRanges =
    [
        // WARP / Tunnel — same ranges used for both; HTTP response disambiguates.
        Parse("188.114.96.0/22",  "Ambiguous"),
        Parse("185.235.81.0/24",  "Ambiguous"),

        // Tunnel-only ranges (no WARP known to use these).
        Parse("198.41.200.0/24",  "Cloudflare Tunnel"),
        Parse("198.41.201.0/24",  "Cloudflare Tunnel"),

        // Workers / Pages — serverless and static site platform.
        Parse("104.18.0.0/16",    "Cloudflare Workers/Pages"),
        Parse("104.19.0.0/16",    "Cloudflare Workers/Pages"),
    ];

    // Detect specific product from response headers.
    public static string? DetectFromHeaders(
        IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        var flat = headers.ToDictionary(
            h => h.Key,
            h => string.Join(", ", h.Value),
            StringComparer.OrdinalIgnoreCase);

        if (flat.ContainsKey("CF-Worker"))
            return "Cloudflare Workers";

        if (flat.TryGetValue("Server", out var srv)
            && srv.Contains("cloudflare", StringComparison.OrdinalIgnoreCase)
            && flat.ContainsKey("NEL") && flat.ContainsKey("Report-To"))
            return "Cloudflare CDN";

        return null;
    }

    // Returns the raw product label from IP range (may be "Ambiguous").
    public static string? DetectFromIp(string ipAddress)
    {
        if (!IpConverter.TryIpToUint(ipAddress, out var ipInt)) return null;
        foreach (var (start, end, product) in IpRanges)
            if (ipInt >= start && ipInt <= end)
                return product;
        return null;
    }

    // Resolves the final product label using all available signals.
    //
    // Priority: header signals > UDP 2408 probe > HTTP response > IP range
    //
    //   udp2408Closed = true  → port 2408 UDP unreachable → NOT a WARP endpoint
    //   udp2408Closed = false → no ICMP unreachable       → likely WARP endpoint
    //   httpResponded = true  → TCP 443/80 serving content → Tunnel
    //   httpResponded = false → no HTTP                    → fallback to UDP signal
    public static string? Resolve(
        string? detectedCdnProvider,
        string ipAddress,
        IEnumerable<KeyValuePair<string, IEnumerable<string>>>? headers,
        bool? httpResponded = null,
        bool? udp2408Closed = null)
    {
        if (detectedCdnProvider != "Cloudflare") return null;

        if (headers != null)
        {
            var fromHeaders = DetectFromHeaders(headers);
            if (fromHeaders != null) return fromHeaders;
        }

        var fromIp = DetectFromIp(ipAddress);

        if (fromIp == "Ambiguous")
        {
            // UDP 2408 closed → definitely not WARP; combine with HTTP to confirm Tunnel.
            if (udp2408Closed == true)
                return httpResponded == true ? "Cloudflare Tunnel" : "Cloudflare CDN";

            // UDP 2408 open (no ICMP) → WARP endpoint, unless HTTP also responds.
            if (udp2408Closed == false)
            {
                if (httpResponded == true)
                    return "Cloudflare Tunnel"; // Both HTTP and UDP 2408 open → Tunnel with WARP co-located
                return "Cloudflare WARP";
            }

            // UDP unknown — fall back to HTTP signal only.
            return httpResponded switch
            {
                true  => "Cloudflare Tunnel",
                false => "Cloudflare WARP",
                null  => "Cloudflare Tunnel/WARP",
            };
        }

        return fromIp ?? "Cloudflare CDN";
    }

    private static (uint Start, uint End, string Product) Parse(string cidr, string product)
    {
        if (!IpConverter.TryParseCidr(cidr, out var start, out var end))
            throw new InvalidOperationException($"Invalid CIDR in CloudflareProductDetector: {cidr}");
        return (start, end, product);
    }
}
