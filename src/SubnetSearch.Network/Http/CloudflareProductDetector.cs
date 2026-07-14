using SubnetSearch.Core.Utilities;

namespace SubnetSearch.Network.Http;

public static class CloudflareProductDetector
{
    // Known Cloudflare IP ranges and their associated products.
    // Ranges marked "Ambiguous" require HTTP probing to distinguish WARP from Tunnel.
    private static readonly (uint Start, uint End, string Product)[] IpRanges =
    [
        // WARP and Tunnel share ranges, so the HTTP response distinguishes them.
        Parse("188.114.96.0/22",  "Ambiguous"),
        Parse("185.235.81.0/24",  "Ambiguous"),

        // Tunnel-only ranges (no WARP known to use these).
        Parse("198.41.200.0/24",  "Cloudflare Tunnel"),
        Parse("198.41.201.0/24",  "Cloudflare Tunnel"),

        // Workers and Pages provide serverless and static site hosting.
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
    // A closed UDP port 2408 rules out a WARP endpoint.
    // No ICMP unreachable response makes a WARP endpoint likely.
    // Content on TCP port 443 or 80 identifies Tunnel.
    // Without an HTTP response, the UDP signal decides the result.
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
            // A closed UDP port 2408 rules out WARP. Use HTTP to confirm Tunnel.
            if (udp2408Closed == true)
                return httpResponded == true ? "Cloudflare Tunnel" : "Cloudflare CDN";

            // An open UDP port 2408 indicates WARP unless HTTP also responds.
            if (udp2408Closed == false)
            {
                if (httpResponded == true)
                    return "Cloudflare Tunnel"; // HTTP with UDP port 2408 identifies Tunnel with colocated WARP.
                return "Cloudflare WARP";
            }

            // Use only the HTTP signal when the UDP result is unknown.
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
